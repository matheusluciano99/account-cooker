//! The fleet orchestrator.
//!
//! By default this runs an **offline, deterministic** simulation: it emits a `Ledger`
//! that the `hunter` crate can analyze, with zero network and full reproducibility
//! from a seed. That is what powers the reproducible before/after demo.
//!
//! Under the `live` feature it drives real accounts against a Solana RPC (see the
//! `live` module). The behavioral logic — personas, splitting, fee-payer rotation,
//! decoys — is identical in both worlds; only the `Chain` sink differs.

use adapters::{adapter_for, ActionContext, PlannedTx};
use chacha20::ChaCha12Rng;
use hunter::model::{AgentId, Ledger, TxRecord};
use noise_core::types::{AccountId, ActionKind};
use persona::Persona;
use rand::{RngExt, SeedableRng};
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap};

pub mod durable;
pub mod funding;

pub use funding::{FundingConfig, FundingPolicy};

#[cfg(feature = "live")]
pub mod live;

/// A sink for transactions. `MockChain` records them; the live backend submits them.
pub trait Chain {
    fn now(&self) -> i64;
    fn set_time(&mut self, ts: i64);
    fn record(&mut self, tx: &PlannedTx, fee_payer: AccountId, operator: Option<AgentId>);
}

/// In-memory ledger. Records exactly the fields an on-chain observer would see.
pub struct MockChain {
    pub ledger: Ledger,
    pub(crate) clock: i64,
    pub(crate) slot: u64,
    pub(crate) sig: u64,
}

impl MockChain {
    pub fn new(start_ts: i64) -> Self {
        MockChain {
            ledger: Ledger::default(),
            clock: start_ts,
            slot: 0,
            sig: 0,
        }
    }
}

impl Chain for MockChain {
    fn now(&self) -> i64 {
        self.clock
    }
    fn set_time(&mut self, ts: i64) {
        self.clock = ts;
    }
    fn record(&mut self, tx: &PlannedTx, fee_payer: AccountId, operator: Option<AgentId>) {
        self.sig += 1;
        self.slot += 1;
        self.ledger.records.push(TxRecord {
            sig: self.sig,
            slot: self.slot,
            ts: self.clock,
            fee_payer,
            source: tx.source,
            dest: tx.dest,
            amount: tx.amount,
            kind: tx.kind,
            operator,
        });
    }
}

/// Noise mode. `Naive` is the sloppy baseline the cooker must beat.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Naive,
    Curupira,
}

#[derive(Clone, Debug)]
pub struct SimConfig {
    pub num_agents: usize,
    pub duration_secs: i64,
    pub start_ts: i64,
    pub mode: Mode,
    pub seed: u64,
    pub num_external: usize,
    /// Curupira-only: enable timing hardening (per-subaccount decorrelated scheduling,
    /// single-source actions, per-record ts jitter). `false` = legacy Curupira (single
    /// agent clock, whole action stamped at one ts). No effect on `Mode::Naive`.
    pub harden_timing: bool,
    pub hardening: HardeningConfig,
    /// Curupira-only: model where fee-payer SOL comes from as a post-pass over the finished
    /// ledger. `None` (default) is byte-identical to the pre-funding engine.
    pub funding: Option<FundingConfig>,
}

/// Tunables for the hardened Curupira path.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HardeningConfig {
    /// Mean seconds between consecutive records within one wake (exponential, min 1s).
    pub intra_gap_mean_secs: f64,
    /// Per-wake probability of a genuine internal consolidation sweep.
    pub consolidation_prob: f64,
    pub sweep_min_sources: usize,
    pub sweep_max_sources: usize,
    /// Scale each subaccount's delay by the agent's subaccount count so an operator's
    /// aggregate action rate stays near the per-agent rate (bounds volume and keeps
    /// coincidental cross-operator co-activity low).
    pub hold_aggregate_rate: bool,
    /// How periodic balance maintenance is represented. Rotating each selected account into
    /// a fresh successor avoids the permanent many-to-one hub that graph analysis trivially
    /// clusters. `DirectHub` is retained as an explicit leaky ablation.
    #[serde(default)]
    pub rebalance: RebalanceStrategy,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RebalanceStrategy {
    #[default]
    RotateAccounts,
    DirectHub,
}

impl Default for HardeningConfig {
    fn default() -> Self {
        HardeningConfig {
            intra_gap_mean_secs: 7.0,
            consolidation_prob: 0.03,
            sweep_min_sources: 2,
            sweep_max_sources: 3,
            hold_aggregate_rate: true,
            rebalance: RebalanceStrategy::RotateAccounts,
        }
    }
}

impl Default for SimConfig {
    fn default() -> Self {
        SimConfig {
            num_agents: 12,
            duration_secs: 3 * 86_400, // three simulated days
            start_ts: 1_700_000_000,
            mode: Mode::Curupira,
            seed: 1,
            num_external: 40,
            harden_timing: true,
            hardening: HardeningConfig::default(),
            funding: None,
        }
    }
}

/// Per-subaccount schedule (hardened path only). Parallel-indexed to `Agent.subaccounts`.
struct SubSched {
    /// Fixed circadian phase offset (seconds) so subaccounts do not wake together.
    phase: i64,
}

struct Agent {
    id: AgentId,
    persona: Persona,
    subaccounts: Vec<AccountId>,
    sub_sched: Vec<SubSched>, // empty for naive/legacy; len == subaccounts for hardened
    main: AccountId,
}

/// A flat scheduler entry. naive/legacy: one per agent (`sub_idx = None`). hardened: one
/// per `(agent, subaccount)` so subaccounts are scheduled independently.
struct Sched {
    agent_idx: usize,
    sub_idx: Option<usize>,
    next_at: i64,
}

/// Seed derivation, shared by fresh runs and durable resume.
pub(crate) fn derive_seed(cfg: &SimConfig) -> u64 {
    cfg.seed ^ (cfg.mode as u64).wrapping_mul(0x9E3779B9)
}

/// A sink notified as a run progresses. `NullSink` does nothing (plain `simulate`); the
/// durable sink journals records and writes checkpoints (see the `durable` module).
pub(crate) trait DurSink {
    fn on_records(&mut self, new: &[TxRecord]) -> std::io::Result<()>;
    /// Called at each top-of-loop boundary (heap full, state consistent). Returns `true` to
    /// stop the run early without finishing — used to simulate a crash in tests.
    fn on_boundary(&mut self, st: &RunState, done: bool) -> std::io::Result<bool>;
}

struct NullSink;
impl DurSink for NullSink {
    fn on_records(&mut self, _: &[TxRecord]) -> std::io::Result<()> {
        Ok(())
    }
    fn on_boundary(&mut self, _: &RunState, _: bool) -> std::io::Result<bool> {
        Ok(false)
    }
}

/// The full mutable state of a run: the parts reconstructible from `(personas, cfg)` plus the
/// dynamic state a checkpoint must capture (rng, heap, chain, event count).
pub(crate) struct RunState {
    pub(crate) agents: Vec<Agent>,
    pub(crate) externals: Vec<AccountId>,
    pub(crate) sched: Vec<Sched>,
    pub(crate) cfg: SimConfig,
    pub(crate) end: i64,
    pub(crate) rng: ChaCha12Rng,
    pub(crate) heap: BinaryHeap<Reverse<(i64, usize)>>,
    pub(crate) chain: MockChain,
    pub(crate) events: u64,
}

/// Build a fresh run from `(personas, cfg)` — identical setup and RNG seeding to the original
/// single-function `simulate`, so the ledger it produces is byte-identical.
pub(crate) fn build_fresh(personas: &[Persona], cfg: &SimConfig) -> RunState {
    assert!(!personas.is_empty(), "need at least one persona");
    let mut rng = ChaCha12Rng::seed_from_u64(derive_seed(cfg));
    let hardened = cfg.mode == Mode::Curupira && cfg.harden_timing;

    let externals: Vec<AccountId> = (0..cfg.num_external.max(1))
        .map(|_| AccountId::random(&mut rng))
        .collect();

    let mut agents: Vec<Agent> = Vec::with_capacity(cfg.num_agents);
    let mut sched: Vec<Sched> = Vec::new();
    for id in 0..cfg.num_agents {
        let persona = personas[id % personas.len()].clone();
        let n = persona.num_subaccounts.max(1);
        // Draw subaccount ids before branching, so both paths share ids for a given seed.
        let subaccounts: Vec<AccountId> = (0..n).map(|_| AccountId::random(&mut rng)).collect();
        let main = subaccounts[0];
        let agent_idx = agents.len();
        let mut sub_sched = Vec::new();

        if !hardened {
            // naive / legacy — single agent clock.
            let sod = cfg.start_ts.rem_euclid(86_400) as u64;
            let d = persona.circadian.next_delay_secs(sod, &mut rng) as i64;
            sched.push(Sched {
                agent_idx,
                sub_idx: None,
                next_at: cfg.start_ts + d,
            });
        } else {
            // hardened — each subaccount gets its own phase-shifted circadian clock.
            for _k in 0..n {
                let phase = rng.random_range(0..86_400) as i64;
                let sod = (cfg.start_ts + phase).rem_euclid(86_400) as u64;
                let mut d = persona.circadian.next_delay_secs(sod, &mut rng) as i64;
                if cfg.hardening.hold_aggregate_rate {
                    d *= n as i64;
                }
                let k = sub_sched.len();
                sub_sched.push(SubSched { phase });
                sched.push(Sched {
                    agent_idx,
                    sub_idx: Some(k),
                    next_at: cfg.start_ts + d.max(1),
                });
            }
        }

        agents.push(Agent {
            id: id as AgentId,
            persona,
            subaccounts,
            sub_sched,
            main,
        });
    }

    let chain = MockChain::new(cfg.start_ts);
    let end = cfg.start_ts + cfg.duration_secs;
    let mut heap: BinaryHeap<Reverse<(i64, usize)>> = BinaryHeap::with_capacity(sched.len());
    for (i, s) in sched.iter().enumerate() {
        heap.push(Reverse((s.next_at, i)));
    }
    RunState {
        agents,
        externals,
        sched,
        cfg: cfg.clone(),
        end,
        rng,
        heap,
        chain,
        events: 0,
    }
}

/// The discrete-event loop, shared by `simulate` and the durable runner. At each top-of-loop
/// boundary the state is consistent and the heap holds every schedule entry, so
/// `sink.on_boundary` may snapshot; `sink.on_records` receives each event's new records.
pub(crate) fn run_core(st: &mut RunState, sink: &mut dyn DurSink) -> std::io::Result<()> {
    loop {
        let done = st
            .heap
            .peek()
            .is_none_or(|Reverse((best, _))| *best > st.end);
        if sink.on_boundary(st, done)? {
            return Ok(());
        }
        if done {
            return Ok(());
        }
        let Reverse((best, si)) = st.heap.pop().unwrap();
        let (agent_idx, sub_idx) = (st.sched[si].agent_idx, st.sched[si].sub_idx);
        // `best` is this agent's logical wake time. One wake may expand into several
        // transactions with intra-action gaps, so another agent can be logically due before
        // the previous wake's last record. Clamp only the observable chain clock; anchoring
        // the next wake to that global clock would serialize a large fleet and destroy its
        // aggregate rate.
        let observable_at = best.max(st.chain.now());
        st.chain.set_time(observable_at);
        let before = st.chain.ledger.records.len();
        match sub_idx {
            None => {
                perform_action(
                    &mut st.chain,
                    &mut st.agents[agent_idx],
                    &st.externals,
                    st.cfg.mode,
                    &mut st.rng,
                );
                let sod = best.rem_euclid(86_400) as u64;
                let d = st.agents[agent_idx]
                    .persona
                    .circadian
                    .next_delay_secs(sod, &mut st.rng) as i64;
                st.heap.push(Reverse((best.saturating_add(d.max(1)), si)));
            }
            Some(k) => {
                perform_action_hardened(
                    &mut st.chain,
                    &mut st.agents[agent_idx],
                    k,
                    &st.externals,
                    &st.cfg,
                    &mut st.rng,
                );
                let phase = st.agents[agent_idx].sub_sched[k].phase;
                let sod = best.saturating_add(phase).rem_euclid(86_400) as u64;
                let mut d = st.agents[agent_idx]
                    .persona
                    .circadian
                    .next_delay_secs(sod, &mut st.rng) as i64;
                if st.cfg.hardening.hold_aggregate_rate {
                    d *= st.agents[agent_idx].subaccounts.len() as i64;
                }
                st.heap.push(Reverse((best.saturating_add(d.max(1)), si)));
            }
        }
        sink.on_records(&st.chain.ledger.records[before..])?;
        st.events += 1;
    }
}

/// Run the simulation and return the observable ledger.
///
/// `Mode::Naive` and legacy Curupira (`harden_timing == false`) use the single-clock
/// `perform_action` path; hardened Curupira uses the per-subaccount `perform_action_hardened`.
pub fn simulate(personas: &[Persona], cfg: &SimConfig) -> Ledger {
    let mut st = build_fresh(personas, cfg);
    run_core(&mut st, &mut NullSink).expect("NullSink never fails");
    finalize_funding(st, cfg)
}

/// Map each agent to its hub (`main`) account, used by the `OperatorHub` funding policy.
pub(crate) fn hubs_of(agents: &[Agent]) -> BTreeMap<AgentId, AccountId> {
    agents.iter().map(|a| (a.id, a.main)).collect()
}

/// Apply the funding post-pass (if configured) and return the final ledger. A no-op when
/// `cfg.funding` is `None`, so the returned ledger is byte-identical to the base run.
pub(crate) fn finalize_funding(st: RunState, cfg: &SimConfig) -> Ledger {
    if cfg.funding.is_none() {
        return st.chain.ledger;
    }
    let hubs = hubs_of(&st.agents);
    let mut ledger = st.chain.ledger;
    funding::apply_funding(&mut ledger, &hubs, cfg);
    ledger
}

fn perform_action(
    chain: &mut MockChain,
    agent: &mut Agent,
    externals: &[AccountId],
    mode: Mode,
    rng: &mut ChaCha12Rng,
) {
    let kind = agent.persona.choose_action(rng);
    let source = agent.subaccounts[rng.random_range(0..agent.subaccounts.len())];
    let counterparty = externals[rng.random_range(0..externals.len())];
    let amount = agent.persona.sample_amount(rng);

    let adapter = adapter_for(kind);
    let ctx = ActionContext {
        source,
        counterparty,
        amount,
    };
    for planned in adapter.plan(&ctx, rng) {
        emit_with_noise(chain, agent, &planned, mode, rng);
    }

    // Curupira interleaves decoys drawn from the persona's own dust model.
    if mode == Mode::Curupira {
        let n = agent.persona.decoy.num_decoys(rng);
        for _ in 0..n {
            let s = agent.subaccounts[rng.random_range(0..agent.subaccounts.len())];
            let d = externals[rng.random_range(0..externals.len())];
            let dust = agent.persona.decoy.dust_amount(rng);
            let p = PlannedTx {
                source: s,
                dest: d,
                amount: dust,
                kind: ActionKind::Dust,
            };
            emit_with_noise(chain, agent, &p, mode, rng);
        }
    }

    maybe_rebalance(chain, agent, mode, rng);
}

/// Exponential inter-record gap (seconds, >= 1) used to spread a hardened wake across time.
fn intra_gap(cfg: &SimConfig, rng: &mut ChaCha12Rng) -> i64 {
    let mean = cfg.hardening.intra_gap_mean_secs.max(1.0);
    let u = rng.random::<f64>().clamp(1e-9, 1.0);
    (-u.ln() * mean).max(1.0) as i64
}

/// A hardened wake: one subaccount acts, each record gets its own jittered timestamp, and
/// decoys use the same source. Normal activity is single-source; the only multi-source
/// structure is the occasional `consolidate_sweep`.
fn perform_action_hardened(
    chain: &mut MockChain,
    agent: &mut Agent,
    sub_idx: usize,
    externals: &[AccountId],
    cfg: &SimConfig,
    rng: &mut ChaCha12Rng,
) {
    let mut t = chain.now();
    let source = agent.subaccounts[sub_idx]; // one source for the whole wake

    // Occasionally perform balance maintenance instead of an outward action.
    if rng.random::<f64>() < cfg.hardening.consolidation_prob {
        match cfg.hardening.rebalance {
            RebalanceStrategy::RotateAccounts => rotate_accounts(chain, agent, &mut t, cfg, rng),
            RebalanceStrategy::DirectHub => consolidate_sweep(chain, agent, &mut t, cfg, rng),
        }
        return;
    }

    let kind = agent.persona.choose_action(rng);
    let counterparty = externals[rng.random_range(0..externals.len())];
    let amount = agent.persona.sample_amount(rng);
    let adapter = adapter_for(kind);
    let ctx = ActionContext {
        source,
        counterparty,
        amount,
    };
    for planned in adapter.plan(&ctx, rng) {
        let parts = noise_core::split::split_amount(planned.amount, &agent.persona.split, rng);
        let parts = if parts.is_empty() {
            vec![planned.amount]
        } else {
            parts
        };
        for part in parts {
            t += intra_gap(cfg, rng); // distinct ts per record
            chain.set_time(t);
            let fee_payer = AccountId::random(rng);
            let tx = PlannedTx {
                source, // same source for every part
                dest: planned.dest,
                amount: part,
                kind: planned.kind,
            };
            chain.record(&tx, fee_payer, Some(agent.id));
        }
    }

    // Decoys use the same acting subaccount.
    let ndec = agent.persona.decoy.num_decoys(rng);
    for _ in 0..ndec {
        t += intra_gap(cfg, rng);
        chain.set_time(t);
        let d = externals[rng.random_range(0..externals.len())];
        let dust = agent.persona.decoy.dust_amount(rng);
        let fee_payer = AccountId::random(rng);
        let tx = PlannedTx {
            source,
            dest: d,
            amount: dust,
            kind: ActionKind::Dust,
        };
        chain.record(&tx, fee_payer, Some(agent.id));
    }
    // No external churn here; `consolidate_sweep` is the only rebalance in this path.
}

/// Move selected subaccounts one-to-one into fresh successor accounts, then make those
/// successors the active accounts for future wakes. This keeps capital mobile without a
/// permanent many-to-one hub. The predecessor edge is still public; the Hunter can evolve
/// activation/lineage heuristics against it, but it no longer gets a privileged hub for free.
fn rotate_accounts(
    chain: &mut MockChain,
    agent: &mut Agent,
    t: &mut i64,
    cfg: &SimConfig,
    rng: &mut ChaCha12Rng,
) {
    let n = agent.subaccounts.len();
    if n < 2 {
        return;
    }
    // Keep index 0 as a stable treasury/funding identity; rotate only operational
    // subaccounts. This preserves causal funding semantics while avoiding a many-to-one
    // operational consolidation hub.
    let available = n - 1;
    let kmax = cfg.hardening.sweep_max_sources.clamp(1, available);
    let kmin = cfg.hardening.sweep_min_sources.clamp(1, kmax);
    let k = if kmin >= kmax {
        kmax
    } else {
        rng.random_range(kmin..=kmax)
    };
    let mut idxs: Vec<usize> = (1..n).collect();
    for i in 0..k {
        let j = i + rng.random_range(0..(available - i));
        idxs.swap(i, j);
    }

    for &sub_idx in idxs.iter().take(k) {
        let source = agent.subaccounts[sub_idx];
        let successor = AccountId::random(rng);
        *t += intra_gap(cfg, rng);
        chain.set_time(*t);
        let tx = PlannedTx {
            source,
            dest: successor,
            amount: agent.persona.sample_amount(rng),
            kind: ActionKind::Transfer,
        };
        chain.record(&tx, AccountId::random(rng), Some(agent.id));
        agent.subaccounts[sub_idx] = successor;
    }
}

/// Move value from `k` distinct non-main subaccounts into the operator's hub (`main`), each
/// at its own jittered timestamp within a short spread.
fn consolidate_sweep(
    chain: &mut MockChain,
    agent: &Agent,
    t: &mut i64,
    cfg: &SimConfig,
    rng: &mut ChaCha12Rng,
) {
    let n = agent.subaccounts.len();
    if n < 2 {
        return;
    }
    let target = agent.main; // per-operator hub == subaccounts[0]
    let avail = n - 1; // non-main indices 1..n
    let kmax = cfg.hardening.sweep_max_sources.min(avail);
    let kmin = cfg.hardening.sweep_min_sources.clamp(1, kmax);
    let k = if kmin >= kmax {
        kmax
    } else {
        rng.random_range(kmin..=kmax)
    };
    // Partial Fisher-Yates over non-main indices 1..n to pick k distinct sources.
    let mut idxs: Vec<usize> = (1..n).collect();
    for i in 0..k {
        let j = i + rng.random_range(0..(avail - i));
        idxs.swap(i, j);
    }
    for &sub in idxs.iter().take(k) {
        let src = agent.subaccounts[sub];
        *t += intra_gap(cfg, rng); // distinct, jittered ts within a short spread
        chain.set_time(*t);
        let amount = agent.persona.sample_amount(rng);
        let fee_payer = AccountId::random(rng);
        let tx = PlannedTx {
            source: src,
            dest: target,
            amount,
            kind: ActionKind::Transfer,
        };
        chain.record(&tx, fee_payer, Some(agent.id));
    }
}

/// The heart of the difference between naive and Curupira behavior.
fn emit_with_noise(
    chain: &mut MockChain,
    agent: &Agent,
    p: &PlannedTx,
    mode: Mode,
    rng: &mut ChaCha12Rng,
) {
    match mode {
        // Sloppy: one stable fee-payer (the main account) pays for everything, no
        // splitting. Fee-payer + co-spend analysis reconstructs the whole entity.
        Mode::Naive => {
            chain.record(p, agent.main, Some(agent.id));
        }
        // Curupira: split the value into non-obvious parts and pay each with a fresh
        // throwaway fee-payer, from a rotating source. No stable fee-payer to cluster on.
        Mode::Curupira => {
            let parts = noise_core::split::split_amount(p.amount, &agent.persona.split, rng);
            let parts = if parts.is_empty() {
                vec![p.amount]
            } else {
                parts
            };
            for part in parts {
                let fee_payer = AccountId::random(rng); // throwaway, funded per-use in live mode
                let source = agent.subaccounts[rng.random_range(0..agent.subaccounts.len())];
                let tx = PlannedTx {
                    source,
                    dest: p.dest,
                    amount: part,
                    kind: p.kind,
                };
                chain.record(&tx, fee_payer, Some(agent.id));
            }
        }
    }
}

/// Periodic consolidation/redistribution.
fn maybe_rebalance(chain: &mut MockChain, agent: &Agent, mode: Mode, rng: &mut ChaCha12Rng) {
    match mode {
        // Naive: funnel every sub-account into the main account. Textbook co-spend.
        Mode::Naive => {
            if rng.random::<f64>() < 0.12 {
                for &sub in agent.subaccounts.iter() {
                    if sub == agent.main {
                        continue;
                    }
                    let amt = rng.random_range(1_000..=100_000);
                    let tx = PlannedTx {
                        source: sub,
                        dest: agent.main,
                        amount: amt,
                        kind: ActionKind::Consolidate,
                    };
                    chain.record(&tx, agent.main, Some(agent.id));
                }
            }
        }
        // Curupira: occasionally move value to a FRESH churn address (no stable hub),
        // paid by a throwaway fee-payer. Nothing for co-spend to latch onto.
        Mode::Curupira => {
            if rng.random::<f64>() < 0.08 {
                let s = agent.subaccounts[rng.random_range(0..agent.subaccounts.len())];
                let churn = AccountId::random(rng);
                let amt = rng.random_range(1_000..=200_000);
                let tx = PlannedTx {
                    source: s,
                    dest: churn,
                    amount: amt,
                    kind: ActionKind::Transfer,
                };
                chain.record(&tx, AccountId::random(rng), Some(agent.id));
            }
        }
    }
}

/// Convenience: run both modes with the same seed for a clean before/after.
pub fn run_comparison(personas: &[Persona], base: &SimConfig) -> (Ledger, Ledger) {
    let naive = simulate(
        personas,
        &SimConfig {
            mode: Mode::Naive,
            ..base.clone()
        },
    );
    let curupira = simulate(
        personas,
        &SimConfig {
            mode: Mode::Curupira,
            ..base.clone()
        },
    );
    (naive, curupira)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hunter::{analyze, AdversaryConfig};

    #[test]
    fn simulation_is_deterministic() {
        let personas = Persona::presets();
        let cfg = SimConfig::default();
        let a = simulate(&personas, &cfg);
        let b = simulate(&personas, &cfg);
        assert_eq!(a.records.len(), b.records.len());
        assert!(!a.records.is_empty());
    }

    fn arms_race_ledgers() -> (Ledger, Ledger, Ledger) {
        let personas = Persona::presets();
        let base = SimConfig::default();
        let naive = simulate(
            &personas,
            &SimConfig {
                mode: Mode::Naive,
                ..base.clone()
            },
        );
        let hardened = simulate(
            &personas,
            &SimConfig {
                mode: Mode::Curupira,
                harden_timing: true,
                ..base.clone()
            },
        );
        let legacy = simulate(
            &personas,
            &SimConfig {
                mode: Mode::Curupira,
                harden_timing: false,
                ..base.clone()
            },
        );
        (naive, hardened, legacy)
    }

    /// Naive and legacy Curupira stay fully de-anonymized under both adversaries; hardened
    /// Curupira drops to a low, nonzero F1 at high precision against the windowed adversary.
    #[test]
    fn honest_arms_race_after_hardening() {
        let (naive, hardened, legacy) = arms_race_ledgers();
        let exact = AdversaryConfig::exact_ts();
        let win = AdversaryConfig::windowed(120);

        let (_, n_win) = analyze(&naive, &win);
        let (_, h_win) = analyze(&hardened, &win);
        let (_, l_win) = analyze(&legacy, &win);
        let (_, n_exact) = analyze(&naive, &exact);
        let (_, h_exact) = analyze(&hardened, &exact);
        let (_, l_exact) = analyze(&legacy, &exact);

        // Naive is fully recovered by both adversaries.
        assert!(
            n_exact.attribution_f1 > 0.9,
            "naive exact f1 {}",
            n_exact.attribution_f1
        );
        assert!(
            n_win.attribution_f1 > 0.9,
            "naive windowed f1 {}",
            n_win.attribution_f1
        );

        // The windowed adversary still fully de-anonymizes legacy Curupira at high precision.
        assert!(
            l_win.attribution_f1 > 0.9,
            "legacy windowed f1 {}",
            l_win.attribution_f1
        );
        assert!(
            l_win.attribution_precision > 0.9,
            "legacy windowed prec {}",
            l_win.attribution_precision
        );
        assert!(
            l_exact.attribution_f1 > 0.9,
            "legacy exact f1 {}",
            l_exact.attribution_f1
        );

        // Exact-ts collapses on hardened Curupira (no same-ts fan-out to key on).
        assert!(
            h_exact.attribution_f1 < 0.3,
            "hardened exact f1 {}",
            h_exact.attribution_f1
        );

        // Windowed vs hardened: nonzero, clearly below naive, at high precision, no collapse.
        assert!(
            h_win.attribution_f1 > 0.0,
            "residual must be nonzero, got {}",
            h_win.attribution_f1
        );
        assert!(
            h_win.attribution_f1 < n_win.attribution_f1 - 0.30,
            "gap to naive too small: hardened {} vs naive {}",
            h_win.attribution_f1,
            n_win.attribution_f1
        );
        assert!(
            h_win.attribution_precision >= 0.80,
            "windowed hardened precision {} — that would be dishonest over-merge",
            h_win.attribution_precision
        );
        assert!(
            h_win.largest_cluster_frac < 0.5,
            "collapse: lcf {}",
            h_win.largest_cluster_frac
        );
    }

    #[test]
    fn naive_unaffected_by_hardening_flag() {
        // Byte-identical guarantee: the naive path ignores harden_timing entirely.
        let personas = Persona::presets();
        let base = SimConfig::default();
        let a = simulate(
            &personas,
            &SimConfig {
                mode: Mode::Naive,
                harden_timing: true,
                ..base.clone()
            },
        );
        let b = simulate(
            &personas,
            &SimConfig {
                mode: Mode::Naive,
                harden_timing: false,
                ..base.clone()
            },
        );
        assert_eq!(a.records.len(), b.records.len());
        for (x, y) in a.records.iter().zip(b.records.iter()) {
            assert_eq!(
                (
                    x.ts,
                    x.slot,
                    x.source,
                    x.dest,
                    x.amount,
                    x.kind,
                    x.fee_payer
                ),
                (
                    y.ts,
                    y.slot,
                    y.source,
                    y.dest,
                    y.amount,
                    y.kind,
                    y.fee_payer
                )
            );
        }
    }

    #[test]
    fn hardened_simulation_is_deterministic() {
        let personas = Persona::presets();
        let cfg = SimConfig::default(); // hardened Curupira by default
        let a = simulate(&personas, &cfg);
        let b = simulate(&personas, &cfg);
        assert_eq!(a.records.len(), b.records.len());
        assert!(!a.records.is_empty());
        for (x, y) in a.records.iter().zip(b.records.iter()) {
            assert_eq!(
                (x.ts, x.slot, x.source, x.dest, x.amount),
                (y.ts, y.slot, y.source, y.dest, y.amount)
            );
        }
    }

    #[test]
    fn observable_time_never_moves_backwards() {
        let personas = Persona::presets();
        for (mode, harden_timing) in [
            (Mode::Naive, false),
            (Mode::Curupira, false),
            (Mode::Curupira, true),
        ] {
            let ledger = simulate(
                &personas,
                &SimConfig {
                    mode,
                    harden_timing,
                    ..SimConfig::default()
                },
            );
            assert!(
                ledger
                    .records
                    .windows(2)
                    .all(|pair| pair[0].ts <= pair[1].ts),
                "{mode:?} harden={harden_timing} emitted a timestamp inversion"
            );
        }
    }

    #[test]
    fn aggregate_activity_scales_with_the_fleet() {
        let personas = Persona::presets();
        let run = |num_agents| {
            simulate(
                &personas,
                &SimConfig {
                    num_agents,
                    duration_secs: 86_400,
                    num_external: 400,
                    ..SimConfig::default()
                },
            )
            .records
            .len()
        };
        let small = run(10);
        let large = run(100);
        assert!(
            large > small * 6,
            "100-agent activity ({large}) did not scale with 10-agent activity ({small})"
        );
    }

    #[test]
    fn legacy_curupira_reproducible_and_distinct_from_hardened() {
        let personas = Persona::presets();
        let base = SimConfig::default();
        let legacy1 = simulate(
            &personas,
            &SimConfig {
                harden_timing: false,
                ..base.clone()
            },
        );
        let legacy2 = simulate(
            &personas,
            &SimConfig {
                harden_timing: false,
                ..base.clone()
            },
        );
        let hardened = simulate(
            &personas,
            &SimConfig {
                harden_timing: true,
                ..base.clone()
            },
        );
        assert_eq!(legacy1.records.len(), legacy2.records.len());
        for (x, y) in legacy1.records.iter().zip(legacy2.records.iter()) {
            assert_eq!((x.ts, x.slot, x.source), (y.ts, y.slot, y.source));
        }
        // The flag actually branches into a different engine.
        assert_ne!(legacy1.records.len(), hardened.records.len());
    }

    #[test]
    fn analyze_is_deterministic_on_fixed_ledger() {
        let personas = Persona::presets();
        let cfg = SimConfig::default();
        let ledger = simulate(&personas, &cfg);
        // Union is commutative and thresholds are on counts, so HashMap iteration order in
        // the grouping heuristics cannot change the outcome — for both adversaries.
        for adv in [AdversaryConfig::exact_ts(), AdversaryConfig::windowed(120)] {
            let (_, r1) = analyze(&ledger, &adv);
            let (_, r2) = analyze(&ledger, &adv);
            assert_eq!(r1.attribution_f1, r2.attribution_f1);
            assert_eq!(r1.num_clusters, r2.num_clusters);
            assert_eq!(r1.attribution_precision, r2.attribution_precision);
            assert_eq!(r1.window_purity, r2.window_purity);
        }
    }

    // Heavy; excluded from the default suite. Run with:
    //   cargo test -p agent-runtime --release -- --ignored scale
    #[test]
    #[ignore]
    fn scale_1000_agents_14_days() {
        use std::time::Instant;
        let personas = Persona::presets();
        // External pool scales with the fleet so a fixed pool doesn't crowd copay buckets.
        let base = SimConfig {
            num_agents: 1000,
            duration_secs: 14 * 86_400,
            num_external: 4000,
            ..SimConfig::default()
        };
        let t0 = Instant::now();
        let naive = simulate(
            &personas,
            &SimConfig {
                mode: Mode::Naive,
                ..base.clone()
            },
        );
        let hardened = simulate(
            &personas,
            &SimConfig {
                mode: Mode::Curupira,
                harden_timing: true,
                ..base.clone()
            },
        );
        let hardened2 = simulate(
            &personas,
            &SimConfig {
                mode: Mode::Curupira,
                harden_timing: true,
                ..base.clone()
            },
        );

        assert!(
            hardened.records.len() > 1_000_000,
            "expected millions of records, got {}",
            hardened.records.len()
        );
        assert_eq!(hardened.records.len(), hardened2.records.len());

        let win = AdversaryConfig::windowed(120);
        let (_, n_win) = analyze(&naive, &win);
        let (_, h_win) = analyze(&hardened, &win);
        let (_, h2_win) = analyze(&hardened2, &win);
        let elapsed = t0.elapsed();
        println!(
            "scale: {} records, naive f1 {:.2}, hardened f1 {:.2}, {:?}",
            hardened.records.len(),
            n_win.attribution_f1,
            h_win.attribution_f1,
            elapsed
        );

        // Determinism at scale (bit-identical).
        assert_eq!(
            h_win.attribution_f1.to_bits(),
            h2_win.attribution_f1.to_bits()
        );
        assert_eq!(h_win.num_clusters, h2_win.num_clusters);

        // Structural arms-race invariants (scale-invariant — NOT the 12-agent constants).
        assert!(
            n_win.attribution_f1 > 0.9,
            "naive windowed f1 {}",
            n_win.attribution_f1
        );
        assert!(
            h_win.attribution_f1 > 0.0,
            "hardened residual must be nonzero {}",
            h_win.attribution_f1
        );
        assert!(
            h_win.attribution_f1 < n_win.attribution_f1 - 0.30,
            "gap to naive too small: hardened {} vs naive {}",
            h_win.attribution_f1,
            n_win.attribution_f1
        );
        assert!(
            h_win.attribution_precision >= 0.80,
            "precision {}",
            h_win.attribution_precision
        );
        assert!(
            h_win.largest_cluster_frac < 0.5,
            "lcf {}",
            h_win.largest_cluster_frac
        );

        // Generous guard against a regression back to super-linear behavior.
        assert!(
            elapsed.as_secs() < 600,
            "scale run took {:?} — possible O(n^2) regression",
            elapsed
        );
    }
}
