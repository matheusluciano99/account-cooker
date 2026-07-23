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
use hunter::model::{AgentId, Ledger, TxRecord};
use noise_core::types::{AccountId, ActionKind};
use persona::Persona;
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};

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
    clock: i64,
    slot: u64,
    sig: u64,
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
    /// single-source actions, per-record ts jitter). `false` = legacy Curupira, whose
    /// ledger is byte-identical to the pre-hardening engine. No effect on `Mode::Naive`.
    pub harden_timing: bool,
    pub hardening: HardeningConfig,
}

/// Tunables for the hardened Curupira path. See the hardening spec.
#[derive(Clone, Debug)]
pub struct HardeningConfig {
    /// Mean seconds between consecutive records within one wake (exponential, min 1s).
    pub intra_gap_mean_secs: f64,
    /// Per-wake probability of a genuine internal consolidation sweep (the honest residual
    /// a windowed adversary can partially recover — this is what keeps F1 > 0).
    pub consolidation_prob: f64,
    pub sweep_min_sources: usize,
    pub sweep_max_sources: usize,
    /// Scale each subaccount's delay by the agent's subaccount count so the operator's
    /// AGGREGATE action rate ~= the legacy per-agent rate (holds volume/runtime down and
    /// keeps coincidental cross-operator co-activity low). Required for the honest bands.
    pub hold_aggregate_rate: bool,
}

impl Default for HardeningConfig {
    fn default() -> Self {
        HardeningConfig {
            intra_gap_mean_secs: 7.0,
            consolidation_prob: 0.03,
            sweep_min_sources: 2,
            sweep_max_sources: 3,
            hold_aggregate_rate: true,
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

/// Run the simulation and return the observable ledger.
///
/// `Mode::Naive` and legacy Curupira (`harden_timing == false`) go through the ORIGINAL
/// `perform_action` path with the original RNG draw order, so their ledgers are byte-for-
/// byte reproducible against the pre-hardening engine. Hardened Curupira takes the
/// per-subaccount path (`perform_action_hardened`).
pub fn simulate(personas: &[Persona], cfg: &SimConfig) -> Ledger {
    assert!(!personas.is_empty(), "need at least one persona");
    let mut rng = StdRng::seed_from_u64(cfg.seed ^ (cfg.mode as u64).wrapping_mul(0x9E3779B9));
    let hardened = cfg.mode == Mode::Curupira && cfg.harden_timing;

    let externals: Vec<AccountId> = (0..cfg.num_external.max(1))
        .map(|_| AccountId::random(&mut rng))
        .collect();

    let mut agents: Vec<Agent> = Vec::with_capacity(cfg.num_agents);
    let mut sched: Vec<Sched> = Vec::new();
    for id in 0..cfg.num_agents {
        let persona = personas[id % personas.len()].clone();
        let n = persona.num_subaccounts.max(1);
        // Draw subaccount ids EXACTLY as before, so hardened shares legacy's ids for the
        // same seed (RNG streams diverge only at the next draw).
        let subaccounts: Vec<AccountId> = (0..n).map(|_| AccountId::random(&mut rng)).collect();
        let main = subaccounts[0];
        let agent_idx = agents.len();
        let mut sub_sched = Vec::new();

        if !hardened {
            // naive / legacy — identical to the pre-hardening engine (one agent clock).
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

    let mut chain = MockChain::new(cfg.start_ts);
    let end = cfg.start_ts + cfg.duration_secs;

    // Discrete-event loop over scheduler entries. Strict `<` picks the first minimum, so
    // for naive/legacy (one entry per agent, in agent order) the pick sequence — and thus
    // the RNG draw order — is identical to the original agent-scan loop.
    loop {
        let (mut pick, mut best) = (None, i64::MAX);
        for (i, s) in sched.iter().enumerate() {
            if s.next_at < best {
                best = s.next_at;
                pick = Some(i);
            }
        }
        let si = match pick {
            Some(i) if best <= end => i,
            _ => break,
        };
        let (agent_idx, sub_idx) = (sched[si].agent_idx, sched[si].sub_idx);
        chain.set_time(best);
        match sub_idx {
            None => {
                perform_action(&mut chain, &mut agents[agent_idx], &externals, cfg.mode, &mut rng);
                let sod = best.rem_euclid(86_400) as u64;
                let d = agents[agent_idx]
                    .persona
                    .circadian
                    .next_delay_secs(sod, &mut rng) as i64;
                sched[si].next_at = best + d.max(1);
            }
            Some(k) => {
                perform_action_hardened(&mut chain, &agents[agent_idx], k, &externals, cfg, &mut rng);
                let phase = agents[agent_idx].sub_sched[k].phase;
                let sod = (best + phase).rem_euclid(86_400) as u64;
                let mut d = agents[agent_idx]
                    .persona
                    .circadian
                    .next_delay_secs(sod, &mut rng) as i64;
                if cfg.hardening.hold_aggregate_rate {
                    d *= agents[agent_idx].subaccounts.len() as i64;
                }
                sched[si].next_at = best + d.max(1);
            }
        }
    }

    chain.ledger
}

fn perform_action(
    chain: &mut MockChain,
    agent: &mut Agent,
    externals: &[AccountId],
    mode: Mode,
    rng: &mut StdRng,
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
fn intra_gap(cfg: &SimConfig, rng: &mut StdRng) -> i64 {
    let mean = cfg.hardening.intra_gap_mean_secs.max(1.0);
    let u = rng.random::<f64>().clamp(1e-9, 1.0);
    (-u.ln() * mean).max(1.0) as i64
}

/// The hardened Curupira action. Unlike `perform_action`, a wake belongs to ONE subaccount
/// (`sub_idx`), every record gets its OWN jittered timestamp, and decoys ride the same
/// source. This deletes the same-ts, multi-source fan-out entirely — a windowed adversary
/// finds only single-source groups from normal activity. The ONLY same-operator structure
/// left is the rare genuine consolidation sweep (`consolidate_sweep`), the honest residual.
fn perform_action_hardened(
    chain: &mut MockChain,
    agent: &Agent,
    sub_idx: usize,
    externals: &[AccountId],
    cfg: &SimConfig,
    rng: &mut StdRng,
) {
    let mut t = chain.now(); // == best
    let source = agent.subaccounts[sub_idx]; // PINNED for the whole wake

    // (first draw) rare honest residual: a genuine internal consolidation to the hub.
    if rng.random::<f64>() < cfg.hardening.consolidation_prob {
        consolidate_sweep(chain, agent, &mut t, cfg, rng);
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
                source, // SAME source for every part — no multi-source fan-out
                dest: planned.dest,
                amount: part,
                kind: planned.kind,
            };
            chain.record(&tx, fee_payer, Some(agent.id));
        }
    }

    // Decoys ride the SAME acting subaccount (kills the decoy-only co-activity leak).
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
    // No external churn in the hardened path: the consolidation sweep is the rebalance
    // analog, and external churn (a fresh dest) was always scoring-inert.
}

/// A genuine internal consolidation: move value from `k` distinct non-main subaccounts to
/// the operator's private hub (`main`), at jittered distinct timestamps inside a short
/// spread. This is the honest residual: exact-ts sees `k` singletons and misses it; a
/// windowed adversary regroups the spread and recovers it — every recovered link real,
/// because the hub is operator-private, so precision stays high while recall stays low.
fn consolidate_sweep(
    chain: &mut MockChain,
    agent: &Agent,
    t: &mut i64,
    cfg: &SimConfig,
    rng: &mut StdRng,
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
            kind: ActionKind::Transfer, // NOT Consolidate: v1 cospend must not trivially harvest it
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
    rng: &mut StdRng,
) {
    match mode {
        // Sloppy: one stable fee-payer (the main account) pays for everything, no
        // splitting. Fee-payer + co-spend analysis reconstructs the whole entity.
        Mode::Naive => {
            chain.record(p, agent.main, Some(agent.id));
        }
        // Curupira: split the value into non-obvious parts and pay each with a FRESH
        // throwaway fee-payer, from a rotating source. No stable fee-payer to cluster on.
        //
        // TODO(harden-timing): every part below is recorded under the SAME `chain.clock`
        // (set once per action in `simulate`), so all parts share one `ts` and land in a
        // single burst — which O Cacador v2's H-COPAY/H-COACT reconstruct with F1~1.0.
        // Fee-payer rotation is useless against this. To actually defeat v2, advance the
        // clock by a jittered gap between parts/decoys (and decorrelate per-subaccount
        // timing instead of one circadian clock per agent). See the hunter burst heuristics.
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
fn maybe_rebalance(chain: &mut MockChain, agent: &Agent, mode: Mode, rng: &mut StdRng) {
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
        let naive = simulate(&personas, &SimConfig { mode: Mode::Naive, ..base.clone() });
        let hardened = simulate(
            &personas,
            &SimConfig { mode: Mode::Curupira, harden_timing: true, ..base.clone() },
        );
        let legacy = simulate(
            &personas,
            &SimConfig { mode: Mode::Curupira, harden_timing: false, ..base.clone() },
        );
        (naive, hardened, legacy)
    }

    /// The pre-registered honest before/after. Band SHAPES are fixed; only the engine
    /// tuning constant `consolidation_prob` could move the residual, and it lands at ~0.14.
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

        // (a) NAIVE is fully recovered by BOTH adversaries (static fee-payer + consolidate).
        assert!(n_exact.attribution_f1 > 0.9, "naive exact f1 {}", n_exact.attribution_f1);
        assert!(n_win.attribution_f1 > 0.9, "naive windowed f1 {}", n_win.attribution_f1);

        // (b) TEETH: the windowed adversary STILL fully de-anonymizes LEGACY (un-hardened)
        //     Curupira, at high precision. So a low hardened F1 is the hardening's doing,
        //     not a crippled adversary.
        assert!(l_win.attribution_f1 > 0.9, "legacy windowed f1 {}", l_win.attribution_f1);
        assert!(l_win.attribution_precision > 0.9, "legacy windowed prec {}", l_win.attribution_precision);
        assert!(l_exact.attribution_f1 > 0.9, "legacy exact f1 {}", l_exact.attribution_f1);

        // (c) DOCUMENTED straw-man (NOT the claim): exact-ts collapses on hardened because
        //     the same-ts fan-out is structurally gone. Expected; not the privacy result.
        assert!(h_exact.attribution_f1 < 0.3, "hardened exact f1 {} (straw-man)", h_exact.attribution_f1);

        // (d) THE CLAIM — against the windowed analyst, hardened Curupira:
        //     nonzero (a genuine consolidation residual survives — noise is not magic)...
        assert!(h_win.attribution_f1 > 0.0, "residual must be nonzero, got {}", h_win.attribution_f1);
        //     ...clearly below naive (noise helps: pre-registered gap > 0.30)...
        assert!(
            h_win.attribution_f1 < n_win.attribution_f1 - 0.30,
            "gap to naive too small: hardened {} vs naive {}",
            h_win.attribution_f1,
            n_win.attribution_f1
        );
        //     ...and HONEST: the residual links are real (high precision), no collapse.
        assert!(
            h_win.attribution_precision >= 0.80,
            "windowed hardened precision {} — that would be dishonest over-merge",
            h_win.attribution_precision
        );
        assert!(h_win.largest_cluster_frac < 0.5, "collapse: lcf {}", h_win.largest_cluster_frac);
    }

    #[test]
    fn naive_unaffected_by_hardening_flag() {
        // Byte-identical guarantee: the naive path ignores harden_timing entirely.
        let personas = Persona::presets();
        let base = SimConfig::default();
        let a = simulate(&personas, &SimConfig { mode: Mode::Naive, harden_timing: true, ..base.clone() });
        let b = simulate(&personas, &SimConfig { mode: Mode::Naive, harden_timing: false, ..base.clone() });
        assert_eq!(a.records.len(), b.records.len());
        for (x, y) in a.records.iter().zip(b.records.iter()) {
            assert_eq!(
                (x.ts, x.slot, x.source, x.dest, x.amount, x.kind, x.fee_payer),
                (y.ts, y.slot, y.source, y.dest, y.amount, y.kind, y.fee_payer)
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
            assert_eq!((x.ts, x.slot, x.source, x.dest, x.amount), (y.ts, y.slot, y.source, y.dest, y.amount));
        }
    }

    #[test]
    fn legacy_curupira_reproducible_and_distinct_from_hardened() {
        let personas = Persona::presets();
        let base = SimConfig::default();
        let legacy1 = simulate(&personas, &SimConfig { harden_timing: false, ..base.clone() });
        let legacy2 = simulate(&personas, &SimConfig { harden_timing: false, ..base.clone() });
        let hardened = simulate(&personas, &SimConfig { harden_timing: true, ..base.clone() });
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
}
