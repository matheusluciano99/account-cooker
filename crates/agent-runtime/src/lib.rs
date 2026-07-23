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
        }
    }
}

struct Agent {
    id: AgentId,
    persona: Persona,
    subaccounts: Vec<AccountId>,
    main: AccountId,
    next_at: i64,
}

/// Run the simulation and return the observable ledger.
pub fn simulate(personas: &[Persona], cfg: &SimConfig) -> Ledger {
    assert!(!personas.is_empty(), "need at least one persona");
    let mut rng = StdRng::seed_from_u64(cfg.seed ^ (cfg.mode as u64).wrapping_mul(0x9E3779B9));

    let externals: Vec<AccountId> = (0..cfg.num_external.max(1))
        .map(|_| AccountId::random(&mut rng))
        .collect();

    let mut agents: Vec<Agent> = Vec::with_capacity(cfg.num_agents);
    for id in 0..cfg.num_agents {
        let persona = personas[id % personas.len()].clone();
        let n = persona.num_subaccounts.max(1);
        let subaccounts: Vec<AccountId> = (0..n).map(|_| AccountId::random(&mut rng)).collect();
        let main = subaccounts[0];
        let sod = cfg.start_ts.rem_euclid(86_400) as u64;
        let d = persona.circadian.next_delay_secs(sod, &mut rng) as i64;
        agents.push(Agent {
            id: id as AgentId,
            persona,
            subaccounts,
            main,
            next_at: cfg.start_ts + d,
        });
    }

    let mut chain = MockChain::new(cfg.start_ts);
    let end = cfg.start_ts + cfg.duration_secs;

    // Discrete-event loop: always advance the earliest-scheduled agent.
    loop {
        let mut pick = None;
        let mut best = i64::MAX;
        for (i, a) in agents.iter().enumerate() {
            if a.next_at < best {
                best = a.next_at;
                pick = Some(i);
            }
        }
        let i = match pick {
            Some(i) if best <= end => i,
            _ => break,
        };

        chain.set_time(best);
        perform_action(&mut chain, &mut agents[i], &externals, cfg.mode, &mut rng);

        let sod = best.rem_euclid(86_400) as u64;
        let d = agents[i].persona.circadian.next_delay_secs(sod, &mut rng) as i64;
        agents[i].next_at = best + d.max(1);
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

    #[test]
    fn curupira_beats_naive_on_attribution() {
        let personas = Persona::presets();
        let cfg = SimConfig::default();
        let (naive, curupira) = run_comparison(&personas, &cfg);
        let adv = AdversaryConfig::default();
        let (_, rn) = analyze(&naive, &adv);
        let (_, rc) = analyze(&curupira, &adv);

        // The whole thesis in one assertion: the adversary reconstructs the naive
        // fleet well and the Curupira fleet poorly.
        assert!(
            rn.attribution_f1 > rc.attribution_f1,
            "naive f1 {} should exceed curupira f1 {}",
            rn.attribution_f1,
            rc.attribution_f1
        );
        assert!(rc.fragmentation > rn.fragmentation);
        assert!(rn.linkage_recall >= rc.linkage_recall);
    }
}
