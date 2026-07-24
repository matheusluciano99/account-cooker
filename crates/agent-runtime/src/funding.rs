//! Fee-payer funding as an observable graph.
//!
//! account-cooker mints a fresh throwaway fee-payer per transaction part. On a real chain each of
//! those throwaways must first be funded with SOL — and that funding transaction is itself
//! observable. If every throwaway traces back to one operator-owned wallet, an analyst walks
//! the common-funder graph and re-links the whole fleet, undoing fee-payer rotation. This
//! module models that funding so the adversary can measure the leak instead of ignoring it.
//!
//! It runs as a PURE POST-PASS over a completed base ledger, on its own seeded RNG stream that
//! never touches the action stream: with `funding: None` the ledger is returned unchanged, and
//! a funded ledger is the base ledger plus an appended, deterministic funding suffix. Funding
//! records carry `kind = Transfer` — indistinguishable on-chain from any other SOL transfer — so
//! the adversary must *infer* which transfers are funding, as it must infer consolidation sweeps.

use crate::{Mode, SimConfig};
use chacha20::ChaCha12Rng;
use hunter::model::{AgentId, Ledger, TxRecord};
use noise_core::types::{AccountId, ActionKind};
use rand::{RngExt, SeedableRng};
use std::collections::{BTreeMap, HashSet};

/// Where the SOL that funds each throwaway fee-payer comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FundingPolicy {
    /// Fund every throwaway from the operator's own hub (`main`). The leaky baseline: the hub is
    /// operator-owned and already recoverable, so the funder graph re-links everything.
    OperatorHub,
    /// One fresh, operator-owned funder wallet per operator. One hop of indirection — which the
    /// funder graph still collapses, since the funder is owned.
    DedicatedFunder,
    /// A bounded pool of `k` relayer accounts shared across ALL operators. A relayer is a
    /// third-party service, not operator-owned; the residual is governed by how many operators
    /// hide behind each relayer (the anonymity set).
    SharedRelayers { k: usize },
}

/// Tunables for the funding post-pass.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct FundingConfig {
    pub policy: FundingPolicy,
    /// `true`: each operator keeps one relayer for the whole run (anonymity set ≈ operators/k).
    /// `false`: a relayer is drawn per funding event (a relayer then spans every operator over a
    /// long run, so the anonymity set approaches the whole fleet regardless of k).
    pub sticky: bool,
    /// Funding lands `[lead_min_secs, lead_max_secs]` before the fee-payer's first use.
    pub lead_min_secs: i64,
    pub lead_max_secs: i64,
    /// A fee-sized top-up, deliberately in a tighter, smaller range than action amounts.
    pub topup_min: u64,
    pub topup_max: u64,
}

impl FundingConfig {
    /// A policy with the standard just-in-time lead and fee-sized top-up.
    pub fn new(policy: FundingPolicy) -> Self {
        FundingConfig {
            policy,
            sticky: true,
            lead_min_secs: 30,
            lead_max_secs: 900,
            topup_min: 20_000,
            topup_max: 60_000,
        }
    }
}

/// Funding RNG seed — a fixed salt on the mode-salted action seed, so the funding stream never
/// collides with the action stream and differs per mode.
pub(crate) fn derive_funding_seed(cfg: &SimConfig) -> u64 {
    crate::derive_seed(cfg) ^ 0xF00D_5EED_0000_0004
}

/// Append funding transactions to `ledger` under `cfg.funding`. No-op for `Mode::Naive` (its
/// fee-payer is the always-present hub, so there is nothing to fund) and a pure function of the
/// completed base ledger, so fresh and resumed runs produce byte-identical funded ledgers.
pub(crate) fn apply_funding(
    ledger: &mut Ledger,
    hubs: &BTreeMap<AgentId, AccountId>,
    cfg: &SimConfig,
) {
    let Some(fcfg) = &cfg.funding else { return };
    if cfg.mode == Mode::Naive {
        return;
    }
    let mut frng = ChaCha12Rng::seed_from_u64(derive_funding_seed(cfg));

    let source_set: HashSet<AccountId> = ledger.records.iter().map(|r| r.source).collect();

    // Assign a funder to each operator (ascending AgentId, so draws are order-stable). Relayers
    // are third-party (operator = None); owned funders keep the operator label.
    let ops: Vec<AgentId> = hubs.keys().copied().collect();
    let relayers: Vec<AccountId> = match fcfg.policy {
        FundingPolicy::SharedRelayers { k } => (0..k.max(1))
            .map(|_| AccountId::random(&mut frng))
            .collect(),
        _ => Vec::new(),
    };
    let mut funder_of: BTreeMap<AgentId, (AccountId, Option<AgentId>)> = BTreeMap::new();
    for &op in &ops {
        let assigned = match fcfg.policy {
            FundingPolicy::OperatorHub => (hubs[&op], Some(op)),
            FundingPolicy::DedicatedFunder => (AccountId::random(&mut frng), Some(op)),
            FundingPolicy::SharedRelayers { .. } if fcfg.sticky => {
                (relayers[frng.random_range(0..relayers.len())], None)
            }
            // Non-sticky: assigned per event below; placeholder is never read.
            FundingPolicy::SharedRelayers { .. } => (relayers[0], None),
        };
        funder_of.insert(op, assigned);
    }
    let per_event_relayer =
        matches!(fcfg.policy, FundingPolicy::SharedRelayers { .. }) && !fcfg.sticky;

    // One funding event per distinct throwaway, at its first use.
    let mut funded: HashSet<AccountId> = HashSet::new();
    let mut events: Vec<TxRecord> = Vec::new();
    for r in &ledger.records {
        let fp = r.fee_payer;
        if source_set.contains(&fp) {
            continue; // an account that also signs as a source is not a throwaway fee-payer
        }
        if !funded.insert(fp) {
            continue; // already funded at an earlier use
        }
        let Some(op) = r.operator else { continue };
        let (funder, label) = if per_event_relayer {
            (relayers[frng.random_range(0..relayers.len())], None)
        } else {
            funder_of[&op]
        };
        if funder == fp {
            continue; // self-funding guard
        }
        let lead =
            frng.random_range(fcfg.lead_min_secs..=fcfg.lead_max_secs.max(fcfg.lead_min_secs));
        let amount = frng.random_range(fcfg.topup_min..=fcfg.topup_max.max(fcfg.topup_min));
        events.push(TxRecord {
            sig: 0,
            slot: 0,
            ts: r.ts - lead,
            fee_payer: funder, // the funder signs (and pays for) its own transfer
            source: funder,
            dest: fp,
            amount,
            kind: ActionKind::Transfer,
            operator: label,
        });
    }

    // Append in a stable time order, continuing the sig/slot counters. The base records' bytes
    // are never touched: a funded ledger is (byte-identical base) + (funding suffix).
    events.sort_by_key(|e| (e.ts, e.dest));
    let mut sig = ledger.records.iter().map(|r| r.sig).max().unwrap_or(0);
    let mut slot = ledger.records.iter().map(|r| r.slot).max().unwrap_or(0);
    for mut e in events {
        sig += 1;
        slot += 1;
        e.sig = sig;
        e.slot = slot;
        ledger.records.push(e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{simulate, HardeningConfig};
    use persona::Persona;

    fn base(funding: Option<FundingConfig>) -> SimConfig {
        SimConfig {
            funding,
            ..SimConfig::default()
        }
    }

    fn same_fields(a: &TxRecord, b: &TxRecord) -> bool {
        (
            a.sig,
            a.slot,
            a.ts,
            a.fee_payer,
            a.source,
            a.dest,
            a.amount,
            a.kind,
        ) == (
            b.sig,
            b.slot,
            b.ts,
            b.fee_payer,
            b.source,
            b.dest,
            b.amount,
            b.kind,
        )
    }

    #[test]
    fn funding_off_is_byte_identical_prefix() {
        // Funding ON leaves the base records untouched and only appends a suffix.
        let personas = Persona::presets();
        let off = simulate(&personas, &base(None));
        for policy in [
            FundingPolicy::OperatorHub,
            FundingPolicy::DedicatedFunder,
            FundingPolicy::SharedRelayers { k: 3 },
        ] {
            let on = simulate(&personas, &base(Some(FundingConfig::new(policy))));
            assert!(
                on.records.len() > off.records.len(),
                "{policy:?} must append funding records"
            );
            for (o, b) in off.records.iter().zip(on.records.iter()) {
                assert!(same_fields(o, b), "{policy:?} perturbed a base record");
            }
        }
    }

    #[test]
    fn naive_gets_no_funding() {
        let personas = Persona::presets();
        let cfg = SimConfig {
            mode: Mode::Naive,
            funding: Some(FundingConfig::new(FundingPolicy::OperatorHub)),
            ..SimConfig::default()
        };
        let with = simulate(&personas, &cfg);
        let without = simulate(
            &personas,
            &SimConfig {
                mode: Mode::Naive,
                funding: None,
                ..SimConfig::default()
            },
        );
        assert_eq!(
            with.records.len(),
            without.records.len(),
            "naive must not be funded"
        );
    }

    #[test]
    fn funding_is_deterministic() {
        let personas = Persona::presets();
        let cfg = base(Some(FundingConfig::new(FundingPolicy::SharedRelayers {
            k: 3,
        })));
        let a = simulate(&personas, &cfg);
        let b = simulate(&personas, &cfg);
        assert_eq!(a.records.len(), b.records.len());
        for (x, y) in a.records.iter().zip(b.records.iter()) {
            assert!(same_fields(x, y));
        }
    }

    #[test]
    fn funding_suffix_is_well_formed() {
        let personas = Persona::presets();
        let off = simulate(&personas, &base(None));
        let on = simulate(
            &personas,
            &base(Some(FundingConfig::new(FundingPolicy::OperatorHub))),
        );
        let fee_set: HashSet<AccountId> = on.records.iter().map(|r| r.fee_payer).collect();
        for f in &on.records[off.records.len()..] {
            assert_eq!(f.kind, ActionKind::Transfer, "funding is a plain transfer");
            assert_eq!(f.fee_payer, f.source, "funder signs its own funding tx");
            assert!(fee_set.contains(&f.dest), "funds a real fee-payer");
            assert_ne!(f.source, f.dest, "no self-funding");
        }
    }

    #[test]
    fn dedicated_funder_stream_does_not_touch_actions() {
        // Two policies with different funding draws must share an identical base prefix.
        let personas = Persona::presets();
        let hub = simulate(
            &personas,
            &base(Some(FundingConfig::new(FundingPolicy::OperatorHub))),
        );
        let ded = simulate(
            &personas,
            &base(Some(FundingConfig::new(FundingPolicy::DedicatedFunder))),
        );
        let off = simulate(&personas, &base(None));
        for i in 0..off.records.len() {
            assert!(same_fields(&hub.records[i], &off.records[i]));
            assert!(same_fields(&ded.records[i], &off.records[i]));
        }
    }

    #[test]
    fn hardening_config_still_default() {
        // Guards against an accidental HardeningConfig change slipping in with this module.
        assert_eq!(HardeningConfig::default().consolidation_prob, 0.03);
    }
}
