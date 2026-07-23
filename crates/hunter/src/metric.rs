//! Turning "the adversary clustered the ledger" into falsifiable NUMBERS.
//!
//! We compare the adversary's predicted clusters against ground-truth operator
//! ownership. This is what makes the cooker a serious contribution instead of a bag
//! of randomness: we can *prove* whether the noise degrades attribution.

use crate::heuristics::Clustering;
use crate::model::{AgentId, Ledger};
use noise_core::types::AccountId;
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug, serde::Serialize)]
pub struct Report {
    /// Distinct accounts in the ledger.
    pub num_accounts: usize,
    /// Operator-owned accounts scored (the ones with ground truth).
    pub owned_accounts: usize,
    /// Clusters the adversary produced.
    pub num_clusters: usize,
    /// Pairwise F1 of the adversary's clustering vs ground truth. LOWER = better privacy.
    pub attribution_f1: f64,
    /// Fraction of same-operator account pairs the adversary correctly linked. LOWER = better.
    pub linkage_recall: f64,
    /// Mean number of distinct adversary-clusters an operator's accounts are spread
    /// across. 1.0 = fully de-anonymized; higher = the adversary can't tell your
    /// accounts are one entity. HIGHER = better privacy.
    pub fragmentation: f64,
    /// Pairwise precision over owned accounts. HIGHER = the adversary's links are real
    /// rather than a trivial over-merge.
    pub attribution_precision: f64,
    /// Fraction of within-burst owned-source pairs that are truly same-operator (pooled,
    /// pair-weighted). A property of the ledger: 1.0 = bursts are pure; lower caps the
    /// precision any burst-based heuristic can reach.
    pub burst_purity: f64,
    /// Largest share of owned accounts in any single predicted cluster. Near 1.0 = the
    /// adversary collapsed the fleet into one cluster.
    pub largest_cluster_frac: f64,
    /// Like `burst_purity` but over Δt windows at `window_secs`: the upper bound on the
    /// precision a windowed adversary can reach.
    pub window_purity: f64,
    /// The window width this report was scored at (0 for identical-ts configs).
    pub window_secs: i64,
    /// Inferred fee-payer funding transactions in the ledger (0 when funding is not modeled).
    pub funding_records: usize,
    /// Mean number of distinct operators hiding behind one funder (over funders of >= 2
    /// fee-payers). 1.0 = each funder serves a single operator (a full leak); larger = fee-payers
    /// hide among more operators (a shared relayer's anonymity set). The honest headline number
    /// for the funding leak.
    pub funder_anonymity_set: f64,
}

/// Number of unordered pairs in a set of `k` items, C(k, 2). `saturating_sub` gives 0 for
/// `k == 0` (no debug-mode underflow) and matches `k*(k-1)/2` for `k >= 1`.
#[inline]
fn c2(k: u64) -> u64 {
    k * k.saturating_sub(1) / 2
}

/// Score a clustering against the ledger's ground truth. `window_secs` selects the window
/// used for `window_purity` (0 = identical-ts); it does not affect the clustering itself.
pub fn evaluate(ledger: &Ledger, clustering: &Clustering, window_secs: i64) -> Report {
    let owner = ledger.ownership();
    let accounts: Vec<AccountId> = owner.keys().copied().collect();

    // Pairwise confusion over owned accounts via a (operator, predicted-cluster) contingency
    // table: same-operator-and-same-cluster pairs are true positives, and the marginals give
    // the predicted-positive and same-operator totals.
    let mut cell: HashMap<(AgentId, Option<usize>), u64> = HashMap::new();
    let mut per_op: HashMap<AgentId, u64> = HashMap::new();
    let mut per_cluster: HashMap<Option<usize>, u64> = HashMap::new();
    for (&acc, &op) in &owner {
        let c = clustering.cluster_of.get(&acc).copied();
        *cell.entry((op, c)).or_insert(0) += 1;
        *per_op.entry(op).or_insert(0) += 1;
        *per_cluster.entry(c).or_insert(0) += 1;
    }
    let tp: u64 = cell.values().map(|&k| c2(k)).sum();
    let pred_pos: u64 = per_cluster.values().map(|&k| c2(k)).sum();
    let same_op_pairs: u64 = per_op.values().map(|&k| c2(k)).sum();
    let fp = pred_pos - tp;
    let fn_ = same_op_pairs - tp;
    let linked_same_op = tp;

    let precision = if tp + fp > 0 {
        tp as f64 / (tp + fp) as f64
    } else {
        0.0
    };
    let recall = if tp + fn_ > 0 {
        tp as f64 / (tp + fn_) as f64
    } else {
        0.0
    };
    let attribution_f1 = if precision + recall > 0.0 {
        2.0 * precision * recall / (precision + recall)
    } else {
        0.0
    };
    let linkage_recall = if same_op_pairs > 0 {
        linked_same_op as f64 / same_op_pairs as f64
    } else {
        0.0
    };

    // Fragmentation: distinct clusters each operator's owned accounts land in.
    let mut ops: HashMap<AgentId, HashSet<usize>> = HashMap::new();
    for (&acc, &op) in &owner {
        if let Some(&c) = clustering.cluster_of.get(&acc) {
            ops.entry(op).or_default().insert(c);
        }
    }
    let fragmentation = if ops.is_empty() {
        1.0
    } else {
        ops.values().map(|s| s.len() as f64).sum::<f64>() / ops.len() as f64
    };

    // Largest-cluster share over OWNED accounts — the trivial-collapse alarm.
    let mut owned_per_cluster: HashMap<usize, usize> = HashMap::new();
    for &acc in owner.keys() {
        if let Some(&c) = clustering.cluster_of.get(&acc) {
            *owned_per_cluster.entry(c).or_insert(0) += 1;
        }
    }
    let largest_cluster_frac = if accounts.is_empty() {
        0.0
    } else {
        owned_per_cluster.values().copied().max().unwrap_or(0) as f64 / accounts.len() as f64
    };

    // Burst purity: reuse `burst_groups` (ts/slot only) and read `operator` — allowed here
    // in the scoring layer, never in a heuristic.
    let (mut pure_pairs, mut total_pairs) = (0u64, 0u64);
    for burst in crate::heuristics::burst_groups(&ledger.records) {
        let mut seen: HashSet<AccountId> = HashSet::new();
        let mut cnt: HashMap<AgentId, u64> = HashMap::new();
        let mut m: u64 = 0;
        for &ix in &burst {
            let r = &ledger.records[ix];
            if let Some(op) = r.operator {
                if seen.insert(r.source) {
                    *cnt.entry(op).or_insert(0) += 1;
                    m += 1;
                }
            }
        }
        total_pairs += c2(m);
        pure_pairs += cnt.values().map(|&c| c2(c)).sum::<u64>();
    }
    let burst_purity = if total_pairs > 0 {
        pure_pairs as f64 / total_pairs as f64
    } else {
        1.0
    };

    // Window purity — the same measure over Δt windows.
    let (mut pure_w, mut total_w) = (0u64, 0u64);
    for group in crate::heuristics::window_groups(&ledger.records, window_secs) {
        let mut seen: HashSet<AccountId> = HashSet::new();
        let mut cnt: HashMap<AgentId, u64> = HashMap::new();
        let mut m: u64 = 0;
        for &ix in &group {
            let r = &ledger.records[ix];
            if let Some(op) = r.operator {
                if seen.insert(r.source) {
                    *cnt.entry(op).or_insert(0) += 1;
                    m += 1;
                }
            }
        }
        total_w += c2(m);
        pure_w += cnt.values().map(|&c| c2(c)).sum::<u64>();
    }
    let window_purity = if total_w > 0 {
        pure_w as f64 / total_w as f64
    } else {
        1.0
    };

    // Funding-graph honesty numbers (ground-truth reads are legal in the metric layer). A
    // funding tx has fee_payer == source (the funder signs its own top-up); real actions have a
    // throwaway fee_payer != source. The anonymity set = distinct operators per funder.
    let funding_records = ledger
        .records
        .iter()
        .filter(|r| r.fee_payer == r.source && r.source != r.dest)
        .count();
    let mut fp_op: HashMap<AccountId, AgentId> = HashMap::new();
    for r in &ledger.records {
        if r.fee_payer != r.source {
            if let Some(op) = r.operator {
                fp_op.insert(r.fee_payer, op);
            }
        }
    }
    let mut anon_sizes: Vec<usize> = Vec::new();
    for fps in crate::heuristics::funding_edges(&ledger.records).values() {
        if fps.len() < 2 {
            continue;
        }
        let ops: HashSet<AgentId> = fps.iter().filter_map(|fp| fp_op.get(fp).copied()).collect();
        if !ops.is_empty() {
            anon_sizes.push(ops.len());
        }
    }
    let funder_anonymity_set = if anon_sizes.is_empty() {
        1.0
    } else {
        anon_sizes.iter().sum::<usize>() as f64 / anon_sizes.len() as f64
    };

    Report {
        num_accounts: ledger.accounts().len(),
        owned_accounts: accounts.len(),
        num_clusters: clustering.sizes.len(),
        attribution_f1,
        linkage_recall,
        fragmentation,
        attribution_precision: precision,
        burst_purity,
        largest_cluster_frac,
        window_purity,
        window_secs,
        funding_records,
        funder_anonymity_set,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::TxRecord;
    use noise_core::types::ActionKind;

    fn acc(n: u8) -> AccountId {
        AccountId([n; 32])
    }

    fn owned(sig: u64, slot: u64, ts: i64, source: AccountId, op: AgentId) -> TxRecord {
        TxRecord {
            sig,
            slot,
            ts,
            fee_payer: acc(200),
            source,
            dest: acc(240),
            amount: 1,
            kind: ActionKind::Transfer,
            operator: Some(op),
        }
    }

    /// Cluster A,B under op 0 and C under op 1, but the adversary lumps all three together.
    #[test]
    fn precision_exposed_and_correct() {
        let (a, b, c) = (acc(1), acc(2), acc(3));
        let ledger = Ledger {
            records: vec![
                owned(1, 1, 100, a, 0),
                owned(2, 2, 100, b, 0),
                owned(3, 3, 100, c, 1),
            ],
        };
        let mut cluster_of = HashMap::new();
        for x in [a, b, c] {
            cluster_of.insert(x, 0usize); // all in one cluster => 1 tp (A,B), 2 fp (A,C),(B,C)
        }
        let cl = Clustering {
            cluster_of,
            sizes: vec![3],
        };
        let r = evaluate(&ledger, &cl, 0);
        assert!((r.attribution_precision - 1.0 / 3.0).abs() < 1e-9);
        assert!(
            (r.largest_cluster_frac - 1.0).abs() < 1e-9,
            "collapse alarm should be 1.0"
        );
    }

    #[test]
    fn largest_cluster_frac_small_when_fragmented() {
        let (a, b, c) = (acc(1), acc(2), acc(3));
        let ledger = Ledger {
            records: vec![
                owned(1, 1, 100, a, 0),
                owned(2, 2, 200, b, 0),
                owned(3, 3, 300, c, 1),
            ],
        };
        let mut cluster_of = HashMap::new();
        cluster_of.insert(a, 0usize);
        cluster_of.insert(b, 1usize);
        cluster_of.insert(c, 2usize);
        let cl = Clustering {
            cluster_of,
            sizes: vec![1, 1, 1],
        };
        let r = evaluate(&ledger, &cl, 0);
        assert!((r.largest_cluster_frac - 1.0 / 3.0).abs() < 1e-9);
    }

    #[test]
    fn burst_purity_pure_and_contaminated() {
        // Pure: one burst, both sources same operator.
        let (a, b) = (acc(1), acc(2));
        let pure = Ledger {
            records: vec![owned(1, 1, 100, a, 0), owned(2, 2, 100, b, 0)],
        };
        let empty = Clustering {
            cluster_of: HashMap::new(),
            sizes: vec![],
        };
        assert!((evaluate(&pure, &empty, 0).burst_purity - 1.0).abs() < 1e-9);

        // Contaminated: one burst spans two operators (a same-second collision).
        let contaminated = Ledger {
            records: vec![owned(1, 1, 100, a, 0), owned(2, 2, 100, b, 1)],
        };
        assert!(evaluate(&contaminated, &empty, 0).burst_purity < 1.0);
    }

    #[test]
    fn funder_anonymity_set_hub_vs_shared() {
        // One funder serving two operators through two fee-payers => anonymity set 2.0.
        let (u, fp1, fp2, s1, s2, d) = (acc(100), acc(1), acc(2), acc(11), acc(12), acc(50));
        let recs = vec![
            // funding txs: fee_payer == source == funder
            TxRecord {
                sig: 1,
                slot: 1,
                ts: 10,
                fee_payer: u,
                source: u,
                dest: fp1,
                amount: 5,
                kind: ActionKind::Transfer,
                operator: None,
            },
            TxRecord {
                sig: 2,
                slot: 2,
                ts: 11,
                fee_payer: u,
                source: u,
                dest: fp2,
                amount: 5,
                kind: ActionKind::Transfer,
                operator: None,
            },
            // actions: fp1 pays for operator 0's s1; fp2 pays for operator 1's s2
            TxRecord {
                sig: 3,
                slot: 3,
                ts: 20,
                fee_payer: fp1,
                source: s1,
                dest: d,
                amount: 1,
                kind: ActionKind::Transfer,
                operator: Some(0),
            },
            TxRecord {
                sig: 4,
                slot: 4,
                ts: 21,
                fee_payer: fp2,
                source: s2,
                dest: d,
                amount: 1,
                kind: ActionKind::Transfer,
                operator: Some(1),
            },
        ];
        let empty = Clustering {
            cluster_of: HashMap::new(),
            sizes: vec![],
        };
        let r = evaluate(&Ledger { records: recs }, &empty, 120);
        assert_eq!(r.funding_records, 2, "two funding txs inferred");
        assert!(
            (r.funder_anonymity_set - 2.0).abs() < 1e-9,
            "one funder hides two operators => anon set 2.0, got {}",
            r.funder_anonymity_set
        );
    }

    #[test]
    fn funder_fields_neutral_without_funding() {
        let (a, b) = (acc(1), acc(2));
        let ledger = Ledger {
            records: vec![owned(1, 1, 100, a, 0), owned(2, 2, 200, b, 0)],
        };
        let empty = Clustering {
            cluster_of: HashMap::new(),
            sizes: vec![],
        };
        let r = evaluate(&ledger, &empty, 0);
        assert_eq!(r.funding_records, 0);
        assert!((r.funder_anonymity_set - 1.0).abs() < 1e-9);
    }

    #[test]
    fn window_purity_reflects_grouping() {
        // Two operators act at ts 100 and 160 — DIFFERENT seconds, so exact-ts bursts are
        // pure singletons (burst_purity == 1.0), but a 120s window merges them.
        let (a, b) = (acc(1), acc(2));
        let ledger = Ledger {
            records: vec![owned(1, 1, 100, a, 0), owned(2, 2, 160, b, 1)],
        };
        let empty = Clustering {
            cluster_of: HashMap::new(),
            sizes: vec![],
        };
        let r0 = evaluate(&ledger, &empty, 0);
        assert!(
            (r0.burst_purity - 1.0).abs() < 1e-9,
            "exact-ts bursts are singletons"
        );
        assert!(
            (r0.window_purity - 1.0).abs() < 1e-9,
            "window 0 == identical-ts, still pure"
        );
        let r120 = evaluate(&ledger, &empty, 120);
        assert!(
            r120.window_purity < 1.0,
            "120s window merges the two operators"
        );
        assert_eq!(r120.window_secs, 120);
    }
}
