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
}

/// Score a clustering against the ledger's ground truth. `window_secs` selects the window
/// used for `window_purity` (0 = identical-ts); it does not affect the clustering itself.
pub fn evaluate(ledger: &Ledger, clustering: &Clustering, window_secs: i64) -> Report {
    let owner = ledger.ownership();
    let accounts: Vec<AccountId> = owner.keys().copied().collect();

    // Pairwise confusion over operator-owned accounts.
    let (mut tp, mut fp, mut fn_) = (0u64, 0u64, 0u64);
    let (mut same_op_pairs, mut linked_same_op) = (0u64, 0u64);
    for i in 0..accounts.len() {
        for j in (i + 1)..accounts.len() {
            let a = accounts[i];
            let b = accounts[j];
            let truth_same = owner[&a] == owner[&b];
            let pred_same = clustering.cluster_of.get(&a) == clustering.cluster_of.get(&b);
            if truth_same {
                same_op_pairs += 1;
                if pred_same {
                    linked_same_op += 1;
                }
            }
            match (truth_same, pred_same) {
                (true, true) => tp += 1,
                (false, true) => fp += 1,
                (true, false) => fn_ += 1,
                (false, false) => {}
            }
        }
    }

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
        let mut seen = HashSet::new();
        let mut op_of_source: Vec<AgentId> = Vec::new();
        for &ix in &burst {
            let r = &ledger.records[ix];
            if let Some(op) = r.operator {
                if seen.insert(r.source) {
                    op_of_source.push(op);
                }
            }
        }
        for i in 0..op_of_source.len() {
            for j in (i + 1)..op_of_source.len() {
                total_pairs += 1;
                if op_of_source[i] == op_of_source[j] {
                    pure_pairs += 1;
                }
            }
        }
    }
    let burst_purity = if total_pairs > 0 {
        pure_pairs as f64 / total_pairs as f64
    } else {
        1.0
    };

    // Window purity — the same measure over Δt windows.
    let (mut pure_w, mut total_w) = (0u64, 0u64);
    for group in crate::heuristics::window_groups(&ledger.records, window_secs) {
        let mut seen = HashSet::new();
        let mut ops: Vec<AgentId> = Vec::new();
        for &ix in &group {
            let r = &ledger.records[ix];
            if let Some(op) = r.operator {
                if seen.insert(r.source) {
                    ops.push(op);
                }
            }
        }
        for i in 0..ops.len() {
            for j in (i + 1)..ops.len() {
                total_w += 1;
                if ops[i] == ops[j] {
                    pure_w += 1;
                }
            }
        }
    }
    let window_purity = if total_w > 0 {
        pure_w as f64 / total_w as f64
    } else {
        1.0
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
        assert!((r.largest_cluster_frac - 1.0).abs() < 1e-9, "collapse alarm should be 1.0");
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
        assert!((r0.burst_purity - 1.0).abs() < 1e-9, "exact-ts bursts are singletons");
        assert!((r0.window_purity - 1.0).abs() < 1e-9, "window 0 == identical-ts, still pure");
        let r120 = evaluate(&ledger, &empty, 120);
        assert!(r120.window_purity < 1.0, "120s window merges the two operators");
        assert_eq!(r120.window_secs, 120);
    }
}
