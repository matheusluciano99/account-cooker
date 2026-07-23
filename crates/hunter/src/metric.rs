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
}

/// Score a clustering against the ledger's ground truth.
pub fn evaluate(ledger: &Ledger, clustering: &Clustering) -> Report {
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

    Report {
        num_accounts: ledger.accounts().len(),
        owned_accounts: accounts.len(),
        num_clusters: clustering.sizes.len(),
        attribution_f1,
        linkage_recall,
        fragmentation,
    }
}
