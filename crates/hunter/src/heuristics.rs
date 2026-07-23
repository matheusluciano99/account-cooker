//! Adversary heuristics: the same tricks real chain-analysis firms use to cluster
//! wallets. Given only the PUBLIC fields of the ledger, produce predicted clusters
//! (a guess at "which accounts are the same entity").
//!
//! These are deliberately strong against naive behavior and are the yardstick the
//! cooker must beat. Everything here is honest heuristic — no ground-truth peeking.

use crate::model::{Ledger, TxRecord};
use noise_core::types::{AccountId, ActionKind};
use std::collections::HashMap;

/// Union-find over account ids (path halving + union by rank).
pub struct UnionFind {
    parent: HashMap<AccountId, AccountId>,
    rank: HashMap<AccountId, u32>,
}

impl UnionFind {
    pub fn new<'a>(accounts: impl Iterator<Item = &'a AccountId>) -> Self {
        let mut parent = HashMap::new();
        let mut rank = HashMap::new();
        for &a in accounts {
            parent.insert(a, a);
            rank.insert(a, 0);
        }
        UnionFind { parent, rank }
    }

    fn ensure(&mut self, a: AccountId) {
        self.parent.entry(a).or_insert(a);
        self.rank.entry(a).or_insert(0);
    }

    pub fn find(&mut self, a: AccountId) -> AccountId {
        self.ensure(a);
        let mut x = a;
        while self.parent[&x] != x {
            let gp = self.parent[&self.parent[&x]];
            self.parent.insert(x, gp); // path halving
            x = gp;
        }
        x
    }

    pub fn union(&mut self, a: AccountId, b: AccountId) {
        let ra = self.find(a);
        let rb = self.find(b);
        if ra == rb {
            return;
        }
        let (ra_rank, rb_rank) = (self.rank[&ra], self.rank[&rb]);
        let (big, small) = if ra_rank >= rb_rank {
            (ra, rb)
        } else {
            (rb, ra)
        };
        self.parent.insert(small, big);
        if ra_rank == rb_rank {
            *self.rank.get_mut(&big).unwrap() += 1;
        }
    }
}

#[derive(Clone, Debug)]
pub struct AdversaryConfig {
    /// Accounts that share a fee-payer are the same entity.
    pub use_fee_payer: bool,
    /// Consolidation into a common destination reveals common ownership of the inputs.
    pub use_cospend: bool,
    /// A value leaving A and (almost) the same value arriving at B shortly after links A->B.
    pub use_temporal_amount: bool,
    pub temporal_window_secs: i64,
    pub amount_tolerance_bps: u32,
}

impl Default for AdversaryConfig {
    fn default() -> Self {
        AdversaryConfig {
            use_fee_payer: true,
            use_cospend: true,
            use_temporal_amount: true,
            temporal_window_secs: 120,
            amount_tolerance_bps: 50,
        }
    }
}

/// The adversary's predicted clustering.
pub struct Clustering {
    pub cluster_of: HashMap<AccountId, usize>,
    pub sizes: Vec<usize>,
}

pub fn cluster(ledger: &Ledger, cfg: &AdversaryConfig) -> Clustering {
    let accounts = ledger.accounts();
    let mut uf = UnionFind::new(accounts.iter());

    // (1) Fee-payer linkage. The signer pays the fee, so fee_payer and source of the
    // same tx are the same entity; and every account that shares a fee_payer collapses
    // together. Devastating against a static per-entity fee-payer.
    if cfg.use_fee_payer {
        let mut rep_by_fee: HashMap<AccountId, AccountId> = HashMap::new();
        for r in &ledger.records {
            uf.union(r.fee_payer, r.source);
            match rep_by_fee.get(&r.fee_payer) {
                Some(&rep) => uf.union(rep, r.source),
                None => {
                    rep_by_fee.insert(r.fee_payer, r.source);
                }
            }
        }
    }

    // (2) Co-spend / consolidation. Inputs funneled into a common destination are
    // common-input-ownership evidence.
    if cfg.use_cospend {
        let mut rep_by_dest: HashMap<AccountId, AccountId> = HashMap::new();
        for r in &ledger.records {
            if r.kind == ActionKind::Consolidate {
                uf.union(r.source, r.dest);
                match rep_by_dest.get(&r.dest) {
                    Some(&rep) => uf.union(rep, r.source),
                    None => {
                        rep_by_dest.insert(r.dest, r.source);
                    }
                }
            }
        }
    }

    // (3) Temporal + amount correlation (peel-chain). Value leaves A, near-equal value
    // reaches B within the window, and A's destination is B => link A and B.
    if cfg.use_temporal_amount {
        let txs: Vec<&TxRecord> = ledger
            .records
            .iter()
            .filter(|r| matches!(r.kind, ActionKind::Transfer | ActionKind::Swap))
            .collect();
        for a in &txs {
            for b in &txs {
                if a.sig == b.sig {
                    continue;
                }
                let dt = b.ts - a.ts;
                if dt < 0 || dt > cfg.temporal_window_secs {
                    continue;
                }
                if a.dest != b.source {
                    continue;
                }
                let tol = (a.amount as u128 * cfg.amount_tolerance_bps as u128 / 10_000) as u64;
                if a.amount.abs_diff(b.amount) <= tol {
                    uf.union(a.source, b.dest);
                }
            }
        }
    }

    // Materialize clusters.
    let mut cluster_of: HashMap<AccountId, usize> = HashMap::new();
    let mut root_to_idx: HashMap<AccountId, usize> = HashMap::new();
    let mut sizes: Vec<usize> = Vec::new();
    for &a in &accounts {
        let root = uf.find(a);
        let idx = *root_to_idx.entry(root).or_insert_with(|| {
            sizes.push(0);
            sizes.len() - 1
        });
        cluster_of.insert(a, idx);
        sizes[idx] += 1;
    }

    Clustering { cluster_of, sizes }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn union_find_basic() {
        let a = AccountId([1u8; 32]);
        let b = AccountId([2u8; 32]);
        let c = AccountId([3u8; 32]);
        let ids = [a, b, c];
        let mut uf = UnionFind::new(ids.iter());
        uf.union(a, b);
        assert_eq!(uf.find(a), uf.find(b));
        assert_ne!(uf.find(a), uf.find(c));
    }
}
