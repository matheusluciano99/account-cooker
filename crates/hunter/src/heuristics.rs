//! Adversary heuristics: the same tricks real chain-analysis firms use to cluster
//! wallets. Given only the PUBLIC fields of the ledger, produce predicted clusters
//! (a guess at "which accounts are the same entity").
//!
//! These are deliberately strong against naive behavior and are the yardstick the
//! cooker must beat. Everything here is honest heuristic — no ground-truth peeking.

use crate::model::{Ledger, TxRecord};
use noise_core::types::{AccountId, ActionKind};
use std::collections::{BTreeSet, HashMap};

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

    // ---- O Cacador v2: burst heuristics ----
    // These attack the one leak fee-payer rotation cannot hide: Curupira stamps every
    // record of a single action with an identical `ts`, and every `source` in that
    // burst is one operator's subaccount. See `burst_groups`.
    /// H-COPAY: common-destination co-payment (ts+dest keyed, repetition-thresholded).
    pub use_burst_copay: bool,
    /// Distinct sources in one (ts,dest) bucket for it to count.
    pub copay_min_sources: usize,
    /// A source-pair must co-pay in >= this many distinct buckets before being unioned.
    pub copay_min_shared_buckets: u32,
    /// H-COACT: whole-burst co-activity (ts keyed, dest-agnostic, repetition-thresholded).
    pub use_burst_coactivity: bool,
    /// A source-pair must co-occur in >= this many distinct bursts before being unioned.
    pub coactivity_min_shared_bursts: u32,
    /// Drop any bucket/burst with more distinct sources than this (guards against giant
    /// same-`ts` collision bursts). Must exceed the largest honest subaccount count.
    pub burst_max_sources: usize,
    /// Exclude `kind == Dust` when building copay buckets (kind is a public field).
    pub exclude_dust_from_copay: bool,
    // ---- ablation-only (default off) ----
    /// H-BURST ceiling: union every source in a burst with NO repetition threshold.
    /// Precision-unsafe; present so the ablation table can show the cost of dropping it.
    pub use_burst_union_ceiling: bool,
    /// Optional subtractive guard: require every non-dust part in a copay bucket to be
    /// >= this floor, else drop the bucket. Can only remove edges, never over-merge.
    pub use_split_shape_guard: bool,
    pub split_min_part_floor: u64,
}

impl Default for AdversaryConfig {
    fn default() -> Self {
        AdversaryConfig {
            use_fee_payer: true,
            use_cospend: true,
            use_temporal_amount: true,
            temporal_window_secs: 120,
            amount_tolerance_bps: 50,

            // v2 linkers default ON; the ceiling and shape-guard are ablation-only.
            use_burst_copay: true,
            copay_min_sources: 2,
            copay_min_shared_buckets: 2,
            use_burst_coactivity: true,
            coactivity_min_shared_bursts: 3,
            burst_max_sources: 10, // > whale's 8 subaccounts: no honest burst is ever dropped
            exclude_dust_from_copay: true,
            use_burst_union_ceiling: false,
            use_split_shape_guard: false,
            split_min_part_floor: 1_000,
        }
    }
}

/// The adversary's predicted clustering.
pub struct Clustering {
    pub cluster_of: HashMap<AccountId, usize>,
    pub sizes: Vec<usize>,
}

/// Group records into bursts: maximal runs that share one `ts` AND are slot-contiguous.
/// Returns record-index groups (into `records`). Reads ONLY `ts`/`slot` — never `operator`.
///
/// Why both conditions: `slot` is a global monotonic +1 counter with no gaps between
/// actions, so slot-contiguity alone would silently chain unrelated operators. Anchoring
/// on identical `ts` is what delimits a single action; slot-contiguity is only an extra
/// guard. The lone residual is two agents scheduled on the same integer second — a
/// collision the downstream repetition thresholds and size cap are built to survive.
pub(crate) fn burst_groups(records: &[TxRecord]) -> Vec<Vec<usize>> {
    let mut order: Vec<usize> = (0..records.len()).collect();
    order.sort_by_key(|&i| records[i].slot); // defensive; records are already in slot order
    let mut groups = Vec::new();
    let mut i = 0;
    while i < order.len() {
        let start = i;
        let ts0 = records[order[i]].ts;
        let mut prev = records[order[i]].slot;
        i += 1;
        while i < order.len() && records[order[i]].ts == ts0 && records[order[i]].slot == prev + 1
        {
            prev = records[order[i]].slot;
            i += 1;
        }
        groups.push(order[start..i].to_vec());
    }
    groups
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

    // ===== O Cacador v2: burst heuristics =====
    // The leak these key on: Curupira calls `chain.set_time()` ONCE per action, so every
    // split part / decoy / rebalance of that action shares an IDENTICAL `ts` and a
    // contiguous `slot` run, and every `source` in the run is one operator's subaccount.
    // Fee-payer rotation and dest-shuffling are invisible to a `ts`-keyed view. The only
    // false-positive channel is two agents colliding on the same integer second; the
    // repetition thresholds and `burst_max_sources` cap neutralize it.

    // (4) H-COPAY: common-destination co-payment. Within each ts-burst, group distinct
    // sources by dest; a source-pair sharing such a (ts,dest) bucket in >= N distinct
    // bursts is one entity. The honest revival of co-spend — splitting itself creates the
    // "many owned sources -> one dest in one instant" pattern this reads.
    if cfg.use_burst_copay {
        let mut weight: HashMap<(AccountId, AccountId), u32> = HashMap::new();
        for burst in burst_groups(&ledger.records) {
            // (sources, has_subfloor_part) per dest within this ts-burst.
            let mut by_dest: HashMap<AccountId, (BTreeSet<AccountId>, bool)> = HashMap::new();
            for &ix in &burst {
                let r = &ledger.records[ix];
                if cfg.exclude_dust_from_copay && r.kind == ActionKind::Dust {
                    continue;
                }
                let e = by_dest.entry(r.dest).or_insert_with(|| (BTreeSet::new(), false));
                e.0.insert(r.source);
                if r.amount < cfg.split_min_part_floor {
                    e.1 = true;
                }
            }
            for (srcs, has_subfloor) in by_dest.values() {
                // Optional shape guard: a real weighted split has no sub-floor parts.
                if cfg.use_split_shape_guard && *has_subfloor {
                    continue;
                }
                if srcs.len() < cfg.copay_min_sources || srcs.len() > cfg.burst_max_sources {
                    continue;
                }
                let v: Vec<AccountId> = srcs.iter().copied().collect(); // BTreeSet => canonical order
                for x in 0..v.len() {
                    for y in (x + 1)..v.len() {
                        *weight.entry((v[x], v[y])).or_insert(0) += 1;
                    }
                }
            }
        }
        for (&(a, b), &w) in &weight {
            if w >= cfg.copay_min_shared_buckets {
                uf.union(a, b);
            }
        }
    }

    // (5) H-COACT: whole-burst co-activity, dest-agnostic. Source-pairs co-present in
    // >= M distinct ts-bursts are one entity. Catches what H-COPAY misses: a real part
    // and a decoy going to different dests in one burst, and decoy-only / rebalance-only
    // subaccounts. Higher threshold because dest-agnostic co-occurrence is a looser signal.
    if cfg.use_burst_coactivity {
        let mut weight: HashMap<(AccountId, AccountId), u32> = HashMap::new();
        for burst in burst_groups(&ledger.records) {
            let mut srcs: BTreeSet<AccountId> = BTreeSet::new();
            for &ix in &burst {
                srcs.insert(ledger.records[ix].source); // include Dust: co-activity is the signal
            }
            if srcs.len() < 2 || srcs.len() > cfg.burst_max_sources {
                continue;
            }
            let v: Vec<AccountId> = srcs.iter().copied().collect();
            for x in 0..v.len() {
                for y in (x + 1)..v.len() {
                    *weight.entry((v[x], v[y])).or_insert(0) += 1;
                }
            }
        }
        for (&(a, b), &w) in &weight {
            if w >= cfg.coactivity_min_shared_bursts {
                uf.union(a, b);
            }
        }
    }

    // (6) H-BURST ceiling (ablation only, default OFF): union every source in a burst with
    // no repetition threshold. Recall ceiling / precision floor — one collision permanently
    // fuses two operators. Present only so the ablation table can show that pushing F1
    // higher costs precision. Never enabled in `Default`.
    if cfg.use_burst_union_ceiling {
        for burst in burst_groups(&ledger.records) {
            let mut srcs: BTreeSet<AccountId> = BTreeSet::new();
            for &ix in &burst {
                srcs.insert(ledger.records[ix].source);
            }
            if srcs.len() < 2 || srcs.len() > cfg.burst_max_sources {
                continue;
            }
            let v: Vec<AccountId> = srcs.iter().copied().collect();
            for k in 1..v.len() {
                uf.union(v[0], v[k]);
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

    // ---- v2 burst-heuristic tests (pure, deterministic, no RNG) ----

    fn acc(n: u8) -> AccountId {
        AccountId([n; 32])
    }

    /// Build a record with a UNIQUE fee-payer per sig, so the fee-payer heuristic never
    /// accidentally cross-links sources in default-config tests. operator is left None:
    /// heuristics must never read it.
    fn rec(
        sig: u64,
        slot: u64,
        ts: i64,
        source: AccountId,
        dest: AccountId,
        amount: u64,
        kind: ActionKind,
    ) -> TxRecord {
        TxRecord {
            sig,
            slot,
            ts,
            fee_payer: acc(200u8.wrapping_add(sig as u8)),
            source,
            dest,
            amount,
            kind,
            operator: None,
        }
    }

    fn led(records: Vec<TxRecord>) -> Ledger {
        Ledger { records }
    }

    /// A config with all legacy heuristics off, so a test isolates one v2 signal.
    fn only(copay: bool, coact: bool, ceiling: bool) -> AdversaryConfig {
        AdversaryConfig {
            use_fee_payer: false,
            use_cospend: false,
            use_temporal_amount: false,
            use_burst_copay: copay,
            use_burst_coactivity: coact,
            use_burst_union_ceiling: ceiling,
            ..AdversaryConfig::default()
        }
    }

    fn same(cl: &Clustering, a: AccountId, b: AccountId) -> bool {
        cl.cluster_of[&a] == cl.cluster_of[&b]
    }

    use ActionKind::{Dust, Transfer};

    #[test]
    fn copay_unions_repeated_same_dest_burst() {
        let (s1, s2, d) = (acc(1), acc(2), acc(10));
        let recs = vec![
            rec(1, 1, 100, s1, d, 1_000_000, Transfer),
            rec(2, 2, 100, s2, d, 1_000_000, Transfer),
            rec(3, 3, 200, s1, d, 1_000_000, Transfer),
            rec(4, 4, 200, s2, d, 1_000_000, Transfer),
        ];
        let cl = cluster(&led(recs), &only(true, false, false));
        assert!(same(&cl, s1, s2), "two shared (ts,dest) buckets should union");
    }

    #[test]
    fn copay_below_threshold_no_union() {
        let (s1, s2, d) = (acc(1), acc(2), acc(10));
        let recs = vec![
            rec(1, 1, 100, s1, d, 1_000_000, Transfer),
            rec(2, 2, 100, s2, d, 1_000_000, Transfer),
        ];
        let cl = cluster(&led(recs), &only(true, false, false));
        assert!(!same(&cl, s1, s2), "one shared bucket is below threshold 2");
    }

    #[test]
    fn copay_temporal_binding_defeats_shared_dest() {
        // opA = {s1,s1b}, opB = {s2,s2b}, all touching the SAME external dest d but at
        // DIFFERENT times. The shared dest must NOT collapse the two operators.
        let (s1, s1b, s2, s2b, d) = (acc(1), acc(2), acc(3), acc(4), acc(10));
        let recs = vec![
            rec(1, 1, 100, s1, d, 1_000_000, Transfer),
            rec(2, 2, 100, s1b, d, 1_000_000, Transfer),
            rec(3, 3, 150, s1, d, 1_000_000, Transfer),
            rec(4, 4, 150, s1b, d, 1_000_000, Transfer),
            rec(5, 5, 500, s2, d, 1_000_000, Transfer),
            rec(6, 6, 500, s2b, d, 1_000_000, Transfer),
            rec(7, 7, 550, s2, d, 1_000_000, Transfer),
            rec(8, 8, 550, s2b, d, 1_000_000, Transfer),
        ];
        let cl = cluster(&led(recs), &only(true, false, false));
        assert!(same(&cl, s1, s1b), "same operator, same bursts");
        assert!(same(&cl, s2, s2b), "same operator, same bursts");
        assert!(
            !same(&cl, s1, s2),
            "global shared dest must NOT merge two operators (the 40-pool trap)"
        );
    }

    #[test]
    fn copay_size_cap_drops_bucket() {
        // 11 distinct sources into one dest in one burst, twice. Above burst_max_sources=10,
        // so the bucket emits no edges at all.
        let d = acc(50);
        let mut recs = Vec::new();
        let mut sig = 0u64;
        for &ts in &[100i64, 200] {
            for s in 1..=11u8 {
                sig += 1;
                recs.push(rec(sig, sig, ts, acc(s), d, 1_000_000, Transfer));
            }
        }
        let cl = cluster(&led(recs), &only(true, false, false));
        assert!(!same(&cl, acc(1), acc(2)), "oversized bucket must be dropped");
    }

    #[test]
    fn copay_excludes_dust() {
        let (s1, s2, s3, d) = (acc(1), acc(2), acc(3), acc(10));
        let recs = vec![
            rec(1, 1, 100, s1, d, 1_000_000, Transfer),
            rec(2, 2, 100, s2, d, 1_000_000, Transfer),
            rec(3, 3, 100, s3, d, 5_000, Dust),
            rec(4, 4, 200, s1, d, 1_000_000, Transfer),
            rec(5, 5, 200, s2, d, 1_000_000, Transfer),
            rec(6, 6, 200, s3, d, 5_000, Dust),
        ];
        let cl = cluster(&led(recs), &only(true, false, false));
        assert!(same(&cl, s1, s2), "real parts co-pay");
        assert!(!same(&cl, s1, s3), "dust source must be excluded from copay");
    }

    #[test]
    fn coact_unions_cross_dest_after_threshold() {
        // Cross-dest co-activity: s1->d1 and s2->d2 in the same burst, 3 times.
        let (s1, s2, d1, d2) = (acc(1), acc(2), acc(11), acc(12));
        let make = |bursts: usize| {
            let mut recs = Vec::new();
            let mut sig = 0u64;
            for b in 0..bursts {
                let ts = 100 + b as i64 * 100;
                sig += 1;
                recs.push(rec(sig, sig, ts, s1, d1, 1_000_000, Transfer));
                sig += 1;
                recs.push(rec(sig, sig, ts, s2, d2, 1_000_000, Transfer));
            }
            recs
        };
        let cl3 = cluster(&led(make(3)), &only(false, true, false));
        assert!(same(&cl3, s1, s2), "3 co-bursts should union (threshold 3)");
        let cl2 = cluster(&led(make(2)), &only(false, true, false));
        assert!(!same(&cl2, s1, s2), "2 co-bursts is below threshold 3");
    }

    #[test]
    fn coact_links_decoy_only_subaccount() {
        // s3 only ever emits Dust decoys, but co-occurs with real sources -> it leaks.
        let (s1, s2, s3, d1, d2, d3) = (acc(1), acc(2), acc(3), acc(11), acc(12), acc(13));
        let mut recs = Vec::new();
        let mut sig = 0u64;
        for b in 0..3 {
            let ts = 100 + b * 100;
            sig += 1;
            recs.push(rec(sig, sig, ts, s1, d1, 1_000_000, Transfer));
            sig += 1;
            recs.push(rec(sig, sig, ts, s2, d2, 1_000_000, Transfer));
            sig += 1;
            recs.push(rec(sig, sig, ts, s3, d3, 5_000, Dust));
        }
        let cl = cluster(&led(recs), &only(false, true, false));
        assert!(same(&cl, s1, s3), "a decoy-only subaccount still leaks via co-activity");
    }

    #[test]
    fn coact_single_collision_no_union() {
        // Two operators collide in ONE shared-ts burst. Below threshold 3 => no merge.
        let (s1, s2, d1, d2) = (acc(1), acc(2), acc(11), acc(12));
        let recs = vec![
            rec(1, 1, 100, s1, d1, 1_000_000, Transfer),
            rec(2, 2, 100, s2, d2, 1_000_000, Transfer),
        ];
        let cl = cluster(&led(recs), &only(false, true, false));
        assert!(!same(&cl, s1, s2), "a single collision must not fuse operators");
    }

    #[test]
    fn ceiling_off_by_default_no_single_burst_union() {
        // Default config: a lone 2-source burst does not union (thresholds unmet, unique
        // fee-payers, no consolidate, dest is not a source).
        let (s1, s2, d) = (acc(1), acc(2), acc(10));
        let recs = vec![
            rec(1, 1, 100, s1, d, 1_000_000, Transfer),
            rec(2, 2, 100, s2, d, 1_000_000, Transfer),
        ];
        let cl = cluster(&led(recs), &AdversaryConfig::default());
        assert!(!same(&cl, s1, s2), "default must not single-burst-union");
    }

    #[test]
    fn ceiling_on_unions_single_burst() {
        let (s1, s2, d) = (acc(1), acc(2), acc(10));
        let recs = vec![
            rec(1, 1, 100, s1, d, 1_000_000, Transfer),
            rec(2, 2, 100, s2, d, 1_000_000, Transfer),
        ];
        let cl = cluster(&led(recs), &only(false, false, true));
        assert!(same(&cl, s1, s2), "ceiling unions a single burst (precision cost)");
    }

    #[test]
    fn burst_groups_splits_on_ts_change() {
        let z = acc(0);
        let recs = vec![
            rec(1, 1, 100, z, z, 0, Transfer),
            rec(2, 2, 100, z, z, 0, Transfer),
            rec(3, 3, 200, z, z, 0, Transfer),
            rec(4, 4, 200, z, z, 0, Transfer),
        ];
        let g = burst_groups(&recs);
        assert_eq!(g, vec![vec![0, 1], vec![2, 3]]);
    }

    #[test]
    fn burst_groups_same_ts_collision_stays_one() {
        let z = acc(0);
        let recs = vec![
            rec(1, 1, 100, z, z, 0, Transfer),
            rec(2, 2, 100, z, z, 0, Transfer),
            rec(3, 3, 100, z, z, 0, Transfer),
        ];
        let g = burst_groups(&recs);
        assert_eq!(g.len(), 1, "same-ts collision stays one burst (the known residual)");
        assert_eq!(g[0].len(), 3);
    }

    #[test]
    fn burst_groups_breaks_on_slot_gap() {
        let z = acc(0);
        let recs = vec![
            rec(1, 1, 100, z, z, 0, Transfer),
            rec(2, 5, 100, z, z, 0, Transfer),
        ];
        let g = burst_groups(&recs);
        assert_eq!(g.len(), 2, "a slot gap breaks the run even at equal ts");
    }
}
