//! Adversary heuristics: the same tricks real chain-analysis firms use to cluster
//! wallets. Given only the PUBLIC fields of the ledger, produce predicted clusters
//! (a guess at "which accounts are the same entity").
//!
//! These are deliberately strong against naive behavior and are the yardstick the
//! cooker must beat. Everything here is honest heuristic — no ground-truth peeking.

use crate::model::{Ledger, TxRecord};
use noise_core::types::AccountId;
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
    /// H-ACTIVATE: a transfer into a previously unseen account that soon becomes an active
    /// source is evidence of key/account rotation.
    pub use_activation_lineage: bool,
    pub activation_window_secs: i64,

    /// H-COPAY: sources paying a common destination in the same group are the same entity.
    pub use_burst_copay: bool,
    /// Distinct sources in one (group, dest) bucket for it to count.
    pub copay_min_sources: usize,
    /// A source-pair must co-pay in >= this many distinct buckets before being unioned.
    pub copay_min_shared_buckets: u32,
    /// H-COACT: sources co-active in the same group (dest-agnostic) are the same entity.
    pub use_burst_coactivity: bool,
    /// A source-pair must co-occur in >= this many distinct groups before being unioned.
    pub coactivity_min_shared_bursts: u32,
    /// Drop any group with more distinct sources than this. Must exceed the largest honest
    /// subaccount count (whale = 8) so no genuine group is ever dropped.
    pub burst_max_sources: usize,
    /// Ignore co-payments below this observable amount (0 = no filter). Keyed on value, the
    /// only thing on-chain — there is no semantic `Dust` label to read.
    pub copay_min_amount: u64,
    /// Ablation only: union every source in a group with no repetition threshold.
    pub use_burst_union_ceiling: bool,
    /// Optional subtractive guard: drop a copay bucket that has any non-dust part below
    /// `split_min_part_floor`. Can only remove edges, never add them.
    pub use_split_shape_guard: bool,
    pub split_min_part_floor: u64,

    /// Group records by a Δt time window instead of identical-ts bursts.
    pub use_windowed: bool,
    /// Window width in seconds when `use_windowed` (0 = identical-ts, a superset of bursts).
    pub window_secs: i64,

    /// H-FUNDER: walk the common-funder graph — accounts whose throwaway fee-payers were funded
    /// by one wallet are one entity. Default OFF so every legacy config is byte-unchanged.
    pub use_funder_graph: bool,
    /// A funder must have funded at least this many distinct fee-payers to count as a pattern.
    pub funder_min_fundees: usize,
    /// Optional ceiling for downstream sources. The default is intentionally high: a large
    /// rotating fleet must not be mistaken for a shared service merely because it is large.
    /// Analysts may lower this only as an explicit shared-service ablation.
    pub funder_max_sources: usize,
}

impl Default for AdversaryConfig {
    fn default() -> Self {
        AdversaryConfig {
            use_fee_payer: true,
            use_cospend: true,
            use_temporal_amount: true,
            temporal_window_secs: 120,
            amount_tolerance_bps: 50,
            use_activation_lineage: true,
            activation_window_secs: 2 * 86_400,

            use_burst_copay: true,
            copay_min_sources: 2,
            copay_min_shared_buckets: 2,
            use_burst_coactivity: true,
            coactivity_min_shared_bursts: 3,
            burst_max_sources: 10,
            copay_min_amount: 0,
            use_burst_union_ceiling: false,
            use_split_shape_guard: false,
            split_min_part_floor: 1_000,
            use_windowed: false,
            window_secs: 120,
            use_funder_graph: false,
            funder_min_fundees: 3,
            funder_max_sources: 100_000,
        }
    }
}

impl AdversaryConfig {
    /// Adds destination-local Δt episodes to the exact-timestamp signals. Co-activity stays
    /// restricted to exact timestamps; applying it to broad windows would merge unrelated
    /// operators. The higher co-payment repetition bar bounds shared-destination collisions.
    pub fn windowed(window_secs: i64) -> Self {
        AdversaryConfig {
            use_windowed: true,
            window_secs,
            copay_min_shared_buckets: 3,
            ..AdversaryConfig::default()
        }
    }

    /// Identical-ts grouping with copay + co-activity. Alias for the default config.
    pub fn exact_ts() -> Self {
        AdversaryConfig::default()
    }

    /// The windowed adversary plus the common-funder graph — used to score funded ledgers.
    pub fn funder_aware(window_secs: i64) -> Self {
        AdversaryConfig {
            use_funder_graph: true,
            ..AdversaryConfig::windowed(window_secs)
        }
    }
}

/// The adversary's predicted clustering.
pub struct Clustering {
    pub cluster_of: HashMap<AccountId, usize>,
    pub sizes: Vec<usize>,
}

/// Group records into bursts: maximal runs that share one `ts` AND are slot-contiguous.
/// Returns record-index groups (into `records`). Reads only `ts`/`slot`, never `operator`.
///
/// Both conditions are required: `slot` is a global +1 counter with no gaps, so contiguity
/// alone would chain unrelated records; the identical-`ts` anchor is what delimits a group.
pub(crate) fn burst_groups(records: &[TxRecord]) -> Vec<Vec<usize>> {
    let mut order: Vec<usize> = (0..records.len()).collect();
    order.sort_by_key(|&i| records[i].slot); // records are already in slot order; sort defensively
    let mut groups = Vec::new();
    let mut i = 0;
    while i < order.len() {
        let start = i;
        let ts0 = records[order[i]].ts;
        let mut prev = records[order[i]].slot;
        i += 1;
        while i < order.len() && records[order[i]].ts == ts0 && records[order[i]].slot == prev + 1 {
            prev = records[order[i]].slot;
            i += 1;
        }
        groups.push(order[start..i].to_vec());
    }
    groups
}

/// Time-proximity components. Sort by (ts, slot, sig) and keep adjacent records in the
/// same component while their gap is at most `window_secs`. Reads only ts/slot/sig, never
/// `operator`.
///
/// `window_secs == 0` groups records with identical `ts` (a superset of `burst_groups`);
/// widening the window can only merge components, never split them.
pub(crate) fn window_groups(records: &[TxRecord], window_secs: i64) -> Vec<Vec<usize>> {
    let mut order: Vec<usize> = (0..records.len()).collect();
    order.sort_by_key(|&i| (records[i].ts, records[i].slot, records[i].sig));
    let window_secs = window_secs.max(0);
    let mut groups = Vec::new();
    let mut i = 0;
    while i < order.len() {
        let mut g = vec![order[i]];
        let mut previous_ts = records[order[i]].ts;
        i += 1;
        while i < order.len() && records[order[i]].ts.saturating_sub(previous_ts) <= window_secs {
            previous_ts = records[order[i]].ts;
            g.push(order[i]);
            i += 1;
        }
        groups.push(g);
    }
    groups
}

/// H-COPAY edge weights: within each group, bucket distinct sources by `dest`; count each
/// qualifying (group, dest) bucket once per source-pair. Group-agnostic: `groups` may be
/// exact-ts bursts or Δt windows.
fn copay_edges(
    groups: &[Vec<usize>],
    records: &[TxRecord],
    cfg: &AdversaryConfig,
) -> HashMap<(AccountId, AccountId), u32> {
    let mut weight: HashMap<(AccountId, AccountId), u32> = HashMap::new();
    for group in groups {
        let mut by_dest: HashMap<AccountId, (BTreeSet<AccountId>, bool)> = HashMap::new();
        for &ix in group {
            let r = &records[ix];
            if r.amount < cfg.copay_min_amount {
                continue;
            }
            let e = by_dest
                .entry(r.dest)
                .or_insert_with(|| (BTreeSet::new(), false));
            e.0.insert(r.source);
            if r.amount < cfg.split_min_part_floor {
                e.1 = true;
            }
        }
        for (srcs, has_subfloor) in by_dest.values() {
            if cfg.use_split_shape_guard && *has_subfloor {
                continue;
            }
            if srcs.len() < cfg.copay_min_sources || srcs.len() > cfg.burst_max_sources {
                continue;
            }
            let v: Vec<AccountId> = srcs.iter().copied().collect();
            for x in 0..v.len() {
                for y in (x + 1)..v.len() {
                    *weight.entry((v[x], v[y])).or_insert(0) += 1;
                }
            }
        }
    }
    weight
}

/// Destination-local co-payment episodes for the windowed adversary. Global fixed buckets
/// have arbitrary boundaries: an unrelated transaction can split two payments that are only
/// seconds apart. A real analyst indexes each destination independently and starts a new
/// episode only after a gap larger than the configured window.
fn windowed_copay_edges(
    records: &[TxRecord],
    cfg: &AdversaryConfig,
) -> HashMap<(AccountId, AccountId), u32> {
    let active_sources: std::collections::HashSet<AccountId> =
        records.iter().map(|r| r.source).collect();
    let mut by_dest: HashMap<AccountId, Vec<usize>> = HashMap::new();
    for (ix, r) in records.iter().enumerate() {
        // A shared protocol, exchange, or merchant can receive from many unrelated users.
        // Restrict the windowed consolidation signal to destinations that later transact,
        // which is observable evidence that the destination may be an internal hub.
        if r.amount >= cfg.copay_min_amount && active_sources.contains(&r.dest) {
            by_dest.entry(r.dest).or_default().push(ix);
        }
    }

    let mut weight: HashMap<(AccountId, AccountId), u32> = HashMap::new();
    let window = cfg.window_secs.max(0);
    for indices in by_dest.values_mut() {
        indices.sort_by_key(|&ix| (records[ix].ts, records[ix].slot, records[ix].sig));
        let mut start = 0;
        while start < indices.len() {
            let mut end = start + 1;
            while end < indices.len()
                && records[indices[end]]
                    .ts
                    .saturating_sub(records[indices[end - 1]].ts)
                    <= window
            {
                end += 1;
            }

            let mut srcs: BTreeSet<AccountId> = BTreeSet::new();
            let mut has_subfloor = false;
            for &ix in &indices[start..end] {
                let r = &records[ix];
                srcs.insert(r.source);
                has_subfloor |= r.amount < cfg.split_min_part_floor;
            }
            if !(cfg.use_split_shape_guard && has_subfloor)
                && srcs.len() >= cfg.copay_min_sources
                && srcs.len() <= cfg.burst_max_sources
            {
                let sources: Vec<AccountId> = srcs.into_iter().collect();
                for x in 0..sources.len() {
                    for y in (x + 1)..sources.len() {
                        *weight.entry((sources[x], sources[y])).or_insert(0) += 1;
                    }
                }
            }
            start = end;
        }
    }
    weight
}

/// H-COACT edge weights: within each group, take the whole set of distinct sources
/// from sponsored transactions and count each group once per source-pair. Self-paid
/// transactions are excluded: unrelated funders submitting in the same second are not
/// evidence of common control.
fn coact_edges(
    groups: &[Vec<usize>],
    records: &[TxRecord],
    cfg: &AdversaryConfig,
) -> HashMap<(AccountId, AccountId), u32> {
    let mut weight: HashMap<(AccountId, AccountId), u32> = HashMap::new();
    for group in groups {
        let mut srcs: BTreeSet<AccountId> = BTreeSet::new();
        for &ix in group {
            let r = &records[ix];
            if r.fee_payer != r.source {
                srcs.insert(r.source);
            }
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
    weight
}

/// Infer the funding graph from public fields only: a transfer whose destination is some
/// account's fee-payer, sent by a different account, looks like a fee-payer top-up. Returns
/// `funder -> {funded fee-payers}`. Deliberately label-free (keys on structure, not a `kind`
/// tag), so it also fires on any real funding a chain would show, and is empty on a ledger with
/// no funding (fee-payers there are fresh randoms that never appear as a destination).
pub(crate) fn funding_edges(records: &[TxRecord]) -> HashMap<AccountId, BTreeSet<AccountId>> {
    let fee_set: std::collections::HashSet<AccountId> =
        records.iter().map(|r| r.fee_payer).collect();
    let mut children: HashMap<AccountId, BTreeSet<AccountId>> = HashMap::new();
    for r in records {
        if r.source != r.dest && fee_set.contains(&r.dest) {
            children.entry(r.source).or_default().insert(r.dest);
        }
    }
    children
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

    // (2) Structural consolidation. A destination that is also an active source and
    // receives value from a small set of distinct sources looks like an internal hub.
    // This uses only graph structure; `ActionKind::Consolidate` is simulator intent and
    // is deliberately not available to the adversary.
    if cfg.use_cospend {
        let active_sources: std::collections::HashSet<AccountId> =
            ledger.records.iter().map(|r| r.source).collect();
        let mut sources_by_dest: HashMap<AccountId, BTreeSet<AccountId>> = HashMap::new();
        for r in &ledger.records {
            if r.amount > 0 && r.source != r.dest && active_sources.contains(&r.dest) {
                sources_by_dest.entry(r.dest).or_default().insert(r.source);
            }
        }
        for (dest, sources) in sources_by_dest {
            if sources.len() < 2 || sources.len() > cfg.burst_max_sources {
                continue;
            }
            for source in sources {
                uf.union(dest, source);
            }
        }
    }

    // (3) Temporal + amount correlation (peel-chain). Value leaves A, near-equal value
    // reaches B within the window, and A's destination is B => link A and B. Candidate `b`s
    // are indexed by `b.source` (which must equal `a.dest`) and range-searched by ts.
    if cfg.use_temporal_amount {
        let txs: Vec<&TxRecord> = ledger
            .records
            .iter()
            .filter(|r| r.amount > 0 && r.source != r.dest)
            .collect();

        let mut by_source: HashMap<AccountId, Vec<(i64, u64, u64, AccountId)>> = HashMap::new();
        for b in &txs {
            by_source
                .entry(b.source)
                .or_default()
                .push((b.ts, b.amount, b.sig, b.dest));
        }
        for v in by_source.values_mut() {
            v.sort_by_key(|&(ts, _amt, sig, _dest)| (ts, sig));
        }

        for a in &txs {
            let bucket = match by_source.get(&a.dest) {
                Some(v) => v,
                None => continue,
            };
            let lo = bucket.partition_point(|&(ts, ..)| ts < a.ts);
            let hi = bucket.partition_point(|&(ts, ..)| ts <= a.ts + cfg.temporal_window_secs);
            let tol = (a.amount as u128 * cfg.amount_tolerance_bps as u128 / 10_000) as u64;
            for &(_bts, bamt, bsig, bdest) in &bucket[lo..hi] {
                if a.sig == bsig {
                    continue;
                }
                if a.amount.abs_diff(bamt) <= tol {
                    uf.union(a.source, bdest);
                }
            }
        }
    }

    // (4) Account-activation lineage. When value enters a previously inactive address and
    // that exact address starts signing shortly afterwards, link the predecessor and
    // successor. This is the public residual of one-to-one account rotation.
    if cfg.use_activation_lineage {
        let mut first_source_at: HashMap<AccountId, i64> = HashMap::new();
        for r in &ledger.records {
            first_source_at
                .entry(r.source)
                .and_modify(|ts| *ts = (*ts).min(r.ts))
                .or_insert(r.ts);
        }
        let window = cfg.activation_window_secs.max(0);
        for r in &ledger.records {
            let Some(&activated_at) = first_source_at.get(&r.dest) else {
                continue;
            };
            if r.amount > 0
                && r.source != r.dest
                && activated_at >= r.ts
                && activated_at.saturating_sub(r.ts) <= window
            {
                uf.union(r.source, r.dest);
            }
        }
    }

    // Group records once (identical-ts bursts or Δt windows), then run the thresholded
    // copay/coact linkers over the groups. Repetition thresholds and `burst_max_sources`
    // bound false positives.
    let groups = if cfg.use_windowed {
        window_groups(&ledger.records, cfg.window_secs)
    } else {
        burst_groups(&ledger.records)
    };

    // (4) Common-destination co-payment: sources sharing a (group, dest) bucket in
    // >= copay_min_shared_buckets groups are unioned.
    if cfg.use_burst_copay {
        let edges = if cfg.use_windowed {
            windowed_copay_edges(&ledger.records, cfg)
        } else {
            copay_edges(&groups, &ledger.records, cfg)
        };
        for (&(a, b), &w) in &edges {
            if w >= cfg.copay_min_shared_buckets {
                uf.union(a, b);
            }
        }
    }

    // (5) Exact-timestamp co-activity (dest-agnostic): sources co-present in
    // >= coactivity_min_shared_bursts groups are unioned. Even the windowed adversary retains
    // this narrower signal; applying co-activity to broad windows would over-merge operators.
    if cfg.use_burst_coactivity {
        let exact_groups;
        let coactivity_groups = if cfg.use_windowed {
            exact_groups = burst_groups(&ledger.records);
            &exact_groups
        } else {
            &groups
        };
        for (&(a, b), &w) in &coact_edges(coactivity_groups, &ledger.records, cfg) {
            if w >= cfg.coactivity_min_shared_bursts {
                uf.union(a, b);
            }
        }
    }

    // (7) Common-funder graph. A funder's fee-payers were signed for by the operator's own
    // sources (heuristic (1) ties each fee-payer to its source); collapsing every source reached
    // through one funder undoes fee-payer rotation. A funder serving more sources than
    // `funder_max_sources` is a shared service (relayer/exchange) — dropped, not attributed.
    if cfg.use_funder_graph {
        let children = funding_edges(&ledger.records);
        // fee-payer -> the sources that used it (a funding tx has fee_payer == source; skip it).
        let mut fp_sources: HashMap<AccountId, BTreeSet<AccountId>> = HashMap::new();
        for r in &ledger.records {
            if r.fee_payer != r.source {
                fp_sources.entry(r.fee_payer).or_default().insert(r.source);
            }
        }
        for (funder, fps) in &children {
            if fps.len() < cfg.funder_min_fundees {
                continue;
            }
            let mut srcs: BTreeSet<AccountId> = BTreeSet::new();
            for fp in fps {
                if let Some(s) = fp_sources.get(fp) {
                    srcs.extend(s.iter().copied());
                }
            }
            if srcs.len() < 2 || srcs.len() > cfg.funder_max_sources {
                continue;
            }
            // Union the funder in too — a real analyst who identifies the funder attributes it to
            // the same entity. Metric-neutral for a relayer (unowned), and it is what restores a
            // dedicated funder's own account to its operator's cluster.
            for &s in &srcs {
                uf.union(*funder, s);
            }
        }
    }

    // (6) Ablation only: union every source in a group with no repetition threshold.
    if cfg.use_burst_union_ceiling {
        for group in &groups {
            let mut srcs: BTreeSet<AccountId> = BTreeSet::new();
            for &ix in group {
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
    use noise_core::types::ActionKind;

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

    // ---- burst-heuristic tests (pure, deterministic, no RNG) ----

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

    /// A config with all other heuristics off, so a test isolates one burst signal.
    fn only(copay: bool, coact: bool, ceiling: bool) -> AdversaryConfig {
        AdversaryConfig {
            use_fee_payer: false,
            use_cospend: false,
            use_temporal_amount: false,
            use_activation_lineage: false,
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
        assert!(
            same(&cl, s1, s2),
            "two shared (ts,dest) buckets should union"
        );
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
        assert!(
            !same(&cl, acc(1), acc(2)),
            "oversized bucket must be dropped"
        );
    }

    #[test]
    fn copay_amount_floor_uses_only_observable_value() {
        let (s1, s2, s3, d) = (acc(1), acc(2), acc(3), acc(10));
        let recs = vec![
            rec(1, 1, 100, s1, d, 1_000_000, Transfer),
            rec(2, 2, 100, s2, d, 1_000_000, Transfer),
            rec(3, 3, 100, s3, d, 5_000, Dust),
            rec(4, 4, 200, s1, d, 1_000_000, Transfer),
            rec(5, 5, 200, s2, d, 1_000_000, Transfer),
            rec(6, 6, 200, s3, d, 5_000, Dust),
        ];
        let cfg = AdversaryConfig {
            copay_min_amount: 10_000,
            ..only(true, false, false)
        };
        let cl = cluster(&led(recs), &cfg);
        assert!(same(&cl, s1, s2), "real parts co-pay");
        assert!(
            !same(&cl, s1, s3),
            "the public amount floor excludes the small transfer without reading its kind"
        );
    }

    #[test]
    fn structural_cospend_does_not_read_action_kind() {
        let (s1, s2, hub, external) = (acc(1), acc(2), acc(9), acc(10));
        let records = vec![
            rec(1, 1, 100, s1, hub, 20_000, Dust),
            rec(2, 2, 101, s2, hub, 30_000, Transfer),
            // The destination is an active account, which is the public hub signal.
            rec(3, 3, 200, hub, external, 40_000, Transfer),
        ];
        let cfg = AdversaryConfig {
            use_cospend: true,
            ..only(false, false, false)
        };
        let cl = cluster(&led(records), &cfg);
        assert!(same(&cl, s1, s2));
        assert!(same(&cl, s1, hub));
    }

    #[test]
    fn structural_cospend_ignores_external_sink() {
        let (s1, s2, external) = (acc(1), acc(2), acc(10));
        let records = vec![
            rec(1, 1, 100, s1, external, 20_000, Transfer),
            rec(2, 2, 101, s2, external, 30_000, Transfer),
        ];
        let cfg = AdversaryConfig {
            use_cospend: true,
            ..only(false, false, false)
        };
        let cl = cluster(&led(records), &cfg);
        assert!(
            !same(&cl, s1, s2),
            "a passive protocol/counterparty is not an internal hub"
        );
    }

    #[test]
    fn activation_lineage_links_a_rotated_account_without_kind_labels() {
        let (old, successor, external) = (acc(1), acc(2), acc(10));
        let records = vec![
            rec(1, 1, 100, old, successor, 50_000, Dust),
            rec(2, 2, 200, successor, external, 70_000, Transfer),
        ];
        let cfg = AdversaryConfig {
            use_activation_lineage: true,
            activation_window_secs: 500,
            ..only(false, false, false)
        };
        assert!(same(&cluster(&led(records), &cfg), old, successor));
    }

    #[test]
    fn activation_lineage_respects_time_and_inactive_destinations() {
        let (old, late, passive) = (acc(1), acc(2), acc(3));
        let records = vec![
            rec(1, 1, 100, old, late, 50_000, Transfer),
            rec(2, 2, 101, old, passive, 50_000, Transfer),
            rec(3, 3, 1000, late, acc(10), 70_000, Transfer),
        ];
        let cfg = AdversaryConfig {
            use_activation_lineage: true,
            activation_window_secs: 500,
            ..only(false, false, false)
        };
        let cl = cluster(&led(records), &cfg);
        assert!(
            !same(&cl, old, late),
            "late activation is outside the window"
        );
        assert!(
            !same(&cl, old, passive),
            "a destination that never signs is not a successor"
        );
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
        assert!(
            same(&cl, s1, s3),
            "a decoy-only subaccount still leaks via co-activity"
        );
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
        assert!(
            !same(&cl, s1, s2),
            "a single collision must not fuse operators"
        );
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
        assert!(
            same(&cl, s1, s2),
            "ceiling unions a single burst (precision cost)"
        );
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
        assert_eq!(
            g.len(),
            1,
            "same-ts collision stays one burst (the known residual)"
        );
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

    // ---- windowed-adversary tests ----

    /// Windowed variant of `only()`: exact-ts config + windowing on.
    fn win_only(copay: bool, coact: bool, window: i64) -> AdversaryConfig {
        AdversaryConfig {
            use_windowed: true,
            window_secs: window,
            ..only(copay, coact, false)
        }
    }

    /// Set of co-grouped sig-pairs (min,max) for a grouping — used to check subset relations.
    fn pairs_of(groups: &[Vec<usize>], recs: &[TxRecord]) -> std::collections::HashSet<(u64, u64)> {
        let mut s = std::collections::HashSet::new();
        for g in groups {
            for x in 0..g.len() {
                for y in (x + 1)..g.len() {
                    let (a, b) = (recs[g[x]].sig, recs[g[y]].sig);
                    s.insert((a.min(b), a.max(b)));
                }
            }
        }
        s
    }

    #[test]
    fn window_groups_merges_within_window() {
        let z = acc(0);
        let recs = vec![
            rec(1, 1, 100, z, z, 0, Transfer),
            rec(2, 2, 150, z, z, 0, Transfer),
            rec(3, 3, 200, z, z, 0, Transfer),
        ];
        assert_eq!(
            window_groups(&recs, 120).len(),
            1,
            "all within 120s of the first"
        );
        assert_eq!(window_groups(&recs, 40).len(), 3, "40s window splits each");
    }

    #[test]
    fn window_groups_window_zero_groups_identical_ts() {
        let z = acc(0);
        let recs = vec![
            rec(1, 1, 100, z, z, 0, Transfer),
            rec(2, 2, 100, z, z, 0, Transfer),
            rec(3, 3, 200, z, z, 0, Transfer),
            rec(4, 4, 200, z, z, 0, Transfer),
        ];
        assert_eq!(
            window_groups(&recs, 0).len(),
            2,
            "window 0 groups identical ts"
        );
    }

    #[test]
    fn window_groups_subsumes_exact_ts() {
        // window(0) pairs superset burst pairs; window(120) superset window(0).
        let z = acc(0);
        let recs = vec![
            rec(1, 1, 100, z, z, 0, Transfer),
            rec(2, 2, 100, z, z, 0, Transfer),
            rec(3, 5, 100, z, z, 0, Transfer), // slot gap: separate burst, same ts
            rec(4, 6, 180, z, z, 0, Transfer),
        ];
        let burst = pairs_of(&burst_groups(&recs), &recs);
        let w0 = pairs_of(&window_groups(&recs, 0), &recs);
        let w120 = pairs_of(&window_groups(&recs, 120), &recs);
        assert!(
            burst.is_subset(&w0),
            "window(0) must subsume exact-ts bursts"
        );
        assert!(w0.is_subset(&w120), "wider window must subsume narrower");
    }

    #[test]
    fn widening_window_never_loses_a_boundary_pair() {
        let z = acc(0);
        let recs = vec![
            rec(1, 1, 0, z, z, 0, Transfer),
            rec(2, 2, 70, z, z, 0, Transfer),
            rec(3, 3, 130, z, z, 0, Transfer),
        ];
        let narrow = pairs_of(&window_groups(&recs, 60), &recs);
        let wide = pairs_of(&window_groups(&recs, 120), &recs);
        assert!(narrow.contains(&(2, 3)));
        assert!(
            narrow.is_subset(&wide),
            "widening a proximity threshold must not discard an existing pair"
        );
    }

    #[test]
    fn window_groups_deterministic_under_shuffle() {
        let z = acc(0);
        let recs = vec![
            rec(1, 1, 100, z, z, 0, Transfer),
            rec(2, 2, 150, z, z, 0, Transfer),
            rec(3, 3, 900, z, z, 0, Transfer),
        ];
        let mut shuffled = recs.clone();
        shuffled.reverse(); // any reordering; grouping keys off (ts,slot,sig), not position
        assert_eq!(
            pairs_of(&window_groups(&recs, 120), &recs),
            pairs_of(&window_groups(&shuffled, 120), &shuffled)
        );
    }

    #[test]
    fn windowed_copay_catches_jittered_sweep() {
        // A sweep to `hub` at nearby-but-distinct ts: exact-ts sees singletons; a 120s
        // window regroups them into one bucket.
        let (s1, s2, hub) = (acc(1), acc(2), acc(9));
        let recs = vec![
            rec(1, 1, 100, s1, hub, 1_000_000, Transfer),
            rec(2, 2, 105, s2, hub, 1_000_000, Transfer),
            rec(3, 3, 1000, s1, hub, 1_000_000, Transfer),
            rec(4, 4, 1006, s2, hub, 1_000_000, Transfer),
            rec(5, 5, 2000, hub, acc(30), 10_000, Transfer),
        ];
        let cl_exact = cluster(&led(recs.clone()), &only(true, false, false));
        assert!(
            !same(&cl_exact, s1, s2),
            "exact-ts misses the jittered sweep"
        );
        let cl_win = cluster(&led(recs), &win_only(true, false, 120));
        assert!(
            same(&cl_win, s1, s2),
            "windowed catches it (2 shared window+hub buckets)"
        );
    }

    #[test]
    fn destination_local_window_ignores_global_bucket_boundaries() {
        let (s1, s2, hub, unrelated) = (acc(1), acc(2), acc(9), acc(30));
        let recs = vec![
            rec(1, 1, 0, unrelated, acc(31), 1_000_000, Transfer),
            rec(2, 2, 119, s1, hub, 1_000_000, Transfer),
            rec(3, 3, 121, s2, hub, 1_000_000, Transfer),
            rec(4, 4, 1000, s1, hub, 1_000_000, Transfer),
            rec(5, 5, 1002, s2, hub, 1_000_000, Transfer),
            rec(6, 6, 2000, hub, acc(32), 10_000, Transfer),
        ];
        let cl = cluster(&led(recs), &win_only(true, false, 120));
        assert!(
            same(&cl, s1, s2),
            "destination-local episodes recover both sweeps despite unrelated records"
        );
    }

    #[test]
    fn windowed_copay_shared_external_no_false_union() {
        // Two operators pay the same external `d`, but in separate windows. Windowing must
        // not merge them.
        let (s1, s1b, s2, s2b, d) = (acc(1), acc(2), acc(3), acc(4), acc(20));
        let recs = vec![
            rec(1, 1, 100, s1, d, 1_000_000, Transfer),
            rec(2, 2, 105, s1b, d, 1_000_000, Transfer),
            rec(3, 3, 1000, s1, d, 1_000_000, Transfer),
            rec(4, 4, 1005, s1b, d, 1_000_000, Transfer),
            rec(5, 5, 5000, s2, d, 1_000_000, Transfer),
            rec(6, 6, 5005, s2b, d, 1_000_000, Transfer),
            rec(7, 7, 6000, s2, d, 1_000_000, Transfer),
            rec(8, 8, 6005, s2b, d, 1_000_000, Transfer),
        ];
        let cl = cluster(&led(recs), &win_only(true, false, 120));
        assert!(
            !same(&cl, s1, s2),
            "shared external at different windows must not merge"
        );
        assert!(
            !same(&cl, s1, s1b) && !same(&cl, s2, s2b),
            "a passive shared destination is intentionally not treated as an owned hub"
        );
    }

    #[test]
    fn windowed_does_not_apply_coactivity_to_broad_windows() {
        let (s1, s2, d1, d2) = (acc(1), acc(2), acc(21), acc(22));
        let make = |wins: usize| {
            let mut recs = Vec::new();
            let mut sig = 0u64;
            for w in 0..wins {
                let ts = 100 + w as i64 * 1000;
                sig += 1;
                recs.push(rec(sig, sig, ts, s1, d1, 1_000_000, Transfer));
                sig += 1;
                recs.push(rec(sig, sig, ts + 5, s2, d2, 1_000_000, Transfer));
            }
            recs
        };
        let cl3 = cluster(&led(make(3)), &win_only(false, true, 120));
        assert!(
            !same(&cl3, s1, s2),
            "dest-agnostic coactivity is restricted to exact timestamps"
        );
    }

    #[test]
    fn windowed_size_cap_drops_bucket() {
        let hub = acc(50);
        let mut recs = Vec::new();
        let mut sig = 0u64;
        for &base in &[100i64, 2000] {
            for s in 1..=11u8 {
                sig += 1;
                recs.push(rec(
                    sig,
                    sig,
                    base + s as i64,
                    acc(s),
                    hub,
                    1_000_000,
                    Transfer,
                ));
            }
        }
        sig += 1;
        recs.push(rec(sig, sig, 4000, hub, acc(60), 10_000, Transfer));
        let cl = cluster(&led(recs), &win_only(true, false, 120));
        assert!(
            !same(&cl, acc(1), acc(2)),
            "an 11-source window bucket is dropped"
        );
    }

    fn only_temporal() -> AdversaryConfig {
        AdversaryConfig {
            use_fee_payer: false,
            use_cospend: false,
            use_temporal_amount: true,
            use_activation_lineage: false,
            use_burst_copay: false,
            use_burst_coactivity: false,
            ..AdversaryConfig::default()
        }
    }

    // ---- funder-graph tests ----

    /// A record with an explicit fee_payer (funding txs set fee_payer == source == funder).
    fn recf(
        sig: u64,
        slot: u64,
        ts: i64,
        fee_payer: AccountId,
        source: AccountId,
        dest: AccountId,
        kind: ActionKind,
    ) -> TxRecord {
        TxRecord {
            sig,
            slot,
            ts,
            fee_payer,
            source,
            dest,
            amount: 1_000_000,
            kind,
            operator: None,
        }
    }

    /// Config isolating H-FUNDER (all other heuristics off).
    fn only_funder() -> AdversaryConfig {
        AdversaryConfig {
            use_fee_payer: false,
            use_cospend: false,
            use_temporal_amount: false,
            use_activation_lineage: false,
            use_burst_copay: false,
            use_burst_coactivity: false,
            use_funder_graph: true,
            funder_min_fundees: 3,
            funder_max_sources: 10,
            ..AdversaryConfig::default()
        }
    }

    #[test]
    fn funder_unions_sources_of_common_funder() {
        // Funder u funds throwaways fp1..fp3; each pays for a distinct source s1..s3.
        let (u, fp1, fp2, fp3, s1, s2, s3, d) = (
            acc(100),
            acc(1),
            acc(2),
            acc(3),
            acc(11),
            acc(12),
            acc(13),
            acc(50),
        );
        let recs = vec![
            recf(1, 1, 10, u, u, fp1, Transfer), // u funds fp1
            recf(2, 2, 11, u, u, fp2, Transfer),
            recf(3, 3, 12, u, u, fp3, Transfer),
            recf(4, 4, 20, fp1, s1, d, Transfer), // fp1 pays for s1's action
            recf(5, 5, 21, fp2, s2, d, Transfer),
            recf(6, 6, 22, fp3, s3, d, Transfer),
        ];
        let cl = cluster(&led(recs), &only_funder());
        assert!(
            same(&cl, s1, s2) && same(&cl, s2, s3),
            "shared funder unions sources"
        );
        assert!(
            same(&cl, u, s1),
            "the funder is unioned into the cluster too"
        );
    }

    #[test]
    fn funder_below_min_fundees_no_union() {
        let (u, fp1, fp2, s1, s2, d) = (acc(100), acc(1), acc(2), acc(11), acc(12), acc(50));
        let recs = vec![
            recf(1, 1, 10, u, u, fp1, Transfer),
            recf(2, 2, 11, u, u, fp2, Transfer),
            recf(3, 3, 20, fp1, s1, d, Transfer),
            recf(4, 4, 21, fp2, s2, d, Transfer),
        ];
        let cl = cluster(&led(recs), &only_funder());
        assert!(!same(&cl, s1, s2), "2 fundees is below min_fundees 3");
    }

    #[test]
    fn funder_size_cap_drops_shared_service() {
        // A relayer funds 11 fee-payers across 11 sources: above funder_max_sources=10, dropped.
        let u = acc(200);
        let mut recs = Vec::new();
        let mut sig = 0u64;
        for i in 1..=11u8 {
            sig += 1;
            recs.push(recf(sig, sig, 10 + sig as i64, u, u, acc(i), Transfer));
        }
        for i in 1..=11u8 {
            sig += 1;
            recs.push(recf(
                sig,
                sig,
                100 + sig as i64,
                acc(i),
                acc(100 + i),
                acc(240),
                Transfer,
            ));
        }
        let cl = cluster(&led(recs), &only_funder());
        assert!(
            !same(&cl, acc(101), acc(102)),
            "oversized funder bucket is dropped as a shared service"
        );
    }

    #[test]
    fn funder_off_by_default() {
        let (u, fp1, fp2, fp3, s1, s2, s3, d) = (
            acc(100),
            acc(1),
            acc(2),
            acc(3),
            acc(11),
            acc(12),
            acc(13),
            acc(50),
        );
        let recs = vec![
            recf(1, 1, 10, u, u, fp1, Transfer),
            recf(2, 2, 11, u, u, fp2, Transfer),
            recf(3, 3, 12, u, u, fp3, Transfer),
            recf(4, 4, 20, fp1, s1, d, Transfer),
            recf(5, 5, 21, fp2, s2, d, Transfer),
            recf(6, 6, 22, fp3, s3, d, Transfer),
        ];
        // Default config: funder graph disabled, unique fee-payers, so no cross-source union.
        let cl = cluster(&led(recs), &AdversaryConfig::default());
        assert!(!same(&cl, s1, s2), "funder graph is off by default");
    }

    #[test]
    fn funder_never_reads_operator() {
        // operator is None on every record, yet the union still happens — proof it is structural.
        let (u, fp1, fp2, fp3, s1, s2, s3, d) = (
            acc(100),
            acc(1),
            acc(2),
            acc(3),
            acc(11),
            acc(12),
            acc(13),
            acc(50),
        );
        let recs = vec![
            recf(1, 1, 10, u, u, fp1, Transfer),
            recf(2, 2, 11, u, u, fp2, Transfer),
            recf(3, 3, 12, u, u, fp3, Transfer),
            recf(4, 4, 20, fp1, s1, d, Transfer),
            recf(5, 5, 21, fp2, s2, d, Transfer),
            recf(6, 6, 22, fp3, s3, d, Transfer),
        ];
        assert!(recs.iter().all(|r| r.operator.is_none()));
        let cl = cluster(&led(recs), &only_funder());
        assert!(same(&cl, s1, s3));
    }

    #[test]
    fn temporal_amount_window_and_tol_boundaries() {
        // Peel chain: s1 -> x at ts=100, then x -> s2 at ts=100+dt links s1 and s2.
        let (s1, x, s2) = (acc(1), acc(9), acc(2));
        let peel = |dt: i64, bamt: u64| {
            led(vec![
                rec(1, 1, 100, s1, x, 1_000_000, Transfer),
                rec(2, 2, 100 + dt, x, s2, bamt, Transfer),
            ])
        };
        assert!(
            same(&cluster(&peel(0, 1_000_000), &only_temporal()), s1, s2),
            "dt=0 unions"
        );
        assert!(
            same(&cluster(&peel(120, 1_000_000), &only_temporal()), s1, s2),
            "dt=window unions"
        );
        assert!(
            !same(&cluster(&peel(121, 1_000_000), &only_temporal()), s1, s2),
            "dt>window no union"
        );
        // tol = 1_000_000 * 50 bps / 10_000 = 5_000.
        assert!(
            same(&cluster(&peel(10, 1_005_000), &only_temporal()), s1, s2),
            "diff==tol unions"
        );
        assert!(
            !same(&cluster(&peel(10, 1_005_001), &only_temporal()), s1, s2),
            "diff>tol no union"
        );
    }
}
