//! O Caçador v5 — a learned (machine-learning) adversary.
//!
//! The heuristic adversary in `heuristics.rs` unions accounts with hand-written rules. This
//! module instead *learns* to link accounts: a logistic-regression classifier over observable
//! pairwise features predicts P(two accounts share an operator), and its predictions are scored
//! two ways — a threshold-free **ROC AUC** (the metric a modern chain-analysis firm reports) and,
//! by thresholding and unioning, the same pairwise F1/precision the heuristic rows report.
//!
//! It stays inside the project's honesty rules:
//! - **Deterministic**: zero-initialised, full-batch gradient descent — no RNG, no seed. Every
//!   float reduction runs over a sorted `Vec`, and probabilities are quantised before the union
//!   threshold, so a run is bit-reproducible within a toolchain.
//! - **No label leakage**: features read ONLY public `TxRecord` fields (never `operator`, and
//!   deliberately never `kind`). `operator` is used only as the training LABEL and for
//!   operator-disjoint cross-validation folds — each pair is scored by a model that trained on
//!   NEITHER of its operators, so a held-out score can never have seen its own answer.
//! - **Genuinely ML, honestly bounded**: alongside the fused model it reports the best
//!   single-feature AUC, so "the model beat any one rule" is measured, not asserted.

// The training loops index several fixed-size `[f64; NFEAT]` arrays by one coordinating index
// (weights, gradients, standardization moments) — a range loop is the clearest form here.
#![allow(clippy::needless_range_loop)]

use crate::heuristics::{burst_groups, funding_edges, window_groups, Clustering, UnionFind};
use crate::metric::{evaluate, Report};
use crate::model::{AgentId, Ledger};
use noise_core::types::AccountId;
use std::collections::{BTreeSet, HashMap};

/// Feature names, in the order the feature vector is built. Printed with the learned weights so
/// the model is explainable.
pub const FEATURE_NAMES: [&str; 8] = [
    "fee_payer_jaccard",
    "dest_jaccard",
    "coburst",
    "windowed_copay",
    "funding_hop",
    "activation_lineage",
    "peel",
    "timespan_overlap",
];
const NFEAT: usize = 8;

#[derive(Clone, Debug)]
pub struct MlConfig {
    pub folds: usize,
    pub iters: usize,
    pub learning_rate: f64,
    pub l2: f64,
    pub threshold: f64,
    pub window_secs: i64,
    pub temporal_window_secs: i64,
    pub amount_tolerance_bps: u32,
    pub activation_window_secs: i64,
    /// Refuse to report an AUC on fewer operators / positive pairs than this (avoids a
    /// flattering number from an undersampled fleet).
    pub min_operators: usize,
    pub min_positive_pairs: usize,
}

impl Default for MlConfig {
    fn default() -> Self {
        MlConfig {
            folds: 5,
            iters: 300,
            learning_rate: 0.3,
            l2: 1e-3,
            threshold: 0.5,
            window_secs: 120,
            temporal_window_secs: 120,
            amount_tolerance_bps: 50,
            activation_window_secs: 2 * 86_400,
            min_operators: 6,
            min_positive_pairs: 20,
        }
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct MlReport {
    /// Threshold-free ranking quality of P(same operator) over held-out pairs. NaN when the
    /// fleet is too small to report honestly (`roc_auc_defined == false`).
    pub roc_auc: f64,
    pub roc_auc_defined: bool,
    /// The pairwise clustering scored exactly like the heuristic adversary (thresholded links).
    pub report: Report,
    /// Learned weight per feature (on the standardised scale) — the model's explanation.
    pub feature_weights: Vec<(&'static str, f64)>,
    /// AUC of each feature used alone; lets a reader see whether fusion beat the best single rule.
    pub single_feature_aucs: Vec<(&'static str, f64)>,
    pub num_pairs: usize,
    pub num_positive_pairs: usize,
    pub folds_used: usize,
}

// ---- pairwise feature construction (observable fields only) ----

fn pair_key(a: AccountId, b: AccountId) -> (AccountId, AccountId) {
    if a <= b {
        (a, b)
    } else {
        (b, a)
    }
}

/// Add one to the weight of every unordered pair within a set of distinct sources.
fn add_clique(edges: &mut HashMap<(AccountId, AccountId), f64>, srcs: &BTreeSet<AccountId>) {
    let v: Vec<AccountId> = srcs.iter().copied().collect();
    for i in 0..v.len() {
        for j in (i + 1)..v.len() {
            *edges.entry(pair_key(v[i], v[j])).or_insert(0.0) += 1.0;
        }
    }
}

/// Everything needed to build a feature vector for any owned pair. All maps key on public fields.
struct Features {
    fee_payers: HashMap<AccountId, BTreeSet<AccountId>>,
    dests: HashMap<AccountId, BTreeSet<AccountId>>,
    span: HashMap<AccountId, (i64, i64)>,
    coburst: HashMap<(AccountId, AccountId), f64>,
    windowed_copay: HashMap<(AccountId, AccountId), f64>,
    funding_hop: HashMap<(AccountId, AccountId), f64>,
    activation: HashMap<(AccountId, AccountId), f64>,
    peel: HashMap<(AccountId, AccountId), f64>,
}

impl Features {
    fn build(ledger: &Ledger, cfg: &MlConfig) -> Features {
        let recs = &ledger.records;

        // Per-account observable aggregates (as a signing source).
        let mut fee_payers: HashMap<AccountId, BTreeSet<AccountId>> = HashMap::new();
        let mut dests: HashMap<AccountId, BTreeSet<AccountId>> = HashMap::new();
        let mut span: HashMap<AccountId, (i64, i64)> = HashMap::new();
        for r in recs {
            fee_payers.entry(r.source).or_default().insert(r.fee_payer);
            dests.entry(r.source).or_default().insert(r.dest);
            let e = span.entry(r.source).or_insert((r.ts, r.ts));
            e.0 = e.0.min(r.ts);
            e.1 = e.1.max(r.ts);
        }

        // (3) co-burst: distinct sources co-present in an exact-ts burst.
        let mut coburst: HashMap<(AccountId, AccountId), f64> = HashMap::new();
        for group in burst_groups(recs) {
            let srcs: BTreeSet<AccountId> = group.iter().map(|&i| recs[i].source).collect();
            add_clique(&mut coburst, &srcs);
        }

        // (4) windowed co-payment: sources sharing a (Δt-window, dest) bucket.
        let mut windowed_copay: HashMap<(AccountId, AccountId), f64> = HashMap::new();
        for group in window_groups(recs, cfg.window_secs) {
            let mut by_dest: HashMap<AccountId, BTreeSet<AccountId>> = HashMap::new();
            for &i in &group {
                by_dest
                    .entry(recs[i].dest)
                    .or_default()
                    .insert(recs[i].source);
            }
            for srcs in by_dest.values() {
                add_clique(&mut windowed_copay, srcs);
            }
        }

        // (5) common funder: sources whose fee-payers were funded by one wallet.
        let children = funding_edges(recs);
        let mut fp_sources: HashMap<AccountId, BTreeSet<AccountId>> = HashMap::new();
        for r in recs {
            if r.fee_payer != r.source {
                fp_sources.entry(r.fee_payer).or_default().insert(r.source);
            }
        }
        let mut funding_hop: HashMap<(AccountId, AccountId), f64> = HashMap::new();
        for fps in children.values() {
            let mut srcs: BTreeSet<AccountId> = BTreeSet::new();
            for fp in fps {
                if let Some(s) = fp_sources.get(fp) {
                    srcs.extend(s.iter().copied());
                }
            }
            add_clique(&mut funding_hop, &srcs);
        }

        // (6) activation lineage: value enters an account that then first signs within the window.
        let mut first_source_at: HashMap<AccountId, i64> = HashMap::new();
        for r in recs {
            first_source_at
                .entry(r.source)
                .and_modify(|t| *t = (*t).min(r.ts))
                .or_insert(r.ts);
        }
        let mut activation: HashMap<(AccountId, AccountId), f64> = HashMap::new();
        let awin = cfg.activation_window_secs.max(0);
        for r in recs {
            if let Some(&at) = first_source_at.get(&r.dest) {
                if r.amount > 0
                    && r.source != r.dest
                    && at >= r.ts
                    && at.saturating_sub(r.ts) <= awin
                {
                    *activation.entry(pair_key(r.source, r.dest)).or_insert(0.0) += 1.0;
                }
            }
        }

        // (7) peel chain: value leaves a, near-equal value leaves a's destination shortly after.
        let mut by_source: HashMap<AccountId, Vec<(i64, u64, u64, AccountId)>> = HashMap::new();
        for r in recs {
            if r.amount > 0 && r.source != r.dest {
                by_source
                    .entry(r.source)
                    .or_default()
                    .push((r.ts, r.amount, r.sig, r.dest));
            }
        }
        for v in by_source.values_mut() {
            v.sort_by_key(|&(ts, _a, sig, _d)| (ts, sig));
        }
        let mut peel: HashMap<(AccountId, AccountId), f64> = HashMap::new();
        for r in recs {
            if r.amount == 0 || r.source == r.dest {
                continue;
            }
            let Some(bucket) = by_source.get(&r.dest) else {
                continue;
            };
            let lo = bucket.partition_point(|&(ts, ..)| ts < r.ts);
            let hi = bucket.partition_point(|&(ts, ..)| ts <= r.ts + cfg.temporal_window_secs);
            let tol = (r.amount as u128 * cfg.amount_tolerance_bps as u128 / 10_000) as u64;
            for &(_bts, bamt, bsig, bdest) in &bucket[lo..hi] {
                if r.sig != bsig && r.amount.abs_diff(bamt) <= tol && r.source != bdest {
                    *peel.entry(pair_key(r.source, bdest)).or_insert(0.0) += 1.0;
                }
            }
        }

        Features {
            fee_payers,
            dests,
            span,
            coburst,
            windowed_copay,
            funding_hop,
            activation,
            peel,
        }
    }

    fn jaccard(a: &BTreeSet<AccountId>, b: &BTreeSet<AccountId>) -> f64 {
        if a.is_empty() && b.is_empty() {
            return 0.0;
        }
        let inter = a.intersection(b).count() as f64;
        let uni = (a.len() + b.len()) as f64 - inter;
        if uni == 0.0 {
            0.0
        } else {
            inter / uni
        }
    }

    fn vector(&self, a: AccountId, b: AccountId) -> [f64; NFEAT] {
        let empty = BTreeSet::new();
        let fpa = self.fee_payers.get(&a).unwrap_or(&empty);
        let fpb = self.fee_payers.get(&b).unwrap_or(&empty);
        let da = self.dests.get(&a).unwrap_or(&empty);
        let db = self.dests.get(&b).unwrap_or(&empty);
        let key = pair_key(a, b);
        let edge = |m: &HashMap<(AccountId, AccountId), f64>| *m.get(&key).unwrap_or(&0.0);
        // Normalise the count-like features with log1p so a few heavy pairs do not dominate the
        // fixed-learning-rate gradient descent.
        let ln1p = |x: f64| (1.0 + x).ln();
        let span_overlap = {
            let (a0, a1) = *self.span.get(&a).unwrap_or(&(0, 0));
            let (b0, b1) = *self.span.get(&b).unwrap_or(&(0, 0));
            let inter = (a1.min(b1) - a0.max(b0)).max(0) as f64;
            let uni = (a1.max(b1) - a0.min(b0)).max(1) as f64;
            inter / uni
        };
        [
            Self::jaccard(fpa, fpb),
            Self::jaccard(da, db),
            ln1p(edge(&self.coburst)),
            ln1p(edge(&self.windowed_copay)),
            ln1p(edge(&self.funding_hop)),
            ln1p(edge(&self.activation)),
            ln1p(edge(&self.peel)),
            span_overlap,
        ]
    }
}

// ---- logistic regression (hand-rolled, deterministic) ----

struct LogReg {
    weights: [f64; NFEAT],
    bias: f64,
    mean: [f64; NFEAT],
    std: [f64; NFEAT],
}

fn sigmoid(z: f64) -> f64 {
    1.0 / (1.0 + (-z).exp())
}

impl LogReg {
    /// Fit L2-regularised weighted logistic regression by full-batch gradient descent. Zero-init
    /// and full-batch => the convex objective's global optimum is reached with no randomness.
    fn fit(x: &[[f64; NFEAT]], y: &[f64], cfg: &MlConfig) -> LogReg {
        let n = x.len();
        // Standardise features on this training set (guard constant features: center only).
        let mut mean = [0.0; NFEAT];
        let mut std = [0.0; NFEAT];
        for row in x {
            for f in 0..NFEAT {
                mean[f] += row[f];
            }
        }
        for m in &mut mean {
            *m /= n as f64;
        }
        for row in x {
            for f in 0..NFEAT {
                let d = row[f] - mean[f];
                std[f] += d * d;
            }
        }
        for s in &mut std {
            *s = (*s / n as f64).sqrt();
            if *s < 1e-9 {
                *s = 1.0;
            }
        }
        let z = |row: &[f64; NFEAT], f: usize| (row[f] - mean[f]) / std[f];

        let pos = y.iter().filter(|&&v| v > 0.5).count().max(1);
        let neg = (n - y.iter().filter(|&&v| v > 0.5).count()).max(1);
        let w_pos = neg as f64 / pos as f64; // upweight the rare same-operator class
        let w_neg = 1.0;

        let mut weights = [0.0; NFEAT];
        let mut bias = 0.0;
        for _ in 0..cfg.iters {
            let mut gw = [0.0; NFEAT];
            let mut gb = 0.0;
            let mut wsum = 0.0;
            for (row, &label) in x.iter().zip(y) {
                let mut zz = bias;
                for f in 0..NFEAT {
                    zz += weights[f] * z(row, f);
                }
                let p = sigmoid(zz);
                let sw = if label > 0.5 { w_pos } else { w_neg };
                let err = sw * (p - label);
                for f in 0..NFEAT {
                    gw[f] += err * z(row, f);
                }
                gb += err;
                wsum += sw;
            }
            let scale = cfg.learning_rate / wsum.max(1.0);
            for f in 0..NFEAT {
                weights[f] -= scale * (gw[f] + cfg.l2 * weights[f]);
            }
            bias -= scale * gb;
        }
        debug_assert!(weights.iter().all(|w| w.is_finite()) && bias.is_finite());
        LogReg {
            weights,
            bias,
            mean,
            std,
        }
    }

    fn predict_proba(&self, row: &[f64; NFEAT]) -> f64 {
        let mut z = self.bias;
        for f in 0..NFEAT {
            z += self.weights[f] * (row[f] - self.mean[f]) / self.std[f];
        }
        sigmoid(z)
    }
}

// ---- ROC AUC (Mann-Whitney U, average ranks for ties) ----

fn roc_auc(scores: &[(f64, bool)]) -> Option<f64> {
    let n_pos = scores.iter().filter(|&&(_, y)| y).count();
    let n_neg = scores.len() - n_pos;
    if n_pos == 0 || n_neg == 0 {
        return None;
    }
    // Sort by score; average ranks over exactly-equal scores (pair-key tiebreak only stabilises
    // the sort, it never breaks a score tie in rank assignment).
    let mut idx: Vec<usize> = (0..scores.len()).collect();
    idx.sort_by(|&i, &j| scores[i].0.total_cmp(&scores[j].0).then(i.cmp(&j)));
    let mut rank_sum_pos = 0.0;
    let mut i = 0;
    while i < idx.len() {
        let mut j = i + 1;
        while j < idx.len() && scores[idx[j]].0 == scores[idx[i]].0 {
            j += 1;
        }
        // ranks i+1..=j (1-based); average for the tie group
        let avg = ((i + 1 + j) as f64) / 2.0;
        for &k in &idx[i..j] {
            if scores[k].1 {
                rank_sum_pos += avg;
            }
        }
        i = j;
    }
    let auc = (rank_sum_pos - (n_pos * (n_pos + 1)) as f64 / 2.0) / (n_pos as f64 * n_neg as f64);
    Some(auc)
}

// ---- the adversary ----

/// Train the learned adversary with operator-disjoint cross-validation and score the ledger.
/// Mirrors `analyze()`: returns the thresholded clustering plus an `MlReport` (AUC + the usual
/// pairwise `Report`).
pub fn ml_attribution(ledger: &Ledger, cfg: &MlConfig) -> (Clustering, MlReport) {
    let owner = ledger.ownership();
    // Owned accounts and their operators, in a stable order.
    let mut accounts: Vec<AccountId> = owner.keys().copied().collect();
    accounts.sort();
    let operators: BTreeSet<AgentId> = owner.values().copied().collect();
    let op_index: HashMap<AgentId, usize> = operators
        .iter()
        .enumerate()
        .map(|(i, &op)| (op, i))
        .collect();
    let k = cfg.folds.min(operators.len()).max(1);
    let fold_of = |op: AgentId| op_index[&op] % k;

    let feats = Features::build(ledger, cfg);

    // All owned pairs, in sorted order, with feature vector, label, and the two folds.
    struct Pair {
        a: AccountId,
        b: AccountId,
        x: [f64; NFEAT],
        y: bool,
        fa: usize,
        fb: usize,
    }
    let mut pairs: Vec<Pair> = Vec::new();
    for i in 0..accounts.len() {
        for j in (i + 1)..accounts.len() {
            let (a, b) = (accounts[i], accounts[j]);
            let (oa, ob) = (owner[&a], owner[&b]);
            pairs.push(Pair {
                a,
                b,
                x: feats.vector(a, b),
                y: oa == ob,
                fa: fold_of(oa),
                fb: fold_of(ob),
            });
        }
    }

    let num_positive = pairs.iter().filter(|p| p.y).count();
    let defined =
        operators.len() >= cfg.min_operators && num_positive >= cfg.min_positive_pairs && k >= 2;

    // Leave-the-pair's-folds-out: one model per unordered fold-set {i,j}, trained on pairs whose
    // both endpoints avoid {i,j}, scoring exactly the pairs landing in {i,j}. Every pair is thus
    // scored by a model blind to both its operators.
    let mut proba: Vec<f64> = vec![0.0; pairs.len()];
    let mut weight_acc = [0.0f64; NFEAT];
    let mut weight_n = 0.0f64;
    if defined {
        for fi in 0..k {
            for fj in fi..k {
                let holdout = |p: &Pair| (p.fa == fi && p.fb == fj) || (p.fa == fj && p.fb == fi);
                let train: Vec<usize> = (0..pairs.len())
                    .filter(|&idx| {
                        let p = &pairs[idx];
                        p.fa != fi && p.fa != fj && p.fb != fi && p.fb != fj
                    })
                    .collect();
                let test: Vec<usize> = (0..pairs.len())
                    .filter(|&idx| holdout(&pairs[idx]))
                    .collect();
                if test.is_empty() {
                    continue;
                }
                if train.is_empty() {
                    continue;
                }
                let tx: Vec<[f64; NFEAT]> = train.iter().map(|&i| pairs[i].x).collect();
                let ty: Vec<f64> = train
                    .iter()
                    .map(|&i| if pairs[i].y { 1.0 } else { 0.0 })
                    .collect();
                let model = LogReg::fit(&tx, &ty, cfg);
                for f in 0..NFEAT {
                    weight_acc[f] += model.weights[f] * train.len() as f64;
                }
                weight_n += train.len() as f64;
                for &idx in &test {
                    proba[idx] = model.predict_proba(&pairs[idx].x);
                }
            }
        }
    }

    // Threshold-free AUC over the pooled held-out scores, plus each single feature's AUC.
    let scored: Vec<(f64, bool)> = pairs
        .iter()
        .enumerate()
        .map(|(i, p)| (proba[i], p.y))
        .collect();
    let (roc, roc_defined) = match (defined, roc_auc(&scored)) {
        (true, Some(a)) => (a, true),
        _ => (f64::NAN, false),
    };
    let single_feature_aucs: Vec<(&'static str, f64)> = (0..NFEAT)
        .map(|f| {
            let s: Vec<(f64, bool)> = pairs.iter().map(|p| (p.x[f], p.y)).collect();
            (FEATURE_NAMES[f], roc_auc(&s).unwrap_or(f64::NAN))
        })
        .collect();

    // Thresholded clustering, scored exactly like the heuristic adversary. Quantise the
    // probability so a sub-ULP libm difference cannot flip a union across toolchains.
    let mut uf = UnionFind::new(ledger.accounts().iter());
    if defined {
        let q = |p: f64| (p * 1e6).round() / 1e6;
        for (i, p) in pairs.iter().enumerate() {
            if q(proba[i]) >= cfg.threshold {
                uf.union(p.a, p.b);
            }
        }
    }
    let clustering = materialize(&mut uf, ledger);
    let report = evaluate(ledger, &clustering, cfg.window_secs);

    let feature_weights: Vec<(&'static str, f64)> = (0..NFEAT)
        .map(|f| {
            let w = if weight_n > 0.0 {
                weight_acc[f] / weight_n
            } else {
                0.0
            };
            (FEATURE_NAMES[f], w)
        })
        .collect();

    (
        clustering,
        MlReport {
            roc_auc: roc,
            roc_auc_defined: roc_defined,
            report,
            feature_weights,
            single_feature_aucs,
            num_pairs: pairs.len(),
            num_positive_pairs: num_positive,
            folds_used: k,
        },
    )
}

/// Materialise a `Clustering` from a settled union-find over all ledger accounts.
fn materialize(uf: &mut UnionFind, ledger: &Ledger) -> Clustering {
    let accounts = ledger.accounts();
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
    use crate::model::TxRecord;
    use noise_core::types::ActionKind;

    fn acc(n: u8) -> AccountId {
        AccountId([n; 32])
    }

    // A small two-operator-ish ledger is not enough for CV; these tests use the engine-free
    // primitives (roc_auc, LogReg) plus structural guarantees. The full arms-race numbers live in
    // the agent-runtime integration test and the CLI demo.

    #[test]
    fn roc_auc_perfect_and_random() {
        // Perfect separation => AUC 1.0.
        let s = vec![(0.9, true), (0.8, true), (0.2, false), (0.1, false)];
        assert!((roc_auc(&s).unwrap() - 1.0).abs() < 1e-12);
        // Inverted => 0.0.
        let s = vec![(0.1, true), (0.9, false)];
        assert!((roc_auc(&s).unwrap() - 0.0).abs() < 1e-12);
        // Single class => undefined.
        assert!(roc_auc(&[(0.5, true), (0.6, true)]).is_none());
    }

    #[test]
    fn roc_auc_ties_average_rank() {
        // Two positives and two negatives all tied => AUC 0.5 (average-rank tie handling).
        let s = vec![(0.5, true), (0.5, false), (0.5, true), (0.5, false)];
        assert!((roc_auc(&s).unwrap() - 0.5).abs() < 1e-12);
    }

    #[test]
    fn logreg_learns_a_separable_signal_deterministically() {
        // Feature 0 perfectly separates; others noise-free zero. Two fits must be identical.
        let mut x = Vec::new();
        let mut y = Vec::new();
        for i in 0..40 {
            let same = i % 2 == 0;
            let mut row = [0.0; NFEAT];
            row[0] = if same { 1.0 } else { 0.0 };
            x.push(row);
            y.push(if same { 1.0 } else { 0.0 });
        }
        let cfg = MlConfig::default();
        let m1 = LogReg::fit(&x, &y, &cfg);
        let m2 = LogReg::fit(&x, &y, &cfg);
        assert_eq!(m1.weights, m2.weights);
        assert_eq!(m1.bias, m2.bias);
        // It learned: a same-pair scores above a different-pair.
        let mut same = [0.0; NFEAT];
        same[0] = 1.0;
        let diff = [0.0; NFEAT];
        assert!(m1.predict_proba(&same) > m1.predict_proba(&diff));
    }

    fn rec(sig: u64, slot: u64, ts: i64, src: AccountId, dest: AccountId, op: AgentId) -> TxRecord {
        TxRecord {
            sig,
            slot,
            ts,
            fee_payer: acc(200u8.wrapping_add(sig as u8)),
            source: src,
            dest,
            amount: 1_000_000,
            kind: ActionKind::Transfer,
            operator: Some(op),
        }
    }

    #[test]
    fn features_never_read_operator() {
        // Permuting the operator labels must not change any feature vector.
        let recs = vec![
            rec(1, 1, 100, acc(1), acc(2), 0),
            rec(2, 2, 100, acc(3), acc(2), 1),
            rec(3, 3, 200, acc(1), acc(4), 0),
        ];
        let a = Features::build(
            &Ledger {
                records: recs.clone(),
            },
            &MlConfig::default(),
        )
        .vector(acc(1), acc(3));
        let mut recs2 = recs;
        for r in &mut recs2 {
            r.operator = r.operator.map(|op| 1 - op);
        }
        let b = Features::build(&Ledger { records: recs2 }, &MlConfig::default())
            .vector(acc(1), acc(3));
        assert_eq!(a, b, "features must not depend on operator labels");
    }
}
