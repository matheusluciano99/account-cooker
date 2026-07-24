//! Adversarial chain-analysis and attribution measurement.
//!
//! An adversarial chain-analysis harness. It runs the same clustering heuristics a
//! real de-anonymization firm would, then MEASURES how well it recovered the truth.
//! Run it against a baseline (naive) ledger and an account-cooker ledger to get the
//! before/after numbers that turn "privacy through noise" into a defensible claim.

pub mod heuristics;
pub mod metric;
pub mod ml;
pub mod model;

pub use heuristics::{cluster, AdversaryConfig, Clustering};
pub use metric::{evaluate, Report};
pub use ml::{ml_attribution, MlConfig, MlReport};
pub use model::{AgentId, Ledger, TxRecord};

/// Convenience: cluster a ledger and score it in one call. The report's `window_purity` is
/// measured at the adversary's window (0 for exact-ts configs).
pub fn analyze(ledger: &Ledger, cfg: &AdversaryConfig) -> (Clustering, Report) {
    let clustering = cluster(ledger, cfg);
    let win = if cfg.use_windowed { cfg.window_secs } else { 0 };
    let report = evaluate(ledger, &clustering, win);
    (clustering, report)
}
