//! `hunter` — "O Cacador" (the Hunter).
//!
//! An adversarial chain-analysis harness. It runs the same clustering heuristics a
//! real de-anonymization firm would, then MEASURES how well it recovered the truth.
//! Run it against a baseline (naive) ledger and against a Curupira ledger to get the
//! before/after numbers that turn "privacy through noise" into a defensible claim.

pub mod heuristics;
pub mod metric;
pub mod model;

pub use heuristics::{cluster, AdversaryConfig, Clustering};
pub use metric::{evaluate, Report};
pub use model::{AgentId, Ledger, TxRecord};

/// Convenience: cluster a ledger and score it in one call.
pub fn analyze(ledger: &Ledger, cfg: &AdversaryConfig) -> (Clustering, Report) {
    let clustering = cluster(ledger, cfg);
    let report = evaluate(ledger, &clustering);
    (clustering, report)
}
