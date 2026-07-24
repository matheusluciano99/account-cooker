//! `noise-core` — pure privacy-through-noise primitives for the account-cooker workspace.
//!
//! Everything here is deterministic given an RNG and free of any network / Solana
//! dependency, so it can be unit-tested without a validator. The live chain layer
//! (see the `agent-runtime` crate's `live` feature) consumes these primitives.
//!
//! Threat-model note: noise alone is cryptographically weak. These primitives raise
//! the cost of behavioral clustering; they are NOT a substitute for encryption or a
//! shielded pool. See the workspace README threat model.

pub mod decoy;
pub mod split;
pub mod timing;
pub mod types;

pub use types::{AccountId, ActionKind};
