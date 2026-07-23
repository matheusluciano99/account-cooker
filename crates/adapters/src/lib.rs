//! Protocol adapters produce the *real intent* transaction(s) for an action. The
//! runtime then wraps them with noise (splitting, fee-payer rotation, decoys).
//!
//! Extensibility is the point: integrating a new Solana protocol = implementing
//! `ProtocolAdapter` once. In `live` mode each adapter builds real Solana instructions;
//! here it emits protocol-agnostic `PlannedTx`es so the logic is testable offline.

use noise_core::types::{AccountId, ActionKind};
use rand::Rng;

/// A single intended transfer of value from `source` to `dest`.
#[derive(Clone, Debug)]
pub struct PlannedTx {
    pub source: AccountId,
    pub dest: AccountId,
    pub amount: u64,
    pub kind: ActionKind,
}

/// Everything an adapter needs to plan an action.
pub struct ActionContext {
    /// The sub-account initiating the action.
    pub source: AccountId,
    /// The external protocol/counterparty account being interacted with.
    pub counterparty: AccountId,
    /// Intended value (lamports).
    pub amount: u64,
}

/// Implement once per protocol. Object-safe so the runtime can hold `Box<dyn ...>`.
pub trait ProtocolAdapter {
    fn kind(&self) -> ActionKind;
    fn plan(&self, ctx: &ActionContext, rng: &mut dyn Rng) -> Vec<PlannedTx>;
}

pub struct TransferAdapter;
impl ProtocolAdapter for TransferAdapter {
    fn kind(&self) -> ActionKind {
        ActionKind::Transfer
    }
    fn plan(&self, ctx: &ActionContext, _rng: &mut dyn Rng) -> Vec<PlannedTx> {
        vec![PlannedTx {
            source: ctx.source,
            dest: ctx.counterparty,
            amount: ctx.amount,
            kind: ActionKind::Transfer,
        }]
    }
}

pub struct StakeAdapter;
impl ProtocolAdapter for StakeAdapter {
    fn kind(&self) -> ActionKind {
        ActionKind::Stake
    }
    fn plan(&self, ctx: &ActionContext, _rng: &mut dyn Rng) -> Vec<PlannedTx> {
        // Delegating stake moves value from the sub-account into a stake account.
        vec![PlannedTx {
            source: ctx.source,
            dest: ctx.counterparty,
            amount: ctx.amount,
            kind: ActionKind::Stake,
        }]
    }
}

pub struct SwapAdapter;
impl ProtocolAdapter for SwapAdapter {
    fn kind(&self) -> ActionKind {
        ActionKind::Swap
    }
    fn plan(&self, ctx: &ActionContext, _rng: &mut dyn Rng) -> Vec<PlannedTx> {
        vec![PlannedTx {
            source: ctx.source,
            dest: ctx.counterparty,
            amount: ctx.amount,
            kind: ActionKind::Swap,
        }]
    }
}

pub struct MemoAdapter;
impl ProtocolAdapter for MemoAdapter {
    fn kind(&self) -> ActionKind {
        ActionKind::Memo
    }
    fn plan(&self, ctx: &ActionContext, _rng: &mut dyn Rng) -> Vec<PlannedTx> {
        // A memo carries no value; amount is zeroed.
        vec![PlannedTx {
            source: ctx.source,
            dest: ctx.source,
            amount: 0,
            kind: ActionKind::Memo,
        }]
    }
}

/// Dispatch to a built-in adapter for the given kind.
pub fn adapter_for(kind: ActionKind) -> Box<dyn ProtocolAdapter> {
    match kind {
        ActionKind::Stake => Box::new(StakeAdapter),
        ActionKind::Swap => Box::new(SwapAdapter),
        ActionKind::Memo => Box::new(MemoAdapter),
        // Transfer, Dust, Consolidate are value moves handled as transfers.
        _ => Box::new(TransferAdapter),
    }
}
