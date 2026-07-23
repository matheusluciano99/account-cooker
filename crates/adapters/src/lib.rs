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

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    fn account(byte: u8) -> AccountId {
        AccountId([byte; 32])
    }

    #[test]
    fn built_in_adapters_preserve_the_intent_shape() {
        let ctx = ActionContext {
            source: account(1),
            counterparty: account(2),
            amount: 42_000,
        };
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);

        for kind in [ActionKind::Transfer, ActionKind::Stake, ActionKind::Swap] {
            let adapter = adapter_for(kind);
            assert_eq!(adapter.kind(), kind);
            let planned = adapter.plan(&ctx, &mut rng);
            assert_eq!(planned.len(), 1);
            assert_eq!(planned[0].source, ctx.source);
            assert_eq!(planned[0].dest, ctx.counterparty);
            assert_eq!(planned[0].amount, ctx.amount);
            assert_eq!(planned[0].kind, kind);
        }
    }

    #[test]
    fn memo_is_a_zero_value_self_intent() {
        let ctx = ActionContext {
            source: account(1),
            counterparty: account(2),
            amount: 42_000,
        };
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        let adapter = adapter_for(ActionKind::Memo);
        let planned = adapter.plan(&ctx, &mut rng);

        assert_eq!(adapter.kind(), ActionKind::Memo);
        assert_eq!(planned.len(), 1);
        assert_eq!(planned[0].source, ctx.source);
        assert_eq!(planned[0].dest, ctx.source);
        assert_eq!(planned[0].amount, 0);
        assert_eq!(planned[0].kind, ActionKind::Memo);
    }

    #[test]
    fn internal_value_moves_use_the_transfer_planner() {
        let ctx = ActionContext {
            source: account(1),
            counterparty: account(2),
            amount: 10,
        };
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);

        for kind in [ActionKind::Dust, ActionKind::Consolidate] {
            let adapter = adapter_for(kind);
            let planned = adapter.plan(&ctx, &mut rng);
            assert_eq!(adapter.kind(), ActionKind::Transfer);
            assert_eq!(planned[0].kind, ActionKind::Transfer);
        }
    }
}
