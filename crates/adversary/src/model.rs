//! The observable ledger and its ground truth.

use noise_core::types::{AccountId, ActionKind};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};

pub type AgentId = u32;

/// One recorded transaction, exactly as an on-chain observer would see it — PLUS a
/// ground-truth `operator` label that the adversary is forbidden to read. The label
/// exists only so the metric layer can score how well the adversary recovered reality.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxRecord {
    pub sig: u64,
    pub slot: u64,
    pub ts: i64,
    pub fee_payer: AccountId,
    pub source: AccountId,
    pub dest: AccountId,
    pub amount: u64,
    pub kind: ActionKind,
    /// GROUND TRUTH ONLY — never an input to any heuristic.
    pub operator: Option<AgentId>,
}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct Ledger {
    pub records: Vec<TxRecord>,
}

impl Ledger {
    /// Every distinct account that appears anywhere in the ledger.
    pub fn accounts(&self) -> BTreeSet<AccountId> {
        let mut s = BTreeSet::new();
        for r in &self.records {
            s.insert(r.fee_payer);
            s.insert(r.source);
            s.insert(r.dest);
        }
        s
    }

    /// Ground-truth ownership: which operator controls each account. An operator
    /// controls the accounts it *signs from* (`source`). Fee-payers and external
    /// counterparties are intentionally excluded — they are not proof of ownership.
    pub fn ownership(&self) -> HashMap<AccountId, AgentId> {
        let mut m = HashMap::new();
        for r in &self.records {
            if let Some(op) = r.operator {
                m.insert(r.source, op);
            }
        }
        m
    }
}
