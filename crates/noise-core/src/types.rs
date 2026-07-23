//! Shared domain types used across every crate.

use rand::Rng;
use serde::{Deserialize, Serialize};

/// A 32-byte account identifier. In `live` mode this maps 1:1 onto a Solana `Pubkey`;
/// in the offline simulator it is just random bytes so the analysis layer is identical.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AccountId(pub [u8; 32]);

impl AccountId {
    /// Fresh random account id.
    pub fn random(rng: &mut impl Rng) -> Self {
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        AccountId(b)
    }

    /// Short, human-readable form for logs and reports (`aabb..yyzz`).
    pub fn short(&self) -> String {
        let h = &self.0;
        format!("{:02x}{:02x}..{:02x}{:02x}", h[0], h[1], h[30], h[31])
    }
}

impl std::fmt::Debug for AccountId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.short())
    }
}

impl std::fmt::Display for AccountId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.short())
    }
}

/// The class of on-chain action an agent can perform. Kept protocol-agnostic; concrete
/// protocols are plugged in via the `ProtocolAdapter` trait in the `adapters` crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    Transfer,
    Stake,
    Swap,
    Memo,
    Dust,
    Consolidate,
}

impl ActionKind {
    /// Stable string key, used in persona TOML weight tables.
    pub fn key(&self) -> &'static str {
        match self {
            ActionKind::Transfer => "transfer",
            ActionKind::Stake => "stake",
            ActionKind::Swap => "swap",
            ActionKind::Memo => "memo",
            ActionKind::Dust => "dust",
            ActionKind::Consolidate => "consolidate",
        }
    }

    /// Parse from a persona weight-table key.
    pub fn from_key(s: &str) -> Option<ActionKind> {
        Some(match s {
            "transfer" => ActionKind::Transfer,
            "stake" => ActionKind::Stake,
            "swap" => ActionKind::Swap,
            "memo" => ActionKind::Memo,
            "dust" => ActionKind::Dust,
            "consolidate" => ActionKind::Consolidate,
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn account_id_is_stable_and_short() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(1);
        let a = AccountId::random(&mut rng);
        assert_eq!(a.short().len(), 10); // "aabb..yyzz"
        assert_eq!(a, a);
    }

    #[test]
    fn action_kind_key_roundtrips() {
        for k in [
            ActionKind::Transfer,
            ActionKind::Stake,
            ActionKind::Swap,
            ActionKind::Memo,
            ActionKind::Dust,
            ActionKind::Consolidate,
        ] {
            assert_eq!(ActionKind::from_key(k.key()), Some(k));
        }
    }
}
