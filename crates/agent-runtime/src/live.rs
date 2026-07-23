//! `live` — the real Solana execution seam (enabled with `--features live`).
//!
//! The offline simulator proves the behavior and MEASURES it. This module is where the
//! same behavior hits a real cluster: it maps simulator `AccountId`s (which are just
//! 32-byte pubkeys) to real `Keypair`s, assembles signed transactions, and submits them
//! via RPC.
//!
//! Status: transaction assembly and RPC submission are implemented against solana-sdk
//! 4.x. Wiring the orchestrator's `perform_action` loop through here (funding throwaway
//! fee-payers, retries, priority fees, real protocol adapters) is the next step — the
//! seams are marked with `TODO(live)`.

use std::collections::HashMap;

use solana_sdk::hash::Hash;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use solana_sdk::signer::keypair::Keypair;
use solana_sdk::signer::Signer;
use solana_sdk::transaction::Transaction;
use solana_system_interface::instruction as system_instruction;

use noise_core::types::AccountId;

type DynErr = Box<dyn std::error::Error>;

/// Maps a simulator `AccountId` (a pubkey) to the `Keypair` that controls it, so the
/// orchestrator can keep operating on `AccountId`s while the live layer signs for real.
#[derive(Default)]
pub struct KeyStore {
    keys: HashMap<AccountId, Keypair>,
}

impl KeyStore {
    /// Register a keypair and return the `AccountId` (its pubkey) the rest of the system uses.
    pub fn insert(&mut self, kp: Keypair) -> AccountId {
        let id = AccountId(kp.pubkey().to_bytes());
        self.keys.insert(id, kp);
        id
    }

    /// Generate, register, and return a fresh throwaway account (e.g. a one-time fee-payer).
    pub fn fresh(&mut self) -> AccountId {
        self.insert(Keypair::new())
    }

    pub fn get(&self, id: &AccountId) -> Option<&Keypair> {
        self.keys.get(id)
    }

    /// The on-chain pubkey for an `AccountId`, no secret required.
    pub fn pubkey(id: &AccountId) -> Pubkey {
        Pubkey::new_from_array(id.0)
    }
}

/// Assemble a signed SOL transfer `from -> to` for `lamports`, with fees paid by `fee_payer`
/// (which may differ from `from` — that is the whole point of fee-payer rotation).
pub fn build_transfer(
    from: &Keypair,
    to: &Pubkey,
    lamports: u64,
    fee_payer: &Keypair,
    recent_blockhash: Hash,
) -> Transaction {
    let ix = system_instruction::transfer(&from.pubkey(), to, lamports);
    if from.pubkey() == fee_payer.pubkey() {
        Transaction::new_signed_with_payer(
            &[ix],
            Some(&fee_payer.pubkey()),
            &[from],
            recent_blockhash,
        )
    } else {
        Transaction::new_signed_with_payer(
            &[ix],
            Some(&fee_payer.pubkey()),
            &[fee_payer, from],
            recent_blockhash,
        )
    }
}

/// A thin RPC-backed chain. In `live` mode this replaces `MockChain` as the sink.
pub struct RpcChain {
    client: solana_client::rpc_client::RpcClient,
}

impl RpcChain {
    /// e.g. `RpcChain::new("https://api.devnet.solana.com")`.
    pub fn new(url: impl Into<String>) -> Self {
        RpcChain {
            client: solana_client::rpc_client::RpcClient::new(url.into()),
        }
    }

    pub fn latest_blockhash(&self) -> Result<Hash, DynErr> {
        Ok(self.client.get_latest_blockhash()?)
    }

    /// Submit and confirm a transfer. `fee_payer` must be funded on-chain.
    ///
    /// TODO(live): the orchestrator must fund each throwaway fee-payer before use (a
    /// small airdrop on devnet, or a sweep from a funded source on mainnet), batch with
    /// priority fees, and retry on blockhash expiry.
    pub fn send_transfer(
        &self,
        from: &Keypair,
        to: &Pubkey,
        lamports: u64,
        fee_payer: &Keypair,
    ) -> Result<Signature, DynErr> {
        let bh = self.latest_blockhash()?;
        let tx = build_transfer(from, to, lamports, fee_payer, bh);
        Ok(self.client.send_and_confirm_transaction(&tx)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keystore_roundtrips_pubkey() {
        let mut ks = KeyStore::default();
        let id = ks.fresh();
        let kp = ks.get(&id).unwrap();
        assert_eq!(KeyStore::pubkey(&id), kp.pubkey());
    }

    #[test]
    fn transfer_is_signed_and_addressed() {
        let from = Keypair::new();
        let to = Keypair::new().pubkey();
        let fee_payer = Keypair::new();
        let tx = build_transfer(&from, &to, 1_000, &fee_payer, Hash::default());
        // Fee-payer is the first account and the tx carries signatures.
        assert_eq!(tx.message.account_keys[0], fee_payer.pubkey());
        assert!(!tx.signatures.is_empty());
    }
}
