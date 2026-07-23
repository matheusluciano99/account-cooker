//! `live` — the real Solana execution seam (enabled with `--features live`).
//!
//! The offline simulator proves the behavior and MEASURES it. This module is where the
//! same behavior hits a real cluster: it maps simulator `AccountId`s (which are just
//! 32-byte pubkeys) to real `Keypair`s, assembles signed transactions, and submits them
//! via RPC.
//!
//! The public `run_live_transfer` path is intentionally narrow and fail-closed: loopback
//! RPC only unless explicitly overridden, hard debit/top-up limits, a freshly funded
//! fee-payer, and idempotent retries of the exact same signed transaction.

use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::str::FromStr;
use std::thread;
use std::time::Duration;

use solana_commitment_config::CommitmentConfig;
use solana_sdk::hash::Hash;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use solana_sdk::signer::keypair::{read_keypair_file, Keypair};
use solana_sdk::signer::Signer;
use solana_sdk::transaction::Transaction;
use solana_system_interface::instruction as system_instruction;
use url::{Host, Url};

use noise_core::types::AccountId;

type DynErr = Box<dyn std::error::Error>;

fn invalid_input(message: impl Into<String>) -> DynErr {
    Box::new(io::Error::new(io::ErrorKind::InvalidInput, message.into()))
}

/// Hard limits and retry behavior for the deliberately small live proof.
#[derive(Clone, Debug)]
pub struct LiveTransferConfig {
    pub rpc_url: String,
    pub payer_path: PathBuf,
    pub destination: String,
    pub lamports: u64,
    pub max_total_debit: u64,
    pub max_fee_payer_topup: u64,
    pub status_polls: u32,
    pub allow_remote_rpc: bool,
    /// `false` produces an RPC-backed quote without submitting transactions.
    pub execute: bool,
}

impl LiveTransferConfig {
    pub fn validate(&self) -> Result<(), DynErr> {
        if !self.allow_remote_rpc && !is_loopback_rpc(&self.rpc_url) {
            return Err(invalid_input(
                "remote RPC refused; use a loopback URL or explicitly allow remote RPC",
            ));
        }
        if self.lamports == 0 {
            return Err(invalid_input("lamports must be greater than zero"));
        }
        if self.max_total_debit < self.lamports {
            return Err(invalid_input(
                "max_total_debit must be at least the transfer amount",
            ));
        }
        if self.max_fee_payer_topup == 0 {
            return Err(invalid_input(
                "max_fee_payer_topup must be greater than zero",
            ));
        }
        if self.status_polls == 0 {
            return Err(invalid_input("status_polls must be greater than zero"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct LiveTransferReceipt {
    pub executed: bool,
    pub rpc_url: String,
    pub source: String,
    pub destination: String,
    pub ephemeral_fee_payer: String,
    pub transfer_lamports: u64,
    pub action_fee_lamports: u64,
    pub funding_fee_lamports: u64,
    pub required_debit_lamports: u64,
    pub source_balance_before: u64,
    pub funding_signature: Option<String>,
    pub action_signature: Option<String>,
}

pub fn is_loopback_rpc(url: &str) -> bool {
    let Ok(parsed) = Url::parse(url.trim()) else {
        return false;
    };
    if !matches!(parsed.scheme(), "http" | "https") {
        return false;
    }
    match parsed.host() {
        Some(Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

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

    fn fee_for(&self, tx: &Transaction) -> Result<u64, DynErr> {
        Ok(self.client.get_fee_for_message(&tx.message)?)
    }

    /// Submit one immutable transaction and retry only those exact bytes/signature. This
    /// makes transport retries idempotent: a delayed first response cannot create a second
    /// transfer. If the blockhash expires without a status, the outcome is returned as an
    /// error instead of silently rebuilding a new transaction.
    fn send_idempotent(&self, tx: &Transaction, status_polls: u32) -> Result<Signature, DynErr> {
        let signature = tx.signatures[0];
        let blockhash = tx.message.recent_blockhash;
        let commitment = CommitmentConfig::confirmed();
        let mut last_send_error = None;

        for _attempt in 0..3 {
            if let Err(error) = self.client.send_transaction(tx) {
                last_send_error = Some(error.to_string());
            }
            for _poll in 0..status_polls {
                let statuses = self.client.get_signature_statuses(&[signature])?.value;
                if let Some(status) = &statuses[0] {
                    if let Some(error) = &status.err {
                        return Err(invalid_input(format!(
                            "transaction {signature} failed: {error:?}"
                        )));
                    }
                    if status.satisfies_commitment(commitment) {
                        return Ok(signature);
                    }
                }
                thread::sleep(Duration::from_millis(250));
            }
            if !self.client.is_blockhash_valid(&blockhash, commitment)? {
                return Err(invalid_input(format!(
                    "transaction {signature} has no confirmed status and its blockhash expired; \
                     refusing to rebuild because the outcome is ambiguous"
                )));
            }
        }
        Err(invalid_input(format!(
            "transaction {signature} was not confirmed after idempotent retries{}",
            last_send_error
                .map(|error| format!("; last send error: {error}"))
                .unwrap_or_default()
        )))
    }

    /// Submit and confirm a transfer. `fee_payer` must be funded on-chain.
    ///
    /// This low-level method assumes the caller has already funded `fee_payer`. The safer
    /// public CLI proof uses `run_live_transfer`, which quotes the fee, applies spend limits,
    /// funds a fresh payer, and retries immutable signed bytes.
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

/// Quote or execute one real SOL transfer with a freshly funded fee-payer. This is the
/// production seam used by the CLI's `live-transfer` proof; it never airdrops, never creates
/// a remote-network default, and never exceeds the caller's explicit debit ceilings.
pub fn run_live_transfer(cfg: &LiveTransferConfig) -> Result<LiveTransferReceipt, DynErr> {
    cfg.validate()?;
    let source = read_keypair_file(&cfg.payer_path)?;
    let destination = Pubkey::from_str(&cfg.destination)
        .map_err(|error| invalid_input(format!("invalid destination pubkey: {error}")))?;
    if source.pubkey() == destination {
        return Err(invalid_input("source and destination must differ"));
    }

    let fee_payer = Keypair::new();
    let chain = RpcChain::new(cfg.rpc_url.clone());
    let quote_hash = chain.latest_blockhash()?;
    let quoted_action = build_transfer(&source, &destination, cfg.lamports, &fee_payer, quote_hash);
    let action_fee = chain.fee_for(&quoted_action)?;
    if action_fee > cfg.max_fee_payer_topup {
        return Err(invalid_input(format!(
            "required fee-payer top-up {action_fee} exceeds limit {}",
            cfg.max_fee_payer_topup
        )));
    }

    let funding_quote = build_transfer(
        &source,
        &fee_payer.pubkey(),
        action_fee,
        &source,
        quote_hash,
    );
    let funding_fee = chain.fee_for(&funding_quote)?;
    let required_debit = cfg
        .lamports
        .checked_add(action_fee)
        .and_then(|value| value.checked_add(funding_fee))
        .ok_or_else(|| invalid_input("required debit overflow"))?;
    if required_debit > cfg.max_total_debit {
        return Err(invalid_input(format!(
            "required debit {required_debit} exceeds limit {}",
            cfg.max_total_debit
        )));
    }
    let source_balance = chain.client.get_balance(&source.pubkey())?;
    if source_balance < required_debit {
        return Err(invalid_input(format!(
            "source balance {source_balance} is below required debit {required_debit}"
        )));
    }

    let mut receipt = LiveTransferReceipt {
        executed: cfg.execute,
        rpc_url: cfg.rpc_url.clone(),
        source: source.pubkey().to_string(),
        destination: destination.to_string(),
        ephemeral_fee_payer: fee_payer.pubkey().to_string(),
        transfer_lamports: cfg.lamports,
        action_fee_lamports: action_fee,
        funding_fee_lamports: funding_fee,
        required_debit_lamports: required_debit,
        source_balance_before: source_balance,
        funding_signature: None,
        action_signature: None,
    };
    if !cfg.execute {
        return Ok(receipt);
    }

    let funding_hash = chain.latest_blockhash()?;
    let funding_tx = build_transfer(
        &source,
        &fee_payer.pubkey(),
        action_fee,
        &source,
        funding_hash,
    );
    let funding_signature = chain.send_idempotent(&funding_tx, cfg.status_polls)?;

    let action_hash = chain.latest_blockhash()?;
    let action_tx = build_transfer(&source, &destination, cfg.lamports, &fee_payer, action_hash);
    let actual_action_fee = chain.fee_for(&action_tx)?;
    if actual_action_fee > action_fee {
        return Err(invalid_input(format!(
            "action fee increased from {action_fee} to {actual_action_fee} after funding; \
             refusing an underfunded submission"
        )));
    }
    let action_signature = chain.send_idempotent(&action_tx, cfg.status_polls)?;
    receipt.funding_signature = Some(funding_signature.to_string());
    receipt.action_signature = Some(action_signature.to_string());
    Ok(receipt)
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

    #[test]
    fn live_limits_fail_closed() {
        let base = LiveTransferConfig {
            rpc_url: "https://api.mainnet-beta.solana.com".into(),
            payer_path: "unused.json".into(),
            destination: Pubkey::new_unique().to_string(),
            lamports: 1,
            max_total_debit: 100_000,
            max_fee_payer_topup: 50_000,
            status_polls: 10,
            allow_remote_rpc: false,
            execute: false,
        };
        assert!(base.validate().is_err(), "remote RPC must be opt-in");
        assert!(is_loopback_rpc("http://127.0.0.1:8899"));
        assert!(is_loopback_rpc("http://localhost:8899"));
        assert!(is_loopback_rpc("http://[::1]:8899"));
        assert!(!is_loopback_rpc("ftp://127.0.0.1:8899"));
        assert!(!is_loopback_rpc("http://localhost:8899@evil.example"));
        assert!(!is_loopback_rpc("not a URL"));

        let too_small = LiveTransferConfig {
            rpc_url: "http://127.0.0.1:8899".into(),
            max_total_debit: 0,
            ..base
        };
        assert!(too_small.validate().is_err());
    }
}
