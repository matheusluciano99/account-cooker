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

use std::io;
use std::path::PathBuf;
use std::str::FromStr;
use std::thread;
use std::time::Duration;

use solana_commitment_config::CommitmentConfig;
use solana_sdk::hash::Hash;
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use solana_sdk::signer::keypair::{read_keypair_file, Keypair};
use solana_sdk::signer::Signer;
use solana_sdk::transaction::Transaction;
use solana_stake_interface::instruction as stake_ix;
use solana_stake_interface::state::{Authorized, Lockup};
use solana_system_interface::instruction as system_instruction;
use url::{Host, Url};

/// SPL Memo program (v2). A memo transaction is an ordinary instruction to this program whose
/// data is the UTF-8 note; no value moves and no account is written.
const MEMO_PROGRAM_ID: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
/// Space of a `StakeStateV2` account; its rent-exempt minimum is queried against this.
const STAKE_ACCOUNT_SPACE: usize = 200;
/// Cap on memo bytes, well under the 1232-byte packet limit.
const MEMO_MAX_BYTES: usize = 500;

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
    /// Lamports sent to the ephemeral fee-payer: its action fee plus the rent-exempt minimum
    /// it must retain so the funding transaction is itself valid.
    pub fee_payer_topup_lamports: u64,
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
    /// e.g. `RpcChain::new("https://api.devnet.solana.com")`. Submits at `confirmed`
    /// commitment, the right basis for blockhashes and preflight; `finalized` sits ~32 slots
    /// back, too stale to submit against.
    pub fn new(url: impl Into<String>) -> Self {
        RpcChain {
            client: solana_client::rpc_client::RpcClient::new_with_commitment(
                url.into(),
                CommitmentConfig::confirmed(),
            ),
        }
    }

    pub fn latest_blockhash(&self) -> Result<Hash, DynErr> {
        Ok(self.client.get_latest_blockhash()?)
    }

    fn fee_for(&self, tx: &Transaction) -> Result<u64, DynErr> {
        Ok(self.client.get_fee_for_message(&tx.message)?)
    }

    /// Minimum balance a `data_len`-byte account must hold to be rent-exempt.
    fn min_rent_exempt(&self, data_len: usize) -> Result<u64, DynErr> {
        Ok(self
            .client
            .get_minimum_balance_for_rent_exemption(data_len)?)
    }

    /// Minimum lamports a delegation must carry on this cluster (1 lamport on a bare validator,
    /// 1 SOL on clusters with the raised-minimum feature active, such as devnet/mainnet).
    fn min_stake_delegation(&self) -> Result<u64, DynErr> {
        Ok(self.client.get_stake_minimum_delegation()?)
    }

    /// The current (non-delinquent) vote account with the most stake — a live delegation target
    /// on whatever cluster the RPC points at. Vote accounts differ per cluster, so this is
    /// resolved at runtime rather than hardcoded.
    pub fn pick_vote_account(&self) -> Result<Pubkey, DynErr> {
        let accounts = self.client.get_vote_accounts()?;
        let best = accounts
            .current
            .iter()
            .max_by_key(|v| v.activated_stake)
            .ok_or_else(|| invalid_input("no current vote accounts on this cluster"))?;
        Pubkey::from_str(&best.vote_pubkey)
            .map_err(|error| invalid_input(format!("bad vote pubkey: {error}")))
    }

    /// Submit one immutable transaction, re-sending those exact bytes periodically until it
    /// confirms or its blockhash expires. Re-sending one signed transaction is idempotent (same
    /// signature), so a congested RPC that drops the first send cannot cause a second effect;
    /// once the blockhash can no longer land, the outcome is unambiguous and no rebuild is
    /// attempted.
    fn send_idempotent(&self, tx: &Transaction, status_polls: u32) -> Result<Signature, DynErr> {
        let signature = tx.signatures[0];
        let blockhash = tx.message.recent_blockhash;
        let commitment = CommitmentConfig::confirmed();
        let mut last_send_error = None;
        // Re-send the same bytes every ~2s (a leader may not pick up a single congested send).
        const RESEND_EVERY: u32 = 8;

        for poll in 0..status_polls.max(1) {
            if poll % RESEND_EVERY == 0 {
                if let Err(error) = self.client.send_transaction(tx) {
                    last_send_error = Some(error.to_string());
                }
                if !self.client.is_blockhash_valid(&blockhash, commitment)? {
                    return Err(invalid_input(format!(
                        "transaction {signature} has no confirmed status and its blockhash \
                         expired; refusing to rebuild because the outcome is ambiguous{}",
                        last_send_error
                            .map(|error| format!("; last send error: {error}"))
                            .unwrap_or_default()
                    )));
                }
            }
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
        Err(invalid_input(format!(
            "transaction {signature} was not confirmed after idempotent retries{}",
            last_send_error
                .map(|error| format!("; last send error: {error}"))
                .unwrap_or_default()
        )))
    }
}

/// A real on-chain action the live seam can execute. Adding a protocol = one variant here plus
/// one arm in `plan_action`; the fail-closed funding/limits/submission envelope is shared.
pub enum LiveAction {
    Transfer {
        destination: Pubkey,
        lamports: u64,
    },
    /// Create a stake account and delegate it to `vote`. `lamports` funds the stake account
    /// (its rent-exempt minimum plus the delegated amount).
    Stake {
        vote: Pubkey,
        lamports: u64,
    },
    Memo {
        text: String,
    },
}

impl LiveAction {
    fn kind(&self) -> &'static str {
        match self {
            LiveAction::Transfer { .. } => "transfer",
            LiveAction::Stake { .. } => "stake",
            LiveAction::Memo { .. } => "memo",
        }
    }
}

/// The instructions + signers for one action, plus what the source parts with (its rent/value,
/// excluding the network fee) and the fields the receipt reports.
struct ActionPlan<'a> {
    instructions: Vec<Instruction>,
    /// Signers required beyond the fee-payer (the source, and a stake account for `Stake`).
    extra_signers: Vec<&'a Keypair>,
    source_debit: u64,
    target: Option<String>,
    stake_account: Option<Pubkey>,
}

/// Build the instructions and signer set for an action. The source signs and funds; the
/// fee-payer (added later) only pays the network fee — never a value source or authority.
fn plan_action<'a>(
    action: &LiveAction,
    source: &'a Keypair,
    stake_kp: Option<&'a Keypair>,
) -> Result<ActionPlan<'a>, DynErr> {
    match action {
        LiveAction::Transfer {
            destination,
            lamports,
        } => {
            if source.pubkey() == *destination {
                return Err(invalid_input("source and destination must differ"));
            }
            Ok(ActionPlan {
                instructions: vec![system_instruction::transfer(
                    &source.pubkey(),
                    destination,
                    *lamports,
                )],
                extra_signers: vec![source],
                source_debit: *lamports,
                target: Some(destination.to_string()),
                stake_account: None,
            })
        }
        LiveAction::Stake { vote, lamports } => {
            let stake =
                stake_kp.ok_or_else(|| invalid_input("stake action needs a stake keypair"))?;
            let authorized = Authorized::auto(&source.pubkey());
            let mut instructions = stake_ix::create_account(
                &source.pubkey(),
                &stake.pubkey(),
                &authorized,
                &Lockup::default(),
                *lamports,
            );
            instructions.push(stake_ix::delegate_stake(
                &stake.pubkey(),
                &source.pubkey(),
                vote,
            ));
            Ok(ActionPlan {
                instructions,
                extra_signers: vec![source, stake],
                source_debit: *lamports,
                target: Some(vote.to_string()),
                stake_account: Some(stake.pubkey()),
            })
        }
        LiveAction::Memo { text } => {
            if text.len() > MEMO_MAX_BYTES {
                return Err(invalid_input(format!(
                    "memo is {} bytes, over the {MEMO_MAX_BYTES}-byte cap",
                    text.len()
                )));
            }
            let program_id = Pubkey::from_str(MEMO_PROGRAM_ID)
                .map_err(|error| invalid_input(format!("bad memo program id: {error}")))?;
            // Attributed memo: the source signs, tying the note to it.
            let ix = Instruction::new_with_bytes(
                program_id,
                text.as_bytes(),
                vec![AccountMeta::new_readonly(source.pubkey(), true)],
            );
            Ok(ActionPlan {
                instructions: vec![ix],
                extra_signers: vec![source],
                source_debit: 0,
                target: None,
                stake_account: None,
            })
        }
    }
}

/// Sign an action's instructions with the fee-payer first, then its extra signers (de-duped, so
/// a self-paid action does not list the same key twice).
fn build_action_tx(plan: &ActionPlan, fee_payer: &Keypair, recent_blockhash: Hash) -> Transaction {
    let mut signers: Vec<&Keypair> = vec![fee_payer];
    for signer in &plan.extra_signers {
        if signer.pubkey() != fee_payer.pubkey() {
            signers.push(signer);
        }
    }
    Transaction::new_signed_with_payer(
        &plan.instructions,
        Some(&fee_payer.pubkey()),
        &signers,
        recent_blockhash,
    )
}

/// Config for the general live-action proof — same fail-closed envelope as the transfer path.
#[derive(Clone, Debug)]
pub struct LiveActionConfig {
    pub rpc_url: String,
    pub payer_path: PathBuf,
    pub action: LiveAction,
    pub max_total_debit: u64,
    pub max_fee_payer_topup: u64,
    pub status_polls: u32,
    pub allow_remote_rpc: bool,
    pub execute: bool,
}

impl Clone for LiveAction {
    fn clone(&self) -> Self {
        match self {
            LiveAction::Transfer {
                destination,
                lamports,
            } => LiveAction::Transfer {
                destination: *destination,
                lamports: *lamports,
            },
            LiveAction::Stake { vote, lamports } => LiveAction::Stake {
                vote: *vote,
                lamports: *lamports,
            },
            LiveAction::Memo { text } => LiveAction::Memo { text: text.clone() },
        }
    }
}

impl std::fmt::Debug for LiveAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.kind())
    }
}

impl LiveActionConfig {
    fn validate(&self) -> Result<(), DynErr> {
        if !self.allow_remote_rpc && !is_loopback_rpc(&self.rpc_url) {
            return Err(invalid_input(
                "remote RPC refused; use a loopback URL or explicitly allow remote RPC",
            ));
        }
        if self.status_polls == 0 {
            return Err(invalid_input("status_polls must be greater than zero"));
        }
        if self.max_fee_payer_topup == 0 {
            return Err(invalid_input(
                "max_fee_payer_topup must be greater than zero",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct LiveActionReceipt {
    pub executed: bool,
    pub rpc_url: String,
    pub source: String,
    pub action_kind: String,
    pub target: Option<String>,
    pub stake_account: Option<String>,
    pub ephemeral_fee_payer: String,
    pub source_debit_lamports: u64,
    pub action_fee_lamports: u64,
    pub funding_fee_lamports: u64,
    pub fee_payer_topup_lamports: u64,
    pub required_debit_lamports: u64,
    pub source_balance_before: u64,
    pub funding_signature: Option<String>,
    pub action_signature: Option<String>,
}

/// Quote or execute one real on-chain action, paying its fee from a freshly funded ephemeral
/// fee-payer. Fail-closed: loopback RPC unless overridden, explicit debit/top-up ceilings,
/// quote-only unless `execute`, and idempotent submission of one immutable signed transaction.
/// Never airdrops; the source must already hold funds.
pub fn run_live_action(cfg: &LiveActionConfig) -> Result<LiveActionReceipt, DynErr> {
    cfg.validate()?;
    let source = read_keypair_file(&cfg.payer_path)?;
    let fee_payer = Keypair::new();
    // A stake account is a fresh throwaway that must sign its own creation; mint it once so the
    // quoted and executed transactions are byte-identical (idempotent submission depends on it).
    let stake_kp = matches!(cfg.action, LiveAction::Stake { .. }).then(Keypair::new);
    let chain = RpcChain::new(cfg.rpc_url.clone());

    if let LiveAction::Stake { lamports, .. } = &cfg.action {
        // The stake account must be rent-exempt AND delegate at least the cluster minimum, or
        // the delegate instruction fails on-chain (StakeError::InsufficientDelegation).
        let stake_rent = chain.min_rent_exempt(STAKE_ACCOUNT_SPACE)?;
        let min_delegation = chain.min_stake_delegation()?;
        let required = stake_rent
            .checked_add(min_delegation)
            .ok_or_else(|| invalid_input("stake funding overflow"))?;
        if *lamports < required {
            return Err(invalid_input(format!(
                "stake funding {lamports} is below rent-exempt minimum {stake_rent} + minimum \
                 delegation {min_delegation} = {required}"
            )));
        }
    }

    let plan = plan_action(&cfg.action, &source, stake_kp.as_ref())?;
    let quote_hash = chain.latest_blockhash()?;
    let quoted_action = build_action_tx(&plan, &fee_payer, quote_hash);
    let action_fee = chain.fee_for(&quoted_action)?;

    // Fund the fee-payer with the rent-exempt minimum plus the action fee, so it stays
    // rent-exempt both when created and after it pays for the action.
    let rent_exempt_min = chain.min_rent_exempt(0)?;
    let fee_payer_topup = action_fee
        .checked_add(rent_exempt_min)
        .ok_or_else(|| invalid_input("fee-payer top-up overflow"))?;
    if fee_payer_topup > cfg.max_fee_payer_topup {
        return Err(invalid_input(format!(
            "required fee-payer top-up {fee_payer_topup} exceeds limit {}",
            cfg.max_fee_payer_topup
        )));
    }

    let funding_quote = build_transfer(
        &source,
        &fee_payer.pubkey(),
        fee_payer_topup,
        &source,
        quote_hash,
    );
    let funding_fee = chain.fee_for(&funding_quote)?;
    let required_debit = plan
        .source_debit
        .checked_add(fee_payer_topup)
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

    let mut receipt = LiveActionReceipt {
        executed: cfg.execute,
        rpc_url: cfg.rpc_url.clone(),
        source: source.pubkey().to_string(),
        action_kind: cfg.action.kind().to_string(),
        target: plan.target.clone(),
        stake_account: plan.stake_account.map(|p| p.to_string()),
        ephemeral_fee_payer: fee_payer.pubkey().to_string(),
        source_debit_lamports: plan.source_debit,
        action_fee_lamports: action_fee,
        funding_fee_lamports: funding_fee,
        fee_payer_topup_lamports: fee_payer_topup,
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
        fee_payer_topup,
        &source,
        funding_hash,
    );
    let funding_signature = chain.send_idempotent(&funding_tx, cfg.status_polls)?;

    let action_hash = chain.latest_blockhash()?;
    let action_tx = build_action_tx(&plan, &fee_payer, action_hash);
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

/// Build a `Stake` action, resolving the vote account: parse `vote` when given, else pick the
/// cluster's highest-stake current vote account via the RPC. Keeps pubkey parsing out of callers
/// that do not depend on solana-sdk (e.g. the CLI crate).
pub fn stake_action(
    rpc_url: &str,
    vote: Option<String>,
    lamports: u64,
) -> Result<LiveAction, DynErr> {
    let vote = match vote {
        Some(v) => Pubkey::from_str(&v)
            .map_err(|error| invalid_input(format!("invalid vote pubkey: {error}")))?,
        None => RpcChain::new(rpc_url).pick_vote_account()?,
    };
    Ok(LiveAction::Stake { vote, lamports })
}

/// The SOL-transfer proof, kept as a stable entry point. It is the `Transfer` case of
/// `run_live_action` with a transfer-shaped config and receipt.
pub fn run_live_transfer(cfg: &LiveTransferConfig) -> Result<LiveTransferReceipt, DynErr> {
    let destination = Pubkey::from_str(&cfg.destination)
        .map_err(|error| invalid_input(format!("invalid destination pubkey: {error}")))?;
    let action_cfg = LiveActionConfig {
        rpc_url: cfg.rpc_url.clone(),
        payer_path: cfg.payer_path.clone(),
        action: LiveAction::Transfer {
            destination,
            lamports: cfg.lamports,
        },
        max_total_debit: cfg.max_total_debit,
        max_fee_payer_topup: cfg.max_fee_payer_topup,
        status_polls: cfg.status_polls,
        allow_remote_rpc: cfg.allow_remote_rpc,
        execute: cfg.execute,
    };
    // Preserve the transfer path's own validation (e.g. lamports > 0).
    cfg.validate()?;
    let r = run_live_action(&action_cfg)?;
    Ok(LiveTransferReceipt {
        executed: r.executed,
        rpc_url: r.rpc_url,
        source: r.source,
        destination: r.target.unwrap_or_default(),
        ephemeral_fee_payer: r.ephemeral_fee_payer,
        transfer_lamports: r.source_debit_lamports,
        action_fee_lamports: r.action_fee_lamports,
        funding_fee_lamports: r.funding_fee_lamports,
        fee_payer_topup_lamports: r.fee_payer_topup_lamports,
        required_debit_lamports: r.required_debit_lamports,
        source_balance_before: r.source_balance_before,
        funding_signature: r.funding_signature,
        action_signature: r.action_signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn memo_instruction_is_well_formed() {
        let source = Keypair::new();
        let fee_payer = Keypair::new();
        let plan = plan_action(&LiveAction::Memo { text: "hi".into() }, &source, None).unwrap();
        assert_eq!(plan.source_debit, 0);
        assert_eq!(plan.instructions.len(), 1);
        assert_eq!(
            plan.instructions[0].program_id,
            Pubkey::from_str(MEMO_PROGRAM_ID).unwrap()
        );
        assert_eq!(plan.instructions[0].data, b"hi");
        let tx = build_action_tx(&plan, &fee_payer, Hash::default());
        assert_eq!(
            tx.message.account_keys[0],
            fee_payer.pubkey(),
            "fee-payer first"
        );
        // Distinct fee-payer and source => two signers.
        assert_eq!(tx.signatures.len(), 2);
    }

    #[test]
    fn memo_program_id_is_the_v2_program() {
        let id = Pubkey::from_str(MEMO_PROGRAM_ID).unwrap();
        assert_eq!(
            id.to_string(),
            "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
        );
    }

    #[test]
    fn oversized_memo_is_rejected() {
        let source = Keypair::new();
        let big = "x".repeat(MEMO_MAX_BYTES + 1);
        assert!(plan_action(&LiveAction::Memo { text: big }, &source, None).is_err());
    }

    #[test]
    fn stake_plan_creates_and_delegates() {
        let source = Keypair::new();
        let stake = Keypair::new();
        let fee_payer = Keypair::new();
        let vote = Pubkey::new_unique();
        let plan = plan_action(
            &LiveAction::Stake {
                vote,
                lamports: 3_000_000,
            },
            &source,
            Some(&stake),
        )
        .unwrap();
        // create_account (system create + stake initialize) + delegate == 3 instructions.
        assert_eq!(plan.instructions.len(), 3);
        assert_eq!(plan.source_debit, 3_000_000);
        assert_eq!(plan.stake_account, Some(stake.pubkey()));
        let tx = build_action_tx(&plan, &fee_payer, Hash::default());
        assert_eq!(tx.message.account_keys[0], fee_payer.pubkey());
        // fee-payer + source + stake account all sign.
        assert_eq!(tx.signatures.len(), 3);
    }

    #[test]
    fn stake_requires_a_stake_keypair() {
        let source = Keypair::new();
        let vote = Pubkey::new_unique();
        assert!(plan_action(
            &LiveAction::Stake {
                vote,
                lamports: 3_000_000
            },
            &source,
            None
        )
        .is_err());
    }

    #[test]
    fn self_paid_action_does_not_double_sign() {
        // When the source also pays (transfer funding edge), the signer set has no duplicate.
        let source = Keypair::new();
        let to = Keypair::new().pubkey();
        let plan = plan_action(
            &LiveAction::Transfer {
                destination: to,
                lamports: 1,
            },
            &source,
            None,
        )
        .unwrap();
        let tx = build_action_tx(&plan, &source, Hash::default());
        assert_eq!(tx.signatures.len(), 1, "source == fee-payer signs once");
    }

    #[test]
    fn live_action_config_fails_closed() {
        let cfg = LiveActionConfig {
            rpc_url: "https://api.mainnet-beta.solana.com".into(),
            payer_path: "unused.json".into(),
            action: LiveAction::Memo { text: "x".into() },
            max_total_debit: 5_000_000,
            max_fee_payer_topup: 2_000_000,
            status_polls: 20,
            allow_remote_rpc: false,
            execute: false,
        };
        assert!(cfg.validate().is_err(), "remote RPC must be opt-in");
        let zero_polls = LiveActionConfig {
            rpc_url: "http://127.0.0.1:8899".into(),
            status_polls: 0,
            ..cfg.clone()
        };
        assert!(zero_polls.validate().is_err());
    }
}
