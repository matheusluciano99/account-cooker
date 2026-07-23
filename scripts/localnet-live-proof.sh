#!/usr/bin/env bash
set -euo pipefail

rpc_url="${CURUPIRA_RPC_URL:-http://127.0.0.1:8899}"
if [[ ! "$rpc_url" =~ ^http://(127\.0\.0\.1|localhost|\[::1\]):[0-9]+/?$ ]]; then
  echo "CURUPIRA_RPC_URL must be a plain loopback HTTP endpoint" >&2
  exit 1
fi
proof_dir="$(mktemp -d "${TMPDIR:-/tmp}/curupira-live-proof.XXXXXX")"
trap 'rm -rf -- "$proof_dir"' EXIT

for required_command in solana solana-keygen cargo jq; do
  if ! command -v "$required_command" >/dev/null 2>&1; then
    echo "missing required command: $required_command" >&2
    exit 1
  fi
done

payer="$proof_dir/payer.json"
destination_key="$proof_dir/destination.json"
receipt="$proof_dir/receipt.json"

solana-keygen new --no-bip39-passphrase --silent --force --outfile "$payer"
solana-keygen new --no-bip39-passphrase --silent --force --outfile "$destination_key"
destination="$(solana-keygen pubkey "$destination_key")"

solana airdrop 2 "$(solana-keygen pubkey "$payer")" --url "$rpc_url" >/dev/null

# Wait for the airdrop to finalize (the tool reads balance at finalized commitment).
for _ in $(seq 1 60); do
  finalized="$(solana balance "$(solana-keygen pubkey "$payer")" --lamports \
    --commitment finalized --url "$rpc_url" | awk '{print $1}')"
  [[ "${finalized:-0}" -ge 2000000000 ]] && break
  sleep 1
done

# The fee-payer top-up must cover the rent-exempt minimum (~0.0009 SOL) plus the action fee,
# so the ceilings are set above that rather than at a bare fee.
cargo run --quiet --features live --bin curupira -- live-transfer \
  --rpc-url "$rpc_url" \
  --payer "$payer" \
  --destination "$destination" \
  --lamports 1000000 \
  --max-total-debit 5000000 \
  --max-fee-payer-topup 2000000 \
  --execute >"$receipt"

jq -e '
  .executed == true
  and (.funding_signature | type == "string")
  and (.action_signature | type == "string")
' "$receipt" >/dev/null

destination_balance="$(solana balance "$destination" --lamports --url "$rpc_url" | awk '{print $1}')"
if [[ "$destination_balance" -ne 1000000 ]]; then
  echo "unexpected destination balance: $destination_balance" >&2
  exit 1
fi

echo "live proof passed: destination=$destination balance=$destination_balance"
jq '{funding_signature, action_signature, ephemeral_fee_payer, fee_payer_topup_lamports, required_debit_lamports}' "$receipt"
