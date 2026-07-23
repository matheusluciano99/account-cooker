# Project context — Curupira

Contribution to the **Superteam Brasil `account-cooker`** bounty ("Build Privacy-Through-Noise
tooling for Solana"). Rust, MIT. See `README.md` for the full pitch and threat model.

**Curupira** = a believable-activity engine that fabricates human-like on-chain behavior at
scale, paired with **O Caçador** ("the Hunter"), an adversarial harness that *measures* how much
that activity degrades wallet clustering/attribution. The thesis: **measure privacy, don't
promise it.**

## Workspace layout

Cargo workspace, `crates/`:

- `noise-core` — pure primitives: value splitting, circadian/Poisson timing, ephemeral/stealth
  address derivation (curve25519), decoy policy. No network deps.
- `persona` — declarative behavior profiles (retail/whale/market-maker) in TOML.
- `hunter` — **O Caçador**: clustering heuristics (fee-payer, co-spend, peel-chain) + metrics
  `attribution_f1` / `linkage_recall` / `fragmentation`.
- `adapters` — `ProtocolAdapter` trait + Transfer/Stake/Swap/Memo (new protocol = 1 impl).
- `agent-runtime` — fleet orchestrator; `MockChain` (offline, deterministic) by default; real
  Solana behind `--features live` (solana-sdk 4.x, `src/live.rs`).
- `cli` (`curupira` binary) — `demo` / `dump` / `report` / `personas`.

## Commands

```bash
cargo test                                # 15 tests, pure logic, no network
cargo run --bin curupira -- demo          # naive vs Curupira before/after table
cargo build --features live               # real Solana integration (compiles; ~1min)
cargo fmt --all --check && cargo clippy --all-targets -- -D warnings
```

## Design constraints (do not violate)

- **Rust only**, **MIT**, production-grade — the bounty is explicit about this.
- **Do NOT depend on Token-2022 Confidential Transfers / the ZK ElGamal Proof Program** — it has
  been disabled on mainnet/devnet since June 2025. Demos must run on localnet/devnet without it.
- **Fee-payer rotation is mandatory** — a static fee-payer defeats the whole point (it's the
  strongest clustering signal). Never let a stable fee-payer pay for an operator's accounts.
- **Not a mixer.** Curupira fabricates activity; it never pools or hides user funds. Keep the
  anti-surveillance framing and the honest threat model in the README.
- **Be honest in metrics.** O Caçador currently uses deterministic heuristics only; a perfect
  attribution-F1 of 0.00 is optimistic. Don't overclaim — that honesty is a credibility signal.

## Roadmap

1. O Caçador v2: transaction-graph connectivity + ML clustering (honest, non-zero numbers).
2. Wire the `live` loop: fund throwaway fee-payers, priority fees, retries; real devnet adapters.
3. Open the PR on the upstream `github.com/solanabr/account-cooker` (repos exist; currently MIT-only).

## Working context / status / strategy

Full status, decisions, deadline, and prioritized next steps: **`.dev-notes/RESUME.md`** (local,
gitignored). Cross-session memory (if available): `~/.claude/projects/-home-godofthemast/memory/bounties-superteam-earn.md`.
