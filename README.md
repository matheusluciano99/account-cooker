# Curupira 🦶‍🔄

**A believable-activity engine for Solana — with an adversarial harness that _measures_ how much it actually defeats wallet clustering.**

> Contribution to the Superteam Brasil [`account-cooker`](https://github.com/solanabr) bounty
> ("Build Privacy-Through-Noise tooling for Solana"). Rust, end-to-end, MIT.

_Curupira_ is the Brazilian folklore creature whose feet point backwards to send trackers the wrong way — which is exactly what this tool does to on-chain trackers.

---

## The problem

On a public ledger every action is legible. Analytics firms and MEV bots cluster wallets,
attribute identity, and front-run intent in real time. `account-cooker` fights this by
drowning your real activity in a sea of _believable_ synthetic activity, so attribution
and clustering become genuinely hard.

The catch, and the reason most "privacy through noise" is snake oil: **noise is
cryptographically weak and statistically attackable.** Naive randomness gives a false
sense of security. So Curupira ships two things that reinforce each other:

1. **A believable-activity engine** — personas with human timing, split payments, rotating
   fee-payers, decoys.
2. **O Caçador ("the Hunter")** — an adversarial harness that runs the same heuristics a
   real de-anonymization firm would, and **puts a number on how linkable your fleet is,
   before and after.** No number, no claim.

## What the demo shows

```
$ cargo run --bin curupira -- demo --agents 12 --days 3 --seed 1

  Curupira — believable activity vs adversarial attribution (O Cacador)
  seed=1  agents=12  days=3

                                   NAIVE    CURUPIRA
  transactions                      1895        7095
  distinct accounts                  112        7306
  adversary clusters                  52         211
  --------------------------------------------------
  attribution F1  (down)            1.00        0.00
  linkage recall  (down)            1.00        0.00
  fragmentation   (up)              1.00        6.00

  Verdict: attribution F1 1.00 -> 0.00 (-100%). The observer that pinned
  each account to one operator no longer can. Noise measured, not promised.
```

**Read this honestly:** F1 → 0.00 means the adversary's _current_ heuristics
(fee-payer linkage, co-spend/consolidation, peel-chain amount+timing correlation) are
fully defeated. It does **not** mean Curupira is unbreakable — O Caçador does not yet
include graph-connectivity or ML behavioral analysis, and the fee-payer rotation shown
here has a real funding cost. See the [threat model](#threat-model). The point of the
harness is precisely to keep the tool honest as the adversary gets stronger.

## Architecture

A Cargo workspace. The interesting, privacy-relevant logic is **pure and unit-tested**;
the chain integration is isolated behind a feature flag.

| crate | role | deps |
|---|---|---|
| `noise-core` | value splitting, human (circadian/Poisson) timing, ephemeral/stealth address derivation (curve25519), decoy policy | pure |
| `persona` | declarative behavior profiles (retail / whale / market-maker) in TOML | pure |
| `hunter` | **O Caçador** — clustering heuristics + `attribution_f1` / `linkage_recall` / `fragmentation` metrics | pure |
| `adapters` | `ProtocolAdapter` trait + Transfer/Stake/Swap/Memo. New protocol = one impl | pure |
| `agent-runtime` | fleet orchestrator; `MockChain` (offline, deterministic) by default, real Solana under `--features live` | rand |
| `curupira-cli` | `demo` / `dump` / `report` / `personas` | clap |

Because the simulator is deterministic (seeded) and offline, **the whole before/after
demo is reproducible on any machine with no validator** — the property judges love.

## Quickstart

```bash
cargo test                          # 15 tests, pure logic — no network needed
cargo run --bin curupira -- demo    # the before/after money-shot above

# export the built-in personas and tweak them (the "trivially customizable" part)
cargo run --bin curupira -- personas --out-dir personas

# dump an observable ledger and score it independently
cargo run --bin curupira -- dump --mode curupira --out ledger.json
cargo run --bin curupira -- report --ledger ledger.json
```

### Live mode (real Solana)

```bash
cargo build --features live         # pulls solana-sdk / solana-client (compiles clean)
```

`agent-runtime::live` maps simulator `AccountId`s to real `Keypair`s, assembles signed
SOL transfers with an arbitrary fee-payer, and submits them via RPC. Wiring the fleet
loop through it (funding throwaway fee-payers, priority fees, retries, real protocol
adapters) is the tracked next step — see `TODO(live)` markers.

## How O Caçador scores (metric definitions)

Every `TxRecord` carries a ground-truth `operator` label that **the adversary never
reads**; it exists only so we can score the adversary's guess.

- **attribution F1** (↓ better) — pairwise F1 of the adversary's predicted clustering vs
  ground-truth operator ownership. High = the adversary reconstructed who owns what.
- **linkage recall** (↓ better) — fraction of your same-operator account pairs the
  adversary correctly linked.
- **fragmentation** (↑ better) — average number of distinct adversary clusters one
  operator's accounts get scattered across. `1.0` = fully de-anonymized.

## Threat model (what this does NOT do)

Honesty is a feature. Curupira raises the _cost_ of behavioral clustering; it is not
encryption and not a mixer.

- **Not a mixer.** Curupira fabricates activity; it does **not** pool or hide user funds.
  No Tornado-Cash-style value obfuscation.
- **Noise is weak alone.** ML classifiers cluster chain activity with very high accuracy;
  decoys/jitter only help when drawn from the same distribution as real activity. That is
  why the harness exists — to catch overclaiming.
- **Timing jitter is weak on Solana** (deterministic leader schedule, low latency). Its
  value is degrading cross-tx temporal correlation, not hiding a single tx.
- **Fee-payer rotation has a cost.** Thousands of single-use fee-payers must be funded,
  and _mass single-use fee-payers are themselves a fingerprint_. A production design uses
  a bounded pool of funded relayers (which drifts toward `mirror-pool` territory) or funds
  from a shielded source.
- **Graph analysis still applies.** O Caçador does not yet do generic transaction-graph
  connectivity or ML; a stronger adversary would recover a non-zero (but still degraded)
  attribution. Strengthening the adversary is the honesty roadmap, not an afterthought.
- **Network metadata de-anonymizes** (RPC IP) regardless of on-chain perfection. Out of
  scope here; do not assume end-to-end anonymity.

## Roadmap

- **O Caçador v2:** transaction-graph connectivity + ML clustering (so the numbers are
  adversarially honest, not artifacts of a weak adversary).
- **Live wiring:** fund-and-rotate fee-payers, priority fees, retries; real Jupiter/stake
  adapters on devnet/localnet.
- **Funding realism:** bounded funded relayer pool + cost accounting.
- **Composability:** expose `noise-core` for the `supersonic-tx` bounty (route cooked
  casts through it).

## License

MIT — see [LICENSE](LICENSE).
