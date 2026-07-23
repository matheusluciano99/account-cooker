# Curupira 🦶🔄

**A believable-activity engine for Solana — with an adversarial harness that _measures_ how much it actually defeats wallet clustering.**

> Contribution to the Superteam Brasil [`account-cooker`](https://github.com/solanabr/account-cooker) bounty
> ("Build Privacy-Through-Noise tooling for Solana"). Rust, end-to-end, MIT.

_Curupira_ is the Brazilian folklore creature whose feet point backwards to send trackers the wrong way — which is exactly what this tool aims to do to on-chain trackers.

---

## The problem

On a public ledger every action is legible. Analytics firms and MEV bots cluster wallets,
attribute identity, and front-run intent in real time. `account-cooker` fights this by
drowning your real activity in a sea of _believable_ synthetic activity, so attribution
and clustering become measurably harder and costlier.

The catch, and the reason most "privacy through noise" is snake oil: **noise is
cryptographically weak and statistically attackable.** Naive randomness gives a false
sense of security. So Curupira ships two things that reinforce each other:

1. **A believable-activity engine** — personas with human timing, split payments, rotating
   fee-payers, decoys — its timing hardened against the strongest heuristics the harness
   itself ships.
2. **O Caçador ("the Hunter")** — an adversarial harness that runs the same heuristics a
   real de-anonymization firm would, and **puts a number on how linkable your fleet is,
   before and after.** No number, no claim.

## What the demo shows — an honest arms race

```
$ cargo run --bin curupira -- demo --agents 12 --days 3 --seed 1

  Curupira — believable activity vs adversarial attribution (O Cacador)
  seed=1  agents=12  days=3

                               NAIVE  CURUPIRA    LEGACY
  transactions                  1895      6164      7095
  distinct accounts              112      6270      7306

  -- adversary: exact-ts v2 (the straw-man per-tx jitter defeats) --
  attribution F1  (down)        1.00      0.00      1.00
  precision                     1.00      0.00      1.00

  -- adversary: windowed v3 (the HEADLINE — buckets by dt) --
  attribution F1  (down)        1.00      0.14      1.00
  precision (up=honest)         1.00      1.00      1.00
  linkage recall  (down)        1.00      0.08      1.00
  largest cluster (down)        0.11      0.05      0.11

  Verdict: against the analyst who buckets by dt, attribution F1 1.00 -> 0.14
  (-86%) at precision 1.00, largest cluster 0.05. A genuine internal-
  consolidation residual survives — noise helps but is NOT magic.
  (The exact-ts adversary sees only F1 0.00 here — the defeated straw-man.)

  O Cacador window sweep on hardened Curupira (the honest arms race):
  windowed adversary      F1    prec  recall    wpur
  --------------------------------------------------
  window=0              0.00    0.00    0.00    0.17
  window=30             0.12    1.00    0.06    0.30
  window=60             0.14    1.00    0.08    0.28
  window=120            0.14    1.00    0.08    0.21
  window=300            0.14    1.00    0.08    0.18
  window=600            0.14    1.00    0.08    0.16
  Reading: at window 0 (exact-ts) the fan-out is gone and F1 collapses. A wider
  window recovers the genuine consolidation residual; precision stays high
  because the swept hub is operator-private. Wider still trades precision for
  recall — that trade IS the honest ceiling on what noise leaves behind.
```

Three ledgers, two adversaries — the columns tell the arms race in order:

- **NAIVE** — no noise. Every adversary fully de-anonymizes it: F1 1.00.
- **LEGACY** — the original Curupira engine (fee-payer rotation, splits, decoys) before
  timing hardening. Rotation alone defeated O Caçador v1 (F1 0.00) — but that number was
  an artifact of a weak adversary. The engine's split fan-out lands N transfers on the
  same destination at the same timestamp, and the v2 burst heuristics
  (H-COPAY / H-COACT) exploit exactly that to fully de-anonymize it:
  **F1 1.00 at precision 1.00**. Fee-payer rotation cannot hide a timing fingerprint.
- **CURUPIRA** — the hardened engine (per-record timestamp jitter, per-subaccount
  decorrelated circadian schedules, single-source actions). Hardening deletes the
  fan-out fingerprint, so the exact-ts adversary collapses to 0.00 — the straw-man. The
  **windowed v3 adversary** re-buckets by Δt and still recovers
  **F1 0.14 at precision 1.00**: a genuine residual left by periodic consolidation
  sweeps into an operator-private hub.

**Read this honestly:** the strong claim is not "F1 → 0". It is: against an adversary
proven to crush both the naive and the un-hardened fleet at 1.00, hardened Curupira holds
at **0.14 with the residual identified and explained** — an 86% reduction, at precision
1.00, so the adversary isn't inflating recall with giant blobs. The window sweep shows
the precision/recall trade a real analyst faces; that trade is the honest ceiling on what
noise leaves behind. But 0.14 is only honest against the attacks O Caçador runs — and the
demo now runs one more.

## The funding graph — where the 0.14 comes undone

Timing hardening decorrelates *when* your fee-payers act. It says nothing about *where their
SOL comes from*. Every throwaway fee-payer must be funded before it can pay, and that funding
transaction is on-chain. If they all trace back to one operator-owned wallet, an analyst walks
the common-funder graph and re-links the whole fleet — fee-payer rotation buys nothing. O
Caçador v4 models this and measures it (`--funding`, and the funder-aware adversary):

```
  -- v4: fee-payer funding (the leak timing hardening cannot fix) --
  funding policy                F1    prec   largest    anon
  ----------------------------------------------------------
  off (not modeled)           0.14    1.00      0.05     1.0
  operator-hub                1.00    1.00      0.11     1.0
  dedicated-funder            1.00    1.00      0.10     1.0
  relayers k=12               0.77    1.00      0.11     1.5

  shared relayer pool sweep (hardened Curupira, funder-aware adversary):
  pool size K             F1    prec  recall    anon
  --------------------------------------------------
  k=1                  0.14    1.00    0.08    12.0
  k=2                  0.26    0.53    0.17     6.0
  k=3                  0.14    1.00    0.08     4.0
  k=6                  0.44    0.68    0.32     2.4
  k=12                 0.77    1.00    0.62     1.5
```

- **off** — the 0.14 residual, funding invisible. This is the optimistic number.
- **operator-hub / dedicated-funder** — fund the throwaways from an operator-owned wallet and
  the funder graph sends attribution straight back to **F1 1.00 at precision 1.00**. One hop of
  indirection (a dedicated funder) buys *nothing* — the funder is still owned, so the harness
  unions it right back in. **Timing hardening's win evaporates.**
- **shared relayer pool** — fund from `K` relayers shared across all operators and the residual
  is governed by the **anonymity set ≈ operators/K** (the `anon` column): each relayer's clients
  hide among each other. Shrink `K` and attribution falls, but once a relayer serves more sources
  than the analyst's shared-service cap it is dropped entirely — you have become a mixer. That is
  `mirror-pool`'s trusted-pool problem, reached from the other direction. (Numbers are the sticky
  client→relayer model; the mid-`K` precision dips are two operators honestly colliding under one
  relayer, printed rather than smoothed.)

The honest finding: **fee-payer rotation is cosmetic unless the funding is decorrelated too, and
the only thing that decorrelates it is an anonymity set you share with other operators.** That is
not a bug in Curupira — it is the measured price of privacy-through-noise, and naming it is the
whole point of shipping the adversary alongside the engine. Every time O Caçador gets stronger,
these numbers get re-measured. See the [threat model](#threat-model-what-this-does-not-do).

## Architecture

A Cargo workspace. The interesting, privacy-relevant logic is **pure and unit-tested**;
the chain integration is isolated behind a feature flag.

| crate | role | notable deps |
|---|---|---|
| `noise-core` | value splitting, human (circadian/Poisson) timing, ephemeral/stealth address derivation (curve25519), decoy policy | `rand`, `curve25519-dalek`, `sha2` |
| `persona` | declarative behavior profiles (retail / whale / market-maker) in TOML | `rand`, `toml` |
| `hunter` | **O Caçador** — clustering adversary (fee-payer linkage, co-spend, temporal peel-chain, burst co-payment/co-activity, Δt-window re-bucketing, common-funder graph) + honesty metrics (F1, precision, recall, fragmentation, purity, largest-cluster share, funder anonymity set) | `serde` |
| `adapters` | `ProtocolAdapter` trait + Transfer/Stake/Swap/Memo. New protocol = one impl | `rand` |
| `agent-runtime` | fleet orchestrator + timing hardening; `MockChain` (offline, deterministic) by default, real Solana under `--features live`; crash-safe journal/checkpoint runs (`durable`) | `chacha20` (checkpointable RNG); `solana-*` under `live` |
| `curupira-cli` | `demo` / `dump` / `run` (durable, resumable) / `report` / `personas` | `clap` |

Because the simulator is deterministic (seeded) and offline, **the whole before/after
demo is reproducible on any machine with no validator** — the property judges love.

## Quickstart

```bash
cargo test --all                    # 65 tests, pure logic — no network needed
cargo run --bin curupira -- demo    # the arms-race matrix + funding graph above

# durable fleet run — journal + checkpoint; SIGKILL it, then resume:
cargo run --bin curupira -- run --dir /tmp/run --out ledger.json
cargo run --bin curupira -- run --dir /tmp/run --out ledger.json --resume

# the heavy proofs: 1000-agent scale + SIGKILL crash-recovery (release, ~30 s)
cargo test --all --release -- --ignored

# export the built-in personas and tweak them (the "trivially customizable" part)
cargo run --bin curupira -- personas --out-dir personas

# model fee-payer funding, then score it with the common-funder heuristic:
cargo run --bin curupira -- dump --mode curupira --funding hub --out ledger.json
cargo run --bin curupira -- report --ledger ledger.json --funder-aware
```

### Live mode (real Solana)

```bash
cargo build --features live         # pulls solana-sdk / solana-client (compiles clean)
```

`agent-runtime::live` maps simulator `AccountId`s to real `Keypair`s, assembles signed
SOL transfers with an arbitrary fee-payer, and submits them via RPC. Wiring the fleet
loop through it (funding throwaway fee-payers, priority fees, retries, real protocol
adapters) is the tracked next step — see `TODO(live)` markers.

## Scale & durability

Built for weeks-long fleets that survive crashes, not a demo loop:

- **Scale.** A `BinaryHeap` scheduler on the engine side and indexed, near-linear
  heuristics on the adversary side keep the whole loop fast: **1,000 agents × 14 days
  (≈ 2.3 M records) simulate and score in ~25 s** on a laptop
  (`scale_1000_agents_14_days`, run with `--ignored`). Grow the external counterparty
  pool with the fleet (`--external`, ~4× agents) so a fixed pool doesn't crowd
  co-payment buckets. **The residual is scale-dependent:** more activity means more
  genuine consolidations for the adversary to recover, so at this scale the same
  windowed adversary reads **F1 0.38 at precision 1.00** (naive and legacy still 1.00;
  reproduce with `demo --agents 1000 --days 14 --external 4000`). Measure your own fleet
  shape — don't quote the 12-agent demo's number for a 1,000-agent deployment.
- **Durability.** `curupira run` journals every record to an append-only `ledger.jsonl`
  and atomically replaces `checkpoint.json` (temp file + fsync + rename), capturing the
  exact RNG state (`ChaCha12Rng::serialize_state`, 49 bytes) and scheduler. Kill the
  process at any moment — `--resume` continues from the checkpoint and the final ledger
  is **byte-identical to an uninterrupted run**. Proven by
  `crates/cli/tests/crash_recovery.rs`, which SIGKILLs a live run mid-write and compares
  hashes; CI runs it in the `stress` job.

## How O Caçador scores (metric definitions)

Every `TxRecord` carries a ground-truth `operator` label that **the adversary never
reads**; it exists only so we can score the adversary's guess.

- **attribution F1** (↓ better) — pairwise F1 of the adversary's predicted clustering vs
  ground-truth operator ownership. High = the adversary reconstructed who owns what.
- **precision** (↑ = honest adversary) — of the account pairs the adversary linked, the
  fraction that truly share an operator. Reported so the harness can't fake recall by
  unioning everything: a blob-everything adversary collapses here.
- **linkage recall** (↓ better) — fraction of your same-operator account pairs the
  adversary correctly linked.
- **fragmentation** (↑ better) — average number of distinct adversary clusters one
  operator's accounts get scattered across. `1.0` = fully de-anonymized.
- **largest cluster share** (↓ better) — fraction of all observed accounts inside the
  adversary's biggest cluster; another guard against degenerate giant-blob clusterings.
- **burst / window purity** — fraction of same-timestamp (or same-Δt-bucket) groups
  containing a single operator: how much the timing channel alone leaks.
- **funder anonymity set** — mean number of distinct operators hiding behind one funder.
  `1.0` = each funder serves a single operator (a full funding-graph leak); larger = more
  operators share a funder (a relayer pool's anonymity set). The headline funding number.

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
- **Fee-payer rotation has a cost, and it is now measured.** Thousands of single-use
  fee-payers must be funded, and O Caçador v4 scores that funding graph: fund them from an
  operator-owned wallet and attribution returns to F1 1.00 regardless of timing hardening
  (see [The funding graph](#the-funding-graph--where-the-014-comes-undone)). The only
  mitigation is a bounded relayer pool whose privacy is an anonymity set of ~operators/K —
  which drifts toward `mirror-pool` territory. The residual there also depends on the
  analyst's shared-service cap; a stronger analyst subdivides a large relayer bucket by
  amount/timing rather than dropping it, so the small-`K` residual is a floor, not a promise.
- **Graph analysis still applies.** O Caçador covers burst and Δt-window timing attacks,
  but not yet generic transaction-graph connectivity or ML behavioral clustering; a
  stronger adversary — or simply a bigger, longer-running fleet (F1 0.38 at 1,000
  agents × 14 days) — recovers more than the 12-agent demo's 0.14. Strengthening the
  adversary is the honesty roadmap, not an afterthought.
- **The funding graph is modeled, not solved.** O Caçador v4 scores the common-funder
  graph (the leak the strongest competing work flags but does not close), so the headline
  numbers now account for it. What remains unmodeled is the funder's *own* funding — a real
  analyst walks up the graph to the exchange/faucet that funded the funder. Treat every
  number here as a lower bound on linkability, not a guarantee.
- **Network metadata de-anonymizes** (RPC IP) regardless of on-chain perfection. Out of
  scope here; do not assume end-to-end anonymity.

## Roadmap

- **O Caçador v5:** multi-hop funding-graph walking (up to the exchange/faucet that funded
  the funder), transaction-graph connectivity, and ML clustering — every upgrade re-measures
  the headline numbers.
- **Live wiring:** fund-and-rotate fee-payers, priority fees, retries; real Jupiter/stake
  adapters on devnet/localnet.
- **Funding realism:** per-use (non-sticky) relayer selection + cost accounting.
- **Composability:** expose `noise-core` for the `supersonic-tx` bounty (route cooked
  casts through it).

## License

MIT — see [LICENSE](LICENSE).
