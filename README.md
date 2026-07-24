# Curupira 🦶🔄

**Believable Solana activity at scale, paired with an adversarial harness that measures
how linkable the resulting accounts remain.**

> Contribution to Superteam Brasil's
> [`account-cooker`](https://superteam.fun/earn/listing/noise) bounty. Rust, end-to-end,
> MIT licensed.

_Curupira_ is the Brazilian folklore creature whose feet point backwards and confuse
trackers. The name fits the goal, but the project does not rely on folklore-grade claims:
every privacy result is scored by **O Caçador**, the adversary shipped in this repository.

## Why this submission is different

Curupira is a complete experiment and an operational foundation, not a random transaction
loop:

- **Believable behavior:** declarative retail, whale, and market-maker personas; circadian
  timing; Poisson arrivals; log-normal amount variation; split payments; decoys; stake, swap,
  memo, and transfer intents.
- **Fleet operation:** deterministic seeded runs, a heap scheduler, custom persona loading,
  cost estimation, append-only journals, atomic checkpoints, exact crash recovery, and
  million-record scale tests.
- **Privacy measurement:** O Caçador attacks fee-payer reuse, graph consolidation,
  activation lineage, peel chains, co-payment/co-activity timing, and fee-payer funding — plus
  a trained logistic-regression classifier (held-out ROC AUC) for the modern-clustering bar.
  It reads only observable transaction fields; ownership labels are confined to scoring/training.
- **Safe live path:** the optional Solana path quotes or executes real SOL transfer, SPL memo,
  and native stake delegation with a freshly funded rotated fee-payer, bounded spend, local-RPC
  default, and idempotent retries of one immutable signed transaction.

The core thesis is deliberately modest: privacy-through-noise can raise attribution cost,
but it is neither encryption nor a mixer. The harness exists to expose where it fails.

## Reproducible results

Run:

```bash
cargo run --release --bin curupira -- demo --agents 12 --days 3 --seed 1
```

The current engine produces:

| adversary result | naive | Curupira | legacy engine |
|---|---:|---:|---:|
| transactions | 1,895 | 6,286 | 7,095 |
| distinct accounts | 112 | 6,455 | 7,306 |
| attribution F1 ↓ | 1.000 | **0.246** | 1.000 |
| attribution precision | 1.000 | **1.000** | 1.000 |
| linkage recall ↓ | 1.000 | **0.140** | 1.000 |
| largest owned cluster ↓ | 0.111 | **0.048** | 0.111 |

That is a **75% reduction in attribution F1** versus the naive fleet while retaining
precision 1.00. It is not a lucky seed:

```bash
cargo run --release --bin curupira -- benchmark \
  --agents 12 --days 3 --seed-start 1 --seeds 10
```

| mode | mean F1 | minimum | maximum |
|---|---:|---:|---:|
| naive | 1.000 | 1.000 | 1.000 |
| Curupira | **0.263** | 0.246 | 0.277 |
| legacy engine | 0.983 | 0.923 | 1.000 |

The hardened result remains non-zero because O Caçador follows observable
predecessor-to-successor activation. This is the honest residual of rotating accounts:

| balance strategy | F1 | precision | recall |
|---|---:|---:|---:|
| one-to-one account rotation (default) | **0.25** | 1.00 | 0.14 |
| direct operator hub (ablation) | 0.77 | 1.00 | 0.62 |

The old many-to-one sweep created a permanent hub. The default now rotates operational
accounts one-to-one, while the adversary still recognizes successor activation. The test
became harder and the engine became safer at the same time.

Full commands, environment, and verification output are recorded in
[`EVIDENCE.md`](EVIDENCE.md).

## The funding graph: the result privacy tools often omit

A new fee-payer must receive SOL before it can pay a fee. That funding edge is public.
With funding modeled, the same seed produces:

| funding policy | F1 | precision | largest cluster | mean funder anonymity set |
|---|---:|---:|---:|---:|
| not modeled | 0.25 | 1.00 | 0.05 | 1.0 |
| operator hub | **1.00** | 1.00 | 0.20 | 1.0 |
| dedicated funder | **1.00** | 1.00 | 0.19 | 1.0 |
| 12 shared relayers | 0.76 | 0.61 | 0.29 | 1.5 |

The conclusion matters more than the favorable number: **fee-payer rotation is cosmetic
when one operator-owned wallet funds every fee-payer.** A dedicated intermediate wallet
does not help. Shared relayers create an anonymity set, but they also cause a simple
common-funder heuristic to merge different operators; its lower precision is uncertainty,
not proof of privacy. Curupira prints precision specifically so a giant-cluster adversary
cannot manufacture a convincing F1.

## Quickstart

Requirements: stable Rust and Cargo.

```bash
# Offline, deterministic, no validator or credentials
cargo test --workspace
cargo run --bin curupira -- demo
cargo run --bin curupira -- benchmark --seeds 10

# Write and score a ledger
cargo run --bin curupira -- dump \
  --mode curupira --funding hub --out ledger.json
cargo run --bin curupira -- report \
  --ledger ledger.json --funder-aware

# Make the operational cost assumption explicit
cargo run --bin curupira -- cost \
  --ledger ledger.json --lamports-per-signature 5000
```

### Custom personas

Export the presets, edit the TOML, and load one file or a whole directory:

```bash
cargo run --bin curupira -- personas --out-dir personas
cargo run --bin curupira -- demo --personas-dir personas
cargo run --bin curupira -- dump \
  --persona personas/retail.toml \
  --persona personas/whale.toml \
  --out ledger.json
```

Invalid action names, non-finite values, negative weights, impossible jitter, empty
profiles, and duplicate persona names fail before a run starts.

### Durable runs

```bash
cargo run --bin curupira -- run \
  --dir /tmp/curupira-run --out ledger.json

# After SIGKILL or another interruption:
cargo run --bin curupira -- run \
  --dir /tmp/curupira-run --out ledger.json --resume
```

`ledger.jsonl` is append-only. `checkpoint.json` is written by temp-file + sync + atomic
rename and contains the RNG, scheduler, counters, chain state, and dynamically rotated
account state. Resume truncates an uncommitted journal tail and refuses configuration or
format mismatches. The final ledger is byte-identical to an uninterrupted run; an ignored
integration test proves this with real `SIGKILL`.

## Safe live Solana proof

Live dependencies are opt-in:

```bash
cargo build --workspace --features live
cargo run --features live --bin curupira -- live-transfer --help   # also: live-memo, live-stake
```

Every live command shares one fail-closed envelope: quote-only unless `--execute`, remote RPC
rejected unless explicitly allowed, explicit total-debit and fee-payer-top-up ceilings, a
freshly funded **rotated** ephemeral fee-payer (rent-exempt-minimum + fee, so the funder itself
never signs the action), and idempotent submission of one immutable transaction. A local
validator proof is automated:

```bash
# Start solana-test-validator or Surfpool on 127.0.0.1:8899 first
./scripts/localnet-live-proof.sh
```

The script creates temporary keys, airdrops only on the selected local endpoint, executes
one transfer, checks both signatures, verifies the destination balance, and removes the
temporary directory. The library never airdrops and never defaults to devnet/mainnet.

**Three real actions are proven on public devnet** (`--rpc-url https://api.devnet.solana.com
--allow-remote-rpc`), each with finalized signatures recorded in [`EVIDENCE.md`](EVIDENCE.md):

- **`live-transfer`** — a native SOL transfer.
- **`live-memo`** — a real SPL Memo instruction (verified in the transaction logs).
- **`live-stake`** — creates a stake account and delegates it to a live vote account (the tool
  auto-picks one), staying rent-exempt and above the cluster's minimum delegation.

Current live scope is intentionally precise: **SOL transfer, rotated fee-payer funding, SPL
memo, and native stake delegation are real Solana transactions proven on localnet and devnet;
swap stays a deterministic intent planner** — Jupiter has no devnet liquidity, so a real devnet
swap is impossible and we do not fake one. The offline `ProtocolAdapter` trait is intentionally
intent-only (no chain deps, for offline testability); the real instruction seam lives in
`agent-runtime/src/live.rs`.

## Architecture

| crate | responsibility |
|---|---|
| `noise-core` | split policy, circadian/Poisson timing, decoy policy, account identifiers |
| `persona` | built-in profiles, TOML serialization, validation |
| `adapters` | protocol-agnostic planners for transfer/stake/swap/memo intents |
| `agent-runtime` | agent scheduler, hardening, account rotation, funding models, durability, optional RPC execution |
| `hunter` | observable-only clustering heuristics and ground-truth-only metrics |
| `curupira-cli` | demo, benchmark, dump, durable run, report, cost, personas, live proof |

The simulator and adversary are isolated from the RPC layer. That makes every behavioral
and attribution result deterministic, cheap to test, and reproducible without a network.

## What O Caçador measures

Every record contains an `operator` label solely for evaluation. Production heuristics
never inspect it.

- **Attribution F1 (lower is better):** pairwise F1 between predicted clusters and real
  operator ownership.
- **Precision:** how many predicted same-owner pairs are correct. Low precision exposes
  indiscriminate over-merging.
- **Linkage recall (lower is better):** how many real same-owner account pairs were linked.
- **Largest cluster share:** catches “put everything in one cluster” attacks.
- **Fragmentation:** number of predicted clusters across one operator's accounts.
- **Burst/window purity:** how much a timing group itself separates operators. This is a
  ledger diagnostic, not an ownership result.
- **Funder anonymity set:** distinct operators behind a common funder. It describes the
  funding topology; it is not a privacy guarantee.

The adversary uses public fields (`source`, `destination`, `fee_payer`, amount, slot, and
time). Action intent such as `Dust` or `Consolidate` is not used to create clustering edges.
Temporal windows are destination-local proximity episodes, avoiding arbitrary global
bucket boundaries. Broad co-activity is not unioned because it would merge unrelated users
who merely transact during the same interval.

## The learned adversary (a trained classifier, not just heuristics)

To measure against *modern* clustering — not only hand-written rules — O Caçador also ships a
learned adversary: a hand-rolled logistic-regression classifier over observable pairwise
features (fee-payer/destination overlap, co-burst, windowed co-payment, common-funder,
activation-lineage, peel-chain, timespan). It predicts P(two accounts share an operator) and is
scored by threshold-free **ROC AUC** — the metric a modern chain-analysis firm reports.

```
  -- adversary: learned logistic model (leave-operators-out CV, held-out) --
                               NAIVE  CURUPIRA    LEGACY
  ROC AUC (down)                1.00      0.63      1.00
  attribution F1 (down)         1.00      0.21      1.00
```

It re-identifies naive and legacy fleets at **AUC 1.00**, and is driven to **AUC 0.63** on
hardened Curupira — barely above the 0.5 coin-flip. The fused model (0.63) edges out its best
single feature (0.59), so the small residual is genuine learned fusion, not one rule in
disguise. Honesty guarantees, all test-guarded:

- **No label leakage:** features never read `operator`; it is used only as the training label
  and for **operator-disjoint** cross-validation — every pair is scored by a model that trained
  on neither of its two operators.
- **Deterministic:** zero-initialised full-batch gradient descent, no RNG; probabilities are
  quantised before the union threshold. Bit-reproducible within a toolchain.
- **Genuinely bounded:** the report prints each single-feature AUC next to the fused AUC, so
  "the model beat any one rule" is measured, not claimed.

The headline: even a trained classifier only reaches AUC ≈ 0.63 on hardened Curupira, and unlike
comparable ML adversaries we then **close the loop** (re-measure after hardening) and **model the
funding graph**. Any external AUC figure is indicative, not a like-for-like comparison.

## Scale and verification

The runtime uses a `BinaryHeap` scheduler. Hot adversarial passes use indexed lookups and
contingency-table scoring instead of all-pairs scans. **1,000 agents over 30 simulated days
produce 4,768,768 records in ~34 s**, and three independent runs of that configuration hash to
a byte-identical trace-hash — determinism at millions of records:

```text
scale: 4768768 records, naive f1 1.00, hardened f1 0.12 (prec 1.00),
       trace-hash 04b26a83…8efe2d46
```

Naive is fully de-anonymized (F1 1.00) at any scale; hardened Curupira holds at F1 0.12 at
precision 1.00 — the same residual as the 12-agent demo, with no giant-cluster collapse.

Reaching a trustworthy number at scale meant fixing our own adversary: dest-agnostic
co-activity links accounts that act in the same second, and at fleet scale unrelated operators
collide every second, so it over-merges into one giant cluster and even *naive* attribution
collapses to F1 0.03. The scale-safe (windowed) adversary disables co-activity and keeps only
precision-clean dest-keyed signals; the exact-ts adversary keeps it for the small-scale
straw-man. This is why reported F1 is the **worst case over both adversaries** — the best any
one achieves.

Heavy ignored tests cover the scale/determinism run above, interrupted-and-resumed runs at
several checkpoints, a `SIGKILL`ed subprocess compared byte-for-byte, and the co-activity
scale-collapse guard. Run them with:

```bash
cargo test --workspace --release -- --ignored
```

CI separately checks format, Clippy with warnings denied, the default test suite, all live
features, shell syntax, and release stress tests.

## Threat model

Curupira raises the cost of deterministic behavioral clustering. It does not make
transactions confidential.

- It does not pool, custody, or obscure user funds and is **not a mixer**.
- Funding ancestry remains public. This harness follows one structural hop, not the full
  path to a faucet, exchange, or bridge.
- RPC IP, infrastructure fingerprints, validator observations, and off-chain identity are
  out of scope.
- Deterministic heuristics are not a substitute for a trained behavioral classifier.
- Cover traffic costs fees and capital movement. `curupira cost` reports explicit
  assumptions; no default fee is presented as universal.
- Real protocol integrations need protocol-specific safety checks, slippage limits, account
  validation, and validator evidence. SOL transfer, SPL memo, and native stake delegation make
  devnet-proven on-chain claims; swap stays an offline planner (no devnet liquidity).
- Every reported result is specific to its seed, fleet shape, duration, funding policy,
  and adversary configuration. Use `benchmark` and measure the intended deployment.

## Roadmap

1. Add local-validator instruction tests for native stake and memo.
2. Integrate a bounded Jupiter quote/swap path with explicit slippage and mint allowlists.
3. Walk multi-hop funding ancestry and add graph-feature/behavioral classifier baselines.
4. Add a durable, rate-limited live fleet executor after the single-transfer safety seam
   has validator evidence.

## License

MIT — see [`LICENSE`](LICENSE).
