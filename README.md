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
  activation lineage, peel chains, co-payment/co-activity timing, and fee-payer funding.
  It reads only observable transaction fields; ownership labels are confined to scoring.
- **Safe live path:** the optional Solana path quotes or executes a real SOL transfer with
  a freshly funded fee-payer, bounded spend, local-RPC default, and idempotent retries of
  one immutable signed transaction.

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
cargo run --features live --bin curupira -- live-transfer --help
```

The command is quote-only unless `--execute` is present and rejects remote RPC endpoints
unless they are explicitly allowed. It requires explicit total-debit and fee-payer-top-up
ceilings. A local validator proof is automated:

```bash
# Start solana-test-validator or Surfpool on 127.0.0.1:8899 first
./scripts/localnet-live-proof.sh
```

The script creates temporary keys, airdrops only on the selected local endpoint, executes
one transfer, checks both signatures, verifies the destination balance, and removes the
temporary directory. The library never airdrops and never defaults to devnet/mainnet.

The same command runs against public **devnet** with `--rpc-url https://api.devnet.solana.com
--allow-remote-rpc`; a proven run and its two finalized signatures are recorded in
[`EVIDENCE.md`](EVIDENCE.md).

Current live scope is intentionally precise: **native SOL transfer and rotated fee-payer
funding are implemented as real Solana transactions, proven on localnet and devnet;
stake/swap/memo adapters are still deterministic intent planners.** They must not be
described as production protocol integrations until corresponding instruction builders and
validator tests land.

## Architecture

| crate | responsibility |
|---|---|
| `noise-core` | split policy, timing, decoys, account identifiers, curve25519 derivation primitives |
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

## Scale and verification

The runtime uses a `BinaryHeap` scheduler. Hot adversarial passes use indexed lookups and
contingency-table scoring instead of all-pairs scans. Heavy ignored tests cover:

- 1,000 agents over 14 simulated days;
- interrupted and resumed runs at several checkpoint boundaries;
- a subprocess killed with `SIGKILL`, followed by byte-for-byte comparison.

Run them with:

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
  validation, and local-validator evidence. Only the bounded SOL path currently makes an
  on-chain execution claim.
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
