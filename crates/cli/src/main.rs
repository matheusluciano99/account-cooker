//! `curupira` CLI.
//!
//! `demo`   run naive vs Curupira fleets and print the before/after attribution numbers
//! `benchmark` repeat the comparison across consecutive seeds
//! `dump`   write a simulated ledger to JSON
//! `report` score a ledger JSON with O Cacador
//! `run`    run a fleet durably (crash-safe checkpoint/resume)
//! `cost`   estimate signature fees and transferred volume for a ledger
//! `live-transfer` quote/execute a bounded real transfer (under `--features live`)

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};

use agent_runtime::durable::{resume_durable, simulate_durable, DurabilityOpts};
use agent_runtime::{simulate, FundingConfig, FundingPolicy, Mode, RebalanceStrategy, SimConfig};
use hunter::model::Ledger;
use hunter::{analyze, AdversaryConfig, Report};
use persona::Persona;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Parse a `--funding` value into an optional policy. `off` (default) models no funding;
/// `relayers` uses `--relayers K`.
fn parse_funding(kind: &str, relayers: usize) -> Result<Option<FundingConfig>> {
    let policy = match kind.to_lowercase().as_str() {
        "off" => return Ok(None),
        "hub" => FundingPolicy::OperatorHub,
        "dedicated" => FundingPolicy::DedicatedFunder,
        "relayers" => FundingPolicy::SharedRelayers { k: relayers.max(1) },
        other => anyhow::bail!("unknown --funding '{other}' (off|hub|dedicated|relayers)"),
    };
    Ok(Some(FundingConfig::new(policy)))
}

fn parse_rebalance(kind: &str) -> Result<RebalanceStrategy> {
    match kind.to_lowercase().as_str() {
        "rotate" | "rotate-accounts" => Ok(RebalanceStrategy::RotateAccounts),
        "hub" | "direct-hub" => Ok(RebalanceStrategy::DirectHub),
        other => anyhow::bail!("unknown --rebalance '{other}' (rotate|hub)"),
    }
}

fn parse_mode(kind: &str) -> Result<Mode> {
    match kind.to_lowercase().as_str() {
        "naive" => Ok(Mode::Naive),
        "curupira" => Ok(Mode::Curupira),
        other => anyhow::bail!("unknown --mode '{other}' (naive|curupira)"),
    }
}

#[derive(Parser)]
#[command(
    name = "curupira",
    version,
    about = "Believable Solana activity at scale + adversarial privacy measurement (O Cacador)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args, Clone, Debug, Default)]
struct PersonaFiles {
    /// Load a custom persona TOML. Repeat this flag to mix several profiles.
    #[arg(long = "persona", value_name = "FILE")]
    files: Vec<PathBuf>,
    /// Load every *.toml persona in this directory, sorted by filename.
    #[arg(long, value_name = "DIR")]
    personas_dir: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run naive vs Curupira fleets with the same seed and print the before/after report.
    Demo {
        #[arg(long, default_value_t = 12)]
        agents: usize,
        #[arg(long, default_value_t = 3)]
        days: i64,
        #[arg(long, default_value_t = 1)]
        seed: u64,
        /// Size of the shared external counterparty pool. Scale it with the fleet
        /// (e.g. ~4x agents) at large scale so a fixed pool doesn't crowd copay buckets.
        #[arg(long, default_value_t = 40)]
        external: usize,
        #[command(flatten)]
        personas: PersonaFiles,
    },
    /// Run the adversarial comparison across several consecutive seeds.
    Benchmark {
        #[arg(long, default_value_t = 12)]
        agents: usize,
        #[arg(long, default_value_t = 3)]
        days: i64,
        #[arg(long, default_value_t = 1)]
        seed_start: u64,
        #[arg(long, default_value_t = 10)]
        seeds: usize,
        #[arg(long, default_value_t = 40)]
        external: usize,
        #[command(flatten)]
        personas: PersonaFiles,
    },
    /// Simulate one fleet and write the observable ledger to a JSON file.
    Dump {
        #[arg(long, default_value = "curupira")]
        mode: String,
        #[arg(long, default_value_t = 12)]
        agents: usize,
        #[arg(long, default_value_t = 3)]
        days: i64,
        #[arg(long, default_value_t = 1)]
        seed: u64,
        #[arg(long, default_value_t = 40)]
        external: usize,
        /// Model fee-payer funding: off (default) | hub | dedicated | relayers.
        #[arg(long, default_value = "off")]
        funding: String,
        /// Relayer pool size when --funding relayers.
        #[arg(long, default_value_t = 4)]
        relayers: usize,
        /// Balance maintenance: rotate (one-to-one successors) | hub (leaky ablation).
        #[arg(long, default_value = "rotate")]
        rebalance: String,
        #[arg(long)]
        out: String,
        #[command(flatten)]
        personas: PersonaFiles,
    },
    /// Run a fleet durably: journals to a run directory and checkpoints as it goes, so a
    /// crash (SIGKILL) can be resumed with `--resume`. The final ledger is byte-identical to
    /// an uninterrupted run.
    Run {
        #[arg(long, default_value = "curupira")]
        mode: String,
        #[arg(long, default_value_t = 12)]
        agents: usize,
        #[arg(long, default_value_t = 3)]
        days: i64,
        #[arg(long, default_value_t = 1)]
        seed: u64,
        #[arg(long, default_value_t = 40)]
        external: usize,
        /// Run directory holding ledger.jsonl + checkpoint.json.
        #[arg(long)]
        dir: String,
        /// Write the final ledger JSON here (same format as `dump`).
        #[arg(long)]
        out: String,
        /// Resume from the checkpoint in --dir instead of starting fresh.
        #[arg(long, default_value_t = false)]
        resume: bool,
        #[arg(long, default_value_t = 10_000)]
        checkpoint_every: u64,
        /// Skip fsync (faster, but not crash-durable across power loss). Default: fsync on.
        #[arg(long, default_value_t = false)]
        no_fsync: bool,
        /// Model fee-payer funding: off (default) | hub | dedicated | relayers.
        #[arg(long, default_value = "off")]
        funding: String,
        /// Relayer pool size when --funding relayers.
        #[arg(long, default_value_t = 4)]
        relayers: usize,
        /// Balance maintenance: rotate (one-to-one successors) | hub (leaky ablation).
        #[arg(long, default_value = "rotate")]
        rebalance: String,
        #[command(flatten)]
        personas: PersonaFiles,
    },
    /// Score an existing ledger JSON with the adversarial harness.
    Report {
        #[arg(long)]
        ledger: String,
        /// Also run the common-funder heuristic (for ledgers with modeled funding).
        #[arg(long, default_value_t = false)]
        funder_aware: bool,
    },
    /// Estimate signature fees and value volume for a simulated ledger.
    Cost {
        #[arg(long)]
        ledger: String,
        /// Explicit fee assumption; Solana fees vary, so there is no hidden default.
        #[arg(long)]
        lamports_per_signature: u64,
    },
    /// Quote or execute one real SOL transfer with a freshly funded fee-payer.
    #[cfg(feature = "live")]
    LiveTransfer {
        /// Defaults to a local validator/Surfpool endpoint. Remote RPC is fail-closed.
        #[arg(long, default_value = "http://127.0.0.1:8899")]
        rpc_url: String,
        /// Solana CLI JSON keypair used as both source and fee-payer funder.
        #[arg(long)]
        payer: PathBuf,
        #[arg(long)]
        destination: String,
        #[arg(long, default_value_t = 1_000)]
        lamports: u64,
        /// Ceiling on the total debit from the payer. Default covers the transfer plus a
        /// rent-exempt fee-payer top-up (~0.0009 SOL) and fees.
        #[arg(long, default_value_t = 5_000_000)]
        max_total_debit: u64,
        /// Ceiling on the ephemeral fee-payer top-up. Default covers the rent-exempt minimum
        /// (~890_880 lamports) plus the action fee.
        #[arg(long, default_value_t = 2_000_000)]
        max_fee_payer_topup: u64,
        #[arg(long, default_value_t = 20)]
        status_polls: u32,
        /// Required to use a non-loopback RPC URL.
        #[arg(long, default_value_t = false)]
        allow_remote_rpc: bool,
        /// Submit transactions. Without this flag the command only quotes and validates.
        #[arg(long, default_value_t = false)]
        execute: bool,
    },
    /// Write the built-in personas to TOML files so they can be customized.
    Personas {
        #[arg(long, default_value = "personas")]
        out_dir: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Demo {
            agents,
            days,
            seed,
            external,
            personas,
        } => demo(agents, days, seed, external, &personas),
        Cmd::Benchmark {
            agents,
            days,
            seed_start,
            seeds,
            external,
            personas,
        } => benchmark(agents, days, seed_start, seeds, external, &personas),
        Cmd::Dump {
            mode,
            agents,
            days,
            seed,
            external,
            funding,
            relayers,
            rebalance,
            out,
            personas,
        } => dump(
            &mode, agents, days, seed, external, &funding, relayers, &rebalance, &out, &personas,
        ),
        Cmd::Run {
            mode,
            agents,
            days,
            seed,
            external,
            dir,
            out,
            resume,
            checkpoint_every,
            no_fsync,
            funding,
            relayers,
            rebalance,
            personas,
        } => run_durable(
            &mode,
            agents,
            days,
            seed,
            external,
            &dir,
            &out,
            resume,
            checkpoint_every,
            !no_fsync,
            &funding,
            relayers,
            &rebalance,
            &personas,
        ),
        Cmd::Report {
            ledger,
            funder_aware,
        } => report(&ledger, funder_aware),
        Cmd::Cost {
            ledger,
            lamports_per_signature,
        } => cost(&ledger, lamports_per_signature),
        #[cfg(feature = "live")]
        Cmd::LiveTransfer {
            rpc_url,
            payer,
            destination,
            lamports,
            max_total_debit,
            max_fee_payer_topup,
            status_polls,
            allow_remote_rpc,
            execute,
        } => live_transfer(
            rpc_url,
            payer,
            destination,
            lamports,
            max_total_debit,
            max_fee_payer_topup,
            status_polls,
            allow_remote_rpc,
            execute,
        ),
        Cmd::Personas { out_dir } => write_personas(&out_dir),
    }
}

fn load_personas(spec: &PersonaFiles) -> Result<Vec<Persona>> {
    let mut paths = spec.files.clone();
    if let Some(dir) = &spec.personas_dir {
        let entries =
            std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))?;
        let mut from_dir = Vec::new();
        for entry in entries {
            let path = entry
                .with_context(|| format!("reading entry in {}", dir.display()))?
                .path();
            if path.extension().is_some_and(|ext| ext == "toml") {
                from_dir.push(path);
            }
        }
        from_dir.sort();
        if from_dir.is_empty() {
            anyhow::bail!("{} contains no *.toml persona files", dir.display());
        }
        paths.extend(from_dir);
    }

    let personas = if paths.is_empty() {
        Persona::presets()
    } else {
        let mut loaded = Vec::with_capacity(paths.len());
        for path in &paths {
            let raw = std::fs::read_to_string(path)
                .with_context(|| format!("reading persona {}", path.display()))?;
            let persona = Persona::from_toml_str(&raw)
                .with_context(|| format!("parsing persona {}", path.display()))?;
            persona
                .validate()
                .with_context(|| format!("validating persona {}", path.display()))?;
            loaded.push(persona);
        }
        loaded
    };

    let mut names = BTreeSet::new();
    for persona in &personas {
        persona
            .validate()
            .with_context(|| format!("validating persona '{}'", persona.name))?;
        if !names.insert(persona.name.clone()) {
            anyhow::bail!("duplicate persona name '{}'", persona.name);
        }
    }
    Ok(personas)
}

fn write_personas(out_dir: &str) -> Result<()> {
    std::fs::create_dir_all(out_dir).with_context(|| format!("creating {out_dir}"))?;
    for p in Persona::presets() {
        let path = format!("{out_dir}/{}.toml", p.name);
        let toml = p.to_toml().context("serializing persona")?;
        std::fs::write(&path, toml).with_context(|| format!("writing {path}"))?;
        println!("wrote {path}");
    }
    Ok(())
}

fn base_cfg(agents: usize, days: i64, seed: u64, external: usize) -> Result<SimConfig> {
    if agents == 0 {
        anyhow::bail!("--agents must be greater than zero");
    }
    if days <= 0 {
        anyhow::bail!("--days must be greater than zero");
    }
    if external == 0 {
        anyhow::bail!("--external must be greater than zero");
    }
    let duration_secs = days
        .checked_mul(86_400)
        .ok_or_else(|| anyhow::anyhow!("--days is too large"))?;
    Ok(SimConfig {
        num_agents: agents,
        duration_secs,
        seed,
        num_external: external,
        ..SimConfig::default()
    })
}

fn demo(
    agents: usize,
    days: i64,
    seed: u64,
    external: usize,
    persona_files: &PersonaFiles,
) -> Result<()> {
    let personas = load_personas(persona_files)?;
    let base = base_cfg(agents, days, seed, external)?;
    // Three ledgers: naive baseline, hardened Curupira (default), and legacy (un-hardened).
    let naive = simulate(
        &personas,
        &SimConfig {
            mode: Mode::Naive,
            ..base.clone()
        },
    );
    let hardened = simulate(
        &personas,
        &SimConfig {
            mode: Mode::Curupira,
            harden_timing: true,
            ..base.clone()
        },
    );
    let legacy = simulate(
        &personas,
        &SimConfig {
            mode: Mode::Curupira,
            harden_timing: false,
            ..base.clone()
        },
    );

    let exact = AdversaryConfig::exact_ts();
    let win = AdversaryConfig::windowed(120);
    let (_, n_x) = analyze(&naive, &exact);
    let (_, h_x) = analyze(&hardened, &exact);
    let (_, l_x) = analyze(&legacy, &exact);
    let (_, n_w) = analyze(&naive, &win);
    let (_, h_w) = analyze(&hardened, &win);
    let (_, l_w) = analyze(&legacy, &win);

    println!();
    println!("  Curupira — believable activity vs adversarial attribution (O Cacador)");
    println!("  seed={seed}  agents={agents}  days={days}");
    println!();
    println!(
        "  {:<24}{:>10}{:>10}{:>10}",
        "", "NAIVE", "CURUPIRA", "LEGACY"
    );
    row3(
        "transactions",
        naive.records.len() as f64,
        hardened.records.len() as f64,
        legacy.records.len() as f64,
        Fmt::Int,
    );
    row3(
        "distinct accounts",
        n_x.num_accounts as f64,
        h_x.num_accounts as f64,
        l_x.num_accounts as f64,
        Fmt::Int,
    );
    println!();
    println!("  -- adversary: graph + exact-timestamp signals --");
    row3(
        "attribution F1  (down)",
        n_x.attribution_f1,
        h_x.attribution_f1,
        l_x.attribution_f1,
        Fmt::F2,
    );
    row3(
        "precision",
        n_x.attribution_precision,
        h_x.attribution_precision,
        l_x.attribution_precision,
        Fmt::F2,
    );
    println!();
    println!("  -- adversary: graph + destination-local dt episodes --");
    row3(
        "attribution F1  (down)",
        n_w.attribution_f1,
        h_w.attribution_f1,
        l_w.attribution_f1,
        Fmt::F2,
    );
    row3(
        "precision (up=honest)",
        n_w.attribution_precision,
        h_w.attribution_precision,
        l_w.attribution_precision,
        Fmt::F2,
    );
    row3(
        "linkage recall  (down)",
        n_w.linkage_recall,
        h_w.linkage_recall,
        l_w.linkage_recall,
        Fmt::F2,
    );
    row3(
        "largest cluster (down)",
        n_w.largest_cluster_frac,
        h_w.largest_cluster_frac,
        l_w.largest_cluster_frac,
        Fmt::F2,
    );
    println!();
    verdict(&n_w, &h_w, &h_x);
    ablation(&hardened);
    rebalance_section(&personas, &base);
    funding_section(&personas, &base, agents);
    println!();
    Ok(())
}

fn rebalance_section(personas: &[Persona], base: &SimConfig) {
    println!();
    println!("  -- graph-only rebalance ablation (no simulator intent labels) --");
    println!(
        "  {:<24}{:>8}{:>8}{:>10}",
        "strategy", "F1", "prec", "recall"
    );
    println!("  {}", "-".repeat(50));
    for (label, rebalance) in [
        ("one-to-one rotation", RebalanceStrategy::RotateAccounts),
        ("direct operator hub", RebalanceStrategy::DirectHub),
    ] {
        let mut cfg = SimConfig {
            mode: Mode::Curupira,
            harden_timing: true,
            ..base.clone()
        };
        cfg.hardening.rebalance = rebalance;
        let report = analyze(&simulate(personas, &cfg), &AdversaryConfig::windowed(120)).1;
        println!(
            "  {label:<24}{:>8.2}{:>8.2}{:>10.2}",
            report.attribution_f1, report.attribution_precision, report.linkage_recall
        );
    }
    println!("  Reading: many-to-one consolidation exposes a permanent hub. One-to-one");
    println!("  rotation removes that hub, but activation-lineage analysis still follows");
    println!("  predecessor -> successor edges. The remaining F1 is measured, not hidden.");
}

fn benchmark(
    agents: usize,
    days: i64,
    seed_start: u64,
    seeds: usize,
    external: usize,
    persona_files: &PersonaFiles,
) -> Result<()> {
    let personas = load_personas(persona_files)?;
    if seeds == 0 {
        anyhow::bail!("--seeds must be greater than zero");
    }
    let mut naive_scores = Vec::with_capacity(seeds);
    let mut hardened_scores = Vec::with_capacity(seeds);
    let mut legacy_scores = Vec::with_capacity(seeds);

    println!(
        "seed sweep: agents={agents} days={} seeds={seeds} start={seed_start}",
        days
    );
    println!(
        "{:<12}{:>10}{:>12}{:>10}",
        "seed", "naive F1", "curupira F1", "legacy F1"
    );
    for offset in 0..seeds {
        let seed = seed_start.wrapping_add(offset as u64);
        let base = base_cfg(agents, days, seed, external)?;
        let score = |mode, harden_timing| {
            let ledger = simulate(
                &personas,
                &SimConfig {
                    mode,
                    harden_timing,
                    ..base.clone()
                },
            );
            analyze(&ledger, &AdversaryConfig::windowed(120))
                .1
                .attribution_f1
        };
        let naive = score(Mode::Naive, false);
        let hardened = score(Mode::Curupira, true);
        let legacy = score(Mode::Curupira, false);
        naive_scores.push(naive);
        hardened_scores.push(hardened);
        legacy_scores.push(legacy);
        println!("{seed:<12}{naive:>10.3}{hardened:>12.3}{legacy:>10.3}");
    }

    let summary = |label: &str, values: &[f64]| {
        let mean = values.iter().sum::<f64>() / values.len() as f64;
        let min = values.iter().copied().fold(f64::INFINITY, f64::min);
        let max = values.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        println!("{label:<12} mean={mean:.3} min={min:.3} max={max:.3}");
    };
    println!();
    summary("naive", &naive_scores);
    summary("curupira", &hardened_scores);
    summary("legacy", &legacy_scores);
    Ok(())
}

/// Model where fee-payer SOL comes from and score with the funder-aware adversary. This shows
/// that timing hardening's win evaporates once funding is visible. A shared relayer creates an
/// anonymity set, but also forces the deterministic adversary to over-merge unrelated operators;
/// precision is therefore printed prominently and low F1 is never presented as a privacy proof.
fn funding_section(personas: &[Persona], base: &SimConfig, agents: usize) {
    let adv = AdversaryConfig::funder_aware(120);
    let hardened_funded = |policy: FundingPolicy| -> Report {
        let cfg = SimConfig {
            mode: Mode::Curupira,
            harden_timing: true,
            funding: Some(FundingConfig::new(policy)),
            ..base.clone()
        };
        analyze(&simulate(personas, &cfg), &adv).1
    };

    println!();
    println!("  -- fee-payer funding (the leak timing hardening cannot fix) --");
    println!(
        "  {:<24}{:>8}{:>8}{:>10}{:>8}",
        "funding policy", "F1", "prec", "largest", "anon"
    );
    println!("  {}", "-".repeat(58));
    // Baseline: hardened, funding not modeled, scored by the same funder-aware adversary.
    let off = {
        let cfg = SimConfig {
            mode: Mode::Curupira,
            harden_timing: true,
            funding: None,
            ..base.clone()
        };
        analyze(&simulate(personas, &cfg), &adv).1
    };
    let row = |label: &str, r: &Report| {
        println!(
            "  {:<24}{:>8.2}{:>8.2}{:>10.2}{:>8.1}",
            label,
            r.attribution_f1,
            r.attribution_precision,
            r.largest_cluster_frac,
            r.funder_anonymity_set
        );
    };
    row("off (not modeled)", &off);
    row("operator-hub", &hardened_funded(FundingPolicy::OperatorHub));
    row(
        "dedicated-funder",
        &hardened_funded(FundingPolicy::DedicatedFunder),
    );
    row(
        &format!("relayers k={agents}"),
        &hardened_funded(FundingPolicy::SharedRelayers { k: agents }),
    );

    // Relayer-pool sweep: shrink K and watch attribution trade against the anonymity set.
    println!();
    println!("  shared relayer pool sweep (hardened Curupira, funder-aware adversary):");
    println!(
        "  {:<18}{:>8}{:>8}{:>8}{:>8}",
        "pool size K", "F1", "prec", "recall", "anon"
    );
    println!("  {}", "-".repeat(50));
    let mut ks = vec![1usize, 2, 3, agents / 2, agents];
    ks.retain(|&k| k >= 1);
    ks.dedup();
    for k in ks {
        let r = hardened_funded(FundingPolicy::SharedRelayers { k });
        println!(
            "  k={:<15}{:>8.2}{:>8.2}{:>8.2}{:>8.1}",
            k, r.attribution_f1, r.attribution_precision, r.linkage_recall, r.funder_anonymity_set
        );
    }
    println!("  Reading: fee-payer rotation hides nothing from the funding graph — operator-hub");
    println!("  and dedicated-funder funding are re-identified at precision 1.00. A shared");
    println!("  relayer creates an anonymity set, but the low precision shows that this");
    println!("  deterministic heuristic is over-merging different operators. That is uncertainty,");
    println!("  not proof of privacy. Assumes sticky client->relayer assignment.");
}

/// Sweep the windowed adversary's width against the hardened ledger and print F1 /
/// precision / recall / window-purity at each width.
fn ablation(hardened: &Ledger) {
    println!();
    println!("  O Cacador window sweep on hardened Curupira (the honest arms race):");
    println!(
        "  {:<18}{:>8}{:>8}{:>8}{:>8}",
        "windowed adversary", "F1", "prec", "recall", "wpur"
    );
    println!("  {}", "-".repeat(50));
    for w in [0i64, 30, 60, 120, 300, 600] {
        let (_, r) = analyze(hardened, &AdversaryConfig::windowed(w));
        println!(
            "  window={:<11}{:>8.2}{:>8.2}{:>8.2}{:>8.2}",
            w, r.attribution_f1, r.attribution_precision, r.linkage_recall, r.window_purity
        );
    }
    println!("  Reading: F1 is stable across this sweep: the residual comes from observable");
    println!("  account-activation/graph lineage, not an arbitrary global time bucket. Window");
    println!("  purity falls as unrelated activity shares wider intervals, while clustering");
    println!("  precision stays high because broad co-activity is deliberately not unioned.");
}

#[derive(Clone, Copy)]
enum Fmt {
    Int,
    F2,
}

fn row3(label: &str, a: f64, b: f64, c: f64, fmt: Fmt) {
    let f = |v: f64| match fmt {
        Fmt::Int => format!("{}", v as i64),
        Fmt::F2 => format!("{v:.2}"),
    };
    println!("  {label:<24}{:>10}{:>10}{:>10}", f(a), f(b), f(c));
}

/// Print the verdict. Claims a win only if attribution fell, stayed nonzero, and stayed
/// honest (precision >= 0.80, no cluster collapse).
fn verdict(naive_w: &Report, hardened_w: &Report, hardened_x: &Report) {
    let helped = hardened_w.attribution_f1 + 0.05 < naive_w.attribution_f1
        && hardened_w.attribution_f1 > 0.0
        && hardened_w.attribution_precision >= 0.80
        && hardened_w.largest_cluster_frac < 0.5;
    if helped {
        let drop = (1.0 - hardened_w.attribution_f1 / naive_w.attribution_f1) * 100.0;
        println!(
            "  Verdict: against graph + local temporal analysis, attribution F1 {:.2} -> {:.2}",
            naive_w.attribution_f1, hardened_w.attribution_f1
        );
        println!(
            "  (-{:.0}%) at precision {:.2}, largest cluster {:.2}. Observable account-",
            drop, hardened_w.attribution_precision, hardened_w.largest_cluster_frac
        );
        println!("  rotation lineage remains — noise helps but is NOT magic.");
        println!(
            "  (Removing destination-local windows leaves F1 {:.2}; graph lineage dominates.)",
            hardened_x.attribution_f1
        );
    } else {
        println!("  Verdict: the noise did not measurably help against the windowed adversary",);
        println!(
            "  (F1 {:.2} vs naive {:.2}). The harness reports it honestly, no spin.",
            hardened_w.attribution_f1, naive_w.attribution_f1
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn dump(
    mode: &str,
    agents: usize,
    days: i64,
    seed: u64,
    external: usize,
    funding: &str,
    relayers: usize,
    rebalance: &str,
    out: &str,
    persona_files: &PersonaFiles,
) -> Result<()> {
    let m = parse_mode(mode)?;
    let mut cfg = SimConfig {
        mode: m,
        funding: parse_funding(funding, relayers)?,
        ..base_cfg(agents, days, seed, external)?
    };
    cfg.hardening.rebalance = parse_rebalance(rebalance)?;
    let personas = load_personas(persona_files)?;
    let ledger = simulate(&personas, &cfg);
    let json = serde_json::to_string_pretty(&ledger)?;
    std::fs::write(out, json).with_context(|| format!("writing {out}"))?;
    println!("wrote {} records to {out}", ledger.records.len());
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_durable(
    mode: &str,
    agents: usize,
    days: i64,
    seed: u64,
    external: usize,
    dir: &str,
    out: &str,
    resume: bool,
    checkpoint_every: u64,
    fsync: bool,
    funding: &str,
    relayers: usize,
    rebalance: &str,
    persona_files: &PersonaFiles,
) -> Result<()> {
    let m = parse_mode(mode)?;
    let mut cfg = SimConfig {
        mode: m,
        funding: parse_funding(funding, relayers)?,
        ..base_cfg(agents, days, seed, external)?
    };
    cfg.hardening.rebalance = parse_rebalance(rebalance)?;
    let personas = load_personas(persona_files)?;
    let dirp = Path::new(dir);
    let opts = DurabilityOpts {
        snapshot_every_events: checkpoint_every.max(1),
        fsync,
    };
    let ledger = if resume && dirp.join("checkpoint.json").exists() {
        resume_durable(&personas, &cfg, dirp, opts).context("resuming durable run")?
    } else {
        simulate_durable(&personas, &cfg, dirp, opts).context("durable run")?
    };
    let json = serde_json::to_string_pretty(&ledger)?;
    std::fs::write(out, json).with_context(|| format!("writing {out}"))?;
    println!(
        "wrote {} records to {out} (run dir {dir})",
        ledger.records.len()
    );
    Ok(())
}

fn report(path: &str, funder_aware: bool) -> Result<()> {
    let raw = std::fs::read_to_string(path).with_context(|| format!("reading {path}"))?;
    let ledger: Ledger = serde_json::from_str(&raw).context("parsing ledger JSON")?;
    let adv = if funder_aware {
        AdversaryConfig::funder_aware(120)
    } else {
        AdversaryConfig::windowed(120)
    };
    let (_, r) = analyze(&ledger, &adv);
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}

fn cost(path: &str, lamports_per_signature: u64) -> Result<()> {
    let raw = std::fs::read_to_string(path).with_context(|| format!("reading {path}"))?;
    let ledger: Ledger = serde_json::from_str(&raw).context("parsing ledger JSON")?;
    let signature_count: u128 = ledger
        .records
        .iter()
        .map(|record| {
            if record.fee_payer == record.source {
                1
            } else {
                2
            }
        })
        .sum();
    let transferred_lamports: u128 = ledger
        .records
        .iter()
        .map(|record| record.amount as u128)
        .sum();
    let estimated_network_fees = signature_count.saturating_mul(lamports_per_signature as u128);
    let result = serde_json::json!({
        "transactions": ledger.records.len(),
        "estimated_signatures": signature_count,
        "lamports_per_signature_assumption": lamports_per_signature,
        "estimated_network_fees_lamports": estimated_network_fees,
        "transferred_lamports": transferred_lamports,
        "note": "Transferred value includes internal rotation and cover traffic; it is volume, not net loss.",
        "scope": "Fees cover the records present in this ledger. If fee-payer funding was not modeled, those funding transactions and fees are excluded."
    });
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

#[cfg(feature = "live")]
#[allow(clippy::too_many_arguments)]
fn live_transfer(
    rpc_url: String,
    payer: PathBuf,
    destination: String,
    lamports: u64,
    max_total_debit: u64,
    max_fee_payer_topup: u64,
    status_polls: u32,
    allow_remote_rpc: bool,
    execute: bool,
) -> Result<()> {
    let receipt =
        agent_runtime::live::run_live_transfer(&agent_runtime::live::LiveTransferConfig {
            rpc_url,
            payer_path: payer,
            destination,
            lamports,
            max_total_debit,
            max_fee_payer_topup,
            status_polls,
            allow_remote_rpc,
            execute,
        })
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    println!("{}", serde_json::to_string_pretty(&receipt)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_modes_and_policies() {
        assert!(parse_mode("typo").is_err());
        assert!(parse_funding("typo", 1).is_err());
        assert!(parse_rebalance("typo").is_err());
    }

    #[test]
    fn rejects_empty_or_overflowing_fleet_dimensions() {
        assert!(base_cfg(0, 1, 1, 1).is_err());
        assert!(base_cfg(1, 0, 1, 1).is_err());
        assert!(base_cfg(1, 1, 1, 0).is_err());
        assert!(base_cfg(1, i64::MAX, 1, 1).is_err());
    }

    #[test]
    fn valid_base_config_preserves_inputs() {
        let cfg = base_cfg(7, 3, 11, 29).unwrap();
        assert_eq!(cfg.num_agents, 7);
        assert_eq!(cfg.duration_secs, 3 * 86_400);
        assert_eq!(cfg.seed, 11);
        assert_eq!(cfg.num_external, 29);
    }
}
