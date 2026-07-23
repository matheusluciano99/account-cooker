//! `curupira` CLI.
//!
//! `demo`   run naive vs Curupira fleets and print the before/after attribution numbers
//! `dump`   write a simulated ledger to JSON
//! `report` score a ledger JSON with O Cacador
//! `run`    run a fleet durably (crash-safe checkpoint/resume)

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use agent_runtime::durable::{resume_durable, simulate_durable, DurabilityOpts};
use agent_runtime::{simulate, FundingConfig, FundingPolicy, Mode, SimConfig};
use hunter::model::Ledger;
use hunter::{analyze, AdversaryConfig, Report};
use persona::Persona;
use std::path::Path;

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
        #[arg(long)]
        out: String,
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
    },
    /// Score an existing ledger JSON with the adversarial harness.
    Report {
        #[arg(long)]
        ledger: String,
        /// Also run the common-funder heuristic (for ledgers with modeled funding).
        #[arg(long, default_value_t = false)]
        funder_aware: bool,
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
        } => demo(agents, days, seed, external),
        Cmd::Dump {
            mode,
            agents,
            days,
            seed,
            external,
            funding,
            relayers,
            out,
        } => dump(
            &mode, agents, days, seed, external, &funding, relayers, &out,
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
        ),
        Cmd::Report {
            ledger,
            funder_aware,
        } => report(&ledger, funder_aware),
        Cmd::Personas { out_dir } => write_personas(&out_dir),
    }
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

fn base_cfg(agents: usize, days: i64, seed: u64, external: usize) -> SimConfig {
    SimConfig {
        num_agents: agents,
        duration_secs: days.max(1) * 86_400,
        seed,
        num_external: external.max(1),
        ..SimConfig::default()
    }
}

fn demo(agents: usize, days: i64, seed: u64, external: usize) -> Result<()> {
    let personas = Persona::presets();
    let base = base_cfg(agents, days, seed, external);
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
    println!("  -- adversary: exact-ts v2 (the straw-man per-tx jitter defeats) --");
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
    println!("  -- adversary: windowed v3 (the HEADLINE — buckets by dt) --");
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
    funding_section(&personas, &base, agents);
    println!();
    Ok(())
}

/// v4: model where fee-payer SOL comes from and score with the funder-aware adversary. Shows
/// that timing hardening's win evaporates once funding is visible, and how a shared relayer pool
/// buys it back as an anonymity set of ~operators/K.
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
    println!("  -- v4: fee-payer funding (the leak timing hardening cannot fix) --");
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
    println!(
        "  and dedicated-funder funding are re-identified at high precision. A shared relayer"
    );
    println!(
        "  pool trades attribution for an anonymity set of ~operators/K; once a relayer serves"
    );
    println!(
        "  more sources than the analyst's shared-service cap it is dropped (you have become a"
    );
    println!("  mixer — mirror-pool territory). Assumes sticky client->relayer assignment.");
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
    println!("  Reading: at window 0 (exact-ts) the fan-out is gone and F1 collapses. A wider");
    println!("  window recovers the genuine consolidation residual; precision stays high");
    println!("  because the swept hub is operator-private. Wider still trades precision for");
    println!("  recall — that trade IS the honest ceiling on what noise leaves behind.");
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
            "  Verdict: against the analyst who buckets by dt, attribution F1 {:.2} -> {:.2}",
            naive_w.attribution_f1, hardened_w.attribution_f1
        );
        println!(
            "  (-{:.0}%) at precision {:.2}, largest cluster {:.2}. A genuine internal-",
            drop, hardened_w.attribution_precision, hardened_w.largest_cluster_frac
        );
        println!("  consolidation residual survives — noise helps but is NOT magic.");
        println!(
            "  (The exact-ts adversary sees only F1 {:.2} here — the defeated straw-man.)",
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
    out: &str,
) -> Result<()> {
    let m = match mode.to_lowercase().as_str() {
        "naive" => Mode::Naive,
        _ => Mode::Curupira,
    };
    let cfg = SimConfig {
        mode: m,
        funding: parse_funding(funding, relayers)?,
        ..base_cfg(agents, days, seed, external)
    };
    let ledger = simulate(&Persona::presets(), &cfg);
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
) -> Result<()> {
    let m = match mode.to_lowercase().as_str() {
        "naive" => Mode::Naive,
        _ => Mode::Curupira,
    };
    let cfg = SimConfig {
        mode: m,
        funding: parse_funding(funding, relayers)?,
        ..base_cfg(agents, days, seed, external)
    };
    let personas = Persona::presets();
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
