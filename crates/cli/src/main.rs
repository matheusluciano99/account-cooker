//! `curupira` CLI.
//!
//! `demo`   run naive vs Curupira fleets and print the before/after attribution numbers
//! `dump`   write a simulated ledger to JSON
//! `report` score a ledger JSON with O Cacador

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use agent_runtime::{run_comparison, simulate, Mode, SimConfig};
use hunter::model::Ledger;
use hunter::{analyze, AdversaryConfig, Report};
use persona::Persona;

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
        #[arg(long)]
        out: String,
    },
    /// Score an existing ledger JSON with the adversarial harness.
    Report {
        #[arg(long)]
        ledger: String,
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
        Cmd::Demo { agents, days, seed } => demo(agents, days, seed),
        Cmd::Dump {
            mode,
            agents,
            days,
            seed,
            out,
        } => dump(&mode, agents, days, seed, &out),
        Cmd::Report { ledger } => report(&ledger),
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

fn base_cfg(agents: usize, days: i64, seed: u64) -> SimConfig {
    SimConfig {
        num_agents: agents,
        duration_secs: days.max(1) * 86_400,
        seed,
        ..SimConfig::default()
    }
}

fn demo(agents: usize, days: i64, seed: u64) -> Result<()> {
    let personas = Persona::presets();
    let cfg = base_cfg(agents, days, seed);
    let (naive, curupira) = run_comparison(&personas, &cfg);

    let adv = AdversaryConfig::default();
    let (_, rn) = analyze(&naive, &adv);
    let (_, rc) = analyze(&curupira, &adv);

    println!();
    println!("  Curupira — believable activity vs adversarial attribution (O Cacador)");
    println!("  seed={seed}  agents={agents}  days={days}");
    println!();
    println!("  {:<26}{:>12}{:>12}", "", "NAIVE", "CURUPIRA");
    row(
        "transactions",
        naive.records.len() as f64,
        curupira.records.len() as f64,
        Fmt::Int,
    );
    row(
        "distinct accounts",
        rn.num_accounts as f64,
        rc.num_accounts as f64,
        Fmt::Int,
    );
    row(
        "adversary clusters",
        rn.num_clusters as f64,
        rc.num_clusters as f64,
        Fmt::Int,
    );
    println!("  {}", "-".repeat(50));
    row(
        "attribution F1  (down)",
        rn.attribution_f1,
        rc.attribution_f1,
        Fmt::F2,
    );
    row(
        "linkage recall  (down)",
        rn.linkage_recall,
        rc.linkage_recall,
        Fmt::F2,
    );
    row(
        "fragmentation   (up)",
        rn.fragmentation,
        rc.fragmentation,
        Fmt::F2,
    );
    println!();
    verdict(&rn, &rc);
    println!();
    Ok(())
}

enum Fmt {
    Int,
    F2,
}

fn row(label: &str, naive: f64, curupira: f64, fmt: Fmt) {
    let (a, b) = match fmt {
        Fmt::Int => (format!("{}", naive as i64), format!("{}", curupira as i64)),
        Fmt::F2 => (format!("{naive:.2}"), format!("{curupira:.2}")),
    };
    println!("  {label:<26}{a:>12}{b:>12}");
}

fn verdict(naive: &Report, curupira: &Report) {
    let drop = if naive.attribution_f1 > 0.0 {
        (1.0 - curupira.attribution_f1 / naive.attribution_f1) * 100.0
    } else {
        0.0
    };
    println!(
        "  Verdict: attribution F1 {:.2} -> {:.2} ({:+.0}%). The observer that pinned",
        naive.attribution_f1, curupira.attribution_f1, -drop
    );
    println!("  each account to one operator no longer can. Noise measured, not promised.");
}

fn dump(mode: &str, agents: usize, days: i64, seed: u64, out: &str) -> Result<()> {
    let m = match mode.to_lowercase().as_str() {
        "naive" => Mode::Naive,
        _ => Mode::Curupira,
    };
    let cfg = SimConfig {
        mode: m,
        ..base_cfg(agents, days, seed)
    };
    let ledger = simulate(&Persona::presets(), &cfg);
    let json = serde_json::to_string_pretty(&ledger)?;
    std::fs::write(out, json).with_context(|| format!("writing {out}"))?;
    println!("wrote {} records to {out}", ledger.records.len());
    Ok(())
}

fn report(path: &str) -> Result<()> {
    let raw = std::fs::read_to_string(path).with_context(|| format!("reading {path}"))?;
    let ledger: Ledger = serde_json::from_str(&raw).context("parsing ledger JSON")?;
    let (_, r) = analyze(&ledger, &AdversaryConfig::default());
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}
