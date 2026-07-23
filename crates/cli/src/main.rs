//! `curupira` CLI.
//!
//! `demo`   run naive vs Curupira fleets and print the before/after attribution numbers
//! `dump`   write a simulated ledger to JSON
//! `report` score a ledger JSON with O Cacador

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use agent_runtime::{simulate, Mode, SimConfig};
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
    let base = base_cfg(agents, days, seed);
    // Three ledgers: naive baseline, hardened Curupira (default), and legacy (un-hardened).
    let naive = simulate(&personas, &SimConfig { mode: Mode::Naive, ..base.clone() });
    let hardened = simulate(
        &personas,
        &SimConfig { mode: Mode::Curupira, harden_timing: true, ..base.clone() },
    );
    let legacy = simulate(
        &personas,
        &SimConfig { mode: Mode::Curupira, harden_timing: false, ..base.clone() },
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
    println!("  {:<24}{:>10}{:>10}{:>10}", "", "NAIVE", "CURUPIRA", "LEGACY");
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
    row3("attribution F1  (down)", n_x.attribution_f1, h_x.attribution_f1, l_x.attribution_f1, Fmt::F2);
    row3("precision", n_x.attribution_precision, h_x.attribution_precision, l_x.attribution_precision, Fmt::F2);
    println!();
    println!("  -- adversary: windowed v3 (the HEADLINE — buckets by dt) --");
    row3("attribution F1  (down)", n_w.attribution_f1, h_w.attribution_f1, l_w.attribution_f1, Fmt::F2);
    row3("precision (up=honest)", n_w.attribution_precision, h_w.attribution_precision, l_w.attribution_precision, Fmt::F2);
    row3("linkage recall  (down)", n_w.linkage_recall, h_w.linkage_recall, l_w.linkage_recall, Fmt::F2);
    row3("largest cluster (down)", n_w.largest_cluster_frac, h_w.largest_cluster_frac, l_w.largest_cluster_frac, Fmt::F2);
    println!();
    verdict(&n_w, &h_w, &h_x);
    ablation(&hardened);
    println!();
    Ok(())
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
        println!(
            "  Verdict: the noise did not measurably help against the windowed adversary",
        );
        println!(
            "  (F1 {:.2} vs naive {:.2}). The harness reports it honestly, no spin.",
            hardened_w.attribution_f1, naive_w.attribution_f1
        );
    }
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
    // Score with the windowed adversary.
    let (_, r) = analyze(&ledger, &AdversaryConfig::windowed(120));
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}
