//! Crash-safe checkpoint/resume for a fleet run.
//!
//! A run writes an append-only `ledger.jsonl` journal and periodically an atomically-replaced
//! `checkpoint.json` control snapshot (RNG, counters, schedule, and rotated accounts). If the
//! process is killed mid-run, `resume_durable` truncates any un-checkpointed journal tail and
//! continues from the last checkpoint. Because the sim is deterministic, the resumed final
//! ledger is byte-identical to an uninterrupted run of the same `(personas, cfg)`.
//!
//! Storage layout (a run directory):
//! ```text
//! <dir>/ledger.jsonl        append-only, one compact-JSON TxRecord per line
//! <dir>/checkpoint.json     atomically-replaced control + account-state snapshot
//! <dir>/checkpoint.json.tmp transient temp file for the temp+rename write
//! ```

use crate::{build_fresh, run_core, DurSink, RunState, SimConfig};
use adversary::model::{Ledger, TxRecord};
use chacha20::ChaCha12Rng;
use noise_core::types::AccountId;
use persona::Persona;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cmp::Reverse;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// On-disk format version. Resume refuses a checkpoint with a different version.
pub const CHECKPOINT_FORMAT: u32 = 2;

/// Identity of a run: resume refuses to continue a checkpoint whose `(personas, cfg)` differ.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RunId {
    pub format: u32,
    pub seed: u64,
    pub mode: u8,
    pub num_agents: usize,
    pub duration_secs: i64,
    pub start_ts: i64,
    pub num_external: usize,
    pub harden_timing: bool,
    /// sha256 of the canonical (personas, hardening) JSON.
    pub inputs_digest: [u8; 32],
}

impl RunId {
    pub fn derive(personas: &[Persona], cfg: &SimConfig) -> RunId {
        let mut h = Sha256::new();
        h.update(serde_json::to_vec(personas).expect("personas serialize"));
        h.update(serde_json::to_vec(&cfg.hardening).expect("hardening serialize"));
        // Fold funding into the digest only when set. This preserves deterministic identities
        // for unfunded runs while ensuring a funding-policy change is refused on resume.
        if let Some(f) = &cfg.funding {
            h.update(serde_json::to_vec(f).expect("funding serialize"));
        }
        RunId {
            format: CHECKPOINT_FORMAT,
            seed: cfg.seed,
            mode: cfg.mode as u8,
            num_agents: cfg.num_agents,
            duration_secs: cfg.duration_secs,
            start_ts: cfg.start_ts,
            num_external: cfg.num_external,
            harden_timing: cfg.harden_timing,
            inputs_digest: h.finalize().into(),
        }
    }
}

/// A durable control snapshot. It holds the 49-byte RNG blob, counters, one timestamp per
/// schedule entry, and the current account identities. Transaction records remain in the
/// append-only journal instead of being copied into every checkpoint.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Checkpoint {
    pub format: u32,
    pub run_id: RunId,
    /// `ChaCha12Rng::serialize_state()` — exactly 49 bytes (serde has no `[u8; 49]` impl).
    pub rng_state: Vec<u8>,
    pub clock: i64,
    pub slot: u64,
    pub sig: u64,
    /// `next_at[si]` for every schedule index (the heap is full at a boundary).
    pub next_at: Vec<i64>,
    /// Current rotating account identities for each agent. Address rotation makes this
    /// dynamic state, so it must be checkpointed alongside the RNG and scheduler.
    pub agent_subaccounts: Vec<Vec<AccountId>>,
    pub agent_mains: Vec<AccountId>,
    /// Records durably written to the journal == `sig` == `slot` == `ledger.records.len()`.
    pub records_emitted: u64,
    /// Byte length of `ledger.jsonl` covering exactly `records_emitted` records.
    pub journal_len_bytes: u64,
    pub events: u64,
}

/// Durability tunables.
#[derive(Clone, Copy, Debug)]
pub struct DurabilityOpts {
    /// Write a checkpoint every this many events (a terminal checkpoint is always written).
    pub snapshot_every_events: u64,
    /// `fsync` the journal + checkpoint + directory (real crash-safety). Off = faster tests.
    pub fsync: bool,
}

impl Default for DurabilityOpts {
    fn default() -> Self {
        DurabilityOpts {
            snapshot_every_events: 10_000,
            fsync: true,
        }
    }
}

impl RunState {
    /// Build a checkpoint from the current (boundary-consistent) state. Read-only on the RNG.
    pub(crate) fn snapshot(&self, run_id: &RunId, journal_len_bytes: u64) -> Checkpoint {
        let mut next_at = vec![i64::MIN; self.sched.len()];
        for &Reverse((na, si)) in self.heap.iter() {
            next_at[si] = na;
        }
        debug_assert!(
            next_at.iter().all(|&x| x != i64::MIN),
            "heap missing a schedule index at snapshot boundary"
        );
        Checkpoint {
            format: CHECKPOINT_FORMAT,
            run_id: run_id.clone(),
            rng_state: self.rng.serialize_state().to_vec(),
            clock: self.chain.clock,
            slot: self.chain.slot,
            sig: self.chain.sig,
            next_at,
            agent_subaccounts: self
                .agents
                .iter()
                .map(|agent| agent.subaccounts.clone())
                .collect(),
            agent_mains: self.agents.iter().map(|agent| agent.main).collect(),
            records_emitted: self.chain.ledger.records.len() as u64,
            journal_len_bytes,
            events: self.events,
        }
    }
}

/// The durable sink: appends records to the journal and writes checkpoints on cadence.
pub struct DurableSink {
    dir: PathBuf,
    journal: BufWriter<File>,
    run_id: RunId,
    every: u64,
    fsync: bool,
    last_snapshot_events: u64,
}

impl DurableSink {
    pub fn create(dir: &Path, run_id: RunId, opts: DurabilityOpts) -> io::Result<Self> {
        fs::create_dir_all(dir)?;
        let _ = fs::remove_file(dir.join("checkpoint.json"));
        let _ = fs::remove_file(dir.join("checkpoint.json.tmp"));
        let f = OpenOptions::new()
            .create(true)
            .write(true)
            .read(true)
            .truncate(true)
            .open(dir.join("ledger.jsonl"))?;
        Ok(Self {
            dir: dir.into(),
            journal: BufWriter::new(f),
            run_id,
            every: opts.snapshot_every_events.max(1),
            fsync: opts.fsync,
            last_snapshot_events: u64::MAX,
        })
    }

    pub fn reopen(
        dir: &Path,
        run_id: RunId,
        opts: DurabilityOpts,
        journal_len_bytes: u64,
    ) -> io::Result<Self> {
        let mut f = OpenOptions::new()
            .write(true)
            .read(true)
            .open(dir.join("ledger.jsonl"))?;
        f.seek(SeekFrom::Start(journal_len_bytes))?;
        Ok(Self {
            dir: dir.into(),
            journal: BufWriter::new(f),
            run_id,
            every: opts.snapshot_every_events.max(1),
            fsync: opts.fsync,
            last_snapshot_events: u64::MAX,
        })
    }

    fn save(&mut self, cp: &Checkpoint) -> io::Result<()> {
        // 1) The journal's first `records_emitted` records must be durable BEFORE a
        //    checkpoint names that count.
        self.journal.flush()?;
        if self.fsync {
            self.journal.get_ref().sync_all()?;
        }
        // 2) Write the checkpoint to a temp file...
        let tmp = self.dir.join("checkpoint.json.tmp");
        let final_ = self.dir.join("checkpoint.json");
        {
            let mut fh = File::create(&tmp)?;
            serde_json::to_writer(&mut fh, cp)?;
            fh.flush()?;
            if self.fsync {
                fh.sync_all()?;
            }
        }
        // 3) ...and publish it with an atomic rename.
        fs::rename(&tmp, &final_)?;
        // 4) fsync the directory so the rename survives a crash.
        if self.fsync {
            File::open(&self.dir)?.sync_all()?;
        }
        Ok(())
    }
}

impl DurSink for DurableSink {
    fn on_records(&mut self, new: &[TxRecord]) -> io::Result<()> {
        for rec in new {
            serde_json::to_writer(&mut self.journal, rec)?;
            self.journal.write_all(b"\n")?;
        }
        Ok(())
    }

    fn on_boundary(&mut self, st: &RunState, done: bool) -> io::Result<bool> {
        let cadence_hit = st.events != 0 && st.events.is_multiple_of(self.every);
        if (done || cadence_hit) && self.last_snapshot_events != st.events {
            self.journal.flush()?;
            if self.fsync {
                self.journal.get_ref().sync_all()?;
            }
            let jlen = self.journal.get_ref().metadata()?.len();
            let cp = st.snapshot(&self.run_id, jlen);
            self.save(&cp)?;
            self.last_snapshot_events = st.events;
        }
        Ok(false)
    }
}

/// Run to completion, durably. On return the run directory holds a terminal checkpoint and a
/// complete journal; the returned `Ledger` is byte-identical to `simulate(personas, cfg)`.
pub fn simulate_durable(
    personas: &[Persona],
    cfg: &SimConfig,
    dir: &Path,
    opts: DurabilityOpts,
) -> io::Result<Ledger> {
    let run_id = RunId::derive(personas, cfg);
    let mut st = build_fresh(personas, cfg);
    let mut sink = DurableSink::create(dir, run_id, opts)?;
    run_core(&mut st, &mut sink)?;
    Ok(crate::finalize_funding(st, cfg))
}

/// Resume an interrupted run from its last checkpoint and finish. Idempotent across any
/// number of crashes; resuming a finished run returns the byte-identical ledger.
pub fn resume_durable(
    personas: &[Persona],
    cfg: &SimConfig,
    dir: &Path,
    opts: DurabilityOpts,
) -> io::Result<Ledger> {
    let raw = fs::read(dir.join("checkpoint.json"))?;
    let cp: Checkpoint =
        serde_json::from_slice(&raw).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if cp.format != CHECKPOINT_FORMAT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("checkpoint format {} != {}", cp.format, CHECKPOINT_FORMAT),
        ));
    }
    let expected = RunId::derive(personas, cfg);
    if cp.run_id != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "checkpoint (personas, cfg) mismatch — refusing to resume",
        ));
    }

    let mut st = build_fresh(personas, cfg);
    if cp.next_at.len() != st.sched.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "next_at length != schedule length",
        ));
    }
    if cp.agent_subaccounts.len() != st.agents.len() || cp.agent_mains.len() != st.agents.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "checkpoint agent account state length mismatch",
        ));
    }
    for (agent, (subaccounts, main)) in st
        .agents
        .iter_mut()
        .zip(cp.agent_subaccounts.into_iter().zip(cp.agent_mains))
    {
        if subaccounts.len() != agent.subaccounts.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "checkpoint subaccount state length mismatch",
            ));
        }
        agent.subaccounts = subaccounts;
        agent.main = main;
    }
    let blob: [u8; 49] = cp
        .rng_state
        .as_slice()
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "rng_state != 49 bytes"))?;
    st.rng = ChaCha12Rng::deserialize_state(&blob);
    st.chain.clock = cp.clock;
    st.chain.slot = cp.slot;
    st.chain.sig = cp.sig;
    st.events = cp.events;
    st.heap.clear();
    for (i, &na) in cp.next_at.iter().enumerate() {
        st.heap.push(Reverse((na, i)));
    }
    st.chain.ledger.records = load_journal_prefix(
        &dir.join("ledger.jsonl"),
        cp.records_emitted,
        cp.journal_len_bytes,
    )?;

    let mut sink = DurableSink::reopen(dir, expected, opts, cp.journal_len_bytes)?;
    run_core(&mut st, &mut sink)?;
    Ok(crate::finalize_funding(st, cfg))
}

/// Load exactly `count` complete records from the journal, first truncating any bytes beyond
/// `len_bytes` (an un-checkpointed crash tail).
fn load_journal_prefix(path: &Path, count: u64, len_bytes: u64) -> io::Result<Vec<TxRecord>> {
    let f = OpenOptions::new().read(true).write(true).open(path)?;
    f.set_len(len_bytes)?;
    let _ = f.sync_all();
    let mut reader = BufReader::new(&f);
    reader.seek(SeekFrom::Start(0))?;
    let mut out = Vec::with_capacity(count as usize);
    let mut line = String::new();
    while (out.len() as u64) < count {
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            break;
        }
        if !line.ends_with('\n') {
            break; // partial trailing line — stop
        }
        let rec: TxRecord = serde_json::from_str(line.trim_end())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        out.push(rec);
    }
    if out.len() as u64 != count {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "journal has {} committed records, checkpoint claims {}",
                out.len(),
                count
            ),
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{simulate, Mode};
    use std::sync::atomic::{AtomicU64, Ordering};

    static CTR: AtomicU64 = AtomicU64::new(0);

    fn tmpdir(tag: &str) -> PathBuf {
        let id = CTR.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "account-cooker_dur_{}_{}_{}",
            std::process::id(),
            tag,
            id
        ));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn small_cfg(mode: Mode, harden: bool) -> SimConfig {
        SimConfig {
            num_agents: 8,
            duration_secs: 2 * 86_400,
            mode,
            harden_timing: harden,
            ..SimConfig::default()
        }
    }

    fn same_records(a: &Ledger, b: &Ledger) -> bool {
        a.records.len() == b.records.len()
            && a.records.iter().zip(&b.records).all(|(x, y)| {
                (
                    x.sig,
                    x.slot,
                    x.ts,
                    x.fee_payer,
                    x.source,
                    x.dest,
                    x.amount,
                    x.kind,
                    x.operator,
                ) == (
                    y.sig,
                    y.slot,
                    y.ts,
                    y.fee_payer,
                    y.source,
                    y.dest,
                    y.amount,
                    y.kind,
                    y.operator,
                )
            })
    }

    #[test]
    fn durable_completion_equals_simulate() {
        let personas = Persona::presets();
        for (mode, harden) in [(Mode::Naive, false), (Mode::Cooker, true)] {
            let cfg = small_cfg(mode, harden);
            let dir = tmpdir("complete");
            let opts = DurabilityOpts {
                snapshot_every_events: 50,
                fsync: false,
            };
            let durable = simulate_durable(&personas, &cfg, &dir, opts).unwrap();
            let golden = simulate(&personas, &cfg);
            assert!(same_records(&durable, &golden), "durable run != simulate");

            // The journal alone reloads to the same ledger.
            let raw = fs::read(dir.join("checkpoint.json")).unwrap();
            let cp: Checkpoint = serde_json::from_slice(&raw).unwrap();
            let recs = load_journal_prefix(
                &dir.join("ledger.jsonl"),
                cp.records_emitted,
                cp.journal_len_bytes,
            )
            .unwrap();
            assert!(
                same_records(&Ledger { records: recs }, &golden),
                "journal != golden"
            );
            let _ = fs::remove_dir_all(&dir);
        }
    }

    /// Stop after K events (no terminal finalize), leaving a mid-run checkpoint, then resume.
    struct CrashSink {
        inner: DurableSink,
        stop_after: u64,
    }
    impl DurSink for CrashSink {
        fn on_records(&mut self, new: &[TxRecord]) -> io::Result<()> {
            self.inner.on_records(new)
        }
        fn on_boundary(&mut self, st: &RunState, done: bool) -> io::Result<bool> {
            self.inner.on_boundary(st, done)?;
            Ok(st.events >= self.stop_after)
        }
    }

    #[test]
    fn mid_run_resume_equals_golden() {
        let personas = Persona::presets();
        for (mode, harden) in [(Mode::Naive, false), (Mode::Cooker, true)] {
            let cfg = small_cfg(mode, harden);
            let golden = simulate(&personas, &cfg);
            let total_events = golden.records.len().max(4);
            for frac in [0.2f64, 0.5, 0.85] {
                let dir = tmpdir("resume");
                let opts = DurabilityOpts {
                    snapshot_every_events: 25,
                    fsync: false,
                };
                let run_id = RunId::derive(&personas, &cfg);
                let mut st = build_fresh(&personas, &cfg);
                let mut crash = CrashSink {
                    inner: DurableSink::create(&dir, run_id, opts).unwrap(),
                    stop_after: (total_events as f64 * frac) as u64,
                };
                run_core(&mut st, &mut crash).unwrap();
                drop(crash);
                // A checkpoint must exist to resume from.
                assert!(
                    dir.join("checkpoint.json").exists(),
                    "no checkpoint at frac {frac}"
                );
                let resumed = resume_durable(&personas, &cfg, &dir, opts).unwrap();
                assert!(
                    same_records(&resumed, &golden),
                    "resume(frac={frac}) != golden"
                );
                let _ = fs::remove_dir_all(&dir);
            }
        }
    }

    /// Crash-safety holds with funding ON: the funding post-pass is applied identically after a
    /// fresh finish and after a mid-run resume, so the funded ledger is byte-identical either way.
    #[test]
    fn mid_run_resume_equals_golden_with_funding() {
        use crate::{FundingConfig, FundingPolicy};
        let personas = Persona::presets();
        let cfg = SimConfig {
            funding: Some(FundingConfig::new(FundingPolicy::SharedRelayers { k: 3 })),
            ..small_cfg(Mode::Cooker, true)
        };
        let golden = simulate(&personas, &cfg);
        let total_events = golden.records.len().max(4);
        for frac in [0.3f64, 0.7] {
            let dir = tmpdir("resume-fund");
            let opts = DurabilityOpts {
                snapshot_every_events: 25,
                fsync: false,
            };
            let run_id = RunId::derive(&personas, &cfg);
            let mut st = build_fresh(&personas, &cfg);
            let mut crash = CrashSink {
                inner: DurableSink::create(&dir, run_id, opts).unwrap(),
                stop_after: (total_events as f64 * frac) as u64,
            };
            run_core(&mut st, &mut crash).unwrap();
            drop(crash);
            let resumed = resume_durable(&personas, &cfg, &dir, opts).unwrap();
            assert!(
                same_records(&resumed, &golden),
                "funded resume(frac={frac}) != golden"
            );
            let _ = fs::remove_dir_all(&dir);
        }
    }

    /// A checkpoint written under one funding policy refuses to resume under another.
    #[test]
    fn resume_refuses_funding_mismatch() {
        use crate::{FundingConfig, FundingPolicy};
        let personas = Persona::presets();
        let hub = SimConfig {
            funding: Some(FundingConfig::new(FundingPolicy::OperatorHub)),
            ..small_cfg(Mode::Cooker, true)
        };
        let dir = tmpdir("fund-mismatch");
        let opts = DurabilityOpts {
            snapshot_every_events: 25,
            fsync: false,
        };
        let run_id = RunId::derive(&personas, &hub);
        let mut st = build_fresh(&personas, &hub);
        let mut crash = CrashSink {
            inner: DurableSink::create(&dir, run_id, opts).unwrap(),
            stop_after: 2,
        };
        run_core(&mut st, &mut crash).unwrap();
        drop(crash);
        let relayers = SimConfig {
            funding: Some(FundingConfig::new(FundingPolicy::SharedRelayers { k: 2 })),
            ..small_cfg(Mode::Cooker, true)
        };
        assert!(
            resume_durable(&personas, &relayers, &dir, opts).is_err(),
            "must refuse a changed funding policy"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// A `None`-funding run keeps the deterministic digest of the unfunded input set.
    #[test]
    fn funding_none_keeps_unfunded_digest() {
        use crate::{FundingConfig, FundingPolicy};
        let personas = Persona::presets();
        let none = small_cfg(Mode::Cooker, true);
        let some = SimConfig {
            funding: Some(FundingConfig::new(FundingPolicy::OperatorHub)),
            ..none.clone()
        };
        let d_none = RunId::derive(&personas, &none);
        let d_some = RunId::derive(&personas, &some);
        assert_ne!(
            d_none.inputs_digest, d_some.inputs_digest,
            "funding must change the digest when set"
        );
        // And two None runs agree (sanity: the None branch adds nothing).
        assert_eq!(
            d_none.inputs_digest,
            RunId::derive(&personas, &none).inputs_digest
        );
    }

    #[test]
    fn resume_truncates_torn_tail_and_rejects_mismatch() {
        let personas = Persona::presets();
        let cfg = small_cfg(Mode::Cooker, true);
        let golden = simulate(&personas, &cfg);
        let dir = tmpdir("torn");
        let opts = DurabilityOpts {
            snapshot_every_events: 25,
            fsync: false,
        };
        let run_id = RunId::derive(&personas, &cfg);
        let mut st = build_fresh(&personas, &cfg);
        let mut crash = CrashSink {
            inner: DurableSink::create(&dir, run_id, opts).unwrap(),
            stop_after: (golden.records.len() as f64 * 0.4) as u64,
        };
        run_core(&mut st, &mut crash).unwrap();
        drop(crash);

        // Append surplus well-formed records + a partial (newline-less) line past the cut.
        {
            let mut f = OpenOptions::new()
                .append(true)
                .open(dir.join("ledger.jsonl"))
                .unwrap();
            for r in &golden.records[0..3] {
                serde_json::to_writer(&mut f, r).unwrap();
                f.write_all(b"\n").unwrap();
            }
            f.write_all(b"{\"sig\":999,\"partial\":").unwrap(); // torn fragment, no newline
        }
        let resumed = resume_durable(&personas, &cfg, &dir, opts).unwrap();
        assert!(
            same_records(&resumed, &golden),
            "torn-tail resume != golden"
        );

        // A config mismatch (different seed => different RunId) is refused.
        let other = SimConfig {
            seed: cfg.seed + 1,
            ..cfg.clone()
        };
        assert!(resume_durable(&personas, &other, &dir, opts).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rng_matches_stdrng_and_round_trips() {
        use rand::rngs::StdRng;
        use rand::{RngExt, SeedableRng};
        // StdRng is a newtype over chacha20::ChaCha12Rng; the streams must match so golden
        // output is unchanged.
        let mut a = StdRng::seed_from_u64(0x1234_5678);
        let mut b = ChaCha12Rng::seed_from_u64(0x1234_5678);
        for _ in 0..256 {
            assert_eq!(a.random::<u64>(), b.random::<u64>());
        }
        // serialize/deserialize from a mid-stream (non-block-aligned) position reproduces the tail.
        let _ = b.random::<u64>();
        let _ = b.random::<u32>();
        let blob = b.serialize_state();
        let mut c = ChaCha12Rng::deserialize_state(&blob);
        for _ in 0..64 {
            assert_eq!(b.random::<u64>(), c.random::<u64>());
        }
    }
}
