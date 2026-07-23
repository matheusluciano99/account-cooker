//! Real SIGKILL crash-recovery proof.
//!
//! Kills the durable runner mid-run twice (a crash, then a crash of a resume), resumes to
//! completion, and asserts the final ledger is BYTE-IDENTICAL to an uninterrupted run. Because
//! the simulator is deterministic, byte-identical also proves no lost or duplicated records
//! (golden's `sig`s are the contiguous 1..=N).
//!
//! Heavy + spawns processes + uses `timeout`. Excluded from the default suite. Run with:
//!   cargo test -p curupira-cli --release -- --ignored crash_recovery

use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_curupira")
}

fn common() -> Vec<&'static str> {
    vec![
        "run",
        "--mode",
        "curupira",
        "--agents",
        "300",
        "--days",
        "7",
        "--external",
        "1200",
        "--seed",
        "9",
        "--checkpoint-every",
        "2000",
    ]
}

#[test]
#[ignore]
fn sigkill_resume_is_byte_identical() {
    let tmp = std::env::temp_dir().join(format!("curupira_crash_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let g_dir = tmp.join("G");
    let c_dir = tmp.join("C");
    let golden = tmp.join("golden.json");
    let resumed = tmp.join("resumed.json");
    let s = |p: &Path| p.to_str().unwrap().to_string();

    // Golden, uninterrupted.
    let st = Command::new(bin())
        .args(common())
        .args(["--dir", &s(&g_dir), "--out", &s(&golden)])
        .status()
        .unwrap();
    assert!(st.success(), "golden run failed");

    // Two SIGKILLs mid-run: a fresh crash, then a crash of a resume.
    for (i, extra) in [Vec::<&str>::new(), vec!["--resume"]]
        .into_iter()
        .enumerate()
    {
        let killed = Command::new("timeout")
            .args(["-s", "KILL", "0.6"])
            .arg(bin())
            .args(common())
            .args(["--dir", &s(&c_dir), "--out", &s(&resumed)])
            .args(&extra)
            .status()
            .unwrap();
        // The run was either killed by a signal (the crash we forced) or — if it happened to
        // finish within the window — exited cleanly. Both are acceptable interruption states.
        assert!(
            killed.signal().is_some() || killed.success(),
            "crash {i}: unexpected status {killed:?}"
        );
        assert!(
            c_dir.join("checkpoint.json").exists(),
            "crash {i}: no checkpoint was written before the kill (workload too short?)"
        );
    }

    // Final resume to completion.
    let st = Command::new(bin())
        .args(common())
        .args(["--dir", &s(&c_dir), "--out", &s(&resumed), "--resume"])
        .status()
        .unwrap();
    assert!(st.success(), "final resume failed");

    // The killer claim: byte-identical to the uninterrupted run.
    let a = std::fs::read(&golden).unwrap();
    let b = std::fs::read(&resumed).unwrap();
    assert!(!a.is_empty(), "golden ledger is empty");
    assert_eq!(
        a, b,
        "resumed ledger is NOT byte-identical to the uninterrupted golden run"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}
