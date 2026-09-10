//! Cases proving the gate runner stays ANSWERABLE when a gate does not return.
//!
//! A gate that hangs -- a deadlocked git child, a wedged subprocess, an accidental infinite loop --
//! used to take the whole runner with it: `cargo xtask gate --all` printed the gates before it and
//! then sat at 4% CPU forever, with the hung gate's rows neither green nor red but simply never
//! printed. SILENTLY PENDING is the worst verdict a gate runner can give, because it is
//! indistinguishable from slow and nobody can act on it.
//!
//! THE CEILING IS WHAT MAKES THE DIFFERENCE OBSERVABLE. `execute` has no ceiling and never will:
//! run these same cases against `gates::execute(&SleepyGate, &cx())` and they do not finish, they
//! sit until the watchdog below fires. That is the behaviour the ceiling replaces with a verdict.
//!
//! Every case runs under its own watchdog, because the red of a missing ceiling is a hang and a
//! hung test binary reports nothing at all.

use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

use xtask::ctx::Ctx;
use xtask::gates::{self, Gate, Report};
use xtask::ledger::{Row, Status, Verdict};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask/ has a parent")
        .to_path_buf()
}

fn cx() -> Ctx {
    Ctx::new(repo_root()).expect("the real tree opens with a writable scratch dir")
}

/// Run `f` on its own thread and REFUSE to wait forever, so a hang is a named failure.
fn within<T: Send + 'static>(
    label: &str,
    limit: Duration,
    f: impl FnOnce() -> T + Send + 'static,
) -> T {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    match rx.recv_timeout(limit) {
        Ok(v) => v,
        Err(_) => panic!("{label}: still running after {limit:?} -- the runner has no ceiling"),
    }
}

/// A gate that does not come back. The ceiling exists for whatever the reason turns out to be;
/// the `git cat-file --batch` deadlock is only the way it happened the first time.
struct SleepyGate;

impl Gate for SleepyGate {
    fn name(&self) -> &'static str {
        "sleepy"
    }
    fn owed(&self) -> Vec<String> {
        vec!["sleepy/one".to_string(), "sleepy/two".to_string()]
    }
    fn run(&self, _cx: &Ctx) -> Verdict {
        std::thread::sleep(Duration::from_secs(600));
        Verdict::of(vec![Row::pass("sleepy/one", "never", "reached")])
    }
    fn selftest(&self, _cx: &Ctx) -> Report {
        Report::new()
    }
}

fn build_sleepy() -> Box<dyn Gate> {
    Box::new(SleepyGate)
}

struct BriskGate;

impl Gate for BriskGate {
    fn name(&self) -> &'static str {
        "brisk"
    }
    fn owed(&self) -> Vec<String> {
        vec!["brisk/one".to_string()]
    }
    fn run(&self, _cx: &Ctx) -> Verdict {
        Verdict::of(vec![Row::pass("brisk/one", "brisk", "done")])
    }
    fn selftest(&self, _cx: &Ctx) -> Report {
        Report::new()
    }
}

fn build_brisk() -> Box<dyn Gate> {
    Box::new(BriskGate)
}

#[test]
fn a_gate_that_runs_past_its_ceiling_is_red_and_says_hung() {
    let verdict = within(
        "execute_within over a gate that sleeps",
        Duration::from_secs(30),
        || gates::execute_within("sleepy", build_sleepy, &cx(), Duration::from_millis(200)),
    );

    assert!(verdict.red, "a gate over its ceiling is RED");
    assert_eq!(
        verdict.rows.len(),
        2,
        "EVERY owed row is accounted for, never silently pending"
    );
    for row in &verdict.rows {
        assert_eq!(row.status, Status::Fail, "{} is FAIL", row.id);
        assert!(
            row.detail.contains("hung") || row.title.contains("hung"),
            "the row says why: {} / {}",
            row.title,
            row.detail
        );
    }
}

/// The ceiling is a guard, not a policy: a gate that finishes inside it is judged exactly as
/// [`gates::execute`] judges it.
#[test]
fn a_gate_inside_its_ceiling_is_reconciled_normally() {
    let verdict = within(
        "execute_within over a brisk gate",
        Duration::from_secs(30),
        || gates::execute_within("brisk", build_brisk, &cx(), Duration::from_secs(30)),
    );
    assert!(!verdict.red, "a green gate stays green: {:?}", verdict.rows);
    assert_eq!(verdict.rows.len(), 1);
}

/// The ceiling has a default, a global override and a per-gate override, in that order of
/// narrowness -- the box that needs a bigger number is never the box the number was written on.
#[test]
fn the_ceiling_has_a_default_a_global_override_and_a_per_gate_override() {
    let default = gates::ceiling_for("kind-isolation", |_| None);
    assert_eq!(default, Some(gates::DEFAULT_GATE_CEILING));

    let global = gates::ceiling_for("kind-isolation", |k| {
        (k == "XTASK_GATE_CEILING_SECS").then(|| "90".to_string())
    });
    assert_eq!(global, Some(Duration::from_secs(90)));

    let per_gate = gates::ceiling_for("kind-isolation", |k| match k {
        "XTASK_GATE_CEILING_SECS" => Some("90".to_string()),
        "XTASK_GATE_CEILING_SECS_KIND_ISOLATION" => Some("7".to_string()),
        _ => None,
    });
    assert_eq!(per_gate, Some(Duration::from_secs(7)), "the narrower wins");

    let off = gates::ceiling_for("kind-isolation", |k| {
        (k == "XTASK_GATE_CEILING_SECS").then(|| "0".to_string())
    });
    assert_eq!(off, None, "0 disables the ceiling");
}

/// AN UNREADABLE OVERRIDE IS THE DEFAULT, never "no ceiling". A typo in an environment variable is
/// exactly the sort of thing that would otherwise re-open the 43-minute hang, silently.
#[test]
fn an_unreadable_override_falls_back_to_the_default_rather_than_disabling_the_ceiling() {
    let bad = gates::ceiling_for("kind-isolation", |k| {
        (k == "XTASK_GATE_CEILING_SECS").then(|| "five minutes".to_string())
    });
    assert_eq!(bad, Some(gates::DEFAULT_GATE_CEILING));
}
