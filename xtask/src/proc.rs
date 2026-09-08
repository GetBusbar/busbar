//! A CHILD PROCESS THAT IS BOUNDED IN TIME.
//!
//! Both runners that shell out — [`crate::parity`], which drives the legacy script a conversion is
//! being compared against, and [`crate::full_gate`], which drives the real CI commands — called
//! `Command::…output()`, which waits forever. A legacy script that hangs (an interpreter blocked on
//! stdin because a flag was dropped), a wedged cargo child, a network read with no timeout of its
//! own: any of them and the run produces NO VERDICT AT ALL — neither red nor green, which is the one
//! state the ledger's whole design refuses. "The gate did not answer" is not one of the four exit
//! codes `cli.rs` contracts, and a runner with no verdict is a runner somebody eventually kills and
//! reports on from memory.
//!
//! ## Why this is a helper and not a crate
//!
//! `std` has no `wait_timeout`, and this crate's near-total absence of dependencies is deliberate.
//! What it needs is small: read both pipes on their own threads so a child that fills a pipe buffer
//! cannot deadlock against a parent that is waiting rather than reading, and poll `try_wait` against
//! a deadline so the parent can decide to stop waiting. No channel, no shared ownership — the parent
//! keeps the `Child` and is therefore the one that can kill it.
//!
//! ## The limit is a parameter, never a constant in here
//!
//! A legacy shell script and `cargo test --workspace` do not deserve the same patience, and a test
//! must be able to ask for a limit measured in milliseconds. Every caller names its own, at the call
//! site, in a diff.

use std::io::Read;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

/// How often the parent asks whether the child is done. Short enough that the limit is honoured to
/// a human's precision, long enough that waiting costs nothing.
const POLL: Duration = Duration::from_millis(25);

/// Run `cmd` to completion, or kill it and refuse once `limit` has passed.
///
/// The error is a message, not an `Output`: a child that had to be killed produced no verdict, and
/// handing back whatever it managed to print would let a caller read a partial run as a whole one.
pub fn output_with_timeout(cmd: &mut Command, limit: Duration) -> Result<Output, String> {
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("could not start the process: {e}"))?;

    // THE PIPES ARE DRAINED WHILE THE CHILD RUNS. A parent that waits without reading deadlocks the
    // moment the child fills a pipe buffer — which would turn this timeout into the very hang it
    // exists to bound, on any child that prints more than a page.
    let mut out = child.stdout.take();
    let mut err = child.stderr.take();
    let ho = std::thread::spawn(move || read_all(&mut out));
    let he = std::thread::spawn(move || read_all(&mut err));

    let deadline = Instant::now() + limit;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(e) => return Err(format!("could not wait for the process: {e}")),
        }
        if Instant::now() >= deadline {
            return Err(kill_and_report(&mut child, limit));
        }
        std::thread::sleep(POLL);
    };

    Ok(Output {
        status,
        stdout: ho.join().unwrap_or_default(),
        stderr: he.join().unwrap_or_default(),
    })
}

fn read_all(pipe: &mut Option<impl Read>) -> Vec<u8> {
    let mut buf = Vec::new();
    if let Some(p) = pipe {
        let _ = p.read_to_end(&mut buf);
    }
    buf
}

/// Kill the child and REAP IT. Without the `wait` the process stays a zombie for the life of the
/// runner, and a `gate --all` that timed out on three gates would leave three behind.
fn kill_and_report(child: &mut Child, limit: Duration) -> String {
    let _ = child.kill();
    let _ = child.wait();
    format!(
        "the process did not finish within {}s and was killed. That is not a failure and not a \
         pass — it is a run with no verdict, which is the one answer this runner may never report. \
         If the command is legitimately slower than its limit, raise the limit at the call site \
         where it is written down.",
        limit.as_secs_f64()
    )
}
