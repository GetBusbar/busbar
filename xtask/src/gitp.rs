//! Git, as a PROCESS, never as a crate.
//!
//! `libgit2`/`gix` is a large dependency in a crate whose selling point is having one; the gates
//! need git's OWN semantics for `cherry-pick -x`, `ls-files` and protected-branch reads; and the
//! process boundary is what lets a self-test point `GIT_DIR` at a throwaway repository.
//!
//! Every invocation is `git -C <root> …`. There is no `cd` anywhere in this crate.

use std::path::Path;
use std::process::Command;

/// Run git and return stdout. A non-zero status is an ERROR, never stdout-so-far: the shell idiom
/// that swallowed a producer's exit status across a pipe is the bug this signature prevents.
pub fn git(root: &Path, args: &[&str]) -> Result<String, String> {
    git_with_env(root, args, &[])
}

/// The same, with extra environment — `GIT_DIR`, `GIT_AUTHOR_*` and friends for a throwaway repo.
pub fn git_with_env(root: &Path, args: &[&str], env: &[(&str, &str)]) -> Result<String, String> {
    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(root).args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd
        .output()
        .map_err(|e| format!("git {}: {e}", args.join(" ")))?;
    if !out.status.success() {
        return Err(format!(
            "git {} exited {}: {}",
            args.join(" "),
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    String::from_utf8(out.stdout)
        .map_err(|e| format!("git {}: non-utf8 stdout: {e}", args.join(" ")))
}

pub fn git_lines(root: &Path, args: &[&str]) -> Result<Vec<String>, String> {
    Ok(git(root, args)?
        .lines()
        .map(str::to_string)
        .filter(|l| !l.trim().is_empty())
        .collect())
}

// ---------------------------------------------------------------------------------------------
// coprocesses
// ---------------------------------------------------------------------------------------------

/// A child that is still running. Killed and reaped on drop, so an early return — a parse that
/// gives up, a `?`, a panic — never leaves a `git … --batch` behind holding a pipe.
struct Reaped(std::process::Child);

impl Drop for Reaped {
    fn drop(&mut self) {
        // Both are ignored on purpose: the ordinary path has already waited, and `kill` on an
        // already-reaped child is an error that means exactly "there was nothing left to do".
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// What a coprocess run gives back: whatever the reader made of stdout, plus the status and
/// stderr the caller needs to tell "no matches" from "git is broken".
pub struct Answered<T> {
    pub value: T,
    pub status: std::process::ExitStatus,
    pub stderr: String,
}

/// **THE ONE WAY THIS CRATE TALKS TO A REQUEST/RESPONSE GIT CHILD.**
///
/// `cat-file --batch`, `check-ignore --stdin`, `hash-object --stdin-paths`, `rev-list --stdin`:
/// every one of them ANSWERS WHILE IT IS STILL BEING ASKED. The obvious shape —
///
/// ```text
/// stdin.write_all(every_request)?;      // parent blocks here…
/// let out = child.wait_with_output()?;  // …and never reaches here
/// ```
///
/// — is a deadlock with a size threshold on it, which is the worst kind. Under the threshold it is
/// correct and fast; over it, the child fills its stdout pipe (64 KiB on Linux, 16 KiB on macOS)
/// with answers nobody is draining and stops reading, the parent fills the stdin pipe with
/// requests nobody is reading, and BOTH ends sit in `anon_pipe_write` forever at 4% CPU. It looks
/// like slow work, not like a hang. `cargo xtask gate --all` wore that for 43 minutes.
///
/// So the three streams get three owners: a WRITER THREAD feeds stdin and closes it at EOF, a
/// DRAINER THREAD takes stderr (small, but an undrained pipe is an undrained pipe), and the
/// CALLER'S thread reads stdout as it arrives. Nothing waits on a full buffer, because nothing
/// holds two of them at once. The reader is handed a `BufRead` rather than a `Vec` so a caller can
/// consume record by record and keep MEMORY bounded too: `line_counts` over a whole tree would
/// otherwise buffer every byte of every file in the repository to count its newlines.
///
/// Whatever the reader leaves behind is drained before the wait, so the child can always finish
/// its last write and exit rather than blocking on a pipe the parent stopped caring about.
pub fn ask<T>(
    root: &Path,
    args: &[&str],
    requests: Vec<u8>,
    read: impl FnOnce(&mut dyn std::io::BufRead) -> T,
) -> Result<Answered<T>, String> {
    use std::io::{BufReader, Read, Write};

    let label = format!("git {}", args.join(" "));
    let mut child = Reaped(
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("{label}: {e}"))?,
    );

    let mut stdin = child.0.stdin.take().ok_or(format!("{label}: no stdin"))?;
    let writer = std::thread::spawn(move || {
        // A broken pipe here is the child having exited early, which the status below reports
        // properly; it is not a reason to fail the read that is about to explain why.
        let _ = stdin.write_all(&requests);
        let _ = stdin.flush();
        drop(stdin); // CLOSE: a `--batch` reader runs until EOF and only then exits.
    });

    let mut stderr = child.0.stderr.take().ok_or(format!("{label}: no stderr"))?;
    let drainer = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr.read_to_end(&mut buf);
        buf
    });

    let stdout = child.0.stdout.take().ok_or(format!("{label}: no stdout"))?;
    let mut out = BufReader::new(stdout);
    let value = read(&mut out);
    // Whatever the reader did not want, so the child's last write completes and it can exit.
    let _ = std::io::copy(&mut out, &mut std::io::sink());
    drop(out);

    let _ = writer.join();
    let stderr = drainer.join().unwrap_or_default();
    let status = child.0.wait().map_err(|e| format!("{label}: {e}"))?;
    Ok(Answered {
        value,
        status,
        stderr: String::from_utf8_lossy(&stderr).trim().to_string(),
    })
}

/// Which of `paths` the working tree's ignore rules exclude — `git check-ignore --stdin`, asked
/// ONCE for the whole batch rather than once per file.
///
/// THE EXIT STATUS IS THREE-VALUED HERE and collapsing it is the hazard: **0** means some path
/// matched, **1** means NONE did (the ordinary answer for a clean scan set, and emphatically not an
/// error), and anything else is git failing. So 1 is `Ok(empty)` and 128 is an `Err` — the opposite
/// of what a plain `success()` test would say, which would report every clean tree as unreadable
/// and every broken git as "nothing is ignored".
///
/// The paths go in NUL-separated (`-z`) because a filename may legally contain a newline, and a
/// line-oriented protocol would silently split one into two paths, neither of which exists.
///
/// IT IS A COPROCESS, so it goes through [`ask`] and not through `wait_with_output`: git prints a
/// match the moment it finds one, and a scan set big enough to fill both pipes at once deadlocked
/// the pair for as long as this wrote every path before reading a single answer.
pub fn check_ignore(root: &Path, paths: &[String]) -> Result<Vec<String>, String> {
    if paths.is_empty() {
        return Ok(Vec::new());
    }
    let mut requests = Vec::new();
    for p in paths {
        requests.extend_from_slice(p.as_bytes());
        requests.push(0);
    }
    let answered = ask(root, &["check-ignore", "--stdin", "-z"], requests, |out| {
        let mut buf = Vec::new();
        let _ = out.read_to_end(&mut buf);
        buf
    })?;
    match answered.status.code() {
        Some(0) | Some(1) => Ok(String::from_utf8_lossy(&answered.value)
            .split('\0')
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect()),
        other => Err(format!(
            "git check-ignore exited {}: {}",
            other.unwrap_or(-1),
            answered.stderr
        )),
    }
}
