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
/// THE WRITE HAPPENS ON ITS OWN THREAD, and that is not a refinement — it is what stops this
/// function from HANGING FOREVER. `git check-ignore --stdin` is a STREAM: it reads a path, decides,
/// writes the matches out, and keeps going. Both pipes are OS pipes with a fixed buffer (64 KiB on
/// Linux, less on macOS). A caller that writes the WHOLE path list before reading a single byte of
/// stdout deadlocks the moment the answers outgrow that buffer: git blocks writing to a stdout
/// nobody is draining, so it stops reading stdin, so the parent blocks writing to a stdin nobody is
/// draining, and neither side can move. Nothing times out — the job simply never ends, which is the
/// worst shape a gate can fail in, because a hang is not red and a scan set only has to grow.
///
/// The size at which it bites is a property of the TREE, not of this code, so it cannot be reasoned
/// away: the scan sets here are whole-repository walks, and one gate whose set is mostly ignored
/// paths (a populated `target/`, a restored build cache) is enough. So the writer thread owns
/// `stdin` and drops it — which is also what sends git EOF — while this thread sits in
/// `wait_with_output`, draining stdout and stderr concurrently.
pub fn check_ignore(root: &Path, paths: &[String]) -> Result<Vec<String>, String> {
    use std::io::Write;

    if paths.is_empty() {
        return Ok(Vec::new());
    }
    let mut child = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["check-ignore", "--stdin", "-z"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("git check-ignore: {e}"))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or("git check-ignore: no stdin pipe".to_string())?;
    let mut buf = Vec::new();
    for p in paths {
        buf.extend_from_slice(p.as_bytes());
        buf.push(0);
    }
    // A closed pipe is git having exited early, which the status below reports properly.
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&buf);
        // Dropping `stdin` here is the EOF git waits for before it exits.
    });
    let out = child
        .wait_with_output()
        .map_err(|e| format!("git check-ignore: {e}"))?;
    // git has exited, so the writer is either done or holding a broken pipe it already ignores.
    let _ = writer.join();
    match out.status.code() {
        Some(0) | Some(1) => Ok(String::from_utf8_lossy(&out.stdout)
            .split('\0')
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect()),
        other => Err(format!(
            "git check-ignore exited {}: {}",
            other.unwrap_or(-1),
            String::from_utf8_lossy(&out.stderr).trim()
        )),
    }
}
