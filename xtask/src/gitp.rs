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
