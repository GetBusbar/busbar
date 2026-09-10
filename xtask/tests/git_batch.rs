//! Cases proving the git COPROCESSES cannot deadlock.
//!
//! THE BUG THESE PIN. `git cat-file --batch` and `git check-ignore --stdin` are request/response
//! coprocesses: the child answers on stdout WHILE the parent is still writing stdin. A parent that
//! writes every request first and only then reads (`write_all(all_of_it)` then
//! `wait_with_output()`) deadlocks the moment the answers exceed the child's stdout pipe buffer --
//! 64 KiB on Linux, 16 KiB on macOS. The child blocks writing an answer nobody is draining; the
//! parent blocks writing a request the child is no longer reading. Both ends sit in
//! `anon_pipe_write` forever, at 4% CPU, looking exactly like slow work. That is what turned
//! `cargo xtask gate --all` into a run that never finished.
//!
//! EVERY CASE HERE RUNS UNDER A WALL-CLOCK CEILING, on purpose: the red of a deadlock is a hang,
//! and a hung test proves nothing because it never reports. The watchdog turns the hang into a
//! named failure the harness can print.

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask/ has a parent")
        .to_path_buf()
}

fn tmpdir(tag: &str) -> PathBuf {
    let d = repo_root().join(".fix").join(format!(
        "xtask-test-{tag}-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).expect("scratch dir");
    d
}

/// Run `f` on its own thread and REFUSE to wait forever. A deadlocked coprocess would otherwise
/// hang the test binary, which reports nothing at all; this reports a failure with a name.
///
/// The worker thread is deliberately LEAKED on timeout: it is blocked in a pipe write and cannot
/// be joined. It dies with the process, and its child dies when the process's pipe ends close.
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
        Err(_) => panic!(
            "{label}: still running after {limit:?} -- the coprocess deadlocked \
             (parent and child both blocked writing a full pipe)"
        ),
    }
}

/// A throwaway repository. `git init` only -- nothing here needs a commit, and a commit would need
/// an identity this test has no business inventing in the caller's config.
fn scratch_repo(tag: &str) -> PathBuf {
    let d = tmpdir(tag);
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(&d)
        .args(["init", "-q"])
        .output()
        .expect("git init runs");
    assert!(out.status.success(), "git init: {out:?}");
    d
}

fn write_blob(repo: &Path, name: &str, bytes: &[u8]) -> String {
    let p = repo.join(name);
    std::fs::write(&p, bytes).expect("blob written");
    hash_objects(repo, &[p]).pop().expect("one oid back")
}

/// `git hash-object -w` over a batch of paths, because one process per blob is the difference
/// between a two-second test and a minute of `fork`.
fn hash_objects(repo: &Path, paths: &[PathBuf]) -> Vec<String> {
    let mut oids = Vec::new();
    for chunk in paths.chunks(400) {
        let out = std::process::Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(["hash-object", "-w", "--"])
            .args(chunk)
            .output()
            .expect("git hash-object runs");
        assert!(out.status.success(), "git hash-object: {out:?}");
        oids.extend(
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .map(str::to_string),
        );
    }
    oids
}

/// THE CALL RETURNS. A `write_all(everything)` + `wait_with_output()` shape does not: it deadlocks
/// on this input, and the interleaved reader is what this case pins.
///
/// BOTH SIDES have to overflow for the deadlock to bite, which is why the fixture is 4000 blobs
/// and not four big ones. 4000 oids is ~164 KiB of REQUESTS, past the pipe buffer, so the parent
/// blocks in `write_all` partway through; the answers are ~1.2 MiB, past the pipe buffer, so the
/// child blocks in its own write with nobody draining. That is the audit ledger's real shape --
/// `audit::rows` asks for every tracked blob in the tree at once -- and it is why `gate --all`
/// hung on a repository this size and not on a toy one.
#[test]
fn line_counts_over_blobs_larger_than_a_pipe_buffer_does_not_deadlock() {
    let repo = scratch_repo("line-counts-deadlock");

    let mut paths = Vec::new();
    let mut bodies = Vec::new();
    std::fs::create_dir_all(repo.join("blobs")).expect("blob dir");
    for i in 0..4000u32 {
        let line = format!("blob {i} line filler filler filler\n");
        let repeats = 300 / line.len() + 1;
        let body = line.repeat(repeats);
        let p = repo.join("blobs").join(format!("blob-{i}.txt"));
        std::fs::write(&p, body.as_bytes()).expect("blob written");
        paths.push(p);
        bodies.push(repeats);
    }
    let mut oids = std::collections::BTreeSet::new();
    let mut expected = std::collections::BTreeMap::new();
    for (oid, lines) in hash_objects(&repo, &paths).into_iter().zip(bodies) {
        expected.insert(oid.clone(), lines);
        oids.insert(oid);
    }

    let repo2 = repo.clone();
    let counts = within(
        "Git::line_counts over 4000 blobs",
        Duration::from_secs(60),
        move || xtask::audit::Git::new(&repo2).line_counts(&oids),
    );

    assert_eq!(
        counts.len(),
        expected.len(),
        "every blob asked for is answered"
    );
    for (oid, lines) in &expected {
        assert_eq!(counts.get(oid), Some(lines), "line count for {oid}");
    }
    let _ = std::fs::remove_dir_all(&repo);
}

/// A record whose header does not parse must END the read rather than shift every later count by
/// one file -- the streaming reader keeps the desync guard the buffered one had.
#[test]
fn line_counts_answers_a_missing_oid_without_desyncing_the_rest() {
    let repo = scratch_repo("line-counts-missing");
    let good = write_blob(&repo, "good.txt", b"one\ntwo\nthree\n");
    let mut oids = std::collections::BTreeSet::new();
    oids.insert(good.clone());
    // A well-formed oid that is not in the object database: git answers "<oid> missing".
    oids.insert("0".repeat(40));

    let repo2 = repo.clone();
    let counts = within(
        "Git::line_counts with a missing oid",
        Duration::from_secs(30),
        move || xtask::audit::Git::new(&repo2).line_counts(&oids),
    );

    assert_eq!(counts.get(&good), Some(&3), "the readable blob is counted");
    let _ = std::fs::remove_dir_all(&repo);
}

/// 60000 paths is ~1.3 MiB of requests and, because every one of them matches, ~1.3 MiB of
/// answers. A shape that writes every request before reading any answer does not return on this
/// input at all — it sits until the 60-second watchdog below fires. The interleaved reader does.
///
/// The scan set of a repository is smaller than that today, which is the whole hazard: the same
/// call is one `.gitignore` rule and one generated directory away from the size that wedges it.
#[test]
fn check_ignore_over_more_paths_than_a_pipe_buffer_holds_does_not_deadlock() {
    let repo = scratch_repo("check-ignore-deadlock");
    std::fs::write(repo.join(".gitignore"), "*.junk\n").expect(".gitignore written");

    let asked: Vec<String> = (0..60000)
        .map(|i| format!("dir/file-{i:06}.junk"))
        .collect();
    let n = asked.len();

    let repo2 = repo.clone();
    let ignored = within(
        "gitp::check_ignore over 60000 ignored paths",
        Duration::from_secs(60),
        move || xtask::gitp::check_ignore(&repo2, &asked),
    )
    .expect("check-ignore answers");

    assert_eq!(ignored.len(), n, "every *.junk path is reported ignored");
    let _ = std::fs::remove_dir_all(&repo);
}

/// ONE PLACE MAY PIPE A CHILD'S STDIN, and it is [`xtask::gitp::ask`].
///
/// The deadlock above is not a bug in a helper, it is a bug in a SHAPE: any `Command` that pipes
/// stdin and then reads the child afterwards has it. Fixing two call sites does nothing about the
/// third somebody writes next month, so the shape itself is what is pinned here — a new
/// `.stdin(Stdio::piped())` anywhere else in `xtask/src` fails this case by name, and the fix is
/// to route it through `ask` rather than to add an exception.
#[test]
fn nothing_outside_the_one_helper_pipes_a_child_stdin() {
    let src = repo_root().join("xtask").join("src");
    let mut offenders = Vec::new();
    let mut stack = vec![src.clone()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("xtask/src is readable") {
            let path = entry.expect("a directory entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            // gitp.rs is the helper itself: it is the one file allowed to hold a pipe.
            if path.file_name().and_then(|f| f.to_str()) == Some("gitp.rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("a readable source file");
            for (n, line) in text.lines().enumerate() {
                if line.contains(".stdin(") && line.contains("piped") {
                    offenders.push(format!(
                        "{}:{}: {}",
                        path.strip_prefix(&src).unwrap_or(&path).display(),
                        n + 1,
                        line.trim()
                    ));
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "a piped child stdin outside gitp::ask -- route it through `ask`, which cannot \
         deadlock, instead of writing the shape that did:\n  {}",
        offenders.join("\n  ")
    );
}
