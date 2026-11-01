// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/plugin-loader/src/highwater.rs`.

use super::*;

/// True when the marks are backed by a data-dir file (so they survive a restart).
fn is_persistent(marks: &HighWaterMarks) -> bool {
    marks.path.is_some()
}

fn tmpdir() -> PathBuf {
    let mut p = std::env::temp_dir();
    let mut rnd = [0u8; 8];
    let _ = getrandom::fill(&mut rnd);
    p.push(format!(
        "busbar-highwater-test-{}",
        rnd.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// The child and its capture files are scoped to this case, including refusal and panic paths.
struct Directory(PathBuf);

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct ChildGuard(Option<std::process::Child>);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl ChildGuard {
    fn finish(&mut self) -> std::process::ExitStatus {
        let until = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            if let Some(status) = self.0.as_mut().unwrap().try_wait().expect("poll child") {
                self.0.take().unwrap().wait().expect("reap child");
                return status;
            }
            assert!(
                std::time::Instant::now() < until,
                "memory-only marks child did not finish"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}

/// PB-13: without a data dir the marks stay live in memory. Run in a private working directory to
/// detect an accidental relative-path file, rather than inspecting an unused temporary directory.
/// The post-exit check observes residual files, not transient creation/deletion or writes elsewhere.
#[test]
fn without_a_data_dir_the_store_creates_no_file() {
    const CHILD: &str = "BUSBAR_HIGHWATER_NO_DIRECTORY_CHILD";
    const FINISHED: &str = "highwater-memory-directory-case-finished";
    if std::env::var_os(CHILD).is_none() {
        let dir = Directory(tmpdir());
        let capture = Directory(tmpdir());
        let stdout_path = capture.0.join("stdout");
        let stderr_path = capture.0.join("stderr");
        let mut child = ChildGuard(Some(
            std::process::Command::new(std::env::current_exe().expect("test executable"))
                .args([
                    "--exact",
                    "highwater::tests::without_a_data_dir_the_store_creates_no_file",
                    "--test-threads=1",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .current_dir(&dir.0)
                .stdout(std::fs::File::create(&stdout_path).expect("capture stdout"))
                .stderr(std::fs::File::create(&stderr_path).expect("capture stderr"))
                .spawn()
                .expect("run the memory-only marks case"),
        ));
        let status = child.finish();
        let stdout = std::fs::read_to_string(stdout_path).expect("read stdout");
        let stderr = std::fs::read_to_string(stderr_path).expect("read stderr");
        assert!(
            status.success() && stdout.contains(FINISHED),
            "child status {}; stdout: {stdout}; stderr: {stderr}",
            status
        );
        assert!(
            std::fs::read_dir(&dir.0).unwrap().next().is_none(),
            "memory-only marks created a working-directory file"
        );
        return;
    }
    let (mut marks, note) = HighWaterMarks::load(None);
    assert!(note.is_none());
    assert!(!is_persistent(&marks));
    assert!(marks.raise("busbar-store-gamma-plugin", "1.2.0"));
    marks.persist().expect("a memory-only persist is a no-op");
    // The floor is live in memory regardless.
    assert_eq!(
        marks.marks().get("busbar-store-gamma-plugin").unwrap(),
        "1.2.0"
    );
    println!("{FINISHED}");
}

/// WITH a data dir the floor survives a restart — which is what makes it an anti-replay control
/// rather than a per-process one.
#[test]
fn with_a_data_dir_the_floor_survives_a_restart() {
    let dir = tmpdir();
    let (mut marks, _) = HighWaterMarks::load(Some(&dir));
    assert!(is_persistent(&marks));
    assert!(marks.raise("busbar-store-gamma-plugin", "1.2.0"));
    marks.persist().unwrap();

    let (reloaded, note) = HighWaterMarks::load(Some(&dir));
    assert!(note.is_none(), "a file this store wrote reloads clean");
    assert_eq!(
        reloaded.marks().get("busbar-store-gamma-plugin").unwrap(),
        "1.2.0",
        "the floor survives the restart"
    );
}

/// The mark is a HIGH-WATER mark: it rises and never falls. An explicit rollback loads an older
/// artifact past its pin; it must not silently erase the floor every other node still enforces.
#[test]
fn the_mark_rises_and_never_falls() {
    let (mut marks, _) = HighWaterMarks::load(None);
    assert!(marks.raise("p", "1.2.0"), "first sighting sets the mark");
    assert!(!marks.raise("p", "1.2.0"), "the same version is idempotent");
    assert!(
        !marks.raise("p", "1.0.0"),
        "an older version never lowers it"
    );
    assert_eq!(marks.marks().get("p").unwrap(), "1.2.0");
    assert!(marks.raise("p", "1.3.0"), "a newer version raises it");
    assert_eq!(marks.marks().get("p").unwrap(), "1.3.0");
}

/// A mark that cannot be parsed is worse than no mark: `version_at_least` refuses an unparsable
/// floor outright, so keeping one would refuse a good plugin forever on the strength of a corrupt
/// byte. Unusable entries are DROPPED and the caller is told.
#[test]
fn unusable_entries_are_dropped_and_reported() {
    let dir = tmpdir();
    std::fs::write(
        dir.join(HIGH_WATER_FILE),
        br#"{"good-plugin":"1.2.0","bad-plugin":"v1.2","BAD NAME":"1.0.0"}"#,
    )
    .unwrap();
    let (marks, note) = HighWaterMarks::load(Some(&dir));
    let m = marks.marks();
    assert_eq!(m.len(), 1, "only the usable entry survives: {m:?}");
    assert_eq!(m.get("good-plugin").unwrap(), "1.2.0");
    let note = note.expect("the operator is told what was dropped");
    assert!(note.contains("bad-plugin"), "{note}");
    assert!(note.contains("BAD NAME"), "{note}");
}

/// FAIL-SOFT on a damaged file: an empty mark set is the same posture as a first boot, whereas
/// refusing the boot would let anyone who can corrupt one JSON file take the node down. Loud, not
/// fatal.
#[test]
fn a_corrupt_file_boots_with_no_floor_and_says_so() {
    let dir = tmpdir();
    std::fs::write(dir.join(HIGH_WATER_FILE), b"{ this is not json").unwrap();
    let (marks, note) = HighWaterMarks::load(Some(&dir));
    assert!(marks.marks().is_empty());
    let note = note.expect("a corrupt floor must be reported");
    assert!(note.contains("NO first-party floor"), "{note}");
}

/// A missing file is the normal first-boot state, not a problem — and no floor, because a first
/// install is not a downgrade.
#[test]
fn a_missing_file_is_a_clean_first_boot() {
    let dir = tmpdir();
    let (marks, note) = HighWaterMarks::load(Some(&dir));
    assert!(note.is_none());
    assert!(marks.marks().is_empty());
    assert!(is_persistent(&marks));
}

/// The persisted file is `0600`: an integrity floor is not a secret, but it is written with the same
/// private mode as every other data-dir file.
#[cfg(unix)]
#[test]
fn the_persisted_floor_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tmpdir();
    let (mut marks, _) = HighWaterMarks::load(Some(&dir));
    marks.raise("p", "1.0.0");
    marks.persist().unwrap();
    let mode = std::fs::metadata(dir.join(HIGH_WATER_FILE))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "got {:o}", mode & 0o777);
    // The write is atomic: no temp file is left behind.
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
}
