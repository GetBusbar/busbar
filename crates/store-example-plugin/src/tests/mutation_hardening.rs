// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Mutation-hardening: closes gaps `src/tests.rs`'s ABI-round-trip coverage didn't pin — narrow
//! boundary conditions in
//! `FileStore::load_from`, `lock_path_for`, `purge_tasks_before`'s age cutoff, and the
//! append-is-idempotent-or-forked settlement on the task-event / call logs.

use super::*;

fn body<T: serde::Serialize>(v: &T) -> Vec<u8> {
    serde_json::to_vec(v).unwrap()
}

fn temp_path(tag: &str) -> PathBuf {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut path = std::env::temp_dir();
    path.push(format!(
        "busbar-store-example-plugin-mutation-{tag}-{}-{n}.json",
        std::process::id(),
    ));
    let _ = std::fs::remove_file(&path);
    path
}

// ── `FileStore::load_from`: the empty-file / present-but-empty-bytes branch ─────────────────────
//
// Mutant: `replace match guard !bytes.is_empty() with true` — an on-disk file that exists but is
// zero bytes long (e.g. created by `OpenOptions::create` racing a write, or a truncated crash) must
// still open as `Durable::default()`, NOT be handed to `serde_json::from_slice` as if it had
// content (which would fail to parse and turn a legitimate "nothing written yet" file into a load
// error).
#[test]
fn a_present_but_empty_file_opens_as_default_state_not_a_parse_error() {
    let path = temp_path("empty-file");
    std::fs::write(&path, b"").unwrap();
    let store = FileStore::open(path.clone()).expect("an empty file must open, not parse-error");
    assert_eq!(
        store.list_task_bodies().unwrap(),
        Vec::<Vec<u8>>::new(),
        "an empty file is Durable::default(), not a parse failure"
    );
    let _ = std::fs::remove_file(&path);
    #[cfg(unix)]
    let _ = std::fs::remove_file(super::lock_path_for(&path));
}

// ── `FileStore::load_from`: NotFound vs every other I/O error ───────────────────────────────────
//
// Mutant: `replace match guard e.kind() == NotFound with true` — only a MISSING file may be treated
// as `Durable::default()`. Any other read error (permission denied, a directory where a file was
// expected, …) must propagate as a load `Err`, or a durable_path that is actually inaccessible for
// some other reason would silently look like an empty-but-working store.
#[test]
fn a_non_not_found_read_error_is_propagated_not_treated_as_empty() {
    // A `durable_path` that names a DIRECTORY: `std::fs::read` on a directory fails with an error
    // whose kind is NOT `NotFound` on every platform this crate targets (unix: `IsADirectory` /
    // some other kind, never `NotFound` since the directory does exist).
    let path = temp_path("is-a-dir");
    std::fs::create_dir_all(&path).unwrap();
    let err = FileStore::open(path.clone())
        .err()
        .expect("a durable_path that is a directory must fail to open, not silently start empty");
    assert!(
        err.contains(&path.display().to_string()) || err.contains("durable_path"),
        "error must name the failing path: {err}"
    );
    let _ = std::fs::remove_dir_all(&path);
}

// ── `lock_path_for`: the relative-vs-absolute parent-path branch ────────────────────────────────
//
// Mutant: `delete !` in `path.parent().filter(|p| !p.as_os_str().is_empty())` — a `durable_path`
// with a real containing directory (the overwhelmingly common case, e.g. `/var/lib/busbar/x.json`)
// must produce a lock file INSIDE that same directory (`/var/lib/busbar/.x.json.lock`), not a
// bare relative name resolved against the process's current directory — two handles on the same
// `durable_path` from two different working directories would then take DIFFERENT lock files and
// the whole cross-handle `flock` guarantee (`FileStore::mutate`'s doc comment) would silently stop
// applying.
#[cfg(unix)]
#[test]
fn lock_path_joins_the_real_parent_directory_when_one_is_present() {
    let got = super::lock_path_for(std::path::Path::new("/tmp/some/dir/durable.json"));
    assert_eq!(
        got,
        std::path::PathBuf::from("/tmp/some/dir/.durable.json.lock"),
        "the lock file must sit beside the data file in its real directory"
    );
}

#[cfg(unix)]
#[test]
fn lock_path_falls_back_to_a_bare_name_when_there_is_no_directory_component() {
    // A path with no parent COMPONENT at all (a bare filename) — parent() is `Some("")`, which the
    // `filter` must drop, falling through to the bare-name branch.
    let got = super::lock_path_for(std::path::Path::new("durable.json"));
    assert_eq!(got, std::path::PathBuf::from(".durable.json.lock"));
}

// ── `FileStore::purge_tasks_before`: the strict `<` age boundary ────────────────────────────────
//
// Mutant: `replace < with <=` — a task whose `ts` is EXACTLY the cutoff must be RETAINED (only
// STRICTLY older rows are purged), matching `purge_call_bodies_before`'s `ts >= before` retention
// (retain everything at-or-after the cutoff — the same boundary stated the other way round).
#[test]
fn purge_tasks_before_retains_a_row_exactly_at_the_cutoff() {
    let s = store_at(temp_path("purge-boundary"));
    let exactly_at_cutoff = body(&serde_json::json!({"id": "at-cutoff"}));
    s.upsert_plane_record(&task_rec_local(
        "at-cutoff",
        100,
        PlaneDisposition::Terminal,
        exactly_at_cutoff.clone(),
    ))
    .unwrap();
    let dropped = s.purge_plane_records_before("task", 100).unwrap();
    assert_eq!(dropped, 0, "a row exactly at the cutoff must be RETAINED");
    assert_eq!(
        s.list_plane_records("task", &PlaneSelector::All).unwrap(),
        vec![exactly_at_cutoff]
    );
}

// ── append-is-idempotent-or-forked settlement, both logs ────────────────────────────────────────
//
// Mutant targets: the `prev.body == body` match guard (both `true`/`false` replacements) and
// `==` → `!=` on the comparison, in both `append_task_event_body` and `append_call_body`.
//
// The rule under test: appending the SAME `(key, seq)` with a BYTE-IDENTICAL body is a harmless
// retry (`Ok(())`, no new row); appending it with a DIFFERENT body is a forked/tampered log and
// must be an `Err` — neither branch may be dropped or inverted.
#[test]
fn append_task_event_body_same_bytes_is_an_idempotent_retry() {
    let s = store_at(temp_path("task-event-retry"));
    let b = b"event-payload".to_vec();
    s.append_plane_record(&rec_local("task_event", "", Some("t1"), 1, b.clone()))
        .unwrap();
    // Byte-identical retry at the same (task_id, seq): Ok, and no duplicate row.
    s.append_plane_record(&rec_local("task_event", "", Some("t1"), 1, b.clone()))
        .expect("a byte-identical retry must be Ok, not a fork error");
    assert_eq!(
        s.list_plane_records("task_event", &PlaneSelector::Parent("t1".into()))
            .unwrap(),
        vec![b],
        "the retry must not append a second row"
    );
}

#[test]
fn append_task_event_body_different_bytes_at_same_key_is_a_fork_error() {
    let s = store_at(temp_path("task-event-fork"));
    s.append_plane_record(&rec_local(
        "task_event",
        "",
        Some("t1"),
        1,
        b"first".to_vec(),
    ))
    .unwrap();
    let err = s
        .append_plane_record(&rec_local(
            "task_event",
            "",
            Some("t1"),
            1,
            b"second".to_vec(),
        ))
        .expect_err("a different body at the same (task_id, seq) must be refused as a fork");
    assert!(
        err.0.contains("fork"),
        "error must name the fork: {}",
        err.0
    );
}

#[test]
fn append_call_body_same_bytes_is_an_idempotent_retry() {
    let s = store_at(temp_path("call-retry"));
    let b = b"call-payload".to_vec();
    s.append_plane_record(&call_rec_local("p1", 1, 10, b.clone()))
        .unwrap();
    s.append_plane_record(&call_rec_local("p1", 1, 10, b.clone()))
        .expect("a byte-identical retry must be Ok, not a fork error");
    assert_eq!(
        s.list_plane_records("call", &PlaneSelector::Parent("p1".into()))
            .unwrap(),
        vec![b],
        "the retry must not append a second row"
    );
}

#[test]
fn append_call_body_different_bytes_at_same_key_is_a_fork_error() {
    let s = store_at(temp_path("call-fork"));
    s.append_plane_record(&call_rec_local("p1", 1, 10, b"first".to_vec()))
        .unwrap();
    let err = s
        .append_plane_record(&call_rec_local("p1", 1, 10, b"second".to_vec()))
        .expect_err("a different body at the same (principal, seq) must be refused as a fork");
    assert!(
        err.0.contains("fork"),
        "error must name the fork: {}",
        err.0
    );
}

// ── small local helpers (mirrors of `tests.rs`'s, kept local to avoid coupling the two files) ───

fn store_at(path: PathBuf) -> FileStore {
    FileStore::open(path).expect("open temp FileStore")
}

fn rec_local(kind: &str, id: &str, parent: Option<&str>, seq: u64, body: Vec<u8>) -> PlaneRecord {
    PlaneRecord {
        kind: kind.into(),
        id: id.into(),
        parent: parent.map(Into::into),
        seq,
        ts: 0,
        disposition: PlaneDisposition::Active,
        body,
    }
}

fn call_rec_local(principal: &str, seq: u64, ts: u64, body: Vec<u8>) -> PlaneRecord {
    PlaneRecord {
        kind: "call".into(),
        id: String::new(),
        parent: Some(principal.into()),
        seq,
        ts,
        disposition: PlaneDisposition::Active,
        body,
    }
}

fn task_rec_local(id: &str, ts: u64, disposition: PlaneDisposition, body: Vec<u8>) -> PlaneRecord {
    PlaneRecord {
        kind: "task".into(),
        id: id.into(),
        parent: None,
        seq: 0,
        ts,
        disposition,
        body,
    }
}
