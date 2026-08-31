// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Neutral-plane-verb coverage for the durable [`FileStore`] backend (1.6.0).
//!
//! Every test drives the store PURELY over the opaque `PlaneRecord` envelope and its serde_json
//! `body` bytes — it writes through a neutral kind-tagged verb (`upsert_/append_/redeem_plane_*`) and
//! reads back through the neutral read verbs (`get_/list_/list_..._parents/purge_plane_*`), proving
//! the plugin ROUND-TRIPS ENVELOPES over the ABI. No test names a `busbar_api` plane row struct: the
//! bodies here are small throwaway serde structs (or opaque byte blobs) defined in THIS module, since
//! the store persists the body verbatim and never decodes it. The purge test pins the retention split
//! the neutral surface must preserve — kind `task` drops only `Terminal` rows, kind `call` drops all
//! older — by setting the envelope's `disposition`/`ts` SIDECAR columns explicitly.

use super::*;

/// A throwaway task body. The store never decodes it; the tests use it only to prove a body written
/// through the envelope reads back byte-for-byte.
#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
struct SampleTask {
    id: String,
    state: String,
}

/// A throwaway MCP-call body, carrying its `seq` so the contention/purge tests can identify a row
/// read back through the opaque list verb without the store ever interpreting it.
#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
struct SampleCall {
    principal: String,
    seq: u64,
}

/// A throwaway demotion body.
#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
struct SampleDemotion {
    server: String,
}

fn body<T: serde::Serialize>(v: &T) -> Vec<u8> {
    serde_json::to_vec(v).unwrap()
}

/// A fresh `FileStore` over a unique temp path (no `tempfile` dev-dep in this fixture crate).
fn store() -> FileStore {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut path = std::env::temp_dir();
    path.push(format!(
        "busbar-store-example-plugin-test-{}-{}.json",
        std::process::id(),
        n
    ));
    let _ = std::fs::remove_file(&path);
    FileStore::open(path).expect("open temp FileStore")
}

/// A generic envelope: `ts` 0, `disposition` Active (the shape most kinds carry).
fn rec(kind: &str, id: &str, parent: Option<&str>, seq: u64, body: Vec<u8>) -> PlaneRecord {
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

/// A `call` envelope with an explicit `ts` SIDECAR — the axis age-based purge sweeps on.
fn call_rec(principal: &str, seq: u64, ts: u64, body: Vec<u8>) -> PlaneRecord {
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

/// A `task` envelope with explicit `ts`/`disposition` SIDECARs — what terminal-only purge reads.
fn task_rec(id: &str, ts: u64, disposition: PlaneDisposition, body: Vec<u8>) -> PlaneRecord {
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

#[test]
fn upsert_and_get_plane_record_task_roundtrips_the_envelope() {
    let s = store();
    let b = body(&SampleTask {
        id: "t1".into(),
        state: "working".into(),
    });

    // WRITE via the neutral verb.
    s.upsert_plane_record(&rec("task", "t1", None, 0, b.clone()))
        .unwrap();

    // READ BACK via get → the same opaque body, byte-for-byte.
    assert_eq!(s.get_plane_record("task", "t1").unwrap(), Some(b.clone()));

    // READ BACK via list("task", All) → the same body.
    assert_eq!(
        s.list_plane_records("task", &PlaneSelector::All).unwrap(),
        vec![b.clone()]
    );

    // The body reads back verbatim, so it still decodes to what was written (the store did not touch
    // it).
    assert_eq!(
        serde_json::from_slice::<SampleTask>(&s.get_plane_record("task", "t1").unwrap().unwrap())
            .unwrap(),
        SampleTask {
            id: "t1".into(),
            state: "working".into()
        }
    );
}

#[test]
fn upsert_plane_record_is_an_upsert_by_id() {
    let s = store();
    let first = body(&SampleTask {
        id: "t1".into(),
        state: "submitted".into(),
    });
    let second = body(&SampleTask {
        id: "t1".into(),
        state: "completed".into(),
    });
    s.upsert_plane_record(&rec("task", "t1", None, 0, first))
        .unwrap();
    s.upsert_plane_record(&rec("task", "t1", None, 0, second.clone()))
        .unwrap();
    // One row, replaced — upsert on (kind, id).
    assert_eq!(
        s.list_plane_records("task", &PlaneSelector::All)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(s.get_plane_record("task", "t1").unwrap(), Some(second));
}

#[test]
fn list_plane_records_task_all_returns_every_body() {
    let s = store();
    let a = body(&SampleTask {
        id: "a".into(),
        state: "working".into(),
    });
    let b = body(&SampleTask {
        id: "b".into(),
        state: "completed".into(),
    });
    s.upsert_plane_record(&rec("task", "a", None, 0, a.clone()))
        .unwrap();
    s.upsert_plane_record(&rec("task", "b", None, 0, b.clone()))
        .unwrap();
    let mut got = s.list_plane_records("task", &PlaneSelector::All).unwrap();
    got.sort();
    let mut want = vec![a, b];
    want.sort();
    assert_eq!(got, want);
}

#[test]
fn append_and_list_plane_records_task_event_roundtrips_the_envelope() {
    let s = store();
    // Opaque bodies — content is irrelevant here; only ordering by seq is asserted.
    let e1 = b"event-1".to_vec();
    let e2 = b"event-2".to_vec();
    s.append_plane_record(&rec("task_event", "", Some("t1"), 1, e1.clone()))
        .unwrap();
    s.append_plane_record(&rec("task_event", "", Some("t1"), 2, e2.clone()))
        .unwrap();
    // Parent selector returns the chain oldest-first by seq, bodies verbatim.
    assert_eq!(
        s.list_plane_records("task_event", &PlaneSelector::Parent("t1".into()))
            .unwrap(),
        vec![e1, e2]
    );
}

/// A pre-framed opaque task-event body — bytes the store must persist and return VERBATIM without ever
/// decoding them. Before the store was made fully opaque, the `task_event` write path decoded the body
/// as a typed row, which HARD-FAILS on a body that has none of those fields, so A2A task
/// submit/transition/dispatch errored whenever this reference plugin was the store. This pins that the
/// write path names no plane type and keeps the bytes as-is.
#[test]
fn a_neutral_task_event_body_round_trips_verbatim() {
    let s = store();
    // An opaque pre-framed envelope the engine writes; the store treats it as bytes.
    let neutral = serde_json::json!({
        "seq": 1u64,
        "prev_hash": "",
        "hash": "1b293d0202f52529b9ae75292c5638675a4ed2ab59e57db5b0f26016a7ef22e1",
        "content": b"|1700000000|task.submitted|ctx-1|key-1|agent-1|submitted".to_vec(),
    });
    let b = serde_json::to_vec(&neutral).unwrap();

    s.append_plane_record(&rec("task_event", "", Some("task-1"), 1, b.clone()))
        .expect("an opaque task-event body must PERSIST — the bug was a StoreError here");
    let read = s
        .list_plane_records("task_event", &PlaneSelector::Parent("task-1".into()))
        .unwrap();
    assert_eq!(
        read,
        vec![b],
        "the body reads back verbatim, byte-for-byte — the engine reframes it, not the store"
    );
}

#[test]
fn append_and_list_plane_records_call_roundtrips_and_enumerates_parents() {
    let s = store();
    for (principal, seq) in [("p1", 1u64), ("p1", 2), ("p2", 1)] {
        let b = body(&SampleCall {
            principal: principal.into(),
            seq,
        });
        s.append_plane_record(&call_rec(principal, seq, 10, b))
            .unwrap();
    }
    // Parent p1's chain, oldest-first by seq, decodes back to what was written.
    let via_neutral: Vec<SampleCall> = s
        .list_plane_records("call", &PlaneSelector::Parent("p1".into()))
        .unwrap()
        .iter()
        .map(|b| serde_json::from_slice(b).unwrap())
        .collect();
    assert_eq!(
        via_neutral,
        vec![
            SampleCall {
                principal: "p1".into(),
                seq: 1
            },
            SampleCall {
                principal: "p1".into(),
                seq: 2
            },
        ]
    );

    // list_plane_record_parents enumerates the distinct principals.
    assert_eq!(
        s.list_plane_record_parents("call").unwrap(),
        vec!["p1".to_string(), "p2".to_string()]
    );
}

#[test]
fn upsert_list_and_delete_plane_record_demotion_roundtrips_the_envelope() {
    let s = store();
    let a = body(&SampleDemotion {
        server: "srv-a".into(),
    });
    let b = body(&SampleDemotion {
        server: "srv-b".into(),
    });
    s.upsert_plane_record(&rec("demotion", "srv-a", None, 0, a.clone()))
        .unwrap();
    s.upsert_plane_record(&rec("demotion", "srv-b", None, 0, b.clone()))
        .unwrap();
    let mut got = s
        .list_plane_records("demotion", &PlaneSelector::All)
        .unwrap();
    got.sort();
    let mut want = vec![a, b.clone()];
    want.sort();
    assert_eq!(got, want);

    // delete_plane_record drops the row keyed by id.
    s.delete_plane_record("demotion", "srv-a").unwrap();
    assert_eq!(
        s.list_plane_records("demotion", &PlaneSelector::All)
            .unwrap(),
        vec![b]
    );
}

#[test]
fn redeem_plane_token_ask_refuses_a_double_redeem() {
    let s = store();
    // First redemption wins; the second is refused — the shared ledger.
    assert!(s.redeem_plane_token("ask", "n1", 100, 1).unwrap());
    assert!(!s.redeem_plane_token("ask", "n1", 100, 1).unwrap());
    // A different nonce is still redeemable.
    assert!(s.redeem_plane_token("ask", "n2", 100, 1).unwrap());
}

/// DURABILITY ACROSS A RESTART: a row written through one `FileStore` handle is found by a second
/// handle opened on the same `durable_path` (the "write, restart, read it back" claim the fixture
/// exists to prove) — driven purely over the envelope.
#[test]
fn a_task_written_by_one_handle_is_read_by_a_reopened_handle() {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "busbar-store-example-plugin-restart-{}-{}.json",
        std::process::id(),
        std::sync::atomic::AtomicU64::new(0).fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&path);

    let b = body(&SampleTask {
        id: "t1".into(),
        state: "working".into(),
    });
    {
        let h1 = FileStore::open(path.clone()).expect("open handle 1");
        h1.upsert_plane_record(&rec("task", "t1", None, 0, b.clone()))
            .unwrap();
    } // handle dropped — simulate a restart

    let h2 = FileStore::open(path.clone()).expect("reopen handle 2");
    assert_eq!(s_get(&h2, "t1"), Some(b));

    let _ = std::fs::remove_file(&path);
    #[cfg(unix)]
    let _ = std::fs::remove_file(super::lock_path_for(&path));
}

fn s_get(s: &FileStore, id: &str) -> Option<Vec<u8>> {
    s.get_plane_record("task", id).unwrap()
}

#[test]
fn purge_plane_records_before_task_drops_only_terminal_rows() {
    let s = store();
    // Two OLD rows: one terminal, one still active (waiting on a human). Terminality rides the
    // envelope's `disposition` SIDECAR, set explicitly on the write.
    s.upsert_plane_record(&task_rec(
        "done",
        10,
        PlaneDisposition::Terminal,
        body(&SampleTask {
            id: "done".into(),
            state: "completed".into(),
        }),
    ))
    .unwrap();
    let waiting_body = body(&SampleTask {
        id: "waiting".into(),
        state: "input-required".into(),
    });
    s.upsert_plane_record(&task_rec(
        "waiting",
        10,
        PlaneDisposition::Active,
        waiting_body.clone(),
    ))
    .unwrap();

    // Purge older than 100 via the NEUTRAL verb.
    let dropped = s.purge_plane_records_before("task", 100).unwrap();
    assert_eq!(dropped, 1, "only the terminal row goes");
    // The active row survives; the terminal one is gone.
    assert_eq!(
        s.list_plane_records("task", &PlaneSelector::All).unwrap(),
        vec![waiting_body]
    );
    assert_eq!(s.get_plane_record("task", "done").unwrap(), None);
}

#[test]
fn purge_plane_records_before_call_drops_all_older() {
    let s = store();
    // ts rides the envelope SIDECAR; the call log drops ALL older, terminal or not.
    let old = body(&SampleCall {
        principal: "p1".into(),
        seq: 1,
    });
    let recent = body(&SampleCall {
        principal: "p1".into(),
        seq: 2,
    });
    s.append_plane_record(&call_rec("p1", 1, 10, old)).unwrap();
    s.append_plane_record(&call_rec("p1", 2, 200, recent.clone()))
        .unwrap();

    let dropped = s.purge_plane_records_before("call", 100).unwrap();
    assert_eq!(dropped, 1);
    assert_eq!(
        s.list_plane_records("call", &PlaneSelector::Parent("p1".into()))
            .unwrap(),
        vec![recent]
    );
}

/// TWO HANDLES on one `durable_path` — the fleet this fixture exists to model — hammering the same
/// table concurrently must not LOSE an update. Each thread appends a uniquely-keyed call row through
/// its handle; every row's `(principal, seq)` is distinct, so a correct store ends with ALL of them.
/// Before the advisory `flock` around the read-modify-write, the two handles' RMW cycles interleaved
/// (both `load()` the same state, both write, the second clobbering the first) and rows went missing —
/// this asserts none do. Deterministically red without the lock under the contention below; green with
/// it.
// Unix-only: the cross-handle serialization this asserts comes from the `flock` in `FileLock`, which
// is a no-op fallback on non-unix (documented on `FileLock`), so this test is deterministically red on
// windows. It never ran there before (a compile error masked it); gate it to its real platform.
#[cfg(unix)]
#[test]
fn two_handles_do_not_lose_updates_under_contention() {
    use std::sync::Arc;

    let mut path = std::env::temp_dir();
    path.push(format!(
        "busbar-store-example-plugin-flock-{}-{}.json",
        std::process::id(),
        std::sync::atomic::AtomicU64::new(0).fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&path);

    // TWO independent handles on the SAME file, each with its own per-handle gate — a fleet.
    let h1 = Arc::new(FileStore::open(path.clone()).expect("open handle 1"));
    let h2 = Arc::new(FileStore::open(path.clone()).expect("open handle 2"));

    const PER_THREAD: u64 = 40;
    let mut threads = Vec::new();
    for (handle, base) in [(h1.clone(), 0u64), (h2.clone(), PER_THREAD)] {
        threads.push(std::thread::spawn(move || {
            for i in 0..PER_THREAD {
                let seq = base + i;
                let b = body(&SampleCall {
                    principal: "p1".into(),
                    seq,
                });
                handle
                    .append_plane_record(&call_rec("p1", seq, 10, b))
                    .unwrap();
            }
        }));
    }
    for t in threads {
        t.join().unwrap();
    }

    // Every one of the 2*PER_THREAD distinct (principal, seq) rows survived — no lost update.
    let bodies = h1
        .list_plane_records("call", &PlaneSelector::Parent("p1".into()))
        .unwrap();
    assert_eq!(
        bodies.len() as u64,
        2 * PER_THREAD,
        "cross-handle RMW lost an update: expected {} rows, found {}",
        2 * PER_THREAD,
        bodies.len()
    );
    let seqs: Vec<u64> = bodies
        .iter()
        .map(|b| serde_json::from_slice::<SampleCall>(b).unwrap().seq)
        .collect();
    assert_eq!(seqs, (0..2 * PER_THREAD).collect::<Vec<_>>());

    let _ = std::fs::remove_file(&path);
    // The lock file exists only on unix (where `FileLock` is a real `flock`); `lock_path_for` is
    // `#[cfg(unix)]` for the same reason, so this cleanup is unix-only too.
    #[cfg(unix)]
    let _ = std::fs::remove_file(super::lock_path_for(&path));
}

#[test]
fn unknown_kind_stays_inert() {
    let s = store();
    // A kind this store does not recognise behaves as the neutral trait default (accept-and-keep-
    // nothing / empty), never an error.
    s.upsert_plane_record(&rec("nope", "x", None, 0, b"garbage".to_vec()))
        .unwrap();
    assert_eq!(s.get_plane_record("nope", "x").unwrap(), None);
    assert!(s
        .list_plane_records("nope", &PlaneSelector::All)
        .unwrap()
        .is_empty());
    assert_eq!(s.purge_plane_records_before("nope", 100).unwrap(), 0);
}
