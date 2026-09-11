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

/// Mutation-testing hardening, added after a `cargo-mutants` run on this crate surfaced gaps this
/// module's ABI-round-trip coverage didn't pin. Kept in its own file rather than folded in here.
mod mutation_hardening;

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

// ── THE SHARED CROSS-BACKEND RETENTION CONFORMANCE ───────────────────────────────────────────────
//
// The purge cells below this comment are THIS fixture's own, written against its own tables. The two
// here are the SHARED ones every backend answers identically (`busbar-plugin-testkit`), and they are
// wired separately on purpose: a ruling added to the shared suite has to reach this plugin on its
// next dependency bump rather than be hand-copied here and then drift, which is the exact failure
// the testkit exists to prevent. A fresh store per check is already an empty namespace, so `ns` only
// has to be stable.

/// The retention sweep drops rows older than the cutoff and NOTHING else — the eighth neutral verb,
/// held to the same ruling as every other backend.
#[test]
fn conformance_plane_purge_honours_the_cutoff() {
    busbar_plugin_testkit::store_conformance::assert_plane_purge_honours_the_cutoff(&store(), "cf");
}

/// The task table's retention rule is terminality AND age, not age alone.
#[test]
fn conformance_plane_purge_task_keeps_active_rows() {
    busbar_plugin_testkit::store_conformance::assert_plane_purge_task_keeps_active_rows(
        &store(),
        "cf",
    );
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

/// A config the operator wrote and this plugin cannot read is a LOAD ERROR. Accepting it and
/// silently opening a `MemoryStore` is the dangerous shape: one stray trailing comma in the
/// `durable_path` line turns a durable store into an ephemeral one, the plugin loads clean, and the
/// rows only stop existing at the next restart. An EMPTY config stays the one and only path to the
/// wrapped RAM store, because "no config" is a thing an operator can actually mean.
#[test]
fn a_malformed_config_is_a_load_error_not_a_silent_demotion_to_ram() {
    assert!(
        open(r#"{"durable_path": "/x",}"#).is_err(),
        "malformed JSON naming a durable path must refuse to load, not fall back to RAM"
    );
    assert!(open("{ not json at all").is_err());
    // The two shapes that legitimately mean "no durable path": no config, and a parsed config that
    // simply does not name one.
    assert!(open("").is_ok());
    assert!(open("{}").is_ok());
}

/// A purged task takes its event chain with it. Nothing else ever removes a `task_event` row — the
/// chain has no retention path of its own — so keeping the events after their task is purged grows
/// the file forever with chains whose parent no longer exists, and leaves the events outliving the
/// retention decision just made about them.
#[test]
fn purging_a_terminal_task_cascades_to_its_event_chain() {
    let s = store();
    for (id, disposition) in [
        ("done", PlaneDisposition::Terminal),
        ("waiting", PlaneDisposition::Active),
    ] {
        s.upsert_plane_record(&task_rec(
            id,
            10,
            disposition,
            body(&SampleTask {
                id: id.into(),
                state: "whatever".into(),
            }),
        ))
        .unwrap();
        s.append_plane_record(&rec("task_event", id, Some(id), 1, b"event-one".to_vec()))
            .unwrap();
    }

    assert_eq!(s.purge_plane_records_before("task", 100).unwrap(), 1);
    assert!(
        s.list_plane_records("task_event", &PlaneSelector::Parent("done".into()))
            .unwrap()
            .is_empty(),
        "the purged task's events must go with it"
    );
    assert_eq!(
        s.list_plane_records("task_event", &PlaneSelector::Parent("waiting".into()))
            .unwrap(),
        vec![b"event-one".to_vec()],
        "a retained task's chain is untouched — this is a cascade, not a second retention rule"
    );
}

/// A push-callback token is LIVE many times over, and dead the moment its task ends.
///
/// The verb beside `redeem_plane_token` and deliberately not a second spelling of it. A single-use
/// redeem is wrong for this token in both directions at once: spent on the first callback it refuses
/// the `input-required` and `completed` a backend legitimately sends afterwards, and answered `true`
/// every time it accepts a captured one forever. So the check is asked THREE times here and answers
/// live all three, then the row is flipped to `Terminal` — the way the plan's revocation leg does —
/// and the fourth is refused.
///
/// Liveness is read off the typed `disposition` column, never decoded out of the body, so this
/// cannot pass by the fixture peeking at bytes a real backend would never open.
#[test]
fn plane_token_live_carries_a_task_and_dies_with_it() {
    let s = store();
    let config = |disposition| PlaneRecord {
        kind: "push_config".to_string(),
        id: "t-1".to_string(),
        parent: None,
        seq: 0,
        ts: 10,
        disposition,
        body: b"{}".to_vec(),
    };

    s.upsert_plane_record(&config(PlaneDisposition::Active))
        .unwrap();
    for nth in 1..=3 {
        assert!(
            s.plane_token_live("push_config", "t-1", 100, 20).unwrap(),
            "callback {nth} of a running task was refused; the check spent the token"
        );
    }

    // The ending revokes it, and every later callback is refused.
    s.upsert_plane_record(&config(PlaneDisposition::Terminal))
        .unwrap();
    assert!(
        !s.plane_token_live("push_config", "t-1", 100, 20).unwrap(),
        "a token whose task has finished is still live — this is the replay"
    );

    // And a deleted configuration holds no capability at all.
    s.upsert_plane_record(&config(PlaneDisposition::Active))
        .unwrap();
    s.delete_plane_record("push_config", "t-1").unwrap();
    assert!(!s.plane_token_live("push_config", "t-1", 100, 20).unwrap());
}

/// The deadline is a real one, and an unknown kind holds nothing live.
///
/// The two calls differ ONLY in the clock, so a pass cannot come from anything but the expiry
/// comparison being made — the comparison the composition root used to skip by passing one timestamp
/// as both sides of it. The unknown-kind arm falls to `false`, the opposite direction from
/// `redeem_plane_token`'s fall-through, because a store that keeps no capability rows holds no live
/// capability even though it has spent nothing.
#[test]
fn plane_token_live_refuses_a_lapsed_token_and_an_unknown_kind() {
    let s = store();
    s.upsert_plane_record(&PlaneRecord {
        kind: "push_config".to_string(),
        id: "t-1".to_string(),
        parent: None,
        seq: 0,
        ts: 10,
        disposition: PlaneDisposition::Active,
        body: b"{}".to_vec(),
    })
    .unwrap();

    assert!(s.plane_token_live("push_config", "t-1", 100, 100).unwrap());
    assert!(
        !s.plane_token_live("push_config", "t-1", 100, 101).unwrap(),
        "a token one second past its deadline is still live"
    );
    assert!(!s.plane_token_live("ask", "t-1", 100, 20).unwrap());
}

// ── THE CRATE'S OWN IN-PROCESS BACKEND (`src/ram.rs`) ────────────────────────────────────────────
//
// `RamStore` replaced a dependency on `busbar-store-memory` — a SIBLING INSTANCE of this crate's own
// kind, which PLUGIN-TREE.md §4 forbids without exception and which the manifest allow-list used to
// waive for this one crate. Deleting the waiver is only honest if the behaviour it covered is now
// asserted HERE, so the three rulings a store gets wrong invisibly are pinned below: the tombstone
// precondition, the delete cascade, and the metering accumulate. The first two are the SHARED
// cross-backend cells from `busbar-plugin-testkit`, wired the same way the plane-purge cells above
// are, so a ruling added to the shared suite reaches this backend on its next dependency bump.

/// `put_key` must not clear a tombstone — the shared ruling, answered by this crate's own backend.
#[test]
fn conformance_ram_put_key_does_not_resurrect_a_tombstone() {
    busbar_plugin_testkit::store_conformance::assert_put_key_does_not_resurrect_a_tombstone(
        &RamStore::new(),
        "ram",
    );
}

/// `delete_key` on an id that was never written is an ERROR, not a silent success.
#[test]
fn conformance_ram_delete_key_unknown_id_is_an_error() {
    busbar_plugin_testkit::store_conformance::assert_delete_key_unknown_id_is_an_error(
        &RamStore::new(),
        "ram",
    );
}

/// The tombstone cascade: the KEY ROW SURVIVES (attribution by id keeps resolving forever and the id
/// is never reissued) while the usage LEDGER for that key is dropped. A backend that deleted the row
/// outright, or that kept the ledger, would pass every round-trip test and still be wrong.
#[test]
fn ram_delete_key_tombstones_the_row_and_drops_its_usage_ledger() {
    let s = RamStore::new();
    let key = busbar_plugin_testkit::store_conformance::live_key("ram_cascade");
    s.put_key(&key).expect("put a live key");
    s.put_usage("ram_cascade", 0, &UsageLedger::default())
        .expect("write the ledger");

    s.delete_key("ram_cascade").expect("tombstone the key");

    let row = s.get_key("ram_cascade").expect("read back").expect(
        "the key ROW survives its own deletion — anything that attributes by key id still resolves",
    );
    assert!(row.deleted_at.is_some(), "the row carries a tombstone");
    assert!(!row.enabled, "a tombstoned key is not enabled");
    assert!(
        s.list_keys().expect("list").iter().any(|k| k.id == row.id),
        "list_keys is UNFILTERED, so the hydrator can observe the new tombstone and evict"
    );
    // Idempotent on a second call, and still not a resurrection.
    s.delete_key("ram_cascade")
        .expect("deleting an already-tombstoned key is idempotent");
}

/// `add_metering` ACCUMULATES into one row per `(key_id, bucket, model, provider)` rather than
/// replacing it, and `list_metering` answers by bucket. A metering row that overwrote instead of
/// summing loses every request but the last, silently, on the billing path.
#[test]
fn ram_add_metering_accumulates_into_one_row_per_bucket() {
    let s = RamStore::new();
    let delta = |requests: u64, tokens_input: u64| MeteringDelta {
        key_id: "ram_meter".into(),
        bucket: 7,
        model: "m".into(),
        provider: "p".into(),
        tokens_input,
        tokens_output: 0,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests,
        billable_requests: requests,
        key_group_at_use: String::new(),
        pricing_version: String::new(),
    };
    s.add_metering(&delta(1, 10)).expect("first charge");
    s.add_metering(&delta(2, 5)).expect("second charge");

    let rows = s.list_metering(7).expect("read the bucket");
    assert_eq!(
        rows.len(),
        1,
        "one row per (key_id, bucket, model, provider)"
    );
    assert_eq!(rows[0].requests, 3, "requests accumulate");
    assert_eq!(rows[0].tokens_input, 15, "tokens accumulate");
    assert!(
        s.list_metering(8).expect("read another bucket").is_empty(),
        "list_metering answers only the bucket it was asked for"
    );
}

/// THE STANDALONE RULING ITSELF, read off the manifest rather than trusted to review. This crate is
/// the copy-me template for `kind: store`; PLUGIN-TREE.md §4 says no crate may name another instance
/// of any kind, "not in a dependency". The `manifest-allowlist` gate is report-only in CI today
/// (`ci.yml`'s construction-gate job carries `continue-on-error: true`), so this cell is the
/// BLOCKING half: it fails `cargo test -p busbar-store-example-plugin` the moment a sibling store
/// reappears in the dependency table, whatever the gate does.
#[test]
fn the_template_names_no_sibling_store_in_its_manifest() {
    let manifest = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
        .expect("read this crate's own Cargo.toml");
    for line in manifest.lines() {
        let decl = line.trim();
        if decl.starts_with('#') {
            continue; // the comment recording WHY the dependency is gone is not a dependency
        }
        let Some(name) = decl.split_once('=').map(|(n, _)| n.trim()) else {
            continue;
        };
        assert!(
            !(name.contains("store") && name != "name"),
            "crates/store-example-plugin/Cargo.toml names '{name}', a sibling instance of this \
             crate's own kind. PLUGIN-TREE.md §4 admits no exception: this crate is the template a \
             third-party store plugin is copied from, and the copy fails kind-isolation:deps on the \
             day it ships. Its backend belongs in this crate (src/ram.rs)."
        );
    }
}

/// THE PERSISTENCE CLAIM AT THE SEAM, against a REAL reopen: write a key, its spend ledger and its
/// metering row through one `FileStore` handle, drop it, open a second handle on the SAME
/// `durable_path`, and read everything back. The shared cross-backend assertion states the claim;
/// this wires it to the one in-tree backend that has a backing to reopen, so the durability half of
/// it is actually earned here rather than degenerating to read-back the way the RAM drivers do.
///
/// Red before green: against the FileStore that delegated its key/usage/metering verbs to an inner
/// `RamStore`, this failed at the first read-back — the second handle's `get_key` was `None`, because
/// the only state that ever reached the disk was the plane-record tables.
#[test]
fn conformance_file_key_spend_and_metering_survive_a_reopen() {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "busbar-store-example-plugin-persist-{}.json",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);

    // The opener the assertion calls twice. Each call is a genuine `FileStore::open` on the same
    // path — the second handle shares nothing in memory with the first, so the only possible source
    // of what it reads is the bytes the first one committed.
    let at = path.clone();
    let open = move || -> std::sync::Arc<dyn Store> {
        std::sync::Arc::new(
            FileStore::open(at.clone()).expect("open a FileStore handle at the durable_path"),
        )
    };
    busbar_plugin_testkit::store_conformance::assert_key_spend_and_metering_survive_a_reopen(
        &open, "file",
    );

    let _ = std::fs::remove_file(&path);
    #[cfg(unix)]
    let _ = std::fs::remove_file(super::lock_path_for(&path));
}

/// The two shared key rulings, now answered by the DURABLE backend as well as by `RamStore` — the
/// key verbs are no longer delegated, so `FileStore` has its own answers to get wrong.
#[test]
fn conformance_file_put_key_does_not_resurrect_a_tombstone() {
    let s = store();
    busbar_plugin_testkit::store_conformance::assert_put_key_does_not_resurrect_a_tombstone(
        &s, "file",
    );
}

#[test]
fn conformance_file_delete_key_unknown_id_is_an_error() {
    let s = store();
    busbar_plugin_testkit::store_conformance::assert_delete_key_unknown_id_is_an_error(&s, "file");
}

/// BACKWARD COMPATIBILITY of the on-disk format: a `durable.json` written before the governance
/// tables existed — one carrying only the plane-record fields — must still open, with the new tables
/// empty, and must still serve its old rows. The new fields are `#[serde(default)]` precisely so an
/// operator's existing file is not a load error after an upgrade; this pins that, since a missing
/// `default` is a runtime failure and not a compile one.
#[test]
fn an_old_durable_file_without_the_governance_tables_still_opens() {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "busbar-store-example-plugin-oldformat-{}.json",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    // Exactly the shape the pre-governance-tables fixture wrote: no `keys`, no `usage`, no
    // `metering`, no `key_revision`.
    let legacy = serde_json::json!({
        "tasks": [{ "id": "t-old", "ts": 10, "disposition": "Active", "body": [1, 2, 3] }],
        "task_event_bodies": [],
        "call_bodies": [],
        "demotions": [],
        "spent_ask_states": [],
        "push_configs": [],
    });
    std::fs::write(&path, serde_json::to_vec(&legacy).unwrap()).expect("seed the legacy file");

    let s = FileStore::open(path.clone()).expect("an old durable.json must still open");
    assert_eq!(
        s.get_plane_record("task", "t-old").unwrap(),
        Some(vec![1u8, 2, 3]),
        "the old file's rows must still be served"
    );
    assert!(
        s.list_keys().unwrap().is_empty(),
        "the absent key table reads as EMPTY, not as a load error"
    );
    assert_eq!(s.get_usage("anything", 0).unwrap(), UsageLedger::default());
    assert!(s.list_metering(0).unwrap().is_empty());

    let _ = std::fs::remove_file(&path);
    #[cfg(unix)]
    let _ = std::fs::remove_file(super::lock_path_for(&path));
}
