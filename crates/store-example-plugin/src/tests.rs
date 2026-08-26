// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Neutral-plane-verb coverage for the durable [`FileStore`] backend (1.6.0 Commit 2).
//!
//! Each test WRITES through a neutral kind-tagged verb and proves the row reads back BOTH through the
//! neutral verb AND through the protocol-named method that owns the same table — i.e. the two
//! surfaces share one backend. The purge test pins the retention split the neutral surface must
//! preserve: kind `task` drops only terminal rows, kind `call` drops all older.

use super::*;

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

fn task(id: &str, state: &str, updated_at: u64) -> TaskRow {
    TaskRow {
        task_id: id.into(),
        context_id: "ctx".into(),
        principal: "key-1".into(),
        direction: "inbound".into(),
        state: state.into(),
        agent_id: "agent-1".into(),
        artifact_cursor: 0,
        push_callback: String::new(),
        created_at: 1,
        updated_at,
    }
}

fn task_event(task_id: &str, seq: u64) -> TaskEventRow {
    TaskEventRow {
        task_id: task_id.into(),
        seq,
        ts: 10,
        kind: "task.working".into(),
        context_id: "ctx".into(),
        principal: "key-1".into(),
        agent_id: "agent-1".into(),
        state: "working".into(),
        request_id: "req".into(),
        prev_hash: String::new(),
        hash: format!("h{seq}"),
    }
}

fn call(principal: &str, seq: u64, ts: u64) -> McpCallRecord {
    McpCallRecord {
        principal: principal.into(),
        seq,
        ts,
        server: "srv".into(),
        tool: "srv_do".into(),
        outcome: "dispatched".into(),
        reason: String::new(),
        tool_digest: "d".into(),
        pin_generation: 1,
        request_id: "req".into(),
        prev_hash: String::new(),
        hash: format!("h{seq}"),
    }
}

fn demotion(server: &str) -> McpDemotionRow {
    McpDemotionRow {
        server: server.into(),
        reason: "drift".into(),
        recorded_at: 5,
    }
}

fn rec(kind: &str, id: &str, parent: Option<&str>, seq: u64, body: Vec<u8>) -> PlaneRecord {
    PlaneRecord {
        kind: kind.into(),
        id: id.into(),
        parent: parent.map(Into::into),
        seq,
        ts: 0,
        disposition: busbar_api::PlaneDisposition::Active,
        body,
    }
}

#[test]
fn upsert_and_get_plane_record_task_roundtrips_through_both_surfaces() {
    let s = store();
    let t = task("t1", "working", 100);
    let body = serde_json::to_vec(&t).unwrap();

    // WRITE via the neutral verb.
    s.upsert_plane_record(&rec("task", "t1", None, 0, body.clone()))
        .unwrap();

    // READ BACK via the neutral verb → same opaque body.
    assert_eq!(
        s.get_plane_record("task", "t1").unwrap(),
        Some(body.clone())
    );

    // READ BACK via the OLD named method → same typed row (shared table).
    assert_eq!(s.get_task("t1").unwrap(), Some(t.clone()));

    // And a body written through the neutral verb decodes to the same row.
    assert_eq!(
        serde_json::from_slice::<TaskRow>(&s.get_plane_record("task", "t1").unwrap().unwrap())
            .unwrap(),
        t
    );
}

#[test]
fn upsert_plane_record_is_an_upsert_by_id() {
    let s = store();
    s.upsert_plane_record(&rec(
        "task",
        "t1",
        None,
        0,
        serde_json::to_vec(&task("t1", "submitted", 1)).unwrap(),
    ))
    .unwrap();
    s.upsert_plane_record(&rec(
        "task",
        "t1",
        None,
        0,
        serde_json::to_vec(&task("t1", "completed", 2)).unwrap(),
    ))
    .unwrap();
    // One row, replaced — matching put_task's upsert-by-task_id.
    assert_eq!(s.list_tasks().unwrap().len(), 1);
    assert_eq!(s.get_task("t1").unwrap().unwrap().state, "completed");
}

#[test]
fn list_plane_records_task_all_matches_list_tasks() {
    let s = store();
    for t in [task("a", "working", 1), task("b", "completed", 2)] {
        s.upsert_plane_record(&rec(
            "task",
            &t.task_id,
            None,
            0,
            serde_json::to_vec(&t).unwrap(),
        ))
        .unwrap();
    }
    let via_neutral: Vec<TaskRow> = s
        .list_plane_records("task", &PlaneSelector::All)
        .unwrap()
        .iter()
        .map(|b| serde_json::from_slice(b).unwrap())
        .collect();
    assert_eq!(via_neutral, s.list_tasks().unwrap());
    assert_eq!(via_neutral.len(), 2);
}

#[test]
fn append_and_list_plane_records_task_event_roundtrips_through_both_surfaces() {
    let s = store();
    for e in [task_event("t1", 1), task_event("t1", 2)] {
        s.append_plane_record(&rec(
            "task_event",
            "",
            Some("t1"),
            e.seq,
            serde_json::to_vec(&e).unwrap(),
        ))
        .unwrap();
    }
    // Neutral parent selector == named list, oldest-first by seq.
    let via_neutral: Vec<TaskEventRow> = s
        .list_plane_records("task_event", &PlaneSelector::Parent("t1".into()))
        .unwrap()
        .iter()
        .map(|b| serde_json::from_slice(b).unwrap())
        .collect();
    assert_eq!(via_neutral, s.list_task_events("t1").unwrap());
    assert_eq!(
        via_neutral.iter().map(|e| e.seq).collect::<Vec<_>>(),
        [1, 2]
    );
}

/// REGRESSION (R2-fix): a NEUTRAL `{seq,prev_hash,hash,content}` task-event body — the shape the
/// engine has written since the seam cleave — round-trips through this store VERBATIM. Before this fix
/// the `task_event` write path decoded the body as a typed `TaskEventRow`, which HARD-FAILS on a
/// neutral body (it has none of those fields), so A2A task submit/transition/dispatch errored whenever
/// this reference plugin was the store. The `call` kind was fixed for this in R1; this pins the twin,
/// so no test hid it again.
#[test]
fn a_neutral_task_event_body_round_trips_verbatim_and_is_not_a_typed_row() {
    let s = store();
    // The engine's neutral envelope: no `TaskEventRow` fields, an opaque pre-framed `content` suffix.
    let neutral = serde_json::json!({
        "seq": 1u64,
        "prev_hash": "",
        "hash": "1b293d0202f52529b9ae75292c5638675a4ed2ab59e57db5b0f26016a7ef22e1",
        "content": b"|1700000000|task.submitted|ctx-1|key-1|agent-1|submitted".to_vec(),
    });
    let body = serde_json::to_vec(&neutral).unwrap();
    // Proof this exercises the bug: the OLD write path's `decode::<TaskEventRow>` fails on this body.
    assert!(
        serde_json::from_slice::<TaskEventRow>(&body).is_err(),
        "the fixture body must be genuinely neutral, or this test would not reach the bug"
    );

    s.append_plane_record(&rec("task_event", "", Some("task-1"), 1, body.clone()))
        .expect("a neutral task-event body must PERSIST — the bug was a StoreError here");
    let read = s
        .list_plane_records("task_event", &PlaneSelector::Parent("task-1".into()))
        .unwrap();
    assert_eq!(
        read,
        vec![body],
        "the neutral body reads back verbatim, byte-for-byte — the engine reframes it, not the store"
    );
}

#[test]
fn append_and_list_plane_records_call_roundtrips_and_enumerates_parents() {
    let s = store();
    for c in [call("p1", 1, 10), call("p1", 2, 20), call("p2", 1, 30)] {
        s.append_plane_record(&rec(
            "call",
            "",
            Some(&c.principal),
            c.seq,
            serde_json::to_vec(&c).unwrap(),
        ))
        .unwrap();
    }
    let via_neutral: Vec<McpCallRecord> = s
        .list_plane_records("call", &PlaneSelector::Parent("p1".into()))
        .unwrap()
        .iter()
        .map(|b| serde_json::from_slice(b).unwrap())
        .collect();
    assert_eq!(via_neutral, s.list_mcp_calls("p1").unwrap());

    // list_plane_record_parents (kind call) == list_mcp_call_principals.
    assert_eq!(
        s.list_plane_record_parents("call").unwrap(),
        s.list_mcp_call_principals().unwrap()
    );
    assert_eq!(
        s.list_plane_record_parents("call").unwrap(),
        vec!["p1".to_string(), "p2".to_string()]
    );
}

#[test]
fn upsert_list_and_delete_plane_record_demotion_roundtrips_through_both_surfaces() {
    let s = store();
    for d in [demotion("srv-a"), demotion("srv-b")] {
        s.upsert_plane_record(&rec(
            "demotion",
            &d.server,
            None,
            0,
            serde_json::to_vec(&d).unwrap(),
        ))
        .unwrap();
    }
    let via_neutral: Vec<McpDemotionRow> = s
        .list_plane_records("demotion", &PlaneSelector::All)
        .unwrap()
        .iter()
        .map(|b| serde_json::from_slice(b).unwrap())
        .collect();
    assert_eq!(via_neutral, s.list_mcp_demotions().unwrap());

    // delete_plane_record == clear_mcp_demotion, visible through both surfaces.
    s.delete_plane_record("demotion", "srv-a").unwrap();
    assert_eq!(s.list_mcp_demotions().unwrap(), vec![demotion("srv-b")]);
    assert_eq!(
        s.list_plane_records("demotion", &PlaneSelector::All)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn redeem_plane_token_ask_matches_redeem_ask_state() {
    let s = store();
    // First redemption wins; the second is refused — the shared ledger.
    assert!(s.redeem_plane_token("ask", "n1", 100, 1).unwrap());
    assert!(!s.redeem_plane_token("ask", "n1", 100, 1).unwrap());
    // And the named surface sees the same spent nonce.
    assert!(!s.redeem_ask_state("n1", 100, 1).unwrap());
    // A different nonce is still redeemable.
    assert!(s.redeem_ask_state("n2", 100, 1).unwrap());
}

#[test]
fn purge_plane_records_before_task_drops_only_terminal_rows() {
    let s = store();
    // Two OLD rows: one terminal, one still active (waiting on a human).
    s.upsert_plane_record(&rec(
        "task",
        "done",
        None,
        0,
        serde_json::to_vec(&task("done", "completed", 10)).unwrap(),
    ))
    .unwrap();
    s.upsert_plane_record(&rec(
        "task",
        "waiting",
        None,
        0,
        serde_json::to_vec(&task("waiting", "input-required", 10)).unwrap(),
    ))
    .unwrap();

    // Purge older than 100 via the NEUTRAL verb.
    let dropped = s.purge_plane_records_before("task", 100).unwrap();
    assert_eq!(dropped, 1, "only the terminal row goes");
    // Identical to the named path's contract.
    let ids: Vec<String> = s
        .list_tasks()
        .unwrap()
        .into_iter()
        .map(|t| t.task_id)
        .collect();
    assert_eq!(ids, vec!["waiting".to_string()]);
}

#[test]
fn purge_plane_records_before_call_drops_all_older() {
    let s = store();
    for c in [call("p1", 1, 10), call("p1", 2, 200)] {
        s.append_plane_record(&rec(
            "call",
            "",
            Some(&c.principal),
            c.seq,
            serde_json::to_vec(&c).unwrap(),
        ))
        .unwrap();
    }
    // Purge older than 100 via the NEUTRAL verb: the call log drops ALL older, terminal or not.
    let dropped = s.purge_plane_records_before("call", 100).unwrap();
    assert_eq!(dropped, 1);
    let remaining = s.list_mcp_calls("p1").unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].ts, 200);
}

/// TWO HANDLES on one `durable_path` — the fleet this fixture exists to model — hammering the same
/// table concurrently must not LOSE an update. Each thread appends a uniquely-keyed MCP call row
/// through its handle; every row's `(principal, seq)` is distinct, so a correct store ends with ALL
/// of them. Before the advisory `flock` around the read-modify-write, the two handles' RMW cycles
/// interleaved (both `load()` the same state, both write, the second clobbering the first) and rows
/// went missing — this asserts none do. Deterministically red without the lock under the contention
/// below; green with it.
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
                let c = call("p1", base + i, 10);
                handle
                    .append_plane_record(&rec(
                        "call",
                        "",
                        Some(&c.principal),
                        c.seq,
                        serde_json::to_vec(&c).unwrap(),
                    ))
                    .unwrap();
            }
        }));
    }
    for t in threads {
        t.join().unwrap();
    }

    // Every one of the 2*PER_THREAD distinct (principal, seq) rows survived — no lost update.
    let rows = h1.list_mcp_calls("p1").unwrap();
    assert_eq!(
        rows.len() as u64,
        2 * PER_THREAD,
        "cross-handle RMW lost an update: expected {} rows, found {}",
        2 * PER_THREAD,
        rows.len()
    );
    let seqs: Vec<u64> = rows.iter().map(|r| r.seq).collect();
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
