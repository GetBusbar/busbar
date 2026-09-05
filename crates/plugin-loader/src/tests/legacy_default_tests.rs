// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The one fallback choke point in `DynStore`, `call_with_legacy_default`, proven from the outside
//! through every verb that routes through it.
//!
//! Binding: only the "plugin does not know this request variant" signal opens a safe default.
//! Three things must hold for each verb that tolerates an old plugin:
//!
//! 1. an unsupported-variant answer yields the verb's INERT default (an `Ok(())` write, an empty
//!    read, a zero purge count) and nothing else;
//! 2. a real answer from the plugin passes through untouched;
//! 3. every other failure shape (a backend error, a caught panic, a bare protocol violation, an
//!    unknown status, a wrong-variant reply) PROPAGATES as an error.
//!
//! The verbs covered are the eight 1.6.0 kind-tagged plane-record verbs plus the four 1.5.x
//! audit/denylist verbs. Seven of the eight record verbs open a default; the eighth,
//! `redeem_plane_token`, is the one deliberate exception (single-use anti-replay fails CLOSED, so an
//! old store answers with an error, never "fresh"), and that exception is pinned here too so it
//! cannot drift into a fail-open default unnoticed.
//!
//! Runs over the in-tree store example plugin with its `call` seam faked, so it runs wherever the
//! workspace is built (no sibling checkout needed).

use super::*;

/// A record with every field populated, so the wire carries something on each verb.
fn record(kind: &str, id: &str) -> PlaneRecord {
    PlaneRecord {
        kind: kind.to_string(),
        id: id.to_string(),
        parent: Some("parent-1".to_string()),
        seq: 7,
        ts: 1_700_000_000,
        disposition: busbar_api::PlaneDisposition::Active,
        body: b"{\"opaque\":true}".to_vec(),
    }
}

/// An audit row for the append verb.
fn audit_row(seq: u64) -> AuditRecord {
    AuditRecord {
        seq,
        ts: 1_700_000_000 + seq,
        action: "keys.create".to_string(),
        resource: "vk_abc".to_string(),
        outcome: "ok".to_string(),
        principal: "admin".to_string(),
        prev_hash: String::new(),
        hash: format!("h{seq}"),
    }
}

/// Serialize a plugin-side response into the leaked static buffer the fake `call` hands back.
fn wire(resp: &StoreResponse) -> &'static [u8] {
    let bytes = serde_json::to_vec(resp).expect("StoreResponse serializes");
    Box::leak(bytes.into_boxed_slice())
}

/// Point the fake plugin at `(status, body)` for the next call.
fn answer(status: i32, body: &'static [u8]) {
    FAKE_CALL_HANDLE.with(|c| c.set((status, body)));
}

/// The two shapes "I do not know this request variant" has ever had on the wire.
const UNSUPPORTED_SHAPES: &[(i32, &[u8], &str)] = &[
    (
        STATUS_UNSUPPORTED,
        b"malformed request JSON: unknown variant",
        "a current-SDK plugin answering STATUS_UNSUPPORTED",
    ),
    (
        STATUS_PROTOCOL,
        b"malformed request JSON: unknown variant `UpsertPlaneRecord`, expected one of `PutKey`",
        "a v1-SDK plugin answering the legacy decode-failure shape",
    ),
];

/// Every failure shape that is NOT the unsupported signal.
const OTHER_FAILURES: &[(i32, &[u8], &str)] = &[
    (STATUS_ERR, b"disk full", "a real backend error"),
    (STATUS_PANIC, b"panicked", "a caught plugin panic"),
    (
        STATUS_PROTOCOL,
        b"",
        "a bare protocol violation (null handle / caller error)",
    ),
    (99, b"", "an unknown status from a future or broken plugin"),
];

/// Run one verb against `store` under a (status, body) answer and return what it handed back.
fn run<T>(
    store: &DynStore,
    status: i32,
    body: &'static [u8],
    op: impl FnOnce(&DynStore) -> StoreResult<T>,
) -> StoreResult<T> {
    answer(status, body);
    op(store)
}

/// The faked example store, or `None` (with a note) when the cdylib is not built — every test
/// skips cleanly then, the same convention the sibling fake-call tests follow, rather than failing
/// on a partial build.
fn open() -> Option<DynStore> {
    let store = dyn_example_store_with_fake_call();
    if store.is_none() {
        eprintln!("skip: store example plugin cdylib not built (run under --workspace)");
    }
    store
}

/// (1) The unsupported signal, in both wire shapes, opens the inert default on the seven
/// defaulting record verbs and the four audit/denylist verbs.
#[test]
fn unsupported_alone_opens_the_inert_default_on_every_defaulting_verb() {
    let Some(store) = open() else {
        return;
    };
    for (status, body, who) in UNSUPPORTED_SHAPES {
        let rec = record("task", "t-1");
        assert_eq!(
            run(&store, *status, body, |s| s.upsert_plane_record(&rec))
                .unwrap_or_else(|e| panic!("upsert_plane_record under {who}: {e:?}")),
            (),
        );
        assert_eq!(
            run(&store, *status, body, |s| s.get_plane_record("task", "t-1"))
                .unwrap_or_else(|e| panic!("get_plane_record under {who}: {e:?}")),
            None,
            "get_plane_record under {who} must read as absent"
        );
        assert_eq!(
            run(&store, *status, body, |s| s.append_plane_record(&rec))
                .unwrap_or_else(|e| panic!("append_plane_record under {who}: {e:?}")),
            (),
        );
        assert_eq!(
            run(&store, *status, body, |s| s
                .list_plane_records("task", &PlaneSelector::All))
            .unwrap_or_else(|e| panic!("list_plane_records under {who}: {e:?}")),
            Vec::<Vec<u8>>::new(),
            "list_plane_records under {who} must read as empty"
        );
        assert_eq!(
            run(&store, *status, body, |s| s
                .list_plane_record_parents("task"))
            .unwrap_or_else(|e| panic!("list_plane_record_parents under {who}: {e:?}")),
            Vec::<String>::new(),
            "list_plane_record_parents under {who} must read as empty"
        );
        assert_eq!(
            run(&store, *status, body, |s| s
                .purge_plane_records_before("task", 9))
            .unwrap_or_else(|e| panic!("purge_plane_records_before under {who}: {e:?}")),
            0,
            "purge_plane_records_before under {who} must report nothing purged"
        );
        assert_eq!(
            run(&store, *status, body, |s| s
                .delete_plane_record("task", "t-1"))
            .unwrap_or_else(|e| panic!("delete_plane_record under {who}: {e:?}")),
            (),
        );

        // The four 1.5.x audit/denylist verbs the same choke point serves.
        assert_eq!(
            run(&store, *status, body, |s| s.append_audit(&audit_row(1)))
                .unwrap_or_else(|e| panic!("append_audit under {who}: {e:?}")),
            (),
        );
        assert_eq!(
            run(&store, *status, body, |s| s.list_audit())
                .unwrap_or_else(|e| panic!("list_audit under {who}: {e:?}")),
            Vec::<AuditRecord>::new(),
        );
        assert_eq!(
            run(&store, *status, body, |s| s.list_audit_tail(5))
                .unwrap_or_else(|e| panic!("list_audit_tail under {who}: {e:?}")),
            Vec::<AuditRecord>::new(),
        );
        assert_eq!(
            run(&store, *status, body, |s| s.list_denylist())
                .unwrap_or_else(|e| panic!("list_denylist under {who}: {e:?}")),
            Vec::<String>::new(),
        );
    }
}

/// The eighth record verb is the deliberate exception: anti-replay must not read an old store as
/// "this redemption was the first". The unsupported signal is an ERROR here, never `Ok(true)`.
#[test]
fn redeem_plane_token_is_the_one_record_verb_that_fails_closed_on_unsupported() {
    let Some(store) = open() else {
        return;
    };
    for (status, body, who) in UNSUPPORTED_SHAPES {
        let out = run(&store, *status, body, |s| {
            s.redeem_plane_token("ask", "nonce", 2_000, 1_000)
        });
        assert!(
            out.is_err(),
            "redeem_plane_token under {who} must refuse (Err), never answer fresh; got {out:?}"
        );
    }
}

/// (2) A real answer from the plugin passes through the choke point untouched, for every verb.
#[test]
fn a_real_answer_passes_through_untouched() {
    let Some(store) = open() else {
        return;
    };
    let ok = STATUS_OK;

    assert_eq!(
        run(&store, ok, wire(&StoreResponse::Unit), |s| s
            .upsert_plane_record(&record("task", "t-1")))
        .unwrap(),
        ()
    );
    assert_eq!(
        run(
            &store,
            ok,
            wire(&StoreResponse::PlaneRecord(Some(b"row".to_vec()))),
            |s| s.get_plane_record("task", "t-1")
        )
        .unwrap(),
        Some(b"row".to_vec())
    );
    assert_eq!(
        run(&store, ok, wire(&StoreResponse::Unit), |s| s
            .append_plane_record(&record("event", "e-1")))
        .unwrap(),
        ()
    );
    assert_eq!(
        run(
            &store,
            ok,
            wire(&StoreResponse::PlaneRecords(vec![
                b"a".to_vec(),
                b"b".to_vec()
            ])),
            |s| s.list_plane_records("event", &PlaneSelector::Parent("t-1".into()))
        )
        .unwrap(),
        vec![b"a".to_vec(), b"b".to_vec()]
    );
    assert_eq!(
        run(
            &store,
            ok,
            wire(&StoreResponse::PlaneRecordParents(vec!["t-1".to_string()])),
            |s| s.list_plane_record_parents("event")
        )
        .unwrap(),
        vec!["t-1".to_string()]
    );
    assert_eq!(
        run(&store, ok, wire(&StoreResponse::Purged(3)), |s| s
            .purge_plane_records_before("task", 9))
        .unwrap(),
        3
    );
    assert_eq!(
        run(&store, ok, wire(&StoreResponse::Unit), |s| s
            .delete_plane_record("task", "t-1"))
        .unwrap(),
        ()
    );
    assert!(
        run(&store, ok, wire(&StoreResponse::Redeemed(true)), |s| s
            .redeem_plane_token("ask", "n", 2_000, 1_000))
        .unwrap(),
        "a real fresh=true answer passes through"
    );
    assert!(
        !run(&store, ok, wire(&StoreResponse::Redeemed(false)), |s| s
            .redeem_plane_token("ask", "n", 2_000, 1_000))
        .unwrap(),
        "a real fresh=false answer passes through"
    );

    let rows = vec![audit_row(1), audit_row(2)];
    assert_eq!(
        run(&store, ok, wire(&StoreResponse::Unit), |s| s
            .append_audit(&audit_row(1)))
        .unwrap(),
        ()
    );
    assert_eq!(
        run(&store, ok, wire(&StoreResponse::Audit(rows.clone())), |s| s
            .list_audit())
        .unwrap(),
        rows
    );
    assert_eq!(
        run(&store, ok, wire(&StoreResponse::Audit(rows.clone())), |s| s
            .list_audit_tail(2))
        .unwrap(),
        rows,
        "a plugin that answers the tail verb itself is trusted for the truncation"
    );
    assert_eq!(
        run(
            &store,
            ok,
            wire(&StoreResponse::Denylist(vec!["vk_revoked".to_string()])),
            |s| s.list_denylist()
        )
        .unwrap(),
        vec!["vk_revoked".to_string()]
    );
}

/// (3) Nothing but the unsupported signal opens a default: a real backend error, a caught panic,
/// a bare protocol violation and an unknown status all surface as errors on every verb, so a
/// durability failure can never be laundered into "the plugin is just old".
#[test]
fn every_other_failure_shape_propagates_on_every_verb() {
    let Some(store) = open() else {
        return;
    };
    for (status, body, what) in OTHER_FAILURES {
        let rec = record("task", "t-err");
        let checks: Vec<(&str, bool)> = vec![
            (
                "upsert_plane_record",
                run(&store, *status, body, |s| s.upsert_plane_record(&rec)).is_err(),
            ),
            (
                "get_plane_record",
                run(&store, *status, body, |s| {
                    s.get_plane_record("task", "t-err")
                })
                .is_err(),
            ),
            (
                "append_plane_record",
                run(&store, *status, body, |s| s.append_plane_record(&rec)).is_err(),
            ),
            (
                "list_plane_records",
                run(&store, *status, body, |s| {
                    s.list_plane_records("task", &PlaneSelector::All)
                })
                .is_err(),
            ),
            (
                "list_plane_record_parents",
                run(&store, *status, body, |s| {
                    s.list_plane_record_parents("task")
                })
                .is_err(),
            ),
            (
                "purge_plane_records_before",
                run(&store, *status, body, |s| {
                    s.purge_plane_records_before("task", 9)
                })
                .is_err(),
            ),
            (
                "delete_plane_record",
                run(&store, *status, body, |s| {
                    s.delete_plane_record("task", "t-err")
                })
                .is_err(),
            ),
            (
                "redeem_plane_token",
                run(&store, *status, body, |s| {
                    s.redeem_plane_token("ask", "n", 2, 1)
                })
                .is_err(),
            ),
            (
                "append_audit",
                run(&store, *status, body, |s| s.append_audit(&audit_row(1))).is_err(),
            ),
            (
                "list_audit",
                run(&store, *status, body, |s| s.list_audit()).is_err(),
            ),
            (
                "list_audit_tail",
                run(&store, *status, body, |s| s.list_audit_tail(5)).is_err(),
            ),
            (
                "list_denylist",
                run(&store, *status, body, |s| s.list_denylist()).is_err(),
            ),
        ];
        for (verb, errored) in checks {
            assert!(
                errored,
                "`{verb}` must FAIL on {what}; answering a default here would hide a real fault"
            );
        }
    }
}

/// A plugin that answers with the WRONG response variant is a contract violation and propagates as
/// an error too: the default is for "does not know the verb", not for "answered nonsense".
#[test]
fn a_wrong_variant_reply_is_an_error_not_a_default() {
    let Some(store) = open() else {
        return;
    };
    let ok = STATUS_OK;
    assert!(run(&store, ok, wire(&StoreResponse::Unit), |s| s
        .get_plane_record("task", "t-1"))
    .is_err());
    assert!(
        run(&store, ok, wire(&StoreResponse::Denylist(vec![])), |s| s
            .list_plane_record_parents("task"))
        .is_err()
    );
    assert!(run(
        &store,
        ok,
        wire(&StoreResponse::PlaneRecords(vec![])),
        |s| s.list_audit()
    )
    .is_err());
    assert!(run(
        &store,
        ok,
        wire(&StoreResponse::PlaneRecordParents(vec![])),
        |s| s.list_denylist()
    )
    .is_err());
    assert!(run(&store, ok, wire(&StoreResponse::Purged(1)), |s| s
        .redeem_plane_token("ask", "n", 2, 1))
    .is_err());
}
