// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! RETENTION ACROSS THE ABI: the plane-record sidecar (`ts` / `disposition`) must survive the
//! engine→plugin hop.
//!
//! The two sidecar columns are the ONLY thing a backend can sweep on without decoding an opaque
//! body, so a wire that drops them does not merely lose a field — it inverts retention for a
//! `dlopen`'ed store. Every appended row lands at ts 0, and an age-based purge with any cutoff above
//! zero therefore deletes the ENTIRE call log; every upserted row lands `Active`, and a
//! terminal-only purge therefore drops nothing, ever, so tasks accumulate without bound.
//!
//! These drive the REAL example plugin over the REAL C ABI (`dlopen` + `busbar_call`), so they
//! assert what a plugin actually receives, not what an in-tree type happens to serialize to. The
//! plugin itself already reads the sidecar correctly on its own trait impl (its in-crate tests pass);
//! only the crossing loses it.

use super::*;

/// A private durable file for one test, plus the plugin config that selects the fixture's
/// file-backed mode.
fn durable_cfg(tag: &str) -> String {
    let dir = std::env::temp_dir().join(format!(
        "busbar-plane-sidecar-{}-{}-{:?}",
        tag,
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).expect("create durable dir");
    let file = dir.join("durable.json");
    let _ = std::fs::remove_file(&file);
    serde_json::json!({ "durable_path": file.to_string_lossy() }).to_string()
}

/// AGE-BASED RETENTION on the `call` kind: rows NEWER than the cutoff survive it.
///
/// Three calls are appended through the ABI at ts 100 / 200 / 300 and swept with a cutoff of 150.
/// Exactly one row is old enough to go. When the wire drops `ts` all three land at 0 and the sweep
/// takes the whole log — the MCP evidence the audit claim rests on, gone on the first retention tick.
#[test]
fn appended_call_rows_newer_than_the_cutoff_survive_a_purge_over_the_abi() {
    let Some(lib) = store_example_plugin_path() else {
        eprintln!("skip: store example plugin cdylib not built (run under --workspace)");
        return;
    };
    let cfg = durable_cfg("call-purge");
    let store = load_store(&lib, &cfg).expect("load store example plugin over the ABI");

    for (seq, ts) in [(1u64, 100u64), (2, 200), (3, 300)] {
        let call = SampleCall {
            principal: "vk_owner".into(),
            seq,
            ts,
            server: "srv".into(),
            tool: "srv_echo".into(),
            outcome: "dispatched".into(),
            reason: String::new(),
            tool_digest: "sha256:aaa".into(),
            pin_generation: 1,
            request_id: format!("req-{seq}"),
            prev_hash: String::new(),
            hash: format!("h{seq}"),
        };
        store
            .append_plane_record(&call_record(&call))
            .expect("append call");
    }

    let purged = store
        .purge_plane_records_before("call", 150)
        .expect("purge calls");
    assert_eq!(
        purged, 1,
        "only the ts-100 row is older than the cutoff; a wire that drops `ts` reports 3"
    );

    let left = n_list_mcp_calls(store.as_ref(), "vk_owner").expect("list calls");
    let seqs: Vec<u64> = left.iter().map(|c| c.seq).collect();
    assert_eq!(
        seqs,
        vec![2, 3],
        "the two rows newer than the cutoff must still be there"
    );
}

/// TERMINAL-ONLY RETENTION on the `task` kind: a terminal task older than the cutoff IS purged.
///
/// When the wire drops `disposition` every task reconstitutes `Active`, so the terminal-only
/// predicate matches nothing and the sweep reports 0 — durable task rows accumulate forever.
#[test]
fn a_terminal_task_is_purged_over_the_abi() {
    let Some(lib) = store_example_plugin_path() else {
        eprintln!("skip: store example plugin cdylib not built (run under --workspace)");
        return;
    };
    let cfg = durable_cfg("task-purge");
    let store = load_store(&lib, &cfg).expect("load store example plugin over the ABI");

    // `completed` is terminal; `input-required` is a live task waiting on a human and must survive
    // the same sweep regardless of age — the split the sidecar exists to express.
    let done = sample_task_row("task-done", "completed", 100);
    let waiting = sample_task_row("task-waiting", "input-required", 100);
    store
        .upsert_plane_record(&task_record(&done))
        .expect("upsert terminal task");
    store
        .upsert_plane_record(&task_record(&waiting))
        .expect("upsert active task");

    let purged = store
        .purge_plane_records_before("task", 200)
        .expect("purge tasks");
    assert_eq!(
        purged, 1,
        "the terminal task is purged; a wire that drops `disposition` reports 0"
    );

    let left = n_list_tasks(store.as_ref()).expect("list tasks");
    let ids: Vec<String> = left.iter().map(|t| t.task_id.clone()).collect();
    assert_eq!(
        ids,
        vec!["task-waiting".to_string()],
        "the interrupted task must survive; only the terminal one goes"
    );
}

/// THE ADDITIVITY CLAIM, in the direction the version rule rests on: the enriched request the engine
/// now sends still decodes in a plugin built BEFORE the sidecar existed — which is why the store
/// payload schema version does not move and every published store keeps loading. Pinned
/// structurally: the mirror below is the pre-sidecar shape of the two write variants, and the
/// CURRENT request's bytes have to land in it. A future rename or retype of one of the old fields
/// stops passing here, which is the difference between an addition and a break the version does not
/// announce. (The reverse direction — an older engine's sidecar-less request decoding in a current
/// plugin — is pinned in plugin-sdk.)
#[test]
fn an_enriched_request_still_decodes_in_a_pre_sidecar_plugin() {
    #[derive(serde::Deserialize)]
    enum LegacyStoreRequest {
        UpsertPlaneRecord {
            kind: String,
            id: String,
            body: Vec<u8>,
        },
        AppendPlaneRecord {
            kind: String,
            parent: String,
            seq: u64,
            body: Vec<u8>,
        },
    }

    let bytes = serde_json::to_vec(&StoreRequest::UpsertPlaneRecord {
        kind: "task".into(),
        id: "task-abc".into(),
        ts: 2_000,
        disposition: PlaneDisposition::Terminal,
        body: vec![1],
    })
    .unwrap();
    match serde_json::from_slice(&bytes).expect("an older plugin still decodes the upsert") {
        LegacyStoreRequest::UpsertPlaneRecord { kind, id, body } => assert_eq!(
            (kind.as_str(), id.as_str(), body),
            ("task", "task-abc", vec![1])
        ),
        _ => panic!("wrong variant"),
    }

    let bytes = serde_json::to_vec(&StoreRequest::AppendPlaneRecord {
        kind: "call".into(),
        id: "vk".into(),
        parent: "vk".into(),
        seq: 3,
        ts: 1_600,
        disposition: PlaneDisposition::Active,
        body: vec![2],
    })
    .unwrap();
    match serde_json::from_slice(&bytes).expect("an older plugin still decodes the append") {
        LegacyStoreRequest::AppendPlaneRecord {
            kind,
            parent,
            seq,
            body,
        } => assert_eq!(
            (kind.as_str(), parent.as_str(), seq, body),
            ("call", "vk", 3, vec![2])
        ),
        _ => panic!("wrong variant"),
    }
}
