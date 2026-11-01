// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `plane_record_write` over a real plane-facing store: the admin write lands only in the named
//! plane's own rows. It never reaches a row the kernel keeps (the durable demotion record among
//! them), and two planes declaring one kind never land on each other's rows.

use std::sync::{Arc, Mutex};

use busbar_contract::plane::PlaneDeclaration;
use busbar_contract::records::{PlaneDisposition, PlaneRecord, PlaneSelector};
use busbar_kernel::host_services::demotion_key;
use busbar_kernel::store::plane_view::{PlaneStore, PlaneStoreView, KIND_DEMOTION};
use busbar_kernel::trust::DemotionRecord;

use super::{plane_record_write_effect, PlaneRecordSink};
use crate::root::units_admin::AdminAnswer;

/// A plane declaring `record_kinds`, keyed `key`; nothing else about it matters here.
fn plane(key: &'static str, record_kinds: &'static [&'static str]) -> PlaneDeclaration {
    PlaneDeclaration {
        key,
        fallback: false,
        config_section: key,
        scope_kinds: &[],
        subject_noun: key,
        admin_noun: key,
        audit_kind: key,
        card_signing_domain: None,
        card_kid_prefix: None,
        owned_config_sections: &[],
        billable_classes: &[],
        fee_units: &[],
        metric_families: &[],
        record_kinds,
        required_config_sections: &[],
        trust_keys: &[],
        served_op_classes: &[],
        caller_credential_refusal: None,
    }
}

/// The record kinds plane-mcp declares at origin/dev (`door.rs` `RECORD_KINDS`).
const MCP_KINDS: &[&str] = &["call", "demotion", "approval", "task"];

/// Every kind the kernel keeps its own rows under in the store's plane records.
const KERNEL_KINDS: &[&str] = &[
    "audit",
    "usage_residual",
    "demotion",
    "trust_decision",
    "ticket",
];

/// A fresh in-memory store, narrowed to the plane-facing seam the admin write and the kernel's
/// demotion record both persist through.
fn store() -> Arc<dyn PlaneStore> {
    PlaneStoreView::narrow(Arc::new(busbar_kernel::governance::MemoryStore::new()))
}

/// The production sink's shape over `store`, recording the kind every record it took landed under.
fn sink_into(store: &Arc<dyn PlaneStore>, landed: &Arc<Mutex<Vec<String>>>) -> PlaneRecordSink {
    let (store, landed) = (Arc::clone(store), Arc::clone(landed));
    Arc::new(move |record: &PlaneRecord| {
        landed.lock().expect("landed").push(record.kind.clone());
        store
            .upsert_plane_record(record.view())
            .map_err(|e| e.to_string())
    })
}

/// One `plane_record_write` of `body` against a node serving `planes`.
fn write(
    body: &serde_json::Value,
    planes: &[PlaneDeclaration],
    sink: &PlaneRecordSink,
) -> AdminAnswer {
    let planes = planes.to_vec();
    let lookup = move |key: &str| planes.iter().find(|p| p.key == key).copied();
    plane_record_write_effect(
        &serde_json::to_vec(body).expect("JSON"),
        1_000,
        &lookup,
        Some(sink),
    )
    .expect("the effect answers")
}

/// The answer's error envelope `(status, code)`.
fn refusal(answer: &AdminAnswer) -> (u16, String) {
    let body: serde_json::Value = serde_json::from_slice(&answer.body).expect("JSON");
    (
        answer.status,
        body["error"]["code"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
    )
}

/// THE KERNEL'S DEMOTION ROW IS NOT THE ADMIN WRITE'S. plane-mcp declares the `demotion` kind, but
/// the rows under it are the kernel's durable demotion record (`DemotionRecord`, replayed at every
/// admit): an admin `plane_record_write` naming the MCP plane must neither overwrite, poison, nor
/// re-dispose the kernel's row, so a demoted upstream cannot be re-opened through the admin verb.
/// Each attempt is refused `403 forbidden` and the kernel's row reads back byte for byte.
#[test]
fn an_admin_record_write_naming_mcp_cannot_alter_a_kernel_demotion_row() {
    let store = store();
    let landed = Arc::new(Mutex::new(Vec::new()));
    let sink = sink_into(&store, &landed);
    let demotions = DemotionRecord::default();
    demotions.set_sink(Arc::clone(&store));

    // The kernel's own row, exactly as `DemotionRecord::record` writes it for the instance `mcp`.
    let key = demotion_key("mcp", "upstream-a");
    let kept = serde_json::to_vec(&serde_json::json!({
        "server": key, "reason": "drifted", "recorded_at": 100
    }))
    .expect("JSON");
    store
        .upsert_plane_record(
            PlaneRecord {
                kind: KIND_DEMOTION.to_string(),
                id: key.clone(),
                parent: None,
                seq: 0,
                ts: 100,
                disposition: PlaneDisposition::Active,
                body: kept.clone(),
            }
            .view(),
        )
        .expect("seeded");

    let mcp = plane("mcp", MCP_KINDS);
    let attempts = [
        // Re-point the row at another upstream: `upstream-a` would replay as never demoted.
        serde_json::json!({"plane": "mcp", "kind": "demotion", "id": key,
            "body": {"server": demotion_key("mcp", "elsewhere"), "reason": "drifted", "recorded_at": 100}}),
        // Poison the row: every later admit would fail to read the demotions.
        serde_json::json!({"plane": "mcp", "kind": "demotion", "id": key, "body": {"nope": true}}),
        // Re-dispose the row as terminal, so a terminal-only purge could take it.
        serde_json::json!({"plane": "mcp", "kind": "demotion", "id": key, "terminal": true,
            "body": {"server": key, "reason": "drifted", "recorded_at": 100}}),
    ];
    for attempt in &attempts {
        assert_eq!(
            refusal(&write(attempt, &[mcp], &sink)),
            (403, "forbidden".to_string()),
            "refused: {attempt}"
        );
    }
    assert!(
        landed.lock().expect("landed").is_empty(),
        "a refusal writes nothing"
    );
    assert_eq!(
        store.get_plane_record(KIND_DEMOTION, &key).expect("read"),
        Some(kept),
        "the kernel's row is byte for byte what the kernel wrote"
    );
    let replayed: Vec<_> = demotions
        .read()
        .expect("the demotions read")
        .into_iter()
        .map(|r| (r.upstream, r.reason, r.recorded_at))
        .collect();
    assert_eq!(replayed, vec![(key, "drifted".to_string(), 100)]);

    // No plane reaches ANY kernel kind through the admin write, whatever it declares.
    let squatter = plane("squatter", KERNEL_KINDS);
    for kind in KERNEL_KINDS {
        let attempt = serde_json::json!({"plane": "squatter", "kind": kind, "id": "x", "body": {}});
        assert_eq!(
            refusal(&write(&attempt, &[squatter], &sink)),
            (403, "forbidden".to_string()),
            "a kernel kind is refused: {kind}"
        );
        assert_eq!(
            store.get_plane_record(kind, "x").expect("read"),
            None,
            "nothing landed under the kernel's `{kind}`"
        );
    }
}

/// TWO PLANES DECLARING ONE KIND KEEP TWO SETS OF ROWS. `alpha` and `beta` both declare `note`; an
/// admin write of `n-1` for each lands in that plane's own rows: neither overwrites the other's,
/// and a read of one plane's rows answers only that plane's.
#[test]
fn two_planes_declaring_one_kind_neither_see_nor_overwrite_each_others_rows() {
    let store = store();
    let landed = Arc::new(Mutex::new(Vec::new()));
    let sink = sink_into(&store, &landed);
    let planes = [plane("alpha", &["note"]), plane("beta", &["note"])];

    for (key, text) in [("alpha", "alpha's"), ("beta", "beta's")] {
        let answer = write(
            &serde_json::json!({"plane": key, "kind": "note", "id": "n-1", "body": {"text": text}}),
            &planes,
            &sink,
        );
        assert_eq!(answer.status, 200, "written");
        let body: serde_json::Value = serde_json::from_slice(&answer.body).expect("JSON");
        assert_eq!(
            (&body["plane"], &body["kind"], &body["id"]),
            (
                &serde_json::json!(key),
                &serde_json::json!("note"),
                &serde_json::json!("n-1")
            ),
            "the answer names the record as the operator wrote it"
        );
    }
    let landed = landed.lock().expect("landed").clone();
    let [alpha, beta] = landed.as_slice() else {
        panic!("two records written: {landed:?}");
    };
    assert_ne!(alpha, beta, "the two planes' rows are keyed apart");
    for (kind, text) in [(alpha, "alpha's"), (beta, "beta's")] {
        let own = format!(r#"{{"text":"{text}"}}"#).into_bytes();
        assert_eq!(
            store
                .list_plane_records(kind, &PlaneSelector::All)
                .expect("listed"),
            vec![own.clone()],
            "a read of one plane's rows answers only its own"
        );
        assert_eq!(
            store.get_plane_record(kind, "n-1").expect("read"),
            Some(own),
            "neither write overwrote the other"
        );
    }
}
