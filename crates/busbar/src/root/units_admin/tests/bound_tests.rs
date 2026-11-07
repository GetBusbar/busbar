// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::{plane_record_write_effect, PlaneRecordSink};
use crate::root::units_admin::AdminAnswer;
use busbar_contract::plane::PlaneDeclaration;
use busbar_contract::records::{PlaneDisposition, PlaneRecord, PlaneSelector};
use busbar_kernel::host_records_async::AsyncHistory;
use busbar_kernel::host_services::demotion_key;
use busbar_kernel::store::plane_view::KIND_DEMOTION;
use std::sync::{Arc, Mutex};

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

const MCP_KINDS: &[&str] = &["call", "demotion", "approval", "task"];

const KERNEL_KINDS: &[&str] = &[
    "audit",
    "usage_residual",
    "demotion",
    "trust_decision",
    "ticket",
];

async fn write(
    body: &serde_json::Value,
    planes: &[PlaneDeclaration],
    sink: &PlaneRecordSink,
) -> AdminAnswer {
    let lookup = |key: &str| planes.iter().find(|p| p.key == key).copied();
    plane_record_write_effect(&serde_json::to_vec(body).unwrap(), 100, &lookup, Some(sink))
        .await
        .expect("effect answers")
        .answer
}
fn refusal(answer: &AdminAnswer) -> (u16, String) {
    let body: serde_json::Value = serde_json::from_slice(&answer.body).unwrap();
    (
        answer.status,
        body["error"]["code"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
    )
}

#[tokio::test]
async fn an_admin_record_write_naming_mcp_cannot_alter_a_kernel_demotion_row() {
    let core = crate::root::real_store::core().await;
    let sink = super::live_records(Arc::clone(&core));
    let kernel = AsyncHistory::authorized_upserts(
        core,
        "busbar.kernel",
        KERNEL_KINDS.iter().map(|k| k.to_string()),
    )
    .unwrap();
    let key = demotion_key("mcp", "upstream-a");
    let kept = PlaneRecord {
        kind: KIND_DEMOTION.into(),
        id: key.clone(),
        parent: None,
        seq: 0,
        ts: 100,
        disposition: PlaneDisposition::Active,
        body: serde_json::to_vec(
            &serde_json::json!({"server":key,"reason":"drifted","recorded_at":100}),
        )
        .unwrap(),
    };
    kernel.upsert(kept.view()).await.unwrap();
    let mcp = plane("mcp", MCP_KINDS);
    for attempt in [
        serde_json::json!({"plane":"mcp","kind":"demotion","id":key,"body":{"nope":true}}),
        serde_json::json!({"plane":"mcp","kind":"demotion","id":key,"terminal":true,"body":{}}),
    ] {
        assert_eq!(
            refusal(&write(&attempt, &[mcp], &sink).await),
            (403, "forbidden".into())
        );
    }
    assert_eq!(kernel.get(KIND_DEMOTION, &key).await.unwrap(), Some(kept));
    let squatter = plane("squatter", KERNEL_KINDS);
    for kind in KERNEL_KINDS {
        let attempt = serde_json::json!({"plane":"squatter","kind":kind,"id":"x","body":{}});
        assert_eq!(
            refusal(&write(&attempt, &[squatter], &sink).await),
            (403, "forbidden".into())
        );
        assert_eq!(kernel.get(kind, "x").await.unwrap(), None);
    }
}

#[tokio::test]
async fn two_planes_declaring_one_kind_neither_see_nor_overwrite_each_others_rows() {
    let core = crate::root::real_store::core().await;
    let sink = super::live_records(Arc::clone(&core));
    let planes = [plane("alpha", &["note"]), plane("beta", &["note"])];
    for (key, text) in [("alpha", "alpha's"), ("beta", "beta's")] {
        let answer = write(
            &serde_json::json!({"plane":key,"kind":"note","id":"n-1","body":{"text":text}}),
            &planes,
            &sink,
        )
        .await;
        assert_eq!(answer.status, 200);
    }
    let mut kinds = Vec::new();
    for (plane, text) in [("alpha", "alpha's"), ("beta", "beta's")] {
        let kind = busbar_kernel::store::plane_view::plane_owned_kind(plane, "note").unwrap();
        let history = AsyncHistory::authorized_upserts(
            Arc::clone(&core),
            &format!("busbar.admin.envelopes/{plane}"),
            [kind.clone()],
        )
        .unwrap();
        let listed = history.list(&kind, &PlaneSelector::All).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(
            listed[0].body,
            format!(r#"{{"text":"{text}"}}"#).into_bytes()
        );
        assert_eq!(
            history.get(&kind, "n-1").await.unwrap(),
            Some(listed[0].clone())
        );
        kinds.push(kind);
    }
    assert_ne!(kinds[0], kinds[1]);
}

#[tokio::test]
async fn an_unknown_plane_write_keeps_its_exact_record_and_never_repeats_the_upsert() {
    use crate::root::units_admin::AdminRequest;
    use busbar_core_admin::idempotency::durable::{self, Refused};

    let core = crate::root::real_store::core().await;
    let store = Arc::new(durable::scoped_store(Arc::clone(&core)).unwrap());
    let replay_store: super::ReplayStore = {
        let store = Arc::clone(&store);
        Arc::new(move || Some(Arc::clone(&store)))
    };
    let submitted = Arc::new(Mutex::new(Vec::new()));
    let native = super::live_records(Arc::clone(&core));
    let sink: PlaneRecordSink = {
        let submitted = Arc::clone(&submitted);
        Arc::new(move |decl, record| {
            let (native, submitted) = (Arc::clone(&native), Arc::clone(&submitted));
            Box::pin(async move {
                submitted.lock().unwrap().push(record.clone());
                native(decl, record).await?;
                Err(super::PlaneWriteFailure::Unknown(None))
            })
        })
    };
    let mut request = AdminRequest {
        method: "POST".into(), path: "/api/v1/admin/plane-record-write".into(),
        credential: None,
        headers: vec![("idempotency-key".into(), "unknown-record".into())],
        body: br#"{"plane":"alpha","kind":"note","id":"n1","parent":"p1","terminal":true,"body":{"n":7}}"#.to_vec(),
        at: 1_700_000_000, unit: 1,
    };
    let cache = super::ReplayCache::new();
    let lookup = |key: &str| (key == "alpha").then_some(plane("alpha", &["note"]));
    async fn ask(
        cache: &super::ReplayCache,
        request: &AdminRequest,
        replay_store: &super::ReplayStore,
        sink: &PlaneRecordSink,
        lookup: &(dyn Fn(&str) -> Option<PlaneDeclaration> + Send + Sync),
    ) -> AdminAnswer {
        super::replayable(
            cache,
            Some(replay_store),
            super::ReplayScope {
                verb: busbar_core_admin::KernelVerb::PlaneRecordWrite,
                actor: "admin",
            },
            request,
            &request.body,
            None,
            || plane_record_write_effect(&request.body, request.at, lookup, Some(sink)),
        )
        .await
        .expect("the write answers")
    }
    let first = ask(&cache, &request, &replay_store, &sink, &lookup).await;
    assert_eq!(first.status, 503);
    let original = submitted.lock().unwrap()[0].clone();
    assert_eq!(
        original,
        PlaneRecord {
            kind: busbar_kernel::store::plane_view::plane_owned_kind("alpha", "note").unwrap(),
            id: "n1".into(),
            parent: Some("p1".into()),
            seq: 0,
            ts: request.at,
            disposition: PlaneDisposition::Terminal,
            body: br#"{"n":7}"#.to_vec(),
        }
    );
    let name =
        busbar_core_admin::verb_name(busbar_core_admin::KernelVerb::PlaneRecordWrite).unwrap();
    let replay_key = ("admin".to_string(), format!("{name}:unknown-record"));
    let kept = match durable::claim_held(&*store, &replay_key, request.at).await {
        Err(Refused::Retained(bytes)) => super::kept_answer(&bytes).expect("readable receipt"),
        other => panic!("the exact unknown receipt must be durable: {other:?}"),
    };
    assert_eq!(
        kept.digest,
        busbar_contract::abi::sdk::digest::sha256(&request.body)
    );
    assert_eq!(kept.answer, first);
    assert_eq!(
        kept.receipt,
        Some(super::EffectReceipt::PlaneRecordWrite {
            record: original.clone(),
            pending: None,
        })
    );
    let history = AsyncHistory::authorized_upserts(
        core,
        "busbar.admin.envelopes/alpha",
        [original.kind.clone()],
    )
    .unwrap();
    assert_eq!(
        history.get(&original.kind, &original.id).await.unwrap(),
        Some(original.clone())
    );
    assert_eq!(
        ask(&cache, &request, &replay_store, &sink, &lookup).await,
        first
    );
    request.at += busbar_core_admin::idempotency::IDEMPOTENCY_TTL_SECS + 1;
    assert_eq!(
        ask(&cache, &request, &replay_store, &sink, &lookup).await,
        first,
        "local custody outlives the replay window"
    );
    assert_eq!(
        ask(
            &super::ReplayCache::new(),
            &request,
            &replay_store,
            &sink,
            &lookup
        )
        .await,
        first,
        "restart replays the durable receipt"
    );
    assert_eq!(
        *submitted.lock().unwrap(),
        vec![original],
        "no retry changed metadata or repeated the upsert"
    );
    request.body = br#"{"plane":"alpha","kind":"note","id":"other","body":{}}"#.to_vec();
    assert_eq!(
        ask(
            &super::ReplayCache::new(),
            &request,
            &replay_store,
            &sink,
            &lookup
        )
        .await
        .status,
        409,
        "a retained key still owns its first body"
    );
    assert_eq!(submitted.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn trust_digest_guard_rejects_stale_and_malformed_reviews_at_the_admin_boundary() {
    use super::{trust_decide_effect, trust_list_effect, TrustDesk};
    use busbar_contract::services::{Caller, HostServices, Ran};
    use busbar_kernel::host_services::{InstanceFacts, KernelServices};
    use busbar_kernel::trust::book::Ruling;
    use busbar_kernel::trust::reverify::Policy;
    use busbar_kernel::trust::section::TrustEntry;
    let kernel = Arc::new(KernelServices::new());
    kernel
        .admit(
            "inst",
            InstanceFacts {
                trust: vec![(
                    "cp".into(),
                    TrustEntry {
                        pin: None,
                        policy: Policy {
                            ttl_ms: 0,
                            recovery_backoff_ms: 0,
                        },
                        approved: Default::default(),
                    },
                )],
                ..InstanceFacts::default()
            },
        )
        .await
        .unwrap();
    let desk: TrustDesk = {
        let kernel = Arc::clone(&kernel);
        Arc::new(move || Some(Arc::clone(&kernel)))
    };
    let caller = Caller {
        instance: Arc::from("inst"),
        plugin: Arc::from("plane"),
        kind: busbar_contract::abi::mechanism::KindCode::Plane,
    };
    let sight = |digest| {
        assert!(matches!(
            kernel.trust_sight(&caller, "cp", digest, Box::new(|_| {})),
            Ran::Now(_)
        ))
    };
    let decide = async |ruling, body| {
        trust_decide_effect(&serde_json::to_vec(&body).unwrap(), ruling, &desk)
            .await
            .unwrap()
    };
    sight("reviewed");
    assert_eq!(
        decide(
            Ruling::Approve,
            serde_json::json!({"key":"inst/cp","expected_digest":"reviewed"})
        )
        .await
        .status,
        200
    );
    sight("changed");
    let before = kernel.trust_rows();
    for ruling in [Ruling::Approve, Ruling::Revoke] {
        let stale = decide(
            ruling,
            serde_json::json!({"key":"inst/cp","expected_digest":"reviewed"}),
        )
        .await;
        assert_eq!(stale.status, 409);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&stale.body).unwrap()["error"]["code"],
            "conflict"
        );
        for guard in [
            serde_json::Value::Null,
            serde_json::json!(7),
            serde_json::json!(""),
            serde_json::json!(" "),
        ] {
            assert_eq!(
                decide(
                    ruling,
                    serde_json::json!({"key":"inst/cp","expected_digest":guard})
                )
                .await
                .status,
                400
            );
        }
        assert_eq!(kernel.trust_rows(), before);
    }
    let listed: serde_json::Value =
        serde_json::from_slice(&trust_list_effect(&desk).unwrap().body).unwrap();
    assert_eq!(listed["keys"][0]["approved"], "reviewed");
    assert_eq!(listed["keys"][0]["seen"], "changed");
    let revoked = decide(
        Ruling::Revoke,
        serde_json::json!({"key":"inst/cp","expected_digest":"changed"}),
    )
    .await;
    assert_eq!(revoked.status, 200);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&revoked.body).unwrap()["seen"],
        "changed"
    );
    let legacy = decide(Ruling::Approve, serde_json::json!({"key":"inst/cp"})).await;
    assert_eq!(legacy.status, 200);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&legacy.body).unwrap()["approved"],
        "changed"
    );
}

#[test]
fn a_native_pending_identity_survives_the_durable_effect_receipt() {
    let value = super::ReplayValue {
        digest: [3; 32],
        answer: AdminAnswer {
            status: 503,
            headers: vec![],
            body: b"pending".to_vec(),
        },
        receipt: Some(super::EffectReceipt::PlaneRecordWrite {
            record: PlaneRecord {
                kind: "owned".into(),
                id: "id".into(),
                parent: Some("opaque".into()),
                seq: 0,
                ts: 42,
                disposition: PlaneDisposition::Terminal,
                body: vec![0, 255],
            },
            pending: Some([7; 16]),
        }),
    };
    let decoded = super::kept_answer(&super::stored_answer(&value)).expect("receipt decodes");
    assert_eq!(decoded.digest, value.digest);
    assert_eq!(decoded.answer, value.answer);
    assert_eq!(decoded.receipt, value.receipt);
}
