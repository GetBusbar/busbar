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
        class_parents: &[],
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
            super::ReplayContext::None,
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
    let kept = match durable::claim_held(&store, &replay_key, request.at).await {
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
        as_replayed(&first)
    );
    request.at += busbar_core_admin::idempotency::IDEMPOTENCY_TTL_SECS + 1;
    assert_eq!(
        ask(&cache, &request, &replay_store, &sink, &lookup).await,
        as_replayed(&first),
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
        as_replayed(&first),
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

/// A kernel with native trust custody: its decision record bound to a real Store and a pool for
/// the durable trust effects (TRUST-ADMIN-PRODUCER-DESIGN r3 §6, condition A-C1).
pub(crate) async fn bound_kernel() -> busbar_kernel::host_services::KernelServices {
    use busbar_kernel::host_services::{BlockingPool, KernelServices};
    let record = Arc::new(busbar_kernel::trust::DemotionRecord::default());
    record
        .set_store(crate::root::real_store::core().await)
        .expect("the native Store keeps trust decisions");
    KernelServices::new()
        .with_demotions(record, "")
        .with_pool(Arc::new(BlockingPool::new(
            tokio::runtime::Handle::current(),
            busbar_kernel::host_records::QUEUE_CAP,
        )))
}

/// The first answer as a replay returns it: the same status and body, and the same headers plus
/// the replay marker (r3 §4.6, condition A-C2).
fn as_replayed(first: &AdminAnswer) -> AdminAnswer {
    let mut replayed = first.clone();
    replayed
        .headers
        .push((super::REPLAYED_HEADER.to_string(), "true".to_string()));
    replayed
}

#[tokio::test]
async fn trust_digest_guard_rejects_stale_and_malformed_reviews_at_the_admin_boundary() {
    use super::{trust_decide_effect, trust_list_effect};
    use busbar_contract::services::{Caller, HostServices, Ran};
    use busbar_kernel::host_services::InstanceFacts;
    use busbar_kernel::trust::book::Ruling;
    use busbar_kernel::trust::reverify::Policy;
    use busbar_kernel::trust::section::TrustEntry;
    use std::sync::atomic::{AtomicBool, Ordering};
    let kernel = Arc::new(bound_kernel().await);
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
    let caller = Caller::for_test(
        Arc::from("inst"),
        busbar_contract::abi::mechanism::KindCode::Plane,
    );
    // A sighting that moves an approved key is a durable trust effect: it may settle later.
    let sight = async |digest| {
        let (sent, settled) = tokio::sync::oneshot::channel();
        match kernel.trust_sight(
            &caller,
            "cp",
            digest,
            Box::new(move |stored| {
                let _ = sent.send(stored);
            }),
        ) {
            Ran::Now(_) => {}
            Ran::Later => {
                settled.await.expect("the sighting settles");
            }
        }
    };
    let audited = AtomicBool::new(false);
    let decide = async |ruling, body| {
        trust_decide_effect(
            &serde_json::to_vec(&body).unwrap(),
            ruling,
            Some(&*kernel),
            "op",
            None,
            &audited,
        )
        .await
        .unwrap()
    };
    let reason = |answer: &AdminAnswer| {
        serde_json::from_slice::<serde_json::Value>(&answer.body).unwrap()["error"]["reason"]
            .clone()
    };
    sight("reviewed").await;
    assert_eq!(
        decide(
            Ruling::Approve,
            serde_json::json!({"key":"inst/cp","expected_digest":"reviewed"})
        )
        .await
        .status,
        200
    );
    assert!(
        audited.load(Ordering::SeqCst),
        "the kernel wrote the request's typed row"
    );
    sight("changed").await;
    let before = kernel.trust_rows();
    for ruling in [Ruling::Approve, Ruling::Revoke] {
        let stale = decide(
            ruling,
            serde_json::json!({"key":"inst/cp","expected_digest":"obsolete"}),
        )
        .await;
        assert_eq!(stale.status, 409);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&stale.body).unwrap()["error"]["code"],
            "conflict"
        );
        assert_eq!(reason(&stale), "reviewed_digest_stale");
        // `null` is a review of a never-sighted key: this key was sighted, so it is stale.
        let unsighted = decide(
            ruling,
            serde_json::json!({"key":"inst/cp","expected_digest":null}),
        )
        .await;
        assert_eq!(unsighted.status, 409);
        assert_eq!(reason(&unsighted), "reviewed_digest_stale");
        for guard in [
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
        serde_json::from_slice(&trust_list_effect(Some(&kernel)).unwrap().body).unwrap();
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
    // r3 §4.1: there is no key-only decision; an omitted review is 428 and changes nothing.
    let after = kernel.trust_rows();
    let omitted = decide(Ruling::Approve, serde_json::json!({"key":"inst/cp"})).await;
    assert_eq!(omitted.status, 428);
    assert_eq!(reason(&omitted), "reviewed_digest_required");
    assert_eq!(kernel.trust_rows(), after);
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

/// The `error` object of an admin answer's envelope.
fn error_of(answer: &AdminAnswer) -> serde_json::Value {
    serde_json::from_slice::<serde_json::Value>(&answer.body).expect("the answer is JSON")["error"]
        .clone()
}

fn header_of<'a>(answer: &'a AdminAnswer, name: &str) -> Option<&'a str> {
    answer
        .headers
        .iter()
        .find(|(header, _)| header == name)
        .map(|(_, value)| value.as_str())
}

/// TRUST-ADMIN-PRODUCER-DESIGN r3 §10.2 R1: no native custody is 503, never a 404 or an approval.
#[tokio::test]
async fn trust_verbs_refuse_unavailable_without_native_custody() {
    use busbar_kernel::trust::book::Ruling;
    let audited = std::sync::atomic::AtomicBool::new(false);
    for ruling in [Ruling::Approve, Ruling::Revoke] {
        let answer = super::trust_decide_effect(
            br#"{"key":"inst/cp","expected_digest":"d1"}"#,
            ruling,
            None,
            "op",
            None,
            &audited,
        )
        .await
        .unwrap();
        assert_eq!(answer.status, 503);
        let error = error_of(&answer);
        assert_eq!(error["code"], "unavailable");
        assert_eq!(error["reason"], "service_unavailable");
        assert_eq!(error["retryable"], true);
        assert_eq!(
            header_of(&answer, super::TRUST_EFFECT_HEADER),
            Some("not_applied")
        );
    }
    assert!(
        !audited.load(std::sync::atomic::Ordering::SeqCst),
        "no kernel ran, so the generic row records the refusal"
    );
}

/// R2: `GET /trust` without custody is 503, never an empty success.
#[test]
fn get_trust_without_custody_is_unavailable() {
    let answer = super::trust_list_effect(None).unwrap();
    assert_eq!(answer.status, 503);
    assert_eq!(error_of(&answer)["reason"], "service_unavailable");
}

/// G15: the trust decision reasons are stable closed reasons with their codes and statuses.
#[test]
fn trust_reason_codes_are_stable() {
    for (reason, code, http) in [
        ("reviewed_digest_required", "invalid_request", 428),
        ("reviewed_digest_stale", "conflict", 409),
        ("decision_in_progress", "conflict", 409),
        ("outcome_not_applied", "conflict", 409),
        ("action_in_flight", "conflict", 409),
        ("service_unavailable", "unavailable", 503),
    ] {
        let row = busbar_kernel::admin::reasons::row(reason)
            .unwrap_or_else(|| panic!("{reason} is a closed reason"));
        assert_eq!((row.code, row.http), (code, http), "{reason}");
    }
}

fn trust_request(key: &str, body: &[u8]) -> crate::root::units_admin::AdminRequest {
    crate::root::units_admin::AdminRequest {
        method: "POST".into(),
        path: "/api/v1/admin/trust/approve".into(),
        credential: None,
        headers: vec![("idempotency-key".into(), key.into())],
        body: body.to_vec(),
        at: 1_700_000_000,
        unit: 1,
    }
}

/// R6 and condition B-C4: a decision under an `Idempotency-Key` runs once; the same key and bytes
/// answer the original answer marked as replayed, audited by one typed replay row; an invalid key
/// is refused before any claim or effect.
#[tokio::test]
async fn trust_approve_honours_idempotency_key() {
    use busbar_contract::services::{Caller, HostServices};
    use busbar_core_admin::KernelVerb;
    use busbar_kernel::host_services::InstanceFacts;
    use busbar_kernel::trust::book::Ruling;
    use busbar_kernel::trust::reverify::Policy;
    use busbar_kernel::trust::section::TrustEntry;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    let kernel = Arc::new(bound_kernel().await);
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
    let caller = Caller::for_test(
        Arc::from("inst"),
        busbar_contract::abi::mechanism::KindCode::Plane,
    );
    let _ = kernel.trust_sight(&caller, "cp", "d1", Box::new(|_| {}));
    let store = crate::root::real_store::admin_scoped().await;
    let replay_store: super::ReplayStore = Arc::new(move || Some(Arc::clone(&store)));
    let cache = super::ReplayCache::new();
    let ran = AtomicUsize::new(0);
    let body = br#"{"key":"inst/cp","expected_digest":"d1"}"#;
    let ask = async |request: &crate::root::units_admin::AdminRequest, audited: &AtomicBool| {
        super::replayable(
            &cache,
            Some(&replay_store),
            super::ReplayScope {
                verb: KernelVerb::TrustApprove,
                actor: "op",
            },
            request,
            &request.body,
            None,
            super::ReplayContext::Trust {
                kernel: Some(&*kernel),
                audited,
            },
            || async {
                ran.fetch_add(1, Ordering::SeqCst);
                super::trust_decide_effect(
                    &request.body,
                    Ruling::Approve,
                    Some(&*kernel),
                    "op",
                    super::idempotency_key(request),
                    audited,
                )
                .await
            },
        )
        .await
        .expect("the decision answers")
    };
    let request = trust_request("review-1", body);
    let first = ask(&request, &AtomicBool::new(false)).await;
    assert_eq!(first.status, 200);
    assert_eq!(
        header_of(&first, super::TRUST_EFFECT_HEADER),
        Some("applied")
    );
    let rows = kernel.trust_rows();
    let replay_audited = AtomicBool::new(false);
    let again = ask(&request, &replay_audited).await;
    assert_eq!(again, as_replayed(&first));
    assert!(
        replay_audited.load(Ordering::SeqCst),
        "the replay wrote its typed row"
    );
    assert_eq!(ran.load(Ordering::SeqCst), 1, "the decision ran once");
    assert_eq!(kernel.trust_rows(), rows);

    let invalid = ask(&trust_request("two words", body), &AtomicBool::new(false)).await;
    assert_eq!(invalid.status, 400);
    assert_eq!(error_of(&invalid)["code"], "invalid_request");
    assert_eq!(ran.load(Ordering::SeqCst), 1, "an invalid key runs nothing");

    let mismatch = ask(
        &trust_request("review-1", br#"{"key":"inst/cp","expected_digest":null}"#),
        &AtomicBool::new(false),
    )
    .await;
    assert_eq!(mismatch.status, 409);
    assert_eq!(error_of(&mismatch)["reason"], "idempotency_mismatch");
    assert_eq!(ran.load(Ordering::SeqCst), 1);
}

/// G18: a retained trust receipt this build cannot read is answered truthfully, never "nothing
/// was done", and runs nothing.
#[tokio::test]
async fn unreadable_receipt_is_answered_truthfully() {
    let held = super::HeldReplay {
        value: super::ReplayValue {
            digest: [1; 32],
            answer: AdminAnswer {
                status: 503,
                headers: vec![],
                body: b"original".to_vec(),
            },
            receipt: Some(super::EffectReceipt::TrustDecision {
                version: 2,
                attempt_op_id: [9; 16],
                key: "inst/cp".into(),
                ruling: "approve".into(),
                decided_at: 1,
                operation: Some("review-1".into()),
            }),
        },
        settlement: None,
    };
    let audited = std::sync::atomic::AtomicBool::new(false);
    let replayed = held
        .replay(
            None,
            super::ReplayContext::Trust {
                kernel: None,
                audited: &audited,
            },
        )
        .await;
    assert_eq!(replayed.answer.status, 503);
    assert!(replayed.terminal.is_none(), "nothing resolves it");
    let message = error_of(&replayed.answer)["message"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        message.contains("cannot be read back by this build; do not re-submit"),
        "{message}"
    );
    assert!(!message.contains("nothing was done"), "{message}");
}

const PIN_CANARY: &str = "pin-material-canary-5c3e";

/// A bound-custody kernel admitting `inst/cp`, declared under a pin whose operator material is the
/// canary and sighted at its declared fingerprint `fp`.
async fn pinned_kernel() -> Arc<busbar_kernel::host_services::KernelServices> {
    use busbar_contract::services::{Caller, HostServices};
    use busbar_kernel::host_services::InstanceFacts;
    use busbar_kernel::trust::reverify::Policy;
    use busbar_kernel::trust::section::{DeclaredPin, TrustEntry};
    let kernel = Arc::new(bound_kernel().await);
    kernel
        .admit(
            "inst",
            InstanceFacts {
                trust: vec![(
                    "cp".into(),
                    TrustEntry {
                        pin: Some(DeclaredPin {
                            mechanism: "fingerprint".into(),
                            root: false,
                            peer_key: false,
                            key: Some(PIN_CANARY.into()),
                            fingerprint: Some("fp".into()),
                        }),
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
    let caller = Caller::for_test(
        Arc::from("inst"),
        busbar_contract::abi::mechanism::KindCode::Plane,
    );
    let _ = kernel.trust_sight(&caller, "cp", "fp", Box::new(|_| {}));
    kernel
}

async fn decide_directly(
    kernel: &busbar_kernel::host_services::KernelServices,
    body: &[u8],
    operation: Option<&str>,
    audited: &std::sync::atomic::AtomicBool,
) -> AdminAnswer {
    super::trust_decide_effect(
        body,
        busbar_kernel::trust::book::Ruling::Approve,
        Some(kernel),
        "op",
        operation,
        audited,
    )
    .await
    .expect("the decision answers")
    .answer
}

/// G3: a stale review is refused as `reviewed_digest_stale`, changes nothing, keeps nothing, and is
/// audited by the kernel's typed row (the host flag is set).
#[tokio::test]
async fn stale_review_refuses_without_mutation_and_names_the_key() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let kernel = pinned_kernel().await;
    let before = kernel.trust_rows();
    let audited = AtomicBool::new(false);
    let answer = decide_directly(
        &kernel,
        br#"{"key":"inst/cp","expected_digest":"not-current"}"#,
        None,
        &audited,
    )
    .await;
    assert_eq!(answer.status, 409);
    assert_eq!(error_of(&answer)["reason"], "reviewed_digest_stale");
    assert_eq!(
        kernel.trust_rows(),
        before,
        "a stale review changes nothing"
    );
    assert!(
        busbar_kernel::trust::TrustReadout::over(Arc::clone(&kernel))
            .kept_decisions()
            .await
            .expect("custody is bound")
            .decisions
            .is_empty(),
        "nothing was kept"
    );
    assert!(
        audited.load(Ordering::SeqCst),
        "the kernel wrote the typed row"
    );
}

/// G16: the kept decision echoes the request's `Idempotency-Key` and its principal.
#[tokio::test]
async fn decision_row_echoes_the_operation_id() {
    use busbar_kernel::trust::book::DecidedBy;
    let kernel = pinned_kernel().await;
    let audited = std::sync::atomic::AtomicBool::new(false);
    let answer = decide_directly(
        &kernel,
        br#"{"key":"inst/cp","expected_digest":"fp"}"#,
        Some("op-123"),
        &audited,
    )
    .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let kept = busbar_kernel::trust::TrustReadout::over(Arc::clone(&kernel))
        .kept_decisions()
        .await
        .expect("custody is bound");
    assert_eq!(kept.decisions.len(), 1);
    assert_eq!(kept.decisions[0].operation.as_deref(), Some("op-123"));
    assert_eq!(
        kept.decisions[0].decided_by,
        Some(DecidedBy::Principal { id: "op".into() })
    );
}

/// G9 (root carriers): the operator's pin material never appears in a decision answer, a refusal,
/// `GET /trust`, or the redacted kept decisions.
#[tokio::test]
async fn no_pin_material_anywhere() {
    let kernel = pinned_kernel().await;
    let audited = std::sync::atomic::AtomicBool::new(false);
    let refused = decide_directly(
        &kernel,
        br#"{"key":"inst/cp","expected_digest":"other"}"#,
        None,
        &audited,
    )
    .await;
    let decided = decide_directly(
        &kernel,
        br#"{"key":"inst/cp","expected_digest":"fp"}"#,
        Some("op-9"),
        &audited,
    )
    .await;
    let listed = super::trust_list_effect(Some(&kernel)).expect("listed");
    let kept = busbar_kernel::trust::TrustReadout::over(Arc::clone(&kernel))
        .kept_decisions()
        .await
        .expect("custody is bound");
    for (carrier, bytes) in [
        ("refusal", refused.body),
        ("decision", decided.body),
        ("GET /trust", listed.body),
        ("kept decisions", format!("{kept:?}").into_bytes()),
    ] {
        assert!(
            !String::from_utf8_lossy(&bytes).contains(PIN_CANARY),
            "{carrier} carries pin material"
        );
    }
}
