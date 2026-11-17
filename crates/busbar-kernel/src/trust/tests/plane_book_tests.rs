// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! W1-K10: the core trust book planes run on (IF §12.14): SIGHT, TRUST_SERVES, TRUST_STATE, `due`, TRUST_VERIFY
//! (today's `trust.verify` body), the operator's approve/revoke/release, durability across a restart, and the
//! TRUST_APPROVAL value reader.

use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use busbar_contract::crypto::ed25519::SigningKey;
use busbar_contract::json::{
    json, JsonContainerTrait as _, JsonValueMutTrait as _, JsonValueTrait as _, Value,
};
use busbar_plugin_abi::host_side::caller::{CallStack, Caller, InstanceLimits};
use busbar_plugin_abi::plane::{
    DISTRUST_CHANGED, DISTRUST_NONE, DISTRUST_NOT_APPROVED, DISTRUST_QUARANTINED, DISTRUST_UNKNOWN,
    DISTRUST_UNSIGHTED, SIGNED_ALGORITHM, SIGNED_MALFORMED_ROOT, SIGNED_NONE, SIGNED_NOT_BY_ROOT,
    SIGNED_VERIFIED,
};
use busbar_plugin_abi::types::KindCode;

use super::*;
use crate::plugin_records::StoreRecords;
use crate::trust::book::TrustBook as Judge;

const PAYLOAD: &[u8] = br#"{"name":"peer","version":"1"}"#;
const KEY_INFO_HEAD: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
const NOW_MS: u64 = 1_800_000_000_000;

fn clock() -> u64 {
    NOW_MS
}

#[derive(Default)]
struct Recorded(Mutex<Vec<(String, String, String, String)>>);

impl TrustAudit for Recorded {
    fn record(&self, action: &'static str, plane: &str, party: &str, detail: &str) {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).push((
            action.to_owned(),
            plane.to_owned(),
            party.to_owned(),
            detail.to_owned(),
        ));
    }
}

impl Recorded {
    fn actions(&self) -> Vec<String> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|(a, ..)| a.clone())
            .collect()
    }
}

fn plane() -> Caller<'static> {
    Caller {
        plugin: "plane-a2a",
        kind: KindCode::Plane,
        name: "agents",
        instance: 1,
        slot: 0,
        chain: 1,
        deadline: std::time::Instant::now() + std::time::Duration::from_secs(30),
        stack: CallStack::default(),
        out_of_process: false,
        limits: InstanceLimits::default(),
    }
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_seed(&[seed; 32]).expect("an Ed25519 seed")
}

fn key_info(k: &SigningKey) -> String {
    STANDARD.encode([&KEY_INFO_HEAD[..], &k.verifying_key().to_bytes()[..]].concat())
}

fn signature(k: &SigningKey, header: &Value, payload: &[u8]) -> Value {
    let protected = URL_SAFE_NO_PAD.encode(header.to_string());
    let input = format!("{protected}.{}", URL_SAFE_NO_PAD.encode(payload));
    let sig = k.sign(input.as_bytes());
    json!({ "protected": protected, "signature": URL_SAFE_NO_PAD.encode(sig) })
}

fn d(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn approvals() -> Vec<(String, TrustEntry)> {
    let remote = approval_entry(
        "trust.agents.remote",
        &json!({
            "root": {"mechanism": "jws_issuer_key", "key": key_info(&key(1))},
            "items": {"search": digest_text(&d(1))},
        }),
    )
    .expect("an approval");
    let plain = approval_entry("trust.agents.plain", &json!({})).expect("an empty approval");
    vec![("remote".to_owned(), remote), ("plain".to_owned(), plain)]
}

struct Rig {
    store: Arc<crate::persistence::facade::CoreStore>,
    audit: Arc<Recorded>,
}

impl Rig {
    async fn new() -> Self {
        Self {
            store: crate::real_store::core().await,
            audit: Arc::new(Recorded::default()),
        }
    }

    /// One process's book over the shared store, admitted with the approvals.
    async fn book(&self) -> CoreTrustBook<StoreRecords> {
        let book = CoreTrustBook::new(
            Arc::new(Judge::default()),
            StoreRecords::new(Arc::clone(&self.store)),
            Arc::clone(&self.audit) as Arc<dyn TrustAudit>,
            clock,
        );
        book.admit("agents", approvals()).await.expect("admitted");
        book
    }
}

#[tokio::test]
async fn an_item_serves_at_its_approved_digest_and_drift_demotes_it() {
    let rig = Rig::new().await;
    let book = rig.book().await;
    let who = plane();
    assert_eq!(
        book.serves(&who, "remote", Some(("search", Some(d(1))))),
        DISTRUST_NONE
    );
    assert_eq!(
        book.serves(&who, "remote", Some(("search", Some(d(2))))),
        DISTRUST_CHANGED
    );
    assert_eq!(
        book.serves(&who, "remote", Some(("other", Some(d(1))))),
        DISTRUST_NOT_APPROVED
    );
    assert_eq!(book.serves(&who, "nobody", None), DISTRUST_UNKNOWN);

    book.sight(&who, "remote", None, &[("search", d(2))])
        .await
        .expect("a sighting");
    assert!(rig.audit.actions().contains(&AUDIT_TRUST_DRIFT.to_owned()));
    assert_eq!(
        book.serves(&who, "remote", Some(("search", Some(d(1))))),
        DISTRUST_CHANGED,
        "a drifted item stays refused, a revert included, until the operator decides it again"
    );

    let mut items = Vec::new();
    book.state(&who, "remote", &mut |item| {
        items.push((
            item.name.to_owned(),
            item.verdict,
            item.approved,
            item.sighted,
        ));
    });
    assert_eq!(
        items,
        vec![(
            "search".to_owned(),
            DISTRUST_CHANGED,
            Some(d(1)),
            Some(d(2))
        )]
    );

    book.approve("agents", "remote", "search", d(2))
        .await
        .expect("the operator approves the sighted digest");
    assert_eq!(
        book.serves(&who, "remote", Some(("search", None))),
        DISTRUST_NONE
    );
    assert_eq!(
        book.approve("agents", "remote", "search", d(3)).await,
        Err(RecordsDenied::Invalid),
        "an approval names the digest the operator reviewed, which must be the current sighting"
    );
    book.revoke("agents", "remote", "search")
        .await
        .expect("revoked");
    assert_eq!(
        book.serves(&who, "remote", Some(("search", None))),
        DISTRUST_NOT_APPROVED
    );
}

#[tokio::test]
async fn decisions_and_demotions_survive_a_restart() {
    let rig = Rig::new().await;
    let who = plane();
    {
        let book = rig.book().await;
        book.sight(&who, "remote", None, &[("search", d(2))])
            .await
            .expect("a sighting");
        book.sight(&who, "remote", None, &[("lookup", d(5))])
            .await
            .expect("a sighting");
        book.approve("agents", "remote", "lookup", d(5))
            .await
            .expect("approved");
    }
    let restarted = rig.book().await;
    assert_eq!(
        restarted.serves(&who, "remote", Some(("search", Some(d(1))))),
        DISTRUST_CHANGED,
        "the drift demotion is durable"
    );
    assert_eq!(
        restarted.serves(&who, "remote", Some(("lookup", Some(d(5))))),
        DISTRUST_NONE,
        "the operator's approval is durable"
    );
}

#[tokio::test]
async fn a_catalogue_that_moves_from_its_pin_quarantines_until_released() {
    let rig = Rig::new().await;
    let who = plane();
    let book = CoreTrustBook::new(
        Arc::new(Judge::default()),
        StoreRecords::new(Arc::clone(&rig.store)),
        Arc::clone(&rig.audit) as Arc<dyn TrustAudit>,
        clock,
    );
    let pinned = approval_entry(
        "trust.agents.remote",
        &json!({
            "root": {"mechanism": "jws_issuer_key", "key": key_info(&key(1))},
            "fingerprint": digest_text(&d(7)),
        }),
    )
    .expect("an approval");
    book.admit("agents", vec![("remote".to_owned(), pinned)])
        .await
        .expect("admitted");
    book.sight(&who, "remote", Some(d(7)), &[])
        .await
        .expect("a sighting at the pin");
    book.approve("agents", "remote", "", d(7))
        .await
        .expect("the operator approves the counterparty");
    assert_eq!(book.serves(&who, "remote", None), DISTRUST_NONE);
    book.sight(&who, "remote", Some(d(8)), &[])
        .await
        .expect("a drifted sighting");
    assert_eq!(book.serves(&who, "remote", None), DISTRUST_QUARANTINED);
    assert!(rig.audit.actions().contains(&AUDIT_TRUST_DRIFT.to_owned()));

    let restarted = CoreTrustBook::new(
        Arc::new(Judge::default()),
        StoreRecords::new(Arc::clone(&rig.store)),
        Arc::clone(&rig.audit) as Arc<dyn TrustAudit>,
        clock,
    );
    let pinned = approval_entry(
        "trust.agents.remote",
        &json!({
            "root": {"mechanism": "jws_issuer_key", "key": key_info(&key(1))},
            "fingerprint": digest_text(&d(7)),
        }),
    )
    .expect("an approval");
    restarted
        .admit("agents", vec![("remote".to_owned(), pinned)])
        .await
        .expect("admitted");
    assert_eq!(
        restarted.serves(&who, "remote", None),
        DISTRUST_QUARANTINED,
        "the quarantine is durable"
    );
    restarted
        .sight(&who, "remote", Some(d(8)), &[])
        .await
        .expect("sighted again");
    restarted
        .release("agents", "remote")
        .await
        .expect("the operator clears the quarantine");
    assert_eq!(restarted.serves(&who, "remote", None), DISTRUST_NONE);
}

#[tokio::test]
async fn due_lists_the_unsighted_counterparties() {
    let rig = Rig::new().await;
    let book = rig.book().await;
    let who = plane();
    let mut due = book.due(&who, NOW_MS / 1_000);
    due.sort();
    assert_eq!(
        due,
        vec![Box::<str>::from("plain"), Box::<str>::from("remote")]
    );
    book.sight(&who, "remote", Some(d(1)), &[])
        .await
        .expect("a sighting");
    assert_eq!(
        book.due(&who, NOW_MS / 1_000),
        vec![Box::<str>::from("plain")]
    );
    assert!(book
        .due(
            &Caller {
                name: "unknown",
                ..plane()
            },
            0
        )
        .is_empty());
    assert_eq!(
        book.serves(&who, "plain", None),
        DISTRUST_UNSIGHTED,
        "a counterparty with no pin and no sighting has nothing to judge by"
    );
}

#[tokio::test]
async fn verify_answers_todays_verdicts_against_the_configured_root() {
    let rig = Rig::new().await;
    let book = rig.book().await;
    let who = plane();
    let eddsa = json!({"alg": "EdDSA", "kid": "k1"});
    let mut named = String::new();

    let good = json!([signature(&key(1), &eddsa, PAYLOAD)]).to_string();
    assert_eq!(
        book.verify(&who, "remote", PAYLOAD, good.as_bytes(), &mut named),
        SIGNED_VERIFIED
    );
    let other = json!([signature(&key(2), &eddsa, PAYLOAD)]).to_string();
    assert_eq!(
        book.verify(&who, "remote", PAYLOAD, other.as_bytes(), &mut named),
        SIGNED_NOT_BY_ROOT
    );
    assert_eq!(
        book.verify(&who, "remote", PAYLOAD, b"", &mut named),
        SIGNED_NONE
    );
    let es = json!([signature(&key(1), &json!({"alg": "ES256"}), PAYLOAD)]).to_string();
    assert_eq!(
        book.verify(&who, "remote", PAYLOAD, es.as_bytes(), &mut named),
        SIGNED_ALGORITHM
    );
    assert_eq!(named, "ES256", "the other algorithm is named");

    let mut named = String::new();
    assert_eq!(
        book.verify(&who, "plain", PAYLOAD, good.as_bytes(), &mut named),
        SIGNED_MALFORMED_ROOT
    );
    assert!(rig
        .audit
        .actions()
        .contains(&AUDIT_TRUST_ROOT_MISSING.to_owned()));
    assert!(rig.audit.actions().contains(&AUDIT_TRUST_VERIFY.to_owned()));
}

#[test]
fn an_approval_value_is_read_strictly() {
    let entry = approval_entry(
        "trust.agents.remote",
        &json!({
            "root": {"mechanism": "jws_issuer_key", "key": "AAAA"},
            "fingerprint": "sha256:00",
            "items": {"a": digest_text(&d(0xAB)), "blank": ""},
        }),
    )
    .expect("an approval");
    let pin = entry.pin.expect("a root pin");
    assert!(pin.root);
    assert_eq!(pin.mechanism, "jws_issuer_key");
    assert_eq!(pin.key.as_deref(), Some("AAAA"));
    assert_eq!(entry.approved.len(), 1, "a blank digest approves nothing");
    assert_eq!(
        entry.approved.get("a").map(String::as_str),
        Some(digest_text(&d(0xAB)).as_str())
    );

    assert!(approval_entry("t", &json!({"tools": {}})).is_err());
    assert!(approval_entry("t", &json!({"items": {"a": "md5:00"}})).is_err());
    assert!(approval_entry("t", &json!({"root": {"mechanism": "x"}})).is_err());
    assert!(approval_entry("t", &json!("text")).is_err());
    assert_eq!(digest_of(&digest_text(&d(3))), Some(d(3)));
    assert_eq!(digest_of("sha256:zz"), None);
}

/// TRUST_VERIFY answers exactly what today's `trust.verify` body (`trust::signed`) answers, verdict and name, over
/// its corpus.
#[tokio::test]
async fn verify_is_todays_trust_verify_body() {
    let rig = Rig::new().await;
    let book = rig.book().await;
    let who = plane();
    let eddsa = json!({"alg": "EdDSA"});
    let good = signature(&key(1), &eddsa, PAYLOAD);
    let tampered = {
        let mut sig = good.clone();
        let mut raw = URL_SAFE_NO_PAD
            .decode(
                sig.get(&"signature")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default(),
            )
            .unwrap_or_default();
        if let Some(b) = raw.get_mut(10) {
            *b ^= 1;
        }
        sig.as_object_mut().expect("a signature object").insert(
            &"signature",
            Value::from(URL_SAFE_NO_PAD.encode(raw).as_str()),
        );
        sig
    };
    let corpus: Vec<(&[u8], Value)> = vec![
        (PAYLOAD, json!([good])),
        (PAYLOAD, json!([tampered])),
        (
            br#"{"name":"peer","version":"2"}"#.as_slice(),
            json!([good]),
        ),
        (PAYLOAD, json!([signature(&key(2), &eddsa, PAYLOAD)])),
        (PAYLOAD, json!([])),
        (PAYLOAD, json!(vec![good.clone(); 9])),
        (PAYLOAD, json!([{"protected": "!!", "signature": "AA"}])),
        (PAYLOAD, json!([{"signature": "AA"}])),
        (
            PAYLOAD,
            json!([signature(&key(1), &json!({"alg": "RS256"}), PAYLOAD)]),
        ),
        (
            PAYLOAD,
            json!([signature(
                &key(1),
                &json!({"alg": "EdDSA", "crit": ["b64"]}),
                PAYLOAD
            )]),
        ),
        (
            PAYLOAD,
            json!([signature(
                &key(1),
                &json!({"alg": "EdDSA", "crit": 3}),
                PAYLOAD
            )]),
        ),
        (
            PAYLOAD,
            json!([{"protected": URL_SAFE_NO_PAD.encode(eddsa.to_string()), "signature": "AAAA"}]),
        ),
        (PAYLOAD, json!({"not": "an array"})),
    ];
    let root = super::super::signed::root_key(&key_info(&key(1))).expect("the root");
    for (payload, sigs) in corpus {
        let today = super::super::signed::verify(payload, &sigs, &root)
            .err()
            .unwrap_or_else(|| (u64::from(SIGNED_VERIFIED), String::new()));
        let mut named = String::new();
        let now = book.verify(
            &who,
            "remote",
            payload,
            sigs.to_string().as_bytes(),
            &mut named,
        );
        assert_eq!((u64::from(now), named), today, "{sigs}");
    }
    let mut named = String::new();
    assert_eq!(
        book.verify(&who, "remote", PAYLOAD, b"", &mut named),
        SIGNED_NONE,
        "no signatures is today's null document"
    );
}
