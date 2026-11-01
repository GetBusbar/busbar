// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::wrap::{Hooks, Wrapped};
use super::*;
use busbar_contract::abi::mechanism::extensions;
use busbar_contract::abi::sdk::store::{rewrap, Op, Step};
use busbar_contract::records::{CredentialMeta, SecretForm};
use std::sync::atomic::{AtomicUsize, Ordering};

static CAS: AtomicUsize = AtomicUsize::new(0);
static PUT: AtomicUsize = AtomicUsize::new(0);
#[path = "store_v3_rewrap_result_tests.rs"]
mod broken_result;
struct Maintenance;
impl Hooks for Maintenance {
    fn put_credential(
        _: &crate::both_ways::store_fixture::MemoryStore,
        _: &mut Op<'_>,
        _: &CredentialSecret,
    ) -> Step<RecordStoreResult<()>> {
        PUT.fetch_add(1, Ordering::SeqCst);
        Step::Ready(Err(RecordStoreError("ordinary live PUT refused".into())))
    }
    fn rewrap_credential(
        _: &crate::both_ways::store_fixture::MemoryStore,
        cx: &mut Op<'_>,
        expected: &CredentialSecret,
        replacement: &str,
    ) -> Step<RecordStoreResult<bool>> {
        CAS.fetch_add(1, Ordering::SeqCst);
        assert_eq!(expected.secret, "v1:plain:OLD_ENVELOPE_CANARY");
        assert_eq!(replacement, "v1:aead:NEW_ENVELOPE_CANARY");
        if expected.meta.id == "pending" {
            if let Some(kept) = cx.resume::<rewrap::Request>() {
                assert_eq!(&kept.expected, expected);
                assert_eq!(kept.replacement, replacement);
            } else {
                assert!(
                    cx.can_pend(),
                    "the loaded store must own a resumable ticket"
                );
                cx.park(rewrap::Request::new(expected, replacement));
                return Step::Pending {
                    wake_at_ns: now_ns().saturating_add(1_000_000),
                };
            }
        }
        Step::Ready(Ok(expected.meta.id != "conflict"))
    }
}

mod capable {
    busbar_contract::statement_extensions!(EXTENSIONS: [
        (busbar_contract::abi::sdk::store::rewrap::INTENT, b"1")
    ]);
    busbar_contract::store_door!(super::Wrapped<super::Maintenance>, "rewrap-capable", "0", 64, extensions: EXTENSIONS);
}
mod incapable {
    busbar_contract::store_door!(
        super::Wrapped<super::Maintenance>,
        "rewrap-incapable",
        "0",
        64
    );
}

fn row(id: &str) -> CredentialSecret {
    CredentialSecret {
        meta: CredentialMeta {
            id: id.into(),
            key_id: "owner".into(),
            kind: "signing".into(),
            slot: 0,
            public_id: "public".into(),
            secret_form: SecretForm::Recoverable,
            created_at: 1,
            updated_at: 1,
            expires_at: None,
            revoked_at: None,
            revoke_reason: None,
            revision: 8,
        },
        secret: "v1:plain:OLD_ENVELOPE_CANARY".into(),
    }
}

fn raw(
    store: &LoadedStore,
    request: &rewrap::Request,
    intent: Option<&[u8]>,
    secret: bool,
) -> Outcome {
    let bytes = to_json(request);
    let ext = intent
        .map(|v| extensions::encode(&[(rewrap::INTENT, v)]))
        .unwrap_or_default();
    let mut head = in_head();
    head.extensions = octets(&ext);
    let mut frame = Frame::new(
        BlobIn {
            head,
            record: Blob {
                ptr: bytes.as_ptr(),
                len: bytes.len(),
                fmt: BLOB_JSON,
                flags: if secret { BLOB_SECRET } else { 0 },
            },
        },
        out_head(),
    );
    let called = store.plugin.call(slot::PUT_CREDENTIAL, &mut frame);
    store.release(called.lease);
    called.outcome
}

#[test]
fn maintenance_requires_capability_intent_and_explicit_result_and_survives_pending() {
    let replacement = "v1:aead:NEW_ENVELOPE_CANARY";
    let old = super::pend_tests::open(incapable::door);
    let error = old
        .rewrap_credential(&row("applied"), replacement)
        .unwrap_err();
    assert!(error.0.contains("does not state credential rewrap"));
    assert_eq!(
        CAS.load(Ordering::SeqCst),
        0,
        "unsupported capability never crosses"
    );
    let store = super::pend_tests::open(capable::door);
    assert!(store.facts().credential_rewrap);
    let mut request = rewrap::Request::new(&row("applied"), replacement);
    assert_eq!(raw(&store, &request, None, true), Outcome::Refused);
    assert_eq!(raw(&store, &request, Some(b"2"), true), Outcome::Refused);
    assert_eq!(raw(&store, &request, Some(b"1"), false), Outcome::Refused);
    request.version = 2;
    assert_eq!(raw(&store, &request, Some(b"1"), true), Outcome::Refused);
    assert_eq!(
        CAS.load(Ordering::SeqCst),
        0,
        "malformed intent never reaches the backend"
    );
    assert_eq!(
        PUT.load(Ordering::SeqCst),
        0,
        "maintenance cannot turn into a mint"
    );
    assert!(store
        .rewrap_credential(&row("applied"), replacement)
        .unwrap());
    assert!(!store
        .rewrap_credential(&row("conflict"), replacement)
        .unwrap());
    assert!(store
        .rewrap_credential(&row("pending"), replacement)
        .unwrap());
    assert_eq!(
        CAS.load(Ordering::SeqCst),
        4,
        "one resume, never a restarted write"
    );
    assert_eq!(PUT.load(Ordering::SeqCst), 0);
    assert!(store.put_credential(&row("ordinary")).is_err());
    assert_eq!(
        PUT.load(Ordering::SeqCst),
        1,
        "ordinary PUT remains its own operation"
    );
    for (door, expected_error) in broken_result::CASES {
        let store = super::pend_tests::open(door);
        let error = store
            .rewrap_credential(&row("applied"), replacement)
            .unwrap_err();
        assert!(error.0.contains(expected_error), "{}", error.0);
    }
}
