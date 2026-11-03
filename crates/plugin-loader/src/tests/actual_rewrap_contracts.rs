// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Real SQLite CAS and the existing hostile answer-lease boundary controls.

use crate::actual_store;
use crate::dispatch::kinds::store::Store;
use crate::dispatch::{
    load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, Frame, LinkedRow, NoSink,
};
use crate::store_v3::LoadedStore;
use busbar_contract::abi::mechanism::call::{
    Blob, OutHead, Outcome, RawOutcome, BLOB_JSON, BLOB_SECRET,
};
use busbar_contract::abi::mechanism::door::{Door, DoorFn, DoorParts};
use busbar_contract::abi::mechanism::extensions;
use busbar_contract::abi::sdk::store::rewrap;
use busbar_contract::abi::store::{slot, BlobIn, Ops};
use busbar_contract::records::{
    CredentialMeta, CredentialSecret, RecordStore, SecretForm, VirtualKey,
};
use std::sync::{Arc, OnceLock};

fn open(door: DoorFn) -> LoadedStore {
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let plugin = load_linked::<Store>(
        &LinkedRow::of(door).expect("actual SQLite statement"),
        Bind {
            instance: "actual-rewrap-contract".into(),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: ConnTable::NoNeeds,
        },
    )
    .expect("actual SQLite descriptor loads");
    LoadedStore::open(
        plugin,
        dispatcher,
        &actual_store::settings(),
        actual_store::mint,
    )
    .expect("actual isolated SQLite database opens")
}

fn seed(store: &LoadedStore) -> CredentialSecret {
    store
        .put_key(&VirtualKey {
            id: "owner".into(),
            enabled: true,
            ..VirtualKey::default()
        })
        .unwrap();
    store
        .put_credential(&CredentialSecret {
            meta: CredentialMeta {
                id: "credential".into(),
                key_id: "owner".into(),
                kind: "sigv4".into(),
                slot: 0,
                public_id: "public".into(),
                secret_form: SecretForm::Recoverable,
                created_at: 1,
                updated_at: 1,
                expires_at: None,
                revoked_at: None,
                revoke_reason: None,
                revision: 0,
            },
            secret: "v1:plain:OLD_ENVELOPE_CANARY".into(),
        })
        .unwrap();
    store
        .list_credentials_since(0)
        .unwrap()
        .into_iter()
        .next()
        .expect("actual stored credential")
}

fn raw(
    store: &LoadedStore,
    request: &rewrap::Request,
    intent: Option<&[u8]>,
    secret: bool,
) -> Outcome {
    let bytes = serde_json::to_vec(request).unwrap();
    let ext = intent
        .map(|v| extensions::encode(&[(rewrap::INTENT, v)]))
        .unwrap_or_default();
    let mut head = crate::dispatch::in_head();
    head.extensions = Blob {
        ptr: ext.as_ptr(),
        len: ext.len(),
        fmt: busbar_contract::abi::mechanism::call::BLOB_OCTETS,
        flags: 0,
    };
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
        crate::dispatch::out_head(),
    );
    let called = store.plugin().call(slot::PUT_CREDENTIAL, &mut frame);
    crate::dispatch::lifecycle::release(store.plugin(), called.lease);
    called.outcome
}

#[test]
fn actual_sqlite_rewrap_requires_secret_intent_and_cas_without_ordinary_put() {
    let store = actual_store::open();
    assert!(store.facts().credential_rewrap);
    let expected = seed(&store);
    let replacement = "v1:aead:NEW_ENVELOPE_CANARY";
    let mut request = rewrap::Request::new(&expected, replacement);
    assert_eq!(raw(&store, &request, None, true), Outcome::Refused);
    assert_eq!(raw(&store, &request, Some(b"2"), true), Outcome::Refused);
    assert_eq!(raw(&store, &request, Some(b"1"), false), Outcome::Refused);
    request.version = 2;
    assert_eq!(raw(&store, &request, Some(b"1"), true), Outcome::Refused);
    assert_eq!(
        store.list_credentials_since(0).unwrap(),
        vec![expected.clone()],
        "invalid maintenance cannot mutate/mint"
    );
    assert!(store.rewrap_credential(&expected, replacement).unwrap());
    let current = store.list_credentials_since(0).unwrap().remove(0);
    assert_eq!(current.secret, replacement);
    assert!(current.meta.revision > expected.meta.revision);
    assert!(
        !store.rewrap_credential(&expected, replacement).unwrap(),
        "old expected row conflicts"
    );
    assert!(
        !store.rewrap_credential(&current, replacement).unwrap(),
        "identical replacement is not a second CAS"
    );
    let mut ordinary = current.clone();
    ordinary.secret = "v1:aead:ORDINARY_PUT_MUST_NOT_REWRAP".into();
    assert!(store.put_credential(&ordinary).is_err());
    assert_eq!(
        store.list_credentials_since(0).unwrap(),
        vec![current],
        "ordinary PUT cannot substitute for maintenance"
    );
}

busbar_contract::statement_extensions!(APPLIED: [(rewrap::RESULT, b"applied")]);
busbar_contract::statement_extensions!(INVALID: [(rewrap::RESULT, b"unknown-result")]);

extern "C" fn missing(
    instance: *mut std::ffi::c_void,
    input: *const std::ffi::c_void,
    out: *mut std::ffi::c_void,
) -> RawOutcome {
    corrupt(instance, input, out, false)
}
extern "C" fn invalid(
    instance: *mut std::ffi::c_void,
    input: *const std::ffi::c_void,
    out: *mut std::ffi::c_void,
) -> RawOutcome {
    corrupt(instance, input, out, true)
}
fn corrupt(
    instance: *mut std::ffi::c_void,
    input: *const std::ffi::c_void,
    out: *mut std::ffi::c_void,
    invalid: bool,
) -> RawOutcome {
    // SAFETY: this PUT_CREDENTIAL wrapper forwards the actual SDK instance and
    // exact live frames unchanged; only its returned result extension is hostile.
    unsafe {
        let ops = &*actual_store::door().ops().cast::<Ops>();
        let ran = ops.put_credential.expect("actual credential slot")(instance, input, out);
        if ran.outcome() == Outcome::Ready {
            (*out.cast::<OutHead>()).extensions = if invalid { INVALID } else { Blob::ABSENT };
        }
        ran
    }
}
extern "C" fn unleased(
    _: *mut std::ffi::c_void,
    _: *const std::ffi::c_void,
    out: *mut std::ffi::c_void,
) -> RawOutcome {
    let ran = RawOutcome::of(Outcome::Ready);
    let mut head = crate::dispatch::out_head();
    head.outcome = ran;
    head.extensions = APPLIED;
    // SAFETY: exact writable OutHead. The absent lease is deliberately malformed.
    unsafe {
        out.cast::<OutHead>().write_unaligned(head);
    }
    ran
}
fn restated(
    cell: &OnceLock<usize>,
    op: busbar_contract::abi::mechanism::call::Op,
) -> &'static Door {
    let address = *cell.get_or_init(|| {
        let actual = *actual_store::door();
        // SAFETY: actual_store retains the validated descriptor and its Store table.
        let mut ops = unsafe { actual.ops().cast::<Ops>().read_unaligned() };
        ops.put_credential = Some(op);
        let ops = Box::leak(Box::new(ops));
        // SAFETY: same immutable actual descriptor, only the existing hostile result slot differs.
        let door = unsafe {
            Door::__from_parts(DoorParts {
                ops: std::ptr::from_ref(ops).cast(),
                ..actual.parts()
            })
        };
        Box::into_raw(Box::new(door)) as usize
    });
    // SAFETY: immutable descriptor and copied table are retained permanently.
    unsafe { &*(address as *const Door) }
}
extern "C" fn missing_door() -> &'static Door {
    static D: OnceLock<usize> = OnceLock::new();
    restated(&D, missing)
}
extern "C" fn invalid_door() -> &'static Door {
    static D: OnceLock<usize> = OnceLock::new();
    restated(&D, invalid)
}
extern "C" fn unleased_door() -> &'static Door {
    static D: OnceLock<usize> = OnceLock::new();
    restated(&D, unleased)
}

#[test]
fn actual_sqlite_rewrap_never_accepts_an_unleased_or_unjudged_result() {
    for (door, diagnostic) in [
        (missing_door as DoorFn, "result is missing or invalid"),
        (invalid_door as DoorFn, "result is missing or invalid"),
        (unleased_door as DoorFn, "without a leased result"),
    ] {
        let store = open(door);
        // Seed through a genuine ordinary PUT before the hostile maintenance slot is used.
        // Missing/invalid wrappers forward it unchanged; the unleased witness cannot seed,
        // so use a real expected row from its own genuine database-independent owner below.
        let expected = if std::ptr::fn_addr_eq(door, unleased_door as DoorFn) {
            seed(&actual_store::open())
        } else {
            seed(&store)
        };
        let error = store
            .rewrap_credential(&expected, "v1:aead:NEW_ENVELOPE_CANARY")
            .unwrap_err();
        assert!(error.0.contains(diagnostic), "{}", error.0);
    }
}

extern "C" fn incapable_door() -> &'static Door {
    static D: OnceLock<usize> = OnceLock::new();
    let address = *D.get_or_init(|| {
        let actual = *actual_store::door();
        // SAFETY: actual_store retains the validated actual Statement and extension range.
        let mut statement = unsafe { actual.statement().read_unaligned() };
        let bytes = if statement.extensions.len == 0 {
            &[][..]
        } else {
            unsafe {
                std::slice::from_raw_parts(statement.extensions.ptr, statement.extensions.len)
            }
        };
        let entries = extensions::entries(bytes)
            .filter(|(key, _)| *key != rewrap::INTENT.as_bytes())
            .map(|(key, value)| {
                (
                    std::str::from_utf8(key).expect("extension keys are UTF-8"),
                    value,
                )
            })
            .collect::<Vec<_>>();
        let bytes = Box::leak(extensions::encode(&entries).into_boxed_slice());
        statement.extensions = Blob {
            ptr: bytes.as_ptr(),
            len: bytes.len(),
            fmt: busbar_contract::abi::mechanism::call::BLOB_OCTETS,
            flags: 0,
        };
        let statement = Box::leak(Box::new(statement));
        // SAFETY: retain the genuine immutable table and every descriptor field,
        // removing only its declared rewrap opt-in to test the host's capability gate.
        let door = unsafe {
            Door::__from_parts(DoorParts {
                statement,
                ..actual.parts()
            })
        };
        Box::into_raw(Box::new(door)) as usize
    });
    // SAFETY: permanent immutable restated descriptor and its Statement.
    unsafe { &*(address as *const Door) }
}

#[test]
fn a_store_without_rewrap_capability_never_crosses_for_maintenance() {
    let store = open(incapable_door);
    assert!(!store.facts().credential_rewrap);
    let expected = seed(&store);
    let before = store
        .plugin()
        .inner
        .crossings
        .load(std::sync::atomic::Ordering::SeqCst);
    let error = store
        .rewrap_credential(&expected, "v1:aead:NEW_ENVELOPE_CANARY")
        .unwrap_err();
    assert!(error.0.contains("does not state credential rewrap"));
    assert_eq!(
        store
            .plugin()
            .inner
            .crossings
            .load(std::sync::atomic::Ordering::SeqCst),
        before,
        "unsupported capability never crosses"
    );
}
