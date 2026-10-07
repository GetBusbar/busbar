// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The root's `records.secret` composition: the read follows the App swap at once, and the services
//! delegate every other service to the kernel's untouched.

use std::sync::Arc;

use busbar_contract::abi::host::service::{SECRET_LIVE, SECRET_NOT_LIVE};
use busbar_contract::services::{
    Caller, CredentialRead, DiskDest, HostServices, Later, NestAsk, Ran, Reading, RecordsList,
    Stored,
};
use busbar_kernel::governance::{GovState, MemoryStore, NewKeySpec};
use busbar_kernel::test_support::TestApp;

use super::{AppCredentials, CredentialServices, RootCredentials, NOT_READABLE};

/// The persisted credential kind of a row-looked-up signed-ingress credential: frozen stored data,
/// read off the kernel's frozen-text fixture rather than spelled here.
fn signed_kind() -> String {
    const FROZEN: &str =
        include_str!("../../../../busbar-kernel/tests/fixtures/frozen_customer_text.yaml");
    FROZEN
        .lines()
        .find_map(|l| l.strip_prefix("signed_credential_kind:"))
        .map(|v| v.trim().to_string())
        .expect("the frozen fixture names the signed credential kind")
}

/// A governance holding one signed-ingress credential: the governance, its id and its secret.
fn gov_with_key(name: &str) -> (Arc<GovState>, String, String) {
    let gov = Arc::new(GovState::new(Arc::new(MemoryStore::new()), None).unwrap());
    let spec = NewKeySpec {
        name: name.to_string(),
        ..Default::default()
    };
    let (_key, _bearer, id, secret) = gov
        .create_key_with_aws(spec, busbar_kernel::store::now())
        .unwrap();
    (gov, id, secret)
}

/// THE READ FOLLOWS THE SWAP (ARCHITECT 2026-10-01): a read through the App's own swap handle sees
/// the CURRENT snapshot. After a swap to an App whose governance holds another credential, the new
/// id reads its secret, live, and the removed id reads the dummy, not live. RED: a source that
/// captured the boot GovState keeps answering the removed id live.
#[test]
fn the_credential_read_follows_the_app_swap() {
    let (first, old_id, old_secret) = gov_with_key("first");
    let (second, new_id, new_secret) = gov_with_key("second");
    let kind = signed_kind();
    let handle = Arc::new(busbar_kernel::state::AppHandle::new(
        TestApp::new().governance(first).build(),
    ));
    let creds = AppCredentials::new(Arc::clone(&handle));
    let (s, live) = creds.read(&kind, &old_id);
    assert_eq!(
        (s.expose_secret().as_str(), live),
        (old_secret.as_str(), true)
    );
    handle.swap(TestApp::new().governance(second).build());
    let (s, live) = creds.read(&kind, &new_id);
    assert_eq!(
        (s.expose_secret().as_str(), live),
        (new_secret.as_str(), true)
    );
    let (s, live) = creds.read(&kind, &old_id);
    assert_eq!(
        (s.expose_secret().as_str(), live),
        (busbar_kernel::auth::DUMMY_SECRET, false),
        "a removed id is no longer live"
    );
}

/// The kernel's services, as a double: each service answers its own number.
struct Inner;
impl HostServices for Inner {
    fn now(&self) -> Reading {
        Reading {
            wall_ns: 11,
            mono_ns: 22,
        }
    }
    fn dest_judge(&self, _: &str, _: u32, _: u32, _: Option<Later>) -> Ran {
        Ran::Now(Stored::ready(1))
    }
    fn records_get(&self, _: &Caller, _: &str, _: &[u8], _: Later) -> Ran {
        Ran::Now(Stored::ready(2))
    }
    fn records_list(&self, _: &Caller, _: RecordsList, _: Later) -> Ran {
        Ran::Now(Stored::ready(3))
    }
    fn records_claim(&self, _: &Caller, _: &str, _: &[u8], _: u64, _: Later) -> Ran {
        Ran::Now(Stored::ready(4))
    }
    fn sign(&self, _: &Caller, _: &[u8]) -> Stored {
        Stored::ready(5)
    }
    fn trust_sight(&self, _: &Caller, _: &str, _: &str, _: Later) -> Ran {
        Ran::Now(Stored::ready(6))
    }
    fn trust_due(&self, _: &Caller) -> Stored {
        Stored::ready(7)
    }
    fn entitlement_check(&self, _: &Caller, _: Option<u64>, _: &str) -> Stored {
        Stored::ready(8)
    }
    fn random_fill(&self, _: u64) -> Stored {
        Stored::ready(9)
    }
    fn trust_verify(&self, _: &Caller, _: &str, _: &[u8], _: &[u8]) -> Stored {
        Stored::ready(10)
    }
    fn records_secret(&self, _: &str, _: &str, _: Later) -> Ran {
        panic!("the credential read is the source's, never the inner services'")
    }
    fn unit_nest(&self, _: &Caller, _: Option<u64>, _: NestAsk, _: Later) -> Ran {
        Ran::Now(Stored::ready(12))
    }
    fn work_open(&self, _: &Caller, _: Option<u64>, _: &str, _: &[u8], _: Later) -> Ran {
        Ran::Now(Stored::ready(13))
    }
    fn work_find(&self, _: &Caller, _: Option<u64>, _: &[u8], _: Later) -> Ran {
        Ran::Now(Stored::ready(14))
    }
    fn work_settle(&self, _: &Caller, _: u64, _: &[u8], _: Later) -> Ran {
        Ran::Now(Stored::ready(15))
    }
    fn work_resume(&self, _: &Caller, _: Option<u64>, _: u64, _: Later) -> Ran {
        Ran::Now(Stored::ready(16))
    }

    fn disk_append(&self, _: &DiskDest, _: Vec<u8>, _: Later) -> Ran {
        Ran::Now(Stored::ready(12))
    }

    fn snapshot_read(&self, _: &Caller, _: u32) -> busbar_contract::services::Snapshot {
        busbar_contract::services::Snapshot::NotReady
    }
}

/// A source answering `kind:id`, live for an id starting `live`.
struct Source;
impl RootCredentials for Source {}
impl CredentialRead for Source {
    fn read(&self, kind: &str, id: &str) -> (busbar_contract::redacted::Redacted<String>, bool) {
        let secret = busbar_contract::redacted::Redacted::new(format!("{kind}:{id}"));
        (secret, id.starts_with("live"))
    }
}

/// THE DELEGATION: every other service is the inner services' answer; `records.secret` is the
/// source's secret in span `0` and its liveness as the value. RED: a service the composition does
/// not forward answers something other than the inner number.
#[test]
fn the_services_delegate_and_serve_the_read() {
    let s = CredentialServices::new(Arc::new(Inner), Arc::new(Source));
    assert_eq!(s.now().mono_ns, 22);
    let caller = Caller {
        instance: Arc::from("the-instance"),
        plugin: Arc::from("the-plugin"),
        kind: busbar_contract::abi::mechanism::KindCode::Auth,
    };
    let now = |ran| match ran {
        Ran::Now(stored) => stored,
        Ran::Later => panic!("answered at once"),
    };
    let list = RecordsList {
        kind: "k".to_string(),
        prefix: Vec::new(),
        after: None,
        limit: 0,
    };
    let values: Vec<u64> = [
        now(s.dest_judge("x", 0, 0, None)),
        now(s.records_get(&caller, "k", b"key", Box::new(|_| {}))),
        now(s.records_list(&caller, list, Box::new(|_| {}))),
        now(s.records_claim(&caller, "k", b"key", 1, Box::new(|_| {}))),
        s.sign(&caller, b"data"),
        now(s.trust_sight(&caller, "peer", "hash", Box::new(|_| {}))),
        s.trust_due(&caller),
        s.entitlement_check(&caller, None, "model:m"),
        s.random_fill(16),
        s.trust_verify(&caller, "peer", b"payload", b"[]"),
    ]
    .iter()
    .map(|s| s.value)
    .collect();
    assert_eq!(values, (1..=10).collect::<Vec<u64>>());
    for (id, value) in [("live-1", SECRET_LIVE), ("gone", SECRET_NOT_LIVE)] {
        let read = now(s.records_secret("a-kind", id, Box::new(|_| {})));
        let span = read.spans[0];
        let bytes = &read.bytes[span.value.offset as usize..][..span.value.len as usize];
        assert_eq!(
            (bytes, read.value),
            (format!("a-kind:{id}").as_bytes(), value)
        );
    }
}

/// THE LATE HANDLE: the serve path composes the services before the App exists, so a late source
/// answers `records.secret` REFUSED until its handle is set, and the credential's secret, live,
/// after. RED: a source read before the App exists would answer the dummy as an ordinary not-live
/// credential, indistinguishable from a revoked one.
#[test]
fn a_late_source_refuses_until_its_handle_is_set() {
    let (gov, id, secret) = gov_with_key("late");
    let kind = signed_kind();
    let (credentials, late) = AppCredentials::late();
    let s = CredentialServices::new(Arc::new(Inner), Arc::new(credentials));
    let Ran::Now(before) = s.records_secret(&kind, &id, Box::new(|_| {})) else {
        panic!("answered at once");
    };
    assert_eq!(before, Stored::refused(NOT_READABLE), "not installed yet");
    assert!(!late.is_set());
    late.set(Arc::new(busbar_kernel::state::AppHandle::new(
        TestApp::new().governance(gov).build(),
    )));
    assert!(late.is_set());
    let Ran::Now(after) = s.records_secret(&kind, &id, Box::new(|_| {})) else {
        panic!("answered at once");
    };
    let span = after.spans[0];
    let bytes = &after.bytes[span.value.offset as usize..][..span.value.len as usize];
    assert_eq!((bytes, after.value), (secret.as_bytes(), SECRET_LIVE));
}
