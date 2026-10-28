// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The root's credential source: the read follows the App swap at once, and the kernel's
//! `records.secret` serves it.

use std::sync::Arc;

use busbar_contract::abi::host::service::{SECRET_LIVE, SECRET_NOT_LIVE};
use busbar_contract::services::{CredentialRead, HostServices, Ran, Stored};
use busbar_kernel::governance::{GovState, MemoryStore, NewKeySpec};
use busbar_kernel::host_services::{KernelServices, NOT_READABLE, NO_CREDENTIAL_SOURCE};
use busbar_kernel::test_support::TestApp;

use super::AppCredentials;

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
        (s.expose(&busbar_kernel::seal::lend()).as_str(), live),
        (old_secret.as_str(), true)
    );
    handle.swap(TestApp::new().governance(second).build());
    let (s, live) = creds.read(&kind, &new_id);
    assert_eq!(
        (s.expose(&busbar_kernel::seal::lend()).as_str(), live),
        (new_secret.as_str(), true)
    );
    let (s, live) = creds.read(&kind, &old_id);
    assert_eq!(
        (s.expose(&busbar_kernel::seal::lend()).as_str(), live),
        (busbar_kernel::auth::DUMMY_SECRET, false),
        "a removed id is no longer live"
    );
}

/// A source answering `kind:id`, live for an id starting `live`.
struct Source;
impl CredentialRead for Source {
    fn read(&self, kind: &str, id: &str) -> (busbar_contract::redacted::Secret<String>, bool) {
        let secret = busbar_contract::redacted::Secret::new(format!("{kind}:{id}"));
        (secret, id.starts_with("live"))
    }
}

/// A `records.secret` answered at once.
fn now(ran: Ran) -> Stored {
    match ran {
        Ran::Now(stored) => stored,
        Ran::Later => panic!("answered at once"),
    }
}

/// THE READ: `records.secret` is the source's secret in span `0` and its liveness as the value.
/// RED: services given no source refuse the read.
#[test]
fn the_kernel_serves_the_read_from_its_source() {
    let s = KernelServices::new().with_credentials(Arc::new(Source));
    for (id, value) in [("live-1", SECRET_LIVE), ("gone", SECRET_NOT_LIVE)] {
        let read = now(s.records_secret("a-kind", id, Box::new(|_| {})));
        let span = read.spans[0];
        let bytes = &read.bytes[span.value.offset as usize..][..span.value.len as usize];
        assert_eq!(
            (bytes, read.value),
            (format!("a-kind:{id}").as_bytes(), value)
        );
    }
    assert_eq!(
        now(KernelServices::new().records_secret("a-kind", "live-1", Box::new(|_| {}))),
        Stored::refused(NO_CREDENTIAL_SOURCE)
    );
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
    let s = KernelServices::new().with_credentials(Arc::new(credentials));
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
