// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use super::{ChargedRequestSnapshot, SnapshotError, SnapshotInput};
use crate::limits::process_admission::{AdmissionClass, ProcessAdmission};
use crate::resource_admission::FrozenRequest;
use crate::state::InvocationId;

fn input<'a>(
    headers: &'a [(&'a str, &'a [u8])],
) -> SnapshotInput<'a, impl Clone + ExactSizeIterator<Item = (&'a str, &'a [u8])>> {
    SnapshotInput {
        method: "POST",
        path: "/original",
        query: "",
        query_present: true,
        authority: "native.example",
        headers: headers.iter().copied(),
        peer: "192.0.2.1:123",
        tls_peer_cert: b"certificate",
        body: b"body",
        now_s: 10,
    }
}

#[test]
fn native_snapshot_preserves_all_original_fields_and_duplicate_header_order() {
    let budget = ProcessAdmission::with_limits(2, 4096, 0);
    let request = budget.try_enter(AdmissionClass::Data).unwrap();
    let headers = [
        ("x-token", b"first".as_slice()),
        ("x-token", b"second".as_slice()),
    ];
    let snapshot = ChargedRequestSnapshot::capture(input(&headers), &request).unwrap();
    snapshot
        .with_auth_input(|view| {
            assert_eq!(
                (view.method, view.path, view.query, view.authority),
                ("POST", "/original", "", "native.example")
            );
            assert_eq!(
                (view.peer, view.tls_peer_cert, view.body, view.now_s),
                (
                    "192.0.2.1:123",
                    b"certificate".as_slice(),
                    b"body".as_slice(),
                    10
                )
            );
            assert_eq!(
                view.headers
                    .iter()
                    .map(|p| (p.name.get(), p.value.get()))
                    .collect::<Vec<_>>(),
                headers
            );
        })
        .unwrap();
    assert!(snapshot.query_present());
    assert_eq!(snapshot.target(), "/original?");
    assert!(snapshot.request().same_request(&request));
    let retained = Arc::clone(&snapshot);
    let charged = budget.used();
    drop(snapshot);
    drop(request);
    assert_eq!(budget.used(), charged);
    assert!(budget.try_enter(AdmissionClass::Data).is_err());
    drop(retained);
    assert_eq!(budget.used(), (0, 0));
    assert!(budget.try_enter(AdmissionClass::Data).is_ok());
}

#[test]
fn independent_captures_pay_independently_and_empty_input_keeps_count() {
    let budget = ProcessAdmission::with_limits(2, 4096, 0);
    let request = budget.try_enter(AdmissionClass::Data).unwrap();
    let first = ChargedRequestSnapshot::capture(input(&[]), &request).unwrap();
    let used = budget.used().0;
    let second = ChargedRequestSnapshot::capture(input(&[]), &request).unwrap();
    assert_eq!(budget.used(), (used * 2, used * 2));
    assert!(!Arc::ptr_eq(&first, &second));
    drop((first, second));
    let empty = ChargedRequestSnapshot::capture(
        SnapshotInput {
            method: "",
            path: "",
            query: "",
            query_present: false,
            authority: "",
            headers: std::iter::empty(),
            peer: "",
            tls_peer_cert: &[],
            body: &[],
            now_s: 0,
        },
        &request,
    )
    .unwrap();
    drop(request);
    assert_eq!(budget.used(), (0, 0));
    assert!(budget.try_enter(AdmissionClass::Data).is_err());
    drop(empty);
    assert!(budget.try_enter(AdmissionClass::Data).is_ok());
}

#[test]
fn every_live_pair_view_has_its_own_credit_and_refusal_does_not_enter_callback() {
    let headers = [("h", b"v".as_slice())];
    let measuring = ProcessAdmission::with_limits(2, 4096, 0);
    let request = measuring.try_enter(AdmissionClass::Data).unwrap();
    let measured = ChargedRequestSnapshot::capture(input(&headers), &request).unwrap();
    let size = measuring.used().0;
    drop((measured, request));
    let pair_size = std::mem::size_of::<busbar_plugin_abi::types::Pair<'_>>();
    let budget = ProcessAdmission::with_limits(2, u32::try_from(size + pair_size).unwrap(), 0);
    let request = budget.try_enter(AdmissionClass::Data).unwrap();
    let snapshot = ChargedRequestSnapshot::capture(input(&headers), &request).unwrap();
    snapshot
        .with_auth_input(|_| {
            assert_eq!(budget.used().0, size + pair_size);
            let mut called = false;
            assert!(matches!(
                snapshot.with_auth_input(|_| called = true),
                Err(SnapshotError::Capacity(_))
            ));
            assert!(!called);
        })
        .unwrap();
    assert_eq!(budget.used().0, size);
    snapshot.with_auth_input(|_| ()).unwrap();
    drop(snapshot);
    assert_eq!(budget.used(), (0, 0));
}

#[test]
fn exact_capture_limit_and_invalid_query_reclaim_every_reservation() {
    let measuring = ProcessAdmission::with_limits(2, 4096, 0);
    let request = measuring.try_enter(AdmissionClass::Data).unwrap();
    let snapshot = ChargedRequestSnapshot::capture(input(&[]), &request).unwrap();
    let size = u32::try_from(measuring.used().0).unwrap();
    drop((snapshot, request));
    for (cap, allowed) in [(size, true), (size - 1, false)] {
        let budget = ProcessAdmission::with_limits(2, cap, 0);
        let request = budget.try_enter(AdmissionClass::Data).unwrap();
        let captured = ChargedRequestSnapshot::capture(input(&[]), &request);
        assert_eq!(captured.is_ok(), allowed);
        drop(captured);
        assert_eq!(budget.used(), (0, 0));
        let mut bad = input(&[]);
        bad.query_present = false;
        bad.query = "unexpected";
        assert!(matches!(
            ChargedRequestSnapshot::capture(bad, &request),
            Err(SnapshotError::Invalid)
        ));
        assert_eq!(budget.used(), (0, 0));
    }
}

#[test]
fn frozen_selection_shares_native_backing_and_rejects_equal_legacy_or_foreign_snapshots() {
    let budget = ProcessAdmission::with_limits(2, 4096, 0);
    let request = budget.try_enter(AdmissionClass::Data).unwrap();
    let snapshot = ChargedRequestSnapshot::capture(input(&[]), &request).unwrap();
    let used = budget.used();
    let invocation = InvocationId::from_request_id(std::num::NonZeroU64::new(1).unwrap());
    let frozen = FrozenRequest::from_snapshot(invocation, 3, Arc::clone(&snapshot));
    assert_eq!(budget.used(), used);
    assert!(frozen.matches_snapshot(&snapshot));
    frozen
        .with_selection_input(|view, body| {
            assert_eq!(
                (view.route, view.auth, view.method, view.path, view.query),
                (3, 0, "POST", "/original", "")
            );
            assert!(view.identity.is_empty());
            assert_eq!(body, b"body");
        })
        .unwrap();
    let foreign = ChargedRequestSnapshot::capture(input(&[]), &request).unwrap();
    assert!(!frozen.matches_snapshot(&foreign));
    let legacy = FrozenRequest::new(
        invocation,
        3,
        "POST".into(),
        "/original".into(),
        "".into(),
        Vec::new(),
        b"body".to_vec(),
    );
    assert!(!legacy.matches_snapshot(&snapshot));
    drop((foreign, legacy, request, snapshot));
    assert_eq!(budget.used(), used);
    assert!(budget.try_enter(AdmissionClass::Data).is_err());
    drop(frozen);
    assert_eq!(budget.used(), (0, 0));
    assert!(budget.try_enter(AdmissionClass::Data).is_ok());
}

struct ChangingHeaders {
    long: bool,
    yielded: bool,
}
impl Clone for ChangingHeaders {
    fn clone(&self) -> Self {
        Self {
            long: false,
            yielded: false,
        }
    }
}
impl Iterator for ChangingHeaders {
    type Item = (&'static str, &'static [u8]);
    fn next(&mut self) -> Option<Self::Item> {
        if self.yielded {
            return None;
        }
        self.yielded = true;
        Some(("h", if self.long { b"long" } else { b"v" }))
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let left = usize::from(!self.yielded);
        (left, Some(left))
    }
}
impl ExactSizeIterator for ChangingHeaders {}

#[test]
fn inconsistent_header_iterator_cannot_trigger_unreserved_growth() {
    let budget = ProcessAdmission::with_limits(2, 4096, 0);
    let request = budget.try_enter(AdmissionClass::Data).unwrap();
    let source = SnapshotInput {
        method: "GET",
        path: "/",
        query: "",
        query_present: false,
        authority: "h",
        headers: ChangingHeaders {
            long: true,
            yielded: false,
        },
        peer: "",
        tls_peer_cert: &[],
        body: &[],
        now_s: 0,
    };
    assert!(matches!(
        ChargedRequestSnapshot::capture(source, &request),
        Err(SnapshotError::Invalid)
    ));
    assert_eq!(budget.used(), (0, 0));
}

#[derive(Clone)]
struct HugeHeaders;
impl Iterator for HugeHeaders {
    type Item = (&'static str, &'static [u8]);
    fn next(&mut self) -> Option<Self::Item> {
        panic!("overflow must refuse before reading headers")
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (usize::MAX, Some(usize::MAX))
    }
}
impl ExactSizeIterator for HugeHeaders {}

#[test]
fn header_extent_overflow_is_rejected_before_copy_or_iteration() {
    let budget = ProcessAdmission::with_limits(2, 4096, 0);
    let request = budget.try_enter(AdmissionClass::Data).unwrap();
    assert!(matches!(
        ChargedRequestSnapshot::capture(
            SnapshotInput {
                method: "",
                path: "",
                query: "",
                query_present: false,
                authority: "",
                headers: HugeHeaders,
                peer: "",
                tls_peer_cert: &[],
                body: &[],
                now_s: 0,
            },
            &request
        ),
        Err(SnapshotError::Overflow)
    ));
    assert_eq!(budget.used(), (0, 0));
}

#[test]
fn retained_body_bytes_keep_the_complete_snapshot_charge_and_original_admission() {
    let budget = ProcessAdmission::with_limits(2, 4096, 0);
    let request = budget.try_enter(AdmissionClass::Data).unwrap();
    let snapshot = ChargedRequestSnapshot::capture(input(&[]), &request).unwrap();
    let charged = budget.used();
    let body = snapshot.body_bytes();
    let tail = body.slice(1..);
    drop((body, snapshot, request));
    assert_eq!(tail.as_ref(), b"ody");
    assert_eq!(budget.used(), charged);
    assert!(budget.try_enter(AdmissionClass::Data).is_err());
    drop(tail);
    assert_eq!(budget.used(), (0, 0));
    assert!(budget.try_enter(AdmissionClass::Data).is_ok());
}

#[test]
fn http_header_map_capture_preserves_every_duplicate_without_a_preliminary_array() {
    let budget = ProcessAdmission::with_limits(2, 4096, 0);
    let request = budget.try_enter(AdmissionClass::Operator).unwrap();
    let mut headers = http::HeaderMap::new();
    headers.append("authorization", http::HeaderValue::from_static("first"));
    headers.append("authorization", http::HeaderValue::from_static("second"));
    headers.append("x-other", http::HeaderValue::from_static("value"));
    let snapshot = ChargedRequestSnapshot::capture_header_map(SnapshotInput {
        method: "POST", path: "/admin", query: "", query_present: false,
        authority: "admin.example", headers: &headers, peer: "peer",
        tls_peer_cert: b"cert", body: b"input", now_s: 10,
    }, &request).unwrap();
    let expected = headers.iter().map(|(name, value)| (name.as_str(), value.as_bytes())).collect::<Vec<_>>();
    assert_eq!(snapshot.headers().collect::<Vec<_>>(), expected);
    assert_eq!(snapshot.headers().count(), 3);
    snapshot.with_auth_input(|view| {
        assert_eq!(view.headers.iter().map(|pair| (pair.name.get(), pair.value.get())).collect::<Vec<_>>(), expected);
    }).unwrap();
    drop((snapshot, request));
    assert_eq!(budget.used(), (0, 0));
}
