// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::abi::export::{ServeOut, StatusOut};
use crate::abi::mechanism::call::{BLOB_JSON, BLOB_SECRET};
use crate::abi::mechanism::lifecycle::{CancelOut, TickOut};
use crate::abi::plane::{PlaneOpenOut, PlaneSnapshot};
use crate::abi::sdk::publish::{ClaimSpec, SnapshotSpec};

fn zeroed<T>() -> T {
    // SAFETY: every `out` here is plain data; all-zero is valid.
    unsafe { std::mem::zeroed() }
}

fn read(s: AbiStr) -> Vec<u8> {
    // SAFETY: the test reads what the writer named, while its owner lives.
    unsafe { std::slice::from_raw_parts(s.ptr, s.len) }.to_vec()
}

#[test]
fn a_scalar_is_set_in_place_however_nested() {
    let mut o: TickOut = zeroed();
    let mut out = Out::new(&mut o);
    out.set(|o| &o.next_tick_ns, 42);
    out.set(|o| &o.head.wake_at_ns, 7);
    assert_eq!((o.next_tick_ns, o.head.wake_at_ns), (42, 7));
}

#[test]
#[should_panic(expected = "not a field of the out")]
fn a_pick_outside_the_out_is_refused() {
    static ELSEWHERE: u64 = 0;
    let mut o: CancelOut = zeroed();
    Out::new(&mut o).set(|_| &ELSEWHERE, 1);
}

#[test]
fn a_leased_blob_is_held_until_release_and_named_in_the_head() {
    let leases = Leases::default();
    let mut o: StatusOut = zeroed();
    let mut out = Out::new(&mut o);
    out.lease(|o| &o.status, &leases, br#"{"a":1}"#.to_vec(), BLOB_JSON);
    assert_eq!(o.head.lease, 1);
    assert_eq!(o.status.fmt, BLOB_JSON);
    assert_eq!(
        read(AbiStr {
            ptr: o.status.ptr,
            len: o.status.len
        }),
        br#"{"a":1}"#
    );
    let mut o2: StatusOut = zeroed();
    Out::new(&mut o2).lease_secret(|o| &o.status, &leases, b"k".to_vec(), 3);
    assert_eq!((o2.head.lease, o2.status.flags), (2, BLOB_SECRET));
    assert_eq!(leases.held(), 2);
    assert_eq!(leases.release(1), Outcome::Ready);
    assert_eq!(leases.release(1), Outcome::Refused);
}

/// RED: a leased string is named where its lease holds it, and the lease's release drops it
/// (a released string's pointer names nothing: the lease is gone).
#[test]
fn a_leased_string_is_held_until_release_and_named_in_the_head() {
    let leases = Leases::default();
    let mut o: ServeOut = zeroed();
    let mut out = Out::new(&mut o);
    out.lease_str(|o| &o.head.error, &leases, "why, at length".to_string());
    assert_eq!(o.head.lease, 1);
    assert_eq!(read(o.head.error), b"why, at length");
    assert_eq!(leases.held(), 1);
    assert_eq!(leases.release(1), Outcome::Ready);
    assert_eq!(leases.held(), 0, "the release drops the string");
    assert_eq!(leases.release(1), Outcome::Refused);
    let mut e: ServeOut = zeroed();
    let mut out = Out::new(&mut e);
    out.lease_str(|o| &o.head.error, &leases, String::new());
    assert_eq!((e.head.lease, e.head.error.len, leases.held()), (0, 0, 0), "empty: no lease");
}

#[test]
fn static_text_and_lists_are_named_where_they_live() {
    const HEADERS: &[AbiStr] = &[AbiStr {
        ptr: b"h".as_ptr(),
        len: 1,
    }];
    let mut o: ServeOut = zeroed();
    let mut out = Out::new(&mut o);
    out.list(|o| &o.headers_out, |o| &o.headers_out_len, HEADERS);
    out.text(|o| &o.head.error, "why");
    // SAFETY: a `'static` list of one.
    assert_eq!(read(unsafe { *o.headers_out }), b"h");
    assert_eq!(o.headers_out_len, 1);
    assert_eq!(read(o.head.error), b"why");
    let mut e: ServeOut = zeroed();
    Out::new(&mut e).list::<AbiStr>(|o| &o.headers_out, |o| &o.headers_out_len, &[]);
    assert!(e.headers_out.is_null());
}

#[test]
fn a_published_value_is_the_sdks_until_its_retire() {
    let gens: Generations<PlaneSnapshot> = Generations::new();
    let mut o: PlaneOpenOut = zeroed();
    let target = String::from("/x");
    let spec = SnapshotSpec {
        claims: vec![ClaimSpec::new("GET", &target, "c", 0)],
        ..SnapshotSpec::default()
    };
    Out::new(&mut o).publish(|o| &o.snapshot, &gens, 4, &spec);
    drop((spec, target));
    // SAFETY: held until `retire(4)`.
    let snap = unsafe { &*o.snapshot };
    assert_eq!(snap.generation, 4);
    // SAFETY: as above.
    assert_eq!(read(unsafe { (*snap.claims).target }), b"/x");
    gens.retire(4);
    assert_eq!(gens.live(), 0);
}

#[test]
fn a_failure_names_its_text_in_the_head() {
    let mut o: CancelOut = zeroed();
    let answered = Out::new(&mut o).fail(Refusal::failed(String::from("no")));
    assert_eq!(answered, Outcome::Failed);
    assert_eq!(read(o.head.error), b"no");
}

#[test]
fn a_body_reports_metrics_and_declared_diagnostics_in_its_envelope() {
    use crate::abi::mechanism::call::{METRIC_ADD, METRIC_SET};
    super::begin_call();
    let mut o: CancelOut = zeroed();
    let mut out = Out::new(&mut o);
    assert!(out.metric(2, METRIC_ADD, 1.0));
    assert!(out.metric(5, METRIC_SET, 7.5));
    assert!(out.diag(1, 2, String::from("BUSBAR-7070 the webhook refused")));
    let env = o.head.envelope;
    assert_eq!((env.metrics_len, env.diags_len), (2, 1));
    // SAFETY: this thread's envelope, live until its next safe call begins.
    let (m, d) = unsafe { (std::slice::from_raw_parts(env.metrics, 2), &*env.diags) };
    assert_eq!(
        (m[0].family_idx, m[0].kind, m[0].value),
        (2, METRIC_ADD, 1.0)
    );
    assert_eq!(
        (m[1].family_idx, m[1].kind, m[1].value),
        (5, METRIC_SET, 7.5)
    );
    assert!(m
        .iter()
        .all(|e| e.label_vals.is_null() && e.label_vals_len == 0));
    assert_eq!((d.id_idx, d.severity), (1, 2));
    assert_eq!(read(d.text), b"BUSBAR-7070 the webhook refused");
    // The next safe call starts an empty envelope.
    super::begin_call();
    let mut o2: CancelOut = zeroed();
    assert!(Out::new(&mut o2).metric(0, METRIC_ADD, 3.0));
    assert_eq!(o2.head.envelope.metrics_len, 1);
}

#[test]
fn a_full_envelope_reports_no_more() {
    use crate::abi::mechanism::call::{MAX_ENVELOPE_ENTRIES, METRIC_ADD};
    super::begin_call();
    let mut o: CancelOut = zeroed();
    let mut out = Out::new(&mut o);
    for _ in 0..MAX_ENVELOPE_ENTRIES {
        assert!(out.metric(0, METRIC_ADD, 1.0));
    }
    assert!(!out.metric(0, METRIC_ADD, 1.0), "the envelope is bounded");
    assert_eq!(o.head.envelope.metrics_len, MAX_ENVELOPE_ENTRIES);
    super::begin_call();
}
