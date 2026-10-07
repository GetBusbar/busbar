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
    assert_eq!(
        (e.head.lease, e.head.error.len, leases.held()),
        (0, 0, 0),
        "empty: no lease"
    );
}

/// RED (REVIEWER's MEDIUM): an answer that leases twice names ONE lease, and the host's one
/// release of it frees both; across N requests nothing is left held. Overwriting `head.lease`
/// instead of chaining leaves one orphaned part per request.
#[test]
fn an_answer_that_leases_twice_is_freed_by_its_one_release_across_requests() {
    let leases = Leases::default();
    for n in 0..8_u64 {
        let mut o: ServeOut = zeroed();
        let mut out = Out::new(&mut o);
        out.lease_str(|o| &o.head.error, &leases, format!("first {n}"));
        out.lease_str(|o| &o.head.error, &leases, format!("second {n}"));
        assert_eq!(read(o.head.error), format!("second {n}").as_bytes());
        assert_eq!(leases.held(), 1, "one answer, one lease");
        assert_eq!(leases.release(o.head.lease), Outcome::Ready);
        assert_eq!(leases.held(), 0, "request {n}: nothing left held");
        assert_eq!(
            leases.release(o.head.lease),
            Outcome::Refused,
            "no part outlives it"
        );
    }
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
fn a_failure_names_its_text_where_its_instance_keeps_it() {
    let kept = Kept::default();
    let reporting: Reporting = std::cell::Cell::new(None);
    let mut o: CancelOut = zeroed();
    let answered = Out::kept(&mut o, &kept, &reporting).fail(Refusal::failed(String::from("no")));
    assert_eq!(answered, Outcome::Failed);
    assert_eq!(read(o.head.error), b"no");
    assert_eq!(kept.held(), (1, 0), "the instance holds the text");
    let mut s: CancelOut = zeroed();
    let answered = Out::kept(&mut s, &kept, &reporting).fail(Refusal::refused("static"));
    assert_eq!(answered, Outcome::Refused);
    assert_eq!(read(s.head.error), b"static");
    assert_eq!(kept.held(), (1, 0), "a static text is named where it lives");
    assert_eq!(read(o.head.error), b"no");
}

#[test]
fn the_instance_keeps_a_bounded_ring_of_texts_each_readable_while_held() {
    let kept = Kept::default();
    let reporting: Reporting = std::cell::Cell::new(None);
    let mut first: CancelOut = zeroed();
    let _ = Out::kept(&mut first, &kept, &reporting).fail(Refusal::failed(String::from("first")));
    for i in 0..KEPT_RING - 1 {
        let mut o: CancelOut = zeroed();
        let _ = Out::kept(&mut o, &kept, &reporting).fail(Refusal::failed(format!("n{i}")));
    }
    assert_eq!(
        read(first.head.error),
        b"first",
        "held until the ring wraps"
    );
    let mut o: CancelOut = zeroed();
    let _ = Out::kept(&mut o, &kept, &reporting).fail(Refusal::failed(String::from("wrap")));
    assert_eq!(
        kept.held().0,
        KEPT_RING,
        "the ring never grows past its bound"
    );
}

#[test]
fn an_instance_less_failure_writes_the_hosts_lent_buffer_and_else_a_fixed_text() {
    // `validate`: the bytes, cut on a char boundary, named in `head.error` inside the buffer.
    let mut buf = [0_u8; 4];
    let lent = Reason {
        buf: buf.as_mut_ptr(),
        cap: buf.len(),
        open: false,
    };
    let mut v: OutHead = zeroed();
    let answered = Out::lent(&mut v, Some(lent)).fail(Refusal::failed(String::from("aéé")));
    assert_eq!(answered, Outcome::Failed);
    assert_eq!((v.error.ptr, v.error.len), (buf.as_ptr(), 3));
    assert_eq!(&buf, b"a\xc3\xa9\0");
    // `open`: the same, with the length in `err_len`.
    let mut buf = [0_u8; 16];
    let lent = Reason {
        buf: buf.as_mut_ptr(),
        cap: buf.len(),
        open: true,
    };
    let mut o: OpenOut = zeroed();
    let answered = Out::lent(&mut o, Some(lent)).fail(Refusal::refused(String::from("boom: x")));
    assert_eq!(answered, Outcome::Refused);
    assert_eq!(o.err_len, 7);
    assert_eq!(&buf[..7], b"boom: x");
    // No buffer lent: the fixed text, and nothing reported.
    let mut n: OpenOut = zeroed();
    let mut out = Out::lent(&mut n, None);
    assert_eq!(
        out.fail(Refusal::failed(String::from("lost"))),
        Outcome::Failed
    );
    assert!(!out.metric(0, crate::abi::mechanism::call::METRIC_ADD, 1.0));
    assert!(!out.diag(0, 0, "lost"));
    assert_eq!(read(n.head.error), NO_REASON_BUFFER.as_bytes());
    assert_eq!(n.err_len, 0);
}

#[test]
fn a_body_reports_metrics_and_declared_diagnostics_in_its_envelope() {
    use crate::abi::mechanism::call::{METRIC_ADD, METRIC_SET};
    let kept = Kept::default();
    let reporting: Reporting = std::cell::Cell::new(None);
    let mut o: CancelOut = zeroed();
    let mut out = Out::kept(&mut o, &kept, &reporting);
    assert!(out.metric(2, METRIC_ADD, 1.0));
    assert!(out.metric(5, METRIC_SET, 7.5));
    assert!(out.diag(1, 2, String::from("BUSBAR-7070 the webhook refused")));
    let env = o.head.envelope;
    assert_eq!((env.metrics_len, env.diags_len), (2, 1));
    // The call returns: its envelope goes to the instance, which keeps it.
    kept.keep(reporting.take().expect("the call reported"));
    // SAFETY: the instance's envelope, kept until KEPT_RING newer ones.
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
    // The next call starts an empty envelope of its own; the first stays as it was.
    let mut o2: CancelOut = zeroed();
    assert!(Out::kept(&mut o2, &kept, &reporting).metric(0, METRIC_ADD, 3.0));
    assert_eq!(o2.head.envelope.metrics_len, 1);
    assert_ne!(o2.head.envelope.metrics, env.metrics);
    assert_eq!(m[0].family_idx, 2);
}

#[test]
fn a_full_envelope_reports_no_more() {
    use crate::abi::mechanism::call::{MAX_ENVELOPE_ENTRIES, METRIC_ADD};
    let kept = Kept::default();
    let reporting: Reporting = std::cell::Cell::new(None);
    let mut o: CancelOut = zeroed();
    let mut out = Out::kept(&mut o, &kept, &reporting);
    for _ in 0..MAX_ENVELOPE_ENTRIES {
        assert!(out.metric(0, METRIC_ADD, 1.0));
    }
    assert!(!out.metric(0, METRIC_ADD, 1.0), "the envelope is bounded");
    assert_eq!(o.head.envelope.metrics_len, MAX_ENVELOPE_ENTRIES);
}

/// THE ROUTE SETTER (ARCHITECT Q-SW6/Q-FL3): the class and the entry's name, the name kept in the
/// instance's memory past the call; with no instance the class is set and no name is.
#[test]
fn an_arrival_names_its_route_and_keeps_the_name() {
    use crate::abi::plane::{ArriveOut, ROUTE_DIRECT};
    let kept = Kept::default();
    let reporting: Reporting = std::cell::Cell::new(None);
    let mut o: ArriveOut = zeroed();
    let name = String::from("entry");
    Out::kept(&mut o, &kept, &reporting).route(ROUTE_DIRECT, &name);
    drop(name);
    assert_eq!((o.route, read(o.pool)), (ROUTE_DIRECT, b"entry".to_vec()));
    let mut bare: ArriveOut = zeroed();
    Out::new(&mut bare).route(ROUTE_DIRECT, "entry");
    assert_eq!((bare.route, bare.pool.len), (ROUTE_DIRECT, 0));
}

/// THE TRUST FACTS SETTER (ARCHITECT 2026-10-06): the counterparty, item and digest a unit rests
/// on, each kept in the instance's memory past the call; an empty counterparty, item or digest
/// states none, and with no instance nothing is stated.
#[test]
fn an_arrival_states_its_trust_facts_and_keeps_them() {
    use crate::abi::plane::ArriveOut;
    let kept = Kept::default();
    let reporting: Reporting = std::cell::Cell::new(None);
    let mut o: ArriveOut = zeroed();
    let (cp, item) = (String::from("peer"), String::from("tool"));
    Out::kept(&mut o, &kept, &reporting).trust(&cp, Some(&item), Some("d1"));
    drop((cp, item));
    assert_eq!(
        (
            read(o.trust_counterparty),
            read(o.trust_item),
            read(o.trust_digest)
        ),
        (b"peer".to_vec(), b"tool".to_vec(), b"d1".to_vec())
    );
    let mut whole: ArriveOut = zeroed();
    Out::kept(&mut whole, &kept, &reporting).trust("peer", Some(""), None);
    assert_eq!(
        (whole.trust_item.len, whole.trust_digest.len),
        (0, 0),
        "no item, no digest"
    );
    let mut none: ArriveOut = zeroed();
    Out::kept(&mut none, &kept, &reporting).trust("", Some("tool"), Some("d1"));
    assert_eq!(none.trust_counterparty.len, 0);
    let mut bare: ArriveOut = zeroed();
    Out::new(&mut bare).trust("peer", None, None);
    assert_eq!(bare.trust_counterparty.len, 0);
}
