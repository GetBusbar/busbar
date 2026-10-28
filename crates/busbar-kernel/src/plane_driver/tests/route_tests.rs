// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PIECE FRAME: what every `on_piece` lends the plane. The unit's claim, dialect and caller
//! reference ride every piece; the member and its pool only an ATTEMPT; the far end's kept head
//! fields only the answer's first piece.

use super::*;

fn bufs(claim: u32) -> PieceBufs {
    let mut b = PieceBufs::new(&BufferCaps::default(), bytes::Bytes::from_static(b"body"));
    b.claim = claim;
    b.dialect = 3;
    b.caller_ref = b"c0ffee".to_vec();
    b.member = b"m1".to_vec();
    b.pool = b"p1".to_vec();
    b.head = FieldList::new(vec![(b"retry-after".to_vec(), b"7".to_vec())]);
    b
}

fn piece(from: u32, attempt_no: u32, head: bool) -> Piece {
    Piece {
        from,
        flags: 0,
        status: (0, 0),
        attempt_no,
        src: Src::None,
        head,
        reason: 0,
    }
}

fn text(s: AbiStr) -> Vec<u8> {
    if s.ptr.is_null() {
        return Vec::new();
    }
    // SAFETY: the frame's strings point into `bufs`, alive for the test.
    unsafe { std::slice::from_raw_parts(s.ptr, s.len).to_vec() }
}

#[test]
fn every_piece_lends_the_units_claim_dialect_and_caller_reference() {
    let mut b = bufs(2);
    for p in [
        piece(FROM_KERNEL, 1, false),
        piece(FROM_CALLER, 0, false),
        piece(FROM_FAR_END, 0, true),
        piece(FROM_FAR_END, 0, false),
    ] {
        let (i, _) = frame(&mut b, &p, 9);
        assert_eq!((i.claim, i.dialect), (2, 3));
        assert_eq!(text(i.caller_ref), b"c0ffee");
    }
    // Two doors of one plane: the claim tells them apart.
    let mut other = bufs(5);
    let (i, _) = frame(&mut other, &piece(FROM_CALLER, 0, false), 9);
    assert_eq!(i.claim, 5);
}

#[test]
fn only_an_attempt_names_its_member_and_pool() {
    let mut b = bufs(0);
    let (i, _) = frame(&mut b, &piece(FROM_KERNEL, 1, false), 9);
    assert_eq!(
        (text(i.member), text(i.pool)),
        (b"m1".to_vec(), b"p1".to_vec())
    );
    let (i, _) = frame(&mut b, &piece(FROM_CALLER, 0, false), 9);
    assert!(text(i.member).is_empty() && text(i.pool).is_empty());
}

#[test]
fn only_the_answers_first_piece_lends_the_kept_head() {
    let mut b = bufs(0);
    let (i, _) = frame(&mut b, &piece(FROM_FAR_END, 0, true), 9);
    assert_eq!(i.head_fields_len, 1);
    // SAFETY: one field in `b.head`.
    let f = unsafe { *i.head_fields };
    assert_eq!(
        (text(f.name), text(f.value)),
        (b"retry-after".to_vec(), b"7".to_vec())
    );
    let (i, _) = frame(&mut b, &piece(FROM_FAR_END, 0, false), 9);
    assert!(i.head_fields.is_null() && i.head_fields_len == 0);
}

/// THE USAGE-TAP FAULT IS READ OFF THE ANSWER (row 155): a plane's answer carrying a usage-tap
/// fault beside its units reads as the reason the kernel counts it under, and one carrying none
/// reads as nothing to count. A byte outside the vocabulary reads as `unknown`: counted, never
/// ignored and never read as none. The steps count each answer's fault once, and a plane writes it
/// on one window of its answer.
#[test]
fn an_answers_usage_tap_fault_reads_as_the_reason_the_kernel_counts() {
    use busbar_contract::abi::plane::{
        OnPieceOut, TAP_FAULT_BAD_JSON, TAP_FAULT_DECODE, TAP_FAULT_NONE,
        TAP_FAULT_UNKNOWN_PROTOCOL,
    };
    let mut o: OnPieceOut = blank_out();
    for (code, reason) in [
        (TAP_FAULT_NONE, None),
        (TAP_FAULT_DECODE, Some("decode")),
        (TAP_FAULT_BAD_JSON, Some("bad_json")),
        (TAP_FAULT_UNKNOWN_PROTOCOL, Some("unknown_protocol")),
        (TAP_FAULT_UNKNOWN_PROTOCOL + 1, Some("unknown")),
        (u8::MAX, Some("unknown")),
    ] {
        o.tap_fault = code;
        assert_eq!(Answer::of(&o).usage_tap_fault(), reason, "{code}");
    }
}

#[test]
fn every_piece_says_whether_the_attempts_member_relays_the_callers_credential() {
    let mut b = bufs(0);
    let (i, _) = frame(&mut b, &piece(FROM_CALLER, 0, false), 9);
    assert_eq!(i.passthrough, 0, "no attempt yet, nothing relayed");
    b.passthrough = true;
    for from in [FROM_KERNEL, FROM_CALLER, FROM_FAR_END] {
        let (i, _) = frame(&mut b, &piece(from, 1, false), 9);
        assert_eq!(i.passthrough, 1);
    }
}

/// F25 row 628: rehomed from the retired engine crate's src/engine/tests/usage_tap_tests.rs::
/// test_stable_hash_is_deterministic. The walk's affinity hash is stable across calls AND processes
/// (unlike `DefaultHasher`) so session affinity survives restarts: FNV-1a pinned to a precomputed
/// golden, so an algorithm or offset/prime swap is caught directly.
#[test]
fn test_stable_hash_is_deterministic() {
    use crate::plane_driver::sticky_hash;
    assert_eq!(sticky_hash(b"session-abc"), 0xe909_c864_ab05_9bea);
    assert_eq!(sticky_hash(b"session-abc"), sticky_hash(b"session-abc"));
    assert_ne!(sticky_hash(b"session-abc"), sticky_hash(b"session-xyz"));
}

/// A unit lent no caller reference frames it absent (a null, zero-length string). Only a driver
/// whose config has `caller_refs: None` (no book) leaves the reference empty: a book's slot always
/// holds a key, the node's per-boot one when it has neither signing material nor a keyset.
#[test]
fn a_unit_lent_no_caller_reference_frames_it_absent() {
    let mut b = bufs(0);
    b.caller_ref.clear();
    let (i, _) = frame(&mut b, &piece(FROM_CALLER, 0, false), 9);
    assert!(i.caller_ref.ptr.is_null() && i.caller_ref.len == 0);
}

// ── F25 rows 630-633: rehomed from the retired engine crate's src/engine/tests/wire_tests.rs. The
// route-policy transparency pair as the pump stamps it
// (`route_policy_fields`, 1.5.5's `maybe_attach_route_policy_gated`), over the full 2x2 matrix of
// the outer (operator opt-in) and inner (a non-default policy chose) gates.

/// Both `x-busbar-route-*` fields the pump would stamp after the plane's own `fields` for
/// `(enabled, policy, member)`, as a `(policy, target)` pair (empty strings when absent); the
/// plane's own fields stay first and untouched.
fn built_route_fields(enabled: bool, policy: Option<&str>, member: &[u8]) -> (String, String) {
    let mut fields: HeadFields = vec![(b"content-type".to_vec(), b"application/json".to_vec())];
    route_policy_fields(&mut fields, enabled, policy, member);
    assert_eq!(
        fields[0],
        (b"content-type".to_vec(), b"application/json".to_vec()),
        "the plane's own fields lead"
    );
    let get = |name: &str| {
        fields
            .iter()
            .find(|(n, _)| n.as_slice() == name.as_bytes())
            .map(|(_, v)| String::from_utf8(v.clone()).expect("utf8"))
            .unwrap_or_default()
    };
    (get(super::HDR_ROUTE_POLICY), get(super::HDR_ROUTE_TARGET))
}

/// F25 row 630: rehomed from the retired engine crate's src/engine/tests/wire_tests.rs::
/// route_policy_headers_suppressed_when_outer_gate_disabled_even_with_a_policy_name. Even with a
/// policy name present, the outer gate off suppresses BOTH fields.
#[test]
fn route_policy_headers_suppressed_when_outer_gate_disabled_even_with_a_policy_name() {
    let (policy, target) = built_route_fields(false, Some("cheapest"), b"claude");
    assert_eq!(
        policy, "",
        "route-policy header must be absent when the outer gate is off"
    );
    assert_eq!(
        target, "",
        "route-target header must be absent when the outer gate is off"
    );
}

/// F25 row 631: rehomed from the retired engine crate's src/engine/tests/wire_tests.rs::
/// route_policy_headers_absent_for_a_default_policy_even_when_outer_gate_enabled. With the outer
/// gate ON, a default routing decision (no policy name) attaches nothing.
#[test]
fn route_policy_headers_absent_for_a_default_policy_even_when_outer_gate_enabled() {
    let (policy, target) = built_route_fields(true, None, b"claude");
    assert_eq!(
        policy, "",
        "no policy name -> no header, regardless of the outer gate"
    );
    assert_eq!(
        target, "",
        "no policy name -> no header, regardless of the outer gate"
    );
}

/// F25 row 632: rehomed from the retired engine crate's src/engine/tests/wire_tests.rs::
/// route_policy_headers_present_only_when_both_gates_open. Both gates open is the only combination
/// that emits the pair, carrying the exact policy name and target member.
#[test]
fn route_policy_headers_present_only_when_both_gates_open() {
    let (policy, target) = built_route_fields(true, Some("cheapest"), b"claude");
    assert_eq!(policy, "cheapest");
    assert_eq!(target, "claude");
    let mut fields: HeadFields = Vec::new();
    route_policy_fields(&mut fields, true, Some("cheapest"), b"claude");
    assert_eq!(
        fields,
        vec![
            (b"x-busbar-route-policy".to_vec(), b"cheapest".to_vec()),
            (b"x-busbar-route-target".to_vec(), b"claude".to_vec()),
        ],
        "exactly the pair, policy first"
    );
}

/// F25 row 633: rehomed from the retired engine crate's src/engine/tests/wire_tests.rs::
/// route_policy_headers_absent_when_both_gates_closed. The fourth combination (outer off, inner off)
/// is also silent, completing the 2x2 matrix.
#[test]
fn route_policy_headers_absent_when_both_gates_closed() {
    let (policy, target) = built_route_fields(false, None, b"claude");
    assert_eq!(policy, "");
    assert_eq!(target, "");
}

/// The reference the driver derives is the node's keyed digest of the principal, never the
/// principal: 64 lower-case hex characters that do not contain it.
#[test]
fn the_caller_reference_is_never_the_principal() {
    let key = crate::auth::CallerRefKey::derive(b"node signing material");
    let r = key.caller_ref("acct:alice@example.com");
    assert_eq!(r.len(), 64);
    assert!(r
        .bytes()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    assert!(!r.contains("alice"));
}

/// A door plane is lent the operator's name of the member (and pool) its attempt was picked from —
/// the entry its own section writes — never the kernel's `(plane key, entry)` key; a name with no
/// plane key is lent as it is.
#[test]
fn a_plane_is_lent_the_operators_name_of_its_member() {
    let key = format!("door{}fs", crate::governance::PLANE_LANE_SEP);
    assert_eq!(super::operator_name(key.as_bytes()), b"fs");
    assert_eq!(super::operator_name(b"gpt-model"), b"gpt-model");
    assert_eq!(super::operator_name(b""), b"");
}

/// Only the REFUSED PIECE lends a reason (`OnPieceIn::reason`, with `PIECE_REFUSED`); every other
/// piece lends `0`.
#[test]
fn only_the_refused_piece_lends_its_reason() {
    let mut b = bufs(0);
    for from in [FROM_KERNEL, FROM_CALLER, FROM_FAR_END] {
        let (i, _) = frame(&mut b, &piece(from, 0, false), 9);
        assert_eq!(i.reason, 0);
    }
    let code = reason_code(ReasonCode::CredentialUnavailable);
    let refused = Piece {
        flags: PIECE_REFUSED | PIECE_LAST,
        reason: code,
        ..piece(FROM_KERNEL, 0, false)
    };
    let (i, _) = frame(&mut b, &refused, 9);
    assert_eq!((i.flags, i.reason), (PIECE_REFUSED | PIECE_LAST, code));
    assert_eq!(refused.continuation().reason, 0, "its re-call carries none");
}

/// THE FINAL MARK AND THE FAILOVER VERDICT READ ONE PREDICATE: for every (streamed, relayed) the
/// first far-end piece is marked `PIECE_FINAL` exactly when a retry verdict would NOT fail the
/// answer over. And every flag set the pump builds for a far-end piece is one the contract admits
/// (`check_piece_in`): the cut mark only on a last piece, the final mark only on the status piece.
/// RED: a final mark computed apart from `fails_over`, or a cut marked on a piece that is not last.
#[test]
fn the_final_mark_agrees_with_the_failover_verdict_and_every_far_flag_set_is_admitted() {
    use busbar_contract::abi::plane::check::check_piece_in;
    for streamed in [false, true] {
        for relayed in [false, true] {
            for last in [false, true] {
                for cut in [false, true] {
                    for fields in [false, true] {
                        for has_status in [false, true] {
                            let piece = FarPiece {
                                last,
                                cut,
                                fields,
                                relayed,
                                ..FarPiece::default()
                            };
                            let flags = far_flags(&piece, has_status, streamed);
                            assert_eq!(
                                check_piece_in(FROM_FAR_END, flags),
                                Ok(()),
                                "{piece:?} status {has_status} streamed {streamed}"
                            );
                            assert_eq!(
                                flags & PIECE_FINAL != 0,
                                has_status && !fails_over(streamed, relayed),
                                "{piece:?} status {has_status} streamed {streamed}"
                            );
                            assert_eq!(flags & PIECE_CUT != 0, last && cut, "{piece:?}");
                        }
                    }
                }
            }
        }
    }
    assert!(fails_over(false, false));
    assert!(!fails_over(true, false) && !fails_over(false, true));
}

/// BODY BY REFERENCE (ABI-MACHINERY S5a): a far-end piece's bytes become the plane's input
/// without a copy: the input is the piece's own allocation.
#[test]
fn a_far_end_piece_is_lent_to_the_plane_without_a_copy() {
    let bytes = b"a far-end chunk".to_vec();
    let at = bytes.as_ptr();
    let mut piece = FarPiece {
        bytes,
        ..FarPiece::default()
    };
    let mut input = Vec::with_capacity(64);
    lend_piece(&mut input, &mut piece);
    assert_eq!(input, b"a far-end chunk");
    assert_eq!(
        input.as_ptr(),
        at,
        "the plane's input is the piece's own bytes, never a copy"
    );
}
