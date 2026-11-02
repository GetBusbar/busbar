// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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

#[test]
fn test_stable_hash_is_deterministic() {
    use crate::plane_driver::sticky_hash;
    assert_eq!(sticky_hash(b"session-abc"), 0xe909_c864_ab05_9bea);
    assert_eq!(sticky_hash(b"session-abc"), sticky_hash(b"session-abc"));
    assert_ne!(sticky_hash(b"session-abc"), sticky_hash(b"session-xyz"));
}

#[test]
fn a_unit_lent_no_caller_reference_frames_it_absent() {
    let mut b = bufs(0);
    b.caller_ref.clear();
    let (i, _) = frame(&mut b, &piece(FROM_CALLER, 0, false), 9);
    assert!(i.caller_ref.ptr.is_null() && i.caller_ref.len == 0);
}

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

#[test]
fn route_policy_headers_absent_when_both_gates_closed() {
    let (policy, target) = built_route_fields(false, None, b"claude");
    assert_eq!(policy, "");
    assert_eq!(target, "");
}

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

#[test]
fn a_plane_is_lent_the_operators_name_of_its_member() {
    let key = format!("door{}fs", crate::governance::PLANE_LANE_SEP);
    assert_eq!(super::operator_name(key.as_bytes()), b"fs");
    assert_eq!(super::operator_name(b"gpt-model"), b"gpt-model");
    assert_eq!(super::operator_name(b""), b"");
}

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

#[test]
fn a_far_end_piece_is_lent_to_the_plane_without_a_copy() {
    let bytes = b"a far-end chunk".to_vec();
    let at = bytes.as_ptr();
    let mut piece = FarPiece {
        bytes,
        ..FarPiece::default()
    };
    let mut input = SessionInput {
        bytes: Vec::with_capacity(64),
        custody: None,
    };
    lend_piece(&mut input, &mut piece);
    assert_eq!(input.bytes, b"a far-end chunk");
    assert_eq!(
        input.bytes.as_ptr(),
        at,
        "the plane's input is the piece's own bytes, never a copy"
    );
}

#[test]
fn clearing_input_does_not_release_its_allocation_custody() {
    struct Owner(Arc<std::sync::atomic::AtomicUsize>);
    impl Drop for Owner {
        fn drop(&mut self) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
    let dropped = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut b = bufs(0);
    b.input = SessionInput {
        bytes: b"retained input".to_vec(),
        custody: Some(Arc::new(Owner(dropped.clone()))),
    };
    b.input.bytes.clear();
    assert_eq!(dropped.load(std::sync::atomic::Ordering::SeqCst), 0);
    let mut far = FarPiece {
        bytes: b"replacement".to_vec(),
        ..FarPiece::default()
    };
    lend_piece(&mut b.input, &mut far);
    assert_eq!(dropped.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(b.input.bytes, b"replacement");
    assert!(b.input.custody.is_none());
    drop(b);
    assert_eq!(dropped.load(std::sync::atomic::Ordering::SeqCst), 1);
}
