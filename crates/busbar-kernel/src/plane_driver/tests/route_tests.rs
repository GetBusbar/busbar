// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PIECE FRAME: what every `on_piece` lends the plane. The unit's claim, dialect and caller
//! reference ride every piece; the member and its pool only an ATTEMPT; the far end's kept head
//! fields only the answer's first piece.

use super::*;

fn bufs(claim: u32) -> PieceBufs {
    let mut b = PieceBufs::new(&BufferCaps::default(), Arc::from(&b"body"[..]));
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
fn a_node_without_signing_material_lends_no_caller_reference() {
    let mut b = bufs(0);
    b.caller_ref.clear();
    let (i, _) = frame(&mut b, &piece(FROM_CALLER, 0, false), 9);
    assert!(i.caller_ref.ptr.is_null() && i.caller_ref.len == 0);
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
