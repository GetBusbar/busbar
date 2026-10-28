// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The entry a unit's per-entry hooks bind over, per route kind.

/// THE GATES ARE BOUND OVER THE ENTRY THE KERNEL RECORDED (audit kernel-K2 leftover A4): the entry
/// the plane's `arrive` named at decode, never the plane's later word. A projection naming another
/// entry, or one where `arrive` named none, refuses the unit; the same entry is bound. A pool's unit
/// binds the member its projection names when the recorded pool holds it; a projection with no
/// entry and no body binds nothing.
#[test]
fn the_gates_bind_over_the_recorded_entry_and_a_projection_naming_another_is_refused() {
    use super::bound_entry;
    use busbar_contract::abi::plane::{ROUTE_DIRECT, ROUTE_LOCAL, ROUTE_POOL};
    let named = |entry: &str| super::Projection {
        pool: entry.to_string(),
        projected: Some(b"{}".to_vec()),
        ..super::Projection::default()
    };
    let (files, shell, none) = (named("files"), named("shell"), named(""));
    // The generation's pools: `pair` holds `files` and nothing else.
    let holds = |pool: &[u8], member: &str| pool == b"pair" && member == "files";
    assert_eq!(
        bound_entry(Some(b"files"), ROUTE_DIRECT, &files, holds).ok(),
        Some(Some("files"))
    );
    assert_eq!(
        bound_entry(None, ROUTE_LOCAL, &none, holds).ok(),
        Some(Some(""))
    );
    assert!(
        bound_entry(Some(b"files"), ROUTE_DIRECT, &shell, holds).is_err(),
        "a projection naming another entry bound that entry's gates"
    );
    assert!(
        bound_entry(None, ROUTE_LOCAL, &shell, holds).is_err(),
        "a projection naming an entry arrive never named bound that entry's gates"
    );
    assert!(
        bound_entry(None, ROUTE_POOL, &shell, holds).is_err(),
        "a pool route naming no pool bound the projection's entry"
    );
    assert_eq!(
        bound_entry(Some(b"pair"), ROUTE_POOL, &files, holds).ok(),
        Some(Some("files")),
        "a pool's unit binds the member its projection names"
    );
    assert_eq!(
        bound_entry(
            Some(b"files"),
            ROUTE_DIRECT,
            &super::Projection::default(),
            holds
        )
        .ok(),
        Some(None),
        "a projection with no entry and no body has nothing to screen"
    );
}

/// RED (Q128 p21#3; ARCHITECT 2026-10-07, THE DESIGN §1 l.183-187): under a pool route the plane's
/// projection may name only a member of the recorded pool. A member of no recorded pool, and the
/// empty entry with a body to screen, are refused; before the fix each bound whatever entry the
/// plane named (another entry's gates, or none at all).
#[test]
fn a_pool_route_binds_only_a_member_of_the_recorded_pool() {
    use super::bound_entry;
    use busbar_contract::abi::plane::ROUTE_POOL;
    let named = |entry: &str| super::Projection {
        pool: entry.to_string(),
        projected: Some(b"{}".to_vec()),
        ..super::Projection::default()
    };
    let holds = |pool: &[u8], member: &str| pool == b"pair" && member == "files";
    assert!(
        bound_entry(Some(b"pair"), ROUTE_POOL, &named("shell"), holds).is_err(),
        "a projection naming an entry outside the recorded pool bound that entry's gates"
    );
    assert!(
        bound_entry(Some(b"pair"), ROUTE_POOL, &named(""), holds).is_err(),
        "a projection naming no entry but stating a body bound the empty entry"
    );
    assert!(
        bound_entry(Some(b"solo"), ROUTE_POOL, &named("files"), holds).is_err(),
        "a member of another pool bound under a pool that does not hold it"
    );
    assert_eq!(
        bound_entry(Some(b"pair"), ROUTE_POOL, &named("files"), holds).ok(),
        Some(Some("files"))
    );
}

/// RED (the A2A TCK, CORE-SEND and 54 other MUSTs: every unaddressed `POST /a2a` hop answered 400
/// `decode_failed`): a unit routed BY SCOPE (`ROUTE_SCOPE`, `ROUTE_SCOPE_LOCAL`) recorded the
/// plane's CANDIDATE LIST at decode, never an entry, and its plane's projection names no entry
/// (the plane cannot know which one the scope resolves to). Its gates bind over the ONE entry the
/// kernel's own Verify resolved the scope to, inside the recorded candidates. Before the fix the
/// candidate list was compared byte-for-byte with the projection's entry, and every such unit was
/// refused unreadable. The binding guarantee still holds: a projection naming any other entry, and
/// a resolved entry outside the recorded candidates, are refused, never bound.
#[test]
fn a_scope_unit_binds_the_entry_its_scope_resolved_to_inside_the_recorded_candidates() {
    use super::scoped_entry;
    let named = |entry: &str| super::Projection {
        pool: entry.to_string(),
        projected: Some(b"{}".to_vec()),
        ..super::Projection::default()
    };
    let candidates: &[u8] = b"conformance, other";
    // The unaddressed unit: the projection names no entry, the scope resolved to `conformance`.
    assert_eq!(
        scoped_entry(Some(candidates), Some(b"conformance"), &named("")).ok(),
        Some(Some("conformance")),
        "an unaddressed scope unit was not bound to the entry its scope resolved to"
    );
    // A projection naming the resolved entry itself binds it too.
    assert_eq!(
        scoped_entry(
            Some(candidates),
            Some(b"conformance"),
            &named("conformance")
        )
        .ok(),
        Some(Some("conformance"))
    );
    // No candidates named: every entry is a candidate, and the resolved one is bound.
    assert_eq!(
        scoped_entry(None, Some(b"solo"), &named("")).ok(),
        Some(Some("solo"))
    );
    // THE GUARANTEE: the plane's later word never trades the resolved entry's gates for another's.
    assert!(
        scoped_entry(Some(candidates), Some(b"conformance"), &named("other")).is_err(),
        "a projection naming another candidate bound that entry's gates"
    );
    assert!(
        scoped_entry(Some(candidates), Some(b"conformance"), &named("shell")).is_err(),
        "a projection naming an entry outside the candidates bound that entry's gates"
    );
    // ...and the binding never widens the recorded candidate list.
    assert!(
        scoped_entry(Some(candidates), Some(b"shell"), &named("")).is_err(),
        "an entry outside the recorded candidates was bound"
    );
    assert!(
        scoped_entry(Some(candidates), Some(b"conform"), &named("")).is_err(),
        "a prefix of a candidate was read as the candidate"
    );
    // A scope zero or several entries reached resolved none: nothing is bound here, and the door
    // refuses the unit `no_destination` (`abi::plane::ROUTE_SCOPE`), never a gate-free hop.
    assert_eq!(
        scoped_entry(Some(candidates), None, &named("")).ok(),
        Some(None)
    );
    assert!(
        scoped_entry(Some(candidates), None, &named("conformance")).is_err(),
        "an unresolved scope bound the entry the plane named"
    );
    // Nothing to screen: nothing bound, as for any route.
    assert_eq!(
        scoped_entry(
            Some(candidates),
            Some(b"conformance"),
            &super::Projection::default()
        )
        .ok(),
        Some(None)
    );
}
