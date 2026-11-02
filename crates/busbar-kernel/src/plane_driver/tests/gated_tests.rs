// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::rewrite_refusal;
use crate::hooks::{REQUIRED_HOOK_UNAVAILABLE_MESSAGE, REQUIRED_HOOK_UNAVAILABLE_STATUS};

#[test]
fn the_seams_own_failed_verdict_keeps_its_503_and_a_hook_status_is_clamped() {
    assert_eq!(
        rewrite_refusal(
            REQUIRED_HOOK_UNAVAILABLE_STATUS,
            REQUIRED_HOOK_UNAVAILABLE_MESSAGE
        ),
        (
            REQUIRED_HOOK_UNAVAILABLE_STATUS,
            REQUIRED_HOOK_UNAVAILABLE_MESSAGE.to_string()
        )
    );
    assert_eq!(rewrite_refusal(503, "mine").0, 403);
    assert_eq!(rewrite_refusal(200, "ok").0, 403);
    assert_eq!(rewrite_refusal(429, "slow").0, 429);
}

#[test]
fn the_gates_bind_over_the_recorded_entry_and_a_projection_naming_another_is_refused() {
    use super::bound_entry;
    use busbar_contract::abi::plane::{ROUTE_DIRECT, ROUTE_LOCAL, ROUTE_POOL};
    let named = |entry: &str| {
        let mut view = super::Projection::empty(entry.to_string(), String::new());
        view.projected = Some(b"{}".to_vec());
        view
    };
    let (files, shell, none) = (named("files"), named("shell"), named(""));

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

#[test]
fn a_pool_route_binds_only_a_member_of_the_recorded_pool() {
    use super::bound_entry;
    use busbar_contract::abi::plane::ROUTE_POOL;
    let named = |entry: &str| {
        let mut view = super::Projection::empty(entry.to_string(), String::new());
        view.projected = Some(b"{}".to_vec());
        view
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

#[test]
fn the_refusal_literal_is_the_shared_constant() {
    const GATE_COULD_NOT_COMPLETE: &str =
        "A required gate could not complete. Please retry shortly.";
    assert_eq!(GATE_COULD_NOT_COMPLETE, REQUIRED_HOOK_UNAVAILABLE_MESSAGE);
    assert_eq!(503, REQUIRED_HOOK_UNAVAILABLE_STATUS);
    assert_eq!(
        rewrite_refusal(503, GATE_COULD_NOT_COMPLETE),
        (503, GATE_COULD_NOT_COMPLETE.to_string()),
        "the gate-first stage serves the shared refusal unchanged"
    );
}

#[test]
fn the_gate_first_binder_names_the_dialect_a_unit_arrived_in() {
    use super::super::HookBinder;
    let host: super::GenerationHost =
        std::sync::Arc::new(|| -> std::sync::Arc<dyn crate::plane_driver::EngineHost> {
            unreachable!("naming a dialect reads no generation")
        });
    let binder = super::HostGatedHooks {
        host,
        plane_key: "plane-a".to_string(),
        keys: std::sync::Arc::new(
            |_: &str| -> Option<std::sync::Arc<busbar_contract::records::VirtualKey>> { None },
        ),
        dialects: vec!["dialect-0".to_string(), "dialect-1".to_string()],
    };
    assert_eq!(binder.dialect(1), "dialect-1");
    assert_eq!(binder.dialect(0), "dialect-0");
    assert_eq!(
        binder.dialect(9),
        "",
        "an index past the plane's dialects names none"
    );
}

#[test]
fn a_scope_unit_binds_the_entry_its_scope_resolved_to_inside_the_recorded_candidates() {
    use super::scoped_entry;
    let named = |entry: &str| {
        let mut view = super::Projection::empty(entry.to_string(), String::new());
        view.projected = Some(b"{}".to_vec());
        view
    };
    let candidates: &[u8] = b"conformance, other";

    assert_eq!(
        scoped_entry(Some(candidates), Some(b"conformance"), &named("")).ok(),
        Some(Some("conformance")),
        "an unaddressed scope unit was not bound to the entry its scope resolved to"
    );

    assert_eq!(
        scoped_entry(
            Some(candidates),
            Some(b"conformance"),
            &named("conformance")
        )
        .ok(),
        Some(Some("conformance"))
    );

    assert_eq!(
        scoped_entry(None, Some(b"solo"), &named("")).ok(),
        Some(Some("solo"))
    );

    assert!(
        scoped_entry(Some(candidates), Some(b"conformance"), &named("other")).is_err(),
        "a projection naming another candidate bound that entry's gates"
    );
    assert!(
        scoped_entry(Some(candidates), Some(b"conformance"), &named("shell")).is_err(),
        "a projection naming an entry outside the candidates bound that entry's gates"
    );

    assert!(
        scoped_entry(Some(candidates), Some(b"shell"), &named("")).is_err(),
        "an entry outside the recorded candidates was bound"
    );
    assert!(
        scoped_entry(Some(candidates), Some(b"conform"), &named("")).is_err(),
        "a prefix of a candidate was read as the candidate"
    );

    assert_eq!(
        scoped_entry(Some(candidates), None, &named("")).ok(),
        Some(None)
    );
    assert!(
        scoped_entry(Some(candidates), None, &named("conformance")).is_err(),
        "an unresolved scope bound the entry the plane named"
    );

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
