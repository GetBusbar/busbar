// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::dispatch::{ConnTable, NoSink};
use busbar_contract::abi::mechanism::route::{Route, RouteAuth, RouteMethod};

struct EntropyFailure(bool);

impl EntropyFailure {
    fn new() -> Self {
        Self(crate::dispatch::handle::ENTROPY_FAILS.with(|flag| flag.replace(true)))
    }
}

impl Drop for EntropyFailure {
    fn drop(&mut self) {
        crate::dispatch::handle::ENTROPY_FAILS.with(|flag| flag.set(self.0));
    }
}

fn empty_routes_survive_entropy(axis: HookRows, module: &str) {
    let candidate = axis.find(module).expect("the existing hook is admitted");
    let result = {
        let _entropy = EntropyFailure::new();
        let error = HookRows::bind(
            candidate,
            &axis.dispatcher,
            "hooks.metadata-bind-control",
            Arc::new(NoSink),
            ConnTable::Probe,
        )
        .expect_err("the existing real bind must require a HostCtx entropy key");
        assert!(error.contains("entropy"), "{error}");
        axis.routes(
            module,
            "hooks.metadata-only",
            &json!({"reject_over_messages": "not-a-number"}),
        )
    };
    assert!(result
        .expect("an admitted empty route list must not bind or validate an instance")
        .is_empty());
}

#[test]
fn linked_empty_route_metadata_survives_entropy_failure() {
    empty_routes_survive_entropy(
        rows(checkpoint_plugin::door, "hook_checkpoint_door", Way::Linked),
        checkpoint_plugin::NAME,
    );
}

#[test]
fn dropped_empty_route_metadata_survives_entropy_failure() {
    empty_routes_survive_entropy(
        rows(
            checkpoint_plugin::door,
            "hook_checkpoint_door",
            Way::Dropped,
        ),
        checkpoint_plugin::NAME,
    );
}

#[test]
fn panicking_hook_empty_route_metadata_survives_entropy_failure() {
    empty_routes_survive_entropy(
        rows(hook_door_plugin::panicking::door, "hook_door", Way::Linked),
        PANICKING_NAME,
    );
}

#[test]
fn route_metadata_refuses_a_missing_tail_and_an_image_statement_mismatch() {
    let untailed = rows(hook_door_plugin::untailed::door, "hook_door", Way::Linked);
    let error = untailed
        .routes(UNTAILED_NAME, "hooks.metadata-untailed", &json!({}))
        .expect_err("empty routes cannot bypass the actual hook kind-tail check");
    assert!(
        error.contains(crate::dispatch::kinds::hook::NO_TAIL),
        "{error}"
    );

    for way in [Way::Linked, Way::Dropped] {
        let axis = rows(checkpoint_plugin::door, "hook_checkpoint_door", way);
        let mut candidate = axis.find(checkpoint_plugin::NAME).unwrap().clone();
        let different = rendering_of(hook_door_plugin::conforming::door)
            .expect("the other existing hook states its real metadata");
        candidate.stated = different.clone();
        if let Origin::Linked(row) = &mut candidate.origin {
            row.statement = different;
        }
        let mismatched = HookRows::of(vec![candidate], Arc::clone(&axis.dispatcher));
        let result = {
            let _entropy = EntropyFailure::new();
            mismatched.routes(
                checkpoint_plugin::NAME,
                "hooks.metadata-mismatched",
                &json!({}),
            )
        };
        let error = result.expect_err("metadata must be admitted from the exact stated image");
        assert!(
            error.contains("Statement is not the one its manifest states"),
            "{way:?}: {error}"
        );
    }
}

#[test]
fn the_entropy_failure_guard_restores_its_thread_after_unwind() {
    let before = crate::dispatch::handle::ENTROPY_FAILS.with(std::cell::Cell::get);
    let panicked = std::panic::catch_unwind(|| {
        let _entropy = EntropyFailure::new();
        assert!(crate::dispatch::handle::ENTROPY_FAILS.with(std::cell::Cell::get));
        panic!("leave the entropy-control scope");
    });
    assert!(panicked.is_err());
    assert_eq!(
        crate::dispatch::handle::ENTROPY_FAILS.with(std::cell::Cell::get),
        before
    );
}

#[path = "../../tests/fixtures/hook_metadata_boundary.rs"]
mod metadata_boundary;

fn ranking_metadata_rows(way: Way) -> HookRows {
    rows(metadata_boundary::door, "hook_metadata_boundary", way)
}

#[test]
fn nonempty_route_metadata_keeps_validation_and_binding() {
    for way in [Way::Linked, Way::Dropped] {
        let axis = ranking_metadata_rows(way);
        let name = ranking_name();
        let invalid = axis
            .routes(&name, "hooks.actual-metadata-invalid", &json!({}))
            .expect_err("a declared route must run actual Ranking VALIDATE");
        assert!(
            invalid.contains("ranking: settings.policy is required"),
            "{invalid}"
        );
        let valid = axis
            .routes(
                &name,
                "hooks.actual-metadata-valid",
                &json!({"policy": "cheapest"}),
            )
            .expect("the same actual validator accepts a real Ranking policy");
        assert_eq!(valid.len(), 1);
        let result = {
            let _entropy = EntropyFailure::new();
            axis.routes(
                &name,
                "hooks.actual-metadata-bind",
                &json!({"policy": "cheapest"}),
            )
        };
        let error = result.expect_err("nonempty route queries require the actual HostCtx binding");
        assert!(error.contains("entropy"), "{error}");
    }
}

#[test]
#[allow(unsafe_code)]
fn route_metadata_returns_owned_routes_after_row_retirement() {
    for way in [Way::Linked, Way::Dropped] {
        let returned = {
            let axis = ranking_metadata_rows(way);
            axis.routes(
                &ranking_name(),
                "hooks.actual-metadata-owned",
                &json!({"policy": "cheapest"}),
            )
            .expect("the metadata restatement uses actual Ranking validation")
        };
        assert_eq!(
            returned,
            vec![Route {
                path: "/hooks/ranking/metadata-boundary".to_owned(),
                method: RouteMethod::Post,
                auth: RouteAuth::Key,
            }]
        );
        // A copied String must not alias the static descriptor's path even while its image is
        // retained. Row retirement above and independent storage are separate ownership controls.
        let door = metadata_boundary::door();
        // SAFETY: this test constructed a static, nonempty, validated route list above.
        let route = unsafe {
            let tail = &*(*door.statement())
                .kind_tail
                .cast::<busbar_contract::abi::hook::Tail>();
            &*tail.routes
        };
        assert_ne!(returned[0].path.as_ptr(), route.path.ptr);
    }
}
