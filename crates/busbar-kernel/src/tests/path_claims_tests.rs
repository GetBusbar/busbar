// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-PATH-CLAIM (IF §12.26, §14), kernel arms: the rule `check_path_claims` applies at config load.

use super::{check_path_claims, ListenerId, PathClaim};

const GET: u32 = 1 << 0;
const POST: u32 = 1 << 1;

fn claim<'a>(
    listener: ListenerId,
    methods: u32,
    pattern: &'a str,
    owner: &'a str,
) -> PathClaim<'a> {
    PathClaim {
        listener,
        methods,
        pattern,
        owner,
    }
}

/// Two export-prometheus instances at `/metrics` on one listener: refused naming both and the path.
#[test]
fn two_exports_on_one_listener_are_refused_naming_both() {
    let claims = [
        claim(ListenerId::Data, GET, "/metrics", "export prom-a"),
        claim(ListenerId::Data, GET, "/metrics", "export prom-b"),
    ];
    let refused = check_path_claims(&claims).expect_err("overlap must refuse");
    assert!(refused.0.contains("export prom-a"), "{}", refused.0);
    assert!(refused.0.contains("export prom-b"), "{}", refused.0);
    assert!(refused.0.contains("`/metrics`"), "{}", refused.0);
}

/// The same two instances on different listeners both serve.
#[test]
fn the_same_path_on_different_listeners_is_accepted() {
    let claims = [
        claim(ListenerId::Export(0), GET, "/metrics", "export prom-a"),
        claim(ListenerId::Export(1), GET, "/metrics", "export prom-b"),
        claim(ListenerId::Data, GET, "/metrics", "export prom-c"),
        claim(ListenerId::Admin, GET, "/metrics", "core"),
    ];
    assert_eq!(check_path_claims(&claims), Ok(()));
}

/// A plane route equal to a core route is refused naming `core`.
#[test]
fn a_plane_route_on_a_core_route_names_core() {
    let claims = [
        claim(ListenerId::Data, GET, "/healthz", "core"),
        claim(ListenerId::Data, GET | POST, "/healthz", "plane llm"),
    ];
    let refused = check_path_claims(&claims).expect_err("core overlap must refuse");
    assert!(refused.0.contains("core"), "{}", refused.0);
    assert!(refused.0.contains("plane llm"), "{}", refused.0);
    assert!(refused.0.contains("`/healthz`"), "{}", refused.0);
}

/// Patterns that differ only in parameter names overlap when a method is shared; disjoint methods do not.
#[test]
fn parameter_names_do_not_separate_patterns_but_methods_do() {
    let shared = [
        claim(ListenerId::Data, POST, "/v1/{model}/chat", "plane a"),
        claim(ListenerId::Data, GET | POST, "/v1/{name}/chat", "plane b"),
    ];
    let refused = check_path_claims(&shared).expect_err("same shape, shared POST");
    assert!(
        refused.0.contains("plane a") && refused.0.contains("plane b"),
        "{}",
        refused.0
    );

    let disjoint = [
        claim(ListenerId::Data, POST, "/v1/{model}/chat", "plane a"),
        claim(ListenerId::Data, GET, "/v1/{name}/chat", "plane b"),
    ];
    assert_eq!(check_path_claims(&disjoint), Ok(()));
}

/// Wildcards normalise by shape too, and a wildcard is never the same shape as a single parameter; the old
/// `:name` / `*rest` spelling normalises to the same shape as `{name}` / `{*rest}`.
#[test]
fn wildcards_and_legacy_parameter_spellings_normalise() {
    let wild = [
        claim(ListenerId::Data, GET, "/files/{*rest}", "plane a"),
        claim(ListenerId::Data, GET, "/files/*path", "plane b"),
    ];
    assert!(check_path_claims(&wild).is_err());

    let colon = [
        claim(ListenerId::Data, GET, "/u/{id}", "plane a"),
        claim(ListenerId::Data, GET, "/u/:user", "plane b"),
    ];
    assert!(check_path_claims(&colon).is_err());

    let distinct = [
        claim(ListenerId::Data, GET, "/files/{*rest}", "plane a"),
        claim(ListenerId::Data, GET, "/files/{one}", "plane b"),
        claim(ListenerId::Data, GET, "/files/static", "plane c"),
    ];
    assert_eq!(check_path_claims(&distinct), Ok(()));
}

/// The reported pair is the first claim that overlaps an earlier one, with that earlier claim, so the text is
/// stable across loads.
#[test]
fn the_first_overlapping_pair_is_reported() {
    let claims = [
        claim(ListenerId::Data, GET, "/a", "export one"),
        claim(ListenerId::Data, GET, "/b", "export two"),
        claim(ListenerId::Data, GET, "/b", "export three"),
        claim(ListenerId::Data, GET, "/a", "export four"),
    ];
    let refused = check_path_claims(&claims).expect_err("two overlaps");
    assert!(
        refused.0.contains("export two") && refused.0.contains("export three"),
        "{}",
        refused.0
    );
}
