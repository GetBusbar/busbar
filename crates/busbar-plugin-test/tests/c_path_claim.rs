// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-PATH-CLAIM (ABI-MIN3-INTERFACE §14): Path claims per listener (§12.26).
//!
//! The rule is `busbar_kernel::path_claims::check_path_claims`, run at config load before any bind. The kernel's
//! own unit tests pin the same shapes; this case drives them through the public API as the conformance suite.

use busbar_kernel::path_claims::{check_path_claims, ListenerId, PathClaim};

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

#[test]
fn path_claims_per_listener() {
    // Two export-prometheus instances at /metrics on one listener: refused naming both and the path.
    let refused = check_path_claims(&[
        claim(ListenerId::Data, GET, "/metrics", "export prom-a"),
        claim(ListenerId::Data, GET, "/metrics", "export prom-b"),
    ])
    .expect_err("two owners of one path on one listener are refused");
    for needle in ["export prom-a", "export prom-b", "/metrics"] {
        assert!(
            refused.0.contains(needle),
            "{needle} missing: {}",
            refused.0
        );
    }

    // The same two on different listeners: both serve.
    assert!(check_path_claims(&[
        claim(ListenerId::Export(0), GET, "/metrics", "export prom-a"),
        claim(ListenerId::Export(1), GET, "/metrics", "export prom-b"),
    ])
    .is_ok());

    // A plane route equal to a core route: refused naming core.
    let refused = check_path_claims(&[
        claim(ListenerId::Data, GET, "/healthz", "core"),
        claim(ListenerId::Data, GET, "/healthz", "plane p"),
    ])
    .expect_err("a plane route on a core route is refused");
    assert!(refused.0.contains("core"), "{}", refused.0);

    // Two planes with patterns differing only in parameter names, sharing a method: refused.
    assert!(check_path_claims(&[
        claim(ListenerId::Data, GET | POST, "/v1/{id}/items", "plane a"),
        claim(ListenerId::Data, POST, "/v1/{name}/items", "plane b"),
    ])
    .is_err());

    // Disjoint methods: accepted.
    assert!(check_path_claims(&[
        claim(ListenerId::Data, GET, "/v1/{id}/items", "plane a"),
        claim(ListenerId::Data, POST, "/v1/{name}/items", "plane b"),
    ])
    .is_ok());
}
