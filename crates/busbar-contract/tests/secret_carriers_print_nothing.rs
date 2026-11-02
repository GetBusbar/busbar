// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What a secret-carrying ABI type says when something formats it.

use busbar_contract::UpstreamAddress;

/// The environment a member-program child is spawned under is the node's credential hand-off: the

#[test]
fn a_program_upstream_does_not_print_or_serialise_its_environment_values() {
    let a = UpstreamAddress::Program {
        path: "/usr/bin/grid-server",
        args: &["--serve"],
        env: &[("GITHUB_TOKEN", "ghp_live-SECRET")],
        extras: &[],
    };

    let printed = format!("{a:?}");
    assert!(
        !printed.contains("ghp_live-SECRET") && !printed.contains("ghp_live"),
        "a program upstream printed a credential out of its environment: {printed}"
    );

    assert!(printed.contains("GITHUB_TOKEN"), "{printed}");
    assert!(printed.contains("15"), "{printed}");
    assert!(printed.contains("/usr/bin/grid-server"), "{printed}");

    let json = serde_json::to_string(&a).expect("an upstream address serialises");
    assert!(
        !json.contains("ghp_live-SECRET") && !json.contains("ghp_live"),
        "a program upstream serialised a credential out of its environment: {json}"
    );
    assert!(json.contains("GITHUB_TOKEN"), "{json}");
}

/// The two arms that carry no environment still say everything they hold.
#[test]
fn the_socket_arms_still_print_what_they_carry() {
    let socket = UpstreamAddress::Socket {
        authority: "10.0.0.7:443",
        sni: Some("api.example.com"),
        extras: &[],
    };
    let printed = format!("{socket:?}");
    assert!(
        printed.contains("10.0.0.7:443") && printed.contains("api.example.com"),
        "{printed}"
    );

    let per_path = UpstreamAddress::Socket {
        authority: "10.0.0.7:443",
        sni: None,
        extras: &[(
            busbar_contract::transport::facts::METHOD,
            "/pkg.Service/Method",
        )],
    };
    let printed = format!("{per_path:?}");
    assert!(
        printed.contains("10.0.0.7:443") && printed.contains("/pkg.Service/Method"),
        "{printed}"
    );
}
