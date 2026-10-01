// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What a secret-carrying ABI type says when something formats it.
//!
//! Every one of these is handed across the plugin ABI, so the code that might format it is code
//! this tree cannot see. The guarantee has to be the type's, not the caller's discipline.

use busbar_contract::{SecretOnce, UpstreamAddress};

/// The environment a `stdio` child is spawned under is the node's credential hand-off: the whole
/// reason the arm names it rather than inheriting it is that inheriting it hands the child every
/// secret the node holds. Naming it puts those values inside an ABI type that the code formatting
/// it — a transport author's log line, a configuration dump — is code this tree cannot read.
#[test]
fn a_program_upstream_does_not_print_or_serialise_its_environment_values() {
    let a = UpstreamAddress::Program {
        path: "/usr/bin/grid-server",
        args: &["--stdio"],
        env: &[("GITHUB_TOKEN", "ghp_live-SECRET")],
        extras: &[],
    };

    let printed = format!("{a:?}");
    assert!(
        !printed.contains("ghp_live-SECRET") && !printed.contains("ghp_live"),
        "a program upstream printed a credential out of its environment: {printed}"
    );
    // What it DOES say: which names are set and how long each value was — enough to diagnose a
    // child spawned without the variable it needed, and nothing a reader could present as it.
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

    // The call-per-path family is a socket that DECLARES its method rather than an arm of its
    // own, and a declared fact is a wire fact and not a credential: it prints whole, which is what
    // a transport author's log line is read to check.
    let grpc = UpstreamAddress::Socket {
        authority: "10.0.0.7:443",
        sni: None,
        extras: &[(
            busbar_contract::transport::facts::METHOD,
            "/pkg.Service/Method",
        )],
    };
    let printed = format!("{grpc:?}");
    assert!(
        printed.contains("10.0.0.7:443") && printed.contains("/pkg.Service/Method"),
        "{printed}"
    );
}

/// The one-time placeholder's nonce IS the secret: it is the thing the encoded bytes must contain
/// exactly once, and a reader who has it has what the verb minted.
#[test]
fn a_one_time_placeholder_does_not_print_its_nonce() {
    // A REAL capability token, not a fixture seal: `Pass<Verify>` is one of the two
    // types this crate implements the sealed `KernelSeal` for (#65).
    fn seal() -> busbar_contract::caps::Pass<busbar_contract::caps::Verify> {
        busbar_contract::caps::Pass::mint(&busbar_contract::caps::KernelSeal::acquire_for_kernel())
    }

    let nonce = 0x0dd1_c0ff_ee15_dead_beef_cafe_f00d_1234_u128;
    let once = SecretOnce::mint(&seal(), nonce, "body.secret");
    let printed = format!("{once:?}");
    assert!(
        !printed.contains(&nonce.to_string()) && !printed.contains(&format!("{nonce:x}")),
        "a one-time placeholder printed its nonce: {printed}"
    );
    // What it DOES say: where the secret is allowed to appear, which is what a mismatch at the
    // encode step needs to be diagnosable.
    assert!(printed.contains("body.secret"), "{printed}");
    assert_eq!(once.nonce(), nonce);
}
