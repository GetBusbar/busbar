// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What a secret-carrying ABI type says when something formats it.
//!
//! Every one of these is handed across the plugin ABI, so the code that might format it is code
//! this tree cannot see. The guarantee has to be the type's, not the caller's discipline.

use busbar_contract::{
    ArrivalLocation, Credential, KeyMaterial, SecretOnce, SecretValue, UpstreamAddress,
};

/// The environment a `stdio` child is spawned under is the node's credential hand-off: the whole
/// reason the arm names it rather than inheriting it is that inheriting it hands the child every
/// secret the node holds. Naming it puts those values inside an ABI type that the code formatting
/// it — a transport author's log line, a configuration dump — is code this tree cannot read.
#[test]
fn a_program_upstream_does_not_print_or_serialise_its_environment_values() {
    let a = UpstreamAddress::Program {
        path: "/usr/bin/mcp-server",
        args: &["--stdio"],
        env: &[("GITHUB_TOKEN", "ghp_live-SECRET")],
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
    assert!(printed.contains("/usr/bin/mcp-server"), "{printed}");

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
    };
    let printed = format!("{socket:?}");
    assert!(
        printed.contains("10.0.0.7:443") && printed.contains("api.example.com"),
        "{printed}"
    );

    let grpc = UpstreamAddress::Grpc {
        authority: "10.0.0.7:443",
        sni: None,
        method: "/pkg.Service/Method",
    };
    let printed = format!("{grpc:?}");
    assert!(
        printed.contains("10.0.0.7:443") && printed.contains("/pkg.Service/Method"),
        "{printed}"
    );
}

#[test]
fn a_credential_does_not_print_the_credential() {
    let c = Credential {
        location: ArrivalLocation::Header("authorization"),
        bytes: b"sk-live-SECRET".to_vec(),
    };
    let printed = format!("{c:?}");
    assert!(
        !printed.contains("SECRET"),
        "a credential printed its own bytes: {printed}"
    );
    assert!(!printed.contains("sk-live"), "{printed}");
    // What it DOES say: where the credential arrived and how long it was — enough to diagnose a
    // scheme that read the wrong header, and nothing a reader could present as the credential.
    assert!(printed.contains("authorization"), "{printed}");
    assert!(printed.contains("14"), "{printed}");
}

#[test]
fn a_resolved_secret_prints_exactly_the_redaction_and_nothing_else() {
    let s = SecretValue::new(b"sk-live-SECRET".to_vec());
    // The whole string, not a substring check: an assertion that the output merely lacks the word
    // SECRET keeps passing if the impl starts printing the length, the first bytes, or a hash of
    // them. What a resolved secret says is one fixed word.
    assert_eq!(format!("{s:?}"), "SecretValue(redacted)");
}

/// The one-time placeholder's nonce IS the secret: it is the thing the encoded bytes must contain
/// exactly once, and a reader who has it has what the verb minted.
#[test]
fn a_one_time_placeholder_does_not_print_its_nonce() {
    struct Verbs;
    impl busbar_contract::plugin::KernelSeal for Verbs {
        fn seal_origin(&self) -> &'static str {
            "test-verbs"
        }
    }

    let nonce = 0x0dd1_c0ff_ee15_dead_beef_cafe_f00d_1234_u128;
    let once = SecretOnce::mint(&Verbs, nonce, "body.secret");
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

#[test]
fn key_material_prints_how_much_and_how_old_but_not_what() {
    let k = KeyMaterial {
        bytes: b"signing-SECRET".to_vec(),
        fetched_at: 1_700_000_000,
    };
    let printed = format!("{k:?}");
    assert!(!printed.contains("SECRET"), "{printed}");
    assert!(
        !printed.contains("115"),
        "the raw bytes were printed: {printed}"
    );
    assert!(
        printed.contains("14") && printed.contains("1700000000"),
        "{printed}"
    );
}
