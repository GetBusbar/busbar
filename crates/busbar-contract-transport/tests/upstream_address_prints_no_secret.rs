// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The one secret-carrying field on an upstream address, and the rendering that is not allowed to
//! say it.
//!
//! `UpstreamAddress::Program` names the environment a child is spawned under, and an environment is
//! where a credential lives. Neither the `Debug` nor the serialization is derived for exactly that
//! reason — and neither was read back by a test, so a hand-rolled rendering that had drifted into
//! printing the values would have been a credential in every transport author's log line and every
//! configuration dump, with nothing failing.
//!
//! What the rendering MAY say is the shape: which names are set, and how long each value was. That
//! is what a reader needs to see that the child was spawned with the variables it was configured
//! with, and it is all they get.

use busbar_contract_transport::UpstreamAddress;

const TOKEN: &str = "sk-live-8f2b1c";

fn spawned() -> UpstreamAddress {
    UpstreamAddress::Program {
        path: "/usr/local/bin/mcp-server",
        args: &["--stdio", "--quiet"],
        env: &[
            ("MCP_API_TOKEN", TOKEN),
            ("HOME", "/var/empty"),
            ("EMPTY", ""),
        ],
    }
}

#[test]
fn a_spawned_programs_debug_says_which_names_are_set_and_never_a_value() {
    let rendered = format!("{:?}", spawned());

    assert!(
        !rendered.contains(TOKEN),
        "the environment's value reached a log line: {rendered}"
    );
    assert!(
        !rendered.contains("/var/empty"),
        "every value is withheld, not just the ones that look secret: {rendered}"
    );

    // What a reader is owed instead: the names, and the size of what sits behind each.
    assert!(rendered.contains("MCP_API_TOKEN"), "{rendered}");
    assert!(rendered.contains("HOME"), "{rendered}");
    assert!(
        rendered.contains(&format!("<{} bytes>", TOKEN.len())),
        "{rendered}"
    );
    assert!(rendered.contains("<0 bytes>"), "{rendered}");

    // And the rest of the arm, which carries nothing secret and is printed plainly.
    assert!(rendered.contains("Program"), "{rendered}");
    assert!(rendered.contains("/usr/local/bin/mcp-server"), "{rendered}");
    assert!(rendered.contains("--stdio"), "{rendered}");
}

#[test]
fn a_program_with_an_empty_environment_says_so_rather_than_saying_nothing() {
    // The posture a transport should default to: a child that inherits nothing. The rendering has to
    // distinguish "no variables" from "a rendering that stopped working".
    let bare = UpstreamAddress::Program {
        path: "/bin/true",
        args: &[],
        env: &[],
    };
    let rendered = format!("{bare:?}");
    assert!(rendered.contains("Program"), "{rendered}");
    assert!(rendered.contains("/bin/true"), "{rendered}");
    assert!(rendered.contains("env: []"), "{rendered}");
}

#[test]
fn the_socket_and_grpc_arms_print_the_facts_that_tell_a_dial_apart() {
    // Neither arm carries a secret, and both are read off a log line while a dial is failing: the
    // pinned address, the certificate name it is checked against, and — for the family whose wire
    // names every call by a path — the method.
    let socket = UpstreamAddress::Socket {
        authority: "10.0.0.7:443",
        sni: Some("api.example.com"),
    };
    let rendered = format!("{socket:?}");
    assert!(rendered.contains("Socket"), "{rendered}");
    assert!(rendered.contains("10.0.0.7:443"), "{rendered}");
    assert!(rendered.contains("api.example.com"), "{rendered}");

    // A pinned address with no name declared says so, rather than offering the address as the name.
    let unnamed = UpstreamAddress::socket("10.0.0.7:443");
    let rendered = format!("{unnamed:?}");
    assert!(rendered.contains("None"), "{rendered}");
    assert_eq!(UpstreamAddress::socket("10.0.0.7:443").sni(), None);

    let grpc = UpstreamAddress::Grpc {
        authority: "10.0.0.8:443",
        sni: None,
        method: "/busbar.Ledger/Settle",
    };
    let rendered = format!("{grpc:?}");
    assert!(rendered.contains("Grpc"), "{rendered}");
    assert!(rendered.contains("10.0.0.8:443"), "{rendered}");
    assert!(rendered.contains("/busbar.Ledger/Settle"), "{rendered}");
}
