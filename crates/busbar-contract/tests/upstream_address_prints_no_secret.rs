// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The one secret-carrying field on an upstream address, and the rendering that is not allowed to

use busbar_contract::transport::registry::facts;
use busbar_contract::transport::UpstreamAddress;

const TOKEN: &str = "sk-live-8f2b1c";

fn spawned() -> UpstreamAddress {
    UpstreamAddress::Program {
        path: "/usr/local/bin/grid-server",
        args: &["--pipe", "--quiet"],
        env: &[
            ("GRID_API_TOKEN", TOKEN),
            ("HOME", "/var/empty"),
            ("EMPTY", ""),
        ],
        extras: &[],
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

    assert!(rendered.contains("GRID_API_TOKEN"), "{rendered}");
    assert!(rendered.contains("HOME"), "{rendered}");
    assert!(
        rendered.contains(&format!("<{} bytes>", TOKEN.len())),
        "{rendered}"
    );
    assert!(rendered.contains("<0 bytes>"), "{rendered}");

    assert!(rendered.contains("Program"), "{rendered}");
    assert!(
        rendered.contains("/usr/local/bin/grid-server"),
        "{rendered}"
    );
    assert!(rendered.contains("--pipe"), "{rendered}");
}

#[test]
fn a_program_with_an_empty_environment_says_so_rather_than_saying_nothing() {
    let bare = UpstreamAddress::Program {
        path: "/bin/true",
        args: &[],
        env: &[],
        extras: &[],
    };
    let rendered = format!("{bare:?}");
    assert!(rendered.contains("Program"), "{rendered}");
    assert!(rendered.contains("/bin/true"), "{rendered}");
    assert!(rendered.contains("env: []"), "{rendered}");
}

#[test]
fn the_socket_and_call_per_path_arms_print_the_facts_that_tell_a_dial_apart() {
    let socket = UpstreamAddress::Socket {
        authority: "10.0.0.7:443",
        sni: Some("api.example.com"),
        extras: &[],
    };
    let rendered = format!("{socket:?}");
    assert!(rendered.contains("Socket"), "{rendered}");
    assert!(rendered.contains("10.0.0.7:443"), "{rendered}");
    assert!(rendered.contains("api.example.com"), "{rendered}");

    let unnamed = UpstreamAddress::socket("10.0.0.7:443");
    let rendered = format!("{unnamed:?}");
    assert!(rendered.contains("None"), "{rendered}");
    assert_eq!(UpstreamAddress::socket("10.0.0.7:443").sni(), None);

    let per_path = UpstreamAddress::Socket {
        authority: "10.0.0.8:443",
        sni: None,
        extras: &[(facts::METHOD, "/busbar.Ledger/Settle")],
    };
    let rendered = format!("{per_path:?}");
    assert!(rendered.contains("Socket"), "{rendered}");
    assert!(rendered.contains("10.0.0.8:443"), "{rendered}");
    assert!(rendered.contains("/busbar.Ledger/Settle"), "{rendered}");
}
