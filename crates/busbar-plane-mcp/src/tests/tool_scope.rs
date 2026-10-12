// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The scope a `token_exchange:` registration's token is asked for, pure: the caller's down-scope
//! over its `mcp_tool` grants on the member's server (a wildcard narrowing to the one tool called),
//! and the registration's approved set for the door's own fetch, each sorted and deduplicated.

use super::*;
use crate::catalogue::Catalogue;

/// Two servers, three approved tools on `fs` (one awaiting approval), one on `git`.
const SECTION: &str = r#"{
  "fs": {"url": "https://mcp.example/fs", "pin": {"mechanism": "unpinned"},
    "tools_allow": {
      "write_file": {"schema_hash": "sha256:bb"},
      "read_file": {"schema_hash": "sha256:aa"},
      "stat": {"schema_hash": "sha256:cc"},
      "draft": {}
    }},
  "git": {"url": "https://mcp.example/git", "pin": {"mechanism": "unpinned"},
    "tools_allow": {"log": {"schema_hash": "sha256:dd"}}}
}"#;

fn section() -> crate::tools_config::ToolsCfg {
    crate::door::read_tools_section(SECTION.as_bytes()).expect("the section reads")
}

/// THE CALLER'S DOWN-SCOPE: the tools its `mcp_tool` grants name on the member's server, never
/// another server's, never one it is not granted, sorted; a wildcard grant is exactly the tool
/// called, not everything the server offers; a caller granted nothing on the server asks for
/// nothing.
#[test]
fn the_down_scope_is_the_callers_grants_on_the_server_and_a_wildcard_is_the_one_tool() {
    let catalogue = Catalogue::build(1, &section());
    let granted = |names: &'static [&'static str]| move |n: &str| names.contains(&n);
    assert_eq!(
        caller_downscope(
            &catalogue,
            "fs",
            "fs_read_file",
            false,
            &granted(&["fs_write_file", "git_log", "fs_read_file"]),
        ),
        "fs_read_file fs_write_file"
    );
    assert_eq!(
        caller_downscope(&catalogue, "fs", "fs_read_file", true, &|_: &str| true),
        "fs_read_file",
        "a wildcard narrows to the tool called"
    );
    assert_eq!(
        caller_downscope(
            &catalogue,
            "fs",
            "fs_read_file",
            false,
            &granted(&["git_log"])
        ),
        ""
    );
}

/// THE DOOR'S OWN FETCH: every tool the registration approves at a digest, `{server}_{tool}`,
/// sorted; a tool awaiting approval is not asked for.
#[test]
fn the_registrations_scope_is_its_approved_tools() {
    let section = section();
    let fs = section.servers.get("fs").expect("fs");
    assert_eq!(
        registration_scope("fs", fs),
        "fs_read_file fs_stat fs_write_file"
    );
}
