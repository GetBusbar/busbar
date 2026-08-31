// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `{server}_{tool}` as the routing key: the separator ambiguity, and the round trip.

use crate::mcp::client::identity::{NameError, ServerId, ToolKey};

#[test]
fn a_server_id_containing_the_separator_is_refused() {
    let err = ServerId::new("file_system").expect_err("`_` in a server id must be refused");
    assert_eq!(err, NameError::ServerIdHasSeparator("file_system".into()));
    // The message has to say WHY, because an operator who reads "invalid" renames it to
    // `file__system` and reintroduces the ambiguity.
    let msg = err.to_string();
    assert!(
        msg.contains("mcp_tool"),
        "message must name the grant kind the ambiguity would corrupt: {msg}"
    );
    assert!(
        msg.contains("Use `-`"),
        "message must say what to type instead: {msg}"
    );
}

/// THE COLLISION THIS RULE EXISTS FOR. Without the refusal above, these two DIFFERENT tools render
/// the same namespaced name, and that name is the value of an `mcp_tool` grant.
#[test]
fn the_separator_rule_is_what_makes_two_different_tools_render_differently() {
    // `a_b` + `c` is unrepresentable: the server id is refused.
    assert!(ServerId::new("a_b").is_err());
    // So the only representable spelling of `a_b_c` is the one below, and parsing it recovers
    // exactly that pair rather than guessing between two readings.
    let parsed = ToolKey::parse("a_b_c").expect("`a` + `b_c` is representable");
    assert_eq!(parsed.server().as_str(), "a");
    assert_eq!(parsed.tool(), "b_c");
}

#[test]
fn a_tool_name_may_contain_the_separator_because_real_tools_do() {
    let k = ToolKey::new(ServerId::new("filesystem").unwrap(), "read_file").unwrap();
    assert_eq!(k.namespaced(), "filesystem_read_file");
    assert_eq!(ToolKey::parse("filesystem_read_file").unwrap(), k);
}

#[test]
fn namespaced_and_display_are_the_same_string() {
    // Two renderings of one value is one rendering too many when the value is compared for equality
    // against a scope grant.
    let k = ToolKey::new(ServerId::new("fs").unwrap(), "read").unwrap();
    assert_eq!(k.namespaced(), k.to_string());
}

#[test]
fn names_outside_the_legal_set_are_refused_on_both_axes() {
    for bad in ["fs server", "fs/server", "fs\"x", "fs\nx", "fs:x"] {
        assert!(
            matches!(ServerId::new(bad), Err(NameError::IllegalCharacter { .. })),
            "server id `{bad}` must be refused"
        );
    }
    let ok = ServerId::new("fs").unwrap();
    for bad in ["read file", "read/file", "read\"x"] {
        assert!(
            matches!(
                ToolKey::new(ok.clone(), bad),
                Err(NameError::IllegalCharacter { .. })
            ),
            "tool name `{bad}` must be refused"
        );
    }
}

#[test]
fn empty_names_are_refused() {
    assert_eq!(
        ServerId::new(""),
        Err(NameError::Empty { what: "server id" })
    );
    assert_eq!(
        ToolKey::new(ServerId::new("fs").unwrap(), ""),
        Err(NameError::Empty { what: "tool name" })
    );
}

#[test]
fn a_rendering_with_no_separator_does_not_parse() {
    // "fs" alone names a server, not a tool. Guessing "server fs, tool fs" would admit a grant
    // nobody wrote.
    assert!(ToolKey::parse("fs").is_err());
}

/// The parse is TOTAL over what it accepts: every key round-trips, including one whose tool name
/// carries several separators.
#[test]
fn every_constructible_key_round_trips() {
    let cases = [
        ("fs", "read"),
        ("fs", "read_file"),
        ("fs", "a_b_c_d"),
        ("my-server.v2", "x"),
    ];
    // A floor on the discovered set: an empty loop here would pass vacuously.
    assert_eq!(cases.len(), 4);
    for (s, t) in cases {
        let k = ToolKey::new(ServerId::new(s).unwrap(), t).unwrap();
        assert_eq!(
            ToolKey::parse(&k.namespaced()).unwrap(),
            k,
            "round trip {s}/{t}"
        );
    }
}
