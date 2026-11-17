// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WP1-GAP-plane-sections r3 (adopted) §2.2, conditions A-C4 and B3.

use super::*;

use busbar_plugin_abi::plane::{tag as t, RouteRec, ROUTE_LINE};
use busbar_plugin_abi::types::KindCode;

const CORE: [&str; 4] = ["auth", "store", "export", "oauth_as"];

fn core(key: &str) -> bool {
    CORE.contains(&key)
}

#[test]
fn a_plane_answers_to_its_alias_else_its_identity() {
    let sections = plane_sections([("busbar-plane-mcp", "mcp"), ("acme-plane", "")], core)
        .expect("distinct instance names");
    assert_eq!(
        sections.identity_of_section("mcp"),
        Some("busbar-plane-mcp")
    );
    assert_eq!(
        sections.identity_of_section("acme-plane"),
        Some("acme-plane")
    );
    assert_eq!(
        sections.identity_of_section("busbar-plane-mcp"),
        None,
        "an aliased plane answers to its alias only"
    );
    assert_eq!(
        sections.identity_of_section("tools"),
        None,
        "a dev shape names no plane (rule R)"
    );
    assert_eq!(sections.names().collect::<Vec<_>>(), ["acme-plane", "mcp"]);
}

#[test]
fn two_planes_answering_one_instance_name_are_refused() {
    let refused = plane_sections([("one", "llm"), ("two", "llm")], core).unwrap_err();
    assert_eq!(
        refused.to_string(),
        "the plane images `one` and `two` both answer to the instance name `llm`; remove one"
    );
}

/// B3: the collision check compares the instance name and labels the field it compared.
#[test]
fn a_plane_named_like_a_core_section_is_refused_naming_the_compared_field() {
    let by_alias = plane_sections([("busbar-plane-x", "store")], core).unwrap_err();
    assert_eq!(
        by_alias.to_string(),
        "plane `busbar-plane-x`: its alias `store` names a core configuration section; a plane \
         instance may not take a core section's name"
    );
    let by_identity = plane_sections([("auth", "")], core).unwrap_err();
    assert_eq!(
        by_identity.to_string(),
        "plane `auth`: its identity `auth` names a core configuration section; a plane instance \
         may not take a core section's name"
    );
}

fn plane(routes: &[u32]) -> Described {
    use busbar_plugin_abi::records::{Records, Reply, Writer as _};
    let mut reply = Reply::new();
    for (i, flags) in routes.iter().enumerate() {
        let rec = RouteRec {
            route: i as u32 + 1,
            methods: 1,
            flags: *flags,
            auth: 1,
        };
        reply.put_pod_tail(t::D_ROUTE, &rec, b"/r").unwrap();
    }
    Described {
        kind: KindCode::Plane,
        methods: 0,
        facts: 0,
        items: Records::new(reply.as_bytes())
            .map(|rec| {
                let rec = rec.unwrap();
                (rec.tag, rec.body.to_vec())
            })
            .collect(),
        schema: None,
        metrics: Vec::new(),
        error_codes_refused: None,
    }
}

#[test]
fn a_line_route_is_read_from_the_admitted_describe() {
    assert!(declares_line_route(&plane(&[0, ROUTE_LINE])));
    assert!(!declares_line_route(&plane(&[0, 0])));
    let mut store = plane(&[ROUTE_LINE]);
    store.kind = KindCode::Store;
    assert!(!declares_line_route(&store), "only a plane serves lines");
}

/// A-C4: judged over the admitted planes, before any instance opens.
#[test]
fn stdio_binds_exactly_one_line_plane() {
    assert_eq!(stdio_instance([("llm", false), ("mcp", true)]), Ok("mcp"));
    assert_eq!(
        stdio_instance([("llm", false)]).unwrap_err().to_string(),
        "`--stdio`: no configured plane serves a line route"
    );
    assert_eq!(
        stdio_instance([("mcp", true), ("a2a", true)])
            .unwrap_err()
            .to_string(),
        "`--stdio`: several configured planes serve a line route: a2a, mcp"
    );
}
