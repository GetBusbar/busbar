// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plane spine: identity, the superset-IR rule, and plane dispatch.

use super::*;

/// Every plane is reachable from `ALL`, and `ALL` has no duplicates. The router, the config
/// validator and the candidate projection all iterate this, so a plane missing from it is a plane
/// that silently does not exist.
#[test]
fn all_is_complete_and_has_no_duplicates() {
    for p in [Plane::Llm, Plane::Mcp, Plane::A2a] {
        assert!(Plane::ALL.contains(&p), "{p:?} is missing from Plane::ALL");
    }
    let mut keys: Vec<&str> = Plane::ALL.iter().map(|p| p.key()).collect();
    let before = keys.len();
    keys.sort_unstable();
    keys.dedup();
    assert_eq!(keys.len(), before, "two planes share a key");
}

/// A plane's identity strings are all DISTINCT across planes. These are the strings that key config
/// sections, scope grants and audit resources; a collision would let one plane's grant admit
/// another plane's traffic, which is the whole thing the plane boundary exists to prevent.
#[test]
fn plane_identity_strings_never_collide_across_planes() {
    let mut sections: Vec<&str> = Plane::ALL.iter().map(|p| p.config_section()).collect();
    sections.sort_unstable();
    let before = sections.len();
    sections.dedup();
    assert_eq!(
        sections.len(),
        before,
        "two planes claim one config section"
    );

    let mut kinds: Vec<&str> = Plane::ALL
        .iter()
        .flat_map(|p| p.scope_kinds())
        .copied()
        .collect();
    kinds.sort_unstable();
    let before = kinds.len();
    kinds.dedup();
    assert_eq!(kinds.len(), before, "two planes claim one scope kind");
}

/// THE SUPERSET-IR RULE, computed rather than asserted per plane: a plane earns a superset IR when
/// it has TWO wire formats to translate between, and not before.
///
/// This is the whole content of `plane-layering.md`. Writing it as `matches!(self, Plane::Llm)`
/// would make it a fact about today's planes; writing it as the COUNT makes it a rule, so the day a
/// second dialect lands on some plane, that plane earns an IR and this test is what says so.
#[test]
fn a_plane_earns_a_superset_ir_at_two_wire_formats_and_not_before() {
    for p in Plane::ALL {
        assert_eq!(
            p.has_superset_ir(),
            p.wire_formats() >= 2,
            "{p:?} disagrees with the rule: {} wire format(s) but has_superset_ir() == {}",
            p.wire_formats(),
            p.has_superset_ir()
        );
    }
}

/// Today, and only as a consequence of the rule above: LLM has one because it translates between
/// the six dialects busbar speaks; MCP and A2A have exactly one wire format each, so a "superset"
/// there would be a representation with one protocol on each side, which is a data model and not an
/// intermediate representation.
#[test]
fn only_the_llm_plane_has_earned_an_ir_today() {
    assert!(Plane::Llm.has_superset_ir());
    assert!(!Plane::Mcp.has_superset_ir());
    assert!(!Plane::A2a.has_superset_ir());
}

/// The LLM plane's wire-format count is DERIVED from the real protocol registry, never a literal.
/// A seventh dialect must not require anyone to remember to bump a number here.
#[test]
fn the_llm_wire_format_count_comes_from_the_protocol_registry() {
    assert_eq!(
        Plane::Llm.wire_formats(),
        crate::proto::KNOWN_PROTOCOLS.len()
    );
    assert!(
        Plane::Llm.wire_formats() >= 2,
        "the registry itself is what earns the LLM plane its IR"
    );
}

/// A transport is NOT a wire format. MCP runs over stdio, streamable HTTP and SSE, and every one of
/// them carries the same JSON-RPC message shape. Counting transports would hand MCP an IR it has
/// not earned, and an IR with nothing to translate between is a lossless-translation bug waiting for
/// somewhere to happen.
#[test]
fn transports_do_not_count_as_wire_formats() {
    assert_eq!(
        Plane::Mcp.wire_formats(),
        1,
        "MCP has three transports and ONE wire format"
    );
}

// ── plane DISPATCH ───────────────────────────────────────────────────────────────────────────────

/// With no plane mounted, everything is LLM: the LLM ingress is the residual, exactly as the
/// protocol catch-all is today.
#[test]
fn with_nothing_mounted_every_path_is_the_llm_plane() {
    let d = PlaneDispatch::default();
    for path in ["/", "/v1/messages", "/mcp", "/a2a", "/pool/v1/messages"] {
        assert_eq!(d.plane_of(path), Plane::Llm, "{path}");
    }
}

/// A mounted plane claims its mount AND everything under it, because an endpoint legitimately has
/// sub-paths. This is the one place a prefix match is correct, unlike an auth bypass.
#[test]
fn a_mounted_plane_claims_its_mount_and_everything_below_it() {
    let d = PlaneDispatch::default().mount(Plane::Mcp, "/mcp");
    assert_eq!(d.plane_of("/mcp"), Plane::Mcp);
    assert_eq!(d.plane_of("/mcp/"), Plane::Mcp);
    assert_eq!(d.plane_of("/mcp/tools/list"), Plane::Mcp);
}

/// THE SEGMENT-BOUNDARY RULE: a sibling path that merely shares a prefix is NOT the plane. A bare
/// `starts_with` would hand `/mcpx` to the MCP plane, which is the same class of over-match the
/// admin `/api` check already guards and the same class the core route-auth table refuses.
#[test]
fn a_prefix_sibling_is_not_the_plane() {
    let d = PlaneDispatch::default().mount(Plane::Mcp, "/mcp");
    for path in ["/mcpx", "/mcpx/tools", "/mc", "/xmcp", "/v1/mcp"] {
        assert_eq!(d.plane_of(path), Plane::Llm, "{path} must not be MCP");
    }
}

/// Two planes mounted at once each claim their own, and neither claims the other's.
#[test]
fn two_mounted_planes_do_not_claim_each_other() {
    let d = PlaneDispatch::default()
        .mount(Plane::Mcp, "/mcp")
        .mount(Plane::A2a, "/a2a");
    assert_eq!(d.plane_of("/mcp/tools/list"), Plane::Mcp);
    assert_eq!(d.plane_of("/a2a/tasks/send"), Plane::A2a);
    assert_eq!(d.plane_of("/v1/messages"), Plane::Llm);
}

/// An UNMOUNTED plane claims nothing, so a deployment that never enabled MCP cannot have a request
/// routed onto the MCP plane by path shape alone. Fail-closed: a plane exists when it is configured,
/// not when its name appears in a URL.
#[test]
fn an_unmounted_plane_claims_nothing() {
    let d = PlaneDispatch::default().mount(Plane::A2a, "/a2a");
    assert_eq!(d.plane_of("/mcp"), Plane::Llm);
    assert_eq!(d.plane_of("/mcp/tools/list"), Plane::Llm);
}

/// A mount is normalised, so an operator writing `/mcp/` or `mcp` gets the same dispatch as `/mcp`.
/// The alternative is a deployment whose plane silently answers nothing because of a trailing slash.
#[test]
fn a_mount_is_normalised_before_it_is_matched() {
    for spelling in ["/mcp", "/mcp/", "mcp", "mcp/"] {
        let d = PlaneDispatch::default().mount(Plane::Mcp, spelling);
        assert_eq!(d.plane_of("/mcp"), Plane::Mcp, "spelling {spelling}");
        assert_eq!(
            d.plane_of("/mcp/tools/list"),
            Plane::Mcp,
            "spelling {spelling}"
        );
        assert_eq!(d.plane_of("/mcpx"), Plane::Llm, "spelling {spelling}");
    }
}

/// The LLM plane cannot be mounted: it IS the residual. Letting an operator mount it would create
/// two ways to reach the same plane and a precedence question with no good answer.
#[test]
fn the_llm_plane_cannot_be_mounted() {
    let d = PlaneDispatch::default().mount(Plane::Llm, "/llm");
    assert_eq!(
        d.plane_of("/llm"),
        Plane::Llm,
        "it is the residual anyway, so the mount is a no-op rather than a second door"
    );
    assert_eq!(d.mount_of(Plane::Llm), None);
}

/// A plane's mount is readable back, which is what lets the router mount the right handler and what
/// lets an inbound-audience check know its own canonical path.
#[test]
fn a_mount_is_readable_back() {
    let d = PlaneDispatch::default().mount(Plane::Mcp, "/mcp");
    assert_eq!(d.mount_of(Plane::Mcp), Some("/mcp"));
    assert_eq!(d.mount_of(Plane::A2a), None);
}
