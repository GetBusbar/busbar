// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plane spine: identity, the superset-IR rule, and plane dispatch — proven on the REAL shipped
//! `[llm, mcp, a2a]` roster.
//!
//! Relocated here from `src/plane/tests/plane_tests.rs` (the A6/HostCtx dev-dependency-cycle
//! cleanup): every test hard-codes the literal keys `"llm"`/`"mcp"`/`"a2a"` and asserts against
//! their REAL declared wire formats (`wire_formats("llm") == busbar_kernel::proto::known_protocols()
//! .len()`, `has_superset_ir("a2a")`, …) — properties of the actual dialect/plane registries, not a
//! shape a neutral fake could stand in for. `register_planes()` below replaces the automatic
//! `#[cfg(test)]` seeding `TEST_BUILTIN_PLANE_DECLS` used to provide; every test calls it first
//! (idempotent, first-wins). A handful of `pub(crate)` items (`Ingress`, `PlaneDispatch::{ingress_of,
//! wire_format_of, mounted_plane_of}`, `sole_wire_format`, `has_superset_ir`, `sole_of`,
//! `superset_of`, `ingress::native::envelope_dialect`) were widened to `pub` for exactly this move.

use busbar_kernel::plane::{
    fallback_key, has_superset_ir, plane_decl, plane_keys, sole_of, sole_wire_format, superset_of,
    wire_format_names, wire_formats, Ingress, PlaneDispatch, WIRE_GRPC, WIRE_JSONRPC,
};

/// Register the real `[llm, mcp, a2a]` roster in the process registry — idempotent (first-wins), so
/// every test can call it unconditionally regardless of run order.
fn register_planes() {
    busbar_llm::testkit::install_test_seams();
    busbar_mcp::testkit::install_test_seams();
    busbar_a2a::testkit::install_test_seams();
}

/// WARM THE SHARED PROTOCOL REGISTRY. Reading `known_protocols()` once, up front, before any plane
/// helper reaches it, keeps the dialect list populated order-independently of whatever order the
/// harness runs tests in.
fn warm_shared_protocol_registry() {
    let _ = busbar_kernel::proto::known_protocols();
}

/// Every plane is reachable from `plane_keys()`, and it has no duplicates. The router, the config
/// validator and the candidate projection all iterate this, so a plane missing from it is a plane
/// that silently does not exist.
#[test]
fn all_is_complete_and_has_no_duplicates() {
    register_planes();
    let all: Vec<&'static str> = plane_keys().collect();
    for key in ["llm", "mcp", "a2a"] {
        assert!(all.contains(&key), "{key} is missing from plane_keys()");
    }
    let mut keys = all.clone();
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
    register_planes();
    let mut sections: Vec<&str> = plane_keys().map(|k| plane_decl(k).config_section).collect();
    sections.sort_unstable();
    let before = sections.len();
    sections.dedup();
    assert_eq!(
        sections.len(),
        before,
        "two planes claim one config section"
    );

    let mut kinds: Vec<&str> = plane_keys()
        .flat_map(|k| plane_decl(k).scope_kinds)
        .copied()
        .collect();
    kinds.sort_unstable();
    let before = kinds.len();
    kinds.dedup();
    assert_eq!(kinds.len(), before, "two planes claim one scope kind");

    let mut audit: Vec<&str> = plane_keys().map(|k| plane_decl(k).audit_kind).collect();
    audit.sort_unstable();
    let before = audit.len();
    audit.dedup();
    assert_eq!(
        audit.len(),
        before,
        "two planes claim one audit resource kind"
    );

    let mut nouns: Vec<&str> = plane_keys().map(|k| plane_decl(k).subject_noun).collect();
    nouns.sort_unstable();
    let before = nouns.len();
    nouns.dedup();
    assert_eq!(nouns.len(), before, "two planes claim one subject noun");
}

/// THE SUPERSET-IR RULE, computed rather than asserted per plane: a plane earns a superset IR when
/// it has TWO wire formats to translate between, and not before.
#[test]
fn a_plane_earns_a_superset_ir_at_two_wire_formats_and_not_before() {
    register_planes();
    for p in plane_keys() {
        assert_eq!(
            has_superset_ir(p),
            wire_formats(p) >= 2,
            "{p:?} disagrees with the rule: {} wire format(s) but has_superset_ir() == {}",
            wire_formats(p),
            has_superset_ir(p)
        );
    }
}

/// Today, and only as a consequence of the rule above, expressed on three example fixture planes.
#[test]
fn the_llm_and_a2a_planes_have_earned_an_ir_today() {
    register_planes();
    warm_shared_protocol_registry();
    assert!(has_superset_ir("llm"));
    assert!(!has_superset_ir("mcp"));
    assert!(
        has_superset_ir("a2a"),
        "A2A serves {:?} — bindings of ONE agent, and two of them is the threshold, stated once \
         and derived",
        wire_format_names("a2a")
    );
}

/// THE A2A LEGS' NAMES ARE THE A2A PLANE'S WIRE FORMATS, and this is the assertion that keeps the
/// two lists one vocabulary rather than two that happen to agree. The card a served agent publishes
/// spells its `protocolBinding` from the plane's list (`serve::servable_bindings` upper-cases it),
/// and the metric label an operator reads spells it from here. If these ever diverge, an operator
/// correlating a Prometheus series with a published binding is silently comparing two strings that
/// no longer describe the same leg.
///
/// Relocated from `src/tests/transport_tests.rs` (the "fix the 38" pass): it asserts real `a2a`
/// wire-format behaviour, so — like every other test in this file — it needs the real roster.
#[test]
fn the_a2a_legs_are_named_by_the_planes_wire_formats() {
    register_planes();
    use busbar_kernel::transport::Transport;
    let wires = wire_format_names("a2a");
    let legs: Vec<&str> = [Transport::JsonRpc, Transport::HttpJson, Transport::Grpc]
        .iter()
        .map(|t| t.name())
        .collect();
    assert_eq!(
        wires,
        legs.as_slice(),
        "the A2A plane's wire formats and the transports its legs ride must be one list"
    );
}

/// The fallback plane's wire-format count is DERIVED from the real protocol registry, never a
/// literal. An additional registered protocol must not require anyone to remember to bump a number
/// here.
#[test]
fn the_llm_wire_format_count_comes_from_the_protocol_registry() {
    register_planes();
    warm_shared_protocol_registry();
    assert_eq!(
        wire_formats("llm"),
        busbar_kernel::proto::known_protocols().len()
    );
    assert!(
        wire_formats("llm") >= 2,
        "the registry itself is what earns the LLM plane its IR"
    );
}

/// A transport is NOT a wire format: a plane can carry several transports for one wire format.
#[test]
fn transports_do_not_count_as_wire_formats() {
    register_planes();
    assert_eq!(
        wire_formats("mcp"),
        1,
        "MCP has three transports and ONE wire format"
    );
}

// ── plane DISPATCH ───────────────────────────────────────────────────────────────────────────────

/// The plane a path resolves to, the fallback included.
fn plane_of(d: &PlaneDispatch, path: &str) -> &'static str {
    match d.ingress_of(path) {
        Ingress::Mounted(key) => key,
        Ingress::Fallback(_) => fallback_key(),
    }
}

/// With no plane mounted, everything is LLM: the LLM ingress is the fallback, exactly as the
/// protocol catch-all is today.
#[test]
fn with_nothing_mounted_every_path_is_the_llm_plane() {
    register_planes();
    let d = PlaneDispatch::default();
    for path in ["/", "/v1/messages", "/mcp", "/a2a", "/pool/v1/messages"] {
        assert_eq!(plane_of(&d, path), "llm", "{path}");
    }
}

/// A mounted plane claims its mount AND everything under it, because an endpoint legitimately has
/// sub-paths.
#[test]
fn a_mounted_plane_claims_its_mount_and_everything_below_it() {
    register_planes();
    let d = PlaneDispatch::default().mount("mcp", "/mcp", WIRE_JSONRPC);
    assert_eq!(plane_of(&d, "/mcp"), "mcp");
    assert_eq!(plane_of(&d, "/mcp/"), "mcp");
    assert_eq!(plane_of(&d, "/mcp/tools/list"), "mcp");
}

/// THE SEGMENT-BOUNDARY RULE: a sibling path that merely shares a prefix is NOT the plane.
#[test]
fn a_prefix_sibling_is_not_the_plane() {
    register_planes();
    let d = PlaneDispatch::default().mount("mcp", "/mcp", WIRE_JSONRPC);
    for path in ["/mcpx", "/mcpx/tools", "/mc", "/xmcp", "/v1/mcp"] {
        assert_eq!(plane_of(&d, path), "llm", "{path} must not be MCP");
    }
}

/// Two planes mounted at once each claim their own, and neither claims the other's.
#[test]
fn two_mounted_planes_do_not_claim_each_other() {
    register_planes();
    let d = PlaneDispatch::default()
        .mount("mcp", "/mcp", WIRE_JSONRPC)
        .mount("a2a", "/a2a", WIRE_JSONRPC);
    assert_eq!(plane_of(&d, "/mcp/tools/list"), "mcp");
    assert_eq!(plane_of(&d, "/a2a/tasks/send"), "a2a");
    assert_eq!(plane_of(&d, "/v1/messages"), "llm");
}

/// An UNMOUNTED plane claims nothing, so a deployment that never enabled MCP cannot have a request
/// routed onto the MCP plane by path shape alone.
#[test]
fn an_unmounted_plane_claims_nothing() {
    register_planes();
    let d = PlaneDispatch::default().mount("a2a", "/a2a", WIRE_JSONRPC);
    assert_eq!(plane_of(&d, "/mcp"), "llm");
    assert_eq!(plane_of(&d, "/mcp/tools/list"), "llm");
}

/// A mount is normalised, so an operator writing `/mcp/` or `mcp` gets the same dispatch as `/mcp`.
#[test]
fn a_mount_is_normalised_before_it_is_matched() {
    register_planes();
    for spelling in ["/mcp", "/mcp/", "mcp", "mcp/"] {
        let d = PlaneDispatch::default().mount("mcp", spelling, WIRE_JSONRPC);
        assert_eq!(plane_of(&d, "/mcp"), "mcp", "spelling {spelling}");
        assert_eq!(
            plane_of(&d, "/mcp/tools/list"),
            "mcp",
            "spelling {spelling}"
        );
        assert_eq!(plane_of(&d, "/mcpx"), "llm", "spelling {spelling}");
    }
}

/// The LLM plane cannot be mounted: it IS the fallback.
#[test]
fn the_llm_plane_cannot_be_mounted() {
    register_planes();
    let d = PlaneDispatch::default().mount(fallback_key(), "/llm", WIRE_JSONRPC);
    assert_eq!(
        plane_of(&d, "/llm"),
        "llm",
        "it is the fallback anyway, so the mount is a no-op rather than a second door"
    );
    assert_eq!(d.mount_of(fallback_key()), None);
}

/// A plane's mount is readable back.
#[test]
fn a_mount_is_readable_back() {
    register_planes();
    let d = PlaneDispatch::default().mount("mcp", "/mcp", WIRE_JSONRPC);
    assert_eq!(d.mount_of("mcp"), Some("/mcp"));
    assert_eq!(d.mount_of("a2a"), None);
}

/// `sole_wire_format` ANSWERS EXACTLY WHEN THERE IS ONE ANSWER, stated over every plane.
#[test]
fn sole_wire_format_answers_exactly_when_a_plane_speaks_one() {
    register_planes();
    warm_shared_protocol_registry();
    for p in plane_keys() {
        assert_eq!(
            sole_wire_format(p).is_some(),
            wire_formats(p) == 1,
            "{p:?} disagrees with the rule: {} wire format(s) but sole_wire_format() == {:?}",
            wire_formats(p),
            sole_wire_format(p)
        );
        assert_eq!(
            wire_formats(p),
            wire_format_names(p).len(),
            "{p:?}'s count must be DERIVED from its name list, never a second literal"
        );
        assert!(
            !wire_format_names(p).is_empty(),
            "{p:?} claims no wire format at all, which is not a plane"
        );
    }
    assert_eq!(sole_wire_format("llm"), None);
    assert_eq!(sole_wire_format("mcp"), Some("jsonrpc"));
    assert_eq!(sole_wire_format("a2a"), None);
}

/// THE LABEL COMES OFF THE DOOR, WHICH IS WHY A SECOND BINDING DOES NOT SILENCE A PLANE.
#[test]
fn a_multi_binding_plane_is_still_labelled_at_the_door_that_was_knocked_on() {
    register_planes();
    let d = PlaneDispatch::default()
        .mount("a2a", "/a2a", WIRE_JSONRPC)
        .mount("a2a", "/lf.a2a.v1.A2AService", WIRE_GRPC);
    assert_eq!(d.mounted_plane_of("/a2a/agents/x"), Some("a2a"));
    assert_eq!(d.wire_format_of("/a2a/agents/x"), Some(WIRE_JSONRPC));
    assert_eq!(
        d.mounted_plane_of("/lf.a2a.v1.A2AService/SendMessage"),
        Some("a2a")
    );
    assert_eq!(
        d.wire_format_of("/lf.a2a.v1.A2AService/SendMessage"),
        Some(WIRE_GRPC)
    );
    assert_eq!(d.mount_of("a2a"), Some("/a2a"));
    assert_eq!(d.wire_format_of("/v1/chat/completions"), None);
}

/// A CLAIM MAY ONLY NAME A DIALECT ITS PLANE ADMITS TO SPEAKING.
#[test]
fn a_claim_only_names_a_wire_format_its_plane_speaks() {
    register_planes();
    for (plane, path, wire) in [
        ("mcp", "/mcp", WIRE_JSONRPC),
        ("a2a", busbar_a2a::a2a::serve::MOUNT_PATH, WIRE_JSONRPC),
        ("a2a", busbar_a2a::a2a::serve::GRPC_MOUNT_PATH, WIRE_GRPC),
    ] {
        assert!(
            wire_format_names(plane).contains(&wire),
            "{plane:?} is mounted at {path} speaking `{wire}`, which it does not declare: {:?}",
            wire_format_names(plane)
        );
    }
}

/// EVERY MOUNTABLE PLANE'S DOOR SHAPES ITS REFUSALS AS JSON-RPC 2.0.
#[test]
fn every_mounted_planes_door_dialect_is_jsonrpc() {
    register_planes();
    for p in plane_keys().filter(|p| *p != fallback_key()) {
        assert_eq!(
            Ingress::Mounted(p).shaping_wire_format(),
            Some(WIRE_JSONRPC),
            "{p:?} is mountable but its door does not speak JSON-RPC — `ingress::native`'s mounted \
             arm would mis-shape its refusals"
        );
        assert_eq!(
            wire_format_names(p).first(),
            Some(&WIRE_JSONRPC),
            "{p:?} is mountable and its canonical binding is not JSON-RPC"
        );
        assert_eq!(
            busbar_kernel::ingress::native::envelope_dialect(Ingress::Mounted(p)),
            WIRE_JSONRPC,
            "{p:?}'s door refusals must not fall through to a vendor envelope"
        );
    }
}

// ── THE MERGED RESOLVER ──────────────────────────────────────────────────────────────────────────

/// THE ORDER OF RESOLUTION, which is the whole of the merge: the MOUNT TABLE first, the path shape
/// only for what is left over.
#[test]
fn the_mount_table_is_read_before_the_path_shape() {
    register_planes();
    let d = PlaneDispatch::default().mount("mcp", "/mcp", WIRE_JSONRPC);
    assert_eq!(d.ingress_of("/mcp"), Ingress::Mounted("mcp"));
    assert_eq!(d.ingress_of("/mcp/tools/list"), Ingress::Mounted("mcp"));
    assert_eq!(
        d.ingress_of("/v1/chat/completions"),
        Ingress::Fallback(Some("openai"))
    );
    assert_eq!(d.ingress_of("/mcpx"), Ingress::Fallback(None));
    assert_eq!(d.ingress_of("/a2a"), Ingress::Fallback(None));
}

/// A MOUNT CANNOT BE INFERRED FROM A URL.
#[test]
fn an_unmounted_plane_is_never_resolved_from_the_path() {
    register_planes();
    let d = PlaneDispatch::default();
    for path in ["/mcp", "/mcp/tools/list", "/a2a", "/a2a/tasks/send"] {
        assert_eq!(
            d.ingress_of(path),
            Ingress::Fallback(None),
            "{path} on a deployment with no plane mounted"
        );
    }
}

/// THE WIRE FORMAT a resolved ingress is labelled and answered in.
#[test]
fn a_resolved_ingress_names_its_own_wire_format() {
    register_planes();
    let d = PlaneDispatch::default().mount("mcp", "/mcp", WIRE_JSONRPC);
    assert_eq!(d.ingress_of("/mcp").wire_format(), Some(WIRE_JSONRPC));
    assert_eq!(
        d.ingress_of("/v1/messages").wire_format(),
        Some("anthropic")
    );
    assert_eq!(d.ingress_of("/stats").wire_format(), None);
    let over = PlaneDispatch::default().mount("mcp", "/v1/messages", WIRE_JSONRPC);
    assert_eq!(
        over.ingress_of("/v1/messages").wire_format(),
        Some(WIRE_JSONRPC)
    );
}

/// `mounted_plane_of` distinguishes the fallback from a mounted plane, and agrees with the
/// resolver everywhere else.
#[test]
fn only_a_mounted_plane_claims_a_path_and_the_two_readings_agree() {
    register_planes();
    let d = PlaneDispatch::default()
        .mount("mcp", "/mcp", WIRE_JSONRPC)
        .mount("a2a", "/a2a", WIRE_JSONRPC);
    for path in [
        "/mcp",
        "/mcp/x",
        "/a2a",
        "/a2a/agents/planner",
        "/mcpx",
        "/v1/chat/completions",
        "/metrics",
        "/",
    ] {
        assert_eq!(
            d.mounted_plane_of(path).unwrap_or(fallback_key()),
            plane_of(&d, path),
            "the two readings disagree about {path}"
        );
    }
    assert_eq!(d.mounted_plane_of("/v1/chat/completions"), None);
    assert_eq!(d.mounted_plane_of("/mcpx"), None);
    assert_eq!(d.mounted_plane_of("/metrics"), None);
    assert_eq!(d.mounted_plane_of("/mcp/tools"), Some("mcp"));
    assert_eq!(d.mounted_plane_of("/a2a/agents/planner"), Some("a2a"));
    assert_eq!(PlaneDispatch::default().mounted_plane_of("/mcp"), None);
}

/// THE ZERO-DIALECT PLANE, pinned. Pure data — no registration needed.
#[test]
fn a_plane_with_zero_wire_formats_is_labelless_and_irless_by_decision() {
    assert_eq!(
        sole_of(&[]),
        None,
        "zero dialects: the ingress boundary has nothing to label a request with"
    );
    assert!(
        !superset_of(0),
        "zero wire formats have earned no superset IR (the threshold is two)"
    );
    assert_eq!(sole_of(&["jsonrpc"]), Some("jsonrpc"));
    assert_eq!(sole_of(&["a", "b"]), None);
    assert!(superset_of(2));
}

/// **The LLM plane's dialect list IS the registry's, so the empty case is the registry's empty case.**
#[test]
fn the_llm_planes_dialects_are_the_registrys_so_an_empty_registry_empties_the_plane() {
    register_planes();
    warm_shared_protocol_registry();
    assert_eq!(
        wire_format_names("llm"),
        busbar_kernel::proto::known_protocols(),
        "the LLM plane's wire formats must track the registry"
    );

    let empty = busbar_kernel::proto::registry::Registry::new(
        busbar_kernel::proto::registry::merged_boot_decls(&[], &[]),
    );
    let names: &'static [&'static str] = empty.codec_protocols();
    assert!(names.is_empty(), "premise: no declarations, no dialects");
    assert_eq!(
        sole_of(names),
        None,
        "a plane with no dialect has nothing to label a request with"
    );
    assert!(
        !superset_of(names.len()),
        "zero dialects have earned no superset IR (the threshold is two)"
    );
}
