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

    // THE AUDIT RESOURCE KIND is on the same footing, and for the same reason: it is the `kind`
    // half of every `kind:name` audit resource the plane's admin verbs record, and the prefix of
    // every action word. Two planes sharing one would make an audit query for one plane's history
    // answer with the other's.
    let mut audit: Vec<&str> = Plane::ALL.iter().map(|p| p.audit_kind()).collect();
    audit.sort_unstable();
    let before = audit.len();
    audit.dedup();
    assert_eq!(
        audit.len(),
        before,
        "two planes claim one audit resource kind"
    );

    // The operator-facing noun a `404` reads back. One rule serves every plane's not-found, so two
    // planes sharing a noun would produce a refusal that names the wrong registration.
    let mut nouns: Vec<&str> = Plane::ALL.iter().map(|p| p.subject_noun()).collect();
    nouns.sort_unstable();
    let before = nouns.len();
    nouns.dedup();
    assert_eq!(nouns.len(), before, "two planes claim one subject noun");
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

/// Today, and only as a consequence of the rule above. LLM has one because it translates between
/// the six dialects busbar speaks. MCP has exactly one wire format, so a "superset" there would be a
/// representation with one protocol on each side, which is a data model and not an intermediate
/// representation.
///
/// **A2A EARNED ONE WHEN ITS SECOND BINDING ARMED, and this line moving is the rule working rather
/// than a test being relaxed.** The threshold was written down before the binding existed, derived
/// from a list rather than from a `matches!`, precisely so that the promotion would fire MECHANICALLY
/// on the day the list grew and nobody would have to remember it was owed. HTTP+JSON is that day.
/// The promotion is not suppressed: it is what `Plane::A2a => &[WIRE_JSONRPC, WIRE_HTTP_JSON]` means.
#[test]
fn the_llm_and_a2a_planes_have_earned_an_ir_today() {
    assert!(Plane::Llm.has_superset_ir());
    assert!(!Plane::Mcp.has_superset_ir());
    assert!(
        Plane::A2a.has_superset_ir(),
        "A2A serves two bindings of one agent, which is the threshold, stated once and derived"
    );
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

/// The plane a path resolves to, the residual included. Built here, over the ONE resolver, so the
/// dispatch table below still reads as "path → plane" while every assertion in it exercises
/// `ingress_of` — the merged resolver is what production reads, and a test helper that read
/// anything else would be pinning a second answer.
fn plane_of(d: &PlaneDispatch, path: &str) -> Plane {
    match d.ingress_of(path) {
        Ingress::Mounted(plane) => plane,
        Ingress::Residual(_) => Plane::Llm,
    }
}

/// With no plane mounted, everything is LLM: the LLM ingress is the residual, exactly as the
/// protocol catch-all is today.
#[test]
fn with_nothing_mounted_every_path_is_the_llm_plane() {
    let d = PlaneDispatch::default();
    for path in ["/", "/v1/messages", "/mcp", "/a2a", "/pool/v1/messages"] {
        assert_eq!(plane_of(&d, path), Plane::Llm, "{path}");
    }
}

/// A mounted plane claims its mount AND everything under it, because an endpoint legitimately has
/// sub-paths. This is the one place a prefix match is correct, unlike an auth bypass.
#[test]
fn a_mounted_plane_claims_its_mount_and_everything_below_it() {
    let d = PlaneDispatch::default().mount(Plane::Mcp, "/mcp");
    assert_eq!(plane_of(&d, "/mcp"), Plane::Mcp);
    assert_eq!(plane_of(&d, "/mcp/"), Plane::Mcp);
    assert_eq!(plane_of(&d, "/mcp/tools/list"), Plane::Mcp);
}

/// THE SEGMENT-BOUNDARY RULE: a sibling path that merely shares a prefix is NOT the plane. A bare
/// `starts_with` would hand `/mcpx` to the MCP plane, which is the same class of over-match the
/// admin `/api` check already guards and the same class the core route-auth table refuses.
#[test]
fn a_prefix_sibling_is_not_the_plane() {
    let d = PlaneDispatch::default().mount(Plane::Mcp, "/mcp");
    for path in ["/mcpx", "/mcpx/tools", "/mc", "/xmcp", "/v1/mcp"] {
        assert_eq!(plane_of(&d, path), Plane::Llm, "{path} must not be MCP");
    }
}

/// Two planes mounted at once each claim their own, and neither claims the other's.
#[test]
fn two_mounted_planes_do_not_claim_each_other() {
    let d = PlaneDispatch::default()
        .mount(Plane::Mcp, "/mcp")
        .mount(Plane::A2a, "/a2a");
    assert_eq!(plane_of(&d, "/mcp/tools/list"), Plane::Mcp);
    assert_eq!(plane_of(&d, "/a2a/tasks/send"), Plane::A2a);
    assert_eq!(plane_of(&d, "/v1/messages"), Plane::Llm);
}

/// An UNMOUNTED plane claims nothing, so a deployment that never enabled MCP cannot have a request
/// routed onto the MCP plane by path shape alone. Fail-closed: a plane exists when it is configured,
/// not when its name appears in a URL.
#[test]
fn an_unmounted_plane_claims_nothing() {
    let d = PlaneDispatch::default().mount(Plane::A2a, "/a2a");
    assert_eq!(plane_of(&d, "/mcp"), Plane::Llm);
    assert_eq!(plane_of(&d, "/mcp/tools/list"), Plane::Llm);
}

/// A mount is normalised, so an operator writing `/mcp/` or `mcp` gets the same dispatch as `/mcp`.
/// The alternative is a deployment whose plane silently answers nothing because of a trailing slash.
#[test]
fn a_mount_is_normalised_before_it_is_matched() {
    for spelling in ["/mcp", "/mcp/", "mcp", "mcp/"] {
        let d = PlaneDispatch::default().mount(Plane::Mcp, spelling);
        assert_eq!(plane_of(&d, "/mcp"), Plane::Mcp, "spelling {spelling}");
        assert_eq!(
            plane_of(&d, "/mcp/tools/list"),
            Plane::Mcp,
            "spelling {spelling}"
        );
        assert_eq!(plane_of(&d, "/mcpx"), Plane::Llm, "spelling {spelling}");
    }
}

/// The LLM plane cannot be mounted: it IS the residual. Letting an operator mount it would create
/// two ways to reach the same plane and a precedence question with no good answer.
#[test]
fn the_llm_plane_cannot_be_mounted() {
    let d = PlaneDispatch::default().mount(Plane::Llm, "/llm");
    assert_eq!(
        plane_of(&d, "/llm"),
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

/// THE BOUNDARY RULE, stated over every plane rather than over the two that happen to satisfy it
/// today: a plane can be labelled at its door exactly when it speaks ONE wire format, and the two
/// halves of that sentence come from one list.
#[test]
fn a_plane_is_labellable_at_its_door_exactly_when_it_speaks_one_wire_format() {
    for p in Plane::ALL {
        assert_eq!(
            p.sole_wire_format().is_some(),
            p.wire_formats() == 1,
            "{p:?} disagrees with the rule: {} wire format(s) but sole_wire_format() == {:?}",
            p.wire_formats(),
            p.sole_wire_format()
        );
        assert_eq!(
            p.wire_formats(),
            p.wire_format_names().len(),
            "{p:?}'s count must be DERIVED from its name list, never a second literal"
        );
        assert!(
            !p.wire_format_names().is_empty(),
            "{p:?} claims no wire format at all, which is not a plane"
        );
    }
    // The consequence, spelled out because it is the reason `observe` needs no plane comparison:
    // the residual is the plane that cannot be labelled at a door, and it is also the only plane
    // that has no door.
    assert_eq!(Plane::Llm.sole_wire_format(), None);
    assert_eq!(Plane::Mcp.sole_wire_format(), Some("jsonrpc"));
    // AND A2A IS NOW THE SECOND PLANE THAT CANNOT BE LABELLED AT ITS DOOR. It has a door, and it
    // speaks two bindings through it, so `plane::observe` passes its traffic through unlabelled and
    // `a2a::ingress::invoke` emits the label itself with the leg the request actually arrived on.
    // That is the rule above doing what it was written for, not a plane losing its metrics.
    assert_eq!(Plane::A2a.sole_wire_format(), None);
}

/// EVERY MOUNTABLE PLANE'S DOOR SPEAKS JSON-RPC 2.0. `ingress::native` refuses on a mounted plane
/// with a JSON-RPC error object without asking WHICH plane, and this is the fact that makes that
/// correct. Pinned rather than assumed: the day a plane's door speaks something else, this test
/// fails and the shaping seam is told to grow an arm, instead of quietly answering that plane's
/// client in a dialect it does not speak — which is the whole failure this unit exists to close.
///
/// IT ASKS `shaping_wire_format`, NOT `sole_wire_format`, and the difference is the point. A2A now
/// speaks two bindings, so "which dialect DID speak" has no answer at the door — but an error body
/// still has to be some shape, and the shape is the plane's FIRST binding. The two questions were
/// answered by one function until the second binding armed, and reading the labelling question here
/// would have made every mounted refusal fall through to OpenAI's envelope.
#[test]
fn every_mounted_planes_door_dialect_is_jsonrpc() {
    for p in Plane::ALL.iter().copied().filter(|p| *p != Plane::Llm) {
        assert_eq!(
            Ingress::Mounted(p).shaping_wire_format(),
            Some(WIRE_JSONRPC),
            "{p:?} is mountable but its door does not speak JSON-RPC — `ingress::native`'s mounted \
             arm would mis-shape its refusals"
        );
        assert_eq!(
            crate::ingress::native::envelope_dialect(Ingress::Mounted(p)),
            WIRE_JSONRPC,
            "{p:?}'s door refusals must not fall through to a vendor envelope"
        );
    }
}

// ── THE MERGED RESOLVER ──────────────────────────────────────────────────────────────────────────

/// THE ORDER OF RESOLUTION, which is the whole of the merge: the MOUNT TABLE first, the path shape
/// only for what is left over. `/v1/chat/completions` names a dialect by shape and is still
/// residual; `/mcp` names none and is nevertheless claimed, because the operator mounted it.
#[test]
fn the_mount_table_is_read_before_the_path_shape() {
    let d = PlaneDispatch::default().mount(Plane::Mcp, "/mcp");
    assert_eq!(d.ingress_of("/mcp"), Ingress::Mounted(Plane::Mcp));
    assert_eq!(
        d.ingress_of("/mcp/tools/list"),
        Ingress::Mounted(Plane::Mcp)
    );
    assert_eq!(
        d.ingress_of("/v1/chat/completions"),
        Ingress::Residual(Some("openai"))
    );
    // The sibling: not the plane, and therefore resolved by shape like any other residual path.
    assert_eq!(d.ingress_of("/mcpx"), Ingress::Residual(None));
    // Nothing mounted there, so the path shape is all there is — and it names nothing.
    assert_eq!(d.ingress_of("/a2a"), Ingress::Residual(None));
}

/// A MOUNT CANNOT BE INFERRED FROM A URL. The same path, on a deployment that mounted nothing, is
/// an ordinary residual path — so the merge cannot have turned an unmounted plane into one that
/// claims paths by name.
#[test]
fn an_unmounted_plane_is_never_resolved_from_the_path() {
    let d = PlaneDispatch::default();
    for path in ["/mcp", "/mcp/tools/list", "/a2a", "/a2a/tasks/send"] {
        assert_eq!(
            d.ingress_of(path),
            Ingress::Residual(None),
            "{path} on a deployment with no plane mounted"
        );
    }
}

/// THE WIRE FORMAT a resolved ingress is labelled and answered in. A mounted plane's is its own —
/// never whichever LLM dialect its path happens to resemble — which is what keeps a metric label
/// and an error envelope from disagreeing about the same request.
#[test]
fn a_resolved_ingress_names_its_own_wire_format() {
    let d = PlaneDispatch::default().mount(Plane::Mcp, "/mcp");
    assert_eq!(d.ingress_of("/mcp").wire_format(), Some(WIRE_JSONRPC));
    assert_eq!(
        d.ingress_of("/v1/messages").wire_format(),
        Some("anthropic")
    );
    // No mount, no dialect: `None` is a real answer, and the reply's shape is decided elsewhere.
    assert_eq!(d.ingress_of("/stats").wire_format(), None);
    // A mount at a path that ALSO names an LLM dialect by shape: the mount wins, both for the
    // envelope and for the label. An operator who mounts a plane over an LLM surface has said which
    // one it is.
    let over = PlaneDispatch::default().mount(Plane::Mcp, "/v1/messages");
    assert_eq!(
        over.ingress_of("/v1/messages").wire_format(),
        Some(WIRE_JSONRPC)
    );
}

/// `mounted_plane_of` distinguishes the residual from a mounted plane, and agrees with the
/// resolver everywhere else — the two must never be able to name different planes for one path.
#[test]
fn only_a_mounted_plane_claims_a_path_and_the_two_readings_agree() {
    let d = PlaneDispatch::default()
        .mount(Plane::Mcp, "/mcp")
        .mount(Plane::A2a, "/a2a");
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
            d.mounted_plane_of(path).unwrap_or(Plane::Llm),
            plane_of(&d, path),
            "the two readings disagree about {path}"
        );
    }
    // The residual is `None`, which is what keeps the ingress boundary off the model plane without
    // a plane comparison. `/mcpx` is residual too: a sibling path inherits neither the plane's
    // grants nor its metrics.
    assert_eq!(d.mounted_plane_of("/v1/chat/completions"), None);
    assert_eq!(d.mounted_plane_of("/mcpx"), None);
    assert_eq!(d.mounted_plane_of("/metrics"), None);
    assert_eq!(d.mounted_plane_of("/mcp/tools"), Some(Plane::Mcp));
    assert_eq!(d.mounted_plane_of("/a2a/agents/planner"), Some(Plane::A2a));
    // Nothing mounted ⇒ nothing claimed, so a deployment that never enabled a plane cannot have a
    // request attributed to it.
    assert_eq!(PlaneDispatch::default().mounted_plane_of("/mcp"), None);
}
