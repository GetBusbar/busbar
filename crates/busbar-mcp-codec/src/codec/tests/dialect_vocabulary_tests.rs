// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DIALECT'S OWN VOCABULARY — the error codes, the name-pointer rule and the two paths — read
//! by a test rather than only by the wire.
//!
//! Thirteen edits to this crate's error codes were all one sentence: **deleting
//! the minus sign from an error-code constant changed nothing any test could see.** `-32700`
//! became `+32700`, and so did `-32601`, `-32602`, `-32020`, `-32021`, `-32022`, `-32000`,
//! `-32030` and both retired codes. A JSON-RPC code is exactly the kind of value that reads
//! plausibly while being wrong: a peer receiving `32601` does not recognise "method not found", it
//! recognises nothing, and the client library's error branch for an unknown code is usually
//! "retry", which is the worst possible answer to a method that will never exist.
//!
//! THE SOURCE FOR THE NUMBERS IS THE CONFORMANCE BATTERY, NOT THIS FILE'S AUTHOR. Every code below
//! is transcribed from `testing/mcp-conformance/src/core/jsonrpc.mjs` (`ERR`,
//! `RETIRED_ERROR_CODES`, `SPEC_RESERVED_RANGE`), which the rig transcribes from the specification
//! itself. Grading a table against a second copy written by the same hand proves only that the hand
//! was consistent; the hazard is both copies drifting together, and a number that has to be changed
//! in a Rust file AND in a JavaScript file read by a different author is a number that does not
//! drift quietly.
//!
//! The rest of the file covers the survivors beside them: `name_source_of` (which `params` member
//! carries the name a request's `Mcp-Name` header must mirror), `protected_resource_metadata_path`
//! and the handler's two identity strings, each of which could be replaced with an empty or
//! constant answer without a single test objecting.

use super::*;

/// `testing/mcp-conformance/src/core/jsonrpc.mjs::ERR`, transcribed. Name as the rig spells it,
/// then the code, then this crate's constant.
const PINNED_RIG_ERR: &[(&str, i64, i64)] = &[
    ("PARSE_ERROR", -32700, CODE_PARSE_ERROR),
    ("INVALID_REQUEST", -32600, CODE_INVALID_REQUEST),
    ("METHOD_NOT_FOUND", -32601, CODE_METHOD_NOT_FOUND),
    ("INVALID_PARAMS", -32602, CODE_INVALID_PARAMS),
    ("INTERNAL_ERROR", -32603, CODE_INTERNAL),
    ("HEADER_MISMATCH", -32020, CODE_HEADER_MISMATCH),
    (
        "MISSING_REQUIRED_CLIENT_CAPABILITY",
        -32021,
        CODE_MISSING_CLIENT_CAPABILITY,
    ),
    (
        "UNSUPPORTED_PROTOCOL_VERSION",
        -32022,
        CODE_UNSUPPORTED_PROTOCOL_VERSION,
    ),
];

/// Every code this dialect shares with the rig, matched value for value. The rig's names are
/// carried into the failure message so a red here says WHICH specification row moved.
#[test]
fn every_shared_error_code_matches_the_conformance_rigs_pinned_table() {
    for (name, pinned, ours) in PINNED_RIG_ERR {
        assert_eq!(
            ours, pinned,
            "{name}: this crate says {ours}, the pinned rig table says {pinned}"
        );
    }
}

/// THE SIGN, AS A PROPERTY. This is the mutation that survived thirteen times over, and it is not
/// caught by comparing two numbers a single author wrote — it is caught by asserting the band the
/// specification puts them in. JSON-RPC 2.0 section 5.1 reserves `-32768..=-32000`; a positive
/// thirty-two-thousand is not in it, and is not a near-miss but a different namespace.
#[test]
fn every_code_this_dialect_defines_is_negative_and_inside_the_reserved_band() {
    assert!(!CODES.is_empty(), "no codes to check");
    for code in CODES {
        assert!(
            *code < 0,
            "{code} is positive — JSON-RPC reserves NEGATIVE codes"
        );
        assert!(
            (-32768..=-32000).contains(code),
            "{code} is outside JSON-RPC section 5.1's -32768..=-32000 reserved band"
        );
    }
    for code in RETIRED_CODES {
        assert!(
            *code < 0,
            "retired code {code} is positive — a retired code must still be recognisable as the \
             code it was, or the ban on emitting it cannot be checked"
        );
    }
}

/// The MCP-SPECIFIC codes sit in the sub-range the specification reserves for itself,
/// `SPEC_RESERVED_RANGE = [-32099, -32020]` in the rig. `CODE_REFUSED` is deliberately OUTSIDE it,
/// in JSON-RPC's implementation-defined server-error range, and that separation is the whole reason
/// it can coexist with codes the specification may add later.
///
/// `CODE_UPSTREAM_UNAVAILABLE` is NOT checked here, because it does not hold this property — see
/// [`the_upstream_unavailable_extension_is_recorded_as_sitting_in_the_reserved_sub_range`] below,
/// which records why and what it costs.
#[test]
fn the_spec_defined_codes_and_this_nodes_own_extensions_do_not_share_a_range() {
    let spec_reserved = -32099..=-32020;
    for code in [
        CODE_HEADER_MISMATCH,
        CODE_MISSING_CLIENT_CAPABILITY,
        CODE_UNSUPPORTED_PROTOCOL_VERSION,
    ] {
        assert!(
            spec_reserved.contains(&code),
            "{code} is a specification-defined code and must sit in -32099..=-32020"
        );
    }
    assert!(
        !spec_reserved.contains(&CODE_REFUSED),
        "CODE_REFUSED sits in the range the specification reserves for its OWN codes, where a \
         future specification code would collide with it"
    );
}

/// `CODE_UPSTREAM_UNAVAILABLE` IS INSIDE THE SPECIFICATION'S RESERVED SUB-RANGE, AND THE PINNED RIG
/// HAS A CHECK THAT SAYS SO.
///
/// `testing/mcp-conformance/src/core/jsonrpc.mjs` pins `SPEC_RESERVED_RANGE = [-32099, -32020]` and
/// `SPEC_DEFINED_CODES` as exactly three codes (`-32020`, `-32021`, `-32022`).
/// `src/suites/server-conformance.mjs:543-546` asserts `BASE.ERR.RESERVED-RANGE`: any error code a
/// probed method answers with that is inside that sub-range and NOT one of those three is a
/// conformance failure. `CODE_UPSTREAM_UNAVAILABLE` is `-32030` — inside the sub-range, not
/// spec-defined — so a probe that provokes an unreachable upstream fails that check. It is latent
/// only because the rig's current probe list does not reach an upstream-unavailable condition.
///
/// `CODE_REFUSED` shows the shape the fix takes: it is `-32000`, deliberately placed in JSON-RPC's
/// IMPLEMENTATION-DEFINED server-error range, and its own doc comment says it was put there
/// "because every reserved code is wrong for a specific reason". The same reasoning was not applied
/// to `-32030`.
///
/// THIS CELL DOES NOT ASSERT THE PLACEMENT IS CORRECT — it asserts the two facts that make the
/// hazard precise, so that the day the specification claims `-32030` this file goes red instead of
/// the wire going quiet. Moving the constant is a wire-visible change across the codec/plane seam
/// and is the owner's call, not this suite's.
#[test]
fn the_upstream_unavailable_extension_is_recorded_as_sitting_in_the_reserved_sub_range() {
    let spec_reserved = -32099..=-32020;
    assert!(
        spec_reserved.contains(&CODE_UPSTREAM_UNAVAILABLE),
        "CODE_UPSTREAM_UNAVAILABLE moved out of the specification's reserved sub-range — if that \
         was deliberate, this cell and the finding it records should be deleted"
    );
    // The three codes the rig pins as specification-defined. If the specification ever claims
    // -32030, this assertion goes red and the collision is a compile-time-adjacent fact rather
    // than a conformance run nobody happened to provoke.
    let spec_defined = [
        CODE_HEADER_MISMATCH,
        CODE_MISSING_CLIENT_CAPABILITY,
        CODE_UNSUPPORTED_PROTOCOL_VERSION,
    ];
    assert!(
        !spec_defined.contains(&CODE_UPSTREAM_UNAVAILABLE),
        "CODE_UPSTREAM_UNAVAILABLE now collides with a specification-defined code"
    );
}

/// `CODES` is the set the plane asserts it may write, so a code defined and left off the list is a
/// code the plane is not allowed to emit — and a duplicate makes two conditions indistinguishable.
#[test]
fn the_declared_code_set_holds_every_constant_exactly_once() {
    for code in [
        CODE_PARSE_ERROR,
        CODE_INVALID_REQUEST,
        CODE_METHOD_NOT_FOUND,
        CODE_INVALID_PARAMS,
        CODE_INTERNAL,
        CODE_HEADER_MISMATCH,
        CODE_MISSING_CLIENT_CAPABILITY,
        CODE_UNSUPPORTED_PROTOCOL_VERSION,
        CODE_REFUSED,
        CODE_UPSTREAM_UNAVAILABLE,
    ] {
        assert_eq!(
            CODES.iter().filter(|c| **c == code).count(),
            1,
            "{code} appears in CODES a number of times other than once"
        );
    }
    assert_eq!(
        CODES.len(),
        10,
        "CODES grew or shrank without this cell moving"
    );
}

/// A RETIRED code must never also be a LIVE one. The rig's clause is that a conformant node MUST
/// NOT emit `-32002` or `-32042`; if either drifted into `CODES` the node would be emitting a
/// meaning a peer still recognises and acts on — which the module header calls out as worse than an
/// unknown code.
#[test]
fn no_retired_code_is_also_a_code_this_dialect_may_write() {
    // `testing/mcp-conformance/src/core/jsonrpc.mjs::RETIRED_ERROR_CODES`.
    assert_eq!(RETIRED_CODES, &[-32002_i64, -32042][..]);
    for retired in RETIRED_CODES {
        assert!(
            !CODES.contains(retired),
            "{retired} is retired AND in the set this node may write"
        );
    }
}

/// WHICH `params` MEMBER CARRIES THE NAME, per method. Mutation could replace this whole function
/// with `None`, with `Some("")`, or with a constant — and could delete any of its three arms — and
/// nothing noticed.
///
/// The consequence is stated in the function's own header: the server half validates the `Mcp-Name`
/// mirror through this and the client half composes it through this. A method that stops reporting
/// its pointer sends a request with no `Mcp-Name` against a server that answers `-32020` to exactly
/// that; a method that reports the WRONG member mirrors the wrong value, which is the same `-32020`
/// with a more confusing log line.
#[test]
fn each_named_method_points_at_the_params_member_that_carries_its_name() {
    assert_eq!(name_source_of("tools/call"), Some("name"));
    assert_eq!(name_source_of("prompts/get"), Some("name"));
    assert_eq!(name_source_of("resources/read"), Some("uri"));
    assert_eq!(name_source_of("tasks/get"), Some("taskId"));
    assert_eq!(name_source_of("tasks/update"), Some("taskId"));
    assert_eq!(name_source_of("tasks/cancel"), Some("taskId"));
}

/// A method with no name pointer answers `None` — and `None` is not the same answer as `Some("")`.
/// An empty pointer would have the header composed against a member with no name, which mirrors
/// nothing and validates against nothing.
#[test]
fn a_method_with_no_name_pointer_answers_none_rather_than_an_empty_one() {
    for method in ["tools/list", "server/discover", "initialize", ""] {
        assert_eq!(
            name_source_of(method),
            None,
            "`{method}` reported a name pointer it does not have"
        );
    }
    for method in ["tools/call", "resources/read", "tasks/get"] {
        let pointer = name_source_of(method).expect("has a pointer");
        assert!(
            !pointer.is_empty(),
            "`{method}` points at an empty params member, which mirrors nothing"
        );
    }
}

/// THE PREFIX RULE THE FUNCTION'S HEADER REFUSES TO USE, asserted as the behaviour that refusal
/// buys. `tasks/result` was REMOVED by this revision. Under a `tasks/*` prefix rule it would report
/// a `taskId` pointer, the header check would fire first, and a request whose only defect is naming
/// a method that no longer exists would be answered `-32020` ("your headers are wrong") instead of
/// `-32601` ("no such method"). Nothing caught the `tasks/*` arm being deleted, or widened.
#[test]
fn a_removed_tasks_method_reports_no_name_pointer_so_it_can_answer_method_not_found() {
    for removed in ["tasks/result", "tasks/list"] {
        assert_eq!(
            name_source_of(removed),
            None,
            "`{removed}` was removed by this revision; reporting a name pointer for it makes a \
             -32601 come back as -32020"
        );
        assert!(
            !IMPLEMENTED_METHODS.contains(&removed),
            "`{removed}` is dispatched, which contradicts it having been removed"
        );
    }
}

/// Every method that reports a name pointer is a method this node actually dispatches. A pointer
/// for a method the node answers `-32601` to is a rule with nothing to apply it to; the reverse
/// (dispatched with no pointer) is legitimate and is not asserted.
#[test]
fn no_method_carries_a_name_pointer_without_being_dispatched() {
    for method in [
        "tools/call",
        "prompts/get",
        "resources/read",
        "tasks/get",
        "tasks/update",
        "tasks/cancel",
    ] {
        assert!(
            name_source_of(method).is_some(),
            "`{method}` lost its name pointer"
        );
        assert!(
            IMPLEMENTED_METHODS.contains(&method),
            "`{method}` carries a name pointer but is not dispatched"
        );
    }
}

/// RFC 9728 section 3.1 inserts the well-known segment between the origin and the resource's path,
/// so the metadata path is a FUNCTION OF THE MOUNT. Mutation replaced the function with the empty
/// string and with a constant: either makes an operator who moved the mount get a discovery
/// document at a path their resource is not at, which is an auth flow that silently cannot start.
#[test]
fn the_metadata_path_is_the_well_known_prefix_joined_to_the_mount_it_was_given() {
    assert_eq!(
        protected_resource_metadata_path(PATH_MCP),
        format!("{PROTECTED_RESOURCE_WELL_KNOWN}{PATH_MCP}")
    );
    // A MOVED mount is the case the function exists for, so it is the case that must be checked
    // with something other than the default.
    for mount in ["/mcp", "/tools/mcp", "/a"] {
        let path = protected_resource_metadata_path(mount);
        assert!(
            path.starts_with(PROTECTED_RESOURCE_WELL_KNOWN),
            "`{path}` does not begin at the RFC 9728 well-known prefix"
        );
        assert!(
            path.ends_with(mount),
            "`{path}` does not end at the mount `{mount}` it was derived from"
        );
        assert_ne!(
            path, PROTECTED_RESOURCE_WELL_KNOWN,
            "the mount `{mount}` was dropped — every mount would share one metadata path"
        );
    }
    // Two different mounts must not derive one metadata path, which is what a constant body does.
    assert_ne!(
        protected_resource_metadata_path("/mcp"),
        protected_resource_metadata_path("/other")
    );
}

/// The well-known prefix is the one RFC 9728 names, and the mount is the one the route table
/// serves. Both are absolute paths: a relative one would resolve against whatever the caller's
/// current path happened to be.
#[test]
fn the_two_paths_are_absolute_and_spelled_as_the_rfc_and_the_route_table_spell_them() {
    assert_eq!(
        PROTECTED_RESOURCE_WELL_KNOWN,
        "/.well-known/oauth-protected-resource"
    );
    assert_eq!(PATH_MCP, "/mcp");
    assert!(PROTECTED_RESOURCE_WELL_KNOWN.starts_with('/'));
    assert!(PATH_MCP.starts_with('/'));
}
