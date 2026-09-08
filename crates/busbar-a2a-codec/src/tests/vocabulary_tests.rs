// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE WIRE VOCABULARY, PINNED AGAINST THE SPECIFICATION RATHER THAN AGAINST ITSELF.
//!
//! `ERRORS`, `LOCAL_VERB_METHODS` and `mounted_route` are the three places this crate turns a
//! specification sentence into bytes, and none of them had a cell here. What that cost was plain:
//! deleting the MINUS SIGN from every row of `ERRORS` — turning `-32001` into `+32001`,
//! nine times over — changed nothing any test could see, and so did replacing `mounted_route`'s
//! whole body with the empty string. A sign that no test reads is a sign the wire can lose.
//!
//! THE SOURCE FOR THE NUMBERS IS NOT THIS CRATE. Every code below is transcribed from the pinned
//! conformance battery's own table, `testing/a2a-harness/a2aht/spec.py` (`ERROR_MAP`, SPEC 5.4
//! "Error Code Mappings", transcribed there from A2A tag v1.0.1). The rig is the source because a
//! table graded against a copy of itself proves only that the copy was faithful to the copy: the
//! whole hazard is that BOTH sides drift together. Writing the numbers out here, beside the
//! specification's own error NAMES, means a row that changes on either side has to be changed in
//! two files whose authors read different documents.

use crate::{mounted_route, MOUNT_PATH};
use crate::{
    ERRORS, ERROR_INFO_DOMAIN, ERROR_INFO_TYPE, LOCAL_VERB_METHODS, MOUNTED_ROUTE_SUFFIXES,
};

/// SPEC 5.4's mapping table, transcribed from `testing/a2a-harness/a2aht/spec.py::ERROR_MAP`, in
/// the specification's own order. The `reason` column is the `google.rpc.ErrorInfo.reason` token
/// this crate reports each code under.
const PINNED_SPEC_5_4: &[(&str, i64, &str)] = &[
    ("TaskNotFoundError", -32001, "TASK_NOT_FOUND"),
    ("TaskNotCancelableError", -32002, "TASK_NOT_CANCELABLE"),
    (
        "PushNotificationNotSupportedError",
        -32003,
        "PUSH_NOTIFICATION_NOT_SUPPORTED",
    ),
    ("UnsupportedOperationError", -32004, "UNSUPPORTED_OPERATION"),
    (
        "ContentTypeNotSupportedError",
        -32005,
        "CONTENT_TYPE_NOT_SUPPORTED",
    ),
    (
        "InvalidAgentResponseError",
        -32006,
        "INVALID_AGENT_RESPONSE",
    ),
    (
        "ExtendedAgentCardNotConfiguredError",
        -32007,
        "EXTENDED_AGENT_CARD_NOT_CONFIGURED",
    ),
    (
        "ExtensionSupportRequiredError",
        -32008,
        "EXTENSION_SUPPORT_REQUIRED",
    ),
    ("VersionNotSupportedError", -32009, "VERSION_NOT_SUPPORTED"),
];

/// EVERY ROW OF `ERRORS`, CODE AND REASON, AGAINST THE PINNED TABLE — IN ORDER, AND WITH NOTHING
/// LEFT OVER ON EITHER SIDE.
///
/// The length assertion is the half that makes the rest mean something: a per-row loop over a table
/// that lost its last row passes every comparison it makes.
#[test]
fn every_a2a_error_code_and_reason_matches_the_pinned_spec_table() {
    assert_eq!(
        ERRORS.len(),
        PINNED_SPEC_5_4.len(),
        "ERRORS has {} rows, SPEC 5.4 pins {} — a row was added or dropped on one side only",
        ERRORS.len(),
        PINNED_SPEC_5_4.len()
    );
    for (i, (spec_name, spec_code, spec_reason)) in PINNED_SPEC_5_4.iter().enumerate() {
        let (code, reason) = ERRORS[i];
        assert_eq!(
            code, *spec_code,
            "row {i} ({spec_name}): ERRORS says {code}, SPEC 5.4 pins {spec_code}"
        );
        assert_eq!(
            reason, *spec_reason,
            "row {i} ({spec_name}): ERRORS reports reason `{reason}`, this crate pins `{spec_reason}`"
        );
    }
}

/// THE SIGN, ON ITS OWN, AS A PROPERTY RATHER THAN AS NINE LITERALS.
///
/// JSON-RPC 2.0 section 5.1 reserves `-32768..=-32000` for pre-defined errors and A2A section 5.4
/// carves `-32001..=-32099` out of it for its own. A POSITIVE thirty-two-thousand is not a
/// near-miss — it is outside the reserved band entirely, so a peer would read it as an
/// implementation-defined code of somebody else's choosing rather than as the protocol's own.
/// Stated as a range check because the failure mode mutation found is a LOST SIGN, and a lost sign
/// is invisible to anything that only compares two numbers that were both written by the same hand.
#[test]
fn every_a2a_error_code_sits_in_the_protocols_reserved_negative_band() {
    for (code, reason) in ERRORS {
        assert!(
            *code < 0,
            "`{reason}` is {code}: a positive code is outside JSON-RPC's reserved band altogether"
        );
        assert!(
            (-32099..=-32001).contains(code),
            "`{reason}` is {code}, outside A2A section 5.4's -32001..=-32099 band"
        );
    }
}

/// No code is spelled twice, and no reason is either. A duplicated row is a condition an operator
/// cannot tell apart from the row it collides with — and it is exactly what a copy-paste edit to a
/// nine-row table produces.
#[test]
fn no_error_code_or_reason_is_used_for_two_conditions() {
    for (i, (code, reason)) in ERRORS.iter().enumerate() {
        for (other_code, other_reason) in &ERRORS[i + 1..] {
            assert_ne!(code, other_code, "code {code} appears twice in ERRORS");
            assert_ne!(
                reason, other_reason,
                "reason `{reason}` appears twice in ERRORS"
            );
        }
    }
}

/// The STANDARD JSON-RPC codes are deliberately ABSENT from `ERRORS` — the module's own header says
/// so, because the specification leaves their `reason` unset and inventing one would put a word on
/// the wire the specification does not define. That absence is load-bearing (the plane publishes
/// `ERRORS` as the set it may write, so a standard code smuggled in would be written with a
/// made-up reason), and nothing asserted it.
#[test]
fn the_standard_jsonrpc_codes_are_not_in_the_a2a_specific_table() {
    // SPEC 9.5, transcribed from `a2aht/spec.py::JSONRPC_STANDARD_ERRORS`.
    for standard in [-32700_i64, -32600, -32601, -32602, -32603] {
        assert!(
            !ERRORS.iter().any(|(code, _)| *code == standard),
            "standard JSON-RPC code {standard} is in the A2A-SPECIFIC table, where every row must \
             carry a reason the specification defines"
        );
    }
}

/// `mounted_route` is the one join both the served route and the plane's claim go through, so an
/// empty or constant answer makes every route on this plane collide at one path. Mutation replaced
/// its whole body with `String::new()` and with a fixed string and nothing noticed.
///
/// Asserted as the join's two OBSERVABLE properties — it starts at the mount and ends with the
/// suffix it was handed — over EVERY suffix the plane declares, so a ninth route added to
/// `MOUNTED_ROUTE_SUFFIXES` is covered the moment it is added.
#[test]
fn a_mounted_route_is_the_mount_joined_to_the_suffix_it_was_given() {
    assert!(
        !MOUNTED_ROUTE_SUFFIXES.is_empty(),
        "no suffixes to check — the loop below would assert nothing"
    );
    for suffix in MOUNTED_ROUTE_SUFFIXES {
        let route = mounted_route(suffix);
        assert_eq!(
            route,
            format!("{MOUNT_PATH}{suffix}"),
            "mounted_route({suffix}) is not the mount joined to the suffix"
        );
        assert!(
            route.starts_with(MOUNT_PATH),
            "mounted_route({suffix}) = `{route}` does not start at the plane's mount"
        );
        assert!(
            route.ends_with(suffix),
            "mounted_route({suffix}) = `{route}` dropped the suffix"
        );
        assert!(
            route.len() > MOUNT_PATH.len(),
            "mounted_route({suffix}) = `{route}` is the bare mount — every route would collide here"
        );
    }
}

/// Two different suffixes must not join to one route. This is what an empty-string body actually
/// COSTS, stated as the consequence rather than as the mechanism: the axum mount registers a
/// pattern twice and panics at startup, so the constant-body mutant is a boot failure, not a
/// cosmetic one.
#[test]
fn two_suffixes_never_join_to_the_same_mounted_route() {
    let routes: Vec<String> = MOUNTED_ROUTE_SUFFIXES
        .iter()
        .map(|s| mounted_route(s))
        .collect();
    for (i, route) in routes.iter().enumerate() {
        for other in &routes[i + 1..] {
            assert_ne!(
                route, other,
                "two suffixes join to `{route}` — a pattern registered twice is a startup panic"
            );
        }
    }
}

/// The local-verb table answers each operation in BOTH dialects: A2A v1.0 spells them
/// `PascalCase`, v0.3 spelled the same operations as slash-separated paths, and both are still
/// answered. So the list must pair up — an odd count, or a `PascalCase` name with no slash twin,
/// means one dialect silently stopped being answered for that operation.
#[test]
fn every_local_verb_is_answered_in_both_dialects() {
    let (pascal, slashed): (Vec<&str>, Vec<&str>) =
        LOCAL_VERB_METHODS.iter().partition(|m| !m.contains('/'));
    assert_eq!(
        pascal.len(),
        slashed.len(),
        "{} PascalCase names against {} slash-path names — one dialect lost an operation",
        pascal.len(),
        slashed.len()
    );
    assert!(!pascal.is_empty(), "no verbs at all");
    for method in LOCAL_VERB_METHODS {
        assert!(!method.is_empty(), "an empty method name is not a method");
    }
}

/// No method is listed twice. The server half dispatches over this list and the plane asserts it
/// carries a row for each; a duplicate makes one of those two counts wrong.
#[test]
fn no_local_verb_method_is_listed_twice() {
    for (i, method) in LOCAL_VERB_METHODS.iter().enumerate() {
        for other in &LOCAL_VERB_METHODS[i + 1..] {
            assert_ne!(
                method, other,
                "`{method}` is listed twice in LOCAL_VERB_METHODS"
            );
        }
    }
}

/// The `ErrorInfo` envelope's two fixed strings, which travel beside every code above. The `@type`
/// is the protobuf type URL SPEC 11.6 names and the domain is the protocol's own — busbar's own
/// domain here would claim these reason tokens are busbar's vocabulary rather than the
/// specification's.
#[test]
fn the_error_info_envelope_names_the_protocols_own_type_and_domain() {
    assert_eq!(ERROR_INFO_TYPE, "type.googleapis.com/google.rpc.ErrorInfo");
    assert_eq!(ERROR_INFO_DOMAIN, "a2a-protocol.org");
}
