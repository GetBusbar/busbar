// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The public metadata routes (COMPLIANCE M2, A2): the MCP plane's protected-resource metadata
//! (RFC 9728 section 3: `/.well-known/oauth-protected-resource` with the resource's path appended)
//! and the A2A plane's agent cards (`/.well-known/agent-card.json`, and one per agent). Each is a
//! plane route whose record admits nobody in particular (`AUTH_PUBLIC`), names no scope and moves
//! no money. Such a route is mounted with no verifier configured at all, is served under the
//! public authority alone (no chain, no key, no unit), and cannot reach a data route: its record
//! cannot carry scope, money, a credential header, a challenge or per-caller state, its class
//! cannot be shared with a principal, its path matches its metadata document and nothing beside
//! it, and a hook bound to it leaves it unmounted (OPEN-3 24, the parked default).

use busbar_contract::route::{path_matches, METHOD_GET, PATH_PATTERN};
use busbar_plugin_abi::plane::AUTH_PUBLIC;

use crate::auth::admission_table::{
    admission_of, decide, mounted, plan, Admission, Authority, BodyRead, Decision, Facts,
    JudgedAt, Offered, Step, Target, Verified, VerifyBy,
};
use crate::auth::native_data::NativeDataRoute;
use crate::auth::reference_plane;
use crate::auth::route_record::wire::{AdmissionItem, CALLERS_SHARED, MONEY_NONE, SCOPE_NONE};
use crate::auth::route_record::{
    CallerState, Money, RecordRefused, RouteClass, RouteRecord, Scope, Who,
};

/// The metadata routes the MCP and A2A planes declare, by pattern, each with a path it serves.
const METADATA: [(&str, &str); 3] = [
    (
        "/.well-known/oauth-protected-resource/mcp",
        "/.well-known/oauth-protected-resource/mcp",
    ),
    (
        "/.well-known/agent-card.json",
        "/.well-known/agent-card.json",
    ),
    (
        "/agents/{id}/.well-known/agent-card.json",
        "/agents/billing/.well-known/agent-card.json",
    ),
];

/// The record a metadata route states on the wire: public, scope none, money none, shared callers,
/// no credential header, no challenge.
fn metadata_record() -> RouteRecord {
    let none: [Box<str>; 0] = [];
    let item = AdmissionItem {
        route: 9,
        scope: SCOPE_NONE,
        money: MONEY_NONE,
        callers: CALLERS_SHARED,
        walk_kind: "",
    };
    RouteRecord::from_wire(0, AUTH_PUBLIC, None, &none, &item, None)
        .expect("a metadata route states a whole record")
}

/// The operator configured nothing a verifier needs: no auth instance reads any header, no ticket
/// store, no signature verifier, no upgrade transport, no public URL.
const NOTHING_OFFERED: Offered = Offered {
    verifier_reads_header: false,
    chain_yields_shared: false,
    upgrade_transport: false,
    ticket_store: false,
    signature_verifier: false,
    challenge_unresolved: false,
};

#[test]
fn public_metadata_routes_mount_with_no_verifier_and_serve_under_the_public_authority_alone() {
    let record = metadata_record();
    assert_eq!(
        record.validate(METHOD_GET, reference_plane::METHODS),
        Ok(())
    );
    assert_eq!(admission_of(&record), Admission::Public);
    assert_eq!(record.mounted_challenge(None), Ok(None));
    // Mounted where nothing at all is configured to verify a caller: discovery precedes any
    // credential (RFC 9728 section 3; A2A agent card discovery).
    assert_eq!(mounted(&record, NOTHING_OFFERED), Ok(Admission::Public));
    // The whole sequence: nobody is verified, no key policy, no scope, no limits, no money, and
    // the request is served under the public authority, never a data one.
    let sequence = plan(Admission::Public, record.money).expect("a public route is reachable");
    assert_eq!(sequence.verify, VerifyBy::Nobody);
    assert!(!sequence.policy);
    assert_eq!(sequence.scope, JudgedAt::Nowhere);
    assert_eq!(sequence.money, JudgedAt::Nowhere);
    assert!(!sequence.upgrade);
    assert_eq!(sequence.serves, Authority::Public);
    // Whatever a caller presents is not read, and it earns nothing: the answer is the public one.
    for presented in [false, true] {
        let mut facts = Facts::arrived(presented, presented);
        assert_eq!(decide(Target::Route(&record), &facts), Decision::Run(Step::Body));
        facts.body = Some(BodyRead::Taken);
        for verified in [None, Some(Verified::Identity { shared: false })] {
            facts.verified = verified;
            assert_eq!(
                decide(Target::Route(&record), &facts),
                Decision::Serve(Authority::Public)
            );
        }
    }
    // Each pattern serves its own metadata document.
    for (pattern, path) in METADATA {
        assert!(path_matches(PATH_PATTERN, pattern, path), "{pattern} {path}");
        assert!(path_matches(PATH_PATTERN, pattern, &format!("{path}/")), "{pattern}");
    }
}

#[test]
fn public_metadata_route_cannot_reach_a_data_route() {
    let public = || RouteRecord {
        class: RouteClass::Data,
        who: Who::PUBLIC,
        cred_header: None,
        challenge: None,
        scope: Scope::none(),
        scope_stated: true,
        money: Money::None,
        caller_state: CallerState::Shared,
    };
    let all = reference_plane::METHODS;
    // A public record that would carry anything a data route has refuses its plane.
    let mut keyed = public();
    keyed.who = Who::PUBLIC.with(Who::PRINCIPAL);
    let mut walked = public();
    walked.scope = Scope::walk("pool");
    let mut paid = public();
    paid.money = Money::Unit;
    let mut carrier = public();
    carrier.cred_header = Some("authorization".into());
    let mut challenged = public();
    challenged.challenge = Some("Bearer".into());
    let mut per_caller = public();
    per_caller.caller_state = CallerState::Distinct;
    for (what, record, refused) in [
        ("a key beside the public class", keyed, RecordRefused::Who),
        ("a scope to walk", walked, RecordRefused::OpenRouteCarriesScopeOrMoney),
        ("money", paid, RecordRefused::OpenRouteCarriesScopeOrMoney),
        ("a credential header", carrier, RecordRefused::CredHeader),
        ("a challenge", challenged, RecordRefused::Challenge),
        ("per-caller state", per_caller, RecordRefused::DistinctWithoutCaller),
    ] {
        assert_eq!(record.validate(METHOD_GET, all), Err(refused), "{what}");
    }
    // The public authority is never a data authority: no unit, no walk, no key.
    let sequence = plan(Admission::Public, Money::None).expect("reachable");
    assert!(!matches!(
        sequence.serves,
        Authority::Billed | Authority::Walk | Authority::Unbilled | Authority::Catalog
    ));
    // A metadata pattern matches its document and no path beside, under or above it: not the
    // planes' data routes, not a second segment where the agent id stands, not a traversal past
    // the document.
    let data_paths = [
        "/mcp",
        "/mcp/tools",
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/mcp/tools",
        "/.well-known/oauth-protected-resource/mcp/../../mcp",
        "/.well-known/agent-card.json/extra",
        "/agents/billing",
        "/agents/billing/v1/message:send",
        "/agents/billing/.well-known/agent-card.json/../../v1/message:send",
        "/agents/billing/tasks/.well-known/agent-card.json",
        "/agents/.well-known/agent-card.json",
        "/v1/message:send",
    ];
    for (pattern, _) in METADATA {
        for path in data_paths {
            assert!(
                !path_matches(PATH_PATTERN, pattern, path),
                "{pattern} must not match {path}"
            );
        }
    }
    // OPEN-3 24 (parked default): a hook bound to a public route leaves it unmounted; it is never
    // served unhooked, and no hook is called with no verified caller.
    assert!(NativeDataRoute::hooks_run(&metadata_record()).is_err());
}
