// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! §14.2 — the per-request generation check, and the refusal ordering.
//!
//! The headline is the test §14.2 names verbatim: *a call whose candidate was resolved under pin
//! generation N is refused at dispatch when the live generation is N+1.* Under a stateless protocol
//! that is not a backstop to session invalidation — it is the defence.

use crate::mcp::client::catalogue::CatalogueCache;
use crate::mcp::client::dispatch::{resolve, revalidate, visible_catalogue, DispatchRefusal};
use crate::mcp::client::egress::EgressDenied;
use crate::mcp::client::support::{approved_server, key_wildcard, key_with_scopes, simple_tool};
use crate::trust::TrustState;
use busbar_api::ScopeRef;

fn seeded() -> CatalogueCache {
    let cache = CatalogueCache::new();
    cache.apply(|servers| {
        servers.insert(
            "fs".into(),
            approved_server(
                "fs",
                vec![simple_tool("read", "r"), simple_tool("write", "w")],
            ),
        );
    });
    cache
}

/// THE §14.2 TEST, in the exact shape the design states it.
#[test]
fn a_call_resolved_under_generation_n_is_refused_when_the_live_generation_is_n_plus_one() {
    let cache = seeded();
    let caller = key_wildcard("k");
    let snapshot = cache.load();
    let resolved = resolve(&snapshot, "fs_read", &caller).expect("resolves");
    assert_eq!(resolved.generation, cache.generation());
    // Still valid: nothing moved.
    assert!(revalidate(&cache, &resolved, &caller).is_ok());

    // The operator quarantines, de-approves, or simply refreshes. Any apply bumps the generation.
    cache.apply(|servers| {
        servers
            .get_mut("fs")
            .unwrap()
            .approval
            .suspend("incident 42");
    });

    let err = revalidate(&cache, &resolved, &caller)
        .expect_err("an in-flight call must not outlive the revocation");
    assert_eq!(
        err,
        DispatchRefusal::GenerationMoved {
            selected: resolved.generation,
            live: resolved.generation + 1
        }
    );
    assert!(
        err.to_string().contains("between selection and dispatch"),
        "the refusal must say when the change happened: {err}"
    );
}

/// The generation bumps on EVERY apply, including one that changes nothing. A no-op refresh costing
/// a retry is strictly better than a real revocation that forgot to bump.
#[test]
fn every_apply_bumps_the_generation_even_a_no_op_one() {
    let cache = seeded();
    let before = cache.generation();
    cache.apply(|_| {});
    assert_eq!(cache.generation(), before + 1);
    cache.apply(|_| {});
    assert_eq!(cache.generation(), before + 2);
}

/// Deregistering a server bumps the generation, which is what makes an already-resolved call fail
/// its re-validation rather than dispatching into a hole.
#[test]
fn a_snapshot_is_immutable_once_handed_out() {
    let cache = seeded();
    let old = cache.load();
    cache.apply(|servers| {
        servers.remove("fs");
    });
    // The old snapshot still has it — that is the whole point of read-copy-update — and the LIVE one
    // does not.
    assert!(old
        .server(&crate::mcp::client::support::sid("fs"))
        .is_some());
    assert!(cache
        .load()
        .server(&crate::mcp::client::support::sid("fs"))
        .is_none());
}

/// A KEY REVOCATION does not bump the catalogue generation, because the catalogue did not change.
/// The second half of `revalidate` is what catches it, and this test is why that half is not
/// redundant.
#[test]
fn a_narrowed_grant_is_caught_at_revalidation_even_though_the_catalogue_did_not_move() {
    let cache = seeded();
    let wide = key_with_scopes(
        "k",
        vec![ScopeRef::mcp_server("fs"), ScopeRef::mcp_tool("fs_read")],
    );
    let snapshot = cache.load();
    let resolved = resolve(&snapshot, "fs_read", &wide).expect("resolves under the wide grant");

    // The operator narrows the key. The catalogue is untouched, so the generation is unchanged.
    let narrowed = key_with_scopes("k", vec![ScopeRef::mcp_server("fs")]);
    assert_eq!(cache.generation(), resolved.generation);

    let err = revalidate(&cache, &resolved, &narrowed)
        .expect_err("a narrowed grant must bite at dispatch");
    assert_eq!(
        err,
        DispatchRefusal::Egress(EgressDenied::NoToolGrant {
            caller: "k".into(),
            tool: "fs_read".into()
        })
    );
}

/// THE HASH-PIN GATE IS A SEPARATE LAYER FROM THE TRUST STATE, and this is the case that shows it:
/// a REJECTED tool leaves the served set without putting the server into quarantine (a rejection is
/// a settled operator decision, not drift — §12.3). The server is `Approved`, the tool is still
/// observed, and dispatching to it must still be refused, by `Approval::serves` and by nothing else.
#[test]
fn a_rejected_tool_is_refused_at_dispatch_even_though_its_server_is_approved() {
    let cache = seeded();
    let caller = key_wildcard("k");
    cache.apply(|servers| {
        servers
            .get_mut("fs")
            .unwrap()
            .approval
            .reject_capability("write");
    });
    let snapshot = cache.load();
    assert_eq!(
        snapshot
            .server(&crate::mcp::client::support::sid("fs"))
            .unwrap()
            .state(),
        TrustState::Approved,
        "a rejection is not drift, so the server stays approved"
    );
    // The sibling tool still dispatches, so the refusal below is about the rejected tool and not
    // about the server having stopped working.
    assert!(resolve(&snapshot, "fs_read", &caller).is_ok());
    let err =
        resolve(&snapshot, "fs_write", &caller).expect_err("a rejected tool must not dispatch");
    assert!(
        matches!(err, DispatchRefusal::SchemaDrift { ref tool, .. } if tool == "fs_write"),
        "got {err:?}"
    );
}

/// REFUSAL ORDER: an ungranted caller learns it is ungranted, and nothing about the upstream's
/// current schema. A refusal that leaks what it is refusing access to has failed at half its job.
#[test]
fn the_grant_is_checked_before_the_tool_is_looked_up() {
    let cache = seeded();
    let ungranted = key_with_scopes("k", vec![]);
    let snapshot = cache.load();
    // The tool does not exist on this server — and the refusal is still about the GRANT, so the
    // caller cannot enumerate the upstream's tool list by watching which name gives which error.
    let err = resolve(&snapshot, "fs_does_not_exist", &ungranted).unwrap_err();
    assert!(matches!(err, DispatchRefusal::Egress(_)), "got {err:?}");
    // A granted caller asking for the same missing tool DOES learn it is missing, which is the
    // control proving the ordering above is doing something.
    let granted = key_wildcard("k2");
    assert_eq!(
        resolve(&snapshot, "fs_does_not_exist", &granted),
        Err(DispatchRefusal::UnknownTool("does_not_exist".into()))
    );
}

#[test]
fn an_unregistered_server_and_a_pending_one_refuse_differently() {
    let cache = seeded();
    cache.apply(|servers| {
        servers.insert(
            "pending".into(),
            crate::mcp::client::catalogue::ServerCatalogue::registered(
                crate::mcp::client::support::sid("pending"),
            ),
        );
    });
    let snapshot = cache.load();
    let caller = key_wildcard("k");
    assert_eq!(
        resolve(&snapshot, "nosuch_tool", &caller),
        Err(DispatchRefusal::UnknownServer("nosuch".into()))
    );
    assert_eq!(
        resolve(&snapshot, "pending_tool", &caller),
        Err(DispatchRefusal::ServerNotApproved {
            server: "pending".into(),
            state: TrustState::Pending
        })
    );
}

#[test]
fn a_malformed_namespaced_name_is_a_distinct_refusal() {
    let cache = seeded();
    let snapshot = cache.load();
    assert!(matches!(
        resolve(&snapshot, "noseparator", &key_wildcard("k")),
        Err(DispatchRefusal::MalformedName(_))
    ));
}

/// THE CATALOGUE FILTER IS AUTHORISATION (owner ruling 2): two grants see two different lists, and a
/// third sees none. Asserted here on the client side's own catalogue projection.
#[test]
fn two_grants_see_two_lists_and_a_third_sees_none() {
    let cache = CatalogueCache::new();
    cache.apply(|servers| {
        servers.insert(
            "fs".into(),
            approved_server(
                "fs",
                vec![simple_tool("read", "r"), simple_tool("write", "w")],
            ),
        );
        servers.insert(
            "db".into(),
            approved_server("db", vec![simple_tool("query", "q")]),
        );
    });
    let snapshot = cache.load();

    let reader = key_with_scopes(
        "reader",
        vec![ScopeRef::mcp_server("fs"), ScopeRef::mcp_tool("fs_read")],
    );
    let dba = key_with_scopes(
        "dba",
        vec![ScopeRef::mcp_server("db"), ScopeRef::mcp_tool("db_query")],
    );
    let nobody = key_with_scopes("nobody", vec![]);

    let names = |k| -> Vec<String> {
        visible_catalogue(&snapshot, k)
            .iter()
            .map(|b| b.key.namespaced())
            .collect()
    };
    assert_eq!(names(&reader), vec!["fs_read".to_string()]);
    assert_eq!(names(&dba), vec!["db_query".to_string()]);
    assert!(names(&nobody).is_empty());
    // A floor, so a catalogue that silently emptied would not make all three assertions pass.
    assert_eq!(names(&key_wildcard("root")).len(), 3);
}
