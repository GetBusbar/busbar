// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE GENERATION RE-CHECK'S COARSENESS AND THE QUARANTINE'S PERSISTENCE.
//!
//! The pin generation is monotonic across the WHOLE cache, not per server, so an apply to one server
//! refuses an in-flight call selected against a completely different one — a spurious refusal by
//! design, because the safe direction is to retry rather than to let any caller pick a per-server
//! counter and miss the one that moved. And a quarantine is a standing fact about a DRIFT the
//! operator has to work: a later catalogue re-publish (a no-op apply, or a refresh that re-observes
//! the same drifted list) advances the generation but is not a re-approval, so the drifted server
//! stays refused until an operator acts.

use crate::mcp::client::catalogue::{CatalogueCache, TransportPin};
use crate::mcp::client::dispatch::{resolve, revalidate, DispatchRefusal};
use crate::mcp::client::support::{approved_server, key_wildcard, sid, simple_tool};
use crate::trust::TrustState;

/// AN UNRELATED SERVER'S APPLY BUMPS THE CACHE-WIDE GENERATION, refusing an in-flight call selected
/// against a different server. A control resolve on the post-bump snapshot proves the TARGET is
/// otherwise perfectly serviceable — the refusal is the coarse generation, nothing about the target.
#[test]
fn an_unrelated_apply_refuses_an_in_flight_call_against_another_server() {
    let cache = CatalogueCache::new();
    cache.apply(|servers| {
        servers.insert(
            "targetsrv".into(),
            approved_server("targetsrv", vec![simple_tool("read", "r")]),
        );
        servers.insert(
            "othersrv".into(),
            approved_server("othersrv", vec![simple_tool("query", "q")]),
        );
    });
    let caller = key_wildcard("k");

    let snapshot = cache.load();
    let resolved = resolve(&snapshot, "targetsrv_read", &caller).expect("resolves");
    // Nothing has moved yet: the in-flight call is valid.
    assert!(revalidate(&cache, &resolved, &caller).is_ok());

    // An operator touches a COMPLETELY DIFFERENT server. Any apply bumps the cache-wide generation.
    cache.apply(|servers| {
        servers
            .get_mut("othersrv")
            .unwrap()
            .approval
            .suspend("unrelated incident");
    });

    // The call selected under the old generation is refused, even though its own server never moved.
    let err = revalidate(&cache, &resolved, &caller)
        .expect_err("a cache-wide generation bump must refuse the in-flight call");
    assert_eq!(
        err,
        DispatchRefusal::GenerationMoved {
            selected: resolved.generation,
            live: resolved.generation + 1,
        }
    );

    // CONTROL: re-selecting the target against the fresh snapshot succeeds, and it is still Approved.
    // So the refusal above was purely the coarse generation, not any fault of the target itself.
    let fresh = cache.load();
    assert_eq!(
        fresh.server(&sid("targetsrv")).unwrap().state(),
        TrustState::Approved,
        "the unrelated apply must not have disturbed the target's trust state"
    );
    let reselected = resolve(&fresh, "targetsrv_read", &caller)
        .expect("the target re-resolves cleanly against the fresh snapshot");
    assert!(
        revalidate(&cache, &reselected, &caller).is_ok(),
        "a call re-selected under the live generation dispatches — the target is serviceable"
    );
}

/// A QUARANTINE SURVIVES LATER NO-OP APPLIES. Once a server has drifted, a catalogue re-publish is
/// NOT a re-approval: a plain no-op apply and a refresh that re-observes the same drifted list both
/// advance the generation but leave the server refused until an operator works the drift.
#[test]
fn a_quarantine_survives_a_later_catalogue_republish() {
    let cache = CatalogueCache::new();
    cache.apply(|servers| {
        servers.insert(
            "driftsrv".into(),
            approved_server("driftsrv", vec![simple_tool("read", "approved-desc")]),
        );
    });
    let caller = key_wildcard("k");

    // The server drifts: it re-serves `read` at a CHANGED description, so the digest moves off the
    // approved one. Same pin, so this is capability drift and derives `Quarantined`.
    let pin = TransportPin::cert_spki("sha256/driftsrv-pin");
    cache.apply(|servers| {
        servers
            .get_mut("driftsrv")
            .unwrap()
            .observe(Some(pin.clone()), vec![simple_tool("read", "DRIFTED-desc")]);
    });
    assert_eq!(
        cache.load().server(&sid("driftsrv")).unwrap().state(),
        TrustState::Quarantined,
        "a changed digest under the standing approval must quarantine the server"
    );
    let refused = resolve(&cache.load(), "driftsrv_read", &caller)
        .expect_err("a quarantined server serves nothing");
    assert_eq!(
        refused,
        DispatchRefusal::ServerNotApproved {
            server: "driftsrv".into(),
            state: TrustState::Quarantined,
        }
    );

    // Later catalogue re-publishes: a plain no-op apply, then a refresh that re-observes the SAME
    // drifted list. Each advances the generation. NONE of them is a re-approval.
    let gen_before = cache.generation();
    cache.apply(|_| {});
    cache.apply(|servers| {
        servers
            .get_mut("driftsrv")
            .unwrap()
            .observe(Some(pin.clone()), vec![simple_tool("read", "DRIFTED-desc")]);
    });
    assert!(
        cache.generation() >= gen_before + 2,
        "each re-publish advances the generation"
    );

    // The drifted server is STILL refused for the same reason — a re-publish did not re-approve it.
    assert_eq!(
        cache.load().server(&sid("driftsrv")).unwrap().state(),
        TrustState::Quarantined,
        "a catalogue re-publish is not a re-approval; the server stays quarantined"
    );
    assert_eq!(
        resolve(&cache.load(), "driftsrv_read", &caller)
            .expect_err("the drifted server stays refused across re-publishes"),
        DispatchRefusal::ServerNotApproved {
            server: "driftsrv".into(),
            state: TrustState::Quarantined,
        }
    );
}
