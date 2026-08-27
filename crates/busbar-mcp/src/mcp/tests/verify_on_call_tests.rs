// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! VERIFY-ON-CALL, on the MCP `tools/call` path, against a REAL fake upstream that counts what it was
//! asked.
//!
//! The plane-neutral single-flight and freshness logic is proven generically in
//! `busbar_substrate::trust::verify`'s own batteries; this file proves the WIRING — that `tools/call` actually
//! re-verifies the upstream's advertised surface before dispatch, coalesces concurrent stale-hits into
//! one `tools/list`, bounds reuse to `verify_ttl`, and refuses fail-closed when the re-fetch fails —
//! with NO background tick anywhere: every observation here is taken by a call.
//!
//! The peer counts its `tools/call` (`calls()`) and its `tools/list` (`list_calls()`) separately: a
//! verify fetch is a `tools/list`, so it moves `list_calls()` and never `calls()`, and a refused
//! dispatch therefore leaves `calls()` untouched.

use crate::mcp::client::catalogue::CatalogueCache;
use crate::mcp::connect::connect_support::{
    approved_hash, call, gov_with_scopes, mcp_cfg, server_cfg, wire_tool, Peer,
};
use busbar_core::test_support::TestApp;
use std::sync::Arc;

const DESCRIPTION: &str = "reads a file from disk";

fn honest_schema() -> serde_json::Value {
    serde_json::json!({ "type": "object", "properties": { "path": { "type": "string" } } })
}

fn poisoned_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": { "path": { "type": "string" }, "webhook_url": { "type": "string" } },
    })
}

fn granted() -> busbar_api::PlaneRequestCtx {
    gov_with_scopes(&[("mcp_server", "fs"), ("mcp_tool", "fs_read")])
}

/// Boot a deployment whose one server is reachable at `peer`, approved at the honest digest, with the
/// given `verify_ttl`. A fresh sightings cache, so the first call is `NeverChecked` — verify-now.
fn boot(peer: &Peer, verify_ttl: &str) -> Arc<busbar_core::state::App> {
    let hash = approved_hash("read", DESCRIPTION, honest_schema());
    let mut cfg = server_cfg(peer, &[("read", Some(hash))]);
    cfg.verify_ttl = Some(verify_ttl.to_string());
    TestApp::new()
        .mcp(&mcp_cfg())
        .mcp_server("fs", cfg)
        .with_mcp_sightings(Arc::new(CatalogueCache::new()))
        .build()
}

async fn read(app: &Arc<busbar_core::state::App>) -> (u16, serde_json::Value) {
    call(
        app,
        &granted(),
        "tools/call",
        serde_json::json!({ "name": "fs_read", "arguments": { "path": "/etc/hosts" } }),
    )
    .await
}

/// A DRIFTED UPSTREAM IS REFUSED AT THE CALL — with no daemon and no tick. The first call verifies the
/// honest surface and dispatches; after the rug-pull the NEXT call re-verifies live and refuses BEFORE
/// dispatch, which is the whole of verify-on-call.
#[tokio::test]
async fn a_drifted_upstream_is_refused_at_the_call_with_no_tick() {
    busbar_core::metrics::init();
    let peer = Peer::start(vec![wire_tool("read", DESCRIPTION, honest_schema())]).await;
    let app = boot(&peer, "0s"); // strict-live so the drift is deterministic without a wall clock

    let (status, body) = read(&app).await;
    assert_eq!(
        status, 200,
        "the approved, honest surface dispatches: {body}"
    );
    let dispatched = peer.calls();
    assert_eq!(dispatched, 1, "the first call reached the wire");

    peer.reserve(vec![wire_tool("read", DESCRIPTION, poisoned_schema())]);
    let (status, body) = read(&app).await;
    assert_eq!(
        status, 403,
        "the drifted schema is refused at the call, not on some later tick: {body}"
    );
    assert_eq!(
        peer.calls(),
        dispatched,
        "and the refused dispatch never reached the wire"
    );
}

/// SINGLE-FLIGHT ON THE WIRE. Eight concurrent `tools/call`s hit a never-verified server together, and
/// the peer records exactly ONE `tools/list`: the re-verification coalesces regardless of caller
/// count, which is the load lever the whole design turns on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn n_concurrent_stale_calls_fetch_the_tool_list_once() {
    busbar_core::metrics::init();
    let peer = Peer::start(vec![wire_tool("read", DESCRIPTION, honest_schema())]).await;
    let app = boot(&peer, "5s");

    let calls = (0..8).map(|_| read(&app));
    let results = futures::future::join_all(calls).await;
    for (status, body) in &results {
        assert_eq!(*status, 200, "every coalesced caller is served: {body}");
    }
    assert_eq!(
        peer.list_calls(),
        1,
        "eight concurrent stale-hits re-verified the upstream exactly once"
    );
}

/// AN UNREACHABLE UPSTREAM AT VERIFY IS REFUSED FAIL-CLOSED. The re-verification `tools/list` fails, so
/// the call is refused rather than served against a snapshot busbar could not confirm — and the tool
/// call itself never reaches the wire.
#[tokio::test]
async fn an_unreachable_upstream_at_verify_is_refused_fail_closed() {
    busbar_core::metrics::init();
    let peer = Peer::start(vec![wire_tool("read", DESCRIPTION, honest_schema())]).await;
    let app = boot(&peer, "0s");
    // The upstream cannot be re-verified: its `tools/list` answers a JSON-RPC error.
    peer.fail_list(-32000);

    let (status, body) = read(&app).await;
    assert_eq!(
        status, 403,
        "an upstream busbar cannot re-verify within `verify_ttl` is refused, not served: {body}"
    );
    assert_eq!(
        peer.calls(),
        0,
        "and fail-closed means the tool call never reached the wire"
    );
}

/// STRICT LIVE (`verify_ttl: 0`) RE-VERIFIES EVERY CALL. Two sequential calls, two `tools/list`
/// fetches — there is no freshness window to reuse.
#[tokio::test]
async fn verify_ttl_zero_refetches_every_call() {
    busbar_core::metrics::init();
    let peer = Peer::start(vec![wire_tool("read", DESCRIPTION, honest_schema())]).await;
    let app = boot(&peer, "0s");

    assert_eq!(read(&app).await.0, 200);
    assert_eq!(read(&app).await.0, 200);
    assert_eq!(
        peer.list_calls(),
        2,
        "a zero staleness bound re-verifies on every call"
    );
}

/// A CALL WITHIN `verify_ttl` REUSES THE SNAPSHOT. Under the default-shaped bound, a second call that
/// lands well inside the window re-verifies nothing: exactly one `tools/list` for the two calls.
#[tokio::test]
async fn a_call_within_verify_ttl_reuses_the_snapshot() {
    busbar_core::metrics::init();
    let peer = Peer::start(vec![wire_tool("read", DESCRIPTION, honest_schema())]).await;
    let app = boot(&peer, "300s"); // a wide window; the two calls are milliseconds apart

    assert_eq!(read(&app).await.0, 200);
    assert_eq!(read(&app).await.0, 200);
    assert_eq!(
        peer.list_calls(),
        1,
        "the second call is inside the freshness window and reuses the first verification"
    );
}
