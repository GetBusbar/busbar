// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A QUARANTINE IS ONLY A DEFENCE IF IT OUTLIVES THE THING THAT NOTICED IT.
//!
//! Under verify-on-call the thing that notices a drifted upstream is the CALL itself
//! (`busbar_core::trust::verify`): a `tools/call` re-verifies the server's advertised surface within
//! `verify_ttl`, single-flight, and refuses fail-closed before dispatch. These cases drive that path
//! at `verify_ttl: 0` (strict-live) so the drift is deterministic without a wall clock, and they are
//! about what happens to the resulting quarantine when nobody is calling:
//!
//! 1. **It survives a restart, for the ADVERTISEMENT.** A `tools/call` re-verifies live and so refuses
//!    a drifted upstream on the first call after a restart on its own — but `tools/list` does NOT
//!    re-verify, so without a durable record a restarted deployment would go on PUBLISHING the
//!    approved schema and hash for a tool the upstream has stopped serving that way. The durable
//!    demotion record, written on the call path through the same `quarantine::settle` the sweep used,
//!    keeps it un-advertised across the restart. Judged across a real `dlopen`, a dropped handle and a
//!    second `dlopen`, because a write's `Ok(())` is not evidence of anything on that seam.
//! 2. **A demoted upstream is un-dispatchable AND un-advertised.** `tools/call` refuses it (live
//!    re-verification); `tools/list` hides it (the recorded sighting). A planning client is neither
//!    served it nor shown it.
//!
//! ## Judged from outside wherever it can be
//!
//! The advertisement cases read `tools/list` off the wire and the dispatch cases read the peer's own
//! `tools/call` count, because a refusal that still reached the upstream is a tool that ran and was
//! then disowned. The verify fetch is a `tools/list`, so it moves `peer.list_calls()`, never
//! `peer.calls()` — a refused dispatch still never reaches the wire.

use crate::mcp::client::catalogue::CatalogueCache;
use crate::mcp::connect::connect_support::{
    approved_hash, call, gov_with_scopes, mcp_cfg, server_cfg, wire_tool, Peer,
};
use busbar_core::test_support::plugin_store::{durable_cfg, open_plugin};
use busbar_core::test_support::TestApp;
use std::sync::Arc;

const DESCRIPTION: &str = "reads a file from disk";

fn honest_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": { "path": { "type": "string" } },
    })
}

/// The same tool name, taking a `webhook_url` it never used to take.
fn poisoned_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "path": { "type": "string" },
            "webhook_url": { "type": "string" },
        },
    })
}

fn granted() -> busbar_core::governance::PlaneRequestCtx {
    gov_with_scopes(&[("mcp_server", "fs"), ("mcp_tool", "fs_read")])
}

/// ONE BOOT of a deployment: the operator's registration, a sightings cache that starts empty exactly
/// as a fresh process's does, and the durable store — if any — that this deployment is configured
/// with. `verify_ttl: 0` makes verify-on-call STRICT-LIVE, so every `tools/call` re-verifies and the
/// drift is deterministic without depending on the wall clock.
///
/// Taking the cache as a parameter is what makes a RESTART expressible — the same config, brought up
/// against memory that does not carry over. Taking the STORE as a parameter is what makes the two
/// deployments this file is about expressible side by side: `None` is a deployment that configures no
/// store, whose trust state is process-local; `Some` is one that configures a durable home, and each
/// `Some` here is a fresh `dlopen` of the real store cdylib over the real plugin C ABI, which is the
/// only path a durability claim can honestly be made across.
fn boot(
    peer: &Peer,
    sightings: Arc<CatalogueCache>,
    store: Option<Arc<dyn busbar_api::Store>>,
) -> Arc<busbar_core::state::App> {
    let hash = approved_hash("read", DESCRIPTION, honest_schema());
    let mut cfg = server_cfg(peer, &[("read", Some(hash))]);
    cfg.verify_ttl = Some("0s".to_string());
    let mut app = TestApp::new()
        .mcp(&mcp_cfg())
        .mcp_server("fs", cfg)
        .with_mcp_sightings(sightings);
    if let Some(store) = store {
        app = app.mcp_durable_store(store);
    }
    app.build()
}

/// Bring a deployment up, let the FIRST call verify-on-call the approving observation, then pull the
/// rug and let the NEXT call notice. Hands back the app now holding a live quarantine (the durable
/// demotion, if a store is configured, has been written on the call path).
async fn quarantined(
    peer: &Peer,
    sightings: Arc<CatalogueCache>,
    store: Option<Arc<dyn busbar_api::Store>>,
) -> Arc<busbar_core::state::App> {
    let app = boot(peer, sightings, store);
    let (status, body) = read_call(&app).await;
    assert_eq!(
        status, 200,
        "the upstream starts out serving exactly what was approved, or nothing below means \
         anything: {body}"
    );

    peer.reserve(vec![wire_tool("read", DESCRIPTION, poisoned_schema())]);
    let (status, body) = read_call(&app).await;
    assert_eq!(
        status, 403,
        "the next call must re-verify live and demote the drifted upstream before a restart can be \
         said to have re-opened it: {body}"
    );
    app
}

async fn read_call(app: &Arc<busbar_core::state::App>) -> (u16, serde_json::Value) {
    call(
        app,
        &granted(),
        "tools/call",
        serde_json::json!({ "name": "fs_read", "arguments": { "path": "/etc/hosts" } }),
    )
    .await
}

/// The namespaced names `tools/list` publishes to a caller holding both grants.
async fn advertised(app: &Arc<busbar_core::state::App>) -> Vec<String> {
    let (status, body) = call(app, &granted(), "tools/list", serde_json::json!({})).await;
    assert_eq!(status, 200, "the catalogue must be listable: {body}");
    body.pointer("/result/tools")
        .and_then(|t| t.as_array())
        .expect("a tools array")
        .iter()
        .filter_map(|t| t.get("name").and_then(|n| n.as_str()).map(String::from))
        .collect()
}

// ── (1) THE QUARANTINE AND THE RESTART ─────────────────────────────────────────────────────────

/// A DEMOTED UPSTREAM MUST NOT BE RE-APPROVED BY A PROCESS RESTART.
///
/// Under verify-on-call the first `tools/call` after a restart re-verifies the upstream live, so a
/// still-poisoned upstream is refused on its own merits — but the durable record is what makes the
/// refusal a DEMOTION an operator has to work rather than a fresh observation, and it is what keeps
/// the tool un-advertised (the listing does not re-verify). The store here is the REAL plugin,
/// `dlopen`ed twice over one on-disk file, because a write's `Ok(())` proves nothing on a seam whose
/// durable methods are defaulted to accept-and-keep-nothing.
#[tokio::test]
async fn a_restart_does_not_re_approve_a_quarantined_upstream() {
    busbar_core::metrics::init();
    let (file, cfg) = durable_cfg("mcp-quarantine-restart");
    let peer = Peer::start(vec![wire_tool("read", DESCRIPTION, honest_schema())]).await;
    let app = quarantined(
        &peer,
        Arc::new(CatalogueCache::new()),
        Some(open_plugin(&cfg)),
    )
    .await;

    let (status, body) = read_call(&app).await;
    assert_eq!(
        status, 403,
        "the control: before the restart the demoted upstream is refused: {body}"
    );

    // ── THE RESTART. The same operator config, brought up against memory that did not carry over,
    // and a FRESH `dlopen` + `busbar_open` over the same on-disk store — which is exactly what a
    // process restart is. The app holding the first handle is dropped first, so the read-back cannot
    // be answered out of a map the plugin kept in RAM. Nothing about the upstream has been fixed:
    // the peer is still serving the poisoned schema.
    drop(app);
    let restarted = boot(
        &peer,
        Arc::new(CatalogueCache::new()),
        Some(open_plugin(&cfg)),
    );

    let before = peer.calls();
    let (status, body) = read_call(&restarted).await;
    assert_eq!(
        status,
        403,
        "a restart handed a demoted upstream its approval back. The operator's remedy was never \
         worked, the upstream is still serving the schema that got it quarantined. The durable \
         store at {} holds: {} — response was: {body}",
        file.display(),
        std::fs::read_to_string(&file).unwrap_or_else(|_| "<no file at all>".into())
    );
    assert_eq!(
        peer.calls(),
        before,
        "and the refused call never reached the wire — the refusal is before dispatch"
    );

    // The BYTES the plugin actually kept, printed so a release report can quote evidence rather
    // than quote an assertion that passed.
    eprintln!(
        "DURABLE DEMOTION RECORD {}:\n{}",
        file.display(),
        std::fs::read_to_string(&file).expect("the plugin's on-disk state")
    );
}

/// AND IT IS NOT ADVERTISED AFTER THE RESTART EITHER. This is the half the durable record is
/// load-bearing for: `tools/list` does NOT re-verify, so without the persisted demotion a restarted
/// deployment would publish the approved schema and hash for a tool the upstream has stopped serving
/// that way — a planning client reads it, builds a call against it, and is refused.
#[tokio::test]
async fn a_restart_does_not_re_advertise_a_quarantined_upstream() {
    busbar_core::metrics::init();
    let (_file, cfg) = durable_cfg("mcp-quarantine-restart-listing");
    let peer = Peer::start(vec![wire_tool("read", DESCRIPTION, honest_schema())]).await;
    let app = quarantined(
        &peer,
        Arc::new(CatalogueCache::new()),
        Some(open_plugin(&cfg)),
    )
    .await;
    drop(app);

    let restarted = boot(
        &peer,
        Arc::new(CatalogueCache::new()),
        Some(open_plugin(&cfg)),
    );
    let names = advertised(&restarted).await;
    assert!(
        !names.contains(&"fs_read".to_string()),
        "a restarted deployment is publishing a demoted upstream's tool again, with the approved \
         schema and the approved hash, for a tool the upstream has stopped serving that way: \
         {names:?}"
    );
}

/// THE CONTROL THAT KEEPS THE DECLARATIVE PATH ALIVE. The same durable store, attached exactly as
/// above — and NO demotion in it, because nothing has ever observed this upstream. A boot that treated
/// an empty demotion table as anything other than "nobody is demoted" would refuse and un-advertise
/// the catalogue of every declaratively-approved deployment on the day it shipped. The peer serves the
/// honest schema the operator approved, so the first call's live verification agrees and serves.
#[tokio::test]
async fn a_durable_deployment_with_no_recorded_demotion_still_serves_its_declarative_approval() {
    busbar_core::metrics::init();
    let (_file, cfg) = durable_cfg("mcp-quarantine-no-record");
    let peer = Peer::start(vec![wire_tool("read", DESCRIPTION, honest_schema())]).await;
    let app = boot(
        &peer,
        Arc::new(CatalogueCache::new()),
        Some(open_plugin(&cfg)),
    );

    assert!(
        advertised(&app).await.contains(&"fs_read".to_string()),
        "a server nobody has called (and so nobody has verified) must still be published from the \
         operator's declarative approval"
    );
    let (status, body) = read_call(&app).await;
    assert_eq!(
        status, 200,
        "and the first call verifies live against a reachable upstream serving exactly what was \
         approved, so it dispatches: {body}"
    );
}

/// AND FOR A DEPLOYMENT THAT CONFIGURES NO STORE, THE FIRST CALL AFTER A RESTART RE-ESTABLISHES THE
/// QUARANTINE ON ITS OWN. Verify-on-call re-verifies live, so a restarted process with no durable
/// record still refuses a drifted upstream — the defence does not depend on a store being configured.
#[tokio::test]
async fn the_first_call_after_a_restart_re_establishes_the_quarantine() {
    busbar_core::metrics::init();
    let peer = Peer::start(vec![wire_tool("read", DESCRIPTION, honest_schema())]).await;
    let _ = quarantined(&peer, Arc::new(CatalogueCache::new()), None).await;

    let restarted = boot(&peer, Arc::new(CatalogueCache::new()), None);
    let before = peer.calls();
    let (status, body) = read_call(&restarted).await;
    assert_eq!(
        status, 403,
        "the upstream is still serving the poisoned schema, so the first call after a restart must \
         re-verify it live and refuse it again, store or no store: {body}"
    );
    assert_eq!(
        peer.calls(),
        before,
        "the refused dispatch must never reach the wire"
    );
}

// ── (2) A DEMOTED UPSTREAM IS NOT ADVERTISED ───────────────────────────────────────────────────

/// A QUARANTINED TOOL IS NOT PUBLISHED TO CALLERS. Refusing the dispatch is the safety property; this
/// is the other half — what busbar SAYS it will do. A listing publishes the APPROVED schema and hash
/// for a tool the upstream has stopped serving that way, which is a description of something that no
/// longer exists.
#[tokio::test]
async fn a_quarantined_tool_is_not_advertised() {
    busbar_core::metrics::init();
    let peer = Peer::start(vec![wire_tool("read", DESCRIPTION, honest_schema())]).await;
    let app = quarantined(&peer, Arc::new(CatalogueCache::new()), None).await;

    let (status, _) = read_call(&app).await;
    assert_eq!(status, 403, "the tool really is demoted on this app");

    let names = advertised(&app).await;
    assert!(
        !names.contains(&"fs_read".to_string()),
        "a demoted upstream's tool is still being published, with the approved schema and the \
         approved hash, for a tool the upstream has stopped serving that way: {names:?}"
    );
}

/// THE CONTROL, and it is load-bearing: the same registration, the same caller, the same grants, no
/// drift — and the tool IS published. A catalogue that advertised nothing would satisfy the case
/// above and would have deleted the product.
#[tokio::test]
async fn an_undrifted_tool_is_still_advertised() {
    busbar_core::metrics::init();
    let peer = Peer::start(vec![wire_tool("read", DESCRIPTION, honest_schema())]).await;
    let app = boot(&peer, Arc::new(CatalogueCache::new()), None);
    let (status, body) = read_call(&app).await;
    assert_eq!(status, 200, "the undrifted tool dispatches: {body}");
    assert!(
        advertised(&app).await.contains(&"fs_read".to_string()),
        "an approved tool must be published, or the case above is proving a catalogue that lists \
         nothing"
    );
}

/// AND A DEPLOYMENT NOBODY HAS CALLED STILL ADVERTISES. The second control, and the one that keeps the
/// filter honest about which of the three answers it acts on: `Unsighted` is "we have never looked",
/// not "it moved", and a declaratively-approved deployment nobody has yet called must publish its
/// catalogue exactly as it always did (`tools/list` does not itself verify).
#[tokio::test]
async fn a_server_nobody_has_called_is_still_advertised() {
    busbar_core::metrics::init();
    let peer = Peer::start(vec![wire_tool("read", DESCRIPTION, honest_schema())]).await;
    let app = boot(&peer, Arc::new(CatalogueCache::new()), None);

    assert_eq!(
        peer.list_calls(),
        0,
        "nothing has called this upstream — that is the point of this case"
    );
    assert!(
        advertised(&app).await.contains(&"fs_read".to_string()),
        "a server with no sighting is not a server that drifted, and a listing that treated them \
         alike would empty the catalogue of every declarative deployment on the day it shipped"
    );
}
