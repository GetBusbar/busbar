// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MCP PLANE'S TEST-KIT — the fixture surface that names MCP plane types, kept ON THE PLANE, so
//! `busbar-core`'s neutral `test_support::TestApp` names none of them.
//!
//! Before the plane split, `TestApp` in busbar-core built the MCP resource/runtime itself (naming
//! `crate::mcp::*` back INTO core through the `#[path]` dual-compile). Now those builder methods live
//! here as an extension trait on the neutral `busbar_core::test_support::TestApp`, and they lower to
//! the real, externally-linked `busbar-mcp` crate through core's neutral install seams
//! (`install_plane_runtime`, `mount_plane`/`admit_plane`, `set_mcp_container_hooks`, `on_built`).
//!
//! The fluent chain (`TestApp::new().mcp(&cfg).mcp_server("s", def)…build()`) is preserved by
//! accumulating into a per-plane [`McpScratch`] stashed in `TestApp`'s type-erased scratch, plus ONE
//! finalizer that runs at the top of `build()` and turns that accumulation into a real plane.

use crate::mcp::client::catalogue::CatalogueCache;
use crate::mcp::config::{McpServerDefCfg, ToolsCfg};
use crate::mcp::{McpCfg, McpResource, McpRuntime};
use busbar_core::state::{App, MCP_RUNTIME_SLOT};
use busbar_core::test_support::TestApp;
use std::sync::Arc;

/// The MCP plane's key in `TestApp`'s scratch map — the same string as `PLANE_DECL.key`.
const SCRATCH_KEY: &str = "mcp";

/// The MCP plane's accumulated fixture state, mutated across the fluent builder chain and consumed
/// once by [`finalize`] at build time. Named only inside busbar-mcp.
#[derive(Default)]
pub(crate) struct McpScratch {
    /// Set by `.mcp(cfg)` — makes the built App an MCP SERVER (mounts the dispatch resource).
    mcp: Option<McpResource>,
    /// The `tools:` registrations + section hooks, accumulated by `.mcp_server(...)`/`.tools_hooks(...)`.
    tool_defs: ToolsCfg,
    /// The LIVE tool-list sightings the built App dispatches against (`.with_mcp_sightings(...)`).
    sightings: Option<Arc<CatalogueCache>>,
    /// Set once the finalizer is registered, so multiple builder calls register it only once.
    registered: bool,
}

/// Ensure the per-plane finalizer is registered exactly once, then hand back the mutable scratch for
/// this builder call to mutate.
fn scratch(app: &mut TestApp) -> &mut McpScratch {
    let needs_register = !app.plane_scratch::<McpScratch>(SCRATCH_KEY).registered;
    if needs_register {
        app.plane_scratch::<McpScratch>(SCRATCH_KEY).registered = true;
        app.register_plane_finalizer(Box::new(finalize));
    }
    app.plane_scratch::<McpScratch>(SCRATCH_KEY)
}

/// BUILD-TIME FINALIZER: consume the accumulated [`McpScratch`] and install the real MCP plane through
/// core's neutral seams. Mirrors what busbar-core's `TestApp::build` used to do inline.
fn finalize(app: &mut TestApp) {
    // Register this plane in the process registry the way production's composition root does, so the
    // fixture registry (config sections, cross-plane refusal, plane resolution) matches a shipped
    // "busbar with MCP" binary.
    busbar_core::plane::registry::register_test_plane(&crate::PLANE_DECL);
    let scratch = app.take_plane_scratch::<McpScratch>(SCRATCH_KEY);

    // THE MCP ENDPOINT (dispatch) resource, when `.mcp(cfg)` configured one. Mount + admission come
    // off the SAME resource the slot installs, so the router surface and the audience check agree.
    if let Some(resource) = scratch.mcp {
        let mount = resource.mount_path().to_string();
        let admission = resource.admission();
        app.install_plane_runtime(crate::PLANE_DECL.key, Arc::new(resource));
        app.mount_plane(
            crate::PLANE_DECL.key,
            &mount,
            busbar_core::plane::WIRE_JSONRPC,
        );
        app.admit_plane(crate::PLANE_DECL.key, admission);
    }

    // THE ALWAYS-PRESENT per-generation runtime bundle, the same home production `appbuild` gives it
    // under `MCP_RUNTIME_SLOT`. Built directly (not via `build_runtime`) so a fixture can still inject
    // its own `sightings`; the other five objects match production's `McpRuntime::build`.
    let runtime: Arc<dyn std::any::Any + Send + Sync> = Arc::new(McpRuntime {
        catalogue: Arc::new(crate::mcp::catalogue::Catalogue::build(&scratch.tool_defs)),
        servers: Arc::new(scratch.tool_defs.clone()),
        pool: Arc::new(crate::mcp::client::pool::McpConnectionPool::new()),
        sightings: scratch.sightings.clone().unwrap_or_default(),
        roots_epochs: Default::default(),
        sampling_spend: Default::default(),
        verify: Default::default(),
    });
    app.install_plane_runtime(MCP_RUNTIME_SLOT, runtime);

    // THE PER-SERVER HOOK SPECS as neutral strings — core resolves the gates against its own
    // hook_registry/hook_env through `resolve_container_gates`, exactly as production does.
    let containers: Vec<(String, Vec<String>)> = scratch
        .tool_defs
        .servers
        .iter()
        .map(|(n, d)| (n.clone(), d.hooks.clone()))
        .collect();
    app.set_mcp_container_hooks(containers, scratch.tool_defs.all_server_hooks.clone());

    // MIRROR boot's durable-MCP-trust REPLAY: after the App exists and its plane sinks are attached,
    // replay recorded demotions into the sightings cache. No-op when no durable store was attached.
    app.on_built(Box::new(|app: &Arc<App>| {
        crate::mcp::demotion::hydrate(&busbar_core::plane_host::engine_host(app));
    }));
}

/// The MCP plane's fixture builder methods, as an extension of the neutral `TestApp`. Every method
/// keeps the exact name/shape the in-core builders had, so the plane's own tests read unchanged aside
/// from a `use busbar_mcp::testkit::TestAppMcpExt;`.
pub trait TestAppMcpExt {
    /// Make the built App an MCP server, from the same `mcp:` config an operator writes. Validates
    /// (rather than accepting a pre-built resource) so a fixture can't mount a combination boot refuses.
    fn mcp(self, cfg: &McpCfg) -> Self;
    /// Register one `tools:` entry — one MCP server — through the SAME value validation the file path
    /// and the admin write path run.
    fn mcp_server(self, name: &str, def: McpServerDefCfg) -> Self;
    /// The reserved section-level `tools.hooks:` attach — the all-MCP hook list.
    fn tools_hooks(self, names: &[&str]) -> Self;
    /// Dispatch against these LIVE sightings — the cache a `connect`/refresh has published into.
    fn with_mcp_sightings(self, cache: Arc<CatalogueCache>) -> Self;
}

impl TestAppMcpExt for TestApp {
    fn mcp(mut self, cfg: &McpCfg) -> Self {
        let r = McpResource::from_cfg(cfg).expect("test mcp config must be valid");
        scratch(&mut self).mcp = Some(r);
        self
    }

    fn mcp_server(mut self, name: &str, def: McpServerDefCfg) -> Self {
        crate::mcp::config::validate_server(name, &def)
            .expect("test tools: entry must be valid config");
        scratch(&mut self)
            .tool_defs
            .servers
            .insert(name.to_string(), def);
        self
    }

    fn tools_hooks(mut self, names: &[&str]) -> Self {
        scratch(&mut self).tool_defs.all_server_hooks =
            names.iter().map(|n| (*n).to_string()).collect();
        self
    }

    fn with_mcp_sightings(mut self, cache: Arc<CatalogueCache>) -> Self {
        scratch(&mut self).sightings = Some(cache);
        self
    }
}

/// SEED every registered MCP server's verification clock as JUST CHECKED, WITHOUT a sighting, so
/// verify-on-call reuses the snapshot rather than re-fetching on the next `tools/call`. Relocated here
/// from busbar-core's `test_support` (it names `mcp::runtime`/`mcp::client` types).
pub fn prefresh_mcp_sightings(app: &App) {
    use crate::mcp::client::catalogue::ServerCatalogue;
    use crate::mcp::client::identity::ServerId;
    let now = busbar_substrate::store::now_ms();
    let servers: Vec<_> = crate::mcp::runtime(app)
        .catalogue
        .servers()
        .filter_map(|e| {
            ServerId::new(&e.id)
                .ok()
                .map(|sid| (sid, e.approval.clone()))
        })
        .collect();
    crate::mcp::runtime(app).sightings.apply(|map| {
        for (sid, approval) in servers {
            let entry = map
                .entry(sid.as_str().to_string())
                .or_insert_with(|| ServerCatalogue::seeded(sid.clone(), approval));
            entry.ledger.last_checked_ms = Some(now);
        }
    });
}
