// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE KERNEL'S TABLES ARE THE ENGINE'S VIEW (status row 83, PR 4a; BUSBAR-1.6.0.md l.639, l.2577,
//! #7). The core's readers of the route tables (the keys and service-operations admin views,
//! `/v1/models`, the `/metrics` lane and pool gauges, the snapshot, group provisioning) read them
//! through [`EngineTablesView`]. Until this PR the llm door's row carried this crate's engine, so
//! they read [`NativeRuntime`](crate::engine::tables::NativeRuntime)'s view. From it on they read the
//! kernel's own [`ConfigTables`], built from the same resolved lanes and pools. Each of the view's
//! ten methods is pinned here to answer the same on the same configuration, BEFORE the engine view
//! is cut, so the comparison can fail.
//!
//! ORDER: both sides hold the pool and model tables in a `HashMap`, as 1.5.5's `App` did (v1.5.5
//! `crates/busbar/src/state.rs:258-260`), so neither `pools()` nor `model_indices()` has an order
//! of its own and every reader orders what it renders. Those two are compared as sets. Everything
//! that has an order (a pool's members, the lanes by index) is compared exactly.

use crate::engine::AppEngineExt as _;
use crate::test_support::{LaneSpec, TestApp};
use busbar_kernel::plane_host::{ConfigTables, EngineTablesView};
use std::collections::BTreeSet;

/// Three lanes on three dialects, a weighted pool that spills into a second one, and the spill pool.
fn app() -> std::sync::Arc<busbar_kernel::state::App> {
    crate::testkit::install_test_seams();
    TestApp::new()
        .lane(LaneSpec::new(
            "vp-model-a",
            crate::proto_codec::PROTO_OPENAI,
            "http://vp-a.test",
        ))
        .lane(LaneSpec::new(
            "vp-model-b",
            crate::proto_codec::PROTO_ANTHROPIC,
            "http://vp-b.test",
        ))
        .lane(LaneSpec::new(
            "vp-model-c",
            crate::proto_codec::PROTO_GEMINI,
            "http://vp-c.test",
        ))
        .pool("vp-main", &[(0, 3), (1, 1)])
        .fallback_pool("vp-spill", &[(2, 1)])
        .on_exhausted(
            "vp-main",
            busbar_kernel::config::pools::OnExhausted::FallbackPool("vp-spill".into()),
        )
        .build()
}

const POOLS: &[&str] = &["vp-main", "vp-spill", "vp-absent"];
const MODELS: &[&str] = &["vp-model-a", "vp-model-b", "vp-model-c", "vp-model-absent"];

/// The view's ten methods that disagree between `a` and `b`, by name. Empty = the same view.
fn differing(a: &dyn EngineTablesView, b: &dyn EngineTablesView) -> Vec<&'static str> {
    let mut out = Vec::new();
    let pools = |v: &dyn EngineTablesView| -> BTreeSet<(String, Vec<usize>)> {
        v.pools()
            .into_iter()
            .map(|(name, members)| (name.to_string(), members))
            .collect()
    };
    if pools(a) != pools(b) {
        out.push("pools");
    }
    if POOLS.iter().any(|p| a.pool_exists(p) != b.pool_exists(p)) {
        out.push("pool_exists");
    }
    let models = |v: &dyn EngineTablesView| -> BTreeSet<(String, usize)> {
        v.model_indices()
            .into_iter()
            .map(|(m, i)| (m.to_string(), i))
            .collect()
    };
    if models(a) != models(b) {
        out.push("model_indices");
    }
    if MODELS.iter().any(|m| a.model_index(m) != b.model_index(m)) {
        out.push("model_index");
    }
    let lane = |v: &dyn EngineTablesView, i: usize| {
        v.lane_view(i).map(|l| {
            (
                l.model.to_string(),
                l.provider.to_string(),
                l.base_url.to_string(),
            )
        })
    };
    if (0..=a.lane_count().max(b.lane_count())).any(|i| lane(a, i) != lane(b, i)) {
        out.push("lane_view");
    }
    if a.lane_count() != b.lane_count() {
        out.push("lane_count");
    }
    if POOLS.iter().any(|p| a.pool_members(p) != b.pool_members(p)) {
        out.push("pool_members");
    }
    if POOLS.iter().any(|p| a.queued_depth(p) != b.queued_depth(p)) {
        out.push("queued_depth");
    }
    if POOLS
        .iter()
        .any(|p| a.on_exhausted_fallback(p) != b.on_exhausted_fallback(p))
    {
        out.push("on_exhausted_fallback");
    }
    if a.upstream_creds() != b.upstream_creds() {
        out.push("upstream_creds");
    }
    out
}

/// The engine's view and the kernel's tables of one built `App`, checked to be TWO objects: with
/// the engine absent the view falls back to the kernel's tables, and the comparison would be a
/// table compared with itself.
fn both(app: &busbar_kernel::state::App) -> (&dyn EngineTablesView, &ConfigTables) {
    let engine = app.engine_tables_view();
    let kernel: &ConfigTables = &app.config_tables;
    assert!(
        !std::ptr::eq(
            engine as *const dyn EngineTablesView as *const u8,
            kernel as *const ConfigTables as *const u8
        ),
        "the engine's view is the kernel's tables already: nothing would be compared"
    );
    (engine, kernel)
}

/// The one method's verdict, over the shared fixture.
fn agrees(method: &str) {
    let app = app();
    let (engine, kernel) = both(&app);
    let diff = differing(engine, kernel);
    assert!(
        !diff.contains(&method),
        "`{method}` answers differently on the kernel's tables than on the engine's view \
         (all differing: {diff:?})"
    );
}

#[test]
fn pools_agree() {
    agrees("pools");
}

#[test]
fn pool_exists_agrees() {
    agrees("pool_exists");
}

#[test]
fn model_indices_agree() {
    agrees("model_indices");
}

#[test]
fn model_index_agrees() {
    agrees("model_index");
}

#[test]
fn lane_view_agrees() {
    agrees("lane_view");
}

#[test]
fn lane_count_agrees() {
    agrees("lane_count");
}

#[test]
fn pool_members_agree() {
    agrees("pool_members");
}

#[test]
fn on_exhausted_fallback_agrees() {
    agrees("on_exhausted_fallback");
}

#[test]
fn upstream_creds_agree() {
    agrees("upstream_creds");
}

/// The live `on_exhausted: queue` depth: one request parked on the engine's walk and one on the
/// kernel's (`set_pool_queued_depth`, which the door's walk reports to) read the same, and both read
/// nothing once it leaves.
#[test]
fn queued_depth_agrees() {
    let app = app();
    let (engine, kernel) = both(&app);
    assert_eq!(
        kernel.queued_depth("vp-main"),
        engine.queued_depth("vp-main")
    );
    let parked = app.engine_tables().queued_depth().park("vp-main");
    busbar_kernel::plane_host::set_pool_queued_depth("vp-main", 1);
    assert_eq!(engine.queued_depth("vp-main"), 1);
    assert_eq!(
        kernel.queued_depth("vp-main"),
        engine.queued_depth("vp-main")
    );
    drop(parked);
    busbar_kernel::plane_host::set_pool_queued_depth("vp-main", 0);
    assert_eq!(
        kernel.queued_depth("vp-main"),
        engine.queued_depth("vp-main")
    );
}

/// RED: the comparison can fail. Against the empty view every method this fixture states answers
/// differently, and the comparison names each of them; a comparison that named nothing here would
/// pass any kernel table at all.
#[test]
fn red_the_comparison_names_every_method_a_different_view_answers_differently() {
    let app = app();
    let (engine, _) = both(&app);
    let diff = differing(engine, &busbar_kernel::plane_host::EMPTY_VIEW);
    for method in [
        "pools",
        "pool_exists",
        "model_indices",
        "model_index",
        "lane_view",
        "lane_count",
        "pool_members",
        "on_exhausted_fallback",
    ] {
        assert!(
            diff.contains(&method),
            "`{method}` was not told apart: {diff:?}"
        );
    }
    assert!(
        differing(engine, engine).is_empty(),
        "a view is the same as itself"
    );
}
