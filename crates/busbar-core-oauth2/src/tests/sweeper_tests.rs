// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SWEEP RUNS ON THE KERNEL'S CLOCK. THE DESIGN §1 has "one clock, which also drives every
//! plugin's tick": the authorization server's expired-record sweep is driven by the kernel's tick
//! through the seam (`AsPlaneSeam::tick`), and the server starts no timer of its own. RED before
//! the fix: every generation spawned its own interval task, and the seam had no tick to drive.
//!
//! A RELOAD FREES THE OLD SERVER. Letting a generation go must free its server: no task of the
//! server's own may hold it.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::config::OauthAsCfg;
use crate::plane::{seam_build, seam_tick, AsPlane, SWEEP_EVERY};

fn block() -> serde_yaml::Value {
    serde_yaml::to_value(OauthAsCfg {
        issuer: "https://gw.example.com".to_string(),
        signing_key: None,
        key_id: None,
        default_grant: Vec::new(),
        access_token_ttl_secs: None,
        refresh_token_ttl_secs: None,
        fapi2: false,
        clients: Vec::new(),
    })
    .expect("the block serializes")
}

/// One generation, as the kernel's build holds it.
fn generation() -> Arc<dyn std::any::Any + Send + Sync> {
    seam_build::<crate::NoConnections>(&block(), Vec::new(), Vec::new(), None, None)
        .expect("builds")
}

fn swept(g: &Arc<dyn std::any::Any + Send + Sync>) -> usize {
    Arc::clone(g)
        .downcast::<AsPlane>()
        .expect("this crate's server")
        .sweep_clock()
        .swept
        .load(Ordering::Relaxed)
}

/// THE SWEEP RUNS ON THE KERNEL'S CLOCK (THE DESIGN §1, "one clock, which also drives every plugin's
/// tick"). RED: building a generation spawned its sweeper's interval task.
#[tokio::test]
async fn a_generation_starts_no_task_of_its_own() {
    let tasks = || {
        tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks()
    };
    let before = tasks();
    let g = generation();
    tokio::task::yield_now().await;
    assert_eq!(
        tasks(),
        before,
        "building a generation started a task of its own; its time-driven work belongs on the \
         kernel's clock (THE DESIGN §1: one clock, which also drives every plugin's tick)"
    );
    drop(g);
}

#[tokio::test(start_paused = true)]
async fn the_sweep_runs_only_on_the_kernels_ticks() {
    let g = generation();

    // No tick, however long the process runs: the server starts no timer, so it never sweeps.
    tokio::time::sleep(SWEEP_EVERY * 5).await;
    assert_eq!(
        swept(&g),
        0,
        "the server swept on a timer of its own; the kernel's clock is the one clock"
    );

    // The kernel's ticks: the first starts the cadence, one inside it sweeps nothing, and the first
    // tick a full cadence after it sweeps once.
    let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    seam_tick(&g, t0).await;
    seam_tick(&g, t0 + SWEEP_EVERY / 2).await;
    assert_eq!(swept(&g), 0, "a tick inside the cadence swept");
    seam_tick(&g, t0 + SWEEP_EVERY).await;
    assert_eq!(swept(&g), 1, "the kernel's due tick did not sweep");

    // A clock that steps back is due nothing.
    seam_tick(&g, t0).await;
    assert_eq!(swept(&g), 1, "a tick behind the last sweep swept again");
    seam_tick(&g, t0 + SWEEP_EVERY * 2).await;
    assert_eq!(swept(&g), 2, "the next due tick did not sweep");
}

#[tokio::test]
async fn a_reload_frees_the_old_server() {
    let old = generation();
    let old_server = {
        let plane = Arc::clone(&old)
            .downcast::<AsPlane>()
            .expect("this crate's server");
        Arc::downgrade(plane.server())
    };

    // THE RELOAD: a new generation is built over the old one, and the old one is let go.
    let new =
        seam_build::<crate::NoConnections>(&block(), Vec::new(), Vec::new(), Some(&old), None)
            .expect("builds");
    drop(old);
    tokio::task::yield_now().await;
    assert!(
        old_server.upgrade().is_none(),
        "the old generation's server outlived its generation"
    );
    seam_tick(&new, SystemTime::now()).await;
}
