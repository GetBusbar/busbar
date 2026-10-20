// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A RELOAD LEAVES ONE SWEEPER. Every config generation builds its own server through the seam and
//! spawns that server's sweeper; letting the old generation go must stop the old sweeper and free
//! the old server. Before the fix the sweep task held its server STRONGLY and forever, so every
//! reload leaked a server and left one more sweeper running.

use std::sync::Arc;

use crate::config::OauthAsCfg;
use crate::plane::{seam_build, AsPlane};

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

#[tokio::test]
async fn a_reload_leaves_exactly_one_sweeper() {
    let old = generation();
    let (old_sweeper, old_server) = {
        let plane = Arc::clone(&old)
            .downcast::<AsPlane>()
            .expect("this crate's server");
        let probe = plane.sweeper().expect("the seam spawns a sweeper").probe();
        (probe, Arc::downgrade(plane.server()))
    };
    assert!(
        old_sweeper.upgrade().is_some(),
        "the first generation sweeps"
    );

    // THE RELOAD: a new generation is built, and the old one is let go.
    let new = generation();
    drop(old);

    // The abort lands when the runtime next polls the old task.
    for _ in 0..100 {
        if old_sweeper.upgrade().is_none() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        old_sweeper.upgrade().is_none(),
        "the old generation's sweeper is still running after a reload"
    );
    assert!(
        old_server.upgrade().is_none(),
        "the old generation's server outlived its generation: the sweeper leaked it"
    );

    let plane = new.downcast::<AsPlane>().expect("this crate's server");
    let live = plane.sweeper().expect("the new generation sweeps").probe();
    assert!(live.upgrade().is_some(), "exactly one sweeper: the new one");
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
