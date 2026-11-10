// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use crate::config::OauthAsCfg;
use crate::plane::{seam_build, AsPlane};

fn block() -> serde_yaml::Value {
    let config = OauthAsCfg {
        issuer: "https://gw.example.com".to_string(),
        signing_key: None,
        key_id: None,
        default_grant: Vec::new(),
        access_token_ttl_secs: None,
        refresh_token_ttl_secs: None,
        fapi2: false,
        clients: Vec::new(),
    };
    serde_yaml::to_value(config.authoring(&busbar_kernel::test_hooks::tokens::seal()))
        .expect("the block serializes")
}

async fn generation() -> Arc<dyn std::any::Any + Send + Sync> {
    seam_build::<crate::NoConnections>(block(), Vec::new(), Vec::new(), None, None)
        .await
        .expect("builds")
}

#[tokio::test]
async fn a_reload_leaves_exactly_one_sweeper() {
    let old = generation().await;
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

    let new = generation().await;
    drop(old);

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

#[tokio::test]
async fn a_generation_starts_no_task_of_its_own() {
    let tasks = || {
        tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks()
    };
    let before = tasks();
    let g = generation().await;
    tokio::task::yield_now().await;
    assert_eq!(
        tasks(),
        before,
        "building a generation started a task of its own; its time-driven work belongs on the \
         kernel's clock (THE DESIGN §1: one clock, which also drives every plugin's tick)"
    );
    drop(g);
}
