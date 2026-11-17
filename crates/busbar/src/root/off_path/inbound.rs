// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The data listener's inbound table, published once per configuration.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use busbar_kernel::inbound as kin;

use crate::root::inbound::{host, staged, ROOT_OWNER};
use crate::root::loader::dispatch::auth_handle;

static GENERATION: AtomicU64 = AtomicU64::new(0);

pub fn publish(app: &Arc<busbar_kernel::state::App>) -> Option<u64> {
    let (guests, door_refusals) = staged().clone()?;
    let generation = GENERATION.fetch_add(1, Ordering::AcqRel) + 1;
    let auths = guests
        .lines()
        .iter()
        .filter_map(|l| match &l.auth {
            busbar_kernel::guest::LineAuth::Chain(names, _) => Some(names),
            busbar_kernel::guest::LineAuth::None => None,
        })
        .flatten()
        .filter_map(|n| Some((n.clone(), app.auth.position_calls(n)?)))
        .collect();
    let body_limit = busbar_kernel::config::limits::installed().map_or(
        busbar_kernel::config::limits::DEFAULT_REQUEST_BODY_MAX_BYTES,
        |l| l.request_body_max_bytes,
    ) as u64;

    let ids = guests
        .lines()
        .iter()
        .map(|_| auth_handle::next_ref_id(auth_handle::RefSpace::Line))
        .collect();
    let listener = kin::Listener {
        guests,
        auths,
        body_limit,
        app: Arc::clone(app),
        door_refusals,
        ids,

        signed_ingress: Arc::new(|_, _| false),
        scope: None,
    };
    if let Err(e) = host().install(ROOT_OWNER, generation, listener) {
        tracing::error!(
            generation,
            error = e,
            "the data listener's inbound table was refused"
        );
        return None;
    }
    auth_handle::publish_generation(generation);
    host().retire_before(generation);
    Some(generation)
}
