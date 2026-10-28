// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `AppHandle::swap` keeps the promise its doc makes (item 552), and `App`'s field docs sit on the
//! fields they describe (item 565).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use busbar_kernel::plane_driver::EngineHost;

/// How many times the bound spawner ran, and whether the host it was handed was a live generation's.
static ATTACHED: AtomicUsize = AtomicUsize::new(0);

fn count_attach(host: &Arc<dyn EngineHost>) {
    // The spawner is handed the INCOMING generation's host, alive: a prober spawned against it
    // holds a `Weak` that upgrades until the next swap retires it.
    assert!(Arc::downgrade(host).upgrade().is_some());
    ATTACHED.fetch_add(1, Ordering::SeqCst);
}

/// THE FIRST ADMIN MUTATION MUST NOT STOP HEALTH PROBING. The swap drops the outgoing generation's
/// host — the only strong reference its probers depend on — so they exit. Unless the swap re-spawns
/// probers against the incoming host, active probing stops for the life of the process, and a lane a
/// breaker tripped dead is never probed back. Every swap runs the spawner the composition root bound,
/// once per swap, and a handle nobody bound one on runs nothing.
#[test]
fn every_swap_re_attaches_the_probers_the_root_bound() {
    let handle = crate::state::AppHandle::new(crate::test_support::TestApp::new().build());
    let before = ATTACHED.load(Ordering::SeqCst);
    handle.swap(crate::test_support::TestApp::new().build());
    assert_eq!(
        ATTACHED.load(Ordering::SeqCst),
        before,
        "nothing was bound, so nothing ran"
    );

    handle.attach_on_swap(count_attach);
    handle.swap(crate::test_support::TestApp::new().build());
    handle.swap(crate::test_support::TestApp::new().build());
    assert_eq!(
        ATTACHED.load(Ordering::SeqCst),
        before + 2,
        "each swap re-attaches the probers to the generation that replaced theirs"
    );
}
