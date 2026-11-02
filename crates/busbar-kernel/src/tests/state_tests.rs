// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use busbar_kernel::plane_driver::EngineHost;

static ATTACHED: AtomicUsize = AtomicUsize::new(0);

fn count_attach(host: &Arc<dyn EngineHost>) {
    assert!(Arc::downgrade(host).upgrade().is_some());
    ATTACHED.fetch_add(1, Ordering::SeqCst);
}

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
