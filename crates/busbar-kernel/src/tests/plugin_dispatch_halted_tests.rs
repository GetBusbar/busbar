// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLUGIN HANDLE LATCH ON `/healthz` (#74).

use super::*;

/// RED: while the handle latch is tripped `/healthz` answers 503 with the neutral reason, and with
/// it untripped the readiness check goes on to the lanes.
#[test]
fn healthz_answers_503_while_the_handle_latch_is_tripped() {
    let halted = plugin_dispatch_halted(true).expect("a tripped latch halts readiness");
    assert_eq!(halted.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(plugin_dispatch_halted(false).is_none());
}
