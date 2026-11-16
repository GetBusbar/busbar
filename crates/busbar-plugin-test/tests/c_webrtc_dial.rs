// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-WEBRTC-DIAL (ABI-MIN3-INTERFACE §14): UP_NEW(CARRIER_RTC) mirror resolution and its FAULTs in core (round 27;
//! K11 + C1 + K8). The transport-webrtc arm runs in its repo.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K8A"]
fn rtc_dial_mirrors_the_accepted_offer() {
    todo!("owner: W1-K8A (C-WEBRTC-DIAL)")
}
