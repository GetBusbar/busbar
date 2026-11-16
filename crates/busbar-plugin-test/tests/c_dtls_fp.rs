// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-DTLS-FP (ABI-MIN3-INTERFACE §14): A datagram `begin` gets a non-empty `local_fingerprint`; a mismatching far
//! end gets PATH_REJECTED and no EV_KEYING.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-C1B; the core arm needs a constructible TransportSession (L9 fills SessionHandle): it runs as busbar-core-connector dtls::session::tests / dtls::carrier::tests over a scripted Live"]
fn a_fingerprint_mismatch_is_path_rejected() {
    todo!("owner: W1-C1B (C-DTLS-FP)")
}
