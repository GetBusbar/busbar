// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-TRANSPORT-BACKPRESSURE (ABI-MIN3-INTERFACE §14): STREAM_FULL/STREAM_WRITABLE, the stall deadline and the conn
//! staying up (C1 + L9). Each framer's arm runs in its repo.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "re-checked 2026-11-16: the connector still drives framers over the old FramerDoor/Framing (crates/busbar-core-connector/src/framer.rs, compose.rs, framed_stream.rs name neither E_REFUSE nor E_CLOSE, and no .alpn(role) call exists in the connector), OUTSTANDING row 6; lands with W1-C1C !2644 (open). STREAM_FULL/STREAM_WRITABLE feed and RESET_STALLED at stream_stall_ms are the connector's, and the per-framer arms are the h2, grpc and webrtc framer images (plugin repos); image arms land with W2-SW-TRANSPORT (OUTSTANDING row 7)"]
fn backpressure_core_arms() {
    todo!("owner: W1-C1C (C-TRANSPORT-BACKPRESSURE)")
}
