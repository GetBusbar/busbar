// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-ALPN (ABI-MIN3-INTERFACE §14): ALPN offers per role and per instance setting.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "re-checked 2026-11-16: core has only the adapter-level cache arm (plugin-loader adapters/transport.rs:1145 alpn_is_cached_per_declared_side, TransportPort::alpn at ports/transport.rs:98); the arm needs the transport-http fixture image offering http1_only, prior_knowledge and default ALPN (plugin repo, not in this tree) and the connector using each role's offer on its own side, which is missing: the connector still drives framers over the old FramerDoor/Framing (crates/busbar-core-connector/src/framer.rs, compose.rs, framed_stream.rs name neither E_REFUSE nor E_CLOSE, and no .alpn(role) call exists in the connector), OUTSTANDING row 6; lands with W1-C1C !2644 (open). Image arm lands with W2-SW-TRANSPORT (OUTSTANDING row 7)"]
fn alpn_offers_per_role() {
    todo!("owner: W1-L9 (C-ALPN)")
}
