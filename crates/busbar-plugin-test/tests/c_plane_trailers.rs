// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-PLANE-TRAILERS (ABI-MIN3-INTERFACE §14): gRPC final status as HTTP/2 trailers and `render(RENDER_REFUSAL)`,
//! byte-equal to 1.5.5. The plane-a2a image arm is on GetBusbar/busbar #217 (WBS delta 4).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K8A; blocked (re-checked on dev 2026-11-16): needs MIN-3 plane serving with render(RENDER_REFUSAL) to emit(E_TRAILERS) (K8A tail, OUTSTANDING row 5), a plane-a2a gRPC double and 1.5.5 golden trailer bytes (plane-a2a repo, whose gRPC binding is not ported: row 23)"]
fn trailers_and_render_refusal_with_a_plane_double() {
    todo!("owner: W1-K8A (C-PLANE-TRAILERS)")
}
