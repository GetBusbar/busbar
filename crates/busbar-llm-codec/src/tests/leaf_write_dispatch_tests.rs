// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Leaf-op write dispatchers fail LOUDLY on an unknown egress protocol, rather than emitting a
//! malformed empty body — the guard for a future leaf-op protocol added without extending the match.

use crate::ir::embeddings::EmbeddingsReq;
use crate::leaf_codec::embeddings_write_request;

// A known protocol ("openai") is exercised by the per-dialect handler tests, so this only pins the
// loud fallback for an unrecognized egress protocol.
#[test]
#[should_panic(expected = "leaf write: unknown egress protocol")]
fn unknown_egress_protocol_panics() {
    let _ = embeddings_write_request("no-such-protocol", &EmbeddingsReq::default());
}
