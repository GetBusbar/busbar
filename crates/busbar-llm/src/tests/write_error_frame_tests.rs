// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The mid-stream error seam, across every declared writer.
//!
//! `proxy::wire` frames a mid-stream terminal error by calling `ProtocolWriter::write_error_frame`
//! — the NEUTRAL seam that lets core emit a native in-band stream-error event without naming the
//! concrete `IrStreamEvent`. The trait default returns `None` (fall back to core's dialect-free
//! frame), so a protocol that forgets to override it would silently downgrade a native error frame
//! to a bare `data:` one. This battery pins, for EVERY protocol in `DECLS`, that the override
//! exists and returns `Some` — the guard against that silent downgrade.
//!
//! Byte-identity to the delegated `write_response_event(&IrStreamEvent::Error(..))` is NOT asserted
//! here, and cannot be by re-invoking: the Responses writer synthesizes a `response.id` and a
//! `now_unix_secs()` `created_at` for a terminal error with no preceding `MessageStart`, so two
//! separate calls legitimately differ on those volatile fields. In production the seam IS that
//! single `write_response_event` call, so identity is exact; the streaming witness batteries in core
//! (`stream_translate_tests`, the mid-stream-error/`response.failed` tests) exercise that live path.

use super::*;
use busbar_core::breaker::{CanonicalSignal, StatusClass};

fn a_mid_stream_error() -> CanonicalSignal {
    // The exact shape `proxy::wire::mid_stream_error_bytes` constructs: a server-class transport
    // failure carrying the human detail as the provider signal.
    CanonicalSignal {
        class: StatusClass::ServerError,
        provider_signal: Some("mid-stream transport failure".to_string()),
        retry_after: None,
    }
}

#[test]
fn every_declared_writer_frames_a_stream_error_in_band() {
    let err = a_mid_stream_error();
    for decl in DECLS {
        // A protocol without a cross-dialect codec (none today; MCP would be one) has no writer.
        let Some(codec) = decl.codec else { continue };

        assert!(
            codec().writer().write_error_frame(&err).is_some(),
            "{}: write_error_frame returned None — a mid-stream error would fall back to core's \
             dialect-free frame instead of this protocol's native stream-error shape",
            decl.name
        );
    }
}
