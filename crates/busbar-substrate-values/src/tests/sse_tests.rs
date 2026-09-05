// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the neutral SSE frame reader (`proxy/sse.rs`).

use super::*;

/// A dropped non-UTF-8 frame is an operator-facing warn on a served path, so it carries a
/// registered `BUSBAR-NNNN` code an operator can look up — the drop itself is unchanged. Emitted
/// twice because a warn callsite's interest is cached process-wide and a concurrent test's
/// dispatcher can make the FIRST emission through this scoped subscriber invisible.
#[test]
fn test_non_utf8_frame_drop_carries_diag_code() {
    use crate::diagnostics::PLANE_SSE_FRAME_NOT_UTF8;
    use crate::test_support::warn_capture::WarnCapture;
    use tracing_subscriber::layer::SubscriberExt as _;

    let cap = WarnCapture::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());
    let out = tracing::subscriber::with_default(subscriber, || {
        let mut r = SseReader::default();
        let first = r.feed(b"data: \xff\xfe\n\n");
        let _ = r.feed(b"data: \xff\xfe\n\n");
        first
    });

    assert!(
        out.is_empty(),
        "a non-UTF-8 frame is still dropped, not relayed"
    );
    let banner = PLANE_SSE_FRAME_NOT_UTF8.banner().to_string();
    assert!(
        cap.contains(&banner),
        "the dropped-frame warning must carry diag={banner}; captured: {:?}",
        cap.messages()
    );
    assert!(
        cap.contains("dropping a non-UTF-8 SSE frame"),
        "the message text is preserved; captured: {:?}",
        cap.messages()
    );
}
