// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The relay frame reader's host-side checks: its dropped-frame warning, captured through this
//! crate's warn-capture testkit, and its diagnostic against the published catalog file. The reader
//! and the rest of its battery live in the plane crate, which performs no file reads.

use crate::sse::*;

/// A dropped non-UTF-8 frame is an operator-facing warn on a served path, so it carries a
/// registered `BUSBAR-NNNN` code an operator can look up — the drop itself is unchanged. Emitted
/// twice because a warn callsite's interest is cached process-wide and a concurrent test's
/// dispatcher can make the FIRST emission through this scoped subscriber invisible. Runs under
/// `test-support`, the feature that brings the host's warn-capture layer into this crate's tests.
#[cfg(feature = "test-support")]
#[test]
fn test_non_utf8_frame_drop_carries_diag_code() {
    use crate::testkit::WarnCapture;
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

/// THE PLANE-CODE DRIFT GUARD (#83a O4): the reader's diagnostic is the published catalog's entry
/// of the same number, field for field — number, class, slug, title, severity, summary, action,
/// since and the retired flag. `docs/diagnostics.json` is the host's rendered catalog, held
/// byte-identical to the host registry by its own drift test, so a constant edited here and not
/// there (or there and not here) fails one of the two.
#[test]
fn the_sse_diagnostic_is_the_catalog_entry_of_its_number() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/diagnostics.json");
    let text = std::fs::read_to_string(path).expect("docs/diagnostics.json is readable");
    let catalog: Vec<serde_json::Value> =
        serde_json::from_str(&text).expect("docs/diagnostics.json is a JSON array");
    let d = PLANE_SSE_FRAME_NOT_UTF8;
    let entry = catalog
        .iter()
        .find(|e| e["number"] == u64::from(d.code))
        .unwrap_or_else(|| panic!("BUSBAR-{:04} is not in the published catalog", d.code));
    let ours = serde_json::json!({
        "code": format!("BUSBAR-{:04}", d.code),
        "number": d.code,
        "class": format!("{:?}", d.class).to_lowercase(),
        "slug": d.slug,
        "title": d.title,
        "severity": d.severity.as_str(),
        "summary": d.summary,
        "action": d.action,
        "since": d.since,
        "retired": d.retired,
    });
    assert_eq!(
        &ours, entry,
        "BUSBAR-{:04} differs from the published catalog entry",
        d.code
    );
}
