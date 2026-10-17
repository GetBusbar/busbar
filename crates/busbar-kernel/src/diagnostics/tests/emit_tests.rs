// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::emit;
use crate::diagnostics::{Class, Diagnostic, Severity};
use std::io::Write;
use std::sync::{Arc, Mutex};

/// A catalogue entry of the shape a first-party plugin declares (the webhook sink's non-2xx code).
const WEBHOOK_DELIVERY_NON_2XX: Diagnostic = Diagnostic {
    code: 7071,
    class: Class::Plane,
    slug: "webhook-delivery-non-2xx",
    title: "t",
    severity: Severity::BenignRecurring,
    summary: "s",
    action: "a",
    since: "1.6.0",
    retired: false,
};

/// A writer the fmt layer writes into, read back by the test.
#[derive(Clone, Default)]
struct Buf(Arc<Mutex<Vec<u8>>>);

impl Write for Buf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Every line, with the level/timestamp prefix the host's layer writes cut off at the level.
fn lines(buf: &Buf) -> Vec<String> {
    let text = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    text.lines()
        .map(|l| {
            l.split_once("DEBUG")
                .map_or(l, |(_, rest)| rest)
                .to_string()
        })
        .collect()
}

/// **A RUNTIME-FIELDED DIAGNOSTIC RENDERS BYTE FOR BYTE AS THE MACRO SITE'S LINE** (K9c): the
/// host's own fmt layer (no target, as `init_logging` builds it) writes the compiled-in
/// `diag_debug!` line and the [`emit`] line identically — message, `diag=`, then the fields in
/// order, a string field quoted by the caller the way the macro's `String` field is.
#[test]
fn a_runtime_fielded_diagnostic_renders_as_the_macro_site_does() {
    let buf = Buf::default();
    let writer = buf.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_target(false)
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        let url = String::from("https://***@hooks.example/a");
        crate::diag_debug!(
            WEBHOOK_DELIVERY_NON_2XX,
            webhook_url = url,
            status = 503u16,
            "request-log webhook delivery returned a non-2xx status; this log was dropped"
        );
        emit(
            &WEBHOOK_DELIVERY_NON_2XX,
            tracing::Level::DEBUG,
            "request-log webhook delivery returned a non-2xx status; this log was dropped",
            &[
                ("webhook_url".into(), format!("{url:?}")),
                ("status".into(), "503".into()),
            ],
        );
    });
    let got = lines(&buf);
    assert_eq!(got.len(), 2, "{got:?}");
    assert_eq!(got[0], got[1]);
    assert!(
        got[1].contains("diag=BUSBAR-7071 webhook_url=\"https://***@hooks.example/a\" status=503"),
        "{got:?}"
    );
}

/// Below the subscriber's level nothing is written — the runtime callsite is filtered as a macro
/// site is.
#[test]
fn a_runtime_diagnostic_below_the_level_is_not_written() {
    let buf = Buf::default();
    let writer = buf.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_max_level(tracing::Level::INFO)
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        emit(&WEBHOOK_DELIVERY_NON_2XX, tracing::Level::DEBUG, "x", &[]);
    });
    assert!(buf.0.lock().unwrap().is_empty());
}
