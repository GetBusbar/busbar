// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CANARY (CHIP-DESIGN v4.1 §12, change 9): no credential the plugin was configured with ever
//! crosses back, through either door. The plugin's `conformance.json` names the credentials its
//! settings carry (`"credentials": ["<value>", ...]`; the test fixture configures its far end with
//! the same unique value). Every op of the kind's script runs, refusals and errors included, and
//! every step's answer and every log record the instance raised is searched for each credential in
//! every spelling a careless path produces: as written, percent-encoded, base64 and hex.

use std::cell::RefCell;
use std::sync::{Arc, Mutex};

use base64::Engine as _;

use crate::dispatch::{Diagnostic, Dropped, EnvelopeSink, Metric};

const MAX_HEARD: usize = 65_536;

/// What one bound instance logged (its #85 diagnostics, log records included).
#[derive(Debug, Default)]
pub struct Heard(Mutex<Vec<Vec<u8>>>);

impl EnvelopeSink for Heard {
    fn metric(&self, _: Metric<'_>) {}
    fn diag(&self, d: Diagnostic<'_>) {
        if let Ok(mut v) = self.0.lock() {
            if v.len() < MAX_HEARD {
                v.push(d.text.to_vec());
            }
        }
    }
    fn dropped(&self, _: Dropped) {}
}

thread_local! {
    static FOLD_HEARD: RefCell<Vec<Arc<Heard>>> = const { RefCell::new(Vec::new()) };
}

/// A sink for one bind, registered with the fold running on this thread.
pub(super) fn heard() -> Arc<Heard> {
    let h = Arc::new(Heard::default());
    FOLD_HEARD.with(|f| f.borrow_mut().push(Arc::clone(&h)));
    h
}

/// Everything the fold's instances logged since the last call.
pub(super) fn take_heard() -> Vec<Vec<u8>> {
    FOLD_HEARD
        .with(|f| std::mem::take(&mut *f.borrow_mut()))
        .iter()
        .flat_map(|h| h.0.lock().map(|v| v.clone()).unwrap_or_default())
        .collect()
}

/// The credentials `inputs` names.
#[must_use]
pub fn credentials(inputs: &serde_json::Value) -> Vec<Vec<u8>> {
    inputs["credentials"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.as_bytes().to_vec())
                .collect()
        })
        .unwrap_or_default()
}

fn percent(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len() * 3);
    for &c in b {
        if c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'~') {
            out.push(c);
        } else {
            out.extend_from_slice(format!("%{c:02X}").as_bytes());
        }
    }
    out
}

/// Every spelling of `secret` the search looks for.
#[must_use]
pub fn spellings(secret: &[u8]) -> Vec<Vec<u8>> {
    let mut out = vec![
        secret.to_vec(),
        percent(secret),
        base64::engine::general_purpose::STANDARD
            .encode(secret)
            .trim_end_matches('=')
            .as_bytes()
            .to_vec(),
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(secret)
            .into_bytes(),
        hex::encode(secret).into_bytes(),
    ];
    out.sort();
    out.dedup();
    out
}

/// The first place in `emitted` (`(where, bytes)`) a spelling of any of `secrets` appears: its
/// `where`, never the value.
#[must_use]
pub fn find(secrets: &[Vec<u8>], emitted: &[(String, Vec<u8>)]) -> Option<String> {
    let needles: Vec<Vec<u8>> = secrets.iter().flat_map(|s| spellings(s)).collect();
    emitted.iter().find_map(|(at, bytes)| {
        needles
            .iter()
            .any(|n| !n.is_empty() && bytes.windows(n.len()).any(|w| w == n.as_slice()))
            .then(|| at.clone())
    })
}
