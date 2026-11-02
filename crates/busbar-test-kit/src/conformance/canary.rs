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

/// The envelope strings one bound instance emitted: diagnostic names/text and metric labels.
#[derive(Debug, Default)]
pub struct Heard(Mutex<Capture>);

#[derive(Debug, Default)]
struct Capture {
    bytes: Vec<Vec<u8>>,
    incomplete: bool,
}

impl Heard {
    fn record(&self, bytes: &[u8]) {
        if let Ok(mut capture) = self.0.lock() {
            if capture.bytes.len() < MAX_HEARD {
                capture.bytes.push(bytes.to_vec());
            } else {
                capture.incomplete = true;
            }
        }
    }

    /// Every observed envelope string, or a refusal when any envelope could not be observed.
    ///
    /// # Errors
    /// Capture was capped, the host dropped an envelope, or the capture mutex was poisoned.
    pub fn captured(&self) -> Result<Vec<Vec<u8>>, &'static str> {
        let capture = self.0.lock().map_err(|_| "capture mutex poisoned")?;
        if capture.incomplete {
            return Err("envelope capture incomplete");
        }
        Ok(capture.bytes.clone())
    }
}

impl EnvelopeSink for Heard {
    fn metric(&self, m: Metric<'_>) {
        for label in m.labels {
            self.record(label);
        }
    }
    fn diag(&self, d: Diagnostic<'_>) {
        if !d.name.is_empty() {
            self.record(d.name);
        }
        self.record(d.text);
    }
    fn dropped(&self, _: Dropped) {
        if let Ok(mut capture) = self.0.lock() {
            capture.incomplete = true;
        }
    }
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

/// Everything the fold's instances emitted since the last call; incomplete capture fails closed.
pub(super) fn take_heard() -> Vec<Vec<u8>> {
    FOLD_HEARD
        .with(|f| std::mem::take(&mut *f.borrow_mut()))
        .iter()
        .flat_map(|h| {
            h.captured()
                .unwrap_or_else(|reason| panic!("canary envelope capture incomplete: {reason}"))
        })
        .collect()
}

/// The credentials `inputs` names.
#[must_use]
pub fn credentials(inputs: &serde_json::Value) -> Vec<Vec<u8>> {
    match inputs.get("credentials") {
        None => Vec::new(),
        Some(v) => v
            .as_array()
            .expect("conformance.json: credentials must be an array")
            .iter()
            .map(|v| {
                v.as_str()
                    .expect("conformance.json: credentials entries must be strings")
            })
            .filter(|s| !s.is_empty())
            .map(|s| s.as_bytes().to_vec())
            .collect(),
    }
}

fn percent(b: &[u8], uppercase: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len() * 3);
    for &c in b {
        if c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'~') {
            out.push(c);
        } else {
            let encoded = if uppercase {
                format!("%{c:02X}")
            } else {
                format!("%{c:02x}")
            };
            out.extend_from_slice(encoded.as_bytes());
        }
    }
    out
}

/// Every spelling of `secret` the search looks for.
#[must_use]
pub fn spellings(secret: &[u8]) -> Vec<Vec<u8>> {
    let mut out = vec![
        secret.to_vec(),
        percent(secret, true),
        percent(secret, false),
        base64::engine::general_purpose::STANDARD
            .encode(secret)
            .trim_end_matches('=')
            .as_bytes()
            .to_vec(),
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(secret)
            .into_bytes(),
        hex::encode(secret).into_bytes(),
        hex::encode_upper(secret).into_bytes(),
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

#[cfg(all(test, loader_self_tests))]
mod capture_tests {
    use super::*;

    fn diagnostic(text: &[u8]) -> Diagnostic<'_> {
        Diagnostic {
            id: 0,
            name: b"",
            severity: 0,
            text,
        }
    }

    #[test]
    fn capture_overflow_cannot_hide_a_later_credential() {
        let heard = Heard::default();
        for _ in 0..MAX_HEARD {
            heard.diag(diagnostic(b"benign"));
        }
        assert!(heard.captured().is_ok());
        heard.diag(diagnostic(b"CANARY-overflow"));
        assert_eq!(heard.captured(), Err("envelope capture incomplete"));
    }

    #[test]
    fn dropped_logs_and_malformed_envelopes_refuse_a_clean_result() {
        for reason in [
            Dropped::Logs(1),
            Dropped::BadArray,
            Dropped::DiagOutOfRange(9),
        ] {
            let heard = Heard::default();
            heard.diag(diagnostic(b"benign"));
            heard.dropped(reason);
            assert_eq!(heard.captured(), Err("envelope capture incomplete"));
        }
    }

    #[test]
    fn poisoned_capture_refuses_a_clean_result() {
        let heard = Heard::default();
        let _ = std::panic::catch_unwind(|| {
            let _guard = heard.0.lock().unwrap();
            panic!("poison the capture");
        });
        assert_eq!(heard.captured(), Err("capture mutex poisoned"));
    }

    #[test]
    fn diagnostic_names_text_and_metric_labels_all_reach_the_canary() {
        let credential = b"CANARY-envelope/";
        for channel in 0..3 {
            let heard = Heard::default();
            match channel {
                0 => heard.diag(Diagnostic {
                    name: credential,
                    ..diagnostic(b"benign")
                }),
                1 => heard.diag(diagnostic(credential)),
                _ => heard.metric(Metric {
                    family: 0,
                    kind: 0,
                    value: 1.0,
                    labels: &[credential],
                }),
            }
            let emitted: Vec<_> = heard
                .captured()
                .unwrap()
                .into_iter()
                .map(|text| ("envelope".to_string(), text))
                .collect();
            assert_eq!(
                find(&[credential.to_vec()], &emitted),
                Some("envelope".to_string())
            );
        }
    }

    #[test]
    fn fold_capture_itself_refuses_an_incomplete_sink() {
        let _ = take_heard();
        let heard = heard();
        heard.dropped(Dropped::Logs(1));
        assert!(std::panic::catch_unwind(take_heard).is_err());
        assert!(take_heard().is_empty());
    }
}
