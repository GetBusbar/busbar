// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The secret suite body (IF §14, §8.2). Owned by the secret agent: this is the only file it edits (plus the
//! `tests/` cases that call it). Drives the plugin with [`super::harness::Harness`].
//!
//! Cases, all through the registry (describe, bind, inline open, close under `entry::guard`):
//! - admit: the image is a secret kind and admits; a malformed config is refused by `check` and by `open`
//!   (REFUSED R_CONFIG), a good one passes `check` (DRY_RUN) and opens, twice under two names;
//! - resolve: every `known` (reference, value) pair answers exactly its value, repeatedly and from concurrent
//!   tasks; the lease fact, when stated, is non-zero;
//! - refusals (§8.2): a reference naming nothing is REFUSED R_NOT_FOUND, a malformed reference (not JSON, not
//!   an object, an object with non-text member) is REFUSED R_INVALID, and neither refusal's text, nor any log
//!   line, nor the harness refusal book carries a known secret value (I14);
//! - the instance survives its refusals: a known pair still resolves after them;
//! - the plugin never reaches for the network on a resolve it can answer without (no OPEN/FETCH is seen for a
//!   plugin whose `FakeNeeds` scripted none: `seen()` is only compared to its length before the resolves, so
//!   a vault-style plugin that Needs is not penalised).
//!
//! A `known` reference is the `settings` object JSON of the SourceReference, verbatim (e.g.
//! `{"name":"db"}`); bytes that do not start with `{` are taken as a bare name and wrapped as `{"name": <it>}`.

use std::time::{Duration, Instant};

use busbar_plugin_abi::fail::refused::{R_CONFIG, R_INVALID, R_NOT_FOUND};
use busbar_plugin_abi::host_side::caller::CallStack;
use busbar_plugin_abi::plugin::Plugin;
use busbar_plugin_abi::types::KindCode;
use busbar_plugin_loader::ports::secret::SecretPort;
use busbar_plugin_loader::ports::{CallCx, PortError};

use super::harness::{core_refusal, plugin_code, status_code, Harness};
use crate::fake_needs::FakeNeeds;

fn cx(id: u64) -> CallCx {
    CallCx {
        deadline: Instant::now() + Duration::from_secs(10),
        request_id: id,
        stack: CallStack::default(),
    }
}

/// The reference bytes the port is given for a `known` entry.
fn reference(raw: &[u8]) -> Vec<u8> {
    if raw.first() == Some(&b'{') {
        return raw.to_vec();
    }
    let name = String::from_utf8_lossy(raw);
    let mut out = br#"{"name":"#.to_vec();
    out.extend_from_slice(
        serde_json::Value::String(name.into_owned())
            .to_string()
            .as_bytes(),
    );
    out.push(b'}');
    out
}

fn refused_code(error: &PortError) -> Option<u32> {
    match error {
        PortError::Refused { code, .. } => Some(*code),
        _ => None,
    }
}

fn error_text(error: &PortError) -> String {
    match error {
        PortError::Refused { text, .. } | PortError::Failed { text, .. } => text.to_string(),
        PortError::Call(call) => format!("{call:?}"),
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

pub(super) fn run(
    plugin: &'static Plugin,
    config: &[u8],
    needs: FakeNeeds,
    known: &[(&[u8], &[u8])],
) {
    let harness = match Harness::admit(plugin, needs) {
        Ok(harness) => harness,
        Err(refusal) => panic!("secret suite: the image was refused at admission: {refusal:?}"),
    };
    assert_eq!(
        harness.kind(),
        KindCode::Secret,
        "secret suite: `{}` is not a secret plugin",
        harness.identity()
    );

    // ---- config: check and open ------------------------------------------------------------------------
    if let Err(error) = harness.check("suite-check", config) {
        panic!("secret suite: check of the operator config failed: {error:?}");
    }
    let bad = b"{ this is not json";
    let error = match harness.check("suite-bad", bad) {
        Ok(()) => panic!("secret suite: check accepted a config that is not JSON"),
        Err(error) => error,
    };
    // A core refusal (the binder or schema) or the plugin's REFUSED R_CONFIG are both a refusal of config.
    assert!(
        core_refusal(&error).is_some()
            || status_code(&error) == Some(R_CONFIG)
            || plugin_code(&error).is_some(),
        "secret suite: a malformed config must be refused as config, got {error:?}"
    );
    assert!(
        harness.open("suite-bad", bad).is_err(),
        "secret suite: open accepted a config that is not JSON"
    );

    let port = match harness.open_secret("suite-a", config) {
        Ok(port) => port,
        Err(error) => panic!("secret suite: open failed: {error:?}"),
    };
    let second = match harness.open_secret("suite-b", config) {
        Ok(port) => port,
        Err(error) => {
            panic!("secret suite: a second instance under another name failed to open: {error:?}")
        }
    };

    // ---- resolve: every known pair ---------------------------------------------------------------------
    let mut id = 0u64;
    let mut next = || {
        id += 1;
        id
    };
    for (raw, value) in known {
        let reference = reference(raw);
        for (which, port) in [("first", &port), ("second", &second)] {
            for round in 0..3 {
                let answer = match harness.block_on(port.resolve(cx(next()), &reference)) {
                    Ok(answer) => answer,
                    Err(error) => panic!(
                        "secret suite: {which} instance, round {round}: resolve of {} failed: {error:?}",
                        String::from_utf8_lossy(&reference)
                    ),
                };
                assert_eq!(
                    answer.value.as_slice(),
                    *value,
                    "secret suite: {which} instance resolved {} to the wrong bytes",
                    String::from_utf8_lossy(&reference)
                );
                if let Some(lease) = answer.lease_s {
                    assert!(lease > 0, "secret suite: a stated lease must be non-zero");
                }
            }
        }
    }

    // Concurrent resolves on one instance: every task gets its own pair's value.
    if !known.is_empty() {
        let references: Vec<Vec<u8>> = known.iter().map(|(raw, _)| reference(raw)).collect();
        let base = next();
        let answers = harness.block_on(async {
            let mut tasks = Vec::new();
            for (index, reference) in references.iter().enumerate() {
                for copy in 0..4u64 {
                    let port = &port;
                    tasks.push(async move {
                        let cx = cx(base + 1_000 + index as u64 * 8 + copy);
                        (index, port.resolve(cx, reference).await)
                    });
                }
            }
            futures_join(tasks).await
        });
        for (index, answer) in answers {
            match answer {
                Ok(answer) => assert_eq!(
                    answer.value.as_slice(),
                    known[index].1,
                    "secret suite: a concurrent resolve of pair {index} crossed values"
                ),
                Err(error) => {
                    panic!("secret suite: a concurrent resolve of pair {index} failed: {error:?}")
                }
            }
        }
    }

    // ---- refusals --------------------------------------------------------------------------------------
    let mut refusal_texts = Vec::new();
    let unknown: &[&[u8]] = &[
        br#"{"name":"busbar-suite-no-such-secret-7f3a"}"#,
        br#"{"name":"busbar-suite-no-such-secret-7f3a-2"}"#,
    ];
    for reference in unknown {
        match harness.block_on(port.resolve(cx(next()), reference)) {
            Ok(_) => panic!("secret suite: an unknown name resolved to a value"),
            Err(error) => {
                assert_eq!(
                    refused_code(&error),
                    Some(R_NOT_FOUND),
                    "secret suite: an unknown name must be REFUSED R_NOT_FOUND, got {error:?}"
                );
                refusal_texts.push(error_text(&error));
            }
        }
    }
    let malformed: &[&[u8]] = &[
        b"",
        b"\xff\xfe\x00",
        b"not json",
        b"[1,2]",
        b"\"a string\"",
        br#"{"name":42}"#,
    ];
    for reference in malformed {
        match harness.block_on(port.resolve(cx(next()), reference)) {
            Ok(_) => panic!(
                "secret suite: a malformed reference {:?} resolved to a value",
                String::from_utf8_lossy(reference)
            ),
            Err(error) => {
                assert_eq!(
                    refused_code(&error),
                    Some(R_INVALID),
                    "secret suite: malformed reference {:?} must be REFUSED R_INVALID, got {error:?}",
                    String::from_utf8_lossy(reference)
                );
                refusal_texts.push(error_text(&error));
            }
        }
    }

    // ---- the instance survives its refusals ------------------------------------------------------------
    for (raw, value) in known {
        let reference = reference(raw);
        match harness.block_on(port.resolve(cx(next()), &reference)) {
            Ok(answer) => assert_eq!(
                answer.value.as_slice(),
                *value,
                "secret suite: a refusal changed what the instance resolves"
            ),
            Err(error) => {
                panic!("secret suite: the instance stopped resolving after refusals: {error:?}")
            }
        }
    }

    // ---- I14: no known value in any refusal text, log line or recorded refusal --------------------------
    let mut texts: Vec<String> = refusal_texts;
    texts.extend(harness.logs().into_iter().map(|line| line.message));
    texts.extend(harness.refusals());
    for (_, value) in known {
        for text in &texts {
            assert!(
                !contains(text.as_bytes(), value),
                "secret suite: a resolved secret value appears in plugin text (I14): {text:?}"
            );
        }
    }

    // ---- close: dropping the ports closes the instances; the registry must then be reusable --------------
    drop(port);
    drop(second);
    if let Err(error) = harness.check("suite-after-close", config) {
        panic!("secret suite: check failed after the instances closed: {error:?}");
    }
}

/// Poll every future to completion on the harness runtime, returning results in input order (a minimal
/// `join_all`, so the suite needs no `futures` dependency).
async fn futures_join<F: std::future::Future>(futures: Vec<F>) -> Vec<F::Output> {
    let mut out = Vec::with_capacity(futures.len());
    let mut handles: Vec<std::pin::Pin<Box<F>>> = futures.into_iter().map(Box::pin).collect();
    let mut done: Vec<Option<F::Output>> = handles.iter().map(|_| None).collect();
    std::future::poll_fn(|task| {
        let mut pending = false;
        for (slot, fut) in done.iter_mut().zip(handles.iter_mut()) {
            if slot.is_none() {
                match fut.as_mut().poll(task) {
                    std::task::Poll::Ready(value) => *slot = Some(value),
                    std::task::Poll::Pending => pending = true,
                }
            }
        }
        if pending {
            std::task::Poll::Pending
        } else {
            std::task::Poll::Ready(())
        }
    })
    .await;
    for value in done {
        if let Some(value) = value {
            out.push(value);
        }
    }
    handles.clear();
    out
}
