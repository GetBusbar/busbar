// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The ports: the adapter trait per kind, consumed by the kernel, and their shared types (IF §11.3). W0-ABI
//! stub: frozen signatures, `todo!()` bodies; L2 fills the shared part, L3-L9 their kind's file.
//!
//! Every port is dyn-compatible and boxes **once** per async call (the adapter's `async` body, which contains
//! the proxy's unboxed step loop). Sync port methods never box. Header lists cross as `&[abi::Pair<'_>]`, which
//! core builds once per request from its `HeaderMap` and shares between auth, plane and hooks (no per-port copy).

pub mod auth;
pub mod export;
pub mod hook;
pub mod plane;
pub mod secret;
pub mod store;
pub mod transport;

use busbar_plugin_abi::fail::CallError;
use busbar_plugin_abi::host_side::caller::CallStack;
use busbar_plugin_abi::records::Records;

use crate::instance::PluginCode;

/// `stack` is the host call stack outside this call; the adapter copies it into Caller.stack. Kernel
/// callers start with `CallStack::default()`; custody passes `who.stack.push(who.instance)` (§12.2).
#[derive(Clone, Copy, Debug)]
pub struct CallCx {
    pub deadline: std::time::Instant,
    pub request_id: u64,
    pub stack: CallStack,
}

/// `text` is always the scrubbed plugin text (§12.16) and is for operators and audit only. `code` may be a
/// kind code; core maps it before any client sees it (§12.15). Round 21: `Failed.retry_after_s` and
/// `backend_status` are `Answer::fail_fact(FACT_RETRY_AFTER_S / FACT_BACKEND_STATUS)` of the FAILED answer
/// (§4.1, §10.2), filled by the one shared builder for every kind; None when the plugin stated none, and always
/// None for `Call`. They are facts: `RetryPolicy` (§12.3) and the login outage page (§8.3) decide with them.
/// Round 34 (PLUGIN-ERROR-CODES): `error` is `Answer::fail_error` resolved through the instance's `ErrorBook`
/// (§11.2) by the same shared builder; display only (§12.3 never reads it, ARC-2). On STREAM_CONTENT `deliver`
/// and every `confirm` it is always None (§8.5). Its `Display` writes core's words and the code only; the text
/// is a separate field (§12.16).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortError {
    Refused {
        code: u32,
        text: Box<str>,
        error: Option<PluginCode>,
    },
    Failed {
        code: u32,
        text: Box<str>,
        retry_after_s: Option<u64>,
        backend_status: Option<u64>,
        error: Option<PluginCode>,
    },
    Call(CallError),
}

#[derive(Clone, Debug, PartialEq)]
pub enum FactVal {
    U(u64),
    Text(Box<str>),
}

pub type Facts = Vec<(u32, FactVal)>;

#[derive(Clone, Copy, Debug)]
pub enum FactRef<'o> {
    U(u64),
    Text(&'o str),
}

/// Round 31: the optional settled part of an `open` answer (§8.8 `settled::decode_settled`), borrowed from the
/// answer buffer. core_cfg = the CORE_CFG records (CoreCfgRec + name + value), validated by the decoder.
pub struct SettledOut<'o> {
    pub config: &'o [u8],
    pub core_cfg: Records<'o>,
}

/// The one shared builder (IF §11.3, §50) of a `PortError` from a terminal answer: None for an OK answer, else
/// REFUSED or FAILED with the plugin's text scrubbed whole and then cut (§12.16, I14), the FAILED answer's two
/// facts (a REFUSED answer carries none, §4.1) and the ERROR number resolved through the instance image's
/// `ErrorBook` (`latch` is the per-instance undeclared-number WARN latch). An answer that is neither OK nor
/// carries no FAIL is the adapter's contract break, not this builder's: None.
pub fn port_error(
    scrub: &busbar_plugin_abi::host_side::scrub::Scrub,
    errors: &crate::instance::ErrorBook,
    latch: &core::sync::atomic::AtomicBool,
    answer: &busbar_plugin_abi::host_side::answer::Answer<'_>,
) -> Option<PortError> {
    let _ = (scrub, errors, latch, answer);
    todo!("W1-L2: the shared PortError builder")
}

/// A refused or failed port answer as the open's error: REFUSED is `Config` (the instance's own settings were
/// refused), FAILED is `Failed`, a call error stays one.
pub fn open_error(error: PortError) -> crate::instance::OpenError {
    let _ = error;
    todo!("W1-L2: the shared OpenError builder")
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicBool, Ordering};

    use busbar_plugin_abi::fail::{failed, refused};
    use busbar_plugin_abi::host_side::answer::Answer;
    use busbar_plugin_abi::host_side::scrub::Scrub;
    use busbar_plugin_abi::records::{tag, FailRec, Reply, U32Rec, Writer};
    use busbar_plugin_abi::types::Status;

    use crate::instance::{ErrorBook, OpenError};

    fn fail(status: Status, code: u32, text: &str, error: u32, facts: &[(u32, u64)]) -> Reply {
        let mut r = Reply::new();
        r.put_pod_tail(
            tag::FAIL,
            &FailRec {
                status: status.0,
                code,
            },
            text.as_bytes(),
        )
        .unwrap();
        if error != 0 {
            r.put_pod(
                tag::ERROR,
                &U32Rec {
                    value: error,
                    _r: 0,
                },
            )
            .unwrap();
        }
        for (k, v) in facts {
            r.put_fact(*k, *v).unwrap();
        }
        r
    }

    static BOOK: ErrorBook = ErrorBook::Declared {
        identity: "acme",
        numbers: &[7, 9],
    };

    #[test]
    fn a_refused_answer_carries_its_code_text_and_resolved_error_and_no_facts() {
        let r = fail(Status::REFUSED, refused::R_CONFIG, "bad port", 7, &[]);
        let a = Answer::parse(Status::REFUSED, r.as_bytes()).unwrap();
        let latch = AtomicBool::new(false);
        let e = port_error(&Scrub::new(), &BOOK, &latch, &a).unwrap();
        let PortError::Refused { code, text, error } = e else {
            panic!("refused")
        };
        assert_eq!((code, &*text), (refused::R_CONFIG, "bad port"));
        assert_eq!(error.unwrap().to_string(), "BUSBAR-acme-0007");
        assert!(!latch.load(Ordering::Relaxed));
    }

    #[test]
    fn a_failed_answer_carries_both_facts_and_an_undeclared_number_is_none_and_latches() {
        use busbar_plugin_abi::fail::fact::{FACT_BACKEND_STATUS, FACT_RETRY_AFTER_S};
        let r = fail(
            Status::FAILED,
            failed::F_UPSTREAM,
            "down",
            8,
            &[(FACT_RETRY_AFTER_S, 30), (FACT_BACKEND_STATUS, 503)],
        );
        let a = Answer::parse(Status::FAILED, r.as_bytes()).unwrap();
        let latch = AtomicBool::new(false);
        assert_eq!(
            port_error(&Scrub::new(), &BOOK, &latch, &a),
            Some(PortError::Failed {
                code: failed::F_UPSTREAM,
                text: "down".into(),
                retry_after_s: Some(30),
                backend_status: Some(503),
                error: None,
            })
        );
        assert!(latch.load(Ordering::Relaxed));
    }

    #[test]
    fn an_ok_answer_is_no_error_and_the_text_is_scrubbed() {
        let ok = Reply::new();
        let a = Answer::parse(Status::OK, ok.as_bytes()).unwrap();
        assert!(port_error(&Scrub::new(), &ErrorBook::None, &AtomicBool::new(false), &a).is_none());
        let r = fail(
            Status::REFUSED,
            refused::R_CONFIG,
            "key hunter2 bad",
            0,
            &[],
        );
        let a = Answer::parse(Status::REFUSED, r.as_bytes()).unwrap();
        let scrub = Scrub::from_needles([&b"hunter2"[..]]);
        let Some(PortError::Refused { text, .. }) =
            port_error(&scrub, &ErrorBook::None, &AtomicBool::new(false), &a)
        else {
            panic!("refused")
        };
        assert!(!text.contains("hunter2"), "{text}");
    }

    #[test]
    fn the_open_error_follows_the_port_error() {
        let refused = PortError::Refused {
            code: refused::R_CONFIG,
            text: "no".into(),
            error: None,
        };
        assert!(matches!(
            open_error(refused),
            OpenError::Config { code, .. } if code == refused::R_CONFIG
        ));
        let failed = PortError::Failed {
            code: failed::F_UPSTREAM,
            text: "down".into(),
            retry_after_s: None,
            backend_status: None,
            error: None,
        };
        assert!(matches!(open_error(failed), OpenError::Failed { .. }));
        let call = PortError::Call(busbar_plugin_abi::fail::CallError::Quarantined);
        assert!(matches!(
            open_error(call),
            OpenError::Call(busbar_plugin_abi::fail::CallError::Quarantined)
        ));
    }
}
