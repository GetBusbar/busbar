// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_ports::PortError;

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
    use busbar_plugin_abi::fail::fact::{FACT_BACKEND_STATUS, FACT_RETRY_AFTER_S};
    use busbar_plugin_abi::types::Status;

    let refused = answer.status == Status::REFUSED;
    if !refused && answer.status != Status::FAILED {
        return None;
    }
    let (code, text) = answer.fail()?;
    let text: Box<str> = busbar_plugin_abi::host_side::scrub::fail_text(scrub, text)
        .as_ref()
        .into();
    let error = errors.resolve(answer.fail_error(), latch);
    Some(if refused {
        PortError::Refused { code, text, error }
    } else {
        PortError::Failed {
            code,
            text,
            retry_after_s: answer.fail_fact(FACT_RETRY_AFTER_S),
            backend_status: answer.fail_fact(FACT_BACKEND_STATUS),
            error,
        }
    })
}

/// A refused or failed port answer as the open's error: REFUSED is `Config` (the instance's own settings were
/// refused), FAILED is `Failed`, a call error stays one.
pub fn open_error(error: PortError) -> crate::instance::OpenError {
    use crate::instance::OpenError;

    match error {
        PortError::Refused { code, text, error } => OpenError::Config {
            code,
            text: text.into(),
            error,
        },
        PortError::Failed {
            code, text, error, ..
        } => OpenError::Failed {
            code,
            text: text.into(),
            error,
        },
        PortError::Call(e) => OpenError::Call(e),
    }
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
