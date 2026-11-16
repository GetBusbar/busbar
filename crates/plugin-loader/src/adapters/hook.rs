// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The hook adapter: `HookPort` over the hook kind's `Proxy` (IF §11.3, §8.4).

use busbar_plugin_abi::host_side::scrub::Scrub;
use busbar_plugin_abi::kinds::hook::hook::{Proxy, Verdict as VerdictRec};
use busbar_plugin_abi::records::{RecErr, Records};

use crate::instance::PluginCode;
use crate::ports::PortError;
use crate::ports::hook::HookAnswer;

/// The hook port over one instance's proxy.
pub struct HookAdapter {
    proxy: Proxy,
}

impl HookAdapter {
    pub fn new(proxy: Proxy) -> Self {
        Self { proxy }
    }

    pub fn proxy(&self) -> &Proxy {
        &self.proxy
    }
}

/// The VERDICT then the answer's data records (IF §8.4); METRIC records are skipped.
fn decode_answer(recs: Records<'_>, scrub: &Scrub) -> Result<HookAnswer, RecErr> {
    let _ = (recs, scrub);
    let _: Option<VerdictRec> = None;
    todo!()
}

/// A REFUSED or FAILED answer as a `PortError`. The text is scrubbed whole, then cut (I14).
#[allow(clippy::too_many_arguments)]
fn port_error(
    scrub: &Scrub,
    failed_answer: bool,
    code: u32,
    text: &str,
    retry_after_s: Option<u64>,
    backend_status: Option<u64>,
    error: Option<PluginCode>,
) -> PortError {
    let _ = (
        scrub,
        failed_answer,
        code,
        text,
        retry_after_s,
        backend_status,
        error,
    );
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_plugin_abi::fail::failed;
    use busbar_plugin_abi::fail::refused::R_POLICY;
    use busbar_plugin_abi::kinds::hook::hook::{
        VERB_ABSTAIN, VERB_PREFER, VERB_REJECT, VERB_RESTRICT, tag,
    };
    use busbar_plugin_abi::records::{Reply, Writer};

    fn scrub_with(secret: &[u8]) -> Scrub {
        Scrub::from_needles([secret])
    }

    fn verdict(r: &mut Reply, verb: u32, status: u32) {
        r.put_pod(
            tag::VERDICT,
            &VerdictRec {
                verb,
                reject_status: status,
            },
        )
        .unwrap();
    }

    #[test]
    fn an_abstain_is_an_empty_answer() {
        let mut r = Reply::new();
        verdict(&mut r, VERB_ABSTAIN, 0);
        let a = decode_answer(Records::new(r.as_bytes()), &Scrub::new()).unwrap();
        assert_eq!(a.verb, VERB_ABSTAIN);
        assert!(
            a.order.is_empty()
                && a.restrict.is_empty()
                && a.message.is_none()
                && a.rewrite.is_none()
        );
        assert_eq!(a.reject_status, None);
    }

    #[test]
    fn order_restrict_message_and_rewrite_come_through() {
        let mut r = Reply::new();
        verdict(&mut r, VERB_PREFER, 0);
        let order: Vec<u8> = [2u32, 0, 1].iter().flat_map(|n| n.to_le_bytes()).collect();
        r.put(tag::ORDER, &order).unwrap();
        r.put_text(tag::RESTRICT, "a").unwrap();
        r.put_text(tag::RESTRICT, "b").unwrap();
        r.put_text(tag::MESSAGE, "over budget").unwrap();
        r.put(tag::REWRITE, b"{\"messages\":[]}").unwrap();
        r.put_metric(1, 1, 1.0, &[]).unwrap();
        let a = decode_answer(Records::new(r.as_bytes()), &Scrub::new()).unwrap();
        assert_eq!(a.order, [2, 0, 1]);
        assert_eq!(
            a.restrict.iter().map(|s| &**s).collect::<Vec<_>>(),
            ["a", "b"]
        );
        assert_eq!(a.message.as_deref(), Some("over budget"));
        assert_eq!(a.rewrite.as_deref(), Some(&b"{\"messages\":[]}"[..]));
    }

    #[test]
    fn only_a_reject_carries_a_status_and_zero_is_none() {
        let mut r = Reply::new();
        verdict(&mut r, VERB_REJECT, 429);
        assert_eq!(
            decode_answer(Records::new(r.as_bytes()), &Scrub::new())
                .unwrap()
                .reject_status,
            Some(429)
        );
        let mut r = Reply::new();
        verdict(&mut r, VERB_REJECT, 0);
        assert_eq!(
            decode_answer(Records::new(r.as_bytes()), &Scrub::new())
                .unwrap()
                .reject_status,
            None
        );
        let mut r = Reply::new();
        verdict(&mut r, VERB_RESTRICT, 429);
        assert_eq!(
            decode_answer(Records::new(r.as_bytes()), &Scrub::new())
                .unwrap()
                .reject_status,
            None
        );
    }

    #[test]
    fn a_malformed_answer_is_a_record_error() {
        let empty = Reply::new();
        assert!(decode_answer(Records::new(empty.as_bytes()), &Scrub::new()).is_err());
        let mut r = Reply::new();
        verdict(&mut r, 99, 0);
        assert!(decode_answer(Records::new(r.as_bytes()), &Scrub::new()).is_err());
        let mut r = Reply::new();
        verdict(&mut r, VERB_PREFER, 0);
        r.put(tag::ORDER, &[1, 2, 3]).unwrap();
        assert!(decode_answer(Records::new(r.as_bytes()), &Scrub::new()).is_err());
        let mut r = Reply::new();
        verdict(&mut r, VERB_PREFER, 0);
        r.put_text(tag::MESSAGE, "x").unwrap();
        r.put_text(tag::MESSAGE, "y").unwrap();
        assert!(decode_answer(Records::new(r.as_bytes()), &Scrub::new()).is_err());
    }

    #[test]
    fn a_message_is_scrubbed_before_it_is_cut() {
        let secret = b"s3cr3t-value-xyz";
        let mut r = Reply::new();
        verdict(&mut r, VERB_REJECT, 403);
        r.put_text(tag::MESSAGE, "denied for s3cr3t-value-xyz today")
            .unwrap();
        let a = decode_answer(Records::new(r.as_bytes()), &scrub_with(secret)).unwrap();
        let m = a.message.unwrap();
        assert!(!m.contains("s3cr3t"), "{m}");
        let long = format!("{}{}", "x".repeat(600), "tail");
        let mut r = Reply::new();
        verdict(&mut r, VERB_REJECT, 403);
        r.put_text(tag::MESSAGE, &long).unwrap();
        let a = decode_answer(Records::new(r.as_bytes()), &Scrub::new()).unwrap();
        assert_eq!(a.message.unwrap().len(), 512);
    }

    #[test]
    fn refused_has_no_facts_and_failed_maps_them() {
        let s = Scrub::new();
        let e = port_error(&s, false, R_POLICY, "no", Some(7), Some(503), None);
        assert_eq!(
            e,
            PortError::Refused {
                code: R_POLICY,
                text: "no".into(),
                error: None
            }
        );
        let e = port_error(
            &s,
            true,
            failed::F_UPSTREAM,
            "down",
            Some(30),
            Some(503),
            None,
        );
        assert_eq!(
            e,
            PortError::Failed {
                code: failed::F_UPSTREAM,
                text: "down".into(),
                retry_after_s: Some(30),
                backend_status: Some(503),
                error: None,
            }
        );
        let e = port_error(&s, true, failed::F_UPSTREAM, "down", None, None, None);
        assert!(matches!(
            e,
            PortError::Failed {
                retry_after_s: None,
                backend_status: None,
                ..
            }
        ));
    }

    #[test]
    fn a_port_error_text_never_carries_a_secret_or_exceeds_the_cut() {
        let s = scrub_with(b"hunter2-hunter2");
        let e = port_error(
            &s,
            true,
            failed::F_UNAVAILABLE,
            "bad hunter2-hunter2 here",
            None,
            None,
            None,
        );
        match e {
            PortError::Failed { text, .. } => assert!(!text.contains("hunter2")),
            other => panic!("{other:?}"),
        }
        let long = "y".repeat(2000);
        match port_error(&s, false, R_POLICY, &long, None, None, None) {
            PortError::Refused { text, .. } => assert_eq!(text.len(), 512),
            other => panic!("{other:?}"),
        }
    }
}
