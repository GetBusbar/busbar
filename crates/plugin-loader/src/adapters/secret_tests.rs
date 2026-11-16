// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! W1-L4: the secret adapter's answer decode and failure shape (IF §8.2, §11.3, §12.16). The proxy loop itself
//! needs a plugin image (the conformance suites, which wait on `Registry::new`); what the adapter adds on top of
//! it is these two pure steps.

use busbar_plugin_abi::fail::{fact, refused, FAIL_TEXT_WIRE_MAX};
use busbar_plugin_abi::host_side::scrub::{Scrub, FAIL_TEXT_SHOWN};
use busbar_plugin_abi::kinds::secret::secret::{tag, F_LEASE_S};
use busbar_plugin_abi::records::{RecErr, Records, Reply, Writer};

use super::*;

const SECRET: &[u8] = b"adapter-secret-0123456789ABCDEF";

fn ok(value: Option<&[u8]>, facts: &[(u32, u64)]) -> Reply {
    let mut w = Reply::new();
    if let Some(v) = value {
        w.put(tag::VALUE, v).unwrap();
    }
    for (k, v) in facts {
        w.put_fact(*k, *v).unwrap();
    }
    w
}

fn decode(w: &Reply) -> Result<SecretAnswer, RecErr> {
    answer_value(Records::new(w.as_bytes()))
}

#[test]
fn an_ok_answer_is_the_value_and_the_lease_it_stated() {
    let a = decode(&ok(Some(SECRET), &[(F_LEASE_S, 90)])).unwrap();
    assert_eq!(a.value.as_slice(), SECRET);
    assert_eq!(a.lease_s, Some(90));
    let a = decode(&ok(Some(b""), &[])).unwrap();
    assert!(a.value.is_empty());
    assert_eq!(a.lease_s, None);
}

#[test]
fn a_malformed_ok_answer_is_a_contract_break() {
    assert_eq!(decode(&ok(None, &[])).err(), Some(RecErr::Size));
    let mut two = ok(Some(b"a"), &[]);
    two.put(tag::VALUE, b"b").unwrap();
    assert_eq!(decode(&two).err(), Some(RecErr::Size));
    let twice = ok(Some(b"a"), &[(F_LEASE_S, 1), (F_LEASE_S, 2)]);
    assert_eq!(decode(&twice).err(), Some(RecErr::Size));
    let other = ok(Some(b"a"), &[(fact::FACT_RETRY_AFTER_S, 1)]);
    assert_eq!(decode(&other).err(), Some(RecErr::Size));
    let mut foreign = ok(Some(b"a"), &[]);
    foreign.put(0x0155, b"x").unwrap();
    assert_eq!(decode(&foreign).err(), Some(RecErr::Unknown(0x0155)));
}

#[test]
fn a_failed_answer_carries_exactly_the_facts_it_stated() {
    let scrub = Scrub::new();
    let e = port_failure(
        &scrub,
        true,
        3,
        "backend said 503",
        Some(30),
        Some(503),
        None,
    );
    assert_eq!(
        e,
        PortError::Failed {
            code: 3,
            text: "backend said 503".into(),
            retry_after_s: Some(30),
            backend_status: Some(503),
            error: None,
        }
    );
    let e = port_failure(&scrub, true, 3, "down", None, None, None);
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
fn a_refusal_is_a_refusal_with_no_facts() {
    let scrub = Scrub::new();
    let e = port_failure(
        &scrub,
        false,
        refused::R_NOT_FOUND,
        "no such name",
        Some(9),
        Some(9),
        None,
    );
    assert_eq!(
        e,
        PortError::Refused {
            code: refused::R_NOT_FOUND,
            text: "no such name".into(),
            error: None,
        }
    );
}

#[test]
fn the_failure_text_is_scrubbed_whole_and_then_cut() {
    let scrub = Scrub::new();
    scrub.register(1, &[SECRET]);
    let secret = core::str::from_utf8(SECRET).unwrap();
    let text = format!("{}{secret}{}", "a".repeat(500), "b".repeat(60));
    for failed in [true, false] {
        let e = port_failure(&scrub, failed, 1, &text, None, None, None);
        let shown = match &e {
            PortError::Failed { text, .. } | PortError::Refused { text, .. } => text,
            PortError::Call(_) => unreachable!(),
        };
        assert!(shown.len() <= FAIL_TEXT_SHOWN);
        assert!(!shown.contains(&secret[..8]), "{shown}");
    }
    // A secret cut by the wire bound leaves no prefix behind.
    let cut = format!("{}{}", "a".repeat(FAIL_TEXT_WIRE_MAX - 12), &secret[..12]);
    let e = port_failure(&scrub, true, 1, &cut, None, None, None);
    let PortError::Failed { text, .. } = e else {
        unreachable!()
    };
    assert!(text.len() <= FAIL_TEXT_SHOWN);
    assert!(!text.contains(&secret[..8]));
}
