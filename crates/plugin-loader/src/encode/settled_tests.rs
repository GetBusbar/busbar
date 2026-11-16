// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! W1-A5: `decode_settled`'s grammar: INSTANCE, then an optional CONFIG and CORE_CFG*, stopping before a last
//! export CUSTODY.

use busbar_plugin_abi::kinds::export::export::tag::CUSTODY;
use busbar_plugin_abi::records::{
    core_cfg, tag, CoreCfgRec, InstanceRec, RecErr, Records, Reply, Writer,
};

use super::*;

fn open() -> Reply {
    let mut w = Reply::new();
    w.put_pod(tag::INSTANCE, &InstanceRec { inst: 7 }).unwrap();
    w
}

fn cfg(w: &mut Reply, section: u32, name: &str, value: &[u8]) {
    let head = CoreCfgRec {
        section,
        name_len: name.len() as u32,
    };
    w.put_pod_tail(tag::CORE_CFG, &head, &[name.as_bytes(), value].concat())
        .unwrap();
}

fn settled(w: &Reply) -> Result<Option<SettledOut<'_>>, RecErr> {
    settled_records(Records::new(w.as_bytes()))
}

#[test]
fn an_open_answer_with_only_an_instance_has_no_settled_part() {
    assert!(settled(&open()).unwrap().is_none());
}

#[test]
fn config_alone_and_config_with_core_cfg_are_borrowed_from_the_answer() {
    let mut w = open();
    w.put(tag::CONFIG, br#"{"a":1}"#).unwrap();
    let got = settled(&w).unwrap().unwrap();
    assert_eq!(got.config, br#"{"a":1}"#);
    assert_eq!(got.core_cfg.count(), 0);

    cfg(
        &mut w,
        core_cfg::UPSTREAM,
        "primary",
        br#"{"url":"https://x"}"#,
    );
    cfg(&mut w, core_cfg::LIMITS, "", b"{}");
    let got = settled(&w).unwrap().unwrap();
    let recs: Vec<_> = got.core_cfg.map(Result::unwrap).collect();
    assert_eq!(recs.len(), 2);
    let (head, tail) = recs[0].pod_tail::<CoreCfgRec>().unwrap();
    assert_eq!(head.section, core_cfg::UPSTREAM);
    assert_eq!(&tail[..head.name_len as usize], b"primary");
    let (head, tail) = recs[1].pod_tail::<CoreCfgRec>().unwrap();
    assert_eq!(
        (head.section, head.name_len, tail),
        (core_cfg::LIMITS, 0, &b"{}"[..])
    );
}

#[test]
fn a_last_custody_record_ends_the_settled_part_and_is_not_in_it() {
    let mut w = open();
    w.put(tag::CONFIG, b"{}").unwrap();
    cfg(&mut w, core_cfg::LIFT, "", br#""/token""#);
    w.put(CUSTODY, &[0; 8]).unwrap();
    let got = settled(&w).unwrap().unwrap();
    assert_eq!(got.core_cfg.count(), 1);

    // An instance with no settled part may still end in CUSTODY.
    let mut w = open();
    w.put(CUSTODY, &[0; 8]).unwrap();
    assert!(settled(&w).unwrap().is_none());

    // CUSTODY that is not last, or a second one, is a kind-range record there.
    let mut w = open();
    w.put(CUSTODY, &[0; 8]).unwrap();
    w.put(CUSTODY, &[0; 8]).unwrap();
    assert_eq!(settled(&w).err(), Some(RecErr::Unknown(CUSTODY)));
    let mut w = open();
    w.put(tag::CONFIG, b"{}").unwrap();
    w.put(CUSTODY, &[0; 8]).unwrap();
    cfg(&mut w, core_cfg::LIMITS, "", b"{}");
    assert_eq!(settled(&w).err(), Some(RecErr::Unknown(CUSTODY)));
}

#[test]
fn any_other_record_after_instance_is_an_unknown_tag() {
    let mut w = open();
    w.put(0x0101, b"").unwrap();
    assert_eq!(settled(&w).err(), Some(RecErr::Unknown(0x0101)));
    let mut w = open();
    w.put(tag::CONFIG, b"{}").unwrap();
    w.put(tag::TEXT, b"x").unwrap();
    assert_eq!(settled(&w).err(), Some(RecErr::Unknown(tag::TEXT)));
}

#[test]
fn core_cfg_needs_config_and_config_comes_once_first() {
    let mut w = open();
    cfg(&mut w, core_cfg::LIMITS, "", b"{}");
    assert!(settled(&w).is_err());
    let mut w = open();
    w.put(tag::CONFIG, b"{}").unwrap();
    w.put(tag::CONFIG, b"{}").unwrap();
    assert!(settled(&w).is_err());
    let mut w = open();
    w.put(tag::CONFIG, b"{}").unwrap();
    cfg(&mut w, core_cfg::LIMITS, "", b"{}");
    w.put(tag::CONFIG, b"{}").unwrap();
    assert!(settled(&w).is_err());
}

#[test]
fn an_answer_without_a_leading_instance_is_refused() {
    let mut w = Reply::new();
    w.put(tag::CONFIG, b"{}").unwrap();
    assert!(settled(&w).is_err());
    assert!(settled_records(Records::new(&[])).is_err());
}

#[test]
fn config_and_core_cfg_values_are_utf8_and_names_follow_the_grammar() {
    let mut w = open();
    w.put(tag::CONFIG, &[0xff, 0xfe]).unwrap();
    assert_eq!(settled(&w).err(), Some(RecErr::Utf8));

    let bad = |section: u32, name: &str, value: &[u8]| {
        let mut w = open();
        w.put(tag::CONFIG, b"{}").unwrap();
        cfg(&mut w, section, name, value);
        settled(&w).is_err()
    };
    assert!(bad(core_cfg::UPSTREAM, "Upper", b"{}"));
    assert!(bad(core_cfg::UPSTREAM, "", b"{}"));
    assert!(bad(core_cfg::UPSTREAM, &"a".repeat(65), b"{}"));
    assert!(bad(core_cfg::UPSTREAM, "has space", b"{}"));
    assert!(bad(core_cfg::UPSTREAM, "ok", &[0xff]));
    assert!(!bad(core_cfg::UPSTREAM, "a.b_c-1", b"{}"));
    assert!(!bad(core_cfg::TRUST_APPROVAL, &"a".repeat(64), b"{}"));
    // LIMITS and LIFT are always the migrating instance's own: the name is empty.
    assert!(!bad(core_cfg::LIMITS, "", b"{}"));
    assert!(bad(core_cfg::LIMITS, "x", b"{}"));
    assert!(bad(core_cfg::LIFT, "x", b"\"/p\""));

    // A name longer than the record is a size error.
    let mut w = open();
    w.put(tag::CONFIG, b"{}").unwrap();
    let head = CoreCfgRec {
        section: core_cfg::UPSTREAM,
        name_len: 9,
    };
    w.put_pod_tail(tag::CORE_CFG, &head, b"abc").unwrap();
    assert_eq!(settled(&w).err(), Some(RecErr::Size));
}

#[test]
fn a_settled_limits_value_is_applied_in_memory_clamped_and_never_over_a_set_number() {
    let base = InstanceLimits {
        max_inflight: 4,
        ..InstanceLimits::default()
    };
    let got = with_limits_json(
        base,
        br#"{"timeout_ms": 700000, "connect_timeout_ms": 1500, "max_inflight": 9, "plaintext": "deny"}"#,
    );
    assert_eq!(
        (got.timeout_ms, got.connect_timeout_ms, got.max_inflight),
        (MAX_LIMIT_MS, 1_500, 4),
        "clamped to 600,000 ms; a number the instance already carries is kept"
    );
    let big = with_limits_json(InstanceLimits::default(), br#"{"max_inflight": 70000}"#);
    assert_eq!(big.max_inflight, MAX_INFLIGHT);
    assert_eq!(
        with_limits_json(InstanceLimits::default(), b"[1]"),
        InstanceLimits::default(),
        "not an object: unchanged"
    );
}
