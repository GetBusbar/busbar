// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-ERROR-RECORDS (ABI-MIN3-INTERFACE §14 round 34; PLUGIN-ERROR-CODES r4): FAIL, ERROR, FACTs in that order,
//! ERROR only when the number is not 0, and the longest such answer fits the first 4 KiB buffer. The record-order
//! arm is W1-A1's (merged); the other arms are the shim's, the C helpers', the answer parse's, the log sink's and
//! the render's. PLUGIN-ERROR-CODES §8 T1-T16 are owned per IF §50's owners paragraph.
//!
//! WBS rule 10: each ignored arm waits for the task that lands the last piece it needs; that task writes the
//! arm's body and un-ignores it in its own MR (red first, then green). Arms of tasks merged before W1-T1 run now.

use busbar_plugin_abi::fail::{fact, failed, Fail, FAIL_TEXT_WIRE_MAX};
use busbar_plugin_abi::records::{tag, FailRec, Records, Reply, U32Rec, Writer};

#[test]
fn fail_error_and_two_facts_fit_the_first_4_kib_in_order() {
    let fail = Fail::failed_because(failed::F_UPSTREAM, "x".repeat(FAIL_TEXT_WIRE_MAX))
        .with_fact(fact::FACT_RETRY_AFTER_S, 30)
        .with_fact(fact::FACT_BACKEND_STATUS, 503)
        .with_error(7071);
    let mut reply = Reply::new();
    let head = FailRec {
        status: fail.status().0,
        code: fail.code(),
    };
    reply
        .put_pod_tail(tag::FAIL, &head, fail.text().as_bytes())
        .expect("fail");
    let error = U32Rec {
        value: u32::from(fail.error()),
        _r: 0,
    };
    reply.put_pod(tag::ERROR, &error).expect("error");
    for (key, value) in fail.facts() {
        reply.put_fact(key, value).expect("fact");
    }
    assert!(reply.len() <= 4096, "{} bytes", reply.len());
    let tags: Vec<u16> = Records::new(reply.as_bytes())
        .map(|rec| rec.expect("framing").tag)
        .collect();
    assert_eq!(tags, [tag::FAIL, tag::ERROR, tag::FACT, tag::FACT]);
    assert_eq!(Fail::failed(failed::F_UPSTREAM).with_error(0).error(), 0);
}

#[test]
#[ignore = "owner: W1-A3"]
fn the_shim_writes_error_only_when_the_number_is_set() {
    todo!("owner: W1-A3 (C-ERROR-RECORDS)")
}

#[test]
#[ignore = "owner: W1-A13"]
fn the_c_helpers_write_the_same_bytes_and_arguments_as_the_rust_shim() {
    todo!("owner: W1-A13 (C-ERROR-RECORDS)")
}

#[test]
#[ignore = "owner: W1-H1"]
fn an_error_record_out_of_place_faults_and_the_accepted_forms_pass() {
    todo!("owner: W1-H1 (C-ERROR-RECORDS)")
}

#[test]
#[ignore = "owner: W1-L2"]
fn a_raw_log_and_an_error_over_9999_render_no_code_and_warn_once() {
    todo!("owner: W1-L2 (C-ERROR-RECORDS)")
}

#[test]
#[ignore = "owner: W1-K8D"]
fn a_bad_d_errors_admits_without_codes_and_a_store_and_gate_hook_still_serve() {
    todo!("owner: W1-K8D (C-ERROR-RECORDS)")
}
