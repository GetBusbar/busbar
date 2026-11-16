// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-FAIL-RESET (ABI-MIN3-INTERFACE §14): `Err(Full)` after writing max_out is exactly one FAIL F_LIMIT and the
//! instance stays LIVE; a REFUSED answer's `records()` is empty.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).
//!
//! The fixture's sync `render` (an export method) writes records until its out buffer is full and returns the
//! `Full` it got, or writes records and then refuses. Through the registry the instance's FAILED F_LIMIT comes
//! back as the port's error and the instance keeps serving (no FAULT, no quarantine). Over busbar-ffi's safe host
//! API the raw answers are read back: exactly one FAIL record each, and the REFUSED answer's `records()` empty.

use busbar_ffi::host::{OpenAnswer, OutLease};
use busbar_ffi::image::Admitted;
use busbar_ffi::{Arg, Bytes, Status};
use busbar_plugin_abi::fail::failed::F_LIMIT;
use busbar_plugin_abi::fail::refused::R_INVALID;
use busbar_plugin_abi::host_side::answer::Answer;
use busbar_plugin_abi::host_side::HOST;
use busbar_plugin_abi::records::{tag, Records};
use busbar_plugin_loader::ports::export::ExportPort;
use busbar_plugin_loader::ports::PortError;
use busbar_plugin_test::fake_needs::FakeNeeds;
use busbar_plugin_test::suites::harness::Harness;

/// `render` scopes: fill the out buffer then return `Err(Full)`; write records then refuse; answer OK.
const SCOPE_FULL: u32 = 1;
const SCOPE_REFUSE: u32 = 2;
const SCOPE_OK: u32 = 3;

/// An export image with D_MAX_OUT = 64 (core clamps it up to its 4 KiB entry-buffer floor, §10.1) whose sync
/// `render` answers per scope. No `unsafe`: the glue is `plugin!`'s output.
mod fixture {
    use busbar_plugin_abi::fail::refused::R_INVALID;
    use busbar_plugin_abi::fail::Fail;
    use busbar_plugin_abi::host::Host;
    use busbar_plugin_abi::need::ChainBytes;
    use busbar_plugin_abi::plugin::{Describe, Endpoints, Open};
    use busbar_plugin_abi::records::{Out, Writer};
    use busbar_plugin_abi::types::Bytes;
    use busbar_plugin_abi::Export;

    use super::{SCOPE_FULL, SCOPE_REFUSE};

    pub struct Filler;

    impl Open for Filler {
        async fn open(_h: &'static Host, _config: ChainBytes) -> Result<Self, Fail> {
            Ok(Filler)
        }

        fn check(_h: &Host, _config: &[u8], _ends: &mut Endpoints<'_>) -> Result<(), Fail> {
            Ok(())
        }

        fn describe(d: &mut Describe<'_>) {
            d.schema(r#"{"type":"object"}"#);
            d.max_out(64);
            d.methods(busbar_plugin_abi::export::M_RENDER);
        }
    }

    impl Export for Filler {
        fn render(
            &self,
            _h: &Host,
            scope: u32,
            _snapshot: Bytes<'_>,
            out: &mut Out<'_>,
        ) -> Result<(), Fail> {
            let body = busbar_plugin_abi::export::tag::BODY;
            if scope == SCOPE_FULL {
                // Up to max_out: every record that fits is written; the first that does not is the `Full`
                // returned (as F_LIMIT, `From<Full> for Fail`).
                out.put(body, &[0xA5u8; 200])?;
                return Ok(());
            }
            out.put_text(busbar_plugin_abi::export::tag::CONTENT_TYPE, "text/plain")?;
            out.put(body, b"ok")?;
            if scope == SCOPE_REFUSE {
                return Err(Fail::refused_because(R_INVALID, "refused after writing"));
            }
            Ok(())
        }
    }

    busbar_plugin_abi::plugin!(Export, Filler, name: "fixture-fail-reset");
}

fn render(port: &dyn ExportPort, scope: u32) -> (Result<(), PortError>, Vec<u8>) {
    let mut body = Vec::new();
    let got = port.render(scope, &[], &mut |_: &str, b: &[u8]| {
        body.extend_from_slice(b)
    });
    (got, body)
}

/// One raw `render` over busbar-ffi's host API on a lease that grows up to `max_out`: the status and the
/// answer's records as (tag, body).
fn raw_render(
    instance: &busbar_ffi::host::Instance<busbar_plugin_abi::export::Marker>,
    scope: u32,
    max_out: usize,
) -> (Status, Vec<(u16, Vec<u8>)>, Option<(u32, usize)>) {
    let mut lease =
        OutLease::new(vec![0; 4096], max_out).unwrap_or_else(|| panic!("the ACTIVE stack is full"));
    let status = instance.call2(
        |vt| &vt.render,
        Arg::u32(scope),
        Arg::bytes(Bytes::new(&[])),
        &mut lease,
    );
    lease.with_answer(|bytes| {
        let recs: Vec<(u16, Vec<u8>)> = Records::new(bytes)
            .map(|rec| match rec {
                Ok(rec) => (rec.tag, rec.body.to_vec()),
                Err(e) => panic!("scope {scope}: the answer is not framed: {e:?}"),
            })
            .collect();
        let parsed = Answer::parse(status, bytes)
            .unwrap_or_else(|e| panic!("scope {scope}: the answer does not validate: {e:?}"));
        let fail = parsed
            .fail()
            .map(|(code, _)| (code, parsed.records().count()));
        (status, recs, fail)
    })
}

#[test]
fn full_is_one_fail_f_limit_and_the_instance_stays_live() {
    let h = Harness::admit(fixture::PLUGIN.plugin(), FakeNeeds::new())
        .unwrap_or_else(|r| panic!("the fixture must be admitted: {r:?}"));
    let port = h
        .open_export("fail-reset", b"{}")
        .unwrap_or_else(|e| panic!("the fixture must open: {e:?}"));

    // Through the registry, twice: FAILED F_LIMIT with no facts and no ERROR (the shim reset what was written:
    // a leftover record before FAIL would not validate and would be FAULT, quarantining the instance), and the
    // instance stays LIVE: the next call is served.
    for round in 1..=2 {
        let (got, body) = render(&*port, SCOPE_FULL);
        match got {
            Err(PortError::Failed {
                code,
                retry_after_s: None,
                backend_status: None,
                error: None,
                ..
            }) => assert_eq!(code, F_LIMIT, "round {round}: the FAIL is F_LIMIT"),
            other => panic!("round {round}: Err(Full) must be one FAILED F_LIMIT, got {other:?}"),
        }
        assert!(
            body.is_empty(),
            "round {round}: nothing of a failed answer reaches the sink"
        );
        let (got, body) = render(&*port, SCOPE_OK);
        assert!(
            got.is_ok(),
            "round {round}: the instance stays LIVE after F_LIMIT, got {got:?}"
        );
        assert_eq!(body, b"ok", "round {round}: the live instance answers");
    }
    let (got, body) = render(&*port, SCOPE_REFUSE);
    assert!(
        matches!(&got, Err(PortError::Refused { code, .. }) if *code == R_INVALID),
        "a refusal after writing is REFUSED R_INVALID, got {got:?}"
    );
    assert!(
        body.is_empty(),
        "nothing of a refused answer reaches the sink"
    );
    assert!(
        render(&*port, SCOPE_OK).0.is_ok(),
        "the instance stays LIVE after a refusal"
    );

    // The raw answers: exactly one FAIL record, nothing the method wrote before it; `records()` empty.
    let image = Admitted::linked(&fixture::PLUGIN)
        .unwrap_or_else(|_| panic!("the fixture image must be admitted by busbar-ffi"));
    let mut opening =
        OutLease::new(vec![0; 4096], 1 << 20).unwrap_or_else(|| panic!("the ACTIVE stack is full"));
    let instance = match image.open::<busbar_plugin_abi::export::Marker>(
        &HOST,
        b"{}".to_vec(),
        0,
        &mut opening,
    ) {
        OpenAnswer::Done(Status::OK, Some(instance)) => instance,
        _ => panic!("the fixture must open over busbar-ffi"),
    };
    drop(opening);

    let (status, recs, fail) = raw_render(&instance, SCOPE_FULL, 4096);
    assert_eq!(status, Status::FAILED, "Err(Full) at max_out is FAILED");
    assert_eq!(
        recs.iter().map(|(t, _)| *t).collect::<Vec<_>>(),
        [tag::FAIL],
        "Err(Full) after writing max_out is exactly one FAIL record"
    );
    assert_eq!(
        fail,
        Some((F_LIMIT, 0)),
        "the FAIL is F_LIMIT and records() is empty"
    );

    let (status, recs, fail) = raw_render(&instance, SCOPE_REFUSE, 4096);
    assert_eq!(status, Status::REFUSED, "a refusal is REFUSED");
    assert_eq!(
        recs.iter().map(|(t, _)| *t).collect::<Vec<_>>(),
        [tag::FAIL],
        "a REFUSED answer is exactly one FAIL record: CONTENT_TYPE and BODY were discarded"
    );
    assert_eq!(
        fail,
        Some((R_INVALID, 0)),
        "a REFUSED answer's records() is empty"
    );

    let (status, recs, fail) = raw_render(&instance, SCOPE_OK, 4096);
    assert_eq!(status, Status::OK, "the raw instance still answers");
    assert_eq!(
        recs.iter().map(|(t, _)| *t).collect::<Vec<_>>(),
        [
            busbar_plugin_abi::export::tag::CONTENT_TYPE,
            busbar_plugin_abi::export::tag::BODY
        ]
    );
    assert_eq!(fail, None, "an OK answer carries no FAIL");
}
