// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-PANIC (ABI-MIN3-INTERFACE §14): A plugin panic in any entry is FAULT and quarantine, never an abort.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).
//!
//! The sibling tests run every entry the branch routes through `driver::step` and its FAULT sink: describe,
//! open (start step and resume), a sync kind method, an async kind method's start step and its resume. Each
//! builds its own `Harness` first: the registry's fault sink attaches to the first registry in the process
//! (`install_sinks`), so the quarantine assertions hold one test per process (nextest, as CI runs).

use std::sync::Arc;
use std::time::{Duration, Instant};

use busbar_plugin_abi::fail::{CallError, FaultReason};
use busbar_plugin_abi::host_side::caller::CallStack;
use busbar_plugin_loader::instance::OpenError;
use busbar_plugin_loader::ports::export::{Delivered, ExportPort};
use busbar_plugin_loader::ports::{CallCx, PortError};
use busbar_plugin_loader::refusal::RefusalCode;
use busbar_plugin_test::fake_needs::FakeNeeds;
use busbar_plugin_test::suites::harness::Harness;

#[test]
#[ignore = "blocked (re-checked 2026-11-16) on #271 and on the missing MIN-3 migrate entry: a panic in `cancel` or `close` is not FAULT + quarantine, because busbar-ffi host.rs `Drop for Chain`/`Drop for Session` (cancel) and `Drop for Instance` (close) call the plugin outside `driver::step` and discard its Status (`let _ = cancel_raw(..)`, `let _ = close(..)`), so nothing reaches `report_fault` (busbar-ffi is owner-pinned, unsafe.yaml); and `migrate` has no MIN-3 entry on the branch (busbar-ffi header.rs `entries()` = describe/open/resume/cancel/close; plugin-loader registry.rs `migrate` is the 1.x door path). Describe, open (start and resume) and kind-method (sync, async start, async resume) panics run as the sibling tests below; cancel and close panics' no-abort half is c_panic_cancel's sibling"]
fn plugin_panic_faults_and_quarantines_without_abort() {
    todo!("owner: W1-L2 (C-PANIC)")
}

/// `render` scope that panics; any other scope answers CONTENT_TYPE + BODY.
const SCOPE_PANIC: u32 = 1;
const SCOPE_OK: u32 = 7;
/// `deliver` attempt that panics in the start step; one that panics after a FETCH (in the resume); any other
/// attempt ACKs the batch.
const ATTEMPT_START_PANIC: u32 = 1;
const ATTEMPT_RESUME_PANIC: u32 = 2;
const ATTEMPT_OK: u32 = 3;

/// An export image that panics where it is told to: in `open` (config `{"open": "panic"}` before any NEED,
/// `{"open": "resume-panic"}` after a FETCH), in the sync `render` (scope [`SCOPE_PANIC`]) and in the async
/// `deliver` (attempts [`ATTEMPT_START_PANIC`], [`ATTEMPT_RESUME_PANIC`]). `describe_panics` is a second image
/// whose `describe` panics. No `unsafe`: the glue is `plugin!`'s output.
mod fixture {
    use std::collections::HashMap;

    use busbar_plugin_abi::fail::refused::R_CONFIG;
    use busbar_plugin_abi::fail::Fail;
    use busbar_plugin_abi::host::Host;
    use busbar_plugin_abi::need::need::{self, Fetch};
    use busbar_plugin_abi::need::{egress, ChainBytes, TrustHandle};
    use busbar_plugin_abi::plugin::{Describe, Endpoints, Open};
    use busbar_plugin_abi::records::{tag as record, Out, Records, Reply, Writer};
    use busbar_plugin_abi::types::Bytes;
    use busbar_plugin_abi::Export;

    use super::{ATTEMPT_RESUME_PANIC, ATTEMPT_START_PANIC, SCOPE_PANIC};

    pub struct Panicky;

    fn open_mode(config: &[u8]) -> Result<Option<String>, Fail> {
        busbar_contract::json::parse::<HashMap<String, String>>(config)
            .map(|mut map| map.remove("open"))
            .map_err(|_| Fail::refused_because(R_CONFIG, "config must be an object"))
    }

    /// One FETCH, its answer ignored: a NEED step, so what follows runs in a `resume`.
    async fn one_need() {
        let req = Fetch {
            method: "GET",
            url: "https://panic.test/step",
            headers: &[],
            body: &[],
            max_body: 64,
            trust: TrustHandle::NONE,
            cert: None,
            egress: egress::OPEN_WEB,
        };
        let _ = need::fetch(&req).await;
    }

    impl Open for Panicky {
        async fn open(_h: &'static Host, config: ChainBytes) -> Result<Self, Fail> {
            match config.with(open_mode)?.as_deref() {
                Some("panic") => panic!("C-PANIC: open panics in its start step"),
                Some("resume-panic") => {
                    one_need().await;
                    panic!("C-PANIC: open panics in its resume")
                }
                _ => Ok(Panicky),
            }
        }

        fn check(_h: &Host, config: &[u8], _ends: &mut Endpoints<'_>) -> Result<(), Fail> {
            open_mode(config).map(|_| ())
        }

        fn describe(d: &mut Describe<'_>) {
            d.schema(r#"{"type":"object"}"#);
            d.methods(busbar_plugin_abi::export::M_DELIVER | busbar_plugin_abi::export::M_RENDER);
            d.item(
                busbar_plugin_abi::export::tag::D_STREAMS,
                &[busbar_plugin_abi::export::STREAM_LOGS as u8],
            );
        }
    }

    impl Export for Panicky {
        async fn deliver(
            &self,
            _h: &'static Host,
            _stream: u32,
            _delivery: u64,
            attempt: u32,
            batch: ChainBytes,
        ) -> Result<Reply, Fail> {
            if attempt == ATTEMPT_START_PANIC {
                panic!("C-PANIC: deliver panics in its start step");
            }
            if attempt == ATTEMPT_RESUME_PANIC {
                one_need().await;
                panic!("C-PANIC: deliver panics in its resume");
            }
            let accepted = batch.with(|bytes| {
                Records::new(bytes)
                    .filter(|rec| matches!(rec, Ok(rec) if rec.tag == record::TEXT))
                    .count() as u64
            });
            let mut reply = Reply::new();
            reply
                .put_pod(
                    busbar_plugin_abi::export::tag::ACK,
                    &busbar_plugin_abi::export::Ack { accepted },
                )
                .map_err(Fail::from)?;
            Ok(reply)
        }

        fn render(
            &self,
            _h: &Host,
            scope: u32,
            _snapshot: Bytes<'_>,
            out: &mut Out<'_>,
        ) -> Result<(), Fail> {
            if scope == SCOPE_PANIC {
                panic!("C-PANIC: render panics");
            }
            out.put_text(busbar_plugin_abi::export::tag::CONTENT_TYPE, "text/plain")?;
            out.put(busbar_plugin_abi::export::tag::BODY, b"ok")?;
            Ok(())
        }
    }

    busbar_plugin_abi::plugin!(Export, Panicky, name: "fixture-panic");

    /// The image whose `describe` panics.
    pub mod describe_panics {
        use busbar_plugin_abi::fail::Fail;
        use busbar_plugin_abi::host::Host;
        use busbar_plugin_abi::need::ChainBytes;
        use busbar_plugin_abi::plugin::{Describe, Endpoints, Open};
        use busbar_plugin_abi::Export;

        pub struct BadDescribe;

        impl Open for BadDescribe {
            async fn open(_h: &'static Host, _config: ChainBytes) -> Result<Self, Fail> {
                Ok(BadDescribe)
            }

            fn check(_h: &Host, _config: &[u8], _ends: &mut Endpoints<'_>) -> Result<(), Fail> {
                Ok(())
            }

            fn describe(_d: &mut Describe<'_>) {
                panic!("C-PANIC: describe panics");
            }
        }

        impl Export for BadDescribe {}

        busbar_plugin_abi::plugin!(Export, BadDescribe, name: "fixture-panic-describe");
    }
}

fn harness() -> Harness {
    Harness::admit(fixture::PLUGIN.plugin(), FakeNeeds::new())
        .unwrap_or_else(|r| panic!("the panic fixture must be admitted: {r:?}"))
}

fn open(h: &Harness, name: &str) -> Arc<dyn ExportPort> {
    h.open_export(name, b"{}")
        .unwrap_or_else(|e| panic!("{name}: the panic fixture must open: {e:?}"))
}

fn cx() -> CallCx {
    CallCx {
        deadline: Instant::now() + Duration::from_secs(30),
        request_id: 1,
        stack: CallStack::default(),
    }
}

fn render(port: &dyn ExportPort, scope: u32) -> Result<Vec<u8>, PortError> {
    let mut body = Vec::new();
    port.render(scope, &[], &mut |_: &str, b: &[u8]| {
        body.extend_from_slice(b)
    })?;
    Ok(body)
}

fn deliver(h: &Harness, port: &dyn ExportPort, attempt: u32) -> Result<Delivered, PortError> {
    let lines: [&[u8]; 1] = [b"one line"];
    h.block_on(port.deliver(
        cx(),
        busbar_plugin_abi::export::STREAM_LOGS,
        1,
        attempt,
        &lines,
    ))
}

fn is_panic_fault(e: &PortError) -> bool {
    matches!(e, PortError::Call(CallError::Fault(FaultReason::Panic)))
}

fn is_quarantined(e: &PortError) -> bool {
    matches!(e, PortError::Call(CallError::Quarantined))
}

/// No abort: after the panic the same image opens a fresh instance that serves both kinds of call.
fn still_serves(h: &Harness, name: &str) {
    let fresh = open(h, name);
    assert_eq!(
        render(&*fresh, SCOPE_OK).unwrap_or_else(|e| panic!("{name}: render failed: {e:?}")),
        b"ok"
    );
    match deliver(h, &*fresh, ATTEMPT_OK) {
        Ok(Delivered::Acked { accepted, .. }) => assert_eq!(accepted, 1, "{name}"),
        other => panic!("{name}: deliver answered {other:?}"),
    }
}

/// After a FAULT the instance is quarantined: every later call, of either kind, is refused before the plugin.
fn assert_quarantined(h: &Harness, port: &dyn ExportPort, what: &str) {
    let rendered = render(port, SCOPE_OK);
    assert!(
        matches!(&rendered, Err(e) if is_quarantined(e)),
        "{what}: a later render must be Quarantined, got {rendered:?}"
    );
    let delivered = deliver(h, port, ATTEMPT_OK);
    assert!(
        matches!(&delivered, Err(e) if is_quarantined(e)),
        "{what}: a later deliver must be Quarantined, got {delivered:?}"
    );
}

#[test]
fn a_panic_in_a_sync_method_faults_and_quarantines_the_instance() {
    let h = harness();
    let port = open(&h, "sync");
    let got = render(&*port, SCOPE_PANIC);
    assert!(
        matches!(&got, Err(e) if is_panic_fault(e)),
        "a panicking render is FAULT Panic, got {got:?}"
    );
    assert_quarantined(&h, &*port, "sync");
    still_serves(&h, "sync-after");
}

#[test]
fn a_panic_in_an_async_start_step_faults_and_quarantines_the_instance() {
    let h = harness();
    let port = open(&h, "start");
    let got = deliver(&h, &*port, ATTEMPT_START_PANIC);
    assert!(
        matches!(&got, Err(e) if is_panic_fault(e)),
        "a deliver panicking in its start step is FAULT Panic, got {got:?}"
    );
    assert_quarantined(&h, &*port, "start");
    still_serves(&h, "start-after");
}

#[test]
fn a_panic_in_a_resume_faults_and_quarantines_the_instance() {
    let h = harness();
    let port = open(&h, "resume");
    let got = deliver(&h, &*port, ATTEMPT_RESUME_PANIC);
    assert!(
        matches!(&got, Err(e) if is_panic_fault(e)),
        "a deliver panicking in its resume is FAULT Panic, got {got:?}"
    );
    assert_quarantined(&h, &*port, "resume");
    still_serves(&h, "resume-after");
}

#[test]
fn a_panic_in_open_faults_and_refuses_the_instance() {
    let h = harness();
    for (name, config) in [
        ("open-start", &br#"{"open":"panic"}"#[..]),
        ("open-resume", &br#"{"open":"resume-panic"}"#[..]),
    ] {
        match h.open_export(name, config) {
            Err(OpenError::Call(CallError::Fault(FaultReason::Panic))) => {}
            Err(e) => panic!("{name}: a panicking open is FAULT Panic, got {e:?}"),
            Ok(_) => panic!("{name}: a panicking open must not build an instance"),
        }
    }
    still_serves(&h, "open-after");
}

#[test]
fn a_panic_in_describe_refuses_the_image() {
    match Harness::admit(fixture::describe_panics::PLUGIN.plugin(), FakeNeeds::new()) {
        Err(refusal) => {
            assert_eq!(refusal.code, RefusalCode::DescribeInvalid, "{refusal:?}");
            assert_eq!(refusal.field, "describe", "{refusal:?}");
        }
        Ok(_) => panic!("an image whose describe panics must be refused"),
    }
    let h = harness();
    still_serves(&h, "describe-after");
}
