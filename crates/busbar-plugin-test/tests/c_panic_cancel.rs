// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-PANIC-CANCEL (ABI-MIN3-INTERFACE §14): A future's and a session's `Drop` panicking during cancel and close:
//! FAULT, quarantine, no abort.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

use core::task::Poll;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use busbar_plugin_abi::host_side::caller::CallStack;
use busbar_plugin_loader::instance::Registry;
use busbar_ports::export::{Delivered, ExportPort};
use busbar_ports::CallCx;

use crate::c_cancel_inflight::{counting_waker, poll_once, rig, spec, YieldNeeds};

#[test]
#[ignore = "blocked (re-checked 2026-11-16) on #271: busbar-ffi host.rs `Drop for Chain` and `Drop for Session` (cancel) and `Drop for Instance` (close) call the plugin outside `driver::step` and discard its Status (`let _ = cancel_raw(..)`, `let _ = close(..)`), so a Drop that panics there answers FAULT to nobody: no `report_fault`, no quarantine, no `plugin_fault` audit (busbar-ffi is owner-pinned, unsafe.yaml). The session half also needs a session-kind (plane/transport) fixture built with plugin!, none in busbar-plugin-test. The no-abort half for a chain future's Drop (cancel) and the plugin value's Drop (close) runs as the sibling test below"]
fn drop_panic_in_cancel_or_close_faults_and_quarantines() {
    todo!("owner: W1-L2 (C-PANIC-CANCEL)")
}

/// An export image whose `deliver` holds a [`Fuse`] across one FETCH (a NEED step): dropped before the chain
/// finished, the fuse's `Drop` panics, inside the plugin's `cancel` entry. With config `{"close": "panic"}` the
/// plugin value's own `Drop` panics, inside its `close` entry. No `unsafe`: the glue is `plugin!`'s output.
mod fixture {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU32, Ordering};

    use busbar_plugin_abi::fail::refused::R_CONFIG;
    use busbar_plugin_abi::fail::Fail;
    use busbar_plugin_abi::host::Host;
    use busbar_plugin_abi::need::need::{self, Fetch};
    use busbar_plugin_abi::need::{egress, ChainBytes, TrustHandle};
    use busbar_plugin_abi::plugin::{Describe, Endpoints, Open};
    use busbar_plugin_abi::records::{tag as record, Records, Reply, Writer};
    use busbar_plugin_abi::Export;

    /// Fuses dropped armed (each panicked).
    pub static FUSES_BLOWN: AtomicU32 = AtomicU32::new(0);
    /// Plugin values dropped whose `Drop` panicked.
    pub static CLOSE_PANICS: AtomicU32 = AtomicU32::new(0);
    /// `release` calls the rig saw.
    pub static RELEASED: AtomicU32 = AtomicU32::new(0);

    pub fn released() {
        RELEASED.fetch_add(1, Ordering::SeqCst);
    }

    struct Fuse {
        armed: bool,
    }

    impl Drop for Fuse {
        fn drop(&mut self) {
            if self.armed {
                FUSES_BLOWN.fetch_add(1, Ordering::SeqCst);
                panic!("C-PANIC-CANCEL: a chain future's Drop panics during cancel");
            }
        }
    }

    pub struct Fused {
        close_panics: bool,
    }

    impl Drop for Fused {
        fn drop(&mut self) {
            if self.close_panics {
                CLOSE_PANICS.fetch_add(1, Ordering::SeqCst);
                panic!("C-PANIC-CANCEL: the plugin value's Drop panics during close");
            }
        }
    }

    fn close_panics(config: &[u8]) -> Result<bool, Fail> {
        busbar_contract::json::parse::<HashMap<String, String>>(config)
            .map(|map| map.get("close").is_some_and(|v| v == "panic"))
            .map_err(|_| Fail::refused_because(R_CONFIG, "config must be an object"))
    }

    impl Open for Fused {
        async fn open(_h: &'static Host, config: ChainBytes) -> Result<Self, Fail> {
            let close_panics = config.with(close_panics)?;
            Ok(Fused { close_panics })
        }

        fn check(_h: &Host, config: &[u8], _ends: &mut Endpoints<'_>) -> Result<(), Fail> {
            close_panics(config).map(|_| ())
        }

        fn describe(d: &mut Describe<'_>) {
            d.schema(r#"{"type":"object"}"#);
            d.methods(busbar_plugin_abi::export::M_DELIVER);
            d.item(
                busbar_plugin_abi::export::tag::D_STREAMS,
                &[busbar_plugin_abi::export::STREAM_LOGS as u8],
            );
        }
    }

    impl Export for Fused {
        async fn deliver(
            &self,
            _h: &'static Host,
            _stream: u32,
            _delivery: u64,
            _attempt: u32,
            batch: ChainBytes,
        ) -> Result<Reply, Fail> {
            let mut fuse = Fuse { armed: true };
            let req = Fetch {
                method: "POST",
                url: "https://sink.test/batch",
                headers: &[],
                body: &[],
                max_body: 64,
                trust: TrustHandle::NONE,
                cert: None,
                egress: egress::OPEN_WEB,
            };
            let _ = need::fetch(&req).await;
            fuse.armed = false;
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
    }

    busbar_plugin_abi::plugin!(Export, Fused, name: "fixture-panic-cancel");
}

/// The fixture's counters are process-wide.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

fn cx() -> CallCx {
    CallCx {
        deadline: Instant::now() + Duration::from_secs(30),
        request_id: 1,
        stack: CallStack::default(),
    }
}

/// Opens instance `name` with `config`; the fixture's `open` makes no NEED, so the first poll is Ready.
fn open(
    registry: &Registry<YieldNeeds>,
    identity: &str,
    name: &str,
    config: &[u8],
) -> Arc<dyn ExportPort> {
    let (waker, _) = counting_waker();
    let spec = spec(identity, name, config);
    let mut fut = registry.open_export(&spec);
    match poll_once(&mut fut, &waker) {
        Poll::Ready(Ok(port)) => port,
        Poll::Ready(Err(e)) => panic!("{name}: the open answered {e:?}"),
        Poll::Pending => panic!("{name}: an open without NEED must be Ready in its first poll"),
    }
}

#[test]
fn a_panicking_drop_in_cancel_or_close_does_not_abort() {
    let _serial = ONE_AT_A_TIME.lock().unwrap_or_else(PoisonError::into_inner);
    let (registry, identity) = rig(fixture::PLUGIN.plugin(), fixture::released);
    let (waker, _) = counting_waker();
    let lines: [&[u8]; 1] = [b"one line"];
    let base = (
        fixture::FUSES_BLOWN.load(Ordering::SeqCst),
        fixture::CLOSE_PANICS.load(Ordering::SeqCst),
        fixture::RELEASED.load(Ordering::SeqCst),
    );

    // Cancel: the deliver chain parks on its FETCH; dropping the port future cancels it, and the plugin future's
    // Drop panics inside the plugin's `cancel` entry. The process goes on.
    let port = open(&registry, &identity, "fuse", b"{}");
    let mut fut = port.deliver(cx(), busbar_plugin_abi::export::STREAM_LOGS, 1, 1, &lines);
    assert!(
        poll_once(&mut fut, &waker).is_pending(),
        "the deliver chain must park on its FETCH"
    );
    drop(fut);
    assert_eq!(
        fixture::FUSES_BLOWN.load(Ordering::SeqCst) - base.0,
        1,
        "the cancel dropped the parked future once, and its Drop panicked"
    );
    assert_eq!(
        fixture::RELEASED.load(Ordering::SeqCst) - base.2,
        1,
        "the cancelled chain is released once after its panicking cancel"
    );

    // Close: the plugin value's Drop panics inside the plugin's `close` entry. The process goes on.
    let closer = open(&registry, &identity, "closer", br#"{"close":"panic"}"#);
    drop(closer);
    assert_eq!(
        fixture::CLOSE_PANICS.load(Ordering::SeqCst) - base.1,
        1,
        "the close dropped the plugin value once, and its Drop panicked"
    );
    drop(port);

    // No abort: the same image opens a fresh instance and serves a whole deliver chain.
    let fresh = open(&registry, &identity, "fresh", b"{}");
    let mut fut = fresh.deliver(cx(), busbar_plugin_abi::export::STREAM_LOGS, 2, 1, &lines);
    assert!(
        poll_once(&mut fut, &waker).is_pending(),
        "the fresh chain parks on its FETCH"
    );
    match poll_once(&mut fut, &waker) {
        Poll::Ready(Ok(Delivered::Acked { accepted, .. })) => assert_eq!(accepted, 1),
        Poll::Ready(Ok(other)) => panic!("the fresh deliver answered {other:?}"),
        Poll::Ready(Err(e)) => panic!("the fresh deliver failed: {e:?}"),
        Poll::Pending => panic!("the fresh deliver must finish after its one NEED"),
    }
    drop(fut);
    assert_eq!(
        fixture::FUSES_BLOWN.load(Ordering::SeqCst) - base.0,
        1,
        "a finished chain's fuse is disarmed"
    );
}
