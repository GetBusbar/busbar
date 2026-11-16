// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-CANCEL (ABI-MIN3-INTERFACE §14): A chain cancelled mid-chain.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

use core::future::{pending, Future};
use core::pin::{pin, Pin};
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use busbar_plugin_abi::host::{
    CallStack, Caller, ConnId, DirNeed, Driver, FetchNeed, First, InstanceLimits, NeedErr, NeedOut,
    Needs, OpenNeed, Pool, RecordNeed, TlsMode,
};
use busbar_plugin_abi::records::tag;
use busbar_plugin_abi::types::KindCode;
use busbar_plugin_test::FakeNeeds;

use crate::bridge_fixture as fx;

fn caller() -> Caller<'static> {
    Caller {
        plugin: "bridge-fixture",
        kind: KindCode::Secret,
        name: "fixture",
        instance: 1,
        slot: 1,
        chain: 0,
        deadline: Instant::now() + Duration::from_secs(60),
        stack: CallStack::default(),
        out_of_process: false,
        limits: InstanceLimits::default(),
    }
}

fn poll_once<F: Future>(fut: Pin<&mut F>) -> Poll<F::Output> {
    fut.poll(&mut Context::from_waker(Waker::noop()))
}

fn first<'i>(started: fx::Started<'i, fx::Secret>) -> First<'i, fx::Secret> {
    started.into()
}

/// Needs whose SECRET never resolves (a slow custody backend), counting `release`.
#[derive(Default)]
struct Stalled {
    released: AtomicU64,
    chains: std::sync::Mutex<Vec<u64>>,
}

impl Needs for Stalled {
    async fn open(
        &self,
        _: &Caller<'_>,
        _: OpenNeed<'_>,
        _: &mut NeedOut<'_>,
    ) -> Result<(), NeedErr> {
        Err(NeedErr::Denied)
    }
    async fn starttls(
        &self,
        _: &Caller<'_>,
        _: ConnId,
        _: TlsMode<'_>,
        _: &mut NeedOut<'_>,
    ) -> Result<(), NeedErr> {
        Err(NeedErr::Denied)
    }
    async fn write(
        &self,
        _: &Caller<'_>,
        _: ConnId,
        _: &[u8],
        _: &mut NeedOut<'_>,
    ) -> Result<(), NeedErr> {
        Err(NeedErr::Denied)
    }
    async fn read(
        &self,
        _: &Caller<'_>,
        _: ConnId,
        _: u32,
        _: &mut NeedOut<'_>,
    ) -> Result<(), NeedErr> {
        Err(NeedErr::Denied)
    }
    async fn close(&self, _: &Caller<'_>, _: ConnId, _: bool) {}
    async fn fetch(
        &self,
        _: &Caller<'_>,
        _: FetchNeed<'_>,
        _: &mut NeedOut<'_>,
    ) -> Result<(), NeedErr> {
        Err(NeedErr::Denied)
    }
    async fn secret(&self, cx: &Caller<'_>, _: u32, _: &mut NeedOut<'_>) -> Result<(), NeedErr> {
        self.chains
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(cx.chain);
        pending().await
    }
    async fn record(
        &self,
        _: &Caller<'_>,
        _: RecordNeed<'_>,
        _: &mut NeedOut<'_>,
    ) -> Result<(), NeedErr> {
        Err(NeedErr::Denied)
    }
    async fn directory(
        &self,
        _: &Caller<'_>,
        _: DirNeed<'_>,
        _: &mut NeedOut<'_>,
    ) -> Result<(), NeedErr> {
        Err(NeedErr::Denied)
    }
    fn release(&self, cx: &Caller<'_>) {
        let chains = self
            .chains
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(
            chains.contains(&cx.chain),
            "released under the chain's own id"
        );
        self.released.fetch_add(1, Ordering::SeqCst);
    }
}

/// A chain parked on a Need that never answers is dropped mid-Need: the guard cancels the plugin's chain inline
/// and releases the chain's Needs exactly once, under the chain's own id; the instance then serves the next
/// chain, which reuses the freed slot.
#[test]
fn a_chain_cancelled_mid_chain_drops_its_future_once() {
    let instance = fx::instance();
    let stalled = Stalled::default();
    {
        let mut drv = Driver::new(&stalled, caller());
        let req = Pool::global().acquire(1 << 20);
        let mut fut = pin!(drv.run(0, 1 << 20, req, |_, lease| first(fx::start(
            &instance, b"secret", lease
        ))));
        assert!(poll_once(fut.as_mut()).is_pending(), "parked on the SECRET");
        assert!(poll_once(fut.as_mut()).is_pending(), "still parked");
        assert_eq!(
            stalled.released.load(Ordering::SeqCst),
            0,
            "nothing released while parked"
        );
    }
    assert_eq!(
        stalled.released.load(Ordering::SeqCst),
        1,
        "released once, at the drop"
    );
    let mut needs = FakeNeeds::new();
    FakeNeeds::secret(&mut needs, "/k", b"v");
    let mut drv = Driver::new(&needs, caller());
    let req = Pool::global().acquire(1 << 20);
    let mut fut = pin!(drv.run(0, 1 << 20, req, |_, lease| first(fx::start(
        &instance, b"secret", lease
    ))));
    let Poll::Ready(Ok(done)) = poll_once(fut.as_mut()) else {
        panic!("the instance serves after the cancel");
    };
    let text = done
        .answer
        .answer()
        .records()
        .map(|rec| rec.expect("framed"))
        .find(|rec| rec.tag == tag::TEXT)
        .map(|rec| rec.body.to_vec());
    assert_eq!(text.as_deref(), Some(&b"v"[..]));
}
