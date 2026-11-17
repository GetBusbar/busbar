// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plugin-side bridge's fixture image (W1-A3; IF §6.2-§6.5): a secret-kind image whose `resolve` chain runs
//! one scenario named by its argument, wired by hand exactly as `plugin!`/`kind!` wire an image (busbar-ffi's
//! `shim::Image` and `Start1` over `busbar_plugin_abi::bridge`), and driven through busbar-ffi's safe host API
//! (`Admitted`, `Instance`, `Chain`, `OutLease`). It is what A3's case arms (C-NEEDFUT-SHARED, C-NEEDFUT-LATE,
//! C-STALE, C-LEAK, C-STALE-PANIC, C-CLOSE-PARKED, C-SLOT-STALE, C-SLOT-REUSE, the shim arms of C-ERROR-RECORDS
//! and C-FAIL-FACTS) run on until a `plugin!` fixture replaces the hand wiring. No `unsafe` (rule 15).
//!
//! Every entry runs inline on the test's thread, so the describe mode is a thread-local; the stashes are statics,
//! one per case, as the cases state them.

use core::cell::Cell;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use busbar_ffi::header::{StampBytes, STAMP_KIND_AT, STAMP_SIZE};
pub use busbar_ffi::host::{Chain, ChainBufs, Instance, OpenAnswer, OutLease, Resumed, Started};
use busbar_ffi::image::Admitted;
use busbar_ffi::shim::{ChainFut, Image, InstOf, Opening, Start1, Step};
use busbar_ffi::slots::{ChainBox, ChainRef, Slots};
use busbar_ffi::vt::{kind, secret, Built};
pub use busbar_ffi::Status;
use busbar_ffi::{plugin, Arg, Bytes, ChainBytes, KindCode, LinkedPlugin, Out, Str, Token};
use busbar_plugin_abi::bridge::{self, Inbox};
use busbar_plugin_abi::fail::{fact, failed, refused, Fail};
use busbar_plugin_abi::host::{Host, HostFns};
use busbar_plugin_abi::need::need::{self as needs, NeedErr};
use busbar_plugin_abi::need::{op, NeedResRec, SecretHandle};
use busbar_plugin_abi::records::{tag, FactRec, Records, Reply, U32Rec, Writer};

/// The fixture's secret kind.
pub type Secret = kind::Secret;

/// A host with no services: the bridge needs none (no grow: every lease is 64 KiB).
pub static HOST: Host = Host::new(
    0,
    HostFns {
        now: None,
        mono: None,
        random: None,
        crypto: None,
        log: None,
        log_level: None,
        grow: None,
        deployment: None,
        migrate_admit: None,
    },
);

/// One plugin value. `alive` is touched by a parked chain's `Drop` (C-CLOSE-PARKED); `gone` is set when the
/// value drops, for the instance opened with config `park`.
pub struct Plugin {
    alive: AtomicBool,
    gone: Option<&'static AtomicBool>,
}

impl Drop for Plugin {
    fn drop(&mut self) {
        self.alive.store(false, Ordering::SeqCst);
        if let Some(gone) = self.gone {
            gone.store(true, Ordering::SeqCst);
        }
    }
}

/// C-CLOSE-PARKED: set when the `park` instance's plugin value dropped.
pub static PARK_GONE: AtomicBool = AtomicBool::new(false);
/// C-CLOSE-PARKED: what the parked chain's local saw when it dropped (plugin alive and not yet gone).
pub static PARK_SAW_ALIVE: AtomicBool = AtomicBool::new(false);

/// A local a parked chain holds across its NEED; its `Drop` reads the plugin it borrows.
struct Held<'p> {
    plugin: &'p Plugin,
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        let alive = self.plugin.alive.load(Ordering::SeqCst) && !PARK_GONE.load(Ordering::SeqCst);
        PARK_SAW_ALIVE.store(alive, Ordering::SeqCst);
    }
}

/// C-STALE's stash.
static STALE: Mutex<Option<ChainBytes>> = Mutex::new(None);
/// C-STALE-PANIC's stash.
static PANICKED: Mutex<Option<ChainBytes>> = Mutex::new(None);
/// C-LEAK's leaked handle.
static LEAKED: Mutex<Option<&'static mut ChainBytes>> = Mutex::new(None);
/// C-NEEDFUT-SHARED's shared future (the single-flight shape): the Need future itself, behind a plain mapping
/// that keeps no state of its own, so a panicking poll leaves it exactly as it was.
type SharedSecret = Box<dyn Future<Output = Result<Vec<u8>, NeedErr>> + Send + Unpin>;
static SHARED: Mutex<Option<SharedSecret>> = Mutex::new(None);

/// Maps a secret Need future's value to a plain `Vec` (the value is copied out; the original zeroizes).
struct ToVec<F>(F);

impl<F, Z> Future for ToVec<F>
where
    F: Future<Output = Result<Z, NeedErr>> + Unpin,
    Z: AsRef<[u8]>,
{
    type Output = Result<Vec<u8>, NeedErr>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0)
            .poll(cx)
            .map(|value| value.map(|value| value.as_ref().to_vec()))
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What the fixture's describe entry (a sync crossing) does.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Describe {
    Plain,
    /// Reads C-STALE-PANIC's stash.
    ReadPanicked,
    /// Reads C-LEAK's leaked handle.
    ReadLeaked,
    /// Polls a Need future.
    PollNeed,
}

std::thread_local! {
    static DESCRIBE: Cell<Describe> = const { Cell::new(Describe::Plain) };
}

/// Runs the image's describe entry in `mode` on this thread.
pub fn describe(mode: Describe) -> Status {
    DESCRIBE.set(mode);
    let mut lease = lease();
    let status = image().describe(&HOST, &mut lease);
    DESCRIBE.set(Describe::Plain);
    status
}

/// The image type.
pub struct Fixture;

static GLOBAL: Slots<ChainBox<Result<Reply, Fail>, Inbox>> = Slots::new();

impl Image for Fixture {
    type Plugin = Plugin;
    type Session = ();
    type Reply = Result<Reply, Fail>;
    type Inbox = Inbox;
    fn global() -> &'static Slots<ChainBox<Self::Reply, Self::Inbox>> {
        &GLOBAL
    }
    fn describe(_h: &'static Host, _out: &mut Out<'_>) -> Status {
        match DESCRIBE.get() {
            Describe::Plain => {}
            // A read that does not FAULT answers OK, which the cases refuse.
            Describe::ReadPanicked => drop(lock(&PANICKED).as_ref().map(ChainBytes::to_vec)),
            Describe::ReadLeaked => drop(lock(&LEAKED).as_ref().map(|bytes| bytes.to_vec())),
            Describe::PollNeed => {
                let mut fut = core::pin::pin!(needs::secret(SecretHandle(1)));
                let mut cx = Context::from_waker(Waker::noop());
                let _ = fut.as_mut().poll(&mut cx);
            }
        }
        Status::OK
    }
    fn open(
        _h: &'static Host,
        config: Bytes<'_>,
        _chained: ChainBytes,
        _flags: u32,
        out: &mut Out<'_>,
    ) -> Opening<Self::Reply, Self::Inbox> {
        let gone = (config.get() == b"park").then_some(&PARK_GONE);
        let plugin = Plugin {
            alive: AtomicBool::new(true),
            gone,
        };
        let inst = Box::new(InstOf::<Fixture>::new(plugin)).into_instance();
        let mut record = [0u8; 16];
        record[..2].copy_from_slice(&tag::INSTANCE.to_le_bytes());
        record[4..8].copy_from_slice(&8u32.to_le_bytes());
        record[8..].copy_from_slice(&inst.to_le_bytes());
        Opening::Done(if out.append(&record) {
            Status::OK
        } else {
            Status::FAULT
        })
    }
    fn poll(
        chain: ChainRef<'_, Self::Reply, Self::Inbox>,
        results: Option<ChainBytes>,
        out: &mut Out<'_>,
    ) -> Step {
        bridge::poll(chain, results, out)
    }
    fn parked(token: Token, out: &mut Out<'_>) -> Status {
        bridge::parked(token, out)
    }
    fn opened(token: Token, out: &mut Out<'_>) -> Status {
        bridge::opened(token, out)
    }
}

impl Start1<Bytes<'static>, 0> for Fixture {
    fn start<'i>(
        p: &'i Plugin,
        _h: &'static Host,
        reference: ChainBytes,
    ) -> (ChainFut<'i, Self::Reply>, Self::Inbox) {
        (Box::pin(run(p, reference)), Inbox::new())
    }
}

static VT: Built<Fixture, secret::Vt> = secret::Vt::build::<Fixture>();
static STAMP: StampBytes = {
    let mut bytes = [0u8; STAMP_SIZE];
    bytes[STAMP_KIND_AT] = KindCode::Secret as u8;
    StampBytes(bytes)
};
static PLUGIN: LinkedPlugin = plugin::<Fixture, Secret>(&VT, &STAMP, Str::EMPTY);

/// Pending once, then Ready: a step with no NEED of its own.
#[derive(Default)]
struct Yield(bool);

impl Future for Yield {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        if self.0 {
            Poll::Ready(())
        } else {
            self.0 = true;
            Poll::Pending
        }
    }
}

/// Polls `fut` once (a combinator's poll), whatever it answers.
async fn poll_once<F: Future + Unpin>(fut: &mut F) -> Poll<F::Output> {
    core::future::poll_fn(|cx| Poll::Ready(Pin::new(&mut *fut).poll(cx))).await
}

/// Polls the shared future once from this chain.
async fn poll_shared() -> Result<Vec<u8>, Fail> {
    let value = core::future::poll_fn(|cx| match lock(&SHARED).as_mut() {
        Some(fut) => Pin::new(fut).poll(cx),
        None => panic!("the shared future is gone"),
    })
    .await?;
    Ok(value)
}

fn text(bytes: &[u8]) -> Result<Reply, Fail> {
    let mut reply = Reply::new();
    reply.put(tag::TEXT, bytes)?;
    Ok(reply)
}

/// One `resolve` chain: the scenario its argument names.
async fn run(p: &Plugin, reference: ChainBytes) -> Result<Reply, Fail> {
    let scenario = reference.to_vec();
    match scenario.as_slice() {
        b"secret" => {
            let value = needs::secret(SecretHandle(1)).await?;
            text(&value)
        }
        b"late-ok" | b"late-stale" => {
            let mut first = Box::pin(needs::secret(SecretHandle(1)));
            assert!(
                poll_once(&mut first).await.is_pending(),
                "step 0 writes its NEED"
            );
            Yield::default().await;
            if scenario.as_slice() == b"late-stale" {
                let _ = needs::secret(SecretHandle(2)).await?;
            }
            let value = first.await?;
            text(&value)
        }
        b"share-a" => {
            let mut fut: SharedSecret = Box::new(ToVec(Box::pin(needs::secret(SecretHandle(1)))));
            assert!(
                poll_once(&mut fut).await.is_pending(),
                "step 0 writes its NEED"
            );
            *lock(&SHARED) = Some(fut);
            Yield::default().await;
            let value = poll_shared().await?;
            text(&value)
        }
        b"share-b" => {
            let _ = needs::secret(SecretHandle(9)).await?;
            let value = poll_shared().await?;
            text(&value)
        }
        b"stash" => {
            *lock(&STALE) = Some(reference);
            text(b"stashed")
        }
        b"read-stash" => {
            let read = lock(&STALE).as_ref().map(ChainBytes::to_vec);
            text(&read.unwrap_or_default())
        }
        b"leak" => {
            *lock(&LEAKED) = Some(Box::leak(Box::new(reference)));
            text(b"leaked")
        }
        b"read-leak" => {
            let read = lock(&LEAKED).as_ref().map(|bytes| bytes.to_vec());
            text(&read.unwrap_or_default())
        }
        b"stash-panic" => {
            *lock(&PANICKED) = Some(reference);
            panic!("plugin code panics mid-poll");
        }
        b"read-panicked" => {
            let read = lock(&PANICKED).as_ref().map(ChainBytes::to_vec);
            text(&read.unwrap_or_default())
        }
        b"park" => {
            let _held = Held { plugin: p };
            let value = needs::secret(SecretHandle(1)).await?;
            text(&value)
        }
        b"foreign" => {
            let _ = needs::secret(SecretHandle(1)).await?;
            Yield::default().await;
            text(b"unreachable")
        }
        b"fail-error" => Err(
            Fail::failed_because(failed::F_UPSTREAM, "the backend said 503")
                .with_error(7071)
                .with_fact(fact::FACT_RETRY_AFTER_S, 30)
                .with_fact(fact::FACT_BACKEND_STATUS, 503),
        ),
        b"fail-facts" => Err(
            Fail::failed_because(failed::F_UPSTREAM, "the backend said 503")
                .with_fact(fact::FACT_RETRY_AFTER_S, 30)
                .with_fact(fact::FACT_BACKEND_STATUS, 503),
        ),
        b"refuse-error" => Err(Fail::refused(refused::R_DENIED).with_error(7070)),
        b"refuse-plain" => Err(Fail::refused(refused::R_DENIED).with_error(0)),
        _ => Err(Fail::refused(refused::R_INVALID)),
    }
}

// ---- the host side ----

/// A fresh 64 KiB out lease (one per entry).
pub fn lease() -> OutLease {
    match OutLease::new(vec![0; 64 * 1024], 1 << 20) {
        Some(lease) => lease,
        None => panic!("the ACTIVE stack is full"),
    }
}

/// The admitted fixture image.
pub fn image() -> Admitted {
    match Admitted::linked(&PLUGIN) {
        Ok(image) => image,
        Err(_) => panic!("the fixture image is refused"),
    }
}

/// A new instance; `config` = `park` arms C-CLOSE-PARKED's drop flag.
pub fn instance_with(config: &[u8]) -> Instance<Secret> {
    let mut lease = lease();
    match image().open::<Secret>(&HOST, config.to_vec(), 0, &mut lease) {
        OpenAnswer::Done(Status::OK, Some(instance)) => instance,
        _ => panic!("the fixture did not open"),
    }
}

pub fn instance() -> Instance<Secret> {
    instance_with(b"{}")
}

/// Starts a `resolve` chain running `scenario`.
pub fn start<'i>(
    instance: &'i Instance<Secret>,
    scenario: &[u8],
    lease: &mut OutLease,
) -> Started<'i, Secret> {
    let mut bufs = ChainBufs::new();
    let at = bufs.push(scenario.to_vec());
    instance.start1(
        |vt| &vt.resolve,
        bufs,
        move |bufs| Arg::bytes(bufs.get(at)),
        lease,
    )
}

/// Starts a chain that must park on NEED.
pub fn parked<'i>(instance: &'i Instance<Secret>, scenario: &[u8]) -> Chain<'i, Secret> {
    match start(instance, scenario, &mut lease()) {
        Started::Need(chain) => chain,
        Started::Done(status) => panic!("{scenario:?} answered {status:?}, not NEED"),
    }
}

/// Starts a chain and returns its final status (it must not NEED).
pub fn done(instance: &Instance<Secret>, scenario: &[u8]) -> Status {
    match start(instance, scenario, &mut lease()) {
        Started::Done(status) => status,
        Started::Need(_) => panic!("{scenario:?} NEEDed"),
    }
}

/// Resumes `chain` with one SECRET result; the final status, or None on NEED.
pub fn resume_secret(
    chain: &mut Chain<'_, Secret>,
    value: &[u8],
    lease: &mut OutLease,
) -> Option<Status> {
    match chain.resume(secret_result(value), lease) {
        Resumed::Need => None,
        Resumed::Done(status, _) => Some(status),
    }
}

/// One NEED_RES record answering a SECRET with `value`.
pub fn secret_result(value: &[u8]) -> Vec<u8> {
    let head = NeedResRec {
        op: op::SECRET,
        status: 0,
        a: 0,
        b: 0,
        lens: [value.len() as u32, 0],
        _r: 0,
    };
    let mut reply = Reply::new();
    if reply.put_pod_tail(tag::NEED_RES, &head, value).is_err() {
        panic!("NEED_RES");
    }
    reply.as_bytes().to_vec()
}

/// The answer's records as (tag, body).
pub fn answer(lease: &OutLease) -> Vec<(u16, Vec<u8>)> {
    lease.with_answer(|bytes| {
        Records::new(bytes)
            .map(|rec| match rec {
                Ok(rec) => (rec.tag, rec.body.to_vec()),
                Err(_) => panic!("the answer is not framed"),
            })
            .collect()
    })
}

/// The answer's tags.
pub fn tags(lease: &OutLease) -> Vec<u16> {
    answer(lease).into_iter().map(|(tag, _)| tag).collect()
}

/// The ERROR record's number, if any (a U32Rec body).
pub fn error_number(lease: &OutLease) -> Option<u32> {
    answer(lease)
        .into_iter()
        .find(|(t, _)| *t == tag::ERROR)
        .map(|(_, body)| {
            assert_eq!(body.len(), core::mem::size_of::<U32Rec>());
            u32::from_le_bytes([body[0], body[1], body[2], body[3]])
        })
}

/// The FACT records' (key, value) pairs.
pub fn facts(lease: &OutLease) -> Vec<(u32, u64)> {
    answer(lease)
        .into_iter()
        .filter(|(t, _)| *t == tag::FACT)
        .map(|(_, body)| {
            assert_eq!(body.len(), core::mem::size_of::<FactRec>());
            let mut key = [0u8; 4];
            key.copy_from_slice(&body[..4]);
            let mut value = [0u8; 8];
            value.copy_from_slice(&body[8..16]);
            (u32::from_le_bytes(key), u64::from_le_bytes(value))
        })
        .collect()
}

/// The answer's TEXT bodies.
pub fn texts(lease: &OutLease) -> Vec<Vec<u8>> {
    answer(lease)
        .into_iter()
        .filter(|(t, _)| *t == tag::TEXT)
        .map(|(_, body)| body)
        .collect()
}

/// The fixture's header as the `&'static Plugin` the frozen suite signatures take (`PLUGIN.plugin()`).
pub fn header() -> &'static busbar_ffi::Plugin {
    PLUGIN.plugin()
}

/// The fixture's `LinkedPlugin` static.
pub fn linked() -> &'static LinkedPlugin {
    &PLUGIN
}
