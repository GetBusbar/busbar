// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plugin-side bridge (IF §6.2-§6.4): one chain's inbox and step counter, the `CURRENT` the Need futures
//! bind to, the one poll every async adapter makes, and the answer writers every shim shares (FAIL, ERROR and
//! FACTs; TOKEN). W1-A3.
//!
//! busbar-ffi owns the raw half (UNSAFE-MIN r3.1): the entries, the slot table, the chain box, the `ChainId`
//! that `ChainBytes` checks and the poll with its own `CURRENT` restore. This module is the safe half the
//! `kind!`/`plugin!` adapters call from `shim::Image::poll`, `parked` and `opened`:
//!
//! - **Inbox.** Each chain's state (`ChainBox`'s `X`) is an [`Inbox`]: its check value (`ChainKey`: the
//!   starting thread's ordinal and that thread's own chain counter, never reused while the image is mapped,
//!   IF §6.2), its step counter (0 at the first poll, +1 per resume, §6.4 step 4), this step's results, and
//!   the NEED records the step is writing.
//! - **CURRENT.** For one poll the inbox's mail is moved into a `const`-initialised thread-local whose type has
//!   no destructor (I13; the const asserts below), by [`CurrentGuard`] alone: it puts back exactly what it found
//!   on return and on unwind (IF §6.2, rounds 12-13), so a nested entry into the same image leaves the outer
//!   poll's CURRENT intact and a panicking poll leaves no CURRENT naming the dead chain. Two thread-local
//!   accesses at set, one at restore; no RMW, no allocation (I5).
//! - **Need futures** (`need.rs`) write their NEED records into the mail and later read their result from it,
//!   after checking it is the chain and the step they wrote at.
//! - **Answers.** Ready(Ok) copies the reply; Ready(Err) zeroes what was written and writes exactly one FAIL,
//!   then one ERROR when the Fail carries a declared number (round 34), then its FACTs (round 21); Pending with
//!   1..=64 NEEDs writes them; Pending with none is FAULT `AwaitedForeign`.

use core::cell::{Cell, RefCell};
use core::mem::ManuallyDrop;
use core::sync::atomic::{AtomicU32, Ordering};
use core::task::Poll;

use zerocopy::IntoBytes;

use crate::fail::{FAIL_TEXT_WIRE_MAX, Fail};
use crate::need::ChainBytes;
use crate::records::{
    FactRec, FailRec, Full, RawWrite, RecHead, Reply, TokenRec, U32Rec, put_parts, tag,
};
use crate::types::{Status, Token};

/// What one poll came to (busbar-ffi's, re-exported for the adapters `plugin!` emits).
#[doc(hidden)]
pub use busbar_ffi::shim::Step;

/// The most NEEDs one step may hold (IF §6.1 rules); more is FAULT.
pub const MAX_NEEDS: u32 = 64;

/// The check value a Need future binds to (IF §6.2 `ChainId`'s thread and serial): unique for every chain the
/// image starts, whatever the slot table does.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ChainKey {
    pub(crate) thread: u32,
    pub(crate) serial: u64,
}

impl PartialEq for ChainKey {
    fn eq(&self, other: &Self) -> bool {
        self.thread == other.thread && self.serial == other.serial
    }
}
impl Eq for ChainKey {}

/// Thread ordinals; 0 is never issued. One RMW per thread lifetime.
static NEXT_THREAD: AtomicU32 = AtomicU32::new(1);

std::thread_local! {
    /// This thread's ordinal, 0 until its first chain.
    static THREAD: Cell<u32> = const { Cell::new(0) };
    /// This thread's chain counter (plain load and store, no RMW).
    static SERIAL: Cell<u64> = const { Cell::new(0) };
    /// The polling chain's mail, `None` outside a poll. `ManuallyDrop`: no TLS destructor is ever armed
    /// (I13); it is `None` whenever no poll runs, because `CurrentGuard` always takes its mail back.
    static CURRENT: ManuallyDrop<RefCell<Option<Mail>>> =
        const { ManuallyDrop::new(RefCell::new(None)) };
}

// IF §6.2: abi's plugin-side thread-locals hold only types with no drop glue.
const _: () = assert!(!core::mem::needs_drop::<Cell<u32>>());
const _: () = assert!(!core::mem::needs_drop::<Cell<u64>>());
const _: () = assert!(!core::mem::needs_drop::<ManuallyDrop<RefCell<Option<Mail>>>>());

impl ChainKey {
    /// A fresh key on this thread. Panics (FAULT `Exhausted`) once the image has issued 2^32 − 2 ordinals.
    fn mint() -> ChainKey {
        let mut thread = THREAD.get();
        if thread == 0 {
            thread = NEXT_THREAD
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                    (next < u32::MAX).then_some(next + 1)
                })
                .unwrap_or_else(|_| {
                    panic!("busbar-plugin-abi: thread ordinals exhausted (Exhausted)")
                });
            THREAD.set(thread);
        }
        let serial = SERIAL.get() + 1;
        SERIAL.set(serial);
        ChainKey { thread, serial }
    }
}

/// One chain's mail: what a poll hands its Need futures.
pub(crate) struct Mail {
    /// The chain's check value.
    pub(crate) key: ChainKey,
    /// The chain's step counter: 0 at the first poll, +1 per resume.
    pub(crate) step: u32,
    /// This step's NEED_RES records (None before the first resume).
    pub(crate) results: Option<ChainBytes>,
    /// The NEED records this poll writes, copied into Out after it (zeroed after the copy, I11).
    pub(crate) needs: Reply,
    /// The NEEDs written in this poll.
    pub(crate) count: u32,
}

/// One chain's state between polls (`ChainBox`'s `X`; IF §6.4 steps 1 and 4). Built by the async start and
/// `open` adapters on the starting thread.
#[doc(hidden)]
pub struct Inbox {
    mail: Option<Mail>,
}

impl Inbox {
    /// A new chain's inbox: a fresh key, step 0.
    pub fn new() -> Inbox {
        Inbox {
            mail: Some(Mail {
                key: ChainKey::mint(),
                step: 0,
                results: None,
                needs: Reply::new(),
                count: 0,
            }),
        }
    }
}

impl Default for Inbox {
    fn default() -> Self {
        Self::new()
    }
}

/// Sets CURRENT to one chain's mail for one poll; `restore` (or `Drop`, on unwind) puts back exactly the value
/// it replaced (IF §6.2: the only writer of CURRENT; never a blanket clear). `!Send`: a local of `poll`.
struct CurrentGuard {
    prev: Option<Option<Mail>>,
    _ns: core::marker::PhantomData<*const ()>,
}

impl CurrentGuard {
    fn set(mail: Mail) -> CurrentGuard {
        CurrentGuard {
            prev: Some(CURRENT.with(|current| current.replace(Some(mail)))),
            _ns: core::marker::PhantomData,
        }
    }
    /// Puts the previous value back and returns this poll's mail.
    fn restore(&mut self) -> Option<Mail> {
        let prev = self.prev.take()?;
        CURRENT.with(|current| current.replace(prev))
    }
}

impl Drop for CurrentGuard {
    fn drop(&mut self) {
        drop(self.restore());
    }
}

/// Runs `f` on the polling chain's mail; None outside a chain poll (a sync method, another thread).
pub(crate) fn with_mail<R>(f: impl FnOnce(&mut Mail) -> R) -> Option<R> {
    CURRENT.with(|current| current.borrow_mut().as_mut().map(f))
}

/// A chain's successful output: what Ready(Ok) writes into Out. `Reply` copies its records; `plugin!`'s `open`
/// answer writes INSTANCE and `Open::settled`.
pub trait Answer {
    fn answer(self, out: &mut busbar_ffi::Out<'_>) -> Result<(), Full>;
}

impl Answer for Reply {
    fn answer(self, out: &mut busbar_ffi::Out<'_>) -> Result<(), Full> {
        if out.append(self.as_bytes()) {
            Ok(())
        } else {
            Err(Full)
        }
    }
}

/// One poll of a chain (IF §6.4 steps 1-4): `results` is the resume's records (None on the first poll). The
/// adapter's `shim::Image::poll` is this call.
pub fn poll<A: Answer>(
    mut chain: busbar_ffi::ChainRef<'_, Result<A, Fail>, Inbox>,
    results: Option<ChainBytes>,
    out: &mut busbar_ffi::Out<'_>,
) -> Step {
    let Some(mut mail) = chain.extra().mail.take() else {
        return Step::Fault;
    };
    if let Some(results) = results {
        let Some(step) = mail.step.checked_add(1) else {
            return Step::Fault;
        };
        mail.step = step;
        mail.results = Some(results);
    }
    mail.count = 0;
    let mut current = CurrentGuard::set(mail);
    let polled = chain.poll();
    let Some(mut mail) = current.restore() else {
        return Step::Fault;
    };
    drop(current);
    let step = match polled {
        Poll::Ready(Ok(answer)) => match answer.answer(out) {
            Ok(()) => Step::Ready(Status::OK),
            Err(Full) => fail_step(out, &Fail::from(Full)),
        },
        Poll::Ready(Err(fail)) => fail_step(out, &fail),
        Poll::Pending if mail.count == 0 || mail.count > MAX_NEEDS => Step::Fault,
        Poll::Pending if out.append(mail.needs.as_bytes()) => Step::Need,
        Poll::Pending => Step::Fault,
    };
    mail.needs.truncate(0);
    chain.extra().mail = Some(mail);
    step
}

fn fail_step(out: &mut busbar_ffi::Out<'_>, fail: &Fail) -> Step {
    match write_fail(out, fail) {
        Ok(status) => Step::Ready(status),
        Err(Full) => Step::Fault,
    }
}

/// After `Step::Need`: the chain's TOKEN record (bit 63 clear), then NEED (§6.4 step 3).
pub fn parked(token: Token, out: &mut busbar_ffi::Out<'_>) -> Status {
    match put_parts(out, tag::TOKEN, &[TokenRec { token }.as_bytes()]) {
        Ok(()) => Status::NEED,
        Err(Full) => Status::FAULT,
    }
}

/// The bytes a session opener's leading TOKEN record takes (RecHead 8 + TokenRec 8; §6.4 step 7).
pub const TOKEN_ROOM: usize = 16;

/// Before a session opener's call: the room for its leading TOKEN at offset 0 (§6.4 step 7); the plugin's
/// records start at offset 16.
pub fn reserve_token(out: &mut busbar_ffi::Out<'_>) -> Result<(), Full> {
    if out.append(&[0; TOKEN_ROOM]) {
        Ok(())
    } else {
        Err(Full)
    }
}

/// After a session opener's `Ok` and the insert: the session TOKEN (bit 63 set) as the answer's first record,
/// in the room `reserve_token` made; OK.
pub fn opened(token: Token, out: &mut busbar_ffi::Out<'_>) -> Status {
    let head = RecHead {
        tag: tag::TOKEN,
        _r: 0,
        len: 8,
    };
    let mut record = [0u8; TOKEN_ROOM];
    record[..8].copy_from_slice(head.as_bytes());
    record[8..].copy_from_slice(TokenRec { token }.as_bytes());
    if out.written() >= TOKEN_ROOM && out.patch(0, &record) {
        Status::OK
    } else {
        Status::FAULT
    }
}

/// A sync method's answer (§6.4 step 2, "the same rule holds for every sync method"): OK as written, or the
/// written bytes zeroed and exactly the Fail's records.
pub fn answer_sync(out: &mut busbar_ffi::Out<'_>, result: Result<(), Fail>) -> Status {
    match result {
        Ok(()) => Status::OK,
        Err(fail) => write_fail(out, &fail).unwrap_or(Status::FAULT),
    }
}

/// Zeroes `[0, out.len)`, sets `len = 0`, then writes exactly one FAIL record (detail cut to
/// `FAIL_TEXT_WIRE_MAX` at a char boundary), one ERROR record when `fail.error() != 0` (round 34), and one FACT
/// record per `fail.facts()` item (round 21). FAIL ≤ 3,096 + ERROR 16 + two FACTs 48 always fit the first 4 KiB
/// buffer. Returns the Fail's status (REFUSED or FAILED).
pub(crate) fn write_fail<W: RawWrite + ?Sized>(out: &mut W, fail: &Fail) -> Result<Status, Full> {
    out.truncate(0);
    let text = fail.text();
    let mut cut = text.len().min(FAIL_TEXT_WIRE_MAX);
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    let head = FailRec {
        status: fail.status().0,
        code: fail.code(),
    };
    put_parts(out, tag::FAIL, &[head.as_bytes(), text[..cut].as_bytes()])?;
    if fail.error() != 0 {
        let error = U32Rec {
            value: u32::from(fail.error()),
            _r: 0,
        };
        put_parts(out, tag::ERROR, &[error.as_bytes()])?;
    }
    for (key, value) in fail.facts() {
        put_parts(out, tag::FACT, &[FactRec { key, _r: 0, value }.as_bytes()])?;
    }
    Ok(fail.status())
}

/// busbar-ffi's `Out` is the sink every bridge writer appends to (its own `room`/`append`/`patch`/`truncate`).
impl RawWrite for busbar_ffi::Out<'_> {
    fn written(&self) -> usize {
        busbar_ffi::Out::written(self)
    }
    fn room(&mut self, need: usize) -> Result<(), Full> {
        if busbar_ffi::Out::room(self, need) {
            Ok(())
        } else {
            Err(Full)
        }
    }
    fn append(&mut self, bytes: &[u8]) {
        let appended = busbar_ffi::Out::append(self, bytes);
        debug_assert!(appended, "append inside the room the last `room` made");
    }
    fn patch(&mut self, at: usize, bytes: &[u8]) {
        let patched = busbar_ffi::Out::patch(self, at, bytes);
        debug_assert!(patched, "patch inside what was written");
    }
    fn truncate(&mut self, len: usize) {
        busbar_ffi::Out::truncate(self, len);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fail::{fact, failed, refused};
    use crate::records::Records;

    /// C-ERROR-RECORDS shim arm (round 34), on the shared writer: FAIL, then ERROR only when the number is set,
    /// then the facts; the text cut at a char boundary; what was written before is gone.
    #[test]
    fn write_fail_writes_fail_error_then_facts() {
        let mut out = Reply::new();
        RawWrite::room(&mut out, 5).ok();
        RawWrite::append(&mut out, b"stale");
        let fail = Fail::failed_because(failed::F_UPSTREAM, "é".repeat(FAIL_TEXT_WIRE_MAX))
            .with_fact(fact::FACT_RETRY_AFTER_S, 30)
            .with_fact(fact::FACT_BACKEND_STATUS, 503)
            .with_error(7071);
        assert_eq!(write_fail(&mut out, &fail).ok(), Some(Status::FAILED));
        let recs: Vec<_> = Records::new(out.as_bytes()).map(|r| r.ok()).collect();
        let tags: Vec<_> = recs.iter().map(|r| r.map(|r| r.tag)).collect();
        assert_eq!(
            tags,
            [
                Some(tag::FAIL),
                Some(tag::ERROR),
                Some(tag::FACT),
                Some(tag::FACT)
            ]
        );
        let Some(Some(fail_rec)) = recs.first() else {
            panic!("no FAIL");
        };
        let Ok((head, detail)) = fail_rec.pod_tail::<FailRec>() else {
            panic!("FAIL body");
        };
        assert_eq!(
            (head.status, head.code),
            (Status::FAILED.0, failed::F_UPSTREAM)
        );
        assert!(detail.len() <= FAIL_TEXT_WIRE_MAX && detail.len() >= FAIL_TEXT_WIRE_MAX - 1);
        assert!(
            core::str::from_utf8(detail).is_ok(),
            "cut at a char boundary"
        );
        assert!(out.len() <= 4096);

        let mut out = Reply::new();
        let plain = Fail::refused(refused::R_DENIED).with_error(0);
        assert_eq!(write_fail(&mut out, &plain).ok(), Some(Status::REFUSED));
        let tags: Vec<_> = Records::new(out.as_bytes())
            .map(|r| r.map(|r| r.tag).ok())
            .collect();
        assert_eq!(
            tags,
            [Some(tag::FAIL)],
            "no ERROR for 0, no facts on REFUSED"
        );
    }

    #[test]
    fn chain_keys_are_never_reused_and_threads_differ() {
        let a = ChainKey::mint();
        let b = ChainKey::mint();
        assert_ne!(a, b);
        assert_eq!(a.thread, b.thread);
        let Ok(c) = std::thread::spawn(ChainKey::mint).join() else {
            panic!("thread");
        };
        assert_ne!(a.thread, c.thread);
    }

    /// C-STALE-PANIC, the restore half: the guard puts back exactly what it found, on return and on unwind,
    /// so a nested poll leaves the outer mail in place and a panicking poll leaves none behind.
    #[test]
    fn the_current_guard_restores_on_return_and_on_unwind() {
        let Some(mut outer_mail) = Inbox::new().mail.take() else {
            panic!("mail");
        };
        let outer_key = outer_mail.key;
        outer_mail.step = 7;
        let mut guard = CurrentGuard::set(outer_mail);
        {
            let Some(inner) = Inbox::new().mail.take() else {
                panic!("mail");
            };
            let inner_key = inner.key;
            let mut nested = CurrentGuard::set(inner);
            assert_eq!(with_mail(|m| m.key), Some(inner_key));
            let back = nested.restore().map(|m| m.key);
            assert_eq!(back, Some(inner_key));
        }
        assert_eq!(with_mail(|m| (m.key, m.step)), Some((outer_key, 7)));
        let unwound = std::panic::catch_unwind(|| {
            let Some(inner) = Inbox::new().mail.take() else {
                panic!("mail");
            };
            let _nested = CurrentGuard::set(inner);
            panic!("a poll panics");
        });
        assert!(unwound.is_err());
        assert_eq!(with_mail(|m| m.key), Some(outer_key), "restored on unwind");
        drop(guard.restore());
        drop(guard);
        assert_eq!(with_mail(|m| m.key), None, "nothing outside a poll");
    }
}
