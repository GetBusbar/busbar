// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A SCRIPTED FAR END for an op's exchange ([`busbar_contract::abi::sdk::exchange::Op::exchange`]): the
//! connector services a framed request crosses (`ESTABLISH`, `WRITE_REQUEST`, `READ_REPLY`,
//! `CLOSE`) answered the way a connector host answers them. Every service PENDS on its first issue
//! and completes on the host's side; the op's RESUME re-issues the same handle and reads the stored
//! result (the replay rule, `abi::sdk::conn`). So a plugin's test drives a `decide`, a `deliver` or
//! any op that asks the far end through PENDING to its answer, and reads what was sent.
//!
//! ```ignore
//! use busbar_test_kit::test_support::far::Far;
//! use busbar_test_kit::test_support::fake::FakeHost;
//!
//! let far = Far::answering(200, b"{\"order\": [1, 0]}");
//! let host = FakeHost::new().far();
//! // open over `host.lend_in(..)`, then call the op on a ticket: PENDING until it is RESUMED
//! // (FLAG_RESUME) often enough, then its answer.
//! assert_eq!(far.sent()[0].method, b"POST");
//! assert_eq!(far.posts(), 1);
//! ```
//!
//! The script is PROCESS-WIDE: a [`Far`] holds it, one test at a time (a second `Far` waits for
//! the first to drop). A service the far end does not script is answered FAILED.
//!
//! TRUST: a connector slot is called with its own `in` and a writable `ServiceOut`; the buffers and
//! descriptors that `in` names are the SDK's own, live until the service completes (the connector
//! ABI, `abi::host::conn::connector`). The slots below read and write exactly those.

use core::ffi::c_void;
use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use busbar_contract::abi::host::conn::connector::{
    service, ReplyIn, ReplyPiece, RequestIn, RequestPiece, REPLY_BODY, REPLY_END, REPLY_HEAD,
    REQUEST_BODY, REQUEST_END, REQUEST_HEAD,
};
use busbar_contract::abi::host::service::{ServiceHead, ServiceOut};
use busbar_contract::abi::mechanism::call::{AbiStr, Outcome, RawOutcome};
use busbar_contract::abi::mechanism::ticket::HostCtx;
use busbar_contract::abi::transport::{fields, FrameSpan};

/// One request the far end was sent, as its framer was handed it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Sent {
    /// The method.
    pub method: Vec<u8>,
    /// The target.
    pub target: Vec<u8>,
    /// The fields, `(name, value)`, in order.
    pub fields: Vec<(Vec<u8>, Vec<u8>)>,
    /// The body.
    pub body: Vec<u8>,
    /// The request's end was written.
    pub ended: bool,
}

/// The far end's script and what it saw.
#[derive(Debug, Default)]
struct Script {
    status: u16,
    reason: Vec<u8>,
    fields: Vec<u8>,
    body: Vec<u8>,
    /// The stored result of each handle the host ran, by `(ticket slot, generation, seq)`.
    stored: HashMap<(u32, u32, u32), (Outcome, u64, u64)>,
    /// How many reply pieces each stream has read.
    reads: HashMap<u64, usize>,
    /// The request each stream is being sent.
    sending: HashMap<u64, Sent>,
    /// Every request sent whole, in order.
    sent: Vec<Sent>,
    /// The next stream.
    next: u64,
    /// Streams established and not closed.
    held: i64,
}

static SCRIPT: Mutex<Option<Script>> = Mutex::new(None);
/// One far end at a time: the script is process-wide.
static SERIAL: Mutex<()> = Mutex::new(());

/// THE SCRIPTED FAR END, held for the test's scope ([`Far::answering`]); its slots are installed
/// in a fake host's connector table by [`super::fake::FakeHost::far`].
#[derive(Debug)]
pub struct Far {
    _one: MutexGuard<'static, ()>,
}

impl Far {
    /// A far end that answers every request `status`, no reason and no fields, then `body`.
    #[must_use]
    pub fn answering(status: u16, body: &[u8]) -> Self {
        Self::replying(status, &[], body)
    }

    /// A far end that answers every request `status` with the fields `fields` (`(name, value)`,
    /// in order), then `body`.
    #[must_use]
    pub fn replying(status: u16, reply_fields: &[(&[u8], &[u8])], body: &[u8]) -> Self {
        let one = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
        let mut block = Vec::new();
        for (name, value) in reply_fields {
            block.extend_from_slice(name);
            block.extend_from_slice(fields::SEPARATOR);
            block.extend_from_slice(value);
            block.extend_from_slice(fields::LINE_END);
        }
        *script() = Some(Script {
            status,
            fields: block,
            body: body.to_vec(),
            next: 1,
            ..Script::default()
        });
        Self { _one: one }
    }

    /// Every request sent whole, in order.
    #[must_use]
    pub fn sent(&self) -> Vec<Sent> {
        with(|s| s.sent.clone())
    }

    /// How many requests were sent whole: what a plugin that POSTs posted.
    #[must_use]
    pub fn posts(&self) -> usize {
        with(|s| s.sent.len())
    }

    /// Streams established and not yet closed: `0` once every exchange closed its stream.
    #[must_use]
    pub fn held(&self) -> i64 {
        with(|s| s.held)
    }
}

impl Drop for Far {
    fn drop(&mut self) {
        *script() = None;
    }
}

fn script() -> MutexGuard<'static, Option<Script>> {
    SCRIPT.lock().unwrap_or_else(PoisonError::into_inner)
}

fn with<T>(f: impl FnOnce(&mut Script) -> T) -> T {
    f(script()
        .as_mut()
        .expect("no far end is scripted (Far::answering)"))
}

fn answer(out: *mut ServiceOut, o: Outcome, value: u64, len: u64) -> RawOutcome {
    // SAFETY: the SDK's `out`, live and writable for the call (the connector ABI).
    let out = unsafe { &mut *out };
    out.outcome = RawOutcome::of(o);
    out.value = value;
    out.len = len;
    if o == Outcome::Failed {
        const UNSCRIPTED: &str = "the scripted far end does not answer this service";
        out.error = AbiStr {
            ptr: UNSCRIPTED.as_ptr(),
            len: UNSCRIPTED.len(),
        };
    }
    RawOutcome::of(o)
}

fn spanned(buf: &[u8], s: FrameSpan) -> &[u8] {
    let (at, len) = (s.offset as usize, s.len as usize);
    buf.get(at..at.saturating_add(len)).unwrap_or(&[])
}

/// One service: the first issue of a handle runs it and PENDS (its result stored); a re-issue
/// answers the stored result.
fn serve(op: u32, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: every service `in` leads with a `ServiceHead` (the connector ABI).
    let head = unsafe { *input.cast::<ServiceHead>() };
    let key = (
        head.handle.ticket.slot,
        head.handle.ticket.generation,
        head.handle.seq,
    );
    let mut g = script();
    let Some(s) = g.as_mut() else {
        return answer(out, Outcome::Failed, 0, 0);
    };
    if let Some(&(o, v, l)) = s.stored.get(&key) {
        return answer(out, o, v, l);
    }
    let (value, len) = match op {
        service::ESTABLISH => {
            let stream = s.next;
            s.next += 1;
            s.held += 1;
            (stream, 0)
        }
        service::WRITE_REQUEST => {
            // SAFETY: a `RequestIn`, its descriptor and bytes the SDK's, live until it completes.
            let io = unsafe { *input.cast::<RequestIn>() };
            // SAFETY: as above.
            let (p, bytes): (RequestPiece, &[u8]) = unsafe {
                (
                    *io.piece,
                    if io.len == 0 {
                        &[]
                    } else {
                        core::slice::from_raw_parts(io.buf, io.len)
                    },
                )
            };
            let sending = s.sending.entry(io.stream).or_default();
            match p.kind {
                REQUEST_HEAD => {
                    sending.method = spanned(bytes, p.method).to_vec();
                    sending.target = spanned(bytes, p.target).to_vec();
                    sending.fields = fields::lines(spanned(bytes, p.fields))
                        .map(|(n, v)| (n.to_vec(), v.to_vec()))
                        .collect();
                }
                REQUEST_BODY => sending.body.extend_from_slice(bytes),
                REQUEST_END => {
                    sending.ended = true;
                    let whole = s.sending.remove(&io.stream).unwrap_or_default();
                    s.sent.push(whole);
                }
                _ => return answer(out, Outcome::Failed, 0, 0),
            }
            (0, io.len as u64)
        }
        service::READ_REPLY => {
            // SAFETY: a `ReplyIn`, its buffer and slot the SDK's, writable until it completes.
            let io = unsafe { *input.cast::<ReplyIn>() };
            let at = s.reads.entry(io.stream).or_default();
            let n = *at;
            *at += 1;
            let mut piece = ReplyPiece {
                kind: [REPLY_HEAD, REPLY_BODY, REPLY_END][n.min(2)],
                code: u32::from(s.status),
                ..ReplyPiece::default()
            };
            let bytes: Vec<u8> = match piece.kind {
                REPLY_HEAD => {
                    piece.reason = FrameSpan {
                        offset: 0,
                        len: s.reason.len() as u64,
                    };
                    piece.fields = FrameSpan {
                        offset: s.reason.len() as u64,
                        len: s.fields.len() as u64,
                    };
                    [s.reason.as_slice(), s.fields.as_slice()].concat()
                }
                REPLY_BODY => s.body.clone(),
                _ => Vec::new(),
            };
            if bytes.len() > io.len {
                // A piece larger than the read the SDK lent: script a smaller reply.
                return answer(out, Outcome::Failed, 0, 0);
            }
            // SAFETY: `io.buf` holds `io.len` writable bytes and `io.piece` a writable descriptor,
            // both the SDK's, until the read completes.
            unsafe {
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), io.buf, bytes.len());
                io.piece.write(piece);
            }
            (0, bytes.len() as u64)
        }
        service::CLOSE => {
            s.held -= 1;
            (0, 0)
        }
        _ => return answer(out, Outcome::Failed, 0, 0),
    };
    s.stored.insert(key, (Outcome::Ready, value, len));
    answer(out, Outcome::Pending, 0, 0)
}

macro_rules! far_slot {
    ($name:ident, $op:expr) => {
        pub(super) extern "C" fn $name(
            _: HostCtx,
            input: *const c_void,
            out: *mut ServiceOut,
        ) -> RawOutcome {
            serve($op, input, out)
        }
    };
}
far_slot!(establish, service::ESTABLISH);
far_slot!(write_request, service::WRITE_REQUEST);
far_slot!(read_reply, service::READ_REPLY);
far_slot!(close, service::CLOSE);
