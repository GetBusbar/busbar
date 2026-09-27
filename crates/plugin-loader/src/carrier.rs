// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOT DOOR'S CARRIER (minor 30; ARCHITECT DEC-SERVE G2; spec Part 3 WorkItem reserved-shape,
//! #28): the host half of the work item's request-head handle and its answer emit slots.
//!
//! A plane that lives in its own repository reads what the caller sent — method, path, query,
//! headers — through the work item's `head_read` accessor slot, and answers with the status,
//! headers and body its provider answered, byte for byte: the head through `emit_head`, a body up to
//! the reply buffer's capacity into the buffer ([`MAX_PLANE_REPLY_LEN`]), a larger one in chunks
//! through `emit_body` on the work item's response-stream handle. [`ServedPlane::answer`] is the one
//! place a work item carrying them is built, for a linked plane and a dropped-in one alike.
//!
//! The head and the emit sink live on the dispatching thread's stack for the dispatch call. A slot
//! answers only for the handle the CURRENT dispatch on its own thread issued ([`Current`]), so a
//! stale or forged handle is refused rather than dereferenced.
//!
//! [`ServedPlane::answer`]: crate::ServedPlane::answer

use busbar_contract::abi::hot::pod::StatusClass;
use busbar_contract::abi::hot::workitem::{HeadField, HeadPart};
use busbar_contract::abi::write_out;
use core::mem::MaybeUninit;
use std::cell::Cell;
use std::os::raw::c_void;
use std::panic::{catch_unwind, AssertUnwindSafe};

/// Cap on one dispatch's buffered reply: the reply channel the host hands the plane. A body larger
/// than this goes out through the response-stream emit kind.
pub const MAX_PLANE_REPLY_LEN: usize = 1024 * 1024;

/// Cap on how many headers one answer head may state.
pub const MAX_ANSWER_HEADERS: usize = 128;

/// What the caller sent, as a work item carries it: every range borrowed for the dispatch call.
#[derive(Debug, Clone, Copy)]
pub struct RequestHead<'a> {
    /// The request method, as sent.
    pub method: &'a [u8],
    /// The request path, without the query.
    pub path: &'a [u8],
    /// The query string, without the `?` (empty for none).
    pub query: &'a [u8],
    /// The headers, `(name, value)`, in the host's order.
    pub headers: &'a [(&'a [u8], &'a [u8])],
}

/// Where a streamed answer goes as the plane writes it. `false` from either call = the caller went
/// away; the plane is told `Gone` and stops.
pub trait ReplyStream {
    /// The answer's head, once, before the first chunk: the status the plane stated (`None` = it
    /// stated none) and its headers.
    fn head(&mut self, status: Option<u16>, headers: &[(Vec<u8>, Vec<u8>)]) -> bool;
    /// One body chunk.
    fn chunk(&mut self, bytes: &[u8]) -> bool;
}

/// What one served dispatch answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HotReply {
    /// The plane's status class (a caught panic, or a reply past the buffer, is `Fault`).
    pub class: StatusClass,
    /// The HTTP status the plane stated through `emit_head` — its provider's — if it stated one.
    pub status: Option<u16>,
    /// The headers it stated, in order (empty when it stated no head).
    pub headers: Vec<(Vec<u8>, Vec<u8>)>,
    /// The buffered body; empty when the body was streamed.
    pub body: Vec<u8>,
    /// The body went out through the [`ReplyStream`] (its head included).
    pub streamed: bool,
}

/// The emit sink one dispatch's `emit_head` / `emit_body` write into.
pub(crate) struct Sink<'s> {
    pub(crate) status: Option<u16>,
    pub(crate) headers: Vec<(Vec<u8>, Vec<u8>)>,
    head_stated: bool,
    pub(crate) streamed: bool,
    gone: bool,
    stream: Option<&'s mut dyn ReplyStream>,
}

impl<'s> Sink<'s> {
    pub(crate) fn new(stream: Option<&'s mut dyn ReplyStream>) -> Self {
        Sink {
            status: None,
            headers: Vec::new(),
            head_stated: false,
            streamed: false,
            gone: false,
            stream,
        }
    }

    pub(crate) fn offers_stream(&self) -> bool {
        self.stream.is_some()
    }
}

thread_local! {
    /// The head and the sink the dispatch running on this thread issued, as addresses.
    static CURRENT: Cell<(usize, u64)> = const { Cell::new((0, 0)) };
}

/// The CURRENT dispatch's handles on this thread, for as long as the guard lives; the previous
/// ones (a nested dispatch's caller) come back on drop.
pub(crate) struct Current((usize, u64));

impl Current {
    pub(crate) fn enter(head: *const c_void, sink: u64) -> Self {
        Current(CURRENT.with(|c| c.replace((head as usize, sink))))
    }
}

impl Drop for Current {
    fn drop(&mut self) {
        CURRENT.with(|c| c.set(self.0));
    }
}

/// The sink `emit` names, when it is the one the current dispatch on this thread issued.
///
/// # Safety
/// The current dispatch's sink is live on this thread's stack for the call (see [`Current`]).
unsafe fn issued_sink<'a>(emit: u64) -> Option<&'a mut Sink<'a>> {
    let (_, sink) = CURRENT.with(Cell::get);
    if emit == 0 || emit != sink {
        return None;
    }
    // SAFETY: the caller's obligation; `emit` is exactly the live sink's address.
    unsafe { (emit as usize as *mut Sink<'a>).as_mut() }
}

/// THE `head_read` ACCESSOR SLOT over a [`RequestHead`] (see [`HeadReadFn`]).
///
/// [`HeadReadFn`]: busbar_contract::abi::hot::HeadReadFn
pub(crate) extern "C-unwind" fn head_read(
    head: *const c_void,
    part: u8,
    index: u32,
    out: *mut MaybeUninit<HeadField>,
) -> StatusClass {
    catch_unwind(AssertUnwindSafe(|| {
        let (current, _) = CURRENT.with(Cell::get);
        if head.is_null() || out.is_null() || head as usize != current {
            return StatusClass::Refused;
        }
        // SAFETY: `head` is the current dispatch's own head, live on this thread for the call.
        let h = unsafe { &*head.cast::<RequestHead<'_>>() };
        let field = match part {
            p if p == HeadPart::Method as u8 => HeadField::new(&[], h.method),
            p if p == HeadPart::Path as u8 => HeadField::new(&[], h.path),
            p if p == HeadPart::Query as u8 => HeadField::new(&[], h.query),
            p if p == HeadPart::Header as u8 => match h.headers.get(index as usize) {
                Some((name, value)) => HeadField::new(name, value),
                None => return StatusClass::Gone,
            },
            _ => return StatusClass::Refused,
        };
        // SAFETY: `out` is the plane's live out-slot; written only on the Ok path.
        unsafe { write_out(out, field) };
        StatusClass::Ok
    }))
    .unwrap_or(StatusClass::Fault)
}

/// A header name the host can serve: a non-empty RFC 9110 token.
fn servable_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(b))
}

/// A header value the host can serve: visible ASCII, space, tab or obs-text — no control byte.
fn servable_value(value: &[u8]) -> bool {
    value
        .iter()
        .all(|&b| b == b'\t' || (0x20..0x7f).contains(&b) || b >= 0x80)
}

/// THE `emit_head` SLOT (see [`EmitHeadFn`]).
///
/// [`EmitHeadFn`]: busbar_contract::abi::hot::EmitHeadFn
pub(crate) extern "C-unwind" fn emit_head(
    emit: u64,
    status: u16,
    headers_ptr: *const HeadField,
    headers_len: usize,
) -> StatusClass {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: `issued_sink` answers only the current dispatch's live sink.
        let Some(sink) = (unsafe { issued_sink(emit) }) else {
            return StatusClass::Refused;
        };
        if sink.head_stated
            || sink.streamed
            || !(100..=999).contains(&status)
            || headers_len > MAX_ANSWER_HEADERS
            || (headers_ptr.is_null() && headers_len > 0)
        {
            return StatusClass::Refused;
        }
        let fields: &[HeadField] = if headers_len == 0 {
            &[]
        } else {
            // SAFETY: a non-null range of `headers_len` fields, live for the call (the slot's
            // discipline).
            unsafe { core::slice::from_raw_parts(headers_ptr, headers_len) }
        };
        let mut headers = Vec::with_capacity(fields.len());
        for field in fields {
            // SAFETY: each field's ranges are live for the call (the slot's discipline).
            let (name, value) = unsafe { (field.name(), field.value()) };
            if !servable_name(name) || !servable_value(value) {
                return StatusClass::Refused;
            }
            headers.push((name.to_vec(), value.to_vec()));
        }
        sink.status = Some(status);
        sink.headers = headers;
        sink.head_stated = true;
        StatusClass::Ok
    }))
    .unwrap_or(StatusClass::Fault)
}

/// THE `emit_body` SLOT (see [`EmitBodyFn`]): the first chunk commits the head to the stream.
///
/// [`EmitBodyFn`]: busbar_contract::abi::hot::EmitBodyFn
pub(crate) extern "C-unwind" fn emit_body(
    emit: u64,
    chunk_ptr: *const u8,
    chunk_len: usize,
) -> StatusClass {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: `issued_sink` answers only the current dispatch's live sink.
        let Some(sink) = (unsafe { issued_sink(emit) }) else {
            return StatusClass::Refused;
        };
        if chunk_ptr.is_null() && chunk_len > 0 {
            return StatusClass::Refused;
        }
        if sink.gone {
            return StatusClass::Gone;
        }
        let first = !sink.streamed;
        let Some(stream) = sink.stream.as_deref_mut() else {
            return StatusClass::Refused;
        };
        let opened = !first || stream.head(sink.status, &sink.headers);
        sink.streamed = true;
        let chunk: &[u8] = if chunk_len == 0 {
            &[]
        } else {
            // SAFETY: a non-null range of `chunk_len` bytes, live for the call.
            unsafe { core::slice::from_raw_parts(chunk_ptr, chunk_len) }
        };
        if !opened || !stream.chunk(chunk) {
            sink.gone = true;
            return StatusClass::Gone;
        }
        StatusClass::Ok
    }))
    .unwrap_or(StatusClass::Fault)
}

#[cfg(test)]
#[path = "tests/carrier_tests.rs"]
mod tests;
