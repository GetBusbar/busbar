// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE LOADED AUTH INSTANCE'S OUTBOUND CALLS AS THE KERNEL MAKES THEM: [`OutboundInstance`]
//! implements the contract's `OutboundAuth` over the one dispatcher's auth handle (THE DESIGN, section 6,
//! section 11.6), so the kernel's egress walk reaches a compiled-in and a dropped-in auth plugin through
//! the same table without naming this crate. The composition root builds it, opens each provider's
//! binding at generation seal, and hands the kernel the handle.
//!
//! `fields` is tried ticket-less first (a cached header answers in place, one crossing on the
//! caller's thread); a plugin that must wait for a refresh is submitted on a ticket and awaited, the
//! host buffers its `in` names lent to the dispatcher until the op completes, so a caller that stops
//! waiting frees nothing a worker still reads.

#![allow(unsafe_code)]

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use busbar_contract::abi::auth::{
    slot, AuthPoint, FieldSpan, FieldsIn, FieldsOut, NamedValue, OpenOutboundIn, OpenOutboundOut,
    RequestFacts, FIELDS_BUF_BYTES, FIELDS_MAX, FIELD_SENSITIVE, MODE_OWN, MODE_PASSTHROUGH,
};
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, DeadlineClass, Outcome, BLOB_ABSENT, BLOB_JSON, BLOB_OCTETS, BLOB_SECRET,
};
use busbar_contract::auth_calls::{AuthField, Fielding, Fields, FieldsRequest, OutboundAuth};
use busbar_contract::redacted::Redacted;

use super::kinds::auth::Auth;
use super::{in_head, out_head, Dispatcher, Frame, Plugin};

/// One open auth instance, the dispatcher that adopted it, and the worker a waiting `fields` is
/// submitted on.
#[derive(Debug, Clone)]
pub struct OutboundInstance {
    plugin: Plugin<Auth>,
    dispatcher: Arc<Dispatcher>,
    worker: u32,
}

impl OutboundInstance {
    /// `plugin`, adopted by `dispatcher`, a waiting `fields` submitted on `worker`.
    pub fn new(plugin: Plugin<Auth>, dispatcher: Arc<Dispatcher>, worker: u32) -> Self {
        OutboundInstance {
            plugin,
            dispatcher,
            worker,
        }
    }
}

const ABSENT_STR: AbiStr = AbiStr {
    ptr: std::ptr::null(),
    len: 0,
};

fn abi_str(b: &[u8]) -> AbiStr {
    AbiStr {
        ptr: b.as_ptr(),
        len: b.len(),
    }
}

fn blob(b: &[u8], fmt: u32, flags: u32) -> Blob {
    Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt,
        flags,
    }
}

const NO_BLOB: Blob = Blob {
    ptr: std::ptr::null(),
    len: 0,
    fmt: BLOB_ABSENT,
    flags: 0,
};

const NO_FIELD: FieldSpan = FieldSpan {
    name: busbar_contract::abi::mechanism::call::Span { offset: 0, len: 0 },
    value: busbar_contract::abi::mechanism::call::Span { offset: 0, len: 0 },
    flags: 0,
    _reserved: 0,
};

/// THE HOST MEMORY ONE `fields` LENDS THE PLUGIN: the request's bytes, the envelope's named values
/// pointing into them, and the buffers the answer is written into. Every pointer an `in` holds
/// points into a heap allocation owned here, which never moves while this lives.
struct Lend {
    request: FieldsRequest,
    named: Vec<NamedValue>,
    field_buf: Vec<u8>,
    fields: Vec<FieldSpan>,
}

// SAFETY: the raw pointers in `named` point only into `request`'s own heap bytes, owned here; the
// plugin writes `field_buf`/`fields` only while its op is in flight, and the host reads them only
// after the op's answer, which the dispatcher orders after the crossing.
unsafe impl Send for Lend {}
// SAFETY: as above; no host code mutates a `Lend` once the op is submitted.
unsafe impl Sync for Lend {}

impl Drop for Lend {
    /// The caller's credential and the auth fields are credential material: zeroised once the
    /// crossing's memory is dropped (after the op's last crossing and the host's copy-out).
    fn drop(&mut self) {
        // The caller's credential zeroises itself (`Redacted`); the field bytes are wiped here.
        self.field_buf.fill(0);
    }
}

impl Lend {
    fn new(request: FieldsRequest, bytes: usize, fields: usize) -> Box<Self> {
        let named = request
            .headers
            .iter()
            .map(|(n, v)| NamedValue {
                name: abi_str(n),
                value: blob(v, BLOB_OCTETS, 0),
            })
            .collect();
        Box::new(Lend {
            request,
            named,
            field_buf: vec![0; bytes],
            fields: vec![NO_FIELD; fields],
        })
    }

    /// The `in` naming this memory under `handle`.
    fn input(&mut self, handle: u64) -> FieldsIn {
        let r = &self.request;
        FieldsIn {
            head: in_head(),
            handle,
            mode: if r.caller_credential.is_some() {
                MODE_PASSTHROUGH
            } else {
                MODE_OWN
            },
            point: r.point.bit(),
            request: RequestFacts {
                method: abi_str(&r.method),
                authority: abi_str(r.authority.as_bytes()),
                canonical_path: abi_str(&r.path),
                query: r.query.as_deref().map_or(ABSENT_STR, abi_str),
                timestamp: r.timestamp,
            },
            caller_credential: r.caller_credential.as_ref().map_or(NO_BLOB, |c| {
                blob(c.expose_secret(), BLOB_OCTETS, BLOB_SECRET)
            }),
            field_buf: self.field_buf.as_mut_ptr(),
            field_buf_cap: self.field_buf.len(),
            fields: self.fields.as_mut_ptr(),
            fields_cap: u32::try_from(self.fields.len()).unwrap_or(u32::MAX),
            _reserved: 0,
            headers: if self.named.is_empty() {
                std::ptr::null()
            } else {
                self.named.as_ptr()
            },
            headers_len: self.named.len(),
            conn: r.conn,
            unit: r.unit,
            // The body is lent only at `HeadBody`, never at another point; a signing style hashes
            // it itself.
            body: match (r.point, r.body.as_deref()) {
                (AuthPoint::HeadBody, Some(b)) => blob(b, BLOB_OCTETS, 0),
                _ => NO_BLOB,
            },
        }
    }

    /// The fields a READY answer wrote, copied out of the host buffer. The dispatcher's validator
    /// (`check_fields`) already bounded every span.
    fn answer(&self, out: &FieldsOut) -> Fields {
        let take = |s: busbar_contract::abi::mechanism::call::Span| {
            let start = s.offset as usize;
            self.field_buf
                .get(start..start.saturating_add(s.len as usize))
                .unwrap_or_default()
                .to_vec()
        };
        Fields::Ready(
            self.fields
                .iter()
                .take(out.fields_len as usize)
                .map(|f| AuthField {
                    name: take(f.name),
                    value: Redacted::new(take(f.value)),
                    sensitive: f.flags & FIELD_SENSITIVE != 0,
                })
                .collect(),
        )
    }
}

/// A copy of `r` for one crossing's lent memory (the caller's credential included; each copy is
/// zeroised when its crossing's memory is dropped).
fn copy(r: &FieldsRequest) -> FieldsRequest {
    FieldsRequest {
        point: r.point,
        conn: r.conn,
        unit: r.unit,
        body: r.body.clone(),
        method: r.method.clone(),
        authority: r.authority.clone(),
        path: r.path.clone(),
        query: r.query.clone(),
        timestamp: r.timestamp,
        headers: r.headers.clone(),
        caller_credential: r.caller_credential.clone(),
    }
}

fn fields_out() -> FieldsOut {
    FieldsOut {
        head: out_head(),
        fields_len: 0,
        needed_fields: 0,
        needed_bytes: 0,
    }
}

/// The sizes a short answer named, never below the host's starting sizes.
fn grown(out: &FieldsOut) -> (usize, usize) {
    (
        usize::try_from(out.needed_bytes)
            .unwrap_or(usize::MAX)
            .max(FIELDS_BUF_BYTES),
        (out.needed_fields as usize).max(FIELDS_MAX as usize),
    )
}

fn settled(outcome: Outcome, lend: &Lend, out: &FieldsOut) -> Fields {
    match outcome {
        Outcome::Ready => lend.answer(out),
        Outcome::Refused => Fields::Refused,
        _ => Fields::Failed,
    }
}

impl OutboundAuth for OutboundInstance {
    fn open_outbound(
        &self,
        style: &str,
        credential: &[u8],
        settings: &serde_json::Value,
    ) -> Result<u64, String> {
        let settings = serde_json::to_vec(settings).map_err(|e| e.to_string())?;
        let mut frame = Frame::new(
            OpenOutboundIn {
                head: in_head(),
                style: abi_str(style.as_bytes()),
                credential: if credential.is_empty() {
                    NO_BLOB
                } else {
                    blob(credential, BLOB_OCTETS, BLOB_SECRET)
                },
                settings: blob(&settings, BLOB_JSON, 0),
            },
            OpenOutboundOut {
                head: out_head(),
                handle: 0,
            },
        );
        let called = self.plugin.call(slot::OPEN_OUTBOUND, &mut frame);
        if called.outcome == Outcome::Ready {
            return Ok(frame.out.handle);
        }
        let why = called
            .error
            .map(|e| String::from_utf8_lossy(&e).into_owned())
            .unwrap_or_default();
        Err(format!(
            "`{}` did not open the outbound style `{style}`: {:?} {why}",
            self.plugin.name(),
            called.outcome
        ))
    }

    fn fields_now(&self, handle: u64, request: &FieldsRequest) -> Option<Fields> {
        let mut lend = Lend::new(copy(request), FIELDS_BUF_BYTES, FIELDS_MAX as usize);
        let mut frame = Frame::new(lend.input(handle), fields_out());
        let mut called = self.plugin.call(slot::FIELDS, &mut frame);
        if let Some(token) = called.recall.take() {
            let (bytes, fields) = grown(&frame.out);
            lend.field_buf.resize(bytes, 0);
            lend.fields.resize(fields, NO_FIELD);
            frame = Frame::new(lend.input(handle), fields_out());
            called = self.plugin.recall(token, slot::FIELDS, &mut frame);
        }
        (called.outcome == Outcome::Ready).then(|| lend.answer(&frame.out))
    }

    fn fields(&self, handle: u64, request: FieldsRequest, deadline_ns: u64) -> Box<dyn Fielding> {
        let this = self.clone();
        let run = async move {
            let Some(ticket) = this.dispatcher.mint(this.worker) else {
                return Fields::Failed;
            };
            let guard = Ticketed {
                dispatcher: Arc::clone(&this.dispatcher),
                ticket,
                answered: false,
            };
            let mut sizes = (FIELDS_BUF_BYTES, FIELDS_MAX as usize);
            let mut first = true;
            loop {
                let mut lend = Lend::new(copy(&request), sizes.0, sizes.1);
                let input = lend.input(handle);
                let lent: Arc<Lend> = Arc::from(lend);
                let reply = this.dispatcher.submit_lent(
                    &this.plugin,
                    ticket,
                    slot::FIELDS,
                    Frame::new(input, fields_out()),
                    DeadlineClass::Call,
                    deadline_ns,
                    Arc::clone(&lent) as super::Lent,
                );
                let done = reply.await;
                let out = done.frame.as_ref().map(|f| f.out);
                match (done.short && first, out) {
                    // THE ONE RE-CALL, on the same ticket, with what the answer said it needs; the
                    // dispatcher answers a second short answer FAULT.
                    (true, Some(out)) => {
                        first = false;
                        sizes = grown(&out);
                    }
                    (_, Some(out)) => {
                        let mut guard = guard;
                        guard.answered = true;
                        break settled(done.outcome, &lent, &out);
                    }
                    (_, None) => break Fields::Failed,
                }
            }
        };
        Box::new(Waiting {
            run: Box::pin(run),
            done: None,
        })
    }
}

/// A submitted `fields`' ticket: recycled when the answer is read, and handed to the client-drop
/// path first when the caller stops waiting before it (the lent memory stays with the op).
struct Ticketed {
    dispatcher: Arc<Dispatcher>,
    ticket: busbar_contract::abi::mechanism::ticket::Ticket,
    answered: bool,
}

impl Drop for Ticketed {
    fn drop(&mut self) {
        if !self.answered {
            self.dispatcher.drop_client(self.ticket);
        }
        self.dispatcher.recycle(self.ticket);
    }
}

/// One `fields` in flight.
struct Waiting {
    run: Pin<Box<dyn Future<Output = Fields> + Send>>,
    done: Option<Fields>,
}

impl Future for Waiting {
    type Output = Fields;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Fields> {
        if let Some(d) = &self.done {
            return Poll::Ready(d.clone());
        }
        match self.run.as_mut().poll(cx) {
            Poll::Ready(d) => {
                self.done = Some(d.clone());
                Poll::Ready(d)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Fielding for Waiting {
    fn settled(&mut self) -> Option<Fields> {
        if self.done.is_none() {
            let mut cx = Context::from_waker(Waker::noop());
            if let Poll::Ready(d) = self.run.as_mut().poll(&mut cx) {
                self.done = Some(d);
            }
        }
        self.done.clone()
    }
}

#[cfg(test)]
#[path = "tests/auth_outbound_tests.rs"]
mod tests;
