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
use std::task::{Context, Poll};

use busbar_contract::abi::auth::{
    slot, AuthPoint, FieldSpan, FieldsIn, FieldsOut, NamedValue, OpenOutboundIn, OpenOutboundOut,
    OutboundReadyIn, OutboundReadyOut, RequestFacts, FIELDS_BUF_BYTES, FIELDS_MAX, FIELD_SENSITIVE,
    MODE_OWN, MODE_PASSTHROUGH,
};
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, DeadlineClass, Outcome, BLOB_ABSENT, BLOB_JSON, BLOB_OCTETS, BLOB_SECRET,
};
use busbar_contract::auth_calls::{AuthField, Fielding, Fields, FieldsRequest, OutboundAuth};
use busbar_contract::redacted::Secret;

use super::call::{Answering, Pending, Ticketed};
use super::kinds::auth::{Auth, AuthFacts, OutboundStyle};
use super::lifecycle::{open_frame, validate_call};
use super::{in_head, out_head, Dispatcher, Done, Frame, Plugin};

/// One open auth instance, the dispatcher that adopted it, and the worker a waiting `fields` is
/// submitted on. The instance is shared, never copied: a [`Plugin`] is `!Clone`, so the tick
/// schedule this instance runs shares the same `Arc`.
#[derive(Debug, Clone)]
pub struct OutboundInstance {
    plugin: Arc<Plugin<Auth>>,
    dispatcher: Arc<Dispatcher>,
    worker: u32,
}

/// THE OUTBOUND STYLES `plugin`'s tail states (THE DESIGN §6 step 3: the auth plugin that serves
/// a style opens the binding). Read once per row by the host, which then binds only the row that
/// serves the style it is asked for.
#[must_use]
pub fn outbound_styles(plugin: &Plugin<Auth>) -> Vec<OutboundStyle> {
    plugin
        .context::<AuthFacts>()
        .map(|f| f.styles.clone())
        .unwrap_or_default()
}

impl OutboundInstance {
    /// `plugin` (owned, or shared through its `Arc`), adopted by `dispatcher`, a waiting `fields`
    /// submitted on `worker`.
    pub fn new(
        plugin: impl Into<Arc<Plugin<Auth>>>,
        dispatcher: Arc<Dispatcher>,
        worker: u32,
    ) -> Self {
        OutboundInstance {
            plugin: plugin.into(),
            dispatcher,
            worker,
        }
    }

    /// `plugin`'s instance OPENED over the settings document `settings` (a JSON object): the
    /// binding's own settings, for a plugin whose needs take their target from them (`target_from`:
    /// the loader declares each such need pinned to what its path resolves to in `settings`, at
    /// this `open`, THE DESIGN §5 PB-100).
    ///
    /// # Errors
    ///
    /// `validate` or `open` did not answer READY, naming the plugin.
    pub fn open_with(
        plugin: Plugin<Auth>,
        dispatcher: Arc<Dispatcher>,
        worker: u32,
        settings: &[u8],
    ) -> Result<Self, String> {
        use busbar_contract::abi::mechanism::lifecycle::slot as lc;
        let named = |what: &str, outcome: Outcome| {
            format!(
                "`{}` did not {what} for its outbound styles: {outcome:?}",
                plugin.name()
            )
        };
        let called = validate_call(&plugin, blob(settings, BLOB_JSON, 0));
        if called.outcome != Outcome::Ready {
            return Err(named("validate", called.outcome));
        }
        let mut f = open_frame(blob(settings, BLOB_JSON, 0));
        let called = plugin.call(lc::OPEN, &mut f);
        if called.outcome != Outcome::Ready {
            return Err(named("open", called.outcome));
        }
        Ok(Self::new(plugin, dispatcher, worker))
    }

    /// THE INSTANCE'S TICK SCHEDULE (THE DESIGN §6.5: a minted credential refreshes ahead of
    /// expiry on `tick`): the one auth schedule, [`super::auth_ticks::ticks`], holding the instance
    /// for as long as it runs.
    pub async fn ticks(self: Arc<Self>) {
        super::auth_ticks::ticks(&self.plugin, &self.dispatcher, self.worker).await;
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
        // The caller's credential zeroises itself (`Secret`); the field bytes are wiped here.
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

    /// The `in` naming this memory under `handle`. `seal` is the host's, lent to the dispatcher: the
    /// caller's credential is revealed under it to be lent to the plugin (the caller refuses a
    /// request that carries one when none was lent).
    fn input(
        &mut self,
        handle: u64,
        seal: Option<&(dyn busbar_contract::plugin::KernelSeal + Send + Sync)>,
    ) -> FieldsIn {
        let r = &self.request;
        let mut head = in_head();
        // The call's extensions blob (the per-call scope, when the request stated one), lent with
        // the rest of the request's bytes.
        if !r.extensions.is_empty() {
            head.extensions = blob(&r.extensions, BLOB_OCTETS, 0);
        }
        FieldsIn {
            head,
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
            caller_credential: match (r.caller_credential.as_ref(), seal) {
                (Some(c), Some(seal)) => blob(c.expose(seal), BLOB_OCTETS, BLOB_SECRET),
                _ => NO_BLOB,
            },
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
                    value: Secret::new(take(f.value)),
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
        extensions: r.extensions.clone(),
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

impl OutboundInstance {
    /// `open_outbound`, its refusal as the plugin wrote it: the outcome and the plugin's own error
    /// text (empty when it wrote none).
    ///
    /// # Errors
    /// The binding did not open: the outcome and the plugin's words.
    pub fn open_outbound_raw(
        &self,
        style: &str,
        credential: &[u8],
        settings: &serde_json::Value,
    ) -> Result<u64, (Outcome, String)> {
        let settings =
            serde_json::to_vec(settings).map_err(|e| (Outcome::Refused, e.to_string()))?;
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
        Err((called.outcome, why))
    }
}

impl OutboundAuth for OutboundInstance {
    fn open_outbound(
        &self,
        style: &str,
        credential: &[u8],
        settings: &serde_json::Value,
    ) -> Result<u64, String> {
        self.open_outbound_raw(style, credential, settings)
            .map_err(|(outcome, why)| {
                format!(
                    "`{}` did not open the outbound style `{style}`: {outcome:?} {why}",
                    self.plugin.name(),
                )
            })
    }

    fn ready(&self, handle: u64) -> bool {
        let mut frame = Frame::new(
            OutboundReadyIn {
                head: in_head(),
                handle,
            },
            OutboundReadyOut {
                head: out_head(),
                ready: 0,
                _reserved: 0,
            },
        );
        // Not READY (a handle this generation does not hold, a fault): not ready, so a prober never
        // sends an unauthenticated request on it.
        self.plugin.call(slot::OUTBOUND_READY, &mut frame).outcome == Outcome::Ready
            && frame.out.ready != 0
    }

    fn fields_now(&self, handle: u64, request: &FieldsRequest) -> Option<Fields> {
        // No seal lent to the dispatcher: a caller credential is not revealed, and the fields fail.
        let seal = self.dispatcher.seal();
        if request.caller_credential.is_some() && seal.is_none() {
            return Some(Fields::Failed);
        }
        let mut lend = Lend::new(copy(request), FIELDS_BUF_BYTES, FIELDS_MAX as usize);
        let mut frame = Frame::new(lend.input(handle, seal), fields_out());
        let mut called = self.plugin.call(slot::FIELDS, &mut frame);
        if let Some(token) = called.recall.take() {
            let (bytes, fields) = grown(&frame.out);
            lend.field_buf.resize(bytes, 0);
            lend.fields.resize(fields, NO_FIELD);
            frame = Frame::new(lend.input(handle, seal), fields_out());
            called = self.plugin.recall(token, slot::FIELDS, &mut frame);
        }
        (called.outcome == Outcome::Ready).then(|| lend.answer(&frame.out))
    }

    fn fields(&self, handle: u64, request: FieldsRequest, deadline_ns: u64) -> Box<dyn Fielding> {
        // No seal lent to the dispatcher: a caller credential is not revealed, and the fields fail.
        if request.caller_credential.is_some() && self.dispatcher.seal().is_none() {
            return Box::new(Failed);
        }
        let Some(call) = Ticketed::mint(&self.dispatcher, self.worker) else {
            return Box::new(Failed);
        };
        Box::new(Pending::new(
            call,
            Asked {
                this: self.clone(),
                handle,
                request,
                deadline_ns,
                lend: None,
                first: true,
            },
        ))
    }
}

/// A `fields` that failed before anything crossed.
struct Failed;

impl Future for Failed {
    type Output = Fields;

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Fields> {
        Poll::Ready(Fields::Failed)
    }
}

impl Fielding for Failed {
    fn settled(&mut self) -> Option<Fields> {
        Some(Fields::Failed)
    }
}

/// One `fields`, submitted on its ticket when first polled: the one re-call a short answer earns,
/// then the fields its lent memory holds.
struct Asked {
    this: OutboundInstance,
    handle: u64,
    request: FieldsRequest,
    deadline_ns: u64,
    /// The memory the last op was lent (the buffers its answer was written into).
    lend: Option<Arc<Lend>>,
    first: bool,
}

impl Asked {
    /// Submit `fields` on `call` over buffers of `bytes` and `fields`.
    fn submit(
        &mut self,
        call: &mut Ticketed<FieldsIn, FieldsOut>,
        (bytes, fields): (usize, usize),
    ) {
        let mut lend = Lend::new(copy(&self.request), bytes, fields);
        let input = lend.input(self.handle, self.this.dispatcher.seal());
        let lent: Arc<Lend> = Arc::from(lend);
        call.submit(
            &*self.this.plugin,
            slot::FIELDS,
            Frame::new(input, fields_out()),
            DeadlineClass::Call,
            self.deadline_ns,
            Arc::clone(&lent) as super::Lent,
        );
        self.lend = Some(lent);
    }
}

impl Answering<FieldsIn, FieldsOut> for Asked {
    type Out = Fields;

    fn start(&mut self, call: &mut Ticketed<FieldsIn, FieldsOut>) {
        self.submit(call, (FIELDS_BUF_BYTES, FIELDS_MAX as usize));
    }

    fn answer(
        &mut self,
        done: Done<FieldsIn, FieldsOut>,
        call: &mut Ticketed<FieldsIn, FieldsOut>,
    ) -> Option<Fields> {
        let out = done.frame.as_ref().map(|f| f.out);
        match (done.short && self.first, out, &self.lend) {
            // THE ONE RE-CALL, on the same ticket, with what the answer said it needs; the
            // dispatcher answers a second short answer FAULT.
            (true, Some(out), _) => {
                self.first = false;
                self.submit(call, grown(&out));
                None
            }
            (_, Some(out), Some(lend)) => Some(settled(done.outcome, lend, &out)),
            _ => Some(Fields::Failed),
        }
    }
}

impl Fielding for Pending<FieldsIn, FieldsOut, Asked> {
    fn settled(&mut self) -> Option<Fields> {
        self.now()
    }
}

#[cfg(test)]
#[path = "tests/auth_outbound_tests.rs"]
mod tests;
