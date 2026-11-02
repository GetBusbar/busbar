// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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
use busbar_contract::abi::mechanism::extensions;
use busbar_contract::abi::sdk::auth_outbound::{EXT_SEALED_FIELDS, SEALED_FIELDS_V1};
use busbar_contract::auth_calls::{AuthField, Fielding, Fields, FieldsRequest, OutboundAuth};
use busbar_contract::redacted::Secret;

use super::call::{Answering, Pending, Ticketed};
use super::kinds::auth::{Auth, AuthFacts, OutboundStyle};
use super::lifecycle::{open_frame, release, validate_call, AnswerLease};
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

#[must_use]
pub fn outbound_styles(plugin: &Plugin<Auth>) -> Vec<OutboundStyle> {
    plugin
        .context::<AuthFacts>()
        .map(|f| f.styles.clone())
        .unwrap_or_default()
}

impl OutboundInstance {
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
        let validated = AnswerLease::new(&plugin, called.lease);
        if called.outcome != Outcome::Ready {
            return Err(named("validate", called.outcome));
        }
        drop(validated);
        let mut f = open_frame(blob(settings, BLOB_JSON, 0));
        let called = plugin.call(lc::OPEN, &mut f);
        let opened = AnswerLease::new(&plugin, called.lease);
        if called.outcome != Outcome::Ready {
            return Err(named("open", called.outcome));
        }
        drop(opened);
        Ok(Self::new(plugin, dispatcher, worker))
    }

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
    fn drop(&mut self) {
        self.field_buf.fill(0);
    }
}

impl Lend {
    fn new(mut request: FieldsRequest, bytes: usize, fields: usize) -> Box<Self> {
        let mut capability = extensions::encode(&[(EXT_SEALED_FIELDS, SEALED_FIELDS_V1)]);
        capability.append(&mut request.extensions);
        request.extensions = capability;
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

    fn input(
        &mut self,
        handle: u64,
        seal: Option<&(dyn busbar_contract::plugin::KernelSeal + Send + Sync)>,
    ) -> FieldsIn {
        let r = &self.request;
        let mut head = in_head();

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

            body: match (r.point, r.body.as_deref()) {
                (AuthPoint::HeadBody, Some(b)) => blob(b, BLOB_OCTETS, 0),
                _ => NO_BLOB,
            },
        }
    }

    fn answer(&self, out: &FieldsOut) -> Fields {
        let Some(require_secure) = security_requirement(out.head.extensions) else {
            return Fields::Failed;
        };
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
                    query: f.flags & busbar_contract::abi::auth::FIELD_QUERY != 0,
                    require_secure,
                })
                .collect(),
        )
    }
}

fn security_requirement(blob: Blob) -> Option<bool> {
    if blob.fmt == BLOB_ABSENT && blob.len == 0 {
        return Some(false);
    }
    if blob.fmt != BLOB_OCTETS || (blob.len != 0 && blob.ptr.is_null()) {
        return None;
    }
    // SAFETY: the validated READY answer owns these bytes until its lease is released below.
    let bytes = unsafe { super::plugin::blob_bytes(blob) };
    let mut consumed = 0;
    let mut secure = false;
    for (key, value) in extensions::entries(bytes) {
        consumed += 2 + key.len() + 4 + value.len();
        if key == EXT_SEALED_FIELDS.as_bytes() {
            if secure || value != SEALED_FIELDS_V1 {
                return None;
            }
            secure = true;
        }
    }
    (consumed == bytes.len()).then_some(secure)
}

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
        let _lease = AnswerLease::new(&self.plugin, called.lease);
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

        let called = self.plugin.call(slot::OUTBOUND_READY, &mut frame);
        let _lease = AnswerLease::new(&self.plugin, called.lease);
        called.outcome == Outcome::Ready && frame.out.ready != 0
    }

    fn fields_now(&self, handle: u64, request: &FieldsRequest) -> Option<Fields> {
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
        let answer = (called.outcome == Outcome::Ready).then(|| lend.answer(&frame.out));
        release(&self.plugin, called.lease);
        answer
    }

    fn fields(&self, handle: u64, request: FieldsRequest, deadline_ns: u64) -> Box<dyn Fielding> {
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

struct Asked {
    this: OutboundInstance,
    handle: u64,
    request: FieldsRequest,
    deadline_ns: u64,

    lend: Option<Arc<Lend>>,
    first: bool,
}

impl Asked {
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
        let answer = match (done.short && self.first, out, &self.lend) {
            (true, Some(out), _) => {
                self.first = false;
                self.submit(call, grown(&out));
                None
            }
            (_, Some(out), Some(lend)) => Some(settled(done.outcome, lend, &out)),
            _ => Some(Fields::Failed),
        };
        release(&self.this.plugin, done.lease);
        answer
    }
}

impl Fielding for Pending<FieldsIn, FieldsOut, Asked> {
    fn settled(&mut self) -> Option<Fields> {
        self.now()
    }
}

#[cfg(test)]
#[path = "tests/auth_outbound_tests.rs"]
pub(crate) mod tests;
