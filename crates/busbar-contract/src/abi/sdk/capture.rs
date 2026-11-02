// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CALL CAPTURE — how a plugin logs (`BUSBAR-1.6.0.md` decision #85, and THE DESIGN, section 11.2).

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};

use tracing_core::field::{Field, Visit};
use tracing_core::span::{Attributes, Id, Record as SpanRecord};
use tracing_core::subscriber::{Interest, Subscriber};
use tracing_core::{Dispatch, Event, Level, LevelFilter, Metadata};
use tracing_log::NormalizeEvent as _;

use crate::abi::mechanism::call::{
    AbiStr, Diag, Envelope, DIAG_LOG, DIAG_LOG_DROPPED, MAX_ENVELOPE_ENTRIES, MAX_TEXT,
    SEVERITY_DEBUG, SEVERITY_ERROR, SEVERITY_INFO, SEVERITY_TRACE, SEVERITY_WARN,
};
use crate::abi::mechanism::ticket::{HostCtx, Ticket};
use crate::abi::sdk::out::{Replies, ReplyKey};

/// `tracing-log`, re-exported for the door macro's expansion: it installs `LogTracer` as the
/// plugin image's `log` logger, so a plugin crate needs no dependency of its own to do it.
#[doc(hidden)]
pub use tracing_log as __tracing_log;

/// Where a plugin image keeps its [`CaptureSlot`]s: one per thread. Implemented only by the type
pub trait CaptureHome {
    /// Run `f` on this thread's slot.
    fn with<R>(f: impl FnOnce(&mut CaptureSlot) -> R) -> R;
    /// This plugin image's immutable returned capture storage, shared by crossing threads.
    fn retention() -> &'static CaptureRetention;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Owner {
    Host(u64),
    Instance(usize),
    Unbound(std::thread::ThreadId),
}

impl Owner {
    fn of(host: HostCtx, instance: *mut std::ffi::c_void) -> Self {
        if !host.is_none() {
            Self::Host(host.handle)
        } else if !instance.is_null() {
            Self::Instance(instance as usize)
        } else {
            Self::Unbound(std::thread::current().id())
        }
    }
}

#[derive(Default)]
pub(crate) struct CapturedReply {
    diags: Vec<Diag>,
    texts: Vec<Box<[u8]>>,
}

// SAFETY: every nonempty text pointer names one of this reply's immutable boxed buffers.
// Invalid declarations are made NULL and are never dereferenced.
unsafe impl Send for CapturedReply {}

impl CapturedReply {
    fn clear(&mut self) {
        self.diags.clear();
        self.texts.clear();
    }

    fn text(&mut self, text: &[u8]) -> AbiStr {
        let owned: Box<[u8]> = text.into();
        let named = AbiStr {
            ptr: owned.as_ptr(),
            len: owned.len(),
        };
        self.texts.push(owned);
        named
    }
}

/// Returned logs belong to the host context and full ticket. The tracing dispatcher remains
/// thread-local, while immutable replies survive another crossing or a ticket changing threads.
#[derive(Default)]
pub struct CaptureRetention {
    owners: Mutex<HashMap<Owner, Arc<Replies<CapturedReply>>>>,
}

pub(crate) struct CaptureReply {
    owner: Owner,
    key: ReplyKey,
    pub(crate) reply: CapturedReply,
}

impl CaptureRetention {
    fn owner(&self, owner: Owner) -> Arc<Replies<CapturedReply>> {
        Arc::clone(
            self.owners
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .entry(owner)
                .or_default(),
        )
    }

    pub(crate) fn begin(
        &self,
        host: HostCtx,
        instance: *mut std::ffi::c_void,
        ticket: Ticket,
    ) -> CaptureReply {
        let owner = Owner::of(host, instance);
        let key = ReplyKey::of(ticket);
        let mut reply = self.owner(owner).take(key).unwrap_or_default();

        reply.clear();
        CaptureReply { owner, key, reply }
    }

    pub(crate) fn keep(
        &self,
        mut reply: CaptureReply,
        closed: bool,
        opened: Option<*mut std::ffi::c_void>,
    ) {
        if closed {
            let retired = self
                .owners
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&reply.owner);
            drop(retired);

            reply.owner = Owner::Unbound(std::thread::current().id());
            reply.key = ReplyKey::of(Ticket::NONE);
        } else if let (Owner::Unbound(_), Some(instance)) = (reply.owner, opened) {
            if !instance.is_null() {
                reply.owner = Owner::Instance(instance as usize);
            }
        }
        self.owner(reply.owner).insert(reply.key, reply.reply);
    }
}

/// One log record the capture kept.
struct Captured {
    severity: u8,
    text: String,
}

/// What the capture holds between the start of a slot body and its reply.
#[derive(Default)]
struct Held {
    records: Vec<Captured>,
    dropped: u64,
}

/// THE CAPTURE: a `tracing` subscriber that keeps every event as a log record. It is the thread's
/// default only while a slot body runs, so it never sees an event raised outside a call.
#[derive(Default)]
pub struct Capture {
    held: Mutex<Held>,
}

impl Capture {
    fn lock(&self) -> std::sync::MutexGuard<'_, Held> {
        self.held.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn take(&self) -> Held {
        std::mem::take(&mut *self.lock())
    }
}

/// The severity a level carries on the wire.
fn severity(level: &Level) -> u8 {
    match *level {
        Level::ERROR => SEVERITY_ERROR,
        Level::WARN => SEVERITY_WARN,
        Level::INFO => SEVERITY_INFO,
        Level::DEBUG => SEVERITY_DEBUG,
        _ => SEVERITY_TRACE,
    }
}

/// An event's fields as text: the message, then every other field as ` key=value`. The fields
/// `tracing-log` adds to a `log` record (`log.target`, `log.file`, ...) are not rendered; the
/// target they carry is the record's own target.
#[derive(Default)]
struct Render {
    message: String,
    fields: String,
}

impl Visit for Render {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        match field.name() {
            "message" => {
                let _ = write!(self.message, "{value:?}");
            }
            name if name.starts_with("log.") => {}
            name => {
                let _ = write!(self.fields, " {name}={value:?}");
            }
        }
    }
}

/// `text` cut to at most [`MAX_TEXT`] bytes, on a character boundary.
fn bounded(mut text: String) -> String {
    if text.len() > MAX_TEXT {
        let mut end = MAX_TEXT;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
    text
}

impl Subscriber for Capture {
    fn register_callsite(&self, _: &'static Metadata<'static>) -> Interest {
        Interest::sometimes()
    }

    fn max_level_hint(&self) -> Option<LevelFilter> {
        Some(LevelFilter::TRACE)
    }

    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _: &Id, _: &SpanRecord<'_>) {}

    fn record_follows_from(&self, _: &Id, _: &Id) {}

    fn event(&self, event: &Event<'_>) {
        {
            let mut held = self.lock();
            if held.records.len() >= MAX_ENVELOPE_ENTRIES {
                held.dropped += 1;
                return;
            }
        }

        let normalized = event.normalized_metadata();
        let meta = normalized.as_ref().unwrap_or_else(|| event.metadata());
        let mut render = Render::default();
        event.record(&mut render);
        let text = bounded(format!(
            "{}: {}{}",
            meta.target(),
            render.message,
            render.fields
        ));
        let mut held = self.lock();
        if held.records.len() >= MAX_ENVELOPE_ENTRIES {
            held.dropped += 1;
        } else {
            held.records.push(Captured {
                severity: severity(meta.level()),
                text,
            });
        }
    }

    fn enter(&self, _: &Id) {}

    fn exit(&self, _: &Id) {}
}

/// One thread's long-lived tracing dispatcher in one plugin image. Returned diagnostics are
pub struct CaptureSlot {
    dispatch: Dispatch,
}

impl Default for CaptureSlot {
    fn default() -> Self {
        Self::new()
    }
}

impl CaptureSlot {
    /// A slot with its own capture.
    #[must_use]
    pub fn new() -> Self {
        Self {
            dispatch: Dispatch::new(Capture::default()),
        }
    }

    /// The capture's dispatcher, for the trampoline to scope a slot body under.
    #[must_use]
    pub fn dispatch(&self) -> Dispatch {
        self.dispatch.clone()
    }

    fn capture(&self) -> Option<&Capture> {
        self.dispatch.downcast_ref::<Capture>()
    }

    /// Forget what the capture holds: the body faulted, and a FAULT reply carries no envelope.
    pub fn discard(&mut self) {
        if let Some(c) = self.capture() {
            drop(c.take());
        }
    }

    /// Fold what the capture holds into the reply's `envelope`: the plugin's own diagnostics first,
    /// then the log records, then one [`DIAG_LOG_DROPPED`] entry if any record did not fit. A reply
    /// with nothing captured is left exactly as the plugin wrote it.
    ///
    /// # Safety
    /// `envelope.diags`, when non-NULL, points to `envelope.diags_len` live [`Diag`]s.
    pub(crate) unsafe fn seal(&mut self, envelope: &mut Envelope, reply: &mut CapturedReply) {
        let Some(held) = self.capture().map(Capture::take) else {
            return;
        };
        if held.records.is_empty() && held.dropped == 0 {
            return;
        }
        let own: &[Diag] = match (envelope.diags.is_null(), envelope.diags_len) {
            (_, 0) => &[],

            (true, _) => return,
            (false, n) if n > MAX_ENVELOPE_ENTRIES => return,
            // SAFETY: the caller's contract.
            (false, n) => unsafe { std::slice::from_raw_parts(envelope.diags, n) },
        };
        let room = MAX_ENVELOPE_ENTRIES - own.len();
        let wanted = held.records.len();
        let fits_all = wanted + usize::from(held.dropped > 0) <= room;
        let kept = if fits_all {
            wanted
        } else {
            room.saturating_sub(1)
        };
        let dropped = held.dropped + (wanted - kept) as u64;

        for diag in own {
            let mut diag = *diag;
            if diag.text.len > MAX_TEXT || (diag.text.len != 0 && diag.text.ptr.is_null()) {
                diag.text.ptr = std::ptr::null();
            } else if diag.text.len != 0 {
                // SAFETY: the caller's diagnostic bytes are live for this crossing, with a
                // bounded non-NULL range. Copy before their source can be retired.
                diag.text =
                    reply.text(unsafe { std::slice::from_raw_parts(diag.text.ptr, diag.text.len) });
            } else {
                diag.text = AbiStr::ZERO;
            }
            reply.diags.push(diag);
        }
        for r in held.records.into_iter().take(kept) {
            let text = reply.text(r.text.as_bytes());
            reply.diags.push(Diag {
                id_idx: DIAG_LOG,
                severity: r.severity,
                text,
                ..Diag::ZERO
            });
        }
        if dropped > 0 && room > 0 {
            let text = reply.text(dropped.to_string().as_bytes());
            reply.diags.push(Diag {
                id_idx: DIAG_LOG_DROPPED,
                severity: SEVERITY_WARN,
                text,
                ..Diag::ZERO
            });
        }
        envelope.diags = reply.diags.as_ptr();
        envelope.diags_len = reply.diags.len();
    }
}

#[cfg(test)]
#[path = "tests/capture_retention_tests.rs"]
mod tests;
