// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CALL CAPTURE — how a plugin logs (`BUSBAR-1.6.0.md` decision #85, and THE DESIGN, section 11.2).
//!
//! Whatever a plugin logs during a call, through `tracing` or through `log`, from its own code or
//! from a library inside it, becomes a [`DIAG_LOG`] diagnostic on that call's reply. The host
//! writes it to the plugin's own log file. A plugin never writes a log anywhere itself.
//!
//! The door macro's trampoline runs every slot body under [`with_default`] with this module's
//! [`Capture`] as the thread's scoped dispatcher, so the capture sees every `tracing` event the
//! body raises, whichever copy of `tracing-core` the plugin image holds. `log` records reach the
//! same capture through `tracing-log`'s `LogTracer`, which the door macro installs as the image's
//! `log` logger (the host installs the same one; see `busbar-kernel`'s logging setup), so a `log`
//! record is a `tracing` event by the time anything sees it. Compiled in or dropped in, the same
//! events reach the same capture and become the same entries.
//!
//! WHERE THE STATE LIVES. The capture's dispatcher is long-lived, because creating a `Dispatch`
//! rebuilds the interest of every callsite in the process, and the reply's entries must outlive
//! the trampoline's return until the host copies them. Both live in ONE [`CaptureSlot`] per thread
//! per plugin image, which the door macro expands in the PLUGIN's crate ([`CaptureHome`]); this
//! module holds only the types.
//!
//! BOUNDS. The capture keeps at most [`MAX_ENVELOPE_ENTRIES`] entries per reply, the plugin's own
//! diagnostics first, and each text at most [`MAX_TEXT`] bytes. Anything over is counted and
//! reported as one [`DIAG_LOG_DROPPED`] entry. The host applies its own bound on top.
//!
//! [`with_default`]: tracing_core::dispatcher::with_default

use std::fmt::Write as _;
use std::sync::Mutex;

use tracing_core::field::{Field, Visit};
use tracing_core::span::{Attributes, Id, Record as SpanRecord};
use tracing_core::subscriber::{Interest, Subscriber};
use tracing_core::{Dispatch, Event, Level, LevelFilter, Metadata};
use tracing_log::NormalizeEvent as _;

use crate::abi::mechanism::call::{
    AbiStr, Diag, Envelope, DIAG_LOG, DIAG_LOG_DROPPED, MAX_ENVELOPE_ENTRIES, MAX_TEXT,
    SEVERITY_DEBUG, SEVERITY_ERROR, SEVERITY_INFO, SEVERITY_TRACE, SEVERITY_WARN,
};

/// `tracing-log`, re-exported for the door macro's expansion: it installs `LogTracer` as the
/// plugin image's `log` logger, so a plugin crate needs no dependency of its own to do it.
#[doc(hidden)]
pub use tracing_log as __tracing_log;

/// Where a plugin image keeps its [`CaptureSlot`]s: one per thread. Implemented only by the type
/// the door macro expands in the plugin's crate.
pub trait CaptureHome {
    /// Run `f` on this thread's slot.
    fn with<R>(f: impl FnOnce(&mut CaptureSlot) -> R) -> R;
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
        // Asked per event: the capture is the default only inside a call.
        Interest::sometimes()
    }

    fn max_level_hint(&self) -> Option<LevelFilter> {
        // Every level: the host filters, per plugin, by its own configured level.
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
        // Rendered outside the lock: a field's `Debug` may itself log.
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

/// ONE THREAD'S CAPTURE in one plugin image: the long-lived dispatcher, and the memory of the last
/// reply it sealed, valid until the next reply sealed on this thread (the host copies a reply's
/// entries before it makes any other call on the thread).
pub struct CaptureSlot {
    dispatch: Dispatch,
    diags: Vec<Diag>,
    texts: Vec<String>,
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
            diags: Vec::new(),
            texts: Vec::new(),
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
    pub unsafe fn seal(&mut self, envelope: &mut Envelope) {
        let Some(held) = self.capture().map(Capture::take) else {
            return;
        };
        if held.records.is_empty() && held.dropped == 0 {
            return;
        }
        let own: &[Diag] = match (envelope.diags.is_null(), envelope.diags_len) {
            (_, 0) => &[],
            // Malformed: the host refuses the array whole, and the records go with it.
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

        // The previous reply on this thread was copied by the host before this call began.
        self.diags.clear();
        self.texts.clear();
        self.diags.extend_from_slice(own);
        let mut severities = Vec::with_capacity(kept + 1);
        for r in held.records.into_iter().take(kept) {
            severities.push((DIAG_LOG, r.severity));
            self.texts.push(r.text);
        }
        if dropped > 0 && room > 0 {
            severities.push((DIAG_LOG_DROPPED, SEVERITY_WARN));
            self.texts.push(dropped.to_string());
        }
        // Each `String`'s bytes stay put while the vector of them grows; only the handles move.
        for ((id_idx, severity), text) in severities.into_iter().zip(&self.texts) {
            self.diags.push(Diag {
                id_idx,
                severity,
                _reserved: [0; 3],
                text: AbiStr {
                    ptr: text.as_ptr(),
                    len: text.len(),
                },
            });
        }
        envelope.diags = self.diags.as_ptr();
        envelope.diags_len = self.diags.len();
    }
}
