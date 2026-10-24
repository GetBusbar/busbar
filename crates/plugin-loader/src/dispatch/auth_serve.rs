// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST AUTH HANDLE'S OUTBOUND SERVER SEAM (THE DESIGN §6, "Auth points and guest lists",
//! items 5 and 7; §11.6): a transport's `auth.call` on an OUTBOUND BINDING'S ref, answered with the
//! auth fields that join the head.
//!
//! The slot (`services::auth_call`) verifies the ref for the calling instance first (owner,
//! generation, mac), then the `in`'s contract check; past those it asks the server the composition
//! root armed here ([`arm`]) whether the ref names one of its outbound bindings. The server owns the
//! rest: the unit the call names (verified against the request's own secret), the binding's handle
//! for the unit's attempt, the plane's scope, a passthrough member's lent credential and the
//! plane's waiver are all resolved host-side from the unit, and the binding's auth is called with
//! the head the transport is about to encode. The VERDICT and the SECRETS never pass through the
//! transport: it is handed only the auth's lines, which it adds (replacing any of the same name)
//! and encodes, and adds nothing after. The loader names no kernel crate.
//!
//! THE ANSWER is held in the service store like every ticketed result, encoded by [`stored`]: the
//! fields' bytes, one span per field, and a trailer holding the answered unit and each field's
//! flags. [`deliver`] writes it into the caller's `buf`, `spans` and `answer`, or answers the short
//! FAILED with the field bytes' and the fields' full sizes.

use std::sync::Arc;

use busbar_contract::abi::auth::FieldSpan;
use busbar_contract::abi::host::service::{
    AuthAnswer, AuthCallIn, ItemSpan, UnitRef, FLOW_CONTINUE,
};
use busbar_contract::abi::mechanism::call::{Outcome, Span};
use busbar_contract::services::Stored;

/// The request the transport is about to encode, as the outbound auth reads it: copied out of the
/// caller's `in` before any pend.
#[derive(Clone)]
pub struct AuthAsk {
    /// The calling transport's instance identity (the owner its ref verified for).
    pub owner: u64,
    /// The binding the verified ref names.
    pub binding: u64,
    /// The unit the transport presents.
    pub unit: UnitRef,
    /// The `POINT_*` bit the call is made at.
    pub point: u32,
    /// The connection and the stream on it.
    pub conn: u64,
    /// The stream.
    pub stream: u64,
    /// The method.
    pub method: Vec<u8>,
    /// The target's path, as it goes out.
    pub target: Vec<u8>,
    /// The authority (`host[:port]`).
    pub authority: Vec<u8>,
    /// The query without `?`; `None` = none.
    pub query: Option<Vec<u8>>,
    /// The head's lines as the transport finalised them, in order.
    pub fields: Vec<(Vec<u8>, Vec<u8>)>,
    /// The whole body, at the body point only.
    pub body: Option<Vec<u8>>,
}

impl std::fmt::Debug for AuthAsk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthAsk")
            .field("owner", &self.owner)
            .field("binding", &self.binding)
            .field("point", &self.point)
            .field("fields", &self.fields.len())
            .finish_non_exhaustive()
    }
}

/// Credential bytes, wiped when they drop (as `auth_outbound`'s field buffer is).
#[derive(Clone, Default)]
pub struct Wiped(pub Vec<u8>);

impl Drop for Wiped {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

impl std::ops::Deref for Wiped {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

/// One auth line the transport adds: its name, its value (credential material) and its flags
/// (`FIELD_SENSITIVE` | `FIELD_QUERY`).
#[derive(Clone)]
pub struct ServedField {
    /// The name.
    pub name: Vec<u8>,
    /// The value; zeroised on drop.
    pub value: Wiped,
    /// The flags.
    pub flags: u32,
}

impl std::fmt::Debug for ServedField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServedField")
            .field("name", &String::from_utf8_lossy(&self.name))
            .field("flags", &self.flags)
            .finish_non_exhaustive()
    }
}

/// What the server answers a call.
#[derive(Debug, Clone)]
pub enum AuthServed {
    /// READY: the auth's lines for the transport to add (none for a waived binding), and the unit
    /// the answer names (the presented one).
    Fields {
        /// The unit.
        unit: UnitRef,
        /// The lines.
        fields: Vec<ServedField>,
    },
    /// REFUSED: the auth refused the request, or the unit is not one the host handed this caller.
    Refused(&'static str),
    /// FAILED: the auth could not answer (its credential is unavailable, its wait ran out).
    Failed(&'static str),
}

/// Where an answer that pends is handed when it is ready.
pub type Answer = Box<dyn FnOnce(AuthServed) + Send>;

/// A PLUGIN'S OWN REQUEST to a registration member (the connection services' framed stream): what
/// the member's binding is to be called with when the framer calls it, recorded host-side before
/// the open, never handed to the transport.
pub struct OwnRequest {
    /// The registration the request names (`EstablishIn::member`).
    pub member: String,
    /// The binding's handle for this request (a refreshed binding's current one); `0` when waived.
    pub handle: u64,
    /// The plugin's stated scope, as the call's extensions blob (empty = none).
    pub extensions: Vec<u8>,
    /// A passthrough member's lent credential (the unit's caller's, or empty); `None` = not
    /// passthrough.
    pub caller_credential: Option<busbar_contract::redacted::Secret<Vec<u8>>>,
    /// The plugin waived the member's binding for this request: the framer is served no line.
    pub waived: bool,
}

impl std::fmt::Debug for OwnRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnRequest")
            .field("member", &self.member)
            .field("waived", &self.waived)
            .finish_non_exhaustive()
    }
}

/// THE COMPOSITION ROOT'S OUTBOUND SERVER: its bindings, their auths and the units' records.
pub trait OutboundServer: Send + Sync {
    /// Whether binding `binding` (a ref verified for `owner`) is one of this server's outbound
    /// bindings; `false` leaves the call to the handle's inbound side.
    fn serves(&self, owner: u64, binding: u64) -> bool;

    /// Serve `ask`: `Some` = answered now; `None` = the answer goes to `later` when it is ready
    /// (the caller's op pends meanwhile). A call with no `later` (no ticket) must answer now.
    fn serve(&self, ask: AuthAsk, later: Option<Answer>) -> Option<AuthServed>;

    /// Record a plugin's own request to a member under a fresh request unit, the one its open names
    /// (`OpenDesc::unit`) so the framer's call is served from it; `None` = nothing recorded (the
    /// open then names no unit, and a framer begun with the member's binding is refused its call).
    fn record_request(&self, request: OwnRequest) -> Option<u64> {
        let _ = request;
        None
    }

    /// Forget the request unit `unit` [`Self::record_request`] answered: its stream closed.
    fn forget_request(&self, unit: u64) {
        let _ = unit;
    }
}

/// The outbound server the connection table's caller `owner` (an instance identity) is served by:
/// its dispatcher's; `None` = none armed, or no such instance.
pub(crate) fn server_for(
    owner: busbar_contract::conn::InstanceId,
) -> Option<Arc<dyn OutboundServer>> {
    super::handle::supplier_of(owner)?
        .route
        .get()?
        .upgrade()?
        .outbound()
}

/// The outbound server the instance `ctx` names is served by: its dispatcher's, armed there by the
/// composition root ([`super::Dispatcher::arm_outbound`]); `None` = none armed.
pub(crate) fn server_of(
    ctx: busbar_contract::abi::mechanism::ticket::HostCtx,
) -> Option<Arc<dyn OutboundServer>> {
    super::handle::resolve(ctx)?
        .route
        .get()?
        .upgrade()?
        .outbound()
}

/// The error text of an outbound call the server answered no fields for.
pub const OUTBOUND_REFUSED: &str = "the binding's auth refused the request";

fn span(offset: usize, len: usize) -> Span {
    Span {
        offset: u32::try_from(offset).unwrap_or(u32::MAX),
        len: u32::try_from(len).unwrap_or(u32::MAX),
    }
}

/// `served` as the service store holds it: READY with the fields' bytes then a trailer (the unit's
/// id and mac, then each field's flags, little-endian), `value` the fields' bytes' length, one span
/// per field; REFUSED or FAILED with their words.
#[must_use]
pub fn stored(served: &AuthServed) -> Stored {
    match served {
        AuthServed::Refused(why) => Stored::refused(why),
        AuthServed::Failed(why) => Stored {
            outcome: Outcome::Failed,
            ..Stored::refused(why)
        },
        AuthServed::Fields { unit, fields } => {
            let mut bytes = Vec::new();
            let mut spans = Vec::with_capacity(fields.len());
            for f in fields {
                let name = span(bytes.len(), f.name.len());
                bytes.extend_from_slice(&f.name);
                let value = span(bytes.len(), f.value.len());
                bytes.extend_from_slice(&f.value);
                spans.push(ItemSpan { key: name, value });
            }
            let value = bytes.len() as u64;
            bytes.extend_from_slice(&unit.id.to_le_bytes());
            bytes.extend_from_slice(&unit.mac.to_le_bytes());
            for f in fields {
                bytes.extend_from_slice(&f.flags.to_le_bytes());
            }
            Stored {
                outcome: Outcome::Ready,
                value,
                bytes,
                spans,
                error: "",
            }
        }
    }
}

/// What [`deliver`] answers: the outcome, the bytes and spans written, a short answer's full sizes
/// and the words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Delivered {
    /// The outcome.
    pub outcome: Outcome,
    /// Bytes written.
    pub len: u64,
    /// Spans written.
    pub items: u64,
    /// A short answer's full byte size.
    pub needed_bytes: u64,
    /// A short answer's full span count.
    pub needed_items: u64,
    /// The words, for FAILED/REFUSED.
    pub error: &'static str,
}

impl Delivered {
    fn bare(outcome: Outcome, error: &'static str) -> Self {
        Self {
            outcome,
            len: 0,
            items: 0,
            needed_bytes: 0,
            needed_items: 0,
            error,
        }
    }
}

/// The caller's buffers an `auth.call` answer is written into (its `in`'s `buf`, `spans` and
/// `answer`).
#[derive(Debug, Clone, Copy)]
pub struct AuthInto {
    /// The bytes.
    pub buf: *mut u8,
    /// Their capacity.
    pub cap: usize,
    /// The spans.
    pub spans: *mut FieldSpan,
    /// Their capacity, in spans.
    pub spans_cap: usize,
    /// The answer slot.
    pub answer: *mut AuthAnswer,
}

impl AuthInto {
    /// `i`'s buffers.
    #[must_use]
    pub fn of(i: &AuthCallIn) -> Self {
        Self {
            buf: i.buf,
            cap: i.cap,
            spans: i.spans,
            spans_cap: i.spans_cap,
            answer: i.answer,
        }
    }
}

/// Write a [`stored`] answer into the caller's `in` buffers: the field bytes into `buf`, a
/// [`FieldSpan`] per field into `spans`, the [`AuthAnswer`] into `answer`. `Err` = the short FAILED
/// (nothing written) with the full sizes. A stored answer this module did not encode is FAULT.
///
/// # Safety
///
/// `i`'s `buf`, `spans` and `answer` are the caller's, live and writable for their capacities (its
/// contract check held them non-NULL for a capacity, and `answer` non-NULL).
pub unsafe fn deliver(
    stored: &Stored,
    i: &AuthInto,
    short: &'static str,
) -> Result<Delivered, Delivered> {
    if stored.outcome != Outcome::Ready {
        return Ok(Delivered::bare(stored.outcome, stored.error));
    }
    let at = usize::try_from(stored.value).unwrap_or(usize::MAX);
    let n = stored.spans.len();
    let Some((fields, trailer)) = stored.bytes.split_at_checked(at) else {
        return Ok(Delivered::bare(Outcome::Fault, ""));
    };
    if trailer.len() != 16 + 4 * n {
        return Ok(Delivered::bare(Outcome::Fault, ""));
    }
    if fields.len() > i.cap || n > i.spans_cap {
        return Err(Delivered {
            needed_bytes: fields.len() as u64,
            needed_items: n as u64,
            ..Delivered::bare(Outcome::Failed, short)
        });
    }
    let word = |k: usize| {
        let mut b = [0_u8; 8];
        b.copy_from_slice(&trailer[k..k + 8]);
        u64::from_le_bytes(b)
    };
    let unit = UnitRef {
        id: word(0),
        mac: word(8),
    };
    // SAFETY: the caller's buffers, their capacities checked above; `answer` non-NULL by the
    // contract check.
    unsafe {
        if !fields.is_empty() {
            std::ptr::copy_nonoverlapping(fields.as_ptr(), i.buf, fields.len());
        }
        for (k, s) in stored.spans.iter().enumerate() {
            let mut flags = [0_u8; 4];
            flags.copy_from_slice(&trailer[16 + 4 * k..20 + 4 * k]);
            i.spans.add(k).write_unaligned(FieldSpan {
                name: s.key,
                value: s.value,
                flags: u32::from_le_bytes(flags),
                _reserved: 0,
            });
        }
        i.answer.write_unaligned(AuthAnswer {
            size: std::mem::size_of::<AuthAnswer>() as u32,
            flow: FLOW_CONTINUE,
            unit,
        });
    }
    Ok(Delivered {
        len: fields.len() as u64,
        items: n as u64,
        ..Delivered::bare(Outcome::Ready, "")
    })
}

#[cfg(test)]
#[path = "tests/auth_serve_tests.rs"]
mod tests;

/// THE ROOT'S OUTBOUND SERVER, as the loader's tests stand it in: ONE double for the process's one
/// server slot, so every suite that arms it arms the same one.
#[cfg(test)]
pub(crate) mod double {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex, OnceLock};

    use super::{Answer, AuthAsk, AuthServed, OutboundServer, OwnRequest, ServedField, Wiped};
    use super::{UnitRef, OUTBOUND_REFUSED};

    /// An outbound binding the double holds (one `authorization` line), and one whose auth refuses.
    pub(crate) const OUTBOUND: u64 = 0x4000_0000_0000_0005;
    pub(crate) const REFUSING: u64 = 0x4000_0000_0000_0006;
    /// The unit the double answers.
    pub(crate) const OUT_UNIT: UnitRef = UnitRef { id: 77, mac: 0x77 };
    /// The tag of every request unit the double records.
    pub(crate) const OWN_UNIT: u64 = 0x6000_0000_0000_0000;

    /// What the double was handed.
    #[derive(Default)]
    pub(crate) struct Double {
        /// Every call it served.
        pub(crate) asks: Mutex<Vec<AuthAsk>>,
        /// Every plugin-own request it recorded, under its unit.
        pub(crate) recorded: Mutex<Vec<(u64, OwnRequest)>>,
        /// Every request unit forgotten.
        pub(crate) forgotten: Mutex<Vec<u64>>,
        next: AtomicU64,
    }

    impl OutboundServer for Double {
        fn serves(&self, _: u64, binding: u64) -> bool {
            binding == OUTBOUND || binding == REFUSING
        }

        fn serve(&self, ask: AuthAsk, _: Option<Answer>) -> Option<AuthServed> {
            let binding = ask.binding;
            self.asks.lock().unwrap().push(ask);
            Some(if binding == REFUSING {
                AuthServed::Refused(OUTBOUND_REFUSED)
            } else {
                AuthServed::Fields {
                    unit: OUT_UNIT,
                    fields: vec![ServedField {
                        name: b"authorization".to_vec(),
                        value: Wiped(b"Bearer sk-out".to_vec()),
                        flags: busbar_contract::abi::auth::FIELD_SENSITIVE,
                    }],
                }
            })
        }

        fn record_request(&self, request: OwnRequest) -> Option<u64> {
            let unit = OWN_UNIT | (self.next.fetch_add(1, Ordering::Relaxed) + 1);
            self.recorded.lock().unwrap().push((unit, request));
            Some(unit)
        }

        fn forget_request(&self, unit: u64) {
            self.forgotten.lock().unwrap().push(unit);
        }
    }

    /// The one double every loader suite serves its outbound calls from (each arms it on its own
    /// route or dispatcher).
    pub(crate) fn armed() -> &'static Arc<Double> {
        static ONE: OnceLock<Arc<Double>> = OnceLock::new();
        ONE.get_or_init(Arc::default)
    }
}
