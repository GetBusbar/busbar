// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CONNECTION TABLE, lowered: [`crate::conn::Conns`] as a `#[repr(C)]` table of host slots.

use std::collections::{HashMap, HashSet};
use std::os::raw::c_void;
use std::sync::{Arc, Mutex};

use crate::abi::shared::{DeclStr, WireField};
use crate::conn::{ConnError, ConnId, Conns, InstanceId};

pub mod connector;

/// The outcome byte every connection slot answers ([`ConnOutcome`]); an unknown byte reads as
/// [`ConnOutcome::Fault`].
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawConnOutcome(pub u8);

/// What a connection slot answered.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnOutcome {
    /// Answered.
    Ok = 0,
    /// [`ConnError::Pending`].
    Pending = 1,
    /// [`ConnError::Timeout`].
    Timeout = 2,
    /// [`ConnError::Closed`].
    Closed = 3,
    /// [`ConnError::NotOwner`].
    NotOwner = 4,
    /// [`ConnError::UndeclaredNeed`].
    UndeclaredNeed = 5,
    /// [`ConnError::Refused`].
    Refused = 6,
    /// [`ConnError::Fault`].
    Fault = 7,
    /// [`ConnError::Unarmed`].
    Unarmed = 8,
    /// [`ConnError::CredentialUnavailable`].
    CredentialUnavailable = 9,
    /// [`ConnError::AuthRefused`].
    AuthRefused = 10,
    /// [`ConnError::AuthFailed`].
    AuthFailed = 11,
}

impl RawConnOutcome {
    /// The outcome of a result.
    #[must_use]
    pub const fn of(r: Result<(), ConnError>) -> Self {
        Self(match r {
            Ok(()) => ConnOutcome::Ok,
            Err(ConnError::Pending) => ConnOutcome::Pending,
            Err(ConnError::Timeout) => ConnOutcome::Timeout,
            Err(ConnError::Closed) => ConnOutcome::Closed,
            Err(ConnError::NotOwner) => ConnOutcome::NotOwner,
            Err(ConnError::UndeclaredNeed) => ConnOutcome::UndeclaredNeed,
            Err(ConnError::Refused) => ConnOutcome::Refused,
            Err(ConnError::Fault) => ConnOutcome::Fault,
            Err(ConnError::Unarmed) => ConnOutcome::Unarmed,
            Err(ConnError::CredentialUnavailable) => ConnOutcome::CredentialUnavailable,
            Err(ConnError::AuthRefused) => ConnOutcome::AuthRefused,
            Err(ConnError::AuthFailed) => ConnOutcome::AuthFailed,
        } as u8)
    }

    /// The result the byte states.
    pub const fn result(self) -> Result<(), ConnError> {
        match self.0 {
            0 => Ok(()),
            1 => Err(ConnError::Pending),
            2 => Err(ConnError::Timeout),
            3 => Err(ConnError::Closed),
            4 => Err(ConnError::NotOwner),
            5 => Err(ConnError::UndeclaredNeed),
            6 => Err(ConnError::Refused),
            8 => Err(ConnError::Unarmed),
            9 => Err(ConnError::CredentialUnavailable),
            10 => Err(ConnError::AuthRefused),
            11 => Err(ConnError::AuthFailed),
            _ => Err(ConnError::Fault),
        }
    }
}

/// The host's context for ONE plugin instance: opaque to the plugin, handed back on every call.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ConnCtx {
    /// The host's per-instance state; never dereferenced by a plugin.
    pub ptr: *mut c_void,
}

/// [`OpenDesc`], borrowed for the call.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WireOpenDesc {
    /// `size_of::<WireOpenDesc>()` at construction.
    pub size: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// The target (UTF-8).
    pub target: DeclStr,
    /// The head fields.
    pub fields: *const WireField,
    /// How many.
    pub fields_len: usize,
    /// The body.
    pub body: *const u8,
    /// Its length.
    pub body_len: usize,
    /// Milliseconds the open may take; `0` = the host's default.
    pub timeout_ms: u64,
    /// [`OpenDesc::method`], appended: a descriptor whose `size` ends before it states none.
    pub method: DeclStr,
    /// [`OpenDesc::head_target`], appended: a descriptor whose `size` ends before it states none.
    pub head_target: DeclStr,
}

/// A [`WireOpenDesc`] as a descriptor without the appended head words states it: read from a
/// plugin whose `size` ends at [`OPEN_DESC_HEADLESS`], never past it.
#[repr(C)]
#[derive(Clone, Copy)]
struct Headless {
    size: u32,
    _reserved: u32,
    target: DeclStr,
    fields: *const WireField,
    fields_len: usize,
    body: *const u8,
    body_len: usize,
    timeout_ms: u64,
}

impl Headless {}

const _: () = assert!(core::mem::size_of::<Headless>() == OPEN_DESC_HEADLESS);

/// How much of a [`WireOpenDesc`] a sized descriptor must state: everything before the appended `method` and `head_target` words.
pub const OPEN_DESC_HEADLESS: usize = core::mem::offset_of!(WireOpenDesc, method);

/// [`WirePiece::flags`]: the status number is present.
pub const PIECE_HAS_CODE: u8 = 1;
/// [`WirePiece::flags`]: the retry-after is present.
pub const PIECE_HAS_RETRY_AFTER: u8 = 2;
/// [`WirePiece::flags`]: the declared body length is present.
pub const PIECE_HAS_DECLARED_LEN: u8 = 4;

/// The heap-stable state behind a `ConnHost`: what its [`ConnCtx`] points at.
struct HostState {
    conns: Arc<dyn Conns>,
    instance: InstanceId,
    held: Mutex<HashMap<ConnId, Held>>,
}

/// What the host holds for a connection so the plugin's borrows stay valid until it closes: every
/// string a slot exposed to the plugin as a [`DeclStr`] range (a piece's status numbering, and the
/// six strings of the facts), interned once and never mutated, shrunk, replaced or moved out until
/// the connection's successful close drops the whole set.
///
/// A later `read` or `facts` answer states its own strings; it never takes the storage an earlier
/// range names. Equal strings share one allocation, so a connection that keeps answering the same
/// numbering or facts holds each once, and a different one adds to the set. Growing the set
/// rehashes the `String` headers, not the heap bytes they own, so a range stays where it was
/// handed out. What the plugin is never shown (the key pin, the client-identity bit) is not kept.
///
/// `epoch` names THIS retention's life. An operation that answers from the backend (`read`,
/// `facts`) takes a clone before it asks, and may publish its strings, and its out-slot, only
/// while the same epoch is still the one in the table ([`Operation::publish`]); a successful close
/// removes the entry (and so the epoch), so a late publication finds it gone and answers
/// [`ConnError::Closed`] instead of recreating a retention nobody will close. The allocation is
/// unique while any operation holds it, so a later entry for the same id can never be mistaken
/// for it.
#[derive(Default)]
struct Held {
    retention: HashSet<String>,
    epoch: Arc<()>,
}

impl Held {
    /// `s` as an exposed range that stays valid until this connection's close: the interned copy is kept.
    fn keep(&mut self, s: &str) -> DeclStr {
        if let Some(kept) = self.retention.get(s) {
            return range(kept);
        }
        self.retention.insert(s.to_owned());
        self.retention
            .get(s)
            .map_or(DeclStr::NONE, |kept| range(kept))
    }
}

impl HostState {
    fn held(&self) -> std::sync::MutexGuard<'_, HashMap<ConnId, Held>> {
        self.held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Begin a `read`/`facts` operation on `conn`: capture the epoch of its retention (an empty
    /// retention when the connection has none yet).
    fn begin(&self, conn: ConnId) -> Operation<'_> {
        let epoch = Arc::clone(&self.held().entry(conn).or_default().epoch);
        Operation {
            host: self,
            conn,
            epoch: Some(epoch),
        }
    }
}

/// One in-flight `read`/`facts` operation on a connection: the retention epoch it captured before
struct Operation<'h> {
    host: &'h HostState,
    conn: ConnId,
    epoch: Option<Arc<()>>,
}

impl Operation<'_> {
    /// Run `publish` over the connection's retention and, under the SAME table guard, let it write
    fn publish(
        &self,
        publish: impl FnOnce(&mut Held) -> Result<(), ConnError>,
    ) -> Result<(), ConnError> {
        let ours = self.epoch.as_ref().ok_or(ConnError::Fault)?;
        let mut held = self.host.held();
        match held.get_mut(&self.conn) {
            Some(entry) if Arc::ptr_eq(&entry.epoch, ours) => publish(entry),
            _ => Err(ConnError::Closed),
        }
    }
}

impl Drop for Operation<'_> {
    fn drop(&mut self) {
        let Some(epoch) = self.epoch.take() else {
            return;
        };
        let retired = {
            let mut held = self.host.held();

            let ours_and_empty = held.get(&self.conn).is_some_and(|entry| {
                Arc::ptr_eq(&entry.epoch, &epoch)
                    && entry.retention.is_empty()
                    && Arc::strong_count(&epoch) == 2
            });
            let retired = if ours_and_empty {
                held.remove(&self.conn)
            } else {
                None
            };

            drop(epoch);
            retired
        };

        drop(retired);
    }
}

/// Run a host slot body over the instance's state, answering the fault byte for a panic or a null
fn hosted(ctx: ConnCtx, body: impl FnOnce(&HostState) -> Result<(), ConnError>) -> RawConnOutcome {
    RawConnOutcome::of(
        crate::abi::sdk::boundary::caught(|| {
            // SAFETY: a non-null context is the `HostState` of the `ConnHost` the host minted it from
            // (`ConnHost::ctx`),
            // alive for the call.
            let host = unsafe { ctx.ptr.cast::<HostState>().as_ref() }.ok_or(ConnError::Fault)?;
            body(host)
        })
        .unwrap_or(Err(ConnError::Fault)),
    )
}

/// A borrowed byte range (NULL only when empty).
///
/// # Safety
/// `ptr`, when non-null, must address `len` readable bytes for the call.
unsafe fn bytes<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8], ConnError> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(ConnError::Fault);
    }
    // SAFETY: per this fn's contract.
    Ok(unsafe { std::slice::from_raw_parts(ptr, len) })
}

/// A borrowed [`DeclStr`] as text (`None` for NULL).
///
/// # Safety
/// A non-null range must address `len` readable bytes for the call.
unsafe fn text<'a>(d: DeclStr) -> Result<Option<&'a str>, ConnError> {
    if d.ptr.is_null() {
        return Ok(None);
    }
    // SAFETY: per this fn's contract.
    std::str::from_utf8(unsafe { bytes(d.ptr, d.len) }?)
        .map(Some)
        .map_err(|_| ConnError::Fault)
}

/// Write one out-param.
///
/// # Safety
/// `out`, when non-null, must address a writable `T`.
unsafe fn set<T>(out: *mut T, v: T) -> Result<(), ConnError> {
    if out.is_null() {
        return Err(ConnError::Fault);
    }
    // SAFETY: per this fn's contract.
    unsafe { out.write(v) };
    Ok(())
}

/// A range the host holds, borrowed.
fn range(s: &str) -> DeclStr {
    DeclStr {
        ptr: s.as_ptr(),
        len: s.len(),
    }
}
