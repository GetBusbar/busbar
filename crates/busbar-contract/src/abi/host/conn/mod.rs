// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CONNECTION TABLE, lowered: [`crate::conn::Conns`] as a `#[repr(C)]` table of host slots.

use std::os::raw::c_void;

use crate::abi::shared::{DeclStr, WireField};
use crate::conn::ConnError;

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
