// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SECRET KIND'S SHARED SOURCE PIECES (`abi::secret`): what every Rust secret source answered

use crate::abi::mechanism::call::Outcome;
use crate::abi::sdk::life::Refusal;
use crate::abi::sdk::out::Out;
use crate::abi::secret::{
    ResolveOut, ERROR_KIND_DENIED, ERROR_KIND_INTERNAL, ERROR_KIND_INVALID, ERROR_KIND_NOT_FOUND,
    ERROR_KIND_UNAVAILABLE,
};
use crate::secret::{SecretErrorKind, SecretModuleError};

/// The `abi::secret::ERROR_KIND_*` code of a [`SecretErrorKind`].
#[must_use]
pub const fn error_kind(kind: SecretErrorKind) -> u32 {
    match kind {
        SecretErrorKind::NotFound => ERROR_KIND_NOT_FOUND,
        SecretErrorKind::Unavailable => ERROR_KIND_UNAVAILABLE,
        SecretErrorKind::Denied => ERROR_KIND_DENIED,
        SecretErrorKind::Invalid => ERROR_KIND_INVALID,
        SecretErrorKind::Internal => ERROR_KIND_INTERNAL,
    }
}

/// A resolve's settings, read at configure time ([`super::settings`]).
pub use super::settings::{settings_of, takes_no_settings};

/// `resolve`'s failure answer: `e`'s code in `error_kind`, its text, FAILED.
pub fn failed(out: &mut Out<'_, ResolveOut>, e: SecretModuleError) -> Outcome {
    out.set(|o| &o.error_kind, error_kind(e.kind));
    out.fail(Refusal::failed(e.message))
}

