// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SECRET KIND'S ABI: its version and its table (the design's locked plugin ABI: one
//! mechanism, every shape in `abi/`). M0 landed the skeleton (the shared lifecycle head only);
//! this is M3-SHAPES (`abi-v2-perkind.md` B.2): the kind's one own operation, `resolve`, and its
//! data shapes. NOTHING dispatches through this yet (M3-wire, after M1) — this crate defines the
//! shapes and their compile-time layout only.
//!
//! B.2, transcribed:
//! - `resolve(settings blob)` returns a [`BLOB_SECRET`](super::mechanism::call::BLOB_SECRET)
//!   lease, or [`Outcome::Failed`](super::mechanism::call::Outcome::Failed) plus
//!   [`ResolveOut::error_kind`], with no material in [`super::mechanism::call::OutHead::error`]'s
//!   text (the error text is operator-facing only; the reason code lives in `error_kind`).
//! - `tick` (the shared lifecycle slot) renews vault leases; it grows no new `in`/`out` for
//!   secret, so nothing is added here beyond the lifecycle's own [`TickIn`](super::mechanism::lifecycle::TickIn)/
//!   [`TickOut`](super::mechanism::lifecycle::TickOut).
//! - `{env: X}` and `{file: Y}` are Statement rewrites: the kernel resolves them into a plain
//!   settings [`Blob`](super::mechanism::call::Blob) before calling `resolve`, so they name no new
//!   wire shape here.
//!
//! ASSUMPTION (M3-SHAPES, noted for the SLOT-LOG; not an owner question — nothing in B.2 or the
//! spec states a secret Statement tail): secret declares no `kind_tail` fields yet. A plugin's
//! `Statement.kind_tail` stays NULL for this kind until a later slot states one; that is
//! append-only-safe (a NULL tail today can gain a [`super::mechanism::door::KindTailHead`]-led
//! struct later without moving anything already laid out here).
//!
//! ASSUMPTION (M3-SHAPES): B.2 does not state `resolve`'s request-path/off-path split or its
//! deadline class. `resolve` may block on a vault call, so it is OFF-PATH, `may_pend`,
//! [`DeadlineClass::Call`](super::mechanism::call::DeadlineClass::Call) (a per-call budget; vault
//! leases are long-lived and reused, not a stream/connection in their own right here — `tick`, not
//! `resolve`, is the renewal path).

use super::mechanism::call::{Blob, InHead, Op, OutHead};
use super::mechanism::lifecycle::{OpsHead, LIFECYCLE_SLOTS};

/// The secret kind's ABI version: v1.5.5 shipped `1` (`SECRET_ABI_VERSION`), so 1.6.0 ships `2`.
pub const ABI_VERSION: u32 = 2;

/// [`InHead::op`] values the secret kind adds after the shared lifecycle, in table order.
///
/// # Examples
/// Every kind op `k` is at slot index `LIFECYCLE_SLOTS + k`, contiguous from the lifecycle:
/// ```
/// use busbar_contract::abi::mechanism::lifecycle::LIFECYCLE_SLOTS;
/// use busbar_contract::abi::secret::{slot, SLOTS};
/// assert_eq!(slot::RESOLVE, LIFECYCLE_SLOTS + 0);
/// assert_eq!(SLOTS, LIFECYCLE_SLOTS + 1);
/// ```
pub mod slot {
    use super::LIFECYCLE_SLOTS;

    /// `resolve`.
    pub const RESOLVE: u32 = LIFECYCLE_SLOTS;
}

/// How many slots the secret kind's whole table holds (the lifecycle plus `resolve`).
pub const SLOTS: u32 = LIFECYCLE_SLOTS + 1;

/// The secret kind's ops table. Leads with the shared [`OpsHead`]; kind op `k` is at slot index
/// [`LIFECYCLE_SLOTS`]` + k` ([`slot`]).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Ops {
    /// The lifecycle.
    pub head: OpsHead,
    /// Resolve a settings blob to a secret lease. OFF-PATH, `may_pend`,
    /// [`DeadlineClass::Call`](super::mechanism::call::DeadlineClass::Call) (assumption, see the
    /// module doc). In [`ResolveIn`], out [`ResolveOut`].
    pub resolve: Option<Op>,
}

/// `resolve`'s `in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ResolveIn {
    /// The head.
    pub head: InHead,
    /// The settings naming what to resolve (a `{env: X}`/`{file: Y}` reference, or the plugin's
    /// own settings shape, already rewritten by the kernel per the Statement rewrite rule).
    pub settings: Blob,
}

// The five variants below are the OLD `SecretErrorKind` (`busbar-contract/src/secret.rs`),
// transcribed into the fixed ABI in its declared order, plus `UNSET` for a `Ready` answer.
/// [`ResolveOut::error_kind`]: unset (a `Ready` answer).
pub const ERROR_KIND_UNSET: u32 = 0;
/// [`ResolveOut::error_kind`]: the named secret does not exist — OLD `SecretErrorKind::NotFound`.
pub const ERROR_KIND_NOT_FOUND: u32 = 1;
/// [`ResolveOut::error_kind`]: the backend (vault, filesystem, environment) could not be reached —
/// OLD `SecretErrorKind::Unavailable`.
pub const ERROR_KIND_UNAVAILABLE: u32 = 2;
/// [`ResolveOut::error_kind`]: the caller is not entitled to it — OLD `SecretErrorKind::Denied`.
pub const ERROR_KIND_DENIED: u32 = 3;
/// [`ResolveOut::error_kind`]: the settings blob itself is malformed — OLD
/// `SecretErrorKind::Invalid`.
pub const ERROR_KIND_INVALID: u32 = 4;
/// [`ResolveOut::error_kind`]: an internal fault in the plugin, not classified above — OLD
/// `SecretErrorKind::Internal`.
pub const ERROR_KIND_INTERNAL: u32 = 5;

/// `resolve`'s `out`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ResolveOut {
    /// The head.
    pub head: OutHead,
    /// The resolved material, as a [`super::mechanism::call::BLOB_SECRET`] blob, held under
    /// `head.lease` until `release(lease)`; absent unless `head.outcome` is
    /// [`Ready`](super::mechanism::call::Outcome::Ready).
    pub secret: Blob,
    /// One of the `ERROR_KIND_*` constants for a [`Failed`](super::mechanism::call::Outcome::Failed)
    /// answer; [`ERROR_KIND_UNSET`] otherwise. Distinct from `head.error`'s free text, which never
    /// carries secret material.
    pub error_kind: u32,
    /// Alignment padding.
    pub _reserved: u32,
}

/// The secret kind's [`super::mechanism::lifecycle::CancelOut::disposition`] vocabulary.
///
/// ASSUMPTION (M3-SHAPES): B.2 states no cancel disposition vocabulary for secret. `resolve` is
/// the only cancellable (`may_pend`) op this kind has, so the one disposition it needs is that a
/// pending resolve was aborted before any lease was granted (nothing to release).
pub mod cancel {
    /// The pending `resolve` was aborted; no lease was granted.
    pub const ABORTED: u32 = 0;
}
