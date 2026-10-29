// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SECRET KIND'S ABI: its version and its table (the design's locked plugin ABI: one
//! mechanism, every shape in `abi/`). M0 landed the skeleton (the shared lifecycle head only);
//! this is M3-SHAPES (`abi-v2-perkind.md` B.2): the kind's one own operation, `resolve`, and its
//! data shapes. The one dispatcher calls this table (`busbar-plugin-loader`,
//! `dispatch::kinds::secret`); the layout golden pins its layout.
//!
//! B.2, transcribed:
//! - `resolve(settings blob)` writes the material into the HOST'S zeroed buffer
//!   ([`ResolveIn::secret_buf`], the credential chip, row 6: host-owned secret bytes: no lease, no copy left on the plugin's
//!   side), or answers [`Outcome::Failed`](super::mechanism::call::Outcome::Failed) plus
//!   [`ResolveOut::error_kind`], with no material in [`super::mechanism::call::OutHead::error`]'s
//!   text (the error text is operator-facing only; the reason code lives in `error_kind`). A value
//!   over the buffer is the short-buffer answer ([`ResolveOut::needed`]).
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

pub mod validate;
use super::mechanism::lifecycle::{OpsHead, LIFECYCLE_SLOTS};

/// The secret kind's ABI version: v1.5.5 shipped `1` (`SECRET_ABI_VERSION`), so 1.6.0 ships `2`.
pub const ABI_VERSION: u32 = 2;

/// The secret kind's layout fingerprint ([`crate::abi::mechanism::layout`]): the fold of
/// [`LAYOUT_SHAPES`], the size, alignment and field offsets of every `#[repr(C)]` struct crossing
/// the secret table. A door states it as built
/// ([`Door::layout`](crate::abi::mechanism::door::Door::layout)) and the loader refuses another;
/// `tests/layout_fingerprint.rs` holds it to its fold.
pub const LAYOUT_FINGERPRINT: u64 = 0x7195caed69bcfcbd;

/// The secret kind's shapes, in fold order ([`crate::layout_shape!`]): every `#[repr(C)]` struct
/// crossing its table, each with every field. A struct `abi/secret/` gains is listed here (gate
/// `abi-location`).
pub const LAYOUT_SHAPES: &[&[u64]] = &[
    crate::layout_shape!(Ops => head, resolve, check),
    crate::layout_shape!(ResolveIn => head, settings, secret_buf, secret_cap),
    crate::layout_shape!(ResolveOut => head, secret, error_kind, _reserved, needed),
    crate::layout_shape!(CheckIn => head, settings, err_buf, err_cap),
];

/// [`InHead::op`] values the secret kind adds after the shared lifecycle, in table order.
///
/// # Examples
/// Every kind op `k` is at slot index `LIFECYCLE_SLOTS + k`, contiguous from the lifecycle:
/// ```
/// use busbar_contract::abi::mechanism::lifecycle::LIFECYCLE_SLOTS;
/// use busbar_contract::abi::secret::{slot, SLOTS};
/// assert_eq!(slot::RESOLVE, LIFECYCLE_SLOTS + 0);
/// assert_eq!(slot::CHECK, LIFECYCLE_SLOTS + 1);
/// assert_eq!(SLOTS, LIFECYCLE_SLOTS + 2);
/// ```
pub mod slot {
    use super::LIFECYCLE_SLOTS;

    /// `resolve`.
    pub const RESOLVE: u32 = LIFECYCLE_SLOTS;
    /// `check`.
    pub const CHECK: u32 = LIFECYCLE_SLOTS + 1;
}

/// How many slots the secret kind's whole table holds (the lifecycle, `resolve` and `check`).
pub const SLOTS: u32 = LIFECYCLE_SLOTS + 2;

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
    /// Judge ONE reference's settings object at config time (`--validate`, boot, an apply), before
    /// anything resolves: PURE (no I/O, no resolve), called with NO instance (the `instance`
    /// argument is NULL), never pends, [`DeadlineClass::Call`](super::mechanism::call::DeadlineClass::Call).
    /// In [`CheckIn`], out [`OutHead`]. READY: the reference is well-formed. FAILED: why, in
    /// `CheckIn::err_buf`, under the lifecycle `validate` refusal rule
    /// ([`check_validate_refusal`](super::mechanism::lifecycle::check_validate_refusal)); the host
    /// renders each line as `<config path of the reference>: <line>`. REFUSED: the plugin does not
    /// serve `check` (the SDK's answer for a door that wires none): every reference passes.
    pub check: Option<Op>,
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
    /// THE HOST'S SECRET BUFFER, zeroed, lent for the call (the credential chip, row 6: host-owned secret bytes): a READY
    /// `resolve` writes the material here and nowhere the host must later release. The host wipes
    /// it when its consumer is done. NULL (with `secret_cap` `0`) = no buffer: every value is short.
    pub secret_buf: *mut u8,
    /// How many bytes `secret_buf` holds.
    pub secret_cap: usize,
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
    /// The resolved material, as a [`super::mechanism::call::BLOB_SECRET`] blob naming the bytes
    /// written at the start of [`ResolveIn::secret_buf`] (its `ptr` is that buffer, its `len` at
    /// most [`ResolveIn::secret_cap`]); absent unless `head.outcome` is
    /// [`Ready`](super::mechanism::call::Outcome::Ready). Never under a lease: `head.lease` is `0`.
    pub secret: Blob,
    /// One of the `ERROR_KIND_*` constants for a [`Failed`](super::mechanism::call::Outcome::Failed)
    /// answer; [`ERROR_KIND_UNSET`] otherwise. Distinct from `head.error`'s free text, which never
    /// carries secret material.
    pub error_kind: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// THE SHORT-BUFFER ANSWER (M-SB, on [`OutHead`]): on a FAILED answer whose value does not fit
    /// [`ResolveIn::secret_cap`], the value's full length (`error_kind` stays
    /// [`ERROR_KIND_UNSET`]); `0` otherwise. The host re-calls once with a buffer that size.
    pub needed: u64,
}

/// The host's first secret buffer, in bytes: an API key or a token fits; a larger value (a PEM
/// chain) is the short-buffer answer and the host re-calls once with its size.
pub const FIRST_SECRET_CAP: usize = 4096;

/// `check`'s `in`: one reference's settings object and the host's reason buffer, as
/// [`ValidateIn`](super::mechanism::lifecycle::ValidateIn) lends one to `validate`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CheckIn {
    /// The head.
    pub head: InHead,
    /// The reference's `settings` object as config wrote it (JSON; a `{env: X}`/`{file: Y}` sugar
    /// already rewritten per the Statement rewrite rule). Never secret material.
    pub settings: Blob,
    /// THE REASON BUFFER, the host's, lent for the call: a `check` that answers FAILED writes why
    /// into it (UTF-8, at most [`CheckIn::err_cap`] bytes, cut on a char boundary) and names those
    /// bytes in `head.error`. NULL (with `err_cap` `0`) = no buffer is lent.
    pub err_buf: *mut u8,
    /// How many bytes `err_buf` holds.
    pub err_cap: usize,
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

// THE SDK's VIEW OF THE SECRET TABLE (`abi::sdk::door`): `resolve`'s `in`/`out`, stated next to
// the table, so `plugin_door!` refuses a kind op wired to any other structs. Every struct named
// here is plain data (integers, raw pointers, `Blob` only): every bit pattern is a valid value,
// which is what `AbiIn`/`AbiOut` promise.
//
// SAFETY (both below): `#[repr(C)]`, leading with `InHead`/`OutHead`, plain data only.
unsafe impl super::sdk::door::AbiIn for ResolveIn {}
unsafe impl super::sdk::door::AbiOut for ResolveOut {}
unsafe impl super::sdk::door::AbiIn for CheckIn {}

super::sdk::door::slot_structs!(
    /// `resolve`'s `in`/`out` for [`plugin_door!`](crate::plugin_door), per [`Ops`]' docs. A plugin
    /// wiring the slot to another op's structs does not compile:
    ///
    /// ```compile_fail,E0271
    /// use busbar_contract::abi::secret::{ResolveIn, ResolveOut};
    /// use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome};
    /// use busbar_contract::abi::mechanism::lifecycle::*;
    /// use busbar_contract::abi::sdk::door::Slot;
    /// # use std::ffi::c_void;
    /// # macro_rules! ready { ($n:ident, $i:ty, $o:ty) => {
    /// #     struct $n;
    /// #     impl Slot for $n { type In = $i; type Out = $o;
    /// #         fn call(_: *mut c_void, _: &$i, _: &mut $o) -> Outcome { Outcome::Ready } }
    /// # } }
    /// # ready!(V, ValidateIn, OutHead); ready!(Op_, OpenIn, OpenOut); ready!(Rf, RefreshIn, OutHead);
    /// # ready!(Rt, GenIn, OutHead); ready!(Tk, TickIn, TickOut); ready!(Dr, DriveIn, OutHead);
    /// # ready!(Cn, CancelIn, CancelOut); ready!(Rl, ReleaseIn, OutHead); ready!(Cl, InHead, OutHead);
    /// ready!(Wrong, InHead, OutHead); // `resolve` wired to the bare lifecycle shapes: refused
    /// busbar_contract::plugin_door! {
    ///     ops: busbar_contract::abi::secret::Ops,
    ///     statement: busbar_contract::abi::sdk::door::statement("wrong", "0", 1),
    ///     lifecycle: { validate: V, open: Op_, refresh: Rf, retire: Rt, tick: Tk, drive: Dr,
    ///                  cancel: Cn, release: Rl, close: Cl },
    ///     kind_ops: { resolve: Wrong },
    /// }
    /// # fn main() { let _ = door(); }
    /// ```
    ///
    /// With `Resolve` reading [`ResolveIn`] and writing [`ResolveOut`] the same plugin compiles
    /// (`abi/sdk/tests/door_tests.rs`, `a_secret_plugin_wires_every_kind_op`).
    Ops {
        slot::RESOLVE => ResolveIn, ResolveOut;
        slot::CHECK => CheckIn, OutHead;
    }
);

#[cfg(test)]
#[path = "../tests/secret_holder_tests.rs"]
mod holder_tests;
