// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SECRET KIND'S ABI: its version and its table (one mechanism, every shape in `abi/`). The

use super::mechanism::call::{Blob, InHead, Op, OutHead};
use super::mechanism::decl::{abi_answers, abi_struct};

pub mod validate;
use super::mechanism::lifecycle::{OpsHead, LIFECYCLE_SLOTS};

/// The secret kind's ABI version.
pub const ABI_VERSION: u32 = super::versions::SECRET.raw();

/// The secret kind's layout fingerprint ([`crate::abi::mechanism::layout`]): the fold of
pub const LAYOUT_FINGERPRINT: u64 = 0x52fda1049968af93;

/// [`InHead::op`] values the secret kind adds after the shared lifecycle, in table order.
///
/// # Examples
/// Every kind op `k` is at slot index `LIFECYCLE_SLOTS + k`, contiguous from the lifecycle:
/// ```
/// use busbar_contract::abi::mechanism::lifecycle::LIFECYCLE_SLOTS;
/// use busbar_contract::abi::secret::{slot, Ops, KIND_SLOTS, SLOTS};
/// use busbar_contract::abi::mechanism::lifecycle::OpsHead;
/// assert_eq!(slot::RESOLVE, LIFECYCLE_SLOTS + 0);
/// assert_eq!(slot::CHECK, LIFECYCLE_SLOTS + 1);
/// assert_eq!(SLOTS, LIFECYCLE_SLOTS + KIND_SLOTS);
/// assert_eq!(
///     std::mem::size_of::<Ops>(),
///     std::mem::size_of::<OpsHead>() + 8 * KIND_SLOTS as usize
/// );
/// ```
pub mod slot {
    use super::LIFECYCLE_SLOTS;

    /// `resolve`.
    pub const RESOLVE: u32 = LIFECYCLE_SLOTS;
    /// `check`.
    pub const CHECK: u32 = LIFECYCLE_SLOTS + 1;
}

/// How many slots the secret kind adds after the shared lifecycle (`resolve` and `check`).
pub const KIND_SLOTS: u32 = 2;

/// How many slots the secret kind's whole table holds (the lifecycle, `resolve` and `check`).
pub const SLOTS: u32 = LIFECYCLE_SLOTS + KIND_SLOTS;

abi_struct! {
    /// The secret kind's ops table. Leads with the shared [`OpsHead`]; kind op `k` is at slot index
    /// [`LIFECYCLE_SLOTS`]` + k` ([`slot`]).
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct Ops {
        /// The lifecycle.
        pub head: OpsHead,
        /// Resolve a settings blob into the host's buffer. OFF-PATH, `may_pend`,
        /// [`DeadlineClass::Call`](super::mechanism::call::DeadlineClass::Call). In [`ResolveIn`], out [`ResolveOut`].
        pub resolve: Option<Op>,
        /// Judge ONE reference's settings object at config time (`--validate`, boot, an apply), before
        /// anything resolves: PURE (no I/O, no resolve), called with NO instance (the `instance`
        /// argument is NULL), never pends, [`DeadlineClass::Call`](super::mechanism::call::DeadlineClass::Call).
        /// In [`CheckIn`], out [`OutHead`]. READY: the reference is well-formed. FAILED: why, in
        /// `CheckIn::err_buf`, under the lifecycle `validate` refusal rule
        /// ([`check_validate_refusal`](super::mechanism::lifecycle::check_validate_refusal)); the host
        /// renders each line as `<config path of the reference>: <line>`. An absent (NULL)
        /// `check` slot, which is what the SDK leaves for a door that wires none, or a REFUSED answer,
        /// means every reference passes.
        pub check: Option<Op>,
    }

    /// `resolve`'s `in`.
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct ResolveIn {
        /// The head.
        pub head: InHead,
        /// The settings naming what to resolve, in the plugin's own settings shape (a shorthand
        /// spelling already rewritten by the host per the Statement rewrite rule).
        pub settings: Blob,
        /// The host's zeroed secret buffer is lent for the call: a READY
        /// `resolve` writes the material here and nowhere the host must later release. The host wipes
        /// it when its consumer is done. NULL (with `secret_cap` `0`) = no buffer: every value is short.
        pub secret_buf: *mut u8,
        /// How many bytes `secret_buf` holds.
        pub secret_cap: usize,
    }
}

/// [`ResolveOut::error_kind`]: unset (a `Ready` answer).
pub const ERROR_KIND_UNSET: u32 = 0;
/// [`ResolveOut::error_kind`]: the named secret does not exist.
pub const ERROR_KIND_NOT_FOUND: u32 = 1;
/// [`ResolveOut::error_kind`]: the caller is not entitled to it.
pub const ERROR_KIND_DENIED: u32 = 3;
/// [`ResolveOut::error_kind`]: the settings blob itself is malformed, or the value is not a
pub const ERROR_KIND_INVALID: u32 = 4;
/// [`ResolveOut::error_kind`]: an internal fault in the plugin, not classified above.
pub const ERROR_KIND_INTERNAL: u32 = 5;

abi_struct! {
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
}

/// The largest secret a resolve may answer, using the shared host-buffer bound.
pub const MAX_SECRET_BYTES: usize = crate::abi::mechanism::check::HARD_MAX_BYTES as usize;

abi_struct! {
    /// `check`'s `in`: one reference's settings object and the host's reason buffer, as
    /// [`ValidateIn`](super::mechanism::lifecycle::ValidateIn) lends one to `validate`.
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct CheckIn {
        /// The head.
        pub head: InHead,
        /// The reference's `settings` object as config wrote it (JSON; a shorthand spelling
        /// already rewritten per the Statement rewrite rule). Never secret material.
        pub settings: Blob,
        /// THE REASON BUFFER, the host's, lent for the call: a `check` that answers FAILED writes why
        /// into it (UTF-8, at most [`CheckIn::err_cap`] bytes, cut on a char boundary) and names those
        /// bytes in `head.error`. NULL (with `err_cap` `0`) = no buffer is lent.
        pub err_buf: *mut u8,
        /// How many bytes `err_buf` holds.
        pub err_cap: usize,
    }
}

/// The secret kind's [`super::mechanism::lifecycle::CancelOut::disposition`] vocabulary.
pub mod cancel {
    /// The pending `resolve` was aborted; no lease was granted.
    pub const ABORTED: u32 = 0;
}

abi_answers! {
    cx: ();
    slot::RESOLVE => resolve(in ResolveIn, out ResolveOut) |_, i, o, _| {
        validate::check_resolve(o, i.secret_buf as usize, i.secret_cap as u64)
    }
}
