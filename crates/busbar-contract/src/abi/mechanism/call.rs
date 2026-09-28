// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE CALL SHAPE: [`Op`], `op(instance, in, out)`, and the two heads every `in` and every
//! `out` of every kind leads with ([`InHead`], [`OutHead`]). A kind's own structs embed the head
//! as their first field and append their fields after it.

use std::os::raw::c_void;

use super::ticket::{HostCtx, Ticket};

/// What an op answered, as the byte crossing the boundary. An unknown byte reads as
/// [`Outcome::Fault`].
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawOutcome(pub u8);

/// What an op answered.
///
/// `Fault` is `0`, so an `out` nobody wrote — zeroed or left as the host's template — reads as a
/// fault, never as a safe default.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The plugin broke its contract (a caught panic, a malformed `out`). Never a safe default.
    Fault = 0,
    /// Done; `out` holds the answer.
    Ready = 1,
    /// Not ready: the plugin registered interest and will `wake` the ticket; the host re-invokes
    /// the same op with [`FLAG_RESUME`].
    Pending = 2,
    /// The operation failed, as the kind defines failure. Distinct from any "no opinion" answer.
    Failed = 3,
    /// The plugin refused the operation (a gate, an undeclared need).
    Refused = 4,
}

impl RawOutcome {
    /// The byte for an outcome.
    #[must_use]
    pub const fn of(o: Outcome) -> Self {
        Self(o as u8)
    }

    /// The outcome the byte states; an unknown byte is [`Outcome::Fault`].
    #[must_use]
    pub const fn outcome(self) -> Outcome {
        match self.0 {
            1 => Outcome::Ready,
            2 => Outcome::Pending,
            3 => Outcome::Failed,
            4 => Outcome::Refused,
            _ => Outcome::Fault,
        }
    }
}

/// THE CALL SHAPE, the same for every slot of every kind: `op(instance, in, out)`.
///
/// * `instance` — the plugin's own instance pointer, as its `open` answered it; opaque to the host.
/// * `input` — a kind's `in` struct, leading with an [`InHead`]. Host-owned, read-only.
/// * `out` — a kind's `out` struct, leading with an [`OutHead`]. Host-owned; the plugin writes it.
///
/// **`extern "C"`, NEVER `extern "C-unwind"`.** Unwinding across a foreign cdylib boundary is
/// undefined behaviour, so no slot type in the mechanism permits it. **ABORT ON ESCAPE:** a panic
/// that escapes a slot body aborts the process (Rust's `extern "C"` guarantee). The SDK's door
/// macro catches every panic first and answers [`Outcome::Fault`]; the abort is the floor under a
/// hand-written slot that did not.
pub type Op =
    extern "C" fn(instance: *mut c_void, input: *const c_void, out: *mut c_void) -> RawOutcome;

/// [`InHead::flags`]: this call RESUMES a call that answered [`Outcome::Pending`], with the same
/// ticket and the same `in`/`out`.
pub const FLAG_RESUME: u32 = 1;

/// The deadline class of an op (the ABI brief's mechanics), carried in
/// [`InHead::deadline_class`].
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeadlineClass {
    /// A per-call budget; on expiry `cancel`, then the kind's timeout outcome.
    Call = 0,
    /// The configured idle/overall timeout of a stream.
    Stream = 1,
    /// The carrier's idle timeout.
    Connection = 2,
    /// Long; never cancelled on client drop or reload; retried with the same `op_id`.
    WriteBehind = 3,
}

impl DeadlineClass {
    /// The class a byte names, or `None` for a byte no class has.
    #[must_use]
    pub const fn from_raw(raw: u8) -> Option<DeadlineClass> {
        match raw {
            0 => Some(DeadlineClass::Call),
            1 => Some(DeadlineClass::Stream),
            2 => Some(DeadlineClass::Connection),
            3 => Some(DeadlineClass::WriteBehind),
            _ => None,
        }
    }
}

/// Borrowed UTF-8 bytes: pointer + length. NULL = absent.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AbiStr {
    /// The bytes; NULL = absent.
    pub ptr: *const u8,
    /// Their length.
    pub len: usize,
}

/// [`Blob::fmt`]: absent.
pub const BLOB_ABSENT: u32 = 0;
/// [`Blob::fmt`]: one JSON document.
pub const BLOB_JSON: u32 = 1;
/// [`Blob::fmt`]: JSON lines.
pub const BLOB_JSONL: u32 = 2;
/// [`Blob::fmt`]: opaque octets.
pub const BLOB_OCTETS: u32 = 3;
/// [`Blob::flags`]: the bytes are secret material; the owner zeroises them on release.
pub const BLOB_SECRET: u32 = 1;

/// A payload: pointer + length, with its format. JSON crosses ONLY as one of these (JSON is only a payload).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Blob {
    /// The bytes; NULL = absent.
    pub ptr: *const u8,
    /// Their length.
    pub len: usize,
    /// [`BLOB_ABSENT`] | [`BLOB_JSON`] | [`BLOB_JSONL`] | [`BLOB_OCTETS`].
    pub fmt: u32,
    /// [`BLOB_SECRET`].
    pub flags: u32,
}

/// The head of every `in` of every kind.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct InHead {
    /// `size_of` the whole `in` struct the host wrote.
    pub size: u32,
    /// The slot index this call is for, in the kind's table order.
    pub op: u32,
    /// [`FLAG_RESUME`].
    pub flags: u32,
    /// [`DeadlineClass`], as its byte.
    pub deadline_class: u8,
    /// Alignment padding.
    pub _reserved: [u8; 3],
    /// The host context `wake` is called with.
    pub host: HostCtx,
    /// The ticket of the request or stream this call belongs to; [`Ticket::NONE`] for a call that
    /// may not pend.
    pub ticket: Ticket,
    /// The deadline, on the kernel's coarse clock (nanoseconds).
    pub deadline_ns: u64,
    /// The trace id.
    pub trace_id: u64,
    /// The extensions blob every op carries (the shared mechanism); absent unless a pending field exists.
    pub extensions: Blob,
}

/// One per-call metric: an INDEX into the families the plugin's Statement declared, range-checked
/// per call (#85).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MetricEntry {
    /// Index into [`super::door::Statement::families`].
    pub family_idx: u32,
    /// [`METRIC_ADD`] | [`METRIC_SET`] | [`METRIC_OBSERVE`]; must agree with the family's kind.
    pub kind: u8,
    /// Alignment padding.
    pub _reserved: [u8; 3],
    /// The value; a non-finite value drops the entry.
    pub value: f64,
    /// One value per label key the family declares, in declaration order.
    pub label_vals: *const AbiStr,
    /// How many.
    pub label_vals_len: usize,
}

/// [`MetricEntry::kind`]: add to a counter.
pub const METRIC_ADD: u8 = 0;
/// [`MetricEntry::kind`]: set a gauge.
pub const METRIC_SET: u8 = 1;
/// [`MetricEntry::kind`]: observe into a histogram.
pub const METRIC_OBSERVE: u8 = 2;

/// One diagnostic: an INDEX into the diagnostic ids the Statement declared, the same scheme as a
/// metric.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Diag {
    /// Index into [`super::door::Statement::diag_ids`].
    pub id_idx: u32,
    /// `0` info, `1` warn, `2` error.
    pub severity: u8,
    /// Alignment padding.
    pub _reserved: [u8; 3],
    /// Operator-facing text; never secret material.
    pub text: AbiStr,
}

/// THE #85 ENVELOPE every reply carries: metrics and diagnostics, both by index.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Envelope {
    /// The metrics.
    pub metrics: *const MetricEntry,
    /// How many.
    pub metrics_len: usize,
    /// The diagnostics.
    pub diags: *const Diag,
    /// How many.
    pub diags_len: usize,
}

/// The head of every `out` of every kind. Host-owned; the host initialises it before the call.
///
/// MEMORY, FOUR CLASSES (the design: plugin-owned memory is valid to its next refresh generation):
/// (i) REQUEST-PATH RESULTS go into HOST-owned buffers the kind's `in`/`out` names as pointer +
/// capacity; the plugin writes at most the capacity and never hands back a pointer for a result.
/// (ii) GENERATION DATA — the Statement, and snapshots a plugin publishes at `open`/`refresh` — stays
/// valid until `retire` of that generation. Door memory is `'static`.
/// (iii) PER-CALL `OutHead.error` and the `Envelope` arrays stay valid until the NEXT op on the same
/// ticket. On [`Ticket::NONE`] they are valid only until the op returns: the
/// host copies them before it makes any other call on that thread.
/// (iv) OFF-PATH LISTS AND SECRETS are held under a lease until `release(lease)`.
/// SIZES: the plugin writes at most `min(out.size, its own size of the struct)` bytes of an `out`,
/// never reads an `in` beyond `in.size`, and reads an absent tail field as zero.
/// FIXED ELEMENTS: the element layouts of [`MetricEntry`], [`Diag`],
/// [`super::door::MetricFamily`] and [`AbiStr`] are fixed by [`super::MECHANISM_VERSION`]; arrays of them
/// carry no stride, so growing one is a mechanism bump.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OutHead {
    /// `size_of` the `out` struct the plugin wrote (the plugin writes back its own).
    pub size: u32,
    /// [`RawOutcome`], mirrored from the return value. The RETURN VALUE is authoritative: the
    /// dispatcher treats an `outcome` that differs from it as [`Outcome::Fault`]. [`Outcome::Pending`]
    /// answered on a [`Ticket::NONE`] call is [`Outcome::Fault`].
    pub outcome: RawOutcome,
    /// Alignment padding.
    pub _reserved: [u8; 3],
    /// For [`Outcome::Pending`]: the latest time the host should re-invoke without a wake; `0` =
    /// only on a wake.
    pub wake_at_ns: u64,
    /// A lease the host hands back to `release`: off-path lists and secrets only; `0` = none.
    pub lease: u64,
    /// For [`Outcome::Failed`]/[`Outcome::Refused`]: the error text; never secret material.
    pub error: AbiStr,
    /// The #85 envelope.
    pub envelope: Envelope,
    /// The extensions blob every reply carries.
    pub extensions: Blob,
}
