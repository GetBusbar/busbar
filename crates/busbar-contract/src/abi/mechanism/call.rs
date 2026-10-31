// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE CALL SHAPE: [`Op`], `op(instance, in, out)`, and the two heads every `in` and every
//! `out` of every kind leads with ([`InHead`], [`OutHead`]). A kind's own structs embed the head
//! as their first field and append their fields after it.

use std::os::raw::c_void;

use super::ticket::{HostCtx, Ticket};
use crate::abi::sdk::generation::Gen;

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

impl AbiStr {
    /// THE EMPTY DECLARATION: every field zero (NULL lists, empty strings, no flags). A plugin
    /// builds its value as `AbiStr { …, ..AbiStr::ZERO }` so a field appended later reads as not
    /// declared.
    pub const ZERO: Self = Self {
        ptr: std::ptr::null(),
        len: 0,
    };
}

impl AbiStr {
    /// `bytes`, borrowed for the call they cross in.
    #[must_use]
    pub fn over(bytes: &[u8]) -> AbiStr {
        AbiStr {
            ptr: bytes.as_ptr(),
            len: bytes.len(),
        }
    }
}

/// HOW AN `AbiStr` IS MADE AND READ (status row 194), through methods rather than its pointer and
/// length fields, which #1471 makes private:
///
/// * [`AbiStr::of`] / [`AbiStr::of_bytes`] — memory that lives for the program (a Statement's
///   strings, a row's, a `'static` answer);
/// * [`AbiStr::lent`] / [`AbiStr::lent_bytes`] — memory that lives at least until the plugin's
///   next refresh generation, proven by the op's generation borrow ([`Gen`]);
/// * [`AbiStr::ABSENT`] — no string (NULL).
///
/// The host and the loader, which lend memory for one call, make one with the `unsafe`
/// [`AbiStr::from_raw_parts`]. A read of the bytes is `unsafe` ([`AbiStr::bytes`]): a value
/// copied out of a call's `in` names memory the host lent for that call alone. A plugin reads the
/// strings the host lends it through [`Lent`](crate::abi::sdk::Lent).
///
/// ```
/// use busbar_contract::abi::mechanism::call::AbiStr;
/// const NAME: AbiStr = AbiStr::of("echo");
/// assert_eq!((NAME.ptr(), NAME.len()), (NAME.ptr, NAME.len));
/// ```
impl AbiStr {
    /// No string: a NULL pointer, zero length.
    pub const ABSENT: AbiStr = AbiStr {
        ptr: std::ptr::null(),
        len: 0,
    };

    /// `s`, which lives for the program. An empty `s` is present and empty, never absent.
    ///
    /// ```
    /// use busbar_contract::abi::mechanism::call::AbiStr;
    /// const NAME: AbiStr = AbiStr::of("echo");
    /// assert_eq!(NAME.len(), 4);
    /// assert!(!AbiStr::of("").is_absent());
    /// ```
    #[must_use]
    pub const fn of(s: &'static str) -> AbiStr {
        Self::of_bytes(s.as_bytes())
    }

    /// `bytes` (any bytes: a field value, a header), which live for the program.
    #[must_use]
    pub const fn of_bytes(bytes: &'static [u8]) -> AbiStr {
        AbiStr {
            ptr: bytes.as_ptr(),
            len: bytes.len(),
        }
    }

    /// `s`, which lives at least until the plugin's next refresh generation: the borrow checker
    /// holds `s` to the op's generation borrow `gen`, so a string of the call's own (a local, the
    /// host's lent `in`) does not compile here.
    #[must_use]
    pub fn lent<'g>(s: &'g str, gen: &Gen<'g>) -> AbiStr {
        Self::lent_bytes(s.as_bytes(), gen)
    }

    /// As [`AbiStr::lent`], for any bytes.
    #[must_use]
    pub fn lent_bytes<'g>(bytes: &'g [u8], gen: &Gen<'g>) -> AbiStr {
        let _ = gen;
        AbiStr {
            ptr: bytes.as_ptr(),
            len: bytes.len(),
        }
    }

    /// The string `len` bytes at `ptr` name (NULL = absent), unchecked: the host's and the
    /// loader's door for the memory they lend one call.
    ///
    /// # Safety
    ///
    /// Every read of the string (the host's, or the plugin's through [`AbiStr::bytes`]) finds
    /// `len` readable bytes at a non-NULL `ptr`, alive and unwritten for as long as that read: the
    /// host keeps what it lends a call alive until the call returns, and nothing it lends reaches
    /// data read after it.
    #[must_use]
    pub const unsafe fn from_raw_parts(ptr: *const u8, len: usize) -> AbiStr {
        AbiStr { ptr, len }
    }

    /// The pointer (NULL = absent). Reading it is safe; reading through it is not.
    #[must_use]
    pub const fn ptr(&self) -> *const u8 {
        self.ptr
    }

    /// The length in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the string is empty (absent or zero-length).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Whether the string is absent (NULL).
    #[must_use]
    pub const fn is_absent(&self) -> bool {
        self.ptr.is_null()
    }

    /// The bytes; empty when absent.
    ///
    /// # Safety
    ///
    /// The string names `len` readable bytes, alive and unwritten for `'a`: one made by
    /// [`AbiStr::of`] always does; one made by [`AbiStr::lent`] until the next refresh generation;
    /// one the host lent a call, until the call returns.
    #[must_use]
    pub unsafe fn bytes<'a>(&self) -> &'a [u8] {
        // SAFETY: the caller's contract.
        unsafe { crate::abi::abi_slice(self.ptr, self.len) }
    }

    /// The bytes as UTF-8; `""` when absent.
    ///
    /// # Safety
    ///
    /// As [`AbiStr::bytes`].
    ///
    /// # Errors
    ///
    /// The bytes are not UTF-8.
    pub unsafe fn as_str<'a>(&self) -> Result<&'a str, std::str::Utf8Error> {
        // SAFETY: the caller's contract.
        std::str::from_utf8(unsafe { self.bytes() })
    }
}

/// A byte range of a buffer the call names, in bytes; `offset ==`
/// [`SPAN_ABSENT`](super::check::SPAN_ABSENT) = absent (distinct from present and empty). THE one
/// span of every kind.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    /// Byte offset into the buffer; [`SPAN_ABSENT`](super::check::SPAN_ABSENT) = absent.
    pub offset: u32,
    /// Byte length.
    pub len: u32,
}

impl Span {
    /// THE EMPTY DECLARATION: every field zero (NULL lists, empty strings, no flags). A plugin
    /// builds its value as `Span { …, ..Span::ZERO }` so a field appended later reads as not
    /// declared.
    pub const ZERO: Self = Self { offset: 0, len: 0 };
}

/// One named field borrowed for the call: a name and its value (any bytes). THE one field of
/// every kind.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Field {
    /// The name.
    pub name: AbiStr,
    /// The value.
    pub value: AbiStr,
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

impl Blob {
    /// THE EMPTY DECLARATION: every field zero (NULL lists, empty strings, no flags). A plugin
    /// builds its value as `Blob { …, ..Blob::ZERO }` so a field appended later reads as not
    /// declared.
    pub const ZERO: Self = Self {
        ptr: std::ptr::null(),
        len: 0,
        fmt: 0,
        flags: 0,
    };
}

impl Blob {
    /// No payload.
    pub const ABSENT: Blob = Blob {
        ptr: std::ptr::null(),
        len: 0,
        fmt: BLOB_ABSENT,
        flags: 0,
    };
}

/// HOW A `Blob` IS MADE AND READ (status row 194), through methods rather than its pointer and
/// length fields, which #1471 makes private: [`Blob::of`] / [`Blob::json`] over memory that lives
/// for the program, [`Blob::lent`] over memory the op's generation borrow ([`Gen`]) proves, the
/// `unsafe` [`Blob::from_raw_parts`] for the host's and the loader's per-call memory.
impl Blob {
    /// `bytes`, which live for the program, as opaque octets ([`BLOB_OCTETS`]); state another
    /// format with [`Blob::with_fmt`].
    ///
    /// ```
    /// use busbar_contract::abi::mechanism::call::{Blob, BLOB_JSON};
    /// const SCHEMA: Blob = Blob::of(br#"{"type":"object"}"#).with_fmt(BLOB_JSON);
    /// assert_eq!(SCHEMA.fmt, BLOB_JSON);
    /// ```
    #[must_use]
    pub const fn of(bytes: &'static [u8]) -> Blob {
        Blob {
            ptr: bytes.as_ptr(),
            len: bytes.len(),
            fmt: BLOB_OCTETS,
            flags: 0,
        }
    }

    /// `bytes`, which live for the program, as one JSON document ([`BLOB_JSON`]).
    #[must_use]
    pub const fn json(bytes: &'static [u8]) -> Blob {
        Self::of(bytes).with_fmt(BLOB_JSON)
    }

    /// `bytes`, which live at least until the plugin's next refresh generation, as opaque octets:
    /// the borrow checker holds them to the op's generation borrow `gen` ([`AbiStr::lent`]).
    #[must_use]
    pub fn lent<'g>(bytes: &'g [u8], gen: &Gen<'g>) -> Blob {
        let s = AbiStr::lent_bytes(bytes, gen);
        Blob {
            ptr: s.ptr,
            len: s.len,
            fmt: BLOB_OCTETS,
            flags: 0,
        }
    }

    /// The same bytes, stated as `fmt` ([`BLOB_ABSENT`] | [`BLOB_JSON`] | [`BLOB_JSONL`] |
    /// [`BLOB_OCTETS`]).
    #[must_use]
    pub const fn with_fmt(mut self, fmt: u32) -> Blob {
        self.fmt = fmt;
        self
    }

    /// The same bytes, flagged `flags` ([`BLOB_SECRET`]).
    #[must_use]
    pub const fn with_flags(mut self, flags: u32) -> Blob {
        self.flags = flags;
        self
    }

    /// The payload `len` bytes at `ptr` name (NULL = absent), of `fmt`, flagged `flags`,
    /// unchecked: the host's and the loader's door for the memory they lend one call.
    ///
    /// # Safety
    ///
    /// As [`AbiStr::from_raw_parts`]: every read of the payload finds `len` readable bytes at a
    /// non-NULL `ptr`, alive and unwritten for as long as that read.
    #[must_use]
    pub const unsafe fn from_raw_parts(ptr: *const u8, len: usize, fmt: u32, flags: u32) -> Blob {
        Blob {
            ptr,
            len,
            fmt,
            flags,
        }
    }

    /// The pointer (NULL = absent). Reading it is safe; reading through it is not.
    #[must_use]
    pub const fn ptr(&self) -> *const u8 {
        self.ptr
    }

    /// The length in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the payload is empty (absent or zero-length).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The bytes; empty when absent.
    ///
    /// # Safety
    ///
    /// As [`AbiStr::bytes`]: the payload names `len` readable bytes, alive and unwritten for `'a`.
    #[must_use]
    pub unsafe fn bytes<'a>(&self) -> &'a [u8] {
        // SAFETY: the caller's contract.
        unsafe { crate::abi::abi_slice(self.ptr, self.len) }
    }
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
    /// The W3C trace id, 16 bytes as `traceparent` carries it; all zero = none.
    pub trace_id: [u8; 16],
    /// The W3C parent span id; `0` = none.
    pub parent_span_id: u64,
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
/// metric — or one of the two reserved ids below, which carry what the plugin LOGGED.
///
/// PLUGIN LOGGING. Whatever a plugin, or a library inside it, logs through `tracing` or `log`
/// during a call is captured by the door macro's trampoline and rides that call's reply as
/// [`DIAG_LOG`] entries; the host writes them to the plugin's own log file. One path, every kind,
/// compiled in or dropped in (`BUSBAR-1.6.0.md` decision #85).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Diag {
    /// Index into [`super::door::Statement::diag_ids`], or [`DIAG_LOG`] / [`DIAG_LOG_DROPPED`].
    pub id_idx: u32,
    /// [`SEVERITY_INFO`], [`SEVERITY_WARN`] or [`SEVERITY_ERROR`]; a [`DIAG_LOG`] entry may also
    /// state [`SEVERITY_DEBUG`] or [`SEVERITY_TRACE`].
    pub severity: u8,
    /// Alignment padding.
    pub _reserved: [u8; 3],
    /// Operator-facing text; never secret material.
    pub text: AbiStr,
}

impl Diag {
    /// THE EMPTY DECLARATION: every field zero (NULL lists, empty strings, no flags). A plugin
    /// builds its value as `Diag { …, ..Diag::ZERO }` so a field appended later reads as not
    /// declared.
    pub const ZERO: Self = Self {
        id_idx: 0,
        severity: 0,
        _reserved: [0; 3],
        text: AbiStr::ZERO,
    };
}

/// [`Diag::id_idx`]: a log record the plugin emitted during the call. Its text is
/// `target: message`, followed by any other fields as ` key=value`.
pub const DIAG_LOG: u32 = u32::MAX;
/// [`Diag::id_idx`]: how many log records the plugin's capture dropped over its bound, as decimal
/// text. At most one per reply, and last.
pub const DIAG_LOG_DROPPED: u32 = u32::MAX - 1;
/// [`Diag::severity`]: info.
pub const SEVERITY_INFO: u8 = 0;
/// [`Diag::severity`]: warn.
pub const SEVERITY_WARN: u8 = 1;
/// [`Diag::severity`]: error.
pub const SEVERITY_ERROR: u8 = 2;
/// [`Diag::severity`]: debug ([`DIAG_LOG`] only).
pub const SEVERITY_DEBUG: u8 = 3;
/// [`Diag::severity`]: trace ([`DIAG_LOG`] only).
pub const SEVERITY_TRACE: u8 = 4;
/// The most entries one envelope array may carry; the host drops a longer array whole.
pub const MAX_ENVELOPE_ENTRIES: usize = 256;
/// The most bytes of error or diagnostic text an entry may carry; longer is a malformed entry.
pub const MAX_TEXT: usize = 4096;

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

impl Envelope {
    /// THE EMPTY DECLARATION: every field zero (NULL lists, empty strings, no flags). A plugin
    /// builds its value as `Envelope { …, ..Envelope::ZERO }` so a field appended later reads as
    /// not declared.
    pub const ZERO: Self = Self {
        metrics: std::ptr::null(),
        metrics_len: 0,
        diags: std::ptr::null(),
        diags_len: 0,
    };
}

/// The head of every `out` of every kind. Host-owned. THE HOST ZEROES THE WHOLE `out` BEFORE EVERY
/// CALL (no template): an `out` the plugin never wrote reads `outcome` [`Outcome::Fault`] (`0`) and
/// every tail field as absent.
///
/// MEMORY, FOUR CLASSES (the design: plugin-owned memory is valid to its next refresh generation):
/// (i) REQUEST-PATH RESULTS go into HOST-owned buffers the kind's `in`/`out` names as pointer +
/// capacity; the plugin writes at most the capacity and never hands back a pointer for a result.
/// (ii) GENERATION DATA — only data a plugin PUBLISHES at `open`/`refresh` — stays valid until
/// `retire` of that generation. The Door and the Statement (the Door points to it) are `'static`.
/// (iii) PER-CALL `OutHead.error` and the `Envelope` arrays stay valid until the NEXT op on the same
/// ticket. On [`Ticket::NONE`] they are valid only until the op returns: the
/// host copies them before it makes any other call on that thread.
/// (iv) OFF-PATH LISTS AND SECRETS are held under a lease until `release(lease)`.
/// SIZES: the plugin writes at most `min(out.size, its own size of the struct)` bytes of an `out`,
/// never reads an `in` beyond `in.size`, and reads an absent tail field as zero.
/// FIXED ELEMENTS: the element layouts of [`MetricEntry`], [`Diag`],
/// [`super::door::MetricFamily`] and [`AbiStr`] are fixed by [`super::MECHANISM_VERSION`]; arrays of them
/// carry no stride, so growing one is a mechanism bump.
///
/// THE SHORT-BUFFER ANSWER (ARCHITECT ruling M-SB: one outcome for every kind; every kind cites this
/// text and does not restate it): "your buffer is too small" is [`Outcome::Failed`] with each
/// `needed_*` the answer needs above the capacity the host gave, and NOTHING applied. The host
/// re-calls ONCE, on the same ticket, with at least `needed_*`; a second short answer is
/// [`Outcome::Fault`]. A non-zero `needed_*` with any outcome other than FAILED is FAULT; FAILED
/// with `0 < needed <= the capacity given` is FAULT. REFUSED never carries `needed_*`.
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
    /// A kind may give it a READY meaning of its own (the auth kind: a reject's reason,
    /// `abi::auth::IdentifyOut`), operator text all the same.
    pub error: AbiStr,
    /// The #85 envelope.
    pub envelope: Envelope,
    /// The extensions blob every reply carries.
    pub extensions: Blob,
}
