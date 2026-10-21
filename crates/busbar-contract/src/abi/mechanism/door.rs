// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR AND THE STATEMENT: the ONE thing a plugin exports, and the plain data it states.
//!
//! A plugin of any kind exports exactly [`super::DOOR_SYMBOL`], a [`DoorFn`] answering a `'static`
//! [`Door`]. A compiled-in plugin is a row holding the same `DoorFn`; the kernel reaches both
//! through the same table and never holds a plugin crate's Rust types (the design: compiled in or
//! dropped in, the same table).

use super::call::{AbiStr, Blob, Op};
use super::lifecycle::OpsHead;
use crate::abi::host::conn::connector::Need;

/// The door. `'static`, answered by [`DoorFn`].
///
/// The loader checks, in order: the manifest's mechanism version (before `dlopen`), that the symbol
/// exists, then `magic == DOOR_MAGIC`, `mechanism_version == MECHANISM_VERSION` and `kind_abi ==`
/// the host's version for `kind`. Older and newer are both refused.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Door {
    /// [`super::DOOR_MAGIC`].
    pub magic: u64,
    /// [`super::MECHANISM_VERSION`].
    pub mechanism_version: u32,
    /// `size_of::<Door>()` at construction.
    pub size: u32,
    /// [`super::KindCode`], as its number.
    pub kind: u32,
    /// The kind's ABI version ([`super::KindCode::abi_version`]).
    pub kind_abi: u32,
    /// The plugin's Statement.
    pub statement: *const Statement,
    /// The kind's ops table; every kind's table begins with [`OpsHead`].
    pub ops: *const OpsHead,
    /// APPEND-ONLY TAIL: `ready` (`abi::mechanism::lifecycle`, READY), in [`super::lifecycle::ReadyIn`],
    /// out [`super::call::OutHead`]; `None` = the plugin has none and is opened exactly as before.
    /// A door whose `size` ends before this field has none: the host reads it only when `size`
    /// covers it.
    pub ready: Option<Op>,
}

/// The door function: the ONE symbol a plugin exports. `extern "C"`: a panic escaping it aborts.
///
/// **`unsafe` (status row 159):** it is foreign code answering a pointer the caller then reads, so
/// it is entered only under a stated contract, like every slot its door leads to.
///
/// # Safety
///
/// The caller guarantees the image defining the door is loaded (a dropped image's library is open
/// for as long as the call and every read of its answer), and that the pointer is a busbar door:
/// read from [`super::DOOR_SYMBOL`] (typed `DoorFn` by the mechanism) or a linked row's door item.
///
/// RED (status row 159): safe code cannot enter a door.
///
/// ```compile_fail,E0133
/// use busbar_contract::abi::mechanism::door::{Door, DoorFn};
/// fn open(door: DoorFn) -> *const Door {
///     door()
/// }
/// ```
pub type DoorFn = unsafe extern "C" fn() -> *const Door;

/// [`MetricFamily::kind`]: a counter.
pub const FAMILY_COUNTER: u8 = 0;
/// [`MetricFamily::kind`]: a gauge.
pub const FAMILY_GAUGE: u8 = 1;
/// [`MetricFamily::kind`]: a histogram.
pub const FAMILY_HISTOGRAM: u8 = 2;

/// One metric family, declared ONCE in the Statement and validated at `open`; a per-call
/// [`super::call::MetricEntry`] names it by index.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MetricFamily {
    /// The family name.
    pub name: AbiStr,
    /// Its help text.
    pub help: AbiStr,
    /// Its unit; absent = none.
    pub unit: AbiStr,
    /// Its label keys, in order.
    pub(crate) label_keys: *const AbiStr,
    /// How many.
    pub(crate) label_keys_len: usize,
    /// [`FAMILY_COUNTER`] | [`FAMILY_GAUGE`] | [`FAMILY_HISTOGRAM`].
    pub kind: u8,
    /// Alignment padding.
    pub _reserved: [u8; 7],
}

// THE LAYOUT, PINNED (status row 194): `MetricFamily`'s pointer and length fields are private to the
// contract, so its offsets are asserted here against their values today and read by the
// layout golden through [`MetricFamily::LAYOUT`].
impl MetricFamily {
    /// Every field's byte offset, in declaration order, each asserted at compile time.
    #[doc(hidden)]
    pub const LAYOUT: &'static [(&'static str, usize)] = layout! {
        MetricFamily, size 72;
        name = 0, help = 16, unit = 32, label_keys = 48, label_keys_len = 56, kind = 64,
        _reserved = 65,
    };
}
const _: &[(&str, usize)] = MetricFamily::LAYOUT;

/// HOW A `MetricFamily` IS MADE (status row 194): [`MetricFamily::new`], its label keys set with
/// [`MetricFamily::with_label_keys`].
impl MetricFamily {
    /// The family `name`, with `help`, `unit` (absent = none) and `kind`, and no label keys.
    #[must_use]
    pub const fn new(name: AbiStr, help: AbiStr, unit: AbiStr, kind: u8) -> MetricFamily {
        MetricFamily {
            name,
            help,
            unit,
            label_keys: std::ptr::null(),
            label_keys_len: 0,
            kind,
            _reserved: [0; 7],
        }
    }

    abi_lists! {
        label_keys, label_keys_len: AbiStr => label_keys_ptr, with_label_keys, with_raw_label_keys;
    }
}

/// THE STATEMENT: what a plugin states about itself, as plain `'static` data. Leads with `size`.
///
/// The same Statement is embedded in the object section, answered by the door and signed in the
/// manifest; the loader compares the three.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Statement {
    /// `size_of::<Statement>()` at construction.
    pub size: u32,
    /// [`super::KindCode`], as its number; equal to the door's.
    pub kind: u32,
    /// The kind's ABI version; equal to the door's.
    pub kind_abi: u32,
    /// The most calls one instance holds in flight; the host clamps it.
    pub max_inflight: u32,
    /// The plugin's name.
    pub name: AbiStr,
    /// The plugin's version.
    pub version: AbiStr,
    /// The metric families every per-call envelope indexes into.
    pub(crate) families: *const MetricFamily,
    /// How many.
    pub(crate) families_len: usize,
    /// The diagnostic ids every per-call envelope indexes into.
    pub(crate) diag_ids: *const AbiStr,
    /// How many.
    pub(crate) diag_ids_len: usize,
    /// The kind's own Statement tail (`abi/<kind>/`), leading with a [`KindTailHead`]; NULL = none.
    pub(crate) kind_tail: *const KindTailHead,
    /// The Statement's extensions.
    pub extensions: Blob,
    /// The settings keys whose values are secret references. The kernel resolves them, in this
    /// order, into [`super::lifecycle::OpenIn::secrets`]. Every kind uses it (auth, store, export and
    /// secret-service credentials).
    pub(crate) secret_refs: *const AbiStr,
    /// How many.
    pub(crate) secret_refs_len: usize,
    /// The settings schema every kind validates settings against (JSON, off-path).
    pub settings_schema: Blob,
    /// The flag marks (`MARK_*`): `one_instance`, `ephemeral`, `catalog`, `blocks`.
    pub marks: u64,
    /// The word marks, each a [`MarkWord`]: the hook words it claims (exclusive) and the carrier
    /// classes it consumes (shared).
    pub(crate) mark_words: *const MarkWord,
    /// How many.
    pub(crate) mark_words_len: usize,
    /// Its live rewrites, each a [`Rewrite`]: the other names config may call it by, the reference
    /// sugar that names it, and the setting keys it moves.
    pub(crate) rewrites: *const Rewrite,
    /// How many.
    pub(crate) rewrites_len: usize,
    /// The top-level config sections it owns or reads.
    pub(crate) sections: *const Section,
    /// How many.
    pub(crate) sections_len: usize,
    /// Its connection needs, `(transport, auth)` per direction.
    pub(crate) needs: *const Need,
    /// How many.
    pub(crate) needs_len: usize,
    /// The settings path its connection target comes from; absent = the plugin names it. A
    /// member-target path (`settings.*.<key>`, [`crate::section::MEMBER_TARGET_PREFIX`]) names each
    /// registration's own target instead: each member route is sealed at it.
    pub target_from: AbiStr,
    /// The settings path its trust anchors come from; absent = the host's default.
    pub trust_from: AbiStr,
    /// The structured answers it declares (the `declares` answers beside the metric families
    /// and diagnostic ids).
    pub(crate) answers: *const AbiStr,
    /// How many.
    pub(crate) answers_len: usize,
    /// The URL schemes it claims (a transport's claims; every other kind states none). Select reads
    /// them off the signed rendering, so a dropped transport is chosen without being opened.
    pub(crate) claims: *const AbiStr,
    /// How many.
    pub(crate) claims_len: usize,
}

// THE LAYOUT, PINNED (status row 194): `Statement`'s pointer and length fields are private to the
// contract, so its offsets are asserted here against their values today and read by the
// layout golden through [`Statement::LAYOUT`].
impl Statement {
    /// Every field's byte offset, in declaration order, each asserted at compile time.
    #[doc(hidden)]
    pub const LAYOUT: &'static [(&'static str, usize)] = layout! {
        Statement, size 288;
        size = 0, kind = 4, kind_abi = 8, max_inflight = 12, name = 16, version = 32, families = 48,
        families_len = 56, diag_ids = 64, diag_ids_len = 72, kind_tail = 80, extensions = 88,
        secret_refs = 112, secret_refs_len = 120, settings_schema = 128, marks = 152,
        mark_words = 160, mark_words_len = 168, rewrites = 176, rewrites_len = 184, sections = 192,
        sections_len = 200, needs = 208, needs_len = 216, target_from = 224, trust_from = 240,
        answers = 256, answers_len = 264, claims = 272, claims_len = 280,
    };
}
const _: &[(&str, usize)] = Statement::LAYOUT;

/// HOW A `Statement` IS MADE (status row 194): from
/// [`statement`](crate::abi::sdk::door::statement) (its name, version and in-flight bound, every
/// list empty), each list set by its setter to items that live for the program, the kind tail by
/// [`Statement::with_kind_tail`]. Its other fields are plain and set directly.
///
/// ```
/// use busbar_contract::abi::mechanism::call::AbiStr;
/// use busbar_contract::abi::mechanism::door::Statement;
/// use busbar_contract::abi::sdk::door::statement;
/// const DIAG_IDS: [AbiStr; 1] = [AbiStr::of("echo.refused")];
/// const STATEMENT: Statement = statement("echo", "1.0.0", 8).with_diag_ids(&DIAG_IDS);
/// assert_eq!(STATEMENT.diag_ids().len(), 1);
/// ```
impl Statement {
    abi_lists! {
        families, families_len: MetricFamily => families_ptr, with_families, with_raw_families;
        diag_ids, diag_ids_len: AbiStr => diag_ids_ptr, with_diag_ids, with_raw_diag_ids;
        secret_refs, secret_refs_len: AbiStr
            => secret_refs_ptr, with_secret_refs, with_raw_secret_refs;
        mark_words, mark_words_len: MarkWord => mark_words_ptr, with_mark_words, with_raw_mark_words;
        rewrites, rewrites_len: Rewrite => rewrites_ptr, with_rewrites, with_raw_rewrites;
        sections, sections_len: Section => sections_ptr, with_sections, with_raw_sections;
        needs, needs_len: Need => needs_ptr, with_needs, with_raw_needs;
        answers, answers_len: AbiStr => answers_ptr, with_answers, with_raw_answers;
        claims, claims_len: AbiStr => claims_ptr, with_claims, with_raw_claims;
    }

    /// Point the kind tail at `tail`, which lives for the program: one of the kinds' tails, each
    /// leading with a [`KindTailHead`] ([`KindTail`]).
    #[must_use]
    pub const fn with_kind_tail<T: KindTail>(mut self, tail: &'static T) -> Self {
        self.kind_tail = std::ptr::from_ref(tail).cast::<KindTailHead>();
        self
    }

    /// Point the kind tail at `tail`, unchecked: a host's own test stating a tail as a foreign
    /// plugin could (a short one, a NULL one), for the host's checks to judge.
    ///
    /// # Safety
    ///
    /// A non-NULL `tail` points at a kind tail leading with a [`KindTailHead`] whose `size` bytes
    /// stay readable and unwritten for as long as the Statement is read.
    #[must_use]
    pub const unsafe fn with_raw_kind_tail(mut self, tail: *const KindTailHead) -> Self {
        self.kind_tail = tail;
        self
    }

    /// The kind tail's raw pointer (NULL = none): the host reads it under its own checks
    /// ([`tail_read_len`]).
    #[must_use]
    pub const fn kind_tail(&self) -> *const KindTailHead {
        self.kind_tail
    }
}

mod sealed {
    /// The private supertrait that closes [`super::KindTail`].
    pub trait Sealed {}
    impl Sealed for crate::abi::store::StoreTail {}
    impl Sealed for crate::abi::auth::AuthTail {}
    impl Sealed for crate::abi::hook::Tail {}
    impl Sealed for crate::abi::export::Tail {}
    impl Sealed for crate::abi::plane::PlaneTail {}
    impl Sealed for crate::abi::transport::TransportTail {}
}

/// A KIND'S STATEMENT TAIL: a `#[repr(C)]` struct leading with a [`KindTailHead`], one per kind
/// that states one. Sealed: only the kinds' own tails are one, so [`Statement::with_kind_tail`]
/// points only at a tail the host knows how to read.
pub trait KindTail: sealed::Sealed + 'static {}
impl KindTail for crate::abi::store::StoreTail {}
impl KindTail for crate::abi::auth::AuthTail {}
impl KindTail for crate::abi::hook::Tail {}
impl KindTail for crate::abi::export::Tail {}
impl KindTail for crate::abi::plane::PlaneTail {}
impl KindTail for crate::abi::transport::TransportTail {}

// ── THE MARKS, REWRITES AND SECTIONS a Statement carries ────────────────────────────────────────
//
// The design's One Statement rule: each fact is declared once. A section, path or scheme mark is
// DERIVED from `sections`, inbound `needs` and transport claims, and never stored.

/// [`Statement::marks`]: at most one instance of the plugin may be configured.
pub const MARK_ONE_INSTANCE: u64 = 1;
/// [`Statement::marks`]: what the plugin holds is lost on restart (the memory store).
pub const MARK_EPHEMERAL: u64 = 1 << 1;
/// [`Statement::marks`]: the plugin answers the kind's catalog (what the build offers).
pub const MARK_CATALOG: u64 = 1 << 2;
/// [`Statement::marks`]: a call may block on slow I/O and is never run inline on a worker.
pub const MARK_BLOCKS: u64 = 1 << 3;
/// Every [`Statement::marks`] bit; any other bit refuses the load.
pub const MARKS_KNOWN: u64 = MARK_ONE_INSTANCE | MARK_EPHEMERAL | MARK_CATALOG | MARK_BLOCKS;

/// [`MarkWord::class`]: a hook word (a strategy word such as a ranking order). EXCLUSIVE: two
/// plugins claiming the same word refuse boot.
pub const MARK_WORD_HOOK: u32 = 1;
/// [`MarkWord::class`]: a carrier class the plugin consumes (an inbound credential carrier an auth
/// plugin reads; the kernel strips it from what a plane sees). SHARED: never a conflict.
pub const MARK_WORD_CARRIER: u32 = 2;
/// [`MarkWord::class`]: the literal prefix of the public id the host issues for the row's
/// credential kinds (an auth row stating `abi::auth::FACT_READS_CREDENTIALS`). Absent = no prefix.
/// SHARED. The five ISSUED marks are the issued credential's shape: the host draws every other
/// symbol from the OS CSPRNG over the stated alphabets and names no format of its own.
pub const MARK_WORD_ISSUED_ID_PREFIX: u32 = 3;
/// [`MarkWord::class`]: the issued public id's total length in characters, prefix included, as a
/// decimal word. SHARED.
pub const MARK_WORD_ISSUED_ID_LENGTH: u32 = 4;
/// [`MarkWord::class`]: the issued public id's alphabet after its prefix: distinct ASCII graphic
/// characters, each drawn with equal weight. SHARED.
pub const MARK_WORD_ISSUED_ID_ALPHABET: u32 = 5;
/// [`MarkWord::class`]: the issued secret's length in characters, as a decimal word. SHARED.
pub const MARK_WORD_ISSUED_SECRET_LENGTH: u32 = 6;
/// [`MarkWord::class`]: the issued secret's alphabet: distinct ASCII graphic characters, each drawn
/// with equal weight. SHARED.
pub const MARK_WORD_ISSUED_SECRET_ALPHABET: u32 = 7;

/// One word mark: its class and the word.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MarkWord {
    /// `MARK_WORD_*`.
    pub class: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// The word.
    pub word: AbiStr,
}

/// [`Rewrite::class`]: `from` is another name config may give the plugin (a module alias). The
/// registry holds it exclusive, beside the plugin's own name. `to` is absent.
pub const REWRITE_ALIAS: u32 = 1;
/// [`Rewrite::class`]: `from` is a reference key naming the plugin (the `k` in `{k: X}`). `to`, if
/// stated, is the settings key the value lands under; this contract does not read it yet.
pub const REWRITE_SUGAR: u32 = 2;
/// [`Rewrite::class`]: the setting key `from` is rewritten to the path `to` before the plugin's
/// section reaches it (a flat key to a nested path).
pub const REWRITE_KEY: u32 = 3;
/// [`Rewrite::class`]: `from` is a sugar word the same Statement declares; `to` is the placeholder
/// a refusal text shows for its value. Accepted and not yet read: a later contract reads it.
pub const REWRITE_SUGAR_SHOWN: u32 = 4;
/// [`Rewrite::class`]: `from` is a sugar word the same Statement declares; `to` is what its value
/// names in a missing-setting refusal. Accepted and not yet read: a later contract reads it.
pub const REWRITE_SUGAR_NAMES: u32 = 5;
/// [`Rewrite::class`]: `from` is a sugar word the same Statement declares; `to` is the core role
/// word its value plays. Accepted and not yet read: a later contract reads it.
pub const REWRITE_SUGAR_ROLE: u32 = 6;

/// One live rewrite.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Rewrite {
    /// `REWRITE_*`.
    pub class: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// What config says.
    pub from: AbiStr,
    /// What it becomes: named for [`REWRITE_KEY`] and the sugar classes after it, optional for
    /// [`REWRITE_SUGAR`], absent for [`REWRITE_ALIAS`].
    pub to: AbiStr,
}

/// [`Section::flags`]: the plugin's declaring section (a plane's verb).
pub const SECTION_DECLARING: u32 = 1;
/// [`Section::flags`]: a document must carry the section when the plugin is linked.
pub const SECTION_REQUIRED: u32 = 1 << 1;
/// [`Section::flags`]: the plugin reads the section but does not own its grammar.
pub const SECTION_CONSUMED: u32 = 1 << 2;

/// One top-level config section the plugin owns or reads.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Section {
    /// The section's key.
    pub name: AbiStr,
    /// `SECTION_*` bits.
    pub flags: u32,
    /// Alignment padding.
    pub _reserved: u32,
}

/// The head every kind's Statement tail leads with.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KindTailHead {
    /// `size_of` the whole kind tail.
    pub size: u32,
    /// Alignment padding.
    pub _reserved: u32,
}

/// THE KIND TAIL GROWTH RULE: a kind tail grows only by APPENDING fields, and its head's `size`
/// says how much of it the plugin wrote. The host reads the plugin's first `min(size, host)` bytes
/// and zero-fills the rest, so a field the plugin predates reads absent (`0`, NULL, an empty
/// string); a newer plugin's bytes past the host's tail are not read. Only a tail smaller than
/// `frozen`, the kind's size when its tail last froze, is refused (`None`). Returns how many of
/// the plugin's bytes the host reads.
#[must_use]
pub const fn tail_read_len(size: u32, frozen: usize, host: usize) -> Option<usize> {
    let size = size as usize;
    if size < frozen {
        return None;
    }
    Some(if size < host { size } else { host })
}
