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
    pub(crate) magic: u64,
    /// [`super::MECHANISM_VERSION`].
    pub(crate) mechanism_version: u32,
    /// `size_of::<Door>()` at construction.
    pub(crate) size: u32,
    /// [`super::KindCode`], as its number.
    pub(crate) kind: u32,
    /// The kind's ABI version ([`super::KindCode::abi_version`]).
    pub(crate) kind_abi: u32,
    /// The plugin's Statement.
    pub(crate) statement: *const Statement,
    /// The kind's ops table; every kind's table begins with [`OpsHead`].
    pub(crate) ops: *const OpsHead,
    /// APPEND-ONLY TAIL: `ready` (`abi::mechanism::lifecycle`, READY), in [`super::lifecycle::ReadyIn`],
    /// out [`super::call::OutHead`]; `None` = the plugin has none and is opened exactly as before.
    /// A door whose `size` ends before this field has none: the host reads it only when `size`
    /// covers it.
    pub(crate) ready: Option<Op>,
}

/// The door function: the ONE symbol a plugin exports. `extern "C"`: a panic escaping it aborts.
///
/// SEALED (status row 195, ARCHITECT ruling on `admit_linked`): it answers a `&'static Door`, and a
/// [`Door`]'s fields are private behind the `unsafe` [`Door::__from_parts`], so every `DoorFn` safe
/// code can name answers a door some `unsafe` constructor vouched for. The C header spells the same
/// symbol `const bb_mech_Door *(*)(void)`; a door read off a `dlsym` is a
/// [`RawDoorFn`](crate::abi::sdk::door::RawDoorFn) until the loader has checked it.
pub type DoorFn = extern "C" fn() -> &'static Door;

/// A door's fields, plain: what [`Door::__from_parts`] takes and [`Door::read_parts`] answers. A
/// `DoorParts` is no door: nothing admits one, so building one is safe.
#[derive(Debug, Clone, Copy)]
pub struct DoorParts {
    /// [`super::DOOR_MAGIC`].
    pub magic: u64,
    /// [`super::MECHANISM_VERSION`].
    pub mechanism_version: u32,
    /// `size_of::<Door>()` at construction.
    pub size: u32,
    /// [`super::KindCode`], as its number.
    pub kind: u32,
    /// The kind's ABI version.
    pub kind_abi: u32,
    /// The plugin's Statement.
    pub statement: *const Statement,
    /// The kind's ops table.
    pub ops: *const OpsHead,
    /// The optional `ready` op.
    pub ready: Option<Op>,
}

impl Door {
    /// THE ONE CONSTRUCTOR, `unsafe` and `#[doc(hidden)]`: the contract's door macro reaches it
    /// through [`crate::abi::sdk::door::door`]; a loader's or a test's hand-laid door names it.
    ///
    /// # Safety
    ///
    /// The door is the `'static` plugin data a [`DoorFn`] may answer: `statement` points at a
    /// `'static` [`Statement`] whose lists, strings, blobs and kind tail point at their stated counts
    /// of live `'static` data, and `ops` at a `'static` table of the kind `kind` names whose every
    /// non-NULL slot honours the call convention (`abi::mechanism::call`). A host reads a door as
    /// it states itself; a door that lies is undefined behaviour in the host.
    #[doc(hidden)]
    #[must_use]
    pub const unsafe fn __from_parts(p: DoorParts) -> Self {
        Self {
            magic: p.magic,
            mechanism_version: p.mechanism_version,
            size: p.size,
            kind: p.kind,
            kind_abi: p.kind_abi,
            statement: p.statement,
            ops: p.ops,
            ready: p.ready,
        }
    }

    /// The door's fields, plain.
    #[must_use]
    pub const fn parts(&self) -> DoorParts {
        DoorParts {
            magic: self.magic,
            mechanism_version: self.mechanism_version,
            size: self.size,
            kind: self.kind,
            kind_abi: self.kind_abi,
            statement: self.statement,
            ops: self.ops,
            ready: self.ready,
        }
    }

    /// [`super::DOOR_MAGIC`].
    #[must_use]
    pub const fn magic(&self) -> u64 {
        self.magic
    }

    /// [`super::MECHANISM_VERSION`].
    #[must_use]
    pub const fn mechanism_version(&self) -> u32 {
        self.mechanism_version
    }

    /// `size_of::<Door>()` at construction.
    #[must_use]
    pub const fn size(&self) -> u32 {
        self.size
    }

    /// [`super::KindCode`], as its number.
    #[must_use]
    pub const fn kind(&self) -> u32 {
        self.kind
    }

    /// The kind's ABI version.
    #[must_use]
    pub const fn kind_abi(&self) -> u32 {
        self.kind_abi
    }

    /// The plugin's Statement.
    #[must_use]
    pub const fn statement(&self) -> *const Statement {
        self.statement
    }

    /// The kind's ops table.
    #[must_use]
    pub const fn ops(&self) -> *const OpsHead {
        self.ops
    }

    /// The optional `ready` op.
    #[must_use]
    pub const fn ready(&self) -> Option<Op> {
        self.ready
    }

    /// Where the append-only `ready` tail starts: the least size a door states.
    #[must_use]
    pub const fn ready_at() -> usize {
        core::mem::offset_of!(Door, ready)
    }

    /// Each field's name and offset, in order: the layout golden's record of the sealed door.
    #[doc(hidden)]
    #[must_use]
    pub const fn __layout() -> [(&'static str, usize); 8] {
        use core::mem::offset_of;
        [
            ("magic", offset_of!(Door, magic)),
            ("mechanism_version", offset_of!(Door, mechanism_version)),
            ("size", offset_of!(Door, size)),
            ("kind", offset_of!(Door, kind)),
            ("kind_abi", offset_of!(Door, kind_abi)),
            ("statement", offset_of!(Door, statement)),
            ("ops", offset_of!(Door, ops)),
            ("ready", offset_of!(Door, ready)),
        ]
    }

    /// A door's leading `(magic, mechanism_version, size)`, read one field at a time and unaligned:
    /// what a loader checks before it trusts the rest.
    ///
    /// # Safety
    ///
    /// `p` is non-NULL and readable through `size`.
    #[must_use]
    pub unsafe fn read_head(p: *const Self) -> (u64, u32, u32) {
        use core::ptr::addr_of;
        // SAFETY: the caller's contract; each field is read unaligned.
        unsafe {
            (
                addr_of!((*p).magic).read_unaligned(),
                addr_of!((*p).mechanism_version).read_unaligned(),
                addr_of!((*p).size).read_unaligned(),
            )
        }
    }

    /// A door's fields, read one at a time and unaligned; `ready` only when the `size` it states
    /// covers it (an absent tail reads as `None`).
    ///
    /// # Safety
    ///
    /// `p` is non-NULL and readable up to `ready` ([`Door::ready_at`]), and through `ready` when
    /// the `size` it states covers it.
    #[must_use]
    pub unsafe fn read_parts(p: *const Self) -> DoorParts {
        use core::ptr::addr_of;
        // SAFETY: the caller's contract; each field is read unaligned, `ready` only when covered.
        unsafe {
            let (magic, mechanism_version, size) = Self::read_head(p);
            let has_ready = size as usize >= Self::ready_at() + size_of::<Option<Op>>();
            DoorParts {
                magic,
                mechanism_version,
                size,
                kind: addr_of!((*p).kind).read_unaligned(),
                kind_abi: addr_of!((*p).kind_abi).read_unaligned(),
                statement: addr_of!((*p).statement).read_unaligned(),
                ops: addr_of!((*p).ops).read_unaligned(),
                ready: if has_ready {
                    addr_of!((*p).ready).read_unaligned()
                } else {
                    None
                },
            }
        }
    }
}

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
    pub label_keys: *const AbiStr,
    /// How many.
    pub label_keys_len: usize,
    /// [`FAMILY_COUNTER`] | [`FAMILY_GAUGE`] | [`FAMILY_HISTOGRAM`].
    pub kind: u8,
    /// Alignment padding.
    pub _reserved: [u8; 7],
}

impl MetricFamily {
    /// THE EMPTY DECLARATION: every field zero (NULL lists, empty strings, no flags). A plugin
    /// builds its value as `MetricFamily { …, ..MetricFamily::ZERO }` so a field appended later
    /// reads as not declared.
    pub const ZERO: Self = Self {
        name: AbiStr::ZERO,
        help: AbiStr::ZERO,
        unit: AbiStr::ZERO,
        label_keys: std::ptr::null(),
        label_keys_len: 0,
        kind: 0,
        _reserved: [0; 7],
    };
}

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
    pub families: *const MetricFamily,
    /// How many.
    pub families_len: usize,
    /// The diagnostic ids every per-call envelope indexes into.
    pub diag_ids: *const AbiStr,
    /// How many.
    pub diag_ids_len: usize,
    /// The kind's own Statement tail (`abi/<kind>/`), leading with a [`KindTailHead`]; NULL = none.
    pub kind_tail: *const KindTailHead,
    /// The Statement's extensions.
    pub extensions: Blob,
    /// The settings keys whose values are secret references. The kernel resolves them, in this
    /// order, into [`super::lifecycle::OpenIn::secrets`]. Every kind uses it (auth, store, export and
    /// secret-service credentials).
    pub secret_refs: *const AbiStr,
    /// How many.
    pub secret_refs_len: usize,
    /// The settings schema every kind validates settings against (JSON, off-path).
    pub settings_schema: Blob,
    /// The flag marks (`MARK_*`): `one_instance`, `ephemeral`, `catalog`, `blocks`.
    pub marks: u64,
    /// The word marks, each a [`MarkWord`]: the hook words it claims (exclusive) and the carrier
    /// classes it consumes (shared).
    pub mark_words: *const MarkWord,
    /// How many.
    pub mark_words_len: usize,
    /// Its live rewrites, each a [`Rewrite`]: the other names config may call it by, the reference
    /// sugar that names it, and the setting keys it moves.
    pub rewrites: *const Rewrite,
    /// How many.
    pub rewrites_len: usize,
    /// The top-level config sections it owns or reads.
    pub sections: *const Section,
    /// How many.
    pub sections_len: usize,
    /// Its connection needs, `(transport, auth)` per direction.
    pub needs: *const Need,
    /// How many.
    pub needs_len: usize,
    /// The settings path its connection target comes from; absent = the plugin names it. A
    /// member-target path (`settings.*.<key>`, [`crate::section::MEMBER_TARGET_PREFIX`]) names each
    /// registration's own target instead: each member route is sealed at it.
    pub target_from: AbiStr,
    /// The settings path its trust anchors come from; absent = the host's default.
    pub trust_from: AbiStr,
    /// The structured answers it declares (the `declares` answers beside the metric families
    /// and diagnostic ids).
    pub answers: *const AbiStr,
    /// How many.
    pub answers_len: usize,
    /// The URL schemes it claims (a transport's claims; every other kind states none). Select reads
    /// them off the signed rendering, so a dropped transport is chosen without being opened.
    pub claims: *const AbiStr,
    /// How many.
    pub claims_len: usize,
}

impl Statement {
    /// THE EMPTY DECLARATION: every field zero (NULL lists, empty strings, no flags). A plugin
    /// builds its value as `Statement { …, ..Statement::ZERO }` so a field appended later reads as
    /// not declared.
    pub const ZERO: Self = Self {
        size: 0,
        kind: 0,
        kind_abi: 0,
        max_inflight: 0,
        name: AbiStr::ZERO,
        version: AbiStr::ZERO,
        families: std::ptr::null(),
        families_len: 0,
        diag_ids: std::ptr::null(),
        diag_ids_len: 0,
        kind_tail: std::ptr::null(),
        extensions: Blob::ZERO,
        secret_refs: std::ptr::null(),
        secret_refs_len: 0,
        settings_schema: Blob::ZERO,
        marks: 0,
        mark_words: std::ptr::null(),
        mark_words_len: 0,
        rewrites: std::ptr::null(),
        rewrites_len: 0,
        sections: std::ptr::null(),
        sections_len: 0,
        needs: std::ptr::null(),
        needs_len: 0,
        target_from: AbiStr::ZERO,
        trust_from: AbiStr::ZERO,
        answers: std::ptr::null(),
        answers_len: 0,
        claims: std::ptr::null(),
        claims_len: 0,
    };
}

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
/// assert_eq!(STATEMENT.diag_ids_len(), 1);
/// assert_eq!(STATEMENT.diag_ids_ptr(), DIAG_IDS.as_ptr());
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

impl MarkWord {
    /// THE EMPTY DECLARATION: every field zero (NULL lists, empty strings, no flags). A plugin
    /// builds its value as `MarkWord { …, ..MarkWord::ZERO }` so a field appended later reads as
    /// not declared.
    pub const ZERO: Self = Self {
        class: 0,
        _reserved: 0,
        word: AbiStr::ZERO,
    };
}

/// [`Rewrite::class`]: `from` is another name config may give the plugin (a module alias). The
/// registry holds it exclusive, beside the plugin's own name. `to` is absent.
pub const REWRITE_ALIAS: u32 = 1;
/// [`Rewrite::class`]: `from` is a reference key naming the plugin (the `k` in `{k: X}`, a secret
/// reference's SUGAR); `to` is the settings key the value lands under, so `{k: X}` is
/// `{ module: k, settings: { <to>: X } }`. The host reads it ([`crate::secret_ref::Sugars`]) and
/// refuses a secret plugin whose sugar states no key, or a word another plugin declares.
pub const REWRITE_SUGAR: u32 = 2;
/// [`Rewrite::class`]: the setting key `from` is rewritten to the path `to` before the plugin's
/// section reaches it (a flat key to a nested path).
pub const REWRITE_KEY: u32 = 3;
/// [`Rewrite::class`]: `from` is a sugar word the same Statement declares; `to` is the placeholder
/// a refusal text shows for its value (absent = the sugar's settings key).
pub const REWRITE_SUGAR_SHOWN: u32 = 4;
/// [`Rewrite::class`]: `from` is a sugar word the same Statement declares; `to` is what its value
/// names in a missing-setting refusal (`requires settings.<key> (<to>)`; absent = `the <key>`).
/// The host reads it ([`crate::secret_ref::Sugars`]).
pub const REWRITE_SUGAR_NAMES: u32 = 5;
/// [`Rewrite::class`]: `from` is a sugar word the same Statement declares; `to` is the core role
/// word its value plays ([`SUGAR_ROLE_FILL`], [`SUGAR_ROLE_PATH`]). Exclusive: two plugins claiming
/// one role refuse the load.
pub const REWRITE_SUGAR_ROLE: u32 = 6;

/// [`REWRITE_SUGAR_ROLE`]: a config `${VAR}` at a credential position names the value of this
/// sugar.
pub const SUGAR_ROLE_FILL: &str = "fill";
/// [`REWRITE_SUGAR_ROLE`]: the value of this sugar is a file path a credential may name in place of
/// its material (a service account's key file).
pub const SUGAR_ROLE_PATH: &str = "path";

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

impl Rewrite {
    /// THE EMPTY DECLARATION: every field zero (NULL lists, empty strings, no flags). A plugin
    /// builds its value as `Rewrite { …, ..Rewrite::ZERO }` so a field appended later reads as not
    /// declared.
    pub const ZERO: Self = Self {
        class: 0,
        _reserved: 0,
        from: AbiStr::ZERO,
        to: AbiStr::ZERO,
    };
}

/// [`Section::flags`]: the plugin's declaring section (a plane's verb).
pub const SECTION_DECLARING: u32 = 1;
/// [`Section::flags`]: a document must carry the section when the plugin is linked.
pub const SECTION_REQUIRED: u32 = 1 << 1;
/// [`Section::flags`]: the plugin reads the section but does not own its grammar.
pub const SECTION_CONSUMED: u32 = 1 << 2;
/// [`Section::flags`]: this section's presence uses the plane (it selects it at boot, Law 7).
///
/// Nothing else reads it: the section's grammar stays whoever owns it, and a plane may be selected
/// by a section it only consumes. A plane's declaring section selects it already, so the two
/// together are refused, as is the bit on any other kind.
pub const SECTION_SELECTS: u32 = 1 << 4;

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

impl Section {
    /// THE EMPTY DECLARATION: every field zero (NULL lists, empty strings, no flags). A plugin
    /// builds its value as `Section { …, ..Section::ZERO }` so a field appended later reads as not
    /// declared.
    pub const ZERO: Self = Self {
        name: AbiStr::ZERO,
        flags: 0,
        _reserved: 0,
    };
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

impl KindTailHead {
    /// THE EMPTY DECLARATION: every field zero (NULL lists, empty strings, no flags). A plugin
    /// builds its value as `KindTailHead { …, ..KindTailHead::ZERO }` so a field appended later
    /// reads as not declared.
    pub const ZERO: Self = Self {
        size: 0,
        _reserved: 0,
    };
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
