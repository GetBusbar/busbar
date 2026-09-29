// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR AND THE STATEMENT: the ONE thing a plugin exports, and the plain data it states.
//!
//! A plugin of any kind exports exactly [`super::DOOR_SYMBOL`], a [`DoorFn`] answering a `'static`
//! [`Door`]. A compiled-in plugin is a row holding the same `DoorFn`; the kernel reaches both
//! through the same table and never holds a plugin crate's Rust types (the design: compiled in or
//! dropped in, the same table).

use super::call::{AbiStr, Blob};
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
}

/// The door function: the ONE symbol a plugin exports. `extern "C"`: a panic escaping it aborts.
pub type DoorFn = extern "C" fn() -> *const Door;

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
    /// The settings path its connection target comes from; absent = the plugin names it.
    pub target_from: AbiStr,
    /// The settings path its trust anchors come from; absent = the host's default.
    pub trust_from: AbiStr,
    /// The structured answers it declares (the `declares` answers beside the metric families
    /// and diagnostic ids).
    pub answers: *const AbiStr,
    /// How many.
    pub answers_len: usize,
}

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
/// [`Rewrite::class`]: `from` is a reference key naming the plugin (the `k` in `{k: X}`). `to` is
/// absent.
pub const REWRITE_SUGAR: u32 = 2;
/// [`Rewrite::class`]: the setting key `from` is rewritten to the path `to` before the plugin's
/// section reaches it (a flat key to a nested path).
pub const REWRITE_KEY: u32 = 3;

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
    /// What it becomes; absent unless [`REWRITE_KEY`].
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
