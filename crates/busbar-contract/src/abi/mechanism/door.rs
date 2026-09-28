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
