// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The MIN-3 plugin interface (ABI-MIN3-INTERFACE, round 34): the records codec, Host services, Need steps,
//! the plugin header, `Open`/`Describe`, the stamp, the fingerprint and the seven kind traits; feature `host`
//! adds core's side (§10), feature `memio` the in-memory IO adapter (§9).
//!
//! Wave 0 (W0-ABI) landed every frozen signature as a compiling stub; each wave-1 task replaces the stubs in
//! the files it owns. W1-A1 owns this file, `types.rs`, `records.rs`, `fail.rs`, `fp.rs`, `versions.rs` and the
//! `mechanism!` block. The crate has no `unsafe` (owner ruling, `deny(unsafe_code)`): every IF item that needs it
//! lives in busbar-ffi, the plugin boundary (UNSAFE-MIN r3.1), and is re-exported here under its frozen path: the
//! views, `Status`/`KindCode`/`Token`, the `Host` table, the `Plugin` header, `ChainBytes`, the slot table and
//! `Out`'s in-place writes (wrapped by `records::Out`). The safe host methods are `host::HostExt`.

#![forbid(unsafe_code)]
#![doc(test(attr(forbid(unsafe_code))))]

/// The `mechanism!` block (IF §7.5). It emits its items unchanged and records their tokens, doc comments
/// included, as `stringify!` spells them; `fp::CORE_FP` folds the three blocks here (records.rs, host.rs,
/// need.rs, in that order) and then busbar-ffi's three (`busbar_ffi::MECHANISM`) with `fp`'s whitespace-blind FNV-1a, so a token or doc change in any
/// block moves CORE_FP and the pin in `ci/abi.pin` fails until it is moved with it. The rustc pin there covers
/// token-spelling drift (r4 §3.2). Each block holds only the `#[repr(C)]`/Pod type definitions and `pub const`
/// items §7.5 lists; impl blocks, the safe API, slots and the bridge stay outside, so refactoring them never
/// moves CORE_FP.
///
/// W1-A1: the IF writes the matcher as `$(#[doc = $d:literal])* $item:item` with the doc values hashed through
/// `concat!`. In `macro_rules` that matcher is a local ambiguity (a `#` can open either the doc repetition or
/// the `item` fragment), so the block is taken as token trees and its docs are hashed where they stand.
macro_rules! mechanism {
    ($($item:tt)*) => {
        $($item)*
        /// This block's tokens, doc comments included (IF §7.5); `fp::CORE_FP` folds it.
        pub(crate) const MECHANISM_BLOCK: &str = stringify!($($item)*);
    };
}

#[doc(hidden)]
pub mod bridge;
pub mod fail;
pub mod fallback_usage;
pub mod fp;
pub mod host;
#[cfg(feature = "host")]
pub mod host_side;
pub mod kind;
pub mod kinds;
#[cfg(feature = "memio")]
pub mod memio;
pub mod need;
pub mod plugin;
pub mod records;
pub mod resource_admission;
/// Wiping byte storage shared with the core contract; plugins name only this facade.
pub mod secure {
    pub use busbar_secure::{Overflow, SecureVec, Tail};
}
pub mod slots;
pub mod stamp;
pub mod types;
pub mod versions;

pub use kinds::auth::{Auth, auth};
pub use kinds::export::{Export, export};
pub use kinds::hook::{Hook, hook};
pub use kinds::plane::{Plane, plane};
pub use kinds::secret::{Secret, secret};
pub use kinds::store::{Store, store};
pub use kinds::transport::{Transport, transport};

/// `export!` emits the one exported symbol (IF §7.7). It is busbar-ffi's, the only macro that crate exports,
/// because its `#[unsafe(no_mangle)]` is the one `unsafe` token a plugin's cdylib crate cannot avoid.
pub use busbar_ffi::export;
