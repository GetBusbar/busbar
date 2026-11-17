// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! busbar-ffi: the plugin boundary, and the only busbar crate that may hold `unsafe` (UNSAFE-MIN r3.1).
//!
//! **The rule (owner directive).** This crate exists only because native plugin code and the host call
//! each other across the C ABI, and those calls cannot be safe without costing speed. It is never a place
//! where any other `unsafe` can be parked. A non-plugin need for `unsafe` (allocators, ACLs, `AsyncFd`, OS
//! calls, anything else) uses a safe crate or goes to the owner; it never comes here. Its `unsafe` total
//! is pinned in the repository's `unsafe.yaml` and only falls:
//! - the files are pinned: `src/{lib,raw,header,vt,shim,slots,host,image}.rs`;
//!   any other file fails the check;
//! - every file's own token count is pinned, so `unsafe` cannot move between files to make room;
//! - the dependencies are pinned: `zerocopy`, and `libloading` and `object` behind feature `host`
//!   (plus `loom` only under `cfg(loom)`, for the slot model check);
//! - the dependents are pinned: busbar-plugin-abi, busbar-plugin-loader (`host`), busbar-plugin-test and
//!   plugin crates, which never enable `host`.
//!
//! **Layout.**
//! - `raw`: the C-layout values both sides share (views, `RawOut`/`Out`, `Status`, the host table, the
//!   branded crypto results, chain-scoped bytes).
//! - `header`: the plugin header, `LinkedPlugin`, `plugin()` and the one exported macro, `export!`.
//! - `vt`: the 7 kind tables, their fn-pointer aliases, the views they name and the sealed `Kind`.
//! - `shim`: the plugin-side entries and the safe adapter traits `kind!` implements.
//! - `slots`: the token table, the instance and the chain box.
//! - `host` and `image` (feature `host`): the loader's side: instances, sessions, chains, the out lease,
//!   the crypto arena, and dlopen with its bounds check.
//!
//! Every `unsafe` block carries a `// SAFETY:` comment; `unsafe_op_in_unsafe_fn`,
//! `clippy::undocumented_unsafe_blocks` and `clippy::multiple_unsafe_ops_per_block` are denied here and
//! never allowed below. No `build.rs`, no `include!`, no proc macro of this crate's own.

#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(clippy::multiple_unsafe_ops_per_block)]

/// The `mechanism!` block (IF §7.5), as busbar-plugin-abi has it: the items unchanged, plus their tokens
/// as `stringify!` spells them, which `CORE_FP` folds after plugin-abi's own blocks (UNSAFE-MIN §4.5).
macro_rules! mechanism {
    ($($item:tt)*) => {
        $($item)*
        /// This block's tokens, doc comments included; `MECHANISM` lists it for CORE_FP.
        pub(crate) const MECHANISM_BLOCK: &str = stringify!($($item)*);
    };
}

pub mod header;
#[cfg(feature = "host")]
pub mod host;
#[cfg(feature = "host")]
pub mod image;
pub mod raw;
pub mod shim;
pub mod slots;
pub mod vt;

pub use header::{LinkedPlugin, Plugin, StampBytes, plugin};
pub use raw::{
    Arg, Bytes, ChainBytes, CryptoReq, CryptoRet, Ctx, DeploymentId, EntryScope, Host, HostFns,
    KindCode, Out, Pair, RawLent, RawOut, Slice, Status, Str, TOKEN_SESSION, Token, View,
};
pub use slots::{ChainBox, ChainRef, Inst, OwnedSlot, Slots, pack, unpack};
pub use vt::{Built, Kind, VtEntry, kind};

/// busbar-ffi's `mechanism!` blocks in their fixed order (raw types, header, the 7 layouts and their
/// aliases). `fp::CORE_FP` in busbar-plugin-abi folds plugin-abi's blocks first, then these, so a layout
/// change here moves CORE_FP (UNSAFE-MIN §4.5; W1-A1F re-pins `ci/abi.pin`).
pub const MECHANISM: [&str; 3] = [
    raw::MECHANISM_BLOCK,
    header::MECHANISM_BLOCK,
    vt::MECHANISM_BLOCK,
];
