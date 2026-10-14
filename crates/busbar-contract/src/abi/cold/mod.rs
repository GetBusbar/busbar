// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! M6-COLD-DELETE RESIDUE: no plugin of any kind rides the COLD/JSON lane any more, and its
//! `open`/`call`/`free`/`close` symbols, log sink, status codes and linked entry are gone with its
//! SDK. What is left is what the HOT lane's loader still shares with it: the handshake a plane or
//! transport image answers before its decl is read (`busbar_abi()`, `busbar_plugin_kind()`) —
//! deleted with the HOT lane. Nothing new may ride this lane.

/// The kind-neutral **TRANSPORT** ABI version, returned by a plugin's `busbar_abi()`. Frozen at 1:
/// this is the low-level linker contract. DISTINCT from the per-kind PAYLOAD schema version (the
/// signed manifest's `abi_version`), which bumps additively per kind. Bumping THIS is a real,
/// no-turning-back linker event — side-by-side migration, never a routine change.
pub const TRANSPORT_VERSION: u32 = 1;

/// The handshake's exported-symbol names the loader resolves after `dlopen`/`LoadLibrary`,
/// NUL-terminated so they pass straight to `libloading`'s C-string symbol lookup. The KIND a library
/// speaks is read from [`symbol::PLUGIN_KIND`], not encoded in the symbol names.
pub mod symbol {
    /// `busbar_abi() -> u32` — the frozen TRANSPORT version handshake ([`super::TRANSPORT_VERSION`]).
    pub const ABI: &[u8] = b"busbar_abi\0";
    /// `busbar_plugin_kind() -> *const u8` — a NUL-terminated string, the ONE kind this lib speaks.
    pub const PLUGIN_KIND: &[u8] = b"busbar_plugin_kind\0";
}

// WHY `"C-unwind"` (not plain `"C"`): under the workspace default `panic = "unwind"`, a Rust panic
// that tries to unwind OUT OF a plain `extern "C"` function is turned by the compiler into an
// immediate ABORT at the callee (plugin) frame — it never reaches the caller, so the loader's
// `catch_unwind` at the call site can NEVER intercept it. `extern "C-unwind"` makes unwinding across
// this boundary DEFINED, so the loader's guard turns a panicking handshake into a clean fail-closed
// error instead of a process abort.

/// `busbar_abi` — returns the [`TRANSPORT_VERSION`] the plugin was built against.
pub type AbiFn = unsafe extern "C-unwind" fn() -> u32;

/// `busbar_plugin_kind` — returns a pointer to a NUL-terminated static string naming the ONE kind
/// this library speaks.
///
/// The return carries NO LENGTH: the engine reads it with `CStr::from_ptr` and walks to the first
/// NUL byte. A pointer into a non-NUL-terminated buffer is therefore an unbounded out-of-bounds read
/// in the ENGINE's address space — undefined behavior, not a load error. So the pointer MUST come
/// from a NUL-terminated static; the SDK's door (`abi::sdk::__door`) answers with one.
pub type PluginKindFn = unsafe extern "C-unwind" fn() -> *const u8;
