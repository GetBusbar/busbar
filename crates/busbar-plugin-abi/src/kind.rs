// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `kind!` macro that declares a kind trait and its module (IF §7.6). W0-ABI stub: frozen signatures, `todo!()` bodies; A4 fills it.

/// Declares one kind: its trait, its module (views, pods, tags, consts, KIND, ABI, FP, `M_*`, ALL, the raw `Vt`
/// and its shims) and, under feature `host`, its Proxy and SessionHandle (IF §7.6). W0-ABI stub: every
/// invocation is a compile error until W1-A4 lands the macro; the frozen contract follows.
///
/// ```text
/// **Grammar** (the builder of `kind.rs` implements exactly this, via a tt-muncher):
///
/// kind! {
///     $(#[doc = $d:literal])*
///     pub trait $Trait:ident : kind = $kind:literal, abi = $abi:literal $(, session)? {
///         views  { $( $(#[doc = $vd:literal])* pub struct $V:ident<'a> { $( pub $vf:ident : $vt:ty ),* $(,)? } )* }
///         pods   { $( $(#[doc = $pd:literal])* pub struct $P:ident { $( pub $pf:ident : $pt:ty ),* $(,)? } )* }
///         tags   { $( $(#[doc = $td:literal])* $TAG:ident = $tv:literal ; )* }
///         consts { $( $(#[doc = $cd:literal])* $C:ident : $ct:ty = $cv:expr ; )* }
///         $(
///             $(#[doc = $md:literal])*
///             sync fn $m:ident ( &self, h: &Host $(, $a:ident : $at:ty)* , out: &mut Out<'_> ) -> Result<(), Fail> $( $def:block )? ;
///         |   // session kinds only: opener (shim mints the token, §6.4 step 7)
///             $(#[doc = $md:literal])*
///             sync open fn $m:ident ( &self, h: &Host $(, $a:ident : $at:ty)* , out: &mut Out<'_> ) -> Result<Session, Fail> $( $def:block )? ;
///         |   // session kinds only: method on a live session (raw arg: tok: Token)
///             $(#[doc = $md:literal])*
///             sync fn $m:ident ( &self, h: &Host, s: &mut Session $(, $a:ident : $at:ty)* , out: &mut Out<'_> ) -> Result<(), Fail> $( $def:block )? ;
///         |   // session kinds only: consumes the session (the shim removes it before the call)
///             $(#[doc = $md:literal])*
///             sync end fn $m:ident ( &self, h: &Host, s: Session $(, $a:ident : $at:ty)* , out: &mut Out<'_> ) -> Result<(), Fail> ;
///         |
///             $(#[doc = $md:literal])*
///             async fn $m:ident ( &self, h: &'static Host $(, $a:ident : $at:ty)* ) -> Result<Reply, Fail> $( $def:block )? ;
///         )*
///     }
/// }
///
/// **No `migrate` rule (round 31, owner ruling, §47; supersedes round 5's "one `migrate` rule").** `kind.rs` emits
/// no `migrate` method on any kind trait, and `plugin!` wires no `migrate` slot (there is none, §7.1). A plugin's
/// migration is its `Open::open`, and its canonical settings come back through `Open::settled` (§7.2). `abi::settled`
/// (in `records.rs`, A1) is two plain functions: `config(w, bag: &[u8])` and `core_cfg(w, section, name, value_json:
/// &[u8])` (round 5's `abi::migrate::{answer, core_cfg, echo}` are deleted). `R_VERSION` is generic refusal code 17
/// (§4.1). Old-format code a plugin needs lives in its own `migrate` module, reachable only from `open`, `check`
/// and `settled` (§15.8).
///
/// With `session`, the emitted trait gets `type Session: Send + 'static;` and `Session` in the grammar means
/// `Self::Session`. Without it, the `open fn`/`end fn`/`s:` forms are a compile error. The raw `Vt` entry of a
/// session method takes `tok: Token` in place of `s`; `open fn` entries take no token and answer TOKEN first.
///
/// **It emits, for `pub trait Auth` (lowercase module = the trait name in snake case):**
///
/// 1. `pub trait Auth: Send + Sync + 'static` with one method per entry:
///    - sync: `fn verify(&self, h: &Host, req: &AuthReq<'_>, out: &mut Out<'_>) -> Result<(), Fail>;`, plus the default body if one is given;
///    - async: `fn login(&self, h: &'static Host, step: u32, input: ChainBytes) -> impl Future<Output = Result<Reply, Fail>> + Send;`.
///      A default body is wrapped as `async move $def`. Implementors write `async fn`;
/// 2. `pub mod auth`:
///    - the `views` structs with `#[repr(C)] #[derive(Clone, Copy)]`, `unsafe impl View`, and a const assert that
///      the size equals the sum of the field sizes;
///    - the `pods` structs with `#[repr(C)] #[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]` (zerocopy, round 8);
///    - `pub mod tag { pub const $TAG: u16 = $tv; }`, with a const assert that each value is in 0x0100..=0x01FF;
///    - the consts;
///    - `pub const KIND: KindCode`, `pub const ABI: u32` (const-asserted equal to `versions::<KIND>`), `pub const FP: u64`;
///    - `pub const M_<METHOD>: u64 = 1 << i` in declaration order, and `pub const ALL: u64`;
///    - `#[repr(C)] pub struct Vt { pub <m>: unsafe extern "C" fn(inst: *const c_void, h: *const Host, <raw args>, out: *mut RawOut) -> Status, .. }`.
///      Raw args: `&V<'_>` → `*const V<'static>`; `Bytes`/`Str` → `Bytes<'static>`/`Str<'static>`; `ChainBytes` → `Bytes<'static>`; `u32`/`u64`/`Token` unchanged;
///    - `pub const fn vt<T: Auth + Open>() -> Vt`, the shims. A sync shim is `entry(..)` (§6.4 step 0) → `&*inst`
///      → (session methods: resolve the token in the session slots, unknown/stale/chain-space token = FAULT
///      `BadToken`) → call → Ok: OK, Err: FAIL record. An async shim follows §6.4;
///    - `#[cfg(feature = "host")] pub struct Proxy` and, for session kinds, `pub struct SessionHandle` (§10.4); the
///      raw session and chain entries are private to the module.
/// 3. A compile error if a method argument is not `SyncArg` (sync) or `AsyncArg` (async).
///
/// `REQUIRED` is not emitted by `kind!`. Each kind declares it in `consts` (§8). The default `Describe` uses it.
///
/// ```
#[macro_export]
macro_rules! kind {
    ($($tt:tt)*) => {
        ::core::compile_error!("kind! lands with W1-A4 (IF §7.6)");
    };
}

/// Wave-0 pass-through for `kinds/*.rs`: emits its items unchanged, so each kind trait is written inside
/// `crate::kind::kind_stub! { .. }` where W1-A4's `kind!` invocation will stand. Nothing else uses it.
macro_rules! kind_stub {
    ($($item:item)*) => { $($item)* };
}
pub(crate) use kind_stub;
