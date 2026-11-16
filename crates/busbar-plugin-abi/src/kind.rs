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

/// `kind!` and `plugin!` over every one of busbar-ffi's seven layouts: each test kind states its kind's full
/// method list (its table needs every slot), a fixture plugin implements it, and `plugin!` builds the header.
#[cfg(test)]
mod tests {
    use crate::fail::{Fail, refused};
    use crate::host::Host;
    use crate::need::ChainBytes;
    use crate::plugin::{Describe, Endpoints, Open};
    use crate::records::{Out, Reply, Writer};

    crate::kind! {
        /// A store-shaped test kind.
        pub trait TStore: kind = 1, abi = 3 {
            views {}
            pods {
                /// One row head.
                pub struct RowRec { pub key_len: u32, pub _r: u32 }
            }
            tags {
                /// A row.
                ROW = 0x0100;
                D_ROWS = 0x0180;
            }
            consts {
                REQUIRED: u64 = 0b1_1111;
                M_READ: u64 = 1 << 0;
            }
            async fn read(&self, h: &'static Host, req: ChainBytes) -> Result<Reply, Fail> {
                let _ = (h, req);
                Err(crate::fail::Fail::unsupported())
            }
            async fn scan(&self, h: &'static Host, req: ChainBytes) -> Result<Reply, Fail> {
                let _ = (h, req);
                Err(crate::fail::Fail::unsupported())
            }
            async fn commit(&self, h: &'static Host, req: ChainBytes) -> Result<Reply, Fail> {
                let _ = (h, req);
                Err(crate::fail::Fail::unsupported())
            }
            async fn clock(&self, h: &'static Host, req: ChainBytes) -> Result<Reply, Fail> {
                let _ = (h, req);
                Err(crate::fail::Fail::unsupported())
            }
            sync fn info(&self, h: &Host, out: &mut Out<'_>) -> Result<(), Fail> {
                let _ = (h, out);
                Ok(())
            }
        }
    }

    crate::kind! {
        /// A secret-shaped test kind.
        pub trait TSecret: kind = 2, abi = 2 {
            views {}
            pods {}
            tags { VALUE = 0x0100; }
            consts { REQUIRED: u64 = 0b1; }
            async fn resolve(&self, h: &'static Host, reference: ChainBytes) -> Result<Reply, Fail>;
        }
    }

    crate::kind! {
        /// An auth-shaped test kind.
        pub trait TAuth: kind = 3, abi = 3 {
            views {
                pub struct AuthReq<'a> {
                    pub flags: u32,
                    pub _r: u32,
                    pub method: Str<'a>,
                    pub path: Str<'a>,
                    pub query: Str<'a>,
                    pub authority: Str<'a>,
                    pub headers: Slice<'a, Pair<'a>>,
                    pub peer: Str<'a>,
                    pub tls_peer_cert: Bytes<'a>,
                    pub body: Bytes<'a>,
                    pub issued: Bytes<'a>,
                    pub now_s: u64,
                }
            }
            pods {}
            tags { GRANT = 0x010A; }
            consts { REQUIRED: u64 = 0b1; }
            /// The sync verify.
            sync fn verify(&self, h: &Host, req: &AuthReq<'_>, out: &mut Out<'_>) -> Result<(), Fail>;
            async fn verify_io(&self, h: &'static Host, req: ChainBytes) -> Result<Reply, Fail> {
                let _ = (h, req);
                Err(crate::fail::Fail::unsupported())
            }
            async fn login(&self, h: &'static Host, step: u32, input: ChainBytes) -> Result<Reply, Fail> {
                let _ = (h, step, input);
                Err(crate::fail::Fail::unsupported())
            }
            async fn outbound(&self, h: &'static Host, req: ChainBytes) -> Result<Reply, Fail> {
                let _ = (h, req);
                Err(crate::fail::Fail::unsupported())
            }
            async fn refresh(&self, h: &'static Host) -> Result<Reply, Fail> {
                let _ = h;
                Err(crate::fail::Fail::unsupported())
            }
            async fn serve(&self, h: &'static Host, req: ChainBytes) -> Result<Reply, Fail> {
                let _ = (h, req);
                Err(crate::fail::Fail::unsupported())
            }
        }
    }

    crate::kind! {
        /// A hook-shaped test kind.
        pub trait THook: kind = 4, abi = 2 {
            views {}
            pods {}
            tags {}
            consts { REQUIRED: u64 = 0b1; }
            sync fn on(&self, h: &Host, point: u32, view: Bytes<'_>, out: &mut Out<'_>) -> Result<(), Fail> {
                let _ = (h, point, view, out);
                Ok(())
            }
            async fn on_io(&self, h: &'static Host, point: u32, view: ChainBytes) -> Result<Reply, Fail> {
                let _ = (h, point, view);
                Err(crate::fail::Fail::unsupported())
            }
        }
    }

    crate::kind! {
        /// An export-shaped test kind.
        pub trait TExport: kind = 5, abi = 3 {
            views {}
            pods {}
            tags {}
            consts { REQUIRED: u64 = 0b1; }
            async fn deliver(
                &self, h: &'static Host, stream: u32, delivery: u64, attempt: u32, batch: ChainBytes
            ) -> Result<Reply, Fail> {
                let _ = (h, stream, delivery, attempt, batch);
                Ok(crate::records::Reply::new())
            }
            sync fn render(&self, h: &Host, stream: u32, snapshot: Bytes<'_>, out: &mut Out<'_>) -> Result<(), Fail> {
                let _ = (h, stream, snapshot, out);
                Err(crate::fail::Fail::unsupported())
            }
            async fn confirm(&self, h: &'static Host, delivery: u64) -> Result<Reply, Fail> {
                let _ = (h, delivery);
                Err(crate::fail::Fail::unsupported())
            }
        }
    }

    crate::kind! {
        /// A plane-shaped test kind.
        pub trait TPlane: kind = 6, abi = 1, session {
            views {
                pub struct PlaneReq<'a> {
                    pub route: u32,
                    pub flags: u32,
                    pub auth: u32,
                    pub _r: u32,
                    pub method: Str<'a>,
                    pub path: Str<'a>,
                    pub query: Str<'a>,
                    pub headers: Slice<'a, Pair<'a>>,
                    pub identity: Bytes<'a>,
                    pub request_id: u64,
                    pub carrier: u64,
                    pub work: Str<'a>,
                    pub ticket_record: Bytes<'a>,
                }
                pub struct Target<'a> {
                    pub attempt: u32,
                    pub flags: u32,
                    pub dialect: Str<'a>,
                    pub model: Str<'a>,
                    pub base_path: Str<'a>,
                    pub upstream: Str<'a>,
                    pub provider: Str<'a>,
                    pub params: Slice<'a, Pair<'a>>,
                }
            }
            pods {}
            tags {}
            consts { REQUIRED: u64 = 0b1111; }
            sync open fn request(&self, h: &Host, req: &PlaneReq<'_>, body: Bytes<'_>, out: &mut Out<'_>) -> Result<Session, Fail>;
            sync fn upstream(&self, h: &Host, s: &mut Session, t: &Target<'_>, out: &mut Out<'_>) -> Result<(), Fail> {
                let _ = (h, s, t, out);
                Ok(())
            }
            sync fn piece(
                &self, h: &Host, s: &mut Session, stream: u32, kind: u32, flags: u32, bytes: Bytes<'_>, out: &mut Out<'_>
            ) -> Result<(), Fail> {
                let _ = (h, s, stream, kind, flags, bytes, out);
                Ok(())
            }
            sync end fn end(&self, h: &Host, s: Session, out: &mut Out<'_>) -> Result<(), Fail>;
            sync fn rewrite(&self, h: &Host, s: &mut Session, bytes: Bytes<'_>, out: &mut Out<'_>) -> Result<(), Fail> {
                let _ = (h, s, bytes, out);
                Err(crate::fail::Fail::unsupported())
            }
            sync fn render(&self, h: &Host, req: &PlaneReq<'_>, code: u32, body: Bytes<'_>, out: &mut Out<'_>) -> Result<(), Fail> {
                let _ = (h, req, code, body, out);
                Err(crate::fail::Fail::unsupported())
            }
            async fn admin(&self, h: &'static Host, op: u32, body: ChainBytes) -> Result<Reply, Fail> {
                let _ = (h, op, body);
                Err(crate::fail::Fail::unsupported())
            }
            sync open fn probe(&self, h: &Host, t: &Target<'_>, out: &mut Out<'_>) -> Result<Session, Fail> {
                let _ = (h, t, out);
                Err(crate::fail::Fail::unsupported())
            }
            sync fn demux(&self, h: &Host, path: Str<'_>, body: Bytes<'_>, out: &mut Out<'_>) -> Result<(), Fail> {
                let _ = (h, path, body, out);
                Err(crate::fail::Fail::unsupported())
            }
        }
    }

    crate::kind! {
        /// A transport-shaped test kind.
        pub trait TTransport: kind = 7, abi = 1, session {
            views {
                pub struct ConnInfo<'a> {
                    pub role: u32,
                    pub flags: u32,
                    pub alpn: Str<'a>,
                    pub sni: Str<'a>,
                    pub peer: Str<'a>,
                    pub local: Str<'a>,
                    pub tls_peer_cert: Bytes<'a>,
                    pub leftover: Bytes<'a>,
                    pub head: Bytes<'a>,
                    pub local_fingerprint: Str<'a>,
                    pub mono_ns: u64,
                }
            }
            pods {}
            tags {}
            consts { REQUIRED: u64 = 0b111_1111; }
            sync open fn begin(&self, h: &Host, conn: &ConnInfo<'_>, out: &mut Out<'_>) -> Result<Session, Fail>;
            sync fn ingest(&self, h: &Host, s: &mut Session, bytes: Bytes<'_>, out: &mut Out<'_>) -> Result<(), Fail> {
                let _ = (h, s, bytes, out);
                Ok(())
            }
            sync fn emit(
                &self, h: &Host, s: &mut Session, stream: u64, kind: u32, flags: u32, bytes: Bytes<'_>, out: &mut Out<'_>
            ) -> Result<(), Fail> {
                let _ = (h, s, stream, kind, flags, bytes, out);
                Ok(())
            }
            sync fn timer(&self, h: &Host, s: &mut Session, out: &mut Out<'_>) -> Result<(), Fail> {
                let _ = (h, s, out);
                Ok(())
            }
            sync fn datagram(
                &self, h: &Host, s: &mut Session, from: u32, flags: u32, bytes: Bytes<'_>, out: &mut Out<'_>
            ) -> Result<(), Fail> {
                let _ = (h, s, from, flags, bytes, out);
                Ok(())
            }
            sync fn event(&self, h: &Host, s: &mut Session, ev: u32, arg: Bytes<'_>, out: &mut Out<'_>) -> Result<(), Fail> {
                let _ = (h, s, ev, arg, out);
                Ok(())
            }
            sync fn offer(&self, h: &Host, role: u32, out: &mut Out<'_>) -> Result<(), Fail> {
                let _ = (h, role, out);
                Ok(())
            }
        }
    }

    /// One fixture per kind: `Open` that answers at once, the kind's required methods, and `plugin!`.
    macro_rules! fixture {
        ($m:ident, $kind:ident, { $($body:tt)* }) => {
            mod $m {
                use super::*;
                pub struct Fx;
                impl super::$kind::Trait for Fx { $($body)* }
                impl Open for Fx {
                    async fn open(_h: &'static Host, _config: ChainBytes) -> Result<Self, Fail> {
                        Ok(Fx)
                    }
                    fn check(_h: &Host, config: &[u8], ends: &mut Endpoints<'_>) -> Result<(), Fail> {
                        if config == b"dial" {
                            ends.open("db.internal:5432", crate::need::need_flag::TLS_REQUIRED, 2);
                        }
                        Ok(())
                    }
                    fn describe(d: &mut Describe<'_>) {
                        d.errors(&[7070, 7071]);
                    }
                }
                crate::plugin!(@kind [super::$kind] Fx);
            }
        };
    }

    // `kind!` re-exports each trait beside its module; the fixture macro names it through an alias module.
    mod store_k {
        pub use super::TStore as Trait;
        pub use super::store::*;
    }
    mod secret_k {
        pub use super::TSecret as Trait;
        pub use super::secret::*;
    }
    mod auth_k {
        pub use super::TAuth as Trait;
        pub use super::auth::*;
    }
    mod hook_k {
        pub use super::THook as Trait;
        pub use super::hook::*;
    }
    mod export_k {
        pub use super::TExport as Trait;
        pub use super::export::*;
    }
    mod plane_k {
        pub use super::TPlane as Trait;
        pub use super::plane::*;
    }
    mod transport_k {
        pub use super::TTransport as Trait;
        pub use super::transport::*;
    }

    fixture!(store_fx, store_k, {});
    fixture!(secret_fx, secret_k, {
        async fn resolve(&self, _h: &'static Host, _reference: ChainBytes) -> Result<Reply, Fail> {
            let mut value = Reply::new();
            value
                .put(super::secret::tag::VALUE, b"s3cret")
                .map_err(Fail::from)?;
            Ok(value)
        }
    });
    fixture!(auth_fx, auth_k, {
        fn verify(
            &self,
            _h: &Host,
            req: &super::auth::AuthReq<'_>,
            out: &mut Out<'_>,
        ) -> Result<(), Fail> {
            if req.flags == 1 {
                // Written, then discarded by the shim (§6.4 step 2).
                out.put(super::auth::tag::GRANT, b"secret grant")
                    .map_err(Fail::from)?;
                return Err(
                    Fail::refused_because(refused::R_BAD_CREDENTIAL, "bad").with_error(7071)
                );
            }
            out.put(super::auth::tag::GRANT, b"ok").map_err(Fail::from)
        }
    });
    fixture!(hook_fx, hook_k, {});
    fixture!(export_fx, export_k, {});
    fixture!(plane_fx, plane_k, {
        type Session = u32;
        fn request(
            &self,
            _h: &Host,
            _req: &super::plane::PlaneReq<'_>,
            _body: crate::types::Bytes<'_>,
            _out: &mut Out<'_>,
        ) -> Result<u32, Fail> {
            Ok(1)
        }
        fn end(&self, _h: &Host, _s: u32, _out: &mut Out<'_>) -> Result<(), Fail> {
            Ok(())
        }
    });
    fixture!(transport_fx, transport_k, {
        type Session = ();
        fn begin(
            &self,
            _h: &Host,
            _conn: &super::transport::ConnInfo<'_>,
            _out: &mut Out<'_>,
        ) -> Result<(), Fail> {
            Ok(())
        }
    });

    /// The macros expand for every kind (WBS W1-A4 "Done"): each table is built over its fixture's image and
    /// each kind module states its numbers.
    #[test]
    fn every_kind_expands_and_builds_its_header() {
        use crate::types::KindCode;
        let kinds = [
            (
                store::KIND,
                store::ABI,
                store::ALL,
                store::FP,
                KindCode::Store,
            ),
            (
                secret::KIND,
                secret::ABI,
                secret::ALL,
                secret::FP,
                KindCode::Secret,
            ),
            (auth::KIND, auth::ABI, auth::ALL, auth::FP, KindCode::Auth),
            (hook::KIND, hook::ABI, hook::ALL, hook::FP, KindCode::Hook),
            (
                export::KIND,
                export::ABI,
                export::ALL,
                export::FP,
                KindCode::Export,
            ),
            (
                plane::KIND,
                plane::ABI,
                plane::ALL,
                plane::FP,
                KindCode::Plane,
            ),
            (
                transport::KIND,
                transport::ABI,
                transport::ALL,
                transport::FP,
                KindCode::Transport,
            ),
        ];
        for (kind, abi, _, fp, code) in kinds {
            assert_eq!(kind, code);
            assert_eq!(abi, crate::versions::abi_of(code));
            assert_ne!(fp, 0, "{code:?}: kind! computes FP");
        }
        let alls: Vec<u64> = kinds.iter().map(|k| k.2).collect();
        assert_eq!(
            alls,
            [
                0b1_1111,
                0b1,
                0b11_1111,
                0b11,
                0b111,
                0b1_1111_1111,
                0b111_1111
            ]
        );
        let mut fps: Vec<u64> = kinds.iter().map(|k| k.3).collect();
        fps.sort_unstable();
        fps.dedup();
        assert_eq!(fps.len(), 7, "every kind block hashes to its own FP");
        assert_eq!(store::tag::ROW, 0x0100);
        assert_eq!(core::mem::size_of::<store::RowRec>(), 8);
        for header in [
            store_fx::PLUGIN.as_ptr(),
            secret_fx::PLUGIN.as_ptr(),
            auth_fx::PLUGIN.as_ptr(),
            hook_fx::PLUGIN.as_ptr(),
            export_fx::PLUGIN.as_ptr(),
            plane_fx::PLUGIN.as_ptr(),
            transport_fx::PLUGIN.as_ptr(),
        ] {
            assert!(!header.is_null());
        }
    }

    /// The default bodies are not hashed; the signatures and docs are (IF §7.5).
    #[test]
    fn the_fingerprint_covers_signatures_not_default_bodies() {
        mod a {
            crate::kind! {
                pub trait B: kind = 2, abi = 2 {
                    views {} pods {} tags {} consts { REQUIRED: u64 = 0b1; }
                    async fn resolve(&self, h: &'static Host, reference: ChainBytes) -> Result<Reply, Fail> {
                        let _ = (h, reference);
                        Ok(crate::records::Reply::new())
                    }
                }
            }
        }
        mod b {
            crate::kind! {
                pub trait B: kind = 2, abi = 2 {
                    views {} pods {} tags {} consts { REQUIRED: u64 = 0b1; }
                    async fn resolve(&self, h: &'static Host, reference: ChainBytes) -> Result<Reply, Fail> {
                        let _ = (h, reference);
                        Err(crate::fail::Fail::unsupported())
                    }
                }
            }
        }
        mod c {
            crate::kind! {
                pub trait B: kind = 2, abi = 2 {
                    views {} pods {} tags {} consts { REQUIRED: u64 = 0b1; }
                    /// A doc line moves the fingerprint.
                    async fn resolve(&self, h: &'static Host, reference: ChainBytes) -> Result<Reply, Fail> {
                        let _ = (h, reference);
                        Err(crate::fail::Fail::unsupported())
                    }
                }
            }
        }
        // a and b differ only in a default body; b and c only by one doc line.
        assert_eq!(a::secret::FP, b::secret::FP, "a default body is not hashed");
        assert_ne!(b::secret::FP, c::secret::FP, "a method doc is hashed");
    }

    #[cfg(feature = "host")]
    mod run {
        use super::*;
        use crate::host::HostFns;
        use crate::plugin::__rt::host::{OpenAnswer, OutLease};
        use crate::plugin::__rt::image::Admitted;
        use crate::plugin::__rt::{Arg, kind as marker};
        use crate::records::{FailRec, MaskRec, Records, U32Rec, tag};
        use crate::types::{Bytes, Slice, Status, Str};

        static HOST: Host = Host::new(
            0,
            HostFns {
                now: None,
                mono: None,
                random: None,
                crypto: None,
                log: None,
                log_level: None,
                grow: None,
                deployment: None,
                migrate_admit: None,
            },
        );

        fn lease() -> OutLease {
            OutLease::new(vec![0; 4096], 1 << 20).expect("a free ACTIVE slot")
        }

        fn tags(lease: &OutLease) -> Vec<u16> {
            lease.with_answer(|answer| {
                Records::new(answer)
                    .map(|rec| rec.expect("framing").tag)
                    .collect()
            })
        }

        fn admitted(plugin: &'static crate::plugin::__rt::LinkedPlugin) -> Admitted {
            match Admitted::linked(plugin) {
                Ok(admitted) => admitted,
                Err(e) => panic!("admit: {e:?}"),
            }
        }

        /// Every table is whole (no null entry) and the stamp names the kind.
        #[test]
        fn every_header_admits() {
            for plugin in [
                &store_fx::PLUGIN,
                &secret_fx::PLUGIN,
                &auth_fx::PLUGIN,
                &hook_fx::PLUGIN,
                &export_fx::PLUGIN,
                &plane_fx::PLUGIN,
                &transport_fx::PLUGIN,
            ] {
                assert_eq!(admitted(plugin).null_field(), None);
            }
            assert_eq!(
                admitted(&auth_fx::PLUGIN).kind(),
                Some(crate::types::KindCode::Auth)
            );
        }

        /// describe: the plugin's D_ERRORS, then the default D_METHODS = REQUIRED.
        #[test]
        fn describe_declares_required_methods_by_default() {
            let mut out = lease();
            let status = admitted(&transport_fx::PLUGIN).describe(&HOST, &mut out);
            assert_eq!(status, Status::OK);
            assert_eq!(tags(&out), [tag::D_ERRORS, tag::D_METHODS]);
            out.with_answer(|answer| {
                let recs: Vec<_> = Records::new(answer).map(|r| r.expect("rec")).collect();
                assert_eq!(
                    recs[0].body,
                    [0x9E, 0x1B, 0x9F, 0x1B],
                    "7070, 7071 little-endian"
                );
                assert_eq!(
                    recs[1].pod::<MaskRec>().expect("mask").mask,
                    transport::REQUIRED
                );
            });
        }

        /// A sync method's Ok keeps its records; its Err discards them and answers FAIL then ERROR (§6.4 step 2).
        #[test]
        fn a_sync_err_is_one_fail_and_its_error_number() {
            let mut out = lease();
            let OpenAnswer::Done(Status::OK, Some(inst)) =
                admitted(&auth_fx::PLUGIN).open::<marker::Auth>(&HOST, b"{}".to_vec(), 0, &mut out)
            else {
                panic!("open answers OK with INSTANCE");
            };
            assert_eq!(tags(&out), [tag::INSTANCE]);
            drop(out);
            let mut req = super::auth::AuthReq {
                flags: 0,
                _r: 0,
                method: Str::EMPTY,
                path: Str::EMPTY,
                query: Str::EMPTY,
                authority: Str::EMPTY,
                headers: Slice::EMPTY,
                peer: Str::EMPTY,
                tls_peer_cert: Bytes::EMPTY,
                body: Bytes::EMPTY,
                issued: Bytes::EMPTY,
                now_s: 0,
            };
            let mut out = lease();
            assert_eq!(
                inst.call1(|vt| &vt.verify, Arg::view(&req), &mut out),
                Status::OK
            );
            assert_eq!(tags(&out), [super::auth::tag::GRANT]);
            drop(out);
            req.flags = 1;
            let mut out = lease();
            assert_eq!(
                inst.call1(|vt| &vt.verify, Arg::view(&req), &mut out),
                Status::REFUSED
            );
            assert_eq!(tags(&out), [tag::FAIL, tag::ERROR]);
            out.with_answer(|answer| {
                let recs: Vec<_> = Records::new(answer).map(|r| r.expect("rec")).collect();
                let (head, text) = recs[0].pod_tail::<FailRec>().expect("fail");
                assert_eq!(
                    (head.status, head.code, text),
                    (1, refused::R_BAD_CREDENTIAL, &b"bad"[..])
                );
                assert_eq!(recs[1].pod::<U32Rec>().expect("error").value, 7071);
            });
        }

        /// DRY_RUN runs `check`: its endpoints are the answer (round 32).
        #[test]
        fn dry_run_answers_the_declared_endpoints() {
            let mut out = lease();
            let OpenAnswer::Done(status, None) = admitted(&store_fx::PLUGIN).open::<marker::Store>(
                &HOST,
                b"dial".to_vec(),
                crate::plugin::OPEN_DRY_RUN,
                &mut out,
            ) else {
                panic!("DRY_RUN has no instance");
            };
            assert_eq!(status, Status::OK);
            assert_eq!(tags(&out), [tag::ENDPOINT]);
        }

        /// An async method that answers at once: its Reply is the answer, with no chain left behind.
        #[test]
        fn an_async_method_ready_at_once_answers_its_reply() {
            use crate::plugin::__rt::host::Started;
            let mut out = lease();
            let OpenAnswer::Done(Status::OK, Some(inst)) =
                admitted(&secret_fx::PLUGIN).open::<marker::Secret>(&HOST, Vec::new(), 0, &mut out)
            else {
                panic!("open answers OK with INSTANCE");
            };
            drop(out);
            let mut out = lease();
            let started = inst.start1(
                |vt| &vt.resolve,
                Default::default(),
                |_| Arg::bytes(Bytes::EMPTY),
                &mut out,
            );
            assert!(matches!(started, Started::Done(Status::OK)));
            assert_eq!(tags(&out), [super::secret::tag::VALUE]);
        }
    }
}
