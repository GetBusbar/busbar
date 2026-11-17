// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `kind!` macro that declares a kind trait and its module (IF §7.6), over busbar-ffi's seven tables and
//! shims (UNSAFE-MIN r3.1): the macro writes no `unsafe` and no raw entry; per kind it emits the trait, the
//! module's items, one image type `Shim<T>` and its safe `busbar_ffi::shim` adapters.

/// Declares one kind: its trait, its module (views, pods, tags, consts, KIND, ABI, FP, ALL, the table and
/// the image's adapters) (IF §7.6).
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
///             sync fn $m:ident ( &self, h: &Host $(, $a:ident : $at:ty)* , out: &mut Out<'_> ) -> Result<(), Fail> ($def:block | ;)
///         |   // session kinds only: opener (shim mints the token, §6.4 step 7)
///             $(#[doc = $md:literal])*
///             sync open fn $m:ident ( &self, h: &Host $(, $a:ident : $at:ty)* , out: &mut Out<'_> ) -> Result<Session, Fail> ($def:block | ;)
///         |   // session kinds only: method on a live session (raw arg: tok: Token)
///             $(#[doc = $md:literal])*
///             sync fn $m:ident ( &self, h: &Host, s: &mut Session $(, $a:ident : $at:ty)* , out: &mut Out<'_> ) -> Result<(), Fail> ($def:block | ;)
///         |   // session kinds only: consumes the session (the shim removes it before the call)
///             $(#[doc = $md:literal])*
///             sync end fn $m:ident ( &self, h: &Host, s: Session $(, $a:ident : $at:ty)* , out: &mut Out<'_> ) -> Result<(), Fail> ;
///         |
///             $(#[doc = $md:literal])*
///             async fn $m:ident ( &self, h: &'static Host $(, $a:ident : $at:ty)* ) -> Result<Reply, Fail> ($def:block | ;)
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
/// ```
///
/// **What it emits** (W1-A4, against UNSAFE-MIN r3.1), for `pub trait Auth: kind = 3, ..`:
///
/// 1. `pub mod auth` (the module is named by the kind number, which names the busbar-ffi layout too) with:
///    - `pub trait Auth: Send + Sync + 'static`, one method per entry, re-exported beside the module. A sync
///      method keeps its signature; an async one returns `impl Future<Output = Result<Reply, Fail>> + Send`
///      (implementors write `async fn`), and its default body is wrapped as `async move $def`;
///    - each `views` struct as busbar-ffi's own view (`pub use`; busbar-ffi owns the four views and their
///      sealed `View`), with a const check that every field the block states exists with its type and that
///      the fields fill the struct;
///    - the `pods` as `#[repr(C)]` zerocopy structs with their `records::Pod` impl; `pub mod tag` (each tag
///      const-checked to 0x0100..=0x01FF); the consts;
///    - `KIND`, `ABI` (const-checked against `versions::abi_of`), `FP`, `ALL`, `Marker` (busbar-ffi's kind
///      marker) and `Vt` (busbar-ffi's table for the kind);
///    - `Shim<T>`, the image of plugin type `T`, with its `busbar_ffi::shim::Image` impl and one adapter per
///      method (`Call0..3`, `Opener1..2`, `Session0..4`, `End0`, `Start0/1/2/4`, slot = declaration order),
///      and `pub const fn vt<T>()`, the kind's table built over `Shim<T>`.
/// 2. A compile error for a method argument that is not one of the FFI shapes (sync: `u32`, `u64`,
///    `Bytes<'_>`, `Str<'_>`, `&View<'_>`; async: `u32`, `u64`, `ChainBytes`).
///
/// Two departures from the IF text, both forced (MIN3-RULINGS-COORD, W1-A4): `macro_rules` cannot change an
/// identifier's case and the owner bans `paste` (UNSAFE-MIN E8), so a kind block states its `M_<METHOD>: u64 =
/// 1 << i;` lines in `consts` and `kind!` emits `ALL` (and checks `REQUIRED` against it); and the `Proxy` and
/// `SessionHandle` of §10.4 are not templated here: busbar-ffi's `Instance`, `Session` and `Chain` are the host
/// handles (UNSAFE-MIN §4.5, "9 `unsafe impl`s deleted"), so each kind states its typed proxy by hand over them
/// (W1-A4b, `host_side/proxy.rs` holds the shared halves). A kind block may end with `extras { items }`, hand-written
/// module items (typed helpers, those proxies, unit tests) that sit in the module and are not in `FP`.
///
/// `REQUIRED` is not emitted by `kind!`. Each kind declares it in `consts` (§8). The default `Describe` uses it.
#[macro_export]
macro_rules! kind {
    // ---- the kind number names the module, the busbar-ffi layout and the KindCode ----
    (@number 1 $($rest:tt)*) => { $crate::kind! { @module store Store $($rest)* } };
    (@number 2 $($rest:tt)*) => { $crate::kind! { @module secret Secret $($rest)* } };
    (@number 3 $($rest:tt)*) => { $crate::kind! { @module auth Auth $($rest)* } };
    (@number 4 $($rest:tt)*) => { $crate::kind! { @module hook Hook $($rest)* } };
    (@number 5 $($rest:tt)*) => { $crate::kind! { @module export Export $($rest)* } };
    (@number 6 $($rest:tt)*) => { $crate::kind! { @module plane Plane $($rest)* } };
    (@number 7 $($rest:tt)*) => { $crate::kind! { @module transport Transport $($rest)* } };

    (@module $m:ident $K:ident [$(#[$doc:meta])*] $Trait:ident $kind:tt $abi:tt [$($session:ident)?]
        [$($views:tt)*] [$($pods:tt)*] [$($tags:tt)*] [$($consts:tt)*] [$($methods:tt)*]
    ) => {
        pub mod $m {
            $crate::kind! { @views $($views)* }
            $crate::kind! { @pods $($pods)* }
            /// The kind's tags: 0x0100..=0x017F call records, 0x0180..=0x01FF describe items.
            pub mod tag {
                $crate::kind! { @tags $($tags)* }
            }
            $crate::kind! { @consts $($consts)* }

            /// The kind code a stamp of this kind carries.
            pub const KIND: $crate::types::KindCode = $crate::types::KindCode::$K;
            /// This kind's ABI version.
            pub const ABI: u32 = $abi;
            const _: () = assert!(KIND as u32 == $kind, "the kind number names another kind");
            const _: () = assert!(
                ABI == $crate::versions::abi_of(KIND),
                "abi is not versions::<KIND>"
            );
            /// busbar-ffi's marker for this kind (its sealed `Kind`), which names the table layout.
            pub type Marker = $crate::plugin::__rt::kind::$K;
            /// The kind's table: busbar-ffi owns the seven layouts (UNSAFE-MIN r3.1).
            pub use $crate::plugin::__rt::vt::$m::Vt;

            /// What `FP` hashes before the method signatures (IF §7.5): the header, every doc, the four blocks.
            const FP_HEAD: &str = stringify!(
                $(#[$doc])* pub trait $Trait: kind = $kind, abi = $abi $(, $session)?
                views { $($views)* } pods { $($pods)* } tags { $($tags)* } consts { $($consts)* }
            );

            /// The image of plugin type `T`: busbar-ffi's shims call `T` through it.
            pub struct Shim<T>(::core::marker::PhantomData<fn() -> T>);

            /// The kind's table built over `Shim<T>`: every entry is busbar-ffi's shim for this image.
            pub const fn vt<T: $Trait + $crate::plugin::Glue>(
            ) -> $crate::plugin::__rt::Built<Shim<T>, Vt> {
                Vt::build::<Shim<T>>()
            }

            impl<T: $Trait + $crate::plugin::Glue> $crate::plugin::__rt::shim::Image for Shim<T> {
                type Plugin = T;
                type Session = $crate::kind!(@session [$($session)?] $Trait T);
                type Reply = $crate::plugin::Outcome<T>;
                type Inbox = $crate::bridge::Inbox;
                fn global() -> &'static $crate::plugin::Slab<T> {
                    <T as $crate::plugin::Glue>::global()
                }
                fn describe(
                    _: &'static $crate::host::Host,
                    out: &mut $crate::plugin::__rt::Out<'_>,
                ) -> $crate::types::Status {
                    $crate::plugin::describe::<T>(REQUIRED, out)
                }
                fn open(
                    h: &'static $crate::host::Host,
                    config: $crate::types::Bytes<'_>,
                    chained: $crate::need::ChainBytes,
                    flags: u32,
                    out: &mut $crate::plugin::__rt::Out<'_>,
                ) -> $crate::plugin::__rt::shim::Opening<$crate::plugin::Outcome<T>, $crate::bridge::Inbox> {
                    $crate::plugin::open::<T>(h, config, chained, flags, out)
                }
                fn poll(
                    chain: $crate::plugin::__rt::ChainRef<'_, $crate::plugin::Outcome<T>, $crate::bridge::Inbox>,
                    results: ::core::option::Option<$crate::need::ChainBytes>,
                    out: &mut $crate::plugin::__rt::Out<'_>,
                ) -> $crate::plugin::__rt::shim::Step {
                    $crate::bridge::poll(chain, results, out)
                }
                fn parked(
                    token: $crate::types::Token,
                    out: &mut $crate::plugin::__rt::Out<'_>,
                ) -> $crate::types::Status {
                    $crate::bridge::parked(token, out)
                }
                fn opened(
                    token: $crate::types::Token,
                    out: &mut $crate::plugin::__rt::Out<'_>,
                ) -> $crate::types::Status {
                    $crate::bridge::opened(token, out)
                }
            }

            $crate::kind! { @methods [$Trait [$($session)?] [$(#[$doc])*]] [0] [] [] $($methods)* }
        }
        pub use $m::$Trait;
    };

    (@session [] $Trait:ident $T:ident) => { () };
    (@session [session] $Trait:ident $T:ident) => { <$T as $Trait>::Session };

    // ---- views: busbar-ffi's own, checked against the block ----
    (@views) => {};
    (@views
        $(#[$vd:meta])* pub struct $V:ident < $lt:lifetime > { $( pub $vf:ident : $vt:ty ),* $(,)? }
        $($rest:tt)*
    ) => {
        $(#[$vd])*
        pub use $crate::plugin::__rt::views::$V;
        const _: () = {
            use $crate::types::*;
            fn fields<$lt>(v: &$V<$lt>) {
                $( let _: &$vt = &v.$vf; )*
            }
            const fn sizes<$lt>() -> usize {
                0 $( + ::core::mem::size_of::<$vt>() )*
            }
            let _: fn(&$V<'static>) = fields;
            assert!(
                sizes() == ::core::mem::size_of::<$V<'static>>(),
                "the view's fields do not fill it"
            );
        };
        $crate::kind! { @views $($rest)* }
    };

    // ---- pods ----
    (@pods) => {};
    (@pods
        $(#[$pd:meta])* pub struct $P:ident { $( $(#[$fd:meta])* pub $pf:ident : $pt:ty ),* $(,)? }
        $($rest:tt)*
    ) => {
        $(#[$pd])*
        #[repr(C)]
        #[derive(
            Clone,
            Copy,
            $crate::plugin::__rt::zerocopy::FromBytes,
            $crate::plugin::__rt::zerocopy::IntoBytes,
            $crate::plugin::__rt::zerocopy::Immutable,
            $crate::plugin::__rt::zerocopy::KnownLayout,
        )]
        pub struct $P { $( $(#[$fd])* pub $pf: $pt ),* }
        impl $crate::records::Pod for $P {}
        $crate::kind! { @pods $($rest)* }
    };

    // ---- tags and consts ----
    (@tags $( $(#[$td:meta])* $TAG:ident = $tv:literal ; )*) => {
        $( $(#[$td])* pub const $TAG: u16 = $tv; )*
        $( const _: () = assert!($TAG >= 0x0100 && $TAG <= 0x01FF, "a kind tag is outside 0x0100..=0x01FF"); )*
    };
    (@consts $( $(#[$cd:meta])* $C:ident : $ct:ty = $cv:expr ; )*) => {
        $( $(#[$cd])* pub const $C: $ct = $cv; )*
    };

    // ---- methods: one at a time, in declaration order (= slot = M_ bit) ----
    (@methods $ctx:tt [$($slot:tt)*] [$($items:tt)*] [$($sigs:tt)*]) => {
        $crate::kind! { @trait $ctx [$($items)*] }
        /// Every method bit of the kind (`M_*` = `1 << slot`, in declaration order).
        pub const ALL: u64 = (1u64 << ($($slot)*)) - 1;
        const _: () = assert!(REQUIRED & !ALL == 0, "REQUIRED names a bit no method has");
        /// The kind fingerprint (IF §7.5): the header, docs, the four blocks and every method signature;
        /// default bodies are not hashed.
        pub const FP: u64 = $crate::fp::fp_parts(&[FP_HEAD.as_bytes(), stringify!($($sigs)*).as_bytes()]);
    };
    // ---- `extras { items }`, after the last method: hand-written module items (the typed helpers, the host-side
    // proxies, unit tests). They sit in the kind's module beside the emitted ones and are not in the FP text
    // (IF §8: helpers are "outside the `kind!` block, so they are not hashed") ----
    (@methods $ctx:tt $slot:tt $items:tt $sigs:tt
        extras { $($extra:item)* }
    ) => {
        $($extra)*
        $crate::kind! { @methods $ctx $slot $items $sigs }
    };
    (@methods $ctx:tt $slot:tt $items:tt $sigs:tt
        $(#[$md:meta])* sync open fn $name:ident ( & $slf:ident , $h:ident : &Host $($args:tt)* )
            -> Result<Session, Fail> $def:block
        $($rest:tt)*
    ) => {
        $crate::kind! { @args [open $ctx $slot $items $sigs [$(#[$md])*] $name $slf $h [] [$def] [$($rest)*]] [] $($args)* }
    };
    (@methods $ctx:tt $slot:tt $items:tt $sigs:tt
        $(#[$md:meta])* sync open fn $name:ident ( & $slf:ident , $h:ident : &Host $($args:tt)* )
            -> Result<Session, Fail> ;
        $($rest:tt)*
    ) => {
        $crate::kind! { @args [open $ctx $slot $items $sigs [$(#[$md])*] $name $slf $h [] [] [$($rest)*]] [] $($args)* }
    };
    (@methods $ctx:tt $slot:tt $items:tt $sigs:tt
        $(#[$md:meta])* sync end fn $name:ident ( & $slf:ident , $h:ident : &Host , $s:ident : Session $($args:tt)* )
            -> Result<(), Fail> ;
        $($rest:tt)*
    ) => {
        $crate::kind! { @args [end $ctx $slot $items $sigs [$(#[$md])*] $name $slf $h [$s] [] [$($rest)*]] [] $($args)* }
    };
    (@methods $ctx:tt $slot:tt $items:tt $sigs:tt
        $(#[$md:meta])* sync fn $name:ident ( & $slf:ident , $h:ident : &Host , $s:ident : &mut Session $($args:tt)* )
            -> Result<(), Fail> $def:block
        $($rest:tt)*
    ) => {
        $crate::kind! { @args [on $ctx $slot $items $sigs [$(#[$md])*] $name $slf $h [$s] [$def] [$($rest)*]] [] $($args)* }
    };
    (@methods $ctx:tt $slot:tt $items:tt $sigs:tt
        $(#[$md:meta])* sync fn $name:ident ( & $slf:ident , $h:ident : &Host , $s:ident : &mut Session $($args:tt)* )
            -> Result<(), Fail> ;
        $($rest:tt)*
    ) => {
        $crate::kind! { @args [on $ctx $slot $items $sigs [$(#[$md])*] $name $slf $h [$s] [] [$($rest)*]] [] $($args)* }
    };
    (@methods $ctx:tt $slot:tt $items:tt $sigs:tt
        $(#[$md:meta])* sync fn $name:ident ( & $slf:ident , $h:ident : &Host $($args:tt)* )
            -> Result<(), Fail> $def:block
        $($rest:tt)*
    ) => {
        $crate::kind! { @args [call $ctx $slot $items $sigs [$(#[$md])*] $name $slf $h [] [$def] [$($rest)*]] [] $($args)* }
    };
    (@methods $ctx:tt $slot:tt $items:tt $sigs:tt
        $(#[$md:meta])* sync fn $name:ident ( & $slf:ident , $h:ident : &Host $($args:tt)* )
            -> Result<(), Fail> ;
        $($rest:tt)*
    ) => {
        $crate::kind! { @args [call $ctx $slot $items $sigs [$(#[$md])*] $name $slf $h [] [] [$($rest)*]] [] $($args)* }
    };
    (@methods $ctx:tt $slot:tt $items:tt $sigs:tt
        $(#[$md:meta])* async fn $name:ident ( & $slf:ident , $h:ident : &'static Host $($args:tt)* )
            -> Result<Reply, Fail> $def:block
        $($rest:tt)*
    ) => {
        $crate::kind! { @args [start $ctx $slot $items $sigs [$(#[$md])*] $name $slf $h [] [$def] [$($rest)*]] [] $($args)* }
    };
    (@methods $ctx:tt $slot:tt $items:tt $sigs:tt
        $(#[$md:meta])* async fn $name:ident ( & $slf:ident , $h:ident : &'static Host $($args:tt)* )
            -> Result<Reply, Fail> ;
        $($rest:tt)*
    ) => {
        $crate::kind! { @args [start $ctx $slot $items $sigs [$(#[$md])*] $name $slf $h [] [] [$($rest)*]] [] $($args)* }
    };

    // ---- arguments: each FFI shape as (name [raw entry type] [plugin type]); anything else does not match ----
    (@args $st:tt [$($acc:tt)*] , $o:ident : &mut Out<'_> $(,)?) => {
        $crate::kind! { @gen $st [$($acc)*] [$o] }
    };
    (@args $st:tt [$($acc:tt)*] $(,)?) => {
        $crate::kind! { @gen $st [$($acc)*] [] }
    };
    (@args $st:tt [$($acc:tt)*] , $a:ident : u32 $($rest:tt)*) => {
        $crate::kind! { @args $st [$($acc)* ($a [u32] [u32])] $($rest)* }
    };
    (@args $st:tt [$($acc:tt)*] , $a:ident : u64 $($rest:tt)*) => {
        $crate::kind! { @args $st [$($acc)* ($a [u64] [u64])] $($rest)* }
    };
    (@args $st:tt [$($acc:tt)*] , $a:ident : Bytes<'_> $($rest:tt)*) => {
        $crate::kind! { @args $st [$($acc)* ($a [$crate::types::Bytes<'static>] [$crate::types::Bytes<'_>])] $($rest)* }
    };
    (@args $st:tt [$($acc:tt)*] , $a:ident : Str<'_> $($rest:tt)*) => {
        $crate::kind! { @args $st [$($acc)* ($a [$crate::types::Str<'static>] [$crate::types::Str<'_>])] $($rest)* }
    };
    (@args $st:tt [$($acc:tt)*] , $a:ident : ChainBytes $($rest:tt)*) => {
        $crate::kind! { @args $st [$($acc)* ($a [$crate::types::Bytes<'static>] [$crate::need::ChainBytes])] $($rest)* }
    };
    (@args $st:tt [$($acc:tt)*] , $a:ident : & $V:ident <'_> $($rest:tt)*) => {
        $crate::kind! { @args $st [$($acc)* ($a [$crate::plugin::__rt::ViewRef<$V<'static>>] [&$V<'_>])] $($rest)* }
    };

    // ---- one method: its trait item (accumulated), its FP text (accumulated) and its adapter (emitted) ----
    (@gen [call $ctx:tt [$($slot:tt)*] [$($items:tt)*] [$($sigs:tt)*] [$(#[$md:meta])*] $name:ident $slf:ident $h:ident [] [$($def:block)?] [$($rest:tt)*]]
        [$(($a:ident [$($raw:tt)*] [$($ty:tt)*]))*] [$o:ident]
    ) => {
        $crate::kind! { @adapter call $ctx [$($slot)*] $name [$(([$($raw)*] [$($ty)*]))*] }
        $crate::kind! { @methods $ctx [$($slot)* + 1]
            [$($items)* $crate::kind! { @fn [$($def)?] $(#[$md])*
                fn $name(&$slf, $h: &$crate::host::Host, $($a: $($ty)*,)* $o: &mut $crate::records::Out<'_>)
                    -> ::core::result::Result<(), $crate::fail::Fail> }]
            [$($sigs)* $(#[$md])* sync fn $name($($a: $($ty)*),*) -> Result<(), Fail>;]
            $($rest)*
        }
    };
    (@gen [on $ctx:tt [$($slot:tt)*] [$($items:tt)*] [$($sigs:tt)*] [$(#[$md:meta])*] $name:ident $slf:ident $h:ident [$s:ident] [$($def:block)?] [$($rest:tt)*]]
        [$(($a:ident [$($raw:tt)*] [$($ty:tt)*]))*] [$o:ident]
    ) => {
        $crate::kind! { @adapter on $ctx [$($slot)*] $name [$(([$($raw)*] [$($ty)*]))*] }
        $crate::kind! { @methods $ctx [$($slot)* + 1]
            [$($items)* $crate::kind! { @fn [$($def)?] $(#[$md])*
                fn $name(&$slf, $h: &$crate::host::Host, $s: &mut Self::Session, $($a: $($ty)*,)* $o: &mut $crate::records::Out<'_>)
                    -> ::core::result::Result<(), $crate::fail::Fail> }]
            [$($sigs)* $(#[$md])* sync fn $name(s: &mut Session $(, $a: $($ty)*)*) -> Result<(), Fail>;]
            $($rest)*
        }
    };
    (@gen [end $ctx:tt [$($slot:tt)*] [$($items:tt)*] [$($sigs:tt)*] [$(#[$md:meta])*] $name:ident $slf:ident $h:ident [$s:ident] [] [$($rest:tt)*]]
        [] [$o:ident]
    ) => {
        $crate::kind! { @adapter end $ctx [$($slot)*] $name [] }
        $crate::kind! { @methods $ctx [$($slot)* + 1]
            [$($items)* $crate::kind! { @fn [] $(#[$md])*
                fn $name(&$slf, $h: &$crate::host::Host, $s: Self::Session, $o: &mut $crate::records::Out<'_>)
                    -> ::core::result::Result<(), $crate::fail::Fail> }]
            [$($sigs)* $(#[$md])* sync end fn $name(s: Session) -> Result<(), Fail>;]
            $($rest)*
        }
    };
    (@gen [open $ctx:tt [$($slot:tt)*] [$($items:tt)*] [$($sigs:tt)*] [$(#[$md:meta])*] $name:ident $slf:ident $h:ident [] [$($def:block)?] [$($rest:tt)*]]
        [$(($a:ident [$($raw:tt)*] [$($ty:tt)*]))*] [$o:ident]
    ) => {
        $crate::kind! { @adapter open $ctx [$($slot)*] $name [$(([$($raw)*] [$($ty)*]))*] }
        $crate::kind! { @methods $ctx [$($slot)* + 1]
            [$($items)* $crate::kind! { @fn [$($def)?] $(#[$md])*
                fn $name(&$slf, $h: &$crate::host::Host, $($a: $($ty)*,)* $o: &mut $crate::records::Out<'_>)
                    -> ::core::result::Result<Self::Session, $crate::fail::Fail> }]
            [$($sigs)* $(#[$md])* sync open fn $name($($a: $($ty)*),*) -> Result<Session, Fail>;]
            $($rest)*
        }
    };
    (@gen [start $ctx:tt [$($slot:tt)*] [$($items:tt)*] [$($sigs:tt)*] [$(#[$md:meta])*] $name:ident $slf:ident $h:ident [] [$($def:block)?] [$($rest:tt)*]]
        [$(($a:ident [$($raw:tt)*] [$($ty:tt)*]))*] []
    ) => {
        $crate::kind! { @adapter start $ctx [$($slot)*] $name [$(([$($raw)*] [$($ty)*]))*] }
        $crate::kind! { @methods $ctx [$($slot)* + 1]
            [$($items)* $crate::kind! { @async [$($def)?] $(#[$md])*
                fn $name(&$slf, $h: &'static $crate::host::Host $(, $a: $($ty)*)*)
                    -> impl ::core::future::Future<
                        Output = ::core::result::Result<$crate::records::Reply, $crate::fail::Fail>,
                    > + Send }]
            [$($sigs)* $(#[$md])* async fn $name($($a: $($ty)*),*) -> Result<Reply, Fail>;]
            $($rest)*
        }
    };

    // ---- a trait item with or without its default body ----
    (@fn [] $($sig:tt)*) => { $($sig)*; };
    (@fn [$def:block] $($sig:tt)*) => { $($sig)* $def };
    (@async [] $($sig:tt)*) => { $($sig)*; };
    (@async [$def:block] $($sig:tt)*) => { $($sig)* { async move $def } };

    (@trait [$Trait:ident [$($session:ident)?] [$(#[$doc:meta])*]] [$($items:tt)*]) => {
        $(#[$doc])*
        pub trait $Trait: Send + Sync + 'static {
            $(
                #[doc = concat!("One live `", stringify!($session), "`: what a session token names (IF §6.5).")]
                type Session: Send + 'static;
            )?
            $($items)*
        }
    };

    // ---- adapters: busbar-ffi's per-slot traits, each a call into `T` and `plugin`'s answer writes ----
    (@adapter call [$Trait:ident $($x:tt)*] [$($slot:tt)*] $name:ident []) => {
        impl<T: $Trait + $crate::plugin::Glue> $crate::plugin::__rt::shim::Call0<{ $($slot)* }> for Shim<T> {
            fn call(
                p: &T,
                h: &'static $crate::host::Host,
                out: &mut $crate::plugin::__rt::Out<'_>,
            ) -> $crate::types::Status {
                $crate::plugin::sync(out, |o| <T as $Trait>::$name(p, h, o))
            }
        }
    };
    (@adapter call [$Trait:ident $($x:tt)*] [$($slot:tt)*] $name:ident
        [([$($r1:tt)*] $t1:tt)]
    ) => {
        impl<T: $Trait + $crate::plugin::Glue> $crate::plugin::__rt::shim::Call1<$($r1)*, { $($slot)* }> for Shim<T> {
            fn call(
                p: &T,
                h: &'static $crate::host::Host,
                a1: $crate::plugin::__rt::Arg<'_, $($r1)*>,
                out: &mut $crate::plugin::__rt::Out<'_>,
            ) -> $crate::types::Status {
                $crate::plugin::sync(out, |o| <T as $Trait>::$name(p, h, a1.get(), o))
            }
        }
    };
    (@adapter call [$Trait:ident $($x:tt)*] [$($slot:tt)*] $name:ident
        [([$($r1:tt)*] $t1:tt) ([$($r2:tt)*] $t2:tt)]
    ) => {
        impl<T: $Trait + $crate::plugin::Glue> $crate::plugin::__rt::shim::Call2<$($r1)*, $($r2)*, { $($slot)* }> for Shim<T> {
            fn call(
                p: &T,
                h: &'static $crate::host::Host,
                a1: $crate::plugin::__rt::Arg<'_, $($r1)*>,
                a2: $crate::plugin::__rt::Arg<'_, $($r2)*>,
                out: &mut $crate::plugin::__rt::Out<'_>,
            ) -> $crate::types::Status {
                $crate::plugin::sync(out, |o| <T as $Trait>::$name(p, h, a1.get(), a2.get(), o))
            }
        }
    };
    (@adapter call [$Trait:ident $($x:tt)*] [$($slot:tt)*] $name:ident
        [([$($r1:tt)*] $t1:tt) ([$($r2:tt)*] $t2:tt) ([$($r3:tt)*] $t3:tt)]
    ) => {
        impl<T: $Trait + $crate::plugin::Glue> $crate::plugin::__rt::shim::Call3<$($r1)*, $($r2)*, $($r3)*, { $($slot)* }> for Shim<T> {
            fn call(
                p: &T,
                h: &'static $crate::host::Host,
                a1: $crate::plugin::__rt::Arg<'_, $($r1)*>,
                a2: $crate::plugin::__rt::Arg<'_, $($r2)*>,
                a3: $crate::plugin::__rt::Arg<'_, $($r3)*>,
                out: &mut $crate::plugin::__rt::Out<'_>,
            ) -> $crate::types::Status {
                $crate::plugin::sync(out, |o| <T as $Trait>::$name(p, h, a1.get(), a2.get(), a3.get(), o))
            }
        }
    };
    (@adapter open [$Trait:ident $($x:tt)*] [$($slot:tt)*] $name:ident
        [([$($r1:tt)*] $t1:tt)]
    ) => {
        impl<T: $Trait + $crate::plugin::Glue> $crate::plugin::__rt::shim::Opener1<$($r1)*, { $($slot)* }> for Shim<T> {
            fn begin(
                p: &T,
                h: &'static $crate::host::Host,
                a1: $crate::plugin::__rt::Arg<'_, $($r1)*>,
                out: &mut $crate::plugin::__rt::Out<'_>,
            ) -> ::core::result::Result<<Self as $crate::plugin::__rt::shim::Image>::Session, $crate::types::Status> {
                $crate::plugin::opener(out, |o| <T as $Trait>::$name(p, h, a1.get(), o))
            }
        }
    };
    (@adapter open [$Trait:ident $($x:tt)*] [$($slot:tt)*] $name:ident
        [([$($r1:tt)*] $t1:tt) ([$($r2:tt)*] $t2:tt)]
    ) => {
        impl<T: $Trait + $crate::plugin::Glue> $crate::plugin::__rt::shim::Opener2<$($r1)*, $($r2)*, { $($slot)* }> for Shim<T> {
            fn begin(
                p: &T,
                h: &'static $crate::host::Host,
                a1: $crate::plugin::__rt::Arg<'_, $($r1)*>,
                a2: $crate::plugin::__rt::Arg<'_, $($r2)*>,
                out: &mut $crate::plugin::__rt::Out<'_>,
            ) -> ::core::result::Result<<Self as $crate::plugin::__rt::shim::Image>::Session, $crate::types::Status> {
                $crate::plugin::opener(out, |o| <T as $Trait>::$name(p, h, a1.get(), a2.get(), o))
            }
        }
    };
    (@adapter on [$Trait:ident $($x:tt)*] [$($slot:tt)*] $name:ident []) => {
        impl<T: $Trait + $crate::plugin::Glue> $crate::plugin::__rt::shim::Session0<{ $($slot)* }> for Shim<T> {
            fn on(
                p: &T,
                h: &'static $crate::host::Host,
                s: &mut <Self as $crate::plugin::__rt::shim::Image>::Session,
                out: &mut $crate::plugin::__rt::Out<'_>,
            ) -> $crate::types::Status {
                $crate::plugin::sync(out, |o| <T as $Trait>::$name(p, h, s, o))
            }
        }
    };
    (@adapter on [$Trait:ident $($x:tt)*] [$($slot:tt)*] $name:ident
        [([$($r1:tt)*] $t1:tt)]
    ) => {
        impl<T: $Trait + $crate::plugin::Glue> $crate::plugin::__rt::shim::Session1<$($r1)*, { $($slot)* }> for Shim<T> {
            fn on(
                p: &T,
                h: &'static $crate::host::Host,
                s: &mut <Self as $crate::plugin::__rt::shim::Image>::Session,
                a1: $crate::plugin::__rt::Arg<'_, $($r1)*>,
                out: &mut $crate::plugin::__rt::Out<'_>,
            ) -> $crate::types::Status {
                $crate::plugin::sync(out, |o| <T as $Trait>::$name(p, h, s, a1.get(), o))
            }
        }
    };
    (@adapter on [$Trait:ident $($x:tt)*] [$($slot:tt)*] $name:ident
        [([$($r1:tt)*] $t1:tt) ([$($r2:tt)*] $t2:tt)]
    ) => {
        impl<T: $Trait + $crate::plugin::Glue> $crate::plugin::__rt::shim::Session2<$($r1)*, $($r2)*, { $($slot)* }> for Shim<T> {
            fn on(
                p: &T,
                h: &'static $crate::host::Host,
                s: &mut <Self as $crate::plugin::__rt::shim::Image>::Session,
                a1: $crate::plugin::__rt::Arg<'_, $($r1)*>,
                a2: $crate::plugin::__rt::Arg<'_, $($r2)*>,
                out: &mut $crate::plugin::__rt::Out<'_>,
            ) -> $crate::types::Status {
                $crate::plugin::sync(out, |o| <T as $Trait>::$name(p, h, s, a1.get(), a2.get(), o))
            }
        }
    };
    (@adapter on [$Trait:ident $($x:tt)*] [$($slot:tt)*] $name:ident
        [([$($r1:tt)*] $t1:tt) ([$($r2:tt)*] $t2:tt) ([$($r3:tt)*] $t3:tt)]
    ) => {
        impl<T: $Trait + $crate::plugin::Glue> $crate::plugin::__rt::shim::Session3<$($r1)*, $($r2)*, $($r3)*, { $($slot)* }> for Shim<T> {
            fn on(
                p: &T,
                h: &'static $crate::host::Host,
                s: &mut <Self as $crate::plugin::__rt::shim::Image>::Session,
                a1: $crate::plugin::__rt::Arg<'_, $($r1)*>,
                a2: $crate::plugin::__rt::Arg<'_, $($r2)*>,
                a3: $crate::plugin::__rt::Arg<'_, $($r3)*>,
                out: &mut $crate::plugin::__rt::Out<'_>,
            ) -> $crate::types::Status {
                $crate::plugin::sync(out, |o| <T as $Trait>::$name(p, h, s, a1.get(), a2.get(), a3.get(), o))
            }
        }
    };
    (@adapter on [$Trait:ident $($x:tt)*] [$($slot:tt)*] $name:ident
        [([$($r1:tt)*] $t1:tt) ([$($r2:tt)*] $t2:tt) ([$($r3:tt)*] $t3:tt) ([$($r4:tt)*] $t4:tt)]
    ) => {
        impl<T: $Trait + $crate::plugin::Glue> $crate::plugin::__rt::shim::Session4<$($r1)*, $($r2)*, $($r3)*, $($r4)*, { $($slot)* }> for Shim<T> {
            fn on(
                p: &T,
                h: &'static $crate::host::Host,
                s: &mut <Self as $crate::plugin::__rt::shim::Image>::Session,
                a1: $crate::plugin::__rt::Arg<'_, $($r1)*>,
                a2: $crate::plugin::__rt::Arg<'_, $($r2)*>,
                a3: $crate::plugin::__rt::Arg<'_, $($r3)*>,
                a4: $crate::plugin::__rt::Arg<'_, $($r4)*>,
                out: &mut $crate::plugin::__rt::Out<'_>,
            ) -> $crate::types::Status {
                $crate::plugin::sync(out, |o| {
                    <T as $Trait>::$name(p, h, s, a1.get(), a2.get(), a3.get(), a4.get(), o)
                })
            }
        }
    };
    (@adapter end [$Trait:ident $($x:tt)*] [$($slot:tt)*] $name:ident []) => {
        impl<T: $Trait + $crate::plugin::Glue> $crate::plugin::__rt::shim::End0<{ $($slot)* }> for Shim<T> {
            fn end(
                p: &T,
                h: &'static $crate::host::Host,
                s: <Self as $crate::plugin::__rt::shim::Image>::Session,
                out: &mut $crate::plugin::__rt::Out<'_>,
            ) -> $crate::types::Status {
                $crate::plugin::sync(out, |o| <T as $Trait>::$name(p, h, s, o))
            }
        }
    };
    (@adapter start [$Trait:ident $($x:tt)*] [$($slot:tt)*] $name:ident []) => {
        impl<T: $Trait + $crate::plugin::Glue> $crate::plugin::__rt::shim::Start0<{ $($slot)* }> for Shim<T> {
            fn start<'i>(
                p: &'i T,
                h: &'static $crate::host::Host,
            ) -> ($crate::plugin::__rt::ChainFut<'i, $crate::plugin::Outcome<T>>, $crate::bridge::Inbox) {
                $crate::plugin::chain(<T as $Trait>::$name(p, h))
            }
        }
    };
    (@adapter start [$Trait:ident $($x:tt)*] [$($slot:tt)*] $name:ident
        [([$($r1:tt)*] [$($t1:tt)*])]
    ) => {
        impl<T: $Trait + $crate::plugin::Glue> $crate::plugin::__rt::shim::Start1<$($r1)*, { $($slot)* }> for Shim<T> {
            fn start<'i>(
                p: &'i T,
                h: &'static $crate::host::Host,
                a1: $($t1)*,
            ) -> ($crate::plugin::__rt::ChainFut<'i, $crate::plugin::Outcome<T>>, $crate::bridge::Inbox) {
                $crate::plugin::chain(<T as $Trait>::$name(p, h, a1))
            }
        }
    };
    (@adapter start [$Trait:ident $($x:tt)*] [$($slot:tt)*] $name:ident
        [([$($r1:tt)*] [$($t1:tt)*]) ([$($r2:tt)*] [$($t2:tt)*])]
    ) => {
        impl<T: $Trait + $crate::plugin::Glue> $crate::plugin::__rt::shim::Start2<$($r1)*, $($r2)*, { $($slot)* }> for Shim<T> {
            fn start<'i>(
                p: &'i T,
                h: &'static $crate::host::Host,
                a1: $($t1)*,
                a2: $($t2)*,
            ) -> ($crate::plugin::__rt::ChainFut<'i, $crate::plugin::Outcome<T>>, $crate::bridge::Inbox) {
                $crate::plugin::chain(<T as $Trait>::$name(p, h, a1, a2))
            }
        }
    };
    (@adapter start [$Trait:ident $($x:tt)*] [$($slot:tt)*] $name:ident
        [([$($r1:tt)*] [$($t1:tt)*]) ([$($r2:tt)*] [$($t2:tt)*]) ([$($r3:tt)*] [$($t3:tt)*]) ([$($r4:tt)*] [$($t4:tt)*])]
    ) => {
        impl<T: $Trait + $crate::plugin::Glue> $crate::plugin::__rt::shim::Start4<$($r1)*, $($r2)*, $($r3)*, $($r4)*, { $($slot)* }> for Shim<T> {
            fn start<'i>(
                p: &'i T,
                h: &'static $crate::host::Host,
                a1: $($t1)*,
                a2: $($t2)*,
                a3: $($t3)*,
                a4: $($t4)*,
            ) -> ($crate::plugin::__rt::ChainFut<'i, $crate::plugin::Outcome<T>>, $crate::bridge::Inbox) {
                $crate::plugin::chain(<T as $Trait>::$name(p, h, a1, a2, a3, a4))
            }
        }
    };

    // ---- the entry: the IF §7.6 grammar ----
    (
        $(#[$doc:meta])*
        pub trait $Trait:ident : kind = $kind:tt , abi = $abi:tt $(, $session:ident)? {
            views { $($views:tt)* }
            pods { $($pods:tt)* }
            tags { $($tags:tt)* }
            consts { $($consts:tt)* }
            $($methods:tt)*
        }
    ) => {
        $crate::kind! { @number $kind [$(#[$doc])*] $Trait $kind $abi [$($session)?]
            [$($views)*] [$($pods)*] [$($tags)*] [$($consts)*] [$($methods)*] }
    };
}

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

        fn lease() -> OutLease<'static> {
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
