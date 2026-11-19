// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `kind!` macro that declares a kind trait and its module (IF §7.6; core 3.0, interface revision C.3).
//! The macro writes no `unsafe` and no raw entry. Per kind it emits the trait, the module's items, one image
//! type `Shim<T>`, one safe `busbar_ffi::shim` adapter per method (each unpacks the one `Call` into the typed
//! trait call the plugin author implements), the kind's table as an array of entries, and the host-side
//! packer of every method (`pack::<method>`), from the one signature.

/// Declares one kind: its trait, its module (views, pods, tags, consts, KIND, ABI, MINOR, FP, ALL, ENTRIES,
/// METHODS, `slot`, `pack`, the table and the image's adapters) (IF §7.6).
///
/// ```text
/// **Grammar** (unchanged for a plugin author; `retired { .. }` is new and optional):
///
/// kind! {
///     $(#[doc = $d:literal])*
///     pub trait $Trait:ident : kind = $kind:literal, abi = $abi:literal $(, session)? {
///         views  { $( $(#[doc = $vd:literal])* pub struct $V:ident<'a> { $( pub $vf:ident : $vt:ty ),* $(,)? } )* }
///         pods   { $( $(#[doc = $pd:literal])* pub struct $P:ident { $( pub $pf:ident : $pt:ty ),* $(,)? } )* }
///         tags   { $( $(#[doc = $td:literal])* $TAG:ident = $tv:literal ; )* }
///         consts { $( $(#[doc = $cd:literal])* $C:ident : $ct:ty = $cv:expr ; )* }
///         $( retired { $( $rt:literal ),* $(,)? } )?
///         $(
///             sync fn $m ( &self, h: &Host $(, $a : $at)* , out: &mut Out<'_> ) -> Result<(), Fail> ($def | ;)
///         |   sync open fn $m ( &self, h: &Host $(, $a : $at)* , out: &mut Out<'_> ) -> Result<Session, Fail> ($def | ;)
///         |   sync fn $m ( &self, h: &Host, s: &mut Session $(, $a : $at)* , out: &mut Out<'_> ) -> Result<(), Fail> ($def | ;)
///         |   sync end fn $m ( &self, h: &Host, s: Session, out: &mut Out<'_> ) -> Result<(), Fail> ;
///         |   async fn $m ( &self, h: &'static Host $(, $a : $at)* ) -> Result<Reply, Fail> ($def | ;)
///         )*
///         $( extras { $($item)* } )?
///     }
/// }
/// ```
///
/// **Argument shapes.** Sync: `u32`, `u64`, `Bytes<'_>`, `Str<'_>`, `&View<'_>` (a `views` struct), and, as
/// the last argument only, `Slice<'_, Bytes<'_>>` (every remaining blob). Async: `u32`, `u64`, `ChainBytes`.
/// Anything else does not match and is a compile error. How each maps onto `Call` is `crate::call`'s one
/// rule; the layout of every method of the seven kinds is tabled in the interface revision's LAYOUT.
///
/// **What it emits**, for `pub trait Auth: kind = 3, ..`:
///
/// 1. `pub mod auth` with:
///    - `pub trait Auth: Send + Sync + 'static`, one method per entry, exactly as before the one call shape:
///      a sync method keeps its signature; an async one returns `impl Future<..> + Send`;
///    - each `views` struct as a plain borrowed struct with its `call::Get` (read from a call) and
///      `call::Put` (written into one) impls; the kind owns its views (busbar-ffi knows no kind);
///    - the `pods`, `pub mod tag` (each tag const-checked into the kind's ranges and against `retired`), the
///      consts;
///    - `KIND`, `ABI` (the first number), `MINOR` (the second), `FP` (the wire fingerprint: names, numbers,
///      field types and order, never comments), `ALL`, `ENTRIES`, `METHODS`, `Marker`;
///    - `slot::<method>`: the method's position in the table; `pack::<method>(mono_ns, args.., f)`: builds the
///      method's `Call` on the stack and hands it to `f`;
///    - `Shim<T>`, the image of plugin type `T`, with its `busbar_ffi::shim::Image` impl and one adapter per
///      method (`Plain`, `Opens`, `OnSession`, `Ends`, `Starts`; slot = declaration order), and
///      `pub const fn table<T>()`, the kind's table: an array of `ENTRIES` entries over `Shim<T>`.
///
/// `macro_rules` cannot change an identifier's case and the owner bans `paste`, so a kind block states its
/// `M_<METHOD>: u64 = 1 << i;` lines in `consts` and `kind!` emits `ALL` (and checks `REQUIRED` against it);
/// `slot` and `pack` items carry the method's own lower-case name. A kind block may end with
/// `extras { items }`, hand-written module items (typed helpers, the host proxies, unit tests) that sit in the
/// module and are not in `FP`.
#[macro_export]
macro_rules! kind {
    // ---- the kind number names the module and the KindCode ----
    (@number 1 $($rest:tt)*) => { $crate::kind! { @module store Store $($rest)* } };
    (@number 2 $($rest:tt)*) => { $crate::kind! { @module secret Secret $($rest)* } };
    (@number 3 $($rest:tt)*) => { $crate::kind! { @module auth Auth $($rest)* } };
    (@number 4 $($rest:tt)*) => { $crate::kind! { @module hook Hook $($rest)* } };
    (@number 5 $($rest:tt)*) => { $crate::kind! { @module export Export $($rest)* } };
    (@number 6 $($rest:tt)*) => { $crate::kind! { @module plane Plane $($rest)* } };
    (@number 7 $($rest:tt)*) => { $crate::kind! { @module transport Transport $($rest)* } };

    (@module $m:ident $K:ident [$(#[$doc:meta])*] $Trait:ident $kind:tt $abi:tt [$($session:ident)?]
        [$($views:tt)*] [$($pods:tt)*] [$($tags:tt)*] [$($consts:tt)*] [$($retired:tt)*] [$($methods:tt)*]
    ) => {
        pub mod $m {
            $crate::kind! { @views $($views)* }
            $crate::kind! { @pods $($pods)* }
            /// The kind's tags. Call records: 0x0100..=0x017F and 0x0200..=0x3FFF. Describe items:
            /// 0x0180..=0x01FF and 0x4000..=0x4FFF. 0x5000 and up is never used (interface revision D.2).
            pub mod tag {
                $crate::kind! { @tags $($tags)* }
            }
            $crate::kind! { @consts $($consts)* }

            /// Tags this kind once used and never will again: a declared tag on this list does not compile,
            /// and one seen in the field is a fault for ever (interface revision D.2).
            pub const RETIRED_TAGS: &[u16] = &[$($retired)*];
            const _: () = assert!(
                !$crate::call::shares(tag::LIST, RETIRED_TAGS),
                "a declared tag is on the kind's retired list"
            );

            /// The kind code a stamp of this kind carries.
            pub const KIND: $crate::types::KindCode = $crate::types::KindCode::$K;
            /// This kind's contract version, first number: it moves when something is changed or removed.
            pub const ABI: u32 = $abi;
            /// This kind's contract version, second number: it moves when something is added.
            pub const MINOR: u32 = $crate::versions::minor_of(KIND);
            const _: () = assert!(KIND as u32 == $kind, "the kind number names another kind");
            const _: () = assert!(
                ABI == $crate::versions::abi_of(KIND),
                "abi is not versions::<KIND>"
            );
            /// busbar-ffi's marker for this kind (its sealed `Kind`): the kind code, nothing else.
            pub type Marker = $crate::plugin::__rt::kind::$K;

            /// What `FP` hashes before the method signatures: the header line. Never a comment.
            const FP_HEAD: &str = stringify!(pub trait $Trait: kind = $kind, abi = $abi $(, $session)?);

            /// The image of plugin type `T`: busbar-ffi's shims call `T` through it.
            pub struct Shim<T>(::core::marker::PhantomData<fn() -> T>);

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

            $crate::kind! { @methods [$Trait [$($session)?] [$(#[$doc])*]] [0] [] [] [] $($methods)* }
        }
        pub use $m::$Trait;
    };

    (@session [] $Trait:ident $T:ident) => { () };
    (@session [session] $Trait:ident $T:ident) => { <$T as $Trait>::Session };

    // ---- views: the kind's own borrowed structs, read from and written into a call field by field ----
    (@views $(
        $(#[$vd:meta])* pub struct $V:ident < $lt:lifetime > { $( $(#[$vfd:meta])* pub $vf:ident : $vt:ty ),* $(,)? }
    )*) => {
        $(
            $(#[$vd])*
            #[derive(Clone, Copy)]
            pub struct $V<$lt> { $( $(#[$vfd])* pub $vf: $vt ),* }
            impl<$lt> $crate::call::Get<$lt> for $V<$lt> {
                fn get(r: &mut $crate::call::Reader<$lt>) -> ::core::option::Option<Self> {
                    ::core::option::Option::Some($V {
                        $( $vf: <$vt as $crate::call::Get<$lt>>::get(r)?, )*
                    })
                }
            }
            impl<$lt> $crate::call::Put<$lt> for &$V<$lt> {
                fn put(self, w: &mut $crate::call::Packer<$lt>) {
                    $( <$vt as $crate::call::Put<$lt>>::put(self.$vf, w); )*
                }
            }
        )*
        /// The views' wire text: names, field names, field types, in order.
        const FP_VIEWS: &str = stringify!($( struct $V { $( $vf: $vt ),* } )*);
    };

    // ---- pods ----
    (@pods $(
        $(#[$pd:meta])* pub struct $P:ident { $( $(#[$fd:meta])* pub $pf:ident : $pt:ty ),* $(,)? }
    )*) => {
        $(
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
        )*
        /// The records' wire text: names, field names, field types, in order.
        const FP_PODS: &str = stringify!($( struct $P { $( $pf: $pt ),* } )*);
    };

    // ---- tags and consts ----
    (@tags $( $(#[$td:meta])* $TAG:ident = $tv:literal ; )*) => {
        $( $(#[$td])* pub const $TAG: u16 = $tv; )*
        $( const _: () = assert!(
            ($TAG >= 0x0100 && $TAG <= 0x01FF) || ($TAG >= 0x0200 && $TAG <= 0x4FFF),
            "a kind tag is outside 0x0100..=0x4FFF"
        ); )*
        /// Every tag the kind declares, in declaration order.
        pub const LIST: &[u16] = &[$($TAG),*];
        /// The tags' wire text: names and numbers.
        pub(super) const FP_TAGS: &str = stringify!($( $TAG = $tv; )*);
    };
    (@consts $( $(#[$cd:meta])* $C:ident : $ct:ty = $cv:expr ; )*) => {
        $( $(#[$cd])* pub const $C: $ct = $cv; )*
        /// The constants' wire text: names, types and values.
        const FP_CONSTS: &str = stringify!($( $C: $ct = $cv; )*);
    };

    // ---- methods: one at a time, in declaration order (= slot = M_ bit) ----
    (@methods $ctx:tt [$($slot:tt)*] [$($items:tt)*] [$($sigs:tt)*] [$($gen:tt)*]) => {
        $crate::kind! { @trait $ctx [$($items)*] }
        /// Every method bit of the kind (`M_*` = `1 << slot`, in declaration order).
        pub const ALL: u64 = (1u64 << ($($slot)*)) - 1;
        /// How many entries this kind's table has in this version.
        pub const ENTRIES: usize = $($slot)*;
        const _: () = assert!(ENTRIES <= 56, "a kind has at most 56 methods (one mask)");
        const _: () = assert!(REQUIRED & !ALL == 0, "REQUIRED names a bit no method has");
        /// The kind's wire fingerprint (interface revision C.4, C.7): the header line, the views, records,
        /// tags and constants, and every method signature. Names, numbers, field types and order; never a
        /// comment, never a default body. This is what a stamp carries for the kind.
        pub const FP: u64 = $crate::fp::fp_parts(&[
            FP_HEAD.as_bytes(),
            FP_VIEWS.as_bytes(),
            FP_PODS.as_bytes(),
            tag::FP_TAGS.as_bytes(),
            FP_CONSTS.as_bytes(),
            stringify!($($sigs)*).as_bytes(),
        ]);
        $crate::kind! { @finish $ctx $($gen)* }
    };
    // ---- `extras { items }`, after the last method: hand-written module items (the typed helpers, the host-side
    // proxies, unit tests). They sit in the kind's module beside the emitted ones and are not in the FP text ----
    (@methods $ctx:tt $slot:tt $items:tt $sigs:tt $gen:tt
        extras { $($extra:item)* }
    ) => {
        $($extra)*
        $crate::kind! { @methods $ctx $slot $items $sigs $gen }
    };
    (@methods $ctx:tt $slot:tt $items:tt $sigs:tt $gen:tt
        $(#[$md:meta])* sync open fn $name:ident ( & $slf:ident , $h:ident : &Host $($args:tt)* )
            -> Result<Session, Fail> $def:block
        $($rest:tt)*
    ) => {
        $crate::kind! { @args [open $ctx $slot $items $sigs $gen [$(#[$md])*] $name $slf $h [] [$def] [$($rest)*]] [] $($args)* }
    };
    (@methods $ctx:tt $slot:tt $items:tt $sigs:tt $gen:tt
        $(#[$md:meta])* sync open fn $name:ident ( & $slf:ident , $h:ident : &Host $($args:tt)* )
            -> Result<Session, Fail> ;
        $($rest:tt)*
    ) => {
        $crate::kind! { @args [open $ctx $slot $items $sigs $gen [$(#[$md])*] $name $slf $h [] [] [$($rest)*]] [] $($args)* }
    };
    (@methods $ctx:tt $slot:tt $items:tt $sigs:tt $gen:tt
        $(#[$md:meta])* sync end fn $name:ident ( & $slf:ident , $h:ident : &Host , $s:ident : Session $($args:tt)* )
            -> Result<(), Fail> ;
        $($rest:tt)*
    ) => {
        $crate::kind! { @args [end $ctx $slot $items $sigs $gen [$(#[$md])*] $name $slf $h [$s] [] [$($rest)*]] [] $($args)* }
    };
    (@methods $ctx:tt $slot:tt $items:tt $sigs:tt $gen:tt
        $(#[$md:meta])* sync fn $name:ident ( & $slf:ident , $h:ident : &Host , $s:ident : &mut Session $($args:tt)* )
            -> Result<(), Fail> $def:block
        $($rest:tt)*
    ) => {
        $crate::kind! { @args [on $ctx $slot $items $sigs $gen [$(#[$md])*] $name $slf $h [$s] [$def] [$($rest)*]] [] $($args)* }
    };
    (@methods $ctx:tt $slot:tt $items:tt $sigs:tt $gen:tt
        $(#[$md:meta])* sync fn $name:ident ( & $slf:ident , $h:ident : &Host , $s:ident : &mut Session $($args:tt)* )
            -> Result<(), Fail> ;
        $($rest:tt)*
    ) => {
        $crate::kind! { @args [on $ctx $slot $items $sigs $gen [$(#[$md])*] $name $slf $h [$s] [] [$($rest)*]] [] $($args)* }
    };
    (@methods $ctx:tt $slot:tt $items:tt $sigs:tt $gen:tt
        $(#[$md:meta])* sync fn $name:ident ( & $slf:ident , $h:ident : &Host $($args:tt)* )
            -> Result<(), Fail> $def:block
        $($rest:tt)*
    ) => {
        $crate::kind! { @args [call $ctx $slot $items $sigs $gen [$(#[$md])*] $name $slf $h [] [$def] [$($rest)*]] [] $($args)* }
    };
    (@methods $ctx:tt $slot:tt $items:tt $sigs:tt $gen:tt
        $(#[$md:meta])* sync fn $name:ident ( & $slf:ident , $h:ident : &Host $($args:tt)* )
            -> Result<(), Fail> ;
        $($rest:tt)*
    ) => {
        $crate::kind! { @args [call $ctx $slot $items $sigs $gen [$(#[$md])*] $name $slf $h [] [] [$($rest)*]] [] $($args)* }
    };
    (@methods $ctx:tt $slot:tt $items:tt $sigs:tt $gen:tt
        $(#[$md:meta])* async fn $name:ident ( & $slf:ident , $h:ident : &'static Host $($args:tt)* )
            -> Result<Reply, Fail> $def:block
        $($rest:tt)*
    ) => {
        $crate::kind! { @args [start $ctx $slot $items $sigs $gen [$(#[$md])*] $name $slf $h [] [$def] [$($rest)*]] [] $($args)* }
    };
    (@methods $ctx:tt $slot:tt $items:tt $sigs:tt $gen:tt
        $(#[$md:meta])* async fn $name:ident ( & $slf:ident , $h:ident : &'static Host $($args:tt)* )
            -> Result<Reply, Fail> ;
        $($rest:tt)*
    ) => {
        $crate::kind! { @args [start $ctx $slot $items $sigs $gen [$(#[$md])*] $name $slf $h [] [] [$($rest)*]] [] $($args)* }
    };

    // ---- arguments: each shape as (name mode [the author's type] [the read type] [the host's type]);
    // anything else does not match ----
    (@args $st:tt [$($acc:tt)*] , $o:ident : &mut Out<'_> $(,)?) => {
        $crate::kind! { @gen $st [$($acc)*] [$o] }
    };
    (@args $st:tt [$($acc:tt)*] $(,)?) => {
        $crate::kind! { @gen $st [$($acc)*] [] }
    };
    (@args $st:tt [$($acc:tt)*] , $a:ident : u32 $($rest:tt)*) => {
        $crate::kind! { @args $st [$($acc)* ($a val [u32] [u32] [u32])] $($rest)* }
    };
    (@args $st:tt [$($acc:tt)*] , $a:ident : u64 $($rest:tt)*) => {
        $crate::kind! { @args $st [$($acc)* ($a val [u64] [u64] [u64])] $($rest)* }
    };
    (@args $st:tt [$($acc:tt)*] , $a:ident : Bytes<'_> $($rest:tt)*) => {
        $crate::kind! { @args $st [$($acc)* ($a val [$crate::types::Bytes<'_>] [$crate::types::Bytes<'_>] [$crate::types::Bytes<'_>])] $($rest)* }
    };
    (@args $st:tt [$($acc:tt)*] , $a:ident : Str<'_> $($rest:tt)*) => {
        $crate::kind! { @args $st [$($acc)* ($a val [$crate::types::Str<'_>] [$crate::types::Str<'_>] [$crate::types::Str<'_>])] $($rest)* }
    };
    (@args $st:tt [$($acc:tt)*] , $a:ident : Slice<'_, Bytes<'_>> $($rest:tt)*) => {
        $crate::kind! { @args $st [$($acc)* ($a val
            [$crate::types::Slice<'_, $crate::types::Bytes<'_>>]
            [$crate::types::Slice<'_, $crate::types::Bytes<'_>>]
            [$crate::types::Slice<'_, $crate::types::Bytes<'_>>])] $($rest)* }
    };
    (@args $st:tt [$($acc:tt)*] , $a:ident : ChainBytes $($rest:tt)*) => {
        $crate::kind! { @args $st [$($acc)* ($a val [$crate::need::ChainBytes] [$crate::need::ChainBytes] [$crate::types::Bytes<'_>])] $($rest)* }
    };
    (@args $st:tt [$($acc:tt)*] , $a:ident : & $V:ident <'_> $($rest:tt)*) => {
        $crate::kind! { @args $st [$($acc)* ($a view [&$V<'_>] [$V<'_>] [&$V<'_>])] $($rest)* }
    };

    // ---- one method: its trait item, its FP text and its generation record (accumulated) and its adapter (emitted) ----
    (@gen [call $ctx:tt [$($slot:tt)*] [$($items:tt)*] [$($sigs:tt)*] [$($gen:tt)*] [$(#[$md:meta])*] $name:ident $slf:ident $h:ident [] [$($def:block)?] [$($rest:tt)*]]
        [$(($a:ident $mode:ident [$($ty:tt)*] [$($rty:tt)*] [$($hty:tt)*]))*] [$o:ident]
    ) => {
        $crate::kind! { @adapter call $ctx [$($slot)*] $name [$(($a $mode [$($rty)*]))*] }
        $crate::kind! { @methods $ctx [$($slot)* + 1]
            [$($items)* $crate::kind! { @fn [$($def)?] $(#[$md])*
                fn $name(&$slf, $h: &$crate::host::Host, $($a: $($ty)*,)* $o: &mut $crate::records::Out<'_>)
                    -> ::core::result::Result<(), $crate::fail::Fail> }]
            [$($sigs)* sync fn $name($($a: $($ty)*),*) -> Result<(), Fail>;]
            [$($gen)* (plain $name [$($slot)*] [$(($a [$($hty)*]))*])]
            $($rest)*
        }
    };
    (@gen [on $ctx:tt [$($slot:tt)*] [$($items:tt)*] [$($sigs:tt)*] [$($gen:tt)*] [$(#[$md:meta])*] $name:ident $slf:ident $h:ident [$s:ident] [$($def:block)?] [$($rest:tt)*]]
        [$(($a:ident $mode:ident [$($ty:tt)*] [$($rty:tt)*] [$($hty:tt)*]))*] [$o:ident]
    ) => {
        $crate::kind! { @adapter on $ctx [$($slot)*] $name [$(($a $mode [$($rty)*]))*] }
        $crate::kind! { @methods $ctx [$($slot)* + 1]
            [$($items)* $crate::kind! { @fn [$($def)?] $(#[$md])*
                fn $name(&$slf, $h: &$crate::host::Host, $s: &mut Self::Session, $($a: $($ty)*,)* $o: &mut $crate::records::Out<'_>)
                    -> ::core::result::Result<(), $crate::fail::Fail> }]
            [$($sigs)* sync fn $name(s: &mut Session $(, $a: $($ty)*)*) -> Result<(), Fail>;]
            [$($gen)* (on_session $name [$($slot)*] [$(($a [$($hty)*]))*])]
            $($rest)*
        }
    };
    (@gen [end $ctx:tt [$($slot:tt)*] [$($items:tt)*] [$($sigs:tt)*] [$($gen:tt)*] [$(#[$md:meta])*] $name:ident $slf:ident $h:ident [$s:ident] [] [$($rest:tt)*]]
        [] [$o:ident]
    ) => {
        $crate::kind! { @adapter end $ctx [$($slot)*] $name [] }
        $crate::kind! { @methods $ctx [$($slot)* + 1]
            [$($items)* $crate::kind! { @fn [] $(#[$md])*
                fn $name(&$slf, $h: &$crate::host::Host, $s: Self::Session, $o: &mut $crate::records::Out<'_>)
                    -> ::core::result::Result<(), $crate::fail::Fail> }]
            [$($sigs)* sync end fn $name(s: Session) -> Result<(), Fail>;]
            [$($gen)* (ends $name [$($slot)*] [])]
            $($rest)*
        }
    };
    (@gen [open $ctx:tt [$($slot:tt)*] [$($items:tt)*] [$($sigs:tt)*] [$($gen:tt)*] [$(#[$md:meta])*] $name:ident $slf:ident $h:ident [] [$($def:block)?] [$($rest:tt)*]]
        [$(($a:ident $mode:ident [$($ty:tt)*] [$($rty:tt)*] [$($hty:tt)*]))*] [$o:ident]
    ) => {
        $crate::kind! { @adapter open $ctx [$($slot)*] $name [$(($a $mode [$($rty)*]))*] }
        $crate::kind! { @methods $ctx [$($slot)* + 1]
            [$($items)* $crate::kind! { @fn [$($def)?] $(#[$md])*
                fn $name(&$slf, $h: &$crate::host::Host, $($a: $($ty)*,)* $o: &mut $crate::records::Out<'_>)
                    -> ::core::result::Result<Self::Session, $crate::fail::Fail> }]
            [$($sigs)* sync open fn $name($($a: $($ty)*),*) -> Result<Session, Fail>;]
            [$($gen)* (opens $name [$($slot)*] [$(($a [$($hty)*]))*])]
            $($rest)*
        }
    };
    (@gen [start $ctx:tt [$($slot:tt)*] [$($items:tt)*] [$($sigs:tt)*] [$($gen:tt)*] [$(#[$md:meta])*] $name:ident $slf:ident $h:ident [] [$($def:block)?] [$($rest:tt)*]]
        [$(($a:ident $mode:ident [$($ty:tt)*] [$($rty:tt)*] [$($hty:tt)*]))*] []
    ) => {
        $crate::kind! { @adapter start $ctx [$($slot)*] $name [$(($a $mode [$($rty)*]))*] }
        $crate::kind! { @methods $ctx [$($slot)* + 1]
            [$($items)* $crate::kind! { @async [$($def)?] $(#[$md])*
                fn $name(&$slf, $h: &'static $crate::host::Host $(, $a: $($ty)*)*)
                    -> impl ::core::future::Future<
                        Output = ::core::result::Result<$crate::records::Reply, $crate::fail::Fail>,
                    > + Send }]
            [$($sigs)* async fn $name($($a: $($ty)*),*) -> Result<Reply, Fail>;]
            [$($gen)* (starts $name [$($slot)*] [$(($a [$($hty)*]))*])]
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

    // ---- how an unpacked argument is handed to the author's method ----
    (@pass val $a:ident) => { $a };
    (@pass view $a:ident) => { &$a };

    // ---- adapters: busbar-ffi's five per-slot traits. Each unpacks the call (`call::Reader`, by position)
    // into the typed trait call; a call off its layout is FAULT ----
    (@adapter call [$Trait:ident $($x:tt)*] [$($slot:tt)*] $name:ident [$(($a:ident $mode:ident [$($rty:tt)*]))*]) => {
        impl<T: $Trait + $crate::plugin::Glue> $crate::plugin::__rt::shim::Plain<{ $($slot)* }> for Shim<T> {
            fn call(
                p: &T,
                h: &'static $crate::host::Host,
                args: $crate::plugin::__rt::Args<'_>,
                out: &mut $crate::plugin::__rt::Out<'_>,
            ) -> $crate::types::Status {
                #[allow(unused_mut, unused_variables)]
                let mut r = $crate::call::Reader::new(args);
                $(
                    let $a: $($rty)* = match $crate::call::Get::get(&mut r) {
                        ::core::option::Option::Some(v) => v,
                        ::core::option::Option::None => return $crate::types::Status::FAULT,
                    };
                )*
                $crate::plugin::sync(out, |o| {
                    <T as $Trait>::$name(p, h, $($crate::kind!(@pass $mode $a),)* o)
                })
            }
        }
    };
    (@adapter open [$Trait:ident $($x:tt)*] [$($slot:tt)*] $name:ident [$(($a:ident $mode:ident [$($rty:tt)*]))*]) => {
        impl<T: $Trait + $crate::plugin::Glue> $crate::plugin::__rt::shim::Opens<{ $($slot)* }> for Shim<T> {
            fn begin(
                p: &T,
                h: &'static $crate::host::Host,
                args: $crate::plugin::__rt::Args<'_>,
                out: &mut $crate::plugin::__rt::Out<'_>,
            ) -> ::core::result::Result<<Self as $crate::plugin::__rt::shim::Image>::Session, $crate::types::Status> {
                #[allow(unused_mut, unused_variables)]
                let mut r = $crate::call::Reader::new(args);
                $(
                    let $a: $($rty)* = match $crate::call::Get::get(&mut r) {
                        ::core::option::Option::Some(v) => v,
                        ::core::option::Option::None => {
                            return ::core::result::Result::Err($crate::types::Status::FAULT);
                        }
                    };
                )*
                $crate::plugin::opener(out, |o| {
                    <T as $Trait>::$name(p, h, $($crate::kind!(@pass $mode $a),)* o)
                })
            }
        }
    };
    (@adapter on [$Trait:ident $($x:tt)*] [$($slot:tt)*] $name:ident [$(($a:ident $mode:ident [$($rty:tt)*]))*]) => {
        impl<T: $Trait + $crate::plugin::Glue> $crate::plugin::__rt::shim::OnSession<{ $($slot)* }> for Shim<T> {
            fn on(
                p: &T,
                h: &'static $crate::host::Host,
                s: &mut <Self as $crate::plugin::__rt::shim::Image>::Session,
                args: $crate::plugin::__rt::Args<'_>,
                out: &mut $crate::plugin::__rt::Out<'_>,
            ) -> $crate::types::Status {
                #[allow(unused_mut, unused_variables)]
                let mut r = $crate::call::Reader::new(args);
                $(
                    let $a: $($rty)* = match $crate::call::Get::get(&mut r) {
                        ::core::option::Option::Some(v) => v,
                        ::core::option::Option::None => return $crate::types::Status::FAULT,
                    };
                )*
                $crate::plugin::sync(out, |o| {
                    <T as $Trait>::$name(p, h, s, $($crate::kind!(@pass $mode $a),)* o)
                })
            }
        }
    };
    (@adapter end [$Trait:ident $($x:tt)*] [$($slot:tt)*] $name:ident []) => {
        impl<T: $Trait + $crate::plugin::Glue> $crate::plugin::__rt::shim::Ends<{ $($slot)* }> for Shim<T> {
            fn end(
                p: &T,
                h: &'static $crate::host::Host,
                s: <Self as $crate::plugin::__rt::shim::Image>::Session,
                _args: $crate::plugin::__rt::Args<'_>,
                out: &mut $crate::plugin::__rt::Out<'_>,
            ) -> $crate::types::Status {
                $crate::plugin::sync(out, |o| <T as $Trait>::$name(p, h, s, o))
            }
        }
    };
    (@adapter start [$Trait:ident $($x:tt)*] [$($slot:tt)*] $name:ident [$(($a:ident $mode:ident [$($rty:tt)*]))*]) => {
        impl<T: $Trait + $crate::plugin::Glue> $crate::plugin::__rt::shim::Starts<{ $($slot)* }> for Shim<T> {
            fn start<'i>(
                p: &'i T,
                h: &'static $crate::host::Host,
                args: $crate::plugin::__rt::ChainArgs<'_>,
            ) -> ::core::option::Option<(
                $crate::plugin::__rt::ChainFut<'i, $crate::plugin::Outcome<T>>,
                $crate::bridge::Inbox,
            )> {
                #[allow(unused_mut, unused_variables)]
                let mut r = $crate::call::ChainReader::new(args);
                $( let $a: $($rty)* = $crate::call::ChainGet::get(&mut r)?; )*
                ::core::option::Option::Some($crate::plugin::chain(<T as $Trait>::$name(p, h $(, $a)*)))
            }
        }
    };

    // ---- one table entry, by the method's role ----
    (@entry plain $T:ident [$($slot:tt)*]) => { $crate::plugin::__rt::shim::plain::<Shim<$T>, { $($slot)* }>() };
    (@entry opens $T:ident [$($slot:tt)*]) => { $crate::plugin::__rt::shim::opens::<Shim<$T>, { $($slot)* }>() };
    (@entry on_session $T:ident [$($slot:tt)*]) => { $crate::plugin::__rt::shim::on_session::<Shim<$T>, { $($slot)* }>() };
    (@entry ends $T:ident [$($slot:tt)*]) => { $crate::plugin::__rt::shim::ends::<Shim<$T>, { $($slot)* }>() };
    (@entry starts $T:ident [$($slot:tt)*]) => { $crate::plugin::__rt::shim::starts::<Shim<$T>, { $($slot)* }>() };

    // ---- after the last method: the table, the names, the slots and the host-side packers ----
    (@finish [$Trait:ident $($x:tt)*]
        $( ($role:ident $name:ident [$($slot:tt)*] [$(($a:ident [$($hty:tt)*]))*]) )*
    ) => {
        /// The method names, by table position.
        pub const METHODS: [&str; ENTRIES] = [$(stringify!($name)),*];

        /// Each method's position in the kind's table (= its `M_*` bit number).
        #[allow(non_upper_case_globals)]
        pub mod slot {
            $( pub const $name: usize = $($slot)*; )*
        }

        /// The kind's table built over `Shim<T>`: an array of `ENTRIES` entries, every one busbar-ffi's
        /// shim for this image, in declaration order.
        pub const fn table<T: $Trait + $crate::plugin::Glue>(
        ) -> $crate::plugin::__rt::Table<Shim<T>, ENTRIES> {
            $crate::plugin::__rt::Table::new([
                $( $crate::kind!(@entry $role T [$($slot)*]), )*
            ])
        }

        /// The host's half of every method: build the method's `Call` on the stack (numbers into `head`,
        /// texts and blobs by position, nothing copied) and hand it to `f` for the one crossing. `mono_ns`
        /// is the host's one clock reading for the operation. The session of a session method is not an
        /// argument: the host's session handle puts its own token in the call.
        pub mod pack {
            #[allow(unused_imports)]
            use super::*;
            $(
                #[allow(clippy::too_many_arguments, unused_mut)]
                pub fn $name<R>(
                    mono_ns: u64,
                    $( $a: $($hty)*, )*
                    f: impl ::core::ops::FnOnce(&$crate::types::Call<'_>) -> R,
                ) -> R {
                    let mut w = $crate::call::Packer::new();
                    $( $crate::call::Put::put($a, &mut w); )*
                    w.with(mono_ns, f)
                }
            )*
        }
    };

    // ---- the entry: the IF §7.6 grammar, with or without a retired list ----
    (
        $(#[$doc:meta])*
        pub trait $Trait:ident : kind = $kind:tt , abi = $abi:tt $(, $session:ident)? {
            views { $($views:tt)* }
            pods { $($pods:tt)* }
            tags { $($tags:tt)* }
            consts { $($consts:tt)* }
            retired { $($retired:tt)* }
            $($methods:tt)*
        }
    ) => {
        $crate::kind! { @number $kind [$(#[$doc])*] $Trait $kind $abi [$($session)?]
            [$($views)*] [$($pods)*] [$($tags)*] [$($consts)*] [$($retired)*] [$($methods)*] }
    };
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
            [$($views)*] [$($pods)*] [$($tags)*] [$($consts)*] [] [$($methods)*] }
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
        pub trait TStore: kind = 1, abi = 4 {
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
        pub trait TSecret: kind = 2, abi = 3 {
            views {}
            pods {}
            tags { VALUE = 0x0100; }
            consts { REQUIRED: u64 = 0b1; }
            async fn resolve(&self, h: &'static Host, reference: ChainBytes) -> Result<Reply, Fail>;
        }
    }

    crate::kind! {
        /// An auth-shaped test kind.
        pub trait TAuth: kind = 3, abi = 4 {
            views {
                pub struct AuthReq<'a> {
                    pub flags: u32,
                    pub _r: u32,
                    pub method: crate::types::Str<'a>,
                    pub path: crate::types::Str<'a>,
                    pub query: crate::types::Str<'a>,
                    pub authority: crate::types::Str<'a>,
                    pub headers: crate::types::Slice<'a, crate::types::Pair<'a>>,
                    pub peer: crate::types::Str<'a>,
                    pub tls_peer_cert: crate::types::Bytes<'a>,
                    pub body: crate::types::Bytes<'a>,
                    pub issued: crate::types::Bytes<'a>,
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
        pub trait THook: kind = 4, abi = 3 {
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
        pub trait TExport: kind = 5, abi = 4 {
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
        pub trait TPlane: kind = 6, abi = 2, session {
            views {
                pub struct PlaneReq<'a> {
                    pub route: u32,
                    pub flags: u32,
                    pub auth: u32,
                    pub _r: u32,
                    pub method: crate::types::Str<'a>,
                    pub path: crate::types::Str<'a>,
                    pub query: crate::types::Str<'a>,
                    pub headers: crate::types::Slice<'a, crate::types::Pair<'a>>,
                    pub identity: crate::types::Bytes<'a>,
                    pub request_id: u64,
                    pub carrier: u64,
                    pub work: crate::types::Str<'a>,
                    pub ticket_record: crate::types::Bytes<'a>,
                }
                pub struct Target<'a> {
                    pub attempt: u32,
                    pub flags: u32,
                    pub dialect: crate::types::Str<'a>,
                    pub model: crate::types::Str<'a>,
                    pub base_path: crate::types::Str<'a>,
                    pub upstream: crate::types::Str<'a>,
                    pub provider: crate::types::Str<'a>,
                    pub params: crate::types::Slice<'a, crate::types::Pair<'a>>,
                    pub admission: crate::types::Bytes<'a>,
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
            sync fn select_resources(&self, h: &Host, mode: u32, req: &PlaneReq<'_>, body: Bytes<'_>, out: &mut Out<'_>) -> Result<(), Fail> {
                let _ = (h, mode, req, body, out);
                Err(crate::fail::Fail::unsupported())
            }
            sync fn channel(&self, h: &Host, s: &mut Session, target: &Target<'_>, out: &mut Out<'_>) -> Result<(), Fail> {
                let _ = (h, s, target, out);
                Err(crate::fail::Fail::unsupported())
            }
        }
    }

    crate::kind! {
        /// A transport-shaped test kind.
        pub trait TTransport: kind = 7, abi = 2, session {
            views {
                pub struct ConnInfo<'a> {
                    pub role: u32,
                    pub flags: u32,
                    pub alpn: crate::types::Str<'a>,
                    pub sni: crate::types::Str<'a>,
                    pub peer: crate::types::Str<'a>,
                    pub local: crate::types::Str<'a>,
                    pub tls_peer_cert: crate::types::Bytes<'a>,
                    pub leftover: crate::types::Bytes<'a>,
                    pub head: crate::types::Bytes<'a>,
                    pub local_fingerprint: crate::types::Str<'a>,
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
                // Plane: slots 0-8, select_resources at 9 (880432c87e) and channel at 10 (d1f06e6381).
                0b111_1111_1111,
                0b111_1111
            ]
        );
        let mut fps: Vec<u64> = kinds.iter().map(|k| k.3).collect();
        fps.sort();
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
                pub trait B: kind = 2, abi = 3 {
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
                pub trait B: kind = 2, abi = 3 {
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
                pub trait B: kind = 2, abi = 3 {
                    views {} pods {} tags {} consts { REQUIRED: u64 = 0b1; }
                    /// A doc line does not move the fingerprint.
                    async fn resolve(&self, h: &'static Host, reference: ChainBytes) -> Result<Reply, Fail> {
                        let _ = (h, reference);
                        Err(crate::fail::Fail::unsupported())
                    }
                }
            }
        }
        // a and b differ only in a default body; b and c only by one doc line. Neither is wire: a wording
        // fix must not move a pin or refuse a plugin (interface revision C.1 cause 3, C.7).
        assert_eq!(a::secret::FP, b::secret::FP, "a default body is not hashed");
        assert_eq!(b::secret::FP, c::secret::FP, "a comment is not hashed");
    }

    #[cfg(feature = "host")]
    mod run {
        use super::*;
        use crate::host::HostFns;
        use crate::plugin::__rt::host::{OpenAnswer, OutLease};
        use crate::plugin::__rt::image::Admitted;
        use crate::plugin::__rt::kind as marker;
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
                service: None,
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
                super::auth::pack::verify(0, &req, |call| inst.call(
                    super::auth::slot::verify,
                    call,
                    &mut out
                )),
                Status::OK
            );
            assert_eq!(tags(&out), [super::auth::tag::GRANT]);
            drop(out);
            req.flags = 1;
            let mut out = lease();
            assert_eq!(
                super::auth::pack::verify(0, &req, |call| inst.call(
                    super::auth::slot::verify,
                    call,
                    &mut out
                )),
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
            let started = inst.start(
                super::secret::slot::resolve,
                Default::default(),
                |_, cross| super::secret::pack::resolve(0, Bytes::EMPTY, cross),
                &mut out,
            );
            assert!(matches!(started, Started::Done(Status::OK)));
            assert_eq!(tags(&out), [super::secret::tag::VALUE]);
        }
    }
}
