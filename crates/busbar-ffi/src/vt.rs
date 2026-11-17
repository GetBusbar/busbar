// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The seven kind tables, the fn-pointer aliases their entries have, the four views they name, and the
//! sealed `Kind` (UNSAFE-MIN §2.2 A2, §2.4; IF §7.6, §8).
//!
//! busbar-ffi owns every layout and implements `Kind` for its seven markers itself, so no caller can
//! pick a table type: `Admitted::vt::<K>` checks `stamp.kind == K::CODE` and the layout is this crate's.
//! A table is built only by its `Vt::build::<M>()`, which fills every entry with a shim instantiated
//! with that one image `M`.
//!
//! `unsafe` here: the aliases of the entries that take an instance pointer (`EntryFn0..=EntryFn5`,
//! `ResumeFn`, `CancelFn`, `CloseFn`). `DescribeFn` and `OpenFn` take no raw pointer and are safe.

#![allow(unsafe_code)]

use core::ffi::c_void;
use core::marker::PhantomData;

use crate::raw::{
    Arg, Bytes, Family, Host, KindCode, Pair, RawOut, Slice, Status, Str, Token, View, ViewRef,
    seal,
};
use crate::shim::{
    self, Call0, Call1, Call2, Call3, End0, Opener1, Opener2, Session0, Session1, Session2,
    Session3, Session4, Start0, Start1, Start2, Start4,
};

mechanism! {
/// A kind entry with no argument: `(inst, h, out)`. Higher-ranked over the call's `'a`.
pub type EntryFn0 = for<'a> unsafe extern "C" fn(*const c_void, &'static Host, &'a mut RawOut) -> Status;
/// A kind entry with one raw argument (a session method's first is its token).
pub type EntryFn1<A1> =
    for<'a> unsafe extern "C" fn(*const c_void, &'static Host, Arg<'a, A1>, &'a mut RawOut) -> Status;
pub type EntryFn2<A1, A2> = for<'a> unsafe extern "C" fn(
    *const c_void, &'static Host, Arg<'a, A1>, Arg<'a, A2>, &'a mut RawOut,
) -> Status;
pub type EntryFn3<A1, A2, A3> = for<'a> unsafe extern "C" fn(
    *const c_void, &'static Host, Arg<'a, A1>, Arg<'a, A2>, Arg<'a, A3>, &'a mut RawOut,
) -> Status;
pub type EntryFn4<A1, A2, A3, A4> = for<'a> unsafe extern "C" fn(
    *const c_void, &'static Host, Arg<'a, A1>, Arg<'a, A2>, Arg<'a, A3>, Arg<'a, A4>, &'a mut RawOut,
) -> Status;
pub type EntryFn5<A1, A2, A3, A4, A5> = for<'a> unsafe extern "C" fn(
    *const c_void, &'static Host, Arg<'a, A1>, Arg<'a, A2>, Arg<'a, A3>, Arg<'a, A4>, Arg<'a, A5>,
    &'a mut RawOut,
) -> Status;
/// Cold. Writes describe items only.
pub type DescribeFn = for<'a> extern "C" fn(&'static Host, &'a mut RawOut) -> Status;
/// Cold. `config` = the bound JSON; flags: DRY_RUN. OK + INSTANCE, or NEED (an open chain), or a FAIL.
pub type OpenFn = for<'a> extern "C" fn(&'static Host, Arg<'a, Bytes<'static>>, u32, &'a mut RawOut) -> Status;
/// Continue a chain; `inst` null for open chains.
pub type ResumeFn = for<'a> unsafe extern "C" fn(
    *const c_void, &'static Host, Arg<'a, u64>, Arg<'a, Bytes<'static>>, &'a mut RawOut,
) -> Status;
/// Drop a chain (bit 63 clear) or a session (bit 63 set); `inst` null = the open slab. Idempotent.
pub type CancelFn = unsafe extern "C" fn(*const c_void, Token) -> Status;
/// Drop the instance with its chains and sessions, the plugin value last.
pub type CloseFn = unsafe extern "C" fn(*const c_void) -> Status;
}

/// One table entry. Nullable in C (a null is refused at admit; past admit a call on it is FAULT). Not
/// `Copy` or `Clone`, and built only by a `Vt::build`, so an entry cannot be lifted out of its table.
#[repr(transparent)]
pub struct VtEntry<F>(Option<F>);

impl<F: Copy> VtEntry<F> {
    pub(crate) const fn new(f: F) -> Self {
        VtEntry(Some(f))
    }
    /// The fn pointer, for the host's call blocks.
    #[cfg(feature = "host")]
    pub(crate) fn get(&self) -> Option<F> {
        self.0
    }
    pub fn is_null(&self) -> bool {
        self.0.is_none()
    }
}

/// A table built for image `M`: every entry is `M`'s shim. Only `Vt::build` makes one.
pub struct Built<M, V> {
    vt: V,
    _m: PhantomData<fn() -> M>,
}

impl<M, V> Built<M, V> {
    const fn new(vt: V) -> Self {
        Built {
            vt,
            _m: PhantomData,
        }
    }
    /// The table's address, for the header's `kind_vt`.
    pub(crate) const fn as_ptr(&self) -> *const c_void {
        core::ptr::from_ref(&self.vt).cast()
    }
}

mod sealed {
    pub trait Kind {}
}

/// One of the seven kinds. Sealed: busbar-ffi implements it for `kind::*` only, so `K::Vt` is always one of
/// its own seven layouts.
pub trait Kind: sealed::Kind + 'static {
    const CODE: KindCode;
    type Vt: Sync + 'static;
}

/// The kind markers.
pub mod kind {
    pub struct Store;
    pub struct Secret;
    pub struct Auth;
    pub struct Hook;
    pub struct Export;
    pub struct Plane;
    pub struct Transport;
}

/// The four views the tables name (IF §8.3, §8.6, §8.7; the C header's view structs). Plain C data:
/// `Copy`, only pointer, length and `View` fields, no implicit padding.
pub mod views {
    use crate::raw::{Bytes, Pair, Slice, Str};

    /// One inbound request (auth `verify`).
    #[repr(C)]
    #[derive(Clone, Copy)]
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

    /// One plane request (`request`, `render`).
    #[repr(C)]
    #[derive(Clone, Copy)]
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

    /// One upstream attempt or probe target (`upstream`, `probe`).
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct Target<'a> {
        pub attempt: u32,
        pub flags: u32,
        pub dialect: Str<'a>,
        pub model: Str<'a>,
        pub base_path: Str<'a>,
        pub upstream: Str<'a>,
        pub provider: Str<'a>,
        pub params: Slice<'a, Pair<'a>>,
        pub admission: Bytes<'a>,
    }

    /// One connection (transport `begin`).
    #[repr(C)]
    #[derive(Clone, Copy)]
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

use views::{AuthReq, ConnInfo, PlaneReq, Target};

const STR: usize = size_of::<Str<'static>>();
const BYTES: usize = size_of::<Bytes<'static>>();
const PAIRS: usize = size_of::<Slice<'static, Pair<'static>>>();
const _: () = assert!(size_of::<AuthReq<'static>>() == 8 + 5 * STR + PAIRS + 3 * BYTES + 8);
const _: () = assert!(size_of::<PlaneReq<'static>>() == 16 + 4 * STR + PAIRS + 2 * BYTES + 16);
const _: () = assert!(size_of::<Target<'static>>() == 8 + 5 * STR + PAIRS);
const _: () = assert!(size_of::<ConnInfo<'static>>() == 8 + 5 * STR + 3 * BYTES + 8);

impl seal::Sealed for AuthReq<'_> {}
impl seal::Sealed for PlaneReq<'_> {}
impl seal::Sealed for Target<'_> {}
impl seal::Sealed for ConnInfo<'_> {}
impl View for AuthReq<'_> {}
impl View for PlaneReq<'_> {}
impl View for Target<'_> {}
impl View for ConnInfo<'_> {}
impl Family for AuthReq<'static> {
    type Of<'a> = AuthReq<'a>;
}
impl Family for PlaneReq<'static> {
    type Of<'a> = PlaneReq<'a>;
}
impl Family for Target<'static> {
    type Of<'a> = Target<'a>;
}
impl Family for ConnInfo<'static> {
    type Of<'a> = ConnInfo<'a>;
}

/// The raw argument types the tables use.
type B = Bytes<'static>;
type St = Str<'static>;
pub type AuthRef = ViewRef<AuthReq<'static>>;
pub type PlaneRef = ViewRef<PlaneReq<'static>>;
pub type TargetRef = ViewRef<Target<'static>>;
pub type ConnRef = ViewRef<ConnInfo<'static>>;

/// What an entry is, in its type, so the host can only call it the way its kind declares it: a plain
/// call, a session opener, a method on a live session, the consuming end, or an async start. Each is
/// `#[repr(transparent)]` over the fn pointer: the C layout is unchanged.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct Plain<F>(pub(crate) F);
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct Opens<F>(pub(crate) F);
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct OnSession<F>(pub(crate) F);
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct Ends<F>(pub(crate) F);
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct Starts<F>(pub(crate) F);

/// The store table (IF §8, the C header's `bb_store_vt`), in declaration order.
pub mod store {
    use super::*;

    #[repr(C)]
    pub struct Vt {
        pub read: VtEntry<Starts<EntryFn1<B>>>,
        pub scan: VtEntry<Starts<EntryFn1<B>>>,
        pub commit: VtEntry<Starts<EntryFn1<B>>>,
        pub clock: VtEntry<Starts<EntryFn1<B>>>,
        pub info: VtEntry<Plain<EntryFn0>>,
    }

    impl Vt {
        /// The table of image `M`: every entry is a shim instantiated with `M`.
        pub const fn build<M>() -> Built<M, Vt>
        where
            M: Start1<B, 0> + Start1<B, 1> + Start1<B, 2> + Start1<B, 3> + Call0<4>,
        {
            Built::new(Vt {
                read: VtEntry::new(Starts(shim::start1::<M, B, 0>)),
                scan: VtEntry::new(Starts(shim::start1::<M, B, 1>)),
                commit: VtEntry::new(Starts(shim::start1::<M, B, 2>)),
                clock: VtEntry::new(Starts(shim::start1::<M, B, 3>)),
                info: VtEntry::new(Plain(shim::sync0::<M, 4>)),
            })
        }
        /// The first null entry, named (admit refuses it, step 9).
        pub fn null_field(&self) -> Option<&'static str> {
            [
                ("read", self.read.is_null()),
                ("scan", self.scan.is_null()),
                ("commit", self.commit.is_null()),
                ("clock", self.clock.is_null()),
                ("info", self.info.is_null()),
            ]
            .into_iter()
            .find_map(|(name, null)| null.then_some(name))
        }
    }

    impl sealed::Kind for kind::Store {}
    impl Kind for kind::Store {
        const CODE: KindCode = KindCode::Store;
        type Vt = Vt;
    }
}

/// The secret table (IF §8, the C header's `bb_secret_vt`), in declaration order.
pub mod secret {
    use super::*;

    #[repr(C)]
    pub struct Vt {
        pub resolve: VtEntry<Starts<EntryFn1<B>>>,
    }

    impl Vt {
        /// The table of image `M`: every entry is a shim instantiated with `M`.
        pub const fn build<M>() -> Built<M, Vt>
        where
            M: Start1<B, 0>,
        {
            Built::new(Vt {
                resolve: VtEntry::new(Starts(shim::start1::<M, B, 0>)),
            })
        }
        /// The first null entry, named (admit refuses it, step 9).
        pub fn null_field(&self) -> Option<&'static str> {
            [("resolve", self.resolve.is_null())]
                .into_iter()
                .find_map(|(name, null)| null.then_some(name))
        }
    }

    impl sealed::Kind for kind::Secret {}
    impl Kind for kind::Secret {
        const CODE: KindCode = KindCode::Secret;
        type Vt = Vt;
    }
}

/// The auth table (IF §8, the C header's `bb_auth_vt`), in declaration order.
pub mod auth {
    use super::*;

    #[repr(C)]
    pub struct Vt {
        pub verify: VtEntry<Plain<EntryFn1<AuthRef>>>,
        pub verify_io: VtEntry<Starts<EntryFn1<B>>>,
        pub login: VtEntry<Starts<EntryFn2<u32, B>>>,
        pub outbound: VtEntry<Starts<EntryFn1<B>>>,
        pub refresh: VtEntry<Starts<EntryFn0>>,
        pub serve: VtEntry<Starts<EntryFn1<B>>>,
    }

    impl Vt {
        /// The table of image `M`: every entry is a shim instantiated with `M`.
        pub const fn build<M>() -> Built<M, Vt>
        where
            M: Call1<AuthRef, 0>
                + Start1<B, 1>
                + Start2<u32, B, 2>
                + Start1<B, 3>
                + Start0<4>
                + Start1<B, 5>,
        {
            Built::new(Vt {
                verify: VtEntry::new(Plain(shim::sync1::<M, AuthRef, 0>)),
                verify_io: VtEntry::new(Starts(shim::start1::<M, B, 1>)),
                login: VtEntry::new(Starts(shim::start2::<M, u32, B, 2>)),
                outbound: VtEntry::new(Starts(shim::start1::<M, B, 3>)),
                refresh: VtEntry::new(Starts(shim::start0::<M, 4>)),
                serve: VtEntry::new(Starts(shim::start1::<M, B, 5>)),
            })
        }
        /// The first null entry, named (admit refuses it, step 9).
        pub fn null_field(&self) -> Option<&'static str> {
            [
                ("verify", self.verify.is_null()),
                ("verify_io", self.verify_io.is_null()),
                ("login", self.login.is_null()),
                ("outbound", self.outbound.is_null()),
                ("refresh", self.refresh.is_null()),
                ("serve", self.serve.is_null()),
            ]
            .into_iter()
            .find_map(|(name, null)| null.then_some(name))
        }
    }

    impl sealed::Kind for kind::Auth {}
    impl Kind for kind::Auth {
        const CODE: KindCode = KindCode::Auth;
        type Vt = Vt;
    }
}

/// The hook table (IF §8, the C header's `bb_hook_vt`), in declaration order.
pub mod hook {
    use super::*;

    #[repr(C)]
    pub struct Vt {
        pub on: VtEntry<Plain<EntryFn2<u32, B>>>,
        pub on_io: VtEntry<Starts<EntryFn2<u32, B>>>,
    }

    impl Vt {
        /// The table of image `M`: every entry is a shim instantiated with `M`.
        pub const fn build<M>() -> Built<M, Vt>
        where
            M: Call2<u32, B, 0> + Start2<u32, B, 1>,
        {
            Built::new(Vt {
                on: VtEntry::new(Plain(shim::sync2::<M, u32, B, 0>)),
                on_io: VtEntry::new(Starts(shim::start2::<M, u32, B, 1>)),
            })
        }
        /// The first null entry, named (admit refuses it, step 9).
        pub fn null_field(&self) -> Option<&'static str> {
            [("on", self.on.is_null()), ("on_io", self.on_io.is_null())]
                .into_iter()
                .find_map(|(name, null)| null.then_some(name))
        }
    }

    impl sealed::Kind for kind::Hook {}
    impl Kind for kind::Hook {
        const CODE: KindCode = KindCode::Hook;
        type Vt = Vt;
    }
}

/// The export table (IF §8, the C header's `bb_export_vt`), in declaration order.
pub mod export {
    use super::*;

    #[repr(C)]
    pub struct Vt {
        pub deliver: VtEntry<Starts<EntryFn4<u32, u64, u32, B>>>,
        pub render: VtEntry<Plain<EntryFn2<u32, B>>>,
        pub confirm: VtEntry<Starts<EntryFn1<u64>>>,
    }

    impl Vt {
        /// The table of image `M`: every entry is a shim instantiated with `M`.
        pub const fn build<M>() -> Built<M, Vt>
        where
            M: Start4<u32, u64, u32, B, 0> + Call2<u32, B, 1> + Start1<u64, 2>,
        {
            Built::new(Vt {
                deliver: VtEntry::new(Starts(shim::start4::<M, u32, u64, u32, B, 0>)),
                render: VtEntry::new(Plain(shim::sync2::<M, u32, B, 1>)),
                confirm: VtEntry::new(Starts(shim::start1::<M, u64, 2>)),
            })
        }
        /// The first null entry, named (admit refuses it, step 9).
        pub fn null_field(&self) -> Option<&'static str> {
            [
                ("deliver", self.deliver.is_null()),
                ("render", self.render.is_null()),
                ("confirm", self.confirm.is_null()),
            ]
            .into_iter()
            .find_map(|(name, null)| null.then_some(name))
        }
    }

    impl sealed::Kind for kind::Export {}
    impl Kind for kind::Export {
        const CODE: KindCode = KindCode::Export;
        type Vt = Vt;
    }
}

/// The plane table (IF §8, the C header's `bb_plane_vt`), in declaration order.
pub mod plane {
    use super::*;

    type PieceFn = OnSession<EntryFn5<u64, u32, u32, u32, B>>;

    #[repr(C)]
    pub struct Vt {
        pub request: VtEntry<Opens<EntryFn2<PlaneRef, B>>>,
        pub upstream: VtEntry<OnSession<EntryFn2<u64, TargetRef>>>,
        pub piece: VtEntry<PieceFn>,
        pub end: VtEntry<Ends<EntryFn1<u64>>>,
        pub rewrite: VtEntry<OnSession<EntryFn2<u64, B>>>,
        pub render: VtEntry<Plain<EntryFn3<PlaneRef, u32, B>>>,
        pub admin: VtEntry<Starts<EntryFn2<u32, B>>>,
        pub probe: VtEntry<Opens<EntryFn1<TargetRef>>>,
        pub demux: VtEntry<Plain<EntryFn2<St, B>>>,
        pub select_resources: VtEntry<Plain<EntryFn3<u32, PlaneRef, B>>>,
    }

    impl Vt {
        /// The table of image `M`: every entry is a shim instantiated with `M`.
        pub const fn build<M>() -> Built<M, Vt>
        where
            M: Opener2<PlaneRef, B, 0>
                + Session1<TargetRef, 1>
                + Session4<u32, u32, u32, B, 2>
                + End0<3>
                + Session1<B, 4>
                + Call3<PlaneRef, u32, B, 5>
                + Start2<u32, B, 6>
                + Opener1<TargetRef, 7>
                + Call2<St, B, 8>
                + Call3<u32, PlaneRef, B, 9>,
        {
            Built::new(Vt {
                request: VtEntry::new(Opens(shim::opener2::<M, PlaneRef, B, 0>)),
                upstream: VtEntry::new(OnSession(shim::session1::<M, TargetRef, 1>)),
                piece: VtEntry::new(OnSession(shim::session4::<M, u32, u32, u32, B, 2>)),
                end: VtEntry::new(Ends(shim::end0::<M, 3>)),
                rewrite: VtEntry::new(OnSession(shim::session1::<M, B, 4>)),
                render: VtEntry::new(Plain(shim::sync3::<M, PlaneRef, u32, B, 5>)),
                admin: VtEntry::new(Starts(shim::start2::<M, u32, B, 6>)),
                probe: VtEntry::new(Opens(shim::opener1::<M, TargetRef, 7>)),
                demux: VtEntry::new(Plain(shim::sync2::<M, St, B, 8>)),
                select_resources: VtEntry::new(Plain(shim::sync3::<M, u32, PlaneRef, B, 9>)),
            })
        }
        /// The first null entry, named (admit refuses it, step 9).
        pub fn null_field(&self) -> Option<&'static str> {
            [
                ("request", self.request.is_null()),
                ("upstream", self.upstream.is_null()),
                ("piece", self.piece.is_null()),
                ("end", self.end.is_null()),
                ("rewrite", self.rewrite.is_null()),
                ("render", self.render.is_null()),
                ("admin", self.admin.is_null()),
                ("probe", self.probe.is_null()),
                ("demux", self.demux.is_null()),
                ("select_resources", self.select_resources.is_null()),
            ]
            .into_iter()
            .find_map(|(name, null)| null.then_some(name))
        }
    }

    impl sealed::Kind for kind::Plane {}
    impl Kind for kind::Plane {
        const CODE: KindCode = KindCode::Plane;
        type Vt = Vt;
    }
}

/// The transport table (IF §8, the C header's `bb_transport_vt`), in declaration order.
pub mod transport {
    use super::*;

    type EmitFn = OnSession<EntryFn5<u64, u64, u32, u32, B>>;

    #[repr(C)]
    pub struct Vt {
        pub begin: VtEntry<Opens<EntryFn1<ConnRef>>>,
        pub ingest: VtEntry<OnSession<EntryFn2<u64, B>>>,
        pub emit: VtEntry<EmitFn>,
        pub timer: VtEntry<OnSession<EntryFn1<u64>>>,
        pub datagram: VtEntry<OnSession<EntryFn4<u64, u32, u32, B>>>,
        pub event: VtEntry<OnSession<EntryFn3<u64, u32, B>>>,
        pub offer: VtEntry<Plain<EntryFn1<u32>>>,
    }

    impl Vt {
        /// The table of image `M`: every entry is a shim instantiated with `M`.
        pub const fn build<M>() -> Built<M, Vt>
        where
            M: Opener1<ConnRef, 0>
                + Session1<B, 1>
                + Session4<u64, u32, u32, B, 2>
                + Session0<3>
                + Session3<u32, u32, B, 4>
                + Session2<u32, B, 5>
                + Call1<u32, 6>,
        {
            Built::new(Vt {
                begin: VtEntry::new(Opens(shim::opener1::<M, ConnRef, 0>)),
                ingest: VtEntry::new(OnSession(shim::session1::<M, B, 1>)),
                emit: VtEntry::new(OnSession(shim::session4::<M, u64, u32, u32, B, 2>)),
                timer: VtEntry::new(OnSession(shim::session0::<M, 3>)),
                datagram: VtEntry::new(OnSession(shim::session3::<M, u32, u32, B, 4>)),
                event: VtEntry::new(OnSession(shim::session2::<M, u32, B, 5>)),
                offer: VtEntry::new(Plain(shim::sync1::<M, u32, 6>)),
            })
        }
        /// The first null entry, named (admit refuses it, step 9).
        pub fn null_field(&self) -> Option<&'static str> {
            [
                ("begin", self.begin.is_null()),
                ("ingest", self.ingest.is_null()),
                ("emit", self.emit.is_null()),
                ("timer", self.timer.is_null()),
                ("datagram", self.datagram.is_null()),
                ("event", self.event.is_null()),
                ("offer", self.offer.is_null()),
            ]
            .into_iter()
            .find_map(|(name, null)| null.then_some(name))
        }
    }

    impl sealed::Kind for kind::Transport {}
    impl Kind for kind::Transport {
        const CODE: KindCode = KindCode::Transport;
        type Vt = Vt;
    }
}
