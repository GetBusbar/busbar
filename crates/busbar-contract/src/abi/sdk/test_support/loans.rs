// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LOANS (SDK-SAFE-TEST-HOST §3.3): a slot `in` and every byte it points to, owned. A test
//! writes the `in` only through setters generated from the contract's own field lists
//! (`lend_kinds_list!`, `lend_store_list!`, `lend_export_list!` and `lent_field_list!`), so safe
//! code never names a pointer: a string or payload is copied into storage the loans own, a host
//! buffer is allocated here, and a nested struct or list is built through its own loans. The last
//! step before a crossing ([`Loans::seal`]) overwrites every listed (pointer, length) pair from the
//! loans' own storage, NULL and 0 when unset, so a forged length cannot reach a plugin.

use std::any::Any;
use std::marker::PhantomData;
use std::mem::{align_of, size_of};

use super::AllZero;
use crate::abi::auth::{
    BeginLoginIn, CompleteLoginIn, FieldSpan, FieldsIn, IdentityBuf, NamedValue, StripName,
    VerifyIn,
};
use crate::abi::export::{
    CheckIn, CheckInstance, ScrapeFamily, ScrapeIn, ScrapeLabel, ScrapeSample,
    ServeIn as ExportServeIn,
};
use crate::abi::hook::{
    BudgetBucketState as HookBudgetBucketState, CandidateDynamic as HookCandidateDynamic,
    CandidateStatic as HookCandidateStatic, DecideIn, MessageView as HookMessageView, NotifyIn,
    PromptView as HookPromptView, RequestView as HookRequestView, SignalEntry as HookSignalEntry,
    SignalValue, SIGNAL_TAG_BOOL, SIGNAL_TAG_F64, SIGNAL_TAG_I64, SIGNAL_TAG_STR, SIGNAL_TAG_U64,
};
use crate::abi::mechanism::call::{AbiStr, Blob, Field, Span, BLOB_SECRET};
use crate::abi::mechanism::lifecycle::{OpenIn, ReadyIn, RefreshIn, ValidateIn};
use crate::abi::plane::{
    ArriveIn, AuthenticatedRouteIn, CatalogIn, OnPieceIn, OutField, PlaneCancelIn, PlaneDriveIn,
    PlaneOpenIn, ProjectIn, ProviderFacts, RecordWrite, RefusalIn, ServeIn, UnitCount,
};
use crate::abi::sdk::door::{blank_in, AbiIn};
use crate::abi::sdk::out::Scalar;
use crate::abi::store::HostBuf as StoreHostBuf;
use crate::abi::transport::route::{FieldPredicate, LineEntry, RouteMatch};
use crate::abi::transport::{
    AcceptIn, AdoptIn, ArrivalIn, BeginIn, ConnFacts, DatagramLane, DatagramPath, DatagramRoute,
    Destination, DialIn, EmitIn, EncodeIn, FinishIn, FramePiece, FramerSink, FramingIn, HeadSlots,
    IngestIn, KeyingMaterial, ListenIn, LocateIn, ReadIn, RefuseIn, WriteIn,
};

/// One allocation the loans own and a pointer field may name.
struct Kept {
    /// The pointer field it backs; `None` for storage a string, a nested value or a list element
    /// owns (its pointer was written once, from this storage, and nothing can rewrite it).
    field: Option<&'static str>,
    /// The host buffer field it was allocated for (a `buf` row), kept when a nested struct's or
    /// list element's storage is adopted, so that buffer's [`Buf`] key still reads it.
    buf: Option<&'static str>,
    ptr: *mut u8,
    /// Its length in elements.
    len: usize,
    /// Its size in bytes.
    bytes: usize,
    _own: Box<dyn Any>,
}

/// A slot `in` (or a struct nested in one) and the storage every pointer in it names.
pub struct Loans<T> {
    input: T,
    kept: Vec<Kept>,
}

impl<T: AbiIn> Loans<T> {
    /// A blank `in`: every field zero, every pointer NULL; the host stamps the head.
    #[must_use]
    pub fn new() -> Self {
        Self::wrap(blank_in())
    }
}

impl<T: AbiIn> Default for Loans<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Copy + Pairs> Loans<T> {
    /// THE LAST STEP BEFORE A CROSSING: every listed (pointer, length) pair rewritten from the
    /// loans' own storage, and the `in` the host lends. Its pointers stay valid while `self` lives.
    #[doc(hidden)]
    #[must_use]
    pub fn seal(&mut self) -> T {
        T::stamp(self);
        self.input
    }
}

impl<T> Loans<T> {
    fn wrap(input: T) -> Self {
        Self {
            input,
            kept: Vec::new(),
        }
    }

    /// The values a host buffer holds after a crossing: as many as it was allocated for. The key
    /// reads its own allocation, lent at the top level or inside a nested struct (a framer's
    /// `sink.wire`); a buffer since replaced by another reads empty.
    #[must_use]
    pub fn read<E: Scalar>(&self, key: &Buf<E>) -> &[E] {
        let Some(k) = self
            .kept
            .iter()
            .find(|k| k.buf == Some(key.field) && k.ptr.addr() == key.at)
        else {
            return &[];
        };
        assert!(align_of::<E>() <= align_of::<u64>() && size_of::<E>() > 0);
        let n = k.len.min(k.bytes / size_of::<E>());
        // SAFETY: `k` is a `Vec<u64>` these loans own, `bytes` long and aligned for `E` (checked
        // above); `n` elements of `E` fit in it. Every bit pattern is a valid `E`: a `Scalar` is
        // a plain number or a struct of plain numbers, holding no pointer, enum or `bool`.
        unsafe { std::slice::from_raw_parts(k.ptr.cast::<E>(), n) }
    }

    /// Owns `v`, under `field` or unnamed, and answers its pointer. What `field` held before is
    /// retired, not freed: it stays owned, named by no field and read by no key, until the loans
    /// drop, so a SHORT answer's re-call lent a grown buffer never frees one the first call was
    /// lent (STH-ROWS D-6, D-8).
    fn keep<E: 'static>(&mut self, field: Option<&'static str>, mut v: Vec<E>) -> *mut u8 {
        let (ptr, len, bytes) = (
            v.as_mut_ptr().cast::<u8>(),
            v.len(),
            size_of::<E>() * v.len(),
        );
        if field.is_some() {
            for k in self.kept.iter_mut().filter(|k| k.field == field) {
                k.field = None;
                k.buf = None;
            }
        }
        self.kept.push(Kept {
            field,
            buf: None,
            ptr,
            len,
            bytes,
            _own: Box::new(v),
        });
        ptr
    }

    /// The storage `field` names, or NULL and 0.
    fn lent(&self, field: &'static str) -> (*mut u8, usize) {
        self.kept
            .iter()
            .find(|k| k.field == Some(field))
            .map_or((std::ptr::null_mut(), 0), |k| (k.ptr, k.len))
    }

    /// A nested value built by `build`, its storage moved in unnamed.
    fn nested<E: Pairs>(&mut self, v: E, build: impl FnOnce(&mut Loans<E>)) -> E {
        let mut l = Loans::wrap(v);
        build(&mut l);
        E::stamp(&mut l);
        self.adopt(l.kept);
        l.input
    }

    fn adopt(&mut self, kept: Vec<Kept>) {
        self.kept
            .extend(kept.into_iter().map(|k| Kept { field: None, ..k }));
    }

    fn own_text(&mut self, s: &[u8]) -> AbiStr {
        let len = s.len();
        AbiStr {
            ptr: self.keep(None, Vec::from(s)).cast_const(),
            len,
        }
    }

    /// The `BLOB_SECRET` payload setters (STH-ROWS D-8): `loans.secret().credential(b, fmt)` lends
    /// the copy flagged as a secret, as production lends a resolved credential. One setter per
    /// `blob` row, each named as its plain setter is.
    pub fn secret(&mut self) -> SecretBlobs<'_, T> {
        SecretBlobs(self)
    }
}

/// The secret-flagged payload setters of one struct's loans ([`Loans::secret`]).
pub struct SecretBlobs<'a, T>(&'a mut Loans<T>);

/// A signal's value, for the `value` setter of a `SignalEntry`'s loans (STH-ROWS D-8): the setter
/// writes the tag and the whole 16-byte union together, so safe code cannot pair the string tag
/// with integer bits. There is no `tag` setter.
#[derive(Debug, Clone, PartialEq)]
pub enum SignalArg {
    /// `SIGNAL_TAG_U64`.
    U64(u64),
    /// `SIGNAL_TAG_I64`.
    I64(i64),
    /// `SIGNAL_TAG_F64`.
    F64(f64),
    /// `SIGNAL_TAG_BOOL`.
    Bool(bool),
    /// `SIGNAL_TAG_STR`: the bytes, copied into storage the loans own.
    Str(Vec<u8>),
}

/// The key to a host buffer the loans allocated: [`Loans::read`] answers its values.
#[derive(Debug, Clone, Copy)]
pub struct Buf<E> {
    field: &'static str,
    /// The allocation's address: which buffer of that field this key names.
    at: usize,
    _e: PhantomData<fn() -> E>,
}

/// The elements of a listed array, each built through its own loans.
pub struct List<E> {
    items: Vec<E>,
    kept: Vec<Kept>,
}

impl<E: AllZero + Pairs> List<E> {
    /// One more element, all zero until `build` sets it.
    pub fn push(&mut self, build: impl FnOnce(&mut Loans<E>)) -> &mut Self {
        let mut l = Loans::wrap(super::zeroed::<E>());
        build(&mut l);
        E::stamp(&mut l);
        self.items.push(l.input);
        self.kept
            .extend(l.kept.into_iter().map(|k| Kept { field: None, ..k }));
        self
    }
}

impl List<AbiStr> {
    /// One more string, copied.
    pub fn text(&mut self, s: impl AsRef<[u8]>) -> &mut Self {
        let mut l = Loans::wrap(());
        let v = l.own_text(s.as_ref());
        self.items.push(v);
        self.kept.extend(l.kept);
        self
    }
}

impl<E> List<E> {
    fn build(build: impl FnOnce(&mut Self)) -> Self {
        let mut l = Self {
            items: Vec::new(),
            kept: Vec::new(),
        };
        build(&mut l);
        l
    }
}

/// How a struct's listed (pointer, length) pairs are rewritten from its loans' storage.
pub trait Pairs: Sized + 'static {
    /// Rewrites every listed pair of `loans`' value.
    fn stamp(loans: &mut Loans<Self>);
}

/// A value with no pointer in it; a `val` setter takes only this.
fn scalar<V: Scalar>(v: V) -> V {
    v
}

/// The pair setters and the [`Pairs`] stamp of each `in`, stated from the lend lists.
macro_rules! loan_pairs {
    ($($ty:ty { $($how:ident($p:ident $(, $n:ident)?) $(-> $el:ty)?;)+ })+) => {$(
        impl Loans<$ty> { $( loan_pairs!(@set $how($p $(, $n)?) $(-> $el)?); )+ }
        impl Pairs for $ty {
            fn stamp(l: &mut Loans<Self>) {
                // A struct whose only pointer is the host tables (`host`) rewrites nothing.
                let _ = &l;
                $( loan_pairs!(@reset l $how($p $(, $n)?)); )+
                $( loan_pairs!(@stamp l $how($p $(, $n)?) $(-> $el)?); )+
            }
        }
    )+};
    (@set bytes($p:ident, $n:ident)) => {
        #[doc = concat!("Lends `", stringify!($p), "`/`", stringify!($n), "`: these bytes, copied.")]
        pub fn $p(&mut self, b: impl AsRef<[u8]>) -> &mut Self {
            self.keep(Some(stringify!($p)), Vec::from(b.as_ref()));
            self
        }
    };
    (@set buf($p:ident, $n:ident) -> $el:ty) => {
        #[doc = concat!("Lends the host buffer `", stringify!($p), "`/`", stringify!($n), "` for `n` values.")]
        pub fn $p(&mut self, n: usize) -> Buf<$el> {
            let words = (n * size_of::<$el>()).div_ceil(size_of::<u64>());
            let at = self.keep(Some(stringify!($p)), vec![0u64; words]).addr();
            if let Some(k) = self.kept.last_mut() {
                k.len = n;
                k.buf = Some(stringify!($p));
            }
            Buf { field: stringify!($p), at, _e: PhantomData }
        }
    };
    (@set list($p:ident, $n:ident) -> $el:ty) => {
        #[doc = concat!("Lends the list `", stringify!($p), "`/`", stringify!($n), "`, each element built by `build`.")]
        pub fn $p(&mut self, build: impl FnOnce(&mut List<$el>)) -> &mut Self {
            let l = List::build(build);
            self.adopt(l.kept);
            self.keep(Some(stringify!($p)), l.items);
            self
        }
    };
    (@set one($p:ident) -> $el:ty) => {
        #[doc = concat!("Lends the one struct `", stringify!($p), "` points to: the first element `build` pushes.")]
        pub fn $p(&mut self, build: impl FnOnce(&mut List<$el>)) -> &mut Self {
            let mut l = List::build(build);
            l.items.truncate(1);
            self.adopt(l.kept);
            self.keep(Some(stringify!($p)), l.items);
            self
        }
    };
    (@set host($p:ident) -> $el:ty) => {};
    (@reset $l:ident bytes($p:ident, $n:ident)) => { $l.input.$n = usize::MAX as _; };
    (@reset $l:ident buf($p:ident, $n:ident)) => { $l.input.$n = usize::MAX as _; };
    (@reset $l:ident list($p:ident, $n:ident)) => { $l.input.$n = usize::MAX as _; };
    (@reset $l:ident one($p:ident)) => {};
    (@reset $l:ident host($p:ident)) => {};
    // Two lists may share one length (`candidates`/`candidate_dynamics`): it is the shorter.
    (@stamp $l:ident bytes($p:ident, $n:ident)) => {
        let (ptr, len) = $l.lent(stringify!($p));
        $l.input.$p = ptr;
        $l.input.$n = ($l.input.$n as usize).min(len) as _;
    };
    (@stamp $l:ident buf($p:ident, $n:ident) -> $el:ty) => {
        let (ptr, len) = $l.lent(stringify!($p));
        $l.input.$p = ptr.cast::<$el>();
        $l.input.$n = ($l.input.$n as usize).min(len) as _;
    };
    (@stamp $l:ident list($p:ident, $n:ident) -> $el:ty) => {
        let (ptr, len) = $l.lent(stringify!($p));
        $l.input.$p = ptr.cast::<$el>();
        $l.input.$n = ($l.input.$n as usize).min(len) as _;
    };
    (@stamp $l:ident one($p:ident) -> $el:ty) => {
        $l.input.$p = $l.lent(stringify!($p)).0.cast::<$el>();
    };
    (@stamp $l:ident host($p:ident) -> $el:ty) => {};
}

lend_kinds_list!(loan_pairs);
lend_store_list!(loan_pairs);
lend_export_list!(loan_pairs);

/// The scalar, string, payload and nested-struct setters of each struct, stated from the field
/// list. Reviewed exclusions: the head (the host stamps it), and the two `val`s that are not
/// pointer-free (a host context, and a signal value whose string arm is a raw `AbiStr`, which
/// `SignalEntry`'s one hand-written `value` setter writes with its tag); any other
/// `val` that is not a [`Scalar`] fails to compile here, so a new one is reviewed before it gets a
/// setter.
macro_rules! loan_fields {
    ($($ty:ty { $($rows:tt)* })+) => {$(
        impl Loans<$ty> { loan_fields!(@rows $($rows)*); }
        loan_fields!(@secret [$ty] $($rows)*);
    )+};
    (@rows) => {};
    // THE SIGNAL VALUE (STH-ROWS D-8): `SignalEntry`'s `tag` and `value` are one reviewed row, so no
    // `tag` setter exists and the union is written whole with the tag that names its live arm.
    (@rows val tag: u32; val value: crate::abi::hook::SignalValue; $($rest:tt)*) => {
        /// Sets the signal's tag and value together: the whole union, then the arm the tag names.
        pub fn value(&mut self, v: SignalArg) -> &mut Self {
            let mut value = SignalValue {
                str_: AbiStr {
                    ptr: std::ptr::null(),
                    len: 0,
                },
            };
            let tag = match v {
                SignalArg::U64(n) => {
                    value.u64_ = n;
                    SIGNAL_TAG_U64
                }
                SignalArg::I64(n) => {
                    value.i64_ = n;
                    SIGNAL_TAG_I64
                }
                SignalArg::F64(x) => {
                    value.f64_ = x;
                    SIGNAL_TAG_F64
                }
                SignalArg::Bool(b) => {
                    value.boolean = u8::from(b);
                    SIGNAL_TAG_BOOL
                }
                SignalArg::Str(s) => {
                    value.str_ = self.own_text(&s);
                    SIGNAL_TAG_STR
                }
            };
            self.input.tag = tag;
            self.input.value = value;
            self
        }
        loan_fields!(@rows $($rest)*);
    };
    (@rows sub head: $t:ty; $($rest:tt)*) => { loan_fields!(@rows $($rest)*); };
    (@rows val $name:ident: crate::abi::mechanism::ticket::HostCtx; $($rest:tt)*) => {
        loan_fields!(@rows $($rest)*);
    };
    (@rows val $name:ident: crate::abi::hook::SignalValue; $($rest:tt)*) => {
        loan_fields!(@rows $($rest)*);
    };
    (@rows val $name:ident: $t:ty; $($rest:tt)*) => {
        #[doc = concat!("Sets `", stringify!($name), "`.")]
        pub fn $name(&mut self, v: $t) -> &mut Self {
            self.input.$name = scalar(v);
            self
        }
        loan_fields!(@rows $($rest)*);
    };
    (@rows str $name:ident; $($rest:tt)*) => {
        #[doc = concat!("Lends the string `", stringify!($name), "`, copied.")]
        pub fn $name(&mut self, s: impl AsRef<[u8]>) -> &mut Self {
            self.input.$name = self.own_text(s.as_ref());
            self
        }
        loan_fields!(@rows $($rest)*);
    };
    (@rows blob $name:ident; $($rest:tt)*) => {
        #[doc = concat!("Lends the payload `", stringify!($name), "` (format `fmt`), copied.")]
        pub fn $name(&mut self, b: impl AsRef<[u8]>, fmt: u32) -> &mut Self {
            let s = self.own_text(b.as_ref());
            self.input.$name = Blob { ptr: s.ptr, len: s.len, fmt, flags: 0 };
            self
        }
        loan_fields!(@rows $($rest)*);
    };
    (@rows sub $name:ident: $t:ty; $($rest:tt)*) => {
        #[doc = concat!("Builds the embedded struct `", stringify!($name), "`.")]
        pub fn $name(&mut self, build: impl FnOnce(&mut Loans<$t>)) -> &mut Self {
            self.input.$name = self.nested(self.input.$name, build);
            self
        }
        loan_fields!(@rows $($rest)*);
    };
    // The secret-flagged payload setters ([`SecretBlobs`]): one per `blob` row, every other row
    // skipped.
    (@secret [$ty:ty]) => {};
    (@secret [$ty:ty] blob $name:ident; $($rest:tt)*) => {
        impl<'a> SecretBlobs<'a, $ty> {
            #[doc = concat!("Lends the payload `", stringify!($name), "` (format `fmt`), copied, flagged `BLOB_SECRET`.")]
            pub fn $name(self, b: impl AsRef<[u8]>, fmt: u32) -> &'a mut Loans<$ty> {
                let s = self.0.own_text(b.as_ref());
                self.0.input.$name = Blob { ptr: s.ptr, len: s.len, fmt, flags: BLOB_SECRET };
                self.0
            }
        }
        loan_fields!(@secret [$ty] $($rest)*);
    };
    (@secret [$ty:ty] $kw:ident $name:ident $(: $t:ty)?; $($rest:tt)*) => {
        loan_fields!(@secret [$ty] $($rest)*);
    };
}

lent_field_list!(loan_fields);

/// The structs whose loans state no pointer pair: nothing to rewrite.
macro_rules! no_pairs {
    ($($ty:ty),+ $(,)?) => {$(
        impl Pairs for $ty {
            fn stamp(_: &mut Loans<Self>) {}
        }
    )+};
}

no_pairs!(
    crate::abi::auth::OpenOutboundIn,
    crate::abi::auth::OutboundReadyIn,
    crate::abi::auth::RequestFacts,
    crate::abi::auth::TargetIn,
    crate::abi::export::DeliverIn,
    crate::abi::hook::ConfigureIn,
    crate::abi::hook::ServeIn,
    crate::abi::hook::StageView,
    crate::abi::hook::UserView,
    crate::abi::mechanism::call::InHead,
    crate::abi::mechanism::lifecycle::CancelIn,
    crate::abi::mechanism::lifecycle::DriveIn,
    crate::abi::mechanism::lifecycle::GenIn,
    crate::abi::mechanism::lifecycle::ReleaseIn,
    crate::abi::mechanism::lifecycle::TickIn,
    crate::abi::mechanism::ticket::HostCtx,
    crate::abi::mechanism::ticket::Ticket,
    crate::abi::secret::CheckIn,
    crate::abi::store::v4::ClockIn,
    crate::abi::store::v4::CommitIn,
    crate::abi::store::v4::ReadIn,
    crate::abi::store::v4::ScanIn,
    crate::abi::transport::ConnIn,
    crate::abi::transport::ShutIn,
    CheckInstance,
    ScrapeLabel,
    HookBudgetBucketState,
    HookMessageView,
    HookSignalEntry,
    NamedValue,
    StripName,
    FieldSpan,
    Field,
    Span,
    OutField,
    ProviderFacts,
    RecordWrite,
    UnitCount,
    ConnFacts,
    DatagramPath,
    DatagramRoute,
    FramePiece,
    HeadSlots,
    crate::abi::transport::FrameSpan,
);
