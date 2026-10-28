// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE POINTER AND LENGTH PAIRS of every struct a call lends (status row 194), from the one list
//! the SDK states its `Lent` accessors from (`lent.rs`): what a [`TestIn`](super::test_in::TestIn)
//! may set together, and nothing else. It lives with its one reader, the test support.

use std::any::TypeId;
use std::mem::offset_of;

use crate::abi::mechanism::call::{AbiStr, Blob};
// The names the lists state their structs by, as `lent.rs` imports them (each list's element types
// ride along unread).
#[allow(unused_imports)]
use crate::abi::auth::{
    BeginLoginIn, CompleteLoginIn, FieldSpan, FieldsIn, IdentityBuf, NamedValue, StripName,
    VerifyIn,
};
#[allow(unused_imports)]
use crate::abi::export::{
    CheckIn, CheckInstance, ScrapeFamily, ScrapeIn, ScrapeLabel, ScrapeSample,
    ServeIn as ExportServeIn,
};
#[allow(unused_imports)]
use crate::abi::hook::{
    BudgetBucketState as HookBudgetBucketState, CandidateDynamic as HookCandidateDynamic,
    CandidateStatic as HookCandidateStatic, DecideIn, MessageView as HookMessageView, NotifyIn,
    PromptView as HookPromptView, RequestView as HookRequestView, SignalEntry as HookSignalEntry,
};
#[allow(unused_imports)]
use crate::abi::mechanism::lifecycle::{OpenIn, ReadyIn, RefreshIn, ValidateIn};
#[allow(unused_imports)]
use crate::abi::mechanism::ticket::HostTables;
#[allow(unused_imports)]
use crate::abi::plane::{
    ArriveIn, CatalogIn, OnPieceIn, OutField, PlaneCancelIn, PlaneDriveIn, PlaneOpenIn, ProjectIn,
    ProviderFacts, RecordWrite, RefusalIn, ServeIn, UnitCount,
};
#[allow(unused_imports)]
use crate::abi::store::{
    AddUsageBatchIn, HostBlobs as StoreHostBlobs, HostBuf as StoreHostBuf, HostRecords, OpBlobsIn,
    RecordEntry, UsageCell,
};
#[allow(unused_imports)]
use crate::abi::transport::{
    AcceptIn, AdoptIn, ArrivalIn, BeginIn, ConnFacts, DatagramLane, DatagramPath, DatagramRoute,
    Destination, DialIn, EmitIn, EncodeIn, FinishIn, FramePiece, FramerSink, FramingIn, HeadSlots,
    IngestIn, KeyingMaterial, ListenIn, LocateIn, ReadIn, RefuseIn, WriteIn,
};

/// One block's pointer and length pairs, per struct: `(pointer, length, length's width)`.
macro_rules! lend_pairs {
    (fn $reg:ident; $($ty:ty { $($how:ident($p:ident $(, $n:ident)?) $(-> $el:ty)?;)+ })+) => {
        fn $reg(t: TypeId) -> Option<Vec<(usize, usize, usize)>> {
            $(
                if t == TypeId::of::<$ty>() {
                    return Some(
                        [$( lend_pairs!(@pair $ty, $how $p $(, $n)?) ),+]
                            .into_iter()
                            .flatten()
                            .collect::<Vec<(usize, usize, usize)>>(),
                    );
                }
            )+
            None
        }
    };
    (@pair $ty:ty, one $p:ident) => { None };
    (@pair $ty:ty, $how:ident $p:ident, $n:ident) => {
        Some((
            offset_of!($ty, $p),
            offset_of!($ty, $n),
            {
                let blank = std::mem::MaybeUninit::<$ty>::uninit();
                // SAFETY: a place projection of an uninitialised value, never read: its address.
                crate::abi::pointee_size(unsafe { std::ptr::addr_of!((*blank.as_ptr()).$n) })
            },
        ))
    };
}

lend_kinds_list!(lend_pairs fn pairs_kinds;);
lend_store_list!(lend_pairs fn pairs_store;);
lend_export_list!(lend_pairs fn pairs_export;);

/// The fields each lent struct embeds: a nested struct (`sub`), a string or a payload, by offset
/// and type, from the one list the field accessors are stated from.
macro_rules! lent_embeds {
    ($($ty:ty { $($how:ident $name:ident $(: $t:ty)?;)+ })+) => {
        fn embeds(t: TypeId) -> Vec<(usize, TypeId)> {
            $(
                if t == TypeId::of::<$ty>() {
                    #[allow(unused_mut)]
                    let mut v = Vec::new();
                    $( lent_embeds!(@one v, $ty, $how $name $(: $t)?); )+
                    return v;
                }
            )+
            Vec::new()
        }
    };
    (@one $v:ident, $ty:ty, sub $name:ident: $t:ty) => {
        $v.push((offset_of!($ty, $name), TypeId::of::<$t>()));
    };
    (@one $v:ident, $ty:ty, str $name:ident) => {
        $v.push((offset_of!($ty, $name), TypeId::of::<AbiStr>()));
    };
    (@one $v:ident, $ty:ty, blob $name:ident) => {
        $v.push((offset_of!($ty, $name), TypeId::of::<Blob>()));
    };
    (@one $v:ident, $ty:ty, val $name:ident: $t:ty) => {};
}

lent_field_list!(lent_embeds);

/// EVERY POINTER AND LENGTH PAIR an `in` of type `t` carries, its embedded structs', strings' and
/// payloads' included, at their offsets in it: `(pointer, length, length's width)`.
pub fn lent_pairs(t: TypeId) -> Vec<(usize, usize, usize)> {
    let word = std::mem::size_of::<usize>();
    let mut out = if t == TypeId::of::<AbiStr>() {
        vec![(offset_of!(AbiStr, ptr), offset_of!(AbiStr, len), word)]
    } else if t == TypeId::of::<Blob>() {
        vec![(offset_of!(Blob, ptr), offset_of!(Blob, len), word)]
    } else {
        pairs_kinds(t)
            .or_else(|| pairs_store(t))
            .or_else(|| pairs_export(t))
            .unwrap_or_default()
    };
    for (at, inner) in embeds(t) {
        out.extend(
            lent_pairs(inner)
                .into_iter()
                .map(|(p, n, w)| (at + p, at + n, w)),
        );
    }
    out
}
