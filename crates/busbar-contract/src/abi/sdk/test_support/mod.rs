// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLUGIN TEST SUPPORT THAT MUST SEE INSIDE THE CONTRACT. Everything else a plugin's tests
//! drive its door with lives in the test kit (`busbar_test_kit::test_support`: a door's Statement
//! read as Rust values, a fake host, door calls whose replies are copied out, a lent `in` built
//! safely); this crate's own tests mount that source here. What stays:
//!
//! * [`zeroed`] and `Default`: the all-zero value of a REVIEWED ABI struct. [`AllZero`] is sealed,
//!   so the constructor cannot be called on any type this module has not reviewed (and `Default`
//!   on a contract type can only be implemented here).
//! * [`lent_pairs`]: the pointer and length pairs of every struct a call lends, from the SDK's own
//!   lending lists.
//! * `chip` (behind the dev-only `test-seal` feature): a sealed credential's bytes, as a test's own
//!   stand-in for the host's wire writes them.
//!
//! TEST ONLY: compiled for this crate's tests and behind the `test-support` feature busbar-test-kit
//! (a dev-dependency only) enables, so no shipped image carries it. It adds no `#[repr(C)]` type
//! and changes no layout.

use crate::abi::sdk::door::{AbiIn, AbiOut};

mod sealed {
    /// Only this module implements it: the reviewed all-zero structs.
    pub trait Sealed {}
}

#[cfg(any(test, feature = "test-seal"))]
pub mod chip;
mod pairs;

/// `t`, lent: what the test kit's fake host hands a door as its host tables.
///
/// # Safety
/// Every pointer in `*t` is valid, as the kind's ABI states it, for `'a`.
#[doc(hidden)]
pub const unsafe fn lend<T>(t: &T) -> crate::abi::sdk::Lent<'_, T> {
    // SAFETY: the caller's promise, as `Lent::new` states it.
    unsafe { crate::abi::sdk::Lent::new(t) }
}

/// The pointer and length pairs (offsets of the pointer, of the length, and the element size) of
/// every list the struct `t` lends, nested structs included: what a test-built `in` may set together.
#[doc(hidden)]
pub use pairs::lent_pairs;

// ── THE ALL-ZERO VALUE ──────────────────────────────────────────────────────────────────────────

/// A REVIEWED ABI struct whose all-zero bit pattern is a valid value. Sealed: the implementors are
/// exactly the structs listed in this module, each under the SAFETY argument beside its list, and
/// arrays of them.
pub trait AllZero: sealed::Sealed + Copy + 'static {}

/// The all-zero `T`: every integer `0`, every raw pointer NULL, every `Option<fn>` `None`. A test
/// fills the fields its call states, as the host does.
///
/// ```ignore
/// use busbar_contract::abi::sdk::test_support::zeroed;
/// use busbar_contract::abi::transport::{FramePiece, IngestIn};
///
/// let mut i: IngestIn = zeroed();
/// let pieces: Vec<FramePiece> = vec![zeroed(); 8];
/// ```
#[must_use]
pub fn zeroed<T: AllZero>() -> T {
    // SAFETY: `AllZero` is sealed. Its implementors are the structs `all_zero!` lists below, each
    // reviewed under the SAFETY argument of its list (all-zero is a valid value of every field),
    // and arrays of them (an array of valid values is valid).
    unsafe { core::mem::zeroed() }
}

impl<T: AllZero, const N: usize> sealed::Sealed for [T; N] {}
impl<T: AllZero, const N: usize> AllZero for [T; N] {}

/// Compiles only for an [`AbiIn`]: the list of slot `in`s below rides that trait's promise.
const fn slot_in<T: AbiIn>() {}
/// Compiles only for an [`AbiOut`]: the list of slot `out`s below rides that trait's promise.
const fn slot_out<T: AbiOut>() {}
/// Compiles for any plain `Copy` row; the review is the SAFETY argument over its list.
const fn row<T: Copy + 'static>() {}

/// `all_zero!(witness: T, ...)`: each `T` is [`AllZero`], its `Default` is [`zeroed`], and
/// `witness::<T>()` must compile.
macro_rules! all_zero {
    ($witness:ident: $($t:ty),+ $(,)?) => {$(
        const _: () = $witness::<$t>();
        impl sealed::Sealed for $t {}
        impl AllZero for $t {}
        impl Default for $t {
            fn default() -> Self {
                zeroed()
            }
        }
    )+};
}

// SAFETY (every slot `in` below): each is an `AbiIn` (checked at compile time by `slot_in`), whose
// unsafe contract states that EVERY initialized bit pattern, all-zero included, is a valid value:
// integers, raw pointers, `Option<fn>` and `#[repr(transparent)]` bytes only.
all_zero!(slot_in:
    crate::abi::mechanism::call::InHead,
    crate::abi::mechanism::lifecycle::ValidateIn,
    crate::abi::mechanism::lifecycle::OpenIn,
    crate::abi::mechanism::lifecycle::GenIn,
    crate::abi::mechanism::lifecycle::RefreshIn,
    crate::abi::mechanism::lifecycle::TickIn,
    crate::abi::mechanism::lifecycle::DriveIn,
    crate::abi::mechanism::lifecycle::CancelIn,
    crate::abi::mechanism::lifecycle::ReleaseIn,
    crate::abi::mechanism::lifecycle::ReadyIn,
    crate::abi::auth::VerifyIn,
    crate::abi::auth::BeginLoginIn,
    crate::abi::auth::CompleteLoginIn,
    crate::abi::auth::OpenOutboundIn,
    crate::abi::auth::OutboundReadyIn,
    crate::abi::auth::FieldsIn,
    crate::abi::auth::TargetIn,
    crate::abi::export::DeliverIn,
    crate::abi::export::ScrapeIn,
    crate::abi::export::CheckIn,
    crate::abi::export::ServeIn,
    crate::abi::hook::DecideIn,
    crate::abi::hook::NotifyIn,
    crate::abi::hook::ConfigureIn,
    crate::abi::hook::ServeIn,
    crate::abi::plane::PlaneOpenIn,
    crate::abi::plane::PlaneDriveIn,
    crate::abi::plane::PlaneCancelIn,
    crate::abi::plane::ArriveIn,
    crate::abi::plane::OnPieceIn,
    crate::abi::plane::RefusalIn,
    crate::abi::plane::ServeIn,
    crate::abi::plane::ProjectIn,
    crate::abi::plane::CatalogIn,
    crate::abi::secret::CheckIn,
    crate::abi::secret::ResolveIn,
    crate::abi::store::AddUsageBatchIn,
    crate::abi::store::AppendPlaneRecordIn,
    crate::abi::store::BlobIn,
    crate::abi::store::GetPlaneRecordIn,
    crate::abi::store::IdIn,
    crate::abi::store::IdReasonIn,
    crate::abi::store::KeyWithCredentialIn,
    crate::abi::store::KindBeforeIn,
    crate::abi::store::KindIdIn,
    crate::abi::store::ListPlaneRecordsIn,
    crate::abi::store::OpBlobsIn,
    crate::abi::store::PutUsageIn,
    crate::abi::store::RecordGetIn,
    crate::abi::store::RecordPutIn,
    crate::abi::store::RecordScanIn,
    crate::abi::store::TokenIn,
    crate::abi::store::U64In,
    crate::abi::store::UpsertPlaneRecordIn,
    crate::abi::store::WindowIn,
    crate::abi::transport::ListenIn,
    crate::abi::transport::AcceptIn,
    crate::abi::transport::DialIn,
    crate::abi::transport::ReadIn,
    crate::abi::transport::WriteIn,
    crate::abi::transport::ConnIn,
    crate::abi::transport::ShutIn,
    crate::abi::transport::ArrivalIn,
    crate::abi::transport::LocateIn,
    crate::abi::transport::BeginIn,
    crate::abi::transport::IngestIn,
    crate::abi::transport::EmitIn,
    crate::abi::transport::EncodeIn,
    crate::abi::transport::RefuseIn,
    crate::abi::transport::FinishIn,
    crate::abi::transport::FramingIn,
    crate::abi::transport::AdoptIn,
);

// SAFETY (every slot `out` below): each is an `AbiOut` (checked at compile time by `slot_out`), whose
// unsafe contract states that every initialized bit pattern, all-zero included, is a valid value.
all_zero!(slot_out:
    crate::abi::mechanism::call::OutHead,
    crate::abi::mechanism::lifecycle::OpenOut,
    crate::abi::mechanism::lifecycle::TickOut,
    crate::abi::mechanism::lifecycle::CancelOut,
    crate::abi::auth::IdentifyOut,
    crate::abi::auth::BeginLoginOut,
    crate::abi::auth::OpenOutboundOut,
    crate::abi::auth::OutboundReadyOut,
    crate::abi::auth::FieldsOut,
    crate::abi::auth::TargetOut,
    crate::abi::export::ScrapeOut,
    crate::abi::export::StatusOut,
    crate::abi::export::CheckOut,
    crate::abi::export::ServeOut,
    crate::abi::hook::ConfigureOut,
    crate::abi::hook::DecideOut,
    crate::abi::hook::DescribeOut,
    crate::abi::hook::ServeOut,
    crate::abi::hook::StatusOut,
    crate::abi::hook::TransformOut,
    crate::abi::plane::PlaneOpenOut,
    crate::abi::plane::PlaneRefreshOut,
    crate::abi::plane::PlaneDriveOut,
    crate::abi::plane::PlaneCancelOut,
    crate::abi::plane::ArriveOut,
    crate::abi::plane::OnPieceOut,
    crate::abi::plane::RefusalOut,
    crate::abi::plane::ServeOut,
    crate::abi::plane::ProjectOut,
    crate::abi::plane::CatalogOut,
    crate::abi::secret::ResolveOut,
    crate::abi::store::CountOut,
    crate::abi::store::HostBytesOut,
    crate::abi::store::HostListOut,
    crate::abi::store::LeasedBlobOut,
    crate::abi::store::LeasedListOut,
    crate::abi::store::LeasedStrListOut,
    crate::abi::store::VerdictOut,
    crate::abi::transport::ListenOut,
    crate::abi::transport::AcceptOut,
    crate::abi::transport::ConnOut,
    crate::abi::transport::IoOut,
    crate::abi::transport::ArrivalOut,
    crate::abi::transport::LocateOut,
    crate::abi::transport::FramerOut,
);

// SAFETY (every row below, reviewed field by field): each is `#[repr(C)]` plain data whose fields
// are integers, raw pointers, `Option<extern "C" fn>` (`None` is the all-zero niche), or another
// struct of this list (`AbiStr`, `Span`, `Field`). `SignalEntry`'s `value` is a `#[repr(C)]` union
// of integers, an `f64` and an `AbiStr`, every one valid at all-zero. No `bool`, enum, reference,
// `NonNull` or non-`Option` function pointer appears in any of them.
all_zero!(row:
    crate::abi::mechanism::call::AbiStr,
    crate::abi::mechanism::call::Blob,
    crate::abi::mechanism::call::Span,
    crate::abi::mechanism::call::Field,
    crate::abi::host::service::HostSlots,
    crate::abi::auth::StripName,
    crate::abi::auth::FieldSpan,
    crate::abi::hook::SignalEntry,
    crate::abi::hook::MessageView,
    crate::abi::plane::OutField,
    crate::abi::plane::RecordWrite,
    crate::abi::plane::UnitCount,
    crate::abi::transport::FramePiece,
    crate::abi::transport::FramerSink,
    crate::abi::transport::ConnFacts,
    crate::abi::transport::Destination,
    crate::abi::host::service::ServiceOut,
    crate::abi::host::service::ItemSpan,
    crate::abi::host::service::ClockReading,
    crate::abi::host::io::IoSlots,
    crate::abi::host::conn::connector::ConnectorSlots,
);

#[cfg(test)]
#[allow(unsafe_code, missing_docs, missing_debug_implementations)]
#[path = "../../../../../busbar-test-kit/src/test_support/mod.rs"]
mod kit;
#[cfg(test)]
pub use kit::*;

#[cfg(test)]
#[path = "../tests/test_support_tests.rs"]
mod tests;
