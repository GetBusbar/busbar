// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The capabilities a [`Grant`](crate::caps::Grant) seals, as type-level markers.
//!
//! Where a [`Pass<S>`](crate::caps::Pass) is the proof that the loop is running one of the ten
//! [steps](crate::caps::step), a `Grant<C>` is the proof that the caller may perform one privileged
//! ACTION — dial an upstream, sign an outbound request, write the book, take the hold out of its
//! cell. The unified vocabulary is two words: `Pass` per stage, `Grant` per capability, both minted
//! only by the kernel's [`KernelSeal`](crate::caps::KernelSeal) (#73).
//!
//! The marker set is sealed on a private supertrait exactly as [`Step`](crate::caps::step::Step) is,
//! so nothing outside this module can invent an eleventh capability or a private marker that would
//! mint grants of its own.

/// The seal on [`Capability`]. Only the markers declared in this module implement it.
mod sealed {
    /// The private supertrait no downstream type can name, and therefore cannot implement.
    pub trait Sealed {}
}

/// One privileged action, as a zero-sized type-level marker.
///
/// `NAME` is the capability as a plain runtime string, used only for a grant's `Debug` — a grant
/// never reaches the wire, so this string is a developer convenience, not an observable byte.
pub trait Capability: sealed::Sealed + Send + Sync + 'static {
    /// The capability as a runtime name, for `Debug` alone.
    const NAME: &'static str;
}

macro_rules! capability_markers {
    ($($(#[$doc:meta])* $name:ident => $wire:expr;)*) => {
        $(
            $(#[$doc])*
            #[derive(Debug, Clone, Copy, PartialEq, Eq)]
            pub struct $name;

            impl sealed::Sealed for $name {}

            impl Capability for $name {
                const NAME: &'static str = $wire;
            }
        )*
    };
}

capability_markers! {
    /// Admittance: opens the admission unit's own [`Hold`](crate::caps::Hold). Was `AdmitToken`.
    Admittance => "admittance";
    /// Dial: seals a destination the unit is allowed to reach. Was `TrustToken`.
    Dial => "dial";
    /// Consumption: reports what a unit actually consumed. Was `UsageToken`.
    Consumption => "consumption";
    /// Write-money: turns a hold plus a usage report into a posting. Was `LedgerToken`.
    WriteMoney => "write-money";
    /// Durable-write: records that a durable write was observed to fail. Was `DurabilityToken`.
    DurableWrite => "durable-write";
    /// Sign: decorates an outbound request and names its secret slots. Was `EgressAuthToken`.
    Sign => "sign";
    /// Key-handle: hands out an opaque handle to resolved key material. Was `TransportKeyToken`.
    KeyHandle => "key-handle";
    /// Admin-verb: mints a one-shot secret placeholder for an administrative verb. Was `AdminToken`.
    AdminVerb => "admin-verb";
    /// Recover: materialises a hold from a journal record after a crash. Was `RecoveryToken`.
    ///
    /// Nothing else in the system can bring a hold into being without passing the door. CI's symbol
    /// scan confines every use of `Grant::<Recover>` to the kernel's recovery module.
    Recover => "recover";
    /// Exit: takes the hold out of its cell and seals the unit's end. Was `ExitToken`.
    Exit => "exit";
}
