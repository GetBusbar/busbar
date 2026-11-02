// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The capabilities a [`Grant`](crate::caps::Grant) seals, as type-level markers.

/// The seal on [`Capability`]. Only the markers declared in this module implement it.
mod sealed {
    /// The private supertrait no downstream type can name, and therefore cannot implement.
    pub trait Sealed {}
}

/// One privileged action, as a zero-sized type-level marker.

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
    /// Exit: takes the hold out of its cell and seals the unit's end. Was `ExitToken`.
    Exit => "exit";
}
