// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The tokens. Holding one is the proof that you are entitled to build the capability it seals.
//! Neither `Clone` nor `Copy`: the loop mints a fresh one per step call and drops it when the call
//! returns, and it is handed to a unit BY REFERENCE, never by value, so a unit never owns one.
//!
//! # The one hole, named out loud
//!
//! A token's real constructor is private to this crate, which is what makes the compile-fail
//! fixtures below genuine. But the kernel is a DIFFERENT crate, and Rust has no way to say "this
//! public function may be called by exactly one other crate", so there is exactly one hole:
//! [`KernelSeal`]. Every mint takes one by reference, and the only way to obtain a `KernelSeal` is
//! a hidden constructor CI's symbol scan confines to the kernel's own source. See the crate-level
//! table: the SHAPE of every token rule is compile-time, WHO may hold a seal is a lint.
//!
//! # What a caller without a token cannot do
//!
//! It cannot mint a token, because a token's fields are private:
//!
//! ```compile_fail,E0423
//! use busbar_caps::{Admit, AdmitToken};
//! let forged = AdmitToken::<Admit>(std::marker::PhantomData);
//! ```
//!
//! It cannot mint a token without a seal, because the mint takes one:
//!
//! ```compile_fail,E0061
//! use busbar_caps::TrustToken;
//! let forged = TrustToken::mint();
//! ```
//!
//! It cannot reach the recovery token, which materialises a hold out of a journal record with no
//! admission at all — the single most dangerous capability in the crate:
//!
//! ```compile_fail,E0061
//! use busbar_caps::RecoveryToken;
//! let forged = RecoveryToken::mint();
//! ```
//!
//! With the seal, every one of those mints is a plain call — the fixtures above fail for the one
//! reason they are meant to:
//!
//! ```
//! use busbar_caps::{Admit, AdmitToken, KernelSeal, RecoveryToken, TrustToken};
//! let seal = KernelSeal::acquire_for_kernel();
//! let _admit: AdmitToken<Admit> = AdmitToken::mint(&seal);
//! let _trust = TrustToken::mint(&seal);
//! let _recovery = RecoveryToken::mint(&seal);
//! ```
//!
//! And it cannot duplicate a token it was lent, because no token is `Clone`:
//!
//! ```compile_fail,E0599
//! use busbar_caps::{Admit, AdmitToken};
//! fn twice(t: &AdmitToken<Admit>) -> AdmitToken<Admit> {
//!     t.clone()
//! }
//! ```

use crate::step::Step;
use std::marker::PhantomData;

/// The proof that the caller is the kernel.
///
/// This is the crate's one deliberate hole (see the module documentation). It exists because token
/// minting has to cross a crate boundary that Rust cannot police, and it is far better to have ONE
/// audited symbol than a public constructor on each of the twelve tokens.
pub struct KernelSeal(());

impl KernelSeal {
    /// Obtain the seal. **Kernel only.** CI's symbol scan fails the build if this name appears
    /// outside the kernel crate's source; see the lint hooks module for the exact list.
    #[doc(hidden)]
    pub fn acquire_for_kernel() -> Self {
        KernelSeal(())
    }
}

impl std::fmt::Debug for KernelSeal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KernelSeal")
    }
}

macro_rules! plain_token {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        ///
        /// Neither `Clone` nor `Copy`; minted fresh by the kernel and dropped when the call it was
        /// lent to returns.
        pub struct $name(PhantomData<()>);

        impl $name {
            /// Mint the token. Kernel only, by way of the seal.
            pub fn mint(_seal: &KernelSeal) -> Self {
                $name(PhantomData)
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(stringify!($name))
            }
        }

        // A token is also what opens the contract's own kernel-built views — the unit a plane
        // reads, a verified destination, a transport key handle. The contract sits below this
        // crate and cannot name a token, so the seam is the other way round: the token satisfies
        // the contract's marker, and a call site reads `issue(&TransportKeyToken, ..)`.
        impl busbar_contract::KernelSeal for $name {
            fn seal_origin(&self) -> &'static str {
                stringify!($name)
            }
        }
    };
}

macro_rules! step_token {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        pub struct $name<S: Step>(PhantomData<fn() -> S>);

        impl<S: Step> $name<S> {
            /// Mint the token for step `S`. Kernel only, by way of the seal.
            pub fn mint(_seal: &KernelSeal) -> Self {
                $name(PhantomData)
            }
        }

        impl<S: Step> std::fmt::Debug for $name<S> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, concat!(stringify!($name), "<{}>"), S::NAME)
            }
        }

        impl<S: Step> busbar_contract::KernelSeal for $name<S> {
            fn seal_origin(&self) -> &'static str {
                stringify!($name)
            }
        }
    };
}

step_token!(
    /// The proof that the loop is running step `S` for the current unit right now.
    ///
    /// Handed by reference to the unit that owns step `S`, and to no one else. It is the only
    /// thing that can build a [`crate::Decision`] for `S`, so a unit cannot answer a question it
    /// was not asked, and it is the only thing that can read one back, so a unit cannot open its
    /// own answer.
    UnitToken
);
step_token!(
    /// The admission unit's own token for step `S`: the one thing that can open a [`crate::Hold`].
    ///
    /// Separate from [`UnitToken`] on purpose — every unit is lent a `UnitToken` for its step, and
    /// if that were enough to open a hold then every unit could open one. Only the admission unit
    /// is lent an `AdmitToken`, and only at the door.
    AdmitToken
);

plain_token!(
    /// The trust unit's token: seals a destination the unit is allowed to reach.
    TrustToken
);
plain_token!(
    /// The usage unit's token: reports what a unit actually consumed.
    UsageToken
);
plain_token!(
    /// The ledger unit's token: turns a hold plus a usage report into a posting.
    LedgerToken
);
plain_token!(
    /// The write-ahead-log unit's token: records that a durable write was observed to fail.
    DurabilityToken
);
plain_token!(
    /// The egress-auth unit's token: decorates an outbound request and names its secret slots.
    EgressAuthToken
);
plain_token!(
    /// The transport-key unit's token: hands out an opaque handle to resolved key material.
    TransportKeyToken
);
plain_token!(
    /// The verbs unit's token: mints a one-shot secret placeholder for an administrative verb.
    AdminToken
);
plain_token!(
    /// The recovery module's token: materialises a hold from a journal record after a crash.
    ///
    /// Nothing else in the system can bring a hold into being without passing the door. CI's symbol
    /// scan confines every use of this type to the kernel's recovery module.
    RecoveryToken
);
plain_token!(
    /// The exit path's token: takes the hold out of its cell and seals the unit's end.
    ///
    /// There are exactly two holders — the exit path and the node's sweep — and a fixture asserts
    /// there is no third.
    ExitToken
);
