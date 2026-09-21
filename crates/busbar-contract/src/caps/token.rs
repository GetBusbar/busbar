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
//! # The unified vocabulary (#73)
//!
//! There are exactly two proof types and one root minter, and no others survive:
//!
//! * [`Pass<S>`] — one per [step](crate::caps::step), the stage-pass the next stage requires.
//! * [`Grant<C>`] — one per [capability](crate::caps::capability), the proof of a privileged action.
//! * [`KernelSeal`] — the single kernel-root minter; nothing else can mint a `Pass` or a `Grant`.
//!
//! # What a caller without a token cannot do
//!
//! It cannot mint a grant, because a grant's field is private:
//!
//! ```compile_fail,E0423
//! use busbar_contract::caps::{Admittance, Grant};
//! let forged = Grant::<Admittance>(std::marker::PhantomData);
//! ```
//!
//! It cannot mint a grant without a seal, because the mint takes one:
//!
//! ```compile_fail,E0061
//! use busbar_contract::caps::{Dial, Grant};
//! let forged = Grant::<Dial>::mint();
//! ```
//!
//! It cannot reach the recovery grant, which materialises a hold out of a journal record with no
//! admission at all — the single most dangerous capability in the crate:
//!
//! ```compile_fail,E0061
//! use busbar_contract::caps::{Grant, Recover};
//! let forged = Grant::<Recover>::mint();
//! ```
//!
//! With the seal, every one of those mints is a plain call — the fixtures above fail for the one
//! reason they are meant to:
//!
//! ```
//! use busbar_contract::caps::{Admittance, Dial, Grant, KernelSeal, Recover};
//! let seal = KernelSeal::acquire_for_kernel();
//! let _admit: Grant<Admittance> = Grant::<Admittance>::mint(&seal);
//! let _trust = Grant::<Dial>::mint(&seal);
//! let _recovery = Grant::<Recover>::mint(&seal);
//! ```
//!
//! And it cannot duplicate a grant it was lent, because no grant is `Clone`:
//!
//! ```compile_fail,E0599
//! use busbar_contract::caps::{Admittance, Grant};
//! fn twice(t: &Grant<Admittance>) -> Grant<Admittance> {
//!     t.clone()
//! }
//! ```

use crate::caps::capability::Capability;
use crate::caps::step::Step;
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

/// The per-request generation a capability proof is bound to (#74).
///
/// IN-PROCESS binding, not crypto: the kernel bumps one `u64` per request and stamps every `Pass`
/// and `Grant` it mints for that request with it; a stage compares the proof's generation against
/// the one the unit context carries (`~1 ns`, no HMAC — a full keyed-hash chain across all ten
/// stages was rejected as a hot-path tax, #74). A proof stamped for call A therefore does not match
/// call B, so a stray or stored proof cannot be replayed across flows. The compare is a `u64` equality
/// and the stamp is eight bytes on the stack — no allocation, so the #71 zero-hot-path-cost property
/// holds (the alloc bench proves it).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CallId(u64);

impl CallId {
    /// The sentinel a proof minted by the plain [`mint`](Pass::mint) carries: not bound to any
    /// request. Direct-minted proofs (a unit's own tests, the composition-root seams) are unbound;
    /// only the loop's per-request mints are bound.
    pub const UNBOUND: CallId = CallId(u64::MAX);

    /// Mint a request generation. Kernel only, by way of the seal. The kernel bumps its own counter
    /// and hands the value here; `u64::MAX` is reserved for [`UNBOUND`](CallId::UNBOUND).
    pub fn seal(_seal: &KernelSeal, generation: u64) -> Self {
        CallId(generation)
    }

    /// The generation as a plain value, for the context to carry and stages to compare.
    pub fn get(self) -> u64 {
        self.0
    }
}

impl std::fmt::Debug for CallId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if *self == CallId::UNBOUND {
            f.write_str("CallId(unbound)")
        } else {
            write!(f, "CallId({})", self.0)
        }
    }
}

/// A stage-pass: the proof that the loop is running step `S` for the current unit right now (#72).
///
/// Handed by reference to the unit that owns step `S`, and to no one else. It is the only thing that
/// can build a [`crate::caps::Decision`] for `S`, so a unit cannot answer a question it was not asked,
/// and it is the only thing that can read one back, so a unit cannot open its own answer.
///
/// Neither `Clone` nor `Copy`; minted fresh by the kernel and dropped when the call it was lent to
/// returns.
pub struct Pass<S: Step> {
    call: CallId,
    _step: PhantomData<fn() -> S>,
}

impl<S: Step> Pass<S> {
    /// Mint the pass for step `S`, unbound to any request. Kernel only, by way of the seal.
    pub fn mint(_seal: &KernelSeal) -> Self {
        Pass {
            call: CallId::UNBOUND,
            _step: PhantomData,
        }
    }

    /// Mint the pass bound to one request's generation (#74). Kernel only. A pass minted for one
    /// call does not [match](Pass::bound_to) another.
    pub fn mint_bound(_seal: &KernelSeal, call: CallId) -> Self {
        Pass {
            call,
            _step: PhantomData,
        }
    }

    /// Whether this pass belongs to `call`. An unbound pass belongs to no request, so it never
    /// matches a bound context — a stray or stored pass is caught here (#74).
    pub fn bound_to(&self, call: CallId) -> bool {
        self.call != CallId::UNBOUND && self.call == call
    }

    /// The request this pass was minted for, if any.
    pub fn call(&self) -> CallId {
        self.call
    }
}

impl<S: Step> std::fmt::Debug for Pass<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Pass<{}>", S::NAME)
    }
}

impl<S: Step> crate::plugin::KernelSeal for Pass<S> {
    fn seal_origin(&self) -> &'static str {
        "Pass"
    }
}

/// A capability grant: the proof that the caller may perform one privileged action `C` (#72/#73).
///
/// The single per-capability proof type. `Grant<Admittance>` opens a [`Hold`](crate::caps::Hold),
/// `Grant<WriteMoney>` settles one, `Grant<Dial>` seals a reachable destination, and so on — one
/// generic type over the sealed [`Capability`](crate::caps::capability) marker set, minted only by
/// the kernel's [`KernelSeal`]. This is the whole of the former token zoo (`AdmitToken`,
/// `TrustToken`, `UsageToken`, `LedgerToken`, `DurabilityToken`, `EgressAuthToken`,
/// `TransportKeyToken`, `AdminToken`, `RecoveryToken`, `ExitToken`), unified.
///
/// A grant is also what opens the contract's own kernel-built views — a verified destination, a
/// transport key handle. The contract sits below this crate and cannot name a grant, so the seam is
/// the other way round: the grant satisfies the contract's marker.
///
/// Neither `Clone` nor `Copy`; minted fresh by the kernel and dropped when the call it was lent to
/// returns.
pub struct Grant<C: Capability> {
    call: CallId,
    _cap: PhantomData<fn() -> C>,
}

impl<C: Capability> Grant<C> {
    /// Mint the grant for capability `C`, unbound to any request. Kernel only, by way of the seal.
    pub fn mint(_seal: &KernelSeal) -> Self {
        Grant {
            call: CallId::UNBOUND,
            _cap: PhantomData,
        }
    }

    /// Mint the grant bound to one request's generation (#74). Kernel only. A grant minted for one
    /// call does not [match](Grant::bound_to) another.
    pub fn mint_bound(_seal: &KernelSeal, call: CallId) -> Self {
        Grant {
            call,
            _cap: PhantomData,
        }
    }

    /// Whether this grant belongs to `call`. An unbound grant belongs to no request, so it never
    /// matches a bound context — a stray or stored grant is caught here (#74).
    pub fn bound_to(&self, call: CallId) -> bool {
        self.call != CallId::UNBOUND && self.call == call
    }

    /// The request this grant was minted for, if any.
    pub fn call(&self) -> CallId {
        self.call
    }
}

impl<C: Capability> std::fmt::Debug for Grant<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Grant<{}>", C::NAME)
    }
}

impl<C: Capability> crate::plugin::KernelSeal for Grant<C> {
    fn seal_origin(&self) -> &'static str {
        "Grant"
    }
}
