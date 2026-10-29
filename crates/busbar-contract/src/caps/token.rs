// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The tokens. Holding one is the proof that you are entitled to build the capability it seals.
//! Neither `Clone` nor `Copy`: the loop mints a fresh one per step call and drops it when the call
//! returns, and it is handed to a unit BY REFERENCE, never by value, so a unit never owns one.
//!
//! # How the kernel, and only the kernel, holds a seal (#65)
//!
//! A token's real constructor is private to this crate, which is what makes the compile-fail
//! fixtures below genuine. Every mint takes a [`KernelSeal`] by reference, and the seal's own
//! constructor is private to this crate too. The kernel is a DIFFERENT crate, and Rust has no way
//! to say "this public function may be called by exactly one other crate", so the seal does not
//! cross by a public constructor. It crosses by a SYMBOL only the kernel defines:
//! [`KernelSeal::deliver`] builds a seal and hands it to `__busbar_kernel_root`, which
//! `busbar-kernel` alone defines. The kernel wraps the seal in a type private to the kernel and
//! hands it back opaque; only kernel code can open it. A caller outside the kernel that calls
//! `deliver` gets a box it cannot open, and a second crate that defines the symbol to catch the
//! seal fails to link (the kernel's definition is always linked: the kernel's own minter lives
//! beside it). A release build has no other way to a seal. The fixture below is data,
//! `fixtures/no_release_seal.md` (like `lint_rules.txt` beside it): the seal scans count every
//! spelling of the minter in Rust source outside the kernel as a mint, and this one is the proof
//! that it does NOT compile:
//!
#![cfg_attr(
    not(feature = "test-seal"),
    doc = include_str!("fixtures/no_release_seal.md")
)]
//!
//! `acquire_for_kernel` survives ONLY for tests (the dev-only `test-seal` feature, one of the four
//! items that feature's exemption names, which `tests/test_seal_is_dev_only.rs` keeps off every non-dev edge), so the test suites that
//! mint tokens to show a step's shape keep doing so, and nothing that ships can.
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
//! With the seal, every one of those mints is a plain call — the fixtures above fail for the one
//! reason they are meant to (the test seal stands in for the kernel's here):
//!
#![cfg_attr(feature = "test-seal", doc = "```")]
#![cfg_attr(not(feature = "test-seal"), doc = "```ignore")]
//! use busbar_contract::caps::{Admittance, Dial, Grant, KernelSeal};
//! let seal = KernelSeal::acquire_for_kernel();
//! let _admit: Grant<Admittance> = Grant::<Admittance>::mint(&seal);
//! let _trust = Grant::<Dial>::mint(&seal);
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
    /// A seal for TESTS. **Absent from every release build:** it exists only under the dev-only
    /// `test-seal` feature, and the kernel's production path never names it (it
    /// takes its seal through [`KernelSeal::deliver`] and the kernel's own symbol, #65).
    ///
    /// The seal TRAIT the kernel-built views take, [`KernelSeal`](crate::plugin::KernelSeal), is
    /// SEALED, and it has exactly three implementors, all at the foot of this file: a real
    /// [`Pass`], a real [`Grant`], and `plugin::TestKernelSeal`. The third exists only in this
    /// crate's own unit tests and when the dev-only `test-seal` feature is on — the contract's one named dev-only exemption (#65, item
    /// 112), declared in the plugin module so a plane's own harness can name it, and absent from
    /// every release build because no non-dev dependency edge enables the feature. So in a release
    /// build the only way to obtain a `&dyn KernelSeal` is to hold a real `Pass` or `Grant`, the
    /// only way to mint one of those is a seal, and the only seal a release build has is the one
    /// the kernel opens out of its own symbol.
    #[doc(hidden)]
    #[cfg(feature = "test-seal")]
    pub fn acquire_for_kernel() -> Self {
        KernelSeal(())
    }

    /// Hand a seal to the kernel, and to nothing else.
    ///
    /// The seal goes to `__busbar_kernel_root`, a symbol only `busbar-kernel` defines. The kernel
    /// wraps it in a type private to the kernel and hands it back boxed as `dyn Any`: the kernel
    /// downcasts it to that type and takes the seal out; any other caller holds a box it cannot
    /// open (it cannot name the type to downcast to). A crate that defined the symbol itself to
    /// catch the seal would be a second definition of a symbol the kernel always links: a link
    /// error, never a quiet interception.
    ///
    /// `#[inline]` on purpose: the call is instantiated only in the crate that calls it, so an
    /// image with no kernel in it (a dropped plugin, this crate's own tests) never references the
    /// symbol.
    ///
    /// The symbol is declared, and the one `unsafe` call made, in [`crate::abi`]: the contract's
    /// unsafe lives in that module and nowhere else (the unsafe policy in `lib.rs`), so this
    /// module stays `forbid(unsafe_code)`.
    #[doc(hidden)]
    #[inline]
    #[must_use]
    pub fn deliver() -> Box<dyn std::any::Any + Send + Sync> {
        crate::abi::kernel_root(KernelSeal(()))
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
/// can build a [`crate::caps::SeatVerdict`] for `S`, so a unit cannot answer a question it was not asked,
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

impl<S: Step> crate::plugin::sealed::KernelSealed for Pass<S> {}

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

// ── the TEST-ONLY seal (#65) ────────────────────────────────────────────────────────────────────
//
// `plugin::TestKernelSeal` is declared in the plugin module so that a PLANE can name it — a plane
// may not name THIS module at all (section 1.2) — but its impls belong here, beside `Pass` and
// `Grant`, because this directory is the one place a reader (and `kernel-seal-impls`) has to look
// to enumerate every type that can present a seal. Gated on this crate's own tests and the dev-only
// feature, so it does not exist in a release build.

#[cfg(any(test, feature = "test-seal"))]
impl crate::plugin::sealed::KernelSealed for crate::plugin::TestKernelSeal {}

#[cfg(any(test, feature = "test-seal"))]
impl crate::plugin::KernelSeal for crate::plugin::TestKernelSeal {
    fn seal_origin(&self) -> &'static str {
        "test-seal: a fixture, not a kernel"
    }
}

impl<C: Capability> crate::plugin::sealed::KernelSealed for Grant<C> {}

impl<C: Capability> crate::plugin::KernelSeal for Grant<C> {
    fn seal_origin(&self) -> &'static str {
        "Grant"
    }
}
