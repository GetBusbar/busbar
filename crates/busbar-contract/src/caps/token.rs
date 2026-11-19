// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The tokens. Holding one is the proof that you are entitled to build the capability it seals.
//! Neither `Clone` nor `Copy`: the loop mints a fresh one per step call and drops it when the call
//! returns, and it is handed to a unit BY REFERENCE, never by value, so a unit never owns one.
//!
//! # Who holds a seal (#65)
//!
//! A token's real constructor is private to this crate, which is what makes the compile-fail
//! fixtures below genuine. Every mint takes a [`KernelSeal`] by reference. The seal TYPE is
//! defined in `busbar-seal` and re-exported here; this crate cannot build one in a release build
//! and neither can any crate that depends on it. The seal's only constructor is the free function
//! `busbar_seal::mint_kernel`, which a crate can name only if it lists `busbar-seal` in its own
//! manifest; a free function does not travel with a re-exported type. Two manifests may list it,
//! `busbar-kernel` (which mints) and this crate (for the type): the `busbar-seal` row of `deny.toml`
//! and the `tools/ci-checks` test `only_the_named_crates_may_depend_on_the_seal_and_the_kernel`
//! hold every manifest to that. `busbar-ports` carries the `compile_fail` proof that a crate
//! without the dependency cannot mint.
//!
//! `KernelSeal::acquire_for_kernel` survives ONLY for tests (the dev-only `test-seal` feature,
//! which `tests/test_seal_is_dev_only.rs` keeps off every non-dev edge, and which `busbar-seal`'s
//! own `compile_fail` fixture proves absent without it), so the test suites that mint tokens to
//! show a step's shape keep doing so, and nothing that ships can.
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

/// The proof that the caller is the kernel: defined in `busbar-seal`, whose free `mint_kernel` is
/// its only constructor (see the module header for who can name that).
///
/// The seal TRAIT the kernel-built views take, [`KernelSeal`](crate::plugin::KernelSeal), is
/// SEALED, and it has exactly three implementors, all at the foot of this file: a real [`Pass`], a
/// real [`Grant`], and `plugin::TestKernelSeal`. The third exists only in this crate's own unit
/// tests and when the dev-only `test-seal` feature is on, declared in the plugin module so a
/// plane's own harness can name it, and absent from every release build because no non-dev
/// dependency edge enables the feature. So in a release build the only way to obtain a
/// `&dyn KernelSeal` is to hold a real `Pass` or `Grant`, the only way to mint one of those is a
/// seal, and the only way to a seal is `busbar_seal::mint_kernel`.
pub use busbar_seal::KernelSeal;

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
    pub const UNBOUND: CallId = CallId(u64::MAX);

    /// Mint a request generation. Kernel only, by way of the seal. The kernel bumps its own counter
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
    pub fn mint_bound(_seal: &KernelSeal, call: CallId) -> Self {
        Pass {
            call,
            _step: PhantomData,
        }
    }

    /// Whether this pass belongs to `call`. An unbound pass belongs to no request, so it never
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
    pub fn mint_bound(_seal: &KernelSeal, call: CallId) -> Self {
        Grant {
            call,
            _cap: PhantomData,
        }
    }

    /// Whether this grant belongs to `call`. An unbound grant belongs to no request, so it never
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
