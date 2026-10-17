// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE KERNEL'S SEAL (#65, ARCHITECT ruling 2026-10-14): the one place a release build obtains a
//! [`KernelSeal`], and the one crate that can.
//!
//! `busbar-contract` keeps the seal's constructor private. It hands a seal out through one symbol,
//! `__busbar_kernel_root`, which it DECLARES and this module alone DEFINES: the contract's
//! [`KernelSeal::deliver`] builds a seal and calls the symbol, and the definition below wraps the
//! seal in [`Held`], a type private to this module, and hands it back boxed as `dyn Any`. Only
//! [`acquire`] can name `Held`, so only the kernel can take the seal back out.
//!
//! What that closes, concretely:
//!
//! * a crate that calls `KernelSeal::deliver()` itself holds a box it cannot open: it cannot name
//!   `Held` to downcast to;
//! * a crate that defines `__busbar_kernel_root` itself, to catch the seal on its way in, is a
//!   SECOND definition of a symbol this crate always links ([`acquire`] lives in this module, so
//!   the object that defines the symbol is the object every kernel caller pulls in): the link
//!   fails. `tests/members/seal_tests.rs` builds exactly that shape and watches the link refuse;
//! * `KernelSeal::acquire_for_kernel` exists only under `cfg(test)` and the dev-only `test-seal`
//!   feature, so no release build carries a public constructor at all.
//!
//! The seal is a zero-sized value: boxing it allocates nothing.

use busbar_contract::caps::KernelSeal;

/// The seal, as only this module can name it.
#[cfg(not(test))]
struct Held(KernelSeal);

/// The kernel's seal. Boot takes one for the [`Kernel`](crate::teller::Kernel); a kernel
/// service that mints a kernel value takes one where it mints.
///
/// `#[inline(never)]` on purpose, and it must stay so: this function and the symbol definition
/// below share one object file (one module is one codegen unit), and every kernel caller links
/// THIS function by name, so the definition is linked into every image the kernel is in. Were it
/// inlined into its callers, the object holding the definition would be pulled in only to resolve
/// the symbol itself, and an image that defined the symbol first would be linked without it: an
/// interception, not a link error.
#[cfg(not(test))]
#[must_use]
#[inline(never)]
pub fn acquire() -> KernelSeal {
    match KernelSeal::deliver().downcast::<Held>() {
        Ok(held) => {
            let Held(seal) = *held;
            seal
        }
        // `deliver` hands the seal to the definition below and returns what it returns, which is
        // always a `Held`; anything else means a second definition of the symbol was linked in
        // place of this one, which the link refuses.
        Err(_) => unreachable!("the kernel's root symbol answered with something not the kernel's"),
    }
}

/// The contract's way in: a seal, delivered to the kernel and to nothing else. Defined here and
/// nowhere else; see the module documentation.
// `no_mangle` is an unsafe attribute (a second definition of the name is undefined behaviour at
// link time, which the linker refuses as a duplicate symbol); this is the one kernel item that
// needs it, so the crate's `deny(unsafe_code)` is lifted for this item only.
// SAFETY: the signature is exactly the declaration in `busbar-contract/src/abi/mod.rs`
// (`fn __busbar_kernel_root(seal: KernelSeal) -> Box<dyn Any + Send + Sync>`), built by the same
// compiler in the same workspace; the body touches no state.
#[cfg(not(test))]
#[allow(unsafe_code)]
#[no_mangle]
pub fn __busbar_kernel_root(seal: KernelSeal) -> Box<dyn std::any::Any + Send + Sync> {
    Box::new(Held(seal))
}

/// THIS CRATE'S OWN UNIT-TEST BUILD (`cfg(test)`) takes the contract's dev-only test seal, and
/// defines no root symbol: the test binary also links the library built WITHOUT `cfg(test)` (the
/// crate's dev edge on itself, `test-support`), which defines `__busbar_kernel_root` once, so a
/// second definition here is the duplicate symbol the link refuses. The release path is witnessed
/// where it is the only path, in the integration test `tests/seal_release_path.rs`.
#[cfg(test)]
#[must_use]
pub fn acquire() -> KernelSeal {
    KernelSeal::acquire_for_kernel()
}

/// THE GRANT A HOST CRATE PRESENTS TO READ A RESOLVED SECRET (Part 2 #54: `Secret::expose` is the
/// one raw accessor, and it is sealed). Minted from the kernel's own seal ([`acquire`]) and lent to
/// host code that holds a `Secret` and must use its value: a hop injection, an outbound credential,
/// a key handed to the TLS stack, the once-shown mint response.
///
/// A plugin is never lent one: its closure is `busbar-contract` alone (Part 2 #40(a)), so it cannot
/// name this crate, and it cannot implement the sealed `KernelSeal` for a type of its own.
#[must_use]
pub fn lend() -> busbar_contract::caps::Grant<busbar_contract::caps::Sign> {
    busbar_contract::caps::Grant::mint(&acquire())
}
