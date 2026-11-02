// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::caps::KernelSeal;

#[cfg(not(test))]
struct Held(KernelSeal);

#[cfg(not(test))]
#[must_use]
#[inline(never)]
pub fn acquire() -> KernelSeal {
    match KernelSeal::deliver().downcast::<Held>() {
        Ok(held) => {
            let Held(seal) = *held;
            seal
        }

        Err(_) => unreachable!("the kernel's root symbol answered with something not the kernel's"),
    }
}

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

#[cfg(test)]
#[must_use]
pub fn acquire() -> KernelSeal {
    KernelSeal::acquire_for_kernel()
}

#[must_use]
pub fn lend() -> busbar_contract::caps::Grant<busbar_contract::caps::Sign> {
    busbar_contract::caps::Grant::mint(&acquire())
}
