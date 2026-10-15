// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! #65: the kernel's seal reaches the kernel and nothing else (`busbar_kernel::seal`), on the
//! release path: this test links the library built without `cfg(test)`, which defines the root
//! symbol once and opens the seal it is handed.

use busbar_contract::caps::KernelSeal;

#[test]
fn the_release_path_hands_the_kernel_a_seal_and_anyone_else_an_unopenable_box() {
    // The kernel's own path: the box its root symbol was handed opens as a seal (`acquire` panics
    // where it does not). What the seal mints is the Teller's to spell, inside `src/` alone
    // (`token-sealed`), so this test holds the seal and mints nothing.
    let _seal: KernelSeal = busbar_kernel::seal::acquire();

    // Anyone else's: the box the contract hands back is the kernel's private wrapper, and it is
    // not a seal (nor a box of one) to anything outside the kernel's seal module.
    let boxed = KernelSeal::deliver();
    assert!(
        !boxed.is::<KernelSeal>(),
        "deliver() handed a caller a bare seal: the seal is reachable outside the kernel"
    );
    assert!(boxed.downcast::<Box<KernelSeal>>().is_err());
}
