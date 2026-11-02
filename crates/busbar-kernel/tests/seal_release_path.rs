// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::caps::KernelSeal;

#[test]
fn the_release_path_hands_the_kernel_a_seal_and_anyone_else_an_unopenable_box() {
    let _seal: KernelSeal = busbar_kernel::seal::acquire();

    let boxed = KernelSeal::deliver();
    assert!(
        !boxed.is::<KernelSeal>(),
        "deliver() handed a caller a bare seal: the seal is reachable outside the kernel"
    );
    assert!(boxed.downcast::<Box<KernelSeal>>().is_err());
}
