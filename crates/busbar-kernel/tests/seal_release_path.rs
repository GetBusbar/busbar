// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::caps::KernelSeal;

// This test binary runs on the shipped allocator, so the release path below is counted as it ships.
#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

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

/// The seal crosses the kernel's root symbol in a `Box<dyn Any>`, but what is boxed has no size, so
/// the box is never allocated: `acquire` and `lend` (which this release path serves, not the test
/// seal) cost no heap bytes on this thread however often the request path calls them.
#[cfg(not(target_env = "msvc"))]
#[test]
fn acquiring_and_lending_the_seal_allocates_nothing() {
    assert_eq!(std::mem::size_of::<KernelSeal>(), 0);
    let allocated = tikv_jemalloc_ctl::thread::allocatedp::read().expect("thread.allocatedp");
    let counting = allocated.get();
    std::hint::black_box(Vec::<u8>::with_capacity(64));
    assert!(
        allocated.get() > counting,
        "the counter must see this thread's allocations"
    );
    let before = allocated.get();
    for _ in 0..10_000 {
        std::hint::black_box(busbar_kernel::seal::acquire());
        std::hint::black_box(busbar_kernel::seal::lend());
        std::hint::black_box(KernelSeal::deliver());
    }
    assert_eq!(
        allocated.get() - before,
        0,
        "the release seal path allocated on the heap"
    );
}
