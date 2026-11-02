// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[cfg(feature = "timing")]
#[test]
fn smoke_records_and_the_scoped_dump_has_the_columns() {
    busbar_kernel::timing::set_enabled(true);
    assert!(
        busbar_kernel::timing::enabled(),
        "the embedding hook did not turn the runtime gate on"
    );
    busbar_kernel::timing::reset();

    for _ in 0..1000 {
        let _t = busbar_kernel::timing::timeit!("hot_cheap");
        std::hint::black_box(2u64 + 2);
    }
    busbar_kernel::timing::record("cold_expensive", 25_000);

    busbar_kernel::timing::record("hot_cheap", 480);
    let out = busbar_kernel::timing::scope("scoped_call", || 40 + 2);
    assert_eq!(out, 42);

    busbar_kernel::timing::dump_scoped();

    busbar_kernel::timing::reset();
    let _t = busbar_kernel::timing::timeit!("after_reset");
    busbar_kernel::timing::dump_scoped();
}
