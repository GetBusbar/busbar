// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The closed sources: what each one converts a raw measurement to, and which of them the kernel
//! derived itself.

use crate::usage::{Direction, LocatorPtr, QuantitySource};

/// The conversion from a raw measurement to the class's own quantity: bytes floor, frames multiply,
/// and a class declared with no divisor converts nothing rather than dividing by zero.
#[test]
fn the_source_conversions_floor_multiply_and_refuse_to_divide_by_nothing() {
    assert_eq!(
        crate::usage::source::quantity_from_raw(&QuantitySource::KernelBytes { divisor: 4 }, 7),
        1
    );
    assert_eq!(
        crate::usage::source::quantity_from_raw(&QuantitySource::KernelBytes { divisor: 0 }, 7),
        0
    );
    assert_eq!(
        crate::usage::source::quantity_from_raw(&QuantitySource::KernelFrames { factor: 2 }, 3),
        6
    );
    assert_eq!(
        crate::usage::source::quantity_from_raw(
            &QuantitySource::KernelFrames { factor: u64::MAX },
            u64::MAX
        ),
        u64::MAX,
        "the frame factor saturates rather than wrapping"
    );
    assert_eq!(
        crate::usage::source::quantity_from_raw(&QuantitySource::Count, 9),
        9
    );
}

/// Every source in the closed set has a conversion decided for it here, one arm at a time.
///
/// The pass-through sources are listed by name rather than swept up by a wildcard: the wildcard is
/// what let this set drift before, because a source added to `busbar-contract` inherited "meter the raw
/// number" from a catch-all instead of from a decision. Listing them means the compiler asks.
#[test]
fn every_source_has_a_decided_conversion() {
    let pass_through = [
        QuantitySource::Locator {
            direction: crate::usage::source::Direction::Response,
            ptr: LocatorPtr::new("/usage/tokens"),
        },
        QuantitySource::TransportUnits,
        QuantitySource::KernelElapsedMono,
        QuantitySource::Count,
        QuantitySource::PlaneCount {
            content_fact_key: "messages".to_string(),
        },
    ];
    for source in pass_through {
        assert_eq!(
            crate::usage::source::quantity_from_raw(&source, 11),
            11,
            "{source:?} already arrives in the class's own quantity"
        );
    }
    // And the two that do convert, so the table below is the whole set.
    assert_eq!(
        crate::usage::source::quantity_from_raw(&QuantitySource::KernelBytes { divisor: 4 }, 11),
        2
    );
    assert_eq!(
        crate::usage::source::quantity_from_raw(&QuantitySource::KernelFrames { factor: 4 }, 11),
        44
    );
}

/// Which sources the kernel derived itself, and which came from somebody else. The split is what
/// decides whether a line wants a companion at all.
#[test]
fn the_closed_sources_split_into_kernel_derived_and_reported() {
    let kernel = [
        QuantitySource::KernelBytes { divisor: 1 },
        QuantitySource::KernelFrames { factor: 1 },
        QuantitySource::KernelElapsedMono,
        QuantitySource::Count,
    ];
    for s in kernel {
        assert!(s.is_kernel_derived(), "{s:?} is the kernel's own");
        assert!(!s.is_reported());
    }
    let reported = [
        QuantitySource::Locator {
            direction: Direction::Response,
            ptr: LocatorPtr::new("/usage/output_tokens"),
        },
        QuantitySource::TransportUnits,
        QuantitySource::PlaneCount {
            content_fact_key: "calls".to_string(),
        },
    ];
    for s in reported {
        assert!(s.is_reported(), "{s:?} came from somebody else");
    }
}
