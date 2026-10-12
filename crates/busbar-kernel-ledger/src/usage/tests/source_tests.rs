// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The closed sources: which of them the kernel derived itself.

use crate::usage::{Direction, LocatorPtr, QuantitySource};

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
