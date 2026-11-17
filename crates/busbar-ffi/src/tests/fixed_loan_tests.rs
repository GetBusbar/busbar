// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::raw::{HostFns, Out};

static HOST: Host = Host::new(
    0,
    HostFns {
        now: None,
        mono: None,
        random: None,
        crypto: None,
        log: None,
        log_level: None,
        grow: None,
        deployment: None,
        migrate_admit: None,
    },
);

#[test]
fn fixed_output_writes_the_lent_backing_without_growth_or_copy() {
    let mut backing = [0xa5; 24];
    let original = backing.as_ptr();
    let written = OutLease::with_fixed(&mut backing, |lease| {
        assert_eq!(lease.raw.cap(), 24);
        assert!(grow(lease.arm(), 24));
        assert!(!grow(lease.arm(), 25));
        assert!(!grow(lease.arm(), usize::MAX));
        assert!(Out::new(lease.arm(), &HOST).append(b"protected reply"));
        lease.with_answer(|bytes| {
            assert_eq!(bytes.as_ptr(), original);
            assert_eq!(bytes, b"protected reply");
        });
        assert!(!grow(lease.arm(), 24));
        assert_eq!(lease.raw.cap(), 24);
        lease.len()
    })
    .expect("a fixed entry");
    assert_eq!(&backing[..written], b"protected reply");
    assert!(backing[written..].iter().all(|byte| *byte == 0));
}

#[test]
fn nested_fixed_output_cannot_grow_the_outer_entry() {
    let mut outer = [0; 16];
    let mut inner = [0; 16];
    OutLease::with_fixed(&mut outer, |a| {
        assert!(grow(a.arm(), 16));
        OutLease::with_fixed(&mut inner, |b| {
            assert!(!grow(a.arm(), 1));
            assert!(grow(b.arm(), 16));
            assert!(Out::new(b.arm(), &HOST).append(b"inner"));
        })
        .expect("nested entry");
        assert!(grow(a.arm(), 16));
        assert!(Out::new(a.arm(), &HOST).append(b"outer"));
    })
    .expect("outer entry");
    assert_eq!(&outer[..5], b"outer");
    assert_eq!(&inner[..5], b"inner");
}

#[test]
fn fixed_output_unregisters_on_unwind_and_after_forgotten_replacement() {
    let before = ACTIVE.with_borrow(|stack| stack.len());
    let mut backing = [0; 16];
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        OutLease::with_fixed(&mut backing, |lease| {
            assert!(Out::new(lease.arm(), &HOST).append(b"partial"));
            panic!("plugin callback unwound");
        });
    }));
    assert!(unwind.is_err());
    assert_eq!(ACTIVE.with_borrow(|stack| stack.len()), before);
    OutLease::with_fixed(&mut backing, |lease| {
        let replacement = OutLease::new(Vec::new(), 0).expect("owned replacement");
        let forgotten = core::mem::replace(lease, replacement);
        core::mem::forget(forgotten);
    })
    .expect("fixed entry");
    assert_eq!(ACTIVE.with_borrow(|stack| stack.len()), before);
}

#[test]
fn fixed_output_has_no_owned_buffer_to_extract() {
    let mut backing = [0; 16];
    OutLease::with_fixed(&mut backing, |lease| {
        let replacement = OutLease::new(Vec::new(), 0).expect("owned replacement");
        let fixed = core::mem::replace(lease, replacement);
        let (owned, written) = fixed.into_buf();
        assert!(owned.is_empty());
        assert_eq!(written, 0);
    })
    .expect("fixed entry");
}

#[test]
fn fixed_output_depth_refuses_without_touching_the_lender() {
    let held: Vec<_> = (0..DEPTH)
        .map(|_| OutLease::new(Vec::new(), 0).expect("within depth"))
        .collect();
    let mut backing = [0xa5; 16];
    assert!(OutLease::with_fixed(&mut backing, |_| panic!("must not enter")).is_none());
    assert_eq!(backing, [0xa5; 16]);
    drop(held);
    assert!(OutLease::with_fixed(&mut backing, |_| ()).is_some());
}
