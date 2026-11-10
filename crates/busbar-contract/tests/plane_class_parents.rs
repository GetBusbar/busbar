// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::{
    mechanism::{door::Statement, rendering, KindCode},
    plane::{ClassParent, PlaneTail, INGRESS_REQUEST_RESPONSE},
};
use std::mem::{offset_of, size_of};

#[test]
fn class_parents_are_signed_and_short_tail_allocations_preserve_prior_rendering() {
    static EDGES: [ClassParent; 2] = [
        ClassParent {
            child: 1,
            parent: 0,
        },
        ClassParent {
            child: 2,
            parent: 0,
        },
    ];
    let mut tail = PlaneTail::EMPTY.with_class_parents(&EDGES);
    tail.ingress = INGRESS_REQUEST_RESPONSE;
    let mut statement = Statement::ZERO;
    statement.kind = KindCode::Plane as u32;
    statement.kind_tail = &tail.head;
    // SAFETY: all tail bytes and static declarations remain live.
    let full = rendering::read(&unsafe { rendering::render(&statement) }.unwrap()).unwrap();
    let suffix: Vec<u8> = [2_u32, 1, 0, 2, 0]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    assert!(full.kind_tail.ends_with(&suffix));

    let old_size = offset_of!(PlaneTail, class_parents);
    tail.head.size = old_size as u32;
    let mut old = vec![0_u64; old_size / size_of::<u64>()];
    assert_eq!(old.len() * size_of::<u64>(), old_size);
    // SAFETY: initialized nonoverlapping allocations have old_size bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(
            (&tail as *const PlaneTail).cast::<u8>(),
            old.as_mut_ptr().cast::<u8>(),
            old_size,
        );
    }
    statement.kind_tail = old.as_ptr().cast();
    // SAFETY: old contains exactly its declared size, with no appended pointers.
    let legacy = rendering::read(&unsafe { rendering::render(&statement) }.unwrap()).unwrap();
    assert_eq!(
        legacy.kind_tail,
        full.kind_tail[..full.kind_tail.len() - suffix.len()]
    );
}
