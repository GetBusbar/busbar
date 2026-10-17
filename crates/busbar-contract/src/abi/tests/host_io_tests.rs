// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host I/O table's shape and its `in` checks (`abi/host/io.rs`): one test per arm.

use super::*;
use std::mem::{offset_of, size_of};

#[test]
fn the_table_holds_one_slot_per_op_in_order() {
    let order = [
        (op::OPEN, offset_of!(IoSlots, open)),
        (op::LISTEN, offset_of!(IoSlots, listen)),
        (op::ACCEPT, offset_of!(IoSlots, accept)),
        (op::READ, offset_of!(IoSlots, read)),
        (op::WRITE, offset_of!(IoSlots, write)),
        (op::READY, offset_of!(IoSlots, ready)),
        (op::SHUT, offset_of!(IoSlots, shut)),
        (op::CLOSE, offset_of!(IoSlots, close)),
        (op::SPAWN, offset_of!(IoSlots, spawn)),
        (op::ENDS, offset_of!(IoSlots, ends)),
    ];
    assert_eq!(order.len() as u32, SLOTS);
    for (k, (index, offset)) in order.into_iter().enumerate() {
        assert_eq!(index, k as u32);
        assert_eq!(offset, 8 + 8 * k);
    }
    assert_eq!(size_of::<IoSlots>(), 8 + 8 * SLOTS as usize);
}

#[test]
fn only_the_readiness_slots_may_pend() {
    let pend: Vec<u32> = (0..SLOTS + 2).filter(|s| may_pend(*s)).collect();
    assert_eq!(pend, [op::ACCEPT, op::READ, op::WRITE, op::READY]);
}

#[test]
fn a_ready_waits_on_exactly_one_direction() {
    assert_eq!(check_dir(DIR_READ), Ok(()));
    assert_eq!(check_dir(DIR_WRITE), Ok(()));
    for bad in [0, DIR_BOTH, 4] {
        assert_eq!(check_dir(bad).unwrap_err().rule, Rule::UnknownCode);
    }
}

#[test]
fn a_shut_names_one_or_both_directions() {
    for good in [DIR_READ, DIR_WRITE, DIR_BOTH] {
        assert_eq!(check_how(good), Ok(()));
    }
    for bad in [0, 4, 7] {
        assert_eq!(check_how(bad).unwrap_err().rule, Rule::UnknownCode);
    }
}

#[test]
fn an_address_buffer_is_at_least_max_addr() {
    let mut buf = [0_u8; MAX_ADDR];
    assert_eq!(check_addr_buf(buf.as_mut_ptr(), MAX_ADDR, "f"), Ok(()));
    assert_eq!(
        check_addr_buf(buf.as_mut_ptr(), MAX_ADDR - 1, "f")
            .unwrap_err()
            .rule,
        Rule::OverCap
    );
    assert_eq!(
        check_addr_buf(std::ptr::null_mut(), MAX_ADDR, "f")
            .unwrap_err()
            .rule,
        Rule::NullWithCount
    );
    assert_eq!(
        check_addr_buf(std::ptr::null_mut(), 0, "f")
            .unwrap_err()
            .rule,
        Rule::OverCap
    );
}

#[test]
fn a_spawn_list_never_counts_a_null() {
    let head = ServiceHead {
        size: size_of::<SpawnIn>() as u32,
        op: op::SPAWN,
        handle: crate::abi::mechanism::ticket::CompletionHandle {
            ticket: crate::abi::mechanism::ticket::Ticket::NONE,
            seq: 0,
            _reserved: 0,
        },
    };
    let none = AbiStr {
        ptr: std::ptr::null(),
        len: 0,
    };
    let ok = SpawnIn {
        head,
        program: none,
        args: std::ptr::null(),
        args_len: 0,
        env: std::ptr::null(),
        env_len: 0,
    };
    assert_eq!(check_spawn_in(&ok), Ok(()));
    let bad = SpawnIn { args_len: 1, ..ok };
    assert_eq!(check_spawn_in(&bad).unwrap_err().rule, Rule::NullWithCount);
    let bad = SpawnIn { env_len: 1, ..ok };
    assert_eq!(check_spawn_in(&bad).unwrap_err().rule, Rule::NullWithCount);
}
