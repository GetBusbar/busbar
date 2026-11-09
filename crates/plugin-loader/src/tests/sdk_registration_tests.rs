// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Foreign descriptors cannot bypass the declaration checks enforced by the Rust SDK.

use crate::dispatch::{
    kinds::{export::Export, hook::Hook},
    load::validate_door,
    LoadError,
};
use busbar_contract::abi::{
    export, hook,
    mechanism::{
        call::{Op, RawOutcome},
        door::Statement,
        lifecycle::OpsHead,
    },
    sdk::door,
};

extern "C" fn refused(
    _: *mut std::ffi::c_void,
    _: *const std::ffi::c_void,
    _: *mut std::ffi::c_void,
) -> RawOutcome {
    panic!("registration must never call a plugin operation")
}

fn head<T>() -> OpsHead {
    OpsHead {
        size: std::mem::size_of::<T>() as u32,
        slots: ((std::mem::size_of::<T>() - std::mem::offset_of!(OpsHead, validate))
            / std::mem::size_of::<Option<Op>>()) as u32,
        validate: Some(refused),
        open: Some(refused),
        refresh: Some(refused),
        retire: Some(refused),
        tick: Some(refused),
        drive: Some(refused),
        cancel: Some(refused),
        release: Some(refused),
        close: Some(refused),
    }
}

#[test]
fn sdk_registration_foreign_export_checks_metadata_even_with_every_operation_present() {
    const TAIL: export::Tail = busbar_contract::abi::sdk::export::tail(&[255], &[]);
    let statement = Box::leak(Box::new(door::stamp::<export::Ops>(Statement {
        kind_tail: std::ptr::from_ref(&TAIL).cast(),
        ..door::statement("invalid-export", "1", 1)
    })));
    let ops = Box::leak(Box::new(export::Ops {
        head: head::<export::Ops>(),
        deliver: Some(refused),
        scrape: Some(refused),
        status: Some(refused),
        check: Some(refused),
        serve: Some(refused),
    }));
    // SAFETY: intentionally invalid stream code, but every descriptor pointer and table is
    // immutable and correctly laid out. No plugin operation is invoked during validation.
    let foreign = unsafe { door::door(statement, ops, None) };
    assert!(
        matches!(validate_door::<Export>(&foreign), Err(LoadError::KindTail(why)) if why.contains("tail.streams.code"))
    );
}

#[test]
fn sdk_registration_foreign_hook_requires_serve_only_for_declared_routes() {
    const ROUTES: &[hook::Route] = &[hook::Route {
        path: door::abi_str("/hook-status"),
        method: door::abi_str("GET"),
        auth: hook::ROUTE_AUTH_ADMIN,
        _reserved: 0,
    }];
    for routed in [false, true] {
        let tail = Box::leak(Box::new(hook::Tail {
            routes: if routed {
                ROUTES.as_ptr()
            } else {
                std::ptr::null()
            },
            routes_len: usize::from(routed),
            ..busbar_contract::abi::sdk::hook::tail(hook::CLASS_GATE, 0, 0)
        }));
        let statement = Box::leak(Box::new(door::stamp::<hook::Ops>(
            busbar_contract::abi::sdk::hook::statement_with_tail(
                door::statement("route-hook", "1", 1),
                tail,
            ),
        )));
        let ops = Box::leak(Box::new(hook::Ops {
            head: head::<hook::Ops>(),
            decide: Some(refused),
            transform: Some(refused),
            notify: Some(refused),
            configure: Some(refused),
            status: Some(refused),
            describe: Some(refused),
            serve: None,
        }));
        // SAFETY: the table and metadata have their actual static layouts and lifetimes.
        let foreign = unsafe { door::door(statement, ops, None) };
        let result = validate_door::<Hook>(&foreign);
        if routed {
            assert!(matches!(
                result,
                Err(LoadError::NullSlot(hook::slot::SERVE))
            ));
        } else {
            assert!(result.is_ok());
        }
    }
}
