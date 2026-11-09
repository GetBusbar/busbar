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

#[test]
fn sdk_registration_foreign_export_requires_handlers_for_its_declared_streams() {
    for streams in [
        &[][..],
        &[export::ExportStream::Metrics as u8][..],
        &[export::ExportStream::Logs as u8][..],
        &[
            export::ExportStream::Metrics as u8,
            export::ExportStream::Logs as u8,
        ][..],
    ] {
        for (deliver, scrape) in [(false, false), (true, false), (false, true), (true, true)] {
            let streams = Box::leak(streams.to_vec().into_boxed_slice());
            let tail = Box::leak(Box::new(busbar_contract::abi::sdk::export::tail(
                streams,
                &[],
            )));
            let statement = Box::leak(Box::new(door::stamp::<export::Ops>(Statement {
                kind_tail: std::ptr::from_ref(tail).cast(),
                ..door::statement("declared-streams", "1", 1)
            })));
            let ops = Box::leak(Box::new(export::Ops {
                head: head::<export::Ops>(),
                deliver: deliver.then_some(refused),
                scrape: scrape.then_some(refused),
                status: Some(refused),
                check: Some(refused),
                serve: None,
            }));
            // SAFETY: static, correctly laid out foreign metadata and operation table;
            // validation inspects pointer presence and never invokes the callbacks.
            let foreign = unsafe { door::door(statement, ops, None) };
            let result = validate_door::<Export>(&foreign);
            if streams.contains(&(export::ExportStream::Logs as u8)) && !deliver {
                assert!(matches!(
                    result,
                    Err(LoadError::NullSlot(export::slot::DELIVER))
                ));
            } else if streams.contains(&(export::ExportStream::Metrics as u8)) && !scrape {
                assert!(matches!(
                    result,
                    Err(LoadError::NullSlot(export::slot::SCRAPE))
                ));
            } else {
                assert!(result.is_ok(), "declared stream handlers should admit");
            }
        }
    }
}

#[test]
fn sdk_registration_foreign_null_kind_tails_are_refused_with_all_handlers_present() {
    let statement = Box::leak(Box::new(door::stamp::<export::Ops>(door::statement(
        "missing-tail",
        "1",
        1,
    ))));
    let ops = Box::leak(Box::new(export::Ops {
        head: head::<export::Ops>(),
        deliver: Some(refused),
        scrape: Some(refused),
        status: Some(refused),
        check: Some(refused),
        serve: Some(refused),
    }));
    // SAFETY: static foreign descriptor with deliberately absent tail; no operation is called.
    let foreign = unsafe { door::door(statement, ops, None) };
    assert!(
        matches!(validate_door::<Export>(&foreign), Err(LoadError::KindTail(why)) if why.contains("no kind tail"))
    );

    let statement = Box::leak(Box::new(door::stamp::<hook::Ops>(door::statement(
        "missing-tail",
        "1",
        1,
    ))));
    let ops = Box::leak(Box::new(hook::Ops {
        head: head::<hook::Ops>(),
        decide: Some(refused),
        transform: Some(refused),
        notify: Some(refused),
        configure: Some(refused),
        status: Some(refused),
        describe: Some(refused),
        serve: Some(refused),
    }));
    // SAFETY: static foreign descriptor with deliberately absent tail; no operation is called.
    let foreign = unsafe { door::door(statement, ops, None) };
    assert!(
        matches!(validate_door::<Hook>(&foreign), Err(LoadError::KindTail(why)) if why.contains("no hook tail"))
    );
}

#[test]
fn sdk_registration_foreign_plane_routes_require_serve() {
    use crate::dispatch::kinds::plane::Plane;
    use busbar_contract::abi::{
        mechanism::door::{KindTailHead, Section, SECTION_DECLARING},
        plane,
    };
    const SECTIONS: &[Section] = &[Section {
        name: door::abi_str("entries"),
        flags: SECTION_DECLARING,
        _reserved: 0,
    }];
    const ROUTES: &[plane::AdminRoute] = &[plane::AdminRoute {
        verb: door::abi_str("GET"),
        target: door::abi_str("/entries"),
        flags: 0,
        _reserved: 0,
        audit_verb: door::abi_str(""),
    }];
    for (routed, serve) in [(false, false), (true, false), (true, true)] {
        // SAFETY: PlaneTail is plain C integers and pointers; empty lists use null pointers.
        let mut tail: plane::PlaneTail = unsafe { std::mem::zeroed() };
        tail.head = KindTailHead {
            size: std::mem::size_of::<plane::PlaneTail>() as u32,
            _reserved: 0,
        };
        tail.ingress = plane::INGRESS_REQUEST_RESPONSE;
        tail.answer_layout = plane::ANSWER_LAYOUT;
        if routed {
            tail.admin_routes = ROUTES.as_ptr();
            tail.admin_routes_len = ROUTES.len();
        }
        let tail = Box::leak(Box::new(tail));
        let statement = Box::leak(Box::new(door::stamp::<plane::Ops>(Statement {
            kind_tail: std::ptr::from_ref(tail).cast(),
            sections: SECTIONS.as_ptr(),
            sections_len: SECTIONS.len(),
            ..door::statement("declared-routes", "1", 1)
        })));
        let ops = Box::leak(Box::new(plane::Ops {
            head: head::<plane::Ops>(),
            arrive: Some(refused),
            on_piece: Some(refused),
            refusal: Some(refused),
            serve: serve.then_some(refused),
            hydrate: Some(refused),
            start: Some(refused),
            project: Some(refused),
            catalog: Some(refused),
        }));
        // SAFETY: static foreign descriptors with real table layout; no operation is called.
        let foreign = unsafe { door::door(statement, ops, None) };
        let result = validate_door::<Plane>(&foreign);
        if routed && !serve {
            assert!(matches!(
                result,
                Err(LoadError::NullSlot(plane::slot::SERVE))
            ));
        } else {
            assert!(
                result.is_ok(),
                "complete plane declaration refused: {:?}",
                result.err()
            );
        }
    }
}

#[test]
fn sdk_registration_transport_direction_is_enforced_before_the_actual_callback() {
    use crate::dispatch::kinds::transport::Transport;
    use crate::dispatch::{
        in_head, lifecycle::open_frame, out_head, Bind, ConnTable, DispatchConfig, Dispatcher,
        Frame, NoSink, Plugin, NO_BLOB,
    };
    use busbar_contract::abi::{
        mechanism::{
            call::{OutHead, Outcome},
            lifecycle::{slot as life, OpenOut},
        },
        transport as t,
    };
    use std::ffi::c_void;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    static INSTANCE: u8 = 0;
    unsafe extern "C" fn ready(_: *mut c_void, _: *const c_void, out: *mut c_void) -> RawOutcome {
        // SAFETY: every operation output starts with its writable OutHead.
        unsafe {
            (*out.cast::<OutHead>()).outcome = RawOutcome::of(Outcome::Ready);
        }
        RawOutcome::of(Outcome::Ready)
    }
    unsafe extern "C" fn open(_: *mut c_void, _: *const c_void, out: *mut c_void) -> RawOutcome {
        // SAFETY: OPEN lends OpenOut. The static instance is never dereferenced or mutated.
        unsafe {
            (*out.cast::<OpenOut>()).instance = std::ptr::from_ref(&INSTANCE).cast_mut().cast();
            ready(std::ptr::null_mut(), std::ptr::null(), out)
        }
    }
    unsafe extern "C" fn entered(_: *mut c_void, _: *const c_void, out: *mut c_void) -> RawOutcome {
        CALLS.fetch_add(1, Ordering::SeqCst);
        // SAFETY: LOCATE lends an output whose leading field is OutHead.
        unsafe {
            (*out.cast::<OutHead>()).outcome = RawOutcome::of(Outcome::Refused);
        }
        RawOutcome::of(Outcome::Refused)
    }
    const CLAIMS: &[t::Claim] = &[t::Claim::ZERO];
    const NAMES: &[busbar_contract::abi::mechanism::call::AbiStr] =
        &[door::abi_str("fixture-entry")];
    for dials in [false, true] {
        let tail = Box::leak(Box::new(t::TransportTail {
            role: t::ROLE_FRAMER,
            claim_rows: CLAIMS.as_ptr(),
            claim_rows_len: CLAIMS.len(),
            facts: t::FACT_ACCEPTS | if dials { t::FACT_DIALS } else { 0 },
            frame_piece_size: std::mem::size_of::<t::FramePiece>() as u32,
            ..t::TransportTail::EMPTY
        }));
        let statement = Box::leak(Box::new(door::stamp::<t::Ops>(Statement {
            kind_tail: std::ptr::from_ref(tail).cast(),
            claims: NAMES.as_ptr(),
            claims_len: NAMES.len(),
            ..door::statement("direction-fixture", "1", 1)
        })));
        let ops = Box::leak(Box::new(t::Ops {
            head: OpsHead {
                open: Some(open),
                close: Some(ready),
                ..head::<t::Ops>()
            },
            listen: Some(refused),
            accept: Some(refused),
            dial: Some(refused),
            read: Some(refused),
            write: Some(refused),
            flush: Some(refused),
            shut: Some(refused),
            arrival: Some(refused),
            locate: Some(entered),
            begin: Some(refused),
            ingest: Some(refused),
            emit: Some(refused),
            encode: Some(refused),
            refuse: Some(refused),
            finish: Some(refused),
            detach: Some(refused),
            adopt: Some(refused),
            timer: Some(refused),
        }));
        // SAFETY: correctly laid out static foreign table and metadata; callbacks obey their outputs.
        let foreign = unsafe { door::door(statement, ops, None) };
        let dispatcher = Arc::new(Dispatcher::new(
            DispatchConfig::default(),
            busbar_contract::services::test_caller_binding(),
        ));
        let plugin = Plugin::<Transport>::bind(
            validate_door::<Transport>(&foreign).unwrap(),
            None,
            Bind {
                instance: format!("direction-fixture-{dials}").into(),
                max_inflight_cap: 4,
                sink: Arc::new(NoSink),
                dispatcher: dispatcher.adopter(),
                conns: ConnTable::NoNeeds,
            },
        )
        .unwrap();
        assert_eq!(
            plugin.call(life::OPEN, &mut open_frame(NO_BLOB)).outcome,
            Outcome::Ready
        );
        for accept in [1, 0] {
            // SAFETY: the input consists of integer fields and nullable borrowed buffers.
            let mut input: t::LocateIn = unsafe { std::mem::zeroed() };
            input.head = in_head();
            input.accept = accept;
            // SAFETY: LocateOut consists of integer fields and its plain C head.
            let mut output: t::LocateOut = unsafe { std::mem::zeroed() };
            output.head = out_head();
            let before = CALLS.load(Ordering::SeqCst);
            let called = plugin.call(t::slot::LOCATE, &mut Frame::new(input, output));
            assert_eq!(called.outcome, Outcome::Refused);
            assert_eq!(CALLS.load(Ordering::SeqCst) - before, usize::from(accept == 1 || dials),
                "outbound without dialing must stop before the callback; supported directions must reach it");
        }
        assert_eq!(
            plugin
                .call(life::CLOSE, &mut Frame::new(in_head(), out_head()))
                .outcome,
            Outcome::Ready
        );
    }
}
