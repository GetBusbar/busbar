// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The framed mount, over a surface that names no protocol.
//!
//! The fixture is deliberately made up, for the reason the vocabulary's own battery gives: a test
//! written against a real protocol's declaration could not tell "this mount is generic" from "this
//! mount happens to fit the one protocol it was written beside".

use super::*;
use busbar_contract_transport::surface::{Answering, BindingDecl};

const SVC: &str = "svc";

const D_ONE: &[Dispatch] = &[Dispatch::Service {
    service: "pkg.v1.Thing",
    method: "DoIt",
    bar: Bar::Credential,
}];

const D_TWO: &[Dispatch] = &[
    Dispatch::Service {
        service: "pkg.v1.Thing",
        method: "WatchIt",
        bar: Bar::Credential,
    },
    // A target row on the same operation, which this mount must ignore: a framed mount serves the
    // framed binding, and reading another binding's rows would serve a path this wire never gets.
    Dispatch::Target {
        path: "/thing/watch",
        method: "GET",
        bar: Bar::Open,
    },
];

const SURFACE: WireSurface = WireSurface {
    bindings: &[BindingDecl {
        name: SVC,
        transport: "grpc",
        mounts: &[],
    }],
    operations: &[
        Operation {
            op: "one",
            dispatch: D_ONE,
            answering: Answering::Unary,
            request_media: "application/grpc",
            response_media: "application/grpc",
        },
        Operation {
            op: "two",
            dispatch: D_TWO,
            answering: Answering::Stream,
            request_media: "application/grpc",
            response_media: "application/grpc",
        },
    ],
};

#[test]
fn a_call_target_splits_into_its_two_names() {
    let call = split_call("/pkg.v1.Thing/DoIt").expect("a well-formed call target");
    assert_eq!(call.service, "pkg.v1.Thing");
    assert_eq!(call.method, "DoIt");
}

/// Anything that is not the two-segment shape is not a call.
///
/// A third segment is the one worth naming: the descriptor cannot produce one, and answering as if
/// it were not there would serve a method the caller did not ask for.
#[test]
fn nothing_but_the_two_segment_shape_is_a_call() {
    assert!(split_call("/pkg.v1.Thing/DoIt/extra").is_none());
    assert!(split_call("/pkg.v1.Thing").is_none());
    assert!(split_call("pkg.v1.Thing/DoIt").is_none());
    assert!(split_call("//DoIt").is_none());
    assert!(split_call("/pkg.v1.Thing/").is_none());
}

/// The path is BUILT from the two names, so it is the path a client derives.
#[test]
fn the_path_round_trips_through_the_split() {
    let path = call_path("pkg.v1.Thing", "DoIt");
    assert_eq!(path, "/pkg.v1.Thing/DoIt");
    let call = split_call(&path).expect("a path this module built is one it can read");
    assert_eq!(call.service, "pkg.v1.Thing");
    assert_eq!(call.method, "DoIt");
}

#[test]
fn a_declared_call_resolves_to_its_operation() {
    let addressed = resolve(&SURFACE, "/pkg.v1.Thing/DoIt").expect("a declared call");
    assert_eq!(addressed.operation.op, "one");
    assert_eq!(addressed.bar, Bar::Credential);
}

/// The two refusals are told apart, and that is the point of there being two.
///
/// A malformed target and a well-formed one naming nothing are different answers to the caller: one
/// is "that is not a call on this wire" and the other is "this server does not implement it".
#[test]
fn the_two_refusals_are_distinguished() {
    assert_eq!(
        resolve(&SURFACE, "/not-a-call").unwrap_err(),
        Unaddressed::NotACall
    );
    assert_eq!(
        resolve(&SURFACE, "/pkg.v1.Thing/Nope").unwrap_err(),
        Unaddressed::NoSuchMethod
    );
}

/// Only the framed rows are served, and the target row on the same operation is not one of them.
#[test]
fn the_declared_calls_are_the_framed_rows_and_nothing_else() {
    assert_eq!(
        declared_calls(&SURFACE),
        vec!["/pkg.v1.Thing/DoIt", "/pkg.v1.Thing/WatchIt"]
    );
}

/// A surface with no framed row declares no call, rather than declaring its target rows as calls.
#[test]
fn a_surface_with_no_framed_row_declares_no_call() {
    const TARGET_ONLY: WireSurface = WireSurface {
        bindings: &[BindingDecl {
            name: "tgt",
            transport: "http",
            mounts: &[],
        }],
        operations: &[Operation {
            op: "only",
            dispatch: &[Dispatch::Target {
                path: "/only",
                method: "GET",
                bar: Bar::Open,
            }],
            answering: Answering::Unary,
            request_media: "",
            response_media: "",
        }],
    };
    assert!(declared_calls(&TARGET_ONLY).is_empty());
    assert_eq!(
        resolve(&TARGET_ONLY, "/pkg.v1.Thing/DoIt").unwrap_err(),
        Unaddressed::NoSuchMethod
    );
}

/// Every outcome maps to a code, the two credential doors stay apart, and only completion is OK.
#[test]
fn the_status_column_is_total_and_keeps_the_two_doors_apart() {
    assert_eq!(status_of(Outcome::Completed), 0);
    assert_eq!(status_of(Outcome::Unauthenticated), 16);
    assert_eq!(status_of(Outcome::Forbidden), 7);
    assert_ne!(
        status_of(Outcome::Unauthenticated),
        status_of(Outcome::Forbidden),
        "collapsing these sends a caller with a bad credential to fix its permissions"
    );
    for outcome in [
        Outcome::Unauthenticated,
        Outcome::Forbidden,
        Outcome::NotFound,
        Outcome::Throttled,
        Outcome::TimedOut,
        Outcome::Cancelled,
        Outcome::Unavailable,
    ] {
        assert_ne!(
            status_of(outcome),
            0,
            "{outcome} is not a success and must not answer OK"
        );
    }
}

/// Both refusals answer the same code, because from the caller's side they mean the same thing:
/// there is no such call here.
#[test]
fn an_unaddressed_call_is_unimplemented_either_way() {
    assert_eq!(UNADDRESSED_STATUS, 12);
    for target in ["/not-a-call", "/pkg.v1.Thing/Nope"] {
        assert!(resolve(&SURFACE, target).is_err());
    }
}
