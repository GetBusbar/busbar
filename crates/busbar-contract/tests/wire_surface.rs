// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The wire-surface vocabulary, over a surface that names no protocol.
//!
//! Every fixture here is deliberately made up. The vocabulary's whole claim is that it describes how
//! an operation is ADDRESSED without knowing what the operation is, and a test written against a
//! real protocol's surface would be unable to tell "this vocabulary is general" from "this
//! vocabulary happens to fit the one protocol it was written beside".

use busbar_contract::transport::surface::{
    match_target, resolve_target, Answering, Bar, BindingDecl, Dispatch, Operation, WireSurface,
};

const DOC: &str = "doc";
const TGT: &str = "tgt";
const SVC: &str = "svc";

const D_ONE: &[Dispatch] = &[
    Dispatch::Target {
        path: "/thing/one",
        method: "POST",
        bar: Bar::Credential,
    },
    Dispatch::Document {
        binding: DOC,
        method: "POST",
        member: "method",
        name: "one",
        bar: Bar::Credential,
    },
    Dispatch::Service {
        service: "x.y.Service",
        method: "One",
        bar: Bar::Credential,
    },
];

const D_TWO: &[Dispatch] = &[
    Dispatch::Target {
        path: "/thing/{id}/part/{part}",
        method: "GET",
        bar: Bar::Credential,
    },
    Dispatch::Target {
        path: "/thing/{id}/part/{part}",
        method: "DELETE",
        bar: Bar::Credential,
    },
];

const D_OPEN: &[Dispatch] = &[Dispatch::Target {
    path: "/open",
    method: "GET",
    bar: Bar::Open,
}];

const SURFACE: WireSurface = WireSurface {
    bindings: &[
        BindingDecl {
            name: DOC,
            transport: "request",
            mounts: &["/mount", "/mount/"],
        },
        BindingDecl {
            name: TGT,
            transport: "request",
            mounts: &[],
        },
        BindingDecl {
            name: SVC,
            transport: "call",
            mounts: &[],
        },
    ],
    operations: &[
        Operation {
            op: "one",
            dispatch: D_ONE,
            answering: Answering::Unary,
            request_media: "application/json",
            response_media: "application/json",
        },
        Operation {
            op: "two",
            dispatch: D_TWO,
            answering: Answering::Stream,
            request_media: "application/json",
            response_media: "text/event-stream",
        },
        Operation {
            op: "open",
            dispatch: D_OPEN,
            answering: Answering::Unary,
            request_media: "",
            response_media: "application/json",
        },
    ],
};

/// A capture matches one segment and hands back its declared name beside its value.
#[test]
fn a_template_yields_its_captures_in_order() {
    let got = match_target("/thing/{id}/part/{part}", "/thing/a/part/b")
        .expect("the target is this template");
    assert_eq!(got.len(), 2);
    assert_eq!((got[0].name, got[0].value), ("id", "a"));
    assert_eq!((got[1].name, got[1].value), ("part", "b"));
}

/// A query and a fragment are not part of the path, so neither stops a match.
#[test]
fn the_query_and_the_fragment_are_cut_before_matching() {
    assert!(match_target("/thing/one", "/thing/one?x=1").is_some());
    assert!(match_target("/thing/one", "/thing/one#frag").is_some());
}

/// An EMPTY segment does not fill a capture.
///
/// The failure this refuses is specific: `/thing//part/b` matching `/thing/{id}/part/{part}` reaches
/// a handler with no identifier at all, which is how a request for one thing becomes a scan of
/// everything.
#[test]
fn an_empty_segment_does_not_fill_a_capture() {
    assert!(match_target("/thing/{id}/part/{part}", "/thing//part/b").is_none());
}

/// A template and a target of different depths never match, in either direction.
#[test]
fn depth_is_part_of_the_match() {
    assert!(match_target("/thing/{id}", "/thing/a/b").is_none());
    assert!(match_target("/thing/{id}/x", "/thing/a").is_none());
}

/// The first row that matches is the answer, in the surface's own order.
#[test]
fn resolution_follows_the_declared_order() {
    let (op, _, captures) =
        resolve_target(&SURFACE, "/thing/a/part/b", "GET").expect("a declared target");
    assert_eq!(op.op, "two");
    assert_eq!(captures.len(), 2);
}

/// One template, two methods, and the method is what tells them apart.
#[test]
fn the_method_is_part_of_the_address() {
    let del = resolve_target(&SURFACE, "/thing/a/part/b", "DELETE").expect("a declared target");
    assert_eq!(del.1.bar(), Bar::Credential);
    assert!(resolve_target(&SURFACE, "/thing/a/part/b", "PUT").is_none());
}

/// A request method is compared case-insensitively, because a wire spells it either way.
#[test]
fn the_method_comparison_ignores_case() {
    assert!(resolve_target(&SURFACE, "/thing/one", "post").is_some());
}

/// The bar is a declaration, and it is readable off any arm.
#[test]
fn the_bar_reads_off_every_arm() {
    let open = resolve_target(&SURFACE, "/open", "GET").expect("declared");
    assert_eq!(open.1.bar(), Bar::Open);
}

// ── the boot check's own refusals, each planted ────────────────────────────────────────────────
