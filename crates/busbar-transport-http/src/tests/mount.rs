// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The document mount's addressing, over a surface that names no protocol.
//!
//! The fixture is made up, and that is the test's whole method: a battery written against a real
//! protocol's declaration could not tell "this mount is generic" from "this mount happens to fit the
//! one protocol it was written beside". What is asserted here is that the mount reads the
//! DECLARATION — the order, the method, the captures, the bar — and nothing else.
//!
//! The driver is a stand-in that records what it was handed. That is the honest shape for a test at
//! this seam: what this crate is responsible for is what it HANDS OVER and what it does with the
//! answer, and a test that ran a real loop would be testing the loop.

use super::*;
use busbar_contract_transport::surface::{Answering, BindingDecl};

const ENVELOPE: &str = "envelope";
const ROUTED: &str = "routed";

const D_EXACT: &[Dispatch] = &[Dispatch::Target {
    path: "/things/summary",
    method: "GET",
    bar: Bar::Open,
}];

const D_ONE: &[Dispatch] = &[
    Dispatch::Target {
        path: "/things/{id}",
        method: "GET",
        bar: Bar::Credential,
    },
    Dispatch::Target {
        path: "/things/{id}",
        method: "DELETE",
        bar: Bar::Credential,
    },
    Dispatch::Document {
        binding: ENVELOPE,
        method: "POST",
        member: "method",
        name: "things/get",
        bar: Bar::Credential,
    },
];

const D_STREAM: &[Dispatch] = &[Dispatch::Document {
    binding: ENVELOPE,
    method: "POST",
    member: "method",
    name: "things/watch",
    bar: Bar::Credential,
}];

const SURFACE: WireSurface = WireSurface {
    bindings: &[
        BindingDecl {
            name: ENVELOPE,
            transport: "http",
            mounts: &["/rpc", "/rpc/"],
        },
        BindingDecl {
            name: ROUTED,
            transport: "http",
            mounts: &[],
        },
    ],
    operations: &[
        Operation {
            op: "summary",
            dispatch: D_EXACT,
            answering: Answering::Unary,
            request_media: "",
            response_media: "application/json",
        },
        Operation {
            op: "get",
            dispatch: D_ONE,
            answering: Answering::Unary,
            request_media: "application/json",
            response_media: "application/json",
        },
        Operation {
            op: "watch",
            dispatch: D_STREAM,
            answering: Answering::Stream,
            request_media: "application/json",
            response_media: "text/event-stream",
        },
    ],
};

fn request<'r>(target: &'r str, method: &'r str) -> Request<'r> {
    Request {
        target,
        method,
        authority: Some("node.example"),
        peer: "203.0.113.7:51234",
        // The base fixture presents NONE of the three a request carries about itself, so every cell
        // that is not about them reads the same four reserved keys it always did — and the cells
        // that ARE about them say so by putting one there.
        credential: None,
        accepts: None,
        media: None,
        body: b"{}",
    }
}

/// A driver that answers a fixed outcome and keeps what it was handed.
///
/// It records the facts as a flat list of pairs rather than a map, because the ORDER is the thing
/// the tests below are about.
#[derive(Debug, Default)]
struct Recorder {
    seen: std::sync::Mutex<Vec<(String, String)>>,
    body: std::sync::Mutex<Vec<u8>>,
    chain: std::sync::Mutex<Vec<&'static str>>,
    op: std::sync::Mutex<Option<String>>,
    bar: std::sync::Mutex<Option<Bar>>,
}

impl UnitDriver for Recorder {
    fn drive(&self, arrival: Arrival<'_>, _surface: &WireSurface) -> Answer {
        *self.seen.lock().expect("recorder") = arrival
            .facts
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        *self.body.lock().expect("recorder") = arrival.body.to_vec();
        *self.chain.lock().expect("recorder") = arrival.chain.to_vec();
        *self.op.lock().expect("recorder") = arrival.operation.map(|o| o.op.to_string());
        *self.bar.lock().expect("recorder") = Some(arrival.bar);
        Answer {
            body: b"the plane's own bytes".to_vec(),
            media: arrival
                .operation
                .map(|o| o.response_media)
                .unwrap_or("")
                .to_string(),
            answering: arrival.operation.map_or(Answering::Unary, |o| o.answering),
            outcome: Outcome::Completed,
        }
    }
}

/// A declared target resolves to its operation, with the bar the row declares.
#[test]
fn a_declared_target_resolves() {
    let r = request("/things/summary", "GET");
    let got = resolve(&SURFACE, &r).expect("a declared target");
    assert_eq!(got.operation.expect("named by the target").op, "summary");
    assert_eq!(got.bar, Bar::Open);
    assert!(got.captures.is_empty());
}

/// One template, two methods, two operations — and the captures come back named.
#[test]
fn the_method_and_the_captures_both_come_off_the_declaration() {
    let r = request("/things/t-7", "DELETE");
    let got = resolve(&SURFACE, &r).expect("a declared target");
    assert_eq!(got.operation.expect("named by the target").op, "get");
    assert_eq!(got.captures.len(), 1);
    assert_eq!(got.captures[0].name, "id");
    assert_eq!(got.captures[0].value, "t-7");
}

/// A declared mount resolves with NO operation: naming it is the plane's, off the document.
///
/// This is the division the whole module is built on, so it is asserted rather than described.
#[test]
fn a_document_mount_leaves_the_operation_to_the_plane() {
    for spelling in ["/rpc", "/rpc/"] {
        let r = request(spelling, "POST");
        let got = resolve(&SURFACE, &r).expect("a declared mount");
        assert!(
            got.operation.is_none(),
            "`{spelling}` is a mount, and the operation on it is the document's to name"
        );
        assert_eq!(got.bar, Bar::Credential);
    }
}

/// A target no declaration names is unaddressed, which is not a refusal.
#[test]
fn an_undeclared_target_is_unaddressed() {
    let r = request("/nothing/here", "GET");
    assert_eq!(resolve(&SURFACE, &r).unwrap_err(), Unaddressed);
    // A declared template with an undeclared method is equally unaddressed: the method is part of
    // the address, so this is not "the route exists and refused" — nothing was addressed at all.
    let r = request("/things/t-7", "PUT");
    assert_eq!(resolve(&SURFACE, &r).unwrap_err(), Unaddressed);
}

/// The bar for a mount is the strictest any of its document rows declares, and fail-closed.
#[test]
fn the_document_bar_is_the_strictest_and_fails_closed() {
    assert_eq!(document_bar(&SURFACE, ENVELOPE), Bar::Credential);
    // A binding with no document row at all answers `Credential`. The other reading — "nothing said
    // it needs one, so it does not" — turns an incomplete declaration into an open door.
    assert_eq!(document_bar(&SURFACE, ROUTED), Bar::Credential);
    assert_eq!(document_bar(&SURFACE, "no-such-binding"), Bar::Credential);
}

/// A binding whose document rows are ALL open reads as open.
#[test]
fn a_binding_whose_rows_are_all_open_reads_as_open() {
    const OPEN_ENVELOPE: WireSurface = WireSurface {
        bindings: &[BindingDecl {
            name: ENVELOPE,
            transport: "http",
            mounts: &["/open"],
        }],
        operations: &[Operation {
            op: "ping",
            dispatch: &[Dispatch::Document {
                binding: ENVELOPE,
                method: "POST",
                member: "method",
                name: "ping",
                bar: Bar::Open,
            }],
            answering: Answering::Unary,
            request_media: "",
            response_media: "",
        }],
    };
    assert_eq!(document_bar(&OPEN_ENVELOPE, ENVELOPE), Bar::Open);
}

/// The tie-back a document binding needs: a class name finds its operation.
#[test]
fn an_operation_is_found_by_the_class_the_plane_named() {
    assert_eq!(
        operation_of(&SURFACE, "watch").expect("declared").answering,
        Answering::Stream
    );
    assert_eq!(
        operation_of(&SURFACE, "watch")
            .expect("declared")
            .response_media,
        "text/event-stream"
    );
    assert!(operation_of(&SURFACE, "not-a-class").is_none());
}

/// The published facts are the reserved keys, then the captures, in that order.
#[test]
fn the_published_facts_are_the_reserved_keys_then_the_captures() {
    let r = request("/things/t-7?verbose=1", "DELETE");
    let addressed = resolve(&SURFACE, &r).expect("a declared target");
    let facts = published_facts(&r, &addressed.captures);
    assert_eq!(
        facts,
        vec![
            // The TARGET, not the matched template: a plane resolving a location needs what arrived.
            (tfacts::PATH, "/things/t-7?verbose=1"),
            (tfacts::METHOD, "DELETE"),
            (tfacts::AUTHORITY, "node.example"),
            (tfacts::PEER, "203.0.113.7:51234"),
            ("id", "t-7"),
        ]
    );
}

/// An arrival with no authority publishes none rather than an empty one.
///
/// `None` is honest: it says the request named no authority, never that it named the empty string.
#[test]
fn an_absent_authority_is_absent_rather_than_empty() {
    let r = Request {
        authority: None,
        ..request("/things/summary", "GET")
    };
    let facts = published_facts(&r, &[]);
    assert!(!facts.iter().any(|(k, _)| *k == tfacts::AUTHORITY));
}

/// **What a request carries ABOUT ITSELF is published, whole, and after the four about where it
/// went.**
///
/// RED FIRST. A mounted arrival published where a request was SENT and nothing about what it
/// PRESENTED — so a plane driven over this mount saw no credential, whatever the caller had sent, and
/// the only honest posture available to it was the anonymous one. The credential in particular is
/// published UNSTRIPPED: the scheme word is part of what arrived, and a transport that removed one
/// would be interpreting a credential it may not read.
#[test]
fn a_request_publishes_the_three_it_carries_about_itself() {
    let r = Request {
        credential: Some("Bearer eyJ.a.b"),
        accepts: Some("text/event-stream"),
        media: Some("application/json"),
        ..request("/things/t-7", "GET")
    };
    let facts = published_facts(&r, &[]);
    assert_eq!(
        facts,
        vec![
            (tfacts::PATH, "/things/t-7"),
            (tfacts::METHOD, "GET"),
            (tfacts::AUTHORITY, "node.example"),
            (tfacts::PEER, "203.0.113.7:51234"),
            // WHOLE, scheme word included. Stripping it here would put a reading of the credential
            // in the one layer that is not allowed to have one.
            (tfacts::CREDENTIAL, "Bearer eyJ.a.b"),
            (tfacts::ACCEPTS, "text/event-stream"),
            (tfacts::MEDIA, "application/json"),
        ]
    );
}

/// **A request that presented none publishes none, rather than an empty one.**
///
/// The same distinction the authority already makes, and here it is a security one: a plane handed an
/// empty credential is being told a credential was presented and is blank, which is not what
/// happened. An anonymous caller must be representable, because "an anonymous caller is refused with
/// a usable challenge" is a rule a protocol can state and a node has to be able to obey.
#[test]
fn an_absent_credential_is_absent_rather_than_empty() {
    let r = request("/things/summary", "GET");
    let facts = published_facts(&r, &[]);
    assert!(!facts.iter().any(|(k, _)| *k == tfacts::CREDENTIAL));
    assert!(!facts.iter().any(|(k, _)| *k == tfacts::ACCEPTS));
    assert!(!facts.iter().any(|(k, _)| *k == tfacts::MEDIA));
}

/// **A capture cannot shadow the credential either.**
///
/// The ordering rule applied to the field where it matters most. A declaration is free to name a
/// capture `credential`, and a unit authenticated against a template capture instead of against what
/// the caller sent would be a door opened by whoever wrote the route.
#[test]
fn a_capture_cannot_shadow_the_credential() {
    let r = Request {
        credential: Some("Bearer real"),
        ..request("/things/t-7", "GET")
    };
    let facts = published_facts(
        &r,
        &[Capture {
            name: tfacts::CREDENTIAL,
            value: "Bearer forged",
        }],
    );
    let arrival = Arrival {
        facts: &facts,
        body: r.body,
        transport: "http",
        chain: &["http"],
        operation: None,
        bar: Bar::Open,
    };
    assert_eq!(arrival.fact(tfacts::CREDENTIAL), Some("Bearer real"));
}

/// A capture named as a reserved key cannot shadow it.
///
/// Every location resolved further in is resolved against these facts, so a declaration that
/// happened to name a capture `path` must not be able to answer a unit about somewhere else. The
/// ordering is what guarantees it, and the lookup is first-match-wins.
#[test]
fn a_capture_cannot_shadow_a_reserved_key() {
    let r = request("/things/t-7", "GET");
    let facts = published_facts(
        &r,
        &[Capture {
            name: tfacts::PATH,
            value: "/somewhere/else",
        }],
    );
    let arrival = Arrival {
        facts: &facts,
        body: r.body,
        transport: "http",
        chain: &["http"],
        operation: None,
        bar: Bar::Open,
    };
    assert_eq!(arrival.fact(tfacts::PATH), Some("/things/t-7"));
}

/// Every reserved key this mount publishes is one it declares.
///
/// The registration check that catches a transport publishing a reserved key it never declared has
/// to have something to compare against, and this is the assertion that the declaration is complete.
#[test]
fn every_published_reserved_key_is_declared() {
    let r = request("/things/t-7", "GET");
    let facts = published_facts(&r, &[]);
    let published: Vec<&str> = facts
        .iter()
        .map(|(k, _)| *k)
        .filter(|k| busbar_contract_transport::registry::facts::is_reserved(k))
        .collect();
    assert!(!published.is_empty(), "the mount publishes reserved keys");
    assert!(
        busbar_contract_transport::registry::facts::undeclared(MOUNT_FACTS, &published).is_none()
    );
}

/// The captures are also offered as a map, for the question a map is the right shape for.
#[test]
fn the_captures_are_offered_as_a_map_too() {
    let r = request("/things/t-7", "GET");
    let addressed = resolve(&SURFACE, &r).expect("a declared target");
    let map = captures_map(&addressed.captures);
    assert_eq!(map.get("id"), Some(&"t-7"));
    assert_eq!(map.len(), 1);
}

/// Serving hands the driver the facts, the bytes, the stack and the addressing — and nothing else.
#[test]
fn serving_hands_the_driver_what_arrived() {
    let driver = Recorder::default();
    let r = request("/things/t-7", "GET");
    let addressed = resolve(&SURFACE, &r).expect("a declared target");
    let answer = serve(&driver, &SURFACE, &r, &addressed, "http", &["tcp", "http"]);
    assert_eq!(answer.body, b"the plane's own bytes");
    assert_eq!(answer.media, "application/json");
    assert_eq!(answer.answering, Answering::Unary);
    assert_eq!(answer.outcome, Outcome::Completed);

    assert_eq!(*driver.body.lock().expect("recorder"), b"{}".to_vec());
    assert_eq!(*driver.chain.lock().expect("recorder"), vec!["tcp", "http"]);
    assert_eq!(
        driver.op.lock().expect("recorder").as_deref(),
        Some("get"),
        "a target-addressed arrival carries the operation the declaration named"
    );
    assert_eq!(*driver.bar.lock().expect("recorder"), Some(Bar::Credential));
    let seen = driver.seen.lock().expect("recorder");
    assert_eq!(seen[0].0, tfacts::PATH);
    assert!(seen.iter().any(|(k, v)| k == "id" && v == "t-7"));
}

/// A document mount hands the driver NO operation, because the document names it.
#[test]
fn serving_a_mount_hands_the_driver_no_operation() {
    let driver = Recorder::default();
    let r = request("/rpc", "POST");
    let addressed = resolve(&SURFACE, &r).expect("a declared mount");
    let _ = serve(&driver, &SURFACE, &r, &addressed, "http", &["http"]);
    assert!(driver.op.lock().expect("recorder").is_none());
}

/// Every outcome maps to a status, the two credential doors stay apart, and nothing maps to 200 but
/// completion.
#[test]
fn the_status_column_is_total_and_keeps_the_two_doors_apart() {
    assert_eq!(status_of(Outcome::Completed), 200);
    assert_eq!(status_of(Outcome::Unauthenticated), 401);
    assert_eq!(status_of(Outcome::Forbidden), 403);
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
            200,
            "{outcome} is not a success and must not answer 200"
        );
    }
}

/// An unaddressed target has a status of its own, because no unit existed to have an outcome.
#[test]
fn an_unaddressed_target_has_its_own_status() {
    assert_eq!(UNADDRESSED_STATUS, 404);
}

/// The detached driver refuses honestly: unavailable, and never a status that blames the caller.
#[test]
fn the_detached_driver_refuses_without_blaming_the_caller() {
    let r = request("/things/summary", "GET");
    let addressed = resolve(&SURFACE, &r).expect("a declared target");
    let answer = serve(
        &busbar_contract_transport::driver::Detached,
        &SURFACE,
        &r,
        &addressed,
        "http",
        &["http"],
    );
    assert_eq!(answer.outcome, Outcome::Unavailable);
    assert!(answer.body.is_empty());
    assert_eq!(status_of(answer.outcome), 503);
}
