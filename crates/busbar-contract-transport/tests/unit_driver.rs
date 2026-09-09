// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The driver seam: the shape a transport hands an arrival across, and the closed set it gets back.

use busbar_contract_transport::driver::{Answer, Arrival, Detached, Outcome, UnitDriver};
use busbar_contract_transport::surface::{
    Answering, Bar, BindingDecl, Dispatch, Operation, WireSurface,
};

const OP: Operation = Operation {
    op: "thing",
    dispatch: &[Dispatch::Target {
        path: "/thing",
        method: "GET",
        bar: Bar::Open,
    }],
    answering: Answering::Unary,
    request_media: "",
    response_media: "application/json",
};

const SURFACE: WireSurface = WireSurface {
    bindings: &[BindingDecl {
        name: "b",
        transport: "http",
        mounts: &[],
    }],
    operations: &[OP],
};

fn arrival<'a>(facts: &'a [(&'a str, &'a str)]) -> Arrival<'a> {
    Arrival {
        facts,
        body: b"{}",
        transport: "http",
        chain: &["tcp", "http"],
        operation: Some(&OP),
        bar: Bar::Open,
    }
}

/// A fact is read by name, and an unpublished one is absent rather than empty.
#[test]
fn a_fact_is_read_by_name() {
    let facts = [("path", "/thing"), ("method", "GET")];
    let a = arrival(&facts);
    assert_eq!(a.fact("path"), Some("/thing"));
    assert_eq!(a.fact("method"), Some("GET"));
    assert_eq!(a.fact("authority"), None);
}

/// FIRST MATCH WINS, which is what makes the transport's ordering load-bearing.
///
/// The failure this refuses is precise: a declaration is free to name a capture `path`, and a
/// lookup that took the last match would answer a unit about somewhere other than where it was
/// sent. The transport publishes the reserved keys first; this is the half of that contract that
/// lives here.
#[test]
fn the_first_published_fact_wins() {
    let facts = [("path", "/the/real/target"), ("path", "/somewhere/else")];
    assert_eq!(arrival(&facts).fact("path"), Some("/the/real/target"));
}

/// An empty answer carries no body and no media type, and says why.
#[test]
fn an_empty_answer_carries_nothing_but_its_outcome() {
    let a = Answer::empty(Outcome::Unavailable);
    assert!(a.body.is_empty());
    assert!(a.media.is_empty());
    assert_eq!(a.answering, Answering::Unary);
    assert_eq!(a.outcome, Outcome::Unavailable);
}

/// The detached driver refuses everything, and refuses it as the NODE's inability.
///
/// Not `Forbidden` and not `NotFound`: a listener whose driver is not wired has nothing to say about
/// the caller, and an outcome that blamed the caller would send it away to fix something that is not
/// wrong.
#[test]
fn the_detached_driver_blames_the_node_and_not_the_caller() {
    let facts = [("path", "/thing")];
    let answered = Detached.drive(arrival(&facts), &SURFACE);
    assert_eq!(answered.outcome, Outcome::Unavailable);
    assert!(answered.body.is_empty());
}

/// The trait is object-safe, which is the whole point: a transport holds `&dyn UnitDriver`.
#[test]
fn the_driver_is_object_safe() {
    let driver: &dyn UnitDriver = &Detached;
    let facts = [("path", "/thing")];
    assert_eq!(
        driver.drive(arrival(&facts), &SURFACE).outcome,
        Outcome::Unavailable
    );
}

/// Every outcome is legible, and no two of them render the same word.
///
/// A vocabulary whose members print identically is one a log cannot be read against.
#[test]
fn every_outcome_renders_a_distinct_word() {
    let all = [
        Outcome::Completed,
        Outcome::Unauthenticated,
        Outcome::Forbidden,
        Outcome::NotFound,
        Outcome::Throttled,
        Outcome::TimedOut,
        Outcome::Cancelled,
        Outcome::Unavailable,
    ];
    let mut words: Vec<String> = all.iter().map(ToString::to_string).collect();
    words.sort();
    let before = words.len();
    words.dedup();
    assert_eq!(before, words.len(), "two outcomes render the same word");
    assert!(words.iter().all(|w| !w.is_empty()));
}

/// A driver may serve more than one surface, which is why the surface travels with the arrival.
///
/// The alternative — a driver holding one surface — needs one driver per protocol and a way for the
/// transport to choose between them, which is the transport knowing which protocol it carries, one
/// indirection further out.
#[test]
fn the_surface_travels_with_the_arrival() {
    /// A driver that answers with the number of operations the surface it was handed declares.
    struct Counting;
    impl UnitDriver for Counting {
        fn drive(&self, _a: Arrival<'_>, surface: &WireSurface) -> Answer {
            Answer {
                body: surface.operations.len().to_string().into_bytes(),
                media: String::new(),
                answering: Answering::Unary,
                outcome: Outcome::Completed,
            }
        }
    }
    const OTHER: WireSurface = WireSurface {
        bindings: SURFACE.bindings,
        operations: &[OP, OP],
    };
    let facts = [("path", "/thing")];
    assert_eq!(Counting.drive(arrival(&facts), &SURFACE).body, b"1");
    assert_eq!(Counting.drive(arrival(&facts), &OTHER).body, b"2");
}
