// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The recovery probe's ownership, which is the whole of the previous release's probe-guard tests.
//!
//! Three claims, and the third is the one that is easy to get wrong. An armed guard that is
//! dropped gives the probe back. A guard that was disarmed — because the dispatch it covers
//! recorded its own outcome — gives nothing back. And every release is checked against the epoch
//! captured at the win, so a guard dropped LATE, after a peer has won a newer probe on the same
//! cell, cannot revert the peer's.

use super::harness::{ok_frames, Health, Script};
use super::{member, Node};
use crate::select::ProbeGuard;
use busbar_contract::DestinationId;

#[test]
fn an_armed_guard_gives_the_probe_back_when_it_is_dropped() {
    let node = Node::with_lanes(&["a"]);
    {
        let _guard = ProbeGuard::new(
            node.breaker.as_ref(),
            "primary",
            DestinationId::new(0),
            7,
            1_000,
        );
    }
    assert_eq!(
        node.breaker.probe_releases(),
        vec![("primary".to_string(), DestinationId::new(0), 7)]
    );
}

#[test]
fn a_disarmed_guard_gives_nothing_back() {
    let node = Node::with_lanes(&["a"]);
    {
        let mut guard = ProbeGuard::new(
            node.breaker.as_ref(),
            "primary",
            DestinationId::new(0),
            7,
            1_000,
        );
        guard.disarm();
        assert!(!guard.is_armed());
    }
    assert!(node.breaker.probe_releases().is_empty());
}

#[test]
fn a_late_guard_releases_only_its_own_epoch() {
    let node = Node::with_lanes(&["a"]);
    {
        let _stale = ProbeGuard::new(
            node.breaker.as_ref(),
            "primary",
            DestinationId::new(0),
            7,
            1_000,
        );
    }
    // The release names the epoch this guard won, not whatever is live now, so the owner check on
    // the other side can refuse it. That the epoch travels is the property; the refusal itself is
    // the breaker unit's.
    assert_eq!(node.breaker.probe_releases()[0].2, 7);
}

#[test]
fn a_delivered_answer_hands_the_probe_to_the_outcome_it_recorded() {
    let mut node = Node::with_lanes(&["a"]);
    node.pool("primary", vec![member(DestinationId::new(0), "a")]);
    node.breaker.set(
        DestinationId::new(0),
        Health {
            cooldown: 30,
            offers_probe: Some(11),
            ..Health::default()
        },
    );
    node.transport.script("a", Script::Frames(ok_frames()));

    assert!(node.route("primary").is_delivered());
    assert!(
        node.breaker.probe_releases().is_empty(),
        "the request owns the probe through the success it recorded"
    );
}

#[test]
fn an_attempt_that_never_dispatched_gives_the_probe_back() {
    let mut node = Node::with_lanes(&["a"]);
    node.pool("primary", vec![member(DestinationId::new(0), "a")]);
    node.breaker.set(
        DestinationId::new(0),
        Health {
            cooldown: 30,
            offers_probe: Some(11),
            ..Health::default()
        },
    );
    // The record cannot be made durable, so nothing is sent and nothing records an outcome.
    *node.journal.fail.lock().unwrap() = true;

    assert!(node.route("primary").shed().is_some());
    assert_eq!(
        node.breaker.probe_releases(),
        vec![("primary".to_string(), DestinationId::new(0), 11)],
        "a cell must never wedge half-open on a path that dispatched nothing"
    );
}

#[test]
fn a_probe_won_with_no_slot_to_use_it_is_given_back_at_once() {
    let node = Node::with_lanes(&["a"]);
    let members = vec![member(DestinationId::new(0), "a")];
    node.breaker.set(
        DestinationId::new(0),
        Health {
            cooldown: 30,
            offers_probe: Some(5),
            ..Health::default()
        },
    );
    node.capacity.set_ceiling(DestinationId::new(0), 1);
    let held = node.capacity.saturate(DestinationId::new(0));

    let mut ctx = node.request_ctx();
    assert!(node.pick("primary", &members, &mut ctx).is_none());
    assert_eq!(
        node.breaker.probe_releases(),
        vec![("primary".to_string(), DestinationId::new(0), 5)],
        "the admission that won the probe is the one that has to give it back when it cannot use it"
    );
    drop(held);
}

#[test]
fn a_failed_attempt_records_before_the_guard_can_release() {
    let mut node = Node::with_lanes(&["a"]);
    node.pool("primary", vec![member(DestinationId::new(0), "a")]);
    node.breaker.set(
        DestinationId::new(0),
        Health {
            cooldown: 30,
            offers_probe: Some(3),
            ..Health::default()
        },
    );
    node.transport.script(
        "a",
        Script::DialError(busbar_contract::TransportError::Refused),
    );

    assert!(node.route("primary").shed().is_some());
    let log = node.breaker.log.lock().unwrap();
    let observed = log
        .iter()
        .position(|e| matches!(e, super::harness::Recorded::Observed(..)));
    let released = log
        .iter()
        .position(|e| matches!(e, super::harness::Recorded::ProbeReleased(..)));
    assert!(
        observed.is_some(),
        "a failed attempt tells the breaker what happened"
    );
    if let (Some(observed), Some(released)) = (observed, released) {
        assert!(
            observed < released,
            "the outcome is recorded first, which is what makes the guard's release a safe no-op"
        );
    }
}
