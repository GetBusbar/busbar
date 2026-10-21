// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EMPTY DECLARATION IS NEVER A GRANT. A plugin builds a contract struct as
//! `T { …, ..T::ZERO }`, so a field it leaves out — or one the contract appends later — reads as
//! its zero. Where that zero would mean something to the host (a point set, a role, a size, a
//! direction, a code), the host's own check must REFUSE a value built from `ZERO`, or read it as
//! nothing declared. Each test below holds one such field to the existing contract check.

use std::mem::size_of;

use busbar_contract::abi::auth::{
    check_inbound_points, check_style_decl, AuthPoints, AuthTail, StyleDecl, AUTH_TAIL_FROZEN,
};
use busbar_contract::abi::host::conn::connector::Need;
use busbar_contract::abi::mechanism::check::{
    check_marks, check_needs, check_rewrites, check_statement_sections,
};
use busbar_contract::abi::mechanism::door::{
    tail_read_len, KindTailHead, MarkWord, Rewrite, Section,
};
use busbar_contract::abi::{plane, transport};

/// What a check answered: its refusal, spelled, or `ACCEPTED`.
fn refused<T, E: std::fmt::Debug>(r: Result<T, E>) -> String {
    match r {
        Ok(_) => "ACCEPTED".to_string(),
        Err(e) => format!("{e:?}"),
    }
}

#[test]
fn a_zero_style_declares_no_point_and_is_refused() {
    let s = StyleDecl::ZERO;
    let got = refused(check_style_decl(s.flags, s.points));
    assert!(got.contains("points.missing"), "{got}");
}

#[test]
fn a_zero_auth_tail_declares_no_capability_and_no_point() {
    let t = AuthTail::ZERO;
    assert_eq!(t.caps, 0);
    assert_eq!(
        check_inbound_points(t.caps, t.inbound_points).unwrap(),
        AuthPoints::EMPTY
    );
}

#[test]
fn a_zero_tail_head_states_no_size_and_is_never_read() {
    assert_eq!(KindTailHead::ZERO.size, 0);
    assert_eq!(
        tail_read_len(
            KindTailHead::ZERO.size,
            AUTH_TAIL_FROZEN,
            size_of::<AuthTail>()
        ),
        None
    );
}

#[test]
fn a_zero_transport_tail_states_no_role_and_is_refused() {
    let got = refused(transport::check::check_tail(
        &transport::TransportTail::ZERO,
    ));
    assert!(got.contains("tail.role"), "{got}");
}

#[test]
fn a_zero_transport_claim_declares_nothing() {
    transport::check::check_claims(&[transport::Claim::ZERO]).unwrap();
}

#[test]
fn zero_transport_rows_are_refused() {
    let got = refused(transport::check::check_status_rows(
        &[transport::StatusRow::ZERO],
        1,
    ));
    assert!(got.contains("status_row.class"), "{got}");
    let got = refused(transport::check::check_fault_rows(
        &[transport::FaultRow::ZERO],
        1,
    ));
    assert!(got.contains("fault_row.fault"), "{got}");
    let got = refused(transport::check::check_settings(&[
        transport::SettingDecl::ZERO,
    ]));
    assert!(got.contains("setting.path"), "{got}");
}

#[test]
fn a_zero_plane_tail_states_no_ingress_and_is_refused() {
    let got = refused(plane::check::check_tail(&plane::PlaneTail::ZERO));
    assert!(got.contains("tail.ingress"), "{got}");
}

#[test]
fn zero_plane_declarations_are_refused() {
    let got = refused(plane::check::check_claims(&[plane::Claim::ZERO], 0));
    assert!(got.contains("claim.verb"), "{got}");
    let got = refused(plane::check::check_dialect_auth(
        &[plane::DialectAuth::ZERO],
        0,
    ));
    assert!(got.contains("dialect_auth.dialect"), "{got}");
    let got = refused(plane::check::check_billable_classes(&[
        plane::BillableClass::ZERO,
    ]));
    assert!(got.contains("billable_class.class"), "{got}");
    let got = refused(plane::check::check_record_chains(
        &[plane::RecordChain::ZERO],
        1,
    ));
    assert!(got.contains("record_chain.framing"), "{got}");
    let got = refused(plane::check::check_trust_keys(&[plane::TrustKey::ZERO]));
    assert!(got.contains("trust_key.key"), "{got}");
    let got = refused(plane::check::check_pin_mechanisms(&[
        plane::PinMechanism::ZERO,
    ]));
    assert!(got.contains("pin_mechanism.token"), "{got}");
}

#[test]
fn a_zero_need_states_no_direction_and_is_refused() {
    let got = refused(check_needs(&[Need::ZERO]));
    assert!(got.contains("need.direction"), "{got}");
}

#[test]
fn zero_statement_entries_are_refused() {
    let got = refused(check_marks(0, &[MarkWord::ZERO]));
    assert!(got.contains("mark_word.class"), "{got}");
    let got = refused(check_rewrites(&[Rewrite::ZERO]));
    assert!(got.contains("rewrite.class"), "{got}");
    let got = refused(check_statement_sections(&[Section::ZERO]));
    assert!(got.contains("section.name"), "{got}");
}
