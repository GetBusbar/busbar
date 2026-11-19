// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! IF §12.23, C-LINE-CARRIER: what core does with one line's `PlaneOut` items and with the end of a carrier.
//! The plane itself is exercised by the image arms; these run the part core owns.

use std::sync::{Arc, Mutex};

use busbar_contract::kinds::codes::KindCode;
use busbar_contract::services::{Caller, Incarnation};
use busbar_plugin_abi::records::{tag as g, Records, U64Rec};
use busbar_ports::plane::PlaneOut;

use busbar_plugin_abi::fail::refused::R_AUTH_REQUIRED;
use busbar_plugin_abi::plane::{AUTH_OPTIONAL, AUTH_PRINCIPAL, AUTH_PUBLIC, AUTH_TICKET};
use busbar_ports::PortError;

use super::{
    admit_line, carrier_end_arg, line_of, refusal_of, LineCaller, LineEffects, LineRefused,
};
use crate::channels::line_carriers::{CarrierSink, LineCarriers};
use crate::plane_driver::port_session::{Answer, Once, Origin, SessionError};
use crate::refusal::CoreRefusals;

fn owner(name: &str) -> Incarnation {
    Caller::for_test(Arc::from(name), KindCode::Plane)
        .incarnation()
        .clone()
}

#[test]
fn selected_current_refusals_keep_auth_expiry_and_group_policy_distinct() {
    use crate::governance::current_credential::CurrentCredentialRefusal as Credential;
    use crate::governance::selected_policy::SelectedPolicyRefusal as Policy;
    use crate::plane_driver::port_egress::SelectedFailure;
    use busbar_contract::caps::ReasonCode;
    use busbar_plugin_abi::fail::{failed::F_INTERNAL, refused::*};

    let refusals = CoreRefusals::default();
    for (reason, code) in [
        (Policy::CurrentAuthority(Credential::Expired), R_EXPIRED),
        (Policy::CurrentAuthority(Credential::KeyExpired), R_EXPIRED),
        (
            Policy::CurrentAuthority(Credential::Revoked),
            R_BAD_CREDENTIAL,
        ),
        (
            Policy::CurrentAuthority(Credential::SigningUnavailable),
            R_BAD_CREDENTIAL,
        ),
        (Policy::CurrentGroup(ReasonCode::GroupFrozen), R_POLICY),
        (Policy::CurrentGroup(ReasonCode::ScopeDenied), R_POLICY),
        (Policy::InvalidBinding, F_INTERNAL),
        (
            Policy::CurrentAuthority(Credential::ForeignAuthority),
            F_INTERNAL,
        ),
    ] {
        assert_eq!(
            super::selected_refusal(7, &SelectedFailure::Policy(reason), &refusals).code,
            code
        );
    }
}

fn recording() -> (CarrierSink, Arc<Mutex<Vec<Vec<u8>>>>) {
    let seen: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
    let into = Arc::clone(&seen);
    let sink: CarrierSink = Arc::new(move |b: &[u8]| {
        into.lock().unwrap().push(b.to_vec());
        true
    });
    (sink, seen)
}

/// One request answer as a line session reads it.
fn answered(
    items: Vec<PlaneOut<'_>>,
    carriers: &LineCarriers,
    me: &Incarnation,
) -> Result<Vec<u8>, LineRefused> {
    let effects = LineEffects {
        carriers,
        owner: me,
    };
    let mut once = Once::default();
    let mut answer = Answer::default();
    for item in items {
        answer.take(&item, Origin::Request, &mut once, &effects);
    }
    line_of(answer.seal().client)
}

#[test]
fn body_pieces_are_one_line_and_respond_and_head_are_not_written() {
    let carriers = LineCarriers::new();
    let me = owner("mcp");
    let line = answered(
        vec![
            PlaneOut::Respond { status: 200 },
            PlaneOut::Header("content-type", b"application/json"),
            PlaneOut::Body(b"{\"a\":"),
            PlaneOut::Body(b"1}"),
            PlaneOut::End,
            PlaneOut::Finish,
        ],
        &carriers,
        &me,
    );
    assert_eq!(line.unwrap(), b"{\"a\":1}".to_vec());
}

#[test]
fn an_answer_with_no_body_writes_no_line() {
    let carriers = LineCarriers::new();
    let me = owner("mcp");
    let line = answered(
        vec![PlaneOut::Respond { status: 202 }, PlaneOut::End],
        &carriers,
        &me,
    );
    assert!(line.unwrap().is_empty());
}

#[test]
fn an_emit_goes_to_its_carrier_at_once_not_into_the_response_line() {
    let carriers = LineCarriers::new();
    let me = owner("mcp");
    let (sink, seen) = recording();
    let id = carriers.open(&me, Arc::from("anon"), sink).get();
    let line = answered(
        vec![
            PlaneOut::Emit {
                carrier: id,
                bytes: b"{\"ask\":1}",
            },
            PlaneOut::Body(b"{\"r\":1}"),
        ],
        &carriers,
        &me,
    );
    assert_eq!(*seen.lock().unwrap(), vec![b"{\"ask\":1}".to_vec()]);
    assert_eq!(line.unwrap(), b"{\"r\":1}".to_vec());
    assert_eq!(carriers.dropped(), 0);
}

#[test]
fn an_emit_to_a_carrier_another_instance_owns_is_dropped_and_counted() {
    let carriers = LineCarriers::new();
    let (sink, seen) = recording();
    let id = carriers
        .open(&owner("other"), Arc::from("anon"), sink)
        .get();
    let line = answered(
        vec![PlaneOut::Emit {
            carrier: id,
            bytes: b"x",
        }],
        &carriers,
        &owner("mcp"),
    );
    assert!(seen.lock().unwrap().is_empty());
    assert_eq!(carriers.dropped(), 1);
    assert!(line.unwrap().is_empty());
}

#[test]
fn a_message_item_has_no_line_form() {
    let carriers = LineCarriers::new();
    let me = owner("mcp");
    let line = answered(
        vec![PlaneOut::Msg {
            flags: 1,
            bytes: b"x",
        }],
        &carriers,
        &me,
    );
    assert!(matches!(
        line,
        Err(LineRefused::Session(SessionError::NotDriven))
    ));
}

#[test]
fn the_carrier_end_argument_is_one_u64_record_holding_the_id() {
    let arg = carrier_end_arg(42);
    let mut recs = Records::new(arg.as_bytes());
    let rec = recs.next().unwrap().unwrap();
    assert_eq!(rec.tag, g::TEXT);
    assert_eq!(rec.pod::<U64Rec>().unwrap().value, 42);
    assert!(recs.next().is_none());
}

fn carrier(authenticated: bool) -> LineCaller {
    LineCaller {
        principal: Arc::from("ada"),
        authenticated,
    }
}

#[tokio::test]
async fn a_line_on_a_principal_route_carries_the_carrier_principal_as_its_identity() {
    let a = admit_line(3, AUTH_PRINCIPAL, &carrier(true), &CoreRefusals::new())
        .await
        .unwrap();
    assert_eq!(a.auth, AUTH_PRINCIPAL);
    let mut recs = Records::new(a.identity_records());
    let first = recs.next().unwrap().unwrap();
    assert_eq!((first.tag, first.text().unwrap()), (g::ID_SUBJECT, "ada"));
}

#[tokio::test]
async fn a_line_of_an_unauthenticated_carrier_on_a_principal_route_is_refused() {
    let refusal = admit_line(3, AUTH_PRINCIPAL, &carrier(false), &CoreRefusals::new())
        .await
        .unwrap_err();
    assert_eq!((refusal.status, refusal.code), (401, R_AUTH_REQUIRED));
}

#[tokio::test]
async fn a_public_line_route_has_no_identity_and_an_optional_one_follows_the_carrier() {
    let refusals = CoreRefusals::new();
    let public = admit_line(3, AUTH_PUBLIC, &carrier(true), &refusals)
        .await
        .unwrap();
    assert!(public.identity_records().is_empty());
    let optional = admit_line(3, AUTH_OPTIONAL, &carrier(true), &refusals)
        .await
        .unwrap();
    assert!(!optional.identity_records().is_empty());
    let optional = admit_line(3, AUTH_OPTIONAL, &carrier(false), &refusals)
        .await
        .unwrap();
    assert!(optional.identity_records().is_empty());
}

#[tokio::test]
async fn a_mask_holding_principal_and_ticket_runs_principal_on_a_line() {
    // No credential header exists on a line, so the ticket class never applies.
    let a = admit_line(
        3,
        AUTH_PRINCIPAL | AUTH_TICKET,
        &carrier(true),
        &CoreRefusals::new(),
    )
    .await
    .unwrap();
    assert_eq!(a.auth, AUTH_PRINCIPAL);
}

#[test]
fn a_port_failure_on_a_line_maps_to_core_s_refusal() {
    let refusal = refusal_of(
        3,
        &PortError::Failed {
            code: 0x1234,
            text: "backend said x".into(),
            retry_after_s: None,
            backend_status: None,
            error: None,
        },
        &CoreRefusals::new(),
    );
    assert_eq!(refusal.status, 502);
    assert!(refusal.code < 0x100);
    assert!(!refusal.text.contains("backend said x"));
}
