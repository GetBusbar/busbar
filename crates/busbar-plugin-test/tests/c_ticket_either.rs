// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-TICKET-EITHER (ABI-MIN3-INTERFACE §14, §12.11 round 15): one PRINCIPAL|TICKET route takes a key or a ticket.
//!
//! W1-K8B's arms are the class rules (`busbar_kernel::auth::route_chain`): the default effective set, the
//! per-request classification ((d): a ticket-marked credential runs TICKET only, never the key chain) and (e)
//! `routes.<id>.auth` narrowing the set. The admission arms (a)-(c), (f) need W1-K10's `Tickets`.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

use busbar_kernel::auth::route_chain::{applied_class, effective_classes};
use busbar_plugin_abi::plane::{
    AUTH_OPERATOR, AUTH_OPTIONAL, AUTH_PRINCIPAL, AUTH_PUBLIC, AUTH_TICKET,
};

const EITHER: u32 = AUTH_PRINCIPAL | AUTH_TICKET;

fn is_ticket(credential: &str) -> bool {
    credential.starts_with("ek_")
}

#[test]
fn the_default_set_and_per_request_classification() {
    assert_eq!(
        effective_classes("calls", EITHER, None),
        Ok(EITHER),
        "a mask with both defaults to both"
    );
    assert_eq!(
        effective_classes("models", AUTH_PRINCIPAL | AUTH_OPTIONAL, None),
        Ok(AUTH_PRINCIPAL)
    );
    assert_eq!(
        effective_classes("health", AUTH_PUBLIC | AUTH_OPERATOR, None),
        Ok(AUTH_PUBLIC),
        "the lowest bit"
    );
    assert_eq!(
        applied_class(EITHER, Some("sk-live-key"), is_ticket),
        AUTH_PRINCIPAL,
        "(a) a key runs the chain"
    );
    assert_eq!(
        applied_class(EITHER, Some("ek_minted"), is_ticket),
        AUTH_TICKET,
        "(b) a ticket runs TICKET"
    );
    assert_eq!(
        applied_class(EITHER, None, is_ticket),
        AUTH_PRINCIPAL,
        "no credential: PRINCIPAL refuses it"
    );
    assert_eq!(
        applied_class(AUTH_PRINCIPAL, Some("ek_expired"), is_ticket),
        AUTH_PRINCIPAL,
        "(d) a set without TICKET never classifies"
    );
}

#[test]
fn routes_auth_narrows_the_set_and_refuses_a_class_the_route_does_not_offer() {
    assert_eq!(
        effective_classes("calls", EITHER, Some(AUTH_PRINCIPAL)),
        Ok(AUTH_PRINCIPAL)
    );
    assert_eq!(
        applied_class(AUTH_PRINCIPAL, Some("ek_minted"), is_ticket),
        AUTH_PRINCIPAL,
        "(e) with `principal` a ticket goes to the key chain, which refuses it"
    );
    assert_eq!(
        effective_classes("calls", EITHER, Some(AUTH_TICKET)),
        Ok(AUTH_TICKET)
    );
    assert_eq!(
        applied_class(AUTH_TICKET, Some("sk-live-key"), is_ticket),
        AUTH_TICKET,
        "(e) with `ticket` a key is judged as a ticket, which refuses it"
    );
    assert_eq!(effective_classes("calls", EITHER, Some(EITHER)), Ok(EITHER));
    assert_eq!(
        effective_classes("models", AUTH_PRINCIPAL, Some(AUTH_PUBLIC)),
        Err("routes.models.auth names 'public', which route 'models' does not offer".to_owned())
    );
    assert_eq!(
        effective_classes(
            "models",
            AUTH_PRINCIPAL | AUTH_OPTIONAL,
            Some(AUTH_PRINCIPAL | AUTH_OPTIONAL)
        ),
        Err("routes.models.auth must be one class word or [principal, ticket]".to_owned())
    );
    assert!(effective_classes("bare", 0, None).is_err());
}

#[test]
#[ignore = "owner: W1-K8B; re-checked 2026-11-16, W2-SW-AUTH: the Tickets store is on dev (busbar-kernel plane_grants/tickets.rs SealedTickets, unit-tested in plane_grants/tests.rs a_once_ticket_admits_exactly_one_request and a_ticket_record_is_read_not_taken_unless_once) but route_chain::applied_class has no production caller, so a PRINCIPAL|TICKET route is not admitted through it until the auth switch-over (draft MR !2481); the boot still builds ClosedTickets without a signing key (min3_boot.rs:158); K10 remainder is open MR !2651"]
fn ticket_either_arms() {
    todo!("owner: W1-K8B (C-TICKET-EITHER admission arms; W1-K10's Tickets)")
}
