// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! PROOF-058 / LEDGER S-C8: what a route's principal need does with an anonymous caller (one that
//! presents no credential, on a chain that does not name the built-in member `anonymous`).
//!
//! - required (`AUTH_PRINCIPAL`): the anonymous caller is refused 401 `R_AUTH_REQUIRED`, before any
//!   plugin code runs, and the refusal's row is an audited one that records "no credential was
//!   presented"; a verified caller is admitted and the plane is handed its identity.
//! - none (`AUTH_PUBLIC`) and optional (`AUTH_OPTIONAL`): the anonymous caller is admitted with no
//!   identity, and no verifier runs for it.
//!
//! Both of core's decisions are asserted: the inbound admission table (`admission_table::decide`,
//! which picks the refusal row and so what is recorded) and the plane port's per-request admission
//! (`port_auth::admit`, which decides what the plane is handed).

use busbar_kernel::auth::admission_table::{
    decide, Authority, BodyBy, BodyRead, Decision, Facts, Policy, Refusal, Step, Target, Verified,
};
use busbar_kernel::auth::core_answer;
use busbar_kernel::auth::route_record::{Money, RouteClass, RouteRecord, Scope, Who};
use busbar_kernel::plane_driver::port_auth::{
    admit, Admitted, Credentials, NoTickets, Principal, Subject,
};
use busbar_kernel::refusal::{ClientRefusal, CoreRefusals};
use busbar_plugin_abi::fail::refused::{R_AUTH_REQUIRED, R_BAD_CREDENTIAL};
use busbar_plugin_abi::plane::{AUTH_OPTIONAL, AUTH_PRINCIPAL, AUTH_PUBLIC};

const ROUTE: u32 = 7;

fn record(who: Who) -> RouteRecord {
    RouteRecord::stated(RouteClass::Data, who, Scope::none(), Money::None)
}

fn anonymous<'a>() -> Credentials<'a> {
    Credentials {
        bearer: None,
        principal: Principal::Anonymous,
        operator: false,
        signed: None,
    }
}

fn verified<'a>(subject: &str) -> Credentials<'a> {
    Credentials {
        principal: Principal::Verified(Subject::Shared(std::sync::Arc::from(subject))),
        ..anonymous()
    }
}

async fn port_admit(effective: u32, creds: Credentials<'_>) -> Result<Admitted, ClientRefusal> {
    admit(
        ROUTE,
        effective,
        &creds,
        &NoTickets,
        &CoreRefusals::new(),
        "",
        0,
    )
    .await
}

/// Walks `decide` for one request on `record`, reporting each step's fact from `answer`, until it
/// refuses or serves. Returns the decision and the steps it asked for, in order.
fn walk(
    record: &RouteRecord,
    mut facts: Facts,
    answer: impl Fn(Step, &mut Facts),
) -> (Decision, Vec<Step>) {
    let mut asked = Vec::new();
    loop {
        match decide(Target::Route(record), &facts) {
            Decision::Run(step) => {
                assert!(
                    !asked.contains(&step),
                    "decide asked for {step:?} twice: {asked:?}"
                );
                asked.push(step);
                answer(step, &mut facts);
            }
            done => return (done, asked),
        }
    }
}

/// A chain that does not name `anonymous` answers a caller with no credential: denied.
fn chain_denies(step: Step, facts: &mut Facts) {
    match step {
        Step::Verify => facts.verified = Some(Verified::Denied),
        Step::Body => facts.body = Some(BodyRead::Taken),
        other => panic!("an unverified caller reached step {other:?}"),
    }
}

/// The chain verified a caller with a distinct subject and a valid key.
fn chain_verifies(step: Step, facts: &mut Facts) {
    match step {
        Step::Verify => facts.verified = Some(Verified::Identity { shared: false }),
        Step::Policy => facts.policy = Some(Policy::Valid),
        Step::Body => facts.body = Some(BodyRead::Taken),
        other => panic!("a principal-only route with no money ran step {other:?}"),
    }
}

#[test]
fn principal_required_refuses_an_anonymous_caller_with_an_audited_row() {
    let required = record(Who::PRINCIPAL);
    let (decision, asked) = walk(&required, Facts::arrived(false, false), chain_denies);
    assert_eq!(
        asked,
        vec![Step::Verify],
        "the chain judges the caller, and nothing runs after it refuses"
    );
    let Decision::Refuse { refusal, verified } = decision else {
        panic!("an anonymous caller on a principal route was not refused: {decision:?}");
    };
    assert_eq!(refusal, Refusal::Unverified { presented: false });
    assert!(
        !verified,
        "the anonymous caller is never treated as verified"
    );

    // The refusal's row: audited, core writes it (no plugin code runs for an unverified caller),
    // and it records that no credential was presented.
    let row = refusal.row(verified);
    assert!(row.audited, "the refusal of an anonymous caller is audited");
    assert_eq!(row.row, "2");
    assert_eq!((row.status, row.code), (401, R_AUTH_REQUIRED));
    assert_eq!(row.by, BodyBy::Core);
    assert!(row.challenge);

    // A presented credential the chain denied is the same answer, recorded under another code:
    // the audit row tells the two apart, the client's bytes do not.
    let (decision, _) = walk(&required, Facts::arrived(true, false), chain_denies);
    let Decision::Refuse { refusal: bad, .. } = decision else {
        panic!("a denied credential on a principal route was not refused: {decision:?}");
    };
    let bad_row = bad.row(false);
    assert!(bad_row.audited);
    assert_eq!((bad_row.status, bad_row.code), (401, R_BAD_CREDENTIAL));
    let anonymous_answer = core_answer::unverified(false, None);
    let bad_answer = core_answer::unverified(true, None);
    assert_eq!(anonymous_answer.status, 401);
    assert_eq!(anonymous_answer.status, bad_answer.status);
    assert_eq!(anonymous_answer.body, bad_answer.body);
}

#[tokio::test]
async fn principal_required_port_refuses_an_anonymous_caller_and_hands_the_plane_nothing() {
    let refused = port_admit(AUTH_PRINCIPAL, anonymous()).await.unwrap_err();
    assert_eq!((refused.status, refused.code), (401, R_AUTH_REQUIRED));
}

#[tokio::test]
async fn principal_required_admits_a_verified_caller_with_its_identity() {
    let required = record(Who::PRINCIPAL);
    let (decision, asked) = walk(&required, Facts::arrived(true, false), chain_verifies);
    assert_eq!(decision, Decision::Serve(Authority::Unbilled));
    assert_eq!(asked, vec![Step::Verify, Step::Policy, Step::Body]);

    let admitted = port_admit(AUTH_PRINCIPAL, verified("ada")).await.unwrap();
    assert_eq!(admitted.auth, AUTH_PRINCIPAL);
    let identity = admitted
        .identity
        .as_ref()
        .expect("a verified caller is handed to the plane with its identity");
    assert_eq!(identity.subject(), "ada");
    assert!(!admitted.identity_records().is_empty());
}

#[tokio::test]
async fn principal_required_is_not_what_none_and_optional_ask_they_admit_an_anonymous_caller() {
    for (who, class, serves) in [
        (Who::PUBLIC, AUTH_PUBLIC, Authority::Public),
        (Who::OPTIONAL, AUTH_OPTIONAL, Authority::Unbilled),
    ] {
        let (decision, asked) = walk(&record(who), Facts::arrived(false, false), chain_denies);
        assert_eq!(
            decision,
            Decision::Serve(serves),
            "{who:?}: an anonymous caller was not admitted"
        );
        assert_eq!(
            asked,
            vec![Step::Body],
            "{who:?}: no verifier runs for a caller that presents no credential"
        );

        let admitted = port_admit(class, anonymous())
            .await
            .unwrap_or_else(|refused| {
                panic!("{who:?}: the port refused an anonymous caller: {refused:?}")
            });
        assert_eq!(admitted.auth, class);
        assert!(
            admitted.identity.is_none() && admitted.identity_records().is_empty(),
            "{who:?}: an anonymous caller is handed to the plane with no identity"
        );
    }
}
