// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Judging the operator claims (OPERATOR-FROM-ADMITTED-AUTH §3.3): first-party only, at most one,
//! and an unreadable statement refused. The operator instance itself is judged through the kernel's
//! bounded admin call (`judge_admin_calls`), as every admin module is (r3.1 §000.3).

fn claim(provider: &str, first_party: bool) -> busbar_contract::auth_calls::OperatorClaim {
    busbar_contract::auth_calls::OperatorClaim {
        provider: provider.to_owned(),
        canonical: format!("busbar-auth-{provider}"),
        principal: "admin".to_owned(),
        first_party,
        version: "1.6.0".to_owned(),
        signer: "busbar".to_owned(),
    }
}

/// OPERATOR-FROM-ADMITTED-AUTH R2: two first-party rows stating the operator is no operator, and
/// the refusal names both; registration order never picks who holds `Full`.
#[test]
fn choose_refuses_two_first_party_operators_naming_both() {
    let claims = busbar_contract::auth_calls::OperatorClaims {
        claims: vec![claim("first-op", true), claim("second-op", true)],
        unreadable: Vec::new(),
    };
    let judged = crate::operator::choose(&claims);
    let refusal = judged
        .words
        .expect_err("two first-party operators are refused");
    assert!(
        refusal.contains("first-op") && refusal.contains("second-op"),
        "{refusal}"
    );
}

/// OPERATOR-FROM-ADMITTED-AUTH R2: a claim that is not first-party never becomes the operator and
/// never counts toward uniqueness; it is kept aside as inert.
#[test]
fn choose_keeps_a_third_party_claim_out_of_the_count() {
    let claims = busbar_contract::auth_calls::OperatorClaims {
        claims: vec![
            claim("third-party-op", false),
            claim("first-party-op", true),
        ],
        unreadable: Vec::new(),
    };
    let judged = crate::operator::choose(&claims);
    assert_eq!(
        judged.words,
        Ok(Some(claim("first-party-op", true))),
        "the one first-party claim is the operator"
    );
    assert_eq!(judged.inert, vec![claim("third-party-op", false)]);

    let only_third = busbar_contract::auth_calls::OperatorClaims {
        claims: vec![claim("third-party-op", false)],
        unreadable: Vec::new(),
    };
    let judged = crate::operator::choose(&only_third);
    assert_eq!(
        judged.words,
        Ok(None),
        "a third-party claim alone is no operator"
    );
    assert_eq!(judged.inert, vec![claim("third-party-op", false)]);
}

/// OPERATOR-FROM-ADMITTED-AUTH R2: a row whose Statement does not read is refused by name, never
/// silently dropped from the count.
#[test]
fn choose_refuses_an_unreadable_statement() {
    let claims = busbar_contract::auth_calls::OperatorClaims {
        claims: vec![claim("first-party-op", true)],
        unreadable: vec![("garbled-row".to_owned(), "expected a tail".to_owned())],
    };
    let refusal = crate::operator::choose(&claims)
        .words
        .expect_err("an unreadable statement is refused");
    assert!(refusal.contains("garbled-row"), "{refusal}");
    assert!(refusal.contains("expected a tail"), "{refusal}");
}
