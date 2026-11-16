// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-LOGIN-KIND (ABI-MIN3-INTERFACE §14): Login kind from describe facts; `browser_login.client_secret` rules;
//! both bits or a bit without `login` is DescribeInvalid.
//!
//! W1-K8B's arms read the kind from `Described.facts` (`busbar_kernel::auth::login_facts`) and gate the steps a
//! kind offers. The `browser_login.client_secret` rules are unchanged code with their own kernel tests
//! (auth/tests/login_tests.rs); the arm that boots ldap/oidc/github images is the auth switch-over's.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

use busbar_contract::auth::LoginKind;
use busbar_kernel::auth::login_facts::{login_kind, offers, LoginFactsInvalid};
use busbar_plugin_abi::auth::{
    FB_LOGIN_CREDENTIAL, FB_LOGIN_REDIRECT, FB_NEEDS_BODY, LOGIN_BEGIN, LOGIN_COMPLETE,
    LOGIN_CREDENTIAL,
};

#[test]
fn login_kind_from_facts() {
    assert_eq!(
        login_kind(FB_LOGIN_REDIRECT, true),
        Ok(Some(LoginKind::Redirect))
    );
    assert_eq!(
        login_kind(FB_LOGIN_CREDENTIAL | FB_NEEDS_BODY, true),
        Ok(Some(LoginKind::Credential)),
        "other fact bits do not change the kind"
    );
    assert_eq!(
        login_kind(FB_NEEDS_BODY, false),
        Ok(None),
        "no login, no bit"
    );
    assert_eq!(
        login_kind(FB_LOGIN_REDIRECT | FB_LOGIN_CREDENTIAL, true),
        Err(LoginFactsInvalid::BothKinds)
    );
    assert_eq!(login_kind(0, true), Err(LoginFactsInvalid::NoKind));
    for bit in [FB_LOGIN_REDIRECT, FB_LOGIN_CREDENTIAL] {
        assert_eq!(
            login_kind(bit, false),
            Err(LoginFactsInvalid::KindWithoutLogin)
        );
    }
}

#[test]
fn a_step_the_kind_does_not_offer_is_never_sent() {
    assert!(
        offers(LoginKind::Redirect, LOGIN_BEGIN) && offers(LoginKind::Redirect, LOGIN_COMPLETE)
    );
    assert!(!offers(LoginKind::Redirect, LOGIN_CREDENTIAL));
    assert!(offers(LoginKind::Credential, LOGIN_CREDENTIAL));
    assert!(
        !offers(LoginKind::Credential, LOGIN_BEGIN)
            && !offers(LoginKind::Credential, LOGIN_COMPLETE)
    );
}

#[test]
#[ignore = "owner: W2-SW-AUTH; re-checked 2026-11-16: the hosted page over the auth-ldap, auth-oidc and auth-github images (draft MR !2481, IF gap in OUTSTANDING section B; the auth port needs the redesign ruled 2026-11-16 ~21:30Z)"]
fn login_kind_images() {
    todo!("owner: W2-SW-AUTH (C-LOGIN-KIND image arm)")
}
