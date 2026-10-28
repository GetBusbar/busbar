// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-contract/src/auth.rs` (moved with the module from `busbar-api`).

use super::*;

/// `AuthPrincipal::actor_id` is the audit-attribution handle: the principal's own id when one
/// resolved, and the literal `"anonymous"` — never empty, never any other placeholder — for the
/// explicit open-front-door case.
#[test]
fn auth_principal_actor_id_is_the_principal_id_or_anonymous() {
    let identified = AuthPrincipal(Some(Principal::from_id("vk_1")));
    assert_eq!(identified.actor_id(), "vk_1");

    let anon = AuthPrincipal(None);
    assert_eq!(anon.actor_id(), "anonymous");
}

/// `CallerToken`'s manual `Debug` must NEVER print the token contents — presence only, and the two
/// presence states must actually differ (a mutant collapsing both arms to the same literal must
/// fail this).
#[test]
fn caller_token_debug_redacts_and_shows_presence_only() {
    let present = CallerToken(Some("super-secret-caller-token".to_string()));
    let dbg = format!("{present:?}");
    assert!(!dbg.contains("super-secret-caller-token"), "{dbg}");
    assert!(dbg.contains("<present>"), "{dbg}");

    let absent = CallerToken(None);
    let dbg = format!("{absent:?}");
    assert!(dbg.contains("<absent>"), "{dbg}");
    assert_ne!(
        format!("{present:?}"),
        format!("{absent:?}"),
        "the present/absent Debug output must actually differ"
    );
}

/// `AuthModule::cacheable` DEFAULTS to `false` — an in-process module is microseconds, and caching
/// its verdicts would only widen the revocation window. A minimal module overriding nothing must
/// get this default, not silently `true`.
#[test]
fn auth_module_cacheable_defaults_to_false() {
    struct Minimal;
    impl AuthModule for Minimal {
        fn name(&self) -> &'static str {
            "minimal"
        }
        fn authenticate(&self, _candidate: Option<&str>) -> AuthVerdict {
            AuthVerdict::Pass
        }
    }
    assert!(!Minimal.cacheable());
}

/// `LoginModule`'s three defaults are ALL fail-closed (`Redirect` kind, `Reject` outcome) so an
/// existing verify-only auth module that implements nothing of `LoginModule` is unaffected and
/// cannot silently start a login flow.
#[test]
fn login_module_defaults_are_fail_closed() {
    struct VerifyOnly;
    impl LoginModule for VerifyOnly {}

    assert_eq!(VerifyOnly.login_kind(), LoginKind::Redirect);
    assert_eq!(
        VerifyOnly.begin_login(&BeginLogin {
            redirect_uri: "https://example.invalid/cb".to_string(),
            state: "s".to_string(),
            code_challenge: "c".to_string(),
            nonce: None,
            scopes: Vec::new(),
        }),
        LoginOutcome::Reject
    );
    assert_eq!(
        VerifyOnly.complete_login(&CompleteLogin::default()),
        LoginOutcome::Reject
    );
}

/// RED (auth ABI defect 2): the login step types never print a credential through `Debug`: not
/// the authorization code or the PKCE verifier, not a hop's form or header values, not a token
/// response's body. Before, each derived `Debug` and printed them verbatim.
#[test]
fn login_debug_never_prints_a_credential() {
    let hop = LoginHop {
        method: "POST".into(),
        url: "https://idp.example/token?code=url-code".into(),
        form: vec![("client_id".into(), "form-value".into())],
        secret_form_field: Some("client_secret".into()),
        headers: vec![("authorization".into(), "Bearer header-token".into())],
    };
    let login = CompleteLogin {
        code: Some("the-code".into()),
        redirect_uri: Some("https://busbar.example/cb".into()),
        code_verifier: Some("the-verifier".into()),
        submitted: vec![("password".into(), Secret::new("the-password".to_string()))],
        token_response: Some(LoginHttpResponse {
            status: 200,
            body: r#"{"access_token":"the-token"}"#.into(),
        }),
    };
    let shown = format!("{login:?} {:?}", LoginOutcome::Exchange(hop));
    for secret in [
        "the-code",
        "the-verifier",
        "the-password",
        "the-token",
        "url-code",
        "form-value",
        "header-token",
    ] {
        assert!(!shown.contains(secret), "`{secret}` printed: {shown}");
    }
    for named in ["redirect_uri", "client_id", "authorization", "status: 200"] {
        assert!(shown.contains(named), "`{named}` not named: {shown}");
    }
}
