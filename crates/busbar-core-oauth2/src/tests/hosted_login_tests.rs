// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn the_button_brands_are_the_legacy_row_and_with_no_row_every_method_is_generic() {
    // This crate's unit binary has no composition root. Supply the same frozen
    // customer rows that the real root's migration-table contract pins.
    static ROWS: std::sync::Once = std::sync::Once::new();
    ROWS.call_once(|| {
        let frozen: serde_yaml::Value = serde_yaml::from_str(include_str!(
            "../../../busbar-kernel/src/tests/fixtures/frozen_customer_text.yaml"
        ))
        .expect("the frozen customer migration rows parse");
        let rows: Vec<(&'static str, &'static str)> = frozen["migration_rows"]
            .as_mapping()
            .expect("the frozen migration rows are a map")
            .iter()
            .map(|(key, value)| {
                let key = key.as_str().expect("a migration row name").to_owned();
                let value = value.as_str().expect("a migration row value").to_owned();
                (
                    &*Box::leak(key.into_boxed_str()),
                    &*Box::leak(value.into_boxed_str()),
                )
            })
            .collect();
        busbar_kernel::config::migration_table::install(Box::leak(rows.into_boxed_slice()));
    });
    let row = busbar_kernel::config::migration_table::text("login_brands");
    let brands: Vec<(&str, &str, &str)> = row
        .split(" | ")
        .map(|b| {
            let f: Vec<&str> = b.split(" : ").collect();
            assert_eq!(f.len(), 3, "`<tokens> : <label> : <icon ref>`: {b}");
            (f[0].split(' ').next().expect("a match token"), f[1], f[2])
        })
        .collect();
    assert_eq!(brands.len(), 3, "1.5.5 branded three providers: {row}");
    for (token, label, icon_ref) in &brands {
        let icon = BRAND_ICONS
            .iter()
            .find(|(r, _)| r == icon_ref)
            .map(|(_, svg)| *svg)
            .unwrap_or_else(|| panic!("no icon asset for `{icon_ref}`"));
        assert_eq!(button_brand(token, None), ((*label).to_string(), icon));
        assert_eq!(
            button_brand("corp-sso", Some(&format!("https://{token}.example"))),
            ((*label).to_string(), icon),
            "the issuer host matches as the name does"
        );
        let body = render_chooser(
            &[((*token).to_string(), button_brand(token, None))],
            "https://busbar.example.com",
        );
        assert!(
            body.contains(&format!(
                "aria-label=\"Continue with {label}\">{icon}<span class=\"plabel\">Continue with {label}</span>"
            )),
            "{token}: {body}"
        );
    }

    assert_eq!(
        button_brand("corp-sso", None),
        ("Corp Sso".to_string(), GENERIC_ICON)
    );

    for (token, _, _) in &brands {
        assert_eq!(
            brand_from("", token, None),
            (titlecase(token), GENERIC_ICON),
            "{token} without the row"
        );
    }
}

#[test]
fn the_same_origin_refresh_rule_against_1_5_5s() {
    for site in [Some("cross-site"), None, Some("none"), Some("same-site")] {
        assert!(!refresh_rotates_under(true, true, site), "{site:?}");
        assert!(refresh_rotates_under(false, true, site), "{site:?}");
    }
    assert!(refresh_rotates_under(true, true, Some("same-origin")));
    for needs in [true, false] {
        assert!(!refresh_rotates_under(needs, false, Some("same-origin")));
    }
}

#[test]
fn begin_with_an_unrepresentable_authorize_url_fails_closed_not_panics() {
    for bad in [
        "https://idp.example.com/authorize\r\nX-Evil: 1",
        "https://idp.example.com/authorize\nX-Evil: 1",
        "https://idp.example.com/authorize?x=\u{0}",
        "https://idp.example.com/authorize?x=\u{7f}",
    ] {
        let resp = begin_outcome(
            "microsoft",
            "https://busbar.example.com",
            "verifier".into(),
            "state".into(),
            "nonce".into(),
            false,
            LoginOutcome::Authorize(bad.to_string()),
        );
        assert_eq!(
            resp.status().as_u16(),
            502,
            "an unrepresentable authorize URL must fail closed as a misbehaving module: {bad:?}"
        );
        assert!(
            resp.headers().get("location").is_none(),
            "no Location may be emitted for {bad:?}"
        );
        assert!(
            resp.headers().get("set-cookie").is_none(),
            "no login cookie may be handed out for {bad:?}"
        );
    }
}

fn assert_branded_error_page(body: &str, heading: &str) {
    assert!(
        body.starts_with("<!doctype html>"),
        "a browser-flow failure must be a full styled HTML document, not plain text: {body}"
    );
    assert!(
        body.contains("class=\"wordmark\">Busbar"),
        "the error card carries the Busbar brand lockup: {body}"
    );
    assert!(
        body.contains("class=\"erricon\""),
        "the error card shows the alert glyph: {body}"
    );

    let heading_esc = heading.replace('\'', "&#39;");
    assert!(
        body.contains(&heading_esc),
        "the error card heading is human-readable ({heading}): {body}"
    );
    assert!(
        body.contains("class=\"backlink\"") && body.contains("href=\"/auth/token\""),
        "the error card links back to sign in: {body}"
    );
    assert!(
        body.contains("Back to sign in"),
        "the back link is labeled: {body}"
    );
}

#[test]
fn key_page_injects_base_url_verbatim() {
    let page = render_key_issued(
        "sam@acme.com",
        "user:sam",
        "bb_live_7Qm2",
        "https://busbar.example.com",
        "microsoft",
    );
    assert!(
        page.contains("https://busbar.example.com"),
        "base_url must be rendered verbatim"
    );
    assert!(
        !page.contains("https://busbar.example.com/v1"),
        "base_url must NOT carry a /v1 suffix (BYOK clients append their own)"
    );
    assert!(page.contains("bb_live_7Qm2"), "the key is shown");

    assert!(page.contains("Refresh key"));
    assert!(page.contains("/auth/token?method=microsoft"));
    assert!(!page.contains("won't see this key again"));
}

#[test]
fn key_page_has_copy_buttons_wired_to_clipboard() {
    let page = render_key_issued(
        "sam@acme.com",
        "user:sam",
        "bb_live_7Qm2",
        "https://busbar.example.com",
        "microsoft",
    );

    assert!(
        page.contains("function bbCopy(") && page.contains("navigator.clipboard"),
        "the self-contained copy JS is inlined"
    );
    assert!(
        page.contains("document.execCommand('copy')"),
        "a non-secure-context fallback is present"
    );

    assert!(
        page.contains("class=\"copy\"")
            && page.contains("aria-label=\"Copy your API key\"")
            && page.contains("onclick=\"bbCopy(this)\""),
        "the key has an accessible, wired Copy button: {page}"
    );
    assert!(
        page.contains("data-copy=\"bb_live_7Qm2\""),
        "the key Copy button carries the key value to copy: {page}"
    );

    assert!(
        page.contains("class=\"copymini\"")
            && page.contains("aria-label=\"Copy the base URL and API key\""),
        "the BYOK block has its own Copy button: {page}"
    );
    assert!(
        page.contains(
            "data-copy=\"base_url: https://busbar.example.com&#10;api_key: bb_live_7Qm2\""
        ),
        "the BYOK Copy button copies the base_url + api_key block: {page}"
    );

    assert!(
        page.contains("class=\"signout\"")
            && page.contains("href=\"/auth/token?logout=1\"")
            && page.contains("Sign out"),
        "the success page offers a Sign out control: {page}"
    );
}

#[test]
fn pkce_code_challenge_is_s256_of_verifier() {
    let verifier = random_b64url(32);
    let challenge = code_challenge_s256(&verifier);
    let expected = B64.encode(ring::digest::digest(
        &ring::digest::SHA256,
        verifier.as_bytes(),
    ));
    assert_eq!(challenge, expected);

    assert!(!challenge.contains('+') && !challenge.contains('/') && !challenge.contains('='));
}

fn body_of(resp: Response) -> String {
    let bytes = futures::executor::block_on(async {
        axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap()
    });
    String::from_utf8(bytes.to_vec()).unwrap()
}

fn door_cookie() -> LoginCookie {
    LoginCookie {
        method: "idp".into(),
        code_verifier: "the-verifier".into(),
        state: "st".into(),
        nonce: "the-core-nonce".into(),
        refresh: false,
    }
}

#[test]
fn a_door_login_begins_with_the_plugins_authorize_url() {
    let resp = begin_outcome(
        "idp",
        "https://busbar.example.com",
        "verifier".into(),
        "state".into(),
        "nonce".into(),
        false,
        LoginOutcome::Authorize("https://idp.example.com/authorize?x=1".into()),
    );
    assert_eq!(resp.status().as_u16(), 302);
    assert_eq!(
        resp.headers().get(header::LOCATION).unwrap(),
        "https://idp.example.com/authorize?x=1"
    );
    assert!(resp
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .any(|v| v.to_str().unwrap_or("").starts_with("busbar_login=")));
}

#[test]
fn a_door_callback_hands_the_plugin_the_cookies_state_and_nonce() {
    let request = callback_request(
        &door_cookie(),
        "the-code".into(),
        "https://busbar.example.com/auth/token".into(),
    );
    assert_eq!(request.state, "st");
    assert_eq!(request.nonce.as_deref(), Some("the-core-nonce"));
    assert_eq!(request.login.code.as_deref(), Some("the-code"));
    assert_eq!(
        request.login.redirect_uri.as_deref(),
        Some("https://busbar.example.com/auth/token")
    );
    assert_eq!(request.login.code_verifier.as_deref(), Some("the-verifier"));
    assert!(
        request.login.token_response.is_none(),
        "the core runs no token exchange for a door plugin"
    );
    assert!(
        request.login.submitted.is_empty(),
        "no credentials ride a callback"
    );
    assert!(
        !format!("{request:?}").contains("REAL-SECRET-XYZ"),
        "not in the complete_login the plugin is handed"
    );
}

#[test]
fn a_door_callback_renders_each_answer_on_its_page() {
    for (outcome, status, heading) in [
        (
            LoginOutcome::SecurityCheckFailed,
            400,
            "Sign-in couldn't be verified",
        ),
        (LoginOutcome::Reject, 401, "Sign-in was declined"),
    ] {
        let resp = callback_outcome("idp", outcome.clone()).unwrap_err();
        assert_eq!(resp.status().as_u16(), status, "{outcome:?}");
        assert_branded_error_page(&body_of(*resp), heading);
    }
    let principal = callback_outcome("idp", LoginOutcome::Identify(Principal::from_id("alice")))
        .expect("an identified principal passes through to the real self-key issuer");
    assert_eq!(principal.id, "alice");
    let unreachable = callback_outcome(
        "idp",
        LoginOutcome::Outage {
            retry_after_secs: None,
        },
    )
    .unwrap_err();
    let page = provider_unreachable(None);

    assert_eq!(unreachable.status().as_u16(), 503);
    assert_eq!(
        unreachable
            .headers()
            .get("retry-after")
            .map(|v| v.to_str().unwrap()),
        Some(PROVIDER_RETRY_AFTER_SECS.to_string().as_str()),
        "retryable: the client is told when"
    );
    assert_eq!(unreachable.status(), page.status());
    assert_eq!(body_of(*unreachable), body_of(page));
}

#[test]
fn an_outage_sends_the_idps_retry_after_clamped() {
    for (stated, sent) in [
        (Some(120), 120),
        (Some(999_999), 3600),
        (Some(u64::MAX), 3600),
        (Some(3600), 3600),
        (Some(1), 1),
        (Some(0), 1),
        (None, 5),
    ] {
        let outcome = LoginOutcome::Outage {
            retry_after_secs: stated,
        };
        let retry_after = |resp: &Response| {
            resp.headers()
                .get("retry-after")
                .map(|v| v.to_str().unwrap().to_string())
        };
        let redirect = callback_outcome("idp", outcome.clone()).unwrap_err();
        assert_eq!(redirect.status().as_u16(), 503, "{stated:?}");
        assert_eq!(retry_after(&redirect), Some(sent.to_string()), "{stated:?}");
        assert_branded_error_page(&body_of(*redirect), "Couldn't reach your provider");

        let posted = credential_outcome("idp", outcome).unwrap_err();
        assert_eq!(posted.status().as_u16(), 503, "{stated:?}");
        assert_eq!(retry_after(&posted), Some(sent.to_string()), "{stated:?}");
        assert_branded_error_page(&body_of(*posted), "Couldn't reach your provider");
    }
}

#[test]
fn a_rejected_begin_callback_and_credential_keep_their_original_response_statuses() {
    let begun = begin_outcome(
        "idp",
        "https://busbar.example.com",
        "verifier".into(),
        "state".into(),
        "nonce".into(),
        false,
        LoginOutcome::Reject,
    );
    let called = callback_outcome("idp", LoginOutcome::Reject).unwrap_err();
    let submitted = credential_outcome("test-login-double", LoginOutcome::Reject).unwrap_err();
    assert_eq!(
        (
            begun.status().as_u16(),
            called.status().as_u16(),
            submitted.status().as_u16()
        ),
        (502, 401, 401),
        "a faulted step finalized as Reject retains begin/callback/credential response statuses",
    );
}

#[test]
fn a_login_cookie_in_a_later_field_matches_its_joined_form() {
    let cookie = door_cookie().encode();
    let mut split = Request::new(Body::empty());
    split
        .headers_mut()
        .append(header::COOKIE, "unrelated=first".parse().unwrap());
    split.headers_mut().append(
        header::COOKIE,
        format!("{LOGIN_COOKIE}={cookie}").parse().unwrap(),
    );
    let mut joined = Request::new(Body::empty());
    joined.headers_mut().insert(
        header::COOKIE,
        format!("unrelated=first; {LOGIN_COOKIE}={cookie}")
            .parse()
            .unwrap(),
    );
    let split_value = read_cookie(&split).expect("the login cookie is present");
    assert_eq!(Some(split_value.clone()), read_cookie(&joined));
    assert_eq!(
        LoginCookie::decode(&split_value).unwrap().state,
        door_cookie().state
    );
}

#[test]
fn login_cookie_fields_keep_first_match_and_existing_pair_grammar() {
    for (fields, expected) in [
        (
            vec!["busbar_login=first", "busbar_login=second"],
            Some("first"),
        ),
        (
            vec!["other=x", "busbar_login=first; busbar_login=second"],
            Some("first"),
        ),
        (vec!["busbar_login=", "busbar_login=second"], Some("")),
        (vec!["bad-pair", " busbar_login=value "], Some("value")),
        (vec!["busbar_login =wrong", "other=x"], None),
    ] {
        let mut req = Request::new(Body::empty());
        for field in fields {
            req.headers_mut()
                .append(header::COOKIE, field.parse().unwrap());
        }
        assert_eq!(read_cookie(&req).as_deref(), expected);
    }
    let mut req = Request::new(Body::empty());
    req.headers_mut().append(
        header::COOKIE,
        axum::http::HeaderValue::from_bytes(b"unreadable=\x80").unwrap(),
    );
    req.headers_mut()
        .append(header::COOKIE, "busbar_login=later".parse().unwrap());
    assert_eq!(read_cookie(&req), None);
}
