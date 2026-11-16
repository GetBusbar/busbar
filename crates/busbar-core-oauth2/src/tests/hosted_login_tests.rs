// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

const NOW: u64 = 1_800_000_000;

fn seal() -> CookieSeal {
    CookieSeal {
        key: Arc::new(StateKey::derive(&[7; 32])),
        now: NOW,
    }
}

#[test]
fn chooser_renders_declared_inert_presentation_and_generic_instance_names() {
    use busbar_contract::auth_calls::{LoginIcon, LoginIconPath, LoginPresentation};
    let presentation = LoginPresentation {
        label: "Example <identity>".into(),
        icon: Some(LoginIcon {
            view_box: [16, 16],
            paths: vec![LoginIconPath {
                data: "M0 0L8 8z".into(),
                fill: "#123456".into(),
            }],
        }),
    };
    presentation.validate().unwrap();
    let button = button_presentation("unrelated-name", Some(&presentation));
    assert_eq!(button.0, presentation.label);
    assert!(button
        .1
        .contains("<path d=\"M0 0L8 8z\" fill=\"#123456\"/>"));
    let body = render_chooser(&[("unrelated-name".into(), button)], "https://host.example");
    assert!(body.contains("Continue with Example &lt;identity&gt;"));
    assert!(!body.contains("<identity>"));
    assert_eq!(
        button_presentation("corp-sso", None),
        ("Corp Sso".into(), GENERIC_ICON.into())
    );
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
            &seal(),
            "provider",
            None,
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
        "sam\x40acme.com",
        "user:sam",
        "bb_live_7Qm2",
        "https://busbar.example.com",
        "provider",
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
    assert!(page.contains("/auth/token?method=provider"));
    assert!(!page.contains("won't see this key again"));
}

#[test]
fn key_page_has_copy_buttons_wired_to_clipboard() {
    let page = render_key_issued(
        "sam\x40acme.com",
        "user:sam",
        "bb_live_7Qm2",
        "https://busbar.example.com",
        "provider",
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
    let expected = B64.encode(busbar_contract::crypto::sha256(verifier.as_bytes()));
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
        iat: NOW,
    }
}

#[test]
fn a_door_login_begins_with_the_plugins_authorize_url() {
    let resp = begin_outcome(
        &seal(),
        "idp",
        None,
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
        .any(|v| v.to_str().unwrap_or("").starts_with("__Host-busbar_login=")));
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
        &seal(),
        "idp",
        None,
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
    let cookie = door_cookie().encode(&seal());
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
        LoginCookie::decode(&split_value, &seal()).unwrap().state,
        door_cookie().state
    );
}

#[test]
fn login_cookie_fields_keep_first_match_and_existing_pair_grammar() {
    for (fields, expected) in [
        (
            vec!["__Host-busbar_login=first", "__Host-busbar_login=second"],
            Some("first"),
        ),
        (
            vec![
                "other=x",
                "__Host-busbar_login=first; __Host-busbar_login=second",
            ],
            Some("first"),
        ),
        (
            vec!["__Host-busbar_login=", "__Host-busbar_login=second"],
            Some(""),
        ),
        (
            vec!["bad-pair", " __Host-busbar_login=value "],
            Some("value"),
        ),
        (vec!["__Host-busbar_login =wrong", "other=x"], None),
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
        .append(header::COOKIE, "__Host-busbar_login=later".parse().unwrap());
    assert_eq!(read_cookie(&req), None);
}

#[test]
fn credential_prompt_uses_declared_label_and_keeps_private_form_transport() {
    use busbar_contract::auth::{FieldKind, LoginField, LoginForm};
    let presentation = busbar_contract::auth_calls::LoginPresentation {
        label: "Example <directory>".into(),
        icon: None,
    };
    let response = begin_outcome(
        &seal(),
        "unrelated-instance",
        Some(&presentation),
        "https://host.example",
        String::new(),
        "state\"value".into(),
        String::new(),
        false,
        LoginOutcome::Prompt(LoginForm {
            fields: vec![LoginField {
                name: "password".into(),
                label: "Password".into(),
                kind: FieldKind::Password,
                required: true,
            }],
        }),
    );
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let cookie = response.headers()[header::SET_COOKIE].to_str().unwrap();
    assert!(cookie.contains("HttpOnly") && cookie.contains("SameSite=Lax"));
    let html = body_of(response);
    assert!(html.contains("Example &lt;directory&gt; credentials"));
    assert!(html.contains("method=\"post\" action=\"/auth/token\""));
    assert!(html.contains("type=\"password\""));
    assert!(html.contains("state&quot;value"));
}

#[test]
fn a_held_subject_sees_the_on_hold_page_with_its_coded_reason() {
    use busbar_kernel::governance::SelfMintRefusal;
    for (reason, says) in [
        (
            SelfMintRefusal::Disabled,
            "BUSBAR-4043: your self-serve key is on hold: an administrator disabled it; ask your \
             Busbar administrator to re-enable or delete it. See \
             https://getbusbar.com/docs/1.6/errors/BUSBAR-4043",
        ),
        (
            SelfMintRefusal::Revoked,
            "BUSBAR-4043: your self-serve key is on hold: an administrator revoked it, and a \
             revoked key is never re-enabled; ask your Busbar administrator to delete it so your \
             next sign-in issues a new key. See https://getbusbar.com/docs/1.6/errors/BUSBAR-4043",
        ),
        (
            SelfMintRefusal::OtherProvider,
            "BUSBAR-4043: your self-serve key is on hold: it was issued through a different \
             sign-in provider; sign in with that provider, or ask your Busbar administrator to \
             delete it. See https://getbusbar.com/docs/1.6/errors/BUSBAR-4043",
        ),
        (
            SelfMintRefusal::Held,
            "BUSBAR-4043: your self-serve key is on hold: your account is on hold; ask your \
             Busbar administrator. See https://getbusbar.com/docs/1.6/errors/BUSBAR-4043",
        ),
    ] {
        let resp = issue_page(
            "https://busbar.example.com",
            "corp",
            SelfKeyIssue::Held(reason),
        );
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{reason:?}");
        let body = body_of(resp);
        assert_branded_error_page(&body, "Your key is on hold");
        assert!(
            body.contains(says),
            "{reason:?}: the page explains the hold with its code: {body}"
        );
        assert!(
            !body.contains("No access yet"),
            "{reason:?}: a hold is not merged with a missing grant: {body}"
        );
    }
}

#[test]
fn the_login_cookie_is_host_prefixed_with_path_root() {
    let response = begin_outcome(
        &seal(),
        "idp",
        None,
        "https://busbar.example.com",
        "verifier".into(),
        "state".into(),
        "nonce".into(),
        false,
        LoginOutcome::Authorize("https://idp.example.com/authorize".into()),
    );
    let cookie = response.headers()[header::SET_COOKIE].to_str().unwrap();
    assert!(cookie.starts_with("__Host-busbar_login="), "{cookie}");
    assert!(
        cookie.contains("; Path=/;") && cookie.contains("Secure"),
        "{cookie}"
    );
    assert!(!cookie.contains("Domain"), "{cookie}");
    assert!(clear_cookie().contains("Path=/;") && clear_cookie().contains("Max-Age=0"));
}

#[test]
fn a_forged_or_tampered_login_cookie_is_refused() {
    use base64::Engine as _;
    let honest = door_cookie().encode(&seal());
    assert!(LoginCookie::decode(&honest, &seal()).is_some());

    // 1.6 dev's attack: a hand-written, unsigned cookie naming the attacker's own state.
    let unsigned = B64.encode(serde_json::to_vec(&door_cookie()).unwrap());
    assert!(LoginCookie::decode(&unsigned, &seal()).is_none());

    // A signed cookie whose payload was edited (here: `refresh` flipped on).
    let (payload, tag) = honest.split_once('.').unwrap();
    let mut edited: serde_json::Value =
        serde_json::from_slice(&B64.decode(payload).unwrap()).unwrap();
    edited["refresh"] = serde_json::Value::Bool(true);
    let edited = format!("{}.{tag}", B64.encode(serde_json::to_vec(&edited).unwrap()));
    assert!(LoginCookie::decode(&edited, &seal()).is_none());

    // Another deployment's key.
    let other = CookieSeal {
        key: Arc::new(StateKey::derive(&[8; 32])),
        now: NOW,
    };
    assert!(LoginCookie::decode(&honest, &other).is_none());
}

#[test]
fn a_login_cookie_expires_with_its_issue_time() {
    let honest = door_cookie().encode(&seal());
    let later = |secs: u64| CookieSeal {
        key: Arc::new(StateKey::derive(&[7; 32])),
        now: NOW + secs,
    };
    assert!(LoginCookie::decode(&honest, &later(600)).is_some());
    assert!(LoginCookie::decode(&honest, &later(601)).is_none());
    let early = CookieSeal {
        key: Arc::new(StateKey::derive(&[7; 32])),
        now: NOW - 3600,
    };
    assert!(
        LoginCookie::decode(&honest, &early).is_none(),
        "an issue time from the future is refused"
    );
}

#[test]
fn throttled_page_is_branded_and_identical_whichever_limiter_tripped() {
    let a = verdict_response(
        "corp-ad",
        CredentialVerdict::Throttled {
            retry_after_secs: 900,
        },
    )
    .unwrap_err();
    let b = verdict_response(
        "other",
        CredentialVerdict::Throttled {
            retry_after_secs: 900,
        },
    )
    .unwrap_err();
    assert_eq!(a.status().as_u16(), 429);
    assert_eq!(a.headers()[header::RETRY_AFTER], "900");
    assert_eq!(a.headers(), b.headers());
    let body = body_of(*a);
    assert_eq!(body, body_of(*b));
    assert_branded_error_page(&body, "Too many sign-in attempts");
    assert!(body.contains("Please wait a few minutes"));
    assert!(!body.to_lowercase().contains("locked"), "never says locked");
}

#[test]
fn the_limiter_verdicts_render_their_pages() {
    for (verdict, status, heading) in [
        (CredentialVerdict::Malformed, 400, "Sign-in didn't finish"),
        (CredentialVerdict::Declined, 401, "Sign-in was declined"),
        (
            CredentialVerdict::Unavailable {
                retry_after_secs: None,
            },
            503,
            "Couldn't reach your provider",
        ),
        (
            CredentialVerdict::Unavailable {
                retry_after_secs: Some(30),
            },
            503,
            "Couldn't reach your provider",
        ),
        (CredentialVerdict::Unfinished, 502, "Sign-in didn't finish"),
    ] {
        let response = verdict_response("idp", verdict.clone()).unwrap_err();
        assert_eq!(response.status().as_u16(), status, "{verdict:?}");
        assert!(
            response
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .any(|v| v.to_str().unwrap().contains("Max-Age=0")),
            "{verdict:?} clears the cookie"
        );
        assert_branded_error_page(&body_of(*response), heading);
    }
}

/// DEPENDENCY-LADDER C6 (form_urlencoded) pins the callback query reader before the hand decoder
/// goes: empty pieces skipped, a bare name kept with an empty value, `+` a space, `%XX` decoded,
/// a short escape kept, invalid UTF-8 replaced.
#[test]
fn the_callback_query_reads_as_a_form() {
    let pairs = parse_query("code=a%2Fb&&state=x+y%21&bare&bad=%zz%4&lossy=%FF&=v");
    let expected: Vec<(String, String)> = [
        ("code", "a/b"),
        ("state", "x y!"),
        ("bare", ""),
        ("bad", "%zz%4"),
        ("lossy", "\u{fffd}"),
        ("", "v"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v.to_owned()))
    .collect();
    assert_eq!(pairs, expected);
}
