//! Configured instances judging requests: a Twilio Media Streams upgrade, a Twilio signed POST, and
//! a Standard Webhooks delivery — the verdicts and the REDs.

use super::*;

/// A request over a plain header list.
fn judge(
    plugin: &WebhookSignature,
    method: &str,
    path: &str,
    query: Option<&str>,
    body: Option<&[u8]>,
    now: u64,
    headers: &[(&str, &[u8])],
) -> Verdict {
    let lookup = |name: &str| {
        headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| *v)
    };
    plugin.judge(&Request {
        method: method.as_bytes(),
        path: path.as_bytes(),
        query: query.map(str::as_bytes),
        body,
        now,
        headers: &lookup,
    })
}

fn identity(subject: &str) -> Verdict {
    Verdict::Identity(VerifiedIdentity {
        subject: subject.into(),
        provider: Some("webhook-signature".into()),
        ..VerifiedIdentity::default()
    })
}

// ── twilio ──────────────────────────────────────────────────────────────────────────────────────

const TOKEN: &[u8] = b"twilio-auth-token";
const TWILIO: &[u8] = br#"{"variant":"twilio","origin":"wss://edge.example.com"}"#;
const PATH: &str = "/twilio/inbound";
const QUERY: &str = "tenant=acme";

fn twilio() -> WebhookSignature {
    WebhookSignature::new(TWILIO, &[TOKEN]).expect("settings are this plugin's")
}

/// What Twilio presents for the upgrade to `wss://edge.example.com/twilio/inbound?tenant=acme`.
fn upgrade_signature() -> String {
    signature::twilio_sign(
        TOKEN,
        b"wss://edge.example.com/twilio/inbound?tenant=acme",
        &[],
    )
}

fn upgrade(path: &str, query: Option<&str>, sig: Option<&[u8]>) -> Verdict {
    let headers: Vec<(&str, &[u8])> = sig.map(|s| ("X-Twilio-Signature", s)).into_iter().collect();
    judge(&twilio(), "GET", path, query, None, 0, &headers)
}

#[test]
fn a_valid_twilio_signature_over_the_requested_url_identifies_the_sender() {
    let sig = upgrade_signature();
    assert_eq!(
        upgrade(PATH, Some(QUERY), Some(sig.as_bytes())),
        identity("webhook-signature:twilio")
    );
    let bare = signature::twilio_sign(TOKEN, b"wss://edge.example.com/twilio/inbound", &[]);
    assert_eq!(
        upgrade(PATH, None, Some(bare.as_bytes())),
        identity("webhook-signature:twilio")
    );
}

#[test]
fn red_a_bad_twilio_signature_is_rejected() {
    let other_token = signature::twilio_sign(
        b"not-the-token",
        b"wss://edge.example.com/twilio/inbound?tenant=acme",
        &[],
    );
    for bad in [
        other_token.as_bytes(),
        b"AAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        b"%%%",
        b"",
    ] {
        assert_eq!(
            upgrade(PATH, Some(QUERY), Some(bad)),
            Verdict::Reject,
            "{bad:?}"
        );
    }
}

#[test]
fn red_a_missing_twilio_signature_header_never_identifies() {
    // Not this plugin's credential: PASS, so a claim whose only alternative is this one has no
    // identity and is refused.
    assert_eq!(upgrade(PATH, Some(QUERY), None), Verdict::Pass);
}

#[test]
fn red_a_twilio_signature_replayed_on_another_url_is_rejected() {
    let sig = upgrade_signature();
    for (path, query) in [
        ("/twilio/other", Some(QUERY)),
        (PATH, Some("tenant=evil")),
        (PATH, None),
    ] {
        assert_eq!(
            upgrade(path, query, Some(sig.as_bytes())),
            Verdict::Reject,
            "{path} {query:?}"
        );
    }
    let elsewhere = WebhookSignature::new(
        br#"{"variant":"twilio","origin":"wss://other.example.com"}"#,
        &[TOKEN],
    )
    .expect("settings");
    let headers: &[(&str, &[u8])] = &[("x-twilio-signature", sig.as_bytes())];
    assert_eq!(
        judge(&elsewhere, "GET", PATH, Some(QUERY), None, 0, headers),
        Verdict::Reject
    );
}

/// Twilio's published example, arriving as the signed form POST it describes.
#[test]
fn twilios_published_vector_verifies_as_a_signed_form_post() {
    let plugin = WebhookSignature::new(
        br#"{"variant":"twilio","origin":"https://mycompany.com"}"#,
        &[b"12345"],
    )
    .expect("settings");
    let body: &[u8] = b"CallSid=CA1234567890ABCDE&Caller=%2B12349013030&Digits=1234&From=%2B12349013030&To=%2B18005551212";
    let headers: &[(&str, &[u8])] = &[("X-Twilio-Signature", b"0/KCTR6DLpKmkAf8muzZqo1nDgQ=")];
    let post = |body: Option<&[u8]>, query: &str| {
        judge(&plugin, "POST", "/myapp.php", Some(query), body, 0, headers)
    };
    assert_eq!(
        post(Some(body), "foo=1&bar=2"),
        identity("webhook-signature:twilio")
    );
    // RED: a tampered parameter, another query, and no body lent.
    let tampered: &[u8] = b"CallSid=CA1234567890ABCDE&Caller=%2B12349013030&Digits=9999&From=%2B12349013030&To=%2B18005551212";
    assert_eq!(post(Some(tampered), "foo=1&bar=2"), Verdict::Reject);
    assert_eq!(post(Some(body), "foo=1&bar=3"), Verdict::Reject);
    assert_eq!(post(None, "foo=1&bar=2"), Verdict::Reject);
}

#[test]
fn a_twilio_json_post_is_bound_by_its_body_sha256() {
    let body: &[u8] = br#"{"property": "value", "boolean": true}"#;
    let query = "bodySHA256=0a1ff7634d9ab3b95db5c9a2dfe9416e41502b283a80c7cf19632632f96e6620";
    let url = format!("wss://edge.example.com/twilio/status?{query}");
    let sig = signature::twilio_sign(TOKEN, url.as_bytes(), &[]);
    let headers: &[(&str, &[u8])] = &[("x-twilio-signature", sig.as_bytes())];
    let post = |body: &[u8]| {
        judge(
            &twilio(),
            "POST",
            "/twilio/status",
            Some(query),
            Some(body),
            0,
            headers,
        )
    };
    assert_eq!(post(body), identity("webhook-signature:twilio"));
    // RED: another body under the same signed URL.
    assert_eq!(post(br#"{"property": "other"}"#), Verdict::Reject);
}

// ── standard-webhooks ───────────────────────────────────────────────────────────────────────────

const SW: &[u8] = br#"{"variant":"standard-webhooks"}"#;
const SW_SECRET: &[u8] = b"whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
const SW_ID: &[u8] = b"msg_p5jXN8AQM9LWM0D4loKWxJek";
const SW_TS: &[u8] = b"1614265330";
const SW_NOW: u64 = 1_614_265_330;
const SW_BODY: &[u8] = br#"{"test": 2432232314}"#;
const SW_SIG: &[u8] = b"v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=";

fn standard() -> WebhookSignature {
    WebhookSignature::new(SW, &[SW_SECRET]).expect("settings are this plugin's")
}

fn delivery(headers: &[(&str, &[u8])], body: Option<&[u8]>, now: u64) -> Verdict {
    judge(
        &standard(),
        "POST",
        "/v1/webhooks/inbound",
        None,
        body,
        now,
        headers,
    )
}

const ALL: &[(&str, &[u8])] = &[
    ("webhook-id", SW_ID),
    ("webhook-timestamp", SW_TS),
    ("webhook-signature", SW_SIG),
];

#[test]
fn the_standard_webhooks_published_vector_identifies_the_sender() {
    let Verdict::Identity(id) = delivery(ALL, Some(SW_BODY), SW_NOW) else {
        panic!("the published vector verifies");
    };
    assert_eq!(id.subject, "webhook-signature:standard-webhooks");
    assert_eq!(id.provider.as_deref(), Some("webhook-signature"));
}

/// The replay key the kernel claims: the message id, for the rest of the window in which its
/// timestamp is acceptable. A later delivery of the same message gets a shorter claim, and one at
/// the window's edge a one-second claim; after the window the message is stale anyway.
#[test]
fn a_verified_delivery_asks_the_kernel_to_admit_its_webhook_id_once_for_the_window() {
    let replay = |now: u64| match delivery(ALL, Some(SW_BODY), now) {
        Verdict::Identity(id) => id.replay.map(|r| (r.key, r.ttl_secs)),
        other => panic!("{other:?}"),
    };
    let key = "standard-webhooks/msg_p5jXN8AQM9LWM0D4loKWxJek".to_string();
    assert_eq!(replay(SW_NOW), Some((key.clone(), 301)));
    assert_eq!(replay(SW_NOW - 300), Some((key.clone(), 601)));
    assert_eq!(replay(SW_NOW + 300), Some((key, 1)));
}

/// A Twilio signature has no nonce or timestamp to key a replay claim on: none is asked.
#[test]
fn a_verified_twilio_request_asks_no_replay_claim() {
    let sig = upgrade_signature();
    assert!(matches!(
        upgrade(PATH, Some(QUERY), Some(sig.as_bytes())),
        Verdict::Identity(VerifiedIdentity { replay: None, .. })
    ));
}

#[test]
fn red_a_bad_standard_webhooks_signature_is_rejected() {
    let wrong: &[(&str, &[u8])] = &[
        ("webhook-id", SW_ID),
        ("webhook-timestamp", SW_TS),
        (
            "webhook-signature",
            b"v1,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc=",
        ),
    ];
    assert_eq!(delivery(wrong, Some(SW_BODY), SW_NOW), Verdict::Reject);
    assert_eq!(
        delivery(ALL, Some(br#"{"test": 1}"#), SW_NOW),
        Verdict::Reject,
        "another body"
    );
    assert_eq!(delivery(ALL, None, SW_NOW), Verdict::Reject, "no body lent");
}

#[test]
fn red_a_stale_standard_webhooks_timestamp_is_rejected() {
    assert_eq!(delivery(ALL, Some(SW_BODY), SW_NOW + 301), Verdict::Reject);
    assert_eq!(delivery(ALL, Some(SW_BODY), SW_NOW - 301), Verdict::Reject);
    // A configured tolerance widens it.
    let wide = WebhookSignature::new(
        br#"{"variant":"standard-webhooks","tolerance_secs":600}"#,
        &[SW_SECRET],
    )
    .expect("settings");
    assert!(matches!(
        judge(&wide, "POST", "/x", None, Some(SW_BODY), SW_NOW + 301, ALL),
        Verdict::Identity(_)
    ));
}

#[test]
fn red_a_missing_standard_webhooks_header_never_identifies() {
    // None of the three: not this plugin's credential.
    assert_eq!(delivery(&[], Some(SW_BODY), SW_NOW), Verdict::Pass);
    // Any one missing: a partial set is rejected.
    for skip in 0..ALL.len() {
        let partial: Vec<(&str, &[u8])> = ALL
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != skip)
            .map(|(_, h)| *h)
            .collect();
        assert_eq!(
            delivery(&partial, Some(SW_BODY), SW_NOW),
            Verdict::Reject,
            "{skip}"
        );
    }
}

// ── settings ────────────────────────────────────────────────────────────────────────────────────

#[test]
fn the_settings_and_the_secret_are_checked_at_open() {
    assert!(WebhookSignature::new(TWILIO, &[]).is_err(), "no secret");
    assert!(
        WebhookSignature::new(TWILIO, &[b""]).is_err(),
        "empty secret"
    );
    assert!(
        WebhookSignature::new(TWILIO, &[TOKEN, TOKEN]).is_err(),
        "two secrets"
    );
    assert!(
        WebhookSignature::new(SW, &[b"whsec_%%%"]).is_err(),
        "not base64"
    );
    for bad in [
        &br#"{"variant":"stripe"}"#[..],
        br#"{"variant":"twilio"}"#,
        br#"{"variant":"twilio","origin":"edge.example.com"}"#,
        br#"{"variant":"twilio","origin":"wss://edge.example.com/"}"#,
        br#"{"variant":"twilio","origin":"wss://edge.example.com?x=1"}"#,
        br#"{"variant":"twilio","origin":"wss://"}"#,
        br#"{"variant":"twilio","origin":"wss://edge.example.com","tolerance_secs":1}"#,
        br#"{"variant":"standard-webhooks","origin":"https://x"}"#,
        br#"{"variant":"twilio","origin":"wss://edge.example.com","subject":""}"#,
        br#"{"variant":"twilio","origin":"wss://edge.example.com","extra":1}"#,
        b"not json",
    ] {
        assert!(
            WebhookSignature::new(bad, &[TOKEN]).is_err(),
            "{}",
            String::from_utf8_lossy(bad)
        );
    }
    let named = WebhookSignature::new(
        br#"{"variant":"twilio","origin":"wss://edge.example.com:8443","subject":"acme-phone"}"#,
        &[TOKEN],
    )
    .expect("a port and a subject are fine");
    let sig = signature::twilio_sign(TOKEN, b"wss://edge.example.com:8443/twilio/inbound", &[]);
    let headers: &[(&str, &[u8])] = &[("x-twilio-signature", sig.as_bytes())];
    assert_eq!(
        judge(&named, "GET", PATH, None, None, 0, headers),
        identity("acme-phone")
    );
}

#[test]
fn the_signing_secret_is_never_formatted() {
    let shown = format!("{:?} {:?}", twilio(), standard());
    assert!(!shown.contains("twilio-auth-token"), "{shown}");
    assert!(!shown.contains("MfKQ9r8G"), "{shown}");
}
