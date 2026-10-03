//! Both variants against their published test vectors, and their REDs.

use super::*;

fn owned(params: &[(&str, &str)]) -> Vec<(Vec<u8>, Vec<u8>)> {
    params
        .iter()
        .map(|(n, v)| (n.as_bytes().to_vec(), v.as_bytes().to_vec()))
        .collect()
}

// ── twilio ──────────────────────────────────────────────────────────────────────────────────────

/// Twilio's published request-validation example (its docs and every official helper library's
/// tests): auth token `12345`, this URL, these POST parameters.
const TOKEN: &[u8] = b"12345";
const URL: &[u8] = b"https://mycompany.com/myapp.php?foo=1&bar=2";
const PARAMS: &[(&str, &str)] = &[
    ("CallSid", "CA1234567890ABCDE"),
    ("Caller", "+12349013030"),
    ("Digits", "1234"),
    ("From", "+12349013030"),
    ("To", "+18005551212"),
];
/// The signature Twilio publishes for it.
const PUBLISHED: &[u8] = b"0/KCTR6DLpKmkAf8muzZqo1nDgQ=";

#[test]
fn twilios_published_test_vector_signs_and_verifies() {
    assert_eq!(
        twilio_sign(TOKEN, URL, &owned(PARAMS)).as_bytes(),
        PUBLISHED
    );
    assert!(twilio_verify(TOKEN, URL, &owned(PARAMS), PUBLISHED));
}

#[test]
fn the_published_vector_verifies_from_its_form_body_in_any_order() {
    // The same parameters as the form body Twilio POSTs, percent-encoded, in another order.
    let body = b"To=%2B18005551212&From=%2B12349013030&Digits=1234&Caller=%2B12349013030&CallSid=CA1234567890ABCDE";
    let params = form_params(body).expect("a form body");
    assert!(twilio_verify(TOKEN, URL, &params, PUBLISHED));
}

/// A repeated identical pair is signed once, and a name's distinct values are signed sorted — the
/// reference validators' `sorted(set(names))`, then `sorted(set(values))` under each.
#[test]
fn a_repeated_pair_is_signed_once_and_a_names_values_sorted() {
    let once = owned(&[("Digits", "1"), ("To", "+1")]);
    let twice = owned(&[("Digits", "1"), ("To", "+1"), ("Digits", "1")]);
    assert_eq!(
        twilio_signed_string(URL, &once),
        twilio_signed_string(URL, &twice)
    );
    let multi = owned(&[("A", "z"), ("A", "b"), ("A", "b")]);
    assert_eq!(
        twilio_signed_string(b"u", &multi),
        b"uAbAz".to_vec(),
        "distinct values, sorted"
    );
}

#[test]
fn a_form_body_decodes_plus_and_percent_escapes() {
    assert_eq!(
        form_params(b"a=x+y&b=%41%2b&c&=v").expect("form"),
        owned(&[("a", "x y"), ("b", "A+"), ("c", ""), ("", "v")])
    );
    assert_eq!(form_params(b"").expect("empty form"), Vec::new());
    assert_eq!(form_params(b"a=%4"), None, "a truncated escape");
    assert_eq!(form_params(b"a=%zz"), None, "a non-hex escape");
}

#[test]
fn a_json_body_is_bound_by_the_body_sha256_its_url_carries() {
    // Twilio's published JSON example body and the bodySHA256 its docs show for it.
    let body = br#"{"property": "value", "boolean": true}"#;
    let hash = b"0a1ff7634d9ab3b95db5c9a2dfe9416e41502b283a80c7cf19632632f96e6620";
    assert!(body_sha256_matches(body, hash));
    assert!(body_sha256_matches(body, &hash.to_ascii_uppercase()));
    assert!(!body_sha256_matches(br#"{"property": "other"}"#, hash));
    assert!(!body_sha256_matches(body, &hash[..63]));
    assert_eq!(
        query_param(b"x=1&bodySHA256=abc&y=2", b"bodySHA256"),
        Some(&b"abc"[..])
    );
    assert_eq!(query_param(b"x=1", b"bodySHA256"), None);
}

#[test]
fn red_a_bad_twilio_signature_is_refused() {
    let params = owned(PARAMS);
    // One changed character of the published signature.
    assert!(!twilio_verify(
        TOKEN,
        URL,
        &params,
        b"1/KCTR6DLpKmkAf8muzZqo1nDgQ="
    ));
    // The right signature under the wrong token.
    assert!(!twilio_verify(b"54321", URL, &params, PUBLISHED));
    // Not base64 at all, and empty.
    assert!(!twilio_verify(TOKEN, URL, &params, b"not base64!"));
    assert!(!twilio_verify(TOKEN, URL, &params, b""));
}

#[test]
fn red_a_twilio_signature_replayed_on_another_url_is_refused() {
    let params = owned(PARAMS);
    for other in [
        &b"https://mycompany.com/other.php?foo=1&bar=2"[..],
        b"https://mycompany.com/myapp.php?foo=1&bar=3",
        b"wss://mycompany.com/myapp.php?foo=1&bar=2",
        b"https://evil.example/myapp.php?foo=1&bar=2",
    ] {
        assert!(
            !twilio_verify(TOKEN, other, &params, PUBLISHED),
            "{other:?}"
        );
    }
    // And with a parameter changed or dropped.
    let mut tampered = params.clone();
    tampered[2].1 = b"9999".to_vec();
    assert!(!twilio_verify(TOKEN, URL, &tampered, PUBLISHED));
    assert!(!twilio_verify(TOKEN, URL, &params[1..], PUBLISHED));
}

// ── standard-webhooks ───────────────────────────────────────────────────────────────────────────

/// The Standard Webhooks specification's published test vector (its reference libraries' tests).
const SW_SECRET: &[u8] = b"whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
const SW_ID: &[u8] = b"msg_p5jXN8AQM9LWM0D4loKWxJek";
const SW_TS: &[u8] = b"1614265330";
const SW_NOW: u64 = 1_614_265_330;
const SW_BODY: &[u8] = br#"{"test": 2432232314}"#;
const SW_PUBLISHED: &[u8] = b"v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=";
const FIVE_MIN: u64 = 300;

fn sw_key() -> Vec<u8> {
    standard_webhooks_key(SW_SECRET).expect("a whsec_ secret")
}

#[test]
fn the_standard_webhooks_published_vector_signs_and_verifies() {
    assert_eq!(
        standard_webhooks_sign(&sw_key(), SW_ID, SW_TS, SW_BODY).as_bytes(),
        SW_PUBLISHED
    );
    assert_eq!(
        standard_webhooks_verify(
            &sw_key(),
            SW_ID,
            SW_TS,
            SW_BODY,
            SW_PUBLISHED,
            SW_NOW,
            FIVE_MIN
        ),
        Ok(())
    );
    // The same secret without its `whsec_` prefix is the same key.
    assert_eq!(
        standard_webhooks_key(&SW_SECRET[6..]).expect("bare base64"),
        sw_key()
    );
}

#[test]
fn any_one_v1_entry_of_the_signature_list_may_match() {
    let list = [
        &b"v1,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc= "[..],
        b"v2,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE= ",
        SW_PUBLISHED,
    ]
    .concat();
    assert_eq!(
        standard_webhooks_verify(&sw_key(), SW_ID, SW_TS, SW_BODY, &list, SW_NOW, FIVE_MIN),
        Ok(())
    );
    // The right bytes under a version other than v1 are not judged.
    assert_eq!(
        standard_webhooks_verify(
            &sw_key(),
            SW_ID,
            SW_TS,
            SW_BODY,
            b"v2,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=",
            SW_NOW,
            FIVE_MIN
        ),
        Err(StandardWebhooksRefusal::BadSignature)
    );
}

#[test]
fn red_a_bad_standard_webhooks_signature_is_refused() {
    let bad = |sig: &[u8], id: &[u8], body: &[u8]| {
        standard_webhooks_verify(&sw_key(), id, SW_TS, body, sig, SW_NOW, FIVE_MIN)
    };
    let refused = Err(StandardWebhooksRefusal::BadSignature);
    assert_eq!(
        bad(
            b"v1,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc=",
            SW_ID,
            SW_BODY
        ),
        refused
    );
    assert_eq!(
        bad(SW_PUBLISHED, b"msg_other", SW_BODY),
        refused,
        "another id"
    );
    assert_eq!(
        bad(SW_PUBLISHED, SW_ID, br#"{"test": 1}"#),
        refused,
        "another body"
    );
    assert_eq!(bad(b"", SW_ID, SW_BODY), refused, "no entries");
    assert_eq!(bad(b"v1,%%%", SW_ID, SW_BODY), refused, "not base64");
    let other_key = standard_webhooks_key(b"whsec_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").expect("key");
    assert_eq!(
        standard_webhooks_verify(
            &other_key,
            SW_ID,
            SW_TS,
            SW_BODY,
            SW_PUBLISHED,
            SW_NOW,
            FIVE_MIN
        ),
        refused
    );
}

#[test]
fn red_a_stale_or_future_timestamp_is_refused_even_with_a_valid_signature() {
    let at = |now: u64| {
        standard_webhooks_verify(
            &sw_key(),
            SW_ID,
            SW_TS,
            SW_BODY,
            SW_PUBLISHED,
            now,
            FIVE_MIN,
        )
    };
    assert_eq!(at(SW_NOW + FIVE_MIN), Ok(()), "at the edge");
    assert_eq!(at(SW_NOW - FIVE_MIN), Ok(()), "at the other edge");
    assert_eq!(
        at(SW_NOW + FIVE_MIN + 1),
        Err(StandardWebhooksRefusal::Stale)
    );
    assert_eq!(
        at(SW_NOW - FIVE_MIN - 1),
        Err(StandardWebhooksRefusal::Stale)
    );
    for ts in [&b"not-a-number"[..], b"", b"-1", b"1614265330.5"] {
        assert_eq!(
            standard_webhooks_verify(
                &sw_key(),
                SW_ID,
                ts,
                SW_BODY,
                SW_PUBLISHED,
                SW_NOW,
                FIVE_MIN
            ),
            Err(StandardWebhooksRefusal::BadTimestamp),
            "{ts:?}"
        );
    }
}

#[test]
fn a_secret_that_is_not_base64_has_no_key() {
    assert_eq!(standard_webhooks_key(b"whsec_%%%"), None);
    assert_eq!(standard_webhooks_key(b"whsec_"), None);
}
