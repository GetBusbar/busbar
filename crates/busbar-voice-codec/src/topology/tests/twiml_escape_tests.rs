// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TwiML THE WEBHOOK HANDS TWILIO, and the escape that is the only thing standing between a
//! caller-influenced URL and the markup around it.
//!
//! `render_connect_stream` interpolates exactly one variable into an XML document, and
//! `xml_escape` is what makes that safe. Mutation deleted its `&` arm and its `'` arm
//! independently, and the whole suite stayed green — which means nothing in this crate ever
//! rendered a URL containing an ampersand or an apostrophe.
//!
//! The ampersand is the one that matters most and it is not an exotic input: `stream_url` is built
//! from an operator-configured `ws_base`, and a base carrying a query string (`wss://h/?x=1&y=2`)
//! is ordinary. Unescaped, the `&` starts an XML entity reference that never terminates, and
//! Twilio's parser rejects the whole document — every inbound call fails to connect, with the
//! failure at the far end of a webhook rather than in any busbar log. The apostrophe arm is the
//! same class one attribute-quoting convention over.
//!
//! `assert_g711_ulaw`'s conjunction is here for the same reason: mutation turned its three-way
//! `&&` into `||`, so a stream matching on ANY ONE of encoding, rate or channel count would be
//! admitted. The function's own header says what that costs — the 8-bytes-per-millisecond barge-in
//! arithmetic is silently wrong, which is the failure mode the refusal exists to prevent.

use super::*;

/// Every character `xml_escape` names, checked one at a time so a deleted arm is a named failure
/// rather than a diff in a long string. The five are XML's own predefined entities.
#[test]
fn every_xml_metacharacter_is_escaped_in_the_rendered_document() {
    for (raw, entity, name) in [
        ('&', "&amp;", "ampersand"),
        ('<', "&lt;", "less-than"),
        ('>', "&gt;", "greater-than"),
        ('"', "&quot;", "quotation mark"),
        ('\'', "&apos;", "apostrophe"),
    ] {
        let url = format!("wss://h/a{raw}b");
        let doc = render_connect_stream(&url);
        assert!(
            doc.contains(&format!("a{entity}b")),
            "the {name} was not escaped: `{doc}`"
        );
        assert!(
            !doc.contains(&format!("a{raw}b")),
            "the {name} reached the document raw: `{doc}`"
        );
    }
}

/// THE ORDINARY INPUT that the deleted `&` arm breaks. A websocket base with a query string is a
/// normal operator configuration, not an attack — and an unescaped `&` in it makes Twilio's parser
/// reject the TwiML, so every inbound call fails to connect.
#[test]
fn a_websocket_base_carrying_a_query_string_renders_parseable_twiml() {
    let doc = render_twiml_for_call("wss://voice.example/?region=eu&v=2", "call-1");
    assert!(
        doc.contains("&amp;"),
        "the query separator was not escaped: `{doc}`"
    );
    // The one thing that makes this document invalid: a bare `&` that is not the start of one of
    // the entities the escape writes.
    for (i, _) in doc.match_indices('&') {
        let tail = &doc[i..];
        assert!(
            ["&amp;", "&lt;", "&gt;", "&quot;", "&apos;"]
                .iter()
                .any(|e| tail.starts_with(e)),
            "a bare ampersand at byte {i} begins an entity reference that never terminates: `{doc}`"
        );
    }
}

/// The escape must not let a value close the attribute it sits in. This is the property the
/// document's structure depends on: one `url="…"` attribute, with the value inside it.
#[test]
fn an_interpolated_value_cannot_close_the_attribute_or_the_element() {
    let doc = render_connect_stream("wss://h/\"/><Say>owned</Say><Stream url=\"x");
    assert!(
        !doc.contains("<Say>"),
        "an interpolated value introduced an element: `{doc}`"
    );
    assert_eq!(
        doc.matches("<Stream").count(),
        1,
        "an interpolated value introduced a second Stream element: `{doc}`"
    );
    assert_eq!(
        doc.matches("/>").count(),
        1,
        "an interpolated value closed the element early: `{doc}`"
    );
}

/// A URL with nothing to escape passes through unchanged — the escape must not mangle the ordinary
/// case while it is protecting the unusual one.
#[test]
fn a_plain_url_survives_the_escape_untouched() {
    let doc = render_twiml_for_call("wss://voice.example", "call-1");
    assert!(doc.contains("url=\"wss://voice.example/twilio/call-1\""));
    assert!(!doc.contains("&amp;"));
}

/// THE MEDIA-FORMAT REFUSAL IS A CONJUNCTION, NOT A DISJUNCTION. Mutation replaced `&&` with `||`;
/// under that mutant a format matching on any single field is admitted, and the barge-in
/// arithmetic — which assumes 8 bytes per millisecond — reads a stream that is not that.
///
/// Checked by holding two of the three fields correct and moving the third, once per field, so
/// every conjunct is load-bearing on its own.
#[test]
fn a_media_format_wrong_in_any_single_field_is_refused() {
    let good = MediaFormat {
        encoding: TWILIO_MULAW_ENCODING.to_string(),
        sample_rate: TWILIO_SAMPLE_RATE,
        channels: TWILIO_CHANNELS,
    };
    assert!(
        assert_g711_ulaw(&good).is_ok(),
        "the locked carrier was refused"
    );

    let wrong_encoding = MediaFormat {
        encoding: "audio/x-alaw".to_string(),
        ..good.clone()
    };
    assert!(
        assert_g711_ulaw(&wrong_encoding).is_err(),
        "a non-mulaw encoding was admitted because the rate and channels happened to match"
    );

    let wrong_rate = MediaFormat {
        sample_rate: 16_000,
        ..good.clone()
    };
    assert!(
        assert_g711_ulaw(&wrong_rate).is_err(),
        "a 16 kHz stream was admitted; the 8-bytes-per-ms barge-in arithmetic is now wrong"
    );

    let wrong_channels = MediaFormat {
        channels: 2,
        ..good.clone()
    };
    assert!(
        assert_g711_ulaw(&wrong_channels).is_err(),
        "a stereo stream was admitted because the encoding and rate happened to match"
    );
}

/// The refusal REPORTS what actually arrived. A format mismatch an operator cannot read is a
/// support ticket rather than a diagnosis, and mutation could replace the whole `Display` with an
/// empty string without a test noticing.
#[test]
fn the_format_refusal_names_the_format_that_actually_arrived() {
    let err = assert_g711_ulaw(&MediaFormat {
        encoding: "audio/x-alaw".to_string(),
        sample_rate: 16_000,
        channels: 2,
    })
    .expect_err("refused");
    let rendered = err.to_string();
    assert!(!rendered.is_empty(), "the refusal rendered to nothing");
    assert!(
        rendered.contains("audio/x-alaw"),
        "`{rendered}` does not name the encoding that arrived"
    );
    assert!(
        rendered.contains("16000"),
        "`{rendered}` does not name the sample rate that arrived"
    );
}

/// Every other `TwilioError` renders a non-empty, distinguishable message. Mutation replaced the
/// whole `Display` implementation with `Ok(())` — an empty string for EVERY variant — and nothing
/// objected; an operator reading the log would see a refusal with no reason at all.
#[test]
fn every_twilio_refusal_renders_a_distinct_non_empty_reason() {
    let rendered: Vec<String> = vec![
        TwilioError::Malformed.to_string(),
        TwilioError::UnknownEvent("nonsense".to_string()).to_string(),
        TwilioError::BadPayload.to_string(),
        TwilioError::Forged {
            expected: "MZ-good".to_string(),
            actual: "MZ-forged".to_string(),
        }
        .to_string(),
    ];
    for r in &rendered {
        assert!(!r.is_empty(), "a refusal rendered to nothing at all");
    }
    for (i, r) in rendered.iter().enumerate() {
        for other in &rendered[i + 1..] {
            assert_ne!(r, other, "two different refusals render identically: `{r}`");
        }
    }
    // The forged-connection refusal is the security-relevant one, so it must name BOTH sides:
    // which streamSid was bound and which one actually presented itself.
    let forged = &rendered[3];
    assert!(
        forged.contains("MZ-good") && forged.contains("MZ-forged"),
        "`{forged}` does not name both the bound and the presented streamSid"
    );
}
