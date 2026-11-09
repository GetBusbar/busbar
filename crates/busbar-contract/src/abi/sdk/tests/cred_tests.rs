// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use super::{settings, Cred, FormBody, Parts, SealedWrite};
use serde::Deserialize;

const CANARY: &str = "CANARY-cred-5f3a9c";

#[derive(Deserialize)]
#[allow(dead_code)]
struct Settings {
    dsn: Cred,
    key: Cred,
    #[serde(default)]
    port: u16,
    name: String,
    mode: Option<Mode>,
}

#[derive(Deserialize, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Mode {
    Fast,
    Safe,
}

#[test]
fn settings_capture_credential_fields_without_interpreting_their_contents() {
    let doc =
        format!(r#"{{"dsn":"opaque-secret","key":"{CANARY}","port":7,"name":"n","mode":"safe"}}"#);
    let settings: Settings = super::settings(doc.as_bytes()).expect("parses");
    assert!(settings.dsn.verify_eq(b"opaque-secret"));
    assert_eq!(settings.key.wire(), CANARY.as_bytes());
    assert_eq!(
        (settings.port, settings.name.as_str(), settings.mode),
        (7, "n", Some(Mode::Safe))
    );
}

#[test]
fn take_wipes_the_credential_setting_where_it_was() {
    let mut doc = serde_json::json!({"key":"k","n":1});
    let key = Cred::take(&mut doc["key"]).expect("string");
    assert_eq!(key.wire(), b"k");
    assert!(doc["key"].is_null());
    assert!(Cred::take(&mut doc["n"]).is_none());
    assert_eq!(doc["n"], 1);
}

#[test]
fn captured_and_rejected_owned_settings_buffers_wipe_before_free() {
    use crate::alloc_counter::InitializedPayloadProbe;
    // This probe covers the shared SDK's settings buffers. Native parsing and its scratch
    // allocations are owned by each plugin and are not exercised by this custody test.
    // SAFETY: instrumented allocations are created and destroyed on this thread.
    let probe = unsafe { InitializedPayloadProbe::start().expect("open memory observer") };
    let credential: Cred = settings(br#""configured credential""#).unwrap();
    // SAFETY: the initialized credential allocation stays live on this thread until drop.
    unsafe {
        crate::alloc_counter::watch_initialized_payload(credential.wire());
    }
    drop(credential);
    assert!(super::settings_lent::<u16>(br#"{"$secret":0}"#, &[b"wrong type secret"]).is_err());
    let observations = probe.finish();
    assert!(!observations.reentered);
    assert!(!observations.payloads.is_empty());
    for record in observations.payloads {
        assert!(record.freed, "owned capture payload freed: {record:?}");
        #[cfg(target_os = "linux")]
        {
            assert_eq!(record.read_error, None);
            assert!(record.complete_read);
            assert_eq!(record.bytes_read, record.len);
            assert!(record.wiped, "capture payload wiped: {record:?}");
        }
    }
}

#[test]
fn a_settings_error_never_quotes_a_value() {
    let cases = [
        format!(r#"{{"dsn":"x","key":"k","name":"n","port":"{CANARY}"}}"#),
        format!(r#"{{"dsn":"x","key":"k","name":"n","mode":"{CANARY}"}}"#),
        format!(r#"{{"dsn":"x","key":7,"name":"{CANARY}"}}"#),
        format!(r#"{{"dsn":"x","key":"k","name":"n","mode":{{"{CANARY}":1}}}}"#),
        format!(r#"{{"dsn":"x","key":"k","name":"{CANARY}" "#),
        format!(r#"{{"key":"{CANARY}","name":"n"}}"#),
    ];
    for doc in cases {
        let Err(e) = settings::<Settings>(doc.as_bytes()) else {
            panic!("expected an error for {doc}");
        };
        let text = format!("{e} {e:?}");
        assert!(!text.contains("CANARY"), "the error quotes a value: {text}");
    }
}

#[test]
fn a_settings_error_names_the_path() {
    let e = settings::<Settings>(br#"{"dsn":"x","key":"k","name":"n","port":"high"}"#)
        .err()
        .expect("error");
    assert_eq!(e.path(), "port");
    assert_eq!(
        e.to_string(),
        "settings: invalid type: string \"***\", expected u16"
    );
    let e = settings::<Settings>(br#"{"dsn":"x","name":"n"}"#)
        .err()
        .expect("error");
    assert!(e.to_string().contains("missing field `key`"), "{e}");
}

#[test]
fn a_sealed_write_assembles_in_order() {
    let c = Cred::captured(zeroize::Zeroizing::new(b"k".to_vec()));
    let w = Parts::new()
        .public(b"authorization: ")
        .sealed(c.bearer())
        .public(b"\r\n");
    assert_eq!(w.len(), 15 + 8 + 2);
    let s = SealedWrite::new(w);
    assert_eq!(&s.buf[..], b"authorization: Bearer k\r\n");
    assert!(!s.finished());
}

#[test]
fn a_form_body_encodes_as_serde_urlencoded_and_seals_its_credential() {
    let secret = Cred::captured(zeroize::Zeroizing::new(b"s&=e cr+t".to_vec()));
    let body = super::FormBody::new()
        .public("grant_type", "client_credentials")
        .public("client_id", "a b")
        .sealed("client_secret", &secret);
    assert_eq!(
        body.names().collect::<Vec<_>>(),
        ["grant_type", "client_id", "client_secret"]
    );
    assert!(!format!("{body:?}").contains("s&=e"));
    let w = body.encoded().expect("encodes");
    assert_eq!(
        &w.buf[..],
        b"grant_type=client_credentials&client_id=a+b&client_secret=s%26%3De+cr%2Bt"
    );
}

/// A form body wipes on drop.
#[test]
fn a_form_body_wipes_on_drop() {
    fn wipes<T: zeroize::ZeroizeOnDrop>(_: &T) {}
    wipes(&super::FormBody::new().public("code", "the-code"));
}

/// A throwaway 2048-bit PKCS #8 test key (generated for this test only).
const JWS_TEST_KEY_B64: &str = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCmblkCTFF4bAqCCbUGsRyBcOTAYRpV7rS3+nX3zHUTqjhzG8tag6piB/n64+NB5DrFhqDLZY7rN47b79UXrRVWzMWm+QtbPrHFas6hqUIBRMKg6AOAydBMdHRdVoIkwVUM/tMU+pbibdYyWKIkZLcbymNgJML5mVesMD5HKT8NB4StRf6Rrw5DFO1aFRv4mAQzTzog/q5d/GSqjiHd1oMsPPgZwiLdqVl8uoZtIDmJZYqdrTd/jTxpVqDCNn64gS/u+4YzV3eGaP84Lob7z2QTYe3fF/r/kqG5JU+/ovCIVnd0nYJl5IdzN2utYJpXYbAGYiznx9MewgZZiD4Q5YktAgMBAAECggEATt01QliFtomDxTDyXhRpDJFBZEPfJd8yNYfyhJSW2dWsYCdIikCf6UocU53PH3cVvmnYIemi+qTeBiw0jr6OwQ3RjxiuH/Oqa4D8HzDEPTOnAnZOyqVXFhOM3HnUu7P9KGZMAcHo46zmdf73/kTXW8zgoDtrRLk8CTTnHfNWlEY7HVryRtZL4KFAuRpYaY36m3LVeOAUm6tl5OZK6pGuF4z6bW84XtLpajjRGkEfkTZiu+UmOddilono+wmwjWnHSiBW3sLkwKMOR7r/oHGRk/B6irSqDzaERrVWR5Oyc1kcNyXTISbxhDWeWYSJIV19qnx4fL11IVeaWIsv89NnxQKBgQDRUkXEHAJIYZZwyav+fM7qkhr6Tz3f1sAHqZf/BGJV47HNIogxxEKGyS/Cjs1pZFtRiy5UC3SaX1zNbzWNyuyAx93pGp0tPMOt6RB/uzPKN0xN0dlq85Mvsjmv2lcSi3Oyx1Kune4SLB/GacrTy5V5HqXk+EcpuJiaBRFNg4wiqwKBgQDLi43i+2lm1afKooEfwnHw3uC8VKVrBhX18RuYiK3/yTLKREwSGwgSLLoYpLVOoRZsdaP1TxHlAETtW4FgladO/m3a9nhMFq+4tVExQd4RU+LKzPoR4+naEMyayRRKJk3x36J4H1vrzPTaiDAamNVuLXtp4Vt36DiC3+Gp0sXDhwKBgH/aft6gNQy8/sT5ieKxnTlN8Mh/ak20wCpt/nc32FCZ+VpRA1tSg0gMzu1JiFIdiGGwX6XaMWixYt/gU5e+IOMwMW1WYjblbKhnOTqrv6B+Uk8eJGzdRkPV2sJ83L5pC0xhzzD1KhtTdD0fFVJ0gWIvxCitNdpX9G3vNnhgJ1JtAoGASg7TqCN7fRv9ud+YhZq05EPjlwJhUWhccyivtrb8QBXPcgKZfvjw3dQCPdcn1J0N0JaY+jcztpN7gLULhL3OqxItnD6TFHQoqVbnXLmvd7SCzvD3h6zaOCpml2bUCAqZz4hjz7rxMgFXkW99uR+kgDryLVr+cck/Tnbw31498F8CgYAtm3jGRbHyAO2SKcyo/L9JFGNr8Cznqy51lKG8+0Rmr3k4dyLeNs4jDySbDriMIyZcztVokQZ/JJKm+khxiDrXEP6uzX+D8eVhTA3lqujwB+vvFIGPJ6QiPWmItRuXgwdIlNr8JAl7YiezC03NQ68WWsBLmjbuhKDvgu5W0Wyrjw==";

#[test]
fn a_jws_assertion_verifies_under_the_keys_public_half() {
    use base64::Engine as _;
    let der = base64::engine::general_purpose::STANDARD
        .decode(JWS_TEST_KEY_B64)
        .expect("b64");
    let key = Cred::captured(zeroize::Zeroizing::new(der.clone()));
    key.rsa_pkcs8_check().expect("a PKCS #8 RSA key");
    let input = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ4In0";
    let sig = key.jws_rs256(input.as_bytes()).expect("signs");
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(sig.wire())
        .expect("b64url");
    let pair = ring::signature::RsaKeyPair::from_pkcs8(&der).expect("key");
    let mut expected = zeroize::Zeroizing::new(vec![0; pair.public().modulus_len()]);
    pair.sign(
        &ring::signature::RSA_PKCS1_SHA256,
        &ring::rand::SystemRandom::new(),
        input.as_bytes(),
        &mut expected,
    )
    .expect("reference signature");
    assert_eq!(raw.as_slice(), expected.as_slice());
    use ring::signature::KeyPair as _;
    ring::signature::UnparsedPublicKey::new(
        &ring::signature::RSA_PKCS1_2048_8192_SHA256,
        pair.public_key().as_ref(),
    )
    .verify(input.as_bytes(), &raw)
    .expect("verifies");
    let body = super::FormBody::new().value(
        "assertion",
        super::FormValue::JwsRs256 {
            key: key.clone(),
            signing_input: input.to_owned(),
        },
    );
    let w = body.encoded().expect("encodes");
    assert!(w.buf.starts_with(format!("assertion={input}.").as_bytes()));
    assert!(Cred::captured(zeroize::Zeroizing::new(b"nope".to_vec()))
        .rsa_pkcs8_check()
        .is_err());
}

#[test]
fn jws_requires_a_complete_pkcs8_rsa_key_on_validation_and_signing() {
    use base64::Engine as _;
    let der = base64::engine::general_purpose::STANDARD
        .decode(JWS_TEST_KEY_B64)
        .expect("fixture");
    let refuses = |bytes: Vec<u8>| {
        let key = Cred::captured(zeroize::Zeroizing::new(bytes));
        assert!(key.rsa_pkcs8_check().is_err());
        assert!(key.jws_rs256(b"header.payload").is_err());
    };
    refuses(Vec::new());
    assert_eq!(&der[22..26], &[4, 0x82, 4, 0xa6]);
    refuses(der[26..].to_vec());
    refuses(der[..der.len() - 1].to_vec());
    let mut trailing = der.clone();
    trailing.push(0);
    refuses(trailing);
    let mut concatenated = der.clone();
    concatenated.extend_from_slice(&der);
    refuses(concatenated);
    let mut v2 = der.clone();
    assert_eq!(&v2[4..7], &[2, 1, 0]);
    v2[6] = 1;
    refuses(v2);
    let mut bad_crt = der.clone();
    *bad_crt.last_mut().expect("fixture") ^= 1;
    refuses(bad_crt);
    let mut indefinite = vec![0x30, 0x80];
    indefinite.extend_from_slice(&der[4..]);
    indefinite.extend_from_slice(&[0, 0]);
    refuses(indefinite);
    let mut nonminimal = vec![0x30, 0x83, 0];
    nonminimal.extend_from_slice(&der[2..]);
    refuses(nonminimal);
}

#[test]
fn jws_rejects_an_inconsistent_private_exponent_before_signing() {
    use base64::Engine as _;

    const PRIVATE_EXPONENT_HEADER: usize = 299;
    const PRIVATE_EXPONENT_END: usize = PRIVATE_EXPONENT_HEADER + 4 + 256;
    let mut der = base64::engine::general_purpose::STANDARD
        .decode(JWS_TEST_KEY_B64)
        .expect("fixture");
    assert_eq!(
        &der[PRIVATE_EXPONENT_HEADER..PRIVATE_EXPONENT_HEADER + 4],
        &[0x02, 0x82, 0x01, 0x00]
    );
    der[PRIVATE_EXPONENT_END - 1] ^= 2;
    let key = Cred::captured(zeroize::Zeroizing::new(der));
    assert!(key.rsa_pkcs8_check().is_err());
    assert!(key.jws_rs256(b"header.payload").is_err());
    let body = super::FormBody::new().value(
        "assertion",
        super::FormValue::JwsRs256 {
            key,
            signing_input: "header.payload".to_owned(),
        },
    );
    assert!(body.encoded().is_err());
}

#[test]
fn jws_preserves_pkcs8_algorithm_and_optional_attribute_rules() {
    use base64::Engine as _;
    fn sequence(content: &[u8]) -> Vec<u8> {
        let mut out = vec![0x30, 0x82];
        out.extend_from_slice(
            &u16::try_from(content.len())
                .expect("fixture length")
                .to_be_bytes(),
        );
        out.extend_from_slice(content);
        out
    }
    let der = base64::engine::general_purpose::STANDARD
        .decode(JWS_TEST_KEY_B64)
        .expect("fixture");
    let mut content = der[4..].to_vec();
    content.extend_from_slice(&[0xa0, 0]);
    let attributed = Cred::captured(zeroize::Zeroizing::new(sequence(&content)));
    attributed.rsa_pkcs8_check().expect("optional attributes");
    let original = Cred::captured(zeroize::Zeroizing::new(der.clone()));
    assert_eq!(
        attributed
            .jws_rs256(b"header.payload")
            .expect("signs")
            .wire(),
        original.jws_rs256(b"header.payload").expect("signs").wire()
    );
    content.extend_from_slice(&[0xa0, 0]);
    let duplicate = Cred::captured(zeroize::Zeroizing::new(sequence(&content)));
    assert!(duplicate.rsa_pkcs8_check().is_err());
    assert!(duplicate.jws_rs256(b"header.payload").is_err());
    let mut missing_null = der[4..].to_vec();
    assert_eq!(&missing_null[3..5], &[0x30, 13]);
    assert_eq!(&missing_null[16..18], &[5, 0]);
    missing_null.drain(16..18);
    missing_null[4] = 11;
    let key = Cred::captured(zeroize::Zeroizing::new(sequence(&missing_null)));
    assert!(key.rsa_pkcs8_check().is_err());
    assert!(key.jws_rs256(b"header.payload").is_err());
    let mut inner_trailing = der[4..].to_vec();
    let private_len = u16::from_be_bytes([inner_trailing[20], inner_trailing[21]]);
    inner_trailing[20..22].copy_from_slice(&(private_len + 1).to_be_bytes());
    inner_trailing.push(0);
    let key = Cred::captured(zeroize::Zeroizing::new(sequence(&inner_trailing)));
    assert!(key.rsa_pkcs8_check().is_err());
    assert!(key.jws_rs256(b"header.payload").is_err());
}

/// SECURE_REQUIRED (CHIP-DESIGN v4.1 change 4): the operator's URL decides. A secure scheme or a
#[test]
fn the_requirement_travels_with_every_seal() {
    let c = Cred::captured(zeroize::Zeroizing::new(b"pw".to_vec()));
    assert!(!c.secure_required() && !c.bearer().secure_required());
    let c = c.require_secure_if(false).require_secure_if(true);
    assert!(c.secure_required());
    let c = c.require_secure_if(false);
    assert!(c.secure_required(), "never relaxed");
    for s in [c.field(), c.bearer(), c.basic("u")] {
        assert!(s.secure_required());
    }
    assert!(!Parts::new().public(b"a").sealed(c.field()).is_empty());
    assert!(SealedWrite::new(Parts::new().sealed(c.field())).secure_required());
    assert!(!SealedWrite::new(Parts::new().public(b"a")).secure_required());
    let body = FormBody::new()
        .sealed("client_secret", &c)
        .encoded()
        .expect("encodes");
    assert!(body.secure_required());
    assert!(!FormBody::new()
        .public("a", "b")
        .encoded()
        .expect("encodes")
        .secure_required());
}

#[test]
fn header_field_values_reject_del_between_allowed_bytes() {
    for (byte, accepted) in [(0x7e, true), (0x7f, false), (0x80, true)] {
        let credential = Cred::captured(zeroize::Zeroizing::new(vec![byte]));
        assert_eq!(
            credential.is_field_value(),
            accepted,
            "header byte {byte:#04x}"
        );
    }
}

#[test]
fn header_field_values_allow_tab_but_reject_neighboring_controls() {
    for (byte, accepted) in [(0x08, false), (0x09, true), (0x0a, false)] {
        let credential = Cred::captured(zeroize::Zeroizing::new(vec![byte]));
        assert_eq!(
            credential.is_field_value(),
            accepted,
            "header byte {byte:#04x}"
        );
    }
}

#[test]
fn header_field_values_allow_space_at_the_visible_byte_boundary() {
    for (byte, accepted) in [(0x1f, false), (0x20, true), (0x21, true)] {
        let credential = Cred::captured(zeroize::Zeroizing::new(vec![byte]));
        assert_eq!(
            credential.is_field_value(),
            accepted,
            "header byte {byte:#04x}"
        );
    }
}
