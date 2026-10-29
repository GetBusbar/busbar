// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use serde::Deserialize;

use super::{settings, Cred, CredUrl, FormBody, Parts, SealedWrite};

const CANARY: &str = "CANARY-cred-5f3a9c";

#[derive(Deserialize)]
#[allow(dead_code)]
struct Settings {
    dsn: CredUrl,
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

fn split(s: &str) -> CredUrl {
    CredUrl::split(s).expect("splits")
}

fn pw(u: &CredUrl) -> Option<Vec<u8>> {
    u.password().map(|c| c.wire().to_vec())
}

#[test]
fn settings_seal_declared_fields_and_keep_the_rest() {
    let doc = format!(
        r#"{{"dsn":"postgres://app:{CANARY}@db:5432/x?sslmode=require","key":"{CANARY}","port":7,"name":"n","mode":"safe"}}"#
    );
    let s: Settings = settings(doc.as_bytes()).expect("parses");
    assert_eq!(s.dsn.public(), "postgres://app@db:5432/x?sslmode=require");
    assert_eq!(pw(&s.dsn).as_deref(), Some(CANARY.as_bytes()));
    assert_eq!(s.key.wire(), CANARY.as_bytes());
    assert_eq!(
        (s.port, s.name.as_str(), s.mode),
        (7, "n", Some(Mode::Safe))
    );
}

#[test]
fn a_settings_error_never_quotes_a_value() {
    let cases = [
        format!(r#"{{"dsn":"x","key":"k","name":"n","port":"{CANARY}"}}"#),
        format!(r#"{{"dsn":"x","key":"k","name":"n","mode":"{CANARY}"}}"#),
        format!(r#"{{"dsn":"x","key":7,"name":"{CANARY}"}}"#),
        format!(r#"{{"dsn":"x","key":"k","name":"n","mode":{{"{CANARY}":1}}}}"#),
        format!(r#"{{"dsn":"x","key":"k","name":"{CANARY}" "#),
        format!(r#"{{"dsn":"a://u:{CANARY}@h?password={CANARY}","key":"k","name":"n"}}"#),
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
fn url_userinfo_and_query_passwords_are_split_out() {
    let u = split("redis://:p%40ss@cache:6379/0");
    assert_eq!(u.public(), "redis://@cache:6379/0");
    assert_eq!(pw(&u).as_deref(), Some(&b"p@ss"[..]));

    let u = split("mysql://root@h:3306/db?password=pw&ssl-mode=required");
    assert_eq!(u.public(), "mysql://root@h:3306/db?ssl-mode=required");
    assert_eq!(pw(&u).as_deref(), Some(&b"pw"[..]));

    let u = split("mysql://u:12?abc@h/db");
    assert_eq!(u.public(), "mysql://u@h/db");
    assert_eq!(pw(&u).as_deref(), Some(&b"12?abc"[..]));
    assert_eq!(u.password_at(), Some(super::PasswordAt::UserinfoUnencoded));

    let u = split("valkey+unix:///run/v.sock?db=2&pass=s%3Dc+ret");
    assert_eq!(u.public(), "valkey+unix:///run/v.sock?db=2");
    assert_eq!(pw(&u).as_deref(), Some(&b"s=c ret"[..]));
    assert_eq!(u.password_at(), Some(super::PasswordAt::Query("pass")));
    assert_eq!(
        split("redis://:x@h").password_at(),
        Some(super::PasswordAt::Userinfo)
    );

    let u = split("https://h/path?email=a@b.c");
    assert_eq!(u.public(), "https://h/path?email=a@b.c");
    assert!(u.password().is_none());

    assert!(CredUrl::split("a://u:x@h?password=y").is_err());
    let u = split("https://u:123/x@siem.example/p");
    assert_eq!(u.public(), "https://u@siem.example/p");
    assert_eq!(u.password_at(), Some(super::PasswordAt::UserinfoUnencoded));
    assert!(split("redis://:a@h") == split("redis://:a@h"));
    assert!(split("redis://:a@h") != split("redis://:b@h"));
}

#[test]
fn keyword_connection_strings_are_split_out() {
    let u = split(r"host=db port=5432 password='x y' user=app");
    assert_eq!(u.public(), "host=db port=5432 user=app");
    let u2 = split(r"host=db password='a \'b\' c' user=app");
    assert_eq!(pw(&u2).as_deref(), Some(&b"a 'b' c"[..]));
    let u4 = split("host = db port=5433 user=u password = 'se cret' dbname=x");
    assert_eq!(u4.public(), "host = db port=5433 user=u dbname=x");
    assert_eq!(pw(&u4).as_deref(), Some(&b"se cret"[..]));
    let u3 = split("host=db password=plain user=app");
    assert_eq!(u3.public(), "host=db user=app");
    assert_eq!(pw(&u3).as_deref(), Some(&b"plain"[..]));
    let _ = u;
}

#[test]
fn plain_text_passes_through() {
    let u = split("/var/run/sock");
    assert_eq!(u.public(), "/var/run/sock");
    assert!(u.password().is_none());
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
fn take_wipes_the_setting_where_it_was() {
    let mut doc = serde_json::json!({"url": "redis://:pw@h", "key": "k", "n": 1});
    let u = CredUrl::take(&mut doc["url"])
        .expect("string")
        .expect("splits");
    assert_eq!(u.public(), "redis://@h");
    assert!(doc["url"].is_null());
    let k = Cred::take(&mut doc["key"]).expect("string");
    assert_eq!(k.wire(), b"k");
    assert!(doc["key"].is_null());
    assert!(Cred::take(&mut doc["n"]).is_none());
    assert_eq!(doc["n"], 1);
}

#[test]
fn a_userinfo_only_split_leaves_the_query_as_written() {
    let u = CredUrl::parse_userinfo("https://bot:t0k@h/hook?password=part-of-the-target")
        .expect("splits");
    assert_eq!(u.public(), "https://bot@h/hook?password=part-of-the-target");
    assert_eq!(pw(&u).as_deref(), Some(&b"t0k"[..]));
    let doc = br#"{"u": "https://:x@h/p?pass=keep"}"#;
    #[derive(serde::Deserialize)]
    struct S {
        u: super::UserinfoUrl,
    }
    let s: S = settings(doc).expect("parses");
    assert_eq!(s.u.public(), "https://@h/p?pass=keep");
    let c = Cred::captured(zeroize::Zeroizing::new(b"a\x01b".to_vec()));
    assert!(!c.is_field_value());
    assert!(c.is_text());
    let c = Cred::captured(zeroize::Zeroizing::new(vec![0xff]));
    assert!(c.is_field_value() && !c.is_text());
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

/// RED (type level): a form body's public values (an authorization code, a PKCE verifier) travel
/// with its credential, so the body wipes them on drop.
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

/// SECURE_REQUIRED (CHIP-DESIGN v4.1 change 4): the operator's URL decides. A secure scheme or a
/// TLS mode that refuses cleartext requires the password to go out secured; a unix socket, or a
/// mode that allows cleartext, requires nothing.
#[test]
fn the_operators_url_decides_whether_the_password_goes_out_secured() {
    let required = |text: &str| {
        CredUrl::parse(text)
            .expect("parses")
            .password()
            .expect("a password")
            .secure_required()
    };
    for yes in [
        "rediss://:pw@cache:6380",
        "https://u:pw@hook.example/x",
        "ldaps://u:pw@dir.example",
        "postgres://u:pw@db/app?sslmode=require",
        "postgres://u:pw@db/app?sslmode=verify-full",
        "mysql://u:pw@db/app?ssl-mode=REQUIRED",
        "host=db sslmode=verify-ca password=pw",
    ] {
        assert!(required(yes), "{yes}");
    }
    for no in [
        "redis://:pw@cache:6379",
        "http://u:pw@hook.example/x",
        "postgres://u:pw@db/app",
        "postgres://u:pw@db/app?sslmode=prefer",
        "postgres://u:pw@%2Fvar%2Frun%2Fpostgresql/app?sslmode=require",
        "postgres://u:pw@/app?host=/tmp&sslmode=require",
        "host=/tmp sslmode=require password=pw",
        "mysql://u:pw@db/app?ssl-mode=PREFERRED",
    ] {
        assert!(!required(no), "{no}");
    }
}

/// The requirement travels with everything the credential makes, and is never relaxed.
#[test]
fn the_requirement_travels_with_every_seal() {
    let c = Cred::captured(zeroize::Zeroizing::new(b"pw".to_vec()));
    assert!(!c.secure_required() && !c.bearer().secure_required());
    let c = c.secure_for("http://x").secure_for("ldaps://dir");
    assert!(c.secure_required());
    let c = c.secure_for("http://x");
    assert!(c.secure_required(), "never relaxed");
    for s in [c.field(), c.bearer(), c.basic("u"), c.resp_auth(None)] {
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
