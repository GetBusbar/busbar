// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use serde::Deserialize;

use super::{settings, Cred, CredUrl, Parts, SealedWrite};

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
