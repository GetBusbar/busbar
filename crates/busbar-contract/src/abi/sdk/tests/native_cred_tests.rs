// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::abi::sdk::cred::{settings, settings_lent, PgAuth, PostgresUrl, ValkeyUrl};

fn password(url: &CredUrl) -> Option<&[u8]> {
    url.password().map(Cred::wire)
}

#[test]
fn postgres_capture_preserves_last_wins_and_native_decoding() {
    let p = CredUrl::parse_postgres(
        "postgres://u:first@h/db?password=second&%70assword=last+%2B&sslmode=require",
    )
    .unwrap();
    assert_eq!(password(&p), Some(&b"last++"[..]));
    assert_eq!(p.public(), "postgres://u@h/db?sslmode=require");
    assert!(p.password().unwrap().secure_required());
    assert_eq!(
        p.redact_echo("first second last++ last+%2b"),
        "<redacted> <redacted> <redacted> <redacted>"
    );
    let p =
        CredUrl::parse_postgres("host=db password='one' password=two\\ words user=app").unwrap();
    assert_eq!(password(&p), Some(&b"two words"[..]));
    assert_eq!(
        p.redact_echo(r"one two words two\ words"),
        "<redacted> <redacted> <redacted>"
    );
    assert_eq!(
        CredUrl::parse_postgres("user=u password=")
            .unwrap()
            .password()
            .unwrap()
            .len(),
        0
    );
    assert!(CredUrl::parse_postgres("user=u")
        .unwrap()
        .password()
        .is_none());
    for invalid in ["%", "%1", "%GG", "%ff"] {
        assert!(CredUrl::parse_postgres(&format!("postgres://u:{invalid}@h/db")).is_err());
        assert!(CredUrl::parse_postgres(&format!("postgres://u@h/db?password={invalid}")).is_err());
    }

    let p = CredUrl::parse_postgres("postgres://u@h/db?pass=value").unwrap();
    assert!(p.password().is_none());
    assert!(p.public().contains("pass=value"));
    assert!(CredUrl::parse("x://u:a@h?password=b").is_err());
}

#[test]
fn postgres_capture_applies_exact_keyword_and_query_auth_policy() {
    for text in [
        r"user=u password=p require_auth=pass\word",
        "user=u password=p require_auth = 'md5,password'",
        "user=u\u{2003}password=p\u{2003}require_auth\u{2003}=\u{2003}password",
        "postgres://u:p@h/db?options=x#y&%72equire_auth=%70assword",
    ] {
        let p = CredUrl::parse_postgres(text).unwrap();
        assert!(p.floor().pg().allows(PgAuth::Password));
        assert!(p.password().unwrap().pg_password_message().is_ok());
    }
    let typed: PostgresUrl = settings(br#""  postgres://u:p@h/db  ""#).unwrap();
    assert_eq!(typed.public(), "postgres://u@h/db");
    assert!(CredUrl::parse_postgres("  postgres://u:p@h/db  ").is_err());
}

#[test]
fn valkey_capture_separates_tcp_and_unix_rules() {
    let p = CredUrl::parse_valkey(" \nReDiSs://u:a%2fb@host/2?protocol=resp2\t ").unwrap();
    assert_eq!(password(&p), Some(&b"a/b"[..]));
    assert!(p.password().unwrap().secure_required());
    assert_eq!(p.redact_echo("a/b a%2Fb A/b"), "<redacted> <redacted> A/b");
    let p =
        CredUrl::parse_valkey("unix:/run/v.sock?db=2&%70ass=first&pass=s%3Dc+ret&password=ignored")
            .unwrap();
    assert_eq!(password(&p), Some(&b"s=c ret"[..]));
    assert_eq!(p.public(), "unix:/run/v.sock?db=2&%70ass=&pass=&password=");
    assert_eq!(
        p.redact_echo("first ignored s%3dc+ret s=c+ret s=c ret"),
        "<redacted> <redacted> <redacted> <redacted> <redacted>"
    );
    let p = CredUrl::parse_valkey("unix:///run/v.sock?pass=%FF").unwrap();
    assert_eq!(password(&p), Some("\u{fffd}".as_bytes()));
    assert_eq!(p.redact_echo("%ff \u{fffd}"), "<redacted> <redacted>");
    let p = CredUrl::parse_valkey("redis://u:p@h?pass=ignored&password=also").unwrap();
    assert_eq!(password(&p), Some(&b"p"[..]));
    assert!(p.public().contains("?pass=&password="));
    let p = CredUrl::parse_valkey("unix://u:ignored@localhost/run/v.sock").unwrap();
    assert!(p.password().is_none());
    assert!(!p.public().contains("ignored"));
}

#[test]
fn valkey_empty_and_invalid_password_metadata_survives_typed_settings() {
    for text in ["redis://:@h", "redis://u:@h", "redis://h"] {
        assert!(CredUrl::parse_valkey(text).unwrap().password().is_none());
    }
    assert!(CredUrl::parse_valkey("unix:/run/v.sock?pass=")
        .unwrap()
        .password()
        .is_some());
    let p: ValkeyUrl = settings_lent(br#"{"$secret":0}"#, &[b"redis://u:%ff@h"]).unwrap();
    assert_eq!(
        p.parsing_error(),
        Some("Password is not valid UTF-8 string")
    );
    assert_eq!(p.public(), "redis://u@h");
    let p: ValkeyUrl = settings(br#""unsupported://u:private@h""#).unwrap();
    assert_eq!(p.parsing_error(), Some("Redis URL did not parse"));
    assert!(!p.public().contains("private"));
}

#[test]
fn redaction_preserves_diagnostics_and_literal_case() {
    let p = CredUrl::parse("mysql://u:p%252fA@h/db").unwrap();
    assert_eq!(
        p.redact_echo("server says p%2fA or p%252fA; p%2FA stays"),
        "server says <redacted> or <redacted>; p%2FA stays"
    );
    let p = CredUrl::parse("mysql://u:p%2FA@h/db").unwrap();
    assert_eq!(
        p.redact_echo("p/a p/A p%2fA p%2FA"),
        "p/a <redacted> <redacted> <redacted>"
    );
    assert_eq!(
        CredUrl::parse("mysql://u:@h/db")
            .unwrap()
            .redact_echo("diagnostic"),
        "diagnostic"
    );
}

#[test]
fn captured_and_rejected_owned_settings_buffers_wipe_before_free() {
    use crate::alloc_counter::InitializedPayloadProbe;
    // SAFETY: all instrumented buffers are owned and destroyed synchronously on this thread.
    let probe = unsafe { InitializedPayloadProbe::start().expect("open memory observer") };
    let p: PostgresUrl =
        settings(br#""user=app password='first secret' password='last secret'""#).unwrap();
    drop(p);
    let p: ValkeyUrl = settings(br#""unix:/run/v.sock?pass=first%20secret&pass=%FF""#).unwrap();
    drop(p);
    assert!(settings::<PostgresUrl>(br#""postgres://u:%ff@h""#).is_err());
    assert!(settings_lent::<u16>(br#"{"$secret":0}"#, &[b"wrong type secret"]).is_err());
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
fn mysql_typed_settings_trim_before_password_and_floor_capture() {
    let p: crate::abi::sdk::cred::MysqlUrl =
        settings(br#""  mysql://u@h/db?secure_auth=false&password=pw   ""#).unwrap();
    assert_eq!(password(&p), Some(&b"pw"[..]));
    assert!(p.floor().mysql_old());
    assert_eq!(p.public(), "mysql://u@h/db?secure_auth=false");
}

#[test]
fn raw_delimiters_do_not_turn_a_path_or_query_into_native_userinfo() {
    for text in [
        "postgres://u:secret?tail@db/d",
        "postgres://u:secret/tail@db/d",
    ] {
        assert!(CredUrl::parse_postgres(text).is_err());
    }
    for text in [
        "redis://u:secret?tail@db/0",
        "redis://u:secret/tail@db/0",
        "redis://u:secret#tail@db/0",
    ] {
        let p = CredUrl::parse_valkey(text).unwrap();
        assert_eq!(p.parsing_error(), Some("Redis URL did not parse"));
        assert!(!p.public().contains("secret"));
        assert!(!p.public().contains("tail"));
        assert!(p.password().is_none());
    }
    let p = CredUrl::parse_valkey("redis://u:12?abc@127.0.0.1/0").unwrap();
    assert!(p.password().is_none());
    assert!(p.parsing_error().is_none());
    assert_eq!(p.public(), "redis://u:12?redacted@");
    assert_eq!(p.redact_echo("12?abc"), "<redacted>");
    let p = CredUrl::parse_valkey("valkeys://u:p@host").unwrap();
    assert!(p.password().unwrap().secure_required());
}

#[test]
fn percent_spelled_postgres_tls_mode_keeps_secure_requirement() {
    let p = CredUrl::parse_postgres("postgres://u:p@h/db?%73slmode=%72equire").unwrap();
    assert!(p.password().unwrap().secure_required());
    assert!(p.credential().secure_required());
}
