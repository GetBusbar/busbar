// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use zeroize::Zeroizing;

use super::{to_vec, REFUSED};
use crate::abi::sdk::cred::Cred;

fn cred(s: &str) -> Cred {
    Cred::captured(Zeroizing::new(s.as_bytes().to_vec()))
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Row {
    scheme: String,
    #[serde(with = "crate::abi::sdk::cred::record")]
    credentials: Cred,
}

#[derive(serde::Serialize)]
struct Outer {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth: Option<Row>,
}

const SECRET: &str = "CANARY-rec-5e1f";

fn row() -> Row {
    Row {
        scheme: "Bearer".into(),
        credentials: cred(SECRET),
    }
}

#[test]
fn a_record_carries_the_credential_as_the_plain_string_it_always_held() {
    let bytes = to_vec(&row()).expect("the record serializes");
    assert_eq!(
        &bytes[..],
        format!(r#"{{"scheme":"Bearer","credentials":"{SECRET}"}}"#).as_bytes()
    );
}

#[test]
fn a_record_reads_back_into_the_same_credential() {
    let bytes = to_vec(&row()).expect("the record serializes");
    let back: Row = serde_json::from_slice(&bytes).expect("the record reads back");
    assert!(back.credentials == cred(SECRET));
    assert_eq!(back.scheme, "Bearer");
}

#[test]
fn a_record_written_before_the_chip_reads_back() {
    let back: Row =
        serde_json::from_str(r#"{"scheme":"Basic","credentials":"x y"}"#).expect("reads");
    assert!(back.credentials == cred("x y"));
}

#[test]
fn nested_and_optional_rows_serialize_inside_the_record_scope() {
    let bytes = to_vec(&Outer {
        id: "c1".into(),
        auth: Some(row()),
    })
    .expect("serializes");
    assert!(std::str::from_utf8(&bytes).unwrap().contains(SECRET));
}

#[test]
fn serializing_outside_a_record_is_refused_and_quotes_nothing() {
    let e = serde_json::to_string(&row()).expect_err("a log line is no record");
    assert!(e.to_string().contains(REFUSED), "{e}");
    assert!(!e.to_string().contains(SECRET));
    let e = serde_json::to_vec_pretty(&Outer {
        id: "c1".into(),
        auth: Some(row()),
    })
    .expect_err("nor is a pretty one");
    assert!(!e.to_string().contains(SECRET));
    assert!(serde_json::to_value(row()).is_err());
}

#[test]
fn the_scope_closes_when_the_record_is_written() {
    let _ = to_vec(&row()).expect("serializes");
    assert!(serde_json::to_string(&row()).is_err());
}

#[test]
fn the_scope_closes_when_the_record_fails() {
    struct Fails;
    impl serde::Serialize for Fails {
        fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom("no"))
        }
    }
    assert!(to_vec(&Fails).is_err());
    assert!(serde_json::to_string(&row()).is_err());
}

#[test]
fn a_credential_that_is_not_text_has_no_record_form() {
    let r = Row {
        scheme: "Bearer".into(),
        credentials: Cred::captured(Zeroizing::new(vec![0xff, 0xfe])),
    };
    assert!(to_vec(&r).is_err());
}
