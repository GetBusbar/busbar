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

#[test]
fn record_growth_failure_and_unwind_wipe_each_initialized_encoder_allocation() {
    use crate::alloc_counter::InitializedPayloadProbe;

    #[derive(serde::Serialize)]
    struct LongRecord {
        auth: Row,
        tail: String,
        stop: Stop,
    }
    struct Stop(u8);
    impl serde::Serialize for Stop {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            match self.0 {
                1 => Err(serde::ser::Error::custom(
                    "record refused after its payload",
                )),
                2 => panic!("record serializer unwound after its payload"),
                _ => serializer.serialize_unit(),
            }
        }
    }

    for stop in 0..3 {
        let secret = SECRET.repeat(1024);
        let record = LongRecord {
            auth: Row {
                scheme: "Bearer".into(),
                credentials: cred(&secret),
            },
            tail: "tail".repeat(32_768),
            stop: Stop(stop),
        };
        // SAFETY: encoder allocations stay owned, initialized and on this thread until they
        // are wiped/freed; the long record forces growth after credential bytes were written.
        let probe = unsafe { InitializedPayloadProbe::start().expect("open payload observer") };
        let encoded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| to_vec(&record)));
        match (stop, encoded) {
            (0, Ok(Ok(bytes))) => {
                assert!(bytes
                    .windows(secret.len())
                    .any(|bytes| bytes == secret.as_bytes()));
                drop(bytes);
            }
            (1, Ok(Err(_))) | (2, Err(_)) => {}
            _ => panic!("wrong serializer outcome"),
        }
        let observed = probe.finish();
        assert!(!observed.reentered);
        assert!(observed.payloads.len() > 2, "the actual encoder grew");
        for payload in observed.payloads {
            assert!(payload.freed, "encoder allocation survived: {payload:?}");
            assert!(
                !payload.reallocated,
                "ordinary realloc retired encoder bytes"
            );
            #[cfg(target_os = "linux")]
            {
                assert_eq!(payload.read_error, None);
                assert!(payload.complete_read);
                assert_eq!(payload.bytes_read, payload.len);
                assert!(
                    payload.wiped,
                    "encoder bytes reached free unwiped: {payload:?}"
                );
            }
            #[cfg(not(target_os = "linux"))]
            assert_eq!(payload.read_error, Some(std::io::ErrorKind::Unsupported));
        }
        assert!(
            serde_json::to_string(&record.auth).is_err(),
            "record scope closed"
        );
    }
}
