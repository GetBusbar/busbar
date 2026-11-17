// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The facade preserves compact bytes and propagates fallible-sink refusals.

use std::{fmt, io};

use busbar_contract::json;
use serde::{Serialize, Serializer};

struct Bounded {
    bytes: Vec<u8>,
    limit: usize,
    refused: bool,
    writes_after_refusal: usize,
}

impl io::Write for Bounded {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.refused {
            self.writes_after_refusal += 1;
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let amount = bytes.len().min(self.limit - self.bytes.len());
        if amount == 0 && !bytes.is_empty() {
            self.refused = true;
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        self.bytes.extend_from_slice(&bytes[..amount]);
        Ok(amount)
    }

    fn flush(&mut self) -> io::Result<()> {
        panic!("the facade must not flush the caller's sink")
    }
}

#[test]
fn every_refused_output_boundary_keeps_the_exact_prefix_and_io_classification() {
    #[derive(Serialize)]
    struct Row<'a> {
        text: &'a str,
        count: u128,
    }
    let row = Row {
        text: "\0\"雪🦀",
        count: u128::MAX,
    };
    let expected =
        r#"{"text":"\u0000\"雪🦀","count":340282366920938463463374607431768211455}"#.as_bytes();
    for limit in 0..expected.len() {
        let mut sink = Bounded {
            bytes: Vec::new(),
            limit,
            refused: false,
            writes_after_refusal: 0,
        };
        let error = json::to_writer(&mut sink, &row).expect_err("bounded sink refuses");
        assert_eq!(error.classify(), json::Category::Io);
        assert_eq!(sink.bytes, expected[..limit]);
        assert_eq!(sink.writes_after_refusal, 0);
    }
    let mut out = Vec::new();
    json::to_writer(&mut out, &row).expect("fresh sink succeeds");
    assert_eq!(out, expected);
    assert_eq!(out, json::to_vec(&row).expect("same compact bytes"));
}

#[test]
fn facade_writes_exact_numbers_and_character_keys_without_changing_bytes() {
    let value = json::parse_value(b"[-0,1.0,1e400,18446744073709551617]").expect("exact tree");
    let mut out = Vec::new();
    json::to_writer(&mut out, &value).expect("raw numbers");
    assert_eq!(out, b"[-0,1.0,1e400,18446744073709551617]");
    out.clear();
    let keys = std::collections::BTreeMap::from([('\0', 1), ('"', 2), ('\\', 3), ('雪', 4)]);
    json::to_writer(&mut out, &keys).expect("character keys");
    assert_eq!(out, r#"{"\u0000":1,"\"":2,"\\":3,"雪":4}"#.as_bytes());
}

struct IgnoresFailure;
impl fmt::Display for IgnoresFailure {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = out.write_str("secret-first");
        let _ = out.write_str("secret-next");
        Ok(())
    }
}
impl Serialize for IgnoresFailure {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[test]
fn swallowed_display_refusal_is_still_an_io_error_without_later_writes() {
    let mut sink = Bounded {
        bytes: Vec::new(),
        limit: 1,
        refused: false,
        writes_after_refusal: 0,
    };
    let error = json::to_writer(&mut sink, &IgnoresFailure).expect_err("first refusal is sticky");
    assert_eq!(error.classify(), json::Category::Io);
    assert_eq!(sink.bytes, b"\"");
    assert_eq!(sink.writes_after_refusal, 0);
}

struct BadDisplay;
impl fmt::Display for BadDisplay {
    fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
        Err(fmt::Error)
    }
}
impl Serialize for BadDisplay {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[test]
fn formatting_only_failure_is_an_error_instead_of_a_panic() {
    let error = json::to_writer(std::io::sink(), &BadDisplay).expect_err("formatting failure");
    assert_eq!(error.classify(), json::Category::TypeUnmatched);
    assert_eq!(error.to_string(), "error while formatting JSON value");
}
