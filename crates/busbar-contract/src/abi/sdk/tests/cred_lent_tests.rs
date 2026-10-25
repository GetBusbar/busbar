// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `settings_lent`: the host's `{"$secret": <index>}` markers read back as the lent bytes.

use std::collections::BTreeMap;

use serde::Deserialize;

use super::{settings_lent, Cred, SettingsError, SECRET_MARKER};

const CANARY: &str = "CANARY-lent-8c1e07";

#[derive(Deserialize)]
#[allow(dead_code)]
struct Server {
    command: String,
    env: BTreeMap<String, Cred>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct Settings {
    key: Cred,
    servers: BTreeMap<String, Server>,
    #[serde(default)]
    port: u16,
}

fn doc(port: &str) -> String {
    format!(
        r#"{{"key":{{"{SECRET_MARKER}":0}},"port":{port},
            "servers":{{"a":{{"command":"run","env":{{"API_KEY":{{"{SECRET_MARKER}":1}},"LOG":{{"{SECRET_MARKER}":2}}}}}}}}}}"#
    )
}

#[test]
fn the_marker_is_the_hosts_word() {
    assert_eq!(SECRET_MARKER, "$secret");
}

#[test]
fn lent_markers_read_back_as_creds() {
    let first = format!("{CANARY}-0");
    let second = format!("{CANARY}-1");
    let lent: [&[u8]; 3] = [first.as_bytes(), second.as_bytes(), b"debug"];
    let s: Settings = settings_lent(doc("7").as_bytes(), &lent).expect("parses");
    assert_eq!(s.key.wire(), first.as_bytes());
    let env = &s.servers["a"].env;
    assert_eq!(env["API_KEY"].wire(), second.as_bytes());
    assert_eq!(env["LOG"].wire(), b"debug");
    assert_eq!((s.port, s.servers["a"].command.as_str()), (7, "run"));
}

#[test]
fn a_document_without_markers_reads_as_settings_does() {
    #[derive(Deserialize)]
    struct Plain {
        key: Cred,
        name: String,
    }
    let p: Plain = settings_lent(br#"{"key":"k","name":"n"}"#, &[]).expect("parses");
    assert_eq!((p.key.wire(), p.name.as_str()), (&b"k"[..], "n"));
}

fn refused(doc: &str, lent: &[&[u8]]) -> SettingsError {
    match settings_lent::<Settings>(doc.as_bytes(), lent) {
        Ok(_) => panic!("refused"),
        Err(e) => e,
    }
}

fn value_free(e: &SettingsError) {
    let shown = format!("{e} {e:?}");
    assert!(
        !shown.contains(CANARY),
        "the error quotes a lent value: {shown}"
    );
}

#[test]
fn a_lent_secret_that_is_not_utf8_is_refused_without_its_bytes() {
    let mut bad = CANARY.as_bytes().to_vec();
    bad.push(0xff);
    let e = refused(&doc("7"), &[CANARY.as_bytes(), &bad, b"x"]);
    value_free(&e);
    assert_eq!(e.path(), "servers.a.env.API_KEY");
    assert!(e.to_string().contains("not UTF-8"), "{e}");
}

#[test]
fn a_marker_out_of_range_is_refused() {
    let e = refused(&doc("7"), &[CANARY.as_bytes(), CANARY.as_bytes()]);
    value_free(&e);
    assert_eq!(e.path(), "servers.a.env.LOG");
    assert!(e.to_string().contains("out of range"), "{e}");
}

#[test]
fn a_marker_that_is_not_an_index_is_refused() {
    let d = format!(r#"{{"key":{{"{SECRET_MARKER}":"{CANARY}"}},"servers":{{}}}}"#);
    let e = refused(&d, &[CANARY.as_bytes()]);
    value_free(&e);
    assert_eq!(e.path(), "key");
}

#[test]
fn the_marker_substitution_never_leaves_a_value_in_an_error() {
    // A lent value landing where the type does not take a string, a later field failing after the
    // substitution, and a document that does not parse: none quotes the lent bytes.
    let lent: [&[u8]; 3] = [CANARY.as_bytes(), CANARY.as_bytes(), CANARY.as_bytes()];
    let wrong_type = format!(r#"{{"key":"k","port":{{"{SECRET_MARKER}":0}},"servers":{{}}}}"#);
    let later = format!(r#"{{"key":{{"{SECRET_MARKER}":0}},"servers":{{"a":{{"env":{{}}}}}}}}"#);
    for d in [
        wrong_type,
        later,
        doc("\"x\""),
        format!("{{\"key\":{{\"{SECRET_MARKER}\":0}}"),
    ] {
        value_free(&refused(&d, &lent));
    }
}
