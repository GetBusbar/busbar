// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `open_outbound`'s body: `sigv4` binds from its settings, and every refusal is 1.5.5's own words
//! in the `credential:` / `settings:` lines the kernel composes (ARCHITECT ruling Q5).

use super::*;
use crate::signing::SignFacts;
use crate::sigv4;

fn open(
    style: &str,
    credential: Option<&str>,
    settings: &str,
) -> (Result<SigV4Binding, Vec<Refusal>>, Vec<OpenNote>) {
    let mut notes = Vec::new();
    let r = open_binding(
        style,
        credential.map(str::as_bytes),
        Some(settings.as_bytes()),
        &mut notes,
    );
    (r, notes)
}

fn lines(r: Result<SigV4Binding, Vec<Refusal>>) -> Vec<String> {
    r.expect_err("the binding is refused")
        .iter()
        .map(Refusal::line)
        .collect()
}

#[test]
fn sigv4_needs_its_three_params_and_notes_an_unsendable_token() {
    assert_eq!(
        lines(
            open(
                SIGV4,
                Some("A:S"),
                r#"{"service":"svc","region":"us-east-1"}"#
            )
            .0
        ),
        ["settings: uses auth: sigv4 but has no `content_type`"]
    );
    let (r, notes) = open(
        SIGV4,
        Some("A:S:T\r\nX"),
        r#"{"service":"svc","region":"us-east-1","content_type":"application/json"}"#,
    );
    assert!(r.is_ok());
    assert_eq!(notes, [OpenNote::SessionToken("svc".to_string())]);
}

#[test]
fn a_keyless_binding_opens_but_signs_nothing() {
    let (r, notes) = open(
        SIGV4,
        None,
        r#"{"service":"svc","region":"us-east-1","content_type":"application/json"}"#,
    );
    let binding = r.expect("a keyless sigv4 binding still opens: the caller's credential may sign");
    assert!(notes.is_empty());
    let hash = sigv4::sha256_hex(b"{}");
    let facts = SignFacts {
        host: "h",
        canonical_uri: "/p",
        payload_hash: &hash,
        timestamp_epoch: 1,
    };
    assert!(binding.sign(&facts).is_empty());
}

#[test]
fn an_unknown_style_or_malformed_settings_is_refused() {
    assert_eq!(
        lines(open("kerberos", Some("k"), "{}").0),
        ["settings: outbound auth style `kerberos` is not served by this plugin"]
    );
    assert_eq!(
        lines(open(SIGV4, Some("k"), "[1]").0),
        ["settings: outbound auth settings must be a JSON object"]
    );
    assert_eq!(
        lines(open("bearer", Some("k"), "{}").0),
        ["settings: outbound auth style `bearer` is not served by this plugin"],
        "bearer is a different mechanism, busbar-auth-header"
    );
}
