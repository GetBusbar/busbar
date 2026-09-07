// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The egress-auth unit is the only thing in the tree that holds a credential in the clear. That
//! is a property of what it HANDS BACK, and nothing else in the crate asserts it.
//!
//! Two things leave `decorate`: an `AuthDecoration`, which travels back through the kernel loop to
//! a caller that is not allowed to see the secret, and — after `substitute` — an envelope, which
//! goes on the wire. The decoration must not carry the secret in any form a `Debug` line, a log, an
//! error or a metric label could pick up. The envelope must carry it in exactly one field, the one
//! the scheme names, and nowhere else. For SigV4 it must not carry it at all: what goes on the wire
//! there is a signature, a value derived from the secret that does not let anyone recover it.
//!
//! The refusal paths matter as much as the happy ones. A credential a config system mangled — a
//! stray CR, an injected NUL — is refused, and the refusal must not quote the thing it refused.
//! That is the exact shape by which a bad-credential error ends up in an operator's log carrying
//! the credential.

use busbar_caps::{AuthDecoration, EgressAuthToken, KernelSeal};
use busbar_unit_egress_auth::{decorate, substitute, EgressBody, Scheme};

/// A credential distinctive enough that any echo of it is unmistakable, and long enough that no
/// prefix of it could occur by chance in a hex digest.
const SECRET: &str = "sk-CANARY-9c1f4a7b-do-not-echo-this-anywhere";

fn token() -> EgressAuthToken {
    EgressAuthToken::mint(&KernelSeal::acquire_for_kernel())
}

fn body() -> EgressBody<'static> {
    EgressBody {
        method: "POST",
        canonical_uri: "/model/anthropic.claude/converse",
        canonical_querystring: "",
        envelope: &[],
        body: b"{\"messages\":[]}",
        timestamp_epoch: 1_440_938_160,
    }
}

fn schemes() -> Vec<(&'static str, Scheme)> {
    vec![
        ("bearer", Scheme::Bearer),
        ("api-key", Scheme::ApiKeyHeader { header: "api-key" }),
        (
            "x-goog-api-key",
            Scheme::ApiKeyHeader {
                header: "x-goog-api-key",
            },
        ),
        (
            "sigv4",
            Scheme::SigV4 {
                access_key_id: "AKIDEXAMPLE",
                region: "us-east-1",
                service: "bedrock",
            },
        ),
    ]
}

/// Nothing a decoration carries — its declared fields, its slot locations, or its `Debug`
/// rendering — contains the secret, for any scheme.
///
/// The decoration is the value that crosses back out of this unit. A slot exists precisely so the
/// secret does not have to: it names WHERE the credential goes, and a location string that carried
/// the credential itself would defeat the whole arrangement while every existing assertion about
/// slot counts and field names stayed true.
#[test]
fn no_decoration_any_scheme_returns_carries_the_secret() {
    for (name, scheme) in schemes() {
        let decoration = decorate(&token(), &scheme, SECRET, &body());

        let rendered = format!("{decoration:?}");
        assert!(
            !rendered.contains(SECRET),
            "the {name} decoration's Debug rendering echoes the credential: {rendered}"
        );

        let AuthDecoration::Decorate { fields, slots, .. } = &decoration else {
            panic!("{name} decorates in place");
        };
        for (k, v) in fields {
            assert!(
                !v.contains(SECRET),
                "the {name} decoration writes the credential into the {k} field literally"
            );
        }
        for slot in slots {
            assert!(
                !slot.location().contains(SECRET),
                "a {name} slot location carries the credential: {}",
                slot.location()
            );
        }
    }
}

/// After substitution the credential appears in exactly one envelope field — the one the scheme
/// names — and in no other, for the schemes that put it on the wire at all.
#[test]
fn substitution_puts_the_credential_in_exactly_one_field() {
    let already_encoded: Vec<(String, String)> = vec![
        ("host".to_string(), "api.openai.com".to_string()),
        ("content-type".to_string(), "application/json".to_string()),
    ];

    for (name, scheme, expect_field, expect_value) in [
        (
            "bearer",
            Scheme::Bearer,
            "authorization",
            format!("Bearer {SECRET}"),
        ),
        (
            "api-key",
            Scheme::ApiKeyHeader { header: "api-key" },
            "api-key",
            SECRET.to_string(),
        ),
        (
            "x-goog-api-key",
            Scheme::ApiKeyHeader {
                header: "x-goog-api-key",
            },
            "x-goog-api-key",
            SECRET.to_string(),
        ),
    ] {
        let decoration = decorate(&token(), &scheme, SECRET, &body());
        let envelope = substitute(&decoration, SECRET, already_encoded.clone());

        let carrying: Vec<&(String, String)> = envelope
            .iter()
            .filter(|(_, v)| v.contains(SECRET))
            .collect();
        assert_eq!(
            carrying.len(),
            1,
            "{name} put the credential in {} fields, not one",
            carrying.len()
        );
        assert!(
            carrying[0].0.eq_ignore_ascii_case(expect_field),
            "{name} put the credential in {} rather than {expect_field}",
            carrying[0].0
        );
        assert_eq!(carrying[0].1, expect_value, "{name}");

        // No field name ever carries it either — a credential in a header NAME is a header a
        // proxy log records in full.
        for (k, _) in &envelope {
            assert!(!k.contains(SECRET), "{name} put the credential in a name");
        }
    }
}

/// SigV4 puts the credential on the wire in NO form. What the `Authorization` header carries is a
/// signature and a non-secret access key id; the signing secret itself never appears, and neither
/// does any prefix of it long enough to be worth guessing from.
#[test]
fn sigv4_sends_a_signature_and_never_the_signing_secret() {
    let decoration = decorate(
        &token(),
        &Scheme::SigV4 {
            access_key_id: "AKIDEXAMPLE",
            region: "us-east-1",
            service: "bedrock",
        },
        SECRET,
        &body(),
    );
    let envelope = substitute(&decoration, SECRET, Vec::new());
    assert!(
        !envelope.is_empty(),
        "SigV4 does decorate — an empty envelope would pass the checks below vacuously"
    );

    for (k, v) in &envelope {
        assert!(!v.contains(SECRET), "the {k} field carries the secret");
        assert!(!k.contains(SECRET), "a field name carries the secret");
        // Any run of the secret long enough to narrow a guess is also absent.
        for len in [8usize, 12, 16, 24] {
            assert!(
                !v.contains(&SECRET[..len]),
                "the {k} field carries the first {len} bytes of the secret"
            );
        }
    }

    let auth = envelope
        .iter()
        .find(|(k, _)| k == "authorization")
        .map(|(_, v)| v.as_str())
        .expect("SigV4 sets an authorization header");
    assert!(auth.contains("Signature="), "{auth}");
    assert!(auth.contains("Credential=AKIDEXAMPLE/"), "{auth}");
}

/// A credential a config system mangled is refused, and the refusal does not quote it.
///
/// `decorate` answers an un-encodable key with the no-header decoration, so the upstream 401s the
/// same way every other bad-credential path does. The value that comes back must not carry the
/// mangled credential either: an error or a decoration that quotes what it refused is how a
/// credential reaches a log.
#[test]
fn a_refused_credential_is_not_echoed_by_the_refusal() {
    let mangled = [
        format!("{SECRET}\r\nx-injected: 1"),
        format!("{SECRET}\n"),
        format!("{SECRET}\0"),
        format!("{SECRET}\x07"),
    ];
    for bad in &mangled {
        for (name, scheme) in [
            ("bearer", Scheme::Bearer),
            ("api-key", Scheme::ApiKeyHeader { header: "api-key" }),
        ] {
            let decoration = decorate(&token(), &scheme, bad, &body());
            let AuthDecoration::Decorate { fields, slots, .. } = &decoration else {
                panic!("{name} refuses in place");
            };
            assert!(
                slots.is_empty() && fields.is_empty(),
                "{name} must refuse a credential with a control byte in it"
            );
            let rendered = format!("{decoration:?}");
            assert!(
                !rendered.contains(SECRET),
                "the {name} refusal echoes what it refused: {rendered}"
            );

            // And substituting the refusal writes nothing at all — not the credential, and not a
            // header with an empty value that would read as a credential the upstream saw.
            assert!(substitute(&decoration, bad, Vec::new()).is_empty());
        }
    }
}

/// A credential that is merely unusual — every printable ASCII character, spaces included — is NOT
/// refused, so the refusal above is about control bytes and not about anything else.
///
/// A refusal that widened to "anything I do not recognise" would take a perfectly valid credential
/// off the wire and turn it into an upstream 401 that reads as a rotation problem.
#[test]
fn only_control_bytes_are_refused_not_merely_unusual_credentials() {
    let printable: String = (0x20u8..=0x7e).map(|b| b as char).collect();
    let decoration = decorate(&token(), &Scheme::Bearer, &printable, &body());
    let AuthDecoration::Decorate { slots, .. } = &decoration else {
        panic!("bearer decorates in place");
    };
    assert_eq!(slots.len(), 1, "a printable credential is not refused");
    let envelope = substitute(&decoration, &printable, Vec::new());
    assert_eq!(
        envelope,
        vec![("authorization".to_string(), format!("Bearer {printable}"))]
    );

    // DEL (0x7f) is a control byte for this purpose and is refused, which is the boundary the loop
    // above stops one short of.
    let with_del = format!("{printable}\x7f");
    let refused = decorate(&token(), &Scheme::Bearer, &with_del, &body());
    let AuthDecoration::Decorate { slots, .. } = &refused else {
        panic!("bearer refuses in place");
    };
    assert!(slots.is_empty(), "DEL is a control byte and is refused");
}
