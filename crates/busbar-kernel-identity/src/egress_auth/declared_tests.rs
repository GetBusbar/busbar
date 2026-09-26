// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A declared egress scheme is read as data: the credential-family table decides first, the lane's
//! credential mode decides the rest, and a signing scheme's region is the declared function of the
//! host.

use super::*;
use busbar_contract::caps::KernelSeal;
use busbar_contract::protocol::CredentialFamily;

fn token() -> Grant<Sign> {
    Grant::<Sign>::mint(&KernelSeal::acquire_for_kernel())
}

fn ctx(creds: UpstreamCreds) -> SigningContext<'static> {
    SigningContext {
        host: "runtime.region-7.example.com",
        canonical_uri: "/model/m/invoke",
        body: br#"{"x":1}"#,
        timestamp_epoch: 1_756_000_000,
        upstream_creds: creds,
    }
}

const KEY_HEADER: CredentialHeader = CredentialHeader::Raw {
    header: "x-key",
    trim_start: true,
};

/// Two credential families and a mode-keyed fallback: a static key family in its own header, an
/// access-token family as a bearer.
const TWO_FAMILIES: EgressScheme = EgressScheme::Static {
    families: &[
        CredentialFamily {
            prefix: "key-",
            presented_as: KEY_HEADER,
        },
        CredentialFamily {
            prefix: "tok-",
            presented_as: CredentialHeader::Bearer,
        },
    ],
    own: CredentialHeader::Raw {
        header: "x-key",
        trim_start: false,
    },
    passthrough: CredentialHeader::Bearer,
};

fn region_of(host: &str) -> Option<&str> {
    host.split('.')
        .nth(1)
        .filter(|label| label.starts_with("region-"))
}

const SIGNING: EgressScheme = EgressScheme::SigV4 {
    service: "svc",
    region_of_host: region_of,
    default_region: "region-0",
    content_type: "application/json",
};

fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
    list.iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// The table decides on the trimmed credential, whatever the mode; a credential in no family is
/// presented by the mode; a signing scheme has no static presentation.
#[test]
fn the_family_table_decides_first_and_the_mode_decides_the_rest() {
    use UpstreamCreds::{Own, Passthrough};
    assert_eq!(
        presentation(&TWO_FAMILIES, "  key-1", Passthrough),
        Some(KEY_HEADER)
    );
    assert_eq!(
        presentation(&TWO_FAMILIES, "tok-1", Own),
        Some(CredentialHeader::Bearer)
    );
    assert_eq!(
        presentation(&TWO_FAMILIES, "opaque", Own),
        Some(CredentialHeader::Raw {
            header: "x-key",
            trim_start: false
        })
    );
    assert_eq!(
        presentation(&TWO_FAMILIES, "opaque", Passthrough),
        Some(CredentialHeader::Bearer)
    );
    assert_eq!(presentation(&SIGNING, "a:b", Own), None);
}

/// Each presentation writes its header: a trimmed family key, a bearer, the verbatim mode fallback,
/// and nothing at all for a credential that is not a legal header value.
#[test]
fn a_static_scheme_presents_the_header_its_table_names() {
    let t = token();
    let own = ctx(UpstreamCreds::Own);
    assert_eq!(
        present(&t, &TWO_FAMILIES, "  key-1", &own),
        pairs(&[("x-key", "key-1")])
    );
    assert_eq!(
        present(&t, &TWO_FAMILIES, "tok-1", &own),
        pairs(&[("authorization", "Bearer tok-1")])
    );
    assert_eq!(
        present(&t, &TWO_FAMILIES, " opaque", &own),
        pairs(&[("x-key", " opaque")])
    );
    assert_eq!(
        present(&t, &EgressScheme::bearer(), "k", &own),
        pairs(&[("authorization", "Bearer k")])
    );
    assert_eq!(
        present(&t, &EgressScheme::header("api-key"), "k", &own),
        pairs(&[("api-key", "k")])
    );
    for scheme in [
        TWO_FAMILIES,
        EgressScheme::bearer(),
        EgressScheme::header("h"),
    ] {
        assert!(present(&t, &scheme, "bad\r\nkey", &own).is_empty());
    }
}

/// A signing scheme signs exactly what the signer signs for the region the host names (or the
/// declared default), and a credential missing its key id or secret presents nothing.
#[test]
fn a_signing_scheme_signs_for_the_region_its_host_names() {
    let t = token();
    for (host, region) in [
        ("runtime.region-7.example.com", "region-7"),
        ("runtime.example.com", "region-0"),
    ] {
        let c = SigningContext {
            host,
            ..ctx(UpstreamCreds::Own)
        };
        let signed = [
            ("content-type".to_string(), "application/json".to_string()),
            ("host".to_string(), host.to_string()),
        ];
        let expected = substitute(
            &decorate(
                &t,
                &Scheme::SigV4 {
                    access_key_id: "AKID",
                    region,
                    service: "svc",
                    session_token: Some(SessionToken("TOK")),
                },
                "SECRET",
                &request(&c, &signed),
            ),
            "SECRET",
            Vec::new(),
        );
        assert_eq!(present(&t, &SIGNING, "AKID:SECRET:TOK", &c), expected);
        assert!(expected[0]
            .1
            .contains(&format!("/{region}/svc/aws4_request")));
    }
    for refused in ["", "AKID", ":SECRET", "AKID:SECRET:bad\ntoken"] {
        assert!(present(&t, &SIGNING, refused, &ctx(UpstreamCreds::Own)).is_empty());
    }
}
