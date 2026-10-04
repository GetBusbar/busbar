// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A declared egress scheme, presented under the `Grant<Sign>` the kernel mints: a static scheme
//! writes the header its credential-family table names, and a signing scheme signs for the region
//! its host names. Moved from `busbar-kernel-identity`'s own suite
//! (`src/egress_auth/declared_tests.rs`), against the unit's public API.

use busbar_contract::caps::{Grant, KernelSeal, Sign};
use busbar_contract::config::UpstreamCreds;
use busbar_contract::protocol::{CredentialFamily, CredentialHeader, EgressScheme, SigningContext};
use busbar_kernel_identity::egress_auth::{
    decorate, present, substitute, EgressBody, Scheme, SessionToken,
};

/// The unit's `Sign` token, minted fresh for each test that presents.
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
        // The request a declared scheme signs: a `POST` of the context's body to its path, the
        // content type and host folded in.
        let request = EgressBody {
            method: "POST",
            canonical_uri: c.canonical_uri,
            canonical_querystring: "",
            envelope: &signed,
            body: c.body,
            timestamp_epoch: c.timestamp_epoch,
        };
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
                &request,
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
