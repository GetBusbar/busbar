// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE BOOT REFUSALS, and the one path everybody gets backwards.

use super::{Identity, Section};
use crate::catalog;

fn code_of(r: Result<Identity, busbar_contract::error::PluginError>) -> String {
    r.expect_err("refused").code
}

fn cfg(issuer: &str) -> Section {
    Section {
        issuer: issuer.to_string(),
        key_id: None,
        default_grant: Vec::new(),
        access_token_ttl_secs: None,
    }
}

/// RFC 8414 §3.1 PUTS THE WELL-KNOWN SEGMENT FIRST, and RFC 9728 §3.1 puts it last. The two
/// documents this deployment serves therefore have their paths built in OPPOSITE orders, a few lines
/// apart, and getting either backwards means every conforming client's discovery 404s while the
/// server looks healthy.
#[test]
fn the_authorization_server_metadata_path_inserts_the_issuer_path_after_the_well_known_segment() {
    let id = Identity::from_section(&cfg("https://gw.example.com/tenant1")).expect("valid");
    assert_eq!(
        id.metadata_path(),
        "/.well-known/oauth-authorization-server/tenant1",
        "RFC 8414 section 3.1: the well-known segment comes BEFORE the issuer's path"
    );
    assert_eq!(id.authorize_path(), "/tenant1/authorize");
    assert_eq!(id.token_path(), "/tenant1/token");
    assert_eq!(id.jwks_uri(), "https://gw.example.com/tenant1/jwks");
}

/// An issuer at an origin root has no path to insert, and the well-known path is the bare one.
#[test]
fn an_issuer_with_no_path_serves_the_bare_well_known_document() {
    let id = Identity::from_section(&cfg("https://gw.example.com")).expect("valid");
    assert_eq!(
        id.metadata_path(),
        "/.well-known/oauth-authorization-server"
    );
    assert_eq!(id.authorize_path(), "/authorize");
    assert_eq!(id.consent_url(), "https://gw.example.com/consent");
}

/// A TRAILING SLASH IS A DIFFERENT SERVER. Every endpoint is `{issuer}/name`, so `https://host/`
/// derives `https://host//token`; and RFC 9207's `iss` comparison is byte-for-byte, so a client that
/// discovered one spelling will refuse the other. Refused at boot rather than normalised away,
/// because normalising hands back a string that no longer equals what the operator wrote.
#[test]
fn an_issuer_with_a_trailing_slash_is_refused_at_boot() {
    assert_eq!(
        code_of(Identity::from_section(&cfg("https://gw.example.com/"))),
        catalog::CONFIG_ISSUER_HAS_TRAILING_SLASH
    );
}

#[test]
fn an_issuer_that_is_not_an_absolute_url_is_refused_at_boot() {
    assert_eq!(
        code_of(Identity::from_section(&cfg("gw.example.com"))),
        catalog::CONFIG_ISSUER_NOT_ABSOLUTE
    );
    assert_eq!(
        code_of(Identity::from_section(&cfg(""))),
        catalog::CONFIG_MISSING_ISSUER
    );
}

/// RFC 8414 §2 defines the issuer as a URL with no query and no fragment.
#[test]
fn an_issuer_with_a_query_or_fragment_is_refused_at_boot() {
    for bad in ["https://gw.example.com?x=1", "https://gw.example.com#f"] {
        assert_eq!(
            code_of(Identity::from_section(&cfg(bad))),
            catalog::CONFIG_ISSUER_HAS_QUERY_OR_FRAGMENT,
            "`{bad}` was accepted as an issuer"
        );
    }
}

/// A `default_grant` entry that is not an RFC 6749 §3.3 scope token is refused AT BOOT, naming the
/// value. It has to be: `policy::default_grant_scopes` builds the registration ceiling from this
/// list and `expect`s it, so an unvalidated entry would be a panic on the first registration rather
/// than a message an operator can act on.
#[test]
fn a_default_grant_entry_that_is_not_a_scope_token_is_refused_at_boot() {
    let mut c = cfg("https://gw.example.com");
    c.default_grant = vec!["tools:read".into(), "not a token".into()];
    assert_eq!(
        code_of(Identity::from_section(&c)),
        catalog::CONFIG_SCOPE_NOT_A_TOKEN
    );
}

/// THE REGISTRATION PATH IS ALWAYS DERIVED. Every validated identity carries a registration path,
/// under the issuer's own prefix, with nothing to switch. Mirrors the metadata document, which is
/// what `oauth-as` routes from; the two must agree or busbar mounts a path the service does not
/// answer.
#[test]
fn the_registration_path_is_always_derived() {
    assert_eq!(
        Identity::from_section(&cfg("https://gw.example.com"))
            .expect("valid")
            .register_path(),
        "/register"
    );
    assert_eq!(
        Identity::from_section(&cfg("https://gw.example.com/tenant1"))
            .expect("valid")
            .register_path(),
        "/tenant1/register",
        "a tenant-prefixed issuer keeps its registration endpoint under the prefix"
    );
}
