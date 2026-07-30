// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The real HTTPS [`JwksFetcher`] over `reqwest`'s BLOCKING client (rustls/ring TLS — the same stack
//! busbar already uses; no second TLS/crypto backend). Blocking because the auth `authenticate` path
//! is synchronous; JWKS fetches are rare (cached + TTL'd), so a blocking GET behind the cache lock is
//! fine and keeps the plugin free of an async runtime, matching the store plugins' synchronous
//! posture.

use crate::cache::JwksFetcher;
use std::io::Read;
use std::time::Duration;

/// Upper bound on a JWKS / discovery document. A real JWKS is a handful of keys — a few KiB; even a
/// tenant rotating aggressively stays well under this. The bound exists because the body arrives
/// from a remote IdP whose `jwks_uri` is itself read out of a remote discovery document, and it is
/// buffered under the single-flight `fetch_gate`, so an unbounded body parks every cold-cache
/// caller behind it as well as consuming the RAM.
const MAX_JWKS_BYTES: usize = 1024 * 1024;

/// Read `r` into a `String`, refusing anything over `cap` bytes.
///
/// `take(cap + 1)`: read ONE byte past the cap so "exactly at the cap" and "over the cap" are
/// distinguishable without trusting Content-Length, which a hostile or chunked response need not
/// supply honestly.
fn read_capped(r: impl Read, cap: usize, url: &str) -> Result<String, String> {
    let mut buf = Vec::new();
    r.take(cap as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("reading {url} response body failed: {e}"))?;
    if buf.len() > cap {
        return Err(format!("{url} JWKS body exceeds the {cap}-byte cap"));
    }
    String::from_utf8(buf).map_err(|_| format!("{url} JWKS body is not UTF-8"))
}

/// Bounded HTTPS fetcher. Holds one reusable blocking client with a connect + total timeout so a hung
/// or slow IdP can never hang auth.
pub struct ReqwestFetcher {
    client: reqwest::blocking::Client,
}

impl ReqwestFetcher {
    /// Build a fetcher with the given total request timeout.
    ///
    /// `extra_root_cert_pem`, when present, is an ADDITIONAL trusted root CA (PEM) layered on top of
    /// the built-in webpki root store — never a replacement for it, and cert validation stays fully
    /// enabled (this is not `danger_accept_invalid_certs`). This is a real operator-facing need: a
    /// self-hosted/internal-CA OIDC provider (e.g. an on-prem Keycloak signed by a corporate CA) whose
    /// JWKS/discovery endpoint doesn't chain to a public root. It doubles as the hook that lets tests
    /// stand up a real local HTTPS JWKS fixture (self-signed, added here) and exercise the genuine
    /// TLS + fetch path instead of stubbing it out.
    pub fn new(timeout: Duration, extra_root_cert_pem: Option<&str>) -> Result<Self, String> {
        let mut builder = reqwest::blocking::Client::builder()
            .timeout(timeout)
            .connect_timeout(timeout)
            // HTTPS-only: a JWKS/discovery endpoint fetched over plaintext could be MITM'd to serve
            // attacker keys. `https_only` refuses any non-TLS URL.
            .https_only(true);
        if let Some(pem) = extra_root_cert_pem {
            let cert = reqwest::Certificate::from_pem(pem.as_bytes())
                .map_err(|e| format!("invalid ca_cert_pem: {e}"))?;
            builder = builder.add_root_certificate(cert);
        }
        let client = builder
            .build()
            .map_err(|e| format!("failed to build JWKS HTTP client: {e}"))?;
        Ok(Self { client })
    }
}

impl JwksFetcher for ReqwestFetcher {
    fn fetch(&self, url: &str) -> Result<String, String> {
        let resp = self
            .client
            .get(url)
            .send()
            .map_err(|e| format!("request to {url} failed: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("{url} returned HTTP {}", resp.status()));
        }
        read_capped(resp, MAX_JWKS_BYTES, url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwks_body_over_the_cap_is_refused() {
        let cap = 16usize;
        let body = std::io::repeat(b'x').take(cap as u64 * 2);
        let err = read_capped(body, cap, "https://idp.example/jwks").unwrap_err();
        assert!(err.contains("exceeds"), "unexpected error: {err}");
    }

    #[test]
    fn jwks_body_exactly_at_the_cap_is_accepted() {
        let cap = 16usize;
        let body = std::io::repeat(b'x').take(cap as u64);
        let out = read_capped(body, cap, "https://idp.example/jwks").unwrap();
        assert_eq!(out.len(), cap);
    }

    #[test]
    fn a_non_utf8_jwks_body_is_a_clean_error_not_a_panic() {
        let body: &[u8] = &[0xff, 0xfe];
        let err = read_capped(body, 1024, "https://idp.example/jwks").unwrap_err();
        assert!(err.contains("not UTF-8"), "unexpected error: {err}");
    }
}
