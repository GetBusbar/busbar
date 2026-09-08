// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NODE'S HALF OF THE CLIENT-ID-METADATA-DOCUMENT MECHANISM: the guarded fetch, and the
//! judgment about what names a document at all.
//!
//! ## Why this stayed behind when the rest of the authorization server left
//!
//! `busbar-control-oauth2` carries the whole of the OAuth 2.1 issuer — the config, the signer, the
//! consent sessions, the registration ceiling, the document checks and the route table. It does not
//! carry THIS, and the reason is the one thing on that path that is not about OAuth at all.
//!
//! A Client ID Metadata Document is fetched from a URL an unauthenticated caller chose, on an
//! endpoint that takes no credential. That is an SSRF surface by construction, and the control that
//! makes it safe is [`crate::net_guard`]'s resolve-then-pin: structural name refusals, EXACTLY ONE
//! resolution, every answered address judged, an unconditional cloud-metadata arm that no knob can
//! move, and then a pin so the socket goes to the address that was judged while the `Host` header,
//! the TLS SNI and the certificate name check all stay on the NAME. That control belongs to the
//! node and to nothing else. A control surface holding its own copy of it would be the second copy
//! of one security control in one tree — which is not hypothetical here: a drifted copy of exactly
//! this guard was a live cloud-metadata bypass on the MCP plane.
//!
//! So the surface declares the seam ([`busbar_control_oauth2::CimdFetch`]) and its own bounds
//! (`MAX_DOCUMENT_BYTES`, `FETCH_TIMEOUT` — this path's, not a card fetch's), and the node supplies
//! the mechanism. The split is exactly: *what a client metadata document is* is the protocol's, and
//! *where a socket may go* is the node's.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use busbar_control_oauth2::cimd::{CimdFetch, FETCH_TIMEOUT, MAX_DOCUMENT_BYTES};

use crate::net_guard::{self, GuardPolicy};

/// THE PRODUCTION FETCH: resolve-then-pin through [`crate::net_guard`], then one GET to the
/// pinned address.
#[derive(Default)]
pub(crate) struct GuardedFetch;

/// This fetch's knobs, built from the bounds the SURFACE declares. Fail-closed in every direction:
/// public HTTPS only, no redirects, a small body and a short clock. There is deliberately no
/// `allow_private` here — a CIMD `client_id` is a stranger's URL by definition, so there is no
/// operator intent for a knob to carry.
fn fetch_policy() -> GuardPolicy {
    GuardPolicy {
        allow_private: false,
        allow_plaintext: false,
        max_redirects: 0,
        max_body_bytes: MAX_DOCUMENT_BYTES,
        timeout: FETCH_TIMEOUT,
    }
}

impl CimdFetch for GuardedFetch {
    /// Does this `client_id` name a metadata document at all? HTTPS, a parseable authority, and no
    /// fragment. Anything else is an ordinary opaque identifier and gets the ordinary answer:
    /// unknown unless registered.
    ///
    /// On the fetch's own implementation rather than in the surface, because "does this parse as an
    /// authority I could dial" is the guard's grammar ([`net_guard::split_url`]) and an
    /// authorization server holding a second opinion about it would be one more copy of the same
    /// judgment.
    fn names_a_document(&self, client_id: &str) -> bool {
        client_id.starts_with("https://")
            && !client_id.contains('#')
            && net_guard::split_url(client_id).is_ok()
    }

    fn fetch<'a>(
        &'a self,
        url: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>> {
        Box::pin(async move {
            let policy = fetch_policy();
            let (https, host, port, _path) =
                net_guard::split_url(url).map_err(|e| e.to_string())?;
            net_guard::judge_scheme(url, https, policy).map_err(|e| e.to_string())?;
            // THE GUARD: structural name refusals, EXACTLY ONE resolution, every answered address
            // judged, then the pin. All of it the node's, including the ordering that keeps the
            // cloud-metadata arm ahead of everything a knob could say.
            let pin = net_guard::resolve_and_pin_async(&host, port, https, policy)
                .await
                .map_err(|e| e.to_string())?;

            // THE PINNED ENGINE CLIENT (`EngineSpec::pinned`): the pin IS the resolver — the
            // socket goes to the address the guard judged while the `Host` header, TLS SNI and
            // the certificate's name check all stay on the name, and every OTHER name refuses
            // with the one shared doctrine text. This deletes the fetch's private copy of the
            // refuse-second-lookup resolver — the third copy of that security control in the
            // tree, which is exactly the divergence-by-duplication failure mode `net_guard`'s
            // header warns about. Redirect non-following is structural in hyper; the 3xx is
            // still surfaced to `refuse_redirect` below so the refusal keeps its own wording.
            let client = busbar_substrate::egress::engine::build_client(
                &busbar_substrate::egress::engine::EngineSpec::pinned(
                    Arc::from(host.as_str()),
                    pin.socket_addr().ip(),
                    None,
                    Vec::new(),
                ),
            )
            .map_err(|e| format!("building the fetch client failed: {e}"))?;

            let uri: http::Uri = url
                .parse()
                .map_err(|e| format!("`{url}` does not parse as a URI: {e}"))?;
            let request = busbar_substrate::egress::engine::request(
                http::Method::GET,
                uri,
                http::HeaderMap::new(),
                bytes::Bytes::new(),
            );
            // ONE deadline for the whole exchange, exactly the client-level total the retired
            // reqwest builder carried: send to head, then every body chunk, under one instant.
            let deadline = tokio::time::Instant::now() + policy.timeout;
            let resp = busbar_substrate::egress::engine::send_bounded(&client, request, deadline)
                .await
                .map_err(|e| format!("fetching `{url}` failed: {}", e.into_cause()))?;
            let status = resp.status();
            net_guard::refuse_redirect(
                status.as_u16(),
                resp.headers()
                    .get(http::header::LOCATION)
                    .and_then(|v| v.to_str().ok()),
            )
            .map_err(|e| e.to_string())?;
            if !status.is_success() {
                return Err(format!("`{url}` answered HTTP {status}"));
            }

            // A CAPPED READ, not a read-then-measure: the ceiling is enforced while the bytes
            // arrive, so an oversized document costs the cap and not itself — and the deadline
            // keeps ticking through it.
            use http_body_util::BodyExt;
            let mut frames = resp.into_body();
            let mut body: Vec<u8> = Vec::new();
            loop {
                let frame = tokio::time::timeout_at(deadline, frames.frame())
                    .await
                    .map_err(|_| {
                        format!(
                            "reading `{url}` failed: {}",
                            busbar_substrate::egress::engine::HOP_DEADLINE_CAUSE
                        )
                    })?;
                match frame {
                    None => break,
                    Some(Err(e)) => return Err(format!("reading `{url}` failed: {e}")),
                    Some(Ok(frame)) => {
                        let Ok(chunk) = frame.into_data() else {
                            continue; // trailers carry no document bytes.
                        };
                        if body.len() + chunk.len() > policy.max_body_bytes {
                            return Err(net_guard::refuse_oversized_body(
                                url,
                                body.len() + chunk.len(),
                                policy,
                            )
                            .expect_err("over the cap by construction")
                            .to_string());
                        }
                        body.extend_from_slice(&chunk);
                    }
                }
            }
            Ok(body)
        })
    }
}

#[cfg(test)]
#[path = "tests/fetch_tests.rs"]
mod fetch_tests;
