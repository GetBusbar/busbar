// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CLIENT ID METADATA DOCUMENT FETCH, filled by the composition.
//!
//! `busbar-control-tokenmint` declares this as a SEAM (`CimdFetch`) and does not implement it, and
//! that is not squeamishness: a CIMD `client_id` is an attacker-supplied URL on an interactive
//! authorization request, so the fetch is an SSRF surface, and the resolve-then-pin guard that
//! makes it safe is the NODE'S — `busbar_substrate::net_guard`, the one copy of that control in the
//! tree. An authorization server does not get its own.
//!
//! The body below is the one `busbar_core::oauth_as::cimd::GuardedFetch` carried, MOVED rather than
//! rewritten: the same policy (public HTTPS only, no redirects, 5 KB, 10 s, no `allow_private`
//! knob — a stranger's URL carries no operator intent), the same ordering that keeps the
//! cloud-metadata arm ahead of everything a knob could say, the same pinned engine client, the same
//! ONE deadline over send-plus-body, and the same capped read that costs the cap rather than the
//! document. A refusal reads in the same words, which is what the byte-identity judge requires.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use busbar_control_tokenmint::CimdFetch;

/// THE PRODUCTION FETCH: resolve-then-pin through the node's guard, then one GET to the pinned
/// address.
#[derive(Default)]
pub struct GuardedFetch;

/// This fetch's knobs. Fail-closed in every direction: public HTTPS only, no redirects, a small
/// body and a short clock. There is deliberately no `allow_private` here — a CIMD `client_id` is a
/// stranger's URL by definition, so there is no operator intent for a knob to carry.
fn fetch_policy() -> busbar_substrate::net_guard::GuardPolicy {
    busbar_substrate::net_guard::GuardPolicy {
        allow_private: false,
        allow_plaintext: false,
        max_redirects: 0,
        max_body_bytes: busbar_control_tokenmint::cimd::MAX_DOCUMENT_BYTES,
        timeout: busbar_control_tokenmint::cimd::FETCH_TIMEOUT,
    }
}

impl CimdFetch for GuardedFetch {
    /// Does this `client_id` name a metadata document at all? HTTPS, a parseable authority, and no
    /// fragment. Anything else is an ordinary opaque identifier and gets the ordinary answer:
    /// unknown unless registered. The legacy `is_cimd_client_id`, moved with the fetch it guards —
    /// on the SAME implementation, so a deployment cannot judge a URL by one grammar and dial it by
    /// another.
    fn names_a_document(&self, client_id: &str) -> bool {
        client_id.starts_with("https://")
            && !client_id.contains('#')
            && busbar_substrate::net_guard::split_url(client_id).is_ok()
    }

    fn fetch<'a>(
        &'a self,
        url: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>> {
        Box::pin(async move {
            let policy = fetch_policy();
            let (https, host, port, _path) =
                busbar_substrate::net_guard::split_url(url).map_err(|e| e.to_string())?;
            busbar_substrate::net_guard::judge_scheme(url, https, policy)
                .map_err(|e| e.to_string())?;
            // THE GUARD: structural name refusals, EXACTLY ONE resolution, every answered address
            // judged, then the pin. All of it core's, including the ordering that keeps the
            // cloud-metadata arm ahead of everything a knob could say.
            let pin =
                busbar_substrate::net_guard::resolve_and_pin_async(&host, port, https, policy)
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
            busbar_substrate::net_guard::refuse_redirect(
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
                            return Err(busbar_substrate::net_guard::refuse_oversized_body(
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
