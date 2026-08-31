// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CLIENT ID METADATA DOCUMENTS: the `client_id`-that-is-a-URL mechanism, served at the
//! `Storage::get_client` seam.
//!
//! The `2026-07-28` MCP revision lists CIMD as the `SHOULD` among the three ways a client obtains
//! a `client_id`. The shape here is the one `oauth_as/mod.rs` records: a `client_id` that parses
//! as an HTTPS URL and is absent from the store is FETCHED, validated (`client_id` equal to the
//! URL it was fetched from, `redirect_uris` taken from the document and exact-matched by
//! `oauth-as` against the request), and materialised as an EPHEMERAL
//! [`oauth_as::client::Client`] under the SAME [`super::policy::default_grant_scopes`] ceiling
//! registration uses. Ephemeral means ephemeral: the materialised client is never written to the
//! store, so there is nothing to revoke, nothing to sweep, and nothing a restart resurrects — the
//! document is re-fetched and re-judged on every request that names it.
//!
//! ## Every failure is an UNKNOWN CLIENT, not an error
//!
//! A fetch that fails, a document that does not parse, and a document that fails validation all
//! answer `Ok(None)` from [`CimdStore::get_client`] — the same answer an unregistered `client_id`
//! gets — with the reason at `warn` for the operator. Mapping them to [`StorageError`] instead
//! would turn an attacker-supplied URL into a 500 an attacker can mint, and would make the
//! refusal distinguishable from "no such client", which is an oracle.
//!
//! ## The fetch is an SSRF surface by construction, and the guard is core's
//!
//! The URL is attacker-supplied. [`GuardedFetch`] goes through [`crate::net_guard`]'s
//! resolve-then-pin — the same unconditional cloud-metadata refusal and the same judged-answer
//! pin as every other guarded fetch in the tree — with this path's OWN bounds: a client metadata
//! document is a few kilobytes and the fetch is on an interactive authorization request, so
//! 5 KB and 10 s, not the card fetch's 512 KB. No redirects: the document lives at the
//! `client_id` or it is not that client's document.
//!
//! ## The validator seam, honestly labelled
//!
//! `oauth-as` ships a CIMD *validator* behind an off-by-default `cimd` feature this tree does not
//! enable. The document checks in [`materialize`] are therefore busbar's own — real checks,
//! enforced today — and the one call swapping the feature on would replace is marked `TODO` at
//! the site, tied to `chore/1.6.0-oauth-as-0.9.3`. The fetch and the seam are unchanged by that
//! bump: the library validates only, it does not fetch, and it exposes no client-resolution hook.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};

use oauth_as::authorization::{AuthorizationCodeRecord, AuthorizationCodeState};
use oauth_as::client::{Client, ClientAuth, ClientId};
use oauth_as::consent::ConsentRecord;
use oauth_as::device::{DeviceGrant, DeviceGrantState};
use oauth_as::grant::GrantType;
use oauth_as::scope::ScopeSet;
use oauth_as::store::{MemoryStorage, RevocationWindow, Storage, StorageError, WriteOutcome};
use oauth_as::token::{IssuedToken, RefreshTokenRecord};

use crate::net_guard::{self, GuardPolicy};

/// The body ceiling for one metadata document. A few kilobytes IS the document class; anything
/// larger is either not a metadata document or an allocation the URL's owner chose the size of.
pub(crate) const MAX_DOCUMENT_BYTES: usize = 5 * 1024;

/// End-to-end ceiling for one fetch. The fetch sits on an INTERACTIVE authorization request, so a
/// slow document host must fail the one login rather than parking a handler for a minute.
pub(crate) const FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// THE FETCH, AS A SEAM. Production installs [`GuardedFetch`]; the flow tests install a stub, so
/// the end-to-end proof drives the real authorize/consent/token wire without a second listener
/// standing in for "the public internet".
pub(crate) trait CimdFetch: Send + Sync {
    /// The document's bytes, or why there are none. The URL arrives exactly as the request spelled
    /// the `client_id`; an implementation must not normalise it, because the document's `client_id`
    /// member is compared byte-for-byte against it afterwards.
    fn fetch<'a>(
        &'a self,
        url: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>>;
}

/// THE PRODUCTION FETCH: resolve-then-pin through [`crate::net_guard`], then one GET to the
/// pinned address.
#[derive(Default)]
pub(crate) struct GuardedFetch;

/// This fetch's knobs. Fail-closed in every direction: public HTTPS only, no redirects, a small
/// body and a short clock. There is deliberately no `allow_private` here — a CIMD `client_id` is a
/// stranger's URL by definition, so there is no operator intent for a knob to carry.
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
            // judged, then the pin. All of it core's, including the ordering that keeps the
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

/// Does this `client_id` name a metadata document at all? HTTPS, a parseable authority, and no
/// fragment. Anything else is an ordinary opaque identifier and gets the ordinary answer:
/// unknown unless registered.
fn is_cimd_client_id(client_id: &str) -> bool {
    client_id.starts_with("https://")
        && !client_id.contains('#')
        && net_guard::split_url(client_id).is_ok()
}

/// VALIDATE THE DOCUMENT AND MATERIALISE THE CLIENT, under the operator's ceiling.
///
/// TODO(chore/1.6.0-oauth-as-0.9.3): `oauth-as` ships a CIMD document validator behind its `cimd`
/// feature; this tree pins 0.9.3 but does not enable that feature. When it is switched on, the
/// checks below hand over to (or are cross-checked against) the crate's validator AT THIS CALL
/// SITE — the fetch, the seam and the ceiling are unchanged by that switch. The checks below are
/// busbar's own and are ENFORCED TODAY; nothing here is a placeholder.
fn materialize(url: &str, body: &[u8], ceiling: &ScopeSet) -> Result<Client, String> {
    let doc: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| format!("not JSON: {e}"))?;
    let Some(doc) = doc.as_object() else {
        return Err("the document is not a JSON object".to_string());
    };

    // THE BINDING CHECK, and the whole reason the mechanism is sound: the document says which
    // `client_id` it is FOR, and it must be the URL it was fetched from, byte for byte. Without
    // this, any HTTPS URL an attacker controls could claim to be any client.
    match doc.get("client_id").and_then(|v| v.as_str()) {
        Some(id) if id == url => {}
        Some(id) => {
            return Err(format!(
                "the document's client_id `{id}` is not the URL it was fetched from"
            ))
        }
        None => return Err("the document carries no client_id member".to_string()),
    }

    // The redirect URIs come from the DOCUMENT, never from the request: `oauth-as` exact-matches
    // the request's `redirect_uri` against this list, which is what makes a stolen `client_id`
    // useless for sending a code anywhere the document's owner did not name.
    let redirect_uris: Vec<String> = match doc.get("redirect_uris").and_then(|v| v.as_array()) {
        Some(list) if !list.is_empty() => list
            .iter()
            .map(|v| match v.as_str() {
                Some(s)
                    if !s.is_empty() && !s.contains('#') && !s.contains(char::is_whitespace) =>
                {
                    Ok(s.to_string())
                }
                _ => Err("redirect_uris entries must be fragment-free URI strings".to_string()),
            })
            .collect::<Result<_, _>>()?,
        _ => return Err("the document carries no redirect_uris".to_string()),
    };

    // A CIMD client is PUBLIC by construction: there is nobody to have pre-shared a secret with.
    // A document asking for a secret-bearing method is asking this server to believe a credential
    // that cannot exist.
    match doc
        .get("token_endpoint_auth_method")
        .and_then(|v| v.as_str())
    {
        None => {}
        Some("none") => {}
        Some(other) => {
            return Err(format!(
                "token_endpoint_auth_method `{other}` is not `none`; a metadata-document client \
                 is public by construction"
            ))
        }
    }

    // The same two grants a DCR registrant may hold, for the same reason (`policy`):
    // `client_credentials` would convert "I exist at a URL" into "I am authorised", and
    // `device_code` is the grant a remote-phishing attacker starts on the victim's behalf.
    let grant_types = match doc.get("grant_types") {
        None => vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
        Some(serde_json::Value::Array(list)) => {
            let mut grants = Vec::new();
            for g in list {
                match g.as_str() {
                    Some("authorization_code") => grants.push(GrantType::AuthorizationCode),
                    Some("refresh_token") => grants.push(GrantType::RefreshToken),
                    Some(other) => {
                        return Err(format!(
                            "grant_type `{other}` is not available to a self-identified client"
                        ))
                    }
                    None => return Err("grant_types entries must be strings".to_string()),
                }
            }
            grants
        }
        Some(_) => return Err("grant_types is not an array".to_string()),
    };

    // The consent screen shows the client's identity, and the SAME impersonation refusal the
    // registration policy applies holds here: a client that arrives by the replacement mechanism
    // must not get to say the word the deprecated one is refused for.
    let name = doc.get("client_name").and_then(|v| v.as_str());
    if name.is_some_and(super::policy::name_impersonates_the_deployment) {
        return Err("the document's client_name impersonates this deployment".to_string());
    }

    // THE CEILING, shared with registration through `default_grant_scopes` so a client arriving
    // by either mechanism lands on the same one. A requested scope outside it is REFUSED rather
    // than narrowed, which is the stronger behaviour: a client told no knows where it stands; a
    // client quietly issued less believes it holds what it asked for.
    let default_scopes = match doc.get("scope").and_then(|v| v.as_str()) {
        None => ceiling.clone(),
        Some(scope) => {
            let requested = ScopeSet::from_tokens(scope.split_ascii_whitespace())
                .map_err(|e| format!("the document's scope is not a scope list: {e}"))?;
            if !requested.is_subset(ceiling) {
                return Err(format!(
                    "the document requests scope `{scope}` outside the operator's default_grant \
                     ceiling"
                ));
            }
            requested
        }
    };

    Ok(Client {
        client_id: ClientId::new(url),
        auth: ClientAuth::Public,
        grant_types,
        redirect_uris,
        allowed_scopes: ceiling.clone(),
        default_scopes,
        name: name.map(str::to_string),
        // NOT a dynamic registration: there is no RFC 7592 management record because there is no
        // stored registration to manage. The document is the registration.
        registration: None,
    })
}

/// THE STORE THIS PLANE RUNS ON: [`MemoryStorage`] with ONE read changed.
///
/// Every method delegates verbatim except [`Storage::get_client`], which — on a miss, for a
/// `client_id` that names a metadata document — fetches, validates and materialises the ephemeral
/// client. Everything `oauth-as` decides about the request (redirect URI exact-match, grant
/// admissibility, scope) it decides against that materialised record, exactly as it would against
/// a stored one.
pub(crate) struct CimdStore {
    inner: MemoryStorage,
    /// The operator's `default_grant`, as the ceiling every materialised client lands under.
    ceiling: ScopeSet,
    /// Swappable so the flow tests can stand in a stub document host; production never swaps it.
    fetcher: RwLock<Arc<dyn CimdFetch>>,
}

impl CimdStore {
    pub(crate) fn new(
        inner: MemoryStorage,
        ceiling: ScopeSet,
        fetcher: Arc<dyn CimdFetch>,
    ) -> Self {
        Self {
            inner,
            ceiling,
            fetcher: RwLock::new(fetcher),
        }
    }

    /// Install a different fetch. Test-only: the end-to-end flow proof needs the real wire and a
    /// controlled document, and a second HTTP listener playing "the internet" would put the SSRF
    /// guard's loopback refusal between the test and the property under test.
    #[cfg(test)]
    pub(crate) fn set_fetcher(&self, fetcher: Arc<dyn CimdFetch>) {
        *self
            .fetcher
            .write()
            .expect("the fetcher lock is only written here and never across a panic") = fetcher;
    }

    /// The current fetch, cloned out so no lock guard crosses an await.
    fn fetcher(&self) -> Arc<dyn CimdFetch> {
        Arc::clone(
            &self
                .fetcher
                .read()
                .expect("the fetcher lock is only written by set_fetcher and never across a panic"),
        )
    }
}

impl Storage for CimdStore {
    async fn get_client(&self, client_id: &ClientId) -> Result<Option<Arc<Client>>, StorageError> {
        // A STORED client wins, whatever its id looks like: the store is what the operator
        // and the registration endpoint wrote, and a fetch cannot override either.
        if let Some(found) = self.inner.get_client(client_id).await? {
            return Ok(Some(found));
        }
        let url = client_id.as_str();
        if !is_cimd_client_id(url) {
            return Ok(None);
        }
        let body = match self.fetcher().fetch(url).await {
            Ok(body) => body,
            Err(why) => {
                // A routine authz denial, one per request for an unknown/unreachable client id — not
                // an operator-actionable fault, so `debug!` (a `warn!` here spams on every probe for a
                // client id that isn't a valid CIMD document).
                tracing::debug!(
                    client_id = url,
                    %why,
                    "oauth_as: the client metadata document fetch was refused or failed; the \
                     client is unknown"
                );
                return Ok(None);
            }
        };
        match materialize(url, &body, &self.ceiling) {
            Ok(client) => Ok(Some(Arc::new(client))),
            Err(why) => {
                // Routine authz denial (a fetched document that fails validation), one per request —
                // `debug!`, not `warn!`, for the same reason as the fetch-failure arm above.
                tracing::debug!(
                    client_id = url,
                    %why,
                    "oauth_as: the client metadata document failed validation; the client is \
                     unknown"
                );
                Ok(None)
            }
        }
    }

    // ── EVERYTHING BELOW DELEGATES VERBATIM. No logic, no logging, no reordering: the wrapper
    //    changes ONE read and must be invisible everywhere else, or the storage-conformance
    //    properties MemoryStorage holds (atomic take_*, compare-and-swap, the revocation barrier)
    //    would silently stop being this store's. ──

    fn put_client(&self, client: Client) -> impl Future<Output = Result<(), StorageError>> + Send {
        self.inner.put_client(client)
    }

    fn compare_and_swap_client(
        &self,
        expected: &Client,
        updated: Client,
    ) -> impl Future<Output = Result<bool, StorageError>> + Send {
        self.inner.compare_and_swap_client(expected, updated)
    }

    fn delete_client(
        &self,
        client_id: &ClientId,
        window: RevocationWindow,
    ) -> impl Future<Output = Result<bool, StorageError>> + Send {
        self.inner.delete_client(client_id, window)
    }

    fn put_device_grant(
        &self,
        grant: DeviceGrant,
    ) -> impl Future<Output = Result<(), StorageError>> + Send {
        self.inner.put_device_grant(grant)
    }

    fn get_device_grant(
        &self,
        device_code: &str,
    ) -> impl Future<Output = Result<Option<DeviceGrant>, StorageError>> + Send {
        self.inner.get_device_grant(device_code)
    }

    fn find_device_grant_by_user_code(
        &self,
        normalized_user_code: &str,
    ) -> impl Future<Output = Result<Option<DeviceGrant>, StorageError>> + Send {
        self.inner
            .find_device_grant_by_user_code(normalized_user_code)
    }

    fn take_device_grant(
        &self,
        device_code: &str,
    ) -> impl Future<Output = Result<Option<DeviceGrant>, StorageError>> + Send {
        self.inner.take_device_grant(device_code)
    }

    fn compare_and_swap_device_grant(
        &self,
        expected: &DeviceGrantState,
        updated: DeviceGrant,
    ) -> impl Future<Output = Result<bool, StorageError>> + Send {
        self.inner.compare_and_swap_device_grant(expected, updated)
    }

    fn put_authorization_code(
        &self,
        record: AuthorizationCodeRecord,
    ) -> impl Future<Output = Result<(), StorageError>> + Send {
        self.inner.put_authorization_code(record)
    }

    fn compare_and_swap_authorization_code(
        &self,
        expected: &AuthorizationCodeState,
        updated: AuthorizationCodeRecord,
    ) -> impl Future<Output = Result<bool, StorageError>> + Send {
        self.inner
            .compare_and_swap_authorization_code(expected, updated)
    }

    fn take_authorization_code(
        &self,
        code: &str,
    ) -> impl Future<Output = Result<Option<AuthorizationCodeRecord>, StorageError>> + Send {
        self.inner.take_authorization_code(code)
    }

    fn put_token(
        &self,
        token: IssuedToken,
    ) -> impl Future<Output = Result<WriteOutcome, StorageError>> + Send {
        self.inner.put_token(token)
    }

    fn get_token(
        &self,
        access_token: &str,
    ) -> impl Future<Output = Result<Option<Arc<IssuedToken>>, StorageError>> + Send {
        self.inner.get_token(access_token)
    }

    fn delete_token(
        &self,
        access_token: &str,
    ) -> impl Future<Output = Result<(), StorageError>> + Send {
        self.inner.delete_token(access_token)
    }

    fn put_refresh_token(
        &self,
        record: RefreshTokenRecord,
    ) -> impl Future<Output = Result<WriteOutcome, StorageError>> + Send {
        self.inner.put_refresh_token(record)
    }

    fn get_refresh_token(
        &self,
        refresh_token: &str,
    ) -> impl Future<Output = Result<Option<Arc<RefreshTokenRecord>>, StorageError>> + Send {
        self.inner.get_refresh_token(refresh_token)
    }

    fn take_refresh_token(
        &self,
        refresh_token: &str,
    ) -> impl Future<Output = Result<Option<RefreshTokenRecord>, StorageError>> + Send {
        self.inner.take_refresh_token(refresh_token)
    }

    fn revoke_token_family(
        &self,
        family_id: &str,
        window: RevocationWindow,
    ) -> impl Future<Output = Result<u64, StorageError>> + Send {
        self.inner.revoke_token_family(family_id, window)
    }

    fn put_consent(
        &self,
        record: ConsentRecord,
    ) -> impl Future<Output = Result<(), StorageError>> + Send {
        self.inner.put_consent(record)
    }

    fn compare_and_swap_consent(
        &self,
        expected: Option<&ConsentRecord>,
        updated: ConsentRecord,
    ) -> impl Future<Output = Result<bool, StorageError>> + Send {
        self.inner.compare_and_swap_consent(expected, updated)
    }

    fn get_consent(
        &self,
        consent_id: &str,
    ) -> impl Future<Output = Result<Option<Arc<ConsentRecord>>, StorageError>> + Send {
        self.inner.get_consent(consent_id)
    }

    fn find_consent(
        &self,
        client_id: &ClientId,
        subject: &str,
    ) -> impl Future<Output = Result<Option<Arc<ConsentRecord>>, StorageError>> + Send {
        self.inner.find_consent(client_id, subject)
    }

    fn consents_for_subject(
        &self,
        subject: &str,
    ) -> impl Future<Output = Result<Vec<Arc<ConsentRecord>>, StorageError>> + Send {
        self.inner.consents_for_subject(subject)
    }

    fn revoke_consent(
        &self,
        consent_id: &str,
        window: RevocationWindow,
    ) -> impl Future<Output = Result<u64, StorageError>> + Send {
        self.inner.revoke_consent(consent_id, window)
    }

    fn sweep_expired(
        &self,
        now: std::time::SystemTime,
    ) -> impl Future<Output = Result<u64, StorageError>> + Send {
        self.inner.sweep_expired(now)
    }
}

#[cfg(test)]
#[path = "tests/cimd_tests.rs"]
mod cimd_tests;
