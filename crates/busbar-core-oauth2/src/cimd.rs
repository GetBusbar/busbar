// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CLIENT ID METADATA DOCUMENTS: the `client_id`-that-is-a-URL mechanism, served at the
//! `Storage::get_client` seam.
//!
//! The `2026-07-28` authorization revision lists CIMD as the `SHOULD` among the three ways a client obtains
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
//! ## The fetch rides the root Connector, and the guard is the connector's
//!
//! The URL is attacker-supplied. [`ConnectorFetch`] sends one GET through the deployment's ONE
//! root Connector, over a need this crate declares there (outbound, `https`, the `open-web` egress
//! class: public HTTPS only), so the connector's single destination guard judges, pins and dials
//! the address exactly as it does for every other outbound connection in the process (THE DESIGN
//! §5, "Destination guard"). This crate checks no destination of its own. What stays here is this
//! path's OWN bounds: a client metadata document is a few kilobytes and the fetch is on an
//! interactive authorization request, so 5 KB and 10 s. No redirects: the document lives at the
//! `client_id` or it is not that client's document.
//!
//! ## The validator is busbar's own
//!
//! `oauth-as` ships a CIMD *validator* behind an off-by-default `cimd` feature this tree does not
//! enable. The document checks in [`materialize`] are therefore busbar's own, and they are the
//! enforced ones. The feature stays off because switching it on changes a customer-visible byte
//! stream: it adds the `client_id_metadata_document_supported` member to the served RFC 8414
//! document, which `tests::signer_tests` pins. The library validates only; it does not fetch.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, RwLock};

use oauth_as::authorization::{AuthorizationCodeRecord, AuthorizationCodeState};
use oauth_as::client::{Client, ClientAuth, ClientId};
use oauth_as::consent::ConsentRecord;
use oauth_as::device::{DeviceGrant, DeviceGrantState};
use oauth_as::grant::GrantType;
use oauth_as::scope::ScopeSet;
use oauth_as::store::{MemoryStorage, RevocationWindow, Storage, StorageError, WriteOutcome};
use oauth_as::token::{IssuedToken, RefreshTokenRecord};

use busbar_contract::abi::host::conn::connector::{DIRECTION_OUTBOUND, EGRESS_OPEN_WEB};
use busbar_contract::abi::mechanism::rendering::{ReadBlob, ReadNeed};
use busbar_contract::conn::{ConnError, ConnId, NeedId, OpenDesc, PieceKind};

use crate::Table;

/// The body ceiling for one metadata document. A few kilobytes IS the document class; anything
/// larger is either not a metadata document or an allocation the URL's owner chose the size of.
pub(crate) const MAX_DOCUMENT_BYTES: usize = 5 * 1024;

/// End-to-end ceiling for one fetch. The fetch sits on an INTERACTIVE authorization request, so a
/// slow document host must fail the one login rather than parking a handler for a minute.
pub(crate) const FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// THE FETCH, AS A SEAM. Production installs [`ConnectorFetch`]; the flow tests install a stub, so
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

/// The one need this crate declares on the root Connector: the document fetch's.
pub(crate) const DOCUMENT_NEED: NeedId = NeedId(0);

/// THE DOCUMENT FETCH'S NEED, as the connector holds it: outbound, over `https`, in the `open-web`
/// egress class (THE DESIGN §5: a destination from request data, public HTTPS only). The target is
/// the plugin's own per open (no `target_from`): a CIMD `client_id` is a stranger's URL by
/// definition, so there is no operator setting for it to come from, and no auth rides it.
pub(crate) fn document_need() -> ReadNeed {
    ReadNeed {
        direction: DIRECTION_OUTBOUND,
        egress_class: EGRESS_OPEN_WEB,
        transport: "https".to_string(),
        auth: String::new(),
        target_from: String::new(),
        trust_from: String::new(),
        details: ReadBlob {
            fmt: 0,
            flags: 0,
            bytes: Vec::new(),
        },
        timeout_ms: u64::try_from(FETCH_TIMEOUT.as_millis()).unwrap_or(u64::MAX),
    }
}

/// THE PRODUCTION FETCH: one GET over the document need on the root Connector, whose destination
/// guard judges, pins and dials the address. `table` reaches the connection table the composition
/// root hands this crate ([`crate::Connections`]); it is read at fetch time, never at build, so a
/// plane built before the connector answers nothing it could not stand behind.
pub(crate) struct ConnectorFetch {
    pub(crate) table: fn() -> Option<Table>,
}

/// The fetch of a server built with no connection table ([`crate::NoConnections`]): every document
/// fetch fails closed, so every metadata-document client is unknown.
pub(crate) fn unconnected() -> Arc<dyn CimdFetch> {
    Arc::new(ConnectorFetch {
        table: <crate::NoConnections as crate::Connections>::table,
    })
}

/// Closes the exchange's connection however the fetch ends, so a refused, failed or oversized
/// document never leaves a connection held on the table.
struct Held<'a> {
    table: &'a Table,
    conn: ConnId,
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        let _ = self.table.conns.close(self.table.owner, self.conn);
    }
}

impl CimdFetch for ConnectorFetch {
    fn fetch<'a>(
        &'a self,
        url: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>> {
        Box::pin(async move {
            let table = (self.table)()
                .ok_or_else(|| "no connection table is installed for the fetch".to_string())?;
            let failed = |e: ConnError| format!("fetching `{url}` failed: {e}");
            // THE NEED, declared once on the table and read back after: a table that will not
            // carry it (no transport serves `https`) refuses here, and the client is unknown.
            if table.declared.declared(table.owner, DOCUMENT_NEED) != Some(Ok(())) {
                table
                    .declared
                    .declare(table.owner, DOCUMENT_NEED, &document_need(), None, None)
                    .map_err(failed)?;
            }
            let deadline = tokio::time::Instant::now() + FETCH_TIMEOUT;
            // The request's head words: the method, and the path and query the framer writes,
            // read by the one shared URL reader (a URL with no path asks for `/`).
            let path = busbar_contract::net::parse_url(url)
                .map_err(|e| format!("`{url}` does not read as a URL: {e}"))?
                .path;
            let conn = table
                .conns
                .open(
                    table.owner,
                    DOCUMENT_NEED,
                    &OpenDesc {
                        target: url,
                        timeout_ms: u64::try_from(FETCH_TIMEOUT.as_millis()).unwrap_or(u64::MAX),
                        method: b"GET",
                        head_target: path.as_bytes(),
                        ..OpenDesc::default()
                    },
                )
                .map_err(failed)?;
            let held = Held {
                table: &table,
                conn,
            };
            read_document(&held, url, deadline).await
        })
    }
}

/// The far end's answer, read to its completion: its status judged on the head (a 3xx is refused:
/// the document lives at the `client_id`; anything else that is not a success is refused), then
/// the body under the document ceiling, enforced while the bytes arrive, so an oversized document
/// costs the cap and not itself. ONE deadline for the whole exchange.
async fn read_document(
    held: &Held<'_>,
    url: &str,
    deadline: tokio::time::Instant,
) -> Result<Vec<u8>, String> {
    let (table, conn) = (held.table, held.conn);
    let mut buf = vec![0u8; 16 * 1024];
    let mut status: Option<u32> = None;
    let mut body: Vec<u8> = Vec::new();
    loop {
        let piece = tokio::time::timeout_at(
            deadline,
            std::future::poll_fn(|cx| table.conns.poll_read(table.owner, conn, cx, &mut buf)),
        )
        .await
        .map_err(|_| format!("fetching `{url}` failed: the fetch's deadline passed"))?
        .map_err(|e| format!("fetching `{url}` failed: {e}"))?;
        match piece.kind {
            PieceKind::Completion => break,
            // The head: its status, judged before any body byte is kept. A fields piece after the
            // body is the far end's trailers, which carry no document bytes.
            PieceKind::Fields | PieceKind::HookReply => {
                if status.is_none() {
                    if let Some(code) = piece.status_code {
                        if (300..400).contains(&code) {
                            return Err(format!(
                                "`{url}` answered HTTP {code}, a redirect; a client metadata \
                                 document is served at its client_id and is never followed \
                                 elsewhere"
                            ));
                        }
                        if !(200..300).contains(&code) {
                            return Err(format!("`{url}` answered HTTP {code}"));
                        }
                        status = Some(code);
                    }
                }
            }
            PieceKind::Body => {
                if status.is_none() {
                    return Err(format!("`{url}` answered no status before its body"));
                }
                if body.len() + piece.len > MAX_DOCUMENT_BYTES {
                    return Err(format!(
                        "`{url}` answered a body over the {MAX_DOCUMENT_BYTES}-byte document \
                         ceiling"
                    ));
                }
                body.extend_from_slice(&buf[..piece.len]);
            }
        }
    }
    if status.is_none() {
        return Err(format!("`{url}` answered no status"));
    }
    Ok(body)
}

/// Does this `client_id` name a metadata document at all? HTTPS, a parseable authority, and no
/// fragment. Anything else is an ordinary opaque identifier and gets the ordinary answer:
/// unknown unless registered.
fn is_cimd_client_id(client_id: &str) -> bool {
    client_id.starts_with("https://")
        && !client_id.contains('#')
        && busbar_contract::net::parse_url(client_id).is_ok_and(|p| !p.userinfo)
}

/// VALIDATE THE DOCUMENT AND MATERIALISE THE CLIENT, under the operator's ceiling.
///
/// These checks ARE busbar's CIMD validator. `oauth-as` 1.0.0 carries its own behind the `cimd`
/// feature, which this tree does not enable: enabling it adds the
/// `client_id_metadata_document_supported` member to the served RFC 8414 document, which is a
/// customer-visible byte change (see the module docs). The fetch, the seam and the ceiling are
/// busbar's either way.
/// (Owner ruling 2026-09-30, N3: a statement of fact, not a deferral.)
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
                // A `\` or a userinfo gives the URI two hosts: the one a reader splitting at `/`
                // names and the one the browser dials. The consent screen must name the host the
                // code goes to, so a URI whose two readings differ is refused outright.
                Some(s)
                    if s.contains('\\')
                        || busbar_contract::net::parse_url(s).is_ok_and(|p| p.userinfo) =>
                {
                    Err("redirect_uris entries carry no backslash and no userinfo".to_string())
                }
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
    /// The operator's `oauth_as.clients:`, by `client_id`. Answered before anything else: the
    /// config is the operator's own word on who these clients are.
    provisioned: HashMap<String, Arc<Client>>,
    /// What the consent screen needs to show of each RFC 9126 pushed request that has not been
    /// redeemed, keyed by `request_uri`. See [`Pushed`].
    pushed: Mutex<HashMap<String, Pushed>>,
}

/// WHAT A PUSHED REQUEST ASKS FOR, kept for the consent screen alone.
///
/// Under PAR the authorization URL carries only `client_id` and `request_uri`, and `oauth-as` has
/// one way to read a pushed record: an atomic take, which SPENDS it. The screen has to name the
/// scope and the redirect host before anyone has decided, and FAPI 2.0 s5.3.2.2 NOTE 3 has the
/// handle spent at the point of authorization, not of loading the page. So the store notes these
/// three values when the record is pushed and forgets them when it is taken or expires; the record
/// itself, and the single use the library enforces on it, are untouched.
#[derive(Clone, Debug)]
pub(crate) struct Pushed {
    pub(crate) client_id: String,
    pub(crate) scope: String,
    pub(crate) redirect_uri: String,
    expires_at: std::time::SystemTime,
    /// Whether the consent screen has shown this request already.
    shown: bool,
}

impl CimdStore {
    pub(crate) fn new(
        inner: MemoryStorage,
        ceiling: ScopeSet,
        fetcher: Arc<dyn CimdFetch>,
        provisioned: Vec<Client>,
    ) -> Self {
        Self {
            inner,
            ceiling,
            fetcher: RwLock::new(fetcher),
            provisioned: provisioned
                .into_iter()
                .map(|c| (c.client_id.as_str().to_string(), Arc::new(c)))
                .collect(),
            pushed: Mutex::new(HashMap::new()),
        }
    }

    /// The summary of a pushed request that is still live, or `None`.
    pub(crate) fn pushed(&self, request_uri: &str) -> Option<Pushed> {
        let pushed = self.pushed.lock().unwrap_or_else(|p| p.into_inner());
        pushed
            .get(request_uri)
            .filter(|p| p.expires_at > std::time::SystemTime::now())
            .cloned()
    }

    /// Mark a live pushed request as shown, answering whether it already had been.
    pub(crate) fn mark_pushed_shown(&self, request_uri: &str) -> bool {
        let mut pushed = self.pushed.lock().unwrap_or_else(|p| p.into_inner());
        pushed
            .get_mut(request_uri)
            .map(|p| std::mem::replace(&mut p.shown, true))
            .unwrap_or(false)
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
        // A PROVISIONED client first: `oauth_as.clients:` is the operator's config.
        if let Some(found) = self.provisioned.get(client_id.as_str()) {
            return Ok(Some(Arc::clone(found)));
        }
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

    // RFC 9126 PAR and the RFC 7523 / RFC 9449 replay ledger: delegated, so the atomic single use
    // of a `request_uri` and the compare-and-set of a replay `jti` stay the properties
    // `MemoryStorage` holds and `storage_conformance` checks. The PAR pair also keeps the consent
    // screen's summary ([`Pushed`]) in step with the record.
    fn put_pushed_authorization_request(
        &self,
        record: oauth_as::par::PushedAuthorizationRequest,
    ) -> impl Future<Output = Result<WriteOutcome, StorageError>> + Send {
        let request_uri = record.request_uri.clone();
        let summary = Pushed {
            client_id: record.client_id.as_str().to_string(),
            scope: record.scope.clone().unwrap_or_default(),
            redirect_uri: record.redirect_uri.clone().unwrap_or_default(),
            expires_at: record.expires_at,
            shown: false,
        };
        let put = self.inner.put_pushed_authorization_request(record);
        async move {
            let outcome = put.await?;
            if matches!(outcome, WriteOutcome::Applied) {
                self.pushed
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .insert(request_uri, summary);
            }
            Ok(outcome)
        }
    }

    fn take_pushed_authorization_request(
        &self,
        request_uri: &str,
    ) -> impl Future<Output = Result<Option<oauth_as::par::PushedAuthorizationRequest>, StorageError>>
           + Send {
        let take = self.inner.take_pushed_authorization_request(request_uri);
        let request_uri = request_uri.to_string();
        async move {
            let taken = take.await?;
            if taken.is_some() {
                self.pushed
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .remove(&request_uri);
            }
            Ok(taken)
        }
    }

    fn claim_replay_id(
        &self,
        id: &str,
        expires_at: std::time::SystemTime,
    ) -> impl Future<Output = Result<bool, StorageError>> + Send {
        self.inner.claim_replay_id(id, expires_at)
    }

    fn sweep_expired(
        &self,
        now: std::time::SystemTime,
    ) -> impl Future<Output = Result<u64, StorageError>> + Send {
        self.pushed
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|_, p| p.expires_at > now);
        self.inner.sweep_expired(now)
    }
}

#[cfg(test)]
#[path = "tests/cimd_tests.rs"]
mod cimd_tests;
