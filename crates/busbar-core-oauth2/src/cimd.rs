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
//! store, so there is nothing to revoke, nothing to sweep, and nothing a restart resurrects.
//!
//! ## Fetched once, held a while, never more than a few at a time
//!
//! The URL is a stranger's, and `/authorize` and `/token` take no credential, so the fetch is
//! bounded ([`Documents`]): a validated document answers for its client for [`DOCUMENT_TTL`] (at
//! most [`MAX_CACHED_DOCUMENTS`] held), concurrent requests naming one uncached document wait on
//! ONE fetch, at most [`MAX_FETCHES_PER_SITE`] fetches run at once for the documents of one site
//! ([`site_of`]: a host's registrable domain under the Public Suffix List, so one owner's many
//! hosts are one site and the tenants of a shared suffix are each their own; an IPv6 literal's /64,
//! the block one end site is handed whole), the documents at address literals share ONE such
//! share between them ([`ADDRESS_LITERALS`]), and at most [`MAX_CONCURRENT_FETCHES`] run at once in
//! all, a request waiting up to [`PERMIT_WAIT`] for one of those. Past that a request naming an
//! uncached document reads as an unknown client, as every other fetch failure does.
//!
//! What a fetch can be held by, and for how long, is what decides who can hold them all:
//!
//! * A far end that never answers (an address that drops the connection attempt, a name whose
//!   resolution stalls) needs nothing the caller owns, and it holds its fetch for at most
//!   [`ANSWER_DEADLINE`]: the far end must answer its response head by then. Addresses are
//!   plentiful, so all of them together hold one site's share.
//! * A far end that answers in time and then sends its document slowly holds its fetch up to
//!   [`FETCH_TIMEOUT`], and one site holds at most its own share.
//!
//! So holding every fetch takes `MAX_CONCURRENT_FETCHES / MAX_FETCHES_PER_SITE` shares at once, at
//! most one of them the addresses': the rest are registrable domains, each one the caller serves
//! slowly or one whose name stalls, named afresh at least every [`ANSWER_DEADLINE`]. No number of
//! addresses does it. A request names no caller this plane can see, so no bound here is per caller.
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

/// How long the far end has to answer its response head. A document host that is up answers in a
/// fraction of this; one that never answers (an address that drops the connection attempt, a name
/// whose resolution stalls) lets its fetch go here rather than at [`FETCH_TIMEOUT`], so a caller
/// cannot hold the fetches with far ends it does not even have to own.
pub(crate) const ANSWER_DEADLINE: std::time::Duration = std::time::Duration::from_secs(3);

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

/// How long a validated document answers for its client before it is fetched again.
pub(crate) const DOCUMENT_TTL: std::time::Duration = std::time::Duration::from_secs(300);

/// The most validated documents held at once.
pub(crate) const MAX_CACHED_DOCUMENTS: usize = 1024;

/// The most document fetches in flight at once.
pub(crate) const MAX_CONCURRENT_FETCHES: usize = 16;

/// The most document fetches in flight at once for the documents of one site ([`site_of`]).
pub(crate) const MAX_FETCHES_PER_SITE: usize = 2;

/// How long a request naming an uncached document waits for a fetch permit before its client reads
/// as unknown.
pub(crate) const PERMIT_WAIT: std::time::Duration = std::time::Duration::from_secs(1);

/// The share every document at an ADDRESS LITERAL takes as well as its own site's. A caller can name
/// any number of addresses it does not own (any one that drops the connection attempt will do), so
/// counted one site each they could hold every fetch; counted together they hold one site's share.
/// Not a host name (it has a space), so no site is ever this.
pub(crate) const ADDRESS_LITERALS: &str = "address literals";

/// The site a document URL's host belongs to, lower-cased: what one owner holds as one unit.
///
/// * A NAME is its registrable domain under the Public Suffix List (`psl`): the hosts one owner
///   can mint freely (`a.attacker.example`, `b.attacker.example`) are one site, and the tenants of a
///   shared suffix (`alice.github.io`, `bob.github.io`, `a.co.uk`) are each their own, so one
///   tenant's slow documents never take another's share. A name that is itself a public suffix is
///   its own site.
/// * An IPv6 literal is its /64: one end site is handed a /64 at the least, and every address in it
///   is that site's to use, so the addresses of one /64 are one site.
/// * An IPv4 literal is its own site: each address is held on its own.
pub(crate) fn site_of(url: &str) -> String {
    let host = busbar_contract::net::parse_url(url)
        .map(|p| p.host.to_ascii_lowercase())
        .unwrap_or_default();
    let host = host.trim_end_matches('.');
    if let Ok(v6) = host.parse::<std::net::Ipv6Addr>() {
        let s = v6.segments();
        return format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3]);
    }
    if host.parse::<std::net::Ipv4Addr>().is_ok() {
        return host.to_string();
    }
    psl::domain_str(host).unwrap_or(host).to_string()
}

/// THE DOCUMENTS ONE SERVER HOLDS AND FETCHES: the validated ones by URL, each until it expires;
/// the fetch in flight for each URL, which every concurrent request naming it waits on; and the
/// permits that bound how many fetches run at once.
pub(crate) struct Documents {
    held: Mutex<HashMap<String, (Arc<Client>, std::time::Instant)>>,
    flights: Mutex<HashMap<String, Flight>>,
    permits: tokio::sync::Semaphore,
    /// Fetches in flight per site ([`site_of`]).
    sites: Mutex<HashMap<String, usize>>,
}

/// One URL's fetch in flight: the client its document validated to, or `None`, once it lands.
type Flight = Arc<tokio::sync::OnceCell<Option<Arc<Client>>>>;

/// One request's hold on a URL's flight. However the request ends, answered or dropped mid-wait,
/// the last hold to go takes the flight out of the map, so a fetch every waiter abandoned leaves no
/// entry behind. Every hold is taken and let go under the map's lock, so the count it reads there is
/// every holder's.
struct Joined<'a> {
    flights: &'a Mutex<HashMap<String, Flight>>,
    url: &'a str,
    flight: Option<Flight>,
}

impl Joined<'_> {
    fn cell(&self) -> &Flight {
        self.flight
            .as_ref()
            .expect("a hold keeps its flight until it is dropped")
    }
}

impl Drop for Joined<'_> {
    fn drop(&mut self) {
        let mut flights = self.flights.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(flight) = self.flight.take() {
            // The map's reference and this one: no other request holds the flight.
            if Arc::strong_count(&flight) == 2
                && flights
                    .get(self.url)
                    .is_some_and(|f| Arc::ptr_eq(f, &flight))
            {
                flights.remove(self.url);
            }
            drop(flight);
        }
    }
}

impl Default for Documents {
    fn default() -> Self {
        Self {
            held: Mutex::new(HashMap::new()),
            flights: Mutex::new(HashMap::new()),
            permits: tokio::sync::Semaphore::new(MAX_CONCURRENT_FETCHES),
            sites: Mutex::new(HashMap::new()),
        }
    }
}

/// The shares a document's fetch takes: its site's ([`site_of`]), and [`ADDRESS_LITERALS`] as well
/// when its host is an address.
fn shares_of(url: &str) -> Vec<String> {
    let literal = busbar_contract::net::parse_url(url)
        .is_ok_and(|p| p.host.parse::<std::net::IpAddr>().is_ok());
    let mut shares = vec![site_of(url)];
    if literal {
        shares.push(ADDRESS_LITERALS.to_string());
    }
    shares
}

/// A fetch's shares of the fetches ([`shares_of`]), held while it runs.
struct SiteShare<'a> {
    sites: &'a Mutex<HashMap<String, usize>>,
    shares: Vec<String>,
}

impl Drop for SiteShare<'_> {
    fn drop(&mut self) {
        let mut sites = self.sites.lock().unwrap_or_else(|p| p.into_inner());
        for share in &self.shares {
            if let Some(n) = sites.get_mut(share) {
                *n -= 1;
                if *n == 0 {
                    sites.remove(share);
                }
            }
        }
    }
}

impl Documents {
    /// Every share `url`'s fetch takes ([`shares_of`]), or `None` when one of them already holds
    /// [`MAX_FETCHES_PER_SITE`].
    fn site_share(&self, url: &str) -> Option<SiteShare<'_>> {
        let shares = shares_of(url);
        let mut sites = self.sites.lock().unwrap_or_else(|p| p.into_inner());
        if shares
            .iter()
            .any(|share| sites.get(share).is_some_and(|n| *n >= MAX_FETCHES_PER_SITE))
        {
            return None;
        }
        for share in &shares {
            *sites.entry(share.clone()).or_insert(0) += 1;
        }
        Some(SiteShare {
            sites: &self.sites,
            shares,
        })
    }

    /// The validated document's client for `url`, while it has not expired.
    fn held(&self, url: &str) -> Option<Arc<Client>> {
        let held = self.held.lock().unwrap_or_else(|p| p.into_inner());
        held.get(url)
            .filter(|(_, until)| *until > std::time::Instant::now())
            .map(|(client, _)| Arc::clone(client))
    }

    /// The fetch in flight for `url`, joined, or a new one, held while the caller waits on it.
    fn flight<'a>(&'a self, url: &'a str) -> Joined<'a> {
        let mut flights = self.flights.lock().unwrap_or_else(|p| p.into_inner());
        Joined {
            flights: &self.flights,
            url,
            flight: Some(Arc::clone(flights.entry(url.to_string()).or_default())),
        }
    }

    /// The fetch for `url` answered `answer`: a client it validated is held.
    fn hold(&self, url: &str, answer: Option<&Arc<Client>>) {
        let Some(client) = answer else { return };
        let now = std::time::Instant::now();
        let mut held = self.held.lock().unwrap_or_else(|p| p.into_inner());
        if held.len() >= MAX_CACHED_DOCUMENTS {
            held.retain(|_, (_, until)| *until > now);
        }
        if held.len() >= MAX_CACHED_DOCUMENTS {
            if let Some(oldest) = held
                .iter()
                .min_by_key(|(_, (_, until))| *until)
                .map(|(k, _)| k.clone())
            {
                held.remove(&oldest);
            }
        }
        held.insert(url.to_string(), (Arc::clone(client), now + DOCUMENT_TTL));
    }
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
#[cfg(test)]
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
            let started = tokio::time::Instant::now();
            let deadline = started + FETCH_TIMEOUT;
            let answer_by = started + ANSWER_DEADLINE;
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
            read_document(&held, url, answer_by, deadline).await
        })
    }
}

/// The far end's answer, read to its completion: its status judged on the head (a 3xx is refused:
/// the document lives at the `client_id`; anything else that is not a success is refused), then
/// the body under the document ceiling, enforced while the bytes arrive, so an oversized document
/// costs the cap and not itself. The head must arrive by `answer_by` ([`ANSWER_DEADLINE`]); the
/// whole exchange must end by `deadline`.
async fn read_document(
    held: &Held<'_>,
    url: &str,
    answer_by: tokio::time::Instant,
    deadline: tokio::time::Instant,
) -> Result<Vec<u8>, String> {
    let (table, conn) = (held.table, held.conn);
    let mut buf = vec![0u8; 16 * 1024];
    let mut status: Option<u32> = None;
    let mut body: Vec<u8> = Vec::new();
    loop {
        let (until, missed) = match status {
            None => (
                answer_by.min(deadline),
                "the far end did not answer within the answer deadline",
            ),
            Some(_) => (deadline, "the fetch's deadline passed"),
        };
        let piece = tokio::time::timeout_at(
            until,
            std::future::poll_fn(|cx| table.conns.poll_read(table.owner, conn, cx, &mut buf)),
        )
        .await
        .map_err(|_| format!("fetching `{url}` failed: {missed}"))?
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

/// The longest client identifier this server fetches (the draft's bound, as `oauth-as` holds it).
pub(crate) const MAX_CLIENT_ID_URL_BYTES: usize = 2048;

/// Does this `client_id` name a metadata document at all? Section 3 of the client-ID metadata
/// document draft, every clause: printable ASCII and at most [`MAX_CLIENT_ID_URL_BYTES`], `https`
/// in lower case, a host, a PATH (`https://client.example` has none), no `.` or `..` path segment
/// (two strings would name one client while section 4.1 compares them byte for byte), no query,
/// no fragment, no userinfo. As `oauth-as`'s own validator holds it, the authority carries no
/// backslash and no percent-escape, and a host that ends in a number is a canonical dotted-quad:
/// a WHATWG reader of the URL would otherwise reach another host than the one read here. Anything
/// else is an ordinary opaque identifier and gets the ordinary answer: unknown unless registered.
fn is_cimd_client_id(client_id: &str) -> bool {
    if client_id.len() > MAX_CLIENT_ID_URL_BYTES
        || !client_id.bytes().all(|b| (0x21..=0x7e).contains(&b))
        || client_id.contains('#')
    {
        return false;
    }
    let Some(rest) = client_id.strip_prefix("https://") else {
        return false;
    };
    let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, path) = rest.split_at(authority_end);
    if authority.is_empty()
        || authority.contains(['@', '\\', '%'])
        || !path.starts_with('/')
        || path.contains('?')
        || path
            .split('/')
            .any(|segment| segment == "." || segment == "..")
    {
        return false;
    }
    let host = match authority.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or_default(),
        None => authority.split(':').next().unwrap_or_default(),
    };
    if host.is_empty()
        || (!host.contains(':')
            && ends_in_a_number(host)
            && host.parse::<std::net::Ipv4Addr>().is_err())
    {
        return false;
    }
    busbar_contract::net::parse_url(client_id).is_ok_and(|p| !p.userinfo)
}

/// Whether a host's last label is all digits or `0x` hex: a WHATWG reader takes it for an IPv4
/// address however it is spelled (`2130706433`, `0x7f000001`, `127.1`).
fn ends_in_a_number(host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    match host.rsplit('.').next() {
        None | Some("") => false,
        Some(last) => match last.strip_prefix("0x").or_else(|| last.strip_prefix("0X")) {
            Some(hex) => hex.chars().all(|c| c.is_ascii_hexdigit()),
            None => last.chars().all(|c| c.is_ascii_digit()),
        },
    }
}

/// Whether a redirect URI is one the server can ever match (RFC 6749 section 3.1.2): ABSOLUTE (a
/// scheme, its first character a letter, then letters, digits, `+`, `-` or `.`, then `:`), no
/// fragment, nothing outside printable ASCII.
fn is_absolute_uri(value: &str) -> bool {
    let Some((scheme, _)) = value.split_once(':') else {
        return false;
    };
    scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        && scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
        && value
            .bytes()
            .all(|b| b != b'#' && (0x21..=0x7e).contains(&b))
}

/// VALIDATE THE DOCUMENT AND MATERIALISE THE CLIENT, under the operator's ceiling.
///
/// These checks ARE busbar's CIMD validator. `oauth-as` 1.0.0 carries its own behind the `cimd`
/// feature, which this tree does not enable: enabling it adds the
/// `client_id_metadata_document_supported` member to the served RFC 8414 document, which is a
/// customer-visible byte change (see the module docs). The fetch, the seam and the ceiling are
/// busbar's either way.
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

    // Section 4.1: the document is world-readable, so it carries no shared secret; and a key
    // (`jwks`, `jwks_uri`) this server cannot register would leave a client its author believes
    // confidential registered as a public one. Refused, not dropped.
    for member in [
        "client_secret",
        "client_secret_expires_at",
        "jwks",
        "jwks_uri",
    ] {
        if doc.contains_key(member) {
            return Err(format!(
                "the document carries `{member}`; a metadata-document client is public by \
                 construction"
            ));
        }
    }

    // The redirect URIs come from the DOCUMENT, never from the request: `oauth-as` exact-matches
    // the request's `redirect_uri` against this list, which is what makes a stolen `client_id`
    // useless for sending a code anywhere the document's owner did not name.
    let redirect_uris: Vec<String> = match doc.get("redirect_uris").and_then(|v| v.as_array()) {
        Some(list) if list.len() > oauth_as::registration::MAX_REGISTERED_REDIRECT_URIS => {
            return Err(format!(
                "the document carries more than {} redirect_uris",
                oauth_as::registration::MAX_REGISTERED_REDIRECT_URIS
            ))
        }
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
                Some(s) if is_absolute_uri(s) => Ok(s.to_string()),
                _ => Err("redirect_uris entries must be absolute, fragment-free URIs".to_string()),
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
    /// What the server holds, carried from generation to generation ([`Records`]).
    records: Arc<Records>,
    /// The operator's `default_grant`, as the ceiling every materialised client lands under.
    ceiling: ScopeSet,
    /// Swappable so the flow tests can stand in a stub document host; production never swaps it.
    fetcher: RwLock<Arc<dyn CimdFetch>>,
    /// The operator's `oauth_as.clients:`, by `client_id`. Answered before anything else: the
    /// config is the operator's own word on who these clients are.
    provisioned: HashMap<String, Arc<Client>>,
    /// The metadata documents held and in flight ([`Documents`]).
    documents: Documents,
}

/// WHAT THE SERVER HOLDS: its records (clients registered, codes, tokens, refresh tokens, consents,
/// pushed requests, the replay ledger) and the consent screen's notes of the pushed requests. A
/// config reload builds a new server over the SAME records, so a reload voids none of them.
///
/// With the deployment's store reachable, the records are the store's ([`crate::shared`]) and every
/// node on that store serves one server; without one (no store is configured), they live in this
/// process.
pub(crate) struct Records {
    inner: Backend,
    /// What the consent screen needs to show of each RFC 9126 pushed request that has not been
    /// redeemed, keyed by `request_uri` (in-process records only; the store's are read from the
    /// pushed record itself). See [`Pushed`].
    pushed: Mutex<HashMap<String, Pushed>>,
    /// Every SELF-REGISTERED client this process's records hold, by `client_id`, with the instant
    /// until which it holds something: the latest expiry of any record written for it, or its
    /// registration (`None`: a record that never lapses). The sweep reclaims a client
    /// [`crate::policy::REGISTERED_CLIENT_IDLE`] past that instant. In-process records only: the
    /// store's sweep reads the same from each client's bucket (`shared`).
    registered: Mutex<HashMap<String, Option<std::time::SystemTime>>>,
}

impl Records {
    pub(crate) fn new(inner: MemoryStorage) -> Self {
        Self {
            inner: Backend::Memory(Box::new(inner)),
            pushed: Mutex::new(HashMap::new()),
            registered: Mutex::new(HashMap::new()),
        }
    }

    /// The records the deployment's store keeps, shared with every node on it.
    pub(crate) fn shared(shared: Arc<crate::shared::Shared>) -> Self {
        Self {
            inner: Backend::Shared(
                crate::shared::SharedStorage::new(Arc::clone(&shared)),
                shared,
            ),
            pushed: Mutex::new(HashMap::new()),
            registered: Mutex::new(HashMap::new()),
        }
    }

    /// `client` was written: when it is a self-registered client in this process's records, it is
    /// tracked, holding something from now.
    fn track(&self, client: &Client) {
        if self.store().is_some() || client.registration.is_none() {
            return;
        }
        let now = std::time::SystemTime::now();
        self.registered
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entry(client.client_id.as_str().to_string())
            .and_modify(|held| *held = held.map(|t| t.max(now)))
            .or_insert(Some(now));
    }

    /// A record lasting until `until` (`None`: it never lapses) was written for `client_id`: a
    /// tracked client holds something until then at least.
    fn holds(&self, client_id: &ClientId, until: Option<std::time::SystemTime>) {
        let mut registered = self.registered.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(held) = registered.get_mut(client_id.as_str()) {
            *held = match (*held, until) {
                (Some(a), Some(b)) => Some(a.max(b)),
                _ => None,
            };
        }
    }

    /// The tracked clients that have held nothing for [`crate::policy::REGISTERED_CLIENT_IDLE`] at
    /// `now`, taken out of the tracking.
    fn idle(&self, now: std::time::SystemTime) -> Vec<String> {
        let mut registered = self.registered.lock().unwrap_or_else(|p| p.into_inner());
        let idle: Vec<String> = registered
            .iter()
            .filter(|(_, held)| {
                held.is_some_and(|t| t + crate::policy::REGISTERED_CLIENT_IDLE <= now)
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in &idle {
            registered.remove(id);
        }
        idle
    }

    /// The store these records are kept in, when they are the deployment's.
    pub(crate) fn store(&self) -> Option<&Arc<crate::shared::Shared>> {
        match &self.inner {
            Backend::Memory(_) => None,
            Backend::Shared(_, shared) => Some(shared),
        }
    }
}

impl Default for Records {
    fn default() -> Self {
        Self::new(MemoryStorage::new())
    }
}

/// Where the records are: this process, or the deployment's store.
pub(crate) enum Backend {
    // Boxed: the in-process store is the large variant, and the enum is held per plane.
    Memory(Box<MemoryStorage>),
    Shared(crate::shared::SharedStorage, Arc<crate::shared::Shared>),
}

/// One `Storage` method, answered by whichever backend holds the records.
macro_rules! delegate {
    ($( fn $name:ident(&self $(, $arg:ident : $ty:ty)* ) -> $ret:ty; )*) => {
        $(
            async fn $name(&self $(, $arg: $ty)*) -> Result<$ret, StorageError> {
                match self {
                    Backend::Memory(m) => m.$name($($arg),*).await,
                    Backend::Shared(s, _) => s.$name($($arg),*).await,
                }
            }
        )*
    };
}

impl Storage for Backend {
    delegate! {
        fn get_client(&self, client_id: &ClientId) -> Option<Arc<Client>>;
        fn put_client(&self, client: Client) -> ();
        fn compare_and_swap_client(&self, expected: &Client, updated: Client) -> bool;
        fn delete_client(&self, client_id: &ClientId, window: RevocationWindow) -> bool;
        fn put_device_grant(&self, grant: DeviceGrant) -> ();
        fn get_device_grant(&self, device_code: &str) -> Option<DeviceGrant>;
        fn find_device_grant_by_user_code(&self, normalized_user_code: &str) -> Option<DeviceGrant>;
        fn take_device_grant(&self, device_code: &str) -> Option<DeviceGrant>;
        fn compare_and_swap_device_grant(&self, expected: &DeviceGrantState, updated: DeviceGrant) -> bool;
        fn put_authorization_code(&self, record: AuthorizationCodeRecord) -> ();
        fn compare_and_swap_authorization_code(&self, expected: &AuthorizationCodeState, updated: AuthorizationCodeRecord) -> bool;
        fn take_authorization_code(&self, code: &str) -> Option<AuthorizationCodeRecord>;
        fn put_pushed_authorization_request(&self, record: oauth_as::par::PushedAuthorizationRequest) -> WriteOutcome;
        fn take_pushed_authorization_request(&self, request_uri: &str) -> Option<oauth_as::par::PushedAuthorizationRequest>;
        fn put_token(&self, token: IssuedToken) -> WriteOutcome;
        fn get_token(&self, access_token: &str) -> Option<Arc<IssuedToken>>;
        fn delete_token(&self, access_token: &str) -> ();
        fn put_refresh_token(&self, record: RefreshTokenRecord) -> WriteOutcome;
        fn get_refresh_token(&self, refresh_token: &str) -> Option<Arc<RefreshTokenRecord>>;
        fn take_refresh_token(&self, refresh_token: &str) -> Option<RefreshTokenRecord>;
        fn revoke_token_family(&self, family_id: &str, window: RevocationWindow) -> u64;
        fn put_consent(&self, record: ConsentRecord) -> ();
        fn compare_and_swap_consent(&self, expected: Option<&ConsentRecord>, updated: ConsentRecord) -> bool;
        fn get_consent(&self, consent_id: &str) -> Option<Arc<ConsentRecord>>;
        fn find_consent(&self, client_id: &ClientId, subject: &str) -> Option<Arc<ConsentRecord>>;
        fn consents_for_subject(&self, subject: &str) -> Vec<Arc<ConsentRecord>>;
        fn revoke_consent(&self, consent_id: &str, window: RevocationWindow) -> u64;
        fn claim_replay_id(&self, id: &str, expires_at: std::time::SystemTime) -> bool;
        fn sweep_expired(&self, now: std::time::SystemTime) -> u64;
    }
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
    /// The pushed `scope`, `None` when the request named none (it is then granted the client's
    /// default, which is what the screen names).
    pub(crate) scope: Option<String>,
    pub(crate) redirect_uri: String,
    expires_at: std::time::SystemTime,
    /// Whether the consent screen has shown this request already.
    shown: bool,
}

impl CimdStore {
    #[cfg(test)]
    pub(crate) fn new(
        inner: MemoryStorage,
        ceiling: ScopeSet,
        fetcher: Arc<dyn CimdFetch>,
        provisioned: Vec<Client>,
    ) -> Self {
        Self::over(Arc::new(Records::new(inner)), ceiling, fetcher, provisioned)
    }

    /// The store over `records` an earlier generation may already hold.
    pub(crate) fn over(
        records: Arc<Records>,
        ceiling: ScopeSet,
        fetcher: Arc<dyn CimdFetch>,
        provisioned: Vec<Client>,
    ) -> Self {
        Self {
            records,
            ceiling,
            fetcher: RwLock::new(fetcher),
            provisioned: provisioned
                .into_iter()
                .map(|c| (c.client_id.as_str().to_string(), Arc::new(c)))
                .collect(),
            documents: Documents::default(),
        }
    }

    /// The summary of a pushed request that is still live, or `None`.
    pub(crate) async fn pushed(&self, request_uri: &str) -> Option<Pushed> {
        if let Some(store) = self.records.store() {
            return match store.pushed(request_uri).await {
                Ok(found) => found.map(|record| Pushed {
                    client_id: record.client_id.as_str().to_string(),
                    scope: record.scope.clone(),
                    redirect_uri: record.redirect_uri.clone().unwrap_or_default(),
                    expires_at: record.expires_at,
                    shown: false,
                }),
                Err(e) => {
                    tracing::debug!(error = %e, "oauth_as: the pushed request could not be read");
                    None
                }
            };
        }
        let pushed = self
            .records
            .pushed
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        pushed
            .get(request_uri)
            .filter(|p| p.expires_at > std::time::SystemTime::now())
            .cloned()
    }

    /// Mark a live pushed request as shown, answering whether it already had been.
    pub(crate) async fn mark_pushed_shown(&self, request_uri: &str) -> bool {
        if let Some(store) = self.records.store() {
            let until = self
                .pushed(request_uri)
                .await
                .map_or_else(std::time::SystemTime::now, |p| p.expires_at);
            return store
                .mark_pushed_shown(request_uri, until)
                .await
                .unwrap_or(false);
        }
        let mut pushed = self
            .records
            .pushed
            .lock()
            .unwrap_or_else(|p| p.into_inner());
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

impl CimdStore {
    /// One fetch of the document at `url`, validated: its client, or `None` (an unknown client)
    /// when the fetch is refused or fails, the document fails validation, or
    /// [`MAX_FETCHES_PER_SITE`] are already in flight for one of its shares ([`shares_of`]), or no
    /// fetch permit frees within [`PERMIT_WAIT`].
    async fn fetch_document(&self, url: &str) -> Option<Arc<Client>> {
        let Some(_share) = self.documents.site_share(url) else {
            tracing::debug!(
                client_id = url,
                "oauth_as: this site's client metadata document fetches are all in flight; the \
                 client is unknown"
            );
            return None;
        };
        let Ok(Ok(_permit)) =
            tokio::time::timeout(PERMIT_WAIT, self.documents.permits.acquire()).await
        else {
            tracing::debug!(
                client_id = url,
                "oauth_as: every client metadata document fetch is in flight; the client is \
                 unknown"
            );
            return None;
        };
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
                return None;
            }
        };
        match materialize(url, &body, &self.ceiling) {
            Ok(client) => Some(Arc::new(client)),
            Err(why) => {
                // Routine authz denial (a fetched document that fails validation), one per request —
                // `debug!`, not `warn!`, for the same reason as the fetch-failure arm above.
                tracing::debug!(
                    client_id = url,
                    %why,
                    "oauth_as: the client metadata document failed validation; the client is \
                     unknown"
                );
                None
            }
        }
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
        if let Some(found) = self.records.inner.get_client(client_id).await? {
            return Ok(Some(found));
        }
        let url = client_id.as_str();
        if !is_cimd_client_id(url) {
            return Ok(None);
        }
        if let Some(held) = self.documents.held(url) {
            return Ok(Some(held));
        }
        let joined = self.documents.flight(url);
        let answer = joined
            .cell()
            .get_or_init(|| self.fetch_document(url))
            .await
            .clone();
        self.documents.hold(url, answer.as_ref());
        drop(joined);
        Ok(answer)
    }

    // ── EVERYTHING BELOW DELEGATES VERBATIM. No logic, no logging, no reordering: the wrapper
    //    changes ONE read and must be invisible everywhere else, or the storage-conformance
    //    properties MemoryStorage holds (atomic take_*, compare-and-swap, the revocation barrier)
    //    would silently stop being this store's. The one addition is bookkeeping BESIDE the
    //    delegation, never in its way: each write that gives a self-registered client something to
    //    hold notes until when ([`Records::holds`]), and the sweep reclaims the clients that have
    //    held nothing for the idle period. ──

    fn put_client(&self, client: Client) -> impl Future<Output = Result<(), StorageError>> + Send {
        self.records.track(&client);
        self.records.inner.put_client(client)
    }

    fn compare_and_swap_client(
        &self,
        expected: &Client,
        updated: Client,
    ) -> impl Future<Output = Result<bool, StorageError>> + Send {
        self.records
            .inner
            .compare_and_swap_client(expected, updated)
    }

    fn delete_client(
        &self,
        client_id: &ClientId,
        window: RevocationWindow,
    ) -> impl Future<Output = Result<bool, StorageError>> + Send {
        self.records
            .registered
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(client_id.as_str());
        self.records.inner.delete_client(client_id, window)
    }

    fn put_device_grant(
        &self,
        grant: DeviceGrant,
    ) -> impl Future<Output = Result<(), StorageError>> + Send {
        self.records.holds(&grant.client_id, Some(grant.expires_at));
        self.records.inner.put_device_grant(grant)
    }

    fn get_device_grant(
        &self,
        device_code: &str,
    ) -> impl Future<Output = Result<Option<DeviceGrant>, StorageError>> + Send {
        self.records.inner.get_device_grant(device_code)
    }

    fn find_device_grant_by_user_code(
        &self,
        normalized_user_code: &str,
    ) -> impl Future<Output = Result<Option<DeviceGrant>, StorageError>> + Send {
        self.records
            .inner
            .find_device_grant_by_user_code(normalized_user_code)
    }

    fn take_device_grant(
        &self,
        device_code: &str,
    ) -> impl Future<Output = Result<Option<DeviceGrant>, StorageError>> + Send {
        self.records.inner.take_device_grant(device_code)
    }

    fn compare_and_swap_device_grant(
        &self,
        expected: &DeviceGrantState,
        updated: DeviceGrant,
    ) -> impl Future<Output = Result<bool, StorageError>> + Send {
        self.records
            .holds(&updated.client_id, Some(updated.expires_at));
        self.records
            .inner
            .compare_and_swap_device_grant(expected, updated)
    }

    fn put_authorization_code(
        &self,
        record: AuthorizationCodeRecord,
    ) -> impl Future<Output = Result<(), StorageError>> + Send {
        self.records
            .holds(&record.client_id, Some(record.expires_at));
        self.records.inner.put_authorization_code(record)
    }

    fn compare_and_swap_authorization_code(
        &self,
        expected: &AuthorizationCodeState,
        updated: AuthorizationCodeRecord,
    ) -> impl Future<Output = Result<bool, StorageError>> + Send {
        self.records
            .holds(&updated.client_id, Some(updated.expires_at));
        self.records
            .inner
            .compare_and_swap_authorization_code(expected, updated)
    }

    fn take_authorization_code(
        &self,
        code: &str,
    ) -> impl Future<Output = Result<Option<AuthorizationCodeRecord>, StorageError>> + Send {
        self.records.inner.take_authorization_code(code)
    }

    fn put_token(
        &self,
        token: IssuedToken,
    ) -> impl Future<Output = Result<WriteOutcome, StorageError>> + Send {
        self.records.holds(&token.client_id, Some(token.expires_at));
        self.records.inner.put_token(token)
    }

    fn get_token(
        &self,
        access_token: &str,
    ) -> impl Future<Output = Result<Option<Arc<IssuedToken>>, StorageError>> + Send {
        self.records.inner.get_token(access_token)
    }

    fn delete_token(
        &self,
        access_token: &str,
    ) -> impl Future<Output = Result<(), StorageError>> + Send {
        self.records.inner.delete_token(access_token)
    }

    fn put_refresh_token(
        &self,
        record: RefreshTokenRecord,
    ) -> impl Future<Output = Result<WriteOutcome, StorageError>> + Send {
        self.records.holds(&record.client_id, record.expires_at);
        self.records.inner.put_refresh_token(record)
    }

    fn get_refresh_token(
        &self,
        refresh_token: &str,
    ) -> impl Future<Output = Result<Option<Arc<RefreshTokenRecord>>, StorageError>> + Send {
        self.records.inner.get_refresh_token(refresh_token)
    }

    fn take_refresh_token(
        &self,
        refresh_token: &str,
    ) -> impl Future<Output = Result<Option<RefreshTokenRecord>, StorageError>> + Send {
        self.records.inner.take_refresh_token(refresh_token)
    }

    fn revoke_token_family(
        &self,
        family_id: &str,
        window: RevocationWindow,
    ) -> impl Future<Output = Result<u64, StorageError>> + Send {
        self.records.inner.revoke_token_family(family_id, window)
    }

    fn put_consent(
        &self,
        record: ConsentRecord,
    ) -> impl Future<Output = Result<(), StorageError>> + Send {
        self.records.holds(&record.client_id, None);
        self.records.inner.put_consent(record)
    }

    fn compare_and_swap_consent(
        &self,
        expected: Option<&ConsentRecord>,
        updated: ConsentRecord,
    ) -> impl Future<Output = Result<bool, StorageError>> + Send {
        self.records.holds(&updated.client_id, None);
        self.records
            .inner
            .compare_and_swap_consent(expected, updated)
    }

    fn get_consent(
        &self,
        consent_id: &str,
    ) -> impl Future<Output = Result<Option<Arc<ConsentRecord>>, StorageError>> + Send {
        self.records.inner.get_consent(consent_id)
    }

    fn find_consent(
        &self,
        client_id: &ClientId,
        subject: &str,
    ) -> impl Future<Output = Result<Option<Arc<ConsentRecord>>, StorageError>> + Send {
        self.records.inner.find_consent(client_id, subject)
    }

    fn consents_for_subject(
        &self,
        subject: &str,
    ) -> impl Future<Output = Result<Vec<Arc<ConsentRecord>>, StorageError>> + Send {
        self.records.inner.consents_for_subject(subject)
    }

    fn revoke_consent(
        &self,
        consent_id: &str,
        window: RevocationWindow,
    ) -> impl Future<Output = Result<u64, StorageError>> + Send {
        self.records.inner.revoke_consent(consent_id, window)
    }

    // RFC 9126 PAR and the RFC 7523 / RFC 9449 replay ledger: delegated, so the atomic single use
    // of a `request_uri` and the compare-and-set of a replay `jti` stay the properties
    // `MemoryStorage` holds and `storage_conformance` checks. The PAR pair also keeps the consent
    // screen's summary ([`Pushed`]) in step with the record.
    fn put_pushed_authorization_request(
        &self,
        record: oauth_as::par::PushedAuthorizationRequest,
    ) -> impl Future<Output = Result<WriteOutcome, StorageError>> + Send {
        self.records
            .holds(&record.client_id, Some(record.expires_at));
        let request_uri = record.request_uri.clone();
        let summary = Pushed {
            client_id: record.client_id.as_str().to_string(),
            scope: record.scope.clone(),
            redirect_uri: record.redirect_uri.clone().unwrap_or_default(),
            expires_at: record.expires_at,
            shown: false,
        };
        let put = self.records.inner.put_pushed_authorization_request(record);
        async move {
            let outcome = put.await?;
            if matches!(outcome, WriteOutcome::Applied) && self.records.store().is_none() {
                self.records
                    .pushed
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
        let take = self
            .records
            .inner
            .take_pushed_authorization_request(request_uri);
        let request_uri = request_uri.to_string();
        async move {
            let taken = take.await?;
            if taken.is_some() {
                self.records
                    .pushed
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
        self.records.inner.claim_replay_id(id, expires_at)
    }

    fn sweep_expired(
        &self,
        now: std::time::SystemTime,
    ) -> impl Future<Output = Result<u64, StorageError>> + Send {
        self.records
            .pushed
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|_, p| p.expires_at > now);
        let sweep = self.records.inner.sweep_expired(now);
        async move {
            let mut removed = sweep.await?;
            // The self-registered clients that have held nothing for the idle period go, each
            // as a deletion: what it held has lapsed, so its barrier needs to bar nothing past now.
            for id in self.records.idle(now) {
                let window = RevocationWindow {
                    recorded_at: now,
                    until: now,
                };
                if self
                    .records
                    .inner
                    .delete_client(&ClientId::new(id.as_str()), window)
                    .await?
                {
                    removed += 1;
                }
            }
            Ok(removed)
        }
    }
}

#[cfg(test)]
#[path = "tests/cimd_tests.rs"]
mod cimd_tests;
