// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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

pub(crate) const MAX_DOCUMENT_BYTES: usize = 5 * 1024;

pub(crate) const FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

pub(crate) const ANSWER_DEADLINE: std::time::Duration = std::time::Duration::from_secs(3);

pub(crate) trait CimdFetch: Send + Sync {
    fn fetch<'a>(
        &'a self,
        url: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>>;
}

pub(crate) const DOCUMENT_TTL: std::time::Duration = std::time::Duration::from_secs(300);

pub(crate) const MAX_CACHED_DOCUMENTS: usize = 1024;

pub(crate) const MAX_CONCURRENT_FETCHES: usize = 16;

pub(crate) const MAX_FETCHES_PER_SITE: usize = 2;

pub(crate) const PERMIT_WAIT: std::time::Duration = std::time::Duration::from_secs(1);

pub(crate) const ADDRESS_LITERALS: &str = "address literals";

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

pub(crate) struct Documents {
    held: Mutex<HashMap<String, (Arc<Client>, std::time::Instant)>>,
    flights: Mutex<HashMap<String, Flight>>,
    permits: tokio::sync::Semaphore,

    sites: Mutex<HashMap<String, usize>>,
}

type Flight = Arc<tokio::sync::OnceCell<Option<Arc<Client>>>>;

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

fn shares_of(url: &str) -> Vec<String> {
    let literal = busbar_contract::net::parse_url(url)
        .is_ok_and(|p| p.host.parse::<std::net::IpAddr>().is_ok());
    let mut shares = vec![site_of(url)];
    if literal {
        shares.push(ADDRESS_LITERALS.to_string());
    }
    shares
}

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

    fn held(&self, url: &str) -> Option<Arc<Client>> {
        let held = self.held.lock().unwrap_or_else(|p| p.into_inner());
        held.get(url)
            .filter(|(_, until)| *until > std::time::Instant::now())
            .map(|(client, _)| Arc::clone(client))
    }

    fn flight<'a>(&'a self, url: &'a str) -> Joined<'a> {
        let mut flights = self.flights.lock().unwrap_or_else(|p| p.into_inner());
        Joined {
            flights: &self.flights,
            url,
            flight: Some(Arc::clone(flights.entry(url.to_string()).or_default())),
        }
    }

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

pub(crate) const DOCUMENT_NEED: NeedId = NeedId(0);

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
        keep_mode: busbar_contract::abi::host::conn::connector::KEEP_NAMED,
        keep_response_headers: Vec::new(),
        deny_response_headers: Vec::new(),
    }
}

pub(crate) struct ConnectorFetch {
    pub(crate) table: fn() -> Option<Table>,
}

#[cfg(test)]
pub(crate) fn unconnected() -> Arc<dyn CimdFetch> {
    Arc::new(ConnectorFetch {
        table: <crate::NoConnections as crate::Connections>::table,
    })
}

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

            if table.declared.declared(table.owner, DOCUMENT_NEED) != Some(Ok(())) {
                table
                    .declared
                    .declare(table.owner, DOCUMENT_NEED, &document_need(), None, None)
                    .map_err(failed)?;
            }
            let started = tokio::time::Instant::now();
            let deadline = started + FETCH_TIMEOUT;
            let answer_by = started + ANSWER_DEADLINE;

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

pub(crate) const MAX_CLIENT_ID_URL_BYTES: usize = 2048;

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

fn materialize(url: &str, body: &[u8], ceiling: &ScopeSet) -> Result<Client, String> {
    let doc: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| format!("not JSON: {e}"))?;
    let Some(doc) = doc.as_object() else {
        return Err("the document is not a JSON object".to_string());
    };

    match doc.get("client_id").and_then(|v| v.as_str()) {
        Some(id) if id == url => {}
        Some(id) => {
            return Err(format!(
                "the document's client_id `{id}` is not the URL it was fetched from"
            ))
        }
        None => return Err("the document carries no client_id member".to_string()),
    }

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

    let name = doc.get("client_name").and_then(|v| v.as_str());
    if name.is_some_and(super::policy::name_impersonates_the_deployment) {
        return Err("the document's client_name impersonates this deployment".to_string());
    }

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

        registration: None,
    })
}

pub(crate) struct CimdStore {
    records: Arc<Records>,

    ceiling: ScopeSet,

    fetcher: RwLock<Arc<dyn CimdFetch>>,

    provisioned: HashMap<String, Arc<Client>>,

    documents: Documents,
}

pub(crate) struct Records {
    inner: Backend,

    pushed: Mutex<HashMap<String, Pushed>>,

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

    fn holds(&self, client_id: &ClientId, until: Option<std::time::SystemTime>) {
        let mut registered = self.registered.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(held) = registered.get_mut(client_id.as_str()) {
            *held = match (*held, until) {
                (Some(a), Some(b)) => Some(a.max(b)),
                _ => None,
            };
        }
    }

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

pub(crate) enum Backend {
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

    #[cfg(test)]
    pub(crate) fn set_fetcher(&self, fetcher: Arc<dyn CimdFetch>) {
        *self
            .fetcher
            .write()
            .expect("the fetcher lock is only written here and never across a panic") = fetcher;
    }

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
        if let Some(found) = self.provisioned.get(client_id.as_str()) {
            return Ok(Some(Arc::clone(found)));
        }

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
