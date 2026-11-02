// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use busbar_contract::abi::store::OpId;
use busbar_contract::kinds::RecordBytes;
use busbar_contract::records::{MeteringDelta, PlaneRecordRef, PlaneSelector, UsageDelta};
use busbar_contract::store_calls::{StoreCall, StoreCalls, StoreFailure};

use oauth_as::client::{Client, ClientAuth, ClientId};
use oauth_as::grant::GrantType;
use oauth_as::scope::ScopeSet;

use crate::config::OauthAsCfg;

const REDIRECT_URI: &str = "http://127.0.0.1:9999/cb";

const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

const SCOPE: &str = "read";
const CLIENT_ID: &str = "flow-test-client";

/// One stored cookie: the three attributes that decide whether it is sent, and the value.
#[derive(Clone, Debug)]
struct Cookie {
    name: String,
    value: String,
    path: String,
    secure: bool,
}

/// A cookie store that applies RFC 6265 §5.1.4 and refuses to guess.
///
/// Deliberately hand-written and deliberately small. A general-purpose jar would be a dependency,
/// and — more to the point — this file's whole claim is that the cookie reaches the paths that read
/// it, so the code deciding that has to be visible in the test rather than three crates away.
#[derive(Default)]
pub(crate) struct Jar {
    cookies: Vec<Cookie>,
    /// `true` when the connection this jar is used over is a secure one. `Secure` cookies are
    /// stored only when it is (RFC 6265bis §5.5), which is what makes a `Secure` attribute on a
    /// plain-HTTP deployment show up here as a missing cookie rather than as nothing at all.
    secure_connection: bool,
}

impl Jar {
    pub(crate) fn new(secure_connection: bool) -> Self {
        Self {
            cookies: Vec::new(),
            secure_connection,
        }
    }

    pub(crate) fn store(&mut self, set_cookie: &str, request_path: &str) {
        let mut parts = set_cookie.split(';');
        let (name, value) = parts
            .next()
            .and_then(|nv| nv.split_once('='))
            .map(|(n, v)| (n.trim().to_string(), v.trim().to_string()))
            .expect("a Set-Cookie header has a name=value pair");
        let mut path: Option<String> = None;
        let mut secure = false;
        let mut max_age: Option<i64> = None;
        for attr in parts {
            let (k, v) = match attr.split_once('=') {
                Some((k, v)) => (k.trim(), v.trim()),
                None => (attr.trim(), ""),
            };
            match k.to_ascii_lowercase().as_str() {
                "path" => path = Some(v.to_string()),
                "secure" => secure = true,
                "max-age" => max_age = v.parse().ok(),
                _ => {}
            }
        }

        let path = match path {
            Some(p) if p.starts_with('/') => p,
            _ => default_path(request_path),
        };
        self.cookies.retain(|c| !(c.name == name && c.path == path));
        if max_age == Some(0) {
            return;
        }
        if secure && !self.secure_connection {
            return;
        }
        self.cookies.push(Cookie {
            name,
            value,
            path,
            secure,
        });
    }

    pub(crate) fn header_for(&self, request_path: &str) -> Option<String> {
        let sent: Vec<String> = self
            .cookies
            .iter()
            .filter(|c| path_matches(request_path, &c.path))
            .filter(|c| self.secure_connection || !c.secure)
            .map(|c| format!("{}={}", c.name, c.value))
            .collect();
        (!sent.is_empty()).then(|| sent.join("; "))
    }
}

fn default_path(request_path: &str) -> String {
    if !request_path.starts_with('/') {
        return "/".to_string();
    }
    match request_path.rfind('/') {
        Some(0) | None => "/".to_string(),
        Some(i) => request_path[..i].to_string(),
    }
}

fn path_matches(request_path: &str, cookie_path: &str) -> bool {
    if request_path == cookie_path {
        return true;
    }
    if !request_path.starts_with(cookie_path) {
        return false;
    }
    cookie_path.ends_with('/') || request_path[cookie_path.len()..].starts_with('/')
}

#[test]
fn the_jar_refuses_to_send_a_cookie_to_a_sibling_path() {
    let mut jar = Jar::new(false);
    jar.store("s=abc; Path=/consent; HttpOnly", "/consent");
    assert_eq!(jar.header_for("/consent").as_deref(), Some("s=abc"));
    assert_eq!(
        jar.header_for("/consent/sub").as_deref(),
        Some("s=abc"),
        "path-match is a prefix match at a `/` boundary"
    );
    assert_eq!(
        jar.header_for("/authorize"),
        None,
        "`/consent` and `/authorize` are SIBLINGS: a cookie scoped to one is never sent to the other"
    );
    assert_eq!(
        jar.header_for("/consentious"),
        None,
        "a prefix that does not end at a `/` boundary is not a path-match"
    );

    let mut jar = Jar::new(false);
    jar.store("s=one; Path=/authorize", "/authorize");
    jar.store("s=two; Path=/consent", "/consent");
    assert_eq!(jar.header_for("/authorize").as_deref(), Some("s=one"));
    assert_eq!(jar.header_for("/consent").as_deref(), Some("s=two"));
    assert_eq!(jar.header_for("/token"), None);
    assert_eq!(jar.header_for("/"), None);

    let mut jar = Jar::new(false);
    jar.store("s=abc; Path=/consent; Secure", "/consent");
    assert_eq!(jar.header_for("/consent"), None);
    let mut jar = Jar::new(true);
    jar.store("s=abc; Path=/consent; Secure", "/consent");
    assert_eq!(jar.header_for("/consent").as_deref(), Some("s=abc"));

    let mut jar = Jar::new(false);
    jar.store("s=abc; Path=/consent", "/consent");
    jar.store("s=; Path=/consent; Max-Age=0", "/consent");
    assert_eq!(jar.header_for("/consent"), None);
}

#[test]
fn the_session_cookie_carries_exactly_the_attributes_it_should() {
    use crate::config::AsIdentity;
    use crate::routes::session_cookies;

    for (issuer, secure_expected) in [
        ("https://as.example.com", true),
        ("http://127.0.0.1:8080", false),
        ("https://gw.example.com/tenant-a", true),
    ] {
        let cfg = OauthAsCfg {
            issuer: issuer.to_string(),
            signing_key: None,
            key_id: None,
            default_grant: Vec::new(),
            access_token_ttl_secs: None,
            refresh_token_ttl_secs: None,
            fapi2: false,
            clients: Vec::new(),
        };
        let id = AsIdentity::from_cfg(&cfg).expect("valid issuer");
        let cookies = session_cookies(&id, "deadbeef");

        let mut jar = Jar::new(secure_expected);
        for c in &cookies {
            jar.store(c, id.consent_path());
        }
        assert!(
            jar.header_for(id.authorize_path()).is_some(),
            "the approval resolver reads this cookie at {}: {cookies:?}",
            id.authorize_path()
        );
        assert!(
            jar.header_for(id.consent_path()).is_some(),
            "the consent POST reads this cookie at {}: {cookies:?}",
            id.consent_path()
        );

        assert_eq!(
            jar.header_for(id.token_path()),
            None,
            "the token endpoint must never see the operator's session: {cookies:?}"
        );
        assert_eq!(jar.header_for(id.jwks_path()), None);
        assert_eq!(jar.header_for(id.metadata_path()), None);
        assert_eq!(
            jar.header_for("/v1/chat/completions"),
            None,
            "a data-plane path on the same origin must never see it either"
        );
        assert_eq!(jar.header_for("/"), None);

        for c in &cookies {
            assert!(c.contains("; HttpOnly"), "script must not read it: {c}");
            assert!(
                c.contains("; SameSite=Lax"),
                "Strict would withhold the cookie on the cross-site top-level navigation that \
                 STARTS this flow: {c}"
            );
            assert_eq!(
                c.contains("; Secure"),
                secure_expected,
                "`Secure` follows the issuer's scheme ({issuer}): {c}"
            );
            assert!(
                c.contains(&format!(
                    "; Max-Age={}",
                    crate::consent::SESSION_TTL.as_secs()
                )),
                "the cookie's lifetime is the SESSION's lifetime, from the same constant: {c}"
            );
            assert!(
                !c.contains("Path=/;") && !c.ends_with("Path=/"),
                "`Path=/` is the widening this fix exists to avoid: {c}"
            );
        }
    }
}

async fn register_defaulting_to(plane: &crate::plane::AsPlane, client_id: &str, default: &[&str]) {
    let scopes = ScopeSet::from_tokens(default.iter().copied()).expect("scope");
    plane
        .server()
        .register_client(Client {
            client_id: ClientId::new(client_id),
            auth: ClientAuth::Public,
            grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
            redirect_uris: vec![REDIRECT_URI.to_string()],
            allowed_scopes: scopes.clone(),
            default_scopes: scopes,
            name: None,
            registration: None,
        })
        .await
        .expect("register client");
}

#[tokio::test]
async fn a_metadata_document_client_naming_no_scope_is_shown_the_default_it_is_granted() {
    let plane = owner_plane();
    plane
        .server()
        .store()
        .set_fetcher(Arc::new(StubDocumentHost(serde_json::json!({
            "client_id":CIMD_CLIENT_ID,"redirect_uris":[REDIRECT_URI],
            "token_endpoint_auth_method":"none","client_name":"an agent",
        }))));
    let shown = plane
        .granted_scope(CIMD_CLIENT_ID, None)
        .await
        .expect("the actual owner resolves the consent grant");
    let token = approved_token(&plane, CIMD_CLIENT_ID).await;
    let record = plane
        .server()
        .introspect(&token.access_token)
        .await
        .expect("introspection must not fail")
        .expect("the freshly minted token must be live");
    let granted = record.scope.to_string();
    assert_eq!(granted, SCOPE, "the operator's default_grant is granted");
    assert_eq!(
        shown, granted,
        "the consent grant resolver must name the scope the approval grants"
    );
}

#[tokio::test]
async fn a_failed_default_scope_lookup_refuses_consent_and_recovers() {
    let fault = Arc::new(FailClientRead {
        inner: crate::testkit::store_calls(),
        fail_next: AtomicBool::new(false),
    });
    let plane = owner_plane_with_store(fault.clone());
    register_defaulting_to(&plane, CLIENT_ID, &[SCOPE]).await;
    fault.fail_next.store(true, Ordering::SeqCst);
    assert!(
        plane.granted_scope(CLIENT_ID, None).await.is_err(),
        "an unresolved grant cannot be approved"
    );
    let shown = plane
        .granted_scope(CLIENT_ID, None)
        .await
        .expect("the lookup recovers");
    let token = approved_token(&plane, CLIENT_ID).await;
    let record = plane
        .server()
        .introspect(&token.access_token)
        .await
        .unwrap()
        .unwrap();
    let granted = record.scope.to_string();
    assert_eq!(
        granted, SCOPE,
        "the recovered request grants its registered default"
    );
    assert_eq!(
        shown, granted,
        "the recovered consent resolver names the grant"
    );
    const EMPTY: &str = "flow-test-shared-empty-default";
    register_defaulting_to(&plane, EMPTY, &[]).await;
    let shown = plane.granted_scope(EMPTY, None).await.unwrap();
    let token = approved_token(&plane, EMPTY).await;
    let record = plane
        .server()
        .introspect(&token.access_token)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        record.scope.to_string(),
        "",
        "a successfully resolved empty default remains valid"
    );
    assert_eq!(shown, "");
}

struct FailClientRead {
    inner: Arc<dyn StoreCalls>,
    fail_next: AtomicBool,
}

impl StoreCalls for FailClientRead {
    fn supports_record_transaction(&self) -> bool {
        self.inner.supports_record_transaction()
    }

    fn record_transaction<'a>(
        &'a self,
        request: &'a busbar_contract::abi::sdk::store::conditional::Request,
    ) -> StoreCall<'a, busbar_contract::abi::sdk::store::conditional::Decision> {
        self.inner.record_transaction(request)
    }

    fn add_usage_batch<'a>(
        &'a self,
        op: OpId,
        cells: &'a [(&'a str, u64, UsageDelta)],
    ) -> StoreCall<'a, ()> {
        self.inner.add_usage_batch(op, cells)
    }

    fn add_metering_batch<'a>(
        &'a self,
        op: OpId,
        deltas: &'a [MeteringDelta],
    ) -> StoreCall<'a, ()> {
        self.inner.add_metering_batch(op, deltas)
    }

    fn record_put<'a>(
        &'a self,
        schema: &'a str,
        key: &'a [u8],
        value: &'a RecordBytes,
    ) -> StoreCall<'a, ()> {
        self.inner.record_put(schema, key, value)
    }

    fn record_get<'a>(
        &'a self,
        schema: &'a str,
        key: &'a [u8],
    ) -> StoreCall<'a, Option<RecordBytes>> {
        if schema == format!("{}bucket.atomic.v1", crate::shared::LABEL)
            && self.fail_next.swap(false, Ordering::SeqCst)
        {
            return Box::pin(async {
                Err(StoreFailure::Failed(
                    "client lookup unavailable".to_string(),
                ))
            });
        }
        self.inner.record_get(schema, key)
    }

    fn record_scan<'a>(
        &'a self,
        schema: &'a str,
        prefix: &'a [u8],
        limit: u32,
    ) -> StoreCall<'a, Vec<(Vec<u8>, RecordBytes)>> {
        self.inner.record_scan(schema, prefix, limit)
    }

    fn upsert_plane_record<'a>(&'a self, record: PlaneRecordRef<'a>) -> StoreCall<'a, ()> {
        self.inner.upsert_plane_record(record)
    }

    fn get_plane_record<'a>(
        &'a self,
        kind: &'a str,
        id: &'a str,
    ) -> StoreCall<'a, Option<Vec<u8>>> {
        if kind == format!("{}bucket", crate::shared::LABEL)
            && self.fail_next.swap(false, Ordering::SeqCst)
        {
            return Box::pin(async {
                Err(StoreFailure::Failed(
                    "client lookup unavailable".to_string(),
                ))
            });
        }
        self.inner.get_plane_record(kind, id)
    }

    fn append_plane_record<'a>(
        &'a self,
        op: OpId,
        record: PlaneRecordRef<'a>,
    ) -> StoreCall<'a, ()> {
        self.inner.append_plane_record(op, record)
    }

    fn list_plane_records<'a>(
        &'a self,
        kind: &'a str,
        selector: &'a PlaneSelector<'a>,
    ) -> StoreCall<'a, Vec<Vec<u8>>> {
        self.inner.list_plane_records(kind, selector)
    }

    fn delete_plane_record<'a>(&'a self, kind: &'a str, id: &'a str) -> StoreCall<'a, ()> {
        self.inner.delete_plane_record(kind, id)
    }

    fn redeem_plane_token<'a>(
        &'a self,
        kind: &'a str,
        token: &'a str,
        expires_at: u64,
        now: u64,
    ) -> StoreCall<'a, bool> {
        self.inner.redeem_plane_token(kind, token, expires_at, now)
    }

    fn plane_token_live<'a>(
        &'a self,
        kind: &'a str,
        token: &'a str,
        expires_at: u64,
        now: u64,
    ) -> StoreCall<'a, bool> {
        self.inner.plane_token_live(kind, token, expires_at, now)
    }
}

const CIMD_CLIENT_ID: &str = "https://client.example/oauth-client";

struct StubDocumentHost(serde_json::Value);

impl crate::cimd::CimdFetch for StubDocumentHost {
    fn fetch<'a>(
        &'a self,
        url: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, String>> + Send + 'a>>
    {
        Box::pin(async move {
            if url == CIMD_CLIENT_ID {
                Ok(serde_json::to_vec(&self.0).expect("the stub document serialises"))
            } else {
                Err(format!("no document at `{url}`"))
            }
        })
    }
}

#[tokio::test]
async fn a_client_id_metadata_document_admits_a_client_end_to_end() {
    let plane = owner_plane();
    plane
        .server()
        .store()
        .set_fetcher(Arc::new(StubDocumentHost(serde_json::json!({
            "client_id":CIMD_CLIENT_ID,"redirect_uris":[REDIRECT_URI],
            "token_endpoint_auth_method":"none","client_name":"an agent","scope":SCOPE,
        }))));
    let token = approved_token(&plane, CIMD_CLIENT_ID).await;
    let record = plane
        .server()
        .introspect(&token.access_token)
        .await
        .expect("introspection must not fail")
        .expect("the freshly minted token must be live");
    assert_eq!(
        record.client_id.as_str(),
        CIMD_CLIENT_ID,
        "the URL is the client's identity, verbatim"
    );
    assert_eq!(record.scope.to_string(), SCOPE);
}

fn owner_plane() -> Arc<crate::plane::AsPlane> {
    owner_plane_with_store(crate::testkit::store_calls())
}

fn owner_plane_with_store(store: Arc<dyn StoreCalls>) -> Arc<crate::plane::AsPlane> {
    let config = OauthAsCfg {
        issuer: "https://as.example.com".into(),
        default_grant: vec![SCOPE.into()],
        ..Default::default()
    };
    let block = serde_yaml::to_value(config).expect("owner config serializes");
    crate::plane::seam_build::<crate::NoConnections>(
        &block,
        Vec::new(),
        Vec::new(),
        None,
        Some(store),
    )
    .expect("the actual owner seam builds over the supplied Store product")
    .downcast::<crate::plane::AsPlane>()
    .unwrap_or_else(|_| panic!("the owner seam returns its plane"))
}

async fn approved_token(
    plane: &crate::plane::AsPlane,
    client_id: &str,
) -> oauth_as::token::TokenResponse {
    let request = oauth_as::authorization::AuthorizationRequest::from_pairs([
        ("response_type", "code"),
        ("client_id", client_id),
        ("redirect_uri", REDIRECT_URI),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
    ]);
    let validated = plane
        .server()
        .validate_authorization_request(&request)
        .await
        .expect("request validates");
    let code = plane
        .server()
        .issue_authorization_code(oauth_as::server::UserApproval::granted(
            &validated,
            "busbar-operator",
        ))
        .await
        .expect("the approved owner request mints a code");
    plane
        .server()
        .token(oauth_as::server::TokenRequest::AuthorizationCode {
            client_id: ClientId::new(client_id),
            client_secret: None,
            code: code.code,
            redirect_uri: Some(REDIRECT_URI.into()),
            code_verifier: Some(VERIFIER.into()),
        })
        .await
        .expect("the approved code exchanges")
}

#[tokio::test]
async fn an_unencodable_login_redirect_fails_closed_rather_than_proceeding() {
    use http_body_util::BodyExt as _;
    let config = OauthAsCfg {
        issuer: "http://bad\rhost/defect2".into(),
        default_grant: vec![SCOPE.into()],
        ..Default::default()
    };
    let identity = crate::config::AsIdentity::from_cfg(&config)
        .expect("the owner identity retains the malformed host input");
    let response = crate::consent::login_redirect(
        &identity.consent_url(),
        "/defect2/authorize?response_type=code&client_id=flow-test-client",
    );
    let status = response.status().as_u16();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("response body")
        .to_bytes();
    let body = String::from_utf8(bytes.to_vec()).expect("response text");
    assert_eq!(status,502,
        "an unencodable login redirect must fail closed with a 502, not proceed as though the resource owner had answered: got {status} {body}");
}

#[tokio::test]
async fn issued_code_tokens_retain_their_live_private_records_for_each_default_scope() {
    let block = serde_yaml::to_value(OauthAsCfg {
        issuer: "https://as.example.com".into(),
        default_grant: vec!["read".into(), "write".into()],
        ..Default::default()
    })
    .unwrap();
    let opaque = crate::plane::seam_build::<crate::NoConnections>(
        &block,
        Vec::new(),
        Vec::new(),
        None,
        Some(crate::testkit::store_calls()),
    )
    .expect("the actual owner seam builds over the supplied Store product");
    let plane = opaque
        .downcast::<crate::plane::AsPlane>()
        .unwrap_or_else(|_| panic!("the owner seam returns its own plane"));
    for (index, default) in ["read", "read write", ""].into_iter().enumerate() {
        let client_id = format!("owner-record-{index}");
        let scope = ScopeSet::parse(default).expect("scope");
        plane
            .server()
            .register_client(Client {
                client_id: ClientId::new(&client_id),
                auth: ClientAuth::Public,
                grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
                redirect_uris: vec![REDIRECT_URI.into()],
                allowed_scopes: scope.clone(),
                default_scopes: scope,
                name: None,
                registration: None,
            })
            .await
            .expect("the real owner storage registers the client");
        let request = oauth_as::authorization::AuthorizationRequest::from_pairs([
            ("response_type", "code"),
            ("client_id", client_id.as_str()),
            ("redirect_uri", REDIRECT_URI),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
        ]);
        let validated = plane
            .server()
            .validate_authorization_request(&request)
            .await
            .expect("request validates");
        let code = plane
            .server()
            .issue_authorization_code(oauth_as::server::UserApproval::granted(
                &validated,
                "busbar-operator",
            ))
            .await
            .expect("the approved owner request mints a code");
        let token = plane
            .server()
            .token(oauth_as::server::TokenRequest::AuthorizationCode {
                client_id: ClientId::new(&client_id),
                client_secret: None,
                code: code.code,
                redirect_uri: Some(REDIRECT_URI.into()),
                code_verifier: Some(VERIFIER.into()),
            })
            .await
            .expect("the approved code exchanges");
        let record = plane
            .server()
            .introspect(&token.access_token)
            .await
            .expect("introspection must not fail")
            .expect("the freshly minted token must be live");
        assert_eq!(record.client_id.as_str(), client_id);
        assert_eq!(record.subject.as_deref(), Some("busbar-operator"));
        assert_eq!(record.scope.to_string(), default);
    }
}
