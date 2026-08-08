// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A minimal HTTP host for black-box conformance runs. This is NOT a production server: the
//! crate is a library and the real host owns HTTP, TLS, and persistence. This example exists so
//! an external conformance harness can drive the library over the wire exactly as a third-party
//! client would.
//!
//! Launch contract (what `conformance-serve.sh` provides to the harness):
//!
//! * binds the address in `OAUTH_AS_ADDR` (default `127.0.0.1:8914`);
//! * serves RFC 8414 metadata at `/.well-known/oauth-authorization-server`;
//! * with `OAUTH_AS_CONFORMANCE_SEED=1` seeds two deterministic clients
//!   (`conformance-public`, `conformance-confidential`) and AUTO-APPROVES every valid
//!   authorization request as user `conformance-user`; a POST of form field `user_code` to the
//!   verification URI approves that device authorization for the same user.
//!
//! The server is deliberately single-threaded and closes every connection after one response:
//! conformance suites run their requests sequentially, and sequential handling keeps this
//! example free of any HTTP-framework dependency.

use std::collections::HashMap;
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use oauth_as::{
    AuthorizationServer, AuthorizeParams, AuthorizeRejection, Client, ClientAuth, ClientId,
    ErrorCode, ErrorResponse, GrantType, MemoryStorage, ScopeSet, ServerConfig, TokenRequest,
};

const CONFORMANCE_SUBJECT: &str = "conformance-user";

fn main() {
    let addr = std::env::var("OAUTH_AS_ADDR").unwrap_or_else(|_| "127.0.0.1:8914".to_string());
    let seed = std::env::var("OAUTH_AS_CONFORMANCE_SEED").as_deref() == Ok("1");
    let issuer = format!("http://{addr}");

    let mut config = ServerConfig::new(issuer.clone(), format!("{issuer}/device"));
    config.poll_interval = Duration::from_secs(1); // keep conformance poll loops fast
    let server = AuthorizationServer::new(config, MemoryStorage::new());

    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("tokio current-thread runtime");

    if seed {
        rt.block_on(seed_clients(&server));
        eprintln!("conformance seed: registered conformance-public and conformance-confidential");
    }

    let listener = TcpListener::bind(&addr).unwrap_or_else(|e| panic!("bind {addr}: {e}"));
    eprintln!("oauth-as conformance server listening on {issuer} (seed={seed})");

    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
        let response = match read_request(&mut stream) {
            Some(req) => rt.block_on(route(&server, &issuer, seed, &req)),
            None => Response::text(400, "malformed HTTP request"),
        };
        let _ = response.write_to(&mut stream);
    }
}

async fn seed_clients(server: &AuthorizationServer<MemoryStorage>) {
    // The seeded fixtures the conformance contract names, verbatim.
    server
        .register_client(Client {
            client_id: ClientId::new("conformance-public"),
            auth: ClientAuth::Public,
            grant_types: vec![GrantType::AuthorizationCode, GrantType::DeviceCode],
            redirect_uris: vec!["http://127.0.0.1:8917/cb".to_string()],
            allowed_scopes: ScopeSet::parse("read write").expect("seed scopes"),
            default_scopes: ScopeSet::empty(),
            name: Some("Conformance public client".into()),
        })
        .await
        .expect("seed conformance-public");
    server
        .register_client(Client {
            client_id: ClientId::new("conformance-confidential"),
            auth: ClientAuth::ConfidentialSecret {
                secret: "conformance-secret-0123456789abcdef".to_string(),
            },
            grant_types: vec![GrantType::AuthorizationCode, GrantType::DeviceCode],
            redirect_uris: vec!["http://127.0.0.1:8917/cb".to_string()],
            allowed_scopes: ScopeSet::parse("read write").expect("seed scopes"),
            default_scopes: ScopeSet::empty(),
            name: Some("Conformance confidential client".into()),
        })
        .await
        .expect("seed conformance-confidential");
}

// ── tiny HTTP plumbing ───────────────────────────────────────────────────────────────────────

struct Request {
    method: String,
    path: String,
    query: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(&name.to_ascii_lowercase()).map(|s| &**s)
    }
}

struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Response {
    fn new(status: u16, content_type: &str, body: Vec<u8>) -> Self {
        Response {
            status,
            headers: vec![("Content-Type".into(), content_type.into())],
            body,
        }
    }

    fn json(status: u16, value: &serde_json::Value) -> Self {
        Response::new(status, "application/json", value.to_string().into_bytes())
    }

    fn text(status: u16, body: &str) -> Self {
        Response::new(
            status,
            "text/plain; charset=utf-8",
            body.as_bytes().to_vec(),
        )
    }

    fn redirect(location: &str) -> Self {
        Response {
            status: 302,
            headers: vec![("Location".into(), location.into())],
            body: Vec::new(),
        }
    }

    fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    fn write_to(&self, stream: &mut TcpStream) -> std::io::Result<()> {
        let reason = match self.status {
            200 => "OK",
            302 => "Found",
            400 => "Bad Request",
            401 => "Unauthorized",
            404 => "Not Found",
            405 => "Method Not Allowed",
            503 => "Service Unavailable",
            _ => "Internal Server Error",
        };
        let mut head = format!("HTTP/1.1 {} {reason}\r\n", self.status);
        for (name, value) in &self.headers {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        head.push_str(&format!(
            "Content-Length: {}\r\nConnection: close\r\n\r\n",
            self.body.len()
        ));
        stream.write_all(head.as_bytes())?;
        stream.write_all(&self.body)?;
        stream.flush()
    }
}

fn read_request(stream: &mut TcpStream) -> Option<Request> {
    // Read the head byte-by-byte until CRLFCRLF (requests here are tiny), then the body.
    let mut head = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 64 * 1024 {
            return None;
        }
        match stream.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => return None,
        }
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let mut lines = head.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split(' ');
    let method = parts.next()?.to_string();
    let target = parts.next()?;
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target.to_string(), String::new()),
    };
    let mut headers = HashMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    let content_length: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        stream.read_exact(&mut body).ok()?;
    }
    Some(Request {
        method,
        path,
        query,
        headers,
        body,
    })
}

fn parse_form(data: &[u8]) -> HashMap<String, String> {
    url::form_urlencoded::parse(data)
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

/// The client credentials a token-plane request presented: from the HTTP Basic header when
/// present (RFC 6749 section 2.3.1; credentials are form-urlencoded inside the header),
/// otherwise from the form body.
fn client_credentials(
    req: &Request,
    form: &HashMap<String, String>,
) -> (Option<String>, Option<String>) {
    if let Some(auth) = req.header("authorization") {
        if let Some(b64) = auth.strip_prefix("Basic ") {
            use base64::Engine as _;
            if let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(b64.trim()) {
                let raw = String::from_utf8_lossy(&raw).into_owned();
                if let Some((id, secret)) = raw.split_once(':') {
                    return (Some(form_urldecode(id)), Some(form_urldecode(secret)));
                }
            }
        }
        // A malformed Authorization header is a failed authentication attempt.
        return (None, None);
    }
    (
        form.get("client_id").cloned(),
        form.get("client_secret").cloned(),
    )
}

/// Percent-decode one form-urlencoded token (RFC 6749 section 2.3.1 encodes Basic credentials
/// this way). The seeded conformance credentials contain no reserved characters, so this only
/// needs to be correct for tokens without embedded `=`/`&`.
fn form_urldecode(s: &str) -> String {
    url::form_urlencoded::parse(s.as_bytes())
        .map(|(k, v)| {
            if v.is_empty() {
                k.into_owned()
            } else {
                format!("{k}={v}")
            }
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn error_json(err: &ErrorResponse) -> Response {
    Response::json(
        err.http_status(),
        &serde_json::to_value(err).expect("error body serializes"),
    )
}

/// Token-endpoint error, with the RFC 6749 section 5.2 WWW-Authenticate on a 401 when the
/// client attempted Authorization-header authentication.
fn token_error(req: &Request, err: &ErrorResponse) -> Response {
    let resp = error_json(err);
    if err.http_status() == 401 && req.header("authorization").is_some() {
        resp.with_header(
            "WWW-Authenticate",
            "Basic realm=\"oauth-authorization-server\"",
        )
    } else {
        resp
    }
}

// ── routing ──────────────────────────────────────────────────────────────────────────────────

async fn route(
    server: &AuthorizationServer<MemoryStorage>,
    issuer: &str,
    seed: bool,
    req: &Request,
) -> Response {
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/.well-known/oauth-authorization-server") => metadata(issuer),
        ("GET", "/authorize") => authorize(server, seed, req).await,
        ("POST", "/token") => token(server, req).await,
        ("POST", "/device_authorization") => device_authorization(server, req).await,
        ("GET", "/device") => Response::text(200, "enter your code (POST user_code to approve)"),
        ("POST", "/device") => approve_device(server, seed, req).await,
        _ => Response::text(404, "not found"),
    }
}

fn metadata(issuer: &str) -> Response {
    Response::json(
        200,
        &serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"),
            "device_authorization_endpoint": format!("{issuer}/device_authorization"),
            "response_types_supported": ["code"],
            "grant_types_supported": [
                "authorization_code",
                "refresh_token",
                "urn:ietf:params:oauth:grant-type:device_code",
            ],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "none"],
        }),
    )
}

async fn authorize(
    server: &AuthorizationServer<MemoryStorage>,
    seed: bool,
    req: &Request,
) -> Response {
    let q = parse_form(req.query.as_bytes());
    let params = AuthorizeParams {
        response_type: q.get("response_type").cloned(),
        client_id: q.get("client_id").cloned(),
        redirect_uri: q.get("redirect_uri").cloned(),
        scope: q.get("scope").cloned(),
        state: q.get("state").cloned(),
        code_challenge: q.get("code_challenge").cloned(),
        code_challenge_method: q.get("code_challenge_method").cloned(),
    };
    if !seed {
        // Without the seeded auto-approval there is no authenticated user to act for.
        return Response::text(
            503,
            "interactive authorization requires a host UI; \
             run with OAUTH_AS_CONFORMANCE_SEED=1 for auto-approval",
        );
    }
    match server.authorize(&params, CONFORMANCE_SUBJECT).await {
        Ok(grant) => {
            let mut url = match url::Url::parse(&grant.redirect_uri) {
                Ok(u) => u,
                Err(_) => return Response::text(500, "registered redirect_uri is not a URL"),
            };
            {
                let mut qp = url.query_pairs_mut();
                qp.append_pair("code", &grant.response.code);
                if let Some(state) = &grant.response.state {
                    qp.append_pair("state", state);
                }
            }
            Response::redirect(url.as_str())
        }
        Err(AuthorizeRejection::Unredirectable(err)) => error_json(&err),
        Err(AuthorizeRejection::Redirect {
            redirect_uri,
            state,
            error,
        }) => {
            let mut url = match url::Url::parse(&redirect_uri) {
                Ok(u) => u,
                Err(_) => return error_json(&error),
            };
            {
                let mut qp = url.query_pairs_mut();
                qp.append_pair("error", error.error.as_str());
                if let Some(d) = &error.error_description {
                    qp.append_pair("error_description", d);
                }
                if let Some(state) = &state {
                    qp.append_pair("state", state);
                }
            }
            Response::redirect(url.as_str())
        }
    }
}

async fn token(server: &AuthorizationServer<MemoryStorage>, req: &Request) -> Response {
    let form = parse_form(&req.body);
    let Some(grant_type) = form.get("grant_type") else {
        return token_error(
            req,
            &ErrorResponse::new(ErrorCode::InvalidRequest)
                .with_description("grant_type is required"),
        );
    };
    let (client_id, client_secret) = client_credentials(req, &form);
    let Some(client_id) = client_id else {
        return token_error(
            req,
            &ErrorResponse::new(ErrorCode::InvalidClient)
                .with_description("client authentication failed: no client identified"),
        );
    };
    let client_id = ClientId::new(client_id);

    let request = match grant_type.as_str() {
        "authorization_code" => TokenRequest::AuthorizationCode {
            client_id,
            client_secret,
            code: form.get("code").cloned().unwrap_or_default(),
            redirect_uri: form.get("redirect_uri").cloned(),
            code_verifier: form.get("code_verifier").cloned(),
        },
        "urn:ietf:params:oauth:grant-type:device_code" => TokenRequest::DeviceCode {
            client_id,
            client_secret,
            device_code: form.get("device_code").cloned().unwrap_or_default(),
        },
        "refresh_token" => {
            let scope = match form.get("scope") {
                None => None,
                Some(raw) => match ScopeSet::parse(raw) {
                    Ok(s) => Some(s),
                    Err(_) => {
                        return token_error(
                            req,
                            &ErrorResponse::new(ErrorCode::InvalidScope)
                                .with_description("scope is not a valid scope string"),
                        )
                    }
                },
            };
            let Some(refresh_token) = form.get("refresh_token").cloned() else {
                return token_error(
                    req,
                    &ErrorResponse::new(ErrorCode::InvalidRequest)
                        .with_description("refresh_token is required"),
                );
            };
            TokenRequest::RefreshToken {
                client_id,
                client_secret,
                refresh_token,
                scope,
            }
        }
        other => {
            return token_error(
                req,
                &ErrorResponse::new(ErrorCode::UnsupportedGrantType)
                    .with_description(format!("grant_type {other} is not supported")),
            )
        }
    };

    match server.token(request).await {
        Ok(token) => Response::json(
            200,
            &serde_json::to_value(&token).expect("token serializes"),
        )
        // RFC 6749 section 5.1: token responses MUST NOT be cached.
        .with_header("Cache-Control", "no-store")
        .with_header("Pragma", "no-cache"),
        Err(err) => token_error(req, &err),
    }
}

async fn device_authorization(
    server: &AuthorizationServer<MemoryStorage>,
    req: &Request,
) -> Response {
    let form = parse_form(&req.body);
    let (client_id, client_secret) = client_credentials(req, &form);
    let Some(client_id) = client_id else {
        return token_error(
            req,
            &ErrorResponse::new(ErrorCode::InvalidRequest)
                .with_description("client_id is required"),
        );
    };
    let scope = match form.get("scope") {
        None => None,
        Some(raw) => match ScopeSet::parse(raw) {
            Ok(s) => Some(s),
            Err(_) => {
                return token_error(
                    req,
                    &ErrorResponse::new(ErrorCode::InvalidScope)
                        .with_description("scope is not a valid scope string"),
                )
            }
        },
    };
    match server
        .device_authorization(
            &ClientId::new(client_id),
            client_secret.as_deref(),
            scope.as_ref(),
        )
        .await
    {
        Ok(resp) => Response::json(200, &serde_json::to_value(&resp).expect("serializes"))
            .with_header("Cache-Control", "no-store"),
        Err(err) => token_error(req, &err),
    }
}

async fn approve_device(
    server: &AuthorizationServer<MemoryStorage>,
    seed: bool,
    req: &Request,
) -> Response {
    if !seed {
        return Response::text(
            503,
            "device approval requires a host UI; \
             run with OAUTH_AS_CONFORMANCE_SEED=1 for auto-approval",
        );
    }
    let form = parse_form(&req.body);
    let Some(user_code) = form.get("user_code") else {
        return Response::text(400, "user_code form field is required");
    };
    match server.approve_device(user_code, CONFORMANCE_SUBJECT).await {
        Ok(()) => Response::text(200, "approved"),
        Err(e) => Response::text(400, &format!("not approved: {e}")),
    }
}
