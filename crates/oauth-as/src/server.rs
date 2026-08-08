// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The authorization server itself: configuration, the clock seam, and the grant state machines.
//!
//! Construction is the crate's ONLY allocation entry point (see the crate docs on zero cost until
//! enabled): a host that never constructs [`AuthorizationServer`] pays nothing. There is no
//! background task; every state transition happens inside a host-driven call.

use std::time::{Duration, SystemTime};

use crate::authorization::{
    AuthorizationCodeRecord, AuthorizationGrant, AuthorizationResponse, AuthorizeParams,
    AuthorizeRejection,
};
use crate::client::{Client, ClientId};
use crate::device::{
    normalize_user_code, DeviceAuthorizationResponse, DeviceGrant, DeviceGrantState,
};
use crate::error::{ErrorCode, ErrorResponse};
use crate::grant::GrantType;
use crate::scope::ScopeSet;
use crate::store::{Storage, StorageError};
use crate::token::{IssuedToken, RefreshTokenRecord, TokenResponse, TokenType};

/// The time source. Injectable so grant expiry and poll pacing are testable without sleeping;
/// production hosts use [`SystemClock`].
pub trait Clock: Send + Sync {
    /// The current instant.
    fn now(&self) -> SystemTime;
}

/// The real clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// Server configuration. [`ServerConfig::new`] fills RFC-shaped defaults; every field is public so
/// hosts override what they need.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerConfig {
    /// The issuer identifier (RFC 8414 `issuer`): the canonical `https` URL of this AS.
    pub issuer: String,
    /// Where a user goes to enter a device user code (RFC 8628 `verification_uri`).
    pub verification_uri: String,
    /// Whether device authorization responses include `verification_uri_complete`
    /// (`{verification_uri}?user_code={code}`).
    pub include_verification_uri_complete: bool,
    /// Device code and user code lifetime. Default 600 seconds.
    pub device_code_ttl: Duration,
    /// Initial minimum poll spacing (RFC 8628 `interval`). Default 5 seconds.
    pub poll_interval: Duration,
    /// How much a `slow_down` raises the required spacing. RFC 8628 section 3.5 mandates the
    /// client add 5 seconds, which is the default.
    pub slow_down_increment: Duration,
    /// Access token lifetime. Default 3600 seconds.
    pub access_token_ttl: Duration,
    /// Whether user-approved grants also issue a refresh token. Default true.
    pub issue_refresh_tokens: bool,
    /// Absolute refresh chain lifetime; `None` (the default) means no time expiry. Rotation
    /// preserves the chain's original expiry rather than sliding it.
    pub refresh_token_ttl: Option<Duration>,
    /// User code length in symbols, excluding the display hyphen. Default 8 (about 34 bits over
    /// the 20-symbol alphabet, the RFC 8628 section 6.1 example shape).
    pub user_code_length: usize,
    /// Authorization code lifetime. Default 60 seconds, well inside the 10-minute maximum RFC
    /// 6749 section 4.1.2 recommends; a code is redeemed by an immediate back-channel call, so a
    /// short life costs nothing and shrinks the interception window.
    pub authorization_code_ttl: Duration,
}

impl ServerConfig {
    /// A config with RFC-shaped defaults; `issuer` and `verification_uri` have no sane default and
    /// are required.
    pub fn new(issuer: impl Into<String>, verification_uri: impl Into<String>) -> Self {
        ServerConfig {
            issuer: issuer.into(),
            verification_uri: verification_uri.into(),
            include_verification_uri_complete: true,
            device_code_ttl: Duration::from_secs(600),
            poll_interval: Duration::from_secs(5),
            slow_down_increment: Duration::from_secs(5),
            access_token_ttl: Duration::from_secs(3600),
            issue_refresh_tokens: true,
            refresh_token_ttl: None,
            user_code_length: 8,
            authorization_code_ttl: Duration::from_secs(60),
        }
    }
}

/// A parsed token-endpoint request (RFC 6749 section 3.2). The host parses the form body and the
/// `Authorization` header into this; `client_secret` is `None` for public clients.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenRequest {
    /// RFC 6749 section 4.1.3: `grant_type=authorization_code`, with the RFC 7636 section 4.5
    /// `code_verifier` (REQUIRED here: this server never issues a code without a challenge).
    AuthorizationCode {
        /// The redeeming client.
        client_id: ClientId,
        /// The client secret, when the client is confidential.
        client_secret: Option<String>,
        /// The single-use authorization code.
        code: String,
        /// The `redirect_uri`, REQUIRED and identical when the authorization request carried one
        /// explicitly (RFC 6749 section 4.1.3).
        redirect_uri: Option<String>,
        /// The PKCE verifier (RFC 7636 section 4.5).
        code_verifier: Option<String>,
    },
    /// RFC 8628 section 3.4: `grant_type=urn:ietf:params:oauth:grant-type:device_code`.
    DeviceCode {
        /// The polling client.
        client_id: ClientId,
        /// The client secret, when the client is confidential.
        client_secret: Option<String>,
        /// The `device_code` from the device authorization response.
        device_code: String,
    },
    /// RFC 6749 section 6: `grant_type=refresh_token`, with OAuth 2.1 rotation.
    RefreshToken {
        /// The refreshing client.
        client_id: ClientId,
        /// The client secret, when the client is confidential.
        client_secret: Option<String>,
        /// The refresh token being redeemed (single use).
        refresh_token: String,
        /// Optional narrowing scope; widening is `invalid_scope`.
        scope: Option<ScopeSet>,
    },
}

/// Rejections for the host-driven verification-UI actions ([`AuthorizationServer::approve_device`]
/// / [`AuthorizationServer::deny_device`]). These are NOT wire errors: the RFC leaves the
/// verification interaction to the implementation, and the host renders these however its UI
/// wants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceApprovalError {
    /// No live grant matches the entered code.
    UnknownUserCode,
    /// The grant existed but its lifetime has passed.
    Expired,
    /// The grant was already approved or denied.
    NotPending,
    /// The storage seam failed.
    Storage(StorageError),
}

impl std::fmt::Display for DeviceApprovalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeviceApprovalError::UnknownUserCode => f.write_str("unknown user code"),
            DeviceApprovalError::Expired => f.write_str("the code has expired"),
            DeviceApprovalError::NotPending => f.write_str("the code was already used"),
            DeviceApprovalError::Storage(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for DeviceApprovalError {}

/// The RFC 8628 section 6.1 example alphabet: 20 consonants, chosen upstream to avoid vowels
/// (accidental words) and easily confused symbols.
const USER_CODE_ALPHABET: &[u8; 20] = b"BCDFGHJKLMNPQRSTVWXZ";

/// Fresh OS randomness, hex encoded: `n` bytes of entropy, `2n` characters. Used for device codes
/// and tokens; 32 bytes = 256 bits, far past any brute-force horizon for a 10-minute artifact.
fn random_hex(n_bytes: usize) -> String {
    let mut buf = vec![0u8; n_bytes];
    getrandom::fill(&mut buf).expect("OS randomness for OAuth artifacts");
    let mut out = String::with_capacity(n_bytes * 2);
    for b in buf {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// A user code of `len` symbols over [`USER_CODE_ALPHABET`], unbiased via rejection sampling.
fn random_user_code(len: usize) -> String {
    let mut out = String::with_capacity(len);
    let mut byte = [0u8; 1];
    while out.len() < len {
        getrandom::fill(&mut byte).expect("OS randomness for OAuth artifacts");
        // 240 is the largest multiple of 20 below 256: values at or above it would bias the
        // low-index symbols if taken modulo, so they are redrawn.
        if byte[0] < 240 {
            out.push(USER_CODE_ALPHABET[(byte[0] % 20) as usize] as char);
        }
    }
    out
}

/// `WDJBMJHT` to `WDJB-MJHT`: hyphenate the middle for display when the length is even and at
/// least 4; otherwise the raw run is the display form.
fn display_user_code(raw: &str) -> String {
    if raw.len() >= 4 && raw.len().is_multiple_of(2) {
        let mid = raw.len() / 2;
        format!("{}-{}", &raw[..mid], &raw[mid..])
    } else {
        raw.to_string()
    }
}

fn storage_error(e: StorageError) -> ErrorResponse {
    // The host sees the real error through its own Storage impl; the wire gets the opaque code.
    let _ = e;
    ErrorResponse::new(ErrorCode::ServerError)
}

/// The authorization server. Generic over the host's [`Storage`] and (for tests) the [`Clock`].
pub struct AuthorizationServer<S: Storage, C: Clock = SystemClock> {
    config: ServerConfig,
    store: S,
    clock: C,
}

impl<S: Storage> AuthorizationServer<S, SystemClock> {
    /// Construct with the real clock. This is the crate's allocation entry point: call it when
    /// (and only when) host config enables the AS.
    pub fn new(config: ServerConfig, store: S) -> Self {
        Self::with_clock(config, store, SystemClock)
    }
}

impl<S: Storage, C: Clock> AuthorizationServer<S, C> {
    /// Construct with an injected clock (tests).
    pub fn with_clock(config: ServerConfig, store: S, clock: C) -> Self {
        AuthorizationServer {
            config,
            store,
            clock,
        }
    }

    /// The configuration.
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    /// The storage seam, for host-side administration (listing, sweeping).
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Register (or replace) a client. Dynamic client registration (RFC 7591) will layer on this.
    pub async fn register_client(&self, client: Client) -> Result<(), StorageError> {
        self.store.put_client(client).await
    }

    /// Authenticate a client for a token-plane call: unknown id and failed secret verification
    /// collapse into the same `invalid_client` so an attacker cannot probe which ids exist.
    async fn authenticate_client(
        &self,
        client_id: &ClientId,
        client_secret: Option<&str>,
    ) -> Result<Client, ErrorResponse> {
        let client = self
            .store
            .get_client(client_id)
            .await
            .map_err(storage_error)?
            .ok_or_else(|| ErrorResponse::new(ErrorCode::InvalidClient))?;
        if !client.auth.verify(client_secret) {
            return Err(ErrorResponse::new(ErrorCode::InvalidClient));
        }
        Ok(client)
    }

    /// Resolve the scope a request will be granted: the client default when the request names
    /// none, otherwise the request, which must sit inside the registration's allowed set.
    fn resolve_scope(
        client: &Client,
        requested: Option<&ScopeSet>,
    ) -> Result<ScopeSet, ErrorResponse> {
        match requested {
            None => Ok(client.default_scopes.clone()),
            Some(s) if s.is_subset(&client.allowed_scopes) => Ok(s.clone()),
            // NB: descriptions must stay inside the RFC 6749 section 5.2 charset (no double
            // quote, no backslash), which scope tokens themselves already satisfy.
            Some(s) => Err(ErrorResponse::new(ErrorCode::InvalidScope)
                .with_description(format!("scope [{s}] exceeds the client registration"))),
        }
    }

    /// RFC 6749 section 4.1.1/4.1.2 with the OAuth 2.1 constraints: validate an authorization
    /// request and, the host having authenticated `subject` and obtained consent, issue the
    /// single-use code.
    ///
    /// Validation order follows RFC 6749 section 4.1.2.1: the client identity and redirection
    /// target are judged FIRST, and until both hold the user agent is never redirected
    /// ([`AuthorizeRejection::Unredirectable`]). Every later failure is delivered to the
    /// validated redirect URI with `state` echoed ([`AuthorizeRejection::Redirect`]).
    ///
    /// PKCE is REQUIRED (OAuth 2.1; RFC 7636 section 4.4.1 makes a missing `code_challenge`
    /// `error=invalid_request`), and only `S256` is accepted; an absent
    /// `code_challenge_method` would default to `plain` (RFC 7636 section 4.3), which this
    /// server does not implement.
    pub async fn authorize(
        &self,
        params: &AuthorizeParams,
        subject: impl Into<String>,
    ) -> Result<AuthorizationGrant, AuthorizeRejection> {
        use AuthorizeRejection::Unredirectable;

        // Client identity first: no redirect until the client is real.
        let client_id = match params.client_id.as_deref() {
            Some(id) if !id.is_empty() => ClientId::new(id),
            _ => {
                return Err(Unredirectable(
                    ErrorResponse::new(ErrorCode::InvalidRequest)
                        .with_description("client_id is required"),
                ))
            }
        };
        let client = self
            .store
            .get_client(&client_id)
            .await
            .map_err(|e| Unredirectable(storage_error(e)))?
            .ok_or_else(|| {
                Unredirectable(
                    ErrorResponse::new(ErrorCode::InvalidRequest)
                        .with_description("unknown client_id"),
                )
            })?;

        // Redirection target second: exact string match against the registration (OAuth 2.1
        // requires exact matching; no wildcard, no prefix). An absent redirect_uri is only
        // acceptable when the registration is unambiguous (RFC 6749 section 3.1.2.3).
        let redirect_uri = match params.redirect_uri.as_deref() {
            Some(uri) => {
                if !client.redirect_uris.iter().any(|r| r == uri) {
                    return Err(Unredirectable(
                        ErrorResponse::new(ErrorCode::InvalidRequest)
                            .with_description("redirect_uri does not match a registered URI"),
                    ));
                }
                uri.to_string()
            }
            None => match client.redirect_uris.as_slice() {
                [only] => only.clone(),
                _ => {
                    return Err(Unredirectable(
                        ErrorResponse::new(ErrorCode::InvalidRequest).with_description(
                            "redirect_uri is required when the registration is not exactly one",
                        ),
                    ))
                }
            },
        };
        let state = params.state.clone();
        let redirect = |error: ErrorResponse| AuthorizeRejection::Redirect {
            redirect_uri: redirect_uri.clone(),
            state: state.clone(),
            error,
        };

        // From here on the error goes back to the client via the redirect URI.
        match params.response_type.as_deref() {
            Some("code") => {}
            Some(_) => {
                return Err(redirect(
                    ErrorResponse::new(ErrorCode::UnsupportedResponseType).with_description(
                        "response_type must be code; OAuth 2.1 removes every other value",
                    ),
                ))
            }
            None => {
                return Err(redirect(
                    ErrorResponse::new(ErrorCode::InvalidRequest)
                        .with_description("response_type is required"),
                ))
            }
        }
        if !client.allows_grant(GrantType::AuthorizationCode) {
            return Err(redirect(
                ErrorResponse::new(ErrorCode::UnauthorizedClient).with_description(
                    "client registration does not include the authorization_code grant",
                ),
            ));
        }
        let code_challenge = match params.code_challenge.as_deref() {
            Some(c) if !c.is_empty() => c.to_string(),
            _ => {
                return Err(redirect(
                    ErrorResponse::new(ErrorCode::InvalidRequest)
                        .with_description("code_challenge is required (RFC 7636 section 4.4.1)"),
                ))
            }
        };
        // RFC 7636 appendix A grammar: 43..=128 characters of the unreserved set. An S256
        // challenge is always exactly 43, but the grammar is the published contract.
        let challenge_grammar_ok = (43..=128).contains(&code_challenge.len())
            && code_challenge
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'));
        if !challenge_grammar_ok {
            return Err(redirect(
                ErrorResponse::new(ErrorCode::InvalidRequest)
                    .with_description("code_challenge is not a valid challenge string"),
            ));
        }
        match params.code_challenge_method.as_deref() {
            Some("S256") => {}
            _ => {
                return Err(redirect(
                    ErrorResponse::new(ErrorCode::InvalidRequest).with_description(
                        "code_challenge_method must be S256; plain is not implemented",
                    ),
                ))
            }
        }
        let scope = match params.scope.as_deref() {
            None => None,
            Some(raw) => match ScopeSet::parse(raw) {
                Ok(s) => Some(s),
                Err(_) => {
                    return Err(redirect(
                        ErrorResponse::new(ErrorCode::InvalidScope)
                            .with_description("scope is not a valid scope string"),
                    ))
                }
            },
        };
        let scope = match Self::resolve_scope(&client, scope.as_ref()) {
            Ok(s) => s,
            Err(e) => return Err(redirect(e)),
        };

        let now = self.clock.now();
        let code = random_hex(32);
        self.store
            .put_authorization_code(AuthorizationCodeRecord {
                code: code.clone(),
                client_id: client.client_id.clone(),
                redirect_uri: params.redirect_uri.clone(),
                scope,
                code_challenge,
                subject: subject.into(),
                state: state.clone(),
                expires_at: now + self.config.authorization_code_ttl,
            })
            .await
            .map_err(|e| redirect(storage_error(e)))?;

        Ok(AuthorizationGrant {
            redirect_uri,
            response: AuthorizationResponse { code, state },
        })
    }

    /// RFC 8628 section 3.1/3.2: start a device authorization.
    pub async fn device_authorization(
        &self,
        client_id: &ClientId,
        client_secret: Option<&str>,
        requested_scope: Option<&ScopeSet>,
    ) -> Result<DeviceAuthorizationResponse, ErrorResponse> {
        let client = self.authenticate_client(client_id, client_secret).await?;
        if !client.allows_grant(GrantType::DeviceCode) {
            return Err(ErrorResponse::new(ErrorCode::UnauthorizedClient)
                .with_description("client registration does not include the device_code grant"));
        }
        let scope = Self::resolve_scope(&client, requested_scope)?;

        let now = self.clock.now();
        let device_code = random_hex(32);
        let user_code = display_user_code(&random_user_code(self.config.user_code_length));
        let grant = DeviceGrant {
            device_code: device_code.clone(),
            user_code: user_code.clone(),
            client_id: client.client_id.clone(),
            scope,
            state: DeviceGrantState::Pending,
            created_at: now,
            expires_at: now + self.config.device_code_ttl,
            interval: self.config.poll_interval,
            last_poll_at: None,
        };
        self.store
            .put_device_grant(grant)
            .await
            .map_err(storage_error)?;

        let verification_uri_complete = self
            .config
            .include_verification_uri_complete
            .then(|| format!("{}?user_code={}", self.config.verification_uri, user_code));
        Ok(DeviceAuthorizationResponse {
            device_code,
            user_code,
            verification_uri: self.config.verification_uri.clone(),
            verification_uri_complete,
            expires_in: self.config.device_code_ttl.as_secs(),
            interval: self.config.poll_interval.as_secs(),
        })
    }

    /// Fetch a still-live pending grant by entered user code, for the verification UI actions.
    async fn pending_grant_by_user_code(
        &self,
        entered_user_code: &str,
    ) -> Result<DeviceGrant, DeviceApprovalError> {
        let normalized = normalize_user_code(entered_user_code);
        let grant = self
            .store
            .find_device_grant_by_user_code(&normalized)
            .await
            .map_err(DeviceApprovalError::Storage)?
            .ok_or(DeviceApprovalError::UnknownUserCode)?;
        if self.clock.now() >= grant.expires_at {
            // Expired: remove it so the user-facing answer and the poll path agree the code is
            // gone; the device's next poll will already find nothing (invalid_grant), which is
            // indistinguishable from a spent code and fine either way.
            let _ = self.store.take_device_grant(&grant.device_code).await;
            return Err(DeviceApprovalError::Expired);
        }
        if grant.state != DeviceGrantState::Pending {
            return Err(DeviceApprovalError::NotPending);
        }
        Ok(grant)
    }

    /// The host's verification UI approves a grant for `subject` (the authenticated user).
    pub async fn approve_device(
        &self,
        entered_user_code: &str,
        subject: impl Into<String>,
    ) -> Result<(), DeviceApprovalError> {
        let mut grant = self.pending_grant_by_user_code(entered_user_code).await?;
        grant.state = DeviceGrantState::Approved {
            subject: subject.into(),
        };
        self.store
            .put_device_grant(grant)
            .await
            .map_err(DeviceApprovalError::Storage)
    }

    /// The host's verification UI records the user's refusal.
    pub async fn deny_device(&self, entered_user_code: &str) -> Result<(), DeviceApprovalError> {
        let mut grant = self.pending_grant_by_user_code(entered_user_code).await?;
        grant.state = DeviceGrantState::Denied;
        self.store
            .put_device_grant(grant)
            .await
            .map_err(DeviceApprovalError::Storage)
    }

    /// The token endpoint (RFC 6749 section 3.2; device grant per RFC 8628 section 3.4/3.5).
    pub async fn token(&self, request: TokenRequest) -> Result<TokenResponse, ErrorResponse> {
        match request {
            TokenRequest::AuthorizationCode {
                client_id,
                client_secret,
                code,
                redirect_uri,
                code_verifier,
            } => {
                self.authorization_code_token(
                    &client_id,
                    client_secret.as_deref(),
                    &code,
                    redirect_uri.as_deref(),
                    code_verifier.as_deref(),
                )
                .await
            }
            TokenRequest::DeviceCode {
                client_id,
                client_secret,
                device_code,
            } => {
                self.device_token(&client_id, client_secret.as_deref(), &device_code)
                    .await
            }
            TokenRequest::RefreshToken {
                client_id,
                client_secret,
                refresh_token,
                scope,
            } => {
                self.refresh_token(
                    &client_id,
                    client_secret.as_deref(),
                    &refresh_token,
                    scope.as_ref(),
                )
                .await
            }
        }
    }

    /// RFC 6749 section 4.1.3 + RFC 7636 section 4.6: redeem an authorization code.
    async fn authorization_code_token(
        &self,
        client_id: &ClientId,
        client_secret: Option<&str>,
        code: &str,
        redirect_uri: Option<&str>,
        code_verifier: Option<&str>,
    ) -> Result<TokenResponse, ErrorResponse> {
        let client = self.authenticate_client(client_id, client_secret).await?;
        if !client.allows_grant(GrantType::AuthorizationCode) {
            return Err(ErrorResponse::new(ErrorCode::UnauthorizedClient));
        }

        // The verifier's own shape is judged before the code is consumed: a malformed request
        // (RFC 6749 section 5.2 `invalid_request`) must stay retryable with the same code.
        let verifier = code_verifier.ok_or_else(|| {
            ErrorResponse::new(ErrorCode::InvalidRequest)
                .with_description("code_verifier is required (RFC 7636 section 4.5)")
        })?;
        if !crate::pkce::verifier_is_valid(verifier) {
            return Err(ErrorResponse::new(ErrorCode::InvalidRequest)
                .with_description("code_verifier is not a valid verifier string"));
        }

        // Consume first (atomic take): a code is single use, and every judgment below that
        // rejects a CONSUMED code deliberately leaves it dead (RFC 6749 section 4.1.2 directs
        // revocation on a second use; destroying on the first suspicious presentation is the
        // conservative reading and the one RFC 7636 section 4.6 verification demands anyway).
        let record = self
            .store
            .take_authorization_code(code)
            .await
            .map_err(storage_error)?
            .ok_or_else(|| ErrorResponse::new(ErrorCode::InvalidGrant))?;
        if record.client_id != client.client_id {
            return Err(ErrorResponse::new(ErrorCode::InvalidGrant));
        }
        if self.clock.now() >= record.expires_at {
            return Err(ErrorResponse::new(ErrorCode::InvalidGrant)
                .with_description("authorization code expired"));
        }
        // RFC 6749 section 4.1.3: when the authorization request carried redirect_uri
        // explicitly, the token request must present the identical value.
        if let Some(bound) = record.redirect_uri.as_deref() {
            if redirect_uri != Some(bound) {
                return Err(ErrorResponse::new(ErrorCode::InvalidGrant)
                    .with_description("redirect_uri does not match the authorization request"));
            }
        }
        // RFC 7636 section 4.6: recompute S256 over the presented verifier and compare.
        if !crate::pkce::verify_s256(verifier, &record.code_challenge) {
            return Err(ErrorResponse::new(ErrorCode::InvalidGrant)
                .with_description("code_verifier does not match the code_challenge"));
        }

        self.issue(&client, Some(record.subject), record.scope, None)
            .await
    }

    /// RFC 8628 sections 3.4/3.5: one device-token poll.
    async fn device_token(
        &self,
        client_id: &ClientId,
        client_secret: Option<&str>,
        device_code: &str,
    ) -> Result<TokenResponse, ErrorResponse> {
        let client = self.authenticate_client(client_id, client_secret).await?;
        if !client.allows_grant(GrantType::DeviceCode) {
            return Err(ErrorResponse::new(ErrorCode::UnauthorizedClient));
        }

        let mut grant = self
            .store
            .get_device_grant(device_code)
            .await
            .map_err(storage_error)?
            .ok_or_else(|| ErrorResponse::new(ErrorCode::InvalidGrant))?;

        // A device_code was issued to exactly one client; anyone else presenting it holds a grant
        // that was not made to them (RFC 6749 section 5.2 `invalid_grant`). The grant is NOT
        // consumed: a stray or malicious cross-client poll must not break the real device.
        if grant.client_id != client.client_id {
            return Err(ErrorResponse::new(ErrorCode::InvalidGrant));
        }

        let now = self.clock.now();

        // Expiry first (RFC 8628 section 3.5 `expired_token`), and the grant is removed: the code
        // can never become valid again, and later polls report plain `invalid_grant`.
        if now >= grant.expires_at {
            let _ = self.store.take_device_grant(device_code).await;
            return Err(ErrorResponse::new(ErrorCode::ExpiredToken));
        }

        // Poll pacing. Too-fast polls get `slow_down`, and the REQUIRED spacing grows by the
        // configured increment (the RFC directs the client to add 5 seconds; the server tracks the
        // same number so it can hold the client to it). The window also restarts at this poll:
        // hammering does not drain the wait.
        if let Some(last) = grant.last_poll_at {
            if now < last + grant.interval {
                grant.interval += self.config.slow_down_increment;
                grant.last_poll_at = Some(now);
                self.store
                    .put_device_grant(grant)
                    .await
                    .map_err(storage_error)?;
                return Err(ErrorResponse::new(ErrorCode::SlowDown));
            }
        }
        grant.last_poll_at = Some(now);

        match grant.state.clone() {
            DeviceGrantState::Pending => {
                self.store
                    .put_device_grant(grant)
                    .await
                    .map_err(storage_error)?;
                Err(ErrorResponse::new(ErrorCode::AuthorizationPending))
            }
            DeviceGrantState::Denied => {
                // Terminal answer, delivered once; the grant is consumed with it.
                let _ = self.store.take_device_grant(device_code).await;
                Err(ErrorResponse::new(ErrorCode::AccessDenied))
            }
            DeviceGrantState::Approved { subject } => {
                // Single use: redemption goes through the atomic take, so a concurrent double
                // poll can only mint one token; the loser sees `invalid_grant`.
                let taken = self
                    .store
                    .take_device_grant(device_code)
                    .await
                    .map_err(storage_error)?
                    .ok_or_else(|| ErrorResponse::new(ErrorCode::InvalidGrant))?;
                self.issue(&client, Some(subject), taken.scope, None).await
            }
        }
    }

    /// RFC 6749 section 6 with OAuth 2.1 rotation: redeem a refresh token, single use.
    async fn refresh_token(
        &self,
        client_id: &ClientId,
        client_secret: Option<&str>,
        refresh_token: &str,
        requested_scope: Option<&ScopeSet>,
    ) -> Result<TokenResponse, ErrorResponse> {
        let client = self.authenticate_client(client_id, client_secret).await?;
        if !client.allows_grant(GrantType::RefreshToken) {
            return Err(ErrorResponse::new(ErrorCode::UnauthorizedClient));
        }

        // Consume first (atomic), then judge. Deliberate consequences: a token presented by the
        // WRONG authenticated client is destroyed rather than left redeemable (leaked-token
        // hardening, in the spirit of RFC 9700's rotation guidance), and a replay after rotation
        // is a plain `invalid_grant`.
        let record = self
            .store
            .take_refresh_token(refresh_token)
            .await
            .map_err(storage_error)?
            .ok_or_else(|| ErrorResponse::new(ErrorCode::InvalidGrant))?;
        if record.client_id != client.client_id {
            return Err(ErrorResponse::new(ErrorCode::InvalidGrant));
        }
        if let Some(expires_at) = record.expires_at {
            if self.clock.now() >= expires_at {
                return Err(ErrorResponse::new(ErrorCode::InvalidGrant)
                    .with_description("refresh token chain expired"));
            }
        }

        // Narrowing only (RFC 6749 section 6: scope must not include any scope not originally
        // granted). A widening attempt is a client bug, not a compromise: put the record back so
        // the mistake is retryable.
        let scope = match requested_scope {
            None => record.scope.clone(),
            Some(s) if s.is_subset(&record.scope) => s.clone(),
            Some(_) => {
                self.store
                    .put_refresh_token(record)
                    .await
                    .map_err(storage_error)?;
                return Err(ErrorResponse::new(ErrorCode::InvalidScope)
                    .with_description("refresh may narrow scope, never widen it"));
            }
        };

        self.issue(
            &client,
            record.subject.clone(),
            scope,
            Some(record.expires_at),
        )
        .await
    }

    /// Mint and persist an access token (and, when configured, a rotated refresh token).
    /// `refresh_chain_expiry`: `None` starts a NEW chain (device redemption); `Some(inherited)`
    /// continues one (rotation keeps the absolute lifetime).
    async fn issue(
        &self,
        client: &Client,
        subject: Option<String>,
        scope: ScopeSet,
        refresh_chain_expiry: Option<Option<SystemTime>>,
    ) -> Result<TokenResponse, ErrorResponse> {
        let now = self.clock.now();
        let access_token = random_hex(32);
        self.store
            .put_token(IssuedToken {
                access_token: access_token.clone(),
                client_id: client.client_id.clone(),
                subject: subject.clone(),
                scope: scope.clone(),
                issued_at: now,
                expires_at: now + self.config.access_token_ttl,
            })
            .await
            .map_err(storage_error)?;

        let refresh_token =
            if self.config.issue_refresh_tokens && client.allows_grant(GrantType::RefreshToken) {
                let expires_at = match refresh_chain_expiry {
                    Some(inherited) => inherited,
                    None => self.config.refresh_token_ttl.map(|ttl| now + ttl),
                };
                let rt = random_hex(32);
                self.store
                    .put_refresh_token(RefreshTokenRecord {
                        refresh_token: rt.clone(),
                        client_id: client.client_id.clone(),
                        subject,
                        scope: scope.clone(),
                        expires_at,
                    })
                    .await
                    .map_err(storage_error)?;
                Some(rt)
            } else {
                None
            };

        Ok(TokenResponse {
            access_token,
            token_type: TokenType::Bearer,
            expires_in: self.config.access_token_ttl.as_secs(),
            refresh_token,
            scope: (!scope.is_empty()).then(|| scope.to_string()),
        })
    }

    /// Opaque-token introspection: `Ok(Some(_))` only for a known, unexpired token.
    pub async fn introspect(
        &self,
        access_token: &str,
    ) -> Result<Option<IssuedToken>, StorageError> {
        Ok(self
            .store
            .get_token(access_token)
            .await?
            .filter(|t| self.clock.now() < t.expires_at))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_codes_use_the_alphabet_and_are_unbiased_in_shape() {
        let code = random_user_code(8);
        assert_eq!(code.len(), 8);
        assert!(code.bytes().all(|b| USER_CODE_ALPHABET.contains(&b)));
    }

    #[test]
    fn display_form_hyphenates_even_lengths() {
        assert_eq!(display_user_code("WDJBMJHT"), "WDJB-MJHT");
        assert_eq!(display_user_code("ABCDEF"), "ABC-DEF");
        assert_eq!(display_user_code("ABCDE"), "ABCDE");
    }

    #[test]
    fn random_hex_has_the_stated_entropy_width() {
        let h = random_hex(32);
        assert_eq!(h.len(), 64);
        assert!(h.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(random_hex(32), random_hex(32));
    }
}
