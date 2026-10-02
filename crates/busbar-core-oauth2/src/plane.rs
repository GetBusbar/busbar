// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RUNNING AUTHORIZATION SERVER: what exists only when `oauth_as:` is configured.
//!
//! Everything expensive on this plane is reachable from [`AsPlane`], and [`AsPlane`] is built in
//! exactly one place — [`AsPlane::build`], called once, from the boot path, only when the operator
//! wrote the config block. That is the whole of the zero-cost-when-off property: `App::oauth_as` is
//! `Option<Arc<AsPlane>>`, and `None` allocates nothing, spawns nothing, and mounts nothing.
//!
//! ## What is deliberately NOT durable, said here rather than discovered
//!
//! The store is `oauth_as::store::MemoryStorage`. Authorization codes, tokens, refresh tokens and
//! registered clients therefore live in this process and are lost on restart. That is a REAL
//! limitation and not a placeholder pretending otherwise: a restarted deployment invalidates every
//! outstanding token and every dynamically registered client, and an agent connected to it has to
//! log in again. Closing it means implementing `oauth_as::store::Storage` over busbar's store
//! plugins, whose `take_*` methods have to be atomic remove-and-return or refresh tokens
//! double-spend across nodes — which is exactly what that crate's `test-util` storage conformance
//! harness exists to check, and is a unit of work in its own right.

use std::sync::Arc;

use oauth_as::server::{
    AssertionAudience, AuthorizationServer, RefreshRotation, ServerConfig, SystemClock,
};
use oauth_as::store::MemoryStorage;

use busbar_kernel::diagnostics::{diag_debug, diag_warn, OAUTH_AS_SWEEP_FAILED};
use busbar_kernel::oauth_as::config::AsIdentity;

use super::signer::{RingEs256Key, RingEs256Verifier};

/// The store this plane runs on: [`MemoryStorage`] behind the ONE changed read that serves Client
/// ID Metadata Documents. See [`super::cimd::CimdStore`].
pub(crate) type AsStore = super::cimd::CimdStore;

/// The concrete server type, named once so the three places that hold it agree by construction
/// rather than by three matching turbofishes.
pub(crate) type AsServer = AuthorizationServer<AsStore, SystemClock>;

/// The HTTP service over [`AsServer`]: `http::Request` in, `http::Response` out, no framework.
pub(crate) type AsService = oauth_as::http::AuthorizationService<AsStore, SystemClock>;

/// EVERYTHING THIS PLANE ALLOCATES. Absent unless `oauth_as:` is configured.
pub(crate) struct AsPlane {
    identity: AsIdentity,
    service: AsService,
    server: Arc<AsServer>,
    /// The consent sessions, shared with the two closures the service was built with. Held here as
    /// well so the consent ROUTE can open a session and stake an approval — the two halves of the
    /// screen are a busbar handler and an `oauth-as` callback, and they have to be looking at the
    /// same table.
    sessions: Arc<super::consent::Sessions>,
    /// The RFC 8414 document the PLAIN posture serves, or `None` under the FAPI 2.0 posture, which
    /// serves `oauth-as`'s own. See [`plain_metadata`].
    plain_metadata: Option<bytes::Bytes>,
}

/// Why the plane could not be built. Distinct from [`super::config::AsCfgError`] because these are
/// failures of the RUNTIME (a key that will not load, an endpoint the library refuses to route)
/// rather than of the grammar, and an operator needs to be able to tell the two apart.
#[derive(Debug)]
pub(crate) enum AsBuildError {
    /// The configured signing key could not be loaded.
    SigningKey(super::signer::KeyError),
    /// The signing key secret reference did not resolve, or did not decode as base64.
    SigningKeyMaterial(String),
    /// `oauth-as` refused to build its service. In practice this is an advertised endpoint that is
    /// not under the issuer, which cannot happen with endpoints this module derives — it is carried
    /// rather than unwrapped because "cannot happen" is not a thing a boot path should assert.
    Service(oauth_as::http::ServiceError),
}

impl std::fmt::Display for AsBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AsBuildError::SigningKey(e) => write!(f, "oauth_as.signing_key: {e}"),
            AsBuildError::SigningKeyMaterial(e) => write!(
                f,
                "oauth_as.signing_key: {e}. It must be a base64-encoded PKCS#8 v1 DER P-256 private \
                 key — what `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
                 -outform DER | base64` produces."
            ),
            AsBuildError::Service(e) => write!(f, "oauth_as: {e}"),
        }
    }
}

impl AsPlane {
    /// Build the plane. Called ONCE, from the boot path, only when `oauth_as:` is present.
    ///
    /// `key_material` is the resolved secret, already read from wherever the `SecretRef` pointed;
    /// `None` means the operator configured no key and accepts an ephemeral one. This function does
    /// not resolve secrets itself, so it stays testable without a secret module and so the one
    /// place that reads operator secrets remains the config layer.
    pub(crate) fn build(
        identity: AsIdentity,
        key_material: Option<&str>,
        protected_resources: Vec<String>,
    ) -> Result<Self, AsBuildError> {
        let key = match key_material {
            Some(b64) => {
                use base64::Engine as _;
                let der = base64::engine::general_purpose::STANDARD
                    .decode(b64.trim())
                    .map_err(|e| AsBuildError::SigningKeyMaterial(e.to_string()))?;
                RingEs256Key::from_pkcs8_der(identity.key_id(), &der)
                    .map_err(AsBuildError::SigningKey)?
            }
            None => {
                let der = RingEs256Key::generate_pkcs8().map_err(AsBuildError::SigningKey)?;
                RingEs256Key::from_pkcs8_der(identity.key_id(), &der)
                    .map_err(AsBuildError::SigningKey)?
            }
        };

        let mut config = ServerConfig::new(identity.issuer(), identity.consent_url());
        config.authorization_endpoint = Some(format!("{}/authorize", identity.issuer()));
        config.token_endpoint = Some(format!("{}/token", identity.issuer()));
        config.jwks_uri = Some(identity.jwks_uri());
        config.registration = Some(super::policy::registration_config(&identity));
        config.access_token_ttl = identity.access_token_ttl();
        config.scopes_supported =
            (!identity.default_grant().is_empty()).then(|| identity.default_grant().to_vec());
        // RFC 8707 §2: the resources this server is WILLING to mint for. Setting it is not optional
        // hygiene. With `None`, any syntactically valid absolute URI is accepted as a `resource`,
        // and under the JWT profile that requested value REPLACES the audience in the `aud` claim —
        // so any client could obtain a token THIS server signed carrying another resource server's
        // identifier, which that server would then verify against our JWKS and honour. The list is
        // busbar's own planes and nothing else.
        config.allowed_resources = Some(
            protected_resources
                .iter()
                .map(|r| r.as_str().into())
                .collect::<Vec<Box<str>>>()
                .into_boxed_slice(),
        );
        config.protected_resources =
            (!protected_resources.is_empty()).then(|| protected_resources.clone());
        // RFC 9068 `at+jwt`, ES256, signed with `ring`. JWT rather than opaque because the resource
        // half of this deployment must be able to establish the audience binding from the token
        // itself: `auth::audience::inspect_bearer` refuses a bearer whose `aud` it cannot read, and
        // it refuses it on purpose — "I cannot tell whether this was minted for me" has one safe
        // answer. An opaque token would be refused by busbar's own front door.
        //
        // The audience is the FIRST protected resource, and is overridden per request by the
        // RFC 8707 `resource` parameter the client sends; the `allowed_resources` list above is what
        // stops that override naming somebody else.
        let audience = protected_resources
            .first()
            .cloned()
            .unwrap_or_else(|| identity.issuer().to_string());
        config.access_token_format = oauth_as::jwt::AccessTokenFormat::Jwt(Box::new(
            oauth_as::jwt::JwtConfig::new(key, audience).with_jwks_uri(identity.jwks_uri()),
        ));

        // THE FAPI 2.0 SECURITY PROFILE, applied only when the operator wrote `fapi2: true`. Every
        // write below is inside this branch, so the plain posture builds the `ServerConfig` it
        // always built. The authorization code lifetime needs no write: `oauth-as`'s default is
        // already the profile's 60-second ceiling (s5.3.2.1-11).
        if identity.fapi2() {
            config = fapi2_posture(config, &identity);
        }

        // The store: `MemoryStorage` behind the CIMD read. The ceiling handed to it is the SAME
        // `default_grant_scopes` the registration config above is built from, so a client arriving
        // by document and one arriving by registration land under one ceiling by construction.
        let store = super::cimd::CimdStore::new(
            MemoryStorage::new(),
            super::policy::default_grant_scopes(&identity),
            Arc::new(super::cimd::GuardedFetch),
            provisioned_clients(&identity),
        );
        let server = Arc::new(
            AuthorizationServer::new(config, store)
                // THE ES256 VERIFIER: what checks an RFC 9449 DPoP proof and an RFC 7523
                // `private_key_jwt` assertion. `oauth-as` refuses every signed credential whose
                // algorithm has no verifier, and advertises exactly the algorithms that have one.
                .with_jws_verifier(Arc::new(RingEs256Verifier))
                .with_registration_policy(Box::new(super::policy::OpenRegistration)),
        );

        let sessions = Arc::new(super::consent::Sessions::default());
        let service = oauth_as::http::ServiceBuilder::new(Arc::clone(&server))
            .with_subject_resolver(super::consent::subject_resolver(Arc::clone(&sessions)))
            .with_approval_resolver(super::consent::approval_resolver(
                Arc::clone(&sessions),
                identity.consent_url(),
            ))
            .build()
            .map_err(AsBuildError::Service)?;
        let plain_metadata = (!identity.fapi2()).then(|| plain_metadata(&server));

        Ok(Self {
            identity,
            service,
            server,
            sessions,
            plain_metadata,
        })
    }

    /// Answer one request: the plane's whole wire surface. The plain posture's metadata document
    /// is the one answer busbar serves itself ([`plain_metadata`]); every other request is
    /// `oauth-as`'s, unchanged.
    pub(crate) async fn handle<B>(&self, request: http::Request<B>) -> oauth_as::http::Response
    where
        B: axum::body::HttpBody,
    {
        if let Some(document) = &self.plain_metadata {
            if request.method() == http::Method::GET
                && request.uri().path() == self.identity.metadata_path()
            {
                let mut response =
                    http::Response::new(oauth_as::http::Body::from(document.clone()));
                response.headers_mut().insert(
                    http::header::CONTENT_TYPE,
                    http::HeaderValue::from_static("application/json;charset=UTF-8"),
                );
                return response;
            }
        }
        // Box::pin: the whole `oauth-as` dispatch future (~56 KB monomorphized), boxed at its one
        // call site, as `routes::forward` did before this method existed.
        Box::pin(self.service.handle(request)).await
    }

    /// The display summary of a pushed request that has not been redeemed yet. See
    /// [`super::cimd::Pushed`].
    pub(crate) fn pushed(&self, request_uri: &str) -> Option<super::cimd::Pushed> {
        self.server.store().pushed(request_uri)
    }

    /// Record that the consent screen showed this pushed request, answering whether it had been
    /// shown before.
    pub(crate) fn mark_pushed_shown(&self, request_uri: &str) -> bool {
        self.server.store().mark_pushed_shown(request_uri)
    }

    pub(crate) fn identity(&self) -> &AsIdentity {
        &self.identity
    }

    pub(crate) fn server(&self) -> &Arc<AsServer> {
        &self.server
    }

    pub(crate) fn sessions(&self) -> &Arc<super::consent::Sessions> {
        &self.sessions
    }
}

/// `oauth_as.clients:` as `oauth-as` clients: confidential, authenticating with an RFC 7523 ES256
/// assertion against the configured PUBLIC keys, for the authorization-code and refresh grants,
/// with the operator's `default_grant` as their whole scope (the same ceiling every other client
/// lands under). The keys were validated at boot (`AsIdentity::from_cfg`): EC P-256, no `d`.
fn provisioned_clients(identity: &AsIdentity) -> Vec<oauth_as::client::Client> {
    let ceiling = super::policy::default_grant_scopes(identity);
    identity
        .clients
        .iter()
        .map(|c| oauth_as::client::Client {
            client_id: oauth_as::client::ClientId::new(&c.client_id),
            auth: oauth_as::client::ClientAuth::ConfidentialAssertion {
                keys: oauth_as::client_assertion::AssertionKeys::PublicKeys {
                    alg: oauth_as::jwt::JwsAlg::Es256,
                    keys: c
                        .jwks
                        .keys
                        .iter()
                        .map(|k| oauth_as::jwt::Jwk::Ec {
                            crv: oauth_as::jwt::EcCurve::P256,
                            x: k.x.clone(),
                            y: k.y.clone(),
                            kid: k.kid.clone(),
                        })
                        .collect(),
                },
            },
            grant_types: vec![
                oauth_as::grant::GrantType::AuthorizationCode,
                oauth_as::grant::GrantType::RefreshToken,
            ],
            redirect_uris: c.redirect_uris.clone(),
            allowed_scopes: ceiling.clone(),
            default_scopes: ceiling.clone(),
            name: Some(c.client_id.clone()),
            registration: None,
        })
        .collect()
}

/// THE FAPI 2.0 SECURITY PROFILE POSTURE, written onto a plain `ServerConfig`. The values are the
/// upstream `fapi2_conformance_server` example's, which is the configuration `oauth-as` 1.0.0 was
/// OpenID-certified under (FAPI2SP OP, private key + DPoP).
fn fapi2_posture(mut config: ServerConfig, identity: &AsIdentity) -> ServerConfig {
    // RFC 9126 PAR, MANDATORY (s5.3.2.2-3), with `redirect_uri` required in the push (s5.3.2.2-6).
    // The endpoint is set to the path `routes::mount` mounts, so the advertised document and the
    // served route cannot drift. The handle lifetime is `oauth-as`'s 60 s, under s5.3.2.2-12's 600.
    let mut par = oauth_as::par::ParConfig::new();
    par.pushed_authorization_request_endpoint = Some(identity.par_endpoint());
    par.require_pushed_authorization_requests = true;
    par.require_redirect_uri = true;
    config.par = Some(Box::new(par));
    // RFC 9449 on every token request: every token is sender-constrained (s5.3.4-2).
    config.require_dpop = true;
    config
        // s5.3.2.1-9 forbids refresh token rotation. Sound only because the line above binds every
        // token to its client's DPoP key; the plain posture keeps rotation and reuse detection.
        .with_refresh_rotation(RefreshRotation::Reuse)
        // s5.3.2.1-8 / s5.3.3.1-5: a client assertion's `aud` is the issuer, as a string.
        .with_assertion_audience(AssertionAudience::IssuerOnly)
        // s5.4.1: ES256 and PS256 only, for every JWS this server verifies or advertises.
        .with_jws_alg_allow_list(oauth_as::jwt::AlgAllowList::fapi())
}

/// THE PLAIN POSTURE'S RFC 8414 DOCUMENT: `oauth-as`'s own, less the members the FAPI 2.0
/// building blocks add to it at COMPILE time (`client_secret_jwt` and `private_key_jwt`, the
/// assertion and DPoP algorithm lists). Those three cargo features cannot be switched off at
/// runtime, and a deployment that did not ask for the profile must not advertise it: busbar's own
/// resource half answers `Bearer` only, so a client that read `dpop_signing_alg_values_supported`
/// and bound its token would be refused by the very plane the token is for. Serialized exactly as
/// `oauth-as` serializes its own (`serde_json::to_vec` of the same struct), so the bytes are the
/// document this posture always served — `signer_tests` pins them.
fn plain_metadata(server: &AsServer) -> bytes::Bytes {
    let mut meta = server.metadata();
    meta.token_endpoint_auth_methods_supported.retain(|m| {
        m != oauth_as::client_assertion::CLIENT_SECRET_JWT
            && m != oauth_as::client_assertion::PRIVATE_KEY_JWT
    });
    meta.token_endpoint_auth_signing_alg_values_supported = None;
    meta.dpop_signing_alg_values_supported = None;
    bytes::Bytes::from(
        serde_json::to_vec(&meta).expect("the RFC 8414 document is plain JSON and serializes"),
    )
}

/// THE SEAM-TYPED BUILDER (`busbar_kernel::oauth_as::seam::AsPlaneSeam::build`): builds the plane AND
/// spawns its sweeper — the whole "how do I come alive" act `appbuild.rs` used to perform inline
/// before the extraction — and hands back the type-erased object `App::oauth_as` stores. This is
/// the function pointer `busbar_core_oauth2::install` actually registers; core cannot call
/// [`AsPlane::build`] directly, since that would name this crate's type from busbar-core.
pub(crate) fn seam_build(
    identity: &AsIdentity,
    key_material: Option<&str>,
    protected_resources: Vec<String>,
) -> Result<Arc<dyn std::any::Any + Send + Sync>, String> {
    let plane = AsPlane::build(identity.clone(), key_material, protected_resources)
        .map_err(|e| e.to_string())?;
    let plane = Arc::new(plane);
    // `Storage::sweep_expired` is the only thing that reclaims anything in `oauth-as`, and it runs
    // when it is called and never otherwise. Spawned here, once per generation — unchanged from the
    // inline call `appbuild.rs` made before this moved behind the seam.
    spawn_sweeper(
        Arc::clone(plane.server()),
        std::time::Duration::from_secs(60),
    );
    Ok(plane as Arc<dyn std::any::Any + Send + Sync>)
}

/// SWEEP EXPIRED RECORDS, forever, on busbar's own timer.
///
/// `Storage::sweep_expired` is the ONLY thing that reclaims anything in `oauth-as`, and it runs when
/// it is called and never otherwise. Expiry is enforced on read, so an unswept deployment is not a
/// security hole — it is a memory one, and the endpoints that fill it take no credential, so an
/// unauthenticated caller sets the rate. A failure is logged and the loop continues: a sweeper that
/// exits on the first transient error is a sweeper that is not running by the time anyone looks.
pub(crate) fn spawn_sweeper(server: Arc<AsServer>, every: std::time::Duration) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(every);
        // The first tick fires immediately, which would sweep an empty store at boot for nothing.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            // The trait must be in scope for the call; `Storage` is imported here rather than at the
            // module top so nothing else in this file can reach for a raw store operation.
            use oauth_as::store::Storage as _;
            // Warn-once transition latch: the sweep runs every tick and a store fault persists, so
            // warn on the TRANSITION into the failing state and hold subsequent ticks at debug.
            // Reset on any successful sweep so a future outage re-warns.
            static SWEEP_FAILED_WARNED: std::sync::atomic::AtomicBool =
                std::sync::atomic::AtomicBool::new(false);
            match server
                .store()
                .sweep_expired(std::time::SystemTime::now())
                .await
            {
                Ok(0) => {
                    SWEEP_FAILED_WARNED.store(false, std::sync::atomic::Ordering::Relaxed);
                }
                Ok(n) => {
                    SWEEP_FAILED_WARNED.store(false, std::sync::atomic::Ordering::Relaxed);
                    tracing::debug!(reclaimed = n, "oauth_as: swept expired records");
                }
                Err(e) => {
                    if !SWEEP_FAILED_WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                        diag_warn!(
                            OAUTH_AS_SWEEP_FAILED,
                            error = %e,
                            "oauth_as: sweeping expired records failed; retrying on the next tick"
                        );
                    } else {
                        diag_debug!(
                            OAUTH_AS_SWEEP_FAILED,
                            error = %e,
                            "oauth_as: sweeping expired records failed; retrying on the next tick"
                        );
                    }
                }
            }
        }
    });
}
