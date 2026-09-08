// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RUNNING AUTHORIZATION SERVER: what exists only when `oauth_as:` is configured.
//!
//! Everything expensive on this surface is reachable from [`OAuth2Control`], and [`OAuth2Control`]
//! is built in exactly one place — [`OAuth2Control::build`], called once, from the composition's
//! boot path, only when the operator wrote the config block. That is the whole of the
//! zero-cost-when-off property: the composition holds an `Option`, and `None` allocates nothing,
//! spawns nothing, and mounts nothing.
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

use oauth_as::server::{AuthorizationServer, ServerConfig, SystemClock};
use oauth_as::store::MemoryStorage;

use crate::config::AsIdentity;
use crate::signer::{RingEs256Key, RingEs256Verifier};

/// The store this surface runs on: [`MemoryStorage`] behind the ONE changed read that serves Client
/// ID Metadata Documents. See [`crate::cimd::CimdStore`].
pub type AsStore = crate::cimd::CimdStore;

/// The concrete server type, named once so the three places that hold it agree by construction
/// rather than by three matching turbofishes.
pub type AsServer = AuthorizationServer<AsStore, SystemClock>;

/// The HTTP service over [`AsServer`]: `http::Request` in, `http::Response` out, no framework.
pub type AsService = oauth_as::http::AuthorizationService<AsStore, SystemClock>;

/// EVERYTHING THIS SURFACE ALLOCATES. Absent unless `oauth_as:` is configured.
pub struct OAuth2Control {
    identity: AsIdentity,
    service: AsService,
    server: Arc<AsServer>,
    /// The consent sessions, shared with the two closures the service was built with. Held here as
    /// well so the consent ROUTE can open a session and stake an approval — the two halves of the
    /// screen are a busbar handler and an `oauth-as` callback, and they have to be looking at the
    /// same table.
    sessions: Arc<crate::consent::Sessions>,
}

/// Why the plane could not be built. Distinct from [`busbar_substrate::config::oauth_as::AsCfgError`] because these are
/// failures of the RUNTIME (a key that will not load, an endpoint the library refuses to route)
/// rather than of the grammar, and an operator needs to be able to tell the two apart.
#[derive(Debug)]
pub enum AsBuildError {
    /// The configured signing key could not be loaded.
    SigningKey(crate::signer::KeyError),
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

impl OAuth2Control {
    /// Build the plane. Called ONCE, from the boot path, only when `oauth_as:` is present.
    ///
    /// `key_material` is the resolved secret, already read from wherever the `SecretRef` pointed;
    /// `None` means the operator configured no key and accepts an ephemeral one. This function does
    /// not resolve secrets itself, so it stays testable without a secret module and so the one
    /// place that reads operator secrets remains the config layer.
    ///
    /// `fetch` is the Client ID Metadata Document seam ([`crate::cimd::CimdFetch`]), supplied by the
    /// composition rather than constructed here: that fetch is an SSRF surface and the guard that
    /// makes it safe is the NODE'S, not an authorization server's. See the `cimd` module header.
    pub fn build(
        identity: AsIdentity,
        key_material: Option<&str>,
        protected_resources: Vec<String>,
        fetch: Arc<dyn crate::cimd::CimdFetch>,
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
        config.registration = Some(crate::policy::registration_config(&identity));
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

        // The store: `MemoryStorage` behind the CIMD read. The ceiling handed to it is the SAME
        // `default_grant_scopes` the registration config above is built from, so a client arriving
        // by document and one arriving by registration land under one ceiling by construction.
        let store = crate::cimd::CimdStore::new(
            MemoryStorage::new(),
            crate::policy::default_grant_scopes(&identity),
            fetch,
        );
        let server = Arc::new(
            AuthorizationServer::new(config, store)
                // Installed even though nothing on this plane verifies a client signature today:
                // `oauth-as` refuses every signed credential when no verifier is installed, and the
                // day `dpop` or `client-assertion` is switched on, a MISSING verifier would be a
                // silent refusal of every conforming client rather than a build error.
                .with_es256_verifier(Arc::new(RingEs256Verifier))
                .with_registration_policy(Box::new(crate::policy::OpenRegistration)),
        );

        let sessions = Arc::new(crate::consent::Sessions::default());
        let service = oauth_as::http::ServiceBuilder::new(Arc::clone(&server))
            .with_subject_resolver(crate::consent::subject_resolver(Arc::clone(&sessions)))
            .with_approval_resolver(crate::consent::approval_resolver(
                Arc::clone(&sessions),
                identity.consent_url(),
            ))
            .build()
            .map_err(AsBuildError::Service)?;

        Ok(Self {
            identity,
            service,
            server,
            sessions,
        })
    }

    pub fn identity(&self) -> &AsIdentity {
        &self.identity
    }

    pub fn service(&self) -> &AsService {
        &self.service
    }

    pub fn server(&self) -> &Arc<AsServer> {
        &self.server
    }

    pub fn sessions(&self) -> &Arc<crate::consent::Sessions> {
        &self.sessions
    }
}

/// A SWEEP THAT FAILED, reported to whoever asked for the sweeper.
///
/// The report is a VALUE rather than a log line because a diagnostic ID is the NODE's vocabulary:
/// `OAUTH_AS_SWEEP_FAILED` is a registered code an operator greps for, and a control surface that
/// stamped one would be minting node vocabulary from outside the node. So this surface says what
/// happened and the composition says it in the node's words — including whether it says it at `warn`
/// or at `debug`, which is what [`SweepFault::first`] is for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SweepFault {
    /// The store's own words for why the sweep failed.
    pub error: String,
    /// TRUE on the TRANSITION into the failing state, FALSE on every tick that stays there.
    ///
    /// The sweep runs every tick and a store fault persists, so an unlatched report would be a
    /// warning per tick for as long as the fault lasts. The latch lives here, with the loop that
    /// knows about the ticks, and the composition reads the flag rather than keeping a second one.
    pub first: bool,
}

/// SWEEP EXPIRED RECORDS, forever, on busbar's own timer.
///
/// `Storage::sweep_expired` is the ONLY thing that reclaims anything in `oauth-as`, and it runs when
/// it is called and never otherwise. Expiry is enforced on read, so an unswept deployment is not a
/// security hole — it is a memory one, and the endpoints that fill it take no credential, so an
/// unauthenticated caller sets the rate. A failure is reported through `fault` and the loop
/// continues: a sweeper that exits on the first transient error is a sweeper that is not running by
/// the time anyone looks.
pub fn spawn_sweeper(
    server: Arc<AsServer>,
    every: std::time::Duration,
    fault: Arc<dyn Fn(SweepFault) + Send + Sync>,
) {
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
                    let first =
                        !SWEEP_FAILED_WARNED.swap(true, std::sync::atomic::Ordering::Relaxed);
                    fault(SweepFault {
                        error: e.to_string(),
                        first,
                    });
                }
            }
        }
    });
}
