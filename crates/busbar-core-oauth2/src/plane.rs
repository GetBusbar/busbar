// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use oauth_as::server::{
    AssertionAudience, AuthorizationServer, RefreshRotation, ServerConfig, SystemClock,
};

use crate::config::AsIdentity;
use busbar_kernel::diagnostics::{
    diag_debug, diag_warn, OAUTH_AS_EPHEMERAL_SIGNING_KEY, OAUTH_AS_SWEEP_FAILED,
};

use super::signer::{Es256Key, Es256Verifier, Ps256Verifier};

// busbar:request-path
#[cfg_attr(
    not(test),
    deny(
        clippy::disallowed_macros,
        clippy::disallowed_methods,
        clippy::disallowed_types,
        clippy::redundant_clone,
        clippy::format_push_string,
        clippy::needless_collect,
        clippy::or_fun_call,
        clippy::needless_pass_by_value,
        clippy::allow_attributes,
        clippy::allow_attributes_without_reason
    )
)]
mod serve;
pub(crate) use serve::Granted;

pub(crate) use serve::{seam_access_standing, seam_verify_dpop};

pub(crate) type AsStore = super::cimd::CimdStore;

pub(crate) type AsServer = AuthorizationServer<AsStore, SystemClock>;

pub(crate) type AsService = oauth_as::http::AuthorizationService<AsStore, SystemClock>;

pub(crate) struct AsPlane {
    identity: AsIdentity,
    /// The admin listener's origin (`busbar_kernel::oauth_as::seam::admin_origin`): where the operator
    /// approval pages live, and the address published for them.
    admin_origin: String,
    service: AsService,
    server: Arc<AsServer>,

    sessions: Arc<super::consent::Sessions>,

    plain_metadata: Option<bytes::Bytes>,

    dpop_verifiers: oauth_as::jwt::JwsVerifiers,

    sweeper: Option<Sweeper>,

    carried: Arc<Carried>,
}

/// WHAT A GENERATION HANDS THE NEXT: everything the server holds rather than reads from config.
pub(crate) struct Carried {
    records: Arc<super::cimd::Records>,
    sessions: Arc<super::consent::Sessions>,
    /// The store-kept signing key (PKCS#8 DER), read by the first generation that ran without
    /// `signing_key` and signed with by every later one that runs without it: a reload does not
    /// void the tokens it signed.
    ephemeral_key: std::sync::OnceLock<Vec<u8>>,
    /// The throttle every generation's server asks ([`serve::Throttle`]): one budget across reloads.
    limiter: Arc<oauth_as::FixedWindowRateLimiter>,
    /// The node's registration budget ([`Registrations`]): one across reloads, as the limiter is.
    registrations: Arc<Registrations>,
}

const REGISTRATIONS_PER_WINDOW: u64 = oauth_as::rate_limit::DEFAULT_CLIENT_REGISTRATION_CAPACITY;

const REGISTRATION_WINDOW: std::time::Duration = oauth_as::rate_limit::DEFAULT_WINDOW;

#[derive(Default)]
pub(crate) struct Registrations {
    state: std::sync::Mutex<RegistrationWindow>,
}

#[derive(Default)]
struct RegistrationWindow {
    /// Which window `admitted` belongs to.
    index: u64,
    /// Registrations admitted in that window.
    admitted: u64,
    /// Registrations being answered now.
    in_flight: u64,
}

impl super::shared::Shared {
    /// Every schema the authorization server's store scope holds: named once, when the scope is
    /// opened at boot.
    pub(crate) fn schemas() -> Vec<String> {
        [
            "bucket", "family", "uc", "key", "ix.tok", "ix.rt", "ix.code", "ix.par", "ix.dev",
            "ix.cons", "ix.fam", "ix.subj", "session", "stake", "replay",
        ]
        .into_iter()
        .map(Self::schema)
        .collect()
    }
}

impl Carried {
    pub(crate) fn over(
        store: Arc<busbar_kernel::persistence::facade::CoreStore>,
    ) -> Result<Self, String> {
        let scoped = busbar_kernel::persistence::scoped::ScopedStore::host_private(
            store,
            "oauth-as",
            super::shared::Shared::schemas(),
        )
        .map_err(|e| format!("oauth_as store: {e:?}"))?;
        Ok(Self {
            records: Arc::new(super::cimd::Records::shared(Arc::new(
                super::shared::Shared::new(Arc::new(scoped)),
            ))),
            sessions: Arc::default(),
            ephemeral_key: std::sync::OnceLock::new(),
            limiter: Arc::default(),
            registrations: Arc::default(),
        })
    }

    pub(crate) fn store(&self) -> &Arc<super::shared::Shared> {
        self.records.store()
    }

    #[cfg(test)]
    pub(crate) fn records(&self) -> Arc<super::cimd::Records> {
        Arc::clone(&self.records)
    }
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
    /// The crypto backend refused what the server needs (an algorithm, or its self-test).
    Crypto(oauth_as::crypto::CryptoError),
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
            AsBuildError::Crypto(e) => write!(f, "oauth_as.crypto: {e}"),
        }
    }
}

impl AsPlane {
    #[cfg(test)]
    pub(crate) async fn build(
        identity: AsIdentity,
        key_material: Option<&str>,
        protected_resources: Vec<String>,
        fetch: Arc<dyn super::cimd::CimdFetch>,
    ) -> Result<Self, AsBuildError> {
        let carried = Carried::over(crate::testkit::memory_store().await)
            .expect("the in-memory store opens the oauth-as scope");
        Self::build_carrying(
            identity,
            crate::testkit::ADMIN_ORIGIN.to_string(),
            key_material,
            protected_resources,
            fetch,
            Arc::new(carried),
        )
        .await
    }

    pub(crate) async fn build_carrying(
        identity: AsIdentity,
        admin_origin: String,
        key_material: Option<&str>,
        protected_resources: Vec<String>,
        fetch: Arc<dyn super::cimd::CimdFetch>,
        carried: Arc<Carried>,
    ) -> Result<Self, AsBuildError> {
        let key = match key_material {
            Some(b64) => {
                use base64::Engine as _;
                let der = base64::engine::general_purpose::STANDARD
                    .decode(b64.trim())
                    .map_err(|e| AsBuildError::SigningKeyMaterial(e.to_string()))?;
                Es256Key::from_pkcs8_der(identity.key_id(), &der)
                    .map_err(AsBuildError::SigningKey)?
            }
            None => {
                let der = match carried.ephemeral_key.get() {
                    Some(der) => der,
                    None => {
                        let fresh = carried
                            .store()
                            .signing_key(|| Es256Key::generate_pkcs8().map_err(|e| e.to_string()))
                            .await
                            .map_err(AsBuildError::SigningKeyMaterial)?;
                        carried.ephemeral_key.get_or_init(|| fresh)
                    }
                };
                Es256Key::from_pkcs8_der(identity.key_id(), der)
                    .map_err(AsBuildError::SigningKey)?
            }
        };

        let verification_uri = format!("{admin_origin}{}", crate::config::OPERATOR_DEVICE_PATH);
        let mut config = ServerConfig::new(identity.issuer(), verification_uri);
        let (authorization, token, device, revocation) = (
            format!("{}/authorize", identity.issuer()),
            format!("{}/token", identity.issuer()),
            format!(
                "{}{}",
                identity.origin(),
                identity.device_authorization_path()
            ),
            format!("{}{}", identity.origin(), identity.revocation_path()),
        );
        config.authorization_endpoint = Some(authorization);
        config.token_endpoint = Some(token);
        config.device_authorization_endpoint = Some(device);
        config.revocation_endpoint = Some(revocation);
        config.jwks_uri = Some(identity.jwks_uri());
        config.registration = Some(super::policy::registration_config(&identity));
        config.access_token_ttl = identity.access_token_ttl();

        config.refresh_token_ttl = Some(identity.refresh_token_ttl());
        let scopes =
            (!identity.default_grant().is_empty()).then(|| identity.default_grant().to_vec());
        config.scopes_supported = scopes;

        let allowed: Box<[Box<str>]> = protected_resources
            .iter()
            .map(|r| r.as_str().into())
            .collect::<Vec<Box<str>>>()
            .into_boxed_slice();
        config.allowed_resources = Some(allowed);
        let audience = protected_resources
            .first()
            .cloned()
            .unwrap_or_else(|| identity.issuer().to_string());
        config.protected_resources =
            (!protected_resources.is_empty()).then_some(protected_resources);
        config.access_token_format = oauth_as::jwt::AccessTokenFormat::Jwt(Box::new(
            oauth_as::jwt::JwtConfig::new(key, audience).with_jwks_uri(identity.jwks_uri()),
        ));

        if identity.fapi2() {
            config = fapi2_posture(config, &identity);
        }

        let store = super::cimd::CimdStore::over(
            Arc::clone(&carried.records),
            super::policy::default_grant_scopes(&identity),
            fetch,
            provisioned_clients(&identity),
        );
        let server = Arc::new(
            AuthorizationServer::new_with_crypto(
                config,
                store,
                Arc::new(super::crypto_provider::FacadeCrypto),
            )
            .map_err(AsBuildError::Crypto)?
            .with_jws_verifier(Arc::new(Es256Verifier))
            .with_jws_verifier(Arc::new(Ps256Verifier))
            .with_registration_policy(Box::new(super::policy::OpenRegistration))
            .with_rate_limiter(Box::new(serve::Throttle {
                limiter: Arc::clone(&carried.limiter),
                registrations: Arc::clone(&carried.registrations),
            })),
        );

        let sessions = Arc::clone(&carried.sessions);
        // The library's own device verification page is never reached: `verification_uri` is on the
        // admin origin, which busbar serves itself (`routes::device_page`), so no CSRF seam is wired.
        let service = oauth_as::http::ServiceBuilder::new(Arc::clone(&server))
            .with_subject_resolver(super::consent::subject_resolver(Arc::clone(&sessions)))
            .with_approval_resolver(super::consent::approval_resolver(
                Arc::clone(&sessions),
                format!("{admin_origin}{}", crate::config::OPERATOR_CONSENT_PATH),
            ))
            .build()
            .map_err(AsBuildError::Service)?;
        let plain_metadata = (!identity.fapi2()).then(|| plain_metadata(&server));
        let mut dpop_verifiers = oauth_as::jwt::JwsVerifiers::new();
        dpop_verifiers.install(Arc::new(Es256Verifier));
        dpop_verifiers.install(Arc::new(Ps256Verifier));

        Ok(Self {
            identity,
            admin_origin,
            service,
            server,
            sessions,
            plain_metadata,
            dpop_verifiers,
            sweeper: None,
            carried,
        })
    }

    pub(crate) fn identity(&self) -> &AsIdentity {
        &self.identity
    }

    /// The admin listener's origin: where the operator approval pages live.
    pub(crate) fn admin_origin(&self) -> &str {
        &self.admin_origin
    }

    /// The consent page's absolute URL, on the admin origin.
    pub(crate) fn consent_url(&self) -> String {
        format!(
            "{}{}",
            self.admin_origin,
            crate::config::OPERATOR_CONSENT_PATH
        )
    }

    pub(crate) fn server(&self) -> &Arc<AsServer> {
        &self.server
    }

    #[cfg(test)]
    pub(crate) fn sessions(&self) -> &Arc<super::consent::Sessions> {
        &self.sessions
    }
}

fn provisioned_clients(identity: &AsIdentity) -> Vec<oauth_as::client::Client> {
    let ceiling = super::policy::default_grant_scopes(identity);
    let clients = identity
        .clients
        .iter()
        .map(|c| oauth_as::client::Client {
            client_id: oauth_as::client::ClientId::new(&c.client_id),
            auth: oauth_as::client::ClientAuth::ConfidentialAssertion {
                keys: oauth_as::client_assertion::AssertionKeys::PublicKeys {
                    alg: if c.jwks.keys.first().is_some_and(|k| k.kty == "RSA") {
                        oauth_as::jwt::JwsAlg::Ps256
                    } else {
                        oauth_as::jwt::JwsAlg::Es256
                    },
                    keys: c.jwks.keys.iter().map(public_jwk).collect(),
                },
            },
            grant_types: {
                let mut grants = vec![oauth_as::grant::GrantType::RefreshToken];
                if !c.redirect_uris.is_empty() {
                    grants.push(oauth_as::grant::GrantType::AuthorizationCode);
                }
                if c.device_authorization {
                    grants.push(oauth_as::grant::GrantType::DeviceCode);
                }
                grants
            },
            redirect_uris: c.redirect_uris.clone(),
            allowed_scopes: ceiling.clone(),
            default_scopes: ceiling.clone(),
            name: Some(c.client_id.clone()),
            registration: None,
        })
        .collect();
    clients
}

fn public_jwk(k: &crate::config::StaticClientJwk) -> oauth_as::jwt::Jwk {
    let member = |v: &Option<String>| v.clone().unwrap_or_default();
    if k.kty == "RSA" {
        oauth_as::jwt::Jwk::Rsa {
            n: member(&k.n),
            e: member(&k.e),
            kid: k.kid.clone(),
        }
    } else {
        oauth_as::jwt::Jwk::Ec {
            crv: oauth_as::jwt::EcCurve::P256,
            x: member(&k.x),
            y: member(&k.y),
            kid: k.kid.clone(),
        }
    }
}

fn fapi2_posture(mut config: ServerConfig, identity: &AsIdentity) -> ServerConfig {
    let mut par = oauth_as::par::ParConfig::new();
    par.pushed_authorization_request_endpoint = Some(identity.par_endpoint());
    par.require_pushed_authorization_requests = true;
    par.require_redirect_uri = true;
    config.par = Some(Box::new(par));

    config.require_dpop = true;
    config
        .with_refresh_rotation(RefreshRotation::Reuse)
        .with_assertion_audience(AssertionAudience::IssuerOnly)
        .with_jws_alg_allow_list(oauth_as::jwt::AlgAllowList::fapi())
}

fn plain_metadata(server: &AsServer) -> bytes::Bytes {
    let mut meta = server.metadata();
    meta.token_endpoint_auth_methods_supported.retain(|m| {
        m != oauth_as::client_assertion::CLIENT_SECRET_JWT
            && m != oauth_as::client_assertion::PRIVATE_KEY_JWT
    });
    meta.token_endpoint_auth_signing_alg_values_supported = None;
    meta.dpop_signing_alg_values_supported = None;
    let document = busbar_contract::json::to_vec(&meta)
        .expect("the RFC 8414 document is plain JSON and serializes");
    bytes::Bytes::from(document)
}

type BuildFuture = std::pin::Pin<
    Box<
        dyn std::future::Future<Output = Result<Arc<dyn std::any::Any + Send + Sync>, String>>
            + Send,
    >,
>;

pub(crate) fn seam_build<C: crate::Connections>(
    block: busbar_contract::yaml::Value,
    secrets: Vec<(String, String)>,
    protected_resources: Vec<String>,
    prior: Option<Arc<dyn std::any::Any + Send + Sync>>,
    store: Arc<busbar_kernel::persistence::facade::CoreStore>,
    admin_origin: String,
) -> BuildFuture {
    Box::pin(async move {
        let identity = crate::config::identity_of(&block)?;
        let carried = match prior.and_then(|p| p.downcast::<AsPlane>().ok()) {
            Some(plane) => {
                // The admin listener is bound once, at boot, and every pending login was sent to the
                // address it published. An apply cannot move it; a restart can.
                if plane.admin_origin != admin_origin {
                    return Err(format!(
                        "oauth_as: the admin listener is `{}` since boot, and this config names \
                         `{admin_origin}` (admin_listen or admin_tls changed). The listener is \
                         bound once at boot and the operator approval pages are published at its \
                         address, so this cannot change on apply. Restart busbar to apply it.",
                        plane.admin_origin
                    ));
                }
                Arc::clone(&plane.carried)
            }
            None => Arc::new(Carried::over(store)?),
        };

        let key_material = match identity.signing_key() {
            None if carried.ephemeral_key.get().is_some() => None,

            None => {
                diag_warn!(
                OAUTH_AS_EPHEMERAL_SIGNING_KEY,
                "oauth_as: no signing_key configured; signing with the key minted once for the \
                 deployment and kept in its store, where whoever reads the store can read it, as \
                 they read the deployment keyset. Set `oauth_as.signing_key` (a secret reference) \
                 to keep the signing key out of the store."
            );
                None
            }
            Some(_) => Some({
                let found = secrets
                    .iter()
                    .find(|(path, _)| path == crate::config::SIGNING_KEY_PATH)
                    .map(|(_, value)| value.as_str())
                    .ok_or_else(|| {
                        format!(
                            "{}: the reference was not resolved",
                            crate::config::SIGNING_KEY_PATH
                        )
                    });
                found?
            }),
        };

        let fetch = Arc::new(super::cimd::ConnectorFetch { table: C::table });
        let mut plane = AsPlane::build_carrying(
            identity,
            admin_origin,
            key_material,
            protected_resources,
            fetch,
            carried,
        )
        .await
        .map_err(|e| e.to_string())?;

        plane.sweeper = Some(sweep_on_clock(
            plane.server(),
            std::time::Duration::from_secs(60),
        ));
        Ok(Arc::new(plane) as Arc<dyn std::any::Any + Send + Sync>)
    })
}

/// Holds the sweep's work alive; the clock task ends when it drops.
pub(crate) struct Sweeper {
    _work: Arc<SweepWork>,
}

impl Sweeper {
    #[cfg(test)]
    pub(crate) fn probe(&self) -> std::sync::Weak<SweepWork> {
        Arc::downgrade(&self._work)
    }
}

impl AsPlane {
    #[cfg(test)]
    pub(crate) fn sweeper(&self) -> Option<&Sweeper> {
        self.sweeper.as_ref()
    }
}

pub(crate) fn sweep_on_clock(server: &Arc<AsServer>, every: std::time::Duration) -> Sweeper {
    let work = Arc::new(SweepWork {
        server: Arc::downgrade(server),
        every,
        due: std::sync::Mutex::new(std::time::Instant::now() + every),
        sweeping: Arc::new(std::sync::atomic::AtomicBool::new(false)),
    });
    let on_clock: Arc<dyn busbar_kernel::tick::ClockWork> = Arc::<SweepWork>::clone(&work);
    busbar_kernel::tick::on_clock(Arc::downgrade(&on_clock));
    Sweeper { _work: work }
}

pub(crate) struct SweepWork {
    server: std::sync::Weak<AsServer>,
    every: std::time::Duration,

    due: std::sync::Mutex<std::time::Instant>,

    sweeping: Arc<std::sync::atomic::AtomicBool>,
}

impl busbar_kernel::tick::ClockWork for SweepWork {
    fn beat(&self, now: std::time::SystemTime) -> Option<busbar_kernel::tick::ClockJob> {
        use std::sync::atomic::Ordering;
        let server = self.server.upgrade()?;
        {
            let mut due = self
                .due
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let at = std::time::Instant::now();
            if at < *due || self.sweeping.swap(true, Ordering::AcqRel) {
                return None;
            }
            *due = at + self.every;
        }
        let sweeping = Arc::clone(&self.sweeping);
        Some(Box::pin(async move {
            sweep_once(&server, now).await;
            sweeping.store(false, Ordering::Release);
        }))
    }
}

async fn sweep_once(server: &AsServer, now: std::time::SystemTime) {
    use oauth_as::store::Storage as _;

    static SWEEP_FAILED_WARNED: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    match server.store().sweep_expired(now).await {
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

#[cfg(test)]
#[path = "tests/sweeper_tests.rs"]
mod sweeper_tests;

#[cfg(test)]
#[path = "tests/access_standing_tests.rs"]
mod access_standing_tests;
