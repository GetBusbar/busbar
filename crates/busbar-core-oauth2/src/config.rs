// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `oauth_as:` BLOCK, and the boot-time refusals that make it either whole or absent.
//!
//! Every derivation happens here, once, so nothing downstream re-parses an issuer or re-decides a
//! path. A config that cannot produce an [`AsPlane`] does not boot: an authorization server that is
//! half-configured is worse than one that is absent, because it ANSWERS — and what it answers with
//! is tokens.

use serde::{Deserialize, Serialize};

use busbar_contract::SecretRef;

/// `oauth_as:` — busbar as an OAuth 2.1 authorization server. ABSENT BY DEFAULT.
///
/// Absent means absent: no server object, no store, no signing key, no sweeper, no route. See the
/// module docs on [`super`] for what "costs nothing when off" is measured against.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OauthAsCfg {
    /// RFC 8414 `issuer`: the canonical absolute URL that names THIS authorization server, and the
    /// value every endpoint below is derived from.
    ///
    /// OPERATOR-CONFIGURED rather than derived from the request's `Host`, for the same reason
    /// `mcp.canonical_uri` is: an issuer a caller can choose by sending a header is not an identity.
    /// It is also what RFC 9207 puts in the `iss` of every authorization response, so a client
    /// comparing it byte-for-byte against what it discovered is doing the mix-up defence — which
    /// only works if this value never moves.
    pub issuer: String,

    /// The ES256 signing key, as a base64 PKCS#8 v1 DER document.
    ///
    /// ABSENT IS LEGAL AND IT IS THE DEVELOPMENT CASE: busbar generates an ephemeral key at boot and
    /// says so at `warn`. That is deliberate, because the alternative — refusing to boot without a
    /// key — makes trying this out a procurement exercise, and the failure it prevents is loud
    /// anyway: an ephemeral key means every token this deployment issued stops verifying the moment
    /// the process restarts. What must NOT happen is a DEFAULT key, which would be a published
    /// private key that signs valid tokens for every deployment that never set this field.
    #[serde(default)]
    pub signing_key: Option<SecretRef>,

    /// The `kid` published in the JWKS and carried in every token header. Advisory; it exists so an
    /// operator rotating keys can tell two of them apart in a log.
    #[serde(default)]
    pub key_id: Option<String>,

    /// THE CEILING. What a client that registered itself — by any mechanism — is allowed to ask
    /// for, and it is the whole of what it gets.
    ///
    /// EMPTY BY DEFAULT, which means a self-registered client may request no scope at all and any
    /// `scope` member on its registration is refused `invalid_client_metadata`. An operator widens
    /// this deliberately; nothing widens it on their behalf, and no request widens it at runtime.
    #[serde(default)]
    pub default_grant: Vec<String>,

    /// Access token lifetime in seconds. Short on purpose (RFC 9728 §7 / the MCP revision's token
    /// theft note both ask for it); a client that wants continuity refreshes.
    #[serde(default)]
    pub access_token_ttl_secs: Option<u64>,

    /// The FAPI 2.0 Security Profile posture (`openid=plain_oauth`, `private_key_jwt`, DPoP). OFF
    /// BY DEFAULT: a block that does not name it is the plain OAuth 2.1 server.
    ///
    /// `true` turns on the whole posture at once, because the profile is one contract and a
    /// half-applied one passes nobody's suite: RFC 9126 PAR routed, advertised and MANDATORY (FAPI
    /// 2.0 s5.3.2.2-3) with `redirect_uri` required in the push (s5.3.2.2-6); RFC 9449 DPoP required
    /// on every token request (s5.3.4-2); refresh tokens reused rather than rotated (s5.3.2.1-9,
    /// sound only because every token is sender-constrained); a client assertion's `aud` must be
    /// the issuer as a string (s5.3.2.1-8, s5.3.3.1-5); and every JWS this server verifies limited
    /// to ES256/PS256 (s5.4.1). The authorization code lifetime is already the profile's 60-second
    /// ceiling (s5.3.2.1-11) in both postures.
    #[serde(default)]
    pub fapi2: bool,

    /// OPERATOR-PROVISIONED CLIENTS: confidential `private_key_jwt` (RFC 7523) clients declared
    /// here rather than registered over the wire. EMPTY BY DEFAULT. RFC 7591 registration cannot
    /// carry a key (`oauth-as` models no `jwks` there), so this is how a `private_key_jwt` client —
    /// the FAPI 2.0 profile's client — gets a `client_id`. Each holds only the PUBLIC half of its
    /// key, and may ask for no more than [`OauthAsCfg::default_grant`].
    #[serde(default)]
    pub clients: Vec<StaticClientCfg>,
}

/// One `oauth_as.clients:` entry.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct StaticClientCfg {
    /// The `client_id` the client authenticates as (its assertion's `iss` and `sub`).
    pub client_id: String,
    /// The redirect URIs, matched EXACTLY at the authorization endpoint (OAuth 2.1 s4.1.3).
    pub redirect_uris: Vec<String>,
    /// The client's public keys, as RFC 7591 s2 `jwks` spells them.
    pub jwks: StaticClientJwks,
}

/// An RFC 7517 JWK Set: `{"keys": [...]}`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct StaticClientJwks {
    pub keys: Vec<StaticClientJwk>,
}

/// One PUBLIC key: EC P-256 for ES256 (`crv`, `x`, `y`) or RSA for PS256 (`n`, `e`, RFC 7518
/// s6.3.1), the two algorithms FAPI 2.0 s5.4.1 admits. Not `deny_unknown_fields`: RFC 7517 s4 has a
/// reader ignore members it does not understand (`use`, `key_ops`, `x5c`, ...), and a JWK pasted
/// from a client's own tooling carries them. `d` is named so it can be REFUSED: every private JWK
/// carries it (RFC 7518 s6.2.2.1, s6.3.2.1), and a private key has no business in a config file.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct StaticClientJwk {
    pub kty: String,
    #[serde(default)]
    pub crv: Option<String>,
    #[serde(default)]
    pub x: Option<String>,
    #[serde(default)]
    pub y: Option<String>,
    #[serde(default)]
    pub n: Option<String>,
    #[serde(default)]
    pub e: Option<String>,
    #[serde(default)]
    pub kid: Option<String>,
    #[serde(default)]
    pub alg: Option<String>,
    #[serde(default)]
    pub d: Option<String>,
}

/// Why an `oauth_as:` block was refused at boot. Every arm names the field and what a correct value
/// looks like, because an operator reading "invalid oauth_as config" cannot act on it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AsCfgError {
    /// `issuer` is empty.
    MissingIssuer,
    /// `issuer` is not an absolute `http(s)` URL.
    IssuerNotAbsolute(String),
    /// `issuer` carries a query or a fragment. RFC 8414 §2 makes the issuer a URL with no query and
    /// no fragment, and it is compared for exact equality, so normalising one away here would hand
    /// back a string that no longer equals what a client discovered.
    IssuerHasQueryOrFragment(String),
    /// `issuer` ends in `/`. A trailing slash makes `{issuer}/token` into `{issuer}//token`, which
    /// is a different path, and the RFC 9207 `iss` comparison is byte-for-byte.
    IssuerHasTrailingSlash(String),
    /// `default_grant` names a scope that is not a legal RFC 6749 §3.3 scope token.
    ScopeNotAToken(String),
    /// An `oauth_as.clients:` entry is malformed; `why` says how.
    StaticClient {
        client_id: String,
        why: &'static str,
    },
}

impl std::fmt::Display for AsCfgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AsCfgError::MissingIssuer => f.write_str(
                "oauth_as.issuer is required. It is this authorization server's identity: the value \
                 a client compares against the `iss` of every response it gets (RFC 9207), and the \
                 base every endpoint is derived from. Example: \
                 `issuer: https://gw.example.com`",
            ),
            AsCfgError::IssuerNotAbsolute(v) => write!(
                f,
                "oauth_as.issuer `{v}` is not an absolute http(s) URL. Example: \
                 `https://gw.example.com`"
            ),
            AsCfgError::IssuerHasQueryOrFragment(v) => write!(
                f,
                "oauth_as.issuer `{v}` carries a query or a fragment. RFC 8414 section 2 defines \
                 the issuer as a URL with neither, and it is compared byte-for-byte."
            ),
            AsCfgError::IssuerHasTrailingSlash(v) => write!(
                f,
                "oauth_as.issuer `{v}` ends in `/`. Every endpoint is derived as `{{issuer}}/name`, \
                 so a trailing slash produces `//name` — a different path from the one clients ask \
                 for. Write it without the slash."
            ),
            AsCfgError::StaticClient { client_id, why } => {
                write!(f, "oauth_as.clients entry `{client_id}`: {why}")
            }
            AsCfgError::ScopeNotAToken(v) => write!(
                f,
                "oauth_as.default_grant entry `{v}` is not a scope token. RFC 6749 section 3.3 \
                 allows printable ASCII except space, double quote and backslash."
            ),
        }
    }
}

/// The VALIDATED authorization server: every endpoint derived, every refusal already taken.
///
/// Holds no key and no server object — those are runtime state and live on `busbar_core_oauth2::plane::AsPlane`
/// (the sibling crate the plane's runtime moved to in 1.6.0). This is the config half, so it can be
/// compared, logged and swapped without touching a secret.
///
/// The fields are `pub` for TWO reasons now, not one. The original reason still holds:
/// `config_validate::secret_refs` must be able to DESTRUCTURE it exhaustively — that walker's whole
/// design is that a newly added secret-bearing field is a COMPILE error rather than an oversight,
/// and a walk through an accessor cannot deliver that (`identity.signing_key()` keeps compiling the
/// day somebody adds a second `SecretRef` here, and the new secret is then one `--validate` reports
/// as fine and the process fails on at runtime). The second reason is the 1.6.0 plane split:
/// `busbar-core-oauth2`'s own gating proof (`tests::mount_tests::inventory`) destructures this the SAME
/// exhaustive way, from OUTSIDE this crate — so the field visibility widened from `pub(crate)` to
/// `pub` to cross that boundary; the exhaustive-destructure discipline itself is unchanged.
#[derive(Clone, Debug, PartialEq)]
pub struct AsIdentity {
    pub issuer: String,
    /// The path component of `issuer`, normalised, so a tenant-prefixed issuer
    /// (`https://host/tenant`) mounts its endpoints under that prefix rather than at the root.
    pub issuer_path: String,
    pub metadata_path: String,
    pub authorize_path: String,
    pub token_path: String,
    /// The RFC 7591 registration endpoint's path. Always derived, never optional: registration is
    /// one of the three always-on ways a client obtains a `client_id` on this plane.
    pub register_path: String,
    pub jwks_path: String,
    pub consent_path: String,
    /// The RFC 9126 pushed authorization request endpoint's path. Always DERIVED, like every path
    /// above; mounted and advertised only under the FAPI 2.0 posture ([`AsIdentity::fapi2`]).
    pub par_path: String,
    /// The FAPI 2.0 Security Profile posture, resolved from `oauth_as.fapi2`. See
    /// [`OauthAsCfg::fapi2`] for everything it turns on.
    pub fapi2: bool,
    /// The validated `oauth_as.clients:`. Public keys only: nothing here is a secret.
    pub clients: Vec<StaticClientCfg>,
    pub default_grant: Vec<String>,
    pub access_token_ttl: std::time::Duration,
    pub key_id: String,
    /// The operator's `signing_key:` reference, carried VERBATIM and unresolved.
    ///
    /// It lives on the validated identity rather than being consumed at `resolve` time because
    /// `config_validate::secret_refs` walks `RootCfg` and must be able to SEE it: a secret the
    /// walker cannot reach is a secret nothing checks, and that walker's whole design is that
    /// omission is a compile error rather than an oversight.
    pub signing_key: Option<SecretRef>,
}

/// RFC 8414 §3.1: the well-known segment goes BEFORE the issuer's path, not after it. This is the
/// one detail of the document that is easy to get backwards, and getting it backwards means every
/// conforming client's discovery 404s. (RFC 9728 inserts the path the OTHER way round, which is why
/// `mcp::PROTECTED_RESOURCE_WELL_KNOWN` and this constant are used differently a few lines apart.)
const AS_WELL_KNOWN: &str = "/.well-known/oauth-authorization-server";

/// The default access token lifetime: ten minutes. Short because the MCP revision's token-theft note
/// asks for short-lived access tokens, and a client that wants continuity has a refresh token.
const DEFAULT_ACCESS_TOKEN_TTL: std::time::Duration = std::time::Duration::from_secs(600);

impl AsIdentity {
    /// Validate and derive. Every refusal is at BOOT rather than at first request: an operator finds
    /// out from a process that will not start, not from an agent that cannot log in.
    pub fn from_cfg(cfg: &OauthAsCfg) -> Result<Self, AsCfgError> {
        let issuer = cfg.issuer.trim();
        if issuer.is_empty() {
            return Err(AsCfgError::MissingIssuer);
        }
        if issuer.contains('?') || issuer.contains('#') {
            return Err(AsCfgError::IssuerHasQueryOrFragment(issuer.to_string()));
        }
        let (_origin, path) = split_absolute(issuer)
            .ok_or_else(|| AsCfgError::IssuerNotAbsolute(issuer.to_string()))?;
        if issuer.ends_with('/') {
            return Err(AsCfgError::IssuerHasTrailingSlash(issuer.to_string()));
        }
        for scope in &cfg.default_grant {
            if !is_scope_token(scope) {
                return Err(AsCfgError::ScopeNotAToken(scope.clone()));
            }
        }
        validate_clients(&cfg.clients)?;

        let issuer_path = path.trim_end_matches('/').to_string();
        let under = |name: &str| format!("{issuer_path}/{name}");

        Ok(Self {
            issuer: issuer.to_string(),
            // The well-known path is `/.well-known/oauth-authorization-server` at the ROOT, with the
            // issuer's own path appended after it (RFC 8414 §3.1).
            metadata_path: format!("{AS_WELL_KNOWN}{issuer_path}"),
            authorize_path: under("authorize"),
            token_path: under("token"),
            register_path: under("register"),
            jwks_path: under("jwks"),
            consent_path: under("consent"),
            par_path: under("par"),
            fapi2: cfg.fapi2,
            clients: cfg.clients.clone(),
            issuer_path,
            default_grant: cfg.default_grant.clone(),
            access_token_ttl: cfg
                .access_token_ttl_secs
                .map_or(DEFAULT_ACCESS_TOKEN_TTL, std::time::Duration::from_secs),
            key_id: cfg.key_id.clone().unwrap_or_else(|| "busbar-as-1".into()),
            signing_key: cfg.signing_key.clone(),
        })
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }
    pub fn metadata_path(&self) -> &str {
        &self.metadata_path
    }
    pub fn authorize_path(&self) -> &str {
        &self.authorize_path
    }
    pub fn token_path(&self) -> &str {
        &self.token_path
    }
    pub fn register_path(&self) -> &str {
        &self.register_path
    }
    pub fn jwks_path(&self) -> &str {
        &self.jwks_path
    }
    pub fn consent_path(&self) -> &str {
        &self.consent_path
    }
    pub fn par_path(&self) -> &str {
        &self.par_path
    }
    /// The absolute RFC 9126 PAR endpoint URL the metadata advertises. Absolute for the reason
    /// `jwks_uri` is: it is a value clients compare, derived once here.
    pub fn par_endpoint(&self) -> String {
        format!("{}{}", self.origin(), self.par_path)
    }
    /// Whether this plane runs the FAPI 2.0 Security Profile posture.
    pub fn fapi2(&self) -> bool {
        self.fapi2
    }
    /// The absolute URL of the consent screen, which is what the authorize endpoint redirects a
    /// browser to. Absolute because the user agent is following it from wherever it started.
    pub fn consent_url(&self) -> String {
        format!("{}{}", self.origin(), self.consent_path)
    }
    pub fn jwks_uri(&self) -> String {
        format!("{}{}", self.origin(), self.jwks_path)
    }
    /// The issuer's `scheme://authority`, with its path removed: the origin busbar's own protected
    /// resources are served on, which `auth::dpop` makes a proof's `htu` from.
    pub fn origin(&self) -> &str {
        &self.issuer[..self.issuer.len() - self.issuer_path.len()]
    }
    pub fn default_grant(&self) -> &[String] {
        &self.default_grant
    }
    pub fn access_token_ttl(&self) -> std::time::Duration {
        self.access_token_ttl
    }
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
    pub fn signing_key(&self) -> Option<&SecretRef> {
        self.signing_key.as_ref()
    }
}

/// Every `oauth_as.clients:` refusal, at boot, naming the client.
fn validate_clients(clients: &[StaticClientCfg]) -> Result<(), AsCfgError> {
    let mut seen = std::collections::HashSet::new();
    for client in clients {
        let refuse = |why| AsCfgError::StaticClient {
            client_id: client.client_id.clone(),
            why,
        };
        if client.client_id.is_empty() {
            return Err(refuse("client_id is empty"));
        }
        if !seen.insert(client.client_id.as_str()) {
            return Err(refuse("the client_id is declared twice"));
        }
        if client.redirect_uris.is_empty() {
            return Err(refuse(
                "redirect_uris is empty; the authorization code has nowhere to go",
            ));
        }
        // OAuth 2.1 s4.1.3 / RFC 6749 s3.1.2: absolute, no fragment, matched exactly.
        if client
            .redirect_uris
            .iter()
            .any(|u| split_absolute(u).is_none() || u.contains('#'))
        {
            return Err(refuse(
                "every redirect_uri must be an absolute http(s) URL with no fragment",
            ));
        }
        if client.jwks.keys.is_empty() {
            return Err(refuse(
                "jwks.keys is empty; a private_key_jwt client needs a key",
            ));
        }
        let kty = &client.jwks.keys[0].kty;
        if client.jwks.keys.iter().any(|k| &k.kty != kty) {
            return Err(refuse(
                "a client's keys must share one algorithm: all EC (ES256) or all RSA (PS256)",
            ));
        }
        for key in &client.jwks.keys {
            if key.d.is_some() {
                return Err(refuse(
                    "a jwks key carries `d`, a PRIVATE key. Configure the public half only; the \
                     private key stays with the client",
                ));
            }
            validate_public_jwk(key).map_err(refuse)?;
        }
    }
    Ok(())
}

/// The shape of one public key: EC P-256 for ES256, or RSA of at least 2048 bits for PS256.
fn validate_public_jwk(key: &StaticClientJwk) -> Result<(), &'static str> {
    let decoded = |v: &Option<String>| {
        v.as_deref().and_then(|v| {
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, v).ok()
        })
    };
    match key.kty.as_str() {
        "EC" => {
            if key.crv.as_deref() != Some("P-256") {
                return Err("an EC key must be P-256 (ES256)");
            }
            if key.alg.as_deref().is_some_and(|alg| alg != "ES256") {
                return Err("an EC key's `alg`, when given, must be ES256");
            }
            let coordinate = |c: &Option<String>| decoded(c).is_some_and(|b| b.len() == 32);
            if !coordinate(&key.x) || !coordinate(&key.y) {
                return Err("a P-256 coordinate (`x`, `y`) is 32 bytes of unpadded base64url");
            }
        }
        "RSA" => {
            // RS256 is what FAPI 2.0 s5.4.1 forbids; an RSA key here signs PS256 or nothing.
            if key.alg.as_deref().is_some_and(|alg| alg != "PS256") {
                return Err("an RSA key's `alg`, when given, must be PS256");
            }
            let modulus = decoded(&key.n).unwrap_or_default();
            let significant = modulus.iter().skip_while(|b| **b == 0).collect::<Vec<_>>();
            let bits = significant.first().map_or(0, |top| {
                significant.len() * 8 - top.leading_zeros() as usize
            });
            if bits < 2048 {
                return Err(
                    "an RSA modulus (`n`) must be at least 2048 bits of unpadded base64url",
                );
            }
            if decoded(&key.e).is_none_or(|e| e.iter().all(|b| *b == 0)) {
                return Err("an RSA key carries its public exponent (`e`)");
            }
        }
        _ => return Err("only EC P-256 (ES256) and RSA (PS256) keys are accepted"),
    }
    Ok(())
}

/// Split an absolute `http(s)` URL into `(origin, path)`, or `None` when it is not one.
///
/// Hand-written for the same reason `mcp::split_absolute` is: what is needed is a STRICT recogniser
/// for one shape, and a permissive general-purpose parser is the wrong tool for a value whose whole
/// job is to be compared for exact equality. A lenient parse that normalised `HTTPS://Host:443/as`
/// would hand back a string that no longer equals the `iss` a client recorded.
fn split_absolute(uri: &str) -> Option<(&str, &str)> {
    let rest = uri
        .strip_prefix("https://")
        .or_else(|| uri.strip_prefix("http://"))?;
    let authority_len = rest.find('/').unwrap_or(rest.len());
    if authority_len == 0 {
        return None;
    }
    let split = uri.len() - rest.len() + authority_len;
    Some((&uri[..split], &uri[split..]))
}

/// RFC 6749 §3.3 `scope-token`: one or more of `%x21 / %x23-5B / %x5D-7E` — printable ASCII except
/// space, double quote and backslash.
fn is_scope_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b == 0x21 || (0x23..=0x5B).contains(&b) || (0x5D..=0x7E).contains(&b))
}

/// THE KERNEL'S ASK, answered here (`busbar_kernel::oauth_as::seam::AsPlaneSeam::check`): the
/// kernel carries the `oauth_as:` block as an opaque value and hands it to its owner. This parses it
/// (a malformed or unknown key is refused here), validates it ([`AsIdentity::from_cfg`], the same
/// refusals with the same text), and returns every secret reference it carries, so the kernel's
/// `--validate` can resolve them and its boot can resolve the signing key.
pub(crate) fn seam_check(block: &serde_yaml::Value) -> Result<Vec<(String, SecretRef)>, String> {
    let identity = identity_of(block)?;
    Ok(secret_refs(&identity)
        .into_iter()
        .map(|(path, key)| (path, key.clone()))
        .collect())
}

/// Parse and validate the opaque block into the validated identity.
pub(crate) fn identity_of(block: &serde_yaml::Value) -> Result<AsIdentity, String> {
    let cfg: OauthAsCfg =
        serde_yaml::from_value(block.clone()).map_err(|e| format!("oauth_as: {e}"))?;
    AsIdentity::from_cfg(&cfg).map_err(|e| e.to_string())
}

/// Every `SecretRef` the validated `oauth_as:` block carries, as `(config path, reference)`.
///
/// THE ES256 SIGNING KEY. `--validate` must be able to resolve it, because the alternative is a
/// deployment that boots, advertises a JWKS, and fails on the first token request of the day with a
/// secret module error.
///
/// Destructured EXHAUSTIVELY rather than read through `identity.signing_key()`, because the accessor
/// would keep compiling on the day a second `SecretRef` is added to the validated identity, and that
/// second secret would then be one `--validate` calls fine and the process fails on at runtime.
/// Everything below `signing_key` is a derived endpoint path or a policy number, and none of them
/// can ever carry a credential, but each is named here so that ADDING one is a compile error
/// somebody has to answer.
pub(crate) fn secret_refs(identity: &AsIdentity) -> Vec<(String, &SecretRef)> {
    let AsIdentity {
        signing_key,
        // The issuer and the nine paths derived from it. Public by construction: every one of
        // them is published in the RFC 8414 metadata document.
        issuer: _,
        issuer_path: _,
        metadata_path: _,
        authorize_path: _,
        token_path: _,
        register_path: _,
        jwks_path: _,
        consent_path: _,
        par_path: _,
        // Policy, not credential: the FAPI 2.0 posture switch, the scope ceiling, the token
        // lifetime, and the advisory `kid` that appears in every published JWKS entry.
        fapi2: _,
        // Operator-provisioned clients: PUBLIC keys only (a configured `d` is a boot refusal).
        clients: _,
        default_grant: _,
        access_token_ttl: _,
        key_id: _,
    } = identity;
    signing_key
        .iter()
        .map(|key| (SIGNING_KEY_PATH.to_string(), key))
        .collect()
}

/// The config path the signing key's reference is reported under.
pub(crate) const SIGNING_KEY_PATH: &str = "oauth_as.signing_key";
