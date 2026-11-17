// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! [`StoreConnections`]: caller connections over the plugin-records store (IF §12.12).
//!
//! - **Grants** live in the core sub-namespace (plane plugin, plane instance name, "connect"), in the caller's
//!   subject scope (SHA-256 of the verified ID_SUBJECT, as a plane's LK_CALLER record), keyed by the configured
//!   upstream name. The value is sealed (AES-256-CTR, then HMAC-SHA256 over the binding and the ciphertext; both
//!   keys derived with HKDF-SHA256 from core's at-rest key, all through `busbar-crypto`), and the MAC binds the
//!   row to (plugin, name, subject, upstream), so a row copied under another key does not open. Grants never
//!   expire on their own; REVOKE, an `outbound` R_CONNECT_REQUIRED ([`settle_outbound`]) or a new grant replace
//!   them. Keyed by names, never runtime ids, so a grant survives restart and reconfigure and every replica reads
//!   it.
//! - **Login state**: BEGIN mints the PKCE verifier, its S256 challenge, the state key and the nonce
//!   ([`super::pkce`]), runs the upstream's auth instance `login(Begin)` and keeps one sealed row per state key in
//!   a core-only namespace (no plugin stamp holds a NUL), TTL [`LOGIN_TTL_S`] (the hosted login cookie's), holding
//!   the plane, the subject, the upstream, `return_to`, the verifier, the nonce and the plugin's STATE. The
//!   callback ([`StoreConnections::callback`]) takes that row once (read and delete in one commit), so a state is
//!   redeemed at most once on any replica, then runs `login(Complete)` and stores the GRANT.

use std::sync::Arc;
use std::time::{Duration, Instant};

use busbar_contract::crypto;
use busbar_contract::secure::SecureVec;
use busbar_plugin_abi::auth::{FB_LOGIN_REDIRECT, SECURITY_CHECK};
use busbar_plugin_abi::fail::refused::R_CONNECT_REQUIRED;
use busbar_plugin_abi::host_side::caller::{BoxFut, CallStack, Caller, InstanceLimits};
use busbar_plugin_abi::plane::{CONN_NONE, CONN_READY, CONN_REFUSED};
use busbar_plugin_abi::types::KindCode;
use busbar_ports::auth::{AuthPort, LoginAnswer, LoginIn, OutboundAnswer};
use busbar_ports::{CallCx, PortError};

use super::callback::CallbackAnswer;
use super::pkce;
use super::CallerConnections;
use crate::plane_grants::{core_caller, core_name};
use crate::plugin_records::{CommitOp, CommitOutcome, PluginRecords, RecordsDenied, Scope};
use crate::upstreams::{UpstreamAuth, Upstreams};

/// The core sub-namespace tag of a plane's grants.
const TAG: &str = "connect";
/// The core-only namespace of pending logins: a stamp name no plugin can hold (it starts with NUL).
const LOGIN_PLUGIN: &str = "\0busbar";
const LOGIN_NAME: &str = "connect-login";
/// How long a BEGIN's login state lives, seconds (the hosted login cookie's `LOGIN_COOKIE_MAX_AGE`).
pub const LOGIN_TTL_S: u64 = 600;
/// The callback's own deadline for the store and the plugin's COMPLETE (the browser request has none of core's).
const CALLBACK_DEADLINE: Duration = Duration::from_secs(30);
const SEAL_INFO: &[u8] = b"busbar.connections.v1";
const IV: usize = 16;
const MAC: usize = 32;
const GRANT_KEY: &[u8] = b"grant/";

/// The opened auth instances a caller connection can run its login through, by configured instance name. The
/// boot's auth instances answer it; an instance that is not open answers `None` (BEGIN refuses, STATUS answers
/// CONN_NONE).
pub trait ConnectLogins: Send + Sync + 'static {
    fn port(&self, instance: &str) -> Option<Arc<dyn AuthPort>>;
}

/// AES-256-CTR + HMAC-SHA256 under keys derived from core's at-rest key.
struct Seal {
    enc: SecureVec,
    mac: SecureVec,
}

impl Seal {
    fn new(at_rest_key: &[u8]) -> Option<Self> {
        if at_rest_key.len() < 32 {
            return None;
        }
        let mut enc = SecureVec::zeroed(32);
        let mut mac = SecureVec::zeroed(32);
        crypto::hkdf_sha256(SEAL_INFO, at_rest_key, b"enc", &mut enc[..]).ok()?;
        crypto::hkdf_sha256(SEAL_INFO, at_rest_key, b"mac", &mut mac[..]).ok()?;
        Some(Self { enc, mac })
    }

    /// `iv ‖ ciphertext ‖ HMAC(binding ‖ iv ‖ ciphertext)`.
    fn seal(&self, binding: &[u8], plain: &[u8]) -> Option<Vec<u8>> {
        let iv: [u8; IV] = crypto::random::<IV>().ok()?;
        let mut out = Vec::with_capacity(IV + plain.len() + MAC);
        out.extend_from_slice(&iv);
        out.resize(IV + plain.len(), 0);
        crypto::aes_ctr::apply(self.enc.as_slice(), &iv, plain, &mut out[IV..]).ok()?;
        let tag =
            crypto::hmac_sha256(self.mac.as_slice(), &[binding, out.as_slice()].concat()).ok()?;
        out.extend_from_slice(&tag);
        Some(out)
    }

    fn open(&self, binding: &[u8], sealed: &[u8]) -> Option<SecureVec> {
        if sealed.len() < IV + MAC {
            return None;
        }
        let (body, tag) = sealed.split_at(sealed.len() - MAC);
        crypto::hmac_sha256_verify(self.mac.as_slice(), &[binding, body].concat(), tag).ok()?;
        let iv: [u8; IV] = body[..IV].try_into().ok()?;
        let mut plain = SecureVec::zeroed(body.len() - IV);
        crypto::aes_ctr::apply(self.enc.as_slice(), &iv, &body[IV..], &mut plain[..]).ok()?;
        Some(plain)
    }
}

/// Length-framed fields (u32 BE length, then the bytes).
fn framed(fields: &[&[u8]]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(fields.iter().map(|f| 4 + f.len()).sum());
    for field in fields {
        out.extend_from_slice(&u32::try_from(field.len()).ok()?.to_be_bytes());
        out.extend_from_slice(field);
    }
    Some(out)
}

/// The inverse of [`framed`] for exactly `N` fields.
fn unframed<const N: usize>(mut bytes: &[u8]) -> Option<[Vec<u8>; N]> {
    let mut out: [Vec<u8>; N] = std::array::from_fn(|_| Vec::new());
    for field in &mut out {
        let (len, rest) = bytes.split_at_checked(4)?;
        let len = usize::try_from(u32::from_be_bytes(len.try_into().ok()?)).ok()?;
        let (text, rest) = rest.split_at_checked(len)?;
        *field = text.to_vec();
        bytes = rest;
    }
    bytes.is_empty().then_some(out)
}

fn grant_binding(plugin: &str, name: &str, subject: &str, upstream: &str) -> Option<Vec<u8>> {
    framed(&[
        b"grant".as_slice(),
        plugin.as_bytes(),
        name.as_bytes(),
        subject.as_bytes(),
        upstream.as_bytes(),
    ])
}

fn login_binding(state_key: &str) -> Option<Vec<u8>> {
    framed(&[b"login".as_slice(), state_key.as_bytes()])
}

fn grant_key(upstream: &str) -> Vec<u8> {
    [GRANT_KEY, upstream.as_bytes()].concat()
}

/// The caller's subject scope: SHA-256 of the verified ID_SUBJECT (IF §12.5), as a plane's LK_CALLER record.
fn subject_scope(subject: &str) -> Scope {
    Scope {
        subject: Some(crypto::sha256(subject.as_bytes())),
    }
}

/// A caller for a namespace core addresses by name alone (the callback has no plane chain).
fn named_caller<'a>(plugin: &'a str, name: &'a str, deadline: Instant) -> Caller<'a> {
    Caller {
        plugin,
        kind: KindCode::Plane,
        name,
        instance: 0,
        slot: 0,
        chain: 0,
        deadline,
        stack: CallStack::default(),
        out_of_process: false,
        limits: InstanceLimits::default(),
    }
}

/// One pending login, as BEGIN keeps it.
struct LoginRow {
    plugin: String,
    name: String,
    subject: String,
    upstream: String,
    return_to: String,
    verifier: String,
    nonce: String,
    state: SecureVec,
}

impl LoginRow {
    fn encode(&self) -> Option<SecureVec> {
        framed(&[
            self.plugin.as_bytes(),
            self.name.as_bytes(),
            self.subject.as_bytes(),
            self.upstream.as_bytes(),
            self.return_to.as_bytes(),
            self.verifier.as_bytes(),
            self.nonce.as_bytes(),
            self.state.as_slice(),
        ])
        .map(SecureVec::from)
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        let [plugin, name, subject, upstream, return_to, verifier, nonce, state] =
            unframed::<8>(bytes)?;
        let text = |v: Vec<u8>| String::from_utf8(v).ok();
        Some(Self {
            plugin: text(plugin)?,
            name: text(name)?,
            subject: text(subject)?,
            upstream: text(upstream)?,
            return_to: text(return_to)?,
            verifier: text(verifier)?,
            nonce: text(nonce)?,
            state: SecureVec::from(state),
        })
    }
}

/// Caller connections over the plugin-records store `R`.
pub struct StoreConnections<R> {
    records: R,
    seal: Seal,
    upstreams: Arc<dyn Upstreams>,
    logins: Arc<dyn ConnectLogins>,
    /// `server.public_url`, without a trailing `/`: the origin BEGIN's `redirect_uri` and `return_to` are judged on.
    public_url: Box<str>,
}

impl<R: PluginRecords> StoreConnections<R> {
    /// Connections over `records`, sealed under keys derived from core's at-rest key (≥ 32 bytes), for the
    /// configured `upstreams`, logging in through `logins`, at `public_url`. `None` when the key is short or the
    /// derivation is refused.
    pub fn new(
        records: R,
        at_rest_key: &[u8],
        upstreams: Arc<dyn Upstreams>,
        logins: Arc<dyn ConnectLogins>,
        public_url: &str,
    ) -> Option<Self> {
        Some(Self {
            records,
            seal: Seal::new(at_rest_key)?,
            upstreams,
            logins,
            public_url: public_url.trim_end_matches('/').into(),
        })
    }

    /// The upstream's caller-connection binding: an `auth` with a `connection` form (a callback path) whose
    /// instance is open and declared FB_LOGIN_REDIRECT. Anything else is no connection (IF §12.12 round 21).
    fn binding(&self, upstream: &str) -> Option<(UpstreamAuth, Arc<dyn AuthPort>)> {
        let def = self.upstreams.get(upstream)?;
        let auth = def.auth.clone()?;
        auth.connect_callback.as_ref()?;
        let port = self.logins.port(&auth.instance)?;
        (port.facts() & FB_LOGIN_REDIRECT != 0).then_some((auth, port))
    }

    fn redirect_uri(&self, callback: &str) -> String {
        format!("{}{callback}", self.public_url)
    }

    /// Where the callback sends the browser: a same-origin path, or a URL on `public_url`; `None` = refused (no
    /// open redirect). Absent = `/`.
    fn return_to(&self, asked: Option<&str>) -> Option<String> {
        let Some(asked) = asked else {
            return Some("/".to_owned());
        };
        let path = asked.starts_with('/') && !asked.starts_with("//") && !asked.contains('\\');
        let ours = !self.public_url.is_empty()
            && asked
                .strip_prefix(&*self.public_url)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'));
        (path || ours).then(|| asked.to_owned())
    }

    async fn put_grant(
        &self,
        plane: &Caller<'_>,
        subject: &str,
        upstream: &str,
        grant: &[u8],
    ) -> Result<(), RecordsDenied> {
        let binding = grant_binding(plane.plugin, plane.name, subject, upstream)
            .ok_or(RecordsDenied::TooLarge)?;
        let sealed = self
            .seal
            .seal(&binding, grant)
            .ok_or(RecordsDenied::Unavailable)?;
        let name = core_name(plane.name, TAG);
        let ns = core_caller(plane, &name);
        self.records
            .put(
                &ns,
                subject_scope(subject),
                &grant_key(upstream),
                &sealed,
                0,
            )
            .await
    }

    async fn read_grant(
        &self,
        plane: &Caller<'_>,
        subject: &str,
        upstream: &str,
    ) -> Result<Option<SecureVec>, RecordsDenied> {
        let name = core_name(plane.name, TAG);
        let ns = core_caller(plane, &name);
        let mut row = None::<Vec<u8>>;
        let found = self
            .records
            .get(
                &ns,
                subject_scope(subject),
                &grant_key(upstream),
                &mut |v| {
                    row = Some(v.to_vec());
                },
            )
            .await?;
        let (true, Some(row)) = (found, row) else {
            return Ok(None);
        };
        let binding = grant_binding(plane.plugin, plane.name, subject, upstream)
            .ok_or(RecordsDenied::TooLarge)?;
        // A row that does not open under this binding is not this caller's grant (tampered or misplaced).
        Ok(self.seal.open(&binding, &row))
    }

    async fn delete_grant(
        &self,
        plane: &Caller<'_>,
        subject: &str,
        upstream: &str,
    ) -> Result<(), RecordsDenied> {
        let name = core_name(plane.name, TAG);
        let ns = core_caller(plane, &name);
        self.records
            .del(&ns, subject_scope(subject), &grant_key(upstream))
            .await
    }

    /// Takes the login row of `state_key` once: read, then read-and-delete in one commit, so exactly one
    /// callback on any replica redeems it. `None` = unknown, expired, spent or not openable.
    async fn take_login(&self, state_key: &str, deadline: Instant) -> Option<LoginRow> {
        let ns = named_caller(LOGIN_PLUGIN, LOGIN_NAME, deadline);
        let key = state_key.as_bytes();
        let mut row = None::<Vec<u8>>;
        let found = self
            .records
            .get(&ns, Scope::default(), key, &mut |v| row = Some(v.to_vec()))
            .await
            .ok()?;
        let row = row.filter(|_| found)?;
        let ops = [
            CommitOp::Equals {
                key,
                value: &row,
                caller: false,
            },
            CommitOp::Del { key, caller: false },
        ];
        match self
            .records
            .commit(&ns, Scope::default(), &ops)
            .await
            .ok()?
        {
            CommitOutcome::Applied => {}
            CommitOutcome::Conflict { .. } => return None,
        }
        let plain = self.seal.open(&login_binding(state_key)?, &row)?;
        LoginRow::decode(&plain)
    }

    /// The browser callback on an upstream's `connect_callback` path (IF §12.12): `path` is the request path,
    /// `query` its raw query. Takes the login state named by `state`, runs the upstream's auth instance
    /// `login(Complete)` with the kept verifier and nonce, stores the GRANT and answers where to send the browser.
    /// A state that is unknown, spent, expired or minted for another callback path, and a plugin SECURITY_CHECK
    /// (e.g. an `iss` mismatch), are the security-check page; any other failure is the failed page.
    pub async fn callback(&self, path: &str, query: &str) -> CallbackAnswer {
        let deadline = Instant::now() + CALLBACK_DEADLINE;
        let Some(state_key) = url::form_urlencoded::parse(query.as_bytes())
            .find(|(k, _)| k == "state")
            .map(|(_, v)| v.into_owned())
        else {
            return CallbackAnswer::SecurityCheck;
        };
        let Some(row) = self.take_login(&state_key, deadline).await else {
            return CallbackAnswer::SecurityCheck;
        };
        let Some((auth, port)) = self.binding(&row.upstream) else {
            return CallbackAnswer::Failed;
        };
        let Some(callback) = auth.connect_callback.as_deref() else {
            return CallbackAnswer::Failed;
        };
        if callback != path {
            return CallbackAnswer::SecurityCheck;
        }
        let redirect_uri = self.redirect_uri(callback);
        let cx = CallCx {
            deadline,
            request_id: 0,
            stack: CallStack::default(),
        };
        let answer = port
            .login(
                cx,
                LoginIn::Complete {
                    callback_query: query,
                    state: row.state.as_slice(),
                    redirect_uri: &redirect_uri,
                    code_verifier: &row.verifier,
                    nonce: &row.nonce,
                    connect: Some(row.upstream.as_str()),
                },
            )
            .await;
        let grant = match answer {
            Ok(LoginAnswer::Grant(grant)) => grant,
            Err(PortError::Refused { code, .. }) if code == SECURITY_CHECK => {
                return CallbackAnswer::SecurityCheck;
            }
            Ok(_) | Err(_) => return CallbackAnswer::Failed,
        };
        let plane = named_caller(&row.plugin, &row.name, deadline);
        match self
            .put_grant(&plane, &row.subject, &row.upstream, grant.as_slice())
            .await
        {
            Ok(()) => CallbackAnswer::Connected {
                location: row.return_to.into(),
            },
            Err(_) => CallbackAnswer::Failed,
        }
    }
}

impl<R: PluginRecords> CallerConnections for StoreConnections<R> {
    fn begin<'a>(
        &'a self,
        who: &'a Caller<'_>,
        subject: &'a str,
        upstream: &'a str,
        return_to: Option<&'a str>,
    ) -> BoxFut<'a, Result<Box<str>, RecordsDenied>> {
        Box::pin(async move {
            let (auth, port) = self.binding(upstream).ok_or(RecordsDenied::Invalid)?;
            let callback = auth
                .connect_callback
                .as_deref()
                .ok_or(RecordsDenied::Invalid)?;
            let return_to = self.return_to(return_to).ok_or(RecordsDenied::Invalid)?;
            let redirect_uri = self.redirect_uri(callback);
            let verifier =
                pkce::random_b64url(pkce::VERIFIER_BYTES).ok_or(RecordsDenied::Unavailable)?;
            let challenge = pkce::code_challenge_s256(&verifier);
            let state_key =
                pkce::random_b64url(pkce::STATE_BYTES).ok_or(RecordsDenied::Unavailable)?;
            let nonce = pkce::random_b64url(pkce::STATE_BYTES).ok_or(RecordsDenied::Unavailable)?;
            let cx = CallCx {
                deadline: who.deadline,
                request_id: 0,
                stack: who.stack,
            };
            let answer = port
                .login(
                    cx,
                    LoginIn::Begin {
                        return_to: &return_to,
                        redirect_uri: &redirect_uri,
                        state_key: &state_key,
                        code_challenge: &challenge,
                        nonce: &nonce,
                        connect: Some(upstream),
                        scope: None,
                    },
                )
                .await;
            let (url, state) = match answer {
                Ok(LoginAnswer::Redirect { url, state }) => (url, state),
                Ok(_) => return Err(RecordsDenied::Invalid),
                Err(_) => return Err(RecordsDenied::Unavailable),
            };
            let row = LoginRow {
                plugin: who.plugin.to_owned(),
                name: who.name.to_owned(),
                subject: subject.to_owned(),
                upstream: upstream.to_owned(),
                return_to,
                verifier,
                nonce,
                state,
            };
            let plain = row.encode().ok_or(RecordsDenied::TooLarge)?;
            let binding = login_binding(&state_key).ok_or(RecordsDenied::TooLarge)?;
            let sealed = self
                .seal
                .seal(&binding, plain.as_slice())
                .ok_or(RecordsDenied::Unavailable)?;
            let ns = named_caller(LOGIN_PLUGIN, LOGIN_NAME, who.deadline);
            self.records
                .put(
                    &ns,
                    Scope::default(),
                    state_key.as_bytes(),
                    &sealed,
                    LOGIN_TTL_S,
                )
                .await?;
            Ok(url)
        })
    }

    fn status<'a>(
        &'a self,
        who: &'a Caller<'_>,
        subject: &'a str,
        upstream: &'a str,
    ) -> BoxFut<'a, u32> {
        Box::pin(async move {
            if self.binding(upstream).is_none() {
                return CONN_NONE;
            }
            match self.read_grant(who, subject, upstream).await {
                Ok(Some(_)) => CONN_READY,
                Ok(None) => CONN_NONE,
                // The store could not answer: never a guessed READY or NONE.
                Err(_) => CONN_REFUSED,
            }
        })
    }

    fn revoke<'a>(
        &'a self,
        who: &'a Caller<'_>,
        subject: &'a str,
        upstream: &'a str,
    ) -> BoxFut<'a, Result<(), RecordsDenied>> {
        Box::pin(async move {
            if self.binding(upstream).is_none() {
                return Err(RecordsDenied::Invalid);
            }
            self.delete_grant(who, subject, upstream).await
        })
    }

    fn grant<'a>(
        &'a self,
        plane: &'a Caller<'_>,
        subject: &'a str,
        upstream: &'a str,
    ) -> BoxFut<'a, Option<SecureVec>> {
        Box::pin(async move {
            self.read_grant(plane, subject, upstream)
                .await
                .ok()
                .flatten()
        })
    }

    fn update<'a>(
        &'a self,
        plane: &'a Caller<'_>,
        subject: &'a str,
        upstream: &'a str,
        grant: &'a [u8],
    ) -> BoxFut<'a, Result<(), RecordsDenied>> {
        Box::pin(async move { self.put_grant(plane, subject, upstream, grant).await })
    }
}

/// What a caller-mode exchange's `outbound` answer does to the stored grant (IF §12.12, §12.2 rule 7): a
/// GRANT_UPDATE replaces it (stored before the credential is published); a REFUSED R_CONNECT_REQUIRED while a
/// grant was `passed` deletes it (the server revoked it), so STATUS answers CONN_NONE and the exchange fails
/// R_CONNECT_REQUIRED. Anything else leaves the grant as it is.
pub async fn settle_outbound(
    connections: &dyn CallerConnections,
    plane: &Caller<'_>,
    subject: &str,
    upstream: &str,
    passed: bool,
    answer: &Result<OutboundAnswer, PortError>,
) -> Result<(), RecordsDenied> {
    match answer {
        Ok(OutboundAnswer {
            grant_update: Some(grant),
            ..
        }) => {
            connections
                .update(plane, subject, upstream, grant.as_slice())
                .await
        }
        Err(PortError::Refused { code, .. }) if passed && *code == R_CONNECT_REQUIRED => {
            connections.revoke(plane, subject, upstream).await
        }
        _ => Ok(()),
    }
}
