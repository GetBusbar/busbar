// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Generation-owned native credentials, selected by the actual pool/member attempt.

use std::collections::BTreeMap;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use busbar_contract::config::UpstreamCreds;
use busbar_contract::conn::OwnedHead;
use busbar_contract::dest::DestinationId;
use busbar_contract::secure::SecureVec;
use busbar_plugin_abi::auth::{FB_NEEDS_BODY_HASH, STYLE_CALLER, STYLE_PER_REQUEST, STYLE_SCOPE};
use busbar_plugin_abi::host_side::caller::BoxFut;
use busbar_ports::auth::{AuthPort, OutboundAnswer, UpstreamIn};
use busbar_ports::{CallCx, PortError};

use super::OwnedUpstreamIn;
use crate::audit_ring::{OUTCOME_APPLIED, OUTCOME_DEGRADED, OUTCOME_REJECTED};
use crate::custody::{
    CredCache, CredGet, CredKey, CredObserver, CredOutcome, CredentialCache, CONFIRM_AFTER,
};
use crate::diagnostics::{UPSTREAM_CREDENTIAL_LAPSED, UPSTREAM_CREDENTIAL_REFRESH_FAILED};
use crate::refresh::{Report, Throttle, HOST_REPORT};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SelectedRouteKey {
    pub plane: Box<str>,
    pub pool: Box<str>,
    pub member: Box<str>,
}

/// Root supplies only admitted, same-generation values. The namespace is allocated once across
/// every selected row using the generation's cache, never from a plane-local destination number.
pub struct NativeBindingSpec {
    pub key: SelectedRouteKey,
    pub destination: DestinationId,
    pub upstream: Box<str>,
    pub auth_instance: u64,
    pub credential_namespace: u64,
    pub style_flags: u64,
    pub mode: UpstreamCreds,
    pub cache_max_s: Option<u32>,
}

pub struct NativeBinding {
    spec: NativeBindingSpec,
    port: Arc<dyn AuthPort>,
    cache: Arc<CredCache>,
    /// Registered (weakly) with the cache for this binding's keys; lives as long as the binding.
    _report: Arc<NativeReport>,
}

/// The audit action of every BUSBAR-8026/8027 report and of a recovery.
pub const REFRESH_ACTION: &str = "upstream_credential.refresh";

/// Names a binding's member in its credential reports. Its source is the auth instance that mints the value: the
/// members it serves share one BUSBAR-8026 rate. Never carries the credential or a digest of it.
struct NativeReport {
    plane: Box<str>,
    pool: Box<str>,
    member: Box<str>,
    upstream: Box<str>,
    auth_instance: u64,
    style: &'static str,
    report: &'static dyn Report,
}

impl NativeReport {
    fn source(&self) -> String {
        format!("auth:{}", self.auth_instance)
    }

    fn resource(&self) -> String {
        format!("member:{}/{}/{}", self.plane, self.pool, self.member)
    }

    fn fields(&self, cause: &'static str, code: u32) -> Vec<(&'static str, String)> {
        vec![
            ("plane", self.plane.to_string()),
            ("pool", self.pool.to_string()),
            ("member", self.member.to_string()),
            ("upstream", self.upstream.to_string()),
            ("reference", self.source()),
            ("style", self.style.to_string()),
            ("cause", cause.to_string()),
            ("error_kind", code.to_string()),
        ]
    }
}

fn millis(d: Duration) -> String {
    d.as_millis().to_string()
}

impl CredObserver for NativeReport {
    fn observe(&self, outcome: CredOutcome, now: Instant, gate: &Throttle) {
        use busbar_plugin_abi::fail::refused::R_NOT_FOUND;
        use tracing::Level;
        match outcome {
            CredOutcome::Failed {
                streak,
                code,
                retry_in,
                expires_in,
            } => {
                let mut fields = self.fields("resolve", code);
                fields.push(("failures", streak.to_string()));
                fields.push(("retry_in_ms", millis(retry_in)));
                fields.push((
                    "expires_in_ms",
                    expires_in.map_or_else(|| "0".to_string(), millis),
                ));
                self.refresh_failed(
                    gate,
                    now,
                    fields,
                    "the member's upstream credential could not be refreshed; the value held is kept until it expires",
                    Level::WARN,
                );
            }
            CredOutcome::Confirming { code } => {
                let what = if code == R_NOT_FOUND {
                    "not-found"
                } else {
                    "permission-denied"
                };
                let mut fields = self.fields("resolve", code);
                fields.push(("answer", what.to_string()));
                fields.push(("confirm_in_ms", millis(CONFIRM_AFTER)));
                self.refresh_failed(
                    gate,
                    now,
                    fields,
                    "the member's upstream credential source answered definitively; it is dropped if a re-read confirms it",
                    Level::WARN,
                );
            }
            CredOutcome::Revoked { code } => {
                self.report.diag(
                    &UPSTREAM_CREDENTIAL_LAPSED,
                    Level::ERROR,
                    "the member's upstream credential was revoked at its source and is no longer presented",
                    &self.fields("revoked-at-source", code),
                );
                self.report
                    .audit(REFRESH_ACTION, &self.resource(), OUTCOME_REJECTED);
            }
            CredOutcome::Lapsed => {
                self.report.diag(
                    &UPSTREAM_CREDENTIAL_LAPSED,
                    Level::ERROR,
                    "the member's upstream credential expired unrenewed and is no longer presented",
                    &self.fields("lease-expired", 0),
                );
                self.report
                    .audit(REFRESH_ACTION, &self.resource(), OUTCOME_REJECTED);
            }
            CredOutcome::Recovered => {
                let fields = vec![
                    ("plane", self.plane.to_string()),
                    ("pool", self.pool.to_string()),
                    ("member", self.member.to_string()),
                    ("reference", self.source()),
                ];
                self.report
                    .info("the member's upstream credential refreshed again", &fields);
                self.report
                    .audit(REFRESH_ACTION, &self.resource(), OUTCOME_APPLIED);
            }
        }
    }
}

impl NativeReport {
    /// BUSBAR-8026 at `level` once per source per minute, audited degraded; the rest at debug, counted in the next.
    fn refresh_failed(
        &self,
        gate: &Throttle,
        now: Instant,
        mut fields: Vec<(&'static str, String)>,
        message: &str,
        level: tracing::Level,
    ) {
        match gate.pass(&self.source(), now) {
            Some(others) => {
                fields.push(("others", others.to_string()));
                self.report
                    .diag(&UPSTREAM_CREDENTIAL_REFRESH_FAILED, level, message, &fields);
                self.report
                    .audit(REFRESH_ACTION, &self.resource(), OUTCOME_DEGRADED);
            }
            None => self.report.diag(
                &UPSTREAM_CREDENTIAL_REFRESH_FAILED,
                tracing::Level::DEBUG,
                message,
                &fields,
            ),
        }
    }
}

fn refused() -> PortError {
    PortError::Refused {
        code: busbar_plugin_abi::fail::refused::R_POLICY,
        text: "native outbound credential unavailable".into(),
        error: None,
    }
}

impl NativeBinding {
    pub fn new(
        spec: NativeBindingSpec,
        port: Arc<dyn AuthPort>,
        cache: Arc<CredCache>,
    ) -> Result<Self, PortError> {
        Self::reporting(spec, port, cache, &HOST_REPORT)
    }

    /// As `new`, reporting this binding's credential outcomes (BUSBAR-8026/8027) to `report`.
    pub fn reporting(
        spec: NativeBindingSpec,
        port: Arc<dyn AuthPort>,
        cache: Arc<CredCache>,
        report: &'static dyn Report,
    ) -> Result<Self, PortError> {
        // Caller/grant provenance and durable delivery admission are a separately held activation.
        if spec.mode != UpstreamCreds::Own
            || spec.style_flags & STYLE_CALLER != 0
            || spec.auth_instance == 0
            || spec.credential_namespace == 0
            || spec.key.plane.is_empty()
            || spec.key.pool.is_empty()
            || spec.key.member.is_empty()
            || spec.upstream.is_empty()
        {
            return Err(refused());
        }
        let observer = Arc::new(NativeReport {
            plane: spec.key.plane.clone(),
            pool: spec.key.pool.clone(),
            member: spec.key.member.clone(),
            upstream: spec.upstream.clone(),
            auth_instance: spec.auth_instance,
            style: if spec.style_flags & STYLE_SCOPE != 0 {
                "scoped"
            } else {
                "shared"
            },
            report,
        });
        let weak: Weak<dyn CredObserver> = Arc::downgrade(&observer) as Weak<dyn CredObserver>;
        cache.observe(spec.auth_instance, spec.credential_namespace, weak);
        Ok(Self {
            spec,
            port,
            cache,
            _report: observer,
        })
    }

    pub fn key(&self) -> &SelectedRouteKey {
        &self.spec.key
    }
    pub fn destination(&self) -> DestinationId {
        self.spec.destination
    }
    pub fn needs_body_hash(&self) -> bool {
        self.port.facts() & FB_NEEDS_BODY_HASH != 0
    }
    pub fn scoped(&self) -> bool {
        self.spec.style_flags & STYLE_SCOPE != 0
    }
    pub fn cache_key(&self, scope: Option<&str>) -> CredKey {
        CredKey {
            auth_instance: self.spec.auth_instance,
            upstream: self.spec.credential_namespace,
            scope: if self.scoped() {
                scope
                    .map(|s| busbar_contract::crypto::sha256(s.as_bytes()))
                    .unwrap_or([0; 32])
            } else {
                [0; 32]
            },
            caller: [0; 32],
        }
    }

    /// One native port call per mint. Direct styles allocate only the port's own future.
    pub async fn credential(
        &self,
        cx: CallCx,
        req: &UpstreamIn<'_>,
    ) -> Result<NativeCredential, PortError> {
        if !req.caller_cred.is_empty() || req.caller_grant.is_some() {
            return Err(refused());
        }
        let input = UpstreamIn {
            method: req.method,
            url: req.url,
            headers: req.headers,
            body_sha256: req.body_sha256.filter(|_| self.needs_body_hash()),
            caller_cred: &[],
            scope: req.scope.filter(|_| self.scoped()),
            caller_grant: None,
            min_valid_s: self.cache.policy().refresh_ahead_s,
        };
        if self.spec.style_flags & STYLE_PER_REQUEST != 0 {
            return complete(self.port.outbound(cx, &input).await?, None)
                .map(NativeCredential::Direct);
        }
        let cap = self.spec.cache_max_s;
        let mint = || -> BoxFut<'_, Result<OutboundAnswer, PortError>> {
            Box::pin(async { complete(self.port.outbound(cx, &input).await?, cap) })
        };
        let detach = || -> BoxFut<'static, Result<OutboundAnswer, PortError>> {
            let port = Arc::clone(&self.port);
            let owned = OwnedUpstreamIn::copy(&input);
            Box::pin(async move { complete(owned.call(&*port, cx).await?, cap) })
        };
        let result = match self.cache.get(
            self.cache_key(input.scope),
            false,
            tokio::time::Instant::now().into_std(),
            mint,
            &detach,
        ) {
            CredGet::Ready(result) => result.map(NativeCredential::Shared),
            CredGet::Wait(wait) => wait.await.map(NativeCredential::Shared),
            CredGet::Direct(direct) => direct.await.map(NativeCredential::Direct),
        };
        result
    }
}

fn complete(mut answer: OutboundAnswer, cap: Option<u32>) -> Result<OutboundAnswer, PortError> {
    if answer.grant_update.is_some() {
        return Err(refused());
    }
    if let Some(cap) = cap {
        answer.cache_s = answer.cache_s.min(cap);
    }
    Ok(answer)
}

#[derive(Clone)]
pub enum SelectedCredential {
    None,
    Required(Arc<NativeBinding>),
}

/// Pool -> member -> the destination and the credential its route selects.
type BindingRows = BTreeMap<Box<str>, BTreeMap<Box<str>, (DestinationId, SelectedCredential)>>;

/// Every configured row is explicit, including no-auth rows. Omission never grants permission.
#[derive(Clone)]
pub struct NativeRouteBindings {
    rows: BindingRows,
}

impl NativeRouteBindings {
    pub fn new(
        rows: impl IntoIterator<Item = (Box<str>, Box<str>, DestinationId, SelectedCredential)>,
    ) -> Result<Self, PortError> {
        let mut bindings: BindingRows = BTreeMap::new();
        for (pool, member, destination, credential) in rows {
            if pool.is_empty() || member.is_empty() {
                return Err(refused());
            }
            if let SelectedCredential::Required(binding) = &credential {
                if binding.key().pool != pool
                    || binding.key().member != member
                    || binding.destination() != destination
                {
                    return Err(refused());
                }
            }
            if bindings
                .entry(pool)
                .or_default()
                .insert(member, (destination, credential))
                .is_some()
            {
                return Err(refused());
            }
        }
        Ok(Self { rows: bindings })
    }

    pub fn select(
        &self,
        pool: &str,
        member: &str,
        destination: DestinationId,
    ) -> Result<&SelectedCredential, PortError> {
        let (stored, credential) = self
            .rows
            .get(pool)
            .and_then(|rows| rows.get(member))
            .ok_or_else(refused)?;
        if *stored != destination {
            return Err(refused());
        }
        Ok(credential)
    }
}

/// No secret-bearing Debug or historical AuthField conversion exists on this path.
pub enum NativeCredential {
    Shared(Arc<OutboundAnswer>),
    Direct(OutboundAnswer),
}

impl NativeCredential {
    pub fn answer(&self) -> &OutboundAnswer {
        match self {
            Self::Shared(answer) => answer,
            Self::Direct(answer) => answer,
        }
    }
    pub fn require_secure(&self) -> bool {
        let answer = self.answer();
        !answer.headers.is_empty() || !answer.query.is_empty()
    }
    pub fn covers_header(&self, name: &[u8]) -> bool {
        self.answer()
            .headers
            .iter()
            .any(|(n, _)| n.as_bytes().eq_ignore_ascii_case(name))
    }
    pub fn sealed_names(&self) -> Vec<String> {
        self.answer()
            .headers
            .iter()
            .map(|(n, _)| n.to_ascii_lowercase())
            .collect()
    }
    pub fn append_to(self, head: &mut OwnedHead) {
        match self {
            Self::Direct(answer) => {
                for (name, value) in answer.headers {
                    head.push(name.into(), value.into_vec());
                }
                for (name, value) in answer.query {
                    append_query(head, &name, &value);
                }
            }
            Self::Shared(answer) => {
                for (name, value) in &answer.headers {
                    head.push(name.to_string(), value.to_vec());
                }
                for (name, value) in &answer.query {
                    append_query(head, name, value);
                }
            }
        }
    }
}

fn append_query(head: &mut OwnedHead, name: &str, value: &[u8]) {
    let mut encoded = SecureVec::new();
    percent_encode(&mut encoded, name.as_bytes());
    encoded.extend_from_slice(b"=");
    percent_encode(&mut encoded, value);
    head.push(
        busbar_contract::conn::SEALED_QUERY_FIELD.to_owned(),
        encoded.into_vec(),
    );
}
fn percent_encode(out: &mut SecureVec, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &b in bytes {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.extend_from_slice(&[b]);
        } else {
            out.extend_from_slice(&[b'%', HEX[usize::from(b >> 4)], HEX[usize::from(b & 15)]]);
        }
    }
}
