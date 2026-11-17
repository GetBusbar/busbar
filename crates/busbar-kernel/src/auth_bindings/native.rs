// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Generation-owned native credentials, selected by the actual pool/member attempt.

use std::collections::BTreeMap;
use std::sync::Arc;

use busbar_contract::config::UpstreamCreds;
use busbar_contract::conn::OwnedHead;
use busbar_contract::dest::DestinationId;
use busbar_contract::secure::SecureVec;
use busbar_plugin_abi::auth::{FB_NEEDS_BODY_HASH, STYLE_CALLER, STYLE_PER_REQUEST, STYLE_SCOPE};
use busbar_plugin_abi::host_side::caller::BoxFut;
use busbar_ports::auth::{AuthPort, OutboundAnswer, UpstreamIn};
use busbar_ports::{CallCx, PortError};
use sha2::{Digest, Sha256};

use super::OwnedUpstreamIn;
use crate::custody::{CredCache, CredGet, CredKey, CredentialCache};

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
        Ok(Self { spec, port, cache })
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
                    .map(|s| Sha256::digest(s.as_bytes()).into())
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
        match self.cache.get(
            self.cache_key(input.scope),
            false,
            tokio::time::Instant::now().into_std(),
            mint,
            &detach,
        ) {
            CredGet::Ready(result) => result.map(NativeCredential::Shared),
            CredGet::Wait(wait) => wait.await.map(NativeCredential::Shared),
            CredGet::Direct(direct) => direct.await.map(NativeCredential::Direct),
        }
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

/// Every configured row is explicit, including no-auth rows. Omission never grants permission.
#[derive(Clone)]
pub struct NativeRouteBindings {
    rows: BTreeMap<Box<str>, BTreeMap<Box<str>, (DestinationId, SelectedCredential)>>,
}

impl NativeRouteBindings {
    pub fn new(
        rows: impl IntoIterator<Item = (Box<str>, Box<str>, DestinationId, SelectedCredential)>,
    ) -> Result<Self, PortError> {
        let mut bindings: BTreeMap<
            Box<str>,
            BTreeMap<Box<str>, (DestinationId, SelectedCredential)>,
        > = BTreeMap::new();
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
