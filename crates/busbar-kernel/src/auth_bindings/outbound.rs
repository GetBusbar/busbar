// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The §12.18 binding's call into the outbound-credential cache (IF §12.2): `mint` borrows the caller's
//! `UpstreamIn` (rules 3 and 5, no copy) and `detach` builds the owned future from an owned copy (rule 2 only,
//! called by the cache at most once and only when it starts the refresh-ahead mint), matching `CredGet::Direct`'s
//! contract that a per-request call allocates what `AuthPort::outbound` allocates and nothing else.

use std::sync::Arc;
use std::time::Instant;

use busbar_plugin_abi::host_side::caller::BoxFut;
use busbar_plugin_abi::types::{Bytes, Pair, Str};
use busbar_ports::auth::{AuthPort, OutboundAnswer, UpstreamIn};
use busbar_ports::{CallCx, PortError};

use crate::custody::{CredGet, CredKey, CredentialCache};

type Owned = Vec<(Box<str>, Vec<u8>)>;

/// An owned copy of an [`UpstreamIn`], made only for a detached refresh-ahead mint.
pub struct OwnedUpstreamIn {
    method: Box<str>,
    url: Box<str>,
    headers: Owned,
    body_sha256: Option<[u8; 32]>,
    caller_cred: Owned,
    scope: Option<Box<str>>,
    caller_grant: Option<Vec<u8>>,
    min_valid_s: u32,
}

fn own(pairs: &[Pair<'_>]) -> Owned {
    pairs
        .iter()
        .map(|p| (Box::from(p.name.get()), p.value.get().to_vec()))
        .collect()
}

fn borrow(owned: &Owned) -> Vec<Pair<'_>> {
    owned
        .iter()
        .map(|(n, v)| Pair {
            name: Str::new(n),
            value: Bytes::new(v),
        })
        .collect()
}

impl OwnedUpstreamIn {
    /// Copy `req`.
    #[must_use]
    pub fn copy(req: &UpstreamIn<'_>) -> Self {
        Self {
            method: req.method.into(),
            url: req.url.into(),
            headers: own(req.headers),
            body_sha256: req.body_sha256,
            caller_cred: own(req.caller_cred),
            scope: req.scope.map(Box::from),
            caller_grant: req.caller_grant.map(<[u8]>::to_vec),
            min_valid_s: req.min_valid_s,
        }
    }

    /// One `outbound` call of `port` over this copy.
    pub async fn call(self, port: &dyn AuthPort, cx: CallCx) -> Result<OutboundAnswer, PortError> {
        let headers = borrow(&self.headers);
        let caller_cred = borrow(&self.caller_cred);
        let req = UpstreamIn {
            method: &self.method,
            url: &self.url,
            headers: &headers,
            body_sha256: self.body_sha256,
            caller_cred: &caller_cred,
            scope: self.scope.as_deref(),
            caller_grant: self.caller_grant.as_deref(),
            min_valid_s: self.min_valid_s,
        };
        port.outbound(cx, &req).await
    }
}

/// The one outbound-credential path for an upstream exchange: `key` is the binding's `CredKey`, `per_request` its
/// `UpstreamAuth.per_request`. The cache decides hit, wait, direct or detached refresh.
pub fn upstream_credential<'a, C: CredentialCache>(
    cache: &'a C,
    port: &'a Arc<dyn AuthPort>,
    cx: CallCx,
    key: CredKey,
    per_request: bool,
    now: Instant,
    req: &'a UpstreamIn<'a>,
) -> CredGet<'a> {
    let mint = move || -> BoxFut<'a, Result<OutboundAnswer, PortError>> { port.outbound(cx, req) };
    let detach = move || -> BoxFut<'static, Result<OutboundAnswer, PortError>> {
        let port = Arc::clone(port);
        let owned = OwnedUpstreamIn::copy(req);
        Box::pin(async move { owned.call(&*port, cx).await })
    };
    cache.get(key, per_request, now, mint, &detach)
}
