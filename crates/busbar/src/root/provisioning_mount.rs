// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! An authenticated provisioning request uses exactly its mounted instance's auth policy.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::body::{Body, Bytes};
use axum::http::{HeaderName, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use busbar_core_admin::provision::{self, ProvisionInstance, Verified};
use busbar_kernel::auth::chain_run::{
    verify_cached, AuthServices, ChainInstance, IdentityPolicy, Verdict,
};
use busbar_kernel::auth::verdicts::VerdictCache;
use busbar_kernel::directory::HoldSet;
use busbar_kernel::issued::IssuedCredentials;
use busbar_kernel::plane_grants::{KeyRefresh, ReplayGuard};
use busbar_kernel::refusal::{CoreRefusals, RefusalMap};
use busbar_plugin_abi::fail::refused::R_POLICY;
use busbar_plugin_abi::host_side::caller::{CallStack, Caller, InstanceLimits};
use busbar_plugin_abi::types::{Bytes as AbiBytes, KindCode, Pair, Str};
use busbar_ports::auth::{AuthIn, AuthPort, Identity, ServeIn};
use busbar_ports::CallCx;

use super::ingress_context::RequestContext;

pub(crate) struct ClientPolicy {
    pub(crate) instance: u64,
    pub(crate) epoch: u64,
    /// The existing App.config_generation owner, never a parallel authority counter.
    pub(crate) current_epoch: Arc<AtomicU64>,
    pub(crate) clients: Vec<Box<str>>,
}

impl IdentityPolicy for ClientPolicy {
    fn epoch(&self) -> u64 {
        self.epoch
    }

    fn authorize(&self, instance: u64, identity: &Identity, _req: &AuthIn<'_>) -> Result<(), u32> {
        if self.current_epoch.load(Ordering::Acquire) == self.epoch
            && instance == self.instance
            && provision::client_entry(&self.clients, identity.subject()).is_some()
        {
            Ok(())
        } else {
            Err(R_POLICY)
        }
    }
}

/// S9's complete mounted auth instance. Values come from its admitted reservation and generation.
pub(crate) struct ProvisionMount {
    pub(crate) name: Box<str>,
    pub(crate) plugin: Box<str>,
    pub(crate) slot: u32,
    pub(crate) out_of_process: bool,
    pub(crate) limits: InstanceLimits,
    pub(crate) port: Arc<dyn AuthPort>,
    pub(crate) keys: Arc<KeyRefresh>,
    pub(crate) holds: Box<[Arc<HoldSet>]>,
    pub(crate) cache: Arc<dyn VerdictCache>,
    pub(crate) issued: Arc<dyn IssuedCredentials>,
    pub(crate) replay: Arc<dyn ReplayGuard>,
    pub(crate) policy: ClientPolicy,
    pub(crate) credential_headers: Vec<HeaderName>,
    pub(crate) body_cap: usize,
    pub(crate) timeout: Duration,
    pub(crate) request_ids: Arc<AtomicU64>,
}

impl ProvisionMount {
    pub(crate) async fn handle(&self, req: Request<Body>) -> Response {
        if self.policy.current_epoch.load(Ordering::Acquire) != self.policy.epoch {
            return StatusCode::FORBIDDEN.into_response();
        }
        if req.extensions().get::<RequestContext>().is_none() {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        let Some(deadline) = Instant::now().checked_add(self.timeout) else {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        };
        let Ok(id) = self
            .request_ids
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
        else {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        };
        let invocation = Invocation {
            mount: self,
            cx: CallCx {
                deadline,
                request_id: id,
                stack: CallStack::default(),
            },
        };
        match tokio::time::timeout_at(
            deadline.into(),
            provision::mount(&invocation, &self.policy.clients, req),
        )
        .await
        {
            Ok(response) => response,
            Err(_) => StatusCode::GATEWAY_TIMEOUT.into_response(),
        }
    }
}

struct Invocation<'a> {
    mount: &'a ProvisionMount,
    cx: CallCx,
}

impl ProvisionInstance for Invocation<'_> {
    fn name(&self) -> &str {
        &self.mount.name
    }
    fn body_cap(&self) -> usize {
        self.mount.body_cap
    }
    fn cred_headers(&self) -> &[HeaderName] {
        &self.mount.credential_headers
    }

    async fn verify(&self, request: &Request<Bytes>) -> Verified {
        let Some(context) = request.extensions().get::<RequestContext>() else {
            return Verified::Failed(StatusCode::SERVICE_UNAVAILABLE);
        };
        let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
            return Verified::Failed(StatusCode::SERVICE_UNAVAILABLE);
        };
        let headers: Vec<Pair<'_>> = request
            .headers()
            .iter()
            .map(|(name, value)| Pair {
                name: Str::new(name.as_str()),
                value: AbiBytes::new(value.as_bytes()),
            })
            .collect();
        let authority = request
            .uri()
            .authority()
            .map(|authority| authority.as_str())
            .or_else(|| {
                request
                    .headers()
                    .get("host")
                    .and_then(|value| value.to_str().ok())
            })
            .unwrap_or_default();
        let req = AuthIn {
            method: request.method().as_str(),
            path: request.uri().path(),
            query: request.uri().query().unwrap_or_default(),
            authority,
            headers: &headers,
            peer: &context.peer,
            tls_peer_cert: &context.tls_peer_cert,
            body: request.body(),
            now_s: now.as_secs(),
        };
        let caller = Caller {
            plugin: &self.mount.plugin,
            kind: KindCode::Auth,
            name: &self.mount.name,
            instance: self.mount.policy.instance,
            slot: self.mount.slot,
            chain: 0,
            deadline: self.cx.deadline,
            stack: self.cx.stack,
            out_of_process: self.mount.out_of_process,
            limits: self.mount.limits,
        };
        let services = AuthServices {
            issued: self.mount.issued.as_ref(),
            replay: self.mount.replay.as_ref(),
            policy: &self.mount.policy,
        };
        let instance = ChainInstance {
            id: self.mount.policy.instance,
            port: self.mount.port.as_ref(),
            caller: &caller,
            keys: &self.mount.keys,
            holds: &self.mount.holds,
        };
        match verify_cached(
            &services,
            self.mount.cache.as_ref(),
            instance,
            self.cx,
            &req,
        )
        .await
        {
            Ok(Verdict::Identity(identity)) => Verified::Principal(identity.subject().into()),
            Ok(Verdict::NotMine) => Verified::NoCredential,
            Ok(Verdict::Rejected { .. }) => Verified::Refused,
            Ok(Verdict::PolicyRejected { .. } | Verdict::Held) => {
                Verified::Failed(StatusCode::FORBIDDEN)
            }
            Err(error) => Verified::Failed(
                StatusCode::from_u16(CoreRefusals::new().for_port(0, &error).status)
                    .unwrap_or(StatusCode::BAD_GATEWAY),
            ),
        }
    }

    async fn serve(&self, client: &str, request: Request<Bytes>) -> Response {
        if self.mount.policy.current_epoch.load(Ordering::Acquire) != self.mount.policy.epoch {
            return StatusCode::FORBIDDEN.into_response();
        }
        let Some(path) = relative_path(&self.mount.name, request.uri().path()) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        let headers: Vec<(&str, &[u8])> = request
            .headers()
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_bytes()))
            .collect();
        let req = ServeIn {
            method: request.method().as_str(),
            path,
            query: request.uri().query().unwrap_or_default(),
            headers: &headers,
            body: request.body(),
            client,
        };
        match self.mount.port.serve(self.cx, &req).await {
            Ok(output) => {
                let Ok(status) = StatusCode::from_u16(output.status) else {
                    return StatusCode::BAD_GATEWAY.into_response();
                };
                let mut response = Response::new(Body::from(output.body));
                *response.status_mut() = status;
                for (name, value) in output.headers {
                    let (Ok(name), Ok(value)) = (
                        HeaderName::from_bytes(name.as_bytes()),
                        axum::http::HeaderValue::from_bytes(&value),
                    ) else {
                        return StatusCode::BAD_GATEWAY.into_response();
                    };
                    response.headers_mut().append(name, value);
                }
                response
            }
            Err(error) => StatusCode::from_u16(CoreRefusals::new().for_port(0, &error).status)
                .unwrap_or(StatusCode::BAD_GATEWAY)
                .into_response(),
        }
    }
}

fn relative_path<'a>(instance: &str, path: &'a str) -> Option<&'a str> {
    let rest = path
        .strip_prefix(provision::MOUNT_PREFIX)?
        .strip_prefix(instance)?;
    rest.starts_with('/').then_some(rest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_kernel::auth::chain_run::IdentityPolicy;

    fn request() -> AuthIn<'static> {
        AuthIn {
            method: "POST",
            path: "/provision/directory/Groups",
            query: "",
            authority: "node",
            headers: &[],
            peer: "127.0.0.1",
            tls_peer_cert: &[],
            body: &[],
            now_s: 1,
        }
    }

    #[test]
    fn client_policy_is_exact_and_bound_to_the_admitted_instance() {
        let policy = ClientPolicy {
            instance: 41,
            epoch: 7,
            current_epoch: Arc::new(AtomicU64::new(7)),
            clients: vec!["IdP".into()],
        };
        assert!(policy
            .authorize(41, &Identity::from_ticket("IdP", ""), &request())
            .is_ok());
        assert!(policy
            .authorize(41, &Identity::from_ticket("idp", ""), &request())
            .is_err());
        assert!(policy
            .authorize(42, &Identity::from_ticket("IdP", ""), &request())
            .is_err());
        assert_eq!(policy.epoch(), 7);
        policy.current_epoch.store(8, Ordering::Release);
        assert!(policy
            .authorize(41, &Identity::from_ticket("IdP", ""), &request())
            .is_err());
    }

    #[test]
    fn provisioning_path_is_relative_to_exact_instance_mount() {
        assert_eq!(
            relative_path("directory", "/provision/directory/Groups"),
            Some("/Groups")
        );
        assert_eq!(
            relative_path("directory", "/provision/directory2/Groups"),
            None
        );
        assert_eq!(relative_path("directory", "/Groups"), None);
    }
}
