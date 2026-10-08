// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE KIND-NEUTRAL OUTBOUND AUTH DOUBLE a test build binds lane credentials on (BUSBAR-1.6.0.md
//! THE DESIGN §1, "Kernel tests use kind-neutral doubles"): a test binary has no composition root,
//! so no auth plugin is linked, and a lane's credential binds here instead. It serves EVERY style,
//! and presents a bound credential (or, for a passthrough request, the caller's) as
//! `authorization: Bearer <credential>`; an empty credential presents nothing. It is not any style's
//! bytes: each style's real bytes are its plugin's, proven by that plugin's conformance suite and
//! by the composition root's tests, which link the real plugins.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use busbar_contract::auth_calls::{
    AuthAxis, AuthCalls, AuthField, Fielding, Fields, FieldsRequest, OutboundAuth, OutboundServing,
};
use busbar_contract::redacted::Redacted;

/// The double's axis: answers no inbound module, serves every outbound style.
#[must_use]
pub fn axis() -> Arc<dyn AuthAxis> {
    Arc::new(DoubleAxis)
}

/// A test build's AUTH AXIS over `registry` (installed in place of the root's opener): the
/// loader's stand-in rows for the inbound chain, this double for every outbound style.
#[must_use]
pub fn stand_in(registry: Arc<busbar_plugin_loader::PluginRegistry>) -> Arc<dyn AuthAxis> {
    Arc::new(StandIn(busbar_plugin_loader::auth_axis::stand_in(registry)))
}

struct StandIn(Arc<dyn AuthAxis>);

impl AuthAxis for StandIn {
    fn linked_names(&self) -> Vec<String> {
        self.0.linked_names()
    }

    fn answers(&self, module: &str) -> bool {
        self.0.answers(module)
    }

    fn linked(&self, module: &str) -> bool {
        self.0.linked(module)
    }

    fn operator(&self) -> Option<(String, String)> {
        self.0.operator()
    }

    fn open(
        &self,
        module: &str,
        label: &str,
        settings: &serde_json::Value,
    ) -> Result<Arc<dyn AuthCalls>, String> {
        self.0.open(module, label, settings)
    }

    fn credential_readers(&self) -> Vec<String> {
        self.0.credential_readers()
    }

    fn serving(
        &self,
        style: &str,
        settings: &serde_json::Value,
    ) -> Result<Option<OutboundServing>, String> {
        DoubleAxis.serving(style, settings)
    }
}

struct DoubleAxis;

impl AuthAxis for DoubleAxis {
    fn linked_names(&self) -> Vec<String> {
        Vec::new()
    }

    fn answers(&self, _module: &str) -> bool {
        false
    }

    fn linked(&self, _module: &str) -> bool {
        false
    }

    fn operator(&self) -> Option<(String, String)> {
        None
    }

    fn open(
        &self,
        module: &str,
        _label: &str,
        _settings: &serde_json::Value,
    ) -> Result<Arc<dyn AuthCalls>, String> {
        Err(format!("no `kind: auth` plugin answers to '{module}'"))
    }

    fn serving(
        &self,
        _style: &str,
        _settings: &serde_json::Value,
    ) -> Result<Option<OutboundServing>, String> {
        Ok(Some(OutboundServing {
            auth: Arc::new(Double::default()),
            flags: busbar_contract::abi::auth::STYLE_CALLER_CREDENTIAL,
            points: busbar_contract::abi::auth::POINT_HEAD,
        }))
    }
}

/// One double instance: its bindings' credentials, by handle.
#[derive(Default)]
struct Double {
    bound: Mutex<HashMap<u64, Vec<u8>>>,
}

fn bearer(credential: &[u8]) -> Fields {
    if credential.is_empty() {
        return Fields::Ready(Vec::new());
    }
    let mut value = b"Bearer ".to_vec();
    value.extend_from_slice(credential);
    Fields::Ready(vec![AuthField {
        name: b"authorization".to_vec(),
        value: Redacted::new(value),
        sensitive: false,
    }])
}

impl OutboundAuth for Double {
    fn open_outbound(
        &self,
        _style: &str,
        credential: &[u8],
        _settings: &serde_json::Value,
    ) -> Result<u64, String> {
        let mut bound = self.bound.lock().unwrap_or_else(|p| p.into_inner());
        let handle = bound.len() as u64 + 1;
        bound.insert(handle, credential.to_vec());
        Ok(handle)
    }

    fn fields_now(&self, handle: u64, request: &FieldsRequest) -> Option<Fields> {
        if let Some(caller) = &request.caller_credential {
            return Some(bearer(caller.expose_secret()));
        }
        let bound = self.bound.lock().unwrap_or_else(|p| p.into_inner());
        Some(bound.get(&handle).map_or(Fields::Refused, |c| bearer(c)))
    }

    fn fields(&self, handle: u64, request: FieldsRequest, _deadline_ns: u64) -> Box<dyn Fielding> {
        Box::new(Settled(self.fields_now(handle, &request)))
    }
}

/// An answer already in hand.
struct Settled(Option<Fields>);

impl std::future::Future for Settled {
    type Output = Fields;
    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Fields> {
        std::task::Poll::Ready(self.0.take().unwrap_or(Fields::Failed))
    }
}

impl Fielding for Settled {
    fn settled(&mut self) -> Option<Fields> {
        self.0.take()
    }
}
