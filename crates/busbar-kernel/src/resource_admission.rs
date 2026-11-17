// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! #408: immutable logical-resource ownership of configured forwarding operands.
//!
//! Selection and operand validation are facts, not execution authority. The final auth
//! consumer must obtain the shared publication admission and finish replay before the
//! forwarding consumer can use these operands. No plugin response grants that authority.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use busbar_contract::records::{ScopeRef, VirtualKey};
use busbar_contract::secure::SecureVec;
use busbar_contract::services::{Caller, Incarnation};
use busbar_plugin_abi::plane::{CARRIER_DEFAULT, CARRIER_HTTP, OUTBOUND_DEFAULT};

use crate::plane_driver::port_egress::Targets;
use crate::plane_driver::port_session::UpExchange;
use crate::plane_driver::port_upstream::Candidate;
use crate::plane_driver::HeadFields;
use crate::state::InvocationId;
use crate::upstreams::{UpstreamDef, Upstreams};

pub const MAX_RESOURCES: usize = 65_536;
pub const MAX_SELECTED: usize = 32;
pub const MAX_KINDS: usize = 8;
pub const MAX_VALUE: usize = 256;

/// A plane's configured fact; never an admitted executable target by itself.
#[derive(Debug, Clone)]
pub struct ForwardFact {
    pub descriptor: u32,
    pub upstream: Box<str>,
    pub dialect: Box<str>,
    pub model: Box<str>,
    pub method: Box<str>,
    pub target: Box<str>,
}

#[derive(Debug, Clone)]
pub struct ResourceFact {
    pub scope: ScopeRef,
    pub forwards: Vec<ForwardFact>,
}

/// Bounded generic reasons; never include provider configuration or request content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceError {
    Kind,
    Value,
    Limit,
    Duplicate,
    Upstream,
    Operands,
    Selection,
    NotSelected,
    Binding,
    Unsupported,
}

/// Host-retained configured target and its single logical owner. Private fields prevent
/// changing a validated association after selection.
pub struct AdmittedForwardDescriptor {
    id: u32,
    scope: ScopeRef,
    upstream: Arc<UpstreamDef>,
    candidate: Candidate,
    dialect: Box<str>,
    model: Box<str>,
    method: Box<str>,
    target: Box<str>,
}

impl std::fmt::Debug for AdmittedForwardDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdmittedForwardDescriptor")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl AdmittedForwardDescriptor {
    pub fn id(&self) -> u32 {
        self.id
    }
    pub fn scope(&self) -> &ScopeRef {
        &self.scope
    }
    pub fn upstream(&self) -> &Arc<UpstreamDef> {
        &self.upstream
    }
    pub fn candidate(&self) -> Candidate {
        self.candidate.clone()
    }
    pub fn dialect(&self) -> &str {
        &self.dialect
    }
    pub fn model(&self) -> &str {
        &self.model
    }
    pub fn method(&self) -> &str {
        &self.method
    }
    pub fn target(&self) -> &str {
        &self.target
    }
}

/// One instance's immutable inventory; S9 retains this in the same published generation
/// as the upstream table used to build it. Equal endpoint text does not merge entries.
#[derive(Debug)]
pub struct ResourceInventory {
    instance: Incarnation,
    namespace: Arc<str>,
    epoch: u64,
    scopes: BTreeSet<(String, String)>,
    descriptors: BTreeMap<u32, Arc<AdmittedForwardDescriptor>>,
}

fn valid_kind(kind: &str) -> bool {
    !kind.is_empty()
        && kind.len() <= 64
        && kind.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && kind
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

fn valid_value(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_VALUE && !value.chars().any(char::is_control)
}

fn add_size(total: &mut usize, bytes: usize, max: usize) -> Result<(), ResourceError> {
    *total = total.checked_add(bytes).ok_or(ResourceError::Limit)?;
    (*total <= max).then_some(()).ok_or(ResourceError::Limit)
}

impl ResourceInventory {
    /// Resolve factual descriptors against the *admitted* upstream and projected target
    /// tables. This root-facing constructor creates no principal authorization.
    pub fn build(
        caller: &Caller,
        epoch: u64,
        kinds: Vec<Box<str>>,
        facts: Vec<ResourceFact>,
        upstreams: Arc<dyn Upstreams>,
        targets: Targets,
        config_byte_limit: usize,
    ) -> Result<Arc<Self>, ResourceError> {
        if caller.kind() != busbar_contract::abi::mechanism::KindCode::Plane {
            return Err(ResourceError::Binding);
        }
        if kinds.is_empty()
            || kinds.len() > MAX_KINDS
            || facts.is_empty()
            || facts.len() > MAX_RESOURCES
        {
            return Err(ResourceError::Limit);
        }
        let mut declared = BTreeSet::new();
        let mut size = 0;
        for kind in kinds {
            if !valid_kind(&kind) {
                return Err(ResourceError::Kind);
            }
            add_size(&mut size, kind.len(), config_byte_limit)?;
            if !declared.insert(kind) {
                return Err(ResourceError::Duplicate);
            }
        }
        let mut scopes = BTreeSet::new();
        let mut descriptors = BTreeMap::new();
        for fact in facts {
            if !declared.contains(fact.scope.kind.as_str()) {
                return Err(ResourceError::Kind);
            }
            if !valid_value(&fact.scope.value) {
                return Err(ResourceError::Value);
            }
            add_size(&mut size, fact.scope.kind.len(), config_byte_limit)?;
            add_size(&mut size, fact.scope.value.len(), config_byte_limit)?;
            if !scopes.insert((fact.scope.kind.clone(), fact.scope.value.clone())) {
                return Err(ResourceError::Duplicate);
            }
            if fact.forwards.is_empty() || fact.forwards.len() > MAX_RESOURCES {
                return Err(ResourceError::Limit);
            }
            for forward in fact.forwards {
                if descriptors.len() == MAX_RESOURCES {
                    return Err(ResourceError::Limit);
                }
                if forward.descriptor == 0 || descriptors.contains_key(&forward.descriptor) {
                    return Err(ResourceError::Duplicate);
                }
                for value in [&*forward.upstream, &*forward.dialect, &*forward.model] {
                    if !valid_value(value) {
                        return Err(ResourceError::Value);
                    }
                    add_size(&mut size, value.len(), config_byte_limit)?;
                }
                add_size(&mut size, forward.method.len(), config_byte_limit)?;
                add_size(&mut size, forward.target.len(), config_byte_limit)?;
                if forward.method.is_empty()
                    || forward.method.len() > 32
                    || !forward.method.bytes().all(|b| b.is_ascii_uppercase())
                    || axum::http::Method::from_bytes(forward.method.as_bytes()).is_err()
                    || !forward.target.starts_with('/')
                    || forward.target.contains('#')
                    || forward
                        .target
                        .parse::<axum::http::uri::PathAndQuery>()
                        .is_err()
                {
                    return Err(ResourceError::Operands);
                }
                let upstream = upstreams
                    .get(&forward.upstream)
                    .ok_or(ResourceError::Upstream)?;
                if upstream.name != forward.upstream
                    || upstream.url.is_none()
                    || upstream.command.is_some()
                {
                    return Err(ResourceError::Upstream);
                }
                let projected = targets(&forward.upstream).ok_or(ResourceError::Upstream)?;
                add_size(&mut size, projected.provider.len(), config_byte_limit)?;
                add_size(&mut size, projected.base_path.len(), config_byte_limit)?;
                for (name, value) in &projected.params {
                    add_size(&mut size, name.len(), config_byte_limit)?;
                    add_size(&mut size, value.len(), config_byte_limit)?;
                }
                let candidate = Candidate {
                    upstream: forward.upstream,
                    provider: projected.provider,
                    base_path: projected.base_path,
                    flags: projected.flags,
                    params: projected.params,
                };
                descriptors.insert(
                    forward.descriptor,
                    Arc::new(AdmittedForwardDescriptor {
                        id: forward.descriptor,
                        scope: fact.scope.clone(),
                        upstream,
                        candidate,
                        dialect: forward.dialect,
                        model: forward.model,
                        method: forward.method,
                        target: forward.target,
                    }),
                );
            }
        }
        Ok(Arc::new(Self {
            instance: caller.incarnation().clone(),
            namespace: Arc::clone(caller.namespace()),
            epoch,
            scopes,
            descriptors,
        }))
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn instance(&self) -> &Incarnation {
        &self.instance
    }
    pub fn descriptor(&self, id: u32) -> Option<&Arc<AdmittedForwardDescriptor>> {
        self.descriptors.get(&id)
    }

    /// Validate against the actual matched mount before freezing selection. Route metadata
    /// and this inventory must come from the same retained generation at the composition root.
    pub fn select_wire(
        self: &Arc<Self>,
        request: FrozenRequest,
        mounted: &crate::plane_driver::port_routes::Mounted,
        bytes: &[u8],
    ) -> Result<SelectedResources, ResourceError> {
        if mounted.route != request.route
            || mounted.resource_kinds.is_empty()
            || mounted.resource_kinds.len() > MAX_KINDS
            || mounted.flags != 0
        {
            return Err(ResourceError::Binding);
        }
        let scopes = busbar_plugin_abi::resource_admission::decode_selection(bytes)
            .map_err(|_| ResourceError::Selection)?;
        if scopes
            .iter()
            .any(|s| !mounted.resource_kinds.iter().any(|k| k.as_ref() == s.kind))
        {
            return Err(ResourceError::Kind);
        }
        let scopes: Vec<ScopeRef> = scopes
            .into_iter()
            .map(|s| ScopeRef {
                kind: s.kind.into(),
                value: s.value.into(),
            })
            .collect();
        self.select(request, &scopes)
    }

    /// Freeze the complete factual all-of set. No role binding or replay is performed here.
    pub fn select(
        self: &Arc<Self>,
        request: FrozenRequest,
        scopes: &[ScopeRef],
    ) -> Result<SelectedResources, ResourceError> {
        if scopes.is_empty() || scopes.len() > MAX_SELECTED {
            return Err(ResourceError::Selection);
        }
        let mut selected = BTreeSet::new();
        for scope in scopes {
            if !valid_kind(&scope.kind) || !valid_value(&scope.value) {
                return Err(ResourceError::Selection);
            }
            let key = (scope.kind.clone(), scope.value.clone());
            if !self.scopes.contains(&key) {
                return Err(ResourceError::NotSelected);
            }
            if !selected.insert(key) {
                return Err(ResourceError::Duplicate);
            }
        }
        Ok(SelectedResources {
            inventory: Arc::clone(self),
            request: Arc::new(request),
            scopes: selected,
        })
    }
}

/// The request owns its bytes through selection and execution. Debug never prints content.
pub struct FrozenRequest {
    invocation: InvocationId,
    route: u32,
    method: Box<str>,
    path: Box<str>,
    query: Box<str>,
    headers: Vec<(Vec<u8>, SecureVec)>,
    body: SecureVec,
}

impl std::fmt::Debug for FrozenRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FrozenRequest")
            .field("invocation", &self.invocation)
            .field("route", &self.route)
            .finish_non_exhaustive()
    }
}

impl FrozenRequest {
    /// Host input already bounded by its real mounted route; never accepts a wire identity.
    pub fn new(
        invocation: InvocationId,
        route: u32,
        method: Box<str>,
        path: Box<str>,
        query: Box<str>,
        headers: HeadFields,
        body: Vec<u8>,
    ) -> Self {
        Self {
            invocation,
            route,
            method,
            path,
            query,
            headers: headers
                .into_iter()
                .map(|(name, value)| (name, SecureVec::from(value)))
                .collect(),
            body: SecureVec::from(body),
        }
    }
    pub fn invocation(&self) -> InvocationId {
        self.invocation
    }
    pub fn route(&self) -> u32 {
        self.route
    }
    pub fn method(&self) -> &str {
        &self.method
    }
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn query(&self) -> &str {
        &self.query
    }
    pub fn headers(&self) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.headers
            .iter()
            .map(|(name, value)| (name.as_slice(), value.as_slice()))
    }
    pub fn body(&self) -> &[u8] {
        self.body.as_slice()
    }

    /// Lend the exact frozen bytes to the pure selector without authenticated identity,
    /// ticket state or session authority. The borrowed input cannot outlive this call.
    pub fn with_selection_input<R>(
        &self,
        f: impl FnOnce(&busbar_ports::plane::PlaneIn<'_>, &[u8]) -> R,
    ) -> Result<R, ResourceError> {
        use busbar_plugin_abi::types::{Bytes, Pair, Str};
        let headers: Vec<Pair<'_>> = self
            .headers
            .iter()
            .map(|(name, value)| {
                Ok(Pair {
                    name: Str::new(core::str::from_utf8(name).map_err(|_| ResourceError::Binding)?),
                    value: Bytes::new(value.as_slice()),
                })
            })
            .collect::<Result<_, ResourceError>>()?;
        let input = busbar_ports::plane::PlaneIn {
            route: self.route,
            flags: 0,
            auth: 0,
            method: &self.method,
            path: &self.path,
            query: &self.query,
            headers: &headers,
            identity: &[],
            request_id: self.invocation.request_id().get(),
            carrier: 0,
            work: "",
            ticket_record: &[],
        };
        Ok(f(&input, self.body()))
    }
}

/// Factual selection only. Final publication authorization and replay are separate,
/// mandatory consumers before these operands may be sent.
#[derive(Debug)]
pub struct SelectedResources {
    inventory: Arc<ResourceInventory>,
    request: Arc<FrozenRequest>,
    scopes: BTreeSet<(String, String)>,
}

impl SelectedResources {
    pub fn invocation(&self) -> InvocationId {
        self.request.invocation
    }
    pub fn epoch(&self) -> u64 {
        self.inventory.epoch
    }
    pub fn instance(&self) -> &Incarnation {
        &self.inventory.instance
    }
    pub fn request(&self) -> &Arc<FrozenRequest> {
        &self.request
    }
    pub fn inventory(&self) -> &Arc<ResourceInventory> {
        &self.inventory
    }
    pub fn scope_allowed(&self, key: &VirtualKey) -> bool {
        self.scopes
            .iter()
            .all(|(kind, value)| key.scope_allowed(kind, value))
    }
    pub fn forward(&self, id: u32) -> Result<BoundForward, ResourceError> {
        let descriptor = self
            .inventory
            .descriptors
            .get(&id)
            .ok_or(ResourceError::NotSelected)?;
        if !self.scopes.contains(&(
            descriptor.scope.kind.clone(),
            descriptor.scope.value.clone(),
        )) {
            return Err(ResourceError::NotSelected);
        }
        Ok(BoundForward {
            inventory: Arc::clone(&self.inventory),
            request: Arc::clone(&self.request),
            descriptor: Arc::clone(descriptor),
        })
    }
}

/// Decoded echoes must be resolved against the current invocation by the ABI consumer;
/// retaining a raw numeric descriptor alone never constructs this host binding.
#[derive(Clone, Debug)]
pub struct ForwardEcho {
    inventory: Arc<ResourceInventory>,
    request: Arc<FrozenRequest>,
    descriptor: u32,
}

#[derive(Debug)]
pub struct BoundForward {
    inventory: Arc<ResourceInventory>,
    request: Arc<FrozenRequest>,
    descriptor: Arc<AdmittedForwardDescriptor>,
}

impl BoundForward {
    pub fn descriptor(&self) -> &AdmittedForwardDescriptor {
        &self.descriptor
    }
    fn echo(&self) -> ForwardEcho {
        ForwardEcho {
            inventory: Arc::clone(&self.inventory),
            request: Arc::clone(&self.request),
            descriptor: self.descriptor.id,
        }
    }

    /// Supply only this invocation's selected immutable descriptor to the plane encoder.
    /// Other independently validated admission protocols may append their own records.
    pub fn write_admission(
        &self,
        out: &mut impl busbar_plugin_abi::records::Writer,
    ) -> Result<(), busbar_plugin_abi::records::Full> {
        busbar_plugin_abi::resource_admission::write_echo(
            out,
            busbar_plugin_abi::resource_admission::DescriptorEcho {
                invocation: self.request.invocation.request_id().get(),
                generation: self.inventory.epoch,
                route: self.request.route,
                descriptor: self.descriptor.id,
                instance: &self.inventory.namespace,
            },
        )
    }

    /// Resolve the *actual encoder response* against this exact host selection. Callers
    /// must retain the decoded echo; regenerating an expected echo is not response validation.
    pub fn resolve_echo(
        &self,
        echo: busbar_plugin_abi::resource_admission::DescriptorEcho<'_>,
    ) -> Result<ForwardEcho, ResourceError> {
        if echo.invocation != self.request.invocation.request_id().get()
            || echo.generation != self.inventory.epoch
            || echo.route != self.request.route
            || echo.instance != self.inventory.namespace.as_ref()
            || echo.descriptor != self.descriptor.id
        {
            return Err(ResourceError::Binding);
        }
        Ok(self.echo())
    }

    /// Validate actual operands and consume the immutable pair. This proves only the
    /// operands: the runtime must also hold completed execution admission for this request.
    pub fn validate(
        &self,
        echo: ForwardEcho,
        candidate: &Candidate,
        dialect: &str,
        model: &str,
        upstream: &Arc<UpstreamDef>,
        exchange: UpExchange,
    ) -> Result<ValidatedForward, ResourceError> {
        if !Arc::ptr_eq(&echo.inventory, &self.inventory)
            || !Arc::ptr_eq(&echo.request, &self.request)
            || echo.descriptor != self.descriptor.id
            || !Arc::ptr_eq(upstream, &self.descriptor.upstream)
        {
            return Err(ResourceError::Binding);
        }
        if candidate != &self.descriptor.candidate
            || dialect != self.descriptor.dialect.as_ref()
            || model != self.descriptor.model.as_ref()
            || exchange.id != 0
            || !matches!(exchange.carrier, CARRIER_DEFAULT | CARRIER_HTTP)
            || exchange.outbound != OUTBOUND_DEFAULT
            || exchange.scope.is_some()
            || !exchange.msgs.is_empty()
            || exchange.cut
            || exchange.method.as_deref() != Some(self.descriptor.method.as_ref())
            || exchange.path.as_deref() != Some(self.descriptor.target.as_ref())
        {
            return Err(ResourceError::Operands);
        }
        Ok(ValidatedForward {
            descriptor: Arc::clone(&self.descriptor),
            request: Arc::clone(&self.request),
            exchange,
        })
    }
}

/// No mutable access to checked operands. Runtime handoff consumes this custody while
/// retaining the completed admission separately; it is not a standalone send capability.
pub struct ValidatedForward {
    descriptor: Arc<AdmittedForwardDescriptor>,
    request: Arc<FrozenRequest>,
    exchange: UpExchange,
}

impl std::fmt::Debug for ValidatedForward {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidatedForward")
            .field("descriptor", &self.descriptor)
            .finish_non_exhaustive()
    }
}

impl ValidatedForward {
    pub fn descriptor(&self) -> &AdmittedForwardDescriptor {
        &self.descriptor
    }
    pub fn request(&self) -> &Arc<FrozenRequest> {
        &self.request
    }
    pub fn exchange(&self) -> &UpExchange {
        &self.exchange
    }
}
