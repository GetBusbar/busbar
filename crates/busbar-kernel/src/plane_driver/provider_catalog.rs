// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Immutable native provider routing facts, resolved before a serving configuration exists.
//! No plugin, credential, destination capability or money owner is opened here.

use std::borrow::Borrow;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use busbar_contract::config::UpstreamCreds;

use crate::config::PoolCfg;

/// Metadata copied from the admitted image of this exact configured instance.
#[derive(Clone, Debug)]
pub struct ProviderPlane {
    pub instance: String,
    pub image: String,
    pub dialects: BTreeSet<String>,
    pub schema: String,
}

/// Internal walk identity is separate from the configured scope used by admission/hooks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteKind {
    NamedPool(String),
    DirectModel(String),
}

/// A validated pool policy plus its routing domain, never an authorization receipt.
#[derive(Clone, Debug)]
pub struct CatalogPool {
    pub kind: RouteKind,
    pub config: PoolCfg,
}

/// The source form chooses the binding interpretation; matching a name against a live registry
/// cannot recover whether the operator wrote a deployment instance or inherited a catalog style.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProviderAuthSelection {
    Implicit,
    Style(String),
    Instance(String),
}

impl ProviderAuthSelection {
    pub fn as_view(&self) -> crate::auth_bindings::ProviderAuth<'_> {
        match self {
            Self::Implicit => crate::auth_bindings::ProviderAuth::None,
            Self::Style(name) => crate::auth_bindings::ProviderAuth::Style(name),
            Self::Instance(name) => crate::auth_bindings::ProviderAuth::Instance(name),
        }
    }
}

/// One pool/member's exact native target. No secret, rate or host-origin data crosses to the plane.
#[derive(Clone, Debug)]
pub struct ResolvedMember {
    pub model: String,
    pub provider: String,
    pub auth_selection: ProviderAuthSelection,
    pub dialect: String,
    pub wire_model: String,
    pub projection: Arc<str>,
    pub base_path: String,
    pub params: Vec<(Box<str>, Box<str>)>,
    pub credential_mode: UpstreamCreds,
    pub max_concurrent: Option<usize>,
    pub max_requests: i64,
    pub attempt_timeout_ms: Option<u64>,
    pub context_max: Option<usize>,
    pub resource: Option<Box<str>>,
}

/// Only root can join these facts to actual routes, NativeBindings and admission owners.
#[derive(Clone, Debug)]
pub struct CatalogPlan {
    pub instance: String,
    pub image: String,
    pub(crate) pools: BTreeMap<String, CatalogPool>,
    pub(crate) selectors: BTreeMap<String, String>,
    pub(crate) targets: BTreeMap<(String, String), ResolvedMember>,
}

impl CatalogPlan {
    pub fn pools(&self) -> &BTreeMap<String, CatalogPool> {
        &self.pools
    }

    /// Resolve only an authored pool/model name. Unknown/empty input grants no default route.
    pub fn select(&self, configured: &str) -> Option<&str> {
        self.selectors.get(configured).map(String::as_str)
    }

    pub fn target(&self, pool: &str, qualified_member: &str) -> Option<&ResolvedMember> {
        self.targets
            .get(&(pool, qualified_member) as &dyn TargetKey)
    }

    pub fn targets(&self) -> &BTreeMap<(String, String), ResolvedMember> {
        &self.targets
    }

    pub fn auth_members(&self) -> impl Iterator<Item = crate::auth_bindings::MemberView<'_>> {
        self.targets
            .values()
            .map(move |target| crate::auth_bindings::MemberView {
                member: &target.model,
                plane: &self.instance,
                image: &self.image,
                provider: &target.provider,
                dialect: Some(&target.dialect),
            })
    }
}

pub type ProviderCatalogs = BTreeMap<String, CatalogPlan>;

/// Resolved once per configuration (off the request path).
pub use crate::off_path::plane_provider_catalog::resolve;

/// A target's (walk key, qualified member) as borrowed text, so a lookup needs no owned key.
trait TargetKey {
    fn key(&self) -> (&str, &str);
}

impl TargetKey for (String, String) {
    fn key(&self) -> (&str, &str) {
        (&self.0, &self.1)
    }
}

impl TargetKey for (&str, &str) {
    fn key(&self) -> (&str, &str) {
        (self.0, self.1)
    }
}

impl<'a> Borrow<dyn TargetKey + 'a> for (String, String) {
    fn borrow(&self) -> &(dyn TargetKey + 'a) {
        self
    }
}

// Ordered as the owned tuple orders: walk key first, then member.
impl PartialEq for dyn TargetKey + '_ {
    fn eq(&self, other: &Self) -> bool {
        self.key() == other.key()
    }
}

impl Eq for dyn TargetKey + '_ {}

impl PartialOrd for dyn TargetKey + '_ {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for dyn TargetKey + '_ {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.key().cmp(&other.key())
    }
}
