// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Who is calling — and the one caller who is nobody.

/// The literal an unauthenticated caller renders as, on every surface that names an actor: the
pub const ANONYMOUS: &str = "anonymous";

/// The caller a module identified.
///
/// `id` is the stable handle the ledger attributes to. `roles` are what the identifying module
/// asserts and grant nothing on their own — the role-binding table for that module is the
/// allow-list. `ttl_secs` is the module's suggestion for how long its verdict may be cached, and is
/// a suggestion only: the cache clamps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    /// The stable identity handle.
    pub id: String,
    /// A display name, when the module knows one.
    pub name: Option<String>,
    /// The roles the identifying module asserts.
    pub roles: Vec<String>,
    /// The module's suggested cache lifetime for this identification, in seconds.
    pub ttl_secs: Option<u64>,
}

impl Principal {
    /// A principal with nothing but a stable id — the shape a built-in module hands back.
    pub fn from_id(id: impl Into<String>) -> Self {
        Principal {
            id: id.into(),
            name: None,
            roles: Vec::new(),
            ttl_secs: None,
        }
    }

    /// The anonymous caller: no id of its own, no roles, no bucket.
    pub fn anonymous() -> Self {
        Principal::from_id(ANONYMOUS)
    }

    /// Whether this principal is the anonymous one.
    pub fn is_anonymous(&self) -> bool {
        self.id == ANONYMOUS
    }

    /// The actor id every surface writes. Identical to `id`, and stated as its own method so the
    pub fn actor_id(&self) -> &str {
        &self.id
    }
}

/// The conversion the loop performs when it seals this step's answer.
impl From<&Principal> for busbar_contract::PrincipalId {
    fn from(p: &Principal) -> Self {
        busbar_contract::PrincipalId::new(p.actor_id())
    }
}
