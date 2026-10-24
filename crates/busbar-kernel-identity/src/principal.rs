// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Who is calling — and the one caller who is nobody.

/// The literal an unauthenticated caller renders as, on every surface that names an actor: the
/// audit row, the chain hash and the idempotency namespace all spell it this way, so nothing that
/// reads an actor id has to know whether a principal was resolved.
///
/// The internal attribution bucket for anonymous traffic is a different string entirely and never
/// reaches a surface; the anonymous principal itself carries no bucket at all.
pub const ANONYMOUS: &str = "anonymous";

/// The two id prefixes a module may not synthesize. `group:` names a governance group and `vk_`
/// names a minted key; a module that claims either would be minting an identity the governance
/// tables believe they alone issue, so the identification is refused rather than trusted.
const RESERVED_ID_PREFIXES: [&str; 2] = ["group:", "vk_"];

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
    /// anonymous rendering is one fact in one place rather than a literal repeated at each surface.
    pub fn actor_id(&self) -> &str {
        &self.id
    }

    /// Whether a module-synthesized id lands in reserved space. An id that does is refused exactly
    /// where governance refuses it: the module does not get to name a group or a minted key.
    pub fn id_is_reserved(id: &str) -> bool {
        RESERVED_ID_PREFIXES.iter().any(|p| id.starts_with(p))
    }
}

/// The conversion the loop performs when it seals this step's answer.
///
/// The two types are kept apart on purpose: this crate's `Principal` carries the credential facts a
/// chain produced, and the contract's identity carries only the actor an accrual is checked
/// against. Everything else the chain learned stays here, where the next chain run can use it, and
/// never travels on the capability that moves money. It is a `From` impl rather than a free
/// function because one crate can now name both halves.
impl From<&Principal> for busbar_contract::PrincipalId {
    fn from(p: &Principal) -> Self {
        busbar_contract::PrincipalId::new(p.actor_id())
    }
}
