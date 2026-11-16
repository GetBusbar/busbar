// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Path claims per listener: at most one instance per (method set, path pattern) on each listener (IF §12.26). W0-ABI stub: frozen signatures, `todo!()` bodies; W1-K8C fills it.

// W0-ABI: `ConfigRefused` is defined in IF §12.25 ("Shared by §12.25 and §12.26"), whose home is the existing
// `hooks` and `config_validate` modules; W0-ABI does not edit those, so the stub defines it here, where §12.26 uses
// it. `StrategyBinding` and `resolve_strategy` (§12.25) are left to their owner (W1-K8C, `hooks`).

/// Core-written refusal text for config load (operator vocabulary only); the caller wraps it in its existing
/// config error. Shared by §12.25 and §12.26.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigRefused(pub String);
/// Which listener a claim is mounted on. `Export(i)` = the dedicated listener of export instance index i, when
/// the operator gave it one; otherwise its scopes are claims on `Data`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ListenerId {
    Data,
    Admin,
    Export(u32),
}
/// K8. One claim; `owner` is operator vocabulary ("export prom-a"), or "core". `methods` = the bit encoding of plane
/// `RouteRec.methods` (§8.6); an export scope claims the GET bit.
pub struct PathClaim<'a> {
    pub listener: ListenerId,
    pub methods: u32,
    pub pattern: &'a str,
    pub owner: &'a str,
}
/// Refuses the first overlapping pair: the text names both owners and the pattern.
pub fn check_path_claims(claims: &[PathClaim<'_>]) -> Result<(), ConfigRefused> {
    let _ = claims;
    todo!()
}

#[cfg(test)]
#[path = "tests/path_claims_tests.rs"]
mod tests;
