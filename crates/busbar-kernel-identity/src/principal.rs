// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Who is calling — the one caller who is nobody, and the ids no auth module may hand back.

/// The literal an unauthenticated caller renders as, on every surface that names an actor: the
/// audit row, the chain hash and the idempotency namespace all spell it this way, so nothing that
/// reads an actor id has to know whether a principal was resolved.
///
/// The internal attribution bucket for anonymous traffic is a different string entirely and never
/// reaches a surface.
pub const ANONYMOUS: &str = "anonymous";

/// The id prefixes an auth module may not hand back. `group:` names a governance group's bucket and
/// `vk_` names a minted key's: a module that identified a caller as either would be naming an
/// identity the governance tables alone issue, and its ledger and rate buckets with it.
pub const RESERVED_ID_PREFIXES: [&str; 2] = ["group:", "vk_"];

/// Whether an id an auth module identified a caller as lands in reserved space
/// ([`RESERVED_ID_PREFIXES`]). The kernel's chain walk refuses such an identification at the
/// position that made it (the data-plane chain and the admin chain alike), and governance refuses
/// to synthesize a key for one: the module does not get to name a group or a minted key.
#[must_use]
pub fn id_is_reserved(id: &str) -> bool {
    RESERVED_ID_PREFIXES.iter().any(|p| id.starts_with(p))
}
