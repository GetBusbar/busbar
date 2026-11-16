// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Core-issued credentials: the ISSUED_WANTED lookup, the issued shapes core mints (IF §12.8) and the request
//! headers core's own API-key check reads (`KEY_CARRIERS`, round 13).

use std::collections::BTreeMap;

use busbar_plugin_abi::host_side::caller::BoxFut;

/// Field-for-field today's busbar-contract `IssuedShape`; it lives in plugin-loader (IF §12.8).
pub use busbar_plugin_loader::ports::auth::IssuedShape;

/// Core-issued credentials (today's records.secret, e.g. kind "sigv4"), looked up for auth ISSUED_WANTED.
/// Only for an auth instance the operator config grants `kind`; otherwise behaves as unknown. Unknown ids
/// return an empty value through the same code path and timing class (the plugin does the constant-time
/// compare against a dummy key).
pub trait IssuedCredentials: Send + Sync + 'static {
    // W0-ABI: the IF's value type is `zeroize::Zeroizing<Vec<u8>>`, which core bans (LR-094); the stub uses its
    // replacement `busbar_contract::secure::SecureVec`.
    fn lookup<'a>(
        &'a self,
        auth_instance: u64,
        kind: &'a str,
        id: &'a str,
    ) -> BoxFut<'a, busbar_contract::secure::SecureVec>;
}

/// Built once by K6 from `Registry::issued_shapes()` after every `add`, before core-admin starts.
pub struct IssuedShapes {
    by_kind: BTreeMap<Box<str>, IssuedShape>,
}

impl IssuedShapes {
    /// The registry already refuses a second, different shape for one kind (`NameConflict` at `add`), so a
    /// repeated kind here carries the same shape; the first is kept.
    pub fn new(shapes: Vec<(&str, IssuedShape)>) -> Self {
        let mut by_kind = BTreeMap::new();
        for (kind, shape) in shapes {
            by_kind.entry(Box::from(kind)).or_insert(shape);
        }
        Self { by_kind }
    }

    pub fn get(&self, kind: &str) -> Option<&IssuedShape> {
        self.by_kind.get(kind)
    }

    /// The shape to mint for `kind`, or core's refusal text when no admitted auth plugin declares it.
    pub fn for_issuing(&self, kind: &str) -> Result<&IssuedShape, String> {
        self.get(kind).ok_or_else(|| unissued_text(kind))
    }
}

/// Core's text when issuing a credential of a kind no admitted auth plugin declares (IF §12.8).
pub fn unissued_text(kind: &str) -> String {
    format!("no admitted auth plugin uses issued credentials of kind `{kind}`")
}

/// busbar-kernel auth: the request headers core's `keys` reader takes a core-issued API key from, in order
/// (1.5.5's client-token lines). `authorization` is read as `Bearer <key>`; the others carry the key verbatim.
/// Core strips the header that carried a verified key before forwarding, as today. No plugin states or reads it.
// W1-K6: the IF places this const in the kernel's `auth` module, which W1-K8B owns in wave 1; it lands here and
// K8B's `Keys::build` reads it from here (or re-exports it) in its MR.
pub const KEY_CARRIERS: [&str; 3] = ["authorization", "x-api-key", "x-goog-api-key"];

/// The first carrier in [`KEY_CARRIERS`] order that carries a key: its index and the key. `header` answers a
/// request header's value by lowercase name. `authorization` counts only as `Bearer <key>` (scheme matched
/// case-insensitively); an empty key carries nothing.
pub fn carried_key<'h>(header: impl Fn(&str) -> Option<&'h str>) -> Option<(usize, &'h str)> {
    KEY_CARRIERS.iter().enumerate().find_map(|(i, name)| {
        let value = header(name)?.trim();
        let key = if i == 0 {
            let (scheme, rest) = value.split_once(' ')?;
            if !scheme.eq_ignore_ascii_case("bearer") {
                return None;
            }
            rest.trim()
        } else {
            value
        };
        (!key.is_empty()).then_some((i, key))
    })
}

#[cfg(test)]
mod tests;
