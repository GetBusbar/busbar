// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Core-issued credentials: the ISSUED_WANTED lookup and the issued shapes core mints (IF §12.8). W0-ABI stub: frozen signatures, `todo!()` bodies; W1-K6 fills it.

use busbar_plugin_abi::host_side::caller::BoxFut;

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
/// Round 12: the shape core mints for one issued kind, from that kind's declaring auth plugin's D_ISSUED_SHAPE
/// (§8.3), via `Registry::issued_shapes` (§11.2). Field-for-field today's busbar-contract `IssuedShape`
/// (auth_calls.rs:285-306), which it replaces; it lives in plugin-loader and the kernel re-exports it.
// W0-ABI: the IF places `IssuedShape` in plugin-loader with a kernel re-export; the kernel does not depend on the
// loader in wave 0, so the stub defines it here. W1-K6 turns this into the re-export with that dependency.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IssuedShape {
    pub id_prefix: Box<str>,
    pub id_len: usize,
    pub id_alphabet: Box<str>,
    pub secret_len: usize,
    pub secret_alphabet: Box<str>,
}
/// Built once by K6 from `Registry::issued_shapes()` after every `add`, before core-admin starts.
pub struct IssuedShapes {
    // W0-ABI: private field (kind -> IssuedShape) lands with W1-K6.
    _stub: (),
}
impl IssuedShapes {
    pub fn new(shapes: Vec<(&str, IssuedShape)>) -> Self {
        let _ = shapes;
        todo!()
    }
    pub fn get(&self, kind: &str) -> Option<&IssuedShape> {
        let _ = (&self._stub, kind);
        todo!()
    }
}
// W0-ABI: `KEY_CARRIERS` (IF §12.8, "busbar-kernel auth") is a const of the kernel's `auth` module (W1-K8B's
// auth/mod.rs), not of this module; W0-ABI does not edit auth/mod.rs beyond its one `mod verdicts;` line.
