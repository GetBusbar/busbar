// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One suite per kind (ABI-MIN3-INTERFACE §14), plus `migrate` (round 31). Each runs the generic cases plus the
//! kind's contract cases against the plugin's own static and, in CI, its release cdylib through admit
//! (`BUSBAR_PLUGIN_CDYLIB=<path>`, built in its own `cargo build --release --lib` step). `config` is the operator
//! form (with secret references); the suite binds it.
//!
//! W1-T1 landed the frozen signatures and types; this module keeps them. The shared [`harness`] admits the
//! plugin image into a `Registry<FakeNeeds>` over the real `HOST` static and a `MemBinder`, opens instances,
//! drives them through the kind's port and collects what the plugin did. Each kind's suite body is its own file
//! (`store.rs`, `secret.rs`, `auth.rs`, `hook.rs`, `export.rs`, `plane.rs`, `transport.rs`, `migrate.rs`), so
//! the per-kind work never touches a shared file. No `unsafe` here: the plugin runs in-process on the SDK safe
//! test host.

pub mod harness;

mod auth;
mod export;
mod hook;
mod migrate;
mod plane;
mod secret;
mod store;
mod transport;

pub use busbar_plugin_abi::plugin::Plugin;
/// The case-input types the suite signatures and case structs mention, public so a plugin's tests name them
/// as `busbar_plugin_test::suites::{AuthIn, PlaneIn, Pair, Plugin}` (IF §14).
pub use busbar_plugin_abi::types::Pair;
pub use busbar_plugin_loader::ports::auth::AuthIn;
pub use busbar_plugin_loader::ports::plane::PlaneIn;

use crate::fake_needs::FakeNeeds;

/// config: the converted bag in operator form (canonical JSON compare), None = canonical already; core_cfg:
/// (section, name, value).
pub enum MigrateExpect<'a> {
    Settled {
        config: Option<&'a [u8]>,
        core_cfg: &'a [(u32, &'a str, &'a [u8])],
    },
    Refused(u32),
}

pub struct AuthCase<'a> {
    pub req: AuthIn<'a>,
    pub expect: Expect<'a>,
}

/// upstream[n] = scripted response pieces for exchange n; lookups = records present before the request.
pub struct PlaneCase<'a> {
    pub req: PlaneIn<'a>,
    pub body: &'a [u8],
    pub upstream: &'a [&'a [&'a [u8]]],
    pub lookups: &'a [(&'a [u8], &'a [u8])],
    pub expect_status: u16,
}

pub struct TransportCase<'a> {
    pub role: u32,
    pub alpn: &'a str,
    pub input: &'a [&'a [u8]],
    pub expect_streams: u32,
}

pub enum Expect<'a> {
    Subject(&'a str),
    NotMine,
    Rejected(u32),
}

// Every suite runs describe/open/close through the registry (round 10: inline under entry::guard, I10). Each
// body lives in `suites/<kind>.rs`; the signatures below are frozen (IF §14).
pub fn store(plugin: &'static Plugin, config: &[u8], needs: FakeNeeds) {
    store::run(plugin, config, needs);
}

/// known: (reference, value) pairs the instance must answer; absent: at least one reference, well-formed in the
/// plugin's own reference grammar, that names nothing and must be REFUSED R_NOT_FOUND (the suite does not assume
/// a reference shape). Fetches an absent reference makes are scripted in `needs` like any other.
pub fn secret(
    plugin: &'static Plugin,
    config: &[u8],
    needs: FakeNeeds,
    known: &[(&[u8], &[u8])],
    absent: &[&[u8]],
) {
    secret::run(plugin, config, needs, known, absent);
}

pub fn auth(plugin: &'static Plugin, config: &[u8], needs: FakeNeeds, cases: &[AuthCase<'_>]) {
    auth::run(plugin, config, needs, cases);
}

pub fn hook(plugin: &'static Plugin, config: &[u8], needs: FakeNeeds) {
    hook::run(plugin, config, needs);
}

pub fn export(plugin: &'static Plugin, config: &[u8], needs: FakeNeeds) {
    export::run(plugin, config, needs);
}

pub fn plane(plugin: &'static Plugin, config: &[u8], needs: FakeNeeds, cases: &[PlaneCase<'_>]) {
    plane::run(plugin, config, needs, cases);
}

pub fn transport(plugin: &'static Plugin, config: &[u8], cases: &[TransportCase<'_>]) {
    transport::run(plugin, config, cases);
}

/// Round 31, any kind: `open` an older `bag` (operator form) through the registry's `open_<kind>` (bind, inline
/// steps, `decode_settled`, unbind_refs) and compare the settled answer; then `open` the returned CONFIG again and
/// require no CONFIG back (canonical is a fixed point) and, for a store, one marker read and no write; then data
/// marked newer than the plugin must give REFUSED R_VERSION (NEWER).
pub fn migrate(plugin: &'static Plugin, bag: &[u8], needs: FakeNeeds, expect: MigrateExpect<'_>) {
    migrate::run(plugin, bag, needs, expect);
}
