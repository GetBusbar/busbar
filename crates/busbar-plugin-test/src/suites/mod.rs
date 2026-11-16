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

/// One scripted transport case. ROLE_CLIENT: after `begin` the suite opens the stream the way core does, with
/// `emit(E_HEAD)` on stream 0 (IF §8.7) carrying a default dial head (GET `/`, authority `peer.test`, scheme
/// `https`), then feeds `input`. The fields are frozen (IF §14); conn facts a case may need beyond them
/// (CONN_UPGRADED and the adopted head, leftover bytes, its own dial head) go on a [`TransportConnCase`].
#[derive(Clone, Copy)]
pub struct TransportCase<'a> {
    pub role: u32,
    pub alpn: &'a str,
    pub input: &'a [&'a [u8]],
    pub expect_streams: u32,
}

/// A [`TransportCase`] with the conn facts the suite otherwise leaves at their defaults, run by
/// [`transport_conns`]. Additive to IF §14: `TransportCase` and `transport` stay as frozen, so every existing
/// struct literal still builds. Build one with [`TransportConnCase::new`] (or `From<TransportCase>`) and the
/// builder methods.
#[derive(Clone, Copy)]
pub struct TransportConnCase<'a> {
    pub case: TransportCase<'a>,
    /// `ConnInfo.flags`: CONN_UPGRADED on a ROLE_SERVER conn core adopted from an UPGRADE. Default 0.
    pub flags: u32,
    /// `ConnInfo.head`: with CONN_UPGRADED, the adopted request's head records (H_METHOD, H_PATH, H_AUTHORITY,
    /// PAIR*, then H_STATUS(101) and the plane's RESPOND PAIR*). Default empty.
    pub head: &'a [u8],
    /// `ConnInfo.leftover`: bytes adopted from the UPGRADE. Default empty.
    pub leftover: &'a [u8],
    /// ROLE_CLIENT only: the head records the suite's `emit(E_HEAD)` on stream 0 carries. Empty = the suite's
    /// default dial head.
    pub dial_head: &'a [u8],
}

impl<'a> TransportConnCase<'a> {
    pub const fn new(case: TransportCase<'a>) -> Self {
        TransportConnCase {
            case,
            flags: 0,
            head: &[],
            leftover: &[],
            dial_head: &[],
        }
    }
    pub const fn flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }
    pub const fn head(mut self, head: &'a [u8]) -> Self {
        self.head = head;
        self
    }
    pub const fn leftover(mut self, leftover: &'a [u8]) -> Self {
        self.leftover = leftover;
        self
    }
    pub const fn dial_head(mut self, dial_head: &'a [u8]) -> Self {
        self.dial_head = dial_head;
        self
    }
}

impl<'a> From<TransportCase<'a>> for TransportConnCase<'a> {
    fn from(case: TransportCase<'a>) -> Self {
        Self::new(case)
    }
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
    let cases: Vec<TransportConnCase<'_>> =
        cases.iter().copied().map(TransportConnCase::new).collect();
    transport::run(plugin, config, &cases);
}

/// Additive to IF §14: [`transport`] over cases that state their conn facts (an upgraded server conn, a dial
/// with its own head).
pub fn transport_conns(plugin: &'static Plugin, config: &[u8], cases: &[TransportConnCase<'_>]) {
    transport::run(plugin, config, cases);
}

/// Round 31, any kind: `open` an older `bag` (operator form) through the registry's `open_<kind>` (bind, inline
/// steps, `decode_settled`, unbind_refs) and compare the settled answer; then `open` the returned CONFIG again and
/// require no CONFIG back (canonical is a fixed point) and, for a store, one marker read and no write; then data
/// marked newer than the plugin must give REFUSED R_VERSION (NEWER).
pub fn migrate(plugin: &'static Plugin, bag: &[u8], needs: FakeNeeds, expect: MigrateExpect<'_>) {
    migrate::run(plugin, bag, needs, expect);
}
