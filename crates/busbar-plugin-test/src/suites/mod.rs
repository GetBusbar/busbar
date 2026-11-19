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
pub(crate) mod store;
mod transport;

pub use busbar_plugin_abi::plugin::Plugin;
/// The case-input types the suite signatures and case structs mention, public so a plugin's tests name them
/// as `busbar_plugin_test::suites::{AuthIn, PlaneIn, Pair, Plugin}` (IF §14).
pub use busbar_plugin_abi::types::Pair;
pub use busbar_ports::auth::AuthIn;
pub use busbar_ports::plane::PlaneIn;

use crate::fake_needs::FakeNeeds;

/// An explicit initial migration input. Purpose is host intent, never inferred from the bag or expectation.
/// Later fixed-point and newer probes use Canonical with these same limits.
pub struct MigrateCase<'a> {
    pub bag: &'a [u8],
    pub purpose: harness::OpenPurpose,
    pub limits: harness::InstanceLimits,
}

/// config: Some requires emitted CONFIG equal to the expected operator-form JSON tree; None requires
/// unchanged settings (an equal CONFIG echo, or no CONFIG, which on a conversion core settles as the bag,
/// #432). core_cfg: (section, name, value).
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

/// A [`TransportCase`] with the conn facts the suite otherwise leaves at their defaults, as [`transport`]
/// runs each case. Additive to IF §14: `TransportCase` and `transport` stay as frozen, so every existing
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

/// What a case's `verify` must end in. `IssuedWanted` is the first call's raw answer. Every other variant is the
/// final verdict as core reaches it: when the first call answers ISSUED_WANTED, the suite looks the id up under the
/// plugin's D_ISSUED_KIND in what [`FakeNeeds::issued`] scripted (empty when nothing was) and calls `verify` once
/// more with it, and a second ISSUED_WANTED is `Rejected(BAD_CREDENTIAL)` (busbar-kernel `auth::chain_run`).
pub enum Expect<'a> {
    /// Raw one-call ISSUED_WANTED: the suite makes no lookup and no second call.
    IssuedWanted(&'a str),
    /// Raw one-call KEYS_STALE; host refresh is tested in kernel.
    KeysStale,
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

/// [`auth`] on settings core migrated from older ones. `case.bag` (older settings, a literal secret included) is
/// opened with `case.purpose` and its settled answer checked against `expect` exactly as [`migrate_legacy`]'s first
/// case checks it (`legacy`: the 1.5.5 D_SECRET_PATH pointers core's marker names, or none); every CORE_CFG(LIFT)
/// literal is then moved into custody as core moves it, and every step of [`auth`] runs, `cases` included, on the
/// settings core persisted. A literal secret is so proven end to end: lifted, referenced, resolved and verifying.
/// `expect` must be `Settled`; a refused migration is [`migrate_case`]'s.
pub fn auth_migrated(
    plugin: &'static Plugin,
    case: MigrateCase<'_>,
    legacy: &[&str],
    needs: FakeNeeds,
    expect: MigrateExpect<'_>,
    cases: &[AuthCase<'_>],
) {
    auth::migrated(plugin, &case, legacy, needs, expect, cases);
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

/// Round 31, any kind: `open` an older `bag` (operator form) through the registry's `open_<kind>` (bind, inline
/// steps, `decode_settled`, unbind_refs) and compare the settled answer; then `open` the returned CONFIG again and
/// require absent or semantically identical CONFIG (canonical is a fixed point) and no CORE_CFG or writes; then data
/// marked newer than the plugin must give REFUSED R_VERSION (NEWER).
pub fn migrate(plugin: &'static Plugin, bag: &[u8], needs: FakeNeeds, expect: MigrateExpect<'_>) {
    migrate_case(
        plugin,
        MigrateCase {
            bag,
            purpose: harness::OpenPurpose::ConvertUnstamped,
            limits: harness::InstanceLimits::default(),
        },
        needs,
        expect,
    );
}

/// Run the migration suite with explicit initial purpose and instance limits. Use Canonical for an
/// already canonical input. A ConvertUnstamped open that answers no CONFIG settles the bag unchanged (#432).
pub fn migrate_case(
    plugin: &'static Plugin,
    case: MigrateCase<'_>,
    needs: FakeNeeds,
    expect: MigrateExpect<'_>,
) {
    migrate::run(plugin, case, &[], needs, expect);
}

/// [`migrate_case`] for a converting case whose bag carries 1.5.5 values at the D_SECRET_PATH pointers `legacy`
/// (LEGACY-KEYFILE-MARKER r2): the first open sees `"$migrated": {"legacy": [..]}` in its bag, as core's
/// migration plan marks it, and the settled answer is compared with the marker stripped.
pub fn migrate_legacy(
    plugin: &'static Plugin,
    case: MigrateCase<'_>,
    legacy: &[&str],
    needs: FakeNeeds,
    expect: MigrateExpect<'_>,
) {
    migrate::run(plugin, case, legacy, needs, expect);
}
