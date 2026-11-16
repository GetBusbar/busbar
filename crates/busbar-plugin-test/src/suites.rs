// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One suite per kind (ABI-MIN3-INTERFACE §14), plus `migrate` (round 31). Each runs the generic cases plus the
//! kind's contract cases against the plugin's own static and, in CI, its release cdylib through admit
//! (`BUSBAR_PLUGIN_CDYLIB=<path>`, built in its own `cargo build --release --lib` step). `config` is the operator
//! form (with secret references); the suite binds it.
//!
//! W1-T1 lands the frozen signatures and types. The bodies wait for the pieces a suite drives a plugin through:
//! `admit_linked`/`admit` (W1-L1), `Registry::new`, which needs the `ConfigBinder` trait homed where the loader
//! can name it (W1-L2; W0-ABI left it out, see instance.rs), the `HOST` static and its raw entries (W1-A2,
//! UNSAFE-MIN), the `kind!`/`plugin!` shims (W1-A4) and the step driver (W1-H1). Until then every suite stops
//! with a message naming them, and no plugin port can run one (the ports start after W1-L2, WBS §3).

use busbar_plugin_abi::plugin::Plugin;
use busbar_plugin_abi::types::KindCode;
use busbar_plugin_loader::ports::auth::AuthIn;
use busbar_plugin_loader::ports::plane::PlaneIn;

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

/// Where every suite stops until its registry exists (module doc).
fn unbuilt(kind: Option<KindCode>, plugin: &'static Plugin, config: &[u8], needs: &FakeNeeds) {
    let _ = (plugin, config, needs);
    todo!(
        "suites ({kind:?}): needs admit_linked (W1-L1), Registry::new with a homed ConfigBinder (W1-L2), the HOST \
         static (W1-A2, UNSAFE-MIN), the kind!/plugin! shims (W1-A4) and the driver (W1-H1)"
    )
}

// Every suite runs describe/open/close through the registry (round 10: inline under entry::guard, I10).
pub fn store(plugin: &'static Plugin, config: &[u8], needs: FakeNeeds) {
    unbuilt(Some(KindCode::Store), plugin, config, &needs);
}

pub fn secret(plugin: &'static Plugin, config: &[u8], needs: FakeNeeds, known: &[(&[u8], &[u8])]) {
    let _ = known;
    unbuilt(Some(KindCode::Secret), plugin, config, &needs);
}

pub fn auth(plugin: &'static Plugin, config: &[u8], needs: FakeNeeds, cases: &[AuthCase<'_>]) {
    let _ = cases;
    unbuilt(Some(KindCode::Auth), plugin, config, &needs);
}

pub fn hook(plugin: &'static Plugin, config: &[u8], needs: FakeNeeds) {
    unbuilt(Some(KindCode::Hook), plugin, config, &needs);
}

pub fn export(plugin: &'static Plugin, config: &[u8], needs: FakeNeeds) {
    unbuilt(Some(KindCode::Export), plugin, config, &needs);
}

pub fn plane(plugin: &'static Plugin, config: &[u8], needs: FakeNeeds, cases: &[PlaneCase<'_>]) {
    let _ = cases;
    unbuilt(Some(KindCode::Plane), plugin, config, &needs);
}

pub fn transport(plugin: &'static Plugin, config: &[u8], cases: &[TransportCase<'_>]) {
    let _ = cases;
    unbuilt(Some(KindCode::Transport), plugin, config, &FakeNeeds::new());
}

/// Round 31, any kind: `open` an older `bag` (operator form) through the registry's `open_<kind>` (bind, inline
/// steps, `decode_settled`, unbind_refs) and compare the settled answer; then `open` the returned CONFIG again and
/// require no CONFIG back (canonical is a fixed point) and, for a store, one marker read and no write; then data
/// marked newer than the plugin must give REFUSED R_VERSION (NEWER).
pub fn migrate(plugin: &'static Plugin, bag: &[u8], needs: FakeNeeds, expect: MigrateExpect<'_>) {
    let _ = expect;
    unbuilt(None, plugin, bag, &needs);
}
