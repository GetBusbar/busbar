// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `HostExt` (IF §5.1, coordinator ruling on W1-U0): the safe host methods are an extension trait over
//! busbar-ffi's `Host`, so call syntax is unchanged once the trait is in scope. Each answer is read from the
//! host table's safe fn pointers; a null (None) entry reads as its panic fallback (I10).

use std::sync::Mutex;

use busbar_plugin_abi::fail::refused;
use busbar_plugin_abi::host::{CryptoErr, CryptoRet, Ctx, DeploymentId, Host, HostExt, HostFns};
use busbar_plugin_abi::types::{Status, Str};

extern "C" fn now(_: Ctx<'_>) -> u64 {
    1_700_000_123_456_789_012
}
extern "C" fn mono(_: Ctx<'_>) -> u64 {
    42
}
extern "C" fn level(_: Ctx<'_>) -> u32 {
    3
}
extern "C" fn deployment(_: Ctx<'_>) -> DeploymentId {
    DeploymentId([7; 16])
}
extern "C" fn zero_deployment(_: Ctx<'_>) -> DeploymentId {
    DeploymentId([0; 16])
}
extern "C" fn rng_fails(ctx: Ctx<'_>, _len: usize) -> CryptoRet<'_> {
    CryptoRet::empty(ctx, 5)
}
extern "C" fn short_answer(ctx: Ctx<'_>, _len: usize) -> CryptoRet<'_> {
    CryptoRet::empty(ctx, 0)
}
extern "C" fn admit_ok(
    _: Ctx<'_>,
    _id: u64,
    _call: &busbar_plugin_abi::types::Call<'_>,
    _out: &mut busbar_plugin_abi::types::RawOut,
) -> Status {
    Status::OK
}
extern "C" fn admit_refused(
    _: Ctx<'_>,
    _id: u64,
    _call: &busbar_plugin_abi::types::Call<'_>,
    _out: &mut busbar_plugin_abi::types::RawOut,
) -> Status {
    Status::REFUSED
}

static LOGGED: Mutex<Vec<(u32, u32, String)>> = Mutex::new(Vec::new());
extern "C" fn log(_: Ctx<'_>, level: u32, error: u32, text: Str<'_>) {
    if let Ok(mut lines) = LOGGED.lock() {
        lines.push((level, error, text.get().to_owned()));
    }
}

static FULL: Host = Host::new(
    0,
    HostFns {
        now: Some(now),
        mono: Some(mono),
        random: Some(rng_fails),
        crypto: None,
        log: Some(log),
        log_level: Some(level),
        grow: None,
        deployment: Some(deployment),
        service: Some(admit_ok),
    },
);
static EMPTY_ANSWERS: Host = Host::new(
    0,
    HostFns {
        now: None,
        mono: None,
        random: Some(short_answer),
        crypto: None,
        log: None,
        log_level: None,
        grow: None,
        deployment: Some(zero_deployment),
        service: Some(admit_refused),
    },
);
static NO_ENTRIES: Host = Host::new(
    0,
    HostFns {
        now: None,
        mono: None,
        random: None,
        crypto: None,
        log: None,
        log_level: None,
        grow: None,
        deployment: None,
        service: None,
    },
);

#[test]
fn the_clocks_read_the_host_table() {
    assert_eq!(FULL.now_ns(), 1_700_000_123_456_789_012);
    assert_eq!(FULL.now_s(), 1_700_000_123);
    assert_eq!(FULL.mono_ns(), 42);
}

#[test]
fn a_null_entry_reads_as_its_panic_fallback() {
    assert_eq!(NO_ENTRIES.now_ns(), 0);
    assert_eq!(NO_ENTRIES.now_s(), 0);
    assert_eq!(NO_ENTRIES.mono_ns(), 0);
    assert!(!NO_ENTRIES.log_enabled(1));
    NO_ENTRIES.log(1, "dropped");
    assert_eq!(NO_ENTRIES.deployment_id(), None);
    assert_eq!(NO_ENTRIES.random::<8>(), Err(CryptoErr::Rng));
    let refused_open = NO_ENTRIES.migrate_admit(1).err().map(|f| f.code());
    assert_eq!(refused_open, Some(refused::R_CONFIG));
}

#[test]
fn log_levels_gate_on_the_hosts_most_verbose_level() {
    assert!(FULL.log_enabled(1));
    assert!(FULL.log_enabled(3));
    assert!(!FULL.log_enabled(4));
    assert!(!FULL.log_enabled(0));
    assert!(!EMPTY_ANSWERS.log_enabled(1));
}

#[test]
fn log_lines_carry_level_error_number_and_text() {
    FULL.log(2, "plain");
    FULL.log_error(1, 17, "numbered");
    let lines = LOGGED.lock().map(|l| l.clone()).unwrap_or_default();
    assert!(lines.contains(&(2, 0, "plain".to_owned())));
    assert!(lines.contains(&(1, 17, "numbered".to_owned())));
}

#[test]
fn the_deployment_id_is_none_until_the_host_knows_it() {
    assert_eq!(FULL.deployment_id(), Some(DeploymentId([7; 16])));
    assert_eq!(EMPTY_ANSWERS.deployment_id(), None);
}

#[test]
fn random_maps_a_failed_status_and_refuses_a_short_answer() {
    assert_eq!(FULL.random::<4>(), Err(CryptoErr::Rng));
    assert_eq!(FULL.random_vec(4), Err(CryptoErr::Rng));
    // OK status but not `len` bytes: a host bug, never read as random bytes.
    assert_eq!(EMPTY_ANSWERS.random::<4>(), Err(CryptoErr::Rng));
    let mut buf = [0u8; 4];
    assert_eq!(EMPTY_ANSWERS.random_into(&mut buf), Err(CryptoErr::Rng));
    assert_eq!(buf, [0; 4], "nothing is copied from a refused answer");
}

#[test]
fn migrate_admit_is_ok_on_ok_and_refused_config_otherwise() {
    assert!(FULL.migrate_admit(1).is_ok());
    let fail = EMPTY_ANSWERS.migrate_admit(1).err();
    assert_eq!(fail.as_ref().map(|f| f.code()), Some(refused::R_CONFIG));
    assert_eq!(fail.map(|f| f.status()), Some(Status::REFUSED));
}
