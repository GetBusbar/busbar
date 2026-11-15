// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The process-wide `Host` static, its fault counters, the deployment id and the log sink (IF §10.7). W0-ABI stub: frozen signatures, `todo!()` bodies; W1-H0 fills it.

use core::sync::atomic::AtomicU64;

// W0-ABI: `pub static HOST: Host;` (IF §10.7: the process-wide Host vtable every plugin gets, every fn in it run
// under `contain`) is omitted: `crate::host::Host` is an opaque wave-0 stub (its fields are raw entry fn
// pointers) that cannot be constructed outside host.rs. It lands with W1-H0 under an escapes admission, with the
// private `contain`, the `DEPLOYMENT` `OnceLock<DeploymentId>` and the per-thread scratch `Arena`.

/// Round 20: host-side fault counters, `[SELF_TEST, HOST_PANIC, LOG_UNATTRIBUTED]` (indices 0, 1 and, round 24, 2:
/// a log line the sink got with no slot, §10.7 `set_log_sink`), written only on the failure paths (one Relaxed
/// `fetch_add`), read by the registry's watchdog thread every tick (§5.2, I10).
pub static HOST_FAULTS: [AtomicU64; 3] = [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];

/// Round 28: the deployment id `Host::deployment` answers. **Round 29: held as one
/// `static DEPLOYMENT: OnceLock<DeploymentId>`** (round 28's two `AtomicU64` with two Relaxed loads could be read
/// torn by a step-2a/2b instance on another thread: one word set, the other still 0, which `deployment_id()` would
/// have returned as `Some` of a half-written id). `set_deployment` is `DEPLOYMENT.set(DeploymentId(id))` (release
/// publication of all 16 bytes at once); `deployment`'s body is `*DEPLOYMENT.get().unwrap_or(&DeploymentId([0; 16]))`
/// under `contain` (one Acquire load, no lock on the read path, no allocation). An all-zero `id` is refused by a
/// debug assert and not stored. Called once by L2's `BootPlan` right after step 2b, with the id the kernel's boot
/// identity read or wrote (boot_identity.rs keep-once pattern, `busbar.deployment.v1`/`id`; K-side, ADMIN-API-1.6
/// AR-01), before the step-2a/2b re-check and before any step-2c instance is migrated or opened (§11.2); a second
/// call with a different id panics in debug and is ignored in release (the row is keep-once).
pub fn set_deployment(id: [u8; 16]) {
    let _ = id;
    todo!()
}

/// Where `Host::log` lines go. The registry installs it once (`Registry::new`): it maps the slot from
/// `watch::current_slot()` to the **slot record** (round 8: never to an `Instance`; the record holds kind,
/// configured name and `Arc<Scrub>` and lives from slot allocation until its lease is released after close or
/// after the last cancel of an Image-owned chain), runs `record.scrub.text(msg)` (§12.16; round 17: 2 RMWs on the
/// thread's own arc-swap debt slot per line, I5's fourth stated exception, and never a free) and emits the scrubbed
/// line attributed to (`kind`, `instance` = configured name) — operator vocabulary only, never the stamp name
/// except inside a core-written code (round 34, I2's exception: `plugin_diag` and the joined text that starts
/// with it), so the line can go to STREAM_LOGS exporters unchanged (I2, round 6). **Round 34
/// (PLUGIN-ERROR-CODES):** the sink gets `log`'s `error` as the raw `u32` and resolves it through the slot
/// record's `ErrorBook` (§11.2 `ErrorBook::resolve`): 0 = no code; above 9999 (checked as a `u32`, before any
/// narrowing, so 65,607 never becomes 71) or not in the book = not declared (no code, one WARN per slot via the
/// record's latch); a refused book = no code, no WARN; else the code. The emitted line carries `kind`,
/// `instance`, `plugin_diag` (only when there is a code) and `text`: a plain `&str` field, never `message` and never
/// `%`/`?`, holding the scrubbed line, or with a code the joined `"{code}: {text}"` written into a fixed stack buffer
/// (≤ 76 + 2 + 512 bytes, no allocation); §12.16 states the quoting rule. A describe-time line renders no code and
/// no WARN (the book does not exist yet). No rate cap: GetBusbar/busbar #241. An Image-owned entry (describe, migrate, open)
/// attributes to the instance-to-be's configured name (describe: `kind` only). Before installation, or outside an
/// entry, lines are dropped. **Round 24, normative:** the sink gets `None` only outside an entry (every guard sets
/// `OWNER`, watched or not); a `None` line, or a slot whose record is already gone, is dropped and counted
/// (`HOST_FAULTS[LOG_UNATTRIBUTED]`, metric `plugin_host_fault_total{fault="log_unattributed"}`), **never emitted
/// unscrubbed** (I14). Round 20: the sink runs inside `log`'s `contain`; a panicking sink drops that line
/// and counts one `HOST_PANIC`, never an abort.
pub fn set_log_sink(sink: fn(slot: Option<u32>, level: u32, error: u32, msg: &str)) {
    let _ = sink;
    todo!()
}
