// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! HEALTH-STATE PERSISTENCE (D3): restart forgets nothing.
//!
//! Busbar's learned reliability state — circuit breakers, cooldown deadlines, latency EWMAs,
//! hard-down latches — plus the admin audit log and the config version history are snapshotted to
//! ONE state file (~every 30s and on graceful shutdown) and restored at boot. Combined with the
//! stable-lane-identity keying (D1), a restart — including an UPGRADE — costs sub-second downtime
//! and zero amnesia, which is what makes "fix the config and restart" the recovery path (D3: no
//! break-glass endpoints exist).
//!
//! The file is a single JSON document written temp-then-atomic-rename (never a torn read), owned
//! by busbar, fail-soft in every direction: unreadable/corrupt/stale at boot ⇒ start fresh with a
//! loud log; unwritable at runtime ⇒ the snapshotter keeps retrying and says so. It contains NO
//! secrets (health metrics, audit metadata, hook definitions).
//!
//! Path resolution: `BUSBAR_STATE_FILE=/path` overrides; empty string disables; unset defaults to
//! `busbar-state.json` next to config.yaml (and disables, loudly, when there is no config path —
//! ephemeral/test mode).

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// One persisted process state: everything a restart would otherwise forget.
#[derive(Serialize, Deserialize)]
pub(crate) struct PersistedState {
    /// Unix seconds when this snapshot was written (staleness gate at restore).
    pub(crate) written_at: u64,
    /// Per-lane health, keyed by stable identity (D1).
    pub(crate) health: Vec<crate::store::LaneHealthSnapshot>,
    /// The admin audit ring (hash chain intact — restored verbatim, resumed after max seq).
    pub(crate) audit: Vec<crate::admin::audit::AuditEntry>,
    /// The config version history, WITH snapshots (rollback works across restarts).
    pub(crate) versions: Vec<crate::admin::versions::PersistedVersion>,
}

/// Snapshots older than this are dropped whole at restore: a week-old picture of provider health
/// is noise, and every cooldown/window inside it long expired. (Fresh restarts — the actual use
/// case — are seconds old.)
const MAX_SNAPSHOT_AGE_SECS: u64 = 7 * 24 * 3600;

/// Resolve the state-file path: env override / explicit disable / default-next-to-config.
pub(crate) fn resolve_path(config_path: Option<&Path>) -> Option<PathBuf> {
    match std::env::var("BUSBAR_STATE_FILE") {
        Ok(v) if v.is_empty() => None, // explicit opt-out
        Ok(v) => Some(PathBuf::from(v)),
        Err(_) => config_path.map(|p| p.with_file_name("busbar-state.json")),
    }
}

/// Write the snapshot atomically + durably via the crate's ONE durable-write choke point
/// ([`crate::durable::write`]): temp → write → flush → fsync(file) → rename → fsync(parent). Errors
/// are RETURNED (the caller logs once and may disable the loop) — persistence must never take busbar
/// down. Collapsing onto the primitive FIXES the former relative-path parent-fsync skip for free: the
/// primitive resolves an empty parent (a relative state-file path) to "." unconditionally and fsyncs
/// it, so the rename is durable even for a relative path (the old `filter(non-empty)` silently
/// dropped it). No other behavior changes.
pub(crate) fn write(path: &Path, state: &PersistedState) -> Result<(), String> {
    let bytes = serde_json::to_vec(state).map_err(|e| format!("serialize state: {e}"))?;
    crate::durable::write(path, &bytes)
        .map_err(|e| format!("persist state {}: {e}", path.display()))
}

/// Read + staleness-gate a snapshot. `None` = no file / unreadable / corrupt / too old — every
/// case logs and boots fresh (fail-soft; a bad state file can never brick startup).
pub(crate) fn read(path: &Path, now: u64) -> Option<PersistedState> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "state file unreadable; booting fresh");
            return None;
        }
    };
    let state: PersistedState = match serde_json::from_slice(&bytes) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "state file corrupt; booting fresh");
            return None;
        }
    };
    if now.saturating_sub(state.written_at) > MAX_SNAPSHOT_AGE_SECS {
        tracing::warn!(
            path = %path.display(),
            age_secs = now.saturating_sub(state.written_at),
            "state file too old; booting fresh"
        );
        return None;
    }
    Some(state)
}

/// Serializes every snapshot write in the process. Three call sites write the SAME file: the
/// periodic snapshotter, the at-signal shutdown write, and the post-drain shutdown write. Once the
/// first two are offloaded to the blocking pool they no longer complete in the order they were
/// issued — an at-signal write queued behind a busy pool could rename its OLDER `written_at`
/// document over the post-drain write's newer one, and `read` only gates on AGE, so the next boot
/// would take the stale snapshot as authoritative. Same single-permit shape, and the same reason, as
/// `governance::spawn_budget_flusher`'s `flush_gate`.
static SNAPSHOT_GATE: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

/// Capture + write off the reactor, through the ONE gate and the ONE `spawn_blocking` seam. AWAITED,
/// not fire-and-forget: the periodic caller's retry/warn bookkeeping needs the `Result`. A panic
/// inside serde/`durable::write` is folded into the `Result` rather than propagated, so a poisoned
/// blocking-pool task can never end persistence — same posture as an I/O error.
pub(crate) async fn write_snapshot_blocking(
    handle: &crate::state::AppHandle,
    path: &Path,
) -> Result<(), String> {
    let _gate = SNAPSHOT_GATE.lock().await;
    // Capture UNDER the gate: `written_at` is stamped in `capture`, so capturing outside it would
    // let a writer serialize an older reading and still land last.
    let app = handle.load();
    let p = path.to_path_buf();
    match tokio::task::spawn_blocking(move || write(&p, &capture(&app))).await {
        Ok(res) => res,
        Err(e) => Err(format!("snapshot task panicked: {e}")),
    }
}

/// Capture the current process state from a live `App`.
pub(crate) fn capture(app: &crate::state::App) -> PersistedState {
    PersistedState {
        written_at: crate::store::now(),
        health: app.store.export_health(),
        audit: crate::admin::audit::AUDIT.export(),
        versions: app.versions.export(),
    }
}

/// How often the snapshotter captures + writes.
const SNAPSHOT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// Re-warn every Nth consecutive failure, so a persistent outage stays visible without a line per
/// tick. A write failure is a time-varying runtime condition, not a static contradiction — warning
/// once and going quiet leaves an operator who missed that line with no signal that persistence has
/// been down for hours.
const SNAPSHOT_WARN_EVERY: u32 = 10;

/// The periodic snapshotter: capture + write on a fixed cadence. Spawned by main after boot; reads
/// the CURRENT app through the handle so it follows config swaps.
pub(crate) fn spawn_snapshotter(handle: std::sync::Arc<crate::state::AppHandle>, path: PathBuf) {
    spawn_snapshotter_with_interval(handle, path, SNAPSHOT_INTERVAL);
}

/// [`spawn_snapshotter`] with the cadence injected, so a test can drive many ticks without waiting.
pub(crate) fn spawn_snapshotter_with_interval(
    handle: std::sync::Arc<crate::state::AppHandle>,
    path: PathBuf,
    interval: std::time::Duration,
) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The first tick fires immediately: an early snapshot exists even for short-lived runs.
        let mut consecutive: u32 = 0;
        let mut last_success = crate::store::now();
        loop {
            tick.tick().await;
            match write_snapshot_blocking(&handle, &path).await {
                Ok(()) => {
                    if consecutive > 0 {
                        tracing::info!(
                            path = %path.display(),
                            failed_attempts = consecutive,
                            outage_secs = crate::store::now().saturating_sub(last_success),
                            "state snapshot recovered"
                        );
                    }
                    consecutive = 0;
                    last_success = crate::store::now();
                }
                // RETRY, never give up. A full disk, an unmounted volume and a momentary NFS blip
                // are indistinguishable here, so exiting on the first error turned any transient
                // fault into permanent loss of the config version history and learned lane health
                // that only this snapshot carries.
                Err(e) => {
                    consecutive = consecutive.saturating_add(1);
                    if consecutive == 1 || consecutive.is_multiple_of(SNAPSHOT_WARN_EVERY) {
                        tracing::warn!(
                            path = %path.display(),
                            error = %e,
                            consecutive_failures = consecutive,
                            last_success_age_secs =
                                crate::store::now().saturating_sub(last_success),
                            "state snapshot failed; retrying on the next tick (an unclean exit \
                             would lose config version history and learned lane health)"
                        );
                    }
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// write → read round-trips; staleness gate drops old snapshots; corrupt files boot fresh.
    #[test]
    fn roundtrip_staleness_and_corruption() {
        let dir = std::env::temp_dir().join(format!("busbar-persist-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("busbar-state.json");

        let state = PersistedState {
            written_at: 1_000_000,
            health: vec![],
            audit: vec![],
            versions: vec![],
        };
        write(&path, &state).expect("write");
        let got = read(&path, 1_000_100).expect("fresh snapshot restores");
        assert_eq!(got.written_at, 1_000_000);
        // No durable temp (`.busbar-state.json.<pid>-<seq>.tmp`, the primitive's unique naming) must
        // linger after a successful write — the rename consumed it and the RAII guard leaves nothing.
        let no_durable_temp = |dir: &std::path::Path| {
            !std::fs::read_dir(dir).unwrap().any(|e| {
                let n = e.unwrap().file_name();
                let n = n.to_string_lossy();
                n.starts_with(".busbar-state.json.") && n.ends_with(".tmp")
            })
        };
        assert!(no_durable_temp(&dir), "no durable temp should remain");
        // A pre-planted stale temp from a prior crashed run must NOT wedge the next write. Under the
        // primitive's per-call-unique naming a foreign leftover has a different name and is simply
        // ignored; the write still succeeds and leaves no durable temp of its own.
        std::fs::write(path.with_extension("json.tmp"), b"stale leftover").unwrap();
        write(&path, &state).expect("write despite a pre-existing stale temp");
        assert!(no_durable_temp(&dir), "no durable temp should remain");
        let _ = std::fs::remove_file(path.with_extension("json.tmp"));

        // Too old: dropped whole.
        assert!(
            read(&path, 1_000_000 + MAX_SNAPSHOT_AGE_SECS + 1).is_none(),
            "stale snapshot must boot fresh"
        );

        // Corrupt: fail-soft.
        std::fs::write(&path, b"{not json").unwrap();
        assert!(read(&path, 1_000_100).is_none(), "corrupt file boots fresh");

        // Missing: silent None.
        std::fs::remove_file(&path).unwrap();
        assert!(read(&path, 1_000_100).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The full D3 restart cycle at module level: capture a live app's state (tripped lane +
    /// audit + versions), write, read back, restore into a FRESH app — the trip, the audit chain,
    /// and the version history all survive.
    #[test]
    fn capture_write_read_restore_cycle() {
        let dir = std::env::temp_dir().join(format!("busbar-cycle-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("busbar-state.json");

        let app_a = crate::test_support::TestApp::new()
            .lane(crate::test_support::LaneSpec::new(
                "m0",
                crate::proto::Protocol::anthropic(),
                "http://127.0.0.1:1/",
            ))
            .pool("p", &[(0, 1)])
            .build();
        app_a.store.record_hard_down(0, "down before restart");
        app_a.versions.record(
            7,
            "admin",
            "hook.register hook:x",
            &app_a.hook_registry,
            &[],
        );
        write(&path, &capture(&app_a)).expect("snapshot");

        // "Reboot": a fresh app with the same lane identity restores the snapshot.
        let app_b = crate::test_support::TestApp::new()
            .lane(crate::test_support::LaneSpec::new(
                "m0",
                crate::proto::Protocol::anthropic(),
                "http://127.0.0.1:1/",
            ))
            .pool("p", &[(0, 1)])
            .build();
        let persisted = read(&path, crate::store::now()).expect("readable + fresh");
        app_b.store.restore_health(&persisted.health);
        app_b.versions.load(persisted.versions);
        // (The AUDIT global is deliberately NOT loaded here — process-global, and tests share it.)

        let restored = &app_b.store.export_health()[0];
        assert_eq!(restored.dead_reason, "down before restart");
        assert!(
            app_b.versions.get(7).is_some(),
            "version history survives the restart"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Path resolution: env override wins, empty disables, default rides next to config.yaml.
    #[test]
    fn path_resolution_rules() {
        // (env manipulation avoided — parallel-test hazard; the unset-env branches are pure.)
        let cfg = std::path::Path::new("/etc/busbar/config.yaml");
        if std::env::var("BUSBAR_STATE_FILE").is_err() {
            assert_eq!(
                resolve_path(Some(cfg)),
                Some(std::path::PathBuf::from("/etc/busbar/busbar-state.json"))
            );
            assert_eq!(resolve_path(None), None, "no config path = disabled");
        }
    }

    /// A transient write failure must not end persistence for the process. Every other periodic task
    /// in the crate retries — the budget flusher re-marks the cell dirty, the revocation sync leaves
    /// its window open, the audit write-through backfills on the next success — and this one used to
    /// `return` on the first error, giving up the config version history and learned lane health
    /// that no other durable path carries.
    #[tokio::test]
    async fn a_failed_snapshot_retries_and_recovers() {
        let dir = std::env::temp_dir().join(format!("busbar-snap-retry-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("state.json"); // parent absent: every write fails until it exists

        let app = crate::test_support::TestApp::new().build();
        let handle = std::sync::Arc::new(crate::state::AppHandle::new(app));
        spawn_snapshotter_with_interval(handle, path.clone(), std::time::Duration::from_millis(10));

        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        assert!(
            !path.exists(),
            "precondition: the writes are genuinely failing"
        );

        std::fs::create_dir_all(&dir).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !path.exists() && std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            path.exists(),
            "the snapshotter recovered once the path became writable"
        );
        assert!(
            read(&path, crate::store::now()).is_some(),
            "and wrote a valid snapshot, not a truncated one"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// class-10c: the SNAPSHOT_GATE guarantees the LAST snapshot ISSUED is the one left on disk, even
    /// when the two writes race on the blocking pool. `written_at` is second-granularity
    /// (`crate::store::now()`), too coarse to trust as the discriminator over a sub-second race, so
    /// this identifies the winner by CONTENT instead: write A carries a large version history (a slow
    /// `spawn_blocking` write — serialize + fsync + rename of a bigger document), write B carries one
    /// distinctive marker entry and is issued 20ms after A starts. Without the gate, A being issued
    /// FIRST but finishing LAST (it is the bigger payload) is the common case, and its rename lands on
    /// top of B's — the OLDER document ends up authoritative. With the gate, B cannot even `capture`
    /// until A's rename has completed, so the on-disk document is always B's.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_last_snapshot_written_is_the_last_one_issued() {
        let dir = std::env::temp_dir().join(format!("busbar-order-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");

        // Write A: a version snapshot carrying a large hook registry (padded `settings`, NOT
        // version COUNT — `VersionLog` caps retained history at `MAX_VERSIONS = 100`, so bulk
        // record() calls alone do not grow the persisted payload), so its capture+serialize+fsync+
        // rename is comparatively slow on the blocking pool.
        let mut big_registry = std::collections::HashMap::new();
        for i in 0..400 {
            let mut settings = serde_json::Map::new();
            settings.insert(
                "pad".to_string(),
                serde_json::Value::String("x".repeat(4096)),
            );
            big_registry.insert(
                format!("hook-{i}"),
                crate::config::HookCfg {
                    kind: crate::config::HookKind::Tap,
                    plugin: "test-hook".to_string(),
                    timeout_ms: 1,
                    on_error: "weighted".to_string(),
                    prompt: crate::config::PromptAccess::Ro,
                    user: crate::config::UserAccess::Ro,
                    priority: 0,
                    at: None,
                    settings,
                    on_empty: None,
                    global: false,
                    default: false,
                },
            );
        }
        let app_a = crate::test_support::TestApp::new().build();
        app_a
            .versions
            .record(1, "admin", "hook.register hook:bulk", &big_registry, &[]);
        let handle_a = std::sync::Arc::new(crate::state::AppHandle::new(app_a));

        // Write B: a single, distinctive marker entry — small and fast — issued strictly AFTER A.
        let app_b = crate::test_support::TestApp::new().build();
        app_b.versions.record(
            1,
            "admin",
            "hook.register hook:MARKER-B",
            &app_b.hook_registry,
            &[],
        );
        let handle_b = std::sync::Arc::new(crate::state::AppHandle::new(app_b));

        let path_a = path.clone();
        let path_b = path.clone();
        let wa = tokio::spawn(async move { write_snapshot_blocking(&handle_a, &path_a).await });
        // A must be ISSUED (and its capture underway) before B is issued, so "B is the last one
        // issued" is unambiguous.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let wb = tokio::spawn(async move { write_snapshot_blocking(&handle_b, &path_b).await });

        let (ra, rb) = tokio::join!(wa, wb);
        ra.unwrap().expect("write A must succeed");
        rb.unwrap().expect("write B must succeed");

        let on_disk = read(&path, crate::store::now()).expect("a snapshot must be on disk");
        assert!(
            on_disk
                .versions
                .iter()
                .any(|v| v.summary.contains("MARKER-B")),
            "the LAST-issued write (B) must be the one on disk, not the earlier, bigger write (A)"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// class-10c §4.6 — DEMONSTRATION, NOT A GATING RED PROOF. Per PIPELINE-BRIEF: there is no
    /// non-flaky RED proof that a write left the reactor — blocking-pool threads share the worker
    /// thread-name prefix, `write` is a free function with no injection seam, and every timing
    /// threshold is machine-dependent in the direction that breaks the suite. Following the in-tree
    /// `2b545ae` precedent (the M8 TOCTOU proof): ship an `#[ignore]`d demonstration carrying its
    /// repro command, with the precondition expressed as an early SKIP rather than a failing assert.
    ///
    /// Shape: time one SYNCHRONOUS `write` of a large payload as `W`. Then run the periodic
    /// snapshotter (which now offloads via `write_snapshot_blocking`) on a SINGLE-WORKER runtime
    /// alongside a 1ms probe loop measuring the largest gap between successive wakeups. If the
    /// snapshot write ran ON the reactor (the pre-offload behaviour), it would starve the probe loop
    /// — sharing the runtime's ONE worker — for roughly `W`; offloaded, the probe loop's gaps stay
    /// near the 1ms tick regardless of `W`.
    ///
    /// Repro: `cargo test -p busbar --bin busbar -- --ignored \
    /// state_persist::tests::snapshot_write_does_not_block_the_reactor --test-threads=1 --nocapture`
    #[test]
    #[ignore = "timing-dependent demonstration, not a gating RED proof — see doc comment; repro: \
                cargo test -p busbar --bin busbar -- --ignored \
                state_persist::tests::snapshot_write_does_not_block_the_reactor \
                --test-threads=1 --nocapture"]
    fn snapshot_write_does_not_block_the_reactor() {
        let big_registry = {
            let mut m = std::collections::HashMap::new();
            for i in 0..2000 {
                let mut settings = serde_json::Map::new();
                settings.insert(
                    "pad".to_string(),
                    serde_json::Value::String("x".repeat(4096)),
                );
                m.insert(
                    format!("hook-{i}"),
                    crate::config::HookCfg {
                        kind: crate::config::HookKind::Tap,
                        plugin: "test-hook".to_string(),
                        timeout_ms: 1,
                        on_error: "weighted".to_string(),
                        prompt: crate::config::PromptAccess::Ro,
                        user: crate::config::UserAccess::Ro,
                        priority: 0,
                        at: None,
                        settings,
                        on_empty: None,
                        global: false,
                        default: false,
                    },
                );
            }
            m
        };

        let dir = std::env::temp_dir().join(format!("busbar-reactor-block-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");

        let app = crate::test_support::TestApp::new().build();
        app.versions
            .record(1, "admin", "hook.register hook:bulk", &big_registry, &[]);
        let state = capture(&app);

        // Baseline: time ONE synchronous write to establish `W`.
        let t0 = std::time::Instant::now();
        write(&path, &state).expect("baseline write");
        let w = t0.elapsed();

        if w < std::time::Duration::from_millis(20) {
            // SKIP, not fail: on a fast disk `W` itself is too close to scheduling noise to be a
            // trustworthy signal either way. Per the brief, withdraw rather than tune a failing
            // assertion into passing.
            eprintln!(
                "SKIP: baseline write W={w:?} is too fast on this machine to distinguish a \
                 reactor-blocked write from ordinary scheduling jitter"
            );
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }

        // A SINGLE-WORKER runtime: the offloaded write and the probe loop only share the reactor's
        // scheduling if the write actually lands there instead of on the blocking pool.
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();

        let max_gap = rt.block_on(async move {
            let handle = std::sync::Arc::new(crate::state::AppHandle::new(app));
            spawn_snapshotter_with_interval(handle, path, std::time::Duration::from_millis(1));

            let mut max_gap = std::time::Duration::ZERO;
            let mut last = std::time::Instant::now();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
            while std::time::Instant::now() < deadline {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                let now = std::time::Instant::now();
                let gap = now.duration_since(last);
                if gap > max_gap {
                    max_gap = gap;
                }
                last = now;
            }
            max_gap
        });

        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            max_gap < w / 2,
            "the probe loop's largest gap ({max_gap:?}) approached the synchronous write time \
             ({w:?}) — the snapshot write appears to have run on the reactor instead of the \
             blocking pool"
        );
    }
}
