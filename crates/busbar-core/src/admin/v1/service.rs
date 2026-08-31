// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The Admin API v1 SERVICE — the application core (the "port").
//!
//! `AdminService` owns every admin OPERATION as a typed async method returning `Result<View,
//! AdminError>`. It holds the shared `App` and knows nothing about HTTP/JSON/MCP: a transport adapter
//! (`super::transport`) drives it and projects the result onto a wire. This is where scope checks,
//! atomicity, and audit live as the surface grows — one place, reused by every transport (REST now;
//! GraphQL/MCP/gRPC later, unchanged).

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use crate::diagnostics::{
    diag_debug, diag_error, diag_warn, ADMIN_STORE_OPERATION_FAILED, GROUP_DELETE_KEY_READ_FAILED,
    PLUGINS_DIR_FINGERPRINT_FAILED, PLUGIN_CATALOG_BLOCKING_TASK_FAILED,
    PLUGIN_CATALOG_SCAN_GATE_TIMEOUT, USAGE_BLOCKING_TASK_JOIN_FAILED,
};
use crate::state::App;

use super::contract::{
    AdminAuthView, AdminError, AuthView, BuildInfo, ConfigValidateView, EffectiveConfigView,
    GroupView, HookHealthView, HookTransportView, HookView, InfoView, KeyUsageView, ModelUsageView,
    ModelView, NamedDefView, Page, PluginView, PoolDetailView, PoolMemberStatusView,
    PoolMemberView, PoolView, ProviderView, TopologyInfo, UsageBreakdown, UsageView, UsageWindow,
};
use crate::config::named_map::NamedMapSection;
use crate::config::{
    DeployCfg, HookCfg, HookKind, HookStage, PromptAccess, ProviderDef, UserAccess,
};

/// The KEY NAMES of one opaque `settings:` bag, sorted — the REDACTED projection EVERY admin read
/// serves instead of the bag itself (see [`NamedDefView::settings_keys`]: a settings value may be a
/// credential and these reads are reachable at READ-ONLY admin scope).
///
/// THE ONE PROJECTION, deliberately: named-map definitions, hook definitions, hook STATUS (desired
/// and reported), and the whole-`RootSettings` config read all go through this function (or through
/// [`redact_settings_bags`], which is this function applied structurally). A second redaction scheme
/// is how a leak comes back — and `scripts/settings-leak-lint.sh` fails the build for any admin
/// projection that grows a raw `settings` bag instead of using one of these two.
pub(crate) fn settings_keys(settings: &serde_json::Map<String, serde_json::Value>) -> Vec<String> {
    let mut keys: Vec<String> = settings.keys().cloned().collect();
    keys.sort();
    keys
}

/// [`settings_keys`] applied STRUCTURALLY to an already-serialized admin body: every `"settings"`
/// member, at any depth, is replaced by a `"settings_keys"` member holding its sorted key names.
///
/// For the reads that serialize a whole typed config tree rather than hand-building a view — today
/// `GET /api/v1/admin/config/settings`, which does `serde_json::to_value(&RootSettings)` and so
/// carries `store.settings` (busbar's OWN docs spell that bag with a credential:
/// `url: rediss://:password@…`, and `plugin-pack` marks a store `url` `x-busbar-secret`). That read
/// requires only READ-ONLY scope while the matching `PUT` requires FULL, so before this a read-only
/// admin could lift the governance ledger's credential — keys, budgets, the hash-chained audit log —
/// entirely out of band of busbar.
///
/// A `settings` value that is NOT an object is redacted to an EMPTY key list rather than passed
/// through: `config::secret::resolve_settings` forwards a non-object bag verbatim, so a bare scalar
/// credential there is fully supported and must not ride out on the "it isn't a map so it can't be a
/// secret" assumption.
pub(crate) fn redact_settings_bags(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::Object(map) => {
            if let Some(bag) = map.remove("settings") {
                let keys = match bag {
                    serde_json::Value::Object(o) => settings_keys(&o),
                    _ => Vec::new(),
                };
                map.insert(
                    "settings_keys".to_string(),
                    serde_json::Value::Array(
                        keys.into_iter().map(serde_json::Value::String).collect(),
                    ),
                );
            }
            for (_, child) in map.iter_mut() {
                redact_settings_bags(child);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                redact_settings_bags(item);
            }
        }
        _ => {}
    }
}

use super::named_def_views::{export_def_view, identity_provider_view, unparseable_def_view};

/// Derive busbar's spend ESTIMATE (micro-units, abstract cost units) for one PER-MODEL metering
/// row from the CURRENT rate card: the row's tier-token split priced at that model's rates, plus
/// the flat per-request fee x requests. Recomputed on every read (reprice-on-read: a rate-card
/// correction changes historical figures on the next read; tokens are the stored truth). Metering
/// rows attribute by the CONFIGURED model name, so the rate lookup goes through the
/// `upstream_model` alias resolution.
fn derive_spend_micros_row(cost: &crate::cost::CostModel, model: &str, b: &UsageBreakdown) -> i64 {
    let tier = busbar_api::TierTokens {
        input: b.tokens_input,
        output: b.tokens_output,
        cache_read: b.tokens_cache_read,
        cache_write: b.tokens_cache_creation, // UsageBreakdown's OWN field name (public admin-API JSON contract, unchanged)
    };
    let resolved = cost.resolve_model_alias(model);
    cost.derive_spend_micros([(resolved, &tier)].into_iter(), b.requests, true)
}

/// Process start instant, for the `info` uptime read. Stamped ONCE at startup by `mark_start()`.
/// A missing value (never stamped — e.g. a unit test that skips `main`) yields a `None` uptime
/// rather than a panic.
static PROCESS_START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
/// Process start EPOCH (unix seconds) — `info.started_at`, the boot-epoch marker consumers use to
/// detect that process-local counters (config_version, breaker trip counts) reset.
static PROCESS_START_EPOCH: std::sync::OnceLock<u64> = std::sync::OnceLock::new();

/// Stamp the process start instant + epoch for the `info` reads. Idempotent (first `set` wins), so
/// it is safe to call unconditionally at startup.
pub fn mark_start() {
    let _ = PROCESS_START.set(std::time::Instant::now());
    let _ = PROCESS_START_EPOCH.set(crate::store::now());
}

/// One cached computation of `store_plugin_catalog`'s tarball-derived rows for one plugins
/// directory (see `catalog_cache`).
struct CatalogCacheEntry {
    /// Fingerprint of the directory's contents (`plugins_dir_fingerprint`) folded together with
    /// the trust config in effect when `rows` was computed. Either changing invalidates the entry.
    key: u64,
    rows: Vec<PluginView>,
    /// Number of times this directory's entry has been (re)computed from a full
    /// `inventory_tarballs` scan — a cache HIT never touches this. Cheap bookkeeping, exercised by
    /// `catalog_repeat_gets_reuse_the_cached_scan` below; harmless outside tests too.
    misses: u64,
    /// Unix-seconds epoch this entry was last (re)computed — the `CATALOG_CACHE_TTL_SECS`
    /// eviction stamp. Not a freshness signal (the fingerprint+trust `key` already detects any
    /// real change); purely bounds how long a stale directory's entry can sit in the map.
    inserted_at: u64,
}

/// How long a `CATALOG_CACHE` entry may sit unpruned: the map has no
/// other eviction and grows once per distinct `plugins_dir` path the process has ever served
/// `GET /plugins?type=store` for — normally one path for the life of the process, but every test in
/// this file uses its own temp directory, and a long-lived process that has rotated through several
/// `plugins.dir` values (config reloads across deploys, multi-tenant test harnesses, etc.) would
/// otherwise accumulate one entry per path forever. Same TTL+`retain()` idiom `admin/mod.rs`'s
/// `IDEMPOTENCY_TTL_SECS`/`idempotency_cache` already establishes for this exact "unbounded map
/// keyed by something caller-influenced" shape — see its `cache.retain(|_, (t, _)| ...)` pruning.
/// Deliberately SHORTER than `IDEMPOTENCY_TTL_SECS` (600s): a pruned catalog entry costs only a
/// re-scan on the next read (no client-visible replay semantics to preserve, unlike an idempotency
/// record), so there is no reason to hold it as long.
const CATALOG_CACHE_TTL_SECS: u64 = 120;

/// Process-wide cache backing `store_plugin_catalog`, keyed by plugins directory path (normally
/// there is exactly one path per running process; tests use many distinct temp directories, hence
/// the map rather than a single slot). See `store_plugin_catalog`'s doc comment for why this cache
/// exists: `inventory_tarballs` fully re-reads and re-unpacks every tarball on every call, and nothing
/// else bounds how often the GET this backs can be called.
static CATALOG_CACHE: OnceLock<Mutex<HashMap<PathBuf, CatalogCacheEntry>>> = OnceLock::new();

fn catalog_cache() -> &'static Mutex<HashMap<PathBuf, CatalogCacheEntry>> {
    CATALOG_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The bound on CONCURRENT catalog re-scans (the single-flight half):
/// `spawn_blocking` alone is not a fix for a hot cache-miss path — this codebase's own established
/// doctrine, per `auth::AUTH_OFFLOAD_PERMITS`'s doc comment and
/// `governance::revocation::RevocationSync`'s `inflight` bound. Unlike those two (which bound
/// concurrent *offloads* of an operation every caller pays for independently), this gate makes N
/// concurrent misses single-flight into exactly ONE real `inventory_tarballs` scan: the caller that
/// wins the gate scans and populates `CATALOG_CACHE`; every caller that queues behind it re-runs
/// `store_plugin_catalog`'s cheap fingerprint+cache check under the gate and finds the entry the
/// winner just wrote, rather than each independently unpacking every tarball. Same single-permit
/// shape as the governance budget flusher's `flush_gate`, for the same reason (serialize an expensive operation
/// callers would otherwise duplicate) — and, like that gate, this also serializes cache HITS behind
/// whichever call currently holds it, trading a little request-path throughput for the simplicity of
/// one lock with no separate fast path. That trade is deliberate: the work under the gate is either
/// a cheap fingerprint compare (hit) or the scan this gate exists to de-duplicate (miss), never
/// anything slower.
static CATALOG_SCAN_GATE: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

/// How long a caller will wait to ACQUIRE [`CATALOG_SCAN_GATE`] before giving up. Mirrors
/// `auth::AUTH_OFFLOAD_PERMITS`'s own `AUTH_OFFLOAD_WAIT` idiom exactly, same
/// value and same reasoning: `GET /plugins?type=store` is deliberately unmetered by the admin rate
/// limiter (see [`Self::store_plugin_catalog_async`]'s doc comment), so an ungated wait here is a
/// PERMANENT-until-restart wedge, not a self-healing one — a stale/hung `plugins_dir` mount (e.g. a
/// wedged NFS read) never returns from `inventory_tarballs`, so the caller that won the gate never
/// releases it, and every subsequent caller would otherwise queue behind it forever. A call that
/// cannot even START the scan within this bound is answered with a clear, retryable error
/// ([`AdminError::Unavailable`]) rather than left to hang — the same fail-fast posture
/// `AUTH_OFFLOAD_WAIT` documents for its own gate. This does NOT fix the underlying hang (the
/// thread that actually won the gate is still parked on the wedged read, same as a wedged auth
/// plugin still burns one blocking-pool thread forever) — it only stops the wedge from cascading
/// into every OTHER caller of this endpoint.
const CATALOG_SCAN_GATE_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// Cheap, order-independent fingerprint of a directory's immediate entries (filename + size +
/// mtime of each, hashed together). NOT a security boundary — only a cache-freshness heuristic for
/// `CATALOG_CACHE` — but adding, removing, or overwriting any file in `dir` changes at least one
/// entry's size or mtime, so install/remove/rollback all invalidate the cache on their own, with no
/// bespoke invalidation hook wired into any of those mutation paths.
///
/// ERROR HANDLING: a MISSING directory is a legitimate, cacheable
/// state — `Ok` with the empty-entries fingerprint — matching `registry::discover`'s own
/// `NotFound` ⇒ `Ok(empty)` treatment (an absent plugins dir is "no plugins", not a failure). Any
/// OTHER I/O error (permission denied, a bad NFS mount, a per-entry `DirEntry`/`metadata()` read
/// failure mid-iteration) is propagated rather than collapsed to the same empty fingerprint: the
/// previous behavior (`unwrap_or_default()` over every failure, including per-entry
/// `.ok()?`/`filter_map` drops) made a directory that was readable-then-unreadable fingerprint
/// IDENTICALLY to an empty one, so a cache entry seeded while the directory was legitimately empty
/// (`[]`, key = empty fingerprint) would keep matching forever and serve that stale `[]` even after
/// the directory became unreadable — instead of the `INVALID: cannot read plugins dir` row
/// `inventory_tarballs`/`registry::discover` would otherwise surface on every call. Fail-closed on
/// per-entry iteration errors too (never silently drop one — same posture as `discover()`'s own
/// `entry.map_err(...)?` propagation), so a single corrupted `DirEntry` can't quietly shrink the
/// fingerprint's view of the directory while the scan below sees the full (correctly failing) set.
fn plugins_dir_fingerprint(dir: &Path) -> std::io::Result<u64> {
    let mut entries: Vec<(std::ffi::OsString, u64, u128)> = Vec::new();
    match std::fs::read_dir(dir) {
        Ok(rd) => {
            for entry in rd {
                let entry = entry?;
                let meta = entry.metadata()?;
                let mtime = meta
                    .modified()?
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0);
                entries.push((entry.file_name(), meta.len(), mtime));
            }
        }
        // A missing directory is NOT a failure — see the doc comment above.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    entries.sort();
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    entries.hash(&mut hasher);
    Ok(hasher.finish())
}

// ── `#[cfg(test)]`-only catalog-scan injection seam ────────────────────────────────────────────────
// `scan_store_plugin_rows` calls `catalog_scan_test_hook!()` once per invocation. In a release build
// (or any test that never arms it) it expands to nothing / is a no-op — the production scan carries
// zero extra indirection. Under test it can inject a DETERMINISTIC artificial delay (so the
// reactor-parking proof does not depend on real gzip/unpack/sig-verify throughput being consistently
// slow across CI hardware) and/or a real panic (exercising `store_plugin_catalog_async`'s
// `spawn_blocking` join-error fallback with genuine unwind, not by exploiting an unrelated defect).
// Global atomics, not a thread-local: the scan runs on a `spawn_blocking` pool thread, a different OS
// thread than the test that arms the hook, so a thread-local (this file's usual `durable.rs`-style
// fault-injection idiom) would not be visible where it is read. Same idiom `durable.rs`'s
// `fault_point!` establishes for zero-cost test-only injection, adapted for the cross-thread case.
#[cfg(test)]
macro_rules! catalog_scan_test_hook {
    ($dir:expr) => {
        catalog_scan_test_hooks::maybe_delay_or_panic($dir)
    };
}
#[cfg(not(test))]
macro_rules! catalog_scan_test_hook {
    ($dir:expr) => {};
}
// No `use` needed here (unlike `durable.rs`'s `fault_point!`): both `macro_rules!` arms above are
// defined BEFORE their one call site in `scan_store_plugin_rows` further down this same file, so
// plain textual macro scoping already resolves the invocation.

#[cfg(test)]
mod catalog_scan_test_hooks {
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::time::Duration;

    /// What to inject, and for WHICH `plugins_dir` — the whole suite's tests run concurrently on
    /// separate OS threads within one process (`cargo test` default), and `spawn_blocking` moves the
    /// scan to yet another thread than the one that armed the hook, so this cannot be a thread-local.
    /// It is instead a single global slot SCOPED to one directory: `maybe_delay_or_panic` only acts
    /// when the scan it is called from is scanning the exact `dir` a test armed, so a concurrently
    /// running, unrelated test's scan (a different `tmp_plugins_dir(...)`) is never affected — only
    /// two tests racing on the SAME directory could collide, and none in this suite share one.
    enum Armed {
        Delay(Duration),
        Panic,
    }
    static SLOT: Mutex<Option<(PathBuf, Armed)>> = Mutex::new(None);

    pub(super) fn maybe_delay_or_panic(dir: &std::path::Path) {
        let armed = SLOT.lock().unwrap();
        let Some((armed_dir, kind)) = armed.as_ref() else {
            return;
        };
        if armed_dir != dir {
            return;
        }
        match kind {
            // `std::thread::sleep` is safe here: always called from a `spawn_blocking` pool thread
            // or a synchronous test, never inline on the reactor.
            Armed::Delay(d) => std::thread::sleep(*d),
            Armed::Panic => {
                drop(armed); // release the lock before unwinding through this frame
                panic!(
                    "catalog_scan_test_hooks: injected panic for {} (spawn_blocking join-error \
                     fallback proof)",
                    dir.display()
                );
            }
        }
    }

    /// RAII guard: clears the armed slot on drop — even on an early return or a panic inside the
    /// scope that armed it — so an armed hook can never leak past the test that set it.
    #[must_use]
    pub(super) struct HookGuard;
    impl Drop for HookGuard {
        fn drop(&mut self) {
            *SLOT.lock().unwrap() = None;
        }
    }

    /// Arm a deterministic minimum scan duration for `dir`, for the life of the returned guard.
    pub(super) fn set_delay(dir: std::path::PathBuf, d: Duration) -> HookGuard {
        *SLOT.lock().unwrap() = Some((dir, Armed::Delay(d)));
        HookGuard
    }

    /// Arm a scan-time panic for `dir`, for the life of the returned guard.
    pub(super) fn set_panic(dir: std::path::PathBuf) -> HookGuard {
        *SLOT.lock().unwrap() = Some((dir, Armed::Panic));
        HookGuard
    }
}

/// The auth modules COMPILED INTO this binary (feature-gated at compile time — real `#[cfg]` on each
/// array element, so this reflects the ACTUAL binary). The single source for both `info`'s build
/// proof and the `plugins?type=auth` catalog. `keys` (the built-in signed-key verifier) is
/// engine-handled and always present; `admin-tokens` (the operator admin credential) is the
/// removable default-on feature.
fn auth_modules_compiled_in() -> Vec<&'static str> {
    [
        crate::config::KEYS_MODULE,
        #[cfg(feature = "auth-admin-tokens")]
        crate::config::ADMIN_TOKENS_MODULE,
    ]
    .to_vec()
}

/// The removable hook plugins COMPILED INTO this binary (feature-gated). Excludes the always-present,
/// non-removable weighted SWRR floor, which is reported separately (as `weighted_floor` / the
/// `weighted` compiled-in entry).
fn hook_plugins_compiled_in() -> Vec<&'static str> {
    [
        #[cfg(feature = "hooks-ranking")]
        "ranking",
    ]
    .to_vec()
}

/// Longest a plugin filename may be — generous headroom over any real tarball name, guarding the
/// filesystem path we build from admin-supplied input.
const MAX_PLUGIN_FILENAME_LEN: usize = 256;

/// Validate an admin-supplied plugin TARBALL filename and return it owned. Fail-closed against path
/// traversal (a filename is the LAST path component only — no `/`, `\`, `..`, or absolute/rooted
/// path can reach outside the plugins directory) and enforce the `.tar.gz`/`.tgz` extension. This
/// is the one gate every plugin write/delete funnels through, so the plugins directory is the hard
/// boundary. The filename is STORAGE ONLY — plugin identity always comes from the signed manifest.
fn validate_plugin_filename(file: &str) -> Result<String, AdminError> {
    if file.is_empty() || file.len() > MAX_PLUGIN_FILENAME_LEN {
        return Err(AdminError::Validation(format!(
            "plugin filename must be 1..={MAX_PLUGIN_FILENAME_LEN} chars"
        )));
    }
    // Reject anything that isn't a bare filename — the component the OS would treat as a directory
    // separator, a parent ref, or a rooted path lets an admin-supplied name escape the plugins dir.
    if file.contains('/') || file.contains('\\') || file.contains("..") {
        return Err(AdminError::Validation(
            "plugin filename must be a bare filename (no path separators or `..`)".into(),
        ));
    }
    // Belt-and-braces: the parsed path must have exactly one normal component equal to `file` (so a
    // platform-specific rooted form, e.g. a Windows drive prefix, can never slip through).
    let path = std::path::Path::new(file);
    let mut comps = path.components();
    match (comps.next(), comps.next()) {
        (Some(std::path::Component::Normal(c)), None) if c == std::ffi::OsStr::new(file) => {}
        _ => {
            return Err(AdminError::Validation(
                "plugin filename must be a single, normal path component".into(),
            ));
        }
    }
    if !busbar_plugin_loader::tarball::is_plugin_tarball(file) {
        return Err(AdminError::Validation(
            "plugin filename must be a `.tar.gz` (or `.tgz`) signed plugin tarball".into(),
        ));
    }
    Ok(file.to_string())
}

/// Best-effort reachability probe for a hook's backing plugin, for the health read. A hook is now an
/// in-process `kind: hook` plugin (the socket/webhook out-of-process transports are retired), so
/// "reachable" means the referenced plugin RESOLVES to a loadable `kind: hook` plugin in the validated
/// registry. Returns `(reachable, detail)`: `Some(true)` when it resolves, `Some(false)` with the
/// reason when it does not.
async fn probe_transport(
    cfg: &HookCfg,
    env: &crate::hooks::HookEnv,
) -> (Option<bool>, Option<String>) {
    match env.registry.resolve(&cfg.plugin) {
        Some(p) if p.manifest.kind == "hook" => (Some(true), None),
        Some(p) => (
            Some(false),
            Some(format!(
                "plugin '{}' resolves to kind '{}', not 'hook'",
                cfg.plugin, p.manifest.kind
            )),
        ),
        None => (
            Some(false),
            Some(match env.registry.unresolved_reason(&cfg.plugin) {
                Some(sk) => format!(
                    "plugin '{}' present but not loaded: {}",
                    cfg.plugin, sk.reason
                ),
                None => format!("plugin '{}' is not installed", cfg.plugin),
            }),
        ),
    }
}

/// Build the next `App` snapshot with `name` registered/updated to `cfg` in the hook registry — the
/// PURE core of `POST /api/v1/admin/hooks` (runtime hook registration). Validates the definition, clones
/// the current snapshot (sharing the live-state `Arc`s), inserts the hook, updates the global-hook
/// wiring, and RE-RESOLVES the rewrite/tap transports so a `global` hook takes effect immediately on
/// swap. Lanes/store/pools/auth are UNTOUCHED, so the store's per-lane breaker state is preserved (no
/// re-index — the safe, store-constraint-free subset of config apply). The caller `AppHandle::swap`s
/// the returned snapshot. Pure + `Result` → unit-testable without the transport.
/// The `settings` map is persisted VERBATIM into the config overlay and re-sent to the hook binary on
/// every reconnect, so an unbounded map bloats the durable overlay and amplifies the reconnect path.
/// These caps are far past any real hook's settings; a compromised `hooks-register` token must not
/// be able to blow them out. Shared by `build_with_hook` (register / PUT) and `patch_hook_settings`
/// (PATCH) so all three write paths enforce ONE limit with no drift.
pub(crate) const MAX_SETTINGS_BYTES: usize = 64 * 1024;
pub(crate) const MAX_SETTINGS_KEYS: usize = 256;
/// Upper bound on a hook name (a registry key persisted to the config overlay + every audit row).
/// Generous headroom over any real hook name; guards the durable-state/audit/reconnect path.
pub(crate) const MAX_HOOK_NAME_LEN: usize = 256;
/// Upper bound on a group name — same rationale as the hook cap (a registry key persisted to the
/// overlay + every audit row). Generous over any real `org/dept/team/user:<sub>` name.
pub(crate) const MAX_GROUP_NAME_LEN: usize = 256;

/// Fail-closed size check for a hook's `settings` map — see the cap rationale above.
pub(crate) fn validate_hook_settings_size(
    settings: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), AdminError> {
    if settings.len() > MAX_SETTINGS_KEYS {
        return Err(AdminError::Validation(format!(
            "settings has too many keys ({}, max {MAX_SETTINGS_KEYS})",
            settings.len()
        )));
    }
    if let Ok(bytes) = serde_json::to_vec(settings) {
        if bytes.len() > MAX_SETTINGS_BYTES {
            return Err(AdminError::Validation(format!(
                "settings too large ({} bytes, max {MAX_SETTINGS_BYTES})",
                bytes.len()
            )));
        }
    }
    Ok(())
}

pub(crate) fn build_with_hook(current: &App, name: &str, cfg: HookCfg) -> Result<App, AdminError> {
    // ── validate the definition (fail-closed, before any mutation) ──
    if name.trim().is_empty() {
        return Err(AdminError::Validation("hook name must not be empty".into()));
    }
    // Cap the name length. The name is a registry key that gets written VERBATIM into the config
    // overlay and every audit row (and echoed on the wire); without a bound a `hooks-register`
    // token could POST a name up to the body-size cap (~MB), bloating the durable overlay / audit /
    // reconnect path — the same defensive posture as the key-id / settings caps.
    if name.len() > MAX_HOOK_NAME_LEN {
        return Err(AdminError::Validation(format!(
            "hook name is {} chars; must be <= {MAX_HOOK_NAME_LEN}",
            name.len()
        )));
    }
    // Reserved names — the SAME rule boot validation enforces (config::RESERVED_HOOK_NAMES): a
    // runtime-registered hook can neither shadow a built-in nor collide with an `on_error` terminal
    // word (which would make the on_error string union ambiguous for every consumer). Previously
    // only the boot/apply path checked this — the register API was the one write path missing it.
    if crate::config::RESERVED_HOOK_NAMES.contains(&name) {
        return Err(AdminError::Validation(format!(
            "hook name `{name}` is reserved (a built-in ranking strategy, auth module, or on_error \
             terminal); pick another name"
        )));
    }
    // The `settings` map rides register/PUT too — cap it here so it is bounded on EVERY write path,
    // not just PATCH.
    validate_hook_settings_size(&cfg.settings)?;
    // A hook must name exactly one `kind: hook` plugin (the retired socket/webhook transports are
    // gone). Emptiness is the structural check here; the plugin's existence/kind is validated against
    // the registry below (register/PUT) and at the plugin pre-flight.
    if cfg.plugin.trim().is_empty() {
        return Err(AdminError::Validation(
            "a hook must name a `kind: hook` plugin via `module:`".into(),
        ));
    }
    // `prompt: rw` is a rewrite grant, meaningless (and unsafe) on a fire-and-forget tap.
    if cfg.kind == HookKind::Tap && cfg.prompt == PromptAccess::Rw {
        return Err(AdminError::Validation(
            "`prompt: rw` is invalid on a `kind: tap` hook (a tap cannot rewrite)".into(),
        ));
    }
    // GRANT IMMUTABILITY: `kind`/`prompt`/`user` are definition-only and FROZEN after first
    // registration. Re-registering a name with different grants is a `conflict` — delete and
    // re-register to change them. This closes the "register `prompt: no`, wire it in, then escalate to
    // `rw`" exfiltration path: a grant can never widen in place. Re-registering with the SAME grants is
    // allowed (an idempotent re-register / settings refresh).
    if let Some(existing) = current.hook_registry.get(name) {
        if existing.kind != cfg.kind || existing.prompt != cfg.prompt || existing.user != cfg.user {
            return Err(AdminError::Conflict(format!(
                "hook `{name}` already exists with different kind/prompt/user grants; grants are \
                 immutable — delete and re-register to change them"
            )));
        }
    }

    // ── build the next snapshot (clone shares live state; only config-derived fields change) ──
    let mut next = current.clone();
    next.config_version = current.config_version.wrapping_add(1);
    let is_global = cfg.global;
    next.hook_registry.insert(name.to_string(), cfg);
    if is_global {
        if !next.global_hooks.iter().any(|n| n == name) {
            next.global_hooks.push(name.to_string());
        }
    } else {
        // A PUT that REPLACES a prior `global: true` hook with `global: false` must DE-WIRE it from
        // the global fan-out — otherwise the stale membership keeps it firing on every request and
        // `hook_view` keeps reporting `global: true`, so the operator's 200 OK silently no-ops the
        // demotion. Mirrors `build_without_hook`'s DELETE cleanup.
        next.global_hooks.retain(|n| n != name);
    }
    // FAIL-CLOSED (open-time variant): before re-resolving, actually OPEN every referenced
    // decision/rewrite gate so a plugin that fails to `open()` ABORTS this register instead of being
    // silently `filter_map`-dropped by the resolvers below (which would return 200 OK while the gate
    // vanished from the routing chain — a fail-open of an admission control on the live reload path).
    // A genuinely-absent plugin stays the legitimate fail-open skip (distinguished inside).
    if let Err(e) = next.hook_env.preopen_gate_hooks(&next.hook_registry) {
        return Err(AdminError::Validation(e));
    }
    // Re-resolve every registry-derived field (transports, plane gates, and the two compute gates)
    // from the new registry so a global hook — and anything it declared — is live after the swap.
    rebuild_hook_derived(&mut next);
    Ok(next)
}

/// Build the next `App` snapshot with `name` REMOVED from the hook registry — the pure core of
/// `DELETE /api/v1/admin/hooks/{name}`. `not_found` if the name is unregistered. Clones the current
/// snapshot (sharing live state), drops the hook from the registry + global wiring, and re-resolves
/// the rewrite/tap transports. Lanes/store untouched (breaker state preserved). Same GLOBAL scope as
/// `build_with_hook`: pool-`hook:` references are resolved into `pool_runtime` at startup and are NOT
/// re-resolved here — that (plus the dangling-ref 409) lands with the broader config/apply.
pub(crate) fn build_without_hook(current: &App, name: &str) -> Result<App, AdminError> {
    if !current.hook_registry.contains_key(name) {
        return Err(AdminError::not_found(format!("hook `{name}`")));
    }
    let mut next = current.clone();
    next.config_version = current.config_version.wrapping_add(1);
    next.hook_registry.remove(name);
    next.global_hooks.retain(|n| n != name);
    rebuild_hook_derived(&mut next);
    Ok(next)
}

/// Build the next `App` snapshot with `name` created-or-replaced in the group registry — the pure
/// core of `POST`/`PUT /api/v1/admin/groups`. VALIDATE-AT-THE-DOOR: the mutated registry is run
/// through the SAME `validate_groups` boot uses (parent references exist, the parent chain is
/// acyclic — any depth, the cycle check is the bound), so a bad group (dangling/cyclic parent) is a `400` that
/// changes nothing. On success the enforcement projection is rebuilt via `CostModel::with_groups`
/// (reusing the rate card + fee unchanged) so the new limits are live after the swap; the governance
/// LEDGER survives (it is Arc-shared, not rebuilt), so past accrual is preserved across the change.
pub(crate) fn build_with_group(
    current: &App,
    name: &str,
    cfg: crate::config::GroupCfg,
) -> Result<App, AdminError> {
    if name.trim().is_empty() {
        return Err(AdminError::Validation(
            "group name must not be empty".into(),
        ));
    }
    if name.len() > MAX_GROUP_NAME_LEN {
        return Err(AdminError::Validation(format!(
            "group name is {} chars; must be <= {MAX_GROUP_NAME_LEN}",
            name.len()
        )));
    }
    // Build the candidate registry and validate it WHOLE before mutating the snapshot — a group's
    // legality (parent exists, chain acyclic) is a property of the tree, not the single entry.
    let mut groups = current.groups_registry.clone();
    groups.insert(name.to_string(), cfg);
    let mut errors = Vec::new();
    crate::config::groups::validate_groups(
        &groups,
        &|p| current.pools.contains_key(p),
        &mut errors,
    );
    if !errors.is_empty() {
        return Err(AdminError::Validation(format!(
            "invalid group `{name}`: {}",
            errors.join("; ")
        )));
    }
    let mut next = current.clone();
    next.config_version = current.config_version.wrapping_add(1);
    next.cost = std::sync::Arc::new(next.cost.with_groups(&groups));
    next.groups_registry = groups;
    Ok(next)
}

/// Build the next `App` snapshot with `name` REMOVED from the group registry — the pure core of
/// `DELETE /api/v1/admin/groups/{name}`. `not_found` if unknown. RE-VALIDATES the reduced tree: if
/// another group still names the removed one as its `parent`, the delete is a `409 conflict` (remove
/// or re-parent the children first) rather than silently orphaning them. On success the enforcement
/// projection is rebuilt (the removed group's buckets disappear); the ledger survives the swap.
/// Count the virtual keys bound to `group` — the BLOCKING half of the group-delete guard, split out
/// of [`build_without_group`] so the pure tree validation carries no store handle at all.
///
/// This is a synchronous `Store::list_keys` round-trip (memory, SQLite plugin, or whatever backend
/// is loaded), so it may take arbitrarily long. It is called ONLY from inside a
/// `Txn::read_store`/`Txn::store_write` closure, i.e. on a `spawn_blocking` thread, never on a Tokio
/// worker. A store failure FAILS CLOSED (`Internal`): a group whose bindings cannot be read is not
/// deletable.
pub(crate) fn count_keys_bound_to(app: &App, group: &str) -> Result<usize, AdminError> {
    let Some(gov) = &app.governance else {
        return Ok(0);
    };
    // NOT a single-key `all_keys().find(id)` lookup (which `GovState::lookup_by_sub`/`Store::get_key`
    // make O(1)): this counts every key bound to a GROUP, and neither `GovState` nor `Store` maintains
    // a by-group index — only `by_hash` (secret) and `by_id` (subject id). A full scan is the only
    // way to answer "how many", so this one stays as-is.
    Ok(gov
        .all_keys()
        .map_err(|e| {
            diag_error!(GROUP_DELETE_KEY_READ_FAILED, group = %group, error = %e, "group delete: cannot read keys to check bindings");
            AdminError::Internal
        })?
        .into_iter()
        .filter(|k| k.group.as_deref() == Some(group))
        .count())
}

pub(crate) fn build_without_group(
    current: &App,
    name: &str,
    bound_keys: usize,
) -> Result<App, AdminError> {
    if !current.groups_registry.contains_key(name) {
        return Err(AdminError::not_found(format!("group `{name}`")));
    }
    // BOUND-KEY GUARD: refuse to delete a group that virtual keys still charge through — an orphaned
    // `key.group` would fail that key CLOSED at every admission (a dangling budget-group reference),
    // and a shared durable store means the binding can outlive this node's config. Reject as a state
    // CONFLICT naming the count (re-bind or delete those keys first) rather than silently orphaning
    // them. Mirrors the dangling-parent guard below.
    //
    // The COUNT is an ARGUMENT, not something this function reads. Counting requires
    // `GovState::all_keys()` — a synchronous, possibly plugin-backed store round-trip — and this
    // builder runs inside the config-mutation critical section. Taking `&GovState` here is what let
    // an earlier version park a Tokio worker under the async lock; with the count passed in there is
    // no store handle in scope to call, so the blocking half MUST be done by the caller's
    // `txn.read_store` closure on `spawn_blocking`. See `count_keys_bound_to`.
    if bound_keys > 0 {
        return Err(AdminError::Conflict(format!(
            "cannot delete group `{name}`: {bound_keys} key(s) are still bound to it; rebind those \
             keys to another group (PATCH /api/v1/admin/keys/{{id}} with `group`) or delete them \
             first"
        )));
    }
    let mut groups = current.groups_registry.clone();
    groups.remove(name);
    // A dangling `parent` after the removal is the only new error a delete can introduce; surface it
    // as a state CONFLICT (something still references this group) so the caller distinguishes it from
    // a malformed request.
    let mut errors = Vec::new();
    crate::config::groups::validate_groups(
        &groups,
        &|p| current.pools.contains_key(p),
        &mut errors,
    );
    if !errors.is_empty() {
        return Err(AdminError::Conflict(format!(
            "cannot delete group `{name}`: {} (re-parent or remove the referencing group first)",
            errors.join("; ")
        )));
    }
    let mut next = current.clone();
    next.config_version = current.config_version.wrapping_add(1);
    next.cost = std::sync::Arc::new(next.cost.with_groups(&groups));
    next.groups_registry = groups;
    Ok(next)
}

/// Build the next `App` snapshot with the whole HOOK SURFACE replaced by a version snapshot — the
/// pure core of `POST /api/v1/admin/config/rollback`. RE-VALIDATES the snapshot against CURRENT reality
/// before any mutation (a snapshot that was valid when recorded may violate an invariant now):
/// per-hook transport XOR + rw-on-tap, at-most-one-default, and no dangling global refs. Clones the
/// current snapshot (sharing live state — lanes/store untouched, breaker state preserved) and
/// re-resolves every global transport. Same restrict-scope as the other builders: pool-resolved
/// hook references are startup-resolved and not re-resolved here.
pub(crate) fn build_with_registry(
    current: &App,
    registry: std::collections::HashMap<String, HookCfg>,
    global_hooks: Vec<String>,
) -> Result<App, AdminError> {
    for (name, cfg) in &registry {
        if cfg.plugin.trim().is_empty() {
            return Err(AdminError::Validation(format!(
                "hook `{name}` must name a `kind: hook` plugin via `module:`"
            )));
        }
        if cfg.kind == HookKind::Tap && cfg.prompt == PromptAccess::Rw {
            return Err(AdminError::Validation(format!(
                "hook `{name}` sets `prompt: rw` on a `kind: tap` (a tap cannot rewrite)"
            )));
        }
    }
    let defaults: Vec<&str> = registry
        .iter()
        .filter(|(_, h)| h.default)
        .map(|(n, _)| n.as_str())
        .collect();
    if defaults.len() > 1 {
        return Err(AdminError::Validation(format!(
            "snapshot has more than one `default: true` hook: {}",
            defaults.join(", ")
        )));
    }
    for g in &global_hooks {
        if !registry.contains_key(g) {
            return Err(AdminError::Validation(format!(
                "snapshot wires unknown global hook `{g}`"
            )));
        }
    }
    let mut next = current.clone();
    next.config_version = current.config_version.wrapping_add(1);
    next.hook_registry = registry;
    next.global_hooks = global_hooks;
    // FAIL-CLOSED (open-time variant): OPEN every referenced decision/rewrite gate before
    // re-resolving so a plugin that fails to `open()` aborts this snapshot install instead of being
    // silently dropped from the routing chain (fail-open). A genuinely-absent plugin stays a skip.
    if let Err(e) = next.hook_env.preopen_gate_hooks(&next.hook_registry) {
        return Err(AdminError::Validation(e));
    }
    rebuild_hook_derived(&mut next);
    Ok(next)
}

/// Byte-size cap on a manifest's embedded `settings_schema` document, checked in
/// [`schema_json_within_bounds`] BEFORE the text is parsed. Well under `unpack`'s own 1 MiB
/// `MAX_MANIFEST_BYTES` (the whole `manifest.json`, of which the schema is one string field) — a
/// real settings schema is a few KiB.
const MAX_INSPECT_SCHEMA_JSON_BYTES: usize = 256 * 1024;

/// Nesting-depth cap for the same document. Generous for any real config schema (which is rarely
/// more than 4-5 levels deep even with `$defs`/`allOf`), tight enough to make a stack-depth attack
/// via a tiny, highly-repetitive document (`[[[[...]]]]`) structurally impossible regardless of how
/// small its byte count is — a byte-size cap ALONE does not bound nesting depth.
const MAX_INSPECT_SCHEMA_JSON_DEPTH: u32 = 64;

/// `POST /plugins/inspect`'s depth/size guard for an attacker-controlled JSON document, run
/// BEFORE the text is ever handed to `serde_json::from_str`.
/// A pathological schema document is a DISTINCT attack from a pathological tarball: even a small
/// byte count can encode unbounded nesting, which the tarball-level caps do not catch. Scans the
/// raw text tracking `{`/`[` nesting depth, correctly skipping the contents of JSON string literals
/// (including escaped quotes) so a string VALUE containing brackets never inflates the count — and
/// never allocates a parsed value itself, so a document that fails this check costs O(length) to
/// reject, not the cost of the recursive-descent parse it is meant to prevent.
fn schema_json_within_bounds(text: &str) -> Result<(), String> {
    if text.len() > MAX_INSPECT_SCHEMA_JSON_BYTES {
        return Err(format!(
            "manifest settings_schema is {} bytes, exceeding the {}-byte cap",
            text.len(),
            MAX_INSPECT_SCHEMA_JSON_BYTES
        ));
    }
    let mut depth: u32 = 0;
    let mut in_string = false;
    let mut escape = false;
    for b in text.bytes() {
        if in_string {
            if escape {
                escape = false;
            } else if b == b'\\' {
                escape = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > MAX_INSPECT_SCHEMA_JSON_DEPTH {
                    return Err(format!(
                        "manifest settings_schema nests deeper than the {MAX_INSPECT_SCHEMA_JSON_DEPTH}-level cap"
                    ));
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    Ok(())
}

/// `schema_url`/`schema_error` for one `GET /plugins` list row: `schema_url` is
/// non-null whenever the manifest declared a `settings_schema` field AT ALL — even if it fails to
/// parse, in which case `schema_error` explains why and `schema_url` still points at `GET
/// /plugins/{name}/schema`, which surfaces the SAME `schema_error` when followed (a
/// present-but-corrupt schema is a worse, distinct condition from "no schema declared", never
/// folded into the same `schema_url: null` a genuinely schema-less plugin gets). Always the
/// ADMIN-PREFIXED relative path — never an absolute URL, never a catalog URL for an unverified
/// remote-catalog artifact (this function is only ever called for a LOCAL manifest already read off
/// disk, so that distinction does not arise here).
fn manifest_schema_url_and_error(
    name: &str,
    settings_schema: Option<&str>,
) -> (Option<String>, Option<String>) {
    let Some(s) = settings_schema else {
        return (None, None);
    };
    let url = Some(format!(
        "{}/plugins/{name}/schema",
        crate::admin::v1::contract::ADMIN_PREFIX
    ));
    match serde_json::from_str::<serde_json::Value>(s) {
        Ok(_) => (url, None),
        Err(e) => (
            url,
            Some(format!("manifest settings_schema is not valid JSON: {e}")),
        ),
    }
}

/// The admin application core. Cheap to construct and clone-free to share (`Arc<App>` inside); a
/// transport builds ONE and hands `Arc<AdminService>` to its routes.
pub(crate) struct AdminService {
    app: Arc<App>,
}

impl AdminService {
    pub(crate) fn new(app: Arc<App>) -> Self {
        Self { app }
    }

    /// `GET /api/v1/admin/info` — version, the COMPILED-IN plugin sets (compliance-by-compilation proof),
    /// uptime, and pool/model/provider topology. Read scope. Infallible today, but returns `Result`
    /// for a uniform transport contract (every op is `Result<View, AdminError>`).
    pub(crate) async fn info(&self) -> Result<InfoView, AdminError> {
        // The compiled-in plugin sets reflect the ACTUAL binary (feature-gated): the `keys` /
        // `admin-tokens` auth builtins plus the ranking hooks. `weighted` is the one baked in
        // (non-removable), so it appears as `weighted_floor` below, not in `hook_plugins`.
        let auth_modules = auth_modules_compiled_in();
        let hook_plugins = hook_plugins_compiled_in();

        let providers: std::collections::BTreeSet<&str> = self
            .app
            .engine_tables()
            .lanes()
            .iter()
            .map(|l| l.provider.as_str())
            .collect();

        Ok(InfoView {
            version: env!("CARGO_PKG_VERSION"),
            build: BuildInfo {
                auth_modules,
                hook_plugins,
                weighted_floor: true,
            },
            uptime_seconds: PROCESS_START.get().map(|s| s.elapsed().as_secs()),
            started_at: PROCESS_START_EPOCH.get().copied(),
            topology: TopologyInfo {
                pools: self.app.engine_tables().pools().len(),
                models: self.app.engine_tables().by_model().len(),
                providers: providers.len(),
            },
            config_persistence: self.app.overlay_path.is_some(),
            config_version: self.app.config_version,
        })
    }

    /// `GET /api/v1/admin/pools` — the pool topology (name + member models/weights). Read scope. Sorted
    /// by name for a stable, diff-friendly listing. Live per-member
    /// status is an additive follow-up.
    pub(crate) async fn list_pools(&self) -> Result<Page<PoolView>, AdminError> {
        let mut pools: Vec<PoolView> = self
            .app
            .engine_tables()
            .pools()
            .iter()
            .map(|(name, members)| PoolView {
                name: name.clone(),
                members: members
                    .iter()
                    .map(|m| PoolMemberView {
                        // `idx` is the stable lane handle; project the lane's model name.
                        model: self.app.engine_tables().lanes()[m.idx].model.clone(),
                        weight: m.weight,
                    })
                    .collect(),
            })
            .collect();
        pools.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(Page::single(pools))
    }

    /// `GET /api/v1/admin/pools/{name}` — the LIVE per-member status of one pool (breaker/concurrency/
    /// latency/tallies), from the same store signals the routing seam ranks on. Read scope.
    /// `not_found` if the pool is unknown.
    pub(crate) async fn get_pool(&self, name: &str) -> Result<PoolDetailView, AdminError> {
        let members = self
            .app
            .engine_tables()
            .pools()
            .get(name)
            .ok_or_else(|| AdminError::not_found(format!("pool `{name}`")))?;
        Ok(self.pool_detail(name, members))
    }

    /// Project one pool's LIVE member status — the shared core of `GET /pools/{name}` and
    /// `GET /pools?detail=true` (one projection, two readers — the shapes can never diverge).
    fn pool_detail(&self, name: &str, members: &[crate::state::WeightedLane]) -> PoolDetailView {
        let now = crate::store::now();
        let members = members
            .iter()
            .map(|m| {
                // `snapshot` is the same release-exposed live summary `/stats` reads (ok/err/trips/
                // dead/inflight — genuinely lane-GLOBAL counters); `available_permits` +
                // `lane_latency_ms` round it out. `usable`/`cooldown_remaining_seconds` are NOT lane
                // counters, though — routing ranks a member per-POOL (`select_weighted_in`), so this
                // endpoint reports the per-pool breaker cell via `ready_in`/`cooldown_remaining_in`,
                // NOT `snapshot`'s any-cell/max-cell lane aggregates (which would mislabel a member
                // as usable in a pool where its OWN cell is tripped, or vice versa).
                let snap = self.app.store.snapshot(m.idx, now);
                PoolMemberStatusView {
                    model: self.app.engine_tables().lanes()[m.idx].model.clone(),
                    weight: m.weight,
                    // `ready_in`, NOT `usable_in`: `usable_in` delegates to the MUTATING `usable_for`,
                    // which can transition an expired-Open cell to HalfOpen and CAS-steal the
                    // single-flight recovery probe. `ready_in` is `select_weighted_in`'s own
                    // side-effect-free predicate — exactly what this read-only endpoint must report.
                    usable: self.app.store.ready_in(name, m.idx, now),
                    cooldown_remaining_seconds: self
                        .app
                        .store
                        .cooldown_remaining_in(name, m.idx, now),
                    available_concurrency: self.app.store.available_permits(m.idx),
                    inflight: snap.inflight,
                    latency_ms: self.app.store.lane_latency_ms(m.idx),
                    ok: snap.ok,
                    err: snap.err,
                    dead: snap.dead,
                    trip_count: snap.trips,
                    last_trip_at: (snap.last_trip_at > 0).then_some(snap.last_trip_at),
                }
            })
            .collect();
        PoolDetailView {
            name: name.to_string(),
            members,
        }
    }

    /// `GET /api/v1/admin/pools?detail=true` — the WHOLE topology with live member status in ONE
    /// call (the summary + per-pool detail split forced an M+1 fan-out per dashboard refresh).
    /// Same row shape as `GET /pools/{name}` via the shared projection. Sorted by name.
    pub(crate) async fn list_pools_detailed(&self) -> Result<Page<PoolDetailView>, AdminError> {
        let mut pools: Vec<PoolDetailView> = self
            .app
            .pools
            .iter()
            .map(|(name, members)| self.pool_detail(name, members))
            .collect();
        pools.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(Page::single(pools))
    }

    /// `GET /api/v1/admin/models` — every model lane + its upstream provider. Read scope. Sorted by
    /// model name. No credentials.
    pub(crate) async fn list_models(&self) -> Result<Page<ModelView>, AdminError> {
        let mut models: Vec<ModelView> = self
            .app
            .lanes
            .iter()
            .map(|l| ModelView {
                model: l.model.clone(),
                provider: l.provider.clone(),
            })
            .collect();
        models.sort_by(|a, b| a.model.cmp(&b.model));
        Ok(Page::single(models))
    }

    /// `GET /api/v1/admin/providers` — distinct upstream providers + the count of model lanes routing
    /// through each. Read scope. Sorted by provider name.
    pub(crate) async fn list_providers(&self) -> Result<Page<ProviderView>, AdminError> {
        let mut counts: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
        for lane in self.app.engine_tables().lanes() {
            *counts.entry(lane.provider.as_str()).or_insert(0) += 1;
        }
        let providers = counts
            .into_iter()
            .map(|(provider, model_count)| ProviderView {
                provider: provider.to_string(),
                model_count,
            })
            .collect();
        Ok(Page::single(providers))
    }

    /// `GET /api/v1/admin/hooks` — the hook registry read. Read scope. Each entry
    /// is the DEFINITION (kind/transport/grants/ordering/stage), never a secret. Sorted by name.
    pub(crate) async fn list_hooks(&self) -> Result<Page<HookView>, AdminError> {
        let mut hooks: Vec<HookView> = self
            .app
            .hook_registry
            .iter()
            .map(|(name, cfg)| self.hook_view(name, cfg))
            .collect();
        hooks.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(Page::single(hooks))
    }

    /// `GET /api/v1/admin/hooks/{name}` — one hook definition, or `not_found` if the name is unregistered.
    pub(crate) async fn get_hook(&self, name: &str) -> Result<HookView, AdminError> {
        self.app
            .hook_registry
            .get(name)
            .map(|cfg| self.hook_view(name, cfg))
            .ok_or_else(|| AdminError::not_found(format!("hook `{name}`")))
    }

    /// `GET /api/v1/admin/<section>` — the GENERIC named-DEFINITION map read (`identity-providers`,
    /// `export`; `tools`/`agents` later). ONE method for every section, parameterized by
    /// [`NamedMapSection`] — the read half of the same "define once, reference by name" grammar the
    /// config file speaks. Definitions only; never a secret (see [`NamedDefView`]). Sorted by name so
    /// the read is stable regardless of the map's insertion order.
    pub(crate) async fn list_named_defs(
        &self,
        section: NamedMapSection,
    ) -> Result<Page<NamedDefView>, AdminError> {
        let mut defs: Vec<NamedDefView> = match section {
            NamedMapSection::IdentityProviders => self
                .app
                .identity_providers
                .iter()
                .map(|(name, cfg)| identity_provider_view(name, cfg))
                .collect(),
            NamedMapSection::Export => self
                .app
                .export_defs
                .iter()
                .map(|(name, cfg)| export_def_view(name, cfg))
                .collect(),
            // Both plane sections read their registrations through the plane's `named_def_list` seam,
            // so this arm names no `busbar_mcp::mcp`/`busbar_a2a::a2a` view or registry type; the empty vec for
            // a plane compiled out is the seam's own `None`.
            NamedMapSection::Tools | NamedMapSection::Agents => {
                plane_named_def_list(section, &self.app)
            }
        };
        // Plus every overlay entry this binary could not parse, explicitly FLAGGED. They are stored
        // but NOT live (dropped at each rebuild), and listing them here is what makes that
        // discoverable to an operator inspecting state rather than boot logs. A name that is live
        // wins — the registry only ever holds names the applier actually dropped.
        for (name, entry) in crate::config::overlay::unparseable_named_map_entries(
            self.app.overlay_path.as_deref(),
            section,
        ) {
            if !defs.iter().any(|d| d.name == name) {
                defs.push(unparseable_def_view(&name, &entry));
            }
        }
        defs.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(Page::single(defs))
    }

    /// `GET /api/v1/admin/<section>/{name}` — ONE named definition, or `not_found`. The single-entry
    /// twin of [`AdminService::list_named_defs`].
    pub(crate) async fn get_named_def(
        &self,
        section: NamedMapSection,
        name: &str,
    ) -> Result<NamedDefView, AdminError> {
        let view = match section {
            NamedMapSection::IdentityProviders => self
                .app
                .identity_providers
                .get(name)
                .map(|cfg| identity_provider_view(name, cfg)),
            NamedMapSection::Export => self
                .app
                .export_defs
                .get(name)
                .map(|cfg| export_def_view(name, cfg)),
            // Both plane sections read their one registration through the plane's `named_def_get`
            // seam; `None` for a plane compiled out is the seam's own `None`.
            NamedMapSection::Tools | NamedMapSection::Agents => {
                plane_named_def_get(section, &self.app, name)
            }
        };
        view.or_else(|| {
            // A stored-but-unparseable overlay entry answers the FLAGGED view rather than a 404: a
            // 404 for a name that is sitting in the operator's own overlay is precisely the silent
            // drop this surfaces.
            crate::config::overlay::unparseable_named_map_entries(
                self.app.overlay_path.as_deref(),
                section,
            )
            .get(name)
            .map(|entry| unparseable_def_view(name, entry))
        })
        .ok_or_else(|| AdminError::not_found(format!("{} `{name}`", section.singular())))
    }

    /// `GET /api/v1/admin/groups` — the `groups:` limit tree read. Read scope. Each entry is the
    /// DEFINITION (parent, enabled, limits, `child_default`), never a secret. Sorted by name (the
    /// registry is already a BTreeMap, so iteration is name-ordered).
    ///
    /// Cursor-paginated by the SAME `{items, next_cursor}` envelope every other growable admin
    /// collection uses (keys/audit/config-versions): unlike `/pools`/`/models`/`/hooks` (bounded by
    /// static config, still a `Page::single`), the group tree GROWS at runtime — `plan_mint_group`
    /// auto-provisions a leaf per self-service key mint — so it needs the same bound every other
    /// growable list has. `start`/`limit` are the caller's already-decoded cursor offset and clamped
    /// page size (see the JSON handler, which owns cursor parsing).
    pub(crate) async fn list_groups(
        &self,
        start: usize,
        limit: usize,
    ) -> Result<Page<GroupView>, AdminError> {
        let all: Vec<GroupView> = self
            .app
            .groups_registry
            .iter()
            .map(|(name, cfg)| GroupView::from_cfg(name, cfg))
            .collect();
        let total = all.len();
        let items: Vec<GroupView> = all.into_iter().skip(start).take(limit).collect();
        let end = start.saturating_add(items.len());
        let next_cursor =
            (end < total).then(|| crate::admin::v1::contract::encode_offset_cursor(end));
        Ok(Page { items, next_cursor })
    }

    /// `GET /api/v1/admin/groups/{name}` — one group definition, or `not_found` if the name is unknown.
    pub(crate) async fn get_group(&self, name: &str) -> Result<GroupView, AdminError> {
        self.app
            .groups_registry
            .get(name)
            .map(|cfg| GroupView::from_cfg(name, cfg))
            .ok_or_else(|| AdminError::not_found(format!("group `{name}`")))
    }

    /// `GET /api/v1/admin/groups/{name}/usage` — the group's derived current-window usage per
    /// enforcement bucket vs its caps. Read scope.
    /// `not_found` for an unknown group; governance off = every bucket reads zero (the caps are
    /// still projected — the definition exists even when nothing enforces).
    pub(crate) async fn get_group_usage(
        &self,
        name: &str,
    ) -> Result<crate::admin::v1::contract::GroupUsageView, AdminError> {
        use crate::admin::v1::contract::{GroupBucketUsageView, GroupUsageView};
        let Some(rt) = self.app.cost.group_named(name) else {
            return Err(AdminError::not_found(format!("group `{name}`")));
        };
        let now = crate::store::now();
        let mut buckets = Vec::with_capacity(rt.buckets.len());
        for b in &rt.buckets {
            let usage = match &self.app.governance {
                Some(gov) => gov
                    // Include the flat per-request fee (`true`) — the group `/usage` read must
                    // match ENFORCEMENT (`try_admit` counts the fee for EVERY chain bucket, groups
                    // included). Passing `false` here understated spend and overstated remaining
                    // budget, so operators saw more headroom than the enforcer actually allows.
                    .derived_bucket_usage(&self.app.cost, &b.bucket_id, b.window, true, now)
                    .map_err(|e| {
                        crate::diagnostics::diag_error!(
                            crate::diagnostics::GROUP_USAGE_READ_FAILED,
                            group = name, bucket = %b.bucket_id, err = %e,
                            "group usage read failed"
                        );
                        AdminError::Internal
                    })?,
                None => Default::default(),
            };
            buckets.push(GroupBucketUsageView {
                window: b.window,
                pool: b.scope.as_ref().map(|s| s.value.clone()),
                requests: usage.requests,
                tokens: usage.tokens,
                spend_cents: usage.spend_cents,
                requests_cap: b.requests_cap,
                tokens_cap: b.tokens_cap,
                tokens_input_cap: b.tokens_input_cap,
                tokens_output_cap: b.tokens_output_cap,
                tokens_cache_read_cap: b.tokens_cache_read_cap,
                tokens_cache_write_cap: b.tokens_cache_write_cap,
                budget_cap: b.budget_cap,
                budget_remaining_cents: b
                    .budget_cap
                    .map(|cap| cap.saturating_sub(usage.spend_cents).max(0)),
            });
        }
        Ok(GroupUsageView {
            group: name.to_string(),
            enabled: rt.enabled,
            buckets,
            as_of: now,
        })
    }

    /// `GET /api/v1/admin/plugins?type=auth|hooks|store|secret` — the plugin catalog for one TYPE.
    /// Read scope. Lists COMPILED-IN plugins (feature-gated, from the binary — the same source as
    /// `info`'s build proof), EXTERNAL plugins (registered over socket/webhook), and DYNAMIC-LIBRARY
    /// plugins from `plugins.dir` (`store`/`secret`, and `auth` rows installed on disk, so every
    /// kind has a real, manifest-backed row to carry `trust`/`schema_url`/`schema_error` on). An
    /// unknown/absent `type` is an `invalid_request` (there is no unified cross-kind list; a caller
    /// must pick one — busbar-ui makes up to FOUR separate `GET /plugins?type=X`
    /// calls to build a full picture).
    pub(crate) async fn list_plugins(&self, ptype: &str) -> Result<Page<PluginView>, AdminError> {
        let mut plugins: Vec<PluginView> = Vec::new();
        match ptype {
            "auth" => {
                // Compiled-in auth modules (feature-gated). Active = wired into its chain: `keys`
                // is engine-handled (a flag, not a boxed module), `admin-tokens` lives on the
                // ADMIN chain, and anything else is a boxed data-plane chain module.
                let chain = self.app.auth.chain_names();
                for name in auth_modules_compiled_in() {
                    let active = if name == crate::config::KEYS_MODULE {
                        self.app.auth.keys_in_chain
                    } else if name == crate::config::ADMIN_TOKENS_MODULE {
                        self.app.admin_chain.iter().any(|m| m == name)
                    } else {
                        chain.contains(&name)
                    };
                    plugins.push(PluginView::basic(
                        name.to_string(),
                        "auth",
                        "compiled-in",
                        Some(active),
                        None,
                    ));
                }
                // DYNAMIC auth modules: a `kind: auth` plugin loaded over the signed hybrid ABI and
                // boxed into the data-plane chain. Its runtime name (`module.name()`, what
                // `role_bindings.<module>` keys off) appears in `chain_names()` but is NOT
                // compiled-in — report each such module as a loaded plugin, always `active` (it is
                // in the chain by construction).
                let compiled = auth_modules_compiled_in();
                for name in &chain {
                    if !compiled.contains(name) {
                        plugins.push(PluginView::basic(
                            name.to_string(),
                            "auth",
                            "plugin",
                            Some(true),
                            None,
                        ));
                    }
                }
                // External auth modules (runtime-registered over socket/webhook) — none until the
                // auth-module registration endpoint lands; the catalog shape is ready.

                // DYNAMIC-LIBRARY `kind: auth` plugins installed in `plugins.dir`: they get the
                // same manifest-backed view `store` rows already get —
                // version/publisher/interface_version/trust/schema_url/schema_error —
                // rather than leaving every dynamic auth plugin as a bare name+active `basic` row).
                // This is the SAME directory scan `type=store`/`type=secret` already run (cached,
                // kind-agnostic), filtered down to `kind: auth` rows here. NOTE: an entry here is
                // "installed on disk", not necessarily "currently wired into the live chain" — the
                // `active: true` "plugin" rows above (from `chain_names()`) are the currently-active
                // signal; correlating the two by manifest name is a real follow-on, not solved here.
                let mut dynamic_auth: Vec<PluginView> = self
                    .store_plugin_catalog_async()
                    .await?
                    .into_iter()
                    .filter(|p| p.r#type == "auth")
                    .collect();
                plugins.append(&mut dynamic_auth);
            }
            "hooks" => {
                // The weighted SWRR floor is compiled in unconditionally (the non-removable default
                // hook); activation is the per-pool default, not summarized here.
                plugins.push(PluginView::basic(
                    "weighted".to_string(),
                    "hooks",
                    "compiled-in",
                    None,
                    None,
                ));
                for name in hook_plugins_compiled_in() {
                    plugins.push(PluginView::basic(
                        name.to_string(),
                        "hooks",
                        "compiled-in",
                        None,
                        None,
                    ));
                }
                // External hooks = the configured registry entries (socket/webhook). Configured ⇒
                // active; the transport target is projected (operator config, not a secret).
                let mut externals: Vec<PluginView> = self
                    .app
                    .hook_registry
                    .iter()
                    .map(|(name, cfg)| {
                        let target = Some(cfg.plugin.clone());
                        PluginView::basic(name.clone(), "hooks", "external", Some(true), target)
                    })
                    .collect();
                externals.sort_by(|a, b| a.name.cmp(&b.name));
                plugins.append(&mut externals);
            }
            // `store` (alias `db`) — DYNAMIC-LIBRARY plugins in the plugins directory. Always includes
            // the compiled-in `memory` default; then every loadable library present, each vetted (ABI
            // handshake) and its signed sidecar manifest read + re-evaluated against the running trust
            // posture. The store the operator configured (`store.module`) is `active`.
            //
            // The underlying scan reads every kind in the shared `plugins.dir` in one pass (cached,
            // kind-agnostic); each row is tagged with its OWN manifest kind (`scan_store_plugin_rows`),
            // so filtering to `r#type == "store"` here is what makes `type=store` show only store
            // plugins — a `secret`/`auth` kind tarball dropped in the same directory no longer leaks
            // into this listing (it did before `type=secret`/richer `type=auth` rows existed, since
            // nothing filtered the scan's mixed-kind output by the requested type).
            "store" | "db" => {
                plugins.extend(
                    self.store_plugin_catalog_async()
                        .await?
                        .into_iter()
                        .filter(|p| p.r#type == "store"),
                );
            }
            // DYNAMIC-LIBRARY `kind: secret` plugins: previously the ONLY accepted `type` values
            // were `auth`, `hooks`, `store`, despite secret plugins being in scope throughout this
            // design. Same directory scan as `store`/`auth`, filtered to `kind: secret`. No
            // compiled-in default (unlike `store`'s `memory`) — there is no built-in secret module
            // that needs a catalog row; `env`/`file` are handled inline by the engine, not as plugins.
            "secret" => {
                plugins.extend(
                    self.store_plugin_catalog_async()
                        .await?
                        .into_iter()
                        .filter(|p| p.r#type == "secret"),
                );
            }
            other => {
                return Err(AdminError::Validation(format!(
                    "unknown plugin type `{other}`: expected `auth`, `hooks`, `secret`, or `store`"
                )));
            }
        }
        Ok(Page::single(plugins))
    }

    /// The DYNAMIC plugin catalog (`GET /api/v1/admin/plugins?type=store`): the compiled-in
    /// `memory` default plus every signed plugin tarball in `plugins.dir`, each with its manifest
    /// metadata and a re-evaluated trust verdict. Sorted by filename after the `memory` head.
    ///
    /// MANIFEST-ONLY INSPECTION (security): this endpoint NEVER `dlopen`s ANY plugin. Each tarball
    /// is unpacked in memory, structurally validated, and trust-evaluated against the RUNNING
    /// policy — pure data checks; no plugin code can run from listing the catalog. Pushing/listing
    /// a plugin over the admin API therefore cannot bypass the trust model: loading only ever
    /// happens through the boot pipeline, which re-runs the same three-phase validation.
    ///
    /// CACHED (see `catalog_cache`): `inventory_tarballs` fully re-reads and re-unpacks (gunzip +
    /// untar + structural + trust) EVERY tarball on EVERY call — fine for a one-off boot scan, but
    /// this backs an authenticated GET a caller can hit as often as it likes (reads are
    /// deliberately unmetered by the admin rate limiter — see `admin/rate.rs`'s
    /// `CONFIG_CLASS_RULES` and the mutation-only gate in `auth::classify_for_rate_limit`). A
    /// legitimate admin polling this endpoint, or a misbehaving admin-token holder, would otherwise
    /// pay a full directory re-scan per request with nothing bounding the rate. The cache is keyed
    /// off a cheap directory fingerprint (name+size+mtime per entry, no read/decompress) plus the
    /// trust config, so any real change — install, remove, rollback, or a `plugins:` config edit —
    /// invalidates it on the very next call with no bespoke invalidation hook wired into any of
    /// those mutation paths.
    ///
    /// SYNCHRONOUS, BLOCKING FILESYSTEM I/O — both the fingerprint read(s) and, on a cache miss, the
    /// full tarball scan. Safe to call directly only from a context that is already off the Tokio
    /// reactor: `reload_store_plugins` (always invoked inside a `txn.read_store` closure, which
    /// `config_transaction`'s `apply()` runs via `spawn_blocking`), tests, and `--validate`/boot
    /// paths. The `GET /plugins?type=store` request path goes through
    /// [`Self::store_plugin_catalog_async`] instead — never this method directly.
    ///
    /// RACE: the fingerprint read and the scan are two independent,
    /// non-atomic directory reads, so a concurrent install/remove between them could let a scan and
    /// its "before" fingerprint observe different directory states. To narrow that window this
    /// re-fingerprints the directory AFTER the scan and only memoizes when the two fingerprints
    /// still match — but this is a NARROWING, not a CLOSING, of the race: an ABA sequence (the
    /// directory changes and then changes back to the same fingerprint mid-scan — plausible on
    /// filesystems with coarse mtime granularity) could still memoize a torn read. Self-healing
    /// either way: the cache is a pure performance layer over a deterministic scan, so the worst
    /// case is one extra rescan on the next call, never a wrong answer served indefinitely (the
    /// fingerprint fix below is what actually prevents a wrong answer being served indefinitely).
    fn store_plugin_catalog(&self) -> Vec<PluginView> {
        // The compiled-in RAM default is always present. Which store backend is ACTIVE is a
        // `store.module` config concern (read via `GET /config`), not summarized per-row here,
        // the same posture the compiled-in hook rows take (`active: None`).
        let mut out = vec![PluginView::basic(
            "memory".to_string(),
            "store",
            "compiled-in",
            None,
            None,
        )];
        let Ok(policy) = self.app.plugins_cfg.to_policy() else {
            return out;
        };

        let now = crate::store::now();
        // Bound the cache with the same TTL+`retain()` idiom
        // `admin/mod.rs`'s `idempotency_cache` uses: prune before every read, not just on write, so
        // an abandoned path's entry cannot sit forever just because nothing keeps writing to it.
        // CLOCK SKEW: `saturating_sub` alone avoids an underflow PANIC if `inserted_at`
        // is somehow in the future (a backward system-clock jump), but silently floors the computed
        // age at 0 — which means the entry looks brand-new and never ages out, quietly defeating the
        // TTL bound for exactly that entry until real time catches back up to `inserted_at`. Treating
        // `inserted_at > now` as ALSO immediately-stale (rather than ageless) closes that: a clock
        // that jumped backward means this entry's true age is UNKNOWN, and unknown age is treated the
        // same as "old" — the safe default for a cache, same posture the fingerprint-freshness check
        // above takes toward any signal it cannot trust.
        catalog_cache().lock().unwrap().retain(|_, e| {
            e.inserted_at <= now && now.saturating_sub(e.inserted_at) < CATALOG_CACHE_TTL_SECS
        });

        // A real I/O error (NOT a missing directory — see the doc
        // comment on `plugins_dir_fingerprint`) means the fingerprint cannot be trusted as a
        // freshness signal at all. Skip the cache entirely (no read, no write) and fall through to
        // the real scan, whose own `discover()` call fails the same way and surfaces the
        // `INVALID: cannot read plugins dir` row — on EVERY call, honestly, until the directory
        // becomes readable again, rather than silently serving whatever was cached before.
        // Warn-once transition latch: this read runs on every catalog GET, so an unlatched warn
        // would spam while the dir stays unreadable. Warn on entry into the failing state; hold
        // subsequent failing reads at debug; clear on the next clean fingerprint so a future outage
        // re-warns.
        static FINGERPRINT_WARNED: std::sync::atomic::AtomicBool =
            std::sync::atomic::AtomicBool::new(false);
        let before = match plugins_dir_fingerprint(&self.app.plugins_dir) {
            Ok(fp) => {
                FINGERPRINT_WARNED.store(false, std::sync::atomic::Ordering::Relaxed);
                Some(fp)
            }
            Err(e) => {
                if !FINGERPRINT_WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                    diag_warn!(
                        PLUGINS_DIR_FINGERPRINT_FAILED,
                        dir = %self.app.plugins_dir.display(),
                        error = %e,
                        "cannot fingerprint plugins dir; bypassing the catalog cache for this read"
                    );
                } else {
                    diag_debug!(
                        PLUGINS_DIR_FINGERPRINT_FAILED,
                        dir = %self.app.plugins_dir.display(),
                        error = %e,
                        "cannot fingerprint plugins dir; still bypassing the catalog cache for this \
                         read (dir not yet readable)"
                    );
                }
                None
            }
        };

        if let Some(before) = before {
            // Cache key: a cheap directory-content fingerprint PLUS the config that governs how
            // each tarball is trust-evaluated. `inventory_tarballs` is a deterministic function of
            // exactly those two things, so a match here is an EXACT cache hit, not a heuristic
            // staleness window — nothing observable differs from re-running the scan.
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            before.hash(&mut hasher);
            format!("{:?}", self.app.plugins_cfg).hash(&mut hasher);
            let key = hasher.finish();

            if let Some(entry) = catalog_cache().lock().unwrap().get(&self.app.plugins_dir) {
                if entry.key == key {
                    out.extend(entry.rows.iter().cloned());
                    return out;
                }
            }

            let rows = Self::scan_store_plugin_rows(&self.app.plugins_dir, &policy);

            // "After" fingerprint: only memoize if the directory still looks like it did before the
            // scan started (see the race caveat in the doc comment above — this narrows, it does
            // not close, the window). A mismatch, or the directory becoming unreadable mid-scan,
            // just means this call doesn't memoize; the data returned below is still the real scan
            // result, correct for THIS call either way.
            if matches!(plugins_dir_fingerprint(&self.app.plugins_dir), Ok(after) if after == before)
            {
                let mut cache = catalog_cache().lock().unwrap();
                let misses = cache
                    .get(&self.app.plugins_dir)
                    .map(|e| e.misses)
                    .unwrap_or(0)
                    + 1;
                cache.insert(
                    self.app.plugins_dir.clone(),
                    CatalogCacheEntry {
                        key,
                        rows: rows.clone(),
                        misses,
                        inserted_at: now,
                    },
                );
            }

            out.extend(rows);
            out
        } else {
            out.extend(Self::scan_store_plugin_rows(&self.app.plugins_dir, &policy));
            out
        }
    }

    /// The pure scan half of [`Self::store_plugin_catalog`]: run `inventory_tarballs` and project
    /// each row to a [`PluginView`]. No cache read, no cache write — split out so both the
    /// cache-miss path above and (indirectly, via the whole-method `spawn_blocking`)
    /// [`Self::store_plugin_catalog_async`] share exactly one implementation of "what a scan is."
    fn scan_store_plugin_rows(
        dir: &Path,
        policy: &busbar_plugin_sign::TrustPolicy,
    ) -> Vec<PluginView> {
        // TEST-ONLY injection point: expands to nothing outside
        // `#[cfg(test)]`, so the release path carries zero indirection. See
        // `catalog_scan_test_hooks` above for what it does and why.
        catalog_scan_test_hook!(dir);
        let mut rows = Vec::new();
        for row in busbar_plugin_loader::inventory_tarballs(dir, policy) {
            let trust = if row.status == "ready" {
                if row.signature == "first-party" || row.signature.starts_with("publisher:") {
                    Some("trusted")
                } else {
                    Some("unverified")
                }
            } else if row.manifest.is_some() {
                Some("rejected")
            } else {
                None
            };
            let name = row
                .manifest
                .as_ref()
                .map(|m| m.name.clone())
                .unwrap_or_else(|| row.file.clone());
            // `r#type` reflects the manifest's OWN `kind` (`GET /plugins?type=secret` support,
            // plus real rows for `auth`) — not hardcoded "store".
            // `kind: hook` and a manifest-less (invalid/corrupt) row both fall back to "store",
            // preserving the exact pre-existing behavior for every case this change doesn't newly
            // cover (a broken upload of unknown kind still surfaces somewhere an operator will see
            // it, and `type=hooks` has its own, unrelated listing mechanism below — not this scan).
            let r#type = match row.manifest.as_ref().map(|m| m.kind.as_str()) {
                Some("secret") => "secret",
                Some("auth") => "auth",
                _ => "store",
            };
            // `schema_url`/`schema_error`: non-null whenever the manifest
            // declared a `settings_schema` at all, even unparseable (`schema_error` then explains
            // why) — never folded into the same `null` a schema-less plugin gets. Always the
            // admin-prefixed RELATIVE path to `GET /plugins/{name}/schema`, resolved by this
            // plugin's real manifest `name` (what that endpoint resolves against), never the
            // installed tarball's filename.
            let (schema_url, schema_error) = match row.manifest.as_ref() {
                Some(m) => manifest_schema_url_and_error(&name, m.settings_schema.as_deref()),
                None => (None, None),
            };
            rows.push(PluginView {
                name,
                r#type,
                loader: "dynamic-library",
                active: None,
                target: Some(row.file.clone()),
                file: Some(row.file.clone()),
                has_schema: schema_url.is_some(),
                version: row.manifest.as_ref().map(|m| m.version.clone()),
                publisher: row.manifest.as_ref().map(|m| m.publisher.clone()),
                interface_version: row.manifest.as_ref().map(|m| m.abi_version),
                trust,
                valid: Some(row.status == "ready"),
                error: (row.status != "ready").then(|| row.status.clone()),
                schema_url,
                schema_error,
            });
        }
        rows
    }

    /// The `GET /plugins?type=store` REQUEST-PATH entry point — the async, reactor-safe wrapper
    /// around [`Self::store_plugin_catalog`]. The synchronous version
    /// performs blocking filesystem I/O on EVERY call, not just a cache miss: the fingerprint
    /// read(s) alone are a `read_dir` + a `metadata()`/`modified()` per entry, and a miss adds the
    /// full `inventory_tarballs` unpack on top — none of it safe to run inline in an `async fn` on a
    /// Tokio worker thread, on an endpoint this codebase deliberately leaves unmetered by the admin
    /// rate limiter (see the doc comment above). Mirrors [`Self::get_usage`]'s `spawn_blocking`
    /// wrapper shape.
    ///
    /// Serialized through [`CATALOG_SCAN_GATE`] (see its doc comment for why, and for the
    /// acknowledged hit-path throughput trade-off): N callers that all miss at the same instant
    /// (e.g. right after boot or a config reload, before any entry exists) single-flight into
    /// exactly one real scan, and every other caller wakes up to find the cache already populated
    /// rather than each independently unpacking every tarball.
    ///
    /// `reload_store_plugins` is UNCHANGED and does not go through here — it already runs inside a
    /// `txn.read_store` closure on `spawn_blocking` (see `admin/v1/json/txn.rs`'s `apply()`), so it
    /// calls the synchronous [`Self::store_plugin_catalog`] directly.
    ///
    /// GATE TIMEOUT: acquiring [`CATALOG_SCAN_GATE`] is bounded by
    /// [`CATALOG_SCAN_GATE_WAIT`] — see that constant's doc comment for why an unbounded wait here
    /// would be a permanent wedge, not a self-healing one, on an endpoint this rate limiter never
    /// meters. A caller that cannot even START the scan within the bound gets a clear
    /// [`AdminError::Unavailable`] rather than a hang.
    async fn store_plugin_catalog_async(&self) -> Result<Vec<PluginView>, AdminError> {
        let _gate = match tokio::time::timeout(CATALOG_SCAN_GATE_WAIT, CATALOG_SCAN_GATE.lock())
            .await
        {
            Ok(guard) => guard,
            Err(_elapsed) => {
                diag_warn!(
                    PLUGIN_CATALOG_SCAN_GATE_TIMEOUT,
                    operation = "list_plugins.store",
                    wait = ?CATALOG_SCAN_GATE_WAIT,
                    "catalog scan gate could not be acquired within the wait bound; a prior scan \
                     is not returning (e.g. a stale/hung plugins_dir mount). Answering with a \
                     retryable error rather than hanging this request too."
                );
                return Err(AdminError::Unavailable(
                    "the plugin catalog scan is taking too long; try again shortly".to_string(),
                ));
            }
        };
        let app = self.app.clone();
        match tokio::task::spawn_blocking(move || AdminService::new(app).store_plugin_catalog())
            .await
        {
            Ok(rows) => Ok(rows),
            Err(join_err) => {
                diag_warn!(
                    PLUGIN_CATALOG_BLOCKING_TASK_FAILED,
                    operation = "list_plugins.store",
                    error = %join_err,
                    "admin blocking task failed"
                );
                // Fail soft to the always-true compiled-in row rather than an admin 500 for what is
                // just a plugin CATALOG read — same posture `store_plugin_catalog` itself takes on
                // an unparseable `plugins_cfg` (`to_policy()` failing) just above.
                Ok(vec![PluginView::basic(
                    "memory".to_string(),
                    "store",
                    "compiled-in",
                    None,
                    None,
                )])
            }
        }
    }

    /// `POST /api/v1/admin/plugins` — INSTALL a plugin: the caller uploads a SIGNED plugin tarball
    /// (`{cdylib + manifest.json}` as one `.tar.gz`); the engine RE-VERIFIES it server-side against
    /// the running `plugins.*` posture (the client is NEVER trusted — the upload may originate
    /// remotely) and atomically writes the tarball into `plugins.dir`. Full scope, audited. The
    /// change takes effect on the next plugin (re)load (restart / config apply), not as a hot swap.
    ///
    /// Verification order (fail-closed, MANIFEST-ONLY — the uploaded code is NEVER `dlopen`ed by
    /// this endpoint, so pushing a plugin over the API cannot execute it and cannot bypass the
    /// trust model; loading only ever happens through the boot pipeline's same three phases):
    /// 1. Filename sanity — a bare `.tar.gz` filename (no path traversal). Storage only; identity
    ///    comes from the signed manifest.
    /// 2. STRUCTURAL — the tarball unpacks in memory; the manifest parses, is complete and
    ///    well-formed, the sha256 binds the library bytes, the abi_version is supported. `400`.
    /// 3. TRUST — signature vs the embedded first-party key / allowlisted publishers, opt-in flags,
    ///    anti-downgrade floors. An untrusted upload is a `409 conflict` (nothing is written).
    /// 4. CONFLICT — the manifest's name/alias must not collide with a DIFFERENT already-installed
    ///    loadable plugin. `409` naming both.
    /// 5. Atomic publish — write to a temp name in the same directory, then rename into place.
    pub(crate) fn install_store_plugin(
        &self,
        file: &str,
        tarball: &[u8],
    ) -> Result<crate::admin::v1::contract::PluginInstallView, AdminError> {
        use busbar_plugin_sign::{evaluate, validate_structure, Verdict, HOST_IDENTITY};

        // ── 1. filename sanity: a bare tarball filename ──
        let file = validate_plugin_filename(file)?;

        let policy = self
            .app
            .plugins_cfg
            .to_policy()
            .map_err(AdminError::Validation)?;

        // ── 2. STRUCTURAL: in-memory unpack + manifest completeness + integrity + abi ──
        let unpacked = busbar_plugin_loader::tarball::unpack(tarball)
            .map_err(|e| AdminError::Validation(format!("invalid plugin tarball: {e}")))?;
        validate_structure(
            &unpacked.manifest,
            &unpacked.lib_bytes,
            &busbar_plugin_loader::supported_abi,
            HOST_IDENTITY,
        )
        .map_err(|e| AdminError::Validation(format!("invalid plugin manifest: {e}")))?;
        let manifest = &unpacked.manifest;

        // ── 3. TRUST re-verify against the RUNNING posture (server-side) ──
        let (trust, publisher) = match evaluate(&unpacked.lib_bytes, manifest, &policy) {
            Ok(Verdict::Trusted { publisher, .. }) => ("trusted", Some(publisher)),
            Ok(Verdict::Allowed { .. }) => ("unverified", Some(manifest.publisher.clone())),
            // An untrusted upload with no matching opt-in is forbidden - a terminal state conflict
            // (retrying the same bytes can't fix it; sign it, or set the opt-in). The `evaluate`
            // reason already names the exact flag to set and is safe to surface.
            Err(rejected) => {
                return Err(AdminError::Conflict(format!(
                    "plugin rejected by the trust policy: {}",
                    rejected.reason
                )));
            }
        };

        // ── 4. CONFLICT vs the already-installed loadable set ──
        // FAIL-OPEN GAP: a corrupt tarball already in the plugins dir makes scan_and_validate Err.
        // The old `if let Ok(reg)` SILENTLY SKIPPED the conflict check and published anyway. Propagate
        // it as a Conflict so we never admit a plugin whose conflict status we could not determine.
        let reg = busbar_plugin_loader::scan_and_validate(&self.app.plugins_dir, &policy).map_err(
            |errors| {
                AdminError::Conflict(format!(
                    "cannot validate the installed plugin set before publishing (fix or remove the \
                     offending tarball first): {}",
                    errors.join("; ")
                ))
            },
        )?;
        for existing in reg.loadable() {
            if existing.file == file {
                continue; // overwriting the same tarball file is a legitimate upgrade
            }
            let clash = existing.manifest.name == manifest.name
                || existing.manifest.alias == manifest.alias
                || existing.manifest.name == manifest.alias
                || existing.manifest.alias == manifest.name;
            // BRICKS THE NEXT BOOT: the old gate exempted a SAME-NAME upload under a DIFFERENT
            // filename (`&& existing.manifest.name != manifest.name`). But boot's phase-3
            // conflicts() hard-rejects two loadable plugins with the same name (different files) -
            // admitting one BRICKS the next restart. Reject it here (409) so we never publish a
            // state boot will refuse: a same-name upgrade must REUSE the existing filename (which
            // hits the `existing.file == file` overwrite path above), not add a second file.
            if clash {
                return Err(AdminError::Conflict(format!(
                    "plugin name/alias conflict: uploaded '{}' (alias '{}', file {}) collides with \
                     installed '{}' (alias '{}', file {}); a same-name upgrade must reuse the \
                     existing filename, not add a second file (boot would reject two files claiming \
                     the same plugin name)",
                    manifest.name,
                    manifest.alias,
                    file,
                    existing.manifest.name,
                    existing.manifest.alias,
                    existing.file
                )));
            }
        }

        // ── 5. atomic publish via the crate's ONE durable-write choke point ──
        // Directory provisioning goes through the primitive too: `std::fs::create_dir_all` leaves the
        // new directory's own entry non-durable, so the FIRST plugin installed into a not-yet-existing
        // plugins dir could vanish with the directory on power loss — despite the response promising
        // it was installed durably. The temp-in-same-dir → write → flush → fsync(file) → rename → fsync(dir) dance is the
        // primitive's. Collapsing onto it FIXES the former leaked-`.tmp`-on-pre-rename-error class for
        // free: the old `{ }` block returned early on a create/write/flush/fsync failure WITHOUT
        // removing the temp (only the rename path cleaned up), so a full disk / I/O error orphaned a
        // `.<file>.<stamp>.tmp` to accumulate across retries. The primitive's RAII guard removes the
        // temp on EVERY error path. The pid+seq temp naming supersedes the bespoke pid+now stamp with
        // the same per-call-uniqueness property.
        let dir = &self.app.plugins_dir;
        crate::durable::create_dir_all(dir)
            .map_err(|e| AdminError::Validation(format!("cannot create plugins dir: {e}")))?;
        let final_path = dir.join(&file);
        crate::durable::write(&final_path, tarball).map_err(|e| {
            AdminError::Validation(format!("cannot publish plugin into plugins dir: {e}"))
        })?;

        Ok(crate::admin::v1::contract::PluginInstallView {
            file,
            name: manifest.name.clone(),
            interface_version: manifest.abi_version,
            trust,
            version: Some(manifest.version.clone()),
            publisher,
            note:
                "installed durably in the plugins directory; the change takes effect on the next \
                   plugin (re)load (restart or config apply), not as a hot swap",
        })
    }

    /// `POST /api/v1/admin/plugins/inspect` — a STATELESS, `read-only`-scope PREVIEW of a
    /// candidate plugin tarball: verify its signature, parse its manifest, and return the SAME
    /// response shape `GET /plugins/{name}/schema` already carries
    /// (`schema`/`schema_error`/`trust`/`source`, plus
    /// `kind`/`restart_required_default` — see [`Self::install_store_plugin`]'s sibling handler for
    /// the shape those two carry), PLUS `name`/`version` so a caller can identify the candidate
    /// before ever committing to `POST /plugins`. Touches NOTHING: no write to `plugins.dir`, no
    /// conflict check against the installed set — an inspect has no interaction with what is
    /// currently loaded (unlike [`Self::install_store_plugin`], steps 4/5 of that pipeline do not
    /// exist here at all). An untrusted/unverified/rejected candidate is reported, not refused — the
    /// whole point is letting an operator see what a not-yet-trusted plugin WOULD need without ever
    /// executing it ("untrusted-render hardening").
    ///
    /// HARDENING (this body is an attacker-controlled,
    /// base64-encoded, COMPRESSED ARCHIVE, reachable by the WEAKEST admin credential in the system,
    /// and the archive must be decompressed and its manifest parsed BEFORE the signature can even be
    /// checked, so the trust check happens strictly after the dangerous part):
    ///   1. a hard cap on the DECODED tarball size, `busbar_plugin_loader::tarball::MAX_TARBALL_FILE_BYTES`
    ///      — the same ceiling `POST /plugins` (install) and the on-disk catalog scan both already
    ///      enforce, checked here BEFORE `unpack` ever runs;
    ///   2. `busbar_plugin_loader::tarball::unpack` itself streams each archive member through a
    ///      cap enforced DURING decompression (`read_entry_bounded`'s `.take(cap + 1)`) — a
    ///      decompression bomb fails fast, never after allocating the bomb — and rejects any
    ///      non-regular-file or path-traversal entry name outright, and errors immediately on a
    ///      second manifest/library member (an entry-count flood cannot accumulate past two real
    ///      entries before the archive is refused);
    ///   3. the embedded `settings_schema` string — the ONE place an attacker-controlled JSON
    ///      document can nest arbitrarily deep on a tiny byte count (every OTHER `Manifest` field is
    ///      a flat scalar, so `unpack`'s own `MAX_MANIFEST_BYTES` size cap is sufficient for the
    ///      manifest itself) — is depth- AND size-bounded via [`schema_json_within_bounds`] BEFORE
    ///      it is ever handed to `serde_json::from_str`, a distinct attack from a pathological
    ///      tarball;
    ///   4. its own dedicated rate bucket (`admin::rate::MutationClass::PluginInspect`), not the
    ///      shared 60/min CRUD bucket and not the unmetered-read bucket — wired in `auth::mod.rs`/
    ///      `admin::rate::classify_mutation` via `contract::PATH_PLUGINS_INSPECT`, exactly like
    ///      `/config/validate`'s existing carve-out.
    pub(crate) fn inspect_plugin(&self, tarball: &[u8]) -> Result<serde_json::Value, AdminError> {
        use busbar_plugin_sign::{evaluate, validate_structure, Verdict, HOST_IDENTITY};

        if tarball.len() as u64 > busbar_plugin_loader::tarball::MAX_TARBALL_FILE_BYTES {
            return Err(AdminError::Validation(format!(
                "decoded tarball is {} bytes, exceeding the {}-byte cap",
                tarball.len(),
                busbar_plugin_loader::tarball::MAX_TARBALL_FILE_BYTES
            )));
        }

        let policy = self
            .app
            .plugins_cfg
            .to_policy()
            .map_err(AdminError::Validation)?;

        let unpacked = busbar_plugin_loader::tarball::unpack(tarball)
            .map_err(|e| AdminError::Validation(format!("invalid plugin tarball: {e}")))?;
        validate_structure(
            &unpacked.manifest,
            &unpacked.lib_bytes,
            &busbar_plugin_loader::supported_abi,
            HOST_IDENTITY,
        )
        .map_err(|e| AdminError::Validation(format!("invalid plugin manifest: {e}")))?;
        let manifest = &unpacked.manifest;

        // Trust is REPORTED, never a refusal to answer — an untrusted/rejected candidate is exactly
        // the case an operator most wants to preview before deciding whether to trust it at all.
        let trust = match evaluate(&unpacked.lib_bytes, manifest, &policy) {
            Ok(Verdict::Trusted { .. }) => "trusted",
            Ok(Verdict::Allowed { .. }) => "unverified",
            Err(_rejected) => "rejected",
        };

        let (schema, schema_error) = match manifest.settings_schema.as_deref() {
            None => (None, None),
            Some(s) => match schema_json_within_bounds(s) {
                Err(reason) => (None, Some(reason)),
                Ok(()) => match serde_json::from_str::<serde_json::Value>(s) {
                    Ok(v) => (Some(v), None),
                    Err(e) => (
                        None,
                        Some(format!("manifest settings_schema is not valid JSON: {e}")),
                    ),
                },
            },
        };

        Ok(serde_json::json!({
            "name": manifest.name,
            "version": manifest.version,
            "kind": manifest.kind,
            "schema": schema,
            "schema_error": schema_error,
            "trust": trust,
            "source": "manifest",
            "restart_required_default": busbar_plugin_sign::kind_restart_default(&manifest.kind),
        }))
    }

    /// `DELETE /api/v1/admin/plugins/{file}` — REMOVE a plugin tarball from the plugins directory.
    /// Full scope. `404 not_found` if the file isn't present. A currently-loaded store keeps
    /// running on its already-loaded handle until the next plugin (re)load — removing the file only
    /// affects the NEXT load (folder = source of truth).
    pub(crate) fn remove_store_plugin(
        &self,
        file: &str,
    ) -> Result<crate::admin::v1::contract::PluginRemoveView, AdminError> {
        let file = validate_plugin_filename(file)?;
        let lib_path = self.app.plugins_dir.join(&file);
        if !lib_path.is_file() {
            return Err(AdminError::not_found(format!("plugin `{file}`")));
        }
        // `durable::remove`, not a bare `remove_file`: the INSTALL fsyncs the plugins directory so
        // the new artifact's directory entry survives a power loss, and a removal that skipped it was
        // the asymmetric half -- a crash right after a delete could resurrect the artifact and load
        // it on the next boot.
        crate::durable::remove(&lib_path)
            .map_err(|e| AdminError::Validation(format!("cannot remove plugin: {e}")))?;
        Ok(crate::admin::v1::contract::PluginRemoveView {
            file,
            removed: true,
        })
    }

    /// `POST /api/v1/admin/plugins/reload` — re-scan the plugins directory and report the current
    /// dynamic-library inventory (the SAME projection `GET /plugins?type=store` produces, minus the
    /// compiled-in `memory` head). Full scope. Reconciles the reported set to the folder (folder =
    /// source of truth), the exact sibling of `config/reload`. A store change still applies on the
    /// next store (re)load, not as a hot swap.
    pub(crate) fn reload_store_plugins(
        &self,
    ) -> Result<crate::admin::v1::contract::PluginReloadView, AdminError> {
        // Reuse the store catalog projection, dropping the compiled-in `memory` head (reload reports
        // only the on-disk dynamic set it reconciled).
        let plugins: Vec<PluginView> = self
            .store_plugin_catalog()
            .into_iter()
            .filter(|p| p.loader == "dynamic-library")
            .collect();
        Ok(crate::admin::v1::contract::PluginReloadView {
            plugins,
            note:
                "hot-reloaded the plugin layer LIVE: a new plugin registry and new kind:hook \
                   transports are serving with no restart, and the prior shared libraries unmap once \
                   in-flight requests drain. A `store` MODULE change still lands on a dedicated store \
                   swap (the token ledger cannot be re-hydrated under load), not this reload.",
        })
    }

    /// The RESOLUTION half of an EXPLICIT plugin ROLLBACK (`POST /api/v1/admin/plugins/rollback`,
    /// 1.5.0). Validate that `file` is a plugin tarball in the plugins dir, unpack + STRUCTURALLY
    /// validate its manifest, and TRUST-verify it against a policy whose first-party floor is LOWERED to
    /// the target's OWN version — so a validly-signed but OLDER artifact (exactly the rollback case)
    /// clears trust here even though it would be an anti-downgrade reject on the automatic path. This is
    /// where "automatic vs explicit" is made concrete: the rollback deliberately relaxes the floor to
    /// the pinned target and only that target; a lower artifact still fails, and a signature/opt-in
    /// failure is still fatal (a rollback can never launder an untrusted artifact). Returns the target
    /// manifest identity (name/version/publisher) + the MERGED pin map (prior overlay pins with this
    /// plugin's name set to the target version) the caller persists and re-derives the policy from.
    ///
    /// `prior_pins` is the current persisted `plugin_versions` overlay section (empty if none).
    pub(crate) fn resolve_plugin_rollback(
        &self,
        file: &str,
        prior_pins: &std::collections::BTreeMap<String, String>,
    ) -> Result<
        (
            busbar_plugin_sign::Manifest,
            std::collections::BTreeMap<String, String>,
        ),
        AdminError,
    > {
        use busbar_plugin_sign::{evaluate, validate_structure, Verdict, HOST_IDENTITY};
        let file = validate_plugin_filename(file)?;
        let lib_path = self.app.plugins_dir.join(&file);
        if !lib_path.is_file() {
            return Err(AdminError::not_found(format!("plugin `{file}`")));
        }
        let bytes = std::fs::read(&lib_path)
            .map_err(|e| AdminError::Validation(format!("cannot read plugin `{file}`: {e}")))?;
        let unpacked = busbar_plugin_loader::tarball::unpack(&bytes)
            .map_err(|e| AdminError::Validation(format!("invalid plugin tarball `{file}`: {e}")))?;
        validate_structure(
            &unpacked.manifest,
            &unpacked.lib_bytes,
            &busbar_plugin_loader::supported_abi,
            HOST_IDENTITY,
        )
        .map_err(|e| AdminError::Validation(format!("invalid plugin manifest `{file}`: {e}")))?;
        let manifest = unpacked.manifest;

        // Build the trust policy with the first-party floor LOWERED to the target artifact's own
        // version — the EXPLICIT relaxation. `min_versions` is carried from base config as-is; we
        // additionally lower THIS plugin's configured floor to the target version so a floored
        // third-party plugin can also roll back. Anything the target does NOT satisfy (a broken
        // signature, an un-opted-in third party) still fails: a rollback authenticates the OPERATOR,
        // never the ARTIFACT.
        let mut policy = self
            .app
            .plugins_cfg
            .to_policy_with_floor(&manifest.version)
            .map_err(AdminError::Validation)?;
        policy
            .min_versions
            .insert(manifest.name.clone(), manifest.version.clone());
        match evaluate(&unpacked.lib_bytes, &manifest, &policy) {
            Ok(Verdict::Trusted { .. }) | Ok(Verdict::Allowed { .. }) => {}
            Err(rejected) => {
                return Err(AdminError::Conflict(format!(
                    "rollback target `{file}` is not loadable under the trust policy even with the \
                     floor lowered to its own version {}: {}. A rollback lowers the anti-downgrade \
                     floor for an explicit operator action; it cannot load an untrusted artifact.",
                    manifest.version, rejected.reason
                )));
            }
        }

        // Merge: this plugin's pin becomes the target version; other plugins' prior pins are preserved.
        let mut pins = prior_pins.clone();
        pins.insert(manifest.name.clone(), manifest.version.clone());
        Ok((manifest, pins))
    }

    /// `GET /api/v1/admin/config` — the EFFECTIVE running config, composed from the same redacted reads as
    /// the individual endpoints (auth/pools/models/providers/hooks/global-hooks). Read scope. Carries
    /// no secret. For drift detection + one-shot inspection; the base-vs-overlay source annotation
    /// lands with the overlay substrate.
    pub(crate) async fn get_config(&self) -> Result<EffectiveConfigView, AdminError> {
        Ok(EffectiveConfigView {
            version: self.app.config_version,
            auth: self.get_auth().await?,
            pools: self.list_pools().await?.items,
            models: self.list_models().await?.items,
            providers: self.list_providers().await?.items,
            hooks: self.list_hooks().await?.items,
            global_hooks: self.app.global_hooks.clone(),
        })
    }

    /// `POST /api/v1/admin/config/validate` — DRY-RUN a proposed config: resolve (`config.yaml` deploy +
    /// `providers.yaml` defs) then run the full boot-time `config_validate`, collecting every error at
    /// once, WITHOUT applying anything. Always succeeds as an operation (`Result::Ok`) — the verdict is
    /// in the view's `ok`/`errors`; a valid request describing an invalid config is `ok: false`, not an
    /// error. Read scope (no mutation). Env interpolation is out of scope (structure + resolution only).
    pub(crate) async fn validate_config(
        &self,
        mut deploy: DeployCfg,
        defs: std::collections::HashMap<String, ProviderDef>,
    ) -> Result<ConfigValidateView, AdminError> {
        // Resolve first (cross-references config.yaml providers against providers.yaml defs); if that
        // fails there is no RootCfg to hand to the semantic validator, so return the resolve errors.
        let root = match crate::config::resolve(&deploy, &defs) {
            Ok(root) => root,
            Err(errors) => return Ok(ConfigValidateView { ok: false, errors }),
        };
        if let Err(errors) = crate::config_validate::validate(&root) {
            return Ok(ConfigValidateView { ok: false, errors });
        }
        // SECURITY (R3-B): the pre-flight below SCANS `plugins.dir` — `fs::read_dir` plus a read of
        // every tarball it finds (`plugins_preflight` → `scan_and_validate`). On THIS endpoint
        // `deploy` is CALLER-SUPPLIED, so honoring its `plugins.dir` turned validation into an
        // arbitrary-path readability + directory-enumeration oracle for any token that can reach it
        // (`plugins.dir: /root/.ssh` reports whether that path is readable and what it contains).
        // PIN the scanned directory to the RUNNING install's plugins dir before preflight: the scan
        // can no longer be steered off the real install, while validation still lints every
        // store/auth/hook/secret REFERENCE against the plugins that are ACTUALLY installed — the
        // meaningful check, and the CI dry-run use case (does this config resolve against what is
        // deployed?). The caller's `plugins.dir` string was already structurally checked by
        // `config_validate::validate` above (no FS access); only the SCAN is pinned.
        deploy.plugins.dir = self.app.plugins_dir.to_string_lossy().into_owned();
        // The SAME post-resolve pre-flight `--validate` runs. Without it this endpoint answered
        // `ok: true` for configs the CLI rejects -- a plugin whose trust posture or store reference
        // does not resolve, a `secrets:` entry naming no `kind: secret` plugin, a secret REFERENCE
        // whose module is neither built-in nor installed -- so an operator could dry-run a config
        // green here and then watch boot fail on it. Manifest-only: nothing is `dlopen`ed.
        if let Err(e) = crate::preflight_plugins_and_secrets(&deploy, &root) {
            return Ok(ConfigValidateView {
                ok: false,
                errors: vec![e],
            });
        }
        Ok(ConfigValidateView {
            ok: true,
            errors: Vec::new(),
        })
    }

    /// `GET /api/v1/admin/admin-auth` — the ADMIN-plane auth config (distinct from the ingress chain).
    /// Read scope. Reports the live `admin_auth` chain — the SAME resource `PUT /api/v1/admin/admin-auth`
    /// writes, so a read-after-write is coherent (previously this hard-coded `["admin-token"]` and
    /// never reflected a PUT). Never a secret.
    pub(crate) async fn get_admin_auth(&self) -> Result<AdminAuthView, AdminError> {
        let modules = self.app.admin_chain.clone();
        Ok(AdminAuthView {
            // An empty chain is the open (anonymous, full-authority) dev posture — NOT configured.
            configured: !modules.is_empty(),
            modules,
        })
    }

    /// `GET /api/v1/admin/usage` — the fleet METERING read (FinOps surface): the current UTC-day
    /// bucket's raw consumption, aggregated per (model, provider) and per key, each row carrying the
    /// full token SPLIT plus a DERIVED `spend_micros` (computed here at read time from the
    /// operator's configured global prices — raw counts are what's stored, so a consumer with its
    /// own price catalog reconstructs cost from the split instead). `requests` counts DELIVERED
    /// responses (the metering tap), not admissions; budget-enforcement state stays on
    /// `GET /keys/{id}/usage`. Read scope. Empty aggregations when governance is disabled. The
    /// store reads run on a blocking thread; never returns a secret — ids/names only.
    /// `window`: a caller-selected PAST bucket start (validated: bucket-aligned, not in the
    /// future); `None` = the current bucket. The response shape is pinned: always one bucket.
    pub(crate) async fn get_usage(&self, window: Option<u64>) -> Result<UsageView, AdminError> {
        let now = crate::store::now();
        let current = crate::governance::metering_bucket(now);
        let bucket = match window {
            None => current,
            Some(w) => {
                if w % crate::governance::METERING_BUCKET_SECS != 0 {
                    return Err(AdminError::Validation(format!(
                        "window must be a UTC-day bucket start (a multiple of {}); got {w}",
                        crate::governance::METERING_BUCKET_SECS
                    )));
                }
                if w > current {
                    return Err(AdminError::Validation("window is in the future".into()));
                }
                w
            }
        };
        let window = UsageWindow {
            start: bucket,
            end: bucket + crate::governance::METERING_BUCKET_SECS,
        };
        let empty = || UsageView {
            window,
            as_of: now,
            currency: (),
            total: UsageBreakdown::default(),
            by_model: Vec::new(),
            by_key: Vec::new(),
            by_key_truncated: false,
            others: None,
        };
        let Some(gov) = self.app.governance.clone() else {
            return Ok(empty());
        };
        type Fetched = (
            Vec<crate::governance::MeteringRow>,
            std::collections::HashMap<String, String>,
        );
        type UsageFetchError = (&'static str, crate::governance::StoreError);
        let joined = tokio::task::spawn_blocking(move || -> Result<Fetched, UsageFetchError> {
            let rows = gov
                .metering_for(bucket)
                .map_err(|e| ("usage.metering", e))?;
            // id → display name, for the by_key rows (a deleted key's history keeps its id).
            let names = gov
                .all_keys()
                .map_err(|e| ("usage.keys", e))?
                .into_iter()
                .map(|k| (k.id, k.name))
                .collect();
            Ok((rows, names))
        })
        .await;
        let cost = self.app.cost.clone();
        let (rows, names) = match joined {
            Ok(Ok(f)) => f,
            // The real store error is logged here — this is the only place it exists, and the wire
            // body deliberately carries none of it so store internals never reach even an
            // authenticated admin. Same `operation`/`error` field vocabulary as `internal_error`
            // (`admin/mod.rs`), so a broken /usage read is greppable alongside every other admin
            // store failure. `operation` distinguishes which of the two reads failed, since each has
            // a different remediation.
            Ok(Err((operation, e))) => {
                diag_error!(ADMIN_STORE_OPERATION_FAILED, operation, error = %e, "admin store operation failed");
                return Err(AdminError::Internal);
            }
            Err(join_err) => {
                diag_error!(
                    USAGE_BLOCKING_TASK_JOIN_FAILED,
                    operation = "usage",
                    error = %join_err,
                    "admin blocking task failed"
                );
                return Err(AdminError::Internal);
            }
        };
        // Aggregate in memory — a bucket is bounded by (keys × models) accumulation rows.
        let mut total = UsageBreakdown::default();
        let mut by_model: std::collections::BTreeMap<(String, String), UsageBreakdown> =
            std::collections::BTreeMap::new();
        let mut by_key: std::collections::BTreeMap<String, UsageBreakdown> =
            std::collections::BTreeMap::new();
        for r in &rows {
            // Spend derives PER ROW (the model is known here - the per-model rate applies), then
            // aggregates ADDITIVELY into total/by_model/by_key, so every rollup is exact under a
            // heterogeneous rate card.
            let row_view = UsageBreakdown {
                tokens_input: r.tokens_input,
                tokens_output: r.tokens_output,
                tokens_cache_read: r.tokens_cache_read,
                // `r` is a store MeteringRow (internal field: tokens_cache_write); UsageBreakdown
                // is the public admin-API view struct and keeps its own JSON field name unchanged.
                tokens_cache_creation: r.tokens_cache_write,
                requests: r.requests,
                spend_micros: 0,
            };
            let row_spend = derive_spend_micros_row(&cost, &r.model, &row_view);
            for b in [
                &mut total,
                by_model
                    .entry((r.model.clone(), r.provider.clone()))
                    .or_default(),
                by_key.entry(r.key_id.clone()).or_default(),
            ] {
                b.tokens_input = b.tokens_input.saturating_add(r.tokens_input);
                b.tokens_output = b.tokens_output.saturating_add(r.tokens_output);
                b.tokens_cache_read = b.tokens_cache_read.saturating_add(r.tokens_cache_read);
                b.tokens_cache_creation =
                    b.tokens_cache_creation.saturating_add(r.tokens_cache_write);
                b.requests = b.requests.saturating_add(r.requests);
                b.spend_micros = b.spend_micros.saturating_add(row_spend);
            }
        }
        let by_model = by_model
            .into_iter()
            .map(|((model, provider), usage)| ModelUsageView {
                model,
                provider,
                usage,
            })
            .collect();
        let mut by_key: Vec<KeyUsageView> = by_key
            .into_iter()
            .map(|(id, usage)| KeyUsageView {
                name: names.get(&id).cloned(),
                id,
                usage,
            })
            .collect();
        // Bound the response (no memory/latency cliff at fleet scale):
        // keep the TOP spenders (the rows a FinOps consumer actually wants first), ordered
        // spend-desc then id for determinism, and SAY when the cap fired.
        const BY_KEY_CAP: usize = 1000;
        by_key.sort_by(|a, b| {
            b.usage
                .spend_micros
                .cmp(&a.usage.spend_micros)
                .then_with(|| a.id.cmp(&b.id))
        });
        let by_key_truncated = by_key.len() > BY_KEY_CAP;
        // FinOps completeness: the tail beyond the cap is summed into an `others` bucket, so
        // total == sum(by_key) + others and every unit stays attributable.
        let others = by_key_truncated.then(|| {
            let mut o = UsageBreakdown::default();
            for row in &by_key[BY_KEY_CAP..] {
                o.tokens_input = o.tokens_input.saturating_add(row.usage.tokens_input);
                o.tokens_output = o.tokens_output.saturating_add(row.usage.tokens_output);
                o.tokens_cache_read = o
                    .tokens_cache_read
                    .saturating_add(row.usage.tokens_cache_read);
                o.tokens_cache_creation = o
                    .tokens_cache_creation
                    .saturating_add(row.usage.tokens_cache_creation);
                o.requests = o.requests.saturating_add(row.usage.requests);
                o.spend_micros = o.spend_micros.saturating_add(row.usage.spend_micros);
            }
            o
        });
        by_key.truncate(BY_KEY_CAP);
        Ok(UsageView {
            window,
            as_of: now,
            currency: (),
            total,
            by_model,
            by_key,
            by_key_truncated,
            others,
        })
    }

    /// `GET /api/v1/admin/auth` — the ingress auth chain + upstream-credential mode. Read scope. Never a
    /// secret: only module names and the mode. This is READ-ONLY at runtime — the ingress chain is
    /// mutated through the config-plane write path (`PUT/POST /api/v1/admin/config`), not a dedicated PUT.
    /// (The ADMIN-plane chain, by contrast, has `PUT /api/v1/admin/admin-auth`.)
    pub(crate) async fn get_auth(&self) -> Result<AuthView, AdminError> {
        Ok(AuthView {
            chain: self.app.auth.chain_names(),
            upstream_credentials: match self.app.upstream_creds() {
                crate::auth::UpstreamCreds::Own => "own",
                crate::auth::UpstreamCreds::Passthrough => "passthrough",
            },
            open: self.app.auth.is_open(),
        })
    }

    /// `GET /api/v1/admin/hooks/{name}/health` — best-effort transport reachability for one hook. Read
    /// scope. `not_found` if the name is unregistered. NEVER fires the hook: for a socket it does a
    /// short-timeout connect probe (`reachable = Some(_)`); for a webhook (or on non-unix) it reports
    /// `reachable = None` with a note (webhooks are probed on demand at request time, not here).
    pub(crate) async fn hook_health(&self, name: &str) -> Result<HookHealthView, AdminError> {
        let cfg = self
            .app
            .hook_registry
            .get(name)
            .ok_or_else(|| AdminError::not_found(format!("hook `{name}`")))?;
        let view = self.hook_view(name, cfg);
        let (reachable, detail) = probe_transport(cfg, &self.app.hook_env).await;
        Ok(HookHealthView {
            name: name.to_string(),
            transport: view.transport,
            reachable,
            detail,
        })
    }

    /// Project a registry `HookCfg` into the wire `HookView` against the LIVE global wiring.
    fn hook_view(&self, name: &str, cfg: &HookCfg) -> HookView {
        project_hook_view(name, cfg, &self.app.global_hooks)
    }
}

/// Project a `HookCfg` into the ONE wire `HookView` shape, against an explicit global-wiring list —
/// shared by the live reads (`self.app.global_hooks`) AND the version-history read (the SNAPSHOT's
/// own wiring), so a hook has exactly one wire representation everywhere (the versions
/// endpoint previously serialized the raw `HookCfg` file shape — a second, accidental wire schema).
/// `global` is true when the hook is named in the wiring list OR declares inline `global: true`.
pub(crate) fn project_hook_view(name: &str, cfg: &HookCfg, global_hooks: &[String]) -> HookView {
    {
        // A hook's transport is now the in-process `kind: hook` plugin it references (the retired
        // socket/webhook transports are gone); report the plugin name as the target.
        let (transport_kind, target) = if cfg.plugin.trim().is_empty() {
            ("none", None)
        } else {
            ("plugin", Some(cfg.plugin.clone()))
        };
        HookView {
            name: name.to_string(),
            kind: match cfg.kind {
                HookKind::Tap => "tap",
                HookKind::Gate => "gate",
            },
            transport: HookTransportView {
                kind: transport_kind,
                target,
            },
            prompt: match cfg.prompt {
                PromptAccess::No => "no",
                PromptAccess::Ro => "ro",
                PromptAccess::Rw => "rw",
            },
            user: match cfg.user {
                UserAccess::No => "no",
                UserAccess::Ro => "ro",
            },
            priority: cfg.priority,
            // STAGE SCOPING, projected honestly: the `phase:` list as configured, and the RESOLVED
            // set it actually means. `resolved_stages` runs the same `fires_at_stage` predicate the
            // firing path does, so this read cannot claim a stage busbar does not fire at. (1.6.0
            // removed the legacy single `at:` projection; `fires_at` is the resolved answer.)
            phase: cfg.phase.iter().copied().map(HookStage::as_str).collect(),
            fires_at: cfg
                .resolved_stages()
                .into_iter()
                .map(HookStage::as_str)
                .collect(),
            on_error: cfg.on_error.clone(),
            timeout_ms: cfg.timeout_ms,
            settings_keys: settings_keys(&cfg.settings),
            global: cfg.global || global_hooks.iter().any(|n| n == name),
            groups: cfg.groups.clone(),
        }
    }
}

/// RE-RESOLVE THE OTHER TWO PLANES' PER-CONTAINER GATES after a hook-registry mutation.
///
/// The registry is what a `tools.<server>.hooks:` / `agents.<agent>.hooks:` NAME resolves against,
/// so a definition registered (or deleted, or re-pointed) through this API changes what those
/// attaches resolve to — and a snapshot that carried the old resolution forward would answer `200
/// OK` to registering a gate that never fires, or keep firing one the operator just deleted. That is
/// the same fail-open the three `resolve_*` calls above exist to close on the pool plane, and the
/// registrations themselves are untouched here: only the attach's RESOLUTION is recomputed.
/// REBUILD EVERY `App` FIELD DERIVED FROM `hook_registry` — the ONE place that knows what those
/// fields are.
///
/// Called by every snapshot builder that rewrites the registry (`build_with_hook`,
/// `build_without_hook`, `build_with_registry`) as the last step, AFTER the builder has settled
/// `hook_registry` + `global_hooks` and run its own `preopen_gate_hooks` fail-closed check.
///
/// WHY IT IS ONE FUNCTION RATHER THAN THREE COPIES. The three builders previously each re-resolved
/// the derived set BY HAND, and every new derived field had to be remembered at three call sites —
/// a structure that had already grown one omission (`requested_signals`, added beside
/// `any_content_hook` in `main.rs` and never wired into the builders, so a hook registered through
/// the API declaring `signals:` was handed candidate payloads that silently lacked them until the
/// next restart). That is the same FAIL-OPEN shape as a register answering `200 OK` while the gate
/// chain stays empty. With the set named once, adding a derived field to `main.rs`'s `App`
/// construction has exactly one other place to touch, and `hook_derived_fields_follow_the_registry`
/// asserts the two agree.
fn rebuild_hook_derived(next: &mut crate::state::App) {
    // ── the config-generation SCALARS derived from the registry ──
    // The IR compute gate follows the registry it is derived from: a newly registered `prompt: ro`
    // hook must be able to see content on the very next request.
    next.any_content_hook = crate::hooks::any_content_hook(&next.hook_registry);
    // The declared-signal bitmask follows it for the identical reason, and `HookCfg::signals`'s own
    // contract states it outright: declaring a signal is "necessary AND sufficient for it to start
    // being computed + projected; nothing else is required". A runtime register IS a config apply.
    next.requested_signals = crate::hooks::requested_signals(&next.hook_registry);

    // ── the RESOLVED transports the request path fires ──
    next.rewrite_hooks = crate::hooks::resolve_rewrite_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.hook_env,
        next.config_version,
    );
    next.tap_hooks = crate::hooks::resolve_tap_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.hook_env,
        next.config_version,
        crate::config::HookStage::Request,
    );
    next.tap_hooks_candidate = crate::hooks::resolve_tap_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.hook_env,
        next.config_version,
        crate::config::HookStage::Candidate,
    );
    next.tap_hooks_routing = crate::hooks::resolve_tap_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.hook_env,
        next.config_version,
        crate::config::HookStage::Routing,
    );
    next.tap_hooks_response = crate::hooks::resolve_tap_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.hook_env,
        next.config_version,
        crate::config::HookStage::Response,
    );
    next.global_gates = crate::hooks::resolve_gate_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.hook_env,
        next.config_version,
    );
    reresolve_plane_gates(next);
}

// Each plane re-resolves its OWN per-registration hook gates through the `reresolve_gates` seam, so
// this fold names no plane registry type. A plane with no per-registration gates (the LLM plane)
// declares `None` and is skipped, exactly as the old plane-gated blocks skipped a compiled-out plane.
fn reresolve_plane_gates(next: &mut crate::state::App) {
    for decl in crate::plane::registry::plane_decls() {
        if let Some(reresolve) = decl.reresolve_gates {
            reresolve(next);
        }
    }
}

/// Project a plane section's registrations onto the shared view through the plane's `named_def_list`
/// seam — resolved by config section, so the admin read path names no plane view type. Empty for a
/// section whose plane is compiled out (no decl) or is not a named-definition map.
fn plane_named_def_list(section: NamedMapSection, app: &crate::state::App) -> Vec<NamedDefView> {
    crate::plane::registry::plane_decl_for_config_section(section.key())
        .and_then(|d| d.named_def_list)
        .map_or_else(Vec::new, |f| {
            f(app as &dyn busbar_substrate::plane_host::PlaneSlots)
        })
}

/// One registration from a plane section, through the plane's `named_def_get` seam. `None` when the
/// plane has no such entry, is compiled out, or is not a named-definition map.
fn plane_named_def_get(
    section: NamedMapSection,
    app: &crate::state::App,
    name: &str,
) -> Option<NamedDefView> {
    crate::plane::registry::plane_decl_for_config_section(section.key())
        .and_then(|d| d.named_def_get)
        .and_then(|f| f(app as &dyn busbar_substrate::plane_host::PlaneSlots, name))
}

#[cfg(test)]
#[path = "tests/service_tests.rs"]
mod tests;
