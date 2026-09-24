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

use busbar_kernel::diagnostics::{
    diag_debug, diag_error, diag_warn, ADMIN_STORE_OPERATION_FAILED, GROUP_DELETE_KEY_READ_FAILED,
    PLUGINS_DIR_FINGERPRINT_FAILED, PLUGIN_CATALOG_BLOCKING_TASK_FAILED,
    PLUGIN_CATALOG_SCAN_GATE_TIMEOUT, USAGE_BLOCKING_TASK_JOIN_FAILED,
};
use busbar_kernel::state::App;

use busbar_kernel::admin::v1::contract::{
    AdminAuthView, AdminError, AuthView, BuildInfo, ConfigValidateView, EffectiveConfigView,
    GroupView, HookHealthView, HookTransportView, HookView, InfoView, KeyUsageView, ModelUsageView,
    ModelView, NamedDefView, Page, PluginView, PoolDetailView, PoolMemberStatusView,
    PoolMemberView, PoolView, ProviderView, TopologyInfo, UsageBreakdown, UsageView, UsageWindow,
};
use busbar_kernel::config::named_map::NamedMapSection;
use busbar_kernel::config::{
    DeployCfg, HookCfg, HookKind, HookStage, PromptAccess, ProviderDef, UserAccess,
};

/// The KEY NAMES of one opaque `settings:` bag, sorted — the REDACTED projection EVERY admin read
/// serves instead of the bag itself (see [`NamedDefView::settings_keys`]: a settings value may be a
/// credential and these reads are reachable at READ-ONLY admin scope).
///
/// THE ONE PROJECTION, deliberately: named-map definitions, hook definitions, hook STATUS (desired
/// and reported), and the whole-`RootSettings` config read all go through this function (or through
/// [`redact_settings_bags`], which is this function applied structurally). A second redaction scheme
/// is how a leak comes back — and `cargo xtask gate settings-leak` fails the build for any admin
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

/// Derive busbar's spend (micro-units, abstract cost units) for one PER-MODEL metering row from
/// the CURRENT rate card: the row's tier-token split priced at that model's rates, plus the flat
/// per-request fee x requests. Metering rows attribute by the CONFIGURED model name, so the rate
/// lookup goes through the `upstream_model` alias resolution.
///
/// **THE FALLBACK, NOT THE MODEL.** Under DECISION #79 a posting prices against the card in force
/// at ITS OWN arrival instant, resolved through the dated history by
/// [`derive_spend_micros_row_at_card`] against the entry `card_at(row.priced_from_ms)` resolves to.
/// This derivation is what the read answers when there is no dated history to resolve against — a
/// build whose composition root installed no [`UsageRateHistory`], or a row whose instant falls in
/// a hole no entry of the snapshot covers.
/// It prices at the CURRENT card — the previous release's reading — but through THE ONE FUNCTION
/// (`CostModel::derive_spend_micros` is `busbar_kernel_ledger::cost::Tally` at that card): a model
/// or class the present card does not price REFUSES (#42, item 31) instead of reading as the flat
/// fee alone, and an overflow refuses instead of pinning (item 28).
pub fn derive_spend_micros_row(
    cost: &busbar_kernel::cost::CostModel,
    model: &str,
    b: &UsageBreakdown,
) -> Result<i64, busbar_kernel_ledger::cost::MoneyError> {
    // Project the metering row's flat tier fields (its OWN JSON-contract names, unchanged) onto the
    // name-keyed unit map the pricer now consumes. `tokens_cache_creation` is the row's field name;
    // it maps onto the canonical `cache_write` unit key.
    let units: std::collections::BTreeMap<String, u64> = [
        (busbar_api::UNIT_INPUT, b.tokens_input),
        (busbar_api::UNIT_OUTPUT, b.tokens_output),
        (busbar_api::UNIT_CACHE_READ, b.tokens_cache_read),
        (busbar_api::UNIT_CACHE_WRITE, b.tokens_cache_creation),
    ]
    .into_iter()
    .filter(|(_, v)| *v != 0)
    .map(|(k, v)| (k.to_string(), v))
    .collect();
    let resolved = cost.resolve_model_alias(model);
    cost.derive_spend_micros([(resolved, &units)].into_iter(), b.requests, true)
}

/// A usage read the one function REFUSED, as the admin wire answers it (OWNER RULING Q25b). A card
/// that is present and silent about a lane or a class is the operator's to fix and is NAMED —
/// `unpriced_class` (409) with the lane and the class in the message — rather than hidden behind a
/// bare 500. The other refusals (no card in force for the instant, a figure out of range) stay
/// `internal`. Every refusal is logged under `operation`, as before.
pub(crate) fn usage_refusal(
    operation: &'static str,
    e: &busbar_kernel_ledger::cost::MoneyError,
) -> AdminError {
    use busbar_kernel_ledger::cost::MoneyError;
    diag_error!(ADMIN_STORE_OPERATION_FAILED, operation, error = %e, "admin store operation failed");
    match e {
        MoneyError::ClassUnpriced { lane, class, .. } => AdminError::UnpricedClass {
            lane: lane.clone(),
            class: Some(class.clone()),
        },
        MoneyError::LaneUnpriced { lane, .. } => AdminError::UnpricedClass {
            lane: lane.clone(),
            class: None,
        },
        MoneyError::NoCardInForce { .. } | MoneyError::Overflow => AdminError::Internal,
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE DATED RATE-CARD HISTORY, ON THE READ PATH — DECISION #79
//
// "Price against the latest rate card" means the latest card whose `effective_from` had ARRIVED at
// the posting's instant, never the latest card ever authored. Publishing a card prices what
// happens after it and leaves the window before its `effective_from` exactly as it was; a signed
// back-dated correction reprices exactly `[effective_from, effective_until)` and nothing outside
// it. The resolution rule itself is not written here — it is
// `busbar_kernel_ledger::cost::HistoryView::card_at`, the one place entitled to say which entry
// answers for an instant, and a second copy of it is how a request comes to be judged at one
// figure and billed at another.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// **THE DATED-HISTORY READ SEAM** — the one question `GET /api/v1/admin/usage` asks of the
/// process's rate-card history, answered by whoever holds it.
///
/// Shaped after [`busbar_kernel::rate_apply`] and for the same reason: the composition root is the
/// only place entitled to hold a deployment's history, so the root installs an implementor once at
/// boot ([`install_usage_rate_history`]) and this crate reaches it by name. A build that installed
/// none answers `None` and the read derives exactly as the previous release did — a no-op rather
/// than a swap quietly dropped.
pub trait UsageRateHistory: Send + Sync {
    /// The process's dated history, PINNED for the length of one read.
    ///
    /// Pinned rather than read per row: a card appended while the read is in flight must not price
    /// half of one response's rows against one history and half against another.
    ///
    /// `None` for a node that has resolved no configuration yet — which is a node with no entry a
    /// row could resolve to, not a node whose rows are free.
    fn history(&self) -> Option<Arc<busbar_kernel_ledger::cost::History>>;
}

/// THE PROCESS-WIDE dated-history source, installed once by the composition root.
static USAGE_RATE_HISTORY: OnceLock<&'static dyn UsageRateHistory> = OnceLock::new();

/// Install the process's dated-history source — the composition root's one write, at boot, before
/// the first usage read. Idempotent by `OnceLock`: a second install is a no-op.
///
/// Until this is called the usage read prices off the current card exactly as the previous release
/// did, which is the honest answer for a binary with no root ledger in it.
pub fn install_usage_rate_history(source: &'static dyn UsageRateHistory) {
    let _ = USAGE_RATE_HISTORY.set(source);
}

/// The installed source, if the composition root installed one.
fn installed_usage_rate_history() -> Option<&'static dyn UsageRateHistory> {
    USAGE_RATE_HISTORY.get().copied()
}

/// **THE INSTANT A METERING ROW RESOLVES AT**: its own FIRST instant — the later of the bucket's
/// start and the price era the row was accrued in.
///
/// Both halves are load-bearing and each alone is wrong.
///
/// The ERA (`priced_from_ms`, the `effective_from` of the entry in force at accrual) is what picks
/// the right CARD: it is why a card published at noon splits the day, and why the afternoon's
/// counts do not price at the morning's rate.
///
/// The CLIP to the bucket is what keeps the instant INSIDE the row's own wall-clock span, and
/// without it a back-dated correction cannot reach the row at all. An entry effective from instant
/// zero dates every row it covers at zero, however many days later those rows were earned; a signed
/// correction over `[effective_from, effective_until)` is a WINDOW IN WALL-CLOCK TIME, and zero
/// falls outside every window an operator would ever name. Resolving at the era start alone
/// therefore made the sanctioned repair path a no-op for exactly the rows it was meant to repair —
/// which a red test caught, and which is the reason this function exists rather than a bare field
/// read at the call site.
///
/// A row whose era is zero because the field predates it lands on its own bucket's start, which is
/// the honest reading for a row nothing dated: the card in force at the beginning of the day it was
/// earned in, never the newest card ever authored.
pub fn row_priced_at_ms(bucket_start_secs: u64, priced_from_ms: u64) -> u64 {
    bucket_start_secs.saturating_mul(1_000).max(priced_from_ms)
}

/// The row's flat tier fields under the reserved class spellings a card entry is written against,
/// so no name is translated between a quantity and the entry that prices it.
///
/// A ZERO QUANTITY IS LEFT OFF rather than priced at zero: a line the row does not carry is not a
/// line. That is also what keeps #42 off this path for a config-built card — `RateCard::from_config`
/// fans every lane out over all four reserved classes (`TierRates::by_class`), so a class the row
/// DOES carry is always one the card names.
fn row_counts(b: &UsageBreakdown) -> impl Iterator<Item = (&'static str, u64)> + '_ {
    [
        (busbar_api::UNIT_INPUT, b.tokens_input),
        (busbar_api::UNIT_OUTPUT, b.tokens_output),
        (busbar_api::UNIT_CACHE_READ, b.tokens_cache_read),
        (busbar_api::UNIT_CACHE_WRITE, b.tokens_cache_creation),
    ]
    .into_iter()
    .filter(|(_, quantity)| *quantity != 0)
}

/// **THE LOOKUP, AND IT IS THE ONE FUNCTION** — one metering row priced through
/// [`busbar_kernel_ledger::cost::price_in_view`], the single implementation of
/// `money = f(ledger_slice, card_history)` that satisfies #79 (`BUSBAR-1.6.0.md:423`), #42 (`:367`)
/// and #81 (`:425`) together.
///
/// Before this, the dated read carried its OWN multiply-and-sum — it called
/// `busbar_kernel_ledger::cost::derive_spend_micros`, which is the LEGACY read-time projection and a
/// second implementation of the same arithmetic. The two agreed on every input either of them
/// answered, and that agreement was the hazard rather than the reassurance: two implementations are
/// two chances to be wrong and two places to remember when the ruling changes. #71 (`:409`) says
/// pricing is read-time and in the kernel; it does not say it may be read-time in two kernels.
///
/// **THE RESOLUTION MOVES INSIDE.** The card is no longer chosen by the caller and handed in: the
/// entry carries its own `arrived_ms` and [`busbar_kernel_ledger::cost::HistoryView::card_at`] — the
/// one place entitled to say which entry answers for an instant — resolves it. #79 is now applied in
/// exactly one place on this path instead of being applied by the caller and trusted here.
///
/// The lane is the row's CONFIGURED model name through the same `upstream_model` alias resolution
/// the flat derivation uses, so a card entry is found by the same name on both paths.
///
/// # A refusal is the answer (#42, items 31 and 28)
///
/// `price_in_view` REFUSES an unnamed lane, an unnamed class, and an accumulator that left the
/// range. This read used to catch that refusal and fall back to the LEGACY projection at the same
/// card — which priced the unnamed lane at the flat fee alone, the silent zero #42 confines to a
/// card that is ABSENT, served on the customer's `GET /admin/usage` as though it were a figure. The
/// fallback is gone: the refusal is returned, and the endpoint fails the read rather than serving a
/// number nobody priced. `card` is kept in the signature for the callers that resolved it; the one
/// function resolves its own.
pub fn derive_spend_micros_row_at_card(
    view: &busbar_kernel_ledger::cost::HistoryView<'_>,
    arrived_ms: u64,
    _card: &busbar_kernel_ledger::cost::RateCard,
    cost: &busbar_kernel::cost::CostModel,
    model: &str,
    b: &UsageBreakdown,
) -> Result<i64, busbar_kernel_ledger::cost::MoneyError> {
    let lane = cost.resolve_model_alias(model);
    // ONE ROW OF A LEDGER SLICE, which is what the metering book projects onto without arithmetic:
    // a lane, counts keyed by meter class, a fee count, and THE INSTANT (#79's resolution key, in
    // MILLISECONDS — `row_priced_at_ms` is what decides which instant this row claims).
    let entry = row_counts(b)
        .fold(
            busbar_kernel_ledger::cost::LedgerEntry::new(lane, arrived_ms),
            |e, (class, quantity)| e.with_whole(class, quantity),
        )
        .with_fee_count(b.requests);
    busbar_kernel_ledger::cost::price_in_view(std::slice::from_ref(&entry), view)?.micros_i64()
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE READ PATH'S THREE MONEY DERIVATIONS, REACHABLE BY NAME (test-support only)
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// The three functions `GET /api/v1/admin/usage` derives a figure with, named so that a test in
/// ANOTHER crate can CALL them instead of reproducing them.
///
/// This module exists because of a proven defect, not for convenience. The composition root's
/// equivalence proof (`crates/busbar/tests/money_one_function_equivalence.rs`) runs every
/// implementation of `money = f(ledger, rate_card)` in the tree side by side, and the admin read is
/// one of them. It could not reach these three, so it carried COPIES — and the copies drifted:
/// [`derive_spend_micros_row_at_card`] grew its `resolve_model_alias` call and the copy never did,
/// invisible because every fixture in that file serves one unaliased lane. Neutering all three of
/// these to `Default::default()` reddened eight tests in this crate and left that file's eleven
/// cases byte-identical, including the one whose assertion message reads "the endpoint agrees with
/// the function". A test that reproduces its subject proves the reproduction.
///
/// **IT IS A `pub use`, NOT A WRAPPER, AND THAT IS THE WHOLE DESIGN.** A wrapper would restate each
/// signature, and a restated signature is a second copy of exactly the kind this module exists to
/// delete — it would go stale the first time one of these grows an argument. Re-exporting the items
/// themselves means the proof calls whatever these functions ARE, and a change to one of them
/// reaches the proof as a compile error rather than as two numbers that quietly stopped meaning the
/// same thing.
///
/// TEST-SUPPORT ONLY: the module is `#[cfg]`-gated, so it does not exist in a default build. The
/// three items are `pub` because a `pub use` cannot re-export a `pub(crate)` one; this crate is
/// `publish = false` and mandatory-compiled-in, and this module is the one documented door to them.
#[cfg(any(test, feature = "test-support"))]
pub mod read_path_money {
    pub use super::{derive_spend_micros_row, derive_spend_micros_row_at_card, row_priced_at_ms};
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
    let _ = PROCESS_START_EPOCH.set(busbar_kernel::store::now());
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
        busbar_kernel::config::KEYS_MODULE,
        #[cfg(feature = "auth-admin-tokens")]
        busbar_kernel::config::ADMIN_TOKENS_MODULE,
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
    env: &busbar_kernel::hooks::HookEnv,
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
/// `build_with_group` RELOCATED to `busbar_kernel::governance::group_provision` (1.6.0 de-alias, stage 2a);
/// re-exported here so every existing call site in this module tree (`handlers.rs`'s group routes)
/// is unchanged.
pub(crate) use busbar_kernel::governance::group_provision::build_with_group;
/// Upper bound on a group name, relocated alongside `build_with_group`. Only this module's OWN test
/// harness (`build_with_group_name_length_boundary_is_exact`) still names it bare via `use
/// super::*`, so a non-test lib build sees no live use of the re-export — allowed, not removed, so
/// production code names no admin-namespaced spelling for a core constant.
#[cfg_attr(not(test), allow(unused_imports))]
pub(crate) use busbar_kernel::governance::group_provision::MAX_GROUP_NAME_LEN;

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

// `pool_known` RELOCATED to `busbar_kernel::governance::group_provision` (1.6.0 de-alias, stage 2a)
// alongside `build_with_group`, its one remaining caller in this file (`build_without_group`,
// below). Named at its call site instead of re-imported under its bare name, to keep this file's
// import list from growing for a single-use helper.

/// The lane at `idx`'s model name projected through the neutral view; empty if the handle is stale.
fn lane_model(view: &dyn busbar_kernel::plane_host::EngineTablesView, idx: usize) -> String {
    view.lane_view(idx)
        .map(|l| l.model.to_string())
        .unwrap_or_default()
}

pub fn build_with_hook(current: &App, name: &str, cfg: HookCfg) -> Result<App, AdminError> {
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
    if busbar_kernel::config::RESERVED_HOOK_NAMES.contains(&name) {
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
pub fn build_without_hook(current: &App, name: &str) -> Result<App, AdminError> {
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

// `build_with_group` RELOCATED to `busbar_kernel::governance::group_provision` (1.6.0 de-alias, stage 2a) —
// re-imported above (`pub(crate) use busbar_kernel::governance::group_provision::{build_with_group,
// MAX_GROUP_NAME_LEN};`) so every call site in this module tree is unchanged.

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
    busbar_kernel::config::groups::validate_groups(
        &groups,
        &|p| busbar_kernel::governance::group_provision::pool_known(current, p),
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
        busbar_kernel::admin::v1::contract::ADMIN_PREFIX
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
    /// The dated rate-card history the usage read resolves against — the process's, installed once
    /// by the composition root ([`install_usage_rate_history`]). `None` in a build that installed
    /// none, and the read then prices exactly as the previous release did.
    rate_history: Option<&'static dyn UsageRateHistory>,
}

// EVERY ADMIN OPERATION — the `impl AdminService` block — is in the file this line names, moved
// there byte-identically because the two of them together were over the impl-file cap.
//
// DECLARED AS A CHILD, WHICH IS WHAT MAKES THE SPLIT FREE: `operations` sees this module's private
// items, so the methods still reach `AdminService`'s private fields and every helper above through
// a single `use super::*`, and every caller still names them on the type exactly as before.
#[path = "service_operations.rs"]
mod operations;

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
            // STAGE SCOPING, projected honestly: the legacy single `at:` (null for every hook
            // written in the current `hooks:` grammar), the `phase:` list as configured, and the
            // RESOLVED set the two of them actually mean. `resolved_stages` runs the same
            // `fires_at_stage` predicate the firing path does, so this read cannot claim a stage
            // busbar does not fire at.
            at: cfg.at.map(HookStage::as_str),
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

/// RE-RESOLVE EVERY COMPILED-IN PLANE'S PER-CONTAINER GATES after a hook-registry mutation.
///
/// The registry is what each plane's own container-level `hooks:` attach NAME resolves against,
/// so a definition registered (or deleted, or re-pointed) through this API changes what those
/// attaches resolve to — and a snapshot that carried the old resolution forward would answer `200
/// OK` to registering a gate that never fires, or keep firing one the operator just deleted. That is
/// the same fail-open the three `resolve_*` calls above exist to close on the pool-scoped hooks, and
/// the registrations themselves are untouched here: only the attach's RESOLUTION is recomputed.
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
fn rebuild_hook_derived(next: &mut busbar_kernel::state::App) {
    // ── the config-generation SCALARS derived from the registry ──
    // The IR compute gate follows the registry it is derived from: a newly registered `prompt: ro`
    // hook must be able to see content on the very next request.
    next.any_content_hook = busbar_kernel::hooks::any_content_hook(&next.hook_registry);
    // The declared-signal bitmask follows it for the identical reason, and `HookCfg::signals`'s own
    // contract states it outright: declaring a signal is "necessary AND sufficient for it to start
    // being computed + projected; nothing else is required". A runtime register IS a config apply.
    next.requested_signals = busbar_kernel::hooks::requested_signals(&next.hook_registry);

    // ── the RESOLVED transports the request path fires ──
    next.rewrite_hooks = busbar_kernel::hooks::resolve_rewrite_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.hook_env,
        next.config_version,
    );
    next.tap_hooks = busbar_kernel::hooks::resolve_tap_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.hook_env,
        next.config_version,
        busbar_kernel::config::HookStage::Request,
    );
    next.tap_hooks_candidate = busbar_kernel::hooks::resolve_tap_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.hook_env,
        next.config_version,
        busbar_kernel::config::HookStage::Candidate,
    );
    next.tap_hooks_routing = busbar_kernel::hooks::resolve_tap_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.hook_env,
        next.config_version,
        busbar_kernel::config::HookStage::Routing,
    );
    next.tap_hooks_response = busbar_kernel::hooks::resolve_tap_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.hook_env,
        next.config_version,
        busbar_kernel::config::HookStage::Response,
    );
    next.global_gates = busbar_kernel::hooks::resolve_gate_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.hook_env,
        next.config_version,
    );
    reresolve_plane_gates(next);
}

// Each plane re-resolves its OWN per-registration hook gates through the `reresolve_gates` seam, so
// this fold names no plane registry type. A plane with no per-registration gates declares `None` and
// is skipped, exactly as the old plane-gated blocks skipped a compiled-out plane.
fn reresolve_plane_gates(next: &mut busbar_kernel::state::App) {
    for decl in busbar_kernel::plane::registry::plane_decls() {
        if let Some(reresolve) = decl.reresolve_gates {
            reresolve(next);
        }
    }
}

/// Project a plane section's registrations onto the shared view through the plane's `named_def_list`
/// seam — resolved by config section, so the admin read path names no plane view type. Empty for a
/// section whose plane is compiled out (no decl) or is not a named-definition map.
fn plane_named_def_list(
    section: NamedMapSection,
    app: &busbar_kernel::state::App,
) -> Vec<NamedDefView> {
    busbar_kernel::plane::registry::plane_decl_for_config_section(section.key())
        .and_then(|d| d.named_def_list)
        .map_or_else(Vec::new, |f| {
            f(app as &dyn busbar_kernel::plane_host::PlaneSlots)
        })
}

/// One registration from a plane section, through the plane's `named_def_get` seam. `None` when the
/// plane has no such entry, is compiled out, or is not a named-definition map.
fn plane_named_def_get(
    section: NamedMapSection,
    app: &busbar_kernel::state::App,
    name: &str,
) -> Option<NamedDefView> {
    busbar_kernel::plane::registry::plane_decl_for_config_section(section.key())
        .and_then(|d| d.named_def_get)
        .and_then(|f| f(app as &dyn busbar_kernel::plane_host::PlaneSlots, name))
}

#[cfg(test)]
#[path = "tests/service_tests.rs"]
mod tests;
