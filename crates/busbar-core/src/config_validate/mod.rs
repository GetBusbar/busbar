// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::{HashMap, HashSet};

use crate::config::RootCfg;
use crate::diagnostics::{
    diag_warn, CONFIG_AUTH_CHAIN_FULL_SCOPE, CONFIG_OPEN_ADMIN_MINT,
    CONFIG_PASSTHROUGH_UNUSED_APIKEY, CONFIG_POOL_HETEROGENEOUS,
};

/// Maximum byte-length of an `affinity.header_name`. HTTP header field-names must be ASCII; an
/// over-long name is rejected at boot so a bad value cannot silently disable affinity at header
/// construction time (the `http` crate rejects non-ASCII/over-long names as an error).
const MAX_AFFINITY_HEADER_NAME_LEN: usize = 64;
/// The exact panic precondition of `tokio::sync::Semaphore::new` (`permits <= MAX_PERMITS`;
/// `usize::MAX >> 3`, target-width-dependent — as low as ~536 million on a 32-bit target). THREE
/// operator-config values feed a `Semaphore::new` directly with no upper bound otherwise:
/// `models.<m>.max_concurrent` (a lane's permit semaphore, main.rs), `limits.max_inbound_concurrent`
/// (tower's `GlobalConcurrencyLimitLayer::new`, which itself calls `Semaphore::new`, main.rs), and
/// `observability.max_inflight_webhook_deliveries` (observability.rs). A value above this bound
/// would panic inside `build_app_from_config` at boot or, on the admin config-apply/reload path,
/// unwind inside a `spawn_blocking` task and surface as an opaque 500 instead of the
/// `400 invalid_request` this validator exists to guarantee.
///
/// Deliberately the PRECONDITION itself, not a policy opinion on what's a "reasonable" limit — this
/// module's operational-limit checks are NEVER coded caps (see the comment on `validate_limits`);
/// they reject only what would break the gateway, not what merely looks large. Every value at or
/// below this bound that boots/applies TODAY keeps doing so unchanged; only values that were ALREADY
/// guaranteed to panic (on this target width) are newly rejected as a clean `400`/boot `die()`
/// instead.
const MAX_SEMAPHORE_PERMITS: usize = tokio::sync::Semaphore::MAX_PERMITS;
// SSRF host guards relocated DOWN into the neutral `busbar-substrate` net_guard leaf (Batch A),
// re-exported here so every in-core caller keeps naming `config_validate::{…}` unchanged and the
// two SSRF guards still single-source their byte-identical atoms.
pub use crate::net_guard::{
    extract_normalized_host, host_is_private_or_loopback, scheme_is, ssrf_blocked_host,
};
// Test-only: the alternate-IPv4 expander moved with the guards; its unit tests still name it here.
#[cfg(test)]
use crate::net_guard::expand_alternate_ipv4;

/// Validate the loaded configuration and collect all errors at once.
/// Returns Ok(()) if valid; Err(Vec<String>) with all validation failures otherwise.
pub(crate) fn validate(cfg: &RootCfg) -> Result<(), Vec<String>> {
    validate_with_unset(cfg, &[])
}

/// As [`validate`], but told which env-var names were UNSET during a Lenient (`--validate` / admin
/// dry-run) load. In Lenient mode an unset `${VAR}` is spliced in as the bare name `VAR` (see
/// `config::EnvSubst::Lenient`), so a URL field that env-templates an unset variable resolves to a
/// scheme-less placeholder and would false-positive the https / SSRF checks. Such a value is validated
/// for real at boot (where an unset var is a hard error), so `--validate` skips the URL-format checks
/// for it here.
#[cold] // boot/admin-only — keeps hot text dense (never inlined into a warm path)
#[inline(never)]
pub fn validate_with_unset(cfg: &RootCfg, unset_env_vars: &[String]) -> Result<(), Vec<String>> {
    // A URL value that contains an unset env-var NAME is a not-yet-resolved `${VAR}` placeholder in this
    // Lenient load (unset `${VAR}` is spliced in as the bare name, which has NO url scheme). Require the
    // value to LACK a `://` scheme before treating a var-name substring match as a placeholder, so a REAL
    // URL that merely contains an unset var name as a substring is still fully https/SSRF-checked and never
    // over-suppressed (boot/reload use Strict subst, so this affects --validate
    // only). Empty list (the boot / default `validate` path) ⇒ this is always false.
    let mut errors = Vec::new();

    // The metadata host-lists are matched by EXACT IP/hostname (see `host_matches_any`); a CIDR/slash
    // entry silently never matches — a confusing no-op. Reject any `/`-bearing entry at boot so a bad
    // config fails fast. Covers the two global lists here and each provider's list inside the loop.
    reject_cidr_metadata_entries(
        "security.blocked_metadata_hosts",
        &cfg.blocked_metadata_hosts,
        &mut errors,
    );
    reject_cidr_metadata_entries(
        "security.allow_metadata_hosts",
        &cfg.allow_metadata_hosts,
        &mut errors,
    );

    // The reasoning effort table drives word<->number projection at the egress seam (the
    // cross-protocol thinking carry). A zero entry would project thinking budgets below every
    // provider minimum (Anthropic floors at 1024) and a non-ascending table makes bucketization
    // non-monotonic (a LARGER numeric budget mapping back to a SMALLER effort word). Reject both
    // at boot rather than ship a table that silently corrupts the mapping.
    {
        let b = cfg.limits.reasoning_effort_budgets;
        if b.minimal == 0 || b.low == 0 || b.medium == 0 || b.high == 0 {
            errors.push(format!(
                "limits.reasoning_effort_budgets entries must be > 0 (got {}/{}/{}/{})",
                b.minimal, b.low, b.medium, b.high
            ));
        }
        if !(b.minimal <= b.low && b.low <= b.medium && b.medium <= b.high) {
            errors.push(format!(
                "limits.reasoning_effort_budgets must be ascending (minimal <= low <= medium <= high); got {}/{}/{}/{}",
                b.minimal, b.low, b.medium, b.high
            ));
        }
    }

    // Collect provider names for pool-name conflict check and member resolution
    let provider_names: HashSet<&str> = cfg.providers.keys().map(|s| s.as_str()).collect();

    // Collect model names and their protocols for unknown-member and heterogeneity checks
    let mut model_protocols: HashMap<&str, &str> = HashMap::new();
    for (model_name, model_cfg) in &cfg.models {
        if let Some(provider_name) = cfg.providers.get(&model_cfg.provider) {
            model_protocols.insert(model_name.as_str(), provider_name.protocol.as_str());
        } else {
            errors.push(format!(
                "model '{}' references unknown provider '{}'",
                model_name, model_cfg.provider
            ));
        }
        // A configured default_max_tokens of 0 would be injected verbatim into a translated request
        // and rejected upstream — fail loud at startup rather than per-request.
        if model_cfg.default_max_tokens == Some(0) {
            errors.push(format!(
                "model '{}' has default_max_tokens: 0; must be > 0 (or omit it to use the {} fallback)",
                model_name,
                crate::proto::DEFAULT_MAX_TOKENS
            ));
        }
        // A `max_concurrent: 0` lane builds a `Semaphore::new(0)` at startup (main.rs), which never
        // grants a permit — every request to the lane is permanently capacity-exhausted with no
        // boot-time diagnostic. Reject it loudly here rather than silently black-holing the lane.
        // OMITTED (None) is the valid default: unbounded (no concurrency cap), the opt-in-limiter
        // posture that mirrors max_requests's -1. Only an explicit `Some(0)` is pathological.
        if model_cfg.max_concurrent == Some(0) {
            errors.push(format!(
                "model '{}' has max_concurrent: 0; must be >= 1, or omit it (default = unbounded)",
                model_name
            ));
        }
        // An explicit `max_concurrent` above this bound WOULD panic `Semaphore::new` in main.rs
        // (`permits <= Semaphore::MAX_PERMITS`) instead of failing validation — see
        // `MAX_SEMAPHORE_PERMITS`'s doc comment. Reject it loudly here rather than let a typo'd or
        // "big number means unlimited" value crash `build_app_from_config` at boot, or turn a 400
        // into a 500 on the admin config-apply/reload path. Omitting the field is still how an
        // operator expresses "unbounded" — main.rs already realizes that as `MAX_SEMAPHORE_PERMITS`
        // itself (see the `unwrap_or` two lines above the `Semaphore::new` call), so this bound
        // never rejects anything an omitted field wouldn't already build fine.
        if let Some(mc_val) = model_cfg.max_concurrent {
            if mc_val > MAX_SEMAPHORE_PERMITS {
                errors.push(format!(
                    "model '{}' has max_concurrent: {mc_val}; must be <= {MAX_SEMAPHORE_PERMITS} \
                     (tokio::sync::Semaphore's hard permit ceiling — a value above it panics at \
                     build time instead of failing validation), or omit the field to mean unbounded",
                    model_name
                ));
            }
        }
        // The exact twin of the `max_concurrent: 0` foot-gun on the lifetime-budget axis. main.rs
        // computes `limited = max_requests >= 0`, so `max_requests: 0` yields `limited=true,
        // budget=0`; store::usable() then rejects any lane with `limited && budget <= 0`, making the
        // lane permanently un-admissible from the first request with no boot diagnostic. A negative
        // value (-1) means unlimited via neg1(), so only 0 is pathological. Reject it loudly here.
        if model_cfg.max_requests == 0 {
            errors.push(format!(
                "model '{}' has max_requests: 0; a lane with a zero lifetime budget never admits a request — use a positive cap, or omit it (default -1 = unlimited)",
                model_name
            ));
        }
        // `attempt_timeout_ms: 0` would race a zero-duration `tokio::time::timeout` against
        // `req.send()` — the timer wins before the connection is even attempted, so EVERY attempt
        // on the lane "times out" instantly and the lane is permanently un-usable (breaker-tripped
        // on first touch) with no boot diagnostic. The same fail-loud rule as max_concurrent:0.
        // Disabling the cap is expressed by omitting the field, not by 0.
        if model_cfg.attempt_timeout_ms == Some(0) {
            errors.push(format!(
                "model '{}' has attempt_timeout_ms: 0; a zero cap fails every attempt instantly — use a positive millisecond value, or omit it to disable the per-attempt cap",
                model_name
            ));
        }
        // `upstream_model`, when set, is sent to the provider as the wire model id — an empty or
        // whitespace-only override would put a blank model on the wire (a guaranteed upstream 400/404)
        // with no boot diagnostic. Reject it loudly; omit the field to fall back to the config key.
        if let Some(um) = &model_cfg.upstream_model {
            if um.trim().is_empty() {
                errors.push(format!(
                    "model '{}' has an empty upstream_model; set a non-empty provider model id, or omit it to use the config key",
                    model_name
                ));
            }
        }
        // Reserved-name check (same rule as the pool and provider loops below): a model named `admin`
        // is reached at `POST /api/v1/admin/messages`, which the auth middleware classifies as the
        // operator admin surface (guarded by admin_token, not a client/virtual-key token). So the
        // model is unreachable to normal clients AND, in governance mode, the admin branch inserts
        // `GovCtx::default()` (key: None) which skips per-model `allowed_pools` enforcement — a
        // governance bypass. Reject at boot rather than ship a silently-inaccessible / governance-
        // bypassing model. (`reserved_admin_name` derives the segment from the auth-middleware
        // `ADMIN_PATH`, so models/pools/providers all share one drift-proof rule.)
        if reserved_admin_name(model_name) {
            errors.push(format!(
                "model name '{}' is reserved: '{}' is the native-API root (the auth middleware routes /{} and /{}/* to the operator admin surface), so a model reachable via /{}/v1/messages is unreachable to clients and bypasses per-model governance; rename it",
                model_name, admin_root_segment(), admin_root_segment(), admin_root_segment(), model_name
            ));
        }
    }

    // All model names, used for the pool/model collision check below (the `named` route resolves
    // pools before models, so a pool sharing a model's name would permanently shadow that model).
    let model_names: HashSet<&str> = cfg.models.keys().map(|s| s.as_str()).collect();

    // Rule 1: Reject a pool name that collides with any provider name OR any model name. Pools,
    // providers, and models must all have distinct names: a pool named like a provider is
    // ambiguous, and a pool named like a model silently shadows that model on the `named` route.
    for pool_name in cfg.pools.keys() {
        if provider_names.contains(pool_name.as_str()) {
            errors.push(format!(
                "pool name '{}' conflicts with provider name '{}'; pools and providers must have distinct names",
                pool_name, pool_name
            ));
        }
        if model_names.contains(pool_name.as_str()) {
            errors.push(format!(
                "pool name '{}' conflicts with model name '{}'; pools and models must have distinct names",
                pool_name, pool_name
            ));
        }
        // Reserved-name check: the auth middleware classifies any request path that is exactly
        // `/api` or starts with `/api/` as the native-API operator surface (guarded by the admin
        // auth chain, NOT a client/virtual-key token). A pool named `api` is reached at
        // `POST /api/v1/messages`, which the middleware intercepts as an admin request — so a
        // normal client_token / virtual-key holder gets a 401 and the pool is permanently
        // unreachable; worse, in governance mode the admin branch inserts `GovCtx::default()`
        // (key: None), so an admin-token holder reaching the pool this way bypasses per-pool
        // allowed_pools enforcement entirely. The collision extends to any name whose first path
        // segment would be `api`. Reject these at boot rather than shipping a silently-inaccessible
        // / governance-bypassing pool. (`reserved_admin_name` DERIVES the segment from the
        // middleware's own `ADMIN_PATH`, so the check and the `is_admin` boundary cannot drift —
        // the previous copied `admin` literal is exactly how they drifted apart.)
        if reserved_admin_name(pool_name) {
            errors.push(format!(
                "pool name '{}' is reserved: '{}' is the native-API root (the auth middleware routes /{} and /{}/* to the operator admin surface), so a pool reachable via that path is unreachable to clients and bypasses per-pool governance; rename it",
                pool_name, admin_root_segment(), admin_root_segment(), admin_root_segment()
            ));
        }
    }

    // UNIFIED `pools:` NEUTRALITY (1.6.0, design `1.6.0-unified-pools.md` §7-8). The single neutral
    // `pools:` map infers each pool's KIND from its members and resolves members by NAME ALONE, which
    // is sound only if names are GLOBALLY UNIQUE: no name defined in two nouns, and no pool name
    // colliding with a noun/member name. Checked here (over the resolved `RootCfg`) so a clean
    // `--validate` is a clean boot — the same reason the context_max conflict moved here.
    validate_unified_pool_names(cfg, &mut errors);

    // The same reserved-prefix collision applies to PROVIDER names: a provider named `api` is
    // reachable via the adhoc route `POST /api/<model>/v1/messages`, whose first segment the auth
    // middleware intercepts as an admin request for the identical reason. Reject it symmetrically.
    for provider_name in cfg.providers.keys() {
        if reserved_admin_name(provider_name) {
            errors.push(format!(
                "provider name '{}' is reserved: '{}' is the native-API root (the auth middleware routes /{} and /{}/* to the operator admin surface), so a provider reachable via the adhoc /{}/<model> route is unreachable to clients; rename it",
                provider_name, admin_root_segment(), admin_root_segment(), admin_root_segment(), admin_root_segment()
            ));
        }
    }

    // Rule 4 and the provider sweep it leads: PARAMETERISED on the known-protocol set. The
    // known-set is read HERE, at the single production reader, and passed down — so the whole
    // provider sweep (not just its protocol arm) is a function a test can drive against an EMPTY
    // set. See `validate_providers_with` for why the empty set is the load-bearing case.
    //
    // Read through `registry().codec_protocols()` rather than the `known_protocols()` re-export:
    // both yield the same codec set (`known_protocols` IS `registry().codec_protocols()`), but the
    // `registry()` accessor SEEDS core's own-test built-in tail first, where the bare re-export does
    // not. Under the test-support surface, validation can be a test's FIRST registry read (an
    // app-boot fixture that never hit a request path), and an unseeded read would spuriously see an
    // empty codec set and refuse a valid provider. Production is unaffected — there `registry()` is
    // the direct substrate re-export and the composition root installed the protocols in `main`.
    validate_providers_with(
        crate::proto::registry::registry().codec_protocols(),
        cfg,
        unset_env_vars,
        &mut errors,
    );

    // Rule 2 & 3: Validate each pool's members
    for (pool_name, pool_cfg) in &cfg.pools {
        let mut member_protocols: HashSet<&str> = HashSet::new();

        // A pool with NO members parses fine but is permanently un-routable: the selector has zero
        // candidates, so every request to the pool exhausts immediately and the forward loop returns
        // a generic 503 with a misleading "overloaded" message — the pool boots and then 503s every
        // request, with no boot diagnostic. This is the empty-set twin of the per-member
        // weight:0 / max_concurrent:0 / breaker n:0 fail-loud guards: reject it here so the operator
        // learns at startup that the pool can never serve a request, rather than diagnosing it from
        // a runtime "overloaded" that points at nothing.
        if pool_cfg.members.is_empty() {
            errors.push(format!(
                "pool '{}' has no members; a pool with an empty member list is un-routable — every request to it 503s with a misleading 'overloaded' message. Add at least one member, or remove the pool",
                pool_name
            ));
        }

        for member in &pool_cfg.members {
            // A `weight: 0` member is silently mis-balanced by the SWRR selector: it contributes 0
            // to the running total and its current_weight never increases, so it is never selected
            // while peers are healthy; an all-zero pool degenerates to always returning the first
            // candidate with no load distribution — and no boot diagnostic. Reject it (mirroring the
            // max_concurrent:0 / breaker n:0 fail-loud rules). Excluding a member is expressed via
            // `exclusions`, not weight 0.
            if member.weight == 0 {
                errors.push(format!(
                    "pool '{}' member '{}' weight must be >= 1 (got 0)",
                    pool_name, member.model
                ));
            }
            // Member-level `attempt_timeout_ms: 0` — same instant-fail foot-gun as the model-level
            // check above, but the member override is consulted FIRST by the engine, so a zero here
            // poisons the member even when the model's own value is sane. Same fail-loud rule.
            if member.attempt_timeout_ms == Some(0) {
                errors.push(format!(
                    "pool '{}' member '{}' has attempt_timeout_ms: 0; a zero cap fails every attempt instantly — use a positive millisecond value, or omit it to inherit the model's setting",
                    pool_name, member.model
                ));
            }
            // Resolve the member model. `model_protocols` only holds models whose provider
            // resolved (the model loop above skips a model whose provider is unknown), so a bare
            // `!model_protocols.contains_key` lumps two distinct failures under one misleading
            // "unknown model" message: a target that names NO configured model, and a target that
            // DOES name a configured model whose `provider` is unresolvable (already reported by the
            // model loop). Distinguish them with the `model_names` set (every configured model name)
            // so the operator sees the accurate diagnostic — "unknown model" only when the model is
            // genuinely absent, and an unresolvable-provider message that points at the real fault
            // otherwise.
            if let Some(&protocol) = model_protocols.get(member.model.as_str()) {
                // Collect protocol for heterogeneity check (only for fully-resolved members).
                member_protocols.insert(protocol);
            } else if model_names.contains(member.model.as_str()) {
                // The model exists but its provider did not resolve (the model loop already pushed
                // the `references unknown provider` error for it). Emit a member-level message that
                // names the real cause rather than claiming the model is undefined.
                errors.push(format!(
                    "pool '{}' member '{}' references model '{}', which is defined but whose provider is unresolvable; fix that model's provider reference (the model's 'references unknown provider' error is reported separately)",
                    pool_name, member.model, member.model
                ));
            } else {
                errors.push(format!(
                    "pool '{}' references unknown model '{}'",
                    pool_name, member.model
                ));
            }
        }

        // Rule 3: Heterogeneous pool warning (WARN, not error)
        if member_protocols.len() > 1 {
            let mut protocols: Vec<&str> = member_protocols.iter().copied().collect();
            protocols.sort();
            diag_warn!(
                CONFIG_POOL_HETEROGENEOUS,
                pool = %pool_name,
                protocols = %protocols.join("+"),
                "heterogeneous pool: cross-protocol failover translates via the IR and may not preserve all provider features"
            );
        }

        // Rule 6: Validate the per-pool breaker trip parameters. Pathological-but-parseable values
        // produce a breaker that either never protects the backend or trips it open on the first
        // hiccup, defeating the failure-handling guarantee. Reject them at startup (fail-loud).
        if let Some(breaker) = &pool_cfg.breaker {
            // A `base_cooldown_secs: 0` or `max_cooldown_secs: 0` parses fine but yields a degenerate
            // breaker with NO cooldown: when the breaker trips open it would re-admit the failing
            // backend immediately (the cooldown window is zero seconds), defeating the back-off the
            // breaker exists to provide. This is the cooldown-axis twin of the trip.* zero-floor
            // guards below (min_requests/window_s/n >= 1) — reject a zero floor on EITHER cooldown
            // field at boot rather than ship a breaker that never actually pauses the backend. (The
            // inversion check below additionally requires max >= base; the two together pin both
            // fields to >= 1 with max >= base.)
            if breaker.base_cooldown_secs == 0 {
                errors.push(format!(
                    "pool '{}' breaker base_cooldown_secs must be >= 1 (got 0); a zero cooldown re-admits a tripped backend immediately, defeating the breaker's back-off",
                    pool_name
                ));
            }
            if breaker.max_cooldown_secs == 0 {
                errors.push(format!(
                    "pool '{}' breaker max_cooldown_secs must be >= 1 (got 0); a zero cooldown re-admits a tripped backend immediately, defeating the breaker's back-off",
                    pool_name
                ));
            }
            // The escalating cooldown clamps at max_cooldown_secs, so a max below the base would
            // pin every cooldown below the configured base — reject the inversion.
            if breaker.max_cooldown_secs < breaker.base_cooldown_secs {
                errors.push(format!(
                    "pool '{}' breaker max_cooldown_secs ({}) must be >= base_cooldown_secs ({})",
                    pool_name, breaker.max_cooldown_secs, breaker.base_cooldown_secs
                ));
            }
            if let Some(trip) = &breaker.trip {
                // min_requests is the floor below which error-rate trips are suppressed; 0 makes the
                // floor vacuous so a single error in an otherwise-empty window can trip.
                if trip.min_requests == 0 {
                    errors.push(format!(
                        "pool '{}' breaker trip.min_requests must be >= 1 (got 0)",
                        pool_name
                    ));
                }
                // window_s is the sliding-window length; a 0 window holds no outcomes so the
                // count is always below min_requests and the error-rate breaker never trips.
                if trip.window_secs == 0 {
                    errors.push(format!(
                        "pool '{}' breaker trip.window_secs must be >= 1 (got 0)",
                        pool_name
                    ));
                }
                match trip.mode {
                    crate::config::BreakerTripMode::ErrorRate => {
                        // threshold is an error-rate fraction; the rate is capped at 1.0, so a
                        // threshold > 1.0 can never trip and <= 0.0 trips on the first error.
                        if !(trip.threshold > 0.0 && trip.threshold <= 1.0) {
                            errors.push(format!(
                                "pool '{}' breaker trip.threshold must be in (0.0, 1.0] for error_rate mode (got {})",
                                pool_name, trip.threshold
                            ));
                        }
                    }
                    crate::config::BreakerTripMode::Consecutive => {
                        // n is the consecutive-failure streak length; n == 0 makes `streak >= 0`
                        // always true so the lane trips on every evaluation.
                        if trip.consecutive_n == 0 {
                            errors.push(format!(
                                "pool '{}' breaker trip.consecutive_n must be >= 1 for consecutive mode (got 0)",
                                pool_name
                            ));
                        }
                    }
                }
            }
        }

        // Rule 6b: Validate the per-pool failover budget. `failover.timeout_secs == 0` is the exact
        // twin of the `max_concurrent: 0` / breaker `window_s: 0` foot-guns: `RequestCtx::new(0)` sets
        // `deadline = start.saturating_add(0) == start`, and the failover loop checks
        // `request_ctx.expired(now())` at the TOP of the very first (primary) iteration with
        // `now >= deadline`. Because `now()` is read fresh and is always `>= start`, the primary attempt
        // is rejected with a 503 before it runs — the pool serves ZERO requests with no boot diagnostic.
        // Reject it loudly here, mirroring the rest of validate()'s fail-loud invariant. (`cap == 0` is
        // benign: the `0..=cap` loop still runs the primary once, so it is NOT rejected.)
        if let Some(failover) = &pool_cfg.failover {
            if failover.timeout_secs == 0 {
                errors.push(format!(
                    "pool '{}' failover.timeout_secs must be >= 1; a 0 budget rejects the primary attempt before it runs (every request 503s)",
                    pool_name
                ));
            } else if failover.timeout_secs > crate::config::MAX_FAILOVER_DEADLINE_SECS {
                // Upper bound: an operator-controlled `timeout_secs` feeds `RequestCtx::new`, which
                // builds an `Instant` deadline; a value near `u64::MAX` (a plausible extra-zeros typo,
                // syntactically valid YAML) would otherwise overflow that math. 24h is already far
                // beyond any sane per-request failover budget, so fail CLOSED here rather than accept a
                // value that can only be a mistake. (`RequestCtx::new` is also overflow-safe as a
                // belt-and-braces second line of defence.)
                errors.push(format!(
                    "pool '{}' failover.timeout_secs ({}) exceeds the maximum of {} s (24h); a per-request failover budget larger than a day is a fat-finger typo. Lower it to <= {} s",
                    pool_name,
                    failover.timeout_secs,
                    crate::config::MAX_FAILOVER_DEADLINE_SECS,
                    crate::config::MAX_FAILOVER_DEADLINE_SECS
                ));
            }
            // Rule 6c: Each `failover.exclusions` entry is a MEMBER MODEL NAME removed from this
            // pool's candidate set at runtime (the selector benches it; primary and failover never
            // pick it). The exclusions are matched against the pool's member targets, so a misspelled
            // or stale entry (e.g. `betaa` for member `beta`) resolves to nothing and silently fails
            // to bench the member the operator intended — and an exclusion that DOES name a member,
            // applied across every member, empties the pool. Mirror the member-target resolution rule
            // (`member.target` is the candidate name) and fail loud on an exclusion that names no
            // member of THIS pool, the same way Rule 7 catches a dangling fallback-pool reference.
            if let Some(exclusions) = &failover.exclusions {
                let member_targets: HashSet<&str> =
                    pool_cfg.members.iter().map(|m| m.model.as_str()).collect();
                for excluded in exclusions {
                    if !member_targets.contains(excluded.as_str()) {
                        errors.push(format!(
                            "pool '{}' failover.exclusions references '{}', which is not a member of the pool; an exclusion must name one of the pool's members (otherwise it silently benches nothing)",
                            pool_name, excluded
                        ));
                    }
                }
            }
        }

        // Rule 7: A well-formed `on_exhausted: fallback_pool:<name>` whose `<name>` is not a
        // configured pool parses fine but silently misses at runtime (proxy engine's
        // `fallback_pools.get(name)` returns None) and cascades to a generic 503 — the configured
        // degraded-routing policy never engages, with no boot diagnostic. Mirror the member-target
        // resolution check and fail loud.
        //
        // Validate/boot drift: a MALFORMED action string (`OnExhausted::parse` -> Err) dies in
        // main.rs at boot but was previously SILENTLY IGNORED here (`if let Ok(..)`), so `--validate`
        // passed a config boot would reject - the cardinal validate/boot-drift sin. Match main.rs:
        // surface the parse error into `errors` so `--validate` catches it too.
        if let Some(crate::config::OnExhaustedCfg::FallbackPool(target)) = &pool_cfg.on_exhausted {
            {
                {
                    if !cfg.pools.contains_key(target) {
                        errors.push(format!(
                            "pool '{}' on_exhausted references unknown fallback pool '{}'",
                            pool_name, target
                        ));
                    } else if target == pool_name {
                        // Self-referential fallback (pool A -> fallback A): the runtime loop guard
                        // (proxy engine `RequestCtx::visited_pools`) silently terminates the chain on
                        // the re-entry, so the configured degraded-routing policy never actually
                        // engages: A exhausts, "falls back" to itself, is recognised as
                        // already-visited, and 503s. A fallback pointing at its own owner is never
                        // meaningful; reject it at boot rather than ship a self-cancelling policy with
                        // no diagnostic. (This is the length-1 case the general cycle walk below would
                        // also catch, called out explicitly for a precise diagnostic.)
                        errors.push(format!(
                            "pool '{}' on_exhausted references itself as its fallback pool ('{}'); a self-referential fallback never engages (the runtime loop guard terminates it on re-entry) so it 503s exactly as having no fallback would. Point it at a different pool or remove on_exhausted",
                            pool_name, target
                        ));
                    }
                }
            }
        }
        // Rule 7c: `on_exhausted: { queue: { max_ms } }` bounds the queue wait. A `max_ms` of 0 is a
        // no-wait queue (degenerates to reject with extra machinery), and a `max_ms` LONGER than the
        // whole failover budget can never be reached — the wait is already clamped to the remaining
        // budget at runtime (`min(max_ms, budget_remaining)`), so a value above it is a silent
        // dead-letter the operator meant as a real bound. Validate against the RESOLVED per-pool
        // timeout (the pool's own `failover.timeout_secs`, else the global default) — the same value
        // the runtime clamps against — so `--validate` catches both foot-guns with an actionable
        // message rather than shipping a queue that never waits or never reaches its ceiling.
        if let Some(crate::config::OnExhaustedCfg::Queue { max_ms }) = &pool_cfg.on_exhausted {
            let resolved_timeout_secs = pool_cfg
                .failover
                .as_ref()
                .map(|f| f.timeout_secs)
                .unwrap_or(crate::config::DEFAULT_FAILOVER_DEADLINE_SECS);
            let budget_ms = resolved_timeout_secs.saturating_mul(1000);
            if *max_ms == 0 {
                errors.push(format!(
                    "pool '{}' on_exhausted.queue.max_ms must be > 0; a 0 wait never queues (it is just `reject` with extra machinery)",
                    pool_name
                ));
            } else if *max_ms > budget_ms {
                errors.push(format!(
                    "pool '{}' on_exhausted.queue.max_ms ({} ms) exceeds the resolved failover budget ({} s = {} ms); a queue longer than the whole failover budget is clamped to it at runtime and never reaches its ceiling. Lower max_ms to <= {} ms or raise failover.timeout_secs",
                    pool_name, max_ms, resolved_timeout_secs, budget_ms, budget_ms
                ));
            }
        }
        // Any other well-formed action (reject / least_bad) needs no dangling-target check.

        // Rule 8: `affinity.mode` is now an `AffinityMode` enum (`session` is the only variant), so an
        // unrecognized spelling is rejected at deserialize time — no hand-check needed there.
        // `affinity.header_name`, however, becomes an outbound/inbound HTTP HEADER NAME: a non-ASCII
        // or over-long value can't be a valid header field-name (the `http` crate rejects it at
        // header construction), so a bad value would either panic the build or silently disable
        // affinity. Validate it at boot: ASCII only, non-empty, and a sane <= 64-char bound.
        if let Some(affinity) = &pool_cfg.affinity {
            if let Some(header_name) = &affinity.header_name {
                // Non-empty: an empty header name is not a valid HTTP field-name, and it PASSES the
                // ASCII + length checks (`"".is_ascii()` is true, `0 > 64` is false) yet silently
                // disables affinity at runtime (`headers.get("")` is always None) — the exact
                // "silently disable affinity" failure this validator's own comment promises to
                // catch.
                if header_name.is_empty() {
                    errors.push(format!(
                        "pool '{}' affinity.header_name must not be empty (an empty HTTP header field-name silently disables session affinity)",
                        pool_name
                    ));
                }
                if !header_name.is_ascii() {
                    errors.push(format!(
                        "pool '{}' affinity.header_name '{}' must be ASCII (an HTTP header field-name cannot contain non-ASCII bytes)",
                        pool_name, header_name
                    ));
                }
                if header_name.len() > MAX_AFFINITY_HEADER_NAME_LEN {
                    errors.push(format!(
                        "pool '{}' affinity.header_name is {} chars; must be <= {}",
                        pool_name,
                        header_name.len(),
                        MAX_AFFINITY_HEADER_NAME_LEN
                    ));
                }
            }
        }
    }

    // Rule 7b: Multi-hop fallback cycle (A -> B -> A, or any longer ring). The per-pool self-ref
    // check above (Rule 7) only catches the length-1 case; a chain that exits the originating pool
    // and loops back through one or more intermediaries is just as defeated at runtime — proxy engine's
    // `RequestCtx::visited_pools` guard terminates the walk the moment it re-enters an already-visited
    // pool, so the configured degraded-routing policy still collapses into a 503 with no boot
    // diagnostic. Detect it at startup by following each pool's resolved fallback edge until the chain
    // either ends (no on_exhausted / non-fallback action), hits a dangling target (already reported
    // by Rule 7), or revisits a pool. To report each distinct cycle EXACTLY ONCE (a 2-ring would
    // otherwise be reported from both members), emit only when the originating `pool_name` is the
    // lexicographically smallest member of the cycle it sits on.
    for pool_name in cfg.pools.keys() {
        // Walk the fallback chain from this pool, recording the ordered path. Stop at the first
        // repeat (the visited check is the terminator; the chain can be at most `pools.len()` long
        // before it must repeat). Names are owned because the resolved target lives inside the parsed
        // `OnExhausted::FallbackPool(String)`, which does not outlive the parse call.
        let mut path: Vec<String> = Vec::new();
        let mut cursor: String = pool_name.clone();
        loop {
            if path.contains(&cursor) {
                // `cursor` closes a cycle. Identify the cycle's members (from the first occurrence
                // of `cursor` in `path` to the end) and report only if this originating pool is the
                // smallest-named member, so each ring is reported once.
                let start = path.iter().position(|p| *p == cursor).unwrap_or(0);
                let ring = &path[start..];
                let min_member = ring
                    .iter()
                    .min()
                    .map(String::as_str)
                    .unwrap_or(cursor.as_str());
                if pool_name.as_str() == min_member && ring.len() > 1 {
                    let mut display: Vec<&str> = ring.iter().map(String::as_str).collect();
                    display.push(cursor.as_str()); // close the ring visually (A -> B -> A)
                    errors.push(format!(
                        "fallback_pool cycle detected: {}; on_exhausted fallback chains must not loop — the runtime loop guard terminates a cycle on re-entry, so every pool in the ring 503s instead of degrading. Break the cycle (point one pool at a non-looping pool or remove its on_exhausted)",
                        display.join(" -> ")
                    ));
                }
                break;
            }
            // Resolve this pool's fallback edge, if any, before pushing so we can stop cleanly.
            let Some(next) = resolve_fallback_target(cfg, &cursor) else {
                break; // chain ends here (no fallback or non-fallback action)
            };
            path.push(cursor);
            // A dangling target was already reported by Rule 7; do not chase it (it is not a pool).
            if !cfg.pools.contains_key(&next) {
                break;
            }
            cursor = next;
        }
    }

    // Rule (hooks/registry): every entry in the top-level `hooks:` registry is validated once, here.
    // A hook is now a `kind: hook` dlopen PLUGIN (the out-of-process socket/webhook transports are
    // retired), so it must name EXACTLY ONE non-empty `plugin:` reference. The plugin's actual
    // existence + `kind: hook` + trust is resolved against the validated registry at the plugin
    // pre-flight (`plugins_preflight`, the shared boot path) — the same fail-closed check store/auth
    // refs get. Here we enforce the structural requirement (a non-empty reference) and the grant/mode
    // rules below. Rejected at startup, never a silent degrade.
    for (hook_name, hook) in &cfg.hooks {
        if hook.plugin.trim().is_empty() {
            errors.push(format!(
                "hook '{hook_name}' names no plugin: set `module:` to a `kind: hook` plugin's \
                 signed-manifest name or alias"
            ));
        }
        // `prompt: rw` grants the REWRITE arm, which only a GATE can return — a tap is fire-and-forget
        // and never replies, so `rw` on a tap is a config error (it would silently never rewrite).
        if hook.prompt == crate::config::PromptAccess::Rw
            && hook.kind == crate::config::HookKind::Tap
        {
            errors.push(format!(
                "hook '{hook_name}' is a tap with `prompt: rw`, but only a gate can rewrite (a tap \
                 never replies). Use `kind: gate`, or lower to `prompt: ro`."
            ));
        }
        // `default: true` marks the hook as a pool's base ORDERING — but a tap is fire-and-forget and
        // never replies, so it can never order. A default tap is meaningless; reject it (the base
        // must be an ordering gate, or the compiled-in backstop).
        if hook.default && hook.kind == crate::config::HookKind::Tap {
            errors.push(format!(
                "hook '{hook_name}' is a tap with `default: true`, but a tap cannot be a pool's base \
                 ordering (it never replies). Only a gate can be the default."
            ));
        }
    }

    // Rule (hooks/reserved-names): a hook in ANY layer (base config, overlay, or the runtime
    // register API — all three write paths share `config::RESERVED_HOOK_NAMES`) may NOT take a name
    // a built-in answers to or an `on_error` terminal word. Registry uniqueness + the closed
    // `on_error` string union (see the const's doc). A collision is a boot error naming the offender.
    for hook_name in cfg.hooks.keys() {
        if crate::config::RESERVED_HOOK_NAMES.contains(&hook_name.as_str()) {
            errors.push(format!(
                "hook '{hook_name}' uses a reserved name (a built-in ranking strategy, auth module, \
                 or on_error terminal); rename the hook — a hook can never shadow a reserved word"
            ));
        }
    }

    // Rule (hooks/at-most-one-default): AT MOST ONE hook may claim `default: true` — it becomes the
    // base ordering a pool inherits when it names none, REPLACING the compiled-in backstop. Two
    // defaults are ambiguous (which base?), so >1 is a boot error naming every offender. This runs on
    // the resolved config, so it fires at boot AND on every admin apply (the apply path re-resolves +
    // re-validates), closing "add a second default live." 0 defaults ⇒ the compiled-in backstop; the
    // single-default check needs no lower bound.
    {
        let mut defaults: Vec<&str> = cfg
            .hooks
            .iter()
            .filter(|(_, h)| h.default)
            .map(|(name, _)| name.as_str())
            .collect();
        if defaults.len() > 1 {
            defaults.sort_unstable();
            errors.push(format!(
                "more than one hook sets `default: true` ({}); at most one hook may be the default \
                 base ordering",
                defaults.join(", ")
            ));
        }
    }

    // Rule (hooks/pool-ref): every gate a pool names (`hook:` / the non-strategy names in
    // `hooks: [...]`) must reference a registry entry that is a GATE (a tap can't influence
    // routing). Dangling or wrong-kind references are startup errors that name the hook.
    for (pool_name, pool_cfg) in &cfg.pools {
        for hook_name in &pool_cfg.gates {
            match cfg.hooks.get(hook_name) {
                None => errors.push(format!(
                    "pool '{pool_name}' references unknown hook '{hook_name}'; define it under \
                     top-level `hooks:`"
                )),
                Some(h) if h.kind != crate::config::HookKind::Gate => errors.push(format!(
                    "pool '{pool_name}' hook '{hook_name}' is a tap, but a hook named in a pool's \
                     `hooks:` list must be a gate (fire-and-wait); a tap cannot influence routing"
                )),
                Some(_) => {}
            }
        }
    }

    // Rule (hooks/on_error): a hook's `on_error` is a NAME — a reserved terminal (`weighted` |
    // `reject` | `first`), a built-in ranking strategy, or another registry GATE (a fallback
    // chain: when the hook fails, the named fallback fires; if THAT fails, its own on_error
    // chains further). Boot proves every chain TERMINATES: an unknown name, a tap fallback, or a
    // cycle (including self-reference) is a startup error — the safety guarantee that a failing
    // gate always bottoms out on something that cannot fail.
    for (hook_name, hook) in &cfg.hooks {
        let mut visited: Vec<&str> = vec![hook_name.as_str()];
        let mut current: &str = hook.on_error.as_str();
        loop {
            // A reserved terminal ends the chain (weighted/reject/first cannot fail).
            if crate::config::on_error_terminal(current).is_some() {
                break;
            }
            // A built-in ranking strategy is infallible (sync, no I/O) — it terminates the chain.
            // Compiled out (`--no-default-features`), naming one is a boot error, never a silent
            // degrade (the same compliance-by-compilation stance as the pool strategy rule).
            if matches!(
                current,
                crate::config::STRATEGY_CHEAPEST
                    | crate::config::STRATEGY_FASTEST
                    | crate::config::STRATEGY_LEAST_BUSY
                    | crate::config::STRATEGY_USAGE
            ) {
                if cfg!(not(feature = "hooks-ranking")) {
                    errors.push(format!(
                        "hook '{hook_name}' on_error names the built-in ranking strategy \
                         '{current}' but this binary was built WITHOUT the `hooks-ranking` \
                         feature. Rebuild with default features or use nothing|weighted|reject|first."
                    ));
                }
                break;
            }
            if visited.contains(&current) {
                errors.push(format!(
                    "hook on_error chain does not terminate: {} -> {current} is a cycle; every \
                     chain must bottom out on nothing|weighted|reject|first or a ranking strategy",
                    visited.join(" -> ")
                ));
                break;
            }
            let Some(next) = cfg.hooks.get(current) else {
                errors.push(format!(
                    "hook '{hook_name}' on_error names unknown fallback '{current}'; use a \
                     reserved terminal (nothing|weighted|reject|first), a ranking strategy, or another \
                     gate in the `hooks:` registry"
                ));
                break;
            };
            if next.kind != crate::config::HookKind::Gate {
                errors.push(format!(
                    "hook '{hook_name}' on_error fallback '{current}' is a tap; a fallback must \
                     be a gate (fire-and-wait) — a tap cannot decide"
                ));
                break;
            }
            visited.push(current);
            current = next.on_error.as_str();
        }
    }

    // Rule (admin_auth/known-modules): the built-in `admin-tokens` module always resolves; any
    // OTHER name is an EXTERNAL `kind: auth` admin plugin, resolved at LOAD (`open_auth` in
    // `build_app_from_config`, which fails boot on a missing/untrusted/wrong-kind tarball) — exactly
    // as the data plane defers non-builtin `auth.chain` names to the plugin-aware check. This
    // function runs before the plugin registry exists, so it CANNOT tell a genuine admin plugin name
    // from a typo here; a non-builtin name is therefore NOT statically rejected (the load-time gate
    // catches an unresolvable one, fail-closed). A CONFIGURED admin token with the module absent is
    // still rejected by `validate_governance` (a silent admin lockout must be loud).

    // Rule (public_url): busbar's PUBLIC base (top-level `public_url:`) is the origin used to build
    // `/auth/token` links and shown to devs as their BYOK `base_url`. When present it must be an
    // absolute origin — https for a public host (plaintext would expose a login/callback URL on the
    // wire; loopback/private http is allowed for local dev), no path/query/fragment (a bare origin;
    // clients append their own suffix), and never a cloud-metadata host (SSRF).
    if let Some(public_url) = cfg.public_url.as_deref() {
        validate_public_url(public_url, &cfg.blocked_metadata_hosts, &mut errors);
    }

    // Rule (role_bindings): bindings are NESTED BY MODULE. Every module key must appear in
    // an auth chain (a binding under a module that never authenticates is dead config - almost
    // certainly a typo'd module name silently granting nothing); every `admin_scope` must be a
    // known scope token; every `group` must exist in the top-level `groups:` tree; a role name
    // must not shadow the reserved operator principal id.
    if let Some(auth) = cfg.auth.as_ref() {
        // A module is "active" for role-binding purposes if it authenticates on either chain OR is a
        // named login method (`auth.methods`): a method resolves an identity through the exchange,
        // after which its `role_bindings.<module>` grant applies. So a binding under a methods-only
        // module is NOT dead config.
        let chain_modules: std::collections::HashSet<&str> = auth
            .chain
            .iter()
            .chain(auth.admin_auth.iter())
            .map(|e| e.module.as_str())
            .chain(auth.methods.keys().map(String::as_str))
            .collect();

        // Rule (browser_login ⇒ public_url): a method that shows a hosted-login button needs a public
        // base to build its authorize/callback URLs. Any `browser_login` with no `public_url` is a
        // boot error naming BOTH so the operator knows what to add.
        if cfg.public_url.is_none() && auth.methods.values().any(|m| m.browser_login.is_some()) {
            errors.push(
                "auth.methods has a `browser_login` method but top-level `public_url:` is unset; a \
                 hosted login button needs busbar's public base to build the authorize/redirect \
                 URLs — set `public_url: https://<busbar-host>`"
                    .to_string(),
            );
        }

        // Rule (key_ttl): the admin-set default key lifetime must parse (fail boot on garbage rather
        // than silently falling back). Same grammar as the admin `expires_in` duration.
        if let Some(ttl) = auth.key_ttl.as_deref() {
            if let Err(e) = crate::admin::parse_duration_secs(ttl) {
                errors.push(format!("auth.key_ttl '{ttl}' is not a valid duration: {e}"));
            }
        }

        // Rule (auth.policy): the token-mint policy block's duration bounds must parse, and a set
        // default must not exceed a set ceiling. Additive 1.6.0 block; same fail-boot-on-garbage
        // posture as `key_ttl` above (a policy that silently ignores a bad TTL is a policy that
        // isn't a policy). Duration strings share the admin `expires_in` grammar.
        let policy = &auth.policy;
        let parse_policy_ttl = |label: &str, ttl: &str, errors: &mut Vec<String>| -> Option<u64> {
            match crate::admin::parse_duration_secs(ttl) {
                Ok(secs) => Some(secs),
                Err(e) => {
                    errors.push(format!("{label} '{ttl}' is not a valid duration: {e}"));
                    None
                }
            }
        };
        let default_secs = policy
            .default_ttl
            .as_deref()
            .and_then(|t| parse_policy_ttl("auth.policy.default_ttl", t, &mut errors));
        let max_secs = policy
            .max_ttl
            .as_deref()
            .and_then(|t| parse_policy_ttl("auth.policy.max_ttl", t, &mut errors));
        if let (Some(d), Some(m)) = (default_secs, max_secs) {
            if d > m {
                errors.push(format!(
                    "auth.policy.default_ttl ('{}', {d}s) exceeds auth.policy.max_ttl ('{}', {m}s); \
                     the default a mint falls back to cannot be longer than the ceiling",
                    policy.default_ttl.as_deref().unwrap_or(""),
                    policy.max_ttl.as_deref().unwrap_or(""),
                ));
            }
        }
        for (role, ceiling) in &policy.mint_ceilings {
            if let Some(ttl) = ceiling.max_ttl.as_deref() {
                if let Some(c) = parse_policy_ttl(
                    &format!("auth.policy.mint_ceilings.{role}.max_ttl"),
                    ttl,
                    &mut errors,
                ) {
                    // A role's ceiling cannot exceed the block-level `max_ttl` — that would let a
                    // delegated minter outrun the deployment-wide cap it is meant to sit under.
                    if let Some(m) = max_secs {
                        if c > m {
                            errors.push(format!(
                                "auth.policy.mint_ceilings.{role}.max_ttl ('{ttl}', {c}s) exceeds \
                                 auth.policy.max_ttl ({m}s); a per-role ceiling cannot exceed the \
                                 deployment-wide mint ceiling"
                            ));
                        }
                    }
                }
            }
        }
        for (module, roles) in &auth.role_bindings {
            if !chain_modules.contains(module.as_str()) {
                errors.push(format!(
                    "role_bindings names module '{module}', which appears in neither auth.chain \
                     nor auth.admin_auth; a binding under an inactive module grants nothing. \
                     Add the module to the chain, e.g.:\n\n    auth:\n      chain:\n        - \
                     {module}: {{ settings: {{}} }}\n"
                ));
            }
            for (role, binding) in roles {
                if reserved_operator_principal_id(role) {
                    errors.push(format!(
                        "role_bindings.{module} binds role '{role}', which shadows the reserved \
                         operator principal id; choose another role name"
                    ));
                }
                if let Some(scope) = binding.admin_scope.as_deref() {
                    if crate::admin::v1::contract::Scope::parse(scope).is_none() {
                        errors.push(format!(
                            "role_bindings.{module}.{role} has unknown admin_scope '{scope}': \
                             expected read-only or full"
                        ));
                    }
                }
                if let Some(group) = binding.group.as_deref() {
                    if !cfg.groups.contains_key(group) {
                        errors.push(format!(
                            "role_bindings.{module}.{role} names group '{group}', which does not \
                             exist.\nPaste this under groups and set its limits:\n\n    \
                             {group}:\n      limits:\n        - {{ requests: 0, per: minute }}\n"
                        ));
                    }
                }
            }
        }

        // Rule (chain entries/max-scope): every entry's `max_admin_scope` must be a known scope
        // token (typos fail at boot), and `full` - lifting the default read-only ceiling on an
        // external chain - is a LOUD boot warning: it is the explicit opt-in requires.
        for entry in auth.chain.iter().chain(auth.admin_auth.iter()) {
            if let Some(scope) = entry.max_admin_scope.as_deref() {
                // The SAME check the admin named-map write path runs (`Scope::parse_ceiling`), so
                // the API can never accept a ceiling this rule would refuse to boot.
                match crate::admin::v1::contract::Scope::parse_ceiling(
                    &format!("auth chain entry '{}'", entry.module),
                    scope,
                ) {
                    Err(e) => errors.push(e),
                    Ok(crate::admin::v1::contract::Scope::Full) => diag_warn!(
                        CONFIG_AUTH_CHAIN_FULL_SCOPE,
                        module = %entry.module,
                        "auth chain entry grants max_admin_scope: full - principals identified by \
                         this module can hold FULL admin authority (the default ceiling is \
                         read-only); make sure this chain is trusted end to end"
                    ),
                    Ok(_) => {}
                }
            }
            // `token:` is the admin-tokens operator credential; on any other module it is inert
            // and almost certainly a misplaced secret. Fail loud.
            if entry.token.is_some() && entry.module != crate::config::ADMIN_TOKENS_MODULE {
                errors.push(format!(
                    "auth chain entry '{}' sets `token:`, which belongs to the built-in \
                     `admin-tokens` module only; move it, e.g.:\n\n    admin_auth:\n      - \
                     admin-tokens: {{ token: {{ env: BUSBAR_ADMIN_TOKEN }} }}\n",
                    entry.module
                ));
            }
            // (1.5.2 scope collapse: the former sibling-incomparable cross-check is GONE — a
            // two-rung chain {read-only, full} can never be incomparable, so `max_admin_scope` and a
            // bound `admin_scope` are always ordered and `Grants::capped_by` cannot surprise-collapse
            // a binding.)
        }
    }

    // Rule (hooks/global-ref): every name in `global_hooks:` must reference a registry entry.
    for name in &cfg.global_hooks {
        if !cfg.hooks.contains_key(name) {
            errors.push(format!(
                "global_hooks references unknown hook '{name}'; define it under top-level `hooks:`"
            ));
        }
    }

    // Rule (compliance-by-compilation): the non-weighted ranking strategies are the `hooks-ranking`
    // plugin. When it's compiled OUT (`--no-default-features`), a pool `policy: <non-weighted>` is a
    // BOOT ERROR — never a silent degrade to weighted. (Inert in the default build; `weighted` always
    // works — it's the engine's inline SWRR floor, not a plugin.)
    #[cfg(not(feature = "hooks-ranking"))]
    for (pool_name, pool_cfg) in &cfg.pools {
        if pool_cfg.policy != crate::config::PoolPolicy::Weighted {
            errors.push(format!(
                "pool '{pool_name}' names the {:?} ranking strategy but this binary was built \
                 WITHOUT the `hooks-ranking` feature — the built-in ranking strategies are absent. \
                 Rebuild with default features, use `hooks: [weighted]` (or name no strategy), or \
                 reference an external ranking hook.",
                pool_cfg.policy
            ));
        }
    }

    // AN MCP DEPLOYMENT MAY NOT HAVE AN OPEN FRONT DOOR. Refused at BOOT, in one place, because
    // the alternative — a check on the request path — is a second opinion about admission on a
    // plane that already has exactly one owner.
    //
    // What goes wrong is worse than "the endpoint is unauthenticated", and both halves go at once.
    // An empty `auth.chain` is the open front door: `run_chain` returns `Open`, admitting with NO
    // principal. The MCP plane's ENTIRE authorization model is that a caller sees and may call only
    // what its key's grant permits — `tools_for(&grant)`, `resolve(&grant, …)` — and a request that
    // carries no key is never NARROWED by one, so the grant predicate answers `true` for every
    // (kind, value) pair it is asked about. That is not "no access", it is WILDCARD access: every
    // registered server, every approved tool, to anyone who can reach the port.
    //
    // The second half is the transitive one. `upstream::authorise` binds the OUTBOUND credential
    // busbar spends to the INBOUND principal's grant — that binding is the confused-deputy defence
    // for the client direction. With no inbound principal there is no grant to bind to, so the
    // defence has nothing to hold onto and busbar will spend its own upstream credentials on behalf
    // of an anonymous caller.
    //
    // Both properties are therefore vacuous in exactly the configuration where nobody is watching,
    // and neither failure is visible from the outside: the deployment answers every request
    // perfectly, which is the problem. So `mcp:` present and no data-plane chain is a config ERROR
    // and the process does not start.
    //
    // NOT "serve anonymous callers an empty catalogue". That looks safe and is not: it is safe only
    // for as long as nothing ever grants by default, and the day a default grant is introduced —
    // for any reason, anywhere else — an anonymous caller silently inherits it. The refusal is
    // about the CONFIGURATION being unstatable, which does not decay.
    // An endpoint plane present with no data-plane auth chain is refused. Read the endpoint through
    // the neutral SECTION-KEYED accessor and name the plane from its REGISTERED decl (`subject_noun`),
    // so this neutral rule carries no plane token: the concrete noun ("MCP server", …) is
    // registry-supplied at runtime, never a literal here.
    let endpoint_section = crate::config::named_map::NamedMapSection::Tools.key();
    if cfg.endpoint_resource(endpoint_section).is_some()
        && cfg.auth.as_ref().is_none_or(|a| a.chain.is_empty())
    {
        // The config KEY and the noun are BOTH registry-supplied at runtime (`PlaneDecl.key` /
        // `.subject_noun`) — the endpoint plane's own vocabulary — so this neutral rule carries no
        // plane token literal while the error still names the exact `<key>:` block and `auth.chain`
        // the operator must fix.
        let decl = crate::plane::registry::plane_decl_for_config_section(endpoint_section);
        let key = decl.map(|d| d.key).unwrap_or("endpoint");
        let noun = decl.map(|d| d.subject_noun).unwrap_or("endpoint");
        errors.push(format!(
            "`{key}:` is configured but auth.chain is empty, which serves the {noun} endpoint to \
             ANONYMOUS callers — and a request that carries no key is never narrowed by one, so it \
             runs with WILDCARD grants over every registered subject on that plane. It also leaves \
             `upstream::authorise` with no inbound grant to bind busbar's outbound credentials to. \
             Close the data-plane chain (`auth: {{ chain: [keys] }}`, or an IdP auth plugin), or \
             remove the `{key}:` block if this deployment is not a {noun}."
        ));
    }

    // Rule 5: Validate auth-block semantics. `auth.chain` is an ordered list of MODULE ENTRIES +
    // `upstream_credentials` a snake_case enum. `AuthCfg` is `deny_unknown_fields`, so the removed
    // 1.4.x keys (`client_tokens:`, `modules:`) fail AT PARSE with serde's "unknown field" - a
    // loud clean-break boot error, no validate-time check needed.
    if let Some(auth) = &cfg.auth {
        // Every module named in the data-plane chain must resolve to EITHER the built-in `keys`
        // module OR a loadable `kind: auth` plugin. This function runs before the plugin registry
        // exists (see this module's own doc + `preflight_plugins_and_secrets`'s doc comment: "the
        // plugin pre-flight... cannot run until the registry exists"), so it CANNOT tell a genuine
        // plugin name from a typo at this point — only `main.rs`'s post-resolve
        // `auth_plugin_refs`/registry check (run right after this) can. Only the names this function
        // CAN judge without registry access are handled here: `keys` passes, and the specific
        // REMOVED 1.4.x names get an immediate, precise migration error (no need to wait for a
        // registry lookup to know `tokens`/`static-tokens` will never resolve to a plugin). Every
        // other name is deferred to the plugin-aware check, not rejected here — an earlier version
        // of this rule hard-rejected every non-`keys` name unconditionally, which meant NO `kind:
        // auth` plugin (auth-oidc included) could ever pass config_validate, since this check ran
        // first and always lost before the plugin-aware one got a chance. FAIL-CLOSED is still
        // preserved: an unresolvable name still hard-fails, just at the check that can actually
        // tell whether it resolves.
        for entry in &auth.chain {
            let name = entry.module.as_str();
            if name == "tokens" || name == "static-tokens" {
                errors.push(format!(
                    "auth.chain names '{name}': the static-token allowlist module was REMOVED \
                     in 1.5.0. Data-plane auth is `keys` (busbar-signed keys, minted via \
                     POST /api/v1/admin/keys) and IdP auth plugins - write:\n\n    auth:\n      \
                     chain:\n        - keys\n"
                ));
            }
        }
        // 1.5.1: busbar NO LONGER auto-generates a signing key at boot (the 1.5.0 behavior
        // wrote `busbar-signing.key` beside the config, which boot-looped a read-only config mount
        // with a misleading Permission-denied). When the deployment actually VERIFIES busbar-signed
        // keys - the built-in `keys` module is in the data-plane chain - `auth.signing_key` is
        // REQUIRED. Fail CLOSED here (at `--validate`/boot) with an actionable message instead of a
        // runtime failure. A deployment that never puts `keys` in the chain issues no signed tokens
        // and needs no signing key.
        let verifies_signed_keys = auth
            .chain
            .iter()
            .any(|e| e.module == crate::config::KEYS_MODULE);
        if verifies_signed_keys && auth.signing_key.is_none() {
            errors.push(
                "auth.signing_key is required for signed-token auth (auth.chain names the \
                 built-in `keys` verifier), but none is set - and busbar no longer auto-generates \
                 one. Generate a key with `busbar --generate-signing-key`, then set auth.signing_key \
                 to a secret reference for it ({file: /path} or {env: VAR} - a SHARED secret across \
                 nodes for a fleet)."
                    .to_string(),
            );
        }
        // MINT-PATH rule (1.5.2): the `keys` verifier authenticates busbar-MINTED virtual keys, and a
        // vkey can ONLY be issued through an admin endpoint. So if `auth.chain` names `keys` but no
        // USABLE ADMIN MINT PATH exists, no key could ever be minted and the data plane would reject
        // EVERY request (a sealed data plane). Fail CLOSED here (fail-fast) rather than boot into a
        // deployment that 401s everything. STRUCTURAL check (validate runs before secrets resolve):
        // see `AuthCfg::usable_mint_path`. An explicit OPEN admin (`admin_auth: []`) counts as a mint
        // path but is dev-only — WARN that anyone can mint. `oidc`/plugin chains never set
        // `keys_in_chain`, so they never trigger this (their identities are externally issued).
        if verifies_signed_keys && !auth.usable_mint_path() {
            errors.push(
                "auth.chain names the built-in `keys` verifier but no admin credential can mint one \
                 — the data plane would reject every request. Configure auth.admin_auth (an \
                 `admin-tokens` entry with a `token:`, or an admin module granting `mint`/`full`), \
                 or remove `keys` from auth.chain."
                    .to_string(),
            );
        }
        if verifies_signed_keys && auth.admin_auth.is_empty() {
            diag_warn!(
                CONFIG_OPEN_ADMIN_MINT,
                "auth.chain names `keys` and auth.admin_auth is explicitly empty (open admin) — \
                 ANYONE can mint virtual keys through the admin API. Acceptable only for dev."
            );
        }
        // `upstream_credentials: passthrough` with a NON-EMPTY configured api_key on a provider is a
        // configuration foot-gun: under passthrough the configured key is NEVER forwarded - the
        // caller's own credential (or an empty one) goes upstream. WARN (not hard-reject): a legit
        // Bedrock-ingress passthrough provider signs per-request via SigV4 and needs no static key.
        // 1.5.3: the mode moved off `auth:` onto the `pools:` section — the all-pools
        // default plus any per-pool override. The warning fires if ANY of them is `passthrough`.
        let any_passthrough = cfg.upstream_credentials == crate::auth::UpstreamCreds::Passthrough
            || cfg
                .pools
                .values()
                .any(|p| p.upstream_credentials == Some(crate::auth::UpstreamCreds::Passthrough));
        if any_passthrough {
            for (provider_name, provider_cfg) in &cfg.providers {
                let resolved_key =
                    crate::config::secret::resolve_builtin_string(&provider_cfg.api_key)
                        .unwrap_or_default();
                if !resolved_key.trim().is_empty() {
                    diag_warn!(
                        CONFIG_PASSTHROUGH_UNUSED_APIKEY,
                        provider = %provider_name,
                        api_key = %provider_cfg.api_key.describe(),
                        "upstream_credentials: passthrough with a NON-EMPTY configured api_key for \
                         this provider: under passthrough the upstream key is \
                         caller_token.unwrap_or(\"\"), so the configured api_key is NEVER forwarded \
                         (a caller presents their own token, or an unauthenticated caller forwards an \
                         empty credential the provider rejects). The configured key is inert dead \
                         config. If you intended static-key gating, use upstream_credentials: own \
                         (plus an auth chain); otherwise clear the referenced secret (a passthrough \
                         provider that signs each request per-call needs no static key)."
                    );
                }
            }
        }
    }

    // Operational-limit sanity checks (NEVER CODED CAPS). A 0 or absurd value here would break the
    // gateway rather than tune it; reject loudly at boot. Deliberately permissive — only the few
    // values where 0/absurd is a foot-gun are constrained (e.g. `max_inbound_concurrent` accepts ANY
    // usize incl. 0, the explicit unlimited posture — the DEFAULT is 8192, not 0).
    validate_limits(&cfg.limits, &mut errors);

    // PER-INSTANCE webhook bounds (1.5.3): `export:` holds NAMED instances, each with its own
    // `delivery_timeout_secs`, so this check runs once per configured sink rather than once over a
    // single process-global value that could only ever describe one of them.
    for (i, w) in cfg.export.request_log_webhooks.iter().enumerate() {
        if w.delivery_timeout_secs < 1 {
            errors.push(format!(
                "the `module: request-log-webhook` export instance targeting '{}' (#{i}) sets \
                 settings.delivery_timeout_secs: 0, which would abort every delivery — it must be \
                 >= 1",
                w.url
            ));
        }
    }

    // A model maps to ONE lane, so its `context_max` must be single-valued across every pool that
    // names it. `build_app_from_config` (boot) rejects a genuine conflict — mirror that here so a
    // clean `--validate` truly implies a clean boot (a conflict would otherwise pass validation and
    // then `die` at real boot). Only DIFFERING explicit values conflict; None/identical are fine.
    {
        let mut seen: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        for pool_cfg in cfg.pools.values() {
            for m in &pool_cfg.members {
                if let Some(c) = m.context_max {
                    match seen.get(m.model.as_str()) {
                        Some(existing) if *existing != c => {
                            errors.push(format!(
                                "model '{}' has conflicting context_max across pools ({} vs {}); a model maps to one lane and must declare a single context_max",
                                m.model, existing, c
                            ));
                        }
                        _ => {
                            seen.insert(m.model.as_str(), c);
                        }
                    }
                }
            }
        }
    }

    // The cost/groups/store/secret surface - the redistributed pieces of the
    // dissolved 1.4.x governance block, now first-class on the resolved config.
    validate_cost_model(cfg, &mut errors);

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Range-check the resolved operational limits. Pushes a message per violation (collect-all, like the
/// rest of `validate`). The bounds are intentionally loose: each default is the production working
/// value, so we only reject values that would make a subsystem non-functional.
fn validate_limits(limits: &crate::config::LimitsResolved, errors: &mut Vec<String>) {
    use crate::config::{REQUEST_BODY_MAX_BYTES_CEIL, REQUEST_BODY_MAX_BYTES_FLOOR};

    // Timeouts must be >= 1s — a 0s timeout fires instantly and breaks the path it guards.
    if limits.upstream_request_timeout_secs < 1 {
        errors.push(
            "limits.upstream_request_timeout_secs must be >= 1 (0 would time out every upstream call \
             instantly)"
                .to_string(),
        );
    }
    if limits.tls_handshake_timeout_secs < 1 {
        errors.push(
            "limits.tls_handshake_timeout_secs must be >= 1 (0 would abort every TLS handshake)"
                .to_string(),
        );
    }
    if limits.request_body_read_timeout_secs < 1 {
        errors.push(
            "limits.request_body_read_timeout_secs must be >= 1 (0 would abort every request whose \
             body is not instantly buffered)"
                .to_string(),
        );
    }
    if limits.max_inflight_webhook_deliveries < 1 {
        errors.push(
            "export.request-log-webhook.settings.max_inflight_deliveries must be >= 1 (a 0-permit \
             semaphore admits nothing, silently dropping every webhook delivery)"
                .to_string(),
        );
    }
    // The webhook exporter seeds a `Semaphore::new(max_inflight_webhook_deliveries())` with no other
    // upper bound — see `MAX_SEMAPHORE_PERMITS`'s doc comment for why this is the panic
    // precondition, not a policy opinion.
    if limits.max_inflight_webhook_deliveries > MAX_SEMAPHORE_PERMITS {
        errors.push(format!(
            "export.request-log-webhook.settings.max_inflight_deliveries must be <= \
             {MAX_SEMAPHORE_PERMITS} (tokio::sync::Semaphore's hard permit ceiling — a value above \
             it panics at build time instead of failing validation)"
        ));
    }
    // The honored-Retry-After ceiling and hard-down cooldown must be >= 1s to be meaningful.
    if limits.max_honored_retry_after_secs < 1 {
        errors.push(
            "limits.max_honored_retry_after_secs must be >= 1 (a 0 ceiling would clamp every honored \
             Retry-After to 0)"
                .to_string(),
        );
    }
    if limits.hard_down_cooldown_secs < 1 {
        errors.push(
            "limits.hard_down_cooldown_secs must be >= 1 (a 0 sticky cooldown would re-ready a \
             hard-down lane immediately)"
                .to_string(),
        );
    }
    // Request-body cap: too small rejects legitimate requests; absurdly large is a memory foot-gun
    // (the body is buffered per request). Bound it to a sane window.
    if limits.request_body_max_bytes < REQUEST_BODY_MAX_BYTES_FLOOR {
        errors.push(format!(
            "limits.request_body_max_bytes ({}) is below the {REQUEST_BODY_MAX_BYTES_FLOOR}-byte floor \
             — too small to admit a minimal request",
            limits.request_body_max_bytes
        ));
    }
    if limits.request_body_max_bytes > REQUEST_BODY_MAX_BYTES_CEIL {
        errors.push(format!(
            "limits.request_body_max_bytes ({}) exceeds the {REQUEST_BODY_MAX_BYTES_CEIL}-byte ceiling \
             — the body is buffered per request, so this risks memory exhaustion",
            limits.request_body_max_bytes
        ));
    }
    // The error-body buffer cap must be >= 1 byte (0 would buffer nothing, losing every upstream
    // error body). The pool-idle, gauge-limit, and probe defaults are all safe at any value (0
    // pool-idle = no keep-alive; 0 gauge limit = emit none). `advanced.rate_sweep_interval == 0` is
    // rejected separately in `validate_governance` — a 0 there would disable the rate-map eviction
    // sweep, so it is a hard error rather than a silently-accepted default.
    if limits.upstream_error_body_max_bytes < 1 {
        errors.push(
            "limits.upstream_error_body_max_bytes must be >= 1 (0 would buffer no upstream error body)"
                .to_string(),
        );
    }
    // The translation-injected max_tokens fallback must be > 0 (a 0 is rejected upstream). This is the
    // GLOBAL fallback; the per-model `default_max_tokens: 0` case is already rejected in the model loop.
    if limits.default_max_tokens < 1 {
        errors.push(
            "limits.default_max_tokens must be >= 1 (0 would be injected verbatim and rejected upstream)"
                .to_string(),
        );
    }
    // SQLite busy_timeout must be >= 0 (the SQLite backend rejects negative). 0 means "fail immediately on lock"
    // — degraded but not broken, so only reject a negative value.
    // Probe fallbacks: the prober floors them at 1 at use, but a 0 here signals operator confusion;
    // reject so the config is honest about what runs.
    if limits.default_probe_interval_secs < 1 {
        errors.push("health.default_probe_interval_secs must be >= 1".to_string());
    }
    if limits.default_probe_timeout_secs < 1 {
        errors.push("health.default_probe_timeout_secs must be >= 1".to_string());
    }
    if limits.default_policy_timeout_ms < 1 {
        errors.push(
            "routing.default_policy_timeout_ms must be >= 1 (0 would make every policy decision time \
             out instantly)"
                .to_string(),
        );
    }
    // A 0 sweep interval would disable the rate-map's idle-entry eviction sweep entirely - it
    // rides on the non-obvious `u32::is_multiple_of(0) == false`, so the sweep never fires and
    // entries for silent keys stay resident until restart. Reject it fail-loud.
    if limits.rate_sweep_interval == 0 {
        errors.push(
            "advanced.rate_sweep_interval is 0; must be >= 1. A value of 0 disables the rate-map \
             idle-entry sweep, leaking entries for silent keys until restart. The default is 256 \
             (sweep every 256 admissions); use a larger value to make sweeps rarer."
                .to_string(),
        );
    }
    // NOTE: `max_inbound_concurrent` is intentionally UNCONSTRAINED — any usize including 0 (the
    // explicit unlimited posture; the DEFAULT is 8192, not 0) is valid, EXCEPT for the
    // `Semaphore::new` panic ceiling below: `apply_inbound_concurrency_limit` (main.rs) wraps the
    // router in a `limits::admission::InboundAdmissionLayer::new(max_inbound_concurrent)` whenever
    // the value is `> 0`, and that layer's `AdmissionGate` calls `Semaphore::new` internally with no
    // bound of its own. See `MAX_SEMAPHORE_PERMITS`'s doc comment.
    if limits.max_inbound_concurrent > MAX_SEMAPHORE_PERMITS {
        errors.push(format!(
            "limits.max_inbound_concurrent must be <= {MAX_SEMAPHORE_PERMITS} (tokio::sync::\
             Semaphore's hard permit ceiling — a value above it panics at build time instead of \
             failing validation), or 0 to disable the inbound-concurrency layer entirely"
        ));
    }
}

// NOTE: a long doc comment used to sit here describing a BLANK-ADMIN-TOKEN boot
// guard validated at this layer. The function it documented is gone — the admin token became a
// SecretRef, so its VALUE is not visible to this (pre-resolution) validation pass at all. The guard
// itself now lives where the value exists: `main::resolve_admin_token`, which refuses an
// empty/whitespace-only resolved token on boot AND on every apply/reload. It is also stricter than
// the old prose: a blank token does not merely lock the admin API, it computes the digest over the
// blank string, so an empty presented credential would authenticate as the operator.

/// Validate the COST + GROUPS + STORE + SECRETS surface of the resolved config:
/// rate_card completeness/wellformedness, the `groups:` limit tree (parents exist, chain acyclic —
/// any depth, the cycle check is the bound; limit values sane), `per_request_fee` sanity, the store
/// module reference, and every
/// secret reference's MODULE resolvability. Paste-ready stubs throughout. Pure - shared verbatim
/// by boot and `--validate` so the two cannot drift.
fn validate_cost_model(cfg: &RootCfg, errors: &mut Vec<String>) {
    if let Some(card) = &cfg.rate_card {
        // Well-formed rates: every tier finite and >= 0 (names the exact config path).
        for (model, r) in card {
            for (tier, v) in [
                ("input_utok", r.input_utok),
                ("output_utok", r.output_utok),
                ("cache_read_utok", r.cache_read_utok),
                ("cache_write_utok", r.cache_write_utok),
            ] {
                if !v.is_finite() || v < 0.0 {
                    errors.push(format!(
                        "rate_card['{model}'].{tier} must be a finite, non-negative \
                         number of micro-units per token (got {v})"
                    ));
                }
            }
        }
        // COMPLETENESS (all-or-nothing): rate_card present => EVERY configured model (by CONFIG
        // name - two providers serving one upstream are two `models:` entries with two card
        // entries) has an entry, or boot/--validate FAIL with a COPY-PASTEABLE zeroed stub of
        // exactly the missing models.
        let mut model_names: Vec<&String> = cfg.models.keys().collect();
        model_names.sort();
        let missing: Vec<&str> = model_names
            .iter()
            .filter(|name| !card.contains_key(name.as_str()))
            .map(|name| name.as_str())
            .collect();
        if !missing.is_empty() {
            let width = missing.iter().map(|m| m.len()).max().unwrap_or(0) + 1;
            let stub: String = missing
                .iter()
                .map(|m| {
                    format!(
                        "    {:width$} {{ input_utok: 0, output_utok: 0, cache_read_utok: 0, cache_write_utok: 0 }}\n",
                        format!("{m}:"),
                        width = width
                    )
                })
                .collect();
            errors.push(format!(
                "rate_card is present but {} configured model{} no rate entry (rate_card is \
                 AUTHORITATIVE and COMPLETE: you either price nothing or price everything).\n\
                 Paste these under rate_card and fill in your rates (micro-units per token):\n\n{stub}",
                missing.len(),
                if missing.len() == 1 { " has" } else { "s have" },
            ));
        }
        // Card entries for models that do not exist are dead config - almost always a typo of a
        // real model name. Fail loud (the completeness stub above covers the other direction).
        for model in card.keys() {
            if !cfg.models.contains_key(model) {
                errors.push(format!(
                    "rate_card names model '{model}', which is not defined under models: \
                     (a rate entry is keyed by the CONFIG model name); remove it or fix the name"
                ));
            }
        }
    }

    if cfg.per_request_fee < 0 {
        errors.push(format!(
            "per_request_fee must be >= 0 (got {}); a negative fee would credit every request",
            cfg.per_request_fee
        ));
    }

    // groups: parents exist, chain acyclic — any depth, the cycle check is the bound (shared
    // with the parse-time module), plus
    // value-level checks the tree walk does not cover.
    crate::config::groups::validate_groups(&cfg.groups, &|p| cfg.pools.contains_key(p), errors);
    for (name, g) in &cfg.groups {
        for limit in &g.limits {
            if limit.amount == 0 {
                errors.push(format!(
                    "groups.{name} has a `{}` limit of 0, which rejects every request through the \
                     group from the first admission; set a positive amount, or set `enabled: \
                     false` to freeze the group explicitly",
                    limit.metric.as_str()
                ));
            }
        }
    }

    // store: the module name must be non-empty; a non-memory module additionally requires the
    // plugin subsystem (checked with the registry in `plugins_preflight`, the shared boot path).
    if let Some(store) = &cfg.store {
        if store.module.trim().is_empty() {
            errors.push(
                "store.module must be non-empty; use `memory` (the compiled-in RAM store) or a \
                 store plugin name/alias (sqlite | postgres | valkey | <third-party>)"
                    .to_string(),
            );
        }
    }

    // SECRET REFERENCES: every secret's MODULE must be resolvable BY NAME. The built-ins are
    // `env` and `file`; ANY OTHER module name is a `kind: secret` PLUGIN reference (vault, aws-sm,
    // …), which is the marquee 1.5.0 "secrets are plugins" feature. Whether such a plugin actually
    // exists + is `kind: secret` + is trusted is resolved against the plugin REGISTRY — but this
    // function runs at boot AND `--validate` BEFORE the plugin pre-flight builds that registry, and
    // captures none, so it CANNOT tell an installed vault plugin from a typo. Therefore the
    // module-EXISTENCE check for a non-built-in module is DEFERRED to the shared plugin pre-flight
    // (`validate_secret_refs`, called from `plugins_preflight`'s two call-sites) — the SAME deferral
    // the `store.module` plugin reference already uses (a non-`memory` store is only checked once the
    // registry exists). Here we validate ONLY the STRUCTURE that is checkable without the registry:
    // the built-in `env`/`file` modules' required settings. The VALUE is never resolved here (CI
    // validates config structure without secrets present); resolution failures are boot-time
    // fail-closed errors.
    let mut check_secret = |what: String, r: &crate::config::SecretRef| {
        // The built-in `env`/`file` modules need a NON-EMPTY key/path. The `{ env: "" }` /
        // `{ file: "" }` sugar already rejects an empty value in the deserializer
        // (secret-ref/src/lib.rs), but the CANONICAL `{ module: env, settings: { key: "" } }` form
        // bypasses that arm — `env_var()`/`file_path()` return `Some("")`, not `None`. Left
        // unchecked, such a config passes `--validate` as "ok" then fail-closes at boot
        // (`std::env::var("")` → Err), so a clean validate would no longer imply a clean boot.
        // Reject both the MISSING and the EMPTY cases here, mirroring the sugar check.
        if r.module == crate::config::secret::SECRET_MODULE_ENV {
            match r.env_var() {
                None => errors.push(format!(
                    "{what}: secret module 'env' requires settings.key (the environment variable \
                     name)"
                )),
                Some(v) if v.trim().is_empty() => errors.push(format!(
                    "{what}: secret module 'env' requires a NON-EMPTY settings.key (the \
                     environment variable name)"
                )),
                Some(_) => {}
            }
        } else if r.module == crate::config::secret::SECRET_MODULE_FILE {
            match r.file_path() {
                None => errors.push(format!(
                    "{what}: secret module 'file' requires settings.path (the file to read)"
                )),
                Some(v) if v.trim().is_empty() => errors.push(format!(
                    "{what}: secret module 'file' requires a NON-EMPTY settings.path (the file to \
                     read)"
                )),
                Some(_) => {}
            }
        }
        // A non-built-in module name (a `kind: secret` plugin reference) is NOT rejected here: its
        // existence is proven against the registry in `validate_secret_refs` at plugin pre-flight.
    };
    // Enumerate EVERY secret reference in the config through ONE shared walk (`secret_refs`), so the
    // structural check here and the registry-backed module-existence check at plugin pre-flight
    // (`validate_secret_refs`) can never drift over WHICH refs they cover.
    for (what, r) in secret_refs(cfg) {
        check_secret(what, r);
    }

    // secrets (module-level `open()` config for `kind: secret` plugins): the built-in `env` / `file`
    // modules take NO module config, so naming them under `secrets:` is a mistake (their settings live
    // per-reference). A non-built-in module additionally requires the plugin subsystem, which the
    // shared `plugins_preflight` verifies against the registry at boot.
    for module in cfg.secrets.keys() {
        if matches!(
            module.as_str(),
            crate::config::secret::SECRET_MODULE_ENV | crate::config::secret::SECRET_MODULE_FILE
        ) {
            errors.push(format!(
                "secrets.{module}: the built-in '{module}' secret module takes no module-level \
                 config; its settings (`key` / `path`) belong on each individual secret reference, \
                 not in the top-level `secrets:` block"
            ));
        }
    }

    // ADMIN-TOKENS availability: a configured admin token with the module compiled OUT would
    // silently disable the admin API (the chain all-Passes) - a silent lockout must be a loud
    // boot error instead.
    #[cfg(not(feature = "auth-admin-tokens"))]
    if cfg
        .auth
        .as_ref()
        .and_then(|a| a.admin_token_ref())
        .is_some()
    {
        errors.push(
            "an admin-tokens token is configured but this binary was built WITHOUT the \
             `auth-admin-tokens` feature — the admin API would be silently disabled. Rebuild with \
             default features or wire an external admin auth module."
                .to_string(),
        );
    }
}

/// The native-API root SEGMENT — `api`, derived from the ONE constant the auth middleware
/// classifies admin requests with ([`crate::auth::ADMIN_PATH`] = `/api`), never a copied literal.
/// This is what keeps [`reserved_admin_name`] and the middleware's `is_admin` boundary from
/// drifting: the drift this replaces is exactly what let a lane named `api` pass validation while
/// the middleware routed `/api/v1/messages` to the admin surface.
fn admin_root_segment() -> &'static str {
    crate::auth::ADMIN_PATH.trim_start_matches('/')
}

/// True when a `role_bindings` role name would shadow the built-in operator PRINCIPAL ID (`admin`,
/// the id the `admin-tokens` module mints — [`busbar_auth_admin_tokens::ADMIN_TOKENS_PRINCIPAL_ID`]).
///
/// A DIFFERENT reservation from [`reserved_admin_name`], and split from it deliberately: that one
/// guards a URL path SEGMENT (`api`), this one guards an identity string (`admin`). They shared one
/// literal only by the coincidence that the admin path used to be `/admin` too; when the path moved
/// to `/api` a single shared check would have silently moved the principal-id reservation to `api`
/// as well. With `auth-admin-tokens` compiled out there is no operator principal to shadow, so
/// nothing is reserved.
fn reserved_operator_principal_id(role: &str) -> bool {
    #[cfg(feature = "auth-admin-tokens")]
    {
        role == busbar_auth_admin_tokens::ADMIN_TOKENS_PRINCIPAL_ID
    }
    #[cfg(not(feature = "auth-admin-tokens"))]
    {
        let _ = role;
        false
    }
}

/// True when a pool / provider / model `name` would collide with the built-in native-API operator
/// surface (`/api`, the admin plane's root).
///
/// The auth middleware (`auth::auth_middleware`) classifies a request as admin with the
/// PATH-BOUNDARY-SAFE test `path == ADMIN_PATH || path.starts_with(ADMIN_PATH_PREFIX)` where
/// `ADMIN_PATH == "/api"` — deliberately NOT a bare `starts_with("/api")`, so sibling names like
/// `apix` are NOT admin. A pool/model name lands as a path SEGMENT (`/<name>/v1/messages`) and a
/// provider name as the first segment of the adhoc route (`/<provider>/<model>/v1/messages`), so a
/// name collides with the admin surface IFF its first `/`-segment is exactly that root segment
/// (`api`). Derived from [`admin_root_segment`] rather than a literal so it can never again name a
/// segment the middleware no longer uses (it used to guard `admin`, long after the admin surface
/// moved to `/api` — the exact drift a customer's `api` pool would have walked through). A name
/// containing a `/` could also smuggle an `api/` first segment, so the first-segment test covers
/// that family too.
fn reserved_admin_name(name: &str) -> bool {
    name.split('/').next() == Some(admin_root_segment())
}

/// Resolve the single `on_exhausted: fallback_pool:<name>` edge out of `pool_name`, if it has one.
/// UNIFIED `pools:` GLOBAL-NAME VALIDATOR (1.6.0). The neutral `pools:` map infers a pool's kind
/// from its members and resolves every member by NAME ALONE. That is sound only when names are
/// globally unique, so this refuses:
///
/// 1. A name defined in TWO nouns (`models:`/`tools:`/`agents:`) — kind inference could not decide
///    which plane a member of that name belongs to, and the router would silently pick one.
/// 2. A POOL name that collides with a member/registration name on the same keyspace — already
///    partly covered for models above; here it is extended to the MCP/A2A nouns.
///
/// (Homogeneity — all of a pool's members being one noun — and unresolvable members are enforced at
/// resolution, in `config::resolve`, where the members are still visible before projection; this
/// function is the name-uniqueness half that makes that inference unambiguous.)
fn validate_unified_pool_names(cfg: &RootCfg, errors: &mut Vec<String>) {
    use std::collections::BTreeSet;
    let models: BTreeSet<&str> = cfg.models.keys().map(|s| s.as_str()).collect();
    // The plane registry nouns read through their always-present type-erased seam. With the owning
    // plane compiled out the seam holds a `RawPlaneSection`, whose `def_names` is empty (a present
    // section is refused at resolve), so no name resolves there — the same answer the per-plane
    // feature gate gave, without naming a plane.
    let tools: BTreeSet<&str> = cfg.tool_defs.def_names().into_iter().collect();
    let agents: BTreeSet<&str> = cfg.agent_defs.def_names().into_iter().collect();

    // (1) No name may be defined in two nouns — the kind of a bare member must be decidable by name.
    for (a, b, name_a, name_b) in [
        (&models, &tools, "models", "tools"),
        (&models, &agents, "models", "agents"),
        (&tools, &agents, "tools", "agents"),
    ] {
        for dup in a.intersection(b) {
            errors.push(format!(
                "`{dup}` is defined in both the top-level `{name_a}:` and `{name_b}:` maps. Pool \
                 member names are resolved by name alone (a pool's kind is inferred from its \
                 members), so a name may live in at most ONE noun. Rename one of them."
            ));
        }
    }

    // (2) A pool name must not collide with a registration name on the plane it routes to (the pool
    // and the registration share the breaker keyspace). Cross-checked against every noun, since a
    // single neutral `pools:` map is not scoped by kind.
    for pool_name in cfg
        .pools
        .keys()
        .chain(cfg.tool_pools.keys())
        .chain(cfg.agent_pools.keys())
    {
        for (set, noun) in [(&tools, "tools"), (&agents, "agents")] {
            if set.contains(pool_name.as_str()) {
                errors.push(format!(
                    "pool name '{pool_name}' conflicts with a `{noun}:` registration of the same \
                     name; a pool and a registration share the failover breaker keyspace, so their \
                     names must be distinct. Rename the pool."
                ));
            }
        }
    }
}

/// Returns `Some(target)` only for a well-formed FallbackPool action; `None` for a pool with no
/// `on_exhausted`, a non-fallback action (reject/least_bad), or an unparseable action (already
/// rejected elsewhere at parse time). The returned name is owned because it lives inside the parsed
/// `OnExhausted` value, which does not outlive this call. Used by the Rule 7b fallback-cycle walk.
fn resolve_fallback_target(cfg: &RootCfg, pool_name: &str) -> Option<String> {
    match cfg.pools.get(pool_name)?.on_exhausted.as_ref()? {
        crate::config::OnExhaustedCfg::FallbackPool(target) => Some(target.clone()),
        _ => None,
    }
}

/// Extract the connect host from a `base_url`, normalized the SAME way the connecting stack
/// (reqwest's `url` crate + glibc getaddrinfo) sees it: scheme stripped, backslashes folded to
/// forward slashes, authority isolated, userinfo dropped, port removed (IPv6 brackets handled),
/// percent-decoded, and a single trailing FQDN-root dot removed. Lowercasing for comparison is left
/// to the caller; the returned string preserves original case but with the above normalizations
/// applied. `None` when the scheme is not http/https or the host is empty.
///
/// Centralizing this means the SSRF metadata check and the private/loopback scheme classifier both
/// reason over the EXACT host the connecting stack will, so neither can be bypassed by an authority
/// trick (backslash, userinfo flip, percent-encoded dots, trailing dot) that only one of them
/// normalized away.
/// `url`'s scheme equals `scheme`, compared CASE-INSENSITIVELY per RFC 3986 §3.1 — the same guard
/// `observability::scheme_is` uses for webhook URLs. A raw `starts_with("https://")` rejects the
/// valid uppercase spelling `HTTPS://host/` that reqwest's `Url::parse` lowercases and accepts, so
/// the provider base_url scheme check must match the webhook guard's case-insensitivity.
/// Validate the top-level `public_url:` — busbar's public origin. Rules (see call site): absolute
/// http/https; a PUBLIC host must use https (loopback/private http is allowed for local dev); the
/// value must be a BARE ORIGIN (`scheme://host[:port]`, optional trailing `/`) with no path, query,
/// or fragment; and it must not target a cloud-metadata host. Uses the SAME host normalization the
/// provider SSRF guard uses so the check sees the authority the connecting stack will.
pub(crate) fn validate_public_url(url: &str, blocked: &[String], errors: &mut Vec<String>) {
    let is_https = scheme_is(url, "https");
    let is_http = scheme_is(url, "http");
    if !is_https && !is_http {
        errors.push(format!(
            "public_url must be an absolute http(s) URL (got '{url}')"
        ));
        return;
    }
    let Some(host) = extract_normalized_host(url) else {
        errors.push(format!("public_url '{url}' has no host"));
        return;
    };
    if is_http && !host_is_private_or_loopback(&host) {
        errors.push(format!(
            "public_url must use https for a public host (got '{url}'); plaintext http is permitted \
             only for a loopback/private base"
        ));
    }
    // No path/query/fragment: strip scheme, fold `\`→`/` (WHATWG), then the authority must be the
    // whole remainder up to at most a single trailing `/`.
    if let Some((_, rest)) = url.split_once("://") {
        let rest = rest.replace('\\', "/");
        if let Some(pos) = rest.find(['/', '?', '#']) {
            let delim = rest.as_bytes()[pos];
            let tail = &rest[pos + 1..];
            if delim != b'/' || !tail.is_empty() {
                errors.push(format!(
                    "public_url must be a bare origin (scheme://host[:port]) with no path, query, or \
                     fragment (got '{url}'); BYOK clients append their own suffix"
                ));
            }
        }
    }
    // Never a cloud-metadata host (busbar's own origin is never IMDS). `allow_all=false`, no
    // per-provider carve-outs — the operator denylist still extends it.
    if let Some(bad) = ssrf_blocked_host(url, &[], false, blocked) {
        errors.push(format!(
            "public_url '{url}' targets a blocked cloud-metadata host '{bad}'"
        ));
    }
}

/// Push an error for every entry in a metadata host-list config key that contains a `/` (CIDR /
/// slash). These lists (`security.blocked_metadata_hosts`, `security.allow_metadata_hosts`, and each
/// provider's `allow_metadata_hosts`) are matched by EXACT IP/hostname via `host_matches_any` — a
/// CIDR like `169.254.0.0/16` never parses as an `Ipv4Addr` and never equals a connect-host string,
/// so it silently matches nothing (a confusing no-op that reads as a working rule). Reject it at boot
/// with a clear message naming the key + offending value, so the operator learns CIDR is unsupported
/// here and lists exact IPs/hostnames instead.
fn reject_cidr_metadata_entries(key: &str, entries: &[String], errors: &mut Vec<String>) {
    for entry in entries {
        if entry.contains('/') {
            errors.push(format!(
                "{key} entry '{entry}' contains '/' (CIDR is not supported here): these lists are matched by EXACT IP or hostname, so a CIDR/slash entry silently never matches and is a no-op. List exact IPs/hostnames instead (e.g. '169.254.169.254', not '169.254.0.0/16')"
            ));
        }
    }
}

/// The hardcoded cloud-metadata denylist entries, as human-readable strings — the single source of
/// truth `ssrf_blocked_host` enforces, surfaced for the `--print-metadata-blocklist` CLI flag and the
/// startup count so `main.rs` does NOT duplicate the list. The CIDR / individual literals are spelled
/// the way an operator would recognize them; the obfuscation defenses (mapped-IPv6, decimal-int,
/// trailing-dot) apply to each but are not enumerated here.
pub fn metadata_denylist_entries() -> Vec<String> {
    [
        // Link-local /16 — IMDS 169.254.169.254, AWS ECS task-creds 169.254.170.2, Tencent
        // 169.254.0.23, and every other link-local metadata endpoint.
        "169.254.0.0/16",
        "100.100.100.200", // Alibaba Cloud ECS
        "168.63.129.16",   // Azure WireServer / platform
        "192.0.0.192",     // Oracle Cloud (OCI) IMDS
        "fd00:ec2::254",   // AWS EC2 IMDSv6
        "metadata.google.internal",
        "metadata.internal",
        "metadata.tencentyun.com",
        "metadata.platformequinix.com",
        "instance-data",
        "instance-data.ec2.internal",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// Enumerating every secret reference in the resolved config, and the two-layer guard that makes
/// forgetting one impossible rather than merely discouraged. Its own module because the guard is a
/// cohesive unit (the walk, the exhaustive destructures, and the type inventory the coverage test
/// checks the source against) and because `mod.rs` is at the structure-lint size ceiling.
mod secret_refs;
pub(crate) use secret_refs::secret_refs;

/// THE PROVIDER SWEEP, PARAMETERISED ON THE KNOWN-PROTOCOL SET — by argument rather than by
/// feature-gating the registry, because a feature that empties the registry would be a SECOND way
/// to have no protocols, and this project's whole objection is to second ways.
///
/// WHY THE WHOLE SWEEP AND NOT JUST ITS PROTOCOL ARM. The arm below
/// ([`validate_provider_protocol_with`]) was already parameterised and already had its empty-set
/// test. What that test could NOT see is the production caller: a re-inlined `!known.contains(p)`
/// in this loop would restore the fail-OPEN with the arm's own test still green, which is exactly
/// the shape D5 exists to catch one level up. So the loop itself takes the set, `known_protocols()`
/// is read at ONE site (`validate_with_unset`'s call to this function), and
/// `an_empty_protocol_set_refuses_every_provider_through_the_real_sweep` drives this whole sweep —
/// the production code path, error ordering and all — against an empty set.
fn validate_providers_with(
    known: &'static [&'static str],
    cfg: &RootCfg,
    unset_env_vars: &[String],
    errors: &mut Vec<String>,
) {
    let is_env_placeholder = |v: &str| {
        !v.contains("://")
            && unset_env_vars
                .iter()
                .any(|u| !u.is_empty() && v.contains(u.as_str()))
    };
    // Rule 4: Validate error_map values on every provider. An EMPTY error_map is valid — a provider
    // may have no provider-specific JSON error codes and rely on HTTP-status classification (the
    // circuit breaker), exactly like the shipped `anthropic` catalog entry. Only the entries that
    // ARE present must name a known StatusClass.
    for (provider_name, provider_cfg) in &cfg.providers {
        // The provider's `protocol` selects a declared `Protocol` from the registry at lane
        // construction. An unknown protocol used to escape this multi-error collection entirely and
        // surface as a lone `die()` deep in `main.rs` (lane build) — so an operator with several
        // config mistakes saw only the first one. Validate it HERE against the single source of
        // truth (`proto::known_protocols()`, DERIVED from the protocol declarations rather than
        // maintained beside them) so a bad protocol is collected alongside every other error.
        // `main.rs`'s `die()` remains a defensive (now unreachable) backstop.
        //
        // THE EMPTY LIST IS ITS OWN ERROR, and this arm is why. The list used to be a compile-time
        // const that could not be empty; it is now derived, and a build with no protocol compiled in
        // would otherwise reject EVERY provider with "must be one of: " and an empty tail — one
        // confusing error per provider, none of them naming the actual cause. It is still a refusal
        // (a proxy with no protocol cannot serve a provider lane, and accepting the config would be
        // the fail-OPEN answer), but it refuses ONCE and says why.
        validate_provider_protocol_with(known, provider_name, &provider_cfg.protocol, errors);

        // Per-provider active-health-probe settings. `interval_secs`/`timeout_secs` are floored at 1
        // by the prober at use, but a literal 0 in config signals operator confusion (a 0 interval/
        // timeout is never what's intended); reject it at boot so the config is honest about what
        // runs — mirroring the global health.default_probe_* checks in validate_limits.
        if let Some(health) = &provider_cfg.health {
            if health.interval_secs == Some(0) {
                errors.push(format!(
                    "provider '{}' health.interval_secs must be >= 1 (got 0)",
                    provider_name
                ));
            }
            if health.timeout_secs == Some(0) {
                errors.push(format!(
                    "provider '{}' health.timeout_secs must be >= 1 (got 0)",
                    provider_name
                ));
            }
        }

        for (code, mapped_class) in &provider_cfg.error_map {
            if crate::config::status_class_from_str(mapped_class).is_none() {
                errors.push(format!(
                    "provider '{}' error_map code '{}': invalid StatusClass '{}', must be one of: rate_limit, overloaded, server_error, timeout, network, auth, billing, client_error, context_length",
                    provider_name, code, mapped_class
                ));
            }
        }

        // The optional auth-style override (`bearer` / `api-key`) is now a `ProviderAuth` enum, so an
        // invalid spelling is rejected at deserialize time — no hand-check needed here.

        // The resolved base_url is the actual upstream target for signed (API-key-bearing) calls.
        // It is operator config (a client never chooses a provider URL — it picks a model NAME that
        // maps through a pool to an operator URL), so there is no client-driven SSRF. Two startup
        // rules apply:
        //
        // SCHEME — keyed off whether the host is PRIVATE/LOOPBACK, not off a flag. A PUBLIC host MUST
        // use `https://` (cleartext would leak the API key on the wire to an off-box wiretap); a
        // PRIVATE/LOOPBACK host (a local Ollama / vLLM / LM Studio on `localhost`, `127.0.0.1`,
        // RFC-1918, or a Tailscale CGNAT address) MAY use plain `http://` — local models rarely
        // terminate TLS and there is no off-box hop to wiretap. So `http://localhost:11434` and
        // `http://10.0.0.5:8000` validate with NO flag, while `http://api.example.com` is rejected.
        // The allow-overrides for THIS provider: the union of its own `allow_metadata_hosts` and the
        // global `security.allow_metadata_hosts`. A host on the denylist is unblocked iff it appears
        // in this union (or `allow_all_metadata` is set). Built once and passed to both the base_url
        // and the path-override SSRF checks below so the two reason over the identical carve-out set.
        reject_cidr_metadata_entries(
            &format!("provider '{provider_name}' allow_metadata_hosts"),
            &provider_cfg.allow_metadata_hosts,
            errors,
        );
        let allow_overrides: Vec<String> = provider_cfg
            .allow_metadata_hosts
            .iter()
            .chain(cfg.allow_metadata_hosts.iter())
            .cloned()
            .collect();

        let base_url = &provider_cfg.base_url;
        let host_for_scheme = extract_normalized_host(base_url);
        let host_is_local = host_for_scheme
            .as_deref()
            .map(host_is_private_or_loopback)
            .unwrap_or(false);
        // Case-INSENSITIVE scheme check (RFC 3986 §3.1) — a raw `starts_with("https://")` rejected
        // the valid uppercase spelling reqwest would accept, and diverged from the webhook guard's
        // `scheme_is`.
        let scheme_ok = is_env_placeholder(base_url)
            || scheme_is(base_url, "https")
            || (host_is_local && scheme_is(base_url, "http"));
        if !scheme_ok {
            errors.push(if scheme_is(base_url, "http") {
                // An http:// scheme that failed the check ⇒ the host is public (or unparseable):
                // plaintext to a public host would leak the key.
                format!(
                    "provider '{}' base_url must use https for a public host (got '{}'); plaintext http is permitted only for a private/loopback local-model upstream",
                    provider_name, base_url
                )
            } else {
                format!(
                    "provider '{}' base_url must use http or https (got '{}')",
                    provider_name, base_url
                )
            });
        } else if let Some(host) = ssrf_blocked_host(
            base_url,
            &allow_overrides,
            cfg.allow_all_metadata,
            &cfg.blocked_metadata_hosts,
        ) {
            // SSRF — block the cloud-metadata DENYLIST (hardcoded + operator additions). A passing
            // scheme alone does not stop SSRF: `https://169.254.169.254/`, `http://100.100.100.200/`,
            // `https://metadata.google.internal/`, etc. point busbar's key-bearing traffic at a
            // credential-leaking metadata service. Everything NOT on the denylist (loopback, RFC-1918,
            // CGNAT, public) is allowed — so local models just work. The three escape hatches (this
            // provider's `allow_metadata_hosts`, the global `security.allow_metadata_hosts`, and the
            // nuclear `security.allow_all_metadata`) carve exceptions (then `ssrf_blocked_host`
            // returns None).
            errors.push(format!(
                "provider '{}' base_url '{}' targets a blocked cloud-metadata host '{}' (cloud-metadata/IMDS endpoints are denied; to override add the host to this provider's allow_metadata_hosts, or security.allow_metadata_hosts to unblock it for all providers, or set security.allow_all_metadata: true to disable the guard entirely — and security.blocked_metadata_hosts extends the denylist)",
                provider_name, base_url, host
            ));
        }

        // The `path` override is appended to `base_url` VERBATIM at request time
        // (`format!("{base}{wire_path}")` in proxy engine), and the composed string is then parsed by
        // reqwest's `url` crate to choose the connect host. base_url validation alone is therefore
        // NOT sufficient: a `path` that does not begin with `/` FUSES into the authority — e.g.
        // base_url `https://api.openai.com` + path `.evil.com/v1` yields
        // `https://api.openai.com.evil.com/v1`, whose host is `api.openai.com.evil.com`, redirecting
        // the lane's signed (API-key-bearing) traffic to an attacker host (credential-relay SSRF).
        // Likewise a `path` smuggling a `@` / `//` / `\` could re-home the authority. Defend in two
        // layers: (1) require a leading `/` so the override can only ever extend the PATH, never the
        // authority; (2) re-run the COMPOSED url through the same ssrf_blocked_host guard so any host
        // it could still introduce is caught with the identical internal/metadata block set as
        // base_url. (The composed string is only checked when base_url is itself an accepted https
        // URL — a bad base_url already errors above.)
        if let Some(path) = &provider_cfg.path {
            if !path.starts_with('/') {
                errors.push(format!(
                    "provider '{}' path '{}' must begin with '/': a path override is appended to base_url verbatim, so a path that does not start with '/' fuses into the host (e.g. base_url + '{}') and can redirect signed traffic to an attacker-controlled host",
                    provider_name, path, path
                ));
            } else if scheme_ok {
                let composed = format!("{}{}", provider_cfg.base_url, path);
                if let Some(host) = ssrf_blocked_host(
                    &composed,
                    &allow_overrides,
                    cfg.allow_all_metadata,
                    &cfg.blocked_metadata_hosts,
                ) {
                    errors.push(format!(
                        "provider '{}' base_url+path '{}' targets a blocked cloud-metadata host '{}' (cloud-metadata/IMDS endpoints are denied; to override add the host to this provider's allow_metadata_hosts, or security.allow_metadata_hosts, or set security.allow_all_metadata: true)",
                        provider_name, composed, host
                    ));
                }
            }
        }
        // Same guards for `path_base` (the URL-model base override, e.g. Vertex): it is prepended to
        // the per-request `/{model}:verb` and appended to base_url, so it must begin with '/' and the
        // composed host must not be a blocked metadata endpoint.
        if let Some(path_base) = &provider_cfg.path_base {
            if !path_base.starts_with('/') {
                errors.push(format!(
                    "provider '{}' path_base '{}' must begin with '/': it is appended to base_url verbatim, so a value that does not start with '/' fuses into the host and can redirect signed traffic to an attacker-controlled host",
                    provider_name, path_base
                ));
            } else if scheme_ok {
                let composed = format!("{}{}", provider_cfg.base_url, path_base);
                if let Some(host) = ssrf_blocked_host(
                    &composed,
                    &allow_overrides,
                    cfg.allow_all_metadata,
                    &cfg.blocked_metadata_hosts,
                ) {
                    errors.push(format!(
                        "provider '{}' base_url+path_base '{}' targets a blocked cloud-metadata host '{}' (cloud-metadata/IMDS endpoints are denied; to override add the host to this provider's allow_metadata_hosts, or security.allow_metadata_hosts, or set security.allow_all_metadata: true)",
                        provider_name, composed, host
                    ));
                }
            }
        }
        // `oauth-client-credentials` needs a token endpoint + scope to run the exchange; without them
        // a lane would boot but never mint a token (every request 401s). Fail at validate time. The
        // token_url carries the client_secret, so it must be https for a public host (loopback/private
        // may use http, mirroring base_url).
        if matches!(
            provider_cfg.auth,
            Some(crate::config::ProviderAuth::OAuthClientCredentials)
        ) {
            if provider_cfg
                .token_url
                .as_deref()
                .unwrap_or("")
                .trim()
                .is_empty()
            {
                errors.push(format!(
                    "provider '{}' uses auth: oauth-client-credentials but has no `token_url` (the OAuth token endpoint the client credentials are POSTed to)",
                    provider_name
                ));
            } else if let Some(tu) = &provider_cfg.token_url {
                // token_url carries the client secret in the POST body, so it gets the SAME two guards
                // as base_url — not a lone scheme check: (1) case-INSENSITIVE https requirement (http
                // permitted only for a private/loopback token endpoint; a raw `starts_with("http://")`
                // let `HTTPS://`/scheme-less/`FTP://` bypass it, the exact base_url bug this mirrors),
                // and (2) the SSRF/metadata denylist — an operator typo/template pointing token_url at
                // IMDS or metadata.google.internal would POST the client secret straight to it.
                let host_private = extract_normalized_host(tu)
                    .as_deref()
                    .map(host_is_private_or_loopback)
                    .unwrap_or(false);
                let tu_scheme_ok = is_env_placeholder(tu)
                    || scheme_is(tu, "https")
                    || (host_private && scheme_is(tu, "http"));
                if !tu_scheme_ok {
                    errors.push(if scheme_is(tu, "http") {
                        format!(
                            "provider '{}' token_url must use https for a public host (got '{}'); it carries the client secret, so plaintext http is permitted only for a private/loopback token endpoint",
                            provider_name, tu
                        )
                    } else {
                        format!(
                            "provider '{}' token_url must use http or https (got '{}')",
                            provider_name, tu
                        )
                    });
                } else if let Some(host) = ssrf_blocked_host(
                    tu,
                    &allow_overrides,
                    cfg.allow_all_metadata,
                    &cfg.blocked_metadata_hosts,
                ) {
                    errors.push(format!(
                        "provider '{}' token_url '{}' targets a blocked cloud-metadata host '{}' (the client secret is POSTed there; cloud-metadata/IMDS endpoints are denied — override via this provider's allow_metadata_hosts, security.allow_metadata_hosts, or security.allow_all_metadata)",
                        provider_name, tu, host
                    ));
                }
            }
            if provider_cfg
                .scope
                .as_deref()
                .unwrap_or("")
                .trim()
                .is_empty()
            {
                errors.push(format!(
                    "provider '{}' uses auth: oauth-client-credentials but has no `scope`",
                    provider_name
                ));
            }
            // Dry-run credential-format check (parity with jwt-bearer below): the `client_id:client_secret`
            // colon-split lives only in `build()`, which `--validate` never reaches, so a malformed
            // credential otherwise passes validate and fails at boot/apply. Check it here when the env var
            // resolves (an unset var can't be validated — caught at boot).
            let cred = crate::config::secret::resolve_builtin_string(&provider_cfg.api_key)
                .unwrap_or_default();
            if !cred.trim().is_empty() {
                if let Err(e) =
                    crate::egress_auth::oauth_client_credentials::validate_credential(&cred)
                {
                    errors.push(format!(
                        "provider '{provider_name}' oauth-client-credentials credential (from {}) is invalid: {e}",
                        provider_cfg.api_key.describe()
                    ));
                }
            }
        }

        // jwt-bearer: dry-run key validation. `build()` (SA-JSON parse + PKCS#8 key check + token_uri
        // SSRF) does NOT run on the `--validate` path, so a malformed credential otherwise surfaces only
        // at boot/apply. Validate it here IF the credential env var is actually set (an unset var can't
        // be validated — it is checked at boot, where unset is a hard error).
        if matches!(
            provider_cfg.auth,
            Some(crate::config::ProviderAuth::JwtBearer)
        ) {
            let cred = crate::config::secret::resolve_builtin_string(&provider_cfg.api_key)
                .unwrap_or_default();
            if !cred.trim().is_empty() {
                // Pass the SAME operator metadata posture the boot path threads into jwt_bearer::build,
                // so the token_uri SSRF check is identical at validate and apply time.
                let ssrf = crate::egress_auth::MetadataSsrfPolicy {
                    allow_overrides: &allow_overrides,
                    allow_all: cfg.allow_all_metadata,
                    blocked_hosts: &cfg.blocked_metadata_hosts,
                };
                if let Err(e) = crate::egress_auth::jwt_bearer::validate_credential(&cred, &ssrf) {
                    errors.push(format!(
                        "provider '{provider_name}' jwt-bearer credential (from {}) is invalid: {e}",
                        provider_cfg.api_key.describe()
                    ));
                }
            }
        }
    }
}

/// The provider-protocol arm of `validate`, PARAMETERISED on the known-protocol set — by argument
/// rather than by feature-gating the registry, because a feature that empties the registry would be
/// a SECOND way to have no protocols, and this project's whole objection is to second ways.
///
/// THE EMPTY SET IS THE LOAD-BEARING CASE. `known_protocols()` is derived from the registry, and
/// the core split (step 3.7) makes emptying it a one-line `Cargo.toml` edit by someone who is not
/// thinking about this module: from step 4 on, a protocol is a dependency edge, and removing an
/// edge is exactly what the deletion gate does per protocol in CI. `!known.contains(p)` alone is
/// the classic vacuous gate — with `known` empty, `contains` is false for NOTHING, every provider
/// validates, and the config that names a protocol this build cannot speak boots to a dead lane.
/// So zero is its OWN refusal: once, naming the build, per provider. The empty-set test in
/// `tests/tests.rs` (`an_empty_protocol_set_refuses_every_provider_naming_the_build`) was watched
/// RED against the contains-only body before this arm existed; do not fold the arms back together.
fn validate_provider_protocol_with(
    known: &'static [&'static str],
    provider_name: &str,
    protocol: &str,
    errors: &mut Vec<String>,
) {
    if known.is_empty() {
        errors.push(format!(
            "provider '{provider_name}' names protocol '{protocol}', but this build has NO protocol \
             with a wire codec compiled in, so no provider lane can be served"
        ));
    } else if !known.contains(&protocol) {
        errors.push(format!(
            "provider '{}' has unknown protocol '{}': must be one of: {}",
            provider_name,
            protocol,
            known.join(", ")
        ));
    }
}

#[cfg(test)]
#[path = "tests/tests.rs"]
mod tests;
