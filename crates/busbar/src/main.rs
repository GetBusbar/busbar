// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//
// busbar — a native-protocol LLM gateway. It fronts many LLM providers and routes each request to
// a model or to a weighted pool of models, translating losslessly between wire protocols and
// protecting each backend with a circuit breaker. The name is electrical: a busbar takes one feed
// and fans it out across many breakered circuits.
//
// Routing — all SIX ingress protocols are first-class; a native SDK can point its base URL at
// busbar unmodified (clients append the protocol path themselves). Mirrors the `--help` ENDPOINTS
// block and the README routing table:
// POST /<model>/v1/messages              Anthropic-format ingress (single model)
// POST /<pool>/v1/messages               a config-defined pool (weighted selection + failover)
// POST /<provider>/<model>/v1/messages   ad-hoc: a specific configured provider+model
// POST /v1/chat/completions              OpenAI-format ingress (model from the body)
// POST /v2/chat                          Cohere-format ingress (model from the body)
// POST /v1/responses                     OpenAI Responses-API ingress (model from the body)
// POST /v1/models/<model>:<action>       Gemini-format ingress (stable v1 alias)
// POST /v1beta/models/<model>:<action>   Gemini-format ingress (v1beta)
// POST /model/<modelId>/converse[-stream] Bedrock Converse / ConverseStream ingress
// GET  /v1/models  /v1beta/models        list models (dialect by protocol fingerprint)
// GET  /stats  /healthz  /metrics
//
// Each model is a "lane" with its own concurrency semaphore, optional lifetime request budget, and
// per-(pool,lane) circuit-breaker health. A pool stacks its members' concurrency into one aggregate
// and distributes via smooth weighted round-robin. Ingress and backend protocols may differ: the
// request and response are translated through a superset intermediate representation (see
// `proto`/`ir`), so e.g. an OpenAI-format client can drive a Gemini or Bedrock backend, or a native
// Responses/Cohere/Gemini/Bedrock client can drive any configured backend.
//
// Failure handling (see `breaker`): transient upstream faults (5xx / overload / rate-limit /
// timeout / network) arm an escalating cooldown; billing and auth faults open the breaker with a
// long sticky cooldown; client-supplied 4xx are relayed verbatim and never penalize the lane; an
// exhausted lifetime budget disables the lane. Tripped lanes recover via a half-open probe.

// busbar contains ZERO `unsafe` code; enforce that as a compile-time guarantee so any future PR that
// introduces an `unsafe` block fails to build rather than slipping in unreviewed.
#![forbid(unsafe_code)]

// Global allocator: jemalloc. The request hot path allocates and frees the request body a few times
// per request (raw bytes → parsed JSON → re-serialized outbound), so RSS under load tracks
// (peak concurrency × payload size). glibc's allocator almost never returns freed pages to the OS,
// so after a big-payload burst the process stays pinned at its peak forever — memory reads as a
// ratchet even though the live set has collapsed. jemalloc plus a background purge thread returns
// dirty/muzzy pages after a short decay, so busbar PLATEAUS under sustained load and falls back to
// idle when the load subsides. `#[global_allocator]` on a static needs no `unsafe`; the background
// purge thread is enabled at startup in `main()` via a safe runtime call (`tikv_jemalloc_ctl::
// background_thread`), so operators get it with zero configuration. NOT on windows-msvc: tikv-jemalloc-sys's
// C build does not compile under native `cl.exe`, so MSVC (a shipped release target + CI gate) falls back
// to the system allocator — the dep is target-gated in Cargo.toml and these two sites match.
#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

mod a2a;
mod admin;
mod auth;
mod auth_cache;
mod billing;
mod breaker;
mod config;
mod config_validate;
mod core_routes;
mod cost;
// The durable-write choke point moved to the shared `busbar-api` crate so the plugin-loader
// (plugins.fetch cache write) can route through the SAME primitive. Re-exported here so every
// existing `crate::durable::*` call site in this binary resolves unchanged.
pub(crate) use busbar_api::durable;
mod egress_auth;
mod endpoints;
mod eventstream;
mod export;
mod governance;
mod handlers;
mod health;
mod hooks;
mod ingress;
mod ir;
mod json;
mod limits;
mod lossless;
mod mcp;
mod media;
mod metrics;
mod net_guard;
mod oauth_as;
mod observability;
mod operation;
mod plane;
mod plugin_routes;
mod profile;
mod proto;
mod proxy;
mod sigv4;
mod state;
mod store;
mod telemetry;
#[cfg(test)]
mod test_support;
mod tls;
mod transport;
mod trust;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;

use auth::AuthMiddleware;

use proto::ProtocolRegistry;
use state::{App, Lane, WeightedLane};
use store::{HealthState, LaneData};

// The upstream-request timeout, pool-idle, and request-body caps that used to live here as `const`s
// are now operator-tunable (`limits.upstream_request_timeout_secs` / `pool_max_idle_per_host` /
// `request_body_max_bytes`), each defaulting to its historical value at the config layer. They are
// threaded from `cfg.limits` into the client builder and router below; the egress translate-body cap
// is COUPLED to `request_body_max_bytes` via `crate::limits::translate_body_max_bytes`.

/// DEPRECATED (1.5.3) environment variable name for the providers.yaml path — migrated to the
/// top-level `providers_file:` key in config.yaml. Still honored for one release (see
/// [`providers_override_from_env`]).
const ENV_PROVIDERS: &str = "BUSBAR_PROVIDERS";
/// Environment variable name for the config.yaml path — the one irreducible bootstrap env var.
const ENV_CONFIG: &str = "BUSBAR_CONFIG";
/// Default path to the deployment config file.
const DEFAULT_CONFIG_PATH: &str = "/etc/busbar/config.yaml";
/// Response header name for the W3C Server-Timing field.
const HEADER_SERVER_TIMING: &str = "server-timing";
/// Sentinel value stored in the `UPSTREAM_RTT_US` task-local when NO upstream hop was dispatched
/// (admin / health / early error). `server_timing_dur_ms` treats this as "report the full request
/// time" rather than subtracting a nonexistent RTT. Only this exact u64::MAX meaning is replaced
/// with the const; overflow/conversion fallbacks that happen to produce u64::MAX are NOT this.
const NO_UPSTREAM_RTT: u64 = u64::MAX;

/// Handle CLI flags before any environment or file access, so they work without a configured
/// deployment. Returns `Some(exit_code)` when the process should exit (after printing), `None` to
/// proceed to normal startup. busbar takes no positional arguments and is configured via
/// environment + YAML; an unrecognized flag is a usage error rather than a silent server start.
fn handle_cli_flags() -> Option<i32> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        None => None, // no args → run the gateway
        Some("--version" | "-V") => {
            println!("busbar {}", env!("CARGO_PKG_VERSION"));
            Some(0)
        }
        Some("--print-metadata-blocklist") => {
            // Print the EFFECTIVE cloud-metadata denylist the running binary enforces: the hardcoded
            // set (single source of truth in config_validate) UNION the operator's
            // `security.blocked_metadata_hosts`. The hardcoded set always prints (no config needed);
            // the operator extension is appended best-effort if BUSBAR_CONFIG is readable + parseable,
            // so the flag is useful even before a deployment is wired up. One entry per line, exit 0.
            let mut entries = config_validate::metadata_denylist_entries();
            let config_path =
                std::env::var(ENV_CONFIG).unwrap_or_else(|_| DEFAULT_CONFIG_PATH.into());
            if let Ok(raw) = std::fs::read_to_string(&config_path) {
                match config::interpolate_env(&raw) {
                    Ok(interpolated) => {
                        match serde_yaml::from_str::<config::DeployCfg>(&interpolated) {
                            Ok(deploy) => {
                                if let Some(sec) = deploy.security {
                                    entries.extend(sec.blocked_metadata_hosts);
                                }
                            }
                            Err(_) => {
                                // The config did not parse (e.g. an unknown/typo'd key now rejected by
                                // deny_unknown_fields). Don't silently print an INCOMPLETE denylist that
                                // omits the operator's `security.blocked_metadata_hosts` — warn instead.
                                // (Deliberately NOT echoing the error, which could quote a config value;
                                // the normal boot path surfaces the precise parse error.)
                                eprintln!(
                                "warning: config at {config_path} did not parse; printing the built-in \
                                 metadata denylist only (security.blocked_metadata_hosts skipped). Run \
                                 busbar normally to see the parse error."
                            );
                            }
                        }
                    }
                    Err(_) => {
                        // Interpolation itself failed (unset var, or — since this fix — a value
                        // that would change the config's YAML structure). Same reasoning as the
                        // parse-failure arm above: don't silently print an incomplete denylist,
                        // and don't echo the error (it could quote a rejected env var's value).
                        eprintln!(
                            "warning: config at {config_path} failed to interpolate; printing the \
                             built-in metadata denylist only (security.blocked_metadata_hosts \
                             skipped). Run busbar normally to see the interpolation error."
                        );
                    }
                }
            }
            for entry in entries {
                println!("{entry}");
            }
            Some(0)
        }
        Some("--validate") => Some(validate_config_command()),
        Some("--generate-signing-key") => Some(generate_signing_key_command()),
        Some("--list-plugins") => Some(list_plugins_command()),
        Some("--migrate-config") => Some(migrate_config_command(args.next())),
        Some("--help" | "-h") => {
            println!(
                "busbar {ver} — native-protocol LLM gateway

USAGE:
    busbar              run the gateway (configured entirely via environment + YAML)
    busbar --help       print this help
    busbar --version    print the version
    busbar --validate   parse + validate config.yaml/providers.yaml AND every plugin manifest
                        (structure, signature/trust, conflicts, abi, version floors) and exit
                        (0 = valid, 1 = errors); no server, no network, no state, no dlopen —
                        safe in CI and before a reload; a clean --validate means boot succeeds
    busbar --list-plugins
                        manifest-only inventory of the plugins dir (name/alias/kind/version,
                        signature verdict, load status + exact reason); never loads plugin code
    busbar --migrate-config <old-config.yaml>
                        mechanically convert a 1.4.x config to the 1.5.0 shape: prints the new
                        YAML to stdout (with TODO/WARNING comments where a human must decide)
                        and a change summary to stderr; ZERO side effects, nothing is written
    busbar --generate-signing-key
                        mint a fresh ed25519 signing key (64 hex chars) to stdout with a paste-
                        ready auth.signing_key snippet on stderr; ZERO side effects, nothing is
                        written — you place it in config.yaml (or wire it as a shared secret)
    busbar --print-metadata-blocklist
                        print the effective cloud-metadata SSRF denylist and exit

ENVIRONMENT:
    BUSBAR_CONFIG       path to config.yaml     (default: /etc/busbar/config.yaml)
    BUSBAR_PROVIDERS    path to providers.yaml  (DEPRECATED — set `providers_file:` in config.yaml;
                        default: providers.yaml next to the resolved config.yaml)
    RUST_LOG            log level: error|warn|info|debug|trace  (default: info)

Flags:
    --safe-mode         boot on base config.yaml alone (quarantine the persisted overlay)

ENDPOINTS (once running, listen address from config.yaml `listen`):
    POST /<model>/v1/messages              Anthropic-format ingress (single model)
    POST /<pool>/v1/messages               route to a configured pool
    POST /<provider>/<model>/v1/messages   ad-hoc direct route
    POST /v1/chat/completions              OpenAI-format ingress
    POST /v2/chat                          Cohere-format ingress
    POST /v1/responses                     Responses-API ingress
    POST /v1/models/<model>:<action>       Gemini-format ingress (stable v1)
    POST /v1beta/models/<model>:<action>   Gemini-format ingress
    POST /model/<modelId>/converse         Bedrock Converse ingress
    POST /model/<modelId>/converse-stream  Bedrock Converse streaming ingress
    GET  /v1/models  /v1beta/models        list models (answers in the caller's dialect)
    GET  /stats  /healthz  /metrics

Docs: https://getbusbar.com   ·   Source: https://github.com/GetBusbar/busbar",
                ver = env!("CARGO_PKG_VERSION")
            );
            Some(0)
        }
        Some(other) => {
            eprintln!("busbar: unrecognized argument '{other}'. Try 'busbar --help'.");
            Some(2)
        }
    }
}

/// `--validate`: parse, resolve, and semantically validate the config WITHOUT booting. Runs the exact
/// same load -> resolve -> validate the gateway runs at boot (so a clean `--validate` means a clean
/// boot), but never binds a listener, writes state, spawns a task, opens TLS, or makes a network call,
/// and does NOT require provider secrets (validation is STRUCTURE, not reachability — the nginx -t rule).
/// Honors BUSBAR_CONFIG/BUSBAR_PROVIDERS/--safe-mode. Prints an OK summary + exits 0 when valid;
/// prints every error (same text boot prints) + exits 1 when not.
fn validate_config_command() -> i32 {
    let providers_override = providers_override_from_env();
    let config_path = std::path::PathBuf::from(
        std::env::var(ENV_CONFIG).unwrap_or_else(|_| DEFAULT_CONFIG_PATH.into()),
    );
    let safe_mode = safe_mode_requested(std::env::args());

    let mut loaded = match load_config_from_disk(
        &config_path,
        providers_override.as_deref(),
        safe_mode,
        config::EnvSubst::Lenient,
    ) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[error] {e}");
            return 1;
        }
    };
    let providers_path = loaded.providers_path.clone();
    let unset_env_vars = loaded.unset_env_vars.clone();
    // Apply the overlay's `root` section (API-set single-value config) onto the base DeployCfg BEFORE
    // resolve, exactly as boot does — so --validate validates the EFFECTIVE config including the
    // rate_card/store/security/limits/… overrides (and re-runs the limits projection + admin-mTLS
    // boot-guard over the merged shape), not just the base file. The hooks/groups sections merge
    // POST-resolve below.
    if let Some(doc) = loaded.overlay_doc.as_ref() {
        config::overlay::apply_root_to_deploy(&mut loaded.deploy, doc);
    }
    let mut cfg = match config::resolve(&loaded.deploy, &loaded.defs) {
        Ok(c) => c,
        Err(errs) => {
            eprintln!("[error] config errors:\n  - {}", errs.join("\n  - "));
            return 1;
        }
    };
    // Merge the persisted overlay's hooks/groups sections exactly as boot does, so --validate
    // validates the EFFECTIVE config (base + API-applied hooks/groups), not just the base file.
    if let Some(doc) = loaded.overlay_doc.take() {
        config::overlay::merge_into(&mut cfg, doc);
    }
    if let Err(errs) = config_validate::validate_with_unset(&cfg, &unset_env_vars) {
        eprintln!(
            "[error] config validation failed:\n  - {}",
            errs.join("\n  - ")
        );
        return 1;
    }
    // PLUGIN PRE-FLIGHT — the EXACT pipeline boot runs (`plugins_preflight` is shared with
    // `build_app_from_config`), so a clean `--validate` means the plugin half of boot succeeds too:
    // consistency (plugins.enabled vs store.module), trust-policy resolution, the three-phase
    // scan of every tarball (structural -> trust -> conflict), and store resolution. Manifest-only:
    // nothing is `dlopen`ed, no store is opened — zero side effects.
    let registry = match preflight_plugins_and_secrets(&loaded.deploy, &cfg) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[error] {e}");
            return 1;
        }
    };

    // STRICT SECRETS, `--validate` only. The pre-flight above is shared with boot and admin apply,
    // where an unresolvable secret WARNS by design. Here the operator is asking whether the config
    // is good, so an env var that is not set is an answer, not a footnote.
    if let Err(e) = validate_builtin_secrets_resolve(&cfg) {
        eprintln!("[error] {e}");
        return 1;
    }
    println!(
        "ok: config valid — {} provider(s), {} model(s), {} pool(s)\n  config:    {}\n  providers: {}",
        cfg.providers.len(),
        cfg.models.len(),
        cfg.pools.len(),
        config_path.display(),
        providers_path.display(),
    );
    if loaded.deploy.plugins.enabled {
        println!(
            "  plugins:   enabled — {} validated, {} skipped (untrusted) in '{}'",
            registry.loadable().len(),
            registry.skipped().len(),
            loaded.deploy.plugins.dir,
        );
        for s in registry.skipped() {
            println!(
                "    skipped: {} ({}) — {}",
                s.manifest.name, s.file, s.reason
            );
        }
    } else {
        println!("  plugins:   disabled (plugins.enabled is false; no plugin will load)");
    }
    if !unset_env_vars.is_empty() {
        println!(
            "  note: {} env var(s) referenced but unset here — required at runtime: {}",
            unset_env_vars.len(),
            unset_env_vars.join(", "),
        );
    }
    0
}

/// `--list-plugins`: MANIFEST-ONLY inventory of every plugin tarball in `plugins.dir` — name,
/// alias, kind, version, signature verdict, and load status (including the exact skip/invalid
/// reason and which one `store.module` selects). NEVER `dlopen`s anything, so an untrusted
/// plugin's code cannot run from listing it. Exit 0 (informational; `--validate` is the gate).
fn list_plugins_command() -> i32 {
    let providers_override = providers_override_from_env();
    let config_path = std::path::PathBuf::from(
        std::env::var(ENV_CONFIG).unwrap_or_else(|_| DEFAULT_CONFIG_PATH.into()),
    );
    // Best-effort config read (lenient env): a missing/broken config falls back to the default
    // plugins block so the inventory still works pre-deployment.
    let (plugins_cfg, store_ref) = match load_config_from_disk(
        &config_path,
        providers_override.as_deref(),
        false,
        config::EnvSubst::Lenient,
    ) {
        Ok(l) => {
            let store = l
                .deploy
                .store
                .as_ref()
                .map(|g| g.module.clone())
                .unwrap_or_else(|| config::GOVERNANCE_STORE_MEMORY.to_string());
            (l.deploy.plugins, store)
        }
        Err(e) => {
            eprintln!("[warn] config not readable ({e}); using the default plugins block");
            (
                config::PluginsCfg::default(),
                config::GOVERNANCE_STORE_MEMORY.to_string(),
            )
        }
    };
    let policy = match plugins_cfg.to_policy() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[error] plugins.trust is invalid: {e}");
            return 1;
        }
    };
    let dir = std::path::PathBuf::from(&plugins_cfg.dir);
    println!(
        "plugins dir: {} (plugins.enabled: {})",
        dir.display(),
        plugins_cfg.enabled
    );
    let rows = busbar_plugin_loader::inventory_tarballs(&dir, &policy);
    if rows.is_empty() {
        println!("no plugin tarballs found");
        return 0;
    }
    println!(
        "{:<34} {:<24} {:<12} {:<6} {:<9} {:<24} STATUS",
        "FILE", "NAME", "ALIAS", "KIND", "VERSION", "SIGNATURE"
    );
    for row in rows {
        let (name, alias, kind, version) = row
            .manifest
            .as_ref()
            .map(|m| {
                (
                    m.name.clone(),
                    m.alias.clone(),
                    m.kind.clone(),
                    m.version.clone(),
                )
            })
            .unwrap_or_else(|| ("-".into(), "-".into(), "-".into(), "-".into()));
        // Which row the configured governance store selects (only meaningful when it would load).
        let selected = plugins_cfg.enabled
            && row.status == "ready"
            && (name == store_ref || alias == store_ref);
        let status = if selected {
            format!("LOADS (store.module: {store_ref})")
        } else if !plugins_cfg.enabled && row.status == "ready" {
            "ready (inert: plugins.enabled is false)".to_string()
        } else {
            row.status.clone()
        };
        println!(
            "{:<34} {:<24} {:<12} {:<6} {:<9} {:<24} {status}",
            row.file, name, alias, kind, version, row.signature
        );
    }
    0
}

/// Print a clean startup error to stderr and exit non-zero. Used for misconfiguration and other
/// boot-time failures so the operator sees a one-line message instead of a Rust panic backtrace.
fn die(msg: impl std::fmt::Display) -> ! {
    eprintln!("[error] {msg}");
    std::process::exit(1);
}

/// Return the open-relay banner to emit when the auth chain is EMPTY (open front door), or `None`
/// when an auth module is engaged. `chain_empty` = the resolved `auth.chain` is empty. `auth_present`
/// distinguishes an explicit empty chain (operator opted in) from a missing `auth:` block
/// (serde-defaulted to open — the silent foot-gun the banner must call out).
fn open_relay_banner(chain_empty: bool, auth_present: bool) -> Option<&'static str> {
    if !chain_empty {
        return None;
    }
    Some(if auth_present {
        "auth is DISABLED (auth.chain is empty) — busbar is running as an OPEN RELAY; do not run this in production"
    } else {
        "auth is DISABLED: no `auth:` block in config — busbar is running as an OPEN RELAY (anyone can use it). Add `auth:` with `chain: [keys]` (and mint virtual keys via the admin API) before exposing it; do not run this in production"
    })
}

/// Return the INERT-KEYS banner to emit when a DURABLE governance store still holds virtual keys
/// from a prior run but the running `auth.chain` does NOT name the `keys` verifier. Enforcement of a
/// virtual key is now decided by the CHAIN SHAPE, not the admin token: only when `keys` is in the
/// data-plane chain does any request resolve to (and get governed by) a stored vkey. So if `keys`
/// is absent, the persisted keys' per-key controls (budget, RPM/TPM, allowed_pools) are silently
/// NOT enforced — no data-plane request ever resolves them. A RAM store can never reach this state
/// (it starts empty every boot), so this is scoped to durable stores. Returns `None` when the state
/// does not apply (RAM store, no keys, or `keys` IS in the chain). `key_count` is the number of keys
/// the store reports at boot; `keys_in_chain` is whether `auth.chain` names the `keys` verifier.
fn inert_durable_keys_banner(
    store_is_durable: bool,
    key_count: usize,
    keys_in_chain: bool,
) -> Option<String> {
    if store_is_durable && key_count > 0 && !keys_in_chain {
        Some(format!(
            "durable governance store contains {key_count} key(s) but auth.chain does not name the \
             `keys` verifier — those keys are INERT and NOT enforced (per-key budget / RPM / TPM / \
             allowed_pools are bypassed; no data-plane request resolves them). Add `keys` to \
             auth.chain to enforce them."
        ))
    } else {
        None
    }
}

/// Resolve each model's single `context_max` from the pool members that reference it.
///
/// A model is realized as exactly one lane (keyed by model name in `by_model`), so its
/// context window must be single-valued across every pool that lists it. We accept the same
/// `context_max` repeated (including the same `Some(_)` in multiple pools, and a mix of an
/// explicit value with `None` — the explicit value wins, since `None` only means "unspecified
/// here"), but reject two DIFFERENT explicit limits for the same model: that is an operator
/// contradiction that previously resolved nondeterministically to whichever pool iterated last.
fn resolve_model_context_max(
    pools: &HashMap<String, config::PoolCfg>,
) -> Result<HashMap<String, Option<usize>>, String> {
    let mut resolved: HashMap<String, Option<usize>> = HashMap::new();
    for pool in pools.values() {
        for m in &pool.members {
            match resolved.get(&m.model) {
                // First sighting of this model, or this member adds no opinion (None) — keep what
                // we have / record what we got.
                None => {
                    resolved.insert(m.model.clone(), m.context_max);
                }
                Some(None) => {
                    // Previously unspecified; let any value (including another None) refine it.
                    resolved.insert(m.model.clone(), m.context_max);
                }
                Some(Some(existing)) => match m.context_max {
                    // No opinion here, or an identical opinion — both fine, keep the explicit value.
                    None => {}
                    Some(c) if c == *existing => {}
                    Some(c) => {
                        return Err(format!(
                            "model '{}' has conflicting context_max across pools ({} vs {}); a model maps to one lane and must declare a single context_max",
                            m.model, existing, c
                        ));
                    }
                },
            }
        }
    }
    Ok(resolved)
}

/// Whether `--safe-mode` was passed: quarantines the persisted overlay entirely (both
/// `validate_config_command` and `run()` read this the same way, so it's factored once here rather
/// than duplicated). Takes the arg iterator as a parameter (instead of calling `std::env::args()`
/// itself) so it's unit-testable against a synthetic arg list.
fn safe_mode_requested(mut args: impl Iterator<Item = String>) -> bool {
    args.any(|a| a == "--safe-mode")
}

/// A store READ failure and a chain-VERIFICATION failure on audit restore are different events: the
/// first is a hiccup, the second is tamper evidence. Reporting both as "chain verification" trains
/// an operator to ignore the one that matters, so `run()`'s restore-error match keys on this to pick
/// `tracing::warn!` vs `tracing::error!`. Module-level (not inlined in the match guard) so it's
/// unit-testable; see `tests/tests.rs`.
fn is_audit_restore_read_hiccup(e: &str) -> bool {
    e.starts_with("audit restore read failed")
}

/// Cap on `BUSBAR_WORKER_THREADS`/`TOKIO_WORKER_THREADS` (see the `.min(MAX_WORKER_THREADS)` call in
/// `main()` for why this exists).
const MAX_WORKER_THREADS: usize = 128;

/// Resolve a worker-thread-count env var, warning on an EXPLICITLY-SET but invalid value rather than
/// silently ignoring it — an unset var is not warned (the normal default path). Module-level (not
/// nested in `main()`) so it's unit-testable; see `tests/tests.rs`.
fn worker_threads_from_env(name: &str) -> Option<usize> {
    match std::env::var(name) {
        Ok(v) => match v.trim().parse::<usize>() {
            Ok(n) if n >= 1 => Some(n),
            _ => {
                eprintln!(
                    "[warn] {name}={v:?} is not a positive integer; ignoring it and using the \
                     default worker-thread count"
                );
                None
            }
        },
        Err(_) => None, // unset — normal default path, no warning
    }
}

/// Best-effort early read of `advanced.worker_threads` from config.yaml (1.5.3). Runs in `main()`
/// BEFORE the tokio runtime is built, so it re-reads the config file (the authoritative load, with
/// full error reporting, happens later in `run()`). A missing/unparseable config yields `None` — the
/// caller falls through to the standard worker-thread default, and `run()` surfaces the real error.
/// Lenient env interpolation so an unset `${VAR}` elsewhere in the file does not abort this probe.
fn worker_threads_from_config() -> Option<usize> {
    let config_path = std::env::var(ENV_CONFIG).unwrap_or_else(|_| DEFAULT_CONFIG_PATH.into());
    let raw = std::fs::read_to_string(&config_path).ok()?;
    let mut unset = Vec::new();
    let interpolated =
        config::interpolate_env_with(&raw, config::EnvSubst::Lenient, &mut unset).ok()?;
    let deploy: config::DeployCfg = serde_yaml::from_str(&interpolated).ok()?;
    match validate_worker_threads_config(deploy.advanced.worker_threads) {
        Ok(v) => v,
        Err(msg) => {
            // Consistency with `worker_threads_from_env`, which WARNS on an invalid value rather than
            // silently dropping it. Pre-tracing (`main()` runs this before the subscriber is built), so
            // it goes to STDERR like the other boot diagnostics.
            eprintln!("[warn] {msg}");
            None
        }
    }
}

/// Validate a config-supplied `advanced.worker_threads`. `Some(0)` is invalid — a Tokio runtime needs
/// at least one worker — and yields `Err(message)` so the caller can WARN consistently with
/// `worker_threads_from_env`'s invalid-value diagnostic instead of silently dropping the operator's
/// explicit `advanced.worker_threads: 0`. Every other value (a positive count, or `None`/unset) passes
/// through unchanged. Module-level (not inlined) so it is unit-testable; see `tests/tests.rs`.
fn validate_worker_threads_config(wt: Option<usize>) -> Result<Option<usize>, String> {
    match wt {
        Some(0) => Err(
            "advanced.worker_threads: 0 in config.yaml is not a positive integer (it must be >= 1); \
             ignoring it and using the default worker-thread count"
                .to_string(),
        ),
        other => Ok(other),
    }
}

/// Resolve a boot-time boolean upstream knob under the env→config migration precedence: the DEPRECATED
/// env var, when SET, wins (honored for one release) — `"0"` or empty means OFF, anything else ON; when
/// UNSET, the config value (`advanced.upstream_*`, carried on `cfg.limits`) stands. The deprecation
/// WARN is emitted at the call site (only when the env var is present). Module-level so the precedence
/// is unit-testable without building the whole client; see `tests/tests.rs`.
fn upstream_bool_env_override(env: Option<std::ffi::OsString>, config_val: bool) -> bool {
    match env {
        Some(v) => v != "0" && !v.is_empty(),
        None => config_val,
    }
}

fn main() {
    // CLI flags first — BEFORE building any runtime. They must work without a configured deployment,
    // and `--version` / `--validate` should never spin up a thread pool.
    if let Some(code) = handle_cli_flags() {
        std::process::exit(code);
    }
    // Enable jemalloc's background purge thread: freed dirty/muzzy pages are returned to the OS after
    // a short idle decay, so RSS falls back to idle after a big-payload burst instead of ratcheting at
    // the peak (the glibc behavior this replaces). Safe wrapper — no `unsafe`. Skipped on windows-msvc,
    // which uses the system allocator (jemalloc dep is target-gated off msvc; see above).
    //
    // Best-effort and VERIFIED at runtime rather than assumed: some platforms/builds lack background-
    // thread support (macOS keeps only foreground purge; jemalloc also flags it as potentially
    // unavailable on musl — and the SHIPPED release is static musl). Read the flag back after writing and
    // WARN if it did not enable, so the plateau-then-fall-back-to-idle behavior is an observed fact, not a
    // silent assumption. Even when the background thread is absent, jemalloc's FOREGROUND decay purge
    // still bounds RSS under load; only the proactive purge during full idle is lost.
    //
    // This runs in `main()` BEFORE the tracing subscriber is installed (that happens in `run()` after the
    // runtime is built), so the diagnostic goes to STDERR via `eprintln!` — the same channel the other
    // pre-subscriber boot messages use — rather than `tracing`, which would silently drop it. Silent on
    // success; only the problem cases (did-not-enable / error) print.
    #[cfg(not(target_env = "msvc"))]
    {
        use tikv_jemalloc_ctl::background_thread;
        let enabled = match background_thread::write(true).and_then(|()| background_thread::read())
        {
            Ok(true) => true, // enabled — RSS falls back to idle; nothing to report
            Ok(false) => {
                eprintln!(
                    "[warn] jemalloc background purge thread did NOT enable on this target (no \
                     background-thread support); enabling busbar's idle purge fallback so RSS still \
                     returns to idle after a load burst"
                );
                false
            }
            Err(e) => {
                eprintln!(
                    "[warn] could not enable jemalloc background purge thread ({e}); enabling \
                     busbar's idle purge fallback so RSS still returns to idle after a load burst"
                );
                false
            }
        };
        // WITHOUT background threads (static-musl release builds — jemalloc compiles them out under
        // musl — and macOS dev builds), jemalloc's decay purge is FOREGROUND-only: it advances only
        // on allocator activity. A fully idle process therefore never purges, so after a big-payload
        // burst RSS ratchets at (roughly) the burst's dirty-page peak forever — observed as
        // idle 8.7 MiB → burst 322 MiB → "idle" 56 MiB that never comes back down. The fallback
        // below restores the return-to-idle property with ZERO unsafe code and ZERO hot-path cost.
        if !enabled {
            spawn_jemalloc_idle_purge_fallback();
        }
    }
    // BUSBAR_PROFILE set → periodically dump the per-stage breakdown to stderr (every 20 s), so a
    // live benchmark run reports stage timings without the in-process test driver. Measurement-only
    // opt-in, absent from any production deployment; zero cost when the env is unset.
    if crate::profile::enabled() {
        std::thread::spawn(|| loop {
            std::thread::sleep(std::time::Duration::from_secs(20));
            crate::profile::dump();
        });
    }
    // Worker-thread count. `BUSBAR_WORKER_THREADS` is the operator override; the DEFAULT is one worker
    // per available core (`available_parallelism`, which respects CPU affinity and cgroup cpuset — but
    // NOT the CFS bandwidth quota `cpu.max`, which it cannot see). So on a quota-limited pod (e.g. 2 CPUs
    // of quota on a 64-core node) this defaults to the NODE's core count, oversubscribing the quota;
    // such deployments should pin `BUSBAR_WORKER_THREADS` to their CPU limit. Uncapped-by-default is
    // what lets throughput scale with cores: v1.3.1–1.3.3 capped the pool at `min(cores, 4)`, which
    // pinned the data plane to ~4 cores and made throughput plateau no matter how big the box (v1.3.0
    // itself was uncapped via `#[tokio::main]`; 1.4.0 restores that default explicitly). The request
    // path is CPU-bound on JSON translate, so it genuinely uses the cores. Footprint-sensitive sidecars
    // (the ~5 MB-idle case) should set `BUSBAR_WORKER_THREADS=1` (or 2): each worker carries a stack and
    // its own allocator arena, so idle RSS grows with the count. Scale up by default, tune down (or to
    // your CPU quota) deliberately.
    // Resolve the worker-thread override, warning on an EXPLICITLY-SET but invalid value rather than
    // silently ignoring it. v1.3.0 ran under `#[tokio::main]`, which fail-fast panicked on a bad
    // `TOKIO_WORKER_THREADS`; 1.4.0 builds the runtime explicitly and would otherwise fall through to
    // all-cores on a `0`/garbage value — a silent footprint surprise. An UNSET var is not warned (it is
    // the normal default path). `TOKIO_WORKER_THREADS` is read as a back-compat fallback so an operator
    // who pinned it on 1.3.0 keeps the same pool size. `eprintln!` because this runs
    // before the tracing subscriber is installed.
    // See the `.min(MAX_WORKER_THREADS)` call below for why this exists.
    // 1.5.3: `advanced.worker_threads` in config.yaml is the home for this knob. `BUSBAR_WORKER_THREADS`
    // still works for one release (deprecation-warned in `worker_threads_from_env` when it parses), and
    // wins when set so an existing pin is honored; else config.yaml; else the standard
    // `TOKIO_WORKER_THREADS`; else one-per-core. The config read is a best-effort early parse (the real
    // load + error reporting happens in `run()` after the runtime is up).
    let worker_threads = worker_threads_from_env("BUSBAR_WORKER_THREADS")
        .inspect(|_| {
            eprintln!(
                "[warn] BUSBAR_WORKER_THREADS is DEPRECATED; set `advanced.worker_threads` in \
                 config.yaml instead (it is honored for now)."
            )
        })
        .or_else(worker_threads_from_config)
        .or_else(|| worker_threads_from_env("TOKIO_WORKER_THREADS"))
        .unwrap_or_else(|| {
            // Fall back to 1 (not 2) when core detection fails, matching v1.3.0's `#[tokio::main]`
            // behavior exactly. Only reachable on an exotic host where `available_parallelism` errors.
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
        })
        // A SANE CEILING. Nothing else in the process bounds concurrent admin requests (the admin
        // router deliberately carries no `GlobalConcurrencyLimitLayer` — see `build_split_routers_
        // with_limits`), so worker-thread count is the actual, if informal, upper bound a few
        // capacity arguments elsewhere lean on (e.g. `admin::audit::WRITE_THROUGH_HEADROOM`'s
        // pressure-valve reserve). An unclamped `available_parallelism()` on very large hardware, or
        // an operator fat-fingering `BUSBAR_WORKER_THREADS`, would otherwise leave that bound
        // unenforced. 128 is far above any realistic core count this process is deployed on and far
        // above what those capacity arguments need.
        .min(MAX_WORKER_THREADS);
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .build()
        .expect("failed to build the tokio runtime")
        .block_on(run());
}

async fn run() {
    // Metrics are configured AFTER the config loads (below, via `metrics::configure`) because they
    // are 100% OPT-IN: `observability.metrics` absent ⇒ no recorder, no `/metrics`, nothing recorded
    // and nothing retained. Nothing may install a recorder before that decision is read.

    // Locate the two config files (env-overridable paths) and run the shared disk-load pipeline —
    // the SAME pipeline `POST /api/v1/admin/config/reload` re-runs at runtime.
    let providers_override = providers_override_from_env();
    let config_path = std::path::PathBuf::from(
        std::env::var(ENV_CONFIG).unwrap_or_else(|_| DEFAULT_CONFIG_PATH.into()),
    );
    let safe_mode = safe_mode_requested(std::env::args());
    let loaded = load_config_from_disk(
        &config_path,
        providers_override.as_deref(),
        safe_mode,
        config::EnvSubst::Strict,
    )
    .unwrap_or_else(|e| die(e));
    let LoadedConfig {
        mut deploy,
        defs,
        providers_path,
        overlay_path,
        config_locked,
        config_read_only,
        overlay_doc,
        unset_env_vars: _,
    } = loaded;

    // 1.5.0 full-config coverage: apply the overlay's `root` section (API-set single-value config —
    // listen/tls/rate_card/store/security/limits/…) onto the base `DeployCfg` BEFORE `resolve`, so
    // the limits projection + the exposed-admin-mTLS boot-guard re-derive over the merged shape. The
    // hooks + groups overlay sections merge POST-resolve (below). `--safe-mode` clears `overlay_doc`,
    // so the root overrides are quarantined too — the whole overlay is one on/off switch.
    if let Some(doc) = overlay_doc.as_ref() {
        config::overlay::apply_root_to_deploy(&mut deploy, doc);
    }

    // The OTLP trace sink — 1.5.3: no longer an `observability:` block, but the `module: otlp`
    // instance of the `export:` NAMED map. Grabbed before `deploy` is borrowed by resolve.
    let otlp_cfg = config::resolve_export(&deploy.export, &mut Vec::new()).otlp;
    // The `advanced.response_headers:` toggles (BOTH default false), read here — same
    // BOOT-ONCE spot as `otlp_cfg` above, for the same reason: `server_timing` is baked into
    // router middleware state below (`build_split_routers_with_limits`) and `route_policy` seeds a
    // process-wide `OnceLock` (`proxy::configure_route_policy_headers`) neither of which a later
    // config apply rebuilds — a live `PUT` is stored but restart-to-apply (see `reload_to_apply`).
    let response_headers_cfg = deploy.advanced.response_headers.clone();
    // `x-busbar-route-policy` / `x-busbar-route-target` are a fingerprintable observable, same class
    // as `Server-Timing: busbar` above, so they too default off and are gated by ONE process-wide
    // decision read at every emission site (`proxy::wire::maybe_attach_route_policy`).
    crate::proxy::configure_route_policy_headers(response_headers_cfg.route_policy);
    // METRICS OPT-IN, read here and nowhere else: 1.5.3 the switch is the built-in `prometheus`
    // EXPORTER (`export.prometheus`) — present ⇒ install the recorder (COLLECTION) with the operator's
    // REQUIRED `buffer_seconds` retention window; absent ⇒ metrics stay off for the life of the
    // process. Called before the App/router is built so the `/metrics` plugin route (DISTRIBUTION, via
    // the built-in exporter) sees a settled recorder decision.
    // 1.5.3: `export:` is a NAMED-DEFINITION map, so the typed per-module projection is lowered here
    // (and reused for `export::configure` below). Any error in it — unknown module, bad settings,
    // duplicate singleton — is reported and FATAL a few lines down in `config::resolve`, which runs
    // the same lowering; discarding the error list here just avoids reporting it twice.
    let resolved_export = config::resolve_export(&deploy.export, &mut Vec::new());
    metrics::configure(
        resolved_export
            .prometheus
            .as_ref()
            .map(|p| Duration::from_secs(p.buffer_seconds)),
    );
    // The top-level `plugins:` block (master switch + dir + trust). Absent = disabled defaults.
    let plugins_cfg = deploy.plugins.clone();

    // BOOT-TIME dead-pid sweep: remove any orphaned plugin staging directory a CRASHED prior busbar
    // left behind (a clean shutdown removes its own; a dead pid's files are unlocked). Runs even
    // when plugins are disabled — the orphan may predate a config change.
    let swept = busbar_plugin_loader::sweep_dead_staging();
    if swept > 0 {
        eprintln!(
            "[info] removed {swept} orphaned plugin staging dir(s) left by a crashed prior run"
        );
    }

    // Install the tracing subscriber now (stderr fmt always; OTLP export if configured) so all
    // subsequent startup and request-path logging is captured.
    observability::init_logging(otlp_cfg.as_ref().map(|o| o.url.as_str()));

    // First line in the logs: which build is running. Operators need this to confirm a deploy /
    // correlate logs to a release without shelling in to run `--version`.
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "busbar starting");
    // 1.5.3 config-management posture (the boot invariant already held in `load_config_from_disk`):
    // LOCKED ⇒ no overlay, mutations refused; MUTABLE ⇒ a writable overlay backend, mutations durable.
    if config_locked {
        tracing::info!(
            "config is LOCKED (config.locked: true): admin-API config mutations are refused; edit \
             config.yaml and POST /config/reload to change config"
        );
    } else if let Some(p) = overlay_path.as_ref() {
        tracing::info!(
            overlay = %p.display(),
            "config is mutable; admin-API changes persist to the overlay backend (durable across restart)"
        );
    } else if config_read_only {
        // MUTABLE by declaration, but the overlay backend is not writable (a read-only config mount).
        // `resolve_backend` already warned with the remediation; repeat the posture here so the one
        // line an operator greps for ("config is ...") never claims a durability busbar does not have.
        tracing::warn!(
            "config is READ-ONLY (the overlay backend is not writable): busbar serves traffic \
             normally, but admin-API config mutations are refused. Set `config.locked: true` to \
             declare this deliberately, or give `config.overlay.file` a writable path."
        );
    }
    // Stamp process start for the `GET /api/v1/admin/info` uptime read.
    admin::mark_start();

    // Resolve deployment + definitions into resolved RootCfg (semantic validation runs inside
    // build_app_from_config — the one construction path).
    let mut cfg = config::resolve(&deploy, &defs)
        .unwrap_or_else(|errs| die(format!("config errors:\n  - {}", errs.join("\n  - "))));
    // The BASE hook + group names (config-defined, pre-overlay): the admin API refuses to
    // PUT-replace / DELETE one (edit config.yaml — the overlay can't durably shadow file config).
    let base_hook_names: std::collections::HashSet<String> = cfg.hooks.keys().cloned().collect();
    let base_group_names: std::collections::HashSet<String> = cfg.groups.keys().cloned().collect();
    // Merge the persisted overlay (API-registered hooks + groups) onto the RESOLVED registry.
    if let Some(doc) = overlay_doc {
        config::overlay::merge_into(&mut cfg, doc);
    }

    // Metadata-SSRF protection status (discoverability). When the nuclear `allow_all_metadata` is set
    // the guard is OFF — that is a security-relevant degradation, so WARN. Otherwise report the count
    // of blocked hosts (hardcoded denylist ∪ security.blocked_metadata_hosts) and point at the CLI
    // flag that dumps the full list.
    if cfg.allow_all_metadata {
        tracing::warn!("metadata protection DISABLED — all cloud-metadata endpoints reachable");
    } else {
        let blocked =
            config_validate::metadata_denylist_entries().len() + cfg.blocked_metadata_hosts.len();
        tracing::info!(
            "metadata protection: {blocked} hosts blocked (--print-metadata-blocklist to view)"
        );
    }

    let listen = cfg.listen.clone();
    let tls_cfg = cfg.tls.clone();
    // The admin plane ALWAYS runs on its own listener (`admin_listen`, default loopback 127.0.0.1:8081)
    // with its own optional TLS/mTLS — never on the data listener. The exposed-admin-requires-mTLS
    // boot-guard has already run in `config::resolve`, so by here `admin_listen` is loopback, mTLS,
    // or an explicit `admin_require_mtls: false` waiver.
    let admin_listen = cfg.admin_listen.clone();
    let admin_tls_cfg = cfg.admin_tls.clone();
    let req_body_max = cfg.limits.request_body_max_bytes;
    let max_inbound = cfg.limits.max_inbound_concurrent;
    // The secret resolver the listeners resolve TLS cert/key/CA references through - the SAME seam
    // (built-in env/file + kind:secret plugins) that resolved provider keys at build time.
    // Boot has no `prior` App, so `build_app_from_config` never resolves a credential rotation here
    // (that branch is gated on `prior.is_some()`) — the discarded closure is always `None`.
    //
    // blocking-ffi-lint: allow — BOOT. Two independent reasons, either sufficient: (1) `run()` is
    // driven by `.block_on(run())` (this file, in `main()`), so it is polled on the MAIN thread, not
    // on a Tokio worker — there is no worker to park; (2) this precedes the `tokio::join!` over
    // `serve_listener` below, so neither listener has been bound, let alone is accepting.
    let (boot_app, _boot_gov_rotate) = build_app_from_config(
        cfg,
        plugins_cfg,
        overlay_path,
        base_hook_names,
        base_group_names,
        (Some(config_path.clone()), Some(providers_path.clone())),
        None,
    )
    .unwrap_or_else(|e| die(e));
    let app = Arc::new(boot_app);

    // Record the BOOT snapshot as version 0 so the version history always has a rollback floor
    // (the pre-any-mutation state).
    app.versions
        .record(0, "system", "boot", &app.hook_registry, &app.global_hooks);

    // DURABLE AUDIT (#17): the audit log is STATEFUL, so its single durable home is the configured
    // governance store — never a side-car file (store-or-RAM rule). When a durable store is configured
    // (sqlite/postgres/valkey), attach it as the write-through SINK (every future admin mutation
    // persists as it is appended) and RESTORE the ring from it: the store is the source of truth, so
    // its history (which can exceed the RAM ring bound) survives restart with the hash chain intact.
    // The RAM default (`store: memory`) has no durable audit — the sink no-ops and the restore reads
    // nothing — so the log is ephemeral BY DESIGN, started fresh on every boot. A chain-verification
    // failure on restore is logged as a tamper signal; there is no file fallback to fall back to.
    if let Some(gov) = app.governance.as_ref() {
        let store = gov.store();
        crate::admin::audit::AUDIT.set_sink(store.clone());
        match crate::admin::audit::AUDIT.restore_from_store(store.as_ref()) {
            Ok(0) => {} // no durable audit (memory default / empty) — start with an empty ring
            Ok(n) => tracing::info!(
                entries = n,
                "audit log restored from the durable governance store"
            ),
            // A store READ failure and a chain-VERIFICATION failure are different events: the first
            // is a hiccup, the second is tamper evidence. Reporting both as "chain verification"
            // trains an operator to ignore the one that matters.
            Err(e) if is_audit_restore_read_hiccup(&e) => tracing::warn!(
                error = %e,
                "could not read the durable audit log; starting with an empty audit ring"
            ),
            Err(e) => tracing::error!(
                error = %e,
                "durable audit CHAIN VERIFICATION failed — the persisted log does not verify \
                 against its own hash chain; starting with an empty audit ring"
            ),
        }
    }

    // DURABLE A2A TASK STATE. A2A is ASYNC BY DESIGN: a task spans turns, can be interrupted
    // waiting on a human, and can outlive the process that started it. An in-memory task table
    // therefore loses every in-flight task and every interrupt on restart, which is the difference
    // between a suspend/resume that is real and one that is nominal. Same shape as the durable audit
    // above and for the same reasons: the configured governance store is the single durable home
    // (store-or-RAM rule), attached as a write-through SINK and read back here.
    //
    // The RAM default (`store: memory`) implements none of the task methods, so the sink no-ops and
    // the restore reads nothing — in-flight tasks are ephemeral BY DESIGN there, exactly as the
    // audit log is. That is reported rather than papered over.
    if let Some(gov) = app.governance.as_ref() {
        let store = gov.store();
        crate::a2a::taskstore::TASKS.set_sink(store.clone());
        match crate::a2a::taskstore::TASKS.restore_from_store(store.as_ref()) {
            Ok(r) if r == crate::a2a::taskstore::Rehydrated::default() => {}
            Ok(r) => {
                tracing::info!(
                    active = r.active,
                    terminal = r.terminal,
                    unreadable = r.unreadable,
                    "A2A in-flight tasks rehydrated from the durable governance store"
                );
                // An UNREADABLE row is an in-flight task that this binary cannot resume. Reported
                // separately and at WARN, because summing it into the restored count is how a task
                // that silently ceased to exist across a deploy stays invisible.
                if r.unreadable > 0 {
                    tracing::warn!(
                        rows = r.unreadable,
                        "persisted A2A task rows could not be read back and are NOT resumable; \
                         they were most likely written by a different engine version"
                    );
                }
                // A chain break is TAMPER EVIDENCE and is a different event from a read hiccup, so
                // it is logged at ERROR and names the task rather than being folded into a count.
                for brk in &r.chain_breaks {
                    tracing::error!(
                        task_id = %brk.task_id,
                        break_detail = %brk,
                        "A2A per-task provenance CHAIN VERIFICATION FAILED on restore"
                    );
                }
            }
            Err(e) => tracing::warn!(
                error = %e,
                "could not read durable A2A task state; in-flight tasks start empty"
            ),
        }
    }

    // DURABLE MCP PER-CALL LOG. The tamper-evident record of who called which tool, under which
    // approved digest, and whether it went out — the Art 26(6) record-keeping pillar, and the thing
    // that makes "tamper-evident audit" a property an operator can exercise rather than a sentence.
    //
    // Attached here for the same reason and in the same shape as the two blocks above: the
    // configured governance store is the single durable home (store-or-RAM rule), attached as a
    // write-through sink and READ BACK, because a write's `Ok(())` proves nothing about a trait
    // whose defaults accept and keep nothing.
    //
    // THE RESTORE IS NOT A FORMALITY. It is the only place in a running deployment where a persisted
    // chain is recomputed, so it is also the only place a tamper is detected — every break it finds
    // is logged at ERROR, naming the principal, while the records stay restored (refusing to restore
    // them would let anyone able to write to the store DELETE a caller's history by corrupting one
    // byte). With `store: memory` nothing is implemented, the sink no-ops and this reports zero: the
    // call log is ephemeral BY DESIGN there, exactly as the audit ring and the task table are.
    if let Some(gov) = app.governance.as_ref() {
        let store = gov.store();
        crate::mcp::calllog::CALLS.set_sink(store.clone());
        match crate::mcp::calllog::CALLS.restore_from_store(store.as_ref()) {
            Ok(r) if r == crate::mcp::calllog::Restored::default() => {}
            Ok(r) => {
                tracing::info!(
                    principals = r.principals,
                    records = r.records,
                    "MCP per-call log restored from the durable governance store"
                );
                // An ENUMERATED-BUT-EMPTY chain is the one shape the verifier cannot judge alone,
                // and it is what one caller's evidence being deleted wholesale looks like. Counted
                // and surfaced separately rather than summed into `principals`.
                if r.empty_chains > 0 {
                    tracing::warn!(
                        principals = r.empty_chains,
                        "the durable MCP call log enumerates these principals but holds NO records \
                         for them; their chains reopen at seq 1"
                    );
                }
                for brk in &r.chain_breaks {
                    tracing::error!(
                        break_detail = %brk,
                        "MCP per-call CHAIN VERIFICATION FAILED on restore — TAMPER EVIDENCE"
                    );
                }
            }
            Err(e) => tracing::warn!(
                error = %e,
                "could not read the durable MCP per-call log; chains start at their persisted \
                 tail being unknown, which means a principal with rows in the store may reopen at \
                 seq 1 and collide"
            ),
        }
    }

    // RELIABILITY STATE IS STATELESS (store-or-RAM rule): circuit breakers, cooldowns, latency EWMAs
    // and hard-down latches live in RAM only and are RE-LEARNED after a restart (a lane that is down
    // re-trips its breaker on request #1). Nothing is restored from disk — the durable config that
    // makes "fix the config and restart" the recovery path lives in the config-overlay persistence,
    // not in a health snapshot. The config version-history ring is likewise RAM-only, re-seeded here
    // at its boot floor (see `app.versions.record(0, …)` above); durable cross-restart rollback would
    // need a store seam, which does not exist over the plugin wire ABI today (see the 1.5.3 report).
    tracing::info!(
        "reliability state (breakers, cooldowns, latency, hard-down) starts fresh on boot and is \
         re-learned from live traffic"
    );

    // Configure the built-in request-log EXPORTERS (every named `request-log-webhook` /
    // `request-log-file` instance) from the resolved `export:` block, reusing the pooled client for
    // webhook delivery. No-op when no request-log sink is configured (the default). The
    // recorder-installing `prometheus` exporter is wired separately (`metrics::configure` above +
    // the `/metrics` plugin route in `build_app_from_config`).
    export::configure(&resolved_export, app.client.get().clone());

    // Spawn the active health probers (one per lane with a probing mode). No-op when every lane is
    // `mode: none` / has no `health:` block. Re-spawned on every config reload/apply (see the admin
    // swap sites) so reloaded lanes get probed and the old generation exits.
    health::spawn_probers(&app);

    // Build the two routers with the operator-configured ingress body cap + the inbound-concurrency
    // layer (installed by default; `limits.max_inbound_concurrent: 0` opts out — no layer). The admin surface is built onto its
    // OWN router (ABSENT from the data router) and served on `admin_listen` below; the data router
    // serves the protocols. Both share one `app_handle`, so config-apply hot-swaps reach both planes.
    // Grab the secret resolver before `app` is moved into the router builder - the TLS listeners
    // resolve cert/key/CA references through it below.
    let tls_secret_resolver = app.secret_resolver.clone();
    let (data_router, admin_router, app_handle) = build_split_routers_with_limits(
        app,
        req_body_max,
        max_inbound,
        response_headers_cfg.server_timing,
    );

    // Graceful shutdown: on ctrl_c (SIGINT) or SIGTERM, stop accepting new connections, let
    // in-flight requests drain, then flush the OTLP tracer so the final (most diagnostic) spans are
    // exported rather than dropped when the runtime tears down. The signal future is panic-free —
    // a failed registration logs and parks forever (so a missing signal facility degrades to "no
    // graceful shutdown", never a crash), and `shutdown_tracing()` is a no-op when OTLP is off.
    // ONE signal fans out to BOTH listeners (data + admin) so both planes drain together.
    let (shutdown_tx, _keep_open) = tokio::sync::broadcast::channel::<()>(1);
    // Publish the sender so `POST /admin/restart` can trigger the SAME drain a signal does. A
    // process-global is the honest home: restarting is a process-wide act, not a property of an
    // `App` snapshot, and `AppHandle` is built before this channel exists.
    crate::admin::restart::publish_shutdown(shutdown_tx.clone());
    {
        let shutdown_tx = shutdown_tx.clone();
        tokio::spawn(async move {
            shutdown_signal().await;
            let _ = shutdown_tx.send(());
        });
    }

    // WRITE-BEHIND BUDGET FLUSHER: the in-memory budget counters are authoritative on the request hot
    // path (no SQLite await on admission); this background task periodically flushes accrued
    // spend/requests to the durable store and runs one FINAL flush when the shutdown signal fires, so
    // a graceful stop loses nothing (an ungraceful crash can lose at most one flush interval). Spawned
    // once here (not on config apply/reload — the reused `Arc<GovState>` keeps its live cells and its
    // already-running flusher). No-op when governance is disabled.
    if let Some(gov) = app_handle.load().governance.clone() {
        // Handle intentionally dropped (not awaited): the flusher runs for the process lifetime and
        // exits its own loop on the shutdown broadcast; nothing here needs to join it.
        std::mem::drop(crate::governance::spawn_budget_flusher(
            gov,
            shutdown_tx.subscribe(),
        ));
    }

    // THE MCP REFRESH JOB — the same defence as the A2A one below, on the other plane, and the
    // reason it exists is that until it did, quarantine-on-drift needed an operator to be present.
    // `mcp::connect::refresh` had exactly ONE production caller and it was the admin verb
    // `POST /admin/tools/{name}/connect`, so an upstream that swapped a tool's schema against an
    // unattended deployment was detected exactly never. Schema hash-pinning with automatic drift
    // quarantine is the one defence the competitive survey found nobody else shipping; it is not
    // automatic if it waits for a human.
    //
    // Spawned only when there is a registration to sweep — a deployment with no `tools:` servers
    // starts no job — and spawned ONCE here rather than on apply, for the same reason the flusher
    // and the A2A job are: a second job against the same registry would double every fetch and race
    // every ledger stamp. It holds the HANDLE, not the app, so a config apply is picked up on the
    // next tick rather than sweeping a generation the operator has already replaced.
    //
    // The decision itself lives in `mcp::spawn_refresh_job` rather than inline here, because
    // `run()` binds real listeners and joins them and so nothing can test a line of it. While this
    // was inline, the whole battery in `mcp/tests/timer_dispatch_tests.rs` called `refresh_sweep`
    // by hand, and deleting this block would have failed exactly nothing.
    //
    // Handle intentionally dropped, exactly as the A2A job's is: it runs for the process lifetime
    // and exits its own loop on the shutdown broadcast.
    std::mem::drop(crate::mcp::spawn_refresh_job(
        &app_handle,
        shutdown_tx.subscribe(),
    ));

    // THE A2A RE-VERIFICATION JOB. An approval is a statement about a document at a moment and
    // nothing keeps it true; the pin catches a change only when somebody looks, and this is what
    // makes somebody look. Spawned only when `agents:` defines a plane — a deployment that fronts
    // no agents starts no job — and spawned once here rather than on apply, for the same reason the
    // flusher is: a second job against the same registry would double every fetch and race every
    // ledger stamp.
    if let Some(plane) = app_handle.load().a2a.clone() {
        tracing::info!(
            agents = plane.len(),
            tick_secs = crate::trust::sweep::SWEEP_TICK.as_secs(),
            "a2a: re-verification job started"
        );
        // PUBLISH BUSBAR'S AGENT-CARD ISSUER KEY, once, at the one moment an operator is watching.
        //
        // busbar signs the cards it serves so external callers have something to pin it BY, and a
        // pin is only a root if the pinning party got the key OUT OF BAND — which means a human has
        // to be able to read it off this deployment and hand it over. It is a PUBLIC key, so a log
        // line is the right place for it; the secret it is derived from never appears here or
        // anywhere else. Logged beside the plane's start rather than at key resolution, because
        // this value only means anything where an A2A plane is actually serving cards.
        if let Some(signer) = app_handle
            .load()
            .governance
            .as_ref()
            .and_then(|g| g.a2a_card_signer())
        {
            tracing::info!(
                kid = signer.kid(),
                issuer_key = signer.issuer_spki_base64(),
                "a2a: agent cards served by this deployment are signed with this key; give it to \
                 callers out of band so they can pin busbar"
            );
        }
        // THE OUTBOUND CLIENT CERTIFICATES, resolved ONCE, HERE, and fatal if they do not.
        //
        // Same discipline as `tls::build_server_config` on the inbound side: a cert/key that does
        // not load is a startup failure naming its source, never a warning. A registration whose
        // `client_identity:` did not resolve could never complete a handshake with its endpoint, so
        // booting past it would produce a deployment that re-verifies nothing for that agent while
        // reading, in config and in the admin API, as though mutual TLS were configured.
        let a2a_identities = crate::a2a::transport::resolve_client_identities(
            &app_handle.load().agent_defs,
            &app_handle.load().secret_resolver,
        )
        .unwrap_or_else(|e| die(format!("a2a: outbound client identity: {e}")));
        // Handle intentionally dropped, exactly as the flusher's is: the job runs for the process
        // lifetime and exits its own loop on the shutdown broadcast.
        // THE PER-AGENT TRANSPORTS, BUILT ONCE for the job's lifetime rather than per tick. The
        // identities were resolved at boot and the plane the job holds is this generation's, so
        // rebuilding the bundle every thirty seconds would re-derive a constant — and, now that a
        // transport can carry a private key, would do so with key material in hand on every tick.
        let live = std::sync::Arc::new(crate::a2a::transport::LiveCardFetch::presenting(
            plane.fetch_policy().clone(),
            &a2a_identities,
        ));
        std::mem::drop(crate::trust::sweep::spawn(
            crate::a2a::verify::ReverifySweeper { plane, live },
            shutdown_tx.subscribe(),
        ));
    }

    // Data plane on `listen`, admin plane on its own `admin_listen`, served concurrently — each with
    // its own TLS/mTLS. `tokio::join!` returns only once BOTH have drained.
    let data_listener = bind_listener(&listen).await;
    let admin_listener = bind_listener(&admin_listen).await;
    tokio::join!(
        serve_listener(
            data_listener,
            data_router,
            tls_cfg,
            tls_secret_resolver.clone(),
            &listen,
            recv_shutdown(shutdown_tx.subscribe()),
        ),
        serve_listener(
            admin_listener,
            admin_router,
            admin_tls_cfg,
            tls_secret_resolver.clone(),
            &admin_listen,
            recv_shutdown(shutdown_tx.subscribe()),
        ),
    );
    // BUDGET WRITE-BEHIND: one FINAL, SYNCHRONOUS flush after the graceful drain, so a graceful stop
    // persists the freshest accrued spend/requests before the process exits. The background flusher's
    // shutdown arm also flushes, but it is a fire-and-forget task that could lose the race with process
    // exit; flushing inline here on the run task guarantees durability (this call blocks briefly under
    // the budget lock, off any request path — the listeners have already drained).
    if let Some(gov) = app_handle.load().governance.clone() {
        let n = gov.flush_budgets();
        tracing::info!(flushed = n, "budget counters flushed on shutdown");
        // The flusher task's own shutdown arm also flushes metering, but it is fire-and-forget and
        // can lose the race with process exit (same reason the budget flush above is inline here).
        let m = gov.flush_metering();
        tracing::info!(flushed = m, "metering rows flushed on shutdown");
    }
    // No state snapshot on shutdown: reliability state is RAM-only (re-learned on boot) and the
    // audit log is written through to the durable store as it happens (store-or-RAM rule — there is
    // no side-car state file to flush).
    observability::shutdown_tracing();
}

/// Bind a TCP listener or `die` with a clear, address-named message. Shared by the data and admin
/// listeners so both fail fast and identically on a bad bind.
async fn bind_listener(addr: &str) -> tokio::net::TcpListener {
    tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| die(format!("cannot bind listen address '{addr}': {e}")))
}

/// One shutdown-broadcast subscription resolved into a plain future. Any receive outcome — a send,
/// or a closed/lagged channel — means "shut down now", so every arm resolves the future.
async fn recv_shutdown(mut rx: tokio::sync::broadcast::Receiver<()>) {
    let _ = rx.recv().await;
}

/// Serve one listener (data OR admin plane) to graceful shutdown. Picks plain-HTTP vs native TLS/mTLS
/// from `tls_cfg` exactly as the single-listener path always has: `None` ⇒ plain HTTP over the shared
/// slow-loris-hardened hyper loop; `Some` ⇒ terminate TLS (mTLS when `client_ca_file` is set), with
/// cert/key/CA loaded and validated up front so a bad path/parse `die`s at startup, not per request.
/// `label` names the plane in log lines and error messages. Any serve error `die`s the process.
async fn serve_listener(
    listener: tokio::net::TcpListener,
    router: Router,
    tls_cfg: Option<crate::config::TlsCfg>,
    secret_resolver: Arc<crate::config::secret::SecretResolver>,
    label: &str,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) {
    match tls_cfg {
        None => {
            tracing::info!(listen = %label, "busbar listening");
            if let Err(e) = tls::serve_plain(listener, router, shutdown).await {
                die(format!("server error on '{label}': {e}"));
            }
        }
        Some(tls) => {
            tls::install_crypto_provider();
            // blocking-ffi-lint: allow — BOOT, once per listener, before that listener accepts.
            // `serve_listener` is not spawned: both calls are arms of the `tokio::join!` in `run()`
            // (this file), and `run()` is polled by `.block_on(run())` on the MAIN thread, so this
            // resolve parks the boot thread rather than a Tokio worker. It also completes before
            // `tls::serve` below is reached, so no connection on this listener can be waiting on it.
            let server_config = tls::build_server_config(&tls, &secret_resolver)
                .unwrap_or_else(|e| die(format!("TLS configuration error for '{label}': {e}")));
            let mtls = tls.client_ca.is_some();
            tracing::info!(listen = %label, mtls, "busbar listening (TLS)");
            if let Err(e) = tls::serve(listener, router, server_config, shutdown).await {
                die(format!("server error on '{label}': {e}"));
            }
        }
    }
}

/// Resolve when the process receives a shutdown signal (SIGINT/ctrl_c, or SIGTERM on Unix). Used as
/// the `axum::serve(...).with_graceful_shutdown` future. Never panics: a signal-handler
/// registration error is logged and the corresponding branch parks forever, so the other branch
/// still triggers shutdown and a registration failure can never abort a worker.
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::warn!(error = %e, "failed to install ctrl_c handler; SIGINT shutdown disabled");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to install SIGTERM handler; SIGTERM shutdown disabled");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
    tracing::info!("shutdown signal received; draining in-flight requests");
}

/// Render a native ingress error envelope (`application/json`) for the fallback handlers, in the
/// dialect the path is spoken in — attaching the `x-amzn-*` headers when that dialect is Bedrock,
/// so the response is indistinguishable from a real vendor 404/405, and answering in JSON-RPC on a
/// path a plane has been MOUNTED on. Shared by the 404 catch-all, [`method_not_allowed_handler`]
/// (405, wrong method on a valid path) and the oversized-body 413 reshape.
///
/// `planes` is the mount table, and it is a parameter rather than something inferred here because
/// a mount is a fact about the deployment: no amount of looking at the path reveals it, and the
/// version of this function that tried shipped an OpenAI envelope onto the MCP plane.
pub(crate) fn fallback_error_response(
    planes: &crate::plane::PlaneDispatch,
    path: &str,
    status: axum::http::StatusCode,
    kind: &str,
    message: &str,
) -> axum::response::Response {
    // The NATIVE-API root speaks the frozen admin envelope for EVERY response — including unmatched
    // paths and wrong methods, which previously fell through to the vendor-native shaping below and
    // leaked `{error:{type}}` bodies onto a surface that promises `{error:{code}}`.
    // Boundary-safe: exact root or root + '/'.
    {
        use crate::admin::v1::contract::{AdminError, API_ROOT};
        if path == API_ROOT || path.starts_with(&format!("{API_ROOT}/")) {
            let e = if status == axum::http::StatusCode::METHOD_NOT_ALLOWED {
                AdminError::MethodNotAllowed
            } else {
                AdminError::not_found("resource")
            };
            return crate::admin::v1::json::err_json(&e);
        }
    }
    // ONE resolver, ONE shaping seam. The provider-specific response headers (Bedrock
    // `x-amzn-RequestId`/`x-amzn-errortype`; Anthropic `request-id`) come with it, dispatched
    // through the writer vtable inside `proxy::ingress_error`, so this handler matches the shape
    // the hot path produces and carries no provider name-branch of its own.
    crate::ingress::native::native_error(planes.ingress_of(path), status, kind, message)
}

// NOTE: the 404 fallback handler is superseded by `ingress::protocol_dispatch`, which owns the
// catch-all and reproduces the same native-envelope 404 shaping for non-protocol paths.

/// 405 fallback: a valid ingress path hit with the wrong method (e.g. GET on a POST-only ingress).
/// axum's built-in 405 is an `Allow`-header-only empty body; reshape to the protocol-native envelope
/// so an SDK sees a vendor-shaped error instead of a bare proxy tell.
async fn method_not_allowed_handler(
    crate::state::CurrentApp(app): crate::state::CurrentApp,
    uri: axum::http::Uri,
) -> axum::response::Response {
    fallback_error_response(
        &app.planes,
        uri.path(),
        axum::http::StatusCode::METHOD_NOT_ALLOWED,
        crate::admin::ERR_TYPE_INVALID_REQUEST,
        "method not allowed for this resource",
    )
}

/// The SENTINEL substring in the `text/plain` body axum's `DefaultBodyLimit` emits when a request
/// exceeds the limit — used to distinguish axum's OWN body-limit 413 from a forward-path-relayed
/// upstream 413, which must pass through untouched.
///
/// SUBSTRING, NOT BYTE-EQUALITY, and that is the fix. This was pinned to axum 0.7's EXACT body
/// (`"length limit exceeded"`), and axum-core 0.5 renders the same rejection as
/// `"Failed to buffer the request body: length limit exceeded"` — the `__define_rejection!`
/// Error-variant arm prefixes the outer `FailedToBufferBody` prose onto the inner error. So on
/// axum 0.8 the equality gate NEVER matched and the whole reshape was dead code in production:
/// every oversized request, admin and data plane alike, answered with a bare `text/plain` body.
/// That broke the admin surface's frozen `{error:{code}}` envelope (tooling that branches on `code`
/// throws on parse) and handed official OpenAI/Anthropic/Bedrock SDKs a router tell instead of the
/// vendor-native JSON envelope.
///
/// Matching the inner error's own words survives that wrapping. The residual risk — a relayed
/// UPSTREAM `text/plain` 413 whose body happens to contain this phrase being reshaped into a JSON
/// envelope of the same status — is far smaller than the risk this replaced, and is bounded to the
/// envelope shape (the status is 413 either way).
///
/// THE REAL GUARD IS THE TEST, not this constant. Every prior test of this path hand-constructed
/// the marker and called the pure reshape function, so all four stayed green while the layer was
/// dead. `oversized_request_413_is_reshaped_on_the_live_stack` drives a real oversized request
/// through the real layer stack, so the next time axum changes its prose the build goes red instead
/// of the reshape silently switching itself off.
const AXUM_BODY_LIMIT_413_MARKER: &[u8] = b"length limit exceeded";

/// Reshape an oversized-body rejection into a protocol-native error. axum's `DefaultBodyLimit`
/// rejects a too-large request with HTTP 413 and a bare `text/plain` body (`"length limit
/// exceeded"`) — a router/proxy tell no native vendor API emits. This middleware wraps the
/// body-limit layer: it captures the request path, runs the inner
/// stack, and when the result is axum's OWN body-limit 413 (identified by the
/// [`AXUM_BODY_LIMIT_413_MARKER`] sentinel body — NOT merely any non-JSON 413), it replaces that
/// response with the inferred ingress protocol's native JSON `request_too_large` envelope (Bedrock
/// variants also gain `x-amzn-*` headers, via [`fallback_error_response`]). Any other 413 — a
/// forward-path-relayed UPSTREAM 413 (whatever its content-type), or one a real ingress handler
/// already shaped as JSON — is passed through untouched.
///
/// The envelope is the one the PATH's resolved ingress speaks, which is why this layer takes the
/// swappable app handle: a body cap fires OUTSIDE routing and OUTSIDE auth, so the mount table is
/// the only thing that can tell it whether `/mcp` is an MCP plane or an unclaimed residual path.
/// Before it had one, every oversized POST — mounted plane or not — was answered in an OpenAI
/// envelope.
async fn reshape_body_limit_413(
    axum::extract::State(handle): axum::extract::State<std::sync::Arc<state::AppHandle>>,
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let path = req.uri().path().to_owned();
    // The snapshot is taken AFTER the inner stack runs, so a config apply mid-request shapes the
    // answer with the mount table that is live when the answer is written.
    let resp = next.run(req).await;
    reshape_oversized_413(&handle.load().planes, &path, resp).await
}

/// Per-process count of requests that entered the middleware stack — the idleness signal for the
/// jemalloc idle-purge fallback (bumped once per request in `server_timing`, read every sweep tick
/// by the purge thread). Wraps harmlessly (only equality-across-a-window is compared).
static REQUEST_ACTIVITY_TICKS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// How often the idle-purge fallback wakes to check for idleness (and how long a request-free window
/// must be before it purges). 15 s keeps "RSS returns to idle within ~60 s of load stopping" with
/// plenty of margin while never firing under any sustained traffic.
#[cfg(not(target_env = "msvc"))]
const IDLE_PURGE_SWEEP_SECS: u64 = 15;

/// FALLBACK idle purge for targets where jemalloc's background purge threads are unavailable
/// (static-musl release builds compile them out; macOS lacks them). jemalloc's decay purge is
/// otherwise FOREGROUND-only — driven by allocator activity — so a fully idle process never returns
/// its freed dirty pages to the OS and RSS ratchets at the last burst's peak (measured on this
/// machine: an 8-worker burst left 595 MiB of freed-but-unpurged RSS parked indefinitely; one purge
/// pass dropped it to 14.7 MiB). This thread watches the request-activity ticker and, after a full
/// sweep window with ZERO requests, forces a one-shot purge of every INITIALIZED arena's dirty pages
/// by writing `arena.<i>.dirty_decay_ms = 0` (jemalloc's documented "purge all unused dirty pages
/// immediately" setting) and then restoring the configured decay value — all through
/// tikv-jemalloc-ctl's SAFE typed mallctl API (`AsName`/`Access`; no `unsafe` anywhere).
///
/// Per-arena (not the `MALLCTL_ARENAS_ALL` pseudo-index) because the ALL write EFAULTs the moment it
/// hits an UNINITIALIZED arena (jemalloc creates arenas lazily; most of the default 4×ncpu set never
/// initialize), poisoning the whole batch. Individual errors on uninitialized arenas are expected
/// and skipped; `arenas.narenas` is re-read each pass so late-created arenas are covered.
///
/// Request behavior is untouched: the purge only ever fires in a window that served NO requests, the
/// restore returns decay to exactly the configured value, and under load the thread does nothing but
/// one atomic read per 15 s. Repeated purges on a long-idle process are no-ops (no dirty pages
/// remain). Best-effort throughout — mallctl errors are skipped, never panicked on.
#[cfg(not(target_env = "msvc"))]
fn spawn_jemalloc_idle_purge_fallback() {
    use tikv_jemalloc_ctl::{Access, AsName};
    // The configured default decay (what arenas run with; the value restored after each purge).
    const ARENAS_DIRTY_DECAY_DEFAULT: &[u8] = b"opt.dirty_decay_ms\0";
    const ARENAS_NARENAS: &[u8] = b"arenas.narenas\0";
    let spawned = std::thread::Builder::new()
        .name("busbar-idle-purge".into())
        .spawn(move || {
            let restore: isize = match ARENAS_DIRTY_DECAY_DEFAULT.name().read() {
                Ok(v) => v,
                Err(e) => {
                    eprintln!(
                        "[warn] jemalloc idle-purge fallback disabled: could not read \
                         opt.dirty_decay_ms ({e})"
                    );
                    return;
                }
            };
            let mut last = REQUEST_ACTIVITY_TICKS.load(std::sync::atomic::Ordering::Relaxed);
            loop {
                std::thread::sleep(std::time::Duration::from_secs(IDLE_PURGE_SWEEP_SECS));
                let cur = REQUEST_ACTIVITY_TICKS.load(std::sync::atomic::Ordering::Relaxed);
                let idle = cur == last;
                last = cur;
                if !idle {
                    continue;
                }
                // Idle window: force the purge on every initialized arena (decay 0 ⇒ jemalloc purges
                // all unused dirty pages during the set), then restore the configured decay. An
                // uninitialized arena's write errors — expected; skip it.
                let narenas: u32 = ARENAS_NARENAS.name().read().unwrap_or(0);
                for i in 0..narenas {
                    let key = format!("arena.{i}.dirty_decay_ms\0");
                    let name = key.as_bytes().name();
                    let _ = name.write(0isize).and_then(|()| name.write(restore));
                }
            }
        });
    if let Err(e) = spawned {
        eprintln!("[warn] could not spawn the jemalloc idle-purge fallback thread ({e})");
    }
}

/// Compute the `Server-Timing` `dur` value (milliseconds) for a request: Busbar's own processing
/// time = total request wall-clock minus the upstream round-trip. `upstream_us == u64::MAX` means
/// "no upstream hop" (admin/health/early error), so the full time is reported. Saturating, so clock
/// skew (upstream measured slightly larger than total) can never underflow into a huge value.
fn server_timing_dur_ms(total_us: u64, upstream_us: u64) -> f64 {
    let internal_us = if upstream_us == NO_UPSTREAM_RTT {
        total_us
    } else {
        total_us.saturating_sub(upstream_us)
    };
    internal_us as f64 / 1000.0
}

/// Always-installed OUTERMOST-ISH middleware: bumps the jemalloc idle-purge activity ticker (see
/// `spawn_jemalloc_idle_purge_fallback`) on every request. Split out of `server_timing`
/// so the ticker keeps incrementing regardless of whether `advanced.response_headers.server_timing`
/// is enabled — the `server_timing` layer itself is now COMPOSED OUT of the stack entirely when
/// disabled (see `apply_common_layers`), so this is the one piece of its old unconditional behavior
/// that must survive the split. One relaxed atomic add; no allocation, no `Instant::now()`.
async fn request_activity_tick(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    REQUEST_ACTIVITY_TICKS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    next.run(req).await
}

/// Outermost middleware: stamps a standard `Server-Timing: busbar;dur=<ms>` response header
/// reporting the latency Busbar itself added — total request wall-clock MINUS the upstream
/// round-trip — so operators (and browser DevTools / APM tools) can see the gateway's own cost
/// in-band on every response, without scraping `/metrics` or wiring traces. The upstream RTT is
/// recorded by the forward path into the [`proxy::UPSTREAM_RTT_US`] task-local for the duration
/// of this scope; a request that never dispatched upstream (admin / health / early error) reports
/// its full processing time. W3C `Server-Timing` `dur` is milliseconds; emitted at µs precision.
///
/// Gated by `advanced.response_headers.server_timing` (default `false`) — but NOT with an internal
/// `if` check like the pre-task-#139 version. `apply_common_layers` installs this middleware LAYER
/// ONLY when the flag is enabled (composition, mirroring `apply_inbound_concurrency_limit`'s
/// `max_inbound_concurrent > 0` gate), so a disabled deployment never runs this function at all: no
/// per-request `Arc<AtomicU64>` allocation, no `Instant::now()`, no task-local `.scope()` — the
/// former anti-pattern where the flag only suppressed the RESPONSE HEADER after paying the full
/// per-request cost regardless.
async fn server_timing(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use std::sync::atomic::Ordering;
    let slot = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(NO_UPSTREAM_RTT));
    let start = std::time::Instant::now();
    let mut resp = proxy::UPSTREAM_RTT_US
        .scope(slot.clone(), next.run(req))
        .await;
    let total_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
    let dur_ms = server_timing_dur_ms(total_us, slot.load(Ordering::Relaxed));
    if let Ok(v) = axum::http::HeaderValue::from_str(&format!("busbar;dur={dur_ms:.3}")) {
        resp.headers_mut()
            .insert(axum::http::HeaderName::from_static(HEADER_SERVER_TIMING), v);
    }
    resp
}

/// Pure reshaping step of [`reshape_body_limit_413`], split out so it is unit-testable without
/// constructing a `Next`. Returns `resp` unchanged unless it is axum's OWN body-limit 413 —
/// identified by status 413 with a non-JSON content-type AND a body exactly equal to
/// [`AXUM_BODY_LIMIT_413_MARKER`] — in which case it is replaced by the inferred ingress protocol's
/// native JSON `request_too_large` envelope. A 413 a real ingress handler already shaped as
/// `application/json`, or any forward-relayed UPSTREAM 413 (different/non-marker body), is passed
/// through verbatim (the body is buffered to inspect the sentinel, then re-attached unchanged).
async fn reshape_oversized_413(
    planes: &crate::plane::PlaneDispatch,
    path: &str,
    resp: axum::response::Response,
) -> axum::response::Response {
    if resp.status() != axum::http::StatusCode::PAYLOAD_TOO_LARGE {
        return resp;
    }
    // A handler (or upstream relay) that already produced an `application/json` 413 is a native
    // too-large envelope — leave it alone without even buffering the body; re-wrapping would
    // corrupt it, and axum's own body-limit reject is never JSON.
    let is_json = resp
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .is_some_and(|ct| ct.starts_with(crate::proxy::APPLICATION_JSON));
    if is_json {
        return resp;
    }
    // Non-JSON 413: it could be axum's OWN body-limit reject (reshape it) OR a forward-relayed
    // UPSTREAM 413 that happens to be non-JSON (e.g. a `text/plain`/`text/html` upstream error —
    // must pass through untouched). Distinguish by the sentinel body. Buffer the body so
    // we can compare it; if it is not the sentinel, re-attach the buffered bytes verbatim.
    use http_body_util::BodyExt as _;
    let (parts, body) = resp.into_parts();
    let bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        // A 413 body that fails to buffer cannot be confirmed as axum's sentinel; pass the
        // already-consumed parts through with an empty body rather than reshape a non-axum reject.
        Err(_) => return axum::response::Response::from_parts(parts, axum::body::Body::empty()),
    };
    if !bytes
        .windows(AXUM_BODY_LIMIT_413_MARKER.len())
        .any(|w| w == AXUM_BODY_LIMIT_413_MARKER)
    {
        // A relayed upstream 413 (or any non-axum 413): pass through untouched, body re-attached.
        return axum::response::Response::from_parts(parts, axum::body::Body::from(bytes));
    }
    fallback_error_response(
        planes,
        path,
        axum::http::StatusCode::PAYLOAD_TOO_LARGE,
        // CANONICAL kind for an oversized payload across the protocol writers.
        crate::proxy::KIND_REQUEST_TOO_LARGE,
        "request body exceeds the maximum allowed size",
    )
}

/// Everything the DISK half of configuration produces, shared by boot and runtime reload.
pub(crate) struct LoadedConfig {
    pub(crate) deploy: config::DeployCfg,
    pub(crate) defs: HashMap<String, config::ProviderDef>,
    /// The RESOLVED providers-catalog path actually read (1.5.3): `config.providers_file` relative to
    /// the config dir, the deprecated `BUSBAR_PROVIDERS` override, or `providers.yaml` next to the
    /// config. Carried so callers display / re-use the same file across a reload.
    pub(crate) providers_path: std::path::PathBuf,
    /// The resolved config-overlay backend path (1.5.3): `Some` = a writable file backend (mutable
    /// config); `None` = either the config is LOCKED (`config.locked: true`) or its backend is not
    /// writable (a read-only config mount — busbar boots and serves, but refuses config mutations).
    /// The boot invariant guarantees `overlay_path.is_none()` whenever busbar cannot durably persist,
    /// so a `Some` path is always one that was probed writable.
    pub(crate) overlay_path: Option<std::path::PathBuf>,
    /// `config.locked` (1.5.3): `true` ⇒ admin-API config mutations are refused at runtime.
    pub(crate) config_locked: bool,
    /// `true` ⇒ the config did NOT declare `config.locked: true`, but its overlay backend is not
    /// writable (the read-only config mount the documented Docker quickstart creates). Busbar boots
    /// and serves; admin-API config mutations are refused because they could not be persisted.
    /// Distinguished from `config_locked` so the boot log can tell the operator which of the two
    /// postures they are in — one they chose, one the filesystem chose for them.
    pub(crate) config_read_only: bool,
    /// The persisted overlay document (API-registered hooks), applied onto the RESOLVED config
    /// (`overlay::merge_into(&mut RootCfg, …)`) after `config::resolve` - the runtime registry is
    /// synthesized there, so the overlay merges post-resolve. `None` = absent / safe mode.
    pub(crate) overlay_doc: Option<config::overlay::OverlayDoc>,
    /// `${VAR}` refs that were UNSET during interpolation. Empty under Strict (boot/reload); populated
    /// under Lenient (--validate), where it becomes the "set these at runtime" note.
    pub(crate) unset_env_vars: Vec<String>,
}

/// The disk-load pipeline: read providers.yaml + config.yaml, env-interpolate (from the process's
/// boot-time environment — a live reload cannot see edited env files; documented), capture the
/// BASE hook names, then merge the persisted overlay (opt-in, fail-soft). Shared verbatim by boot
/// and `POST /api/v1/admin/config/reload`, so a reload IS a boot-equivalent read of disk truth.
/// `--migrate-config <old.yaml>`: mechanically convert a 1.4.x config to the 1.5.0 shape.
/// Prints the migrated YAML (with a TODO/WARNING comment header) to STDOUT and the change summary
/// to STDERR - zero side effects, nothing is written, no env interpolation (a `${VAR}` reference
/// passes through verbatim so the output stays a template). Exit 0 on success (even with TODOs -
/// they are review items, not errors), 1 on unreadable/unparseable input, 2 on a missing path.
fn migrate_config_command(path: Option<String>) -> i32 {
    let Some(path) = path else {
        eprintln!(
            "busbar: --migrate-config requires a path: busbar --migrate-config <old-config.yaml>"
        );
        return 2;
    };
    let raw = match std::fs::read_to_string(&path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("busbar: cannot read '{path}': {e}");
            return 1;
        }
    };
    match config::migrate::migrate_config(&raw) {
        Ok(out) => {
            print!("{}", out.yaml);
            eprintln!("migrated '{path}' to the 1.5.0 config shape.");
            if !out.changes.is_empty() {
                eprintln!(
                    "
CHANGES ({}):",
                    out.changes.len()
                );
                for c in &out.changes {
                    eprintln!("  - {c}");
                }
            }
            if !out.warnings.is_empty() {
                eprintln!(
                    "
WARNINGS ({}) - semantic flips needing review:",
                    out.warnings.len()
                );
                for w in &out.warnings {
                    eprintln!("  ! {w}");
                }
            }
            if !out.todos.is_empty() {
                eprintln!(
                    "
TODO ({}) - a human must decide:",
                    out.todos.len()
                );
                for t in &out.todos {
                    eprintln!("  * {t}");
                }
            }
            eprintln!(
                "
Review the output, then run `busbar --validate` on it before deploying.                  NOTE: 1.x virtual keys do not carry over - mint fresh signed keys (the 1.5.0                  security headline: keys now expire)."
            );
            0
        }
        Err(e) => {
            eprintln!("busbar: --migrate-config failed: {e}");
            1
        }
    }
}

/// Resolve the DEPRECATED `BUSBAR_PROVIDERS` override, warning once when it is set. `None` ⇒ let
/// [`load_config_from_disk`] resolve the catalog from `config.providers_file` or the default
/// (`providers.yaml` next to config.yaml). One-release back-compat for the env→config migration.
fn providers_override_from_env() -> Option<std::path::PathBuf> {
    let v = std::env::var(ENV_PROVIDERS)
        .ok()
        .filter(|s| !s.is_empty())?;
    eprintln!(
        "[warn] {ENV_PROVIDERS} is DEPRECATED; set `providers_file:` in config.yaml instead (it is \
         honored for now)."
    );
    Some(std::path::PathBuf::from(v))
}

/// `providers_override`: the DEPRECATED `BUSBAR_PROVIDERS` path (Some ⇒ set), or the live
/// providers path a runtime reload wants to re-use. When `None`, the catalog path is resolved from
/// `config.providers_file` (relative to the config dir) or defaults to `providers.yaml` next to the
/// resolved config.yaml (1.5.3).
pub(crate) fn load_config_from_disk(
    config_path: &std::path::Path,
    providers_override: Option<&std::path::Path>,
    safe_mode: bool,
    env_mode: config::EnvSubst,
) -> Result<LoadedConfig, String> {
    let mut unset_env_vars: Vec<String> = Vec::new();
    // 1.5.3: read + parse config.yaml FIRST — it may name the providers catalog (`providers_file:`).
    let raw_config = std::fs::read_to_string(config_path).map_err(|e| {
        format!(
            "cannot read config file '{}': {e} (set {ENV_CONFIG})",
            config_path.display()
        )
    })?;
    let interpolated_config =
        config::interpolate_env_with(&raw_config, env_mode, &mut unset_env_vars)
            .map_err(|e| format!("config.yaml: {e}"))?;
    // LOUD FAIL-CLOSED on a 1.x config: detect the 1.x structural markers BEFORE the
    // typed parse, so an outdated config gets the NAMED "run --migrate-config" error instead of
    // a pile of unknown-field messages - and, critically, so nothing from 1.x can half-parse
    // into 1.5.0 semantics (the `allowed_pools: []` all->none flip, vanished budgets).
    if let Ok(doc) = serde_yaml::from_str::<serde_yaml::Value>(&interpolated_config) {
        let markers = config::migrate::detect_legacy_markers(&doc);
        if !markers.is_empty() {
            return Err(format!(
                "config.yaml: {}",
                config::migrate::legacy_config_error(&markers)
            ));
        }
    }
    let deploy: config::DeployCfg = serde_yaml::from_str(&interpolated_config).map_err(|e| {
        format!(
            "config.yaml: invalid YAML: {}",
            config::augment_config_error(e)
        )
    })?;

    // 1.5.3: resolve the providers CATALOG path. Precedence: the explicit override (the deprecated
    // `BUSBAR_PROVIDERS` env var, or a runtime reload re-using its boot path) > `config.providers_file`
    // (relative to the config dir) > `providers.yaml` next to the resolved config.yaml.
    let config_dir = config_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let providers_path: std::path::PathBuf = match providers_override {
        Some(p) => p.to_path_buf(),
        None => match deploy.providers_file.as_deref() {
            Some(f) => {
                let p = std::path::Path::new(f);
                if p.is_absolute() {
                    p.to_path_buf()
                } else {
                    config_dir.join(p)
                }
            }
            None => config_dir.join("providers.yaml"),
        },
    };
    let raw_providers = std::fs::read_to_string(&providers_path).map_err(|e| {
        format!(
            "cannot read providers file '{}': {e} (set `providers_file:` in config.yaml, or {ENV_PROVIDERS})",
            providers_path.display()
        )
    })?;
    let interpolated_providers =
        config::interpolate_env_with(&raw_providers, env_mode, &mut unset_env_vars)
            .map_err(|e| format!("providers.yaml: {e}"))?;
    let defs: HashMap<String, config::ProviderDef> = serde_yaml::from_str(&interpolated_providers)
        .map_err(|e| format!("providers.yaml: invalid YAML: {e}"))?;

    // 1.5.3: resolve the config-management posture + overlay backend from the `config:` block, and
    // ENFORCE the boot invariant (`locked` XOR a writable overlay). The deprecated
    // `BUSBAR_CONFIG_OVERLAY` env var is honored only when `config.overlay` is unset. The writability
    // probe runs at boot/reload (Strict) but not under `--validate` (Lenient), which must stay
    // side-effect-free.
    let env_overlay = std::env::var("BUSBAR_CONFIG_OVERLAY")
        .ok()
        .filter(|s| !s.is_empty())
        .map(std::path::PathBuf::from);
    let probe_fs = matches!(env_mode, config::EnvSubst::Strict);
    let resolution = config::overlay::resolve_backend(
        &deploy.config,
        config_path,
        env_overlay.as_deref(),
        probe_fs,
    )?;
    let overlay_path = resolution.path;
    let config_locked = resolution.locked;
    let config_read_only = resolution.read_only_backend;

    if safe_mode {
        // `--safe-mode`: boot on the operator-owned base config ALONE — the persisted overlay
        // (API-registered hooks) is quarantined, not deleted. The escape hatch for "an applied
        // hook is harming traffic and re-applies itself every boot".
        tracing::warn!(
            "SAFE MODE: config overlay NOT merged — running on base config.yaml alone (the \
             overlay file is untouched; boot without --safe-mode to re-apply it)"
        );
        return Ok(LoadedConfig {
            deploy,
            defs,
            providers_path,
            overlay_path,
            config_locked,
            config_read_only,
            overlay_doc: None,
            unset_env_vars,
        });
    }
    // An overlay from a NEWER busbar is refused, not ignored: it is intact and meaningful, so
    // starting without it would run with the operator's API-registered hooks and groups — security
    // gates included — silently absent. `--safe-mode` boots on base config alone without touching
    // the file, so this is a one-flag recovery rather than a brick.
    if let Some(p) = overlay_path.as_ref() {
        if let config::overlay::OverlayReadState::VersionTooNew(v) = config::overlay::read_state(p)
        {
            return Err(format!(
                "config overlay '{}' was written by a newer busbar (overlay version {v}; this                  binary understands {}). Starting without it would silently drop API-registered                  hooks and groups. Upgrade busbar, or boot with --safe-mode to run on config.yaml                  alone (the overlay is left untouched).",
                p.display(),
                config::overlay::OVERLAY_VERSION
            ));
        }
    }
    let overlay_doc = overlay_path.as_ref().and_then(|p| {
        let doc = config::overlay::read(p);
        if let Some(ref d) = doc {
            tracing::info!(
                path = %p.display(),
                hooks = d.hooks.len(),
                "config overlay loaded (merged onto the resolved config after resolve)"
            );
        }
        doc
    });
    Ok(LoadedConfig {
        deploy,
        defs,
        providers_path,
        overlay_path,
        config_locked,
        config_read_only,
        overlay_doc,
        unset_env_vars,
    })
}

/// Build a complete `App` from a RESOLVED config — the ONE construction path shared by boot
/// (`prior = None`) and the config plane's apply/reload (`prior = Some(current)`). On apply,
/// process-lifetime state is REUSED from the prior snapshot (HTTP client pool, governance key DB,
/// version history, mutation-rate windows) and the health store is rebuilt with every surviving
/// lane's learned state RESTORED BY STABLE IDENTITY — so a lane-set change never
/// misattributes or discards breaker/latency knowledge. Errors are returned (never process-exit):
/// boot maps them to `die`, the apply endpoints to `invalid_request` — an invalid apply changes
/// nothing.
///
/// PLUGIN PRE-FLIGHT — the ONE pipeline shared byte-for-byte by BOOT (`build_app_from_config`),
/// config APPLY/RELOAD, and `busbar --validate`, so the pre-flight gate can never drift from real
/// boot behavior. Fail-closed at every step:
///
/// 1. CONSISTENCY: a non-`memory` `store.module` with `plugins.enabled: false` (or the block
///    absent) is an error NAMING THE FLAG — a dropped-in tarball is inert until the switch is on.
/// 2. POLICY: `plugins.trust` resolves (embedded first-party key + third-party publishers + the
///    explicit opt-ins + anti-downgrade floors); a malformed key is an error.
/// 3. SCAN: when enabled, every tarball in `plugins.dir` runs the three-phase pipeline
///    (structural -> trust -> conflict) via [`busbar_plugin_loader::scan_and_validate`]. ANY
///    invalid tarball/manifest or ANY name/alias conflict aborts with every problem named; an
///    untrusted plugin is SKIPPED (warn-logged, never `dlopen`ed).
/// 4. RESOLUTION: the configured `store.module` (alias OR canonical name, resolved against the
///    manifest registry — never a filename) must resolve to a loadable `kind: store` plugin.
///
/// Returns the validated registry (empty when plugins are disabled and no plugin is referenced).
/// NO plugin code runs in this function (manifest-only; `dlopen` happens later, at store open).
pub(crate) fn plugins_preflight(
    store_cfg: Option<&config::StoreCfg>,
    auth_cfg: Option<&config::AuthCfg>,
    identity_providers: &config::IdentityProviders,
    hooks_cfg: &std::collections::HashMap<String, config::HookCfg>,
    plugins_cfg: &config::PluginsCfg,
    export_cfg: &config::ExportCfg,
) -> Result<busbar_plugin_loader::PluginRegistry, String> {
    let store_ref = store_cfg
        .map(|g| g.module.as_str())
        .unwrap_or(config::GOVERNANCE_STORE_MEMORY);
    let store_is_plugin = store_ref != config::GOVERNANCE_STORE_MEMORY;

    // Every non-builtin `auth.chain` module is a `kind: auth` plugin — the same manifest-only
    // pre-flight the store ref gets, so `--validate` catches a missing/wrong-kind/untrusted auth
    // plugin BEFORE boot. `keys` is engine-handled (never a plugin); `test-groups-module` is the
    // compiled-in test stand-in — ONLY actually registered under `#[cfg(test)]`
    // (`AuthMiddleware::new`, `crates/busbar/src/auth/mod.rs`), so filtering it out
    // unconditionally here made `--validate`/`config_validate::validate` silently agree a RELEASE
    // config naming it is fine, while real boot still hard-failed (the invariant `--validate`
    // clean => the plugin half of boot succeeds too, documented a few lines below, broke). Gate
    // the exemption the same way the module itself is gated.
    let auth_plugin_refs: Vec<&str> = auth_cfg
        .map(|a| {
            a.chain
                .iter()
                .map(|e| e.module.as_str())
                .filter(|m| is_real_auth_plugin_ref(m, cfg!(test)))
                .collect()
        })
        .unwrap_or_default();
    let has_auth_plugin = !auth_plugin_refs.is_empty();

    // Every `identity-providers:` DEFINITION whose `module:` is not a built-in is likewise a
    // `kind: auth` plugin reference — checked here over the DEFINITION map rather than over the
    // resolved chain, because that is the only layer that sees an UNREFERENCED definition.
    // `resolve_auth` is keyed off `auth.chain:`/`auth.admin_auth:`, and `AuthCfg.methods` only
    // exists at all when an `auth:` block does, so a provider defined through
    // `PUT /identity-providers/{name}` and not yet referenced was validated by NOTHING: the API
    // answered 200 and stored a `module:` that can never authenticate anyone. `export:` has had the
    // equivalent check since 1.5.3 (`resolve_export` refuses an unknown exporter and names the
    // built-ins); it just needed no registry, because the export vocabulary is a const list.
    // Carries (name, module) pairs so the diagnostics can name the offending DEFINITION, not only
    // the module string — two providers can share one typo'd module.
    let idp_plugin_refs: Vec<(&str, &str)> = identity_providers
        .iter()
        .map(|(name, def)| (name.as_str(), def.module.trim()))
        // An EMPTY module is `resolve_auth`'s rule ("must be a non-empty module name"), reported
        // there in its own words; do not shadow it with a less specific "no such plugin".
        .filter(|(_, m)| !m.is_empty() && is_real_identity_provider_plugin_ref(m, cfg!(test)))
        .collect();
    let idp_refs_human = |refs: &[(&str, &str)]| {
        refs.iter()
            .map(|(n, m)| format!("identity-providers.{n} (module '{m}')"))
            .collect::<Vec<_>>()
            .join(", ")
    };

    // Every hook references a `kind: hook` plugin — the same manifest-only pre-flight the store/auth
    // refs get. Deduped for the messages, but validated as the set of names each hook declares.
    let hook_plugin_refs: Vec<String> = {
        let mut v: Vec<String> = hooks_cfg.values().map(|h| h.plugin.clone()).collect();
        v.sort();
        v.dedup();
        v
    };
    let has_hook_plugin = !hook_plugin_refs.is_empty();

    // 1. Consistency: referencing a plugin store while the master switch is off is a NAMED error.
    if store_is_plugin && !plugins_cfg.enabled {
        return Err(format!(
            "store.module: '{store_ref}' requires the plugin subsystem, but plugins.enabled is \
             false (the default). Set plugins.enabled: true and place the signed \
             '{store_ref}' store plugin tarball in the plugins directory ('{}'), or set \
             store.module: memory.",
            plugins_cfg.dir
        ));
    }
    // Same consistency gate for an auth plugin: a configured `kind: auth` module cannot load with
    // the plugin subsystem off — fail-closed, never a silently-open front door.
    if has_auth_plugin && !plugins_cfg.enabled {
        return Err(format!(
            "auth.chain names plugin module(s) [{}], which require the plugin subsystem, but \
             plugins.enabled is false (the default). Set plugins.enabled: true and place the \
             signed auth plugin tarball(s) in the plugins directory ('{}').",
            auth_plugin_refs.join(", "),
            plugins_cfg.dir
        ));
    }

    // Same consistency gate for a hook plugin: a configured `kind: hook` module cannot load with
    // the plugin subsystem off — fail-closed, never a silently-absent gate.
    if has_hook_plugin && !plugins_cfg.enabled {
        return Err(format!(
            "the hooks registry names plugin module(s) [{}], which require the plugin subsystem, \
             but plugins.enabled is false (the default). Set plugins.enabled: true and place the \
             signed `kind: hook` plugin tarball(s) in the plugins directory ('{}').",
            hook_plugin_refs.join(", "),
            plugins_cfg.dir
        ));
    }

    // Same consistency gate for an identity-provider DEFINITION: with the plugin subsystem off the
    // registry is empty by construction, so the only modules that can ever back a provider are the
    // built-ins — naming anything else is a config error today, not a latent one. Ordered AFTER the
    // `auth.chain` gate on purpose: a provider that IS on a chain gets that gate's more specific
    // "auth.chain names plugin module(s)" wording, and this one covers the definitions no chain
    // reaches.
    if !idp_plugin_refs.is_empty() && !plugins_cfg.enabled {
        return Err(format!(
            "{} require(s) the plugin subsystem, but plugins.enabled is false (the default). With \
             plugins off, a provider's `module:` must be one of the built-ins: {}. Set \
             plugins.enabled: true and place the signed `kind: auth` plugin tarball(s) in the \
             plugins directory ('{}'), or name a built-in.",
            idp_refs_human(&idp_plugin_refs),
            config::BUILTIN_IDENTITY_PROVIDERS.join(" | "),
            plugins_cfg.dir
        ));
    }

    // 2. Policy resolution (embedded first-party key + configured third-party trust).
    let policy = plugins_cfg
        .to_policy()
        .map_err(|e| format!("plugins.trust is invalid: {e}"))?;

    // Disabled and nothing referenced: the registry is empty and NOTHING in the directory is even
    // read (drop-is-inert).
    if !plugins_cfg.enabled {
        tracing::info!(
            "plugins: disabled (plugins.enabled is false; tarballs in the directory are inert)"
        );
        return Ok(busbar_plugin_loader::PluginRegistry::empty());
    }

    // 3. Three-phase scan over the plugins directory. Fail-closed on invalid/conflict.
    let dir = std::path::Path::new(&plugins_cfg.dir);
    let registry = busbar_plugin_loader::scan_and_validate(dir, &policy)
        .map_err(|errs| format!("plugin validation failed:\n  - {}", errs.join("\n  - ")))?;
    tracing::info!(
        dir = %plugins_cfg.dir,
        loadable = registry.loadable().len(),
        skipped = registry.skipped().len(),
        "plugins: enabled"
    );
    for s in registry.skipped() {
        tracing::warn!(
            plugin = %s.manifest.name,
            file = %s.file,
            reason = %s.reason,
            "plugin present but NOT loaded (trust policy)"
        );
    }
    for p in registry.loadable() {
        match &p.verdict {
            busbar_plugin_sign::Verdict::Trusted {
                publisher,
                first_party,
            } => tracing::info!(
                plugin = %p.manifest.name,
                alias = %p.manifest.alias,
                kind = %p.manifest.kind,
                version = %p.manifest.version,
                publisher = %publisher,
                first_party,
                "plugin validated"
            ),
            busbar_plugin_sign::Verdict::Allowed { reason, .. } => tracing::warn!(
                plugin = %p.manifest.name,
                alias = %p.manifest.alias,
                kind = %p.manifest.kind,
                reason = %reason,
                "plugin validated as UNVERIFIED (permitted by an explicit plugins.trust opt-in)"
            ),
        }
    }

    // 4. The configured store must resolve to a loadable store plugin.
    if store_is_plugin {
        match registry.resolve(store_ref) {
            Some(p) if p.manifest.kind == "store" => {}
            Some(p) => {
                return Err(format!(
                    "store.module: '{store_ref}' resolves to plugin '{}' of kind '{}', not a \
                     store plugin",
                    p.manifest.name, p.manifest.kind
                ));
            }
            None => {
                return Err(match registry.unresolved_reason(store_ref) {
                    Some(s) => format!(
                        "store.module: '{store_ref}' matches plugin '{}' ({}) but it was not \
                         loaded: {}",
                        s.manifest.name, s.file, s.reason
                    ),
                    None => format!(
                        "no plugin matching store.module: '{store_ref}' is installed in '{}' \
                         (plugins ARE enabled; loadable: [{}]). Two things to check: is the plugin \
                         subsystem enabled? (it is) — and is the signed tarball actually IN the \
                         folder? Add it to plugins.fetch or drop the signed tarball in the \
                         directory, or set store.module: memory.",
                        plugins_cfg.dir,
                        registry
                            .loadable()
                            .iter()
                            .map(|p| p.manifest.name.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                });
            }
        }
    }

    // 5. Every configured auth-chain plugin must resolve to a loadable `kind: auth` plugin. Same
    // manifest-only resolution as the store ref (no `dlopen` here; the real load happens in
    // `AuthMiddleware::new` at App construction). A missing/wrong-kind/untrusted auth plugin fails
    // `--validate` and boot alike — a typo'd or absent front-door module must never pass silently.
    for auth_ref in &auth_plugin_refs {
        match registry.resolve(auth_ref) {
            Some(p) if p.manifest.kind == "auth" => {}
            Some(p) => {
                return Err(format!(
                    "auth.chain module '{auth_ref}' resolves to plugin '{}' of kind '{}', not an \
                     `auth` plugin",
                    p.manifest.name, p.manifest.kind
                ));
            }
            None => {
                return Err(match registry.unresolved_reason(auth_ref) {
                    Some(s) => format!(
                        "auth.chain module '{auth_ref}' matches plugin '{}' ({}) but it was not \
                         loaded: {}",
                        s.manifest.name, s.file, s.reason
                    ),
                    None => format!(
                        "no plugin matching auth.chain module '{auth_ref}' is installed in '{}' \
                         (plugins ARE enabled; loadable: [{}]). Two things to check: is the plugin \
                         subsystem enabled? (it is) — and is the signed `kind: auth` tarball \
                         actually IN the folder? Add it to plugins.fetch or drop the signed tarball \
                         in the directory, or remove it from auth.chain.",
                        plugins_cfg.dir,
                        registry
                            .loadable()
                            .iter()
                            .map(|p| p.manifest.name.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                });
            }
        }
    }

    // 6. Every hook's `plugin:` ref must resolve to a loadable `kind: hook` plugin. Same manifest-only
    // resolution as store/auth (no `dlopen` here; the real load happens in `resolve_gate_transport` at
    // App construction). A missing/wrong-kind/untrusted hook plugin fails `--validate` and boot alike.
    for hook_ref in &hook_plugin_refs {
        match registry.resolve(hook_ref) {
            Some(p) if p.manifest.kind == "hook" => {}
            Some(p) => {
                return Err(format!(
                    "a hook references plugin '{hook_ref}', which resolves to plugin '{}' of kind \
                     '{}', not a `hook` plugin",
                    p.manifest.name, p.manifest.kind
                ));
            }
            None => {
                return Err(match registry.unresolved_reason(hook_ref) {
                    Some(s) => format!(
                        "a hook references plugin '{hook_ref}', matching plugin '{}' ({}) but it \
                         was not loaded: {}",
                        s.manifest.name, s.file, s.reason
                    ),
                    None => format!(
                        "no plugin matching the hook reference '{hook_ref}' is installed in '{}' \
                         (plugins ARE enabled; loadable: [{}]). Two things to check: is the plugin \
                         subsystem enabled? (it is) — and is the signed `kind: hook` tarball \
                         actually IN the folder? Add it to plugins.fetch or drop the signed tarball \
                         in the directory, or remove the hook.",
                        plugins_cfg.dir,
                        registry
                            .loadable()
                            .iter()
                            .map(|p| p.manifest.name.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                });
            }
        }
    }

    // 6b. Every `identity-providers:` DEFINITION's non-built-in `module:` must resolve to a loadable
    // `kind: auth` plugin — the definition-side counterpart of the `auth.chain` resolution above,
    // and the check that finally covers a provider NO chain references (the admin API's whole write
    // surface). Manifest-only, like its siblings.
    for (name, module) in &idp_plugin_refs {
        match registry.resolve(module) {
            Some(p) if p.manifest.kind == "auth" => {}
            Some(p) => {
                return Err(format!(
                    "identity-providers.{name}.module: '{module}' resolves to plugin '{}' of kind \
                     '{}', not an `auth` plugin. A provider's `module:` must be a built-in or a \
                     `kind: auth` plugin; the modules available right now are: {}.",
                    p.manifest.name,
                    p.manifest.kind,
                    valid_identity_provider_modules(&registry)
                ));
            }
            None => {
                return Err(match registry.unresolved_reason(module) {
                    Some(s) => format!(
                        "identity-providers.{name}.module: '{module}' matches plugin '{}' ({}) but \
                         it was not loaded: {}",
                        s.manifest.name, s.file, s.reason
                    ),
                    None => format!(
                        "identity-providers.{name}.module: no `kind: auth` plugin named or aliased \
                         '{module}' is installed in '{}' (plugins ARE enabled), and it is not a \
                         built-in. The modules a provider may name right now are: {}. Check the \
                         spelling against the plugin's manifest name/alias (see --list-plugins), \
                         add the signed tarball to the plugins directory, or name a built-in.",
                        plugins_cfg.dir,
                        valid_identity_provider_modules(&registry)
                    ),
                });
            }
        }
    }

    // 7. PLUGIN HTTP ROUTE COLLISION CHECK — MANIFEST-LEVEL, nothing dlopened. Walk every
    // loadable export/hook plugin's DECLARED routes in the SAME deterministic scan order the registry
    // produced, namespace-confine each, and fail LOUD naming the owning plugin on the first
    // {path, method} collision — e.g. `plugin "datadog" cannot register GET /metrics — already
    // registered by "prometheus"`. The IDENTICAL check backs boot and `--validate` (both call this
    // preflight), and the SAME confinement + first-to-claim logic backs the live table built at App
    // construction (`plugin_routes::build_route_table`), so the manifest check and what actually mounts
    // cannot diverge. Route declarations are read straight from each signed manifest; a plugin that
    // declares none contributes nothing (today's manifests carry no routes, so the set is empty until
    // the export/hook route-manifest field lands — the wiring is here so that is a data change, not a
    // control-flow one).
    let route_owners: Vec<(String, crate::plugin_routes::RouteKind)> = registry
        .loadable()
        .iter()
        .filter_map(|p| match p.manifest.kind.as_str() {
            "export" => Some((
                p.manifest.name.clone(),
                crate::plugin_routes::RouteKind::Export,
            )),
            "hook" => Some((
                p.manifest.name.clone(),
                crate::plugin_routes::RouteKind::Hook,
            )),
            _ => None,
        })
        .collect();
    let mut route_decls: Vec<(
        String,
        crate::plugin_routes::RouteKind,
        busbar_plugin_loader::Route,
    )> = route_owners
        .into_iter()
        .flat_map(|(name, kind)| {
            // A plugin's DECLARED routes are read straight from its signed manifest. The manifest
            // route field is not yet defined, so this yields nothing today; when it lands, map each
            // declared route to `(name, kind, route)` HERE — the confinement + collision logic is
            // already wired and tested.
            Vec::<busbar_plugin_loader::Route>::new()
                .into_iter()
                .map(move |r| (name.clone(), kind, r))
        })
        .collect();
    // The BUILT-IN exporters (`crate::export`) also claim routes (the `prometheus` exporter's
    // `GET /metrics`). Prepend them in the SAME collision set so a loaded third-party export/hook
    // plugin that tries to claim a path a built-in already owns fails LOUD at `--validate`/boot, e.g.
    // `plugin "datadog" cannot register GET /metrics — already registered by "prometheus"`.
    let mut built_in = crate::export::route_owners(export_cfg);
    built_in.append(&mut route_decls);
    let route_decls = built_in;
    crate::plugin_routes::preflight_route_collisions(&route_decls)
        .map_err(|e| format!("plugin route registration conflict: {e}"))?;

    Ok(registry)
}

/// Resolve the operator ADMIN credential — the `admin-tokens` chain entry's `token:` secret ref —
/// with the BLANK-TOKEN guard. Shared by boot and the apply/reload path so the two cannot drift.
///
/// FAIL-CLOSED twice over:
/// * an unresolvable ref refuses boot/apply (a silently-absent token would lock the admin API
///   while the operator believes it is guarded);
/// * a ref that resolves to EMPTY or ALL-WHITESPACE is refused too. The
///   documented boot guard for this had been lost in the move to secret refs, and the consequence
///   is worse than the docs described: the digest is computed over the blank string, so
///   `admin_token_hash` is `Some(sha256(""))` — a REAL credential that an `Authorization: Bearer `
///   with an empty value satisfies. An env var that expanded to nothing would silently hand the
///   whole admin surface to an unauthenticated caller.
fn resolve_admin_token(
    auth: Option<&config::AuthCfg>,
    resolver: &config::secret::SecretResolver,
) -> Result<Option<busbar_api::Redacted<String>>, String> {
    let Some(r) = auth.and_then(|a| a.admin_token_ref()) else {
        return Ok(None);
    };
    let token = resolver
        .resolve_string(r)
        .map_err(|e| format!("auth.admin_auth admin-tokens token did not resolve: {e}"))?;
    if token.trim().is_empty() {
        return Err(
            "auth.admin_auth admin-tokens `token:` resolved to an EMPTY/whitespace-only value. \
             Refusing to start: the digest would be taken over the blank string, so an empty \
             credential would authenticate as the operator. Check the referenced env var / file \
             actually holds the token, or remove the `token:` to disable the admin API deliberately."
                .to_string(),
        );
    }
    Ok(Some(busbar_api::Redacted::new(token)))
}

/// Parse resolved bytes into a 32-byte ed25519 secret: accept RAW 32 bytes or 64 hex chars. Shared
/// by the signing-key resolver and the `--generate-signing-key` self-check.
fn parse_signing_secret(bytes: &[u8]) -> Result<[u8; 32], String> {
    if bytes.len() == 32 {
        let mut out = [0u8; 32];
        out.copy_from_slice(bytes);
        return Ok(out);
    }
    if let Ok(s) = std::str::from_utf8(bytes) {
        let s = s.trim();
        if s.len() == 64 {
            if let Ok(v) = hex::decode(s) {
                let mut out = [0u8; 32];
                out.copy_from_slice(&v);
                return Ok(out);
            }
        }
    }
    Err(
        "auth.signing_key must resolve to a 32-byte ed25519 secret key (raw 32 bytes or 64 hex \
         characters)"
            .to_string(),
    )
}

/// Resolve the KEY-SIGNING key. `auth.signing_key` is a reference to an EXISTING secret
/// (env/file/plugin) resolving to the ed25519 secret material (32 raw bytes, or 64 hex chars) busbar
/// mints + verifies virtual-key tokens with. Fleet-shared: every node resolves the SAME secret so
/// they verify each other's tokens.
///
/// 1.5.1 BREAKING CHANGE: busbar NO LONGER auto-generates and persists a signing key at boot (the
/// 1.5.0 behavior wrote `busbar-signing.key` beside the config, which boot-looped a read-only config
/// mount with a misleading Permission-denied). When `auth.signing_key` is absent this returns `None`;
/// `config_validate` fails CLOSED at `--validate`/boot if the deployment actually uses signed-token
/// auth (the `keys` verifier in the chain), and the mint path fails closed with a clear message
/// otherwise. Generate a key with `busbar --generate-signing-key`.
///
/// FAIL-CLOSED: a configured-but-unresolvable / malformed signing key refuses boot.
fn resolve_signing_key(
    auth: Option<&config::AuthCfg>,
    resolver: &config::secret::SecretResolver,
) -> Result<Option<governance::signing::TokenSigner>, String> {
    use governance::signing::{TokenSigner, DEFAULT_KID};

    let Some(sk) = auth.and_then(|a| a.signing_key.as_ref()) else {
        // No configured key: busbar does not generate one (1.5.1). A deployment that verifies
        // busbar-signed keys is REQUIRED to provide it (enforced fail-closed by config_validate);
        // one that never issues signed tokens simply has no signer.
        return Ok(None);
    };
    let bytes = resolver.resolve(sk).map_err(|e| {
        format!(
            "auth.signing_key did not resolve: {e}. auth.signing_key is a reference to an EXISTING \
             secret (env/file/plugin) - it does NOT generate a key. Provide the key first (a \
             32-byte raw or 64-hex-char ed25519 secret: `busbar --generate-signing-key`, or \
             `openssl rand -hex 32`), or OMIT auth.signing_key entirely if this deployment never \
             issues busbar-signed keys."
        )
    })?;
    let secret = parse_signing_secret(&bytes)?;
    Ok(Some(TokenSigner::from_secret_bytes(&secret, DEFAULT_KID)))
}

/// `--generate-signing-key`: mint a fresh ed25519 signing secret from the OS RNG and PRINT it (as 64
/// hex chars) plus a paste-ready `auth.signing_key` snippet + a fleet note. ZERO side effects - like
/// `--validate`/`--migrate-config`, it writes nothing; the operator PLACES the key (busbar never
/// edits their config). Exit 0 on success, 1 if the OS entropy source is unavailable.
fn generate_signing_key_command() -> i32 {
    use governance::signing::{TokenSigner, DEFAULT_KID};
    let signer = match TokenSigner::generate(DEFAULT_KID) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("busbar: could not generate a signing key: {e}");
            return 1;
        }
    };
    let hex = hex::encode(signer.secret_bytes());
    let (secret_line, guidance) = signing_key_command_output(&hex);
    // The secret (64 hex chars) goes to STDOUT ONLY so it is pipeable/captureable
    // (`busbar --generate-signing-key > /run/secrets/busbar-signing.key`); the guidance goes to
    // STDERR so a capture gets ONLY the key — the guidance itself must therefore be secret-free
    // (SECURITY: it must never embed `hex`, or the master key leaks into any sink that captures stderr:
    // systemd journal, CI/build logs, terminal scrollback). See `signing_key_command_output`.
    println!("{secret_line}");
    eprintln!("{guidance}");
    0
}

/// Split the `--generate-signing-key` output into (STDOUT secret line, STDERR guidance). The secret
/// `hex` appears ONLY in the stdout line; the stderr guidance uses a NON-SECRET placeholder that points
/// at the stdout value, so a stderr capture never leaks the master signing key. Pure (no I/O) so the
/// stdout-only-secret contract is unit-testable (see `signing_key_guidance_omits_secret`), not merely
/// asserted in a comment. `auth.signing_key` is a secret REFERENCE (never an inline literal — busbar
/// rejects that), so the snippets wire the key via `{ file }` / `{ env }`.
fn signing_key_command_output(hex: &str) -> (String, String) {
    let secret_line = hex.to_string();
    let guidance = "\n# ed25519 signing key for busbar-signed virtual keys (64 hex chars, printed above on stdout).\n\
         # auth.signing_key is a secret REFERENCE, not an inline value - wire the key like so:\n\
         #\n\
         #   # write it to a file, then reference the file:\n\
         #   busbar --generate-signing-key > /run/secrets/busbar-signing.key\n\
         #   auth:\n\
         #     signing_key: { file: /run/secrets/busbar-signing.key }\n\
         #\n\
         #   # or export it and reference the env var (fleet: SAME value on every node).\n\
         #   # paste the 64-hex key printed above on stdout (NOT shown here, so this guidance stays\n\
         #   # secret-free and safe to capture in a journal/CI log):\n\
         #   export BUSBAR_SIGNING_KEY=<paste-the-64-hex-key-printed-above>\n\
         #   auth:\n\
         #     signing_key: { env: BUSBAR_SIGNING_KEY }\n\
         #\n\
         # Fleet-shared so every node verifies the same tokens; rotating it REVOKES every \
         outstanding virtual key."
        .to_string();
    (secret_line, guidance)
}

/// Validate ONE `secrets:` block key against the plugin registry and return the plugin's CANONICAL
/// name. Fail-closed (an `Err`) when the key names a reserved built-in resolver (`env`/`file`, which
/// take no module-level config), when no loadable plugin is named or aliased by it, or when the
/// resolved plugin is not `kind: secret`. Shared by `build_secret_resolver` (boot) and the
/// `--validate` pre-flight so both apply the identical policy (a mistyped/aliased
/// `secrets:` key must never silently open a plugin with `{}`).
fn validate_secret_module(
    registry: &busbar_plugin_loader::PluginRegistry,
    module: &str,
) -> Result<String, String> {
    if module == config::secret::SECRET_MODULE_ENV || module == config::secret::SECRET_MODULE_FILE {
        return Err(format!(
            "secrets.{module}: '{module}' is a built-in secret resolver, not a plugin; it takes no \
             module-level configuration. Remove this `secrets:` entry (reference it inline as \
             {{ {module}: … }} where the secret is used)."
        ));
    }
    match registry.resolve(module) {
        Some(p) if p.manifest.kind == "secret" => Ok(p.manifest.name.clone()),
        Some(p) => Err(format!(
            "secrets.{module}: plugin '{}' has kind '{}', not 'secret'; only a kind: secret plugin \
             can back a `secrets:` block entry",
            p.manifest.name, p.manifest.kind
        )),
        None => Err(format!(
            "secrets.{module}: no loadable `kind: secret` plugin is named or aliased '{module}' \
             (check the spelling against the plugin's manifest name/alias, and that the plugin \
             loaded — see --list-plugins)"
        )),
    }
}

/// THE POST-RESOLVE HALF OF `--validate`, in one place.
///
/// `config_validate::validate` is only part of what makes a config valid: the plugin pre-flight
/// (consistency, trust resolution, the three-phase tarball scan, store resolution) and the two
/// secret-reference checks are the rest, and they cannot run until the registry exists. Every caller
/// that asks "is this config valid?" must run ALL of it -- `--validate` assembled the steps by hand
/// and `POST /api/v1/admin/config/validate` ran only the first, so the admin dry-run answered
/// `ok: true` for configs the CLI rejects and an operator could ship one straight into a failed boot.
///
/// Whether `m` names a REAL `auth.chain` plugin ref that must resolve against the plugin registry
/// (`true`) vs a builtin/test stand-in that's exempt (`false`). `keys` is engine-handled, never a
/// plugin. `test-groups-module` is ONLY actually registered as a chain module under
/// `#[cfg(test)]` (`AuthMiddleware::new`, `crates/busbar/src/auth/mod.rs`) — `is_test_build` MUST
/// be `cfg!(test)` at the real call site, so this exemption only fires in a test binary. Module-
/// level (not inlined into the `.filter(...)` closure) so the exact predicate that determines
/// `--validate`/`config_validate::validate`'s pass/fail is unit-testable independent of which
/// binary flavor happens to be running `cargo test` — see `tests/tests.rs`. A prior version
/// exempted `test-groups-module` UNCONDITIONALLY (no `is_test_build` gate at all), which made
/// `--validate` silently agree a RELEASE config naming it was fine while real boot still hard-
/// failed (`AuthMiddleware::new` has no non-test arm for it) — breaking the documented invariant
/// a few lines below ("a clean `--validate` means the plugin half of boot succeeds too").
fn is_real_auth_plugin_ref(m: &str, is_test_build: bool) -> bool {
    m != config::KEYS_MODULE && !(is_test_build && m == "test-groups-module")
}

/// The DEFINITION-side twin of [`is_real_auth_plugin_ref`]: whether an
/// `identity-providers.<name>.module:` is a REAL `kind: auth` plugin reference that must resolve
/// against the registry, as opposed to a built-in the engine handles inline
/// ([`config::BUILTIN_IDENTITY_PROVIDERS`] — `keys` and `admin-tokens`) or a compiled-in test
/// stand-in. Separate from the chain predicate because the two answer different questions over
/// different vocabularies: `auth.chain:` never carries `admin-tokens` (that plane is `admin_auth:`),
/// so the chain predicate exempts only `keys`, while EVERY built-in is legal as a definition's
/// module. Same `is_test_build` discipline for the same reason: `test-scope-module` /
/// `test-groups-module` are only ever registered under `#[cfg(test)]` (`AuthPlugins::build`,
/// `crates/busbar/src/auth/mod.rs`), so exempting them unconditionally would make `--validate`
/// silently bless a RELEASE config that real boot still hard-fails.
fn is_real_identity_provider_plugin_ref(m: &str, is_test_build: bool) -> bool {
    !config::BUILTIN_IDENTITY_PROVIDERS.contains(&m)
        && !(is_test_build && matches!(m, "test-groups-module" | "test-scope-module"))
}

/// The human list of every module an `identity-providers.<name>.module:` may legally name RIGHT NOW:
/// the built-ins, plus every loaded `kind: auth` plugin. Named as a SET, never counted — the same
/// "name the whole valid vocabulary" discipline the `export.<n>.streams:` diagnostic follows.
fn valid_identity_provider_modules(registry: &busbar_plugin_loader::PluginRegistry) -> String {
    let mut names: Vec<String> = config::BUILTIN_IDENTITY_PROVIDERS
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    names.extend(
        registry
            .loadable()
            .iter()
            .filter(|p| p.manifest.kind == "auth")
            .map(|p| p.manifest.name.clone()),
    );
    names.join(" | ")
}

/// Manifest-only, like the pre-flight it wraps: nothing is `dlopen`ed and no store is opened, so it
/// is safe on the admin read path.
pub(crate) fn preflight_plugins_and_secrets(
    deploy: &config::DeployCfg,
    cfg: &config::RootCfg,
) -> Result<busbar_plugin_loader::PluginRegistry, String> {
    let registry = plugins_preflight(
        deploy.store.as_ref(),
        cfg.auth.as_ref(),
        &cfg.identity_providers,
        &cfg.hooks,
        &deploy.plugins,
        &cfg.export,
    )?;
    validate_secret_modules(&registry, &cfg.secrets)?;
    validate_secret_refs(&registry, cfg)?;
    Ok(registry)
}

/// Validate EVERY `secrets:` block entry against the registry (the `--validate` counterpart of the
/// per-entry check `build_secret_resolver` runs at boot). Returns the FIRST offending entry's error.
fn validate_secret_modules(
    registry: &busbar_plugin_loader::PluginRegistry,
    secret_modules: &std::collections::BTreeMap<String, config::SecretModuleCfg>,
) -> Result<(), String> {
    for module in secret_modules.keys() {
        validate_secret_module(registry, module)?;
    }
    Ok(())
}

/// Validate every SECRET REFERENCE's module against the plugin registry — the deferred half of the
/// secret-reference check `config_validate` cannot do (it runs before the registry exists). The
/// built-in `env`/`file` modules always pass; ANY OTHER module name is a `kind: secret` PLUGIN
/// reference (the 1.5.0 "secrets are plugins" feature: `api_key: { module: acme-vault, … }`, TLS
/// cert/key, `auth.signing_key`, the admin token) and must resolve to a LOADED, TRUSTED, `kind:
/// secret` plugin. A genuine typo (no built-in, no plugin) is a hard boot / `--validate` error;
/// an installed vault/aws-sm plugin PASSES. Shared by boot (`build_app_from_config`) and the
/// `--validate` pre-flight so the two cannot drift. Returns the FIRST offending reference's error.
fn validate_secret_refs(
    registry: &busbar_plugin_loader::PluginRegistry,
    cfg: &config::RootCfg,
) -> Result<(), String> {
    for (what, r) in config_validate::secret_refs(cfg) {
        if r.module == config::secret::SECRET_MODULE_ENV
            || r.module == config::secret::SECRET_MODULE_FILE
        {
            continue; // built-in resolver — already structurally checked in config_validate
        }
        match registry.resolve(&r.module) {
            Some(p) if p.manifest.kind == "secret" => {}
            Some(p) => {
                return Err(format!(
                    "{what} references secret module '{}', but plugin '{}' has kind '{}', not \
                     'secret'; only a `kind: secret` plugin can back a secret reference",
                    r.module, p.manifest.name, p.manifest.kind
                ));
            }
            None => {
                return Err(format!(
                    "{what} references secret module '{}', which is not a built-in (`env` | `file`) \
                     and no loadable `kind: secret` plugin is named or aliased '{}'. Fix the \
                     spelling, install/trust the plugin (see --list-plugins), or use a built-in, \
                     e.g.:\n\n    {what}: {{ env: MY_SECRET_VAR }}\n",
                    r.module, r.module
                ));
            }
        }
    }
    Ok(())
}

/// RESOLVE every built-in (`env` / `file`) secret reference, for `--validate` ONLY.
///
/// `config_validate` proves a reference is well-FORMED; it cannot prove the variable is set or the
/// file is readable, because it runs before anything touches the environment. Without this,
/// `--validate` reported a config VALID while boot would warn and then serve a gateway whose every
/// upstream request fails on a missing credential: success reported for something that cannot work.
///
/// DELIBERATELY NOT IN `preflight_plugins_and_secrets`. That pre-flight is SHARED with boot and with
/// the admin apply/reload path, where an unresolvable secret is a WARNING by design, not a refusal
/// (`test_admin_v1_config_settings_unresolvable_store_secret_warns_not_rejects` pins that). A live
/// config change must not be rejected for a secret that may resolve on the next deploy. The operator
/// asking `--validate` is asking a different question, and deserves the strict answer.
///
/// Returns the FIRST unresolvable reference's error, naming the field so it is actionable.
fn validate_builtin_secrets_resolve(cfg: &config::RootCfg) -> Result<(), String> {
    let builtins = config::secret::SecretResolver::builtins_only();
    for (what, r) in config_validate::secret_refs(cfg) {
        if r.module != config::secret::SECRET_MODULE_ENV
            && r.module != config::secret::SECRET_MODULE_FILE
        {
            continue; // plugin-backed: the plugin may not be loadable here, and preflight covers it
        }
        if let Err(e) = builtins.resolve(r) {
            return Err(format!("{what}: {e}"));
        }
    }
    Ok(())
}

/// Build the [`config::secret::SecretResolver`] the engine resolves every secret reference through:
/// the built-in `env`/`file` modules inline, and any OTHER module name via a loaded `kind: secret`
/// plugin from `registry` (opened per resolution; a secret module is off every hot path so the
/// per-call open + resolve is fine). FAIL-CLOSED: `open_secret` errors surface as an unresolvable
/// secret. When the plugin subsystem is off the registry is empty and every non-built-in reference
/// is a fail-closed error at resolve time.
fn build_secret_resolver(
    registry: Arc<busbar_plugin_loader::PluginRegistry>,
    secret_modules: &std::collections::BTreeMap<String, config::SecretModuleCfg>,
) -> Result<config::secret::SecretResolver, String> {
    // MODULE-LEVEL config delivery for `kind: secret` plugins: resolve each configured
    // `secrets.<module>.settings` ONCE at boot and hand it to the plugin's `open()`, exactly as
    // `store.settings` configures the store plugin. Without this a secret plugin's `open()` always
    // received `{}`, so a Vault-style plugin's address/namespace/token/CA had to be repeated in EVERY
    // SecretRef — multiplying secret exposure and defeating the open-vs-resolve separation the ABI
    // is designed around.
    //
    // The module config is resolved against the BUILT-IN env/file resolvers ONLY (a `builtins_only`
    // resolver). A secret module cannot resolve its OWN `open()` config through a secret plugin —
    // that would be a bootstrap cycle — so `{ token: { env: VAULT_TOKEN } }` resolves but
    // `{ token: { module: some-other-secret-plugin } }` is a fail-closed error.
    let builtins = config::secret::SecretResolver::builtins_only();
    // Key the open-config map by the plugin's CANONICAL name, not by the literal `secrets:` block
    // key: a `SecretRef` may name the plugin by EITHER its canonical name or its alias, and
    // the registry resolves both — but a bare string-equality lookup on the block key would MISS the
    // other spelling and silently open the plugin with `{}` (dropping the operator's configured
    // address/token/CA). Canonicalize the block key through the SAME by_name/by_alias resolution the
    // registry uses, so a `secrets:` entry written under an alias and a `SecretRef` written under the
    // canonical name (or vice versa) line up. A `secrets:` entry that resolves to NOTHING — a typo, or
    // a module that names one of the reserved built-in resolvers (`env`/`file`, which take no
    // module-level open config) — is a hard boot error: silently passing `{}` for a mis-typed module
    // is exactly the failure this closes. The `--validate` path applies the identical policy via the
    // shared `validate_secret_module`/`validate_secret_modules` helpers.
    let mut open_config: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    // Which `secrets:` block key produced each canonical entry, so an ALIAS/CANONICAL collision can
    // be named precisely.
    let mut claimed_by: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    for (module, mcfg) in secret_modules {
        // Validate + canonicalize the block key against the registry (shared with --validate). A
        // reserved built-in name, an unknown module, or a non-secret plugin is a hard error here.
        let canonical = validate_secret_module(&registry, module)?;
        // TWO SPELLINGS, ONE MODULE: a `secrets:` block written under BOTH a plugin's alias and its
        // canonical name canonicalizes to the same key, and the second insert silently DROPPED the
        // first entry's open() config — one of the two blocks (address, token, CA) just vanished,
        // with the module still loading happily on the survivor. Ambiguous by construction: there is
        // no defensible rule for which one wins. Fail LOUD and name both spellings.
        if let Some(previous) = claimed_by.get(&canonical) {
            return Err(format!(
                "secrets: the module '{canonical}' is configured TWICE — once as '{previous}' and \
                 once as '{module}' (an alias and its canonical name resolve to the same plugin). \
                 One of the two blocks would be silently dropped; keep exactly one."
            ));
        }
        let resolved = config::secret::resolve_settings(&mcfg.settings, &builtins)
            .map_err(|e| format!("secrets.{module} settings: {e}"))?;
        claimed_by.insert(canonical.clone(), module.clone());
        open_config.insert(canonical, serde_json::Value::Object(resolved).to_string());
    }
    Ok(config::secret::SecretResolver::with_plugin(Box::new(
        move |module: &str, settings: &str| -> Result<Vec<u8>, String> {
            // Canonicalize the referenced module the SAME way, so an alias-vs-name spelling difference
            // between the `secrets:` block and this `SecretRef` still finds the configured open() JSON.
            // A module that does not resolve falls through to `open_secret` below, which produces the
            // authoritative "no such plugin" error.
            let canonical = registry
                .resolve(module)
                .map(|p| p.manifest.name.as_str())
                .unwrap_or(module);
            // Deliver the module's configured open() JSON (default `{}` for an unconfigured module).
            let open_cfg = open_config
                .get(canonical)
                .map(String::as_str)
                .unwrap_or("{}");
            let m = registry.open_secret(module, open_cfg)?;
            m.resolve(
                &serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(settings)
                    .map_err(|e| format!("secret settings are not a JSON object: {e}"))?,
            )
            .map_err(|e| e.to_string())
        },
    )))
}

/// A queued-but-not-yet-applied governance credential rotation: `build_app_from_config` resolves it
/// but does NOT invoke it (see the call site below for why). `Send` because it is carried across the
/// `spawn_blocking` boundary the admin transaction (`txn.rs`) applies it on.
pub(crate) type GovCredentialRotation = Box<dyn FnOnce() + Send>;

/// The `plugins.fetch` download closure the engine hands to `busbar_plugin_loader::fetch_plugins`.
/// Enforces the SAME cloud-metadata SSRF denylist provider URLs face (fetch is off-box, key-adjacent
/// I/O) and requires https for a public host, then performs the GET. The GET runs on a DEDICATED
/// std::thread with its own current-thread runtime, so it is safe whether the caller sits on a tokio
/// worker (boot) or a `spawn_blocking` thread (reload) — a nested `block_on` on a runtime thread would
/// otherwise panic. The loader owns cache/verify/atomic-write; this owns network + SSRF.
fn plugin_fetch_downloader(blocked: &[String]) -> impl Fn(&str) -> Result<Vec<u8>, String> {
    plugin_fetch_downloader_with_cap(blocked, config::DEFAULT_PLUGIN_FETCH_MAX_BYTES)
}

/// Same as [`plugin_fetch_downloader`] with an explicit download-size cap — split out so a test can
/// exercise the over-cap rejection path against a small in-memory server without actually moving
/// hundreds of megabytes through loopback. Production always calls [`plugin_fetch_downloader`], which
/// pins `cap` to [`config::DEFAULT_PLUGIN_FETCH_MAX_BYTES`].
fn plugin_fetch_downloader_with_cap(
    blocked: &[String],
    cap: usize,
) -> impl Fn(&str) -> Result<Vec<u8>, String> {
    let blocked: Vec<String> = blocked.to_vec();
    move |url: &str| -> Result<Vec<u8>, String> {
        // Scheme: https required for a public host; plaintext http only for loopback/private (a local
        // dev registry). Mirrors the provider base_url rule.
        let https = config_validate::scheme_is(url, "https");
        if !https {
            let host_local = config_validate::extract_normalized_host(url)
                .as_deref()
                .map(config_validate::host_is_private_or_loopback)
                .unwrap_or(false);
            if !(config_validate::scheme_is(url, "http") && host_local) {
                return Err(format!(
                    "plugins.fetch url must use https for a public host (got '{url}')"
                ));
            }
        }
        // SSRF: never fetch from a cloud-metadata host (no per-provider carve-outs; the operator
        // denylist still extends the built-in list).
        if let Some(bad) = config_validate::ssrf_blocked_host(url, &[], false, &blocked) {
            return Err(format!(
                "plugins.fetch url '{url}' targets a blocked cloud-metadata host '{bad}'"
            ));
        }
        let url = url.to_string();
        std::thread::scope(|s| {
            s.spawn(|| -> Result<Vec<u8>, String> {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| format!("fetch runtime: {e}"))?;
                rt.block_on(async {
                    let resp = reqwest::Client::new()
                        .get(&url)
                        .send()
                        .await
                        .map_err(|e| format!("GET {url}: {e}"))?;
                    let status = resp.status();
                    if !status.is_success() {
                        return Err(format!("GET {url}: HTTP {status}"));
                    }
                    // A declared Content-Length over the cap is rejected BEFORE reading a single body
                    // byte — the fast, cheap path for the common case of an honest oversized response.
                    // Not load-bearing on its own (a dishonest/absent header falls through to the
                    // streamed cap below), just an early exit.
                    if let Some(len) = resp.content_length() {
                        if len as usize > cap {
                            return Err(format!(
                                "GET {url}: declared Content-Length {len} exceeds the {cap}-byte \
                                 plugins.fetch download cap"
                            ));
                        }
                    }
                    // Stream with a running byte counter (never `resp.bytes()`, which buffers the
                    // ENTIRE — possibly multi-gigabyte — body before any cap could apply) so a
                    // mistyped or compromised URL serving an unbounded body is rejected with a clear
                    // error instead of OOMing busbar on boot or `/plugins/reload`.
                    let (bytes, end) = crate::proxy::read_capped(resp, cap).await;
                    match end {
                        crate::proxy::ReadEnd::Complete => Ok(bytes.to_vec()),
                        crate::proxy::ReadEnd::Truncated => Err(format!(
                            "GET {url}: response exceeded the {cap}-byte plugins.fetch download cap; \
                             refusing to buffer a truncated download"
                        )),
                        crate::proxy::ReadEnd::TransportError => {
                            Err(format!("read body {url}: connection failed mid-download"))
                        }
                    }
                })
            })
            .join()
            .map_err(|_| "plugins.fetch download thread panicked".to_string())?
        })
    }
}

pub(crate) fn build_app_from_config(
    cfg: config::RootCfg,
    plugins_cfg: config::PluginsCfg,
    overlay_path: Option<std::path::PathBuf>,
    base_hook_names: std::collections::HashSet<String>,
    base_group_names: std::collections::HashSet<String>,
    config_paths: (Option<std::path::PathBuf>, Option<std::path::PathBuf>),
    prior: Option<&state::App>,
) -> Result<(state::App, Option<GovCredentialRotation>), String> {
    // Install the resolved operational limits process-wide BEFORE any subsystem reads them —
    // running here (not in main) so a config APPLY/RELOAD refreshes them too. The values threaded
    // explicitly (client/store/router/TLS) read `cfg.limits` directly; the deep call-stack sites
    // (translate-body cap, metrics gauge limit, webhook timeout, governance sqlite/sweep, health
    // probe fallbacks, routing policy timeout) read the installed values.
    //
    // …THROUGH A GUARD, because everything below this line is fallible. The install has to come
    // first (the build itself reads these values), but a build that goes on to FAIL must not leave
    // the rejected config's limits installed under the old `App` that keeps serving. The guard
    // restores the previous values on drop unless the build reaches its `Ok`, so "an invalid apply
    // changes nothing" holds for process-wide limits the same way it holds for everything else.
    let limits_guard = limits::InstallGuard::install(&cfg.limits);
    // The config version this App will carry — computed ONCE up front because hook-transport
    // resolution stamps it into every socket configure preamble (the preamble's
    // settings_version must be the REAL version of the settings it delivers, not a hardcoded 0).
    let app_config_version = prior.map_or(0, |p| p.config_version.wrapping_add(1));
    // Semantic validation — the same gate boot has always had, now on the ONE construction path
    // so an apply/reload validates identically and an invalid config changes nothing.
    if let Err(validation_errors) = config_validate::validate(&cfg) {
        return Err(format!(
            "config validation failed:\n  - {}",
            validation_errors.join("\n  - ")
        ));
    }
    // The resolved `export:` block drives the built-in exporters' plugin-route table below. Captured
    // before `cfg`'s fields are consumed by the `App` struct literal.
    let cfg_export = cfg.export.clone();
    let auth_cfg = cfg
        .auth
        .clone()
        .unwrap_or_else(config::AuthCfg::default_none);

    // DECLARATIVE PLUGIN FETCH (`plugins.fetch:`) — download the operator-declared signed tarballs
    // into `plugins.dir` BEFORE preflight scans it. Runs at BOOT and on `POST /plugins/reload` (both
    // reach this construction path), NEVER in `--validate` (that path never calls
    // `build_app_from_config`, preserving its zero-side-effect/no-network contract), and NEVER
    // per-request. `prior.is_none()` is the boot(fatal-on-miss) vs reload(warn-on-miss) discriminator.
    // Signature verification stays the trust gate below; fetch is integrity/cache + delivery only.
    if plugins_cfg.enabled && !plugins_cfg.fetch.is_empty() {
        let specs = plugins_cfg.fetch_specs()?;
        let dir = std::path::Path::new(&plugins_cfg.dir).to_path_buf();
        // Ensure the target dir exists so the atomic rename has a home.
        if let Err(e) = crate::durable::create_dir_all(&dir) {
            return Err(format!(
                "plugins.fetch: cannot create plugins dir '{}': {e}",
                dir.display()
            ));
        }
        let downloader = plugin_fetch_downloader(&cfg.blocked_metadata_hosts);
        let outcomes =
            busbar_plugin_loader::fetch_plugins(&dir, &specs, prior.is_none(), &downloader)
                .map_err(|errs| format!("plugins.fetch failed:\n  - {}", errs.join("\n  - ")))?;
        for outcome in &outcomes {
            match outcome {
                busbar_plugin_loader::FetchOutcome::Cached { filename } => {
                    tracing::info!(filename, "plugins.fetch: cached (pin match, no download)")
                }
                busbar_plugin_loader::FetchOutcome::Fetched { filename } => {
                    tracing::info!(filename, "plugins.fetch: downloaded + verified")
                }
                busbar_plugin_loader::FetchOutcome::Warned { url, error } => {
                    tracing::warn!(
                        url,
                        error,
                        "plugins.fetch: miss on reload; keeping current artifact"
                    )
                }
            }
        }
    }

    // PLUGIN PRE-FLIGHT (the ONE shared pipeline; see the fn doc). Run UP FRONT so the secret
    // resolver - and the store open below - both draw on the same validated registry. A non-memory
    // store, an unresolvable secret plugin, or any invalid tarball fails boot here.
    let plugin_registry = Arc::new(plugins_preflight(
        cfg.store.as_ref(),
        cfg.auth.as_ref(),
        &cfg.identity_providers,
        &cfg.hooks,
        &plugins_cfg,
        &cfg.export,
    )?);

    // Every SECRET REFERENCE whose module is not a built-in (`env`/`file`) must resolve to a loaded
    // `kind: secret` plugin — the deferred half of the check `config_validate::validate` cannot do
    // (it runs before the registry exists). A typo'd module fails boot HERE; the documented vault
    // `api_key: { module: acme-vault }` passes once the plugin is loaded + trusted. This is the boot
    // twin of the `--validate` check, sharing `validate_secret_refs`/`config_validate::secret_refs`.
    validate_secret_refs(&plugin_registry, &cfg)?;

    // The SECRET RESOLVER: built-in env/file resolve inline; any other module delegates to a
    // loaded `kind: secret` plugin via the registry (fail-closed if the plugin subsystem is off or
    // the module is unknown). Shared by provider keys, the admin token, and the TLS listener.
    let secret_resolver = Arc::new(build_secret_resolver(
        plugin_registry.clone(),
        &cfg.secrets,
    )?);

    let mut lanes_data = Vec::new();
    // Validated provider handle for each lane, captured in lockstep with `lanes_data` below. The
    // first loop already resolves `cfg.providers.get(&mc.provider)` (failing loud via `die` on a
    // missing provider), so the lane-build loop reuses that handle instead of re-looking it up —
    // there is no second lookup and no `expect` on the startup path.
    let mut lane_provider_cfgs: Vec<&config::ProviderCfg> = Vec::new();
    let mut by_model = HashMap::new();
    // Per-model configured default_max_tokens (injected at the translation seam for protocols that
    // require max_tokens). Captured here because `cfg.models` is consumed by this loop.
    let mut model_default_max_tokens: std::collections::HashMap<String, Option<u32>> =
        std::collections::HashMap::new();
    // Single source of truth for each provider's resolved API key. The secret-bearing env read
    // happens exactly once per provider here; both the empty-key warning below and the later
    // `Lane.api_key` population reuse this value, so the warning and the captured key can never
    // diverge (and we don't read the same env var twice).
    let mut provider_api_keys: HashMap<String, String> = HashMap::new();
    // Build lanes in a DETERMINISTIC order (sorted by model name) rather than `cfg.models`'
    // HashMap iteration order, which is randomized per process start. Lane index is assigned here
    // (`by_model` → `lanes_data.len()`), so a random iteration order gave each lane a different
    // index every boot — surfacing as non-reproducible `/stats` lane ordering and metric lane-series
    // identity that shifts across restarts (a scrape/dashboard annoyance and a flaky-test source).
    // Sorting makes the whole observable surface stable. (Mirrors the deterministic-resolution fix
    // already applied to `model_context_max` below.)
    // Resolve the COST MODEL from THIS config (rate card + budget groups + flat fee) BEFORE
    // `cfg.models` is consumed below. Rebuilt on every apply/reload - unlike the GovState ledger,
    // which survives the swap - so a rate-card correction reprices every derived figure on the
    // next read (tokens are the truth).
    let cost = Arc::new(crate::cost::CostModel::resolve_parts(
        cfg.rate_card.as_ref(),
        cfg.per_request_fee,
        &cfg.groups,
    ));

    let mut sorted_models: Vec<_> = cfg.models.into_iter().collect();
    sorted_models.sort_by(|a, b| a.0.cmp(&b.0));
    for (model, mc) in sorted_models {
        model_default_max_tokens.insert(model.clone(), mc.default_max_tokens);
        let Some(provider_cfg) = cfg.providers.get(&mc.provider) else {
            return Err(format!(
                "model '{model}' references unknown provider '{}'",
                mc.provider
            ));
        };
        let key = provider_api_keys.entry(mc.provider.clone()).or_insert_with(|| {
            // Resolve the provider credential through its SECRET REFERENCE. An unresolvable
            // secret degrades to the empty key with a loud warning (parity with the old empty
            // env-var posture: keyless local upstreams - ollama/vLLM - are legitimate).
            match secret_resolver.resolve_string(&provider_cfg.api_key) {
                Ok(k) => k,
                Err(e) => {
                    tracing::warn!(provider = %mc.provider, "provider api_key did not resolve: {e}");
                    String::new()
                }
            }
        });
        if key.is_empty() {
            eprintln!(
                "[warn] provider {} api_key ({}) empty",
                mc.provider,
                provider_cfg.api_key.describe()
            );
        }
        let limited = mc.max_requests >= 0;
        // `max_concurrent` is an OPT-IN limiter: omitted (None) = UNBOUNDED. Realize "unbounded" as a
        // semaphore seeded with `Semaphore::MAX_PERMITS` (usize::MAX >> 3) — a lane will never reach
        // 2^60 concurrent in-flight requests, so this never throttles, yet it keeps the entire
        // permit-based dispatch path (which every selection route depends on) intact. A literal
        // usize::MAX would PANIC: `Semaphore::new` asserts `permits <= MAX_PERMITS`. `max` records the
        // same count so /stats `inflight = max - available` stays coherent.
        let max_concurrent = mc
            .max_concurrent
            .unwrap_or(tokio::sync::Semaphore::MAX_PERMITS);
        by_model.insert(model.clone(), lanes_data.len());
        lane_provider_cfgs.push(provider_cfg);
        lanes_data.push(LaneData {
            model: model.clone(),
            provider: mc.provider.clone(),
            max: max_concurrent,
            sem: std::sync::Arc::new(tokio::sync::Semaphore::new(max_concurrent)),
            limited,
            budget: if limited { mc.max_requests } else { -1 },
            cooldown_until: 0,
            streak: 0,
            dead: false,
            dead_reason: String::new(),
            ok: 0,
            err: 0,
            client_fault: 0,
            upstream_model: mc.upstream_model.clone(),
            attempt_timeout_ms: mc.attempt_timeout_ms,
            reasoning: mc.reasoning.unwrap_or(false),
            prompt_caching: mc.prompt_caching.unwrap_or(false),
        });

        eprintln!(
            "  model {} via {} ({}) max {}{}",
            model,
            mc.provider,
            provider_cfg.base_url.trim_end_matches('/'),
            // Show the operator-facing form: an omitted cap reads "unbounded", not 2^60.
            match mc.max_concurrent {
                Some(n) => n.to_string(),
                None => "unbounded".to_string(),
            },
            // Surface the alias→wire-id indirection at boot so an operator can see this lane sends a
            // different model string upstream than the config key it's filed under.
            match &mc.upstream_model {
                Some(u) => format!(" → upstream {u}"),
                None => String::new(),
            }
        );
    }

    let registry = ProtocolRegistry::with_builtins();

    // Build a map from model name to context_max. A model is one lane shared across every pool that
    // names it, so its context_max must be single-valued. Previously the last pool to iterate (in
    // nondeterministic HashMap order) silently won, so a model carrying `context_max: Some(128000)`
    // in one pool and `None` (or a different limit) in another could end up with whichever value the
    // iteration happened to land on — defeating the context-length failover exclusion in proxy engine
    // and losing pool-specific limits without a diagnostic. Resolve it deterministically and fail
    // loud on a genuine conflict instead.
    let model_context_max = resolve_model_context_max(&cfg.pools)?;

    let mut lanes = Vec::new();
    for (idx, ld) in lanes_data.iter().enumerate() {
        // Reuse the provider handle resolved (and validated via `die`) in the lanes_data loop above,
        // captured in lockstep into `lane_provider_cfgs`. No redundant re-lookup / `expect` here.
        let provider_cfg = lane_provider_cfgs[idx];
        let Some(protocol) = registry.get(&provider_cfg.protocol) else {
            return Err(format!(
                "provider '{}' uses unknown protocol '{}' (supported: anthropic, openai, gemini, bedrock, responses, cohere)",
                ld.provider, provider_cfg.protocol
            ));
        };
        // Reuse the single env read captured in the lanes_data loop above (same source of truth as
        // the empty-key warning); no second read of the secret-bearing env var.
        let api_key = provider_api_keys
            .get(&ld.provider)
            .cloned()
            .unwrap_or_default();
        // Resolve the outbound credential once. Most auth styles are a simple sync lookup; the OAuth
        // styles parse their credential material here (failing loud on a bad key) and start a
        // background token minter/refresher. `api_key` carries that material.
        //
        // Both OAuth mechanisms vet their token endpoint (oauth `token_url`, jwt-bearer SA `token_uri`)
        // for SSRF against the operator's REAL metadata posture so the boot-time check matches
        // config_validate's validate-time check EXACTLY (validate == apply) and both mechanisms behave
        // identically: the allow-override set is the SAME union config_validate builds (this provider's
        // `allow_metadata_hosts` ∪ the global `security.allow_metadata_hosts`), plus the nuclear
        // `allow_all_metadata` and the operator's extra `blocked_metadata_hosts`. Threading it into
        // jwt-bearer too means a global `blocked_metadata_hosts` deny is enforced on a jwt
        // `token_uri`, and `allow_all_metadata` uniformly disables the guard for both.
        let allow_overrides: Vec<String> = provider_cfg
            .allow_metadata_hosts
            .iter()
            .chain(cfg.allow_metadata_hosts.iter())
            .cloned()
            .collect();
        let ssrf = egress_auth::MetadataSsrfPolicy {
            allow_overrides: &allow_overrides,
            allow_all: cfg.allow_all_metadata,
            blocked_hosts: &cfg.blocked_metadata_hosts,
        };
        let credential = match provider_cfg.auth {
            // `jwt-bearer`: `api_key` is the service-account JSON (inline) or a key-file path. A
            // configured `scope:` overrides the default cloud-platform scope (else `None` → default).
            // A configured `subject:` (RFC 7523 `sub`) is opt-in: `None` (the default, every existing
            // Vertex AI config) omits the claim entirely, unchanged from before this field existed.
            Some(config::ProviderAuth::JwtBearer) => egress_auth::jwt_bearer::build(
                &api_key,
                provider_cfg.scope.as_deref(),
                provider_cfg.subject.as_deref(),
                &ssrf,
            )
            .map_err(|e| format!("provider '{}' (jwt-bearer auth): {e}", ld.provider))?,
            // `oauth-client-credentials`: `api_key` is `client_id:client_secret`; `token_url`+`scope`
            // come from the provider config (required — the config validator also rejects them absent).
            Some(config::ProviderAuth::OAuthClientCredentials) => {
                let token_url = provider_cfg.token_url.as_deref().ok_or_else(|| {
                    format!(
                        "provider '{}' (oauth-client-credentials auth) requires `token_url`",
                        ld.provider
                    )
                })?;
                let scope = provider_cfg.scope.as_deref().ok_or_else(|| {
                    format!(
                        "provider '{}' (oauth-client-credentials auth) requires `scope`",
                        ld.provider
                    )
                })?;
                egress_auth::oauth_client_credentials::build(&api_key, token_url, scope, &ssrf)
                    .map_err(|e| {
                        format!(
                            "provider '{}' (oauth-client-credentials auth): {e}",
                            ld.provider
                        )
                    })?
            }
            _ => egress_auth::resolve(&provider_cfg.protocol, provider_cfg.auth),
        };
        let base_url = provider_cfg.base_url.trim_end_matches('/').to_string();
        lanes.push(Lane {
            model: ld.model.clone(),
            provider: ld.provider.clone(),
            // Precompute the SigV4 signed-host once at boot (pure function of base_url) so the forward
            // path borrows it into SigningContext instead of re-parsing/allocating it per request.
            signing_host: proxy::host_from_base(&base_url),
            base_url,
            api_key: busbar_api::Redacted::new(api_key),
            credential,
            protocol,
            max: ld.max,
            error_map: Arc::new(provider_cfg.error_map.clone()),
            context_max: model_context_max.get(&ld.model).copied().flatten(),
            path: provider_cfg.path.clone(),
            path_base: provider_cfg.path_base.clone(),
            health: provider_cfg.health.clone(),
            upstream_model: ld.upstream_model.clone(),
            attempt_timeout_ms: ld.attempt_timeout_ms,
            reasoning: ld.reasoning,
            prompt_caching: ld.prompt_caching,
            default_max_tokens: model_default_max_tokens.get(&ld.model).copied().flatten(),
        });
    }

    let mut pools = HashMap::new();
    for (name, pool) in &cfg.pools {
        // Wire per-member weights from config into the pool structure.
        // Each pool member has a weight; default is 1 if not specified.
        let mut weighted_members: Vec<WeightedLane> = Vec::with_capacity(pool.members.len());
        for m in pool.members.iter() {
            {
                let Some(&lane_idx) = by_model.get(&m.model) else {
                    return Err(format!(
                        "pool '{name}' references unknown model '{}'",
                        m.model
                    ));
                };
                weighted_members.push(WeightedLane {
                    idx: lane_idx,
                    weight: m.weight, // from config PoolMember.weight (default 1)
                    // Per-member attempt cap: one model, different hang budgets per pool/workload.
                    attempt_timeout_ms: m.attempt_timeout_ms,
                    reasoning: m.reasoning,
                });
            }
        }
        pools.insert(name.clone(), weighted_members);
    }

    eprintln!("busbar: {} models, {} pools", lanes.len(), pools.len());
    for (n, wl_vec) in &pools {
        let agg: usize = wl_vec.iter().map(|wl| lanes[wl.idx].max).sum();
        eprintln!(
            "  pool /{} = [{}] aggregate {}",
            n,
            wl_vec
                .iter()
                .map(|wl| lanes[wl.idx].model.clone())
                .collect::<Vec<_>>()
                .join(", "),
            agg
        );
    }

    // Loud warning for an empty `auth.chain` (open relay). Not fatal — busbar still starts (useful for
    // local dev) — but operators must not run this in production. NOTE: an ABSENT `auth:` block
    // serde-defaults to an empty chain too (`AuthCfg::default_none`), so a config that merely omits
    // `auth:` silently becomes an open relay. Surface this at ERROR level (not warn — a warn is
    // suppressed under RUST_LOG=error, the very level an operator most likely runs in production)
    // AND unconditionally on stderr, so the open-relay state cannot be masked by log configuration.
    if let Some(banner) = open_relay_banner(auth_cfg.chain.is_empty(), cfg.auth.is_some()) {
        eprintln!("[error] {banner}");
        tracing::error!("{banner}");
    }

    // FAIL-CLOSED: the auth chain resolves every non-builtin `auth.chain` module as a `kind: auth`
    // plugin via the SAME validated registry the store/secret plugins load through. A configured
    // auth plugin that cannot be loaded (missing/untrusted tarball, wrong kind, ABI failure) aborts
    // boot here rather than silently dropping the module and leaving the front door open.
    let auth_mw = Arc::new(
        AuthMiddleware::new(&auth_cfg, &plugin_registry, &secret_resolver)
            .map_err(|e| format!("auth chain construction failed: {e}"))?,
    );
    // ADMIN-plane external auth plugins (1.5.2 admin-plane OIDC): resolve every non-builtin
    // `admin_auth:` entry as a signed `kind: auth` plugin through the SAME validated registry. Runs
    // on boot AND reload (this whole function is `build_app_from_config`, called on both), so a
    // reload can never leave a stale/empty admin chain. FAIL-CLOSED: an unresolvable admin module
    // aborts the build rather than silently disabling the admin plane.
    let admin_modules = Arc::new(
        crate::auth::AdminAuthChain::build(&auth_cfg, &plugin_registry, &secret_resolver)
            .map_err(|e| format!("admin auth chain construction failed: {e}"))?,
    );
    // HOSTED-LOGIN methods (1.5.2): resolve every `auth.methods:` entry as a login-capable
    // `kind: auth` plugin (ABI v2). Also runs on boot AND reload (this whole fn). FAIL-CLOSED: an
    // unresolvable method — or a `browser_login` method backed by a pre-v2 plugin (capability gate)
    // — aborts the build rather than surfacing a 500 at request time.
    let login_methods = Arc::new(
        crate::auth::token::LoginMethods::build(&auth_cfg, &plugin_registry, &secret_resolver)
            .map_err(|e| format!("auth.methods (hosted login) construction failed: {e}"))?,
    );
    // Thread the operator-configured hard-down cooldown + honored-Retry-After ceiling into the store
    // (both default to their historical const at the config layer).
    // Carry-over: an APPLY/RELOAD (prior = Some) restores every surviving lane's learned
    // health state BY STABLE IDENTITY from the prior store; boot (None) starts fresh.
    let store: Arc<dyn crate::store::LaneRuntime> = match prior {
        Some(p) => Arc::new(HealthState::new_with_limits_restored(
            lanes_data.clone(),
            cfg.limits.hard_down_cooldown_secs,
            cfg.limits.max_honored_retry_after_secs,
            &p.store.export_health(),
        )),
        None => Arc::new(HealthState::new_with_limits(
            lanes_data.clone(),
            cfg.limits.hard_down_cooldown_secs,
            cfg.limits.max_honored_retry_after_secs,
        )),
    };

    // Global default failover config — the fallback for pools that don't set their own. A fixed
    // default (not "whatever pool HashMap iteration happens to yield first", which was
    // nondeterministic across restarts).
    let failover_cfg = Some(crate::config::FailoverCfg {
        timeout_secs: crate::config::DEFAULT_FAILOVER_DEADLINE_SECS,
        exclusions: None,
        max_hops: crate::config::DEFAULT_FAILOVER_CAP,
    });

    // The fallback-pool routing table: on_exhausted `fallback_pool:<name>` looks a pool up here,
    // so it mirrors the pools map (any pool can be a fallback target).
    let fallback_pools = pools.clone();

    // The upstream HTTP client, built ONCE — as N per-thread SHARDS (see `UpstreamClients`): each
    // worker thread keeps its own client/pool, so no request ever crosses another core's pool
    // lock. Constructed before the pool-runtime loop so the webhook routing transport can reuse
    // it (a shard clone shares that shard's connection pool + the `redirect:none` SSRF posture);
    // the sharded set is then moved into `App` below.
    let upstream_client = if let Some(p) = prior {
        // REUSED across applies: the pooled connections + their kept-alive upstream sockets.
        p.client.clone()
    } else {
        // Opt-in HTTP/2 PRIOR-KNOWLEDGE for CLEARTEXT upstreams (no TLS/ALPN to negotiate over):
        // `BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE=1` makes the shared client assume h2 without ALPN. This
        // is a PROCESS-WIDE, DEFAULT-OFF switch — production keeps ALPN (safe against h1 upstreams);
        // it exists so a cleartext h2c backend (e.g. the benchmark mock, or an in-mesh h2c service)
        // can exercise multiplexing without TLS. It FORCES h2, so every configured upstream must speak
        // h2c when set — never enable it against a mixed/h1 fleet. Read once at client-build time.
        // 1.5.3: home is `advanced.upstream_h2_prior_knowledge` in config.yaml (carried on
        // `cfg.limits`); the `BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE` env var overrides it for one release,
        // with a deprecation warn.
        let h2_env = std::env::var_os("BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE");
        if h2_env.is_some() {
            tracing::warn!(
                "BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE is DEPRECATED; set \
                 `advanced.upstream_h2_prior_knowledge` in config.yaml (honored for now)."
            );
        }
        let h2_prior_knowledge =
            upstream_bool_env_override(h2_env, cfg.limits.upstream_h2_prior_knowledge);
        // Opt-out ESCAPE HATCH for the ALPN h2 default: `BUSBAR_UPSTREAM_HTTP1_ONLY=1` pins the
        // shared client to HTTP/1.1 (reqwest `.http1_only()`), so ALPN never offers h2 at all. This
        // is a PROCESS-WIDE, DEFAULT-OFF switch — production keeps the ALPN default (h2 where the
        // backend accepts it, h1 otherwise); it exists as an operational rollback lever in case a
        // specific upstream negotiates h2 but misbehaves on it (flow-control stalls, broken
        // keep-alive pings, intermediary bugs) and you need the pre-h2 wire behavior back without a
        // rebuild. Mutually exclusive in spirit with the h2c opt-in above (forcing h1 AND forcing
        // h2 makes no sense); if both are set, http1-only wins because it is applied last. Read
        // once at client-build time. 1.5.3: home is `advanced.upstream_http1_only` in config.yaml
        // (carried on `cfg.limits`); the `BUSBAR_UPSTREAM_HTTP1_ONLY` env var overrides it for one
        // release, with a deprecation warn.
        let http1_env = std::env::var_os("BUSBAR_UPSTREAM_HTTP1_ONLY");
        if http1_env.is_some() {
            tracing::warn!(
                "BUSBAR_UPSTREAM_HTTP1_ONLY is DEPRECATED; set `advanced.upstream_http1_only` in \
                 config.yaml (honored for now)."
            );
        }
        let http1_only = upstream_bool_env_override(http1_env, cfg.limits.upstream_http1_only);
        let shard_count = crate::state::UpstreamClients::shard_count();
        // The per-host idle budget is divided across shards so the TOTAL kept-alive sockets
        // toward any single upstream stay at the configured value (never below 1 per shard).
        let idle_per_host_per_shard = cfg
            .limits
            .pool_max_idle_per_host
            .div_ceil(shard_count)
            .max(1);
        let make_one = || {
            let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(
                cfg.limits.upstream_request_timeout_secs,
            ));
            builder = builder
                // Bound the TCP connect separately from the coarse overall timeout: a stalled SYN would
                // otherwise hang up to the streaming `.timeout()` (minutes) before failover kicks in.
                .connect_timeout(Duration::from_secs(10))
                // Keep idle upstream sockets alive so a middlebox silently dropping a long-idle
                // keep-alive connection is detected proactively, not discovered as a spurious failure on
                // the next request (added latency + a needless failover hop).
                .tcp_keepalive(Duration::from_secs(60))
                // Disable Nagle's algorithm on the EGRESS sockets. Busbar writes a whole request body in
                // one shot and then immediately awaits the response, so Nagle has nothing to coalesce —
                // but on a small body it interacts with the peer's delayed-ACK to hold the final segment
                // for up to ~40 ms waiting for an ACK that only arrives once the peer's timer fires. That
                // manifests as a bimodal tail-latency spike (a native SDK, which also sets TCP_NODELAY,
                // never sees it) and is pure added latency on the request path. Inbound accepted sockets
                // already set this (tls.rs serve loops); this brings the egress leg to parity. `axum`'s
                // own serve() defaults nodelay on; reqwest does NOT, so it must be set explicitly.
                .tcp_nodelay(true)
                // HTTP/2 to the upstream, NEGOTIATED via ALPN (NOT prior-knowledge): over TLS the client
                // offers `h2,http/1.1` and uses whichever the backend accepts, so an h2-capable provider
                // (Anthropic, OpenAI, Vertex, Bedrock all speak h2) multiplexes many concurrent requests
                // over ONE connection — collapsing the per-request connect+TLS handshake and the socket /
                // epoll pressure that caps proxy RPS on a core-bound box — while an HTTP/1-only backend
                // transparently stays on h1. By DEFAULT we do NOT call `.http2_prior_knowledge()` (that
                // would FORCE h2 and break every h1 upstream and a plaintext h1 mock) — it is applied only
                // when the cleartext-h2c opt-in below is set. H2 keep-alive pings keep a multiplexed
                // connection healthy through idle gaps without the h1 trick of holding N sockets open. No
                // behavior change against an h1-only upstream on the default (ALPN) path.
                .http2_keep_alive_interval(Duration::from_secs(30))
                .http2_keep_alive_timeout(Duration::from_secs(10))
                .http2_adaptive_window(true)
                .pool_max_idle_per_host(idle_per_host_per_shard)
                // Idle keep-alive lifetime — EXPLICIT 300s default, replacing reqwest's implicit 90s:
                // the warm working set (amortized TCP+TLS handshakes / h2 sessions) survives
                // inter-burst gaps of a few minutes instead of being reaped and re-paid as cold
                // handshakes when the next burst lands. Safe at 300s because `tcp_keepalive(60s)`
                // above actively validates idle sockets (a silently-dropped connection is caught by
                // the probe, not by a failed request), and bounded by `pool_max_idle_per_host` + OS
                // reclamation. Operator-tunable via `limits.pool_idle_timeout_secs`.
                .pool_idle_timeout(Duration::from_secs(cfg.limits.pool_idle_timeout_secs))
                // SSRF guard: do NOT follow redirects. The startup SSRF blocklist (config_validate.rs
                // ssrf_blocked_host) only vets the configured base_url; it does not see redirect targets.
                // reqwest's default policy follows up to 10 redirects, so a compromised/malicious upstream
                // could 30x-redirect a vetted base_url to an internal address (169.254.169.254 metadata,
                // localhost, RFC1918) and busbar would follow it — forwarding the signed request
                // (x-api-key / SigV4 Authorization on same-host redirects) to the internal target,
                // defeating the blocklist at runtime. Upstream AI provider APIs do not redirect as part of
                // normal operation, so disabling redirect following entirely closes the vector at no cost.
                .redirect(reqwest::redirect::Policy::none());
            // Cleartext h2c opt-in (bench / in-mesh): FORCE h2 without ALPN. Default-off; when set, every
            // upstream must speak h2c. Applied last so it overrides the ALPN default above.
            if h2_prior_knowledge {
                builder = builder.http2_prior_knowledge();
            }
            // HTTP/1-only escape hatch: pin the client to h1 (no ALPN h2 offer). Applied last so it
            // wins over both the ALPN default and the h2c opt-in above.
            if http1_only {
                builder = builder.http1_only();
            }
            builder.build().expect("build upstream HTTP client")
        };
        crate::state::UpstreamClients::build(shard_count, make_one)
    };

    // The `default:` hook (if any) — the base ordering that pools which named none inherit, replacing
    // the compiled-in weighted backstop (everything-is-a-hook model). At most one (validated).
    let default_hook = hooks::default_hook_name(&cfg.hooks).map(str::to_string);
    // The hook plugin-resolution environment: the validated registry + shared projectors. Every hook
    // `plugin:` ref opens a `DlopenPolicy` through this. Built once and cloned into each resolver and
    // onto `App` (for the control-plane reads + scrape).
    let hook_env = hooks::HookEnv::new(plugin_registry.clone(), secret_resolver.clone());

    // FAIL-CLOSED: resolve every hook's SecretRef settings ONCE, up front, so an unresolvable
    // hook secret aborts boot/reload here — matching the store path (above) and the auth chain
    // (`AuthMiddleware::new`). Without this, a gate whose SecretRef fails to resolve would be
    // silently dropped from the routing chain by `resolve_pool_gates`/`resolve_on_error_chain`
    // (fail-OPEN), letting traffic the gate was configured to restrict/reject flow unfiltered.
    hook_env.preresolve_hook_secrets(&cfg.hooks)?;

    // The store's SecretRefs are resolved only on the BOOT arm (`prior == None`), because the store
    // backend is reused across a hot reload. So a `PUT /config/settings` naming an unresolvable ref
    // returned 200, persisted it, and the NEXT restart died in `resolve_settings` before serving.
    //
    // WARN, never fail: the store is restart-to-apply, so staging a ref whose secret the
    // orchestrator mounts on the next deploy is a legitimate workflow — and `tls` already accepts
    // exactly that. Rejecting here would make the store stricter than the block beside it.
    if let Some(store_cfg) = cfg.store.as_ref() {
        if let Err(e) = config::secret::resolve_settings(&store_cfg.settings, &secret_resolver) {
            tracing::warn!(
                store = %store_cfg.module,
                error = %e,
                "store settings hold a secret reference that does not resolve here; the store is \
                 restart-to-apply, so THIS WILL FAIL THE NEXT RESTART unless the secret exists then"
            );
        }
    }

    // FAIL-CLOSED (open-time variant): actually OPEN every referenced decision/rewrite gate up
    // front so an `open()`-time failure of a PRESENT plugin aborts boot/reload here — matching the
    // store (`open_store`) and auth (`AuthMiddleware::new`) paths. Without this, a gate whose plugin
    // fails to `open()` (constructor rejecting cfg_json, staging/mmap failure, ABI/kind mismatch
    // observable only on load) is silently `filter_map`-dropped by the resolvers below (fail-OPEN),
    // letting traffic a Reject/restrict/rewrite gate was configured to filter flow unfiltered while
    // boot reports success. A GENUINELY-ABSENT plugin stays the legitimate fail-open skip.
    // `plugins_preflight` is manifest-only (no dlopen) and `preresolve_hook_secrets` only resolves
    // SecretRefs, so neither catches an `open()` failure — this pass does.
    hook_env.preopen_gate_hooks(&cfg.hooks)?;

    // Per-pool runtime config (failover/exclusions), keyed by pool name.
    let mut pool_runtime = std::collections::HashMap::new();
    for (pool_name, pool_cfg) in &cfg.pools {
        pool_runtime.insert(
            pool_name.clone(),
            state::PoolRuntime {
                failover: pool_cfg.failover.clone(),
                // 1.5.3: the pool's own `upstream_credentials:` OVERRIDES the all-pools
                // `pools.upstream_credentials:` default; `None` inherits it.
                upstream_credentials: pool_cfg.upstream_credentials,
                affinity: pool_cfg.affinity.clone(),
                breaker: pool_cfg.breaker.as_ref().map(store::BreakerCfg::from),
                // Operator-declared member metadata (tier/cost/tags) keyed by lane idx, for the
                // routing Candidate projection. Mirrors the WeightedLane construction's target→lane
                // mapping (by_model). Read only inside the policy arm of the seam.
                members: pool_cfg
                    .members
                    .iter()
                    .filter_map(|m| {
                        by_model.get(&m.model).map(|&idx| {
                            (
                                idx,
                                state::MemberMeta {
                                    tier: m.tier.clone(),
                                    // The routing cost scalar derives from the member's
                                    // MODEL's rate_card entry - cost lives on no pool member.
                                    cost_per_mtok: cfg
                                        .rate_card
                                        .as_ref()
                                        .and_then(|card| card.get(&m.model))
                                        .map(crate::config::rate_entry_per_mtok),
                                    tags: m.tags.clone(),
                                },
                            )
                        })
                    })
                    .collect(),
                // Resolve the routing policy ONCE here. `weighted` (default) ⇒ `None` ⇒ the zero-cost
                // inline SWRR path; a `default:` hook replaces that base for pools that named none; a
                // `kind: hook` plugin base opens a `DlopenPolicy` through the plugin registry.
                policy: hooks::resolve_pool_ordering(
                    pool_cfg,
                    &cfg.hooks,
                    &hook_env,
                    default_hook.as_deref(),
                    app_config_version,
                ),
                // This pool's decision gates, resolved once here (priority carried for the phase-2
                // chain merge). NOT re-resolved on config apply yet — same scope caveat as `policy`.
                gates: hooks::resolve_pool_gates(
                    pool_cfg,
                    &cfg.hooks,
                    &hook_env,
                    app_config_version,
                ),
                rewrite_hooks: hooks::resolve_pool_rewrites(
                    pool_cfg,
                    &cfg.hooks,
                    &hook_env,
                    app_config_version,
                ),
            },
        );
    }

    // Parse on_exhausted configs per pool
    let mut on_exhausted_cfgs = std::collections::HashMap::new();
    for (pool_name, pool_cfg) in &cfg.pools {
        if let Some(ref on_exc) = pool_cfg.on_exhausted {
            // The structured config value maps directly (unknown spellings already failed parse).
            let mode = on_exc.to_runtime();
            tracing::info!(pool = %pool_name, on_exhausted = ?mode, "pool exhaustion policy");
            on_exhausted_cfgs.insert(pool_name.clone(), mode);
        } else {
            // Default to Status503 if not specified
            on_exhausted_cfgs.insert(pool_name.clone(), crate::config::OnExhausted::Status503);
        }
    }

    // PLUGIN PRE-FLIGHT: the same fail-closed pipeline `--validate` runs (consistency -> policy ->
    // three-phase scan -> store resolution). Runs on EVERY construction path (boot, apply, reload),
    // so a bad plugin state can never produce a partial App. When plugins are disabled and nothing
    // references one, this is a no-op empty registry.
    // open the governance store + load the virtual-key cache when enabled.
    // Credentials RE-RESOLVED on this apply/reload; the rotation closure is handed back to the
    // caller (see `Ok((app, rotate_gov_credentials))` below) rather than applied here. Resolution
    // itself happens HERE and is FAIL-CLOSED: an `auth.admin_auth` token ref or an `auth.signing_key`
    // that no longer resolves aborts the apply rather than silently leaving the old credential live.
    let mut rotate_gov_credentials: Option<GovCredentialRotation> = None;
    let governance = if let Some(p) = prior {
        // REUSED across applies: the keys + spend/rate state must survive config changes. But the
        // CREDENTIALS on it are config, not state: `GovState` used to freeze the admin-token digest
        // and the signing key at construction, so rotating either SecretRef and reloading had no
        // effect whatsoever — the process kept accepting the boot-time credential for its entire
        // life. Re-resolve both refs against the fresh resolver and swap them
        // into the reused instance.
        //
        // SCOPE: a credential is re-resolved exactly when THIS config DECLARES it — an
        // `admin-tokens` entry in `auth.admin_auth`/`auth.chain` for the admin token, an explicit
        // `auth.signing_key` for the signing key. A config that declares neither is not asserting
        // "no credential"; it simply does not own that credential (the dev signing key is
        // generate-and-persist at BOOT, and re-running that on every reload would churn key
        // material), so the live one stands. REMOVING a declaration therefore still needs a restart
        // — documented, and the narrow case; ROTATING one, the operational path that matters and
        // the one that silently did nothing, now works.
        if let Some(gs) = p.governance.clone() {
            let auth = cfg.auth.as_ref();
            let declares_admin_tokens = auth.is_some_and(|a| {
                a.admin_auth
                    .iter()
                    .chain(a.chain.iter())
                    .any(|e| e.module == crate::config::ADMIN_TOKENS_MODULE)
            });
            // FAIL-CLOSED: a declared ref that no longer resolves ABORTS the apply. The alternative
            // — carry on serving with the old credential — is exactly the defect being fixed.
            let admin_token: Option<Option<busbar_api::Redacted<String>>> = if declares_admin_tokens
            {
                // Declared with no token ref resolves to `None`: the admin API is credential-less
                // BY CONFIGURATION, so fail closed and disable it rather than keep the old secret.
                Some(
                    resolve_admin_token(auth, &secret_resolver)
                        .map_err(|e| format!("{e} (nothing was changed)"))?,
                )
            } else {
                None
            };
            let signer = match auth.and_then(|a| a.signing_key.as_ref()) {
                Some(_) => Some(resolve_signing_key(auth, &secret_resolver)?),
                None => None,
            };
            if admin_token.is_some() || signer.is_some() {
                rotate_gov_credentials = Some(Box::new(move || {
                    if let Some(token) = admin_token {
                        gs.set_admin_token(token.as_ref().map(|r| r.expose_secret().as_str()));
                    }
                    if let Some(signer) = signer {
                        gs.set_signing_key(signer);
                    }
                }));
            }
        }
        p.governance.clone()
    } else {
        // Governance is ALWAYS available (it is inert until an admin token is set and virtual keys are
        // minted). Only the STORE backend is a choice: ephemeral RAM by default, or a store PLUGIN
        // (resolved by alias or canonical name from the validated registry — the engine sees only the
        // returned `dyn Store`, exactly like a compiled-in backend).
        let g = cfg.store.clone().unwrap_or_default();
        let store: Arc<dyn governance::Store> =
            if g.module == crate::config::GOVERNANCE_STORE_MEMORY {
                tracing::warn!(
                    "store: in-memory (ephemeral) - keys, groups' usage, and ledgers reset on \
                     restart; configure a durable store plugin for persistence"
                );
                Arc::new(governance::MemoryStore::new())
            } else {
                // Resolve any SecretRef-typed setting (e.g. a `licenseKey`) against the secret
                // store BEFORE the settings cross the ABI (ADR-0010). FAIL-CLOSED: an unresolvable
                // ref refuses the store load rather than handing the plugin a dangling reference.
                let resolved = config::secret::resolve_settings(&g.settings, &secret_resolver)
                    .map_err(|e| format!("store '{}' settings: {e}", g.module))?;
                let cfg_json = serde_json::Value::Object(resolved).to_string();
                match plugin_registry.open_store(&g.module, &cfg_json) {
                    Ok(s) => Arc::from(s),
                    Err(e) => return Err(format!("store '{}' plugin load failed: {e}", g.module)),
                }
            };
        // The operator ADMIN credential: the `admin-tokens` chain entry's `token:` secret ref.
        // FAIL-CLOSED: a configured-but-unresolvable admin token refuses boot (a silently-absent
        // token would lock the admin API while the operator believes it is guarded).
        let admin_token: Option<busbar_api::Redacted<String>> =
            resolve_admin_token(cfg.auth.as_ref(), &secret_resolver)?;
        // The KEY-SIGNING key: resolve `auth.signing_key` (a secret ref) to 32 ed25519 secret
        // bytes. ABSENT => no signer (1.5.1: busbar no longer auto-generates one; config_validate
        // has already failed closed if the `keys` verifier is in the chain). Fleet deployments
        // provide it (shared) so every node verifies the same tokens.
        let signer = resolve_signing_key(cfg.auth.as_ref(), &secret_resolver)?;
        match governance::GovState::new_with_signer(
            store,
            admin_token.as_ref().map(|r| r.expose_secret().clone()),
            signer,
        ) {
            Ok(gs) => {
                let gs = Arc::new(gs);
                // BOOT-ONLY crash-recovery: hydrate the in-memory token-ledger cells (key buckets +
                // budget-group buckets) from the durable store so a restart resumes enforcement from
                // the persisted ledger. A no-op for the empty RAM store.
                // Fail-open: a store error here is FATAL - resuming with empty (reset) budget
                // cells would let a maxed-out key spend its whole cap again. Fail boot loudly.
                if let Err(e) = gs.hydrate_budgets(&cost, crate::store::now()) {
                    return Err(format!(
                        "governance boot: budget hydration failed ({e}); refusing to start with an \
                         unenforced (reset) ledger. Fix the durable store and restart."
                    ));
                }
                // BOOT FAIL-CLOSED: every stored key naming a budget_group must resolve in THIS
                // config (mint validates it; a shared durable store can carry keys minted under a
                // config another node no longer has). A dangling reference is a boot error naming
                // the offender with the paste-ready fix.
                // A store error reading the keys here must NOT be swallowed (the old `if let
                // Ok(keys)` skipped the whole dangling-reference check on error, so a boot-time store
                // blip published a config whose keys were never validated). Propagate it - fail boot.
                let keys = gs.all_keys().map_err(|e| {
                    format!(
                        "governance boot: could not read stored keys to validate budget_group \
                         references ({e}); refusing to start unvalidated. Fix the durable store and \
                         restart."
                    )
                })?;
                for k in &keys {
                    if let Some(group) = k.group.as_deref() {
                        if cost.group_named(group).is_none() {
                            return Err(format!(
                                "virtual key '{}' names group '{group}', which does not exist in the top-level groups block.\n\
                                 Paste this under groups and set real limits:\n\n    {group}:\n      limits:\n        - {{ budget: 0, per: month }}\n",
                                k.id
                            ));
                        }
                    }
                }
                // INERT-KEYS GUARD: a durable store may carry virtual keys minted in a prior run
                // whose data-plane chain no longer names the `keys` verifier — no request then
                // resolves them and their per-key controls are silently bypassed. Surface it LOUD:
                // ERROR level (survives RUST_LOG=error) AND unconditionally on stderr, mirroring the
                // open-relay banner so log config can't mask it. RAM stores can't reach this state,
                // so `key_count` there is 0 (or the store is non-durable) and the banner is None.
                // `all_keys()` failure is non-fatal — treat as 0 keys (the enforcement gate is
                // unaffected; we only lose the advisory). Inertness is now recomputed from CHAIN
                // SHAPE (is `keys` in the running chain?), not the admin token.
                let store_is_durable = g.module != crate::config::GOVERNANCE_STORE_MEMORY;
                let key_count = gs.all_keys().map(|k| k.len()).unwrap_or(0);
                let keys_in_chain = auth_mw.keys_in_chain;
                if let Some(banner) =
                    inert_durable_keys_banner(store_is_durable, key_count, keys_in_chain)
                {
                    eprintln!("[error] {banner}");
                    tracing::error!("{banner}");
                }
                Some(gs)
            }
            Err(e) => return Err(format!("governance init failed: {e}")),
        }
    };

    // Resolve the global rewrite hooks (prompt: rw gates in global_hooks) into priority-ordered
    // transports ONCE. Empty unless the operator configured a rewrite hook — zero cost by default.
    let rewrite_hooks =
        hooks::resolve_rewrite_hooks(&cfg.hooks, &cfg.global_hooks, &hook_env, app_config_version);
    // Resolve the global request-stage tap hooks the same way. Empty unless configured.
    let tap_hooks = hooks::resolve_tap_hooks(
        &cfg.hooks,
        &cfg.global_hooks,
        &hook_env,
        app_config_version,
        config::HookStage::Request,
    );
    let tap_hooks_candidate = hooks::resolve_tap_hooks(
        &cfg.hooks,
        &cfg.global_hooks,
        &hook_env,
        app_config_version,
        config::HookStage::Candidate,
    );
    let tap_hooks_routing = hooks::resolve_tap_hooks(
        &cfg.hooks,
        &cfg.global_hooks,
        &hook_env,
        app_config_version,
        config::HookStage::Routing,
    );
    let tap_hooks_response = hooks::resolve_tap_hooks(
        &cfg.hooks,
        &cfg.global_hooks,
        &hook_env,
        app_config_version,
        config::HookStage::Response,
    );
    // Resolve the global DECISION gates (non-rewrite gates in global_hooks) — fired for a verdict on
    // every request. Empty unless configured.
    let global_gates =
        hooks::resolve_gate_hooks(&cfg.hooks, &cfg.global_hooks, &hook_env, app_config_version);

    // EVERY fallible step of THIS build has now succeeded, so `rotate_gov_credentials` (if any) is
    // ready to run. It is NOT invoked here, though: `GovState` is a process-lifetime `Arc` shared
    // with the OLD `App` that is still serving, so invoking it now would mutate the live engine's
    // credentials even though the candidate `App` returned below is only a CANDIDATE — the admin
    // transaction wrapping this call (`txn.rs`) still has a fallible PERSIST step to run, and on a
    // persist failure the transaction discards this candidate and swaps nothing. Firing the
    // rotation here would leave the "nothing was changed" response a lie: the shared `GovState`
    // would already carry the new credential while the old (rejected) `App` keeps serving. The
    // caller is responsible for invoking the returned closure — after its own persist step (if any)
    // has succeeded, never before.

    // The probe schedule is live state, not config-derived: it carries each lane's next-probe deadline
    // and the prober generation. `App::clone` shares it (Arc), so an in-place mutation swap keeps the
    // phase; a REBUILD must do the same, or a mutation cadence faster than the probe interval —
    // /config/settings meters at 10/min, the default interval is 30s — replaces every generation before
    // its first tick and probing goes dark while still logging that it is enabled. Carried ONLY when the
    // lane set is identical, because deadlines are indexed by lane: a changed lane set makes the old
    // indices mean something else, and a genuine lane change SHOULD re-establish probing.
    //
    // zip ≡ set-equality HERE, not in general: `cfg.models` is a `HashMap<String, ModelCfg>`, so model
    // names are UNIQUE keys, and both lane vectors are built by sorting those keys before reaching this
    // point. Two vectors built from the same unique-key set via the same deterministic sort are
    // identical element-for-element, so an elementwise compare and a set compare accept exactly the
    // same configs. Do NOT reuse this shortcut for a lane source that is not sorted-from-a-unique-key-
    // set: there the zip would start accepting a shifted-index pairing.
    let probe_schedule = match prior {
        Some(p)
            if p.lanes.len() == lanes.len()
                && p.lanes
                    .iter()
                    .zip(lanes.iter())
                    .all(|(a, b)| a.model == b.model && a.provider == b.provider) =>
        {
            p.probe_schedule.clone()
        }
        _ => Arc::new(crate::health::ProbeSchedule::new(lanes.len())),
    };

    // Plugin HTTP routes: the BUILT-IN exporters (`crate::export`) declare their routes
    // into the snapshot — today the `prometheus` exporter's `GET /metrics` when `export.prometheus` is
    // configured. Rebuilt on every config apply. A collision (a future loaded export/hook plugin
    // claiming a built-in's path) is a LOUD build failure naming the owner, never last-writer-wins.
    //
    // The rebuilt TABLE is not the same thing as what the ROUTER serves: each path is registered on
    // the router once, at boot, and an apply swaps only `Arc<App>`. So REMOVING `export.prometheus`
    // takes effect immediately (`plugin_route_dispatch` resolves the owner from the current snapshot
    // and 404s), while ADDING it needs a RESTART. `boot_route_paths` below is what remembers which
    // paths the router actually has, so a config mutation can SAY so instead of
    // reporting success for a route that will keep 404ing.
    let plugin_routes = std::sync::Arc::new(crate::plugin_routes::build_route_table(
        crate::export::route_decls(&cfg_export),
    )?);
    // Seeded ONCE, on a fresh boot (`prior == None`) from the table that is about to be mounted;
    // every rebuild inherits the boot value unchanged. Deliberately NOT recomputed per rebuild — a
    // recomputed set would say every newly declared path is already mounted, which is the exact
    // silent no-op this exists to report.
    let boot_route_paths = prior.map_or_else(
        || std::sync::Arc::new(plugin_routes.paths()),
        |p| p.boot_route_paths.clone(),
    );

    // THE A2A PLANE, lowered ONCE and read twice below: as the registry the re-verification job
    // sweeps, and as the source of the dispatch table's A2A admission facts. Lowering it twice would
    // let the mounted surface and the registry behind it come from two different readings of one
    // config generation.
    let a2a_plane =
        crate::a2a::plane::A2aPlane::from_config(&cfg.agent_defs, cfg.public_url.as_deref());

    // THE AUTHORIZATION SERVER, built ONCE, and only when the operator asked for one. Everything
    // this plane costs hangs off this `Option`: absent, nothing below runs, `App::oauth_as` is
    // `None`, `oauth_as::routes::mount` returns the router untouched, and no sweeper exists.
    //
    // The RFC 8707 `allowed_resources` list is busbar's OWN protected resources and nothing else.
    // Left unset, `oauth-as` would mint a token carrying whatever `resource` a client asked for in
    // its `aud`, which any resource server verifying against our JWKS would then honour — so the
    // list is derived here, from the planes this deployment actually serves, rather than configured
    // separately where it could disagree with them.
    let oauth_as_plane = match cfg.oauth_as.as_ref() {
        None => None,
        Some(identity) => {
            let key_material = match identity.signing_key() {
                None => {
                    tracing::warn!(
                        "oauth_as: no signing_key configured, so an EPHEMERAL ES256 key was \
                         generated. Every token this deployment issues stops verifying when the \
                         process restarts. Set `oauth_as.signing_key` for anything but a trial."
                    );
                    None
                }
                Some(reference) => Some(
                    secret_resolver
                        .resolve_string(reference)
                        .map_err(|e| format!("oauth_as.signing_key: {e}"))?,
                ),
            };
            let protected_resources: Vec<String> = cfg
                .mcp
                .as_ref()
                .map(|r| r.canonical_uri().to_string())
                .into_iter()
                .collect();
            let plane = crate::oauth_as::plane::AsPlane::build(
                identity.clone(),
                key_material.as_deref(),
                protected_resources,
            )
            .map_err(|e| e.to_string())?;
            let plane = Arc::new(plane);
            // `Storage::sweep_expired` is the only thing that reclaims anything in `oauth-as`, and
            // it runs when it is called and never otherwise. Spawned here, once per generation.
            crate::oauth_as::plane::spawn_sweeper(
                Arc::clone(plane.server()),
                std::time::Duration::from_secs(60),
            );
            Some(plane)
        }
    };

    // The generation's hook CONTENT ceiling, installed once here and read on the hook seam with a
    // single relaxed load — never recomputed per request, and never consulted at all on a
    // deployment with no content-granted hook, because no content projection is built there.
    crate::proxy::set_hook_content_max_bytes(cfg.limits.hook_content_max_bytes);

    let app = App {
        // The all-pools `upstream_credentials:` default (1.5.3 — moved off `auth:`).
        upstream_credentials: cfg.upstream_credentials,
        // Telemetry-bank slot table for this generation, registered BEFORE the config-derived
        // collections move into the snapshot. Identical label sets across applies re-intern to the
        // same slots, so hot-path counters accumulate monotonically across config generations.
        tslots: Arc::new(telemetry::AppSlots::build(
            &lanes,
            &pools,
            &by_model,
            crate::plane::Plane::Llm,
        )),
        probe_schedule,
        lanes,
        store,
        by_model,
        pools,
        client: upstream_client.clone(),
        auth: auth_mw.clone(),
        rewrite_hooks,
        tap_hooks,
        tap_hooks_candidate,
        tap_hooks_routing,
        tap_hooks_response,
        global_gates,
        hook_env: hook_env.clone(),
        hook_registry: cfg.hooks.clone(),
        requested_signals: hooks::requested_signals(&cfg.hooks),
        any_content_hook: hooks::any_content_hook(&cfg.hooks),
        export_projections: cfg.export.projection_union(),
        global_hooks: cfg.global_hooks.clone(),
        groups_registry: cfg.groups.clone(),
        base_group_names,
        // The two NAMED-DEFINITION maps the generic admin CRUD serves, carried verbatim off the
        // resolved config (the EFFECTIVE base+overlay shape).
        identity_providers: cfg.identity_providers.clone(),
        export_defs: cfg.export_defs.clone(),
        agent_defs: cfg.agent_defs.clone(),
        // THE A2A PLANE, built only when `agents:` defines one. A deployment that fronts no agents
        // gets `None` here and nothing downstream: no registry, no re-verification job. Built from
        // THIS generation's config on every apply, deliberately — a registration an operator
        // removed must stop being re-verified, and one whose pin they changed must be judged
        // against the pin they now declare.
        a2a: a2a_plane.clone(),
        // History + rate windows are Arc-shared across applies (process-lifetime state).
        versions: prior.map_or_else(
            || Arc::new(admin::versions::VersionLog::new()),
            |p| p.versions.clone(),
        ),
        mutation_limiter: prior.map_or_else(
            || Arc::new(admin::rate::MutationLimiter::new()),
            |p| p.mutation_limiter.clone(),
        ),
        idempotency_cache: prior.map_or_else(
            || Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            |p| p.idempotency_cache.clone(),
        ),
        base_hook_names,
        admin_chain: cfg.admin_auth.clone(),
        admin_modules,
        login_methods,
        public_url: cfg.public_url.clone(),
        // The MCP plane, and the dispatch table that governs it, are built from ONE validated
        // object in ONE act: the resource that mounts the ingress is the same resource whose
        // canonical URI becomes the audience the middleware enforces there. Absent `mcp:`, the
        // dispatch table is empty and `admission_for` answers `None` for every path, so the
        // audience check costs one `Option` test on the hot path and changes nothing.
        //
        // THE SECOND CONSUMER. A2A mounts and admits through the very same two verbs, with its own
        // strings and no new code in `plane/` — which is the claim that module's own doc made when
        // it was written for a consumer that did not exist yet. A2A admits only when it has a
        // RECEIVING side (`A2aPlane::admission` answers `None` without a `public_url`), so a
        // delegation-only deployment claims no path and binds no audience.
        planes: Arc::new({
            let mut dispatch = crate::plane::PlaneDispatch::default();
            if let Some(r) = cfg.mcp.as_ref() {
                dispatch = dispatch
                    .mount(
                        crate::plane::Plane::Mcp,
                        r.mount_path(),
                        crate::plane::WIRE_JSONRPC,
                    )
                    .admit(crate::plane::Plane::Mcp, r.admission());
            }
            if let Some(admission) = a2a_plane.as_ref().and_then(|p| p.admission()) {
                dispatch = dispatch
                    .mount(
                        crate::plane::Plane::A2a,
                        crate::a2a::serve::MOUNT_PATH,
                        crate::plane::WIRE_JSONRPC,
                    )
                    // THE SECOND BINDING'S PATH, claimed by the same act and for the same reason.
                    // gRPC is served at the path the vendored `a2a.proto` dictates rather than under
                    // the plane's mount, and a claimed path is where `admission_for` finds the RFC
                    // 8707 audience — so leaving it out would not merely mislabel the leg, it would
                    // admit a token minted for some other resource on it.
                    .mount(
                        crate::plane::Plane::A2a,
                        crate::a2a::serve::GRPC_MOUNT_PATH,
                        crate::plane::WIRE_GRPC,
                    )
                    .admit(crate::plane::Plane::A2a, admission);
            }
            dispatch
        }),
        mcp: cfg.mcp.clone().map(Arc::new),
        oauth_as: oauth_as_plane.clone(),
        // THE CATALOGUE SNAPSHOT, built here and only here. It takes the next PIN GENERATION on
        // construction, so every config apply — including one that changes nothing about `tools:` —
        // moves the generation and a call admitted under the previous one is refused at dispatch —
        // an in-flight call cannot outlive the approval it was admitted under, which is the whole
        // point of taking the generation here rather than reading config at dispatch time.
        // Building it beside the `App` is what makes the swap atomic: the
        // whole `Arc<App>` is replaced under one lock, so there is no window in which the catalogue
        // and the config that produced it disagree.
        mcp_catalogue: Arc::new(crate::mcp::catalogue::Catalogue::build(&cfg.tool_defs)),
        mcp_servers: Arc::new(cfg.tool_defs.clone()),
        mcp_pool: Arc::new(crate::mcp::client::pool::McpConnectionPool::new()),
        // CARRIED ACROSS THE APPLY. A sighting is what accumulated, not what the operator intended,
        // so a config apply must not erase it: dropping the observations here would clear a
        // quarantine as a side effect of an unrelated edit.
        mcp_sightings: prior.map_or_else(
            || Arc::new(crate::mcp::client::catalogue::CatalogueCache::new()),
            |p| p.mcp_sightings.clone(),
        ),
        // CARRIED ACROSS THE APPLY for the same reason, and it is the same class of mistake: an
        // approval already spent is evidence, not intent, and a config apply that forgot it would
        // hand every outstanding confirmation back to whoever still holds it.
        mcp_spent_approvals: prior.map_or_else(
            || Arc::new(crate::mcp::askstate::SpentAskStates::new()),
            |p| p.mcp_spent_approvals.clone(),
        ),
        credential_cache: prior.map_or_else(
            || Arc::new(auth_cache::CredentialCache::new()),
            |p| p.credential_cache.clone(),
        ),
        auth_scope_caps: cfg
            .auth
            .as_ref()
            .map(project_auth_scope_caps)
            .unwrap_or_default(),
        role_bindings: cfg
            .auth
            .as_ref()
            .map(|a| a.role_bindings.clone())
            .unwrap_or_default(),
        config_path: config_paths.0,
        providers_path: config_paths.1,
        overlay_path,
        config_version: app_config_version,
        max_keys_per_principal: cfg.limits.max_keys_per_principal,
        max_auto_provisioned_groups: cfg.limits.max_auto_provisioned_groups,
        failover_cfg,
        pool_runtime,
        fallback_pools,
        on_exhausted_cfgs,
        queued_depth: std::sync::Arc::new(crate::state::QueuedDepth::default()),
        governance,
        secret_resolver,
        cost,
        plugins_dir: std::path::PathBuf::from(&plugins_cfg.dir),
        plugins_cfg,
        default_max_tokens: cfg.limits.default_max_tokens,
        reasoning_effort_budgets: {
            let b = cfg.limits.reasoning_effort_budgets;
            [b.minimal, b.low, b.medium, b.high]
        },
        // Where `auth.key_ttl` is finally READ: the self-serve mint's token lifetime.
        // Config-validate already proved this parses; the fallback keeps a bad value from panicking.
        self_key_ttl_secs: cfg
            .auth
            .as_ref()
            .and_then(|a| a.key_ttl.as_deref())
            .map(|s| admin::parse_duration_secs(s).unwrap_or(admin::DEFAULT_KEY_TTL_SECS))
            .unwrap_or(admin::DEFAULT_KEY_TTL_SECS),
        // Arc-shared like `versions`/`mutation_limiter`: a REBUILD carries the SAME counter forward
        // (ids stay monotonic across a config reload) while a fresh boot seeds it once from OS
        // entropy (see `state::seed_request_id_counter`) so restarts don't restamp `0, 1, 2, …`.
        request_id_counter: prior.map_or_else(
            || {
                Arc::new(std::sync::atomic::AtomicU64::new(
                    state::seed_request_id_counter(),
                ))
            },
            |p| p.request_id_counter.clone(),
        ),
        plugin_routes,
        boot_route_paths,
    };
    // The build reached its end without a single fallible step refusing: KEEP the limits installed
    // at the top. Every earlier `return Err` / `?` drops the guard instead and rolls them back.
    limits_guard.commit();
    Ok((app, rotate_gov_credentials))
}

/// Build the busbar HTTP router for a given `App` state with default limits. Factored out so the
/// full route table + auth middleware can be exercised end-to-end in tests; production (`main`) calls
/// `build_router_with_limits` with the operator-configured values, so this convenience wrapper is
/// reached only from the test harness.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn build_router(app: std::sync::Arc<state::App>) -> Router {
    // Convenience builder for tests / callers without an explicit limits handle: the historical 32
    // MiB body cap (via the installed `limits`, falling back to the default when uninstalled) and NO
    // inbound-concurrency layer (`0` = unlimited) — byte-for-byte today's behavior. Production goes
    // through `build_router_with_limits` with the operator-configured values.
    build_router_with_limits(
        app,
        limits::translate_body_max_bytes(),
        crate::config::DEFAULT_MAX_INBOUND_CONCURRENT,
        crate::config::DEFAULT_RESPONSE_HEADERS_SERVER_TIMING,
    )
    .0
}

/// Router builder with EXPLICIT limits, building the COMBINED router (admin mounted on the data
/// routes). Used only by the test harness (`build_router`) to exercise the full route table + auth
/// middleware end-to-end on one router; production always serves admin on its OWN listener via
/// `build_split_routers_with_limits`, so admin and data never share a listener at runtime.
/// `max_inbound_concurrent == 0` ⇒ NO concurrency layer (a true no-op); `> 0` wraps the whole router
/// in a `limits::admission::InboundAdmissionLayer` as the OUTERMOST layer.
#[cfg_attr(not(test), allow(dead_code))]
fn build_router_with_limits(
    app: std::sync::Arc<state::App>,
    request_body_max_bytes: usize,
    max_inbound_concurrent: usize,
    server_timing_enabled: bool,
) -> (Router, std::sync::Arc<state::AppHandle>) {
    // Capture the plugin route table before `app` moves into the handle (both planes mount from it).
    let plugin_routes = app.plugin_routes.clone();
    // The MCP resource is captured before `app` moves into the handle, for the same reason the
    // plugin route table is: the mount is decided ONCE, from this generation's config, and a route
    // set is not something a later hot-swap can rewrite.
    let mcp = app.mcp.clone();
    let a2a = app.a2a.clone();
    let oauth_as = app.oauth_as.clone();
    let handle = std::sync::Arc::new(state::AppHandle::new(app));
    // TEST-ONLY combined router: mount the Admin API v1 onto the DATA route table so one router
    // exercises the whole surface. Production never does this — `build_split_routers_with_limits`
    // mounts admin on its OWN router served on a separate listener. Both planes' plugin routes are
    // mounted here (the combined router IS both listeners).
    let (router, core_routes) = base_data_router(
        &plugin_routes,
        mcp.as_deref(),
        a2a.as_ref(),
        oauth_as.as_ref(),
    );
    let router = admin::transport::mount(router, &admin::JsonV1);
    let router = crate::plugin_routes::mount_plugin_routes(router, &plugin_routes, true);
    let router = apply_common_layers(
        router,
        core_routes,
        &handle,
        request_body_max_bytes,
        server_timing_enabled,
    );
    (
        apply_inbound_concurrency_limit(router, max_inbound_concurrent),
        handle,
    )
}

/// The DATA-plane route table — protocols, discovery, and health/metrics/stats — WITHOUT the admin
/// surface. Pre-state (`Router<Arc<AppHandle>>`); the admin API is mounted separately (onto this
/// router in the single-listener case, or onto its own router in the split case) so it can move to
/// a dedicated listener without any of these routes coming with it.
fn base_data_router(
    plugin_routes: &crate::plugin_routes::PluginRouteTable,
    mcp: Option<&crate::mcp::McpResource>,
    a2a: Option<&std::sync::Arc<crate::a2a::plane::A2aPlane>>,
    oauth_as: Option<&std::sync::Arc<crate::oauth_as::plane::AsPlane>>,
) -> (
    Router<std::sync::Arc<state::AppHandle>>,
    crate::core_routes::CoreRouteTable,
) {
    use busbar_plugin_loader::{RouteAuth, RouteMethod};
    // EVERY core route is mounted through `CoreRouter::route`, which takes the handler and the
    // admission bar in ONE act (`core_routes`): a route the auth middleware knows nothing about is
    // not a thing this function can produce.
    let router = crate::core_routes::CoreRouter::new()
        .route("/stats", RouteMethod::Get, RouteAuth::Key, endpoints::stats)
        // The liveness probe is the one always-open core route: a probe must not require a caller
        // token. Declared here rather than asserted by the middleware, so the openness belongs to
        // the route and travels with whichever router mounts it.
        .route(
            crate::auth::HEALTHZ_PATH,
            RouteMethod::Get,
            RouteAuth::None,
            endpoints::healthz,
        );
    // METRICS ARE OPT-IN (the built-in `prometheus` EXPORTER, `export.prometheus`). 1.5.3: busbar's
    // OWN `/metrics` exposition is no longer a core route here — it is served by the built-in
    // prometheus exporter through the plugin HTTP endpoint registration (`mount_plugin_routes` below,
    // the well-known `/metrics` exception), resolved at scrape time so a hot-swap never leaves it
    // stale. The HOOK-metrics scrape (`/metrics/hooks`) stays a core route, mounted only
    // when the recorder is installed (`metrics::enabled()`), reserved against plugin claims.
    let router = if metrics::enabled() {
        // A SEPARATE exposition from busbar's own `/metrics` so a hook can never type-conflict or
        // shadow a first-party series. Verbatim hook metric names + an auto `hook="<name>"` label, so
        // an external dashboard built against a hook repoints here and just works.
        // Stale-while-revalidate; never blocks on a hook socket.
        router.route(
            "/metrics/hooks",
            RouteMethod::Get,
            RouteAuth::Key,
            crate::hooks::scrape::handler,
        )
    } else {
        router
    };
    let router = router
        // busbar's OWN API keeps explicit routes (it is not a protocol dialect): discovery,
        // health/metrics/stats above, and the named/adhoc conveniences below.
        // OpenAI list-models: SDKs call `models.list()` first; UIs build pickers from it.
        // Governance-scoped like /stats (restricted keys see only their reachable names).
        // Token exchange (1.5.2): a verified IdP identity mints its own self-serve key. DATA plane
        // only, and declared `RouteAuth::None` because the handler runs the auth chain ITSELF (it
        // needs the identified principal to self-scope the minted key). The declaration is what
        // confines that bypass to this router: the admin plane, which does not mount the route,
        // does not inherit its bypass.
        .route(
            crate::auth::exchange::AUTH_TOKEN_PATH,
            RouteMethod::Get,
            RouteAuth::None,
            crate::auth::token::browser,
        )
        .route(
            crate::auth::exchange::AUTH_TOKEN_PATH,
            RouteMethod::Post,
            RouteAuth::None,
            crate::auth::exchange::exchange,
        )
        .route(
            "/v1/models",
            RouteMethod::Get,
            RouteAuth::Key,
            endpoints::list_models,
        )
        .route(
            "/v1beta/models",
            RouteMethod::Get,
            RouteAuth::Key,
            endpoints::list_models_v1beta,
        )
        .route(
            "/{name}/v1/messages",
            RouteMethod::Post,
            RouteAuth::Key,
            ingress::named,
        )
        .route(
            "/{provider}/{model}/v1/messages",
            RouteMethod::Post,
            RouteAuth::Key,
            ingress::adhoc,
        );
    // THE MCP PLANE, mounted only when `mcp:` is configured. A deployment that is not an MCP server
    // carries none of these routes: no ingress, no metadata document, nothing in the route table and
    // therefore nothing for the auth middleware to consult. That is the same posture the AS design
    // requires of its own routes, and it is what makes "is this deployment an MCP server?" a
    // question the mounted surface answers rather than a config flag someone has to trust.
    //
    // The paths are CONCRETE, derived from the operator's canonical URI at mount time. No prefix
    // matching anywhere: `/.well-known/oauth-protected-resource/mcp` is registered as that exact
    // string, so the auth middleware's exact-match discipline survives a route whose path is not a
    // literal (see `core_routes::CoreRoute::path`).
    let router = match mcp {
        None => router,
        Some(resource) => router
            // RFC 9728 §3: the protected-resource metadata document is READ WITHOUT CREDENTIALS.
            // It must be — every caller who needs it is by definition one that does not have a
            // token yet, so requiring one would be a discovery loop with no entrance. This is the
            // ONE open route on this plane and it says so at the mount, where the openness travels
            // with the route rather than being asserted from a distance.
            .route(
                resource.metadata_path().to_string(),
                RouteMethod::Get,
                RouteAuth::None,
                crate::mcp::resource::metadata,
            )
            // The endpoint itself. `RouteAuth::Key` sends it through the normal chain, where the
            // plane's admission facts make the verifier require this deployment's canonical URI as
            // the token's audience — the RFC 8707 confused-deputy defence, enforced in the verifier
            // rather than in the handler so a route added here later cannot forget it.
            .route(
                resource.mount_path().to_string(),
                RouteMethod::Post,
                RouteAuth::Key,
                crate::mcp::ingress::rpc,
            )
            // GET and DELETE answer 405: this revision has no GET stream and no sessions. They are
            // `RouteAuth::Key` like the POST, so an anonymous caller gets the 401 challenge and the
            // 405 is only ever shown to an admitted one — a protected resource should not describe
            // its own surface before it knows who is asking.
            .route(
                resource.mount_path().to_string(),
                RouteMethod::Get,
                RouteAuth::Key,
                crate::mcp::ingress::legacy_verb,
            )
            .route(
                resource.mount_path().to_string(),
                RouteMethod::Delete,
                RouteAuth::Key,
                crate::mcp::ingress::legacy_verb,
            ),
    };

    // THE A2A PLANE, mounted on exactly the same terms and by the plane's own module: no `agents:`
    // (or no `public_url`, so no receiving side) means no route in the table at all, which is what
    // keeps "is this deployment an A2A server?" a question the mounted surface answers.
    let router = crate::a2a::ingress::mount(router, a2a);
    // THE AUTHORIZATION SERVER'S ROUTES, or none of them. Same posture as the two planes above: a
    // deployment that is not an authorization server carries no `/authorize`, no `/token`, no
    // metadata document and nothing in the route table.
    let router = crate::oauth_as::routes::mount(router, oauth_as);
    // PLUGIN HTTP ROUTES: the collision-checked, namespace-confined `none`/`key`-auth
    // routes an export/hook plugin declared. Reserved HERE — BEFORE the catch-all fallback below —
    // because `ingress::protocol_dispatch` claims every unclaimed path by construction, so a plugin
    // route wired after it would never match. The admin-auth routes are mounted on the admin listener
    // instead (see `build_split_routers_with_limits`), physically absent from this data plane.
    // They carry their OWN declared auth (`plugin_routes::PluginRouteTable`), so they are outside
    // the core table by construction rather than by omission.
    let router =
        router.map_router(|r| crate::plugin_routes::mount_plugin_routes(r, plugin_routes, false));
    router
        .map_router(|r| {
            r
                // EVERY protocol endpoint — chat and the 1.2 operations, all six dialects — flows
                // through the catch-all: Router (dumb protocol ID from path+headers) → that
                // protocol's RequestHandler (reads path+body, decides the operation) → its
                // OperationHandler cell. Adding a protocol or an operation never touches this file.
                // Unknown paths / wrong methods keep the pre-collapse native-envelope 404/405
                // shaping (no bare-proxy tells). A fallback claims no path, so it declares no route:
                // it takes the normal data-plane bar like any unclaimed path always has.
                .fallback(ingress::protocol_dispatch)
                // Wrong-method hits on a VALID path (axum's built-in 405) get the same
                // native-envelope treatment as the 404 fallback above.
                .method_not_allowed_fallback(method_not_allowed_handler)
        })
        .into_parts()
}

/// Apply the shared middleware stack — auth chain, request-body cap, 413 reshaping, server-timing —
/// and bind the swappable `AppHandle` state. Identical for the single-listener router and each
/// split-plane router, so both planes get the SAME auth + limit posture and both see config-apply
/// hot-swaps (they share one `handle`).
fn apply_common_layers(
    router: Router<std::sync::Arc<state::AppHandle>>,
    core_routes: crate::core_routes::CoreRouteTable,
    handle: &std::sync::Arc<state::AppHandle>,
    request_body_max_bytes: usize,
    server_timing_enabled: bool,
) -> Router {
    let router = router
        // The router's state is a swappable `AppHandle` (the config-apply hot-swap seam). Every
        // handler reads the CURRENT snapshot via the `CurrentApp` extractor; the auth middleware
        // loads it too. Until an admin apply calls `swap()`, this is identical to a fixed `Arc<App>`.
        .layer(axum::middleware::from_fn_with_state(
            handle.clone(),
            auth::auth_middleware,
        ))
        // THIS ROUTER's core route-auth table, handed to the auth middleware. Applied AFTER the
        // auth layer, which in axum means OUTSIDE it, so the extension is present by the time the
        // middleware extracts it. Per-router (not per-process) on purpose: the data plane and the
        // admin plane mount different core routes, and a route's bypass belongs to the plane that
        // serves it.
        .layer(axum::Extension(std::sync::Arc::new(core_routes)))
        // Cap request body size (buffered before the handler) to bound per-request memory. Driven by
        // `limits.request_body_max_bytes` (default 32 MiB); COUPLED with the egress translate-body cap
        // (`limits::translate_body_max_bytes`) — both read the SAME knob so an accepted request is
        // always buffer-translatable on the cross-protocol path.
        .layer(axum::extract::DefaultBodyLimit::max(request_body_max_bytes))
        // Outermost: reshape the body-limit layer's bare-text 413 into a protocol-native JSON
        // envelope. Must wrap the `DefaultBodyLimit` layer above, so it is applied LAST (the last
        // `.layer()` is the outermost on the response path) and therefore sees that layer's 413.
        .layer(axum::middleware::from_fn_with_state(
            handle.clone(),
            reshape_body_limit_413,
        ))
        // THE PLANE INGRESS BOUNDARY. Outside the auth layer, which in axum means it observes the
        // FINAL response — including a 401 the auth chain issued before any handler ran, which on
        // a mounted plane is exactly the failure an operator has no other signal for. It emits for
        // a path a plane CLAIMS BY MOUNT and passes everything else straight through, so the
        // residual plane (every protocol endpoint, `/healthz`, `/metrics`, the admin surface) is
        // untouched and cannot be double-counted against `ingress::finish_inner`.
        .layer(axum::middleware::from_fn_with_state(
            handle.clone(),
            crate::plane::observe::observe,
        ));
    // Always installed (cheap: one relaxed atomic add, no allocation) — the jemalloc idle-purge
    // activity ticker must keep incrementing whether or not `server_timing` below is installed.
    let router = router.layer(axum::middleware::from_fn(request_activity_tick));
    // Outermost, and COMPOSED IN ONLY WHEN ENABLED, for speed: an earlier version
    // installed this layer UNCONDITIONALLY and gated only the response header with a runtime `if`
    // inside `server_timing`, so every request paid an `Arc<AtomicU64>` allocation, an
    // `Instant::now()`, and a task-local `.scope()` even with the header suppressed. Gated on
    // `advanced.response_headers.server_timing` (default `false`): when `false` the layer is simply
    // NOT ADDED to the stack — zero per-request cost — mirroring
    // `apply_inbound_concurrency_limit`'s `max_inbound_concurrent > 0` composition gate below. Must
    // stay the LAST `.layer()` when present so it wraps (and times) everything inside it.
    let router = if server_timing_enabled {
        router.layer(axum::middleware::from_fn(server_timing))
    } else {
        router
    };
    router.with_state(handle.clone())
}

/// Build SEPARATE data-plane and admin-plane routers sharing ONE `AppHandle`, for the split-listener
/// deployment (`admin_listen` set). The admin surface is mounted ONLY on the admin router — it is
/// absent from the data router, so the data listener physically cannot serve `/api/v1/admin/*` (no
/// double-exposure: the whole point of splitting is that admin is not reachable on the public bind).
/// Both planes carry the identical middleware stack; the inbound-concurrency cap applies to the DATA
/// plane only (the low-volume admin plane is uncapped, matching today's default). Returns
/// `(data_router, admin_router, shared_handle)`.
fn build_split_routers_with_limits(
    app: std::sync::Arc<state::App>,
    request_body_max_bytes: usize,
    max_inbound_concurrent: usize,
    server_timing_enabled: bool,
) -> (Router, Router, std::sync::Arc<state::AppHandle>) {
    // Capture the plugin route table before `app` moves into the handle.
    let plugin_routes = app.plugin_routes.clone();
    let mcp = app.mcp.clone();
    let a2a = app.a2a.clone();
    let oauth_as = app.oauth_as.clone();
    let handle = std::sync::Arc::new(state::AppHandle::new(app));
    // DATA plane: protocols + health/metrics/stats + the `none`/`key`-auth plugin routes, NO admin
    // mount and NO admin-auth plugin routes (those are physically absent from the data listener).
    let (data, data_core_routes) = base_data_router(
        &plugin_routes,
        mcp.as_deref(),
        a2a.as_ref(),
        oauth_as.as_ref(),
    );
    let data = apply_common_layers(
        data,
        data_core_routes,
        &handle,
        request_body_max_bytes,
        server_timing_enabled,
    );
    let data = apply_inbound_concurrency_limit(data, max_inbound_concurrent);
    // ADMIN plane: a liveness probe (unauthenticated, like the data plane's) + the admin surface +
    // the `admin`-auth plugin routes (confined to this listener exactly like `/api/v1/admin/*`).
    // `/healthz` bypasses auth so probes work on the admin port too; every `/api/v1/admin/*` route
    // stays behind the admin auth chain.
    let (admin, admin_core_routes) = crate::core_routes::CoreRouter::new()
        .route(
            crate::auth::HEALTHZ_PATH,
            busbar_plugin_loader::RouteMethod::Get,
            busbar_plugin_loader::RouteAuth::None,
            endpoints::healthz,
        )
        .into_parts();
    let admin = admin::transport::mount(admin, &admin::JsonV1);
    let admin = crate::plugin_routes::mount_plugin_routes(admin, &plugin_routes, true);
    let admin = apply_common_layers(
        admin,
        admin_core_routes,
        &handle,
        request_body_max_bytes,
        server_timing_enabled,
    );
    (data, admin, handle)
}

/// OUTERMOST inbound-concurrency cap. `max_inbound_concurrent == 0` disables the layer entirely (a
/// true no-op) — but `0` is NOT the default; `DEFAULT_MAX_INBOUND_CONCURRENT` is `8192`, so the layer
/// IS installed out of the box and an operator opts OUT with `0`, not in. When `> 0` (including the
/// default), [`limits::admission::InboundAdmissionLayer`] (one `AdmissionGate`, shared across ALL
/// requests) bounds in-flight inbound work: a request that arrives with the cap FULL is SHED with a
/// 503 immediately rather than queued for a permit (Bug 4). Applied as the last `.layer()` so it is
/// outermost (it must admission-control before any inner work, including body buffering). Factored
/// out so the add-only-when-`>0` rule is unit-testable in isolation.
/// Project the resolved `auth:` block onto [`state::App::auth_scope_caps`] — the per-PROVIDER admin
/// trust CEILING (`max_admin_scope:`) the admin authorization step floors every non-`admin-tokens`
/// verdict against.
///
/// KEYED BY PROVIDER NAME, not by the backing plugin MODULE. That is the whole point of the 1.5.3
/// named-definition pattern and the invariant [`crate::auth::ChainVerdict::Identified`] states
/// verbatim: two NAMED providers may share one plugin module and must get INDEPENDENT bindings and
/// ceilings. The lookup side (`auth::module_admin_scope_cap`) reads this map with the provider NAME
/// (the identity a chain verdict carries), and `role_bindings` is name-keyed too — so a module-keyed
/// build here disagreed with both. The dominant effect was fail-CLOSED (a miss floors to
/// `read-only`, silently ignoring an operator's explicit `max_admin_scope: full`), but a config in
/// which one provider's NAME equals a DIFFERENT provider's MODULE handed the first provider's
/// ceiling to the second — an escalation. Name-keying closes both.
fn project_auth_scope_caps(a: &config::AuthCfg) -> std::collections::HashMap<String, String> {
    a.chain
        .iter()
        .chain(a.admin_auth.iter())
        .filter_map(|e| {
            e.max_admin_scope
                .as_ref()
                .map(|sc| (e.name.clone(), sc.clone()))
        })
        .collect()
}

fn apply_inbound_concurrency_limit(router: Router, max_inbound_concurrent: usize) -> Router {
    if max_inbound_concurrent > 0 {
        router.layer(limits::admission::InboundAdmissionLayer::new(
            max_inbound_concurrent,
        ))
    } else {
        router
    }
}

#[cfg(test)]
#[path = "tests/tests.rs"]
mod tests;
