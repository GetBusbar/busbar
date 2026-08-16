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

// The engine. Everything below composes busbar-core; the module imports keep the boot code's
// paths reading the way they did when these modules were this crate's own.
use std::sync::Arc;
use std::time::Duration;

use axum::Router;

use busbar_core::{admin, config, config_validate, export, health, metrics, observability, tls};
use busbar_core::{
    build_app_from_config, build_split_routers_with_limits, load_config_from_disk,
    preflight_plugins_and_secrets, validate_builtin_secrets_resolve, LoadedConfig,
    DEFAULT_CONFIG_PATH, ENV_CONFIG, ENV_PROVIDERS, REQUEST_ACTIVITY_TICKS,
};

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

/// Whether `--safe-mode` was passed: quarantines the persisted overlay entirely (both
/// `validate_config_command` and `run()` read this the same way, so it's factored once here rather
/// than duplicated). Takes the arg iterator as a parameter (instead of calling `std::env::args()`
/// itself) so it's unit-testable against a synthetic arg list.
fn safe_mode_requested(mut args: impl Iterator<Item = String>) -> bool {
    args.any(|a| a == "--safe-mode")
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

/// REGISTER THE LINKED PROTOCOL CRATES — the composition root's one write into the protocol axis
/// (`busbar_core::proto::registry::install_protocols`). Each linked dialect contributes its `&DECL`
/// here and nowhere else; core's own built-in table keeps the dialects that have not been extracted
/// yet. Feature-gated per crate so a deletion build (`--no-default-features`, or default minus one
/// `proto-*` feature) drops the dependency edge AND the registration line together — which is what
/// makes `cargo build -p busbar` without a dialect a complete deletion, not a link error.
fn register_protocols() {
    static INSTALLED: &[&busbar_core::proto::ProtocolDecl] = &[
        #[cfg(feature = "proto-anthropic")]
        &busbar_proto_anthropic::DECL,
        #[cfg(feature = "proto-mcp")]
        &busbar_proto_mcp::DECL,
    ];
    busbar_core::proto::registry::install_protocols(INSTALLED);
}

fn main() {
    // PROTOCOL REGISTRATION FIRST — before the CLI flags, because `--validate` reads the protocol
    // set. This is the composition root's whole knowledge of the protocol crates: one line per
    // linked dialect, handed to the registry seam before anything reads it. A dialect absent from
    // the build (its feature off) is simply never registered, and a config that names it gets the
    // unknown-protocol refusal — the deletion test's runtime half (scripts/proto-deletion-gate.sh).
    register_protocols();
    // CLI flags next — BEFORE building any runtime. They must work without a configured deployment,
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
    if busbar_core::profile::enabled() {
        std::thread::spawn(|| loop {
            std::thread::sleep(std::time::Duration::from_secs(20));
            busbar_core::profile::dump();
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
    busbar_core::proxy::configure_route_policy_headers(response_headers_cfg.route_policy);
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

    // DURABLE STATE HYDRATION — the audit ring, the A2A task table, the MCP per-call log and
    // the MCP demotion/spent-approval records, restored from the configured governance store
    // BEFORE a listener is bound. One boot entry point (`busbar_core::boot::hydrate_all`)
    // rather than four widened statics: the sinks (`AUDIT`, `TASKS`, `CALLS`) and their
    // restore verbs stay crate-private in core, so nothing outside the engine can swap a sink
    // out from under the hash chains. The narration (which restore is a hiccup, which is
    // tamper evidence) moved with the code; see busbar-core/src/boot.rs.
    busbar_core::boot::hydrate_all(&app);
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
    busbar_core::admin::restart::publish_shutdown(shutdown_tx.clone());
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
        std::mem::drop(busbar_core::governance::spawn_budget_flusher(
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
    std::mem::drop(busbar_core::mcp::spawn_refresh_job(
        &app_handle,
        shutdown_tx.subscribe(),
    ));

    // THE A2A RE-VERIFICATION JOB — hydration's sibling: spawned once, here, and folded into
    // `busbar_core::boot` so the sweeper, the live-fetch transport and the identity resolver
    // stay crate-private in core (the widened surface is exactly where a plane-shaped API
    // could grow). Fatal if an outbound client identity does not
    // resolve, exactly as before — the refusal text is the boot function's.
    busbar_core::boot::spawn_a2a_reverify(&app_handle, &shutdown_tx).unwrap_or_else(|e| die(e));
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
    tls_cfg: Option<busbar_core::config::TlsCfg>,
    secret_resolver: Arc<busbar_core::config::secret::SecretResolver>,
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

/// Resolve when the process receives a shutdown signal: SIGINT/ctrl_c everywhere, plus SIGTERM on
/// unix and CTRL_CLOSE/CTRL_SHUTDOWN on Windows (the events an orderly non-interactive stop
/// actually delivers on each platform). Used as
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

    // WINDOWS HAS NO SIGTERM, BUT IT DOES HAVE AN ORDERLY STOP, and `ctrl_c` alone does not hear it.
    // `tokio::signal::ctrl_c` on Windows is CTRL_C_EVENT only — an interactive Ctrl+C. Every
    // NON-interactive stop arrives as a different console control event: `docker stop` on a Windows
    // container and a closing console send CTRL_CLOSE_EVENT, and a machine shutdown sends
    // CTRL_SHUTDOWN_EVENT. With only the `ctrl_c` arm, all of those bypassed the graceful-shutdown
    // future entirely and the process was killed with requests still in flight — the drain this
    // function exists to trigger simply did not run, silently, on the platform's most common stop.
    // Each arm degrades exactly like the unix one: a registration failure is logged and that branch
    // parks, so it can never abort the others.
    // Each event is registered INDEPENDENTLY, and that is the same fail-soft rule the unix arm
    // states: one registration failing must cost only its own branch. Folding both into one
    // sequential setup would let a failure on the SECOND discard the first one that had already
    // succeeded, degrading a partial failure all the way to no coverage instead of to the coverage
    // that was actually available.
    #[cfg(windows)]
    let terminate = async {
        let close = async {
            match tokio::signal::windows::ctrl_close() {
                Ok(mut sig) => {
                    sig.recv().await;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to install ctrl_close handler; CTRL_CLOSE shutdown disabled");
                    std::future::pending::<()>().await;
                }
            }
        };
        let shutdown = async {
            match tokio::signal::windows::ctrl_shutdown() {
                Ok(mut sig) => {
                    sig.recv().await;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to install ctrl_shutdown handler; CTRL_SHUTDOWN shutdown disabled");
                    std::future::pending::<()>().await;
                }
            }
        };
        tokio::select! {
            _ = close => {}
            _ = shutdown => {}
        }
    };

    #[cfg(not(any(unix, windows)))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
    tracing::info!("shutdown signal received; draining in-flight requests");
}

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

/// `--generate-signing-key`: mint a fresh ed25519 signing secret from the OS RNG and PRINT it (as 64
/// hex chars) plus a paste-ready `auth.signing_key` snippet + a fleet note. ZERO side effects - like
/// `--validate`/`--migrate-config`, it writes nothing; the operator PLACES the key (busbar never
/// edits their config). Exit 0 on success, 1 if the OS entropy source is unavailable.
fn generate_signing_key_command() -> i32 {
    // The mint lives behind `busbar_core::boot`: the CLI needs a hex string, not a `TokenSigner`,
    // so the signer type and its default kid stay crate-private in core.
    let hex = match busbar_core::boot::generate_signing_key_hex() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("busbar: could not generate a signing key: {e}");
            return 1;
        }
    };
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

#[cfg(test)]
#[path = "tests/tests.rs"]
mod tests;
