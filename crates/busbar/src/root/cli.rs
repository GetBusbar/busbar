// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE FLAG SURFACE — everything busbar answers on the command line instead of on a socket.
//!
//! `main()` has two halves and they have nothing to do with each other. One BOOTS AND SERVES: it
//! sizes the runtime, installs the four axes, resolves configuration, seals the composition root,
//! binds listeners and runs until a signal. The other ANSWERS AND EXITS: `--version`, `--help`,
//! `--build-info`, `--print-metadata-blocklist`, `--validate`, `--list-plugins`,
//! `--migrate-config`, `--generate-signing-key` — each of which prints, returns an exit code, and
//! never binds anything. This file is the second half, and it is here because one file over the
//! `structure-lint:oversized` cap measures two things at once and tells you about neither.
//!
//! ## What binds the two halves together, and why it is not a duplicate
//!
//! The serving half reads the SAME flags this one does — `-c`/`--config`, `--providers`,
//! `BUSBAR_CONFIG`, `BUSBAR_PROVIDERS` — so the scanners that resolve them ([`value_flag`],
//! [`config_path_flag`], [`providers_override`], [`resolve_config_path`]) and the two
//! override notices live here and are `pub(crate)` rather than copied. A `--validate` that
//! resolved its config path by a different rule than boot does would be a clean check of a file
//! the gateway will never read, which is the one thing `--validate` exists to rule out.
//!
//! ## Why it is under the composition root and not beside `main.rs`
//!
//! Not taste — coverage. `xtask/src/audit.rs` special-cases the binary crate (`SPLIT_CRATE`) into
//! exactly two production audit scopes, `crates/busbar/src/root` and `crates/busbar/src/main.rs`,
//! and pushes no scope for `crates/busbar/src` itself. A module at `src/cli.rs` would belong to
//! neither and would be read by no audit round; under `src/root/` the directory scope already
//! covers it. `src/build_stamp.rs` is the standing example of the other outcome.
//!
//! Boot ORDER already puts the flags here: the root's own note records that boot runs kernel,
//! interner, transports, planes, the two boot checks, *then* the CLI flags — because `--validate`
//! reads the plane and protocol lists and every axis must be installed before any reader.

use busbar_kernel::{config, config_validate};
use busbar_kernel::{
    load_config_from_disk, preflight_plugins_and_secrets, validate_builtin_secrets_resolve,
    DEFAULT_CONFIG_PATH, ENV_CONFIG, ENV_PROVIDERS,
};

use crate::{build_info_line, safe_mode_requested};

/// Handle CLI flags before any environment or file access, so they work without a configured
/// deployment. Returns `Some(exit_code)` when the process should exit (after printing), `None` to
/// proceed to normal startup. busbar takes no positional arguments and is configured via
/// environment + YAML; an unrecognized flag is a usage error rather than a silent server start.
pub(crate) fn handle_cli_flags() -> Option<i32> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        None => None, // no args → run the gateway
        Some("--version" | "-V") => {
            // Version AND build posture on one line each: an operator correlating a perf number to a
            // binary sees immediately whether it was the optimized release build or a local debug/
            // non-PGO build (the misdiagnosis this stamp exists to prevent).
            println!("busbar {}", env!("CARGO_PKG_VERSION"));
            println!("build: {}", build_info_line());
            Some(0)
        }
        Some("--build-info") => {
            // The raw stamp line ALONE (no version prefix), for CI to parse and assert against. Kept
            // separate from `--version` so the gate greps a stable single line.
            println!("{}", build_info_line());
            Some(0)
        }
        Some("--print-metadata-blocklist") => {
            // Print the EFFECTIVE cloud-metadata denylist the running binary enforces: the hardcoded
            // set (single source of truth in config_validate) UNION the operator's
            // `security.blocked_metadata_hosts`. The hardcoded set always prints (no config needed);
            // the operator extension is appended best-effort if BUSBAR_CONFIG is readable + parseable,
            // so the flag is useful even before a deployment is wired up. One entry per line, exit 0.
            let mut entries = config_validate::metadata_denylist_entries();
            let config_path = resolve_config_path(config_path_flag().as_deref());
            if let Ok(raw) = std::fs::read_to_string(&config_path) {
                match config::interpolate_env(&raw) {
                    Ok(interpolated) => {
                        match config::deploy_from_yaml_str(&interpolated) {
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
                                "warning: {code}: config at {config_path} did not parse; printing the \
                                 built-in metadata denylist only (security.blocked_metadata_hosts \
                                 skipped). Run busbar normally to see the parse error.",
                                code = busbar_substrate_values::diagnostics::CLI_METADATA_BLOCKLIST_CONFIG_UNREADABLE.banner()
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
                            "warning: {code}: config at {config_path} failed to interpolate; printing \
                             the built-in metadata denylist only (security.blocked_metadata_hosts \
                             skipped). Run busbar normally to see the interpolation error.",
                            code = busbar_substrate_values::diagnostics::CLI_METADATA_BLOCKLIST_CONFIG_UNREADABLE.banner()
                        );
                    }
                }
            }
            for entry in entries {
                println!("{entry}");
            }
            Some(0)
        }
        // The STDIO SERVE MODE is not an exit-and-print flag: it proceeds to the ordinary boot and
        // is read again inside `run()`, where it swaps the two TCP listeners for the process's own
        // stdin/stdout. Recognised here so it is not refused as an unknown argument.
        Some("--mcp-stdio") => None,
        Some("--validate") => Some(validate_config_command()),
        Some("--generate-signing-key") => Some(generate_signing_key_command()),
        Some("--list-plugins") => Some(list_plugins_command()),
        Some("--migrate-config") => Some(migrate_config_command(args.next())),
        Some("--help" | "-h") => {
            println!(
                "busbar {ver} — native-protocol LLM gateway

USAGE:
    busbar [-c <path>] [--providers <path>]
                        run the gateway (configured via environment + YAML; the two optional flags
                        point busbar at its config.yaml / providers.yaml — see CONFIG INPUTS below)
    busbar --help       print this help
    busbar --version    print the version (and the build-provenance stamp)
    busbar --build-info print the build-provenance stamp alone (profile / opt-level / lto /
                        debug-assertions / pgo / target / target-cpu) — how this binary was built,
                        for correlating a perf number to a build and for CI's build-parity gate
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

CONFIG INPUTS:
    -c, --config <path> path to config.yaml. Precedence: this flag > BUSBAR_CONFIG env >
                        /etc/busbar/config.yaml (default). Accepts `-c <path>`, `--config <path>`,
                        and `--config=<path>`.
    --providers <path>  path to providers.yaml. Precedence: this flag > `providers_file:` in
                        config.yaml > providers.yaml next to the resolved config.yaml (default).
                        Accepts `--providers <path>` and `--providers=<path>`.

ENVIRONMENT:
    BUSBAR_CONFIG       path to config.yaml     (default: /etc/busbar/config.yaml; overridden by
                        -c/--config)
    BUSBAR_PROVIDERS    path to providers.yaml  (DEPRECATED — set `providers_file:` in config.yaml;
                        default: providers.yaml next to the resolved config.yaml)
    RUST_LOG            log level: error|warn|info|debug|trace  (default: info)

Flags:
    --safe-mode         boot on base config.yaml alone (quarantine the persisted overlay)
    --mcp-stdio         serve the MCP plane on THIS PROCESS's stdin/stdout (newline-delimited
                        JSON-RPC) instead of binding any listener — for an MCP host that runs
                        busbar as a child process. Requires the `mcp:` block; on a deployment with
                        a configured `auth.chain`, BUSBAR_MCP_STDIO_CREDENTIAL must carry a
                        credential the chain admits (audience-bound to mcp.canonical_uri), and the
                        whole session runs as that key — budgets, audit and hooks apply

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
        // `-c`/`--config`/`--providers` (value-taking flags) as the FIRST argument mean "run the
        // gateway with these config/providers paths" — proceed to boot. `run()` (and each command
        // path) scans the FULL arg list for their values, so they are honored wherever they appear;
        // recognizing them here only stops the leading one from being rejected as an unknown argument.
        // The unknown-flag rejection below is unchanged.
        Some(a)
            if a == "-c"
                || a == "--config"
                || a == "--providers"
                || a.starts_with("--config=")
                || a.starts_with("--providers=") =>
        {
            None
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
/// Honors `-c`/`--config`, `--providers`, `BUSBAR_CONFIG`, and `--safe-mode` exactly as boot does.
/// Prints an OK summary + exits 0 when valid;
/// prints every error (same text boot prints) + exits 1 when not.
fn validate_config_command() -> i32 {
    let providers_override = providers_override();
    let config_path = std::path::PathBuf::from(resolve_config_path(config_path_flag().as_deref()));
    let safe_mode = safe_mode_requested(std::env::args());

    let mut loaded = match load_config_from_disk(
        &config_path,
        providers_override.as_deref(),
        safe_mode,
        config::EnvSubst::Lenient,
    ) {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "[error] {}: {e}",
                busbar_substrate_values::diagnostics::CLI_VALIDATE_CONFIG_INVALID.banner()
            );
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
            eprintln!(
                "[error] {}: config errors:\n  - {}",
                busbar_substrate_values::diagnostics::CLI_VALIDATE_CONFIG_INVALID.banner(),
                errs.join("\n  - ")
            );
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
            "[error] {}: config validation failed:\n  - {}",
            busbar_substrate_values::diagnostics::CLI_VALIDATE_CONFIG_INVALID.banner(),
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
            eprintln!(
                "[error] {}: {e}",
                busbar_substrate_values::diagnostics::CLI_VALIDATE_PLUGIN_PREFLIGHT_FAILED.banner()
            );
            return 1;
        }
    };

    // STRICT SECRETS, `--validate` only. The pre-flight above is shared with boot and admin apply,
    // where an unresolvable secret WARNS by design. Here the operator is asking whether the config
    // is good, so an env var that is not set is an answer, not a footnote.
    if let Err(e) = validate_builtin_secrets_resolve(&cfg) {
        eprintln!(
            "[error] {}: {e}",
            busbar_substrate_values::diagnostics::CLI_VALIDATE_CONFIG_INVALID.banner()
        );
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
    let providers_override = providers_override();
    let config_path = std::path::PathBuf::from(resolve_config_path(config_path_flag().as_deref()));
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
            eprintln!(
                "[warn] {}: config not readable ({e}); using the default plugins block",
                busbar_substrate_values::diagnostics::CLI_LIST_PLUGINS_CONFIG_UNREADABLE.banner()
            );
            (
                config::PluginsCfg::default(),
                config::GOVERNANCE_STORE_MEMORY.to_string(),
            )
        }
    };
    let policy = match plugins_cfg.to_policy() {
        Ok(p) => p,
        Err(e) => {
            eprintln!(
                "[error] {}: plugins.trust is invalid: {e}",
                busbar_substrate_values::diagnostics::CLI_LIST_PLUGINS_TRUST_INVALID.banner()
            );
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

/// Resolve the config.yaml path under the flag-first precedence (1.6.0):
/// `-c`/`--config <path>` flag > `BUSBAR_CONFIG` env > compiled-in `DEFAULT_CONFIG_PATH`. The ONE
/// resolver every config-path consumer routes through, so the precedence is stated once. `cli` is the
/// value of the `--config` flag (scanned from the process args via [`config_path_flag`]); `None` ⇒
/// no flag passed, fall through to the env layer and then the default.
pub(crate) fn resolve_config_path(cli: Option<&str>) -> String {
    match cli {
        Some(p) => p.to_string(),
        None => std::env::var(ENV_CONFIG).unwrap_or_else(|_| DEFAULT_CONFIG_PATH.into()),
    }
}

/// Scan an arg iterator for a value-taking flag and return the LAST occurrence's value. Accepts
/// `--long value`, `--long=value`, and (when `short` is `Some("-x")`) the short `-x value` form.
/// Takes the iterator as a parameter (like `safe_mode_requested`) so it is unit-testable against a
/// synthetic arg list rather than the process environment.
pub(crate) fn value_flag(
    args: impl Iterator<Item = String>,
    long: &str,
    short: Option<&str>,
) -> Option<String> {
    let eq_prefix = format!("{long}=");
    let mut result = None;
    let mut iter = args;
    while let Some(a) = iter.next() {
        if let Some(v) = a.strip_prefix(&eq_prefix) {
            result = Some(v.to_string());
        } else if a == long || short == Some(a.as_str()) {
            if let Some(v) = iter.next() {
                result = Some(v);
            }
        }
    }
    result
}

/// The `-c`/`--config <path>` flag value from the process args (`None` ⇒ not passed). See
/// [`resolve_config_path`] for the precedence this feeds.
pub(crate) fn config_path_flag() -> Option<String> {
    value_flag(std::env::args().skip(1), "--config", Some("-c"))
}

/// The providers-catalog override handed to [`load_config_from_disk`]: the `--providers <path>` flag
/// value, else the deprecated `BUSBAR_PROVIDERS` env var (`None` ⇒ neither, so the catalog resolves
/// from `providers_file:` or the default next to config.yaml). Precedence is `--providers` flag >
/// `BUSBAR_PROVIDERS` env > `providers_file:` config key > `providers.yaml` default.
pub(crate) fn providers_override() -> Option<std::path::PathBuf> {
    value_flag(std::env::args().skip(1), "--providers", None)
        .map(std::path::PathBuf::from)
        .or_else(providers_override_from_env)
}

/// Resolve the DEPRECATED `BUSBAR_PROVIDERS` override, warning once when it is set. `None` ⇒ unset
/// or empty. Kept so an operator's existing pin keeps working across the upgrade to the
/// `providers_file:` config key. Pre-subscriber (it runs before tracing is installed under
/// `--validate` and at boot alike), so the warning goes to stderr like the other boot diagnostics.
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

/// The config-path override notice (1.6.0): `Some(msg)` when BOTH the `--config` flag and the
/// `BUSBAR_CONFIG` env var are set to DIFFERENT paths — the flag wins, so an operator whose env value
/// was ignored is told why. `None` when the flag is absent, the env is unset, or the two are equal (no
/// real override to explain). Pure so the "REAL override only" rule is unit-testable.
pub(crate) fn config_override_notice(flag: Option<&str>, env: Option<&str>) -> Option<String> {
    match (flag, env) {
        (Some(f), Some(e)) if f != e => Some(format!(
            "config: using --config '{f}' (overrides BUSBAR_CONFIG='{e}')"
        )),
        _ => None,
    }
}

/// The providers-catalog override notice (1.6.0): `Some(msg)` when the `--providers` flag is set AND
/// config.yaml ALSO declares a DIFFERENT `providers_file:` — the flag wins, so name both. `None` when
/// the flag is absent, the config declared no `providers_file:`, or the two are equal. Pure for
/// unit-testing the "flag alone / matching values ⇒ no notice" rule.
pub(crate) fn providers_override_notice(
    flag: Option<&str>,
    providers_file: Option<&str>,
) -> Option<String> {
    match (flag, providers_file) {
        (Some(f), Some(pf)) if f != pf => Some(format!(
            "providers catalog: using --providers '{f}' (overrides providers_file: '{pf}' from config.yaml)"
        )),
        _ => None,
    }
}

/// `--generate-signing-key`: mint a fresh ed25519 signing secret from the OS RNG and PRINT it (as 64
/// hex chars) plus a paste-ready `auth.signing_key` snippet + a fleet note. ZERO side effects - like
/// `--validate`/`--migrate-config`, it writes nothing; the operator PLACES the key (busbar never
/// edits their config). Exit 0 on success, 1 if the OS entropy source is unavailable.
fn generate_signing_key_command() -> i32 {
    // The mint lives behind `busbar_kernel::boot`: the CLI needs a hex string, not a `TokenSigner`,
    // so the signer type and its default kid stay crate-private in core.
    let hex = match busbar_kernel::boot::generate_signing_key_hex() {
        Ok(h) => h,
        Err(e) => {
            eprintln!(
                "busbar: {}: could not generate a signing key: {e}",
                busbar_substrate_values::diagnostics::SIGNING_KEY_GENERATION_FAILED.banner()
            );
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
pub(crate) fn signing_key_command_output(hex: &str) -> (String, String) {
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
