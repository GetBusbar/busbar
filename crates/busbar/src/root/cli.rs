// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel::{config, config_validate, diagnostics};
use busbar_kernel::{load_config_from_disk, DEFAULT_CONFIG_PATH, ENV_CONFIG, ENV_PROVIDERS};

use crate::{build_info_line, safe_mode_requested};

const EXIT_SUCCESS: i32 = 0;
const EXIT_FAILURE: i32 = 1;
const EXIT_USAGE: i32 = 2;

const OPTION_VERSION: &str = "--version";
const OPTION_VERSION_SHORT: &str = "-V";
const OPTION_BUILD_INFO: &str = "--build-info";
const OPTION_METADATA_BLOCKLIST: &str = "--print-metadata-blocklist";
const OPTION_VALIDATE: &str = "--validate";
const OPTION_GENERATE_SIGNING_KEY: &str = "--generate-signing-key";
const OPTION_LIST_PLUGINS: &str = "--list-plugins";
const OPTION_MIGRATE_CONFIG: &str = "--migrate-config";
const OPTION_HELP: &str = "--help";
const OPTION_HELP_SHORT: &str = "-h";
const OPTION_CONFIG: &str = "--config";
const OPTION_CONFIG_SHORT: &str = "-c";
pub(super) const OPTION_PROVIDERS: &str = "--providers";
const OPTION_CONFIG_ASSIGNMENT: &str = "--config=";
const OPTION_PROVIDERS_ASSIGNMENT: &str = "--providers=";

const HELP_HEAD: &str = "

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
";

const HELP_ENDPOINTS_HEAD: &str = "
ENDPOINTS (once running, listen address from config.yaml `listen`):
";

const HELP_TAIL: &str = "    GET  /stats  /healthz  /metrics

Docs: https://getbusbar.com   ·   Source: https://github.com/GetBusbar/busbar\n";

pub(crate) fn render_help(ver: &str, planes: &[&[super::linked::CliHelpRow]]) -> String {
    let rows = || planes.iter().flat_map(|rows| rows.iter());
    let mut out = format!("busbar {ver}");
    if let Some((_, tagline)) = rows().find(|(slot, _)| *slot == "tagline") {
        out.push_str(" — ");
        out.push_str(tagline);
    }
    out.push_str(HELP_HEAD);
    for (_, lines) in rows().filter(|(slot, _)| *slot == "flag") {
        out.push_str(lines);
        out.push('\n');
    }
    out.push_str(HELP_ENDPOINTS_HEAD);
    for (_, lines) in rows().filter(|(slot, _)| *slot == "endpoint") {
        out.push_str(lines);
        out.push('\n');
    }
    out.push_str(HELP_TAIL);
    out
}

pub(crate) fn help_rows() -> Vec<&'static [super::linked::CliHelpRow]> {
    static DOOR_ROWS: std::sync::OnceLock<Vec<Vec<super::linked::CliHelpRow>>> =
        std::sync::OnceLock::new();
    let door_rows = DOOR_ROWS.get_or_init(|| {
        crate::LINKED
            .plane_doors
            .iter()
            .filter_map(|door| {
                match crate::root::loader::dispatch::kinds::plane::linked_cli_help(*door) {
                    Ok(Some(text)) => {
                        Some(busbar_contract::abi::plane::cli_help::rows(text).collect())
                    }
                    _ => None,
                }
            })
            .collect()
    });
    let mut rows: Vec<&'static [super::linked::CliHelpRow]> = crate::LINKED.cli_help.to_vec();
    rows.extend(door_rows.iter().map(Vec::as_slice));
    rows.extend(dropped_rows().iter().map(Vec::as_slice));
    rows
}

fn dropped_rows() -> &'static [Vec<super::linked::CliHelpRow>] {
    static TEXTS: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    static ROWS: std::sync::OnceLock<Vec<Vec<super::linked::CliHelpRow>>> =
        std::sync::OnceLock::new();
    let Some(candidates) = crate::root::boot::DOOR_CANDIDATES.get() else {
        return &[];
    };
    let texts = TEXTS.get_or_init(|| dropped_help(candidates));
    ROWS.get_or_init(|| {
        texts
            .iter()
            .map(|text| busbar_contract::abi::plane::cli_help::rows(text).collect())
            .collect()
    })
}

pub(crate) fn dropped_help(candidates: &[crate::root::loader::boot::Candidate]) -> Vec<String> {
    use crate::root::loader::boot::Origin;
    use crate::root::loader::dispatch::kinds::plane::rendered_cli_help;
    candidates
        .iter()
        .filter(|c| matches!(c.origin, Origin::Dropped { .. }))
        .filter_map(|c| rendered_cli_help(&c.stated).ok().flatten())
        .collect()
}

pub(crate) fn is_plane_flag(planes: &[&[super::linked::CliHelpRow]], arg: &str) -> bool {
    planes
        .iter()
        .flat_map(|rows| rows.iter())
        .filter(|(slot, _)| *slot == "flag")
        .any(|(_, lines)| lines.split_whitespace().next() == Some(arg))
}

pub(crate) fn handle_cli_flags() -> Option<i32> {
    let supplied: Vec<String> = std::env::args().skip(1).collect();
    let mut values = supplied.iter();
    while let Some(arg) = values.next() {
        if arg == OPTION_MIGRATE_CONFIG {
            values.next();
            continue;
        }
        if matches!(
            arg.as_str(),
            OPTION_CONFIG | OPTION_CONFIG_SHORT | OPTION_PROVIDERS
        ) && values.next().is_none()
        {
            eprintln!("busbar: {arg} requires a value. Try 'busbar --help'.");
            return Some(EXIT_USAGE);
        }
    }
    let mut args = supplied.into_iter();

    let command = loop {
        let arg = args.next();
        match arg.as_deref() {
            Some(OPTION_CONFIG | OPTION_CONFIG_SHORT | OPTION_PROVIDERS) => {
                args.next();
            }
            Some(crate::OPTION_SAFE_MODE) => {}
            Some(a)
                if a.starts_with(OPTION_CONFIG_ASSIGNMENT)
                    || a.starts_with(OPTION_PROVIDERS_ASSIGNMENT) => {}
            _ => break arg,
        }
    };
    match command.as_deref() {
        None => None,
        Some(OPTION_VERSION | OPTION_VERSION_SHORT) => {
            println!("busbar {}", env!("CARGO_PKG_VERSION"));
            println!("build: {}", build_info_line());
            Some(EXIT_SUCCESS)
        }
        Some(OPTION_BUILD_INFO) => {
            println!("{}", build_info_line());
            Some(EXIT_SUCCESS)
        }
        Some(OPTION_METADATA_BLOCKLIST) => {
            let mut entries = config_validate::metadata_enforced_entries();
            let config_path = resolve_config_path(config_path_flag().as_deref());
            if let Ok(raw) = std::fs::read_to_string(&config_path) {
                match config::interpolate_env(&raw) {
                    Ok(interpolated) => match config::deploy_from_yaml_str(&interpolated) {
                        Ok(deploy) => {
                            if let Some(sec) = deploy.security {
                                entries.extend(sec.blocked_metadata_hosts);
                            }
                        }
                        Err(_) => {
                            eprintln!(
                                "warning: {code}: config at {config_path} did not parse; printing the \
                                 built-in metadata denylist only (security.blocked_metadata_hosts \
                                 skipped). Run busbar normally to see the parse error.",
                                code = diagnostics::CLI_METADATA_BLOCKLIST_CONFIG_UNREADABLE.banner()
                            );
                        }
                    },
                    Err(_) => {
                        eprintln!(
                            "warning: {code}: config at {config_path} failed to interpolate; printing \
                             the built-in metadata denylist only (security.blocked_metadata_hosts \
                             skipped). Run busbar normally to see the interpolation error.",
                            code = diagnostics::CLI_METADATA_BLOCKLIST_CONFIG_UNREADABLE.banner()
                        );
                    }
                }
            }
            for entry in entries {
                println!("{entry}");
            }
            Some(EXIT_SUCCESS)
        }

        Some(arg) if is_plane_flag(&help_rows(), arg) => None,
        Some(OPTION_VALIDATE) => Some(validate_config_command()),
        Some(OPTION_GENERATE_SIGNING_KEY) => Some(generate_signing_key_command()),
        Some(OPTION_LIST_PLUGINS) => Some(list_plugins_command()),
        Some(OPTION_MIGRATE_CONFIG) => Some(migrate_config_command(args.next())),
        Some(OPTION_HELP | OPTION_HELP_SHORT) => {
            print!("{}", render_help(env!("CARGO_PKG_VERSION"), &help_rows()));
            Some(EXIT_SUCCESS)
        }
        Some(other) => {
            eprintln!("busbar: unrecognized argument '{other}'. Try 'busbar --help'.");
            Some(EXIT_USAGE)
        }
    }
}

pub(crate) fn validate_config_command() -> i32 {
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
                diagnostics::CLI_VALIDATE_CONFIG_INVALID.banner()
            );
            return EXIT_FAILURE;
        }
    };
    let providers_path = loaded.providers_path.clone();
    let unset_env_vars = loaded.unset_env_vars.clone();

    if let Some(doc) = loaded.overlay_doc.as_ref() {
        config::overlay::apply_root_to_deploy(&mut loaded.deploy, doc);
    }
    let mut cfg = match config::resolve(&loaded.deploy, &loaded.defs) {
        Ok(c) => c,
        Err(errs) => {
            eprintln!(
                "[error] {}: config errors:\n  - {}",
                diagnostics::CLI_VALIDATE_CONFIG_INVALID.banner(),
                errs.join("\n  - ")
            );
            return EXIT_FAILURE;
        }
    };

    if let Some(doc) = loaded.overlay_doc.take() {
        config::overlay::merge_into(&mut cfg, doc);
    }

    let destination_guard =
        |c: &config::RootCfg| crate::root::connector::guard_for(&c.destinations()).map(|_| ());
    let registry = match config_validate::check(
        &cfg,
        config_validate::Check {
            plugins: &loaded.deploy.plugins,
            unset_env_vars: &unset_env_vars,
            root: &destination_guard,
            fetch: None,
            resolve_builtins: true,
        },
    ) {
        Ok(r) => r,
        Err(config_validate::Refusal::Config(errs)) => {
            eprintln!(
                "[error] {}: config validation failed:\n  - {}",
                diagnostics::CLI_VALIDATE_CONFIG_INVALID.banner(),
                errs.join("\n  - ")
            );
            return EXIT_FAILURE;
        }
        Err(config_validate::Refusal::Root(e)) => {
            eprintln!(
                "[error] {}: config validation failed:\n  - {e}",
                diagnostics::CLI_VALIDATE_CONFIG_INVALID.banner()
            );
            return EXIT_FAILURE;
        }
        Err(config_validate::Refusal::Plugins(e)) => {
            eprintln!(
                "[error] {}: {e}",
                diagnostics::CLI_VALIDATE_PLUGIN_PREFLIGHT_FAILED.banner()
            );
            return EXIT_FAILURE;
        }
        Err(config_validate::Refusal::Unresolved(e)) => {
            eprintln!(
                "[error] {}: {e}",
                diagnostics::CLI_VALIDATE_CONFIG_INVALID.banner()
            );
            return EXIT_FAILURE;
        }
    };

    let Some(registry) = crate::root::loader::rows::registry_arc(registry) else {
        eprintln!(
            "[error] {}: the plugin rows are not this root's registry",
            diagnostics::CLI_VALIDATE_PLUGIN_PREFLIGHT_FAILED.banner()
        );
        return EXIT_FAILURE;
    };

    let root = crate::root::boot::RootListens {
        listen: &cfg.listen,
        admin_listen: &cfg.admin_listen,
    };
    let stages = match crate::root::boot::validate(&config_path, &registry, &root) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "[error] {}: {e}",
                diagnostics::CLI_VALIDATE_PLUGIN_PREFLIGHT_FAILED.banner()
            );
            return EXIT_FAILURE;
        }
    };
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
            // A copy of a plugin this build links, at its version, was validated too: the linked
            // row serves it under the one-version rule.
            registry.loadable().len() + registry.linked_copies().len(),
            registry.skipped().len(),
            loaded.deploy.plugins.dir,
        );
        for s in registry.skipped() {
            println!(
                "    skipped: {} ({}) — {}",
                s.manifest.name, s.file, s.reason
            );
        }

        for line in stages.lines() {
            tracing::debug!(target: "busbar::validate", "{}", line.trim_start());
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
    EXIT_SUCCESS
}

const LIST_PLUGINS_HEADER: &str = "FILE                               NAME                     ALIAS        KIND   VERSION   SIGNATURE                STATUS";

fn list_plugins_command() -> i32 {
    let providers_override = providers_override();
    let config_path = std::path::PathBuf::from(resolve_config_path(config_path_flag().as_deref()));

    let (plugins_cfg, store_ref) = match load_config_from_disk(
        &config_path,
        providers_override.as_deref(),
        false,
        config::EnvSubst::Lenient,
    ) {
        Ok(l) => {
            let store = l.deploy.store.as_ref().map(|g| g.module.clone());
            (l.deploy.plugins, store)
        }
        Err(e) => {
            eprintln!(
                "[warn] {}: config not readable ({e}); using the default plugins block",
                diagnostics::CLI_LIST_PLUGINS_CONFIG_UNREADABLE.banner()
            );
            (config::PluginsCfg::default(), None)
        }
    };
    plugins_cfg.warn_invalid_floors();
    let policy = match crate::root::boot::trust_policy(&plugins_cfg, env!("CARGO_PKG_VERSION")) {
        Ok(p) => p,
        Err(e) => {
            eprintln!(
                "[error] {}: plugins.trust is invalid: {e}",
                diagnostics::CLI_LIST_PLUGINS_TRUST_INVALID.banner()
            );
            return EXIT_FAILURE;
        }
    };
    let dir = std::path::PathBuf::from(&plugins_cfg.dir);
    println!(
        "plugins dir: {} (plugins.enabled: {})",
        dir.display(),
        plugins_cfg.enabled
    );
    let rows = crate::root::loader::inventory_tarballs(&dir, &policy);
    if rows.is_empty() {
        println!("no plugin tarballs found");
        return EXIT_SUCCESS;
    }
    println!("{LIST_PLUGINS_HEADER}");
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

        let selected = store_ref.as_deref().filter(|s| {
            plugins_cfg.enabled
                && row.status == "ready"
                && row.manifest.as_ref().is_some_and(|m| m.answers_to(s))
        });
        let status = if let Some(store_ref) = selected {
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
    EXIT_SUCCESS
}

fn migrate_config_command(path: Option<String>) -> i32 {
    let Some(path) = path else {
        eprintln!(
            "busbar: --migrate-config requires a path: busbar --migrate-config <old-config.yaml>"
        );
        return EXIT_USAGE;
    };
    let raw = match std::fs::read_to_string(&path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("busbar: cannot read '{path}': {e}");
            return EXIT_FAILURE;
        }
    };

    let host =
        crate::root::config_migrate::RootHost::for_document(&raw, std::path::Path::new(&path));
    match config::migrate::migrate_config_with(&raw, &host) {
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
            EXIT_SUCCESS
        }
        Err(e) => {
            eprintln!("busbar: --migrate-config failed: {e}");
            EXIT_FAILURE
        }
    }
}

pub(crate) fn resolve_config_path(cli: Option<&str>) -> String {
    match cli {
        Some(p) => p.to_string(),
        None => std::env::var(ENV_CONFIG).unwrap_or_else(|_| DEFAULT_CONFIG_PATH.into()),
    }
}

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
        } else if matches!(
            a.as_str(),
            OPTION_MIGRATE_CONFIG | OPTION_CONFIG | OPTION_CONFIG_SHORT | OPTION_PROVIDERS
        ) {
            iter.next();
        }
    }
    result
}

pub(crate) fn config_path_flag() -> Option<String> {
    value_flag(
        std::env::args().skip(1),
        OPTION_CONFIG,
        Some(OPTION_CONFIG_SHORT),
    )
}

pub(crate) fn providers_override() -> Option<std::path::PathBuf> {
    value_flag(std::env::args().skip(1), OPTION_PROVIDERS, None)
        .map(std::path::PathBuf::from)
        .or_else(providers_override_from_env)
}

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

pub(crate) fn config_override_notice(flag: Option<&str>, env: Option<&str>) -> Option<String> {
    match (flag, env) {
        (Some(f), Some(e)) if f != e => Some(format!(
            "config: using --config '{f}' (overrides BUSBAR_CONFIG='{e}')"
        )),
        _ => None,
    }
}

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

fn generate_signing_key_command() -> i32 {
    let hex = match busbar_kernel::boot::generate_signing_key_hex() {
        Ok(h) => h,
        Err(e) => {
            eprintln!(
                "busbar: {}: could not generate a signing key: {e}",
                diagnostics::SIGNING_KEY_GENERATION_FAILED.banner()
            );
            return EXIT_FAILURE;
        }
    };
    let (secret_line, guidance) = signing_key_command_output(&hex);

    println!("{secret_line}");
    eprintln!("{guidance}");
    EXIT_SUCCESS
}

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

#[cfg(test)]
#[path = "tests/cli.rs"]
mod tests;
