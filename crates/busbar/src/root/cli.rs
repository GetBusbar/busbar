// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel::{config, config_validate, diagnostics};
use busbar_kernel::{load_config_from_disk, DEFAULT_CONFIG_PATH, ENV_CONFIG};

use crate::build_info_line;

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
const OPTION_HELP: &str = "--help";
const OPTION_HELP_SHORT: &str = "-h";
const OPTION_CONFIG: &str = "--config";
const OPTION_CONFIG_SHORT: &str = "-c";
const OPTION_PROVIDERS: &str = "--providers";
const PATH_VALUES: &str = "configuration path flags require explicit values";

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
                        (0 = offline checks passed, 1 = errors); no server or network;
                        no application Store opening or overlay recovery. Authorized native
                        grammar/check callbacks may run. Passing does not guarantee boot,
                        plugin readiness or backend reachability
    busbar --list-plugins
                        manifest-only inventory of the plugins dir (name/alias/kind/version,
                        signature verdict, load status + exact reason); never loads plugin code
    busbar --principal-transition <spec-or-plan.json>
           --transition-action inspect|prepare|check|apply|verify|initialize-fresh|
                               initialize-fresh-and-serve|reauthorize
           [--transition-attestation <attestation.json>]
                        principal maintenance using the configured Store.
                        inspect requires --principal-transition - (no input) and prints only
                        config, key, group, overlay and receipt hashes plus admitted auth bindings.
                        prepare reads a specification and prints a plan; initialize-fresh reads
                        a namespace creation receipt. apply requires a fresh cold attestation.
                        initialize-fresh-and-serve requires an explicit exclusive ephemeral-instance
                        creation receipt, initializes that opened Store, then runs ordinary boot.
                        All other actions exit after maintenance; initialize-fresh requires a
                        durable namespace witness and never authorizes an ephemeral instance.
                        reauthorize requires explicit evidence that a new artifact/settings
                        vector leaves all principal outputs unchanged; never infers issuer continuity.
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
    RUST_LOG            log level: error|warn|info|debug|trace  (default: info)

Flags:
    --ignore-overlay    boot on base config.yaml alone (the Store overlay is left untouched)
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

pub(crate) enum Parsed {
    Exit(i32),
    Serve,
}

/// The command line, read once by one lexopt parser. Every option takes its own value, so a value
/// spelled like a flag (`--config --providers`) is never read as one.
#[derive(Default)]
pub(crate) struct Argv {
    pub(crate) config: Option<String>,
    pub(crate) providers: Option<String>,
    pub(crate) ignore_overlay: bool,
    /// Every other argument, in order: the first one is the command.
    pub(crate) words: Vec<String>,
    /// The principal-transition values, in `principal_transition::FLAGS` order.
    pub(crate) transition: [Option<String>; 4],
    /// The first malformed option; nothing runs past it.
    pub(crate) refusal: Option<&'static str>,
}

impl Argv {
    pub(crate) fn parse(args: impl IntoIterator<Item = impl Into<std::ffi::OsString>>) -> Self {
        use super::principal_transition::{FLAGS, INPUT_FLAG};
        let mut parser = lexopt::Parser::from_args(args);
        let mut argv = Self::default();
        loop {
            // `--` and short clusters (`-cfoo`, `-c=x`, `-Vx`) stay whole words, as they always were.
            let whole = parser.try_raw_args().and_then(|mut raw| {
                raw.next_if(|arg| {
                    let arg = arg.as_encoded_bytes();
                    arg == b"--" || (arg.len() > 2 && arg[0] == b'-' && arg[1] != b'-')
                })
            });
            let name = match whole {
                Some(word) => word.to_string_lossy().into_owned(),
                None => match parser.next() {
                    Ok(Some(lexopt::Arg::Short(short))) => format!("-{short}"),
                    Ok(Some(lexopt::Arg::Long(long))) => format!("--{long}"),
                    Ok(Some(lexopt::Arg::Value(word))) => word.to_string_lossy().into_owned(),
                    _ => break,
                },
            };
            match (name.as_str(), FLAGS.iter().position(|flag| *flag == name)) {
                (_, Some(slot)) => {
                    let refusal = "principal transition flags require explicit values";
                    let value = argv.value(&mut parser, refusal, name == INPUT_FLAG);
                    if argv.transition[slot].replace(value).is_some() {
                        argv.refusal
                            .get_or_insert("duplicate principal transition flag");
                    }
                }
                (OPTION_CONFIG | OPTION_CONFIG_SHORT, _) => {
                    argv.config = Some(argv.value(&mut parser, PATH_VALUES, false));
                }
                (OPTION_PROVIDERS, _) => {
                    argv.providers = Some(argv.value(&mut parser, PATH_VALUES, false));
                }
                _ => match parser.optional_value() {
                    Some(value) => argv
                        .words
                        .push(format!("{name}={}", value.to_string_lossy())),
                    None if name == crate::OPTION_IGNORE_OVERLAY => argv.ignore_overlay = true,
                    None => {
                        if name.starts_with("-c=") {
                            argv.refusal
                                .get_or_insert("use -c <path> or --config=<path>");
                        }
                        argv.words.push(name);
                    }
                },
            }
        }
        argv
    }

    /// The option's value; a missing, empty, non-UTF-8 or flag-like one is refused.
    fn value(&mut self, parser: &mut lexopt::Parser, refusal: &'static str, dash: bool) -> String {
        let value = parser
            .value()
            .ok()
            .and_then(|value| value.into_string().ok());
        let value = value.unwrap_or_default();
        if value.is_empty() || (value.starts_with('-') && !(dash && value == "-")) {
            self.refusal.get_or_insert(refusal);
        }
        value
    }
}

/// This process's command line.
pub(crate) fn argv() -> &'static Argv {
    static ARGV: std::sync::OnceLock<Argv> = std::sync::OnceLock::new();
    ARGV.get_or_init(|| Argv::parse(std::env::args_os().skip(1)))
}

/// Explicit informational commands exit; ordinary startup owns data upgrades.
pub(crate) fn handle_cli_flags() -> Parsed {
    ordinary_cli_flags().map_or(Parsed::Serve, Parsed::Exit)
}

fn ordinary_cli_flags() -> Option<i32> {
    let argv = argv();
    // A maintenance mode owns the whole command line; boot runs it once the Store is open.
    let maintenance = super::principal_transition::command(argv).map(|command| command.is_some());
    match maintenance {
        Ok(true) => return None,
        Ok(false) => {}
        Err(error) => {
            eprintln!(
                "[error] {}",
                diagnostics::coded::cli_invalid_arguments(error)
            );
            return Some(EXIT_USAGE);
        }
    }
    const REMOVED_SAFE_MODE: &str = "--safe-mode";
    if argv.words.iter().any(|a| a == REMOVED_SAFE_MODE) {
        eprintln!("busbar: unrecognized argument '{REMOVED_SAFE_MODE}'. Try 'busbar --help'.");
        return Some(EXIT_USAGE);
    }
    match argv.words.first().map(String::as_str) {
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
            if let Some(refusal) = crate::root::boot::start_refusal() {
                eprintln!(
                    "[error] {}",
                    diagnostics::CLI_VALIDATE_CONFIG_INVALID.coded(refusal)
                );
                return Some(EXIT_FAILURE);
            }
            let mut entries = config_validate::metadata_enforced_entries();
            let config_path = resolve_config_path(argv.config.as_deref());
            if let Ok(raw) = std::fs::read_to_string(&config_path) {
                match config::interpolate_env(&raw) {
                    Ok(interpolated) => {
                        match crate::root::boot::start_grammar().and_then(|grammar| {
                            config::deploy_from_yaml_str(&interpolated, grammar)
                                .map_err(|e| e.to_string())
                        }) {
                            Ok(deploy) => {
                                if let Some(sec) = deploy.security {
                                    entries.extend(sec.blocked_metadata_hosts);
                                }
                            }
                            Err(_) => {
                                eprintln!(
                                    "warning: {}",
                                    diagnostics::CLI_METADATA_BLOCKLIST_CONFIG_UNREADABLE.coded(
                                        format_args!(
                                    "config at {config_path} did not parse; printing the built-in \
                                     metadata denylist only (security.blocked_metadata_hosts \
                                     skipped). Run busbar normally to see the parse error"
                                )
                                    )
                                );
                            }
                        }
                    }
                    Err(_) => {
                        eprintln!(
                            "warning: {}",
                            diagnostics::CLI_METADATA_BLOCKLIST_CONFIG_UNREADABLE.coded(
                                format_args!(
                                    "config at {config_path} failed to interpolate; printing the \
                                 built-in metadata denylist only (security.blocked_metadata_hosts \
                                 skipped). Run busbar normally to see the interpolation error"
                                )
                            )
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
        Some(OPTION_HELP | OPTION_HELP_SHORT) => {
            print!("{}", render_help(env!("CARGO_PKG_VERSION"), &help_rows()));
            Some(EXIT_SUCCESS)
        }
        Some(other) => {
            eprintln!(
                "[error] {}",
                diagnostics::coded::cli_unrecognized_argument(other)
            );
            Some(EXIT_USAGE)
        }
    }
}

/// A refusal that carries a list: the coded head line (`[error] BUSBAR-NNNN: <head>. See <link>`)
/// and one `  - <item>` line per error, each item already carrying its own code and link.
fn refusal_list(
    code: &busbar_contract::diagnostic::Diagnostic,
    head: &str,
    items: &[String],
) -> String {
    let mut out = format!("[error] {}", code.coded(head));
    for item in items {
        out.push_str("\n  - ");
        out.push_str(item);
    }
    out
}

/// What `--validate`'s offline judgement established about the authored (unmigrated) bytes.
pub(crate) struct Validated {
    pub cfg: config::RootCfg,
    /// The loaded documents; the overlay document has already been merged into `cfg`.
    pub loaded: busbar_kernel::LoadedConfig,
    /// `config_validate::check`'s registry.
    pub registry: std::sync::Arc<dyn busbar_contract::plugin_rows::PluginRows>,
}

/// Which step of `--validate`'s judgement refused, with the refusal it carried.
#[derive(Debug)]
pub(crate) enum ValidateRefusal {
    /// `load_config_from_disk` refused the files.
    Load(String),
    /// `config::resolve` refused the loaded documents.
    Resolve(Vec<String>),
    /// `config_validate::check` refused the resolved configuration.
    Check(config_validate::Refusal),
}

impl ValidateRefusal {
    /// The coded refusal `--validate` prints for this outcome.
    pub(crate) fn render(&self) -> String {
        match self {
            Self::Load(e) => format!(
                "[error] {}",
                diagnostics::CLI_VALIDATE_CONFIG_INVALID.coded(e)
            ),
            Self::Resolve(errs) => refusal_list(
                &diagnostics::CLI_VALIDATE_CONFIG_INVALID,
                "config errors",
                errs,
            ),
            Self::Check(config_validate::Refusal::Config(errs)) => refusal_list(
                &diagnostics::CLI_VALIDATE_CONFIG_INVALID,
                "config validation failed",
                errs,
            ),
            Self::Check(config_validate::Refusal::Root(e)) => refusal_list(
                &diagnostics::CLI_VALIDATE_CONFIG_INVALID,
                "config validation failed",
                std::slice::from_ref(e),
            ),
            Self::Check(config_validate::Refusal::Plugins(e)) => format!(
                "[error] {}",
                diagnostics::CLI_VALIDATE_PLUGIN_PREFLIGHT_FAILED.coded(e)
            ),
            Self::Check(config_validate::Refusal::Unresolved(e)) => format!(
                "[error] {}",
                diagnostics::CLI_VALIDATE_CONFIG_INVALID.coded(e)
            ),
        }
    }
}

/// `--validate`'s offline judgement of the authored bytes: load, overlay, resolve, overlay merge
/// and `config_validate::check`. Reads files only; never opens a Store or loads plugin code.
pub(crate) fn validate_judged(
    config_path: &std::path::Path,
    providers_override: Option<&std::path::Path>,
    ignore_overlay: bool,
) -> Result<Validated, ValidateRefusal> {
    if let Some(refusal) = crate::root::boot::start_refusal() {
        return Err(ValidateRefusal::Load(refusal));
    }
    let mut loaded = load_config_from_disk(
        config_path,
        providers_override,
        ignore_overlay,
        config::EnvSubst::Lenient,
    )
    .map_err(ValidateRefusal::Load)?;
    let unset_env_vars = loaded.unset_env_vars.clone();

    if let Some(doc) = loaded.overlay_doc.as_ref() {
        config::overlay::apply_root_to_deploy(&mut loaded.deploy, doc)
            .map_err(ValidateRefusal::Load)?;
    }
    let mut cfg =
        config::resolve(&loaded.deploy, &loaded.defs).map_err(ValidateRefusal::Resolve)?;

    if let Some(doc) = loaded.overlay_doc.take() {
        config::overlay::merge_into(&mut cfg, doc);
    }

    let destination_guard = |c: &config::RootCfg| {
        crate::root::connector::guard_for(&c.destinations())?;
        crate::root::connector::trust_store_of(&c.outbound_tls)
            .map(|_| ())
            .map_err(|errors| errors.join("\n  - "))
    };
    // The dropped-in secret modules start judged, checked through a read-scoped view: none of them
    // is admitted onto the live axis (SECRET-SHORTHAND-BOOT §3.6, B4).
    let view = crate::root::boot::start_secret_view();
    let registry = config_validate::check(
        &cfg,
        config_validate::Check {
            plugins: &loaded.deploy.plugins,
            unset_env_vars: &unset_env_vars,
            root: &destination_guard,
            fetch: None,
            resolve_builtins: true,
            secret_axis: Some(&view),
        },
    )
    .map_err(ValidateRefusal::Check)?;
    Ok(Validated {
        cfg,
        loaded,
        registry,
    })
}

pub(crate) fn validate_config_command() -> i32 {
    for w in crate::root::retired_env::ignored_launch_env(|n| std::env::var_os(n)) {
        eprintln!("{w}");
    }
    let argv = argv();
    let providers_override = argv.providers.as_deref().map(std::path::PathBuf::from);
    let config_path = std::path::PathBuf::from(resolve_config_path(argv.config.as_deref()));
    let ignore_overlay = argv.ignore_overlay;

    let Validated {
        cfg,
        loaded,
        registry,
    } = match validate_judged(&config_path, providers_override.as_deref(), ignore_overlay) {
        Ok(v) => v,
        Err(refusal) => {
            eprintln!("{}", refusal.render());
            return EXIT_FAILURE;
        }
    };
    let providers_path = loaded.providers_path.clone();
    let unset_env_vars = loaded.unset_env_vars.clone();

    let Some(registry) = crate::root::loader::rows::registry_arc(registry) else {
        eprintln!(
            "[error] {}",
            diagnostics::CLI_VALIDATE_PLUGIN_PREFLIGHT_FAILED
                .coded("the plugin rows are not this root's registry")
        );
        return EXIT_FAILURE;
    };

    let root = crate::root::boot::RootListens {
        listen: &cfg.listen,
        admin_listen: &cfg.admin_listen,
    };
    let stages = match crate::root::boot::validate(
        &config_path,
        &registry,
        &root,
        cfg.listen_explicit || cfg.tls.is_some(),
    ) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "[error] {}",
                diagnostics::CLI_VALIDATE_PLUGIN_PREFLIGHT_FAILED.coded(e)
            );
            return EXIT_FAILURE;
        }
    };
    // Validation runs before any log subscriber exists, so the unpriced-class advisory boot logs
    // would be lost; a valid config still reports it.
    for advisory in config_validate::rate_card_advisories(&cfg) {
        eprintln!(
            "[warn] {}: {advisory}",
            diagnostics::CONFIG_RATE_CARD_MISSING.banner()
        );
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

/// The plugins block and store reference `--list-plugins` inventories against.
///
/// A config file that exists but cannot be read, parsed or env-substituted is refused (BUSBAR-3016):
/// inventorying the default plugins dir would describe a directory the deployment does not use. The
/// default block applies only when there is no config file at the resolved path (a bare inventory).
fn list_plugins_config(
    config_path: &std::path::Path,
    providers: Option<&std::path::Path>,
) -> Result<(config::PluginsCfg, Option<String>), String> {
    if !config_path.exists() {
        eprintln!(
            "[info] no config file at {}; inventorying the default plugins block",
            config_path.display()
        );
        return Ok((config::PluginsCfg::default(), None));
    }
    // Report mode: the inventory never refuses for the grammar. A read whose phase 1 refuses (an
    // invalid archive, a conflict) is typed under the empty grammar, and the refusal is printed as
    // an inventory line ([`list_plugins_command`] prints the start refusal).
    let loaded = busbar_kernel::appbuild::read_config_documents(
        config_path,
        providers,
        false,
        config::EnvSubst::Lenient,
        &busbar_kernel::appbuild::AcceptAll,
        busbar_kernel::appbuild::DocumentPatchLoad {
            patch: None,
            providers_patch: None,
            admission: None,
        },
    )
    .and_then(|raw| {
        let grammar = raw.own_grammar().unwrap_or_else(|refusal| {
            println!("grammar: {refusal}");
            config::Grammar::empty()
        });
        raw.typed(&grammar)
    });
    match loaded {
        Ok(l) => {
            let store = l.deploy.store.as_ref().map(|g| g.module.clone());
            Ok((l.deploy.plugins, store))
        }
        Err(e) => Err(diagnostics::CLI_LIST_PLUGINS_CONFIG_UNREADABLE.coded(format_args!(
            "config {} exists but is not readable ({e}); refusing to inventory the default plugins block",
            config_path.display()
        ))
        .to_string()),
    }
}

fn list_plugins_command() -> i32 {
    let argv = argv();
    let config_path = std::path::PathBuf::from(resolve_config_path(argv.config.as_deref()));

    let (plugins_cfg, store_ref) = match list_plugins_config(
        &config_path,
        argv.providers.as_deref().map(std::path::Path::new),
    ) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[error] {e}");
            return EXIT_FAILURE;
        }
    };
    plugins_cfg.warn_invalid_floors();
    if let Some(refusal) = crate::root::boot::start_refusal() {
        println!("process start: {refusal}");
    }
    let policy = match crate::root::boot::trust_policy(&plugins_cfg, env!("CARGO_PKG_VERSION")) {
        Ok(p) => p,
        Err(e) => {
            eprintln!(
                "[error] {}",
                diagnostics::CLI_LIST_PLUGINS_TRUST_INVALID
                    .coded(format_args!("plugins.trust is invalid: {e}"))
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

pub(crate) fn resolve_config_path(cli: Option<&str>) -> String {
    match cli {
        Some(p) => p.to_string(),
        None => std::env::var(ENV_CONFIG).unwrap_or_else(|_| DEFAULT_CONFIG_PATH.into()),
    }
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
                "[error] {}",
                diagnostics::SIGNING_KEY_GENERATION_FAILED
                    .coded(format_args!("could not generate a signing key: {e}"))
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
