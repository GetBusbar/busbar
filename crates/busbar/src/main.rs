// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//
// busbar — the composition root binary. It is the one place that names every wire, every
// compiled-in plane, and every unit the kernel runs, and wires them together at boot; see
// `src/root/mod.rs` for the three-axis shape (wire / plane / unit) this crate composes.
//
// The protocol, routing, and plane-specific behavior this binary boots are each owned by their own
// crate (the engine core and the individual plane crates) and are not this file's concern — see the
// linked crates' own docs and the README for what a running deployment answers on the wire, and
// `root::cli` (what `busbar --help` renders) for the CLI surface this binary exposes.
//
// See `register_protocols`/`register_planes`/`register_diagnostics` below
// for the composition root's one write into each axis: each linked crate contributes its own
// declarations here, under its own Cargo feature, and nowhere else.

#![forbid(unsafe_code)]

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use std::sync::Arc;
use std::time::Duration;

use axum::Router;

use busbar_kernel::{config, config_validate, diagnostics, export, snapshot};
use busbar_kernel::{load_config_from_disk, LoadedConfig, ENV_CONFIG};

#[cfg(unix)]
use busbar_core_connector::listen::DEFAULT_HANDSHAKE_TIMEOUT;
use busbar_core_connector::listen::{AcceptLimits, Listening};

#[cfg(not(target_env = "msvc"))]
use busbar_kernel::REQUEST_ACTIVITY_TICKS;

pub(crate) fn build_info_line() -> String {
    format!(
        "profile={profile} opt-level={opt} lto={lto} debug-assertions={da} pgo={pgo} \
         target={target} target-cpu={cpu} target-features={features} \
         codegen-units={units} receipt={receipt} package={package} manifest={manifest} \
         source-commit={source} source-clean={clean}",
        profile = env!("BUSBAR_BUILD_PROFILE"),
        opt = env!("BUSBAR_BUILD_OPT_LEVEL"),
        lto = env!("BUSBAR_BUILD_LTO"),
        units = env!("BUSBAR_BUILD_CODEGEN_UNITS"),
        receipt = env!("BUSBAR_BUILD_RECEIPT"),
        package = env!("BUSBAR_BUILD_PACKAGE"),
        manifest = env!("BUSBAR_BUILD_MANIFEST"),
        source = env!("BUSBAR_BUILD_SOURCE_COMMIT"),
        clean = env!("BUSBAR_BUILD_SOURCE_CLEAN"),
        da = if cfg!(debug_assertions) {
            "true"
        } else {
            "false"
        },
        pgo = env!("BUSBAR_BUILD_PGO"),
        target = env!("BUSBAR_BUILD_TARGET"),
        cpu = env!("BUSBAR_BUILD_TARGET_CPU"),
        // `+lse` on the default arm64 Linux release (armv8.1 ISA floor), `default` everywhere
        // else — including the armv8.0-compatible arm64 variant, which is exactly how the two
        // arm64 artifacts identify themselves from the binary alone (see build.rs).
        features = env!("BUSBAR_BUILD_TARGET_FEATURES"),
    )
}

fn die(msg: impl std::fmt::Display) -> ! {
    eprintln!("[error] {}: {msg}", diagnostics::BOOT_FATAL_ERROR.banner());
    std::process::exit(1);
}

const OPTION_SAFE_MODE: &str = "--safe-mode";

fn safe_mode_requested(mut args: impl Iterator<Item = String>) -> bool {
    args.any(|a| a == OPTION_SAFE_MODE)
}

fn line_flag_passed(args: impl Iterator<Item = String>) -> bool {
    line_serve_requested(&root::cli::help_rows(), args)
}

fn line_serve_requested(
    planes: &[&[root::linked::CliHelpRow]],
    mut args: impl Iterator<Item = String>,
) -> bool {
    args.any(|a| root::cli::is_plane_flag(planes, &a))
}

const MAX_WORKER_THREADS: usize = 128;

#[cfg(test)]
fn worker_threads_from_env(name: &str) -> Option<usize> {
    let mut warnings = Vec::new();
    let n = worker_threads_from_env_noting(name, &mut warnings);
    warnings.iter().for_each(|w| eprintln!("{w}"));
    n
}

fn worker_threads_from_env_noting(name: &str, warnings: &mut Vec<String>) -> Option<usize> {
    match std::env::var(name) {
        Ok(v) => match v.trim().parse::<usize>() {
            Ok(n) if n >= 1 => Some(n),
            _ => {
                warnings.push(format!(
                    "[warn] {code}: {name}={v:?} is not a positive integer; ignoring it and using \
                     the default worker-thread count",
                    code = diagnostics::WORKER_THREADS_INVALID.banner()
                ));
                None
            }
        },
        Err(_) => None,
    }
}

#[cfg(test)]
fn worker_threads_from_config() -> Option<usize> {
    let mut warnings = Vec::new();
    let n = worker_threads_from_config_noting(&mut warnings);
    warnings.iter().for_each(|w| eprintln!("{w}"));
    n
}

fn worker_threads_from_config_noting(warnings: &mut Vec<String>) -> Option<usize> {
    let config_path = root::cli::resolve_config_path(root::cli::config_path_flag().as_deref());
    let raw = std::fs::read_to_string(&config_path).ok()?;
    let mut unset = Vec::new();
    let interpolated =
        config::interpolate_env_with(&raw, config::EnvSubst::Lenient, &mut unset).ok()?;

    let doc: serde_yaml::Value = serde_yaml::from_str(&interpolated).ok()?;
    let worker_threads = match doc.get("advanced").and_then(|a| a.get("worker_threads")) {
        None | Some(serde_yaml::Value::Null) => None,
        Some(v) => Some(usize::try_from(v.as_u64()?).ok()?),
    };
    match validate_worker_threads_config(worker_threads) {
        Ok(v) => v,
        Err(msg) => {
            warnings.push(format!(
                "[warn] {}: {msg}",
                diagnostics::WORKER_THREADS_INVALID.banner()
            ));
            None
        }
    }
}

fn resolve_worker_threads() -> (usize, Vec<String>) {
    let mut warnings = Vec::new();
    let n = worker_threads_from_env_noting("BUSBAR_WORKER_THREADS", &mut warnings)
        .inspect(|_| {
            warnings.push(
                "[warn] BUSBAR_WORKER_THREADS is DEPRECATED; set `advanced.worker_threads` in \
                 config.yaml instead (it is honored for now)."
                    .to_string(),
            )
        })
        .or_else(|| worker_threads_from_config_noting(&mut warnings))
        .or_else(|| worker_threads_from_env_noting("TOKIO_WORKER_THREADS", &mut warnings))
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
        })
        .min(MAX_WORKER_THREADS);
    (n, warnings)
}

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

include!(concat!(env!("OUT_DIR"), "/linked.rs"));

include!(concat!(env!("OUT_DIR"), "/linked_hook_names.rs"));

fn register_protocols() {
    root::linked::register_protocols(&LINKED, ROOT_UNITS);
}

fn register_planes() {
    root::migration_table::install();

    root::linked::register_stores(&LINKED);
    busbar_kernel::preflight::install_linked_auth(
        LINKED.auths,
        root::auth_bindings::operator_words(),
    );

    let dropped = root::boot::dropped_from_config(&LINKED);

    busbar_kernel::preflight::install_declared_styles(root::door_steps::declared_styles());
    root::boot::discover_planes(&LINKED, dropped);
    root::linked::register_planes();
    root::linked::register_exports(dropped);

    root::settings_public::install(&LINKED, dropped);

    busbar_core_oauth2::install::<root::connector::AuthServerConns>();

    busbar_core_admin::install();

    root::linked::seal(ROOT_UNITS);
}

fn register_diagnostics() -> busbar_kernel::diagnostics::Catalogue {
    root::linked::register_diagnostics(&LINKED)
}

static WORKERS: std::sync::LazyLock<(usize, Vec<String>)> =
    std::sync::LazyLock::new(resolve_worker_threads);

fn main() {
    if let Err(e) = busbar_kernel::observability::init_log_bridge() {
        eprintln!("busbar: the `log` bridge is not installed: {e}");
    }

    let late_services = root::serve::LateServices::new();
    root::boot::install_native_load_guard().unwrap_or_else(|error| die(error));

    if let Err(e) = root::loader::dispatch::handle::arm() {
        eprintln!("busbar: {e}");
        std::process::exit(1);
    }
    let dispatcher = root::dispatch::boot(WORKERS.0, &late_services);
    root::doors::install_dispatcher(dispatcher);

    register_protocols();

    register_planes();

    root::doors::install_plugin_logs(root::boot::plugin_logs());

    let catalogue = register_diagnostics();

    if let Some(code) = root::cli::handle_cli_flags() {
        std::process::exit(code);
    }

    #[cfg(not(target_env = "msvc"))]
    {
        use tikv_jemalloc_ctl::background_thread;
        let enabled = match background_thread::write(true).and_then(|()| background_thread::read())
        {
            Ok(true) => true,
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

        if !enabled {
            spawn_jemalloc_idle_purge_fallback();
        }
    }

    if busbar_kernel::profile::enabled() {
        std::thread::spawn(|| loop {
            std::thread::sleep(std::time::Duration::from_secs(20));
            busbar_kernel::profile::dump();
        });
    }

    let (worker_threads, warnings) = &*WORKERS;
    for w in warnings {
        eprintln!("{w}");
    }
    let worker_threads = *worker_threads;

    busbar_kernel::topology::set_data_workers(worker_threads);
    let control_work = ControlWork::new();
    control_work.register();
    #[cfg(unix)]
    {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build the tokio control runtime")
            .block_on(run(worker_threads, late_services, catalogue, control_work));
    }
    #[cfg(not(unix))]
    {
        let worker_work = control_work.clone();
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(worker_threads)
            .on_thread_start(move || worker_work.register())
            .enable_all()
            .build()
            .expect("failed to build the tokio runtime")
            .block_on(run(worker_threads, late_services, catalogue, control_work));
    }
}

/// The control listener, line carrier and callbacks use the same detached custody as data workers.
#[derive(Clone)]
struct ControlWork {
    detached: Arc<busbar_kernel::detached::DetachedTasks>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
}

impl ControlWork {
    fn new() -> Self {
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        Self {
            detached: busbar_kernel::detached::DetachedTasks::new(),
            shutdown_tx,
            shutdown_rx,
        }
    }

    fn register(&self) {
        busbar_kernel::detached::set_worker_detached(Arc::clone(&self.detached));
        busbar_kernel::detached::set_worker_shutdown(self.shutdown_rx.clone());
    }

    async fn drain(&self) {
        let _ = self.shutdown_tx.send(true);
        let _ = tokio::time::timeout(
            busbar_kernel::detached::DETACHED_DRAIN_GRACE,
            self.detached.drained(),
        )
        .await;
    }
}

struct BootstrapDestJudge(std::sync::RwLock<Arc<dyn busbar_kernel::host_services::DestJudge>>);

impl BootstrapDestJudge {
    fn new(judge: Arc<dyn busbar_kernel::host_services::DestJudge>) -> Arc<Self> {
        Arc::new(Self(std::sync::RwLock::new(judge)))
    }
    fn snapshot(&self) -> Arc<dyn busbar_kernel::host_services::DestJudge> {
        self.0.read().unwrap_or_else(|p| p.into_inner()).clone()
    }
    fn replace(&self, judge: Arc<dyn busbar_kernel::host_services::DestJudge>) {
        let old = {
            let mut held = self.0.write().unwrap_or_else(|p| p.into_inner());
            std::mem::replace(&mut *held, judge)
        };
        drop(old);
    }
}

impl busbar_kernel::host_services::DestJudge for BootstrapDestJudge {
    fn judge_name(&self, dest: &str, class: u32, refuse_private: bool) -> Result<(), u64> {
        self.snapshot().judge_name(dest, class, refuse_private)
    }
    fn judge(
        &self,
        dest: &str,
        class: u32,
        refuse_private: bool,
        done: Box<dyn FnOnce(busbar_kernel::host_services::Admitted) + Send>,
    ) -> Option<busbar_kernel::host_services::Admitted> {
        self.snapshot().judge(dest, class, refuse_private, done)
    }
    fn judge_reaching(
        &self,
        dest: &str,
        class: u32,
        done: Box<dyn FnOnce(busbar_kernel::host_services::Admitted) + Send>,
    ) -> Option<busbar_kernel::host_services::Admitted> {
        self.snapshot().judge_reaching(dest, class, done)
    }
    fn judge_answer(
        &self,
        host: &str,
        addrs: &[std::net::IpAddr],
        class: u32,
    ) -> Result<(), busbar_kernel::host_services::DestRefusal> {
        self.snapshot().judge_answer(host, addrs, class)
    }
    fn judge_host(
        &self,
        host: &str,
        class: u32,
    ) -> Result<(), busbar_kernel::host_services::DestRefusal> {
        self.snapshot().judge_host(host, class)
    }
    fn destinations_applied(&self, destinations: &config::Destinations) {
        self.snapshot().destinations_applied(destinations);
    }
}

#[cfg(test)]
mod bootstrap_destination_tests {
    use super::*;
    use busbar_kernel::host_services::DestJudge as _;

    #[test]
    fn the_installed_bootstrap_seam_receives_the_complete_recovered_security_policy() {
        let policy = |block_private_addresses| config::Destinations {
            block_private_addresses,
            allow: Vec::new(),
            legacy_allow: Vec::new(),
            url_allow: Vec::new(),
            blocked: Vec::new(),
            allow_all_metadata: false,
        };
        let holder = BootstrapDestJudge::new(root::connector::guard_for(&policy(false)).unwrap());
        let installed: Arc<dyn busbar_kernel::host_services::DestJudge> = holder.clone();
        let class = busbar_contract::abi::host::conn::connector::EGRESS_PROVIDER;
        assert!(installed
            .judge_name("https://10.2.3.4", class, false)
            .is_ok());
        holder.replace(root::connector::guard_for(&policy(true)).unwrap());
        assert!(installed
            .judge_name("https://10.2.3.4", class, false)
            .is_err());
        assert!(holder.judge_name("https://10.2.3.4", class, false).is_err());
    }
}

async fn run(
    data_workers: usize,
    late_services: std::sync::Arc<root::serve::LateServices>,
    catalogue: busbar_kernel::diagnostics::Catalogue,
    control_work: ControlWork,
) {
    root::observe::install(catalogue);

    let cli_config = root::cli::config_path_flag();

    if let Some(notice) = root::cli::config_override_notice(
        cli_config.as_deref(),
        std::env::var(ENV_CONFIG).ok().as_deref(),
    ) {
        eprintln!("[info] {notice}");
    }
    let providers_override = root::cli::providers_override();
    let config_path =
        std::path::PathBuf::from(root::cli::resolve_config_path(cli_config.as_deref()));
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
        overlay_path: _,
        config_locked,
        config_read_only: _,
        overlay_doc: _,
        unset_env_vars: _,
    } = loaded;

    let base_cfg = config::resolve(&deploy, &defs)
        .unwrap_or_else(|errors| die(format!("base config errors: {}", errors.join("; "))));
    config_validate::validate(&base_cfg)
        .unwrap_or_else(|errors| die(format!("base config errors: {}", errors.join("; "))));
    let base_store_settings = serde_json::to_value(&base_cfg.store)
        .unwrap_or_else(|error| die(format!("base Store settings: {error}")));
    let dest = BootstrapDestJudge::new(root::connector::dest_judge(&base_cfg));
    let commit_guard: Arc<dyn busbar_kernel::host_services::DestJudge> = dest.clone();
    let (credentials, credential_handle) = root::credentials::AppCredentials::late();
    root::serve::compose(dest.clone(), &late_services, credentials);
    root::boot::note_provider_urls(
        base_cfg
            .providers
            .values()
            .map(|provider| provider.base_url.clone()),
    );
    root::boot::check_bootstrap_transports(&deploy.plugins)
        .unwrap_or_else(|error| die(format!("bootstrap transport archive admission: {error}")));
    let _connector = root::connector::boot(
        LINKED_TRANSPORT_DOORS,
        &root::policy::client_settings(&base_cfg.limits),
        dest.clone(),
        &[base_cfg.listen.as_str(), base_cfg.admin_listen.as_str()],
    );
    let anchor_store = busbar_kernel::appbuild::bootstrap_config_store(&base_cfg, &deploy.plugins)
        .unwrap_or_else(|error| die(format!("base Store overlay anchor: {error}")));
    let floor_calls = anchor_store
        .calls
        .as_ref()
        .cloned()
        .unwrap_or_else(|| die("base Store has no typed plugin-floor calls"));
    root::boot::bind_plugin_floor(floor_calls)
        .unwrap_or_else(|error| die(format!("Store plugin-floor authority: {error}")));
    let overlay_path = if config_locked {
        None
    } else {
        let calls = anchor_store
            .calls
            .as_ref()
            .cloned()
            .unwrap_or_else(|| die("base Store has no typed config-overlay calls"));
        Some(config::overlay::OverlayStore::new(calls).unwrap_or_else(|error| die(error)))
    };
    let overlay_doc = if safe_mode {
        None
    } else {
        overlay_path
            .as_ref()
            .map(|store| store.read_required())
            .transpose()
            .unwrap_or_else(|error| die(format!("Store config overlay recovery refused: {error}")))
            .flatten()
    };

    if let Some(notice) = root::cli::providers_override_notice(
        root::cli::value_flag(std::env::args().skip(1), "--providers", None).as_deref(),
        deploy.providers_file(),
    ) {
        eprintln!("[info] {notice}");
    }

    if let Some(doc) = overlay_doc.as_ref() {
        config::overlay::apply_root_to_deploy(&mut deploy, doc);
    }

    let response_headers_cfg = deploy.advanced.response_headers.clone();

    busbar_kernel::plane_driver::configure_route_policy_headers(response_headers_cfg.route_policy);

    let resolved_export = config::resolve_export(&deploy.export, &mut Vec::new());
    snapshot::configure(
        resolved_export
            .recorder
            .as_ref()
            .map(|p| Duration::from_secs(p.buffer_seconds)),
    );

    let plugins_cfg = deploy.plugins.clone();
    root::boot::admit_recovered_plugins(&plugins_cfg)
        .unwrap_or_else(|error| die(format!("Store plugin-floor admission: {error}")));

    let swept = root::loader::sweep_dead_staging();
    if swept > 0 {
        eprintln!(
            "[info] removed {swept} orphaned plugin staging dir(s) left by a crashed prior run"
        );
    }

    if let Err(e) = busbar_kernel::observability::init_logging(line_flag_passed(std::env::args())) {
        eprintln!("busbar: tracing subscriber already initialized: {e}");
    }

    tracing::info!(version = env!("CARGO_PKG_VERSION"), "busbar starting");

    if config_locked {
        tracing::info!(
            "config is LOCKED (config.locked: true): admin-API config mutations are refused; edit \
             config.yaml and POST /config/reload to change config"
        );
    } else if let Some(p) = overlay_path.as_ref() {
        tracing::info!(
            overlay = %p.display(),
            "config is mutable; admin-API changes persist to the configured Store (restart durability follows that Store)"
        );
    }

    busbar_core_admin::mark_start();

    let mut cfg = config::resolve(&deploy, &defs)
        .unwrap_or_else(|errs| die(format!("config errors:\n  - {}", errs.join("\n  - "))));

    dest.replace(root::connector::dest_judge(&cfg));
    root::boot::note_provider_urls(
        cfg.providers
            .values()
            .map(|provider| provider.base_url.clone()),
    );
    root::connector::finalize_boot(
        &root::policy::client_settings(&cfg.limits),
        &[cfg.listen.as_str(), cfg.admin_listen.as_str()],
    )
    .unwrap_or_else(|error| die(format!("effective connector boot configuration: {error}")));

    let base_hook_names: std::collections::HashSet<String> = cfg.hooks.keys().cloned().collect();
    let base_group_names: std::collections::HashSet<String> = cfg.groups.keys().cloned().collect();

    if let Some(doc) = overlay_doc {
        config::overlay::merge_into(&mut cfg, doc);
    }

    if cfg.allow_all_metadata {
        tracing::warn!(
            diag = %diagnostics::METADATA_PROTECTION_DISABLED.banner(),
            "metadata protection DISABLED — all cloud-metadata endpoints reachable"
        );
    } else {
        let blocked =
            config_validate::metadata_denylist_entries().len() + cfg.blocked_metadata_hosts.len();
        tracing::info!(
            "metadata protection: {blocked} hosts blocked (--print-metadata-blocklist to view)"
        );
    }

    let listen = cfg.listen.clone();
    let tls_cfg = cfg.tls.clone();

    let admin_listen = cfg.admin_listen.clone();
    let admin_tls_cfg = cfg.admin_tls.clone();
    let req_body_max = cfg.limits.request_body_max_bytes;
    let max_inbound = cfg.limits.max_inbound_concurrent;

    let _sealed = root::registry::seal_or_exit(&LINKED, root::policy::client_settings(&cfg.limits));

    let dropped_doors =
        root::boot::dropped_transports(&root::policy::client_settings(&cfg.limits)).doors;

    root::boot::load_door_planes(
        deploy
            .door_sections()
            .keys()
            .chain(root::door_steps::kernel_sections(&cfg).keys())
            .copied(),
    );

    export::plugin::open(&cfg.export).unwrap_or_else(|e| die(format!("config errors:\n  - {e}")));

    for step in ROOT_UNITS.iter().filter_map(|u| u.on_config) {
        step(&cfg.limits);
    }

    let composes: Vec<root::linked::Compose> = LINKED
        .compose
        .iter()
        .filter_map(|capture| capture(&cfg))
        .collect();

    let door_providers = root::door_steps::provider_routes(
        &cfg.providers,
        &config_validate::MetadataPosture::global(&cfg),
    );

    let door_kernel_sections = root::door_steps::kernel_sections(&cfg);

    let door_model_pools = root::model_egress::ModelPools::of(&cfg);

    let door_pools = root::serve::door_pools(&cfg.plane_pools);

    let root_rules = Arc::new(root::door_steps::Rules::hearing(commit_guard));

    root_rules.hold_unloaded(root::door_steps::unloaded_doors());
    let listener_plan = Arc::new(root::serve::ListenerPlan::new(
        root::door_steps::listener_needs(&cfg).unwrap_or_else(|e| die(e)),
        root::serve::transport_offers(LINKED.transports, &dropped_doors),
        &|scheme| root::connector::the().framer_for(scheme),
    ));
    root_rules
        .hold_listeners(Arc::clone(&listener_plan))
        .unwrap_or_else(|e| die(e));

    let store_module = cfg
        .store
        .as_ref()
        .map_or_else(String::new, |store| store.module.clone());
    let boot_store = if serde_json::to_value(&cfg.store)
        .unwrap_or_else(|error| die(format!("effective Store settings: {error}")))
        == base_store_settings
    {
        Some(anchor_store)
    } else {
        None
    };

    let (boot_app, _boot_gov_rotate, boot_limits) =
        busbar_kernel::appbuild::build_app_from_config_with_store(
            cfg,
            plugins_cfg,
            overlay_path,
            base_hook_names,
            base_group_names,
            (Some(config_path.clone()), Some(providers_path.clone())),
            None,
            &(Arc::clone(&root_rules) as Arc<dyn busbar_kernel::appbuild::RootRules>),
            boot_store,
            true,
        )
        .unwrap_or_else(|e| die(e));

    boot_limits.stage_boot();
    let app = Arc::new(boot_app);

    for compose in composes {
        compose(&*app.secret_resolver);
    }

    busbar_kernel::admin::seam::record_boot(&app);

    busbar_kernel::boot::hydrate_all(&app).unwrap_or_else(|e| die(e));

    let planes: Vec<_> = busbar_kernel::plane_driver::registry::plane_decls()
        .iter()
        .map(|d| &d.declaration)
        .collect();
    let signer = app
        .governance
        .clone()
        .map(|g| g as Arc<dyn busbar_kernel::host_services::SignKey>);
    root::serve::attach(
        &late_services,
        app.governance.as_deref(),
        signer,
        &app.demotion_record,
        &planes,
    );

    let door_auths = root::door_steps::process_auths();

    let door_live_handle: std::sync::Arc<
        std::sync::OnceLock<std::sync::Weak<busbar_kernel::state::AppHandle>>,
    > = std::sync::Arc::default();
    let door_models = root::model_egress::ModelServing {
        pools: door_model_pools,
        lanes: app
            .engine_tables_view()
            .model_indices()
            .into_iter()
            .map(|(model, lane)| (model.to_string(), lane))
            .collect(),
        app: root::model_egress::LiveApp::new(
            std::sync::Arc::clone(&door_live_handle),
            std::sync::Arc::clone(&app),
        ),
    };
    let door_reach = root::door_steps::DoorReach {
        providers: &door_providers,
        secrets: Arc::clone(&app.secret_resolver)
            as Arc<dyn busbar_contract::secret::SecretResolve>,
        auths: std::sync::Arc::clone(&door_auths),
        conns: Arc::clone(root::connector::the()) as Arc<dyn busbar_contract::conn::PollConns>,
        stream_ceiling_secs: app.limits.as_ref().map_or(
            busbar_kernel::config::limits::DEFAULT_UPSTREAM_REQUEST_TIMEOUT_SECS,
            |l| l.upstream_request_timeout_secs,
        ),
        catalog: Some(&deploy.models),
        models: Some(&door_models),
        upgrades: root::serve::upgrade_carriers(LINKED.transports, &dropped_doors),
    };
    let mut served = root::serve::compose_served_checked(
        app.governance.clone(),
        root::boot::door_planes(),
        &root::dispatch::dispatcher(),
        &late_services,
        &root::serve::with_pools(
            {
                let mut sections = deploy.door_sections();
                for (key, value) in door_kernel_sections {
                    sections.entry(key).or_insert(value);
                }
                sections
            },
            &door_pools,
        ),
        deploy.public_url.as_deref(),
        &door_reach,
        Some({
            let (live, boot) = (
                std::sync::Arc::clone(&door_live_handle),
                std::sync::Arc::downgrade(&app),
            );
            std::sync::Arc::new(move || {
                let app = match live.get() {
                    Some(handle) => handle
                        .upgrade()
                        .expect("the serving application owner has retired")
                        .load(),
                    None => boot.upgrade().expect("the boot application is still owned"),
                };
                busbar_kernel::plane_driver::engine_host(&app)
            })
        }),
        &app.serve_tables,
        &|served| {
            listener_plan.mount_planes(
                served,
                &app,
                &root::serve::upgrade_carriers(LINKED.transports, &dropped_doors),
            )?;
            Ok(listener_plan.binds().to_vec())
        },
    )
    .unwrap_or_else(|e| die(e));
    listener_plan
        .share_claim_doors(&mut served)
        .unwrap_or_else(|e| die(e));
    root_rules.hold_owned_anchors(&served.need_trust());
    root_rules.hold_member_tls_sections(&served.member_tls_sections());

    if app.governance.is_some() {
        root_rules.hold_unopened(
            served
                .unopened(root::boot::door_planes())
                .into_iter()
                .chain(root::boot::unbound_sections()),
        );
    }
    served.spawn_ticks();

    tracing::info!(
        "reliability state (breakers, cooldowns, latency, hard-down) starts fresh on boot and is \
         re-learned from live traffic"
    );

    export::plugin::start().unwrap_or_else(|e| die(format!("config errors:\n  - {e}")));

    let on_host = LINKED.on_host;
    let boot_host = (!on_host.is_empty()).then(|| busbar_kernel::plane_driver::engine_host(&app));
    if let Some(host) = &boot_host {
        for spawn in on_host {
            spawn(host);
        }
    }

    let tls_secret_resolver = app.secret_resolver.clone();

    let book = (app.governance.is_some()
        || cfg!(feature = "root-admin")
        || ROOT_UNITS.iter().any(|u| u.opens_book)
        || !served.planes.is_empty())
    .then(|| root::boot::book(&app, &store_module).unwrap_or_else(|e| die(e)));

    boot_limits.keep().unwrap_or_else(|e| die(e));

    let door_appliers = served.appliers();
    let door_post = served.post.clone();

    if let Some(refusal) = root::serve::lines::refusal() {
        die(refusal);
    }

    let mut served = served;
    let line_served = line_flag_passed(std::env::args()).then(|| std::mem::take(&mut served));

    drop(served);
    let app_handle = Arc::new(busbar_kernel::state::AppHandle::new(app));
    let admin_router = busbar_kernel::router::build_admin_router_on_with_dispatch_layer(
        &app_handle,
        req_body_max,
        response_headers_cfg.server_timing,
        root::listener::deferred_dispatch_layer,
    );
    let data_router = listener_plan.router(
        &app_handle,
        "listen".into(),
        req_body_max,
        max_inbound,
        response_headers_cfg.server_timing,
    );
    let mut physical_routers = std::collections::HashMap::new();
    for bind in listener_plan.stream_binds() {
        let router = listener_plan.router(
            &app_handle,
            bind.at.clone(),
            req_body_max,
            max_inbound,
            response_headers_cfg.server_timing,
        );
        physical_routers.insert(bind.at.clone(), router);
    }
    credential_handle.set(std::sync::Arc::clone(&app_handle));
    let _ = door_live_handle.set(std::sync::Arc::downgrade(&app_handle));

    if let Some(kernel) = late_services.kernel() {
        kernel.attach_tickets(std::sync::Arc::new(root::serve::LiveTickets(
            std::sync::Arc::downgrade(&app_handle),
        )));
    }

    let _ = root::inbound::install(root::doors::dispatcher());
    {
        let app = app_handle.load();
        let guests = listener_plan.data_guests(&app).unwrap_or_else(|e| die(e));
        let refusals = listener_plan
            .prepared(&app, "listen")
            .expect("boot prepared the actual root data router")
            .refusals
            .clone();
        root::inbound::stage(guests, refusals);
    }
    let _ = root::inbound::publish(&app_handle.load());
    app_handle.on_apply(Box::new({
        let plan = Arc::clone(&listener_plan);
        move |app| {
            let guests = plan.data_guests(app).expect(
                "RootRules checked this candidate's physical listener lists before publication",
            );
            let refusals = plan
                .prepared(app, "listen")
                .expect("RootRules prepared this candidate's actual physical router")
                .refusals
                .clone();
            root::inbound::stage(guests, refusals);
            let _ = root::inbound::publish(app);
        }
    }));
    app_handle.on_apply(Box::new({
        let door_appliers = door_appliers.clone();
        move |app| door_appliers.apply(app)
    }));

    if let Some(post) = door_post {
        let (auths, live) = (
            std::sync::Arc::clone(&door_auths),
            std::sync::Arc::clone(&door_live_handle),
        );
        let upgrades = root::serve::upgrade_carriers(LINKED.transports, &dropped_doors);
        app_handle.on_apply(Box::new(move |next| {
            let Some(cfg) = next
                .config_projection
                .as_ref()
                .and_then(|p| p.downcast_ref::<root::door_steps::DoorConfig>())
            else {
                return;
            };
            let models = root::model_egress::ModelServing {
                pools: cfg.model_pools.clone(),
                lanes: next
                    .engine_tables_view()
                    .model_indices()
                    .into_iter()
                    .map(|(model, lane)| (model.to_string(), lane))
                    .collect(),
                app: root::model_egress::LiveApp::new(
                    std::sync::Arc::clone(&live),
                    std::sync::Arc::clone(next),
                ),
            };
            let reach = root::door_steps::DoorReach {
                providers: &cfg.providers,
                secrets: Arc::clone(&next.secret_resolver)
                    as Arc<dyn busbar_contract::secret::SecretResolve>,
                auths: std::sync::Arc::clone(&auths),
                conns: Arc::clone(root::connector::the())
                    as Arc<dyn busbar_contract::conn::PollConns>,
                stream_ceiling_secs: busbar_kernel::config::limits::installed().map_or(
                    busbar_kernel::config::limits::DEFAULT_UPSTREAM_REQUEST_TIMEOUT_SECS,
                    |l| l.upstream_request_timeout_secs,
                ),
                models: Some(&models),
                catalog: None,
                upgrades: upgrades.clone(),
            };
            door_appliers.refresh_models(
                &cfg.sections,
                &root::serve::DoorEgress {
                    reach: &reach,
                    journal: std::sync::Arc::clone(&post)
                        as std::sync::Arc<dyn busbar_kernel_egress::ports::Journal>,
                },
            );
        }));
    }

    app_handle.on_apply(Box::new(|app| {
        root::boot::follow_plugin_logs(root::boot::plugin_logs(), &app.plugins_cfg);
    }));

    app_handle.on_apply(Box::new(|_| {
        let refused = root::doors::refresh_live(&root::policy::client_settings(
            &busbar_kernel::config::limits::installed().unwrap_or_default(),
        ));
        for why in refused {
            tracing::warn!(error = %why, "a transport kept its settings across a config apply");
        }
    }));

    if let Some(kernel) = late_services.kernel() {
        let _attached = kernel.attach_standing(busbar_kernel::plane_driver::live_standing(
            app_handle.clone(),
        ));
    }

    if let Some(book) = &book {
        let app = app_handle.load();
        let ctx = root::linked::BookCtx { book, app: &app };
        for step in ROOT_UNITS.iter().filter_map(|u| u.on_book) {
            step(&ctx);
        }
    }

    #[cfg(feature = "root-admin")]
    let admin_router = match &book {
        Some(book) => root::units_admin::mount_node(
            admin_router,
            req_body_max,
            &app_handle,
            book,
            None,
            &late_services,
            root::adapters::BreakerPolicy::new(),
        ),
        None => admin_router,
    };

    if let Some(host) = boot_host {
        app_handle.set_snapshot_host(host);
    }

    if let Some(&spawn) = on_host.first() {
        app_handle.attach_on_swap(spawn);
    }

    let (shutdown_tx, _keep_open) = tokio::sync::broadcast::channel::<()>(1);
    let worker_shutdown_rx = control_work.shutdown_rx.clone();
    {
        let rx = shutdown_tx.subscribe();
        let shutdown_level = control_work.shutdown_tx.clone();
        tokio::spawn(async move {
            recv_shutdown(rx).await;
            let _ = shutdown_level.send(true);
        });
    }

    let line_shutdown = line_served.as_ref().map(|_| shutdown_tx.subscribe());

    busbar_core_admin::restart::publish_shutdown(shutdown_tx.clone());
    {
        let shutdown_tx = shutdown_tx.clone();
        tokio::spawn(async move {
            shutdown_signal().await;
            let _ = shutdown_tx.send(());
        });
    }

    if let Some(gov) = app_handle.load().governance.clone() {
        std::mem::drop(busbar_kernel::governance::spawn_budget_flusher(
            gov,
            shutdown_tx.subscribe(),
            Some(app_handle.clone()),
        ));
    }

    busbar_kernel::boot::start_planes(&app_handle).unwrap_or_else(|e| die(e));

    if let Some(served) = line_served {
        let stop = recv_shutdown(line_shutdown.unwrap_or_else(|| shutdown_tx.subscribe()));
        let code = root::serve::lines::serve_lines(
            served,
            app_handle.clone(),
            || root::kernel::ROOT_CARD.pin(),
            stop,
        )
        .await;
        control_work.drain().await;
        let gov = app_handle.load().governance.clone();
        root::shutdown::tail(gov, &late_services, book.as_ref().map(|b| &b.durability)).await;
        std::process::exit(code);
    }

    let framer = listener_framer(
        &listen,
        root::listener::framed::DATA_SCHEME,
        &listener_plan,
        "listen",
    );
    let mut plugin_listeners = Vec::new();
    for bind in listener_plan.stream_binds() {
        let framer = listener_framer(&bind.at, &bind.transport, &listener_plan, &bind.at);
        let tls: Option<busbar_kernel::config::sections::TlsCfg> = bind
            .tls
            .clone()
            .map(serde_json::from_value)
            .transpose()
            .unwrap_or_else(|e| die(format!("{}: {e}", bind.at)));
        let addr = bind.listen.to_string();
        busbar_core_connector::tls::prepare(&addr, tls.as_ref(), &tls_secret_resolver, true)
            .unwrap_or_else(|e| die(e.to_string()));
        let limits = busbar_core_connector::listen::AcceptLimits {
            max_conns: usize::try_from(bind.max_conns).unwrap_or(usize::MAX),
            handshake_timeout: busbar_core_connector::listen::DEFAULT_HANDSHAKE_TIMEOUT,
        };
        let router = physical_routers
            .remove(&bind.at)
            .expect("each physical listener has its own boot router");
        plugin_listeners.push((limits, framer, tls, addr, router));
    }
    let mut plugin_tasks = Vec::new();
    for (limits, framer, tls, addr, router) in plugin_listeners {
        plugin_tasks.push(serve_private_listener(
            addr,
            limits,
            router,
            tls,
            Arc::clone(&tls_secret_resolver),
            shutdown_tx.subscribe(),
            worker_shutdown_rx.clone(),
            framer,
        ));
    }

    #[cfg(unix)]
    {
        let binds = listener_plan.binds();
        let bound_at = |setting: &str, addr: &str| {
            binds
                .iter()
                .find(|b| b.at == setting)
                .map(|b| b.listen.to_string())
                .unwrap_or_else(|| {
                    die(format!(
                        "cannot bind listen address '{addr}': it resolves to no socket address"
                    ))
                })
        };
        let data_at = bound_at("listen", &listen);
        let admin_at = bound_at("admin_listen", &admin_listen);

        let admin_via = root::connector::the().address_via();
        let admin_listener =
            Listening::bind_stream(admin_via.as_ref(), &admin_at, ROOT_BIND_LIMITS).unwrap_or_else(
                |e| die(format!("cannot bind listen address '{admin_listen}': {e}")),
            );
        let data_handles = serve_thread_per_core(
            data_workers,
            listen.clone(),
            data_at,
            data_router,
            tls_cfg,
            tls_secret_resolver.clone(),
            &shutdown_tx,
            worker_shutdown_rx,
            framer,
        );
        tracing::debug!(
            listen = %admin_listen,
            carrier = %root::connector::carrier_name(admin_via.as_ref()),
            "admin listening through the connector"
        );
        serve_listener(
            admin_listener,
            admin_router,
            admin_tls_cfg,
            tls_secret_resolver.clone(),
            &admin_listen,
            recv_shutdown(shutdown_tx.subscribe()),
            None,
            true,
            None,
        )
        .await;

        let _ = tokio::task::spawn_blocking(move || {
            for h in data_handles {
                let _ = h.join();
            }
        })
        .await;
    }
    #[cfg(not(unix))]
    {
        let _ = data_workers;
        let data_listener = root::listener::SocketAdmits::new(bind_listener(&listen).await);
        let admin_listener = root::listener::SocketAdmits::new(bind_listener(&admin_listen).await);
        tokio::join!(
            serve_listener(
                data_listener,
                data_router,
                tls_cfg,
                tls_secret_resolver.clone(),
                &listen,
                recv_shutdown(shutdown_tx.subscribe()),
                None,
                true,
                Some(framer),
            ),
            serve_listener(
                admin_listener,
                admin_router,
                admin_tls_cfg,
                tls_secret_resolver.clone(),
                &admin_listen,
                recv_shutdown(shutdown_tx.subscribe()),
                None,
                true,
                None,
            ),
        );
    }
    let _ = tokio::task::spawn_blocking(move || {
        for task in plugin_tasks {
            let _ = task.join();
        }
    })
    .await;
    control_work.drain().await;

    let gov = app_handle.load().governance.clone();
    root::shutdown::tail(gov, &late_services, book.as_ref().map(|b| &b.durability)).await;
}

#[cfg(unix)]
const ROOT_BIND_LIMITS: AcceptLimits = AcceptLimits {
    max_conns: usize::MAX,
    handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
};

#[cfg(not(unix))]
async fn bind_listener(addr: &str) -> tokio::net::TcpListener {
    tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| die(format!("cannot bind listen address '{addr}': {e}")))
}

fn listener_framer(
    listen: &str,
    scheme: &str,
    plan: &Arc<root::serve::ListenerPlan>,
    at: &str,
) -> root::listener::framed::DataFramer {
    let framer = root::listener::framed::listener_framer(
        Arc::new(|scheme: &str| root::connector::the().framer_for(scheme)),
        scheme,
        plan.policy(at.into()),
    )
    .unwrap_or_else(|| {
        die(format!(
            "cannot serve data listener '{listen}': no loaded transport plugin provides an \
         accepting framer for '{}'; load a transport plugin that accepts this listener's scheme",
            scheme,
        ))
    });
    tracing::debug!(
        framer = %framer.door().facts().name,
        "data door served through its framer's accept side"
    );
    framer
}

async fn recv_shutdown(mut rx: tokio::sync::broadcast::Receiver<()>) {
    let level = busbar_kernel::detached::worker_shutdown();
    tokio::select! {
        _ = rx.recv() => {},
        () = busbar_kernel::detached::shutdown_fired(level) => {},
    }
}

#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn serve_thread_per_core(
    n: usize,
    addr: String,

    bind_at: String,
    data_router: Router,
    tls_cfg: Option<busbar_kernel::config::sections::TlsCfg>,
    secret_resolver: Arc<busbar_kernel::config::secret::SecretResolver>,
    shutdown_tx: &tokio::sync::broadcast::Sender<()>,
    worker_shutdown: tokio::sync::watch::Receiver<bool>,

    framer: root::listener::framed::DataFramer,
) -> Vec<std::thread::JoinHandle<()>> {
    if tls_cfg.is_some() {
        let _ =
            busbar_core_connector::tls::prepare(&addr, tls_cfg.as_ref(), &secret_resolver, true)
                .unwrap_or_else(|e| die(e.to_string()));
    }
    let core_ids = core_affinity::get_core_ids().unwrap_or_default();
    let cores: Vec<Option<core_affinity::CoreId>> =
        (0..n).map(|i| core_ids.get(i).copied()).collect();

    tracing::debug!(
        runtimes = cores.len(),
        pinned = core_ids.len().min(n),
        listen = %addr,
        "thread-per-core data plane: one SO_REUSEPORT listener per worker (admin + background \
         tasks stay on the control runtime)"
    );

    let mut balancers: Vec<Option<root::listener::ConnBalancer>> =
        root::listener::ConnBalancer::build(cores.len())
            .into_iter()
            .map(Some)
            .collect();
    let mut handles = Vec::with_capacity(cores.len());
    for (i, core_id) in cores.into_iter().enumerate() {
        let router = data_router.clone();
        let tls = tls_cfg.clone();
        let resolver = secret_resolver.clone();
        let listen = addr.clone();
        let shutdown_rx = shutdown_tx.subscribe();
        let worker_shutdown = worker_shutdown.clone();
        let balancer = balancers[i].take();
        let bind_at = bind_at.clone();
        let framer = framer.clone();
        let spawned = std::thread::Builder::new()
            .name(format!("busbar-core-{i}"))
            .spawn(move || {
                if let Some(id) = core_id {
                    core_affinity::set_for_current(id);
                }

                busbar_kernel::topology::set_worker_id(i);

                let detached = busbar_kernel::detached::DetachedTasks::new();
                busbar_kernel::detached::set_worker_detached(detached.clone());

                busbar_kernel::detached::set_worker_shutdown(worker_shutdown);
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap_or_else(|e| {
                        die(format!("failed to build per-core data runtime {i}: {e}"))
                    });
                rt.block_on(async move {
                    let via = crate::root::connector::the().address_via();
                    let listener = Listening::bind_stream(via.as_ref(), &bind_at, ROOT_BIND_LIMITS)
                        .unwrap_or_else(|e| {
                            die(format!(
                                "cannot bind SO_REUSEPORT data listener on '{listen}' (per-core \
                             runtime {i}): {e}"
                            ))
                        });
                    tracing::debug!(
                        listen = %listen,
                        carrier = %crate::root::connector::carrier_name(via.as_ref()),
                        "data door listening through the connector"
                    );
                    serve_listener(
                        listener,
                        router,
                        tls,
                        resolver,
                        &listen,
                        recv_shutdown(shutdown_rx),
                        balancer,
                        i == 0,
                        Some(framer),
                    )
                    .await;

                    let _ = tokio::time::timeout(
                        busbar_kernel::detached::DETACHED_DRAIN_GRACE,
                        detached.drained(),
                    )
                    .await;
                });
            })
            .unwrap_or_else(|e| die(format!("cannot spawn per-core data thread {i}: {e}")));
        handles.push(spawned);
    }
    handles
}

#[allow(clippy::too_many_arguments)]
fn serve_private_listener(
    addr: String,
    limits: AcceptLimits,
    router: Router,
    tls: Option<busbar_kernel::config::sections::TlsCfg>,
    resolver: Arc<busbar_kernel::config::secret::SecretResolver>,
    shutdown: tokio::sync::broadcast::Receiver<()>,
    worker_shutdown: tokio::sync::watch::Receiver<bool>,
    framer: root::listener::framed::DataFramer,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("busbar-listener".into())
        .spawn(move || {
            let detached = busbar_kernel::detached::DetachedTasks::new();
            busbar_kernel::detached::set_worker_detached(detached.clone());
            busbar_kernel::detached::set_worker_shutdown(worker_shutdown);
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap_or_else(|e| die(format!("cannot build listener runtime for {addr}: {e}")));
            runtime.block_on(async move {
                let via = root::connector::the().address_via();
                let listener = Listening::bind_stream(via.as_ref(), &addr, limits)
                    .unwrap_or_else(|e| die(format!("cannot bind listener {addr}: {e}")));
                serve_listener(
                    listener,
                    router,
                    tls,
                    resolver,
                    &addr,
                    recv_shutdown(shutdown),
                    None,
                    true,
                    Some(framer),
                )
                .await;
                let _ = tokio::time::timeout(
                    busbar_kernel::detached::DETACHED_DRAIN_GRACE,
                    detached.drained(),
                )
                .await;
            });
        })
        .unwrap_or_else(|e| die(format!("cannot spawn listener worker: {e}")))
}

#[allow(clippy::too_many_arguments)]
async fn serve_listener(
    listener: impl busbar_core_connector::listen::Admits,
    router: Router,
    tls_cfg: Option<busbar_kernel::config::sections::TlsCfg>,
    secret_resolver: Arc<busbar_kernel::config::secret::SecretResolver>,
    label: &str,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,

    balancer: Option<root::listener::ConnBalancer>,

    log_at_info: bool,

    framer: Option<root::listener::framed::DataFramer>,
) {
    let security = match tls_cfg {
        None => {
            if log_at_info {
                tracing::info!(listen = %label, "busbar listening");
            } else {
                tracing::debug!(listen = %label, "busbar listening");
            }
            None
        }
        Some(tls) => {
            let security =
                busbar_core_connector::tls::prepare(label, Some(&tls), &secret_resolver, true)
                    .unwrap_or_else(|e| die(e.to_string()));
            let mtls = tls.client_ca.is_some();
            if log_at_info {
                tracing::info!(listen = %label, mtls, "busbar listening (TLS)");
            } else {
                tracing::debug!(listen = %label, mtls, "busbar listening (TLS)");
            }
            Some(security)
        }
    };
    let result = match framer {
        Some(framer) => {
            root::listener::serve_admitted_framed(
                listener,
                router,
                security,
                shutdown,
                balancer,
                Some(framer),
            )
            .await
        }
        None => {
            root::listener::serve_admitted(listener, router, security, shutdown, balancer).await
        }
    };
    if let Err(e) = result {
        die(format!("server error on '{label}': {e}"));
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::warn!(
                diag = %diagnostics::SHUTDOWN_SIGNAL_HANDLER_INSTALL_FAILED.banner(),
                error = %e, "failed to install ctrl_c handler; SIGINT shutdown disabled"
            );
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
                tracing::warn!(
                    diag = %diagnostics::SHUTDOWN_SIGNAL_HANDLER_INSTALL_FAILED.banner(),
                    error = %e, "failed to install SIGTERM handler; SIGTERM shutdown disabled"
                );
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(windows)]
    let terminate = async {
        let close = async {
            match tokio::signal::windows::ctrl_close() {
                Ok(mut sig) => {
                    sig.recv().await;
                }
                Err(e) => {
                    tracing::warn!(
                        diag = %diagnostics::SHUTDOWN_SIGNAL_HANDLER_INSTALL_FAILED.banner(),
                        error = %e, "failed to install ctrl_close handler; CTRL_CLOSE shutdown disabled"
                    );
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
                    tracing::warn!(
                        diag = %diagnostics::SHUTDOWN_SIGNAL_HANDLER_INSTALL_FAILED.banner(),
                        error = %e, "failed to install ctrl_shutdown handler; CTRL_SHUTDOWN shutdown disabled"
                    );
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

#[cfg(not(target_env = "msvc"))]
const IDLE_PURGE_SWEEP_SECS: u64 = 15;

#[cfg(not(target_env = "msvc"))]
fn spawn_jemalloc_idle_purge_fallback() {
    use tikv_jemalloc_ctl::{Access, AsName};

    const ARENAS_DIRTY_DECAY_DEFAULT: &[u8] = b"opt.dirty_decay_ms\0";
    let spawned = std::thread::Builder::new()
        .name("busbar-idle-purge".into())
        .spawn(move || {
            match Access::<isize>::read(ARENAS_DIRTY_DECAY_DEFAULT.name()) {
                Ok(_) => {}
                Err(e) => {
                    eprintln!(
                        "[warn] {}: jemalloc idle-purge fallback disabled: could not read \
                         opt.dirty_decay_ms ({e})",
                        diagnostics::JEMALLOC_IDLE_PURGE_FALLBACK_UNAVAILABLE.banner()
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
                purge_idle_arenas();
            }
        });
    if let Err(e) = spawned {
        eprintln!(
            "[warn] {}: could not spawn the jemalloc idle-purge fallback thread ({e})",
            diagnostics::JEMALLOC_IDLE_PURGE_FALLBACK_UNAVAILABLE.banner()
        );
    }
}

#[cfg(not(target_env = "msvc"))]
fn purge_idle_arenas() {
    use tikv_jemalloc_ctl::{Access, AsName};
    const ARENAS_NARENAS: &[u8] = b"arenas.narenas\0";
    let narenas: u32 = ARENAS_NARENAS.name().read().unwrap_or(0);
    for i in 0..narenas {
        let key = format!("arena.{i}.dirty_decay_ms\0");
        let name = key.as_bytes().name();
        let Ok(prior) = Access::<isize>::read(name) else {
            continue;
        };
        if prior == 0 {
            continue;
        }
        let _ = name.write(0isize).and_then(|()| name.write(prior));
    }
}

mod root;

#[cfg(test)]
#[path = "../../../dist/default/tests/common/mod.rs"]
pub(crate) mod test_common;

#[cfg(test)]
mod build_stamp;

#[cfg(test)]
#[path = "tests/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/catalogue_tests.rs"]
mod catalogue_tests;

#[cfg(all(test, distribution_root))]
#[path = "../../../dist/default/tests/common/root_install.rs"]
mod dist_root_install;

#[cfg(all(test, distribution_root))]
#[path = "tests/distribution.rs"]
mod distribution;
