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
// See `register_protocols`/`register_root`/`register_diagnostics` below for the composition root's
// one write into each axis. Every plugin is a MIN-3 image (`busbar-plugin-abi`): the linked images
// are admitted through the loader's one checked path and opened by the boot in `root::min3_boot`.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(dead_code, unused_imports, unused_macros))]
// The root's listener futures prove `Send`/`Sync` across the serving App graph, which is deeper
// than the default 128 auto-trait steps (as in busbar-kernel); the graph is acyclic.
#![recursion_limit = "256"]

#[cfg(all(not(target_env = "msvc"), not(test)))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// Test builds count every allocation for the per-request work-budget gate (`perf/work-budget.toml`).
#[cfg(all(not(target_env = "msvc"), test))]
#[global_allocator]
static GLOBAL: stats_alloc::StatsAlloc<tikv_jemallocator::Jemalloc> =
    stats_alloc::StatsAlloc::new(tikv_jemallocator::Jemalloc);

use std::sync::Arc;
use std::time::Duration;

use busbar_kernel::{config, config_validate, diagnostics, export, snapshot};
use busbar_kernel::{LoadedConfig, ENV_CONFIG};

use busbar_core_connector::listen::AcceptLimits;
#[cfg(unix)]
use busbar_core_connector::listen::Listening;

#[cfg(not(target_env = "msvc"))]
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
    eprintln!("[error] {}", diagnostics::BOOT_FATAL_ERROR.coded(msg));
    root::exit::exit(1);
}

/// [`die`] over a list: the coded head line, then one `  - <item>` line per error, each item
/// carrying its own code and link.
fn die_list<T: std::fmt::Display>(head: &str, items: impl IntoIterator<Item = T>) -> ! {
    let mut out = format!("[error] {}", diagnostics::BOOT_FATAL_ERROR.coded(head));
    for item in items {
        out.push_str(&format!("\n  - {item}"));
    }
    eprintln!("{out}");
    root::exit::exit(1);
}

const OPTION_IGNORE_OVERLAY: &str = "--ignore-overlay";

fn ignore_overlay_requested(mut args: impl Iterator<Item = String>) -> bool {
    args.any(|a| a == OPTION_IGNORE_OVERLAY)
}

/// A store refusal preserves ordinary boot detail and redacts principal transitions.
fn store_boot_refusal(transition: bool, error: String) -> String {
    if transition {
        "principal transition base Store opening refused".to_owned()
    } else {
        error
    }
}

/// Whether this process serves its one plane line route on stdin/stdout instead of binding
/// listeners: core's own `--stdio`, never a plugin-stated flag (WP1-GAP r3 §1.3, #428).
fn line_serve_requested(argv: &root::cli::Argv) -> bool {
    argv.stdio
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
                    "[warn] {}",
                    diagnostics::WORKER_THREADS_INVALID.coded(format_args!(
                        "{name}={v:?} is not a positive integer; ignoring it and using the \
                         default worker-thread count"
                    ))
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
    let config_path = root::cli::resolve_config_path(root::cli::argv().config.as_deref());
    let raw = std::fs::read_to_string(&config_path).ok()?;
    let mut unset = Vec::new();
    let interpolated =
        config::interpolate_env_with(&raw, config::EnvSubst::Lenient, &mut unset).ok()?;

    use busbar_contract::yaml::ValueExt;
    let doc: busbar_contract::yaml::Value = busbar_contract::yaml::from_str(&interpolated).ok()?;
    let worker_threads = match doc.get("advanced").and_then(|a| a.get("worker_threads")) {
        None | Some(busbar_contract::yaml::Value::Null) => None,
        Some(v) => Some(usize::try_from(v.as_u64()?).ok()?),
    };
    match validate_worker_threads_config(worker_threads) {
        Ok(v) => v,
        Err(msg) => {
            warnings.push(format!(
                "[warn] {}",
                diagnostics::WORKER_THREADS_INVALID.coded(msg)
            ));
            None
        }
    }
}

fn resolve_worker_threads() -> (usize, Vec<String>) {
    let mut warnings = Vec::new();
    let n = worker_threads_from_config_noting(&mut warnings)
        .or_else(|| worker_threads_from_env_noting("TOKIO_WORKER_THREADS", &mut warnings))
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
        })
        .min(MAX_WORKER_THREADS);
    (n, warnings)
}

/// Resolve the effective recovered config, then the supported Tokio fallback.
fn recovered_data_workers(
    configured: Option<usize>,
    fallback_env: Option<usize>,
    available: usize,
) -> usize {
    configured
        .filter(|n| *n != 0)
        .or(fallback_env)
        .unwrap_or(available)
        .clamp(1, MAX_WORKER_THREADS)
}

#[cfg(test)]
mod recovered_worker_tests {
    use super::*;

    #[test]
    fn recovered_worker_count_honors_effective_config_and_tokio_fallback() {
        assert_eq!(recovered_data_workers(Some(7), Some(3), 2), 7);
        assert_eq!(recovered_data_workers(None, Some(3), 2), 3);
        assert_eq!(recovered_data_workers(None, None, 2), 2);
        assert_eq!(recovered_data_workers(Some(0), None, 2), 2);
        assert_eq!(
            recovered_data_workers(Some(usize::MAX), None, 2),
            MAX_WORKER_THREADS
        );
    }

    #[test]
    fn recovered_data_runtime_keeps_control_alive_and_drains_registered_work() {
        let control = busbar_kernel::rt::multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        control.block_on(async {
            let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
            let (serving_done_tx, serving_done_rx) = tokio::sync::oneshot::channel();
            let (shutdown_seen_tx, shutdown_seen_rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = tokio::sync::oneshot::channel();
            let finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let finished_work = finished.clone();
            // The effective Store value replaces the bootstrap budget, on the actual scheduler.
            let workers = recovered_data_workers(Some(3), None, 1);
            let data = spawn_multithread_data(workers, shutdown_rx, async move {
                assert_eq!(tokio::runtime::Handle::current().metrics().num_workers(), 3);
                let tracker = busbar_kernel::detached::worker_detached().unwrap();
                tokio::task::spawn_blocking(move || {
                    assert!(Arc::ptr_eq(
                        &tracker,
                        &busbar_kernel::detached::worker_detached().unwrap()
                    ));
                    assert!(busbar_kernel::detached::worker_shutdown().is_some());
                })
                .await
                .unwrap();
                tokio::spawn(async move {
                    let shutdown = busbar_kernel::detached::worker_shutdown();
                    assert!(shutdown.is_some());
                    assert!(busbar_kernel::detached::worker_detached().is_some());
                    busbar_kernel::detached::spawn_detached(async move {
                        busbar_kernel::detached::shutdown_fired(shutdown).await;
                        shutdown_seen_tx.send(()).unwrap();
                        release_rx.await.unwrap();
                        finished_work.store(true, std::sync::atomic::Ordering::Release);
                    });
                })
                .await
                .unwrap();
                serving_done_tx.send(()).unwrap();
            });
            tokio::time::timeout(Duration::from_secs(3), serving_done_rx)
                .await
                .unwrap()
                .unwrap();
            // Bootstrap/control tasks still run while data custody waits for detached work.
            assert_eq!(
                tokio::spawn(async { tokio::runtime::Handle::current().metrics().num_workers() })
                    .await
                    .unwrap(),
                1
            );
            shutdown_tx.send(true).unwrap();
            tokio::time::timeout(Duration::from_secs(3), shutdown_seen_rx)
                .await
                .unwrap()
                .unwrap();
            assert!(!data.is_finished());
            release_tx.send(()).unwrap();
            tokio::task::spawn_blocking(move || data.join())
                .await
                .unwrap()
                .unwrap();
            assert!(finished.load(std::sync::atomic::Ordering::Acquire));
            assert_eq!(tokio::spawn(async { 42 }).await.unwrap(), 42);
        });
    }
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

fn register_protocols() {
    root::linked::register_protocols(&LINKED);
}

/// The root's one write into the kernel's install seams, before any configuration is read: the
/// root's install record, the native images' start prepare, the start scan of `plugins.dir`, the
/// operator binding, the public settings table and the start grammar.
fn register_root() {
    root::linked::register_stores();

    // WP3 step 2: the native image prepare (verify, manifest read, describe; no instance opens) runs before
    // the start scan, so --validate, --list-plugins and the start grammar read the native secret words.
    if let Err(refusal) = root::boot::images::publish_start() {
        eprintln!("busbar: {refusal}");
        root::exit::exit(2);
    }
    let scan = root::boot::start_scan();
    let dropped = root::boot::install_start(scan);
    busbar_kernel::preflight::install_operator(root::auth_bindings::operator_binding(dropped));
    root::linked::register_dropped(dropped);

    root::settings_public::install();
    root::boot::bind_start_grammar();

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
    // First, before anything touches crypto: the backend's power-on self-test gates boot (#172).
    if let Err(e) = busbar_contract::crypto::self_test() {
        die(e);
    }
    if let Err(e) = busbar_kernel::observability::init_log_bridge() {
        eprintln!("busbar: the `log` bridge is not installed: {e}");
    }
    // The exiting arms that need no plugin state run before anything is scanned, read or
    // registered (WP1-GAP r3 §1.2, B2): only the crypto self-test above precedes them.
    if let Some(code) = root::cli::early_cli_flags() {
        root::exit::exit(code);
    }

    root::boot::install_native_load_guard().unwrap_or_else(|error| die(error));

    // Force this boot's node now, so its one OS draw never lands on a request worker.
    let _ = busbar_kernel::door::node();

    register_protocols();

    register_root();

    let catalogue = register_diagnostics();

    match root::cli::handle_cli_flags() {
        root::cli::Parsed::Exit(code) => root::exit::exit(code),
        root::cli::Parsed::Serve => {}
    }

    // The one subscriber, installed before any work so admission's diagnostics (the first-start
    // wait line, a takeover, an exit-time hand-over) reach stderr (FIRST-START-TAKEOVER §2.8).
    // A RUST_LOG the console filter cannot read stops boot here: it is never silently replaced
    // by the default level.
    let trace_publisher = match busbar_kernel::observability::init_logging() {
        Ok(publisher) => Some(publisher),
        Err(busbar_kernel::observability::LoggingError::RustLog(e)) => die(e),
        Err(e @ busbar_kernel::observability::LoggingError::AlreadyInitialized(_)) => {
            eprintln!("busbar: {e}");
            None
        }
    };

    let (_, warnings) = &*WORKERS;
    for w in warnings {
        eprintln!("{w}");
    }
    // Refuse retired launch inputs before migration or any configuration is read.
    root::retired_env::check_launch_env(|n| std::env::var_os(n)).unwrap_or_else(|error| die(error));
    // Migrate-on-boot step 1 (MIGRATE-ON-BOOT r42 §3): config.yaml's one field, before anything else
    // reads it. An unstamped config is planned in memory here and written at step 5.
    {
        let argv = root::cli::argv();
        let config =
            std::path::PathBuf::from(root::cli::resolve_config_path(argv.config.as_deref()));
        root::migrate::run(&config, argv.providers.is_some(), argv.ignore_overlay)
            .unwrap_or_else(|error| die(error));
    }
    #[cfg(not(unix))]
    let worker_threads = WORKERS.0;

    let control_work = ControlWork::new();
    control_work.register();
    #[cfg(unix)]
    {
        busbar_kernel::rt::current_thread()
            .enable_all()
            .build()
            .expect("failed to build the tokio control runtime")
            .block_on(run(catalogue, control_work, trace_publisher));
    }
    #[cfg(not(unix))]
    {
        let worker_work = control_work.clone();
        busbar_kernel::rt::multi_thread()
            .worker_threads(worker_threads)
            .on_thread_start(move || worker_work.register())
            .enable_all()
            .build()
            .expect("failed to build the tokio control runtime")
            .block_on(run(catalogue, control_work, trace_publisher));
    }
    // Every return from `run` (a one-shot command, a serve-and-shutdown) leaves here, so an
    // unpublished first start is handed over on a normal return too (FIRST-START-TAKEOVER §2.7).
    root::exit::exit(0);
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
    fn judge_target_name(
        &self,
        target: busbar_kernel::host_services::Destination<'_>,
        refuse_private: bool,
    ) -> Result<(), u64> {
        self.snapshot().judge_target_name(target, refuse_private)
    }
    fn judge_target(
        &self,
        target: busbar_kernel::host_services::Destination<'_>,
        refuse_private: bool,
        reach: bool,
        done: Box<dyn FnOnce(busbar_kernel::host_services::Admitted) + Send>,
    ) -> Option<busbar_kernel::host_services::Admitted> {
        self.snapshot()
            .judge_target(target, refuse_private, reach, done)
    }
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
            blocked: Vec::new(),
            listens: Vec::new(),
        };
        let holder = BootstrapDestJudge::new(root::connector::guard_for(&policy(false)).unwrap());
        let installed: Arc<dyn busbar_kernel::host_services::DestJudge> = holder.clone();
        let class = busbar_contract::conn::codes::EGRESS_PROVIDER;
        let target = busbar_kernel::host_services::Destination {
            authority: "\x310.2.3.4:443",
            secure: true,
            egress_class: class,
        };
        assert!(installed.judge_target_name(target, false).is_ok());
        assert!(installed
            .judge_name("https://\x310.2.3.4", class, false)
            .is_ok());
        holder.replace(root::connector::guard_for(&policy(true)).unwrap());
        assert!(installed.judge_target_name(target, false).is_err());
        assert!(installed
            .judge_name("https://\x310.2.3.4", class, false)
            .is_err());
        assert!(holder
            .judge_name("https://\x310.2.3.4", class, false)
            .is_err());
    }
}

async fn run(
    catalogue: busbar_kernel::diagnostics::Catalogue,
    control_work: ControlWork,
    trace_publisher: Option<busbar_kernel::export::traces::TracePublisher>,
) {
    let process_io = root::boot::process::ProcessIo::new().unwrap_or_else(|error| die(error));
    // The start stage made the process's one ProcessResources (a process installs its plugin sinks once).
    let plugin_process = root::boot::images::process().unwrap_or_else(|error| die(error));
    root::admission::install_process(&plugin_process);
    let export_observers = root::export_observer::ExportObservers::new();
    root::observe::install(catalogue);
    // Until the listener's own handler owns signals, SIGTERM/SIGINT exit through `root::exit`, so
    // an armed first-start owner hands over (FIRST-START-TAKEOVER §2.7).
    let signal_handoff = root::exit::exit_on_signal();

    let argv = root::cli::argv();

    if let Some(notice) = root::cli::config_override_notice(
        argv.config.as_deref(),
        std::env::var(ENV_CONFIG).ok().as_deref(),
    ) {
        eprintln!("[info] {notice}");
    }
    let providers_override = argv.providers.as_deref().map(std::path::PathBuf::from);
    let config_path =
        std::path::PathBuf::from(root::cli::resolve_config_path(argv.config.as_deref()));
    let ignore_overlay = ignore_overlay_requested(std::env::args());
    if ignore_overlay {
        busbar_kernel::appbuild::IGNORE_OVERLAY_FLAG
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
    let principal_transition =
        root::principal_transition::command(argv).unwrap_or_else(|error| die(error));
    if let Some(command) = principal_transition.as_ref() {
        command
            .validate_record_bootstrap_input(
                std::env::var_os(busbar_kernel::host_record_bootstrap::RECEIPT_ENV).is_some(),
            )
            .unwrap_or_else(|error| die(error));
    }
    let boot_error = |context: &str, detail: String| {
        if principal_transition.is_some() {
            context.to_owned()
        } else {
            detail
        }
    };
    // Every configuration read of this boot runs under the boot's reader rules: an unstamped boot
    // reads the document the migrate seam planned at step 1 (held in memory until step 5 writes it),
    // every other boot reads the file. The gateway reads only current bytes.
    let config_rules = root::boot_app::ConfigRules {
        process: std::sync::Arc::clone(&plugin_process),
    };
    if let Some(refusal) = root::boot::start_refusal() {
        die(boot_error(
            "plugins directory refused at process start",
            refusal,
        ));
    }
    // A start whose `plugins:` block on disk is in a pre-1.6 shape judges the operator credential
    // from the planned config's block, before the load (OPERATOR-FROM-ADMITTED-AUTH §3.4.1).
    root::auth_bindings::bind_from_planned(&config_path).unwrap_or_else(|error| {
        die(boot_error(
            "principal transition operator credential refused",
            error,
        ))
    });
    let raw = busbar_kernel::appbuild::read_config_documents(
        &config_path,
        providers_override.as_deref(),
        ignore_overlay,
        config::EnvSubst::Strict,
        &config_rules,
        busbar_kernel::appbuild::DocumentPatchLoad {
            patch: None,
            providers_patch: None,
            admission: None,
        },
    )
    // The read's own grammar already appended its report (one line per file not admitted).
    .unwrap_or_else(|e| {
        die(boot_error(
            "principal transition configuration load refused",
            e,
        ))
    });
    let file_plugins = raw.plugins_block().unwrap_or_else(|error| die(error));
    let file_images = root::boot::images::prepare(
        &plugin_process,
        &config::grammar::PhaseOneIn::of(&file_plugins),
    )
    .unwrap_or_else(|error| die(error.0));
    // The boot's images are the serving set: their secret grammar is the native secret axis.
    file_images.publish_secrets();
    // ... and their hook facts are what config validation reads of hooks (WP3 hook step).
    file_images.publish_hooks();
    let loaded = raw
        .typed(&file_images.grammar)
        .unwrap_or_else(|error| die(error));
    let LoadedConfig {
        deploy,
        defs,
        resource_ownership: _,
        providers_path,
        overlay_path: _,
        config_locked,
        config_read_only: _,
        overlay_doc: _,
        unset_env_vars: _,
        operator_reference,
    } = loaded;

    let base_cfg = root::boot_app::store_bootstrap(&deploy).unwrap_or_else(|errors| {
        die(boot_error(
            "Store bootstrap configuration refused",
            format!(
                "Store bootstrap configuration errors: {}",
                errors.join("; ")
            ),
        ))
    });
    let authoring_seal = busbar_kernel::seal::acquire();
    let base_store_settings = serde_json::to_value(
        base_cfg
            .store
            .as_ref()
            .map(|store| store.authoring(&authoring_seal)),
    )
    .unwrap_or_else(|error| {
        die(boot_error(
            "principal transition base Store configuration refused",
            format!("base Store settings: {error}"),
        ))
    });
    let file_grammar = base_cfg
        .grammar()
        .unwrap_or_else(|error| die(error.0))
        .clone();
    let mut effective_images = file_images.clone();
    let boot_instances = Arc::new(root::boot::inputs::BootInstances::capture(&base_cfg));
    let config_rules = root::boot_app::ProtectedRules {
        reader: config_rules,
        images: file_images
            .protect(&base_cfg)
            .unwrap_or_else(|error| die(error)),
        instances: Arc::clone(&boot_instances),
    };
    let guard_judge = root::connector::dest_judge(&base_cfg);
    let boot_guard = guard_judge.guard().clone();
    let dest = BootstrapDestJudge::new(guard_judge);
    let commit_guard: Arc<dyn busbar_kernel::host_services::DestJudge> = dest.clone();
    let bootstrap = Box::pin(async {
        let _connector = root::connector::boot(
            process_io.handle(),
            &root::policy::client_settings(&base_cfg.limits),
            dest.clone(),
            &base_cfg.own_listens(),
        );
        root::connector::install_trust_store(&base_cfg, false);
        // The MIN-3 registry boots here, before the Store opens and before any listener serves: images, the
        // kernel's sides, then 2a, 2b, the deployment point, 2c. A Store with no admitted MIN-3 image stops the boot.
        let conversion_images = file_images.clone();
        let (bootstrap_ready, store_admission) = root::min3_boot::prepare_bootstrap(
            process_io.handle(), &plugin_process, file_images, &base_cfg, boot_guard.clone(), root::cli::argv().stdio,
        ).await.unwrap_or_else(|error| die(store_boot_refusal(principal_transition.is_some(), error)))
            .unwrap_or_else(|| die("the configured Store has no admitted MIN-3 instance"));
        if bootstrap_ready.converting() {
            let conversion = root::min3_boot::prepare_serving(
                bootstrap_ready, &plugin_process, conversion_images, &base_cfg,
                &Default::default(), boot_guard,
            ).await.unwrap_or_else(|error| die(error));
            let observation_reservation = export_observers.reserve(conversion.export_names())
                .unwrap_or_else(|error| die(error));
            let _ = root::min3_boot::finish(
                conversion, store_admission, None,
                busbar_kernel::plane_driver::port_work::governed_binder(None, Default::default()),
                None,
                &observation_reservation,
            )
                .await.unwrap_or_else(|error| die(error));
            die("unstamped conversion returned without its required restart");
        }
        let anchor_store = store_admission.store().expect("confirmed Store admission");
        root::exit::arm(&anchor_store);
        // Migrate-on-boot step 4 (MIGRATE-ON-BOOT r42 §3 4a, 4b): the 1.5.5 rows a store's data step
        // left under IMPORT become native records under this admission, sealed and verified, before
        // anything reads them. An empty IMPORT costs one one-row scan.
        let keys = root::migrate_records::Keys::from_core(&bootstrap_ready.core)
            .unwrap_or_else(|error| die(error));
        root::migrate::records_with_keys(anchor_store.clone(), keys)
            .await
            .unwrap_or_else(|error| die(error));
        // config.yaml's operator definitions as read, before any stored document patch: the operator
        // file-policy reference this process starts with (OPERATOR-FROM-ADMITTED-AUTH §000.1).
        let operator_reference = Arc::new(operator_reference);
        let mut deploy = deploy;
        let mut defs = defs;
        let mut providers_path = providers_path;
        // Even --ignore-overlay must observe a pending transition in the anchor namespace before
        // overlay recovery or application construction can open another effective Store.
        if principal_transition.is_none() {
            busbar_kernel::governance::principal_transition::pending_guard_native(anchor_store.clone())
                .await
                .unwrap_or_else(|error| die(error));
        }
        root::boot::bind_plugin_floor(anchor_store.clone())
            .await
            .unwrap_or_else(|error| die(boot_error("Store plugin-floor authority refused", error)));
        let mut overlay_path = if config_locked && principal_transition.is_none() {
            None
        } else {
            Some(
                config::overlay::OverlayStore::from_core(anchor_store.clone())
                    .unwrap_or_else(|error| die(boot_error("Store overlay unavailable", error))),
            )
        };
        let overlay_doc = if ignore_overlay {
            None
        } else if let Some(store) = overlay_path.as_ref() {
            store
                .read_required_async()
                .await
                .unwrap_or_else(|error| die(boot_error("Store overlay recovery refused", error)))
        } else {
            None
        };

        // The base Store remains the bootstrap anchor. Its durable document layer is parsed with
        // boot's schema before the established typed overlays, never substituted for the anchor.
        // The post-Store recompute (SECRET-SHORTHAND-BOOT §3.7): the Store's patches and plugin
        // version pins are part of this generation's read, so its grammar is phase 1 over the
        // patched documents with the pins, and the documents are typed under that grammar. It must
        // declare every item the documents use as the start grammar did (BUSBAR-3170).
        if let Some(doc) = overlay_doc.as_ref().filter(|doc| {
            doc.document_patch.is_some()
                || doc.providers_patch.is_some()
                || !doc.plugin_versions.is_empty()
        }) {
            let (patched, images) = config_rules.read_under_store(
                &config_path,
                providers_override.as_deref(),
                doc,
            )
            .unwrap_or_else(|error| {
                die(boot_error(
                    "principal transition Store document overlay refused",
                    format!("Store document overlay refused: {error}"),
                ))
            });
            effective_images = images;
            let pinned = match (patched.deploy.grammar.get(), patched.deploy.grammar.used()) {
                (Ok(generation), Ok(used)) => {
                    config::grammar::pin(&file_grammar, generation, used, config::grammar::Pin::Store)
                }
                (Err(refusal), _) | (_, Err(refusal)) => Err(refusal.0),
            };
            if let Err(refusal) = pinned {
                die(boot_error("Store plugin pins refused", refusal));
            }
            // A stored patch that moves the operator credential or the plugin admission set is
            // refused here, naming its paths and remedies: never applied or dropped silently.
            if let Some(patch) = doc.document_patch.as_ref() {
                config::operator_file::stored_document_patch(patch, &patched).unwrap_or_else(
                    |error| die(boot_error("Store document overlay refused", error)),
                );
            }
            if patched.config_locked && principal_transition.is_none() {
                overlay_path = None;
            }
            deploy = patched.deploy;
            defs = patched.defs;
            providers_path = patched.providers_path;
        }

        if let Some(notice) = root::cli::providers_override_notice(
            argv.providers.as_deref(),
            deploy.providers_file(),
        ) {
            eprintln!("[info] {notice}");
        }

        let resource_ownership = config::ResourceOwnership::capture(&deploy);
        let base_hook_names = resource_ownership.hook_names().clone();
        let base_group_names = resource_ownership.group_names().clone();
        if let Some(doc) = overlay_doc.as_ref() {
            resource_ownership.validate_named_maps(doc).unwrap_or_else(|error| {
                die(boot_error("Store overlay refused", error))
            });
            config::overlay::apply_root_to_deploy(&mut deploy, doc).unwrap_or_else(|error| {
                die(boot_error(
                    "Store overlay refused",
                    format!("Store overlay refused: {error}"),
                ))
            });
        }

        let mut fresh_record_bootstrap = None;
        let mut judged_effective = None;
        if let Some(command) = principal_transition.as_ref() {
            command
                .validate_overlay_mode(config_locked, overlay_doc.is_some())
                .unwrap_or_else(|error| die(error));
            let transition_source_sha256 = root::principal_transition::source_fingerprint(
                &config_path,
                &providers_path,
                deploy.document_source_fingerprints,
            )
            .unwrap_or_else(|error| die(error));
            // This branch precedes governors, usage recovery, correction tasks and listeners.
            // Reconstruct the same effective config that normal application boot consumes.
            let provider_planes = root::min3_provider_plan::descriptors(&effective_images)
                .unwrap_or_else(|error| die(error));
            let mut effective = config::resolve_with_provider_planes(&deploy, &defs, &provider_planes)
                .unwrap_or_else(|_| die("principal transition effective configuration refused"))
                .config;
            if let Some(doc) = overlay_doc.as_ref() {
                config::overlay::merge_into(&mut effective, doc.clone());
            }
            boot_instances.check(&effective).unwrap_or_else(|error| die(error));
            // The one semantic judgement of this boot's effective configuration, made exactly as
            // construction makes it. A serving transition hands it to construction below.
            let judged = config_validate::judge_effective(&effective, &deploy.plugins)
                .unwrap_or_else(|errors| {
                    die(format!(
                        "principal transition effective configuration errors: {}",
                        errors.join("; ")
                    ))
                });
            let result = root::principal_transition::execute(
                command,
                &effective,
                &deploy.plugins,
                &anchor_store,
                &base_store_settings,
                &transition_source_sha256,
                overlay_doc.as_ref(),
            )
            .await
            .unwrap_or_else(|_| die("principal transition refused; input or bound Store state does not satisfy cold transition requirements"));
            println!(
                "{}",
                serde_json::to_string(&result.report)
                    .unwrap_or_else(|_| die("principal transition output failed"))
            );
            fresh_record_bootstrap = result.record_bootstrap;
            if !command.continues_serving() {
                return None;
            }
            // The explicit fresh-instance action resumes every ordinary admission below. The same
            // anchor is handed to appbuild; it must never be reopened as a new ephemeral namespace.
            busbar_kernel::governance::principal_transition::pending_guard_native(anchor_store.clone())
                .await
                .unwrap_or_else(|_| die("fresh principal baseline is not ready for serving"));
            if config_locked {
                overlay_path = None;
            }
            judged_effective = Some((effective, judged));
        }

        Some((
            store_admission,
            anchor_store,
            deploy,
            defs,
            providers_path,
            overlay_path,
            overlay_doc,
            base_hook_names,
            base_group_names,
            fresh_record_bootstrap,
            judged_effective,
            operator_reference,
            effective_images,
            bootstrap_ready,
        ))
    })
    .await;
    let Some((
        store_admission,
        anchor_store,
        deploy,
        defs,
        providers_path,
        overlay_path,
        overlay_doc,
        base_hook_names,
        base_group_names,
        fresh_record_bootstrap,
        judged_effective,
        operator_reference,
        effective_images,
        bootstrap_ready,
    )) = bootstrap
    else {
        return;
    };

    // Data workers are created after Store recovery, on their own runtimes. The
    // control runtime and bootstrap plugin dispatcher already exist and keep their own budgets.
    let data_workers = {
        let mut ignored_warnings = Vec::new();
        let selected = recovered_data_workers(
            deploy.advanced.worker_threads,
            worker_threads_from_env_noting("TOKIO_WORKER_THREADS", &mut ignored_warnings),
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1),
        );
        busbar_kernel::topology::set_data_workers(selected);
        selected
    };

    let deregister_delay = deploy.advanced.shutdown.deregister_delay;
    let response_headers_cfg = deploy.advanced.response_headers.clone();
    // `audit.seal_every` (SEALING-FIX §3.4): the notary's stamp cadence, validated 1-1000 ms.
    let audit_seal_every = deploy.audit.seal_every;

    busbar_kernel::router::configure_server_timing(response_headers_cfg.server_timing);

    let resolved_export = config::resolve_export_in(
        &deploy.export,
        &mut Vec::new(),
        config::ExportRead(deploy.grammar.read_context()),
    );
    snapshot::configure_telemetry(
        &deploy.telemetry,
        resolved_export
            .recorder
            .as_ref()
            .map(|p| Duration::from_secs(p.retention_seconds)),
    );
    // ADMIN-API-1.6 §3.5: what unit records keep of the end user and request headers, for the
    // life of the process.
    root::records_capture::configure(&deploy.records);

    let plugins_cfg = deploy.plugins.clone();
    root::boot::admit_recovered_plugins(&plugins_cfg)
        .await
        .unwrap_or_else(|error| die(format!("Store plugin-floor admission: {error}")));

    let swept = root::loader::sweep_dead_staging();
    if swept > 0 {
        eprintln!(
            "[info] removed {swept} orphaned plugin staging dir(s) left by a crashed prior run"
        );
    }

    // The subscriber is `main`'s, installed once before any work; nothing here installs another.

    if ignore_overlay {
        tracing::warn!(
            diag = %diagnostics::OVERLAY_IGNORED.banner(),
            "IGNORE OVERLAY: config overlay NOT merged — running on base config.yaml/providers.yaml alone \
             (the Store overlay is untouched; boot without --ignore-overlay to re-apply it)"
        );
    }

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        crypto_backend = busbar_contract::crypto::BACKEND,
        crypto_module = busbar_contract::crypto::module_version(),
        "busbar starting"
    );

    if config_locked {
        tracing::info!(
            "config is LOCKED (config.locked: true): admin-API config mutations are refused; edit \
             config.yaml and POST /config/reload to change config"
        );
    } else if let Some(p) = overlay_path.as_ref().filter(|p| p.is_ephemeral()) {
        tracing::info!(
            overlay = %p.display(),
            "config is mutable; admin-API changes are held by the in-memory Store: live changes last until restart, restart-only changes are refused (BUSBAR-8016)"
        );
    } else if let Some(p) = overlay_path.as_ref() {
        tracing::info!(
            overlay = %p.display(),
            "config is mutable; admin-API changes persist to the configured Store (restart durability follows that Store)"
        );
    }

    busbar_core_admin::mark_start();

    let provider_planes =
        root::min3_provider_plan::descriptors(&effective_images).unwrap_or_else(|error| die(error));
    let resolved = config::resolve_with_provider_planes(&deploy, &defs, &provider_planes)
        .unwrap_or_else(|errs| die_list("config errors", errs));
    let mut cfg = resolved.config;
    let provider_catalogs = resolved.catalogs;
    boot_instances
        .check(&cfg)
        .unwrap_or_else(|error| die(error));

    dest.replace(root::connector::dest_judge(&cfg));
    root::connector::install_trust_store(&cfg, true);
    root::connector::finalize_boot(
        &root::policy::client_settings(&cfg.limits),
        &cfg.own_listens(),
    )
    .unwrap_or_else(|error| die(format!("effective connector boot configuration: {error}")));

    // Semantic validation of the effective configuration runs once per boot. Ordinarily that is
    // inside the boot's one application build (`root::boot_app::BootApp`: `appbuild` ->
    // `config_validate::check_with`), after the export sinks open and before any Store
    // publication or listener. A fresh-instance transition already judged its effective
    // configuration (the same deploy, definitions and overlay) before writing its Store baseline:
    // the application is built from that judged value and consumes that one result, so neither the
    // pass nor its warnings repeat.
    let (mut cfg, judged) = match judged_effective {
        Some((effective, judged)) => (effective, Some(judged)),
        None => {
            if let Some(doc) = overlay_doc {
                config::overlay::merge_into(&mut cfg, doc);
            }
            (cfg, None)
        }
    };
    boot_instances
        .check(&cfg)
        .unwrap_or_else(|error| die(error));
    // Boot is a disk read: the built App holds config.yaml's operator definitions as the reference.
    cfg.operator_file_defs = Some(operator_reference);

    let blocked =
        config_validate::metadata_denylist_entries().len() + cfg.blocked_metadata_hosts.len();
    tracing::info!(
        "metadata protection: {blocked} hosts blocked (--print-metadata-blocklist to view)"
    );

    let req_body_max = cfg.limits.request_body_max_bytes;
    let max_inbound = cfg.limits.max_inbound_concurrent;
    let request_admission =
        busbar_kernel::limits::process_admission::ProcessAdmission::new(max_inbound);
    // STORAGE-JOIN-r2: the Node's terminal book is funded from this boot admission before any
    // plane, book, listener or recovery exists. No fallback account: refusal fails the boot.
    if let Err(why) = root::plane_node::node().bind_terminal_storage(&request_admission) {
        tracing::error!(error = why, "terminal custody storage binding failed");
        die(format!("terminal custody storage binding failed: {why}"));
    }
    use busbar_kernel::limits::process_admission::AdmissionClass;

    root::registry::check_or_exit(LINKED.claims);

    let export_config = cfg.export.clone();

    let root_rules = Arc::new(root::door_steps::Rules::with_reader(
        Some(commit_guard),
        Arc::new(config_rules),
    ));

    let listener_needs = root::door_steps::listener_needs(&cfg).unwrap_or_else(|error| die(error));
    let native_request_timeout = Duration::from_secs(cfg.limits.request_body_read_timeout_secs);
    let native_handshake_timeout = Duration::from_secs(cfg.limits.tls_handshake_timeout_secs);
    // Root policy: the configured upstream response budget also bounds active native
    // output; the runtime keeps that deadline absolute through partial writes.
    let native_write_timeout = Duration::from_secs(cfg.limits.upstream_request_timeout_secs);

    let record_bootstrap_store = serde_json::to_value(
        cfg.store
            .as_ref()
            .map(|store| store.authoring(&authoring_seal)),
    )
    .unwrap_or_else(|error| die(format!("effective Store settings: {error}")));
    let boot_store = if serde_json::to_value(
        cfg.store
            .as_ref()
            .map(|store| store.authoring(&authoring_seal)),
    )
    .unwrap_or_else(|error| die(format!("effective Store settings: {error}")))
        == base_store_settings
    {
        Some(anchor_store)
    } else {
        if principal_transition
            .as_ref()
            .is_some_and(root::principal_transition::Command::continues_serving)
        {
            die("fresh principal initialization lost its bootstrap Store binding");
        }
        die(
            "recovered configuration changes the admitted Store; use an explicit Store migration and update the bootstrap Store binding before serving",
        )
    };

    let _boot_store_binding = boot_store;
    let native_bootstrap_sources = bootstrap_ready.sources();
    let serving_ready = root::min3_boot::prepare_serving(
        bootstrap_ready,
        &plugin_process,
        effective_images,
        &cfg,
        &provider_catalogs,
        root::connector::dest_judge(&cfg).guard().clone(),
    )
    .await
    .unwrap_or_else(|error| die(error));
    let preparation = root::boot_app::Preparation {
        secret_resolver: serving_ready.resolver(),
        startup: store_admission,
        config: cfg,
        judged,
        plugins: plugins_cfg,
        overlay: overlay_path,
        deploy,
        definitions: defs,
        base_hook_names,
        base_group_names,
        config_path: config_path.clone(),
        providers_path: providers_path.clone(),
        providers_override: providers_override.clone(),
        rules: root_rules.clone(),
        shutdown_rx: control_work.shutdown_rx.clone(),
        shutdown_tx: control_work.shutdown_tx.clone(),
    };
    // The boot's one App, built over the store admission it holds: the MIN-3 walk's, or the old ABI's
    // current dataset (until #274).
    let boot_app = root::boot_app::BootApp::new(preparation);
    loop {
        if *control_work.shutdown_rx.borrow() {
            die("shutdown requested during startup validation");
        }
        if boot_app
            .readiness()
            .await
            .unwrap_or_else(|error| die(error))
            .is_some()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let ready = loop {
        if *control_work.shutdown_rx.borrow() {
            die("shutdown requested before startup publication");
        }
        if let Some(candidate) = boot_app.take().await.unwrap_or_else(|error| die(error)) {
            break candidate;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    };
    // Migrate-on-boot step 5 (MIGRATE-ON-BOOT r42 §3): every instance has opened, and nothing
    // serves or produces yet. An upgraded config.yaml is written in place now. The boot then closes
    // every instance it owns (the App and each instance it opened, the core store and its
    // admission, the node book and its lease task, an old ABI store's prepared session), so no
    // instance's descriptor reaches the new image, and re-executes onto the stamped file. A stamped
    // boot passes straight through, with every owner kept as before.
    if let Some(written) = root::migrate::finish(Some(ready.core.clone()))
        .await
        .unwrap_or_else(|error| die(error))
    {
        let owners = (ready, boot_app, _boot_store_binding);
        die(root::migrate::restart(
            written,
            owners,
            // Nothing is cancelled (R16): dropping the lease task's handle leaves it running until
            // the exec replaces this image a moment later.
            drop,
            root::migrate::reexec,
        ));
    }
    let root::boot_app::ReadyCandidate {
        startup: store_admission,
        app,
        book,
        limits: boot_limits,
        node_lease_task,
        ..
    } = ready;
    root::plane_node::node().bind_book(Arc::clone(&book.durability));
    // Native DATA audit r2: Node receives original signed pages before any native admission;
    // without the original notary binding the process refuses readiness before effects.
    root::plane_node::node()
        .bind_native_notary()
        .unwrap_or_else(|error| die(format!("native DATA audit custody: {error}")));
    root::plane_node::node()
        .bind_response_intents(
            store_admission
                .store()
                .unwrap_or_else(|| die("response intent has no admitted Store")),
            book.response_intents
                .as_ref()
                .cloned()
                .unwrap_or_else(|| die("response intent service was not constructed")),
        )
        .unwrap_or_else(|error| die(error));
    let book = Some(book);
    // The same durably confirmed generation becomes live before any producer starts.
    boot_limits.keep().notify();

    let services = root::serve::compose(
        dest.clone(),
        &app,
        store_admission
            .store()
            .unwrap_or_else(|| die("S7 has no admitted Store")),
    );

    // Explicit same-open ephemeral initialization uses its newly committed principal baseline
    // as a real Store witness. It follows exactly the ordinary receipt consumer before admission.
    if let Some(receipt) = fresh_record_bootstrap {
        if std::env::var_os(busbar_kernel::host_record_bootstrap::RECEIPT_ENV).is_some() {
            die("fresh record bootstrap and a cold receipt file are mutually exclusive");
        }
        let fingerprint =
            busbar_kernel::host_record_bootstrap::store_fingerprint(&record_bootstrap_store);
        let kernel = services
            .kernel()
            .unwrap_or_else(|| die("record bootstrap has no installed kernel"));
        kernel
            .arm_record_bootstrap(receipt, &fingerprint, |schema, key, value| {
                root::boot::bootstrap_witness(schema, key, value)
            })
            .await
            .unwrap_or_else(|error| die(format!("fresh record bootstrap refused: {error}")));
    }

    // Only the process operator can provide this cold-start receipt. Reload never reads it.
    // Consumption is durable in the attached store and must finish before any plane admission.
    if let Some(path) = std::env::var_os(busbar_kernel::host_record_bootstrap::RECEIPT_ENV) {
        let fingerprint =
            busbar_kernel::host_record_bootstrap::store_fingerprint(&record_bootstrap_store);
        let kernel = services
            .kernel()
            .unwrap_or_else(|| die("record bootstrap has no installed kernel"));
        let receipt = tokio::task::spawn_blocking(
            move || -> Result<busbar_kernel::host_record_bootstrap::ColdRecordReceipt, String> {
                use std::io::Read;
                let file = std::fs::File::open(path)
                    .map_err(|error| format!("read cold record bootstrap receipt: {error}"))?;
                let mut bytes = Vec::new();
                file.take(16_385)
                    .read_to_end(&mut bytes)
                    .map_err(|error| format!("read cold record bootstrap receipt: {error}"))?;
                if bytes.len() > 16_384 {
                    return Err("cold record bootstrap receipt exceeds 16384 bytes".into());
                }
                serde_json::from_slice(&bytes)
                    .map_err(|error| format!("parse cold record bootstrap receipt: {error}"))
            },
        )
        .await
        .unwrap_or_else(|error| die(format!("cold record bootstrap failed: {error}")));
        let receipt =
            receipt.unwrap_or_else(|error| die(format!("cold record bootstrap refused: {error}")));
        kernel
            .arm_record_bootstrap(receipt, &fingerprint, |schema, key, value| {
                root::boot::bootstrap_witness(schema, key, value)
            })
            .await
            .unwrap_or_else(|error| die(format!("cold record bootstrap refused: {error}")));
    }

    let observation_reservation = export_observers
        .reserve(serving_ready.export_names())
        .unwrap_or_else(|error| die(error));
    let (store_admission, mut generation_workers, exports, native, selected_policy) =
        root::min3_boot::finish(
            serving_ready,
            store_admission,
            services.kernel(),
            busbar_kernel::plane_driver::port_work::governed_binder(
                app.governance.clone(),
                app.role_bindings.clone(),
            ),
            Some(root::min3_boot::ServingEnvironment::new(&app)),
            &observation_reservation,
        )
        .await
        .unwrap_or_else(|error| die(error));

    let listener_plan = Arc::new(
        root::min3_listener_plan::NativeListenerPlan::new(listener_needs, &native.framers)
            .unwrap_or_else(|error| die(error)),
    );

    let export_registry = export::plugin::open_prepared(
        &export_config,
        &exports.calls(),
        Arc::clone(&app.amendments),
    )
    .unwrap_or_else(|error| die_list("config errors", [error]));
    let mut app = Arc::unwrap_or_clone(app);
    selected_policy
        .install_initial(&mut app)
        .unwrap_or_else(|error| die(error));
    app.secret_resolver = Arc::clone(&native.resolver);
    let auth_epoch = app
        .config_generation
        .load(std::sync::atomic::Ordering::Acquire);
    root::min3_admin_auth::install(&mut app, Arc::clone(&native.auth), auth_epoch)
        .unwrap_or_else(|error| die(error));
    let app = Arc::new(
        export::plugin::assemble_routes(app, &export_config, native.seats.clone(), export_registry)
            .unwrap_or_else(|error| die_list("config errors", [error])),
    );

    // The native seats this generation serves, their billing and the node's posting site.
    let served = root::serve::compose_native(
        Arc::clone(&native),
        app.governance.clone(),
        &app.serve_tables,
    );
    let native_candidates = root::min3_candidate::Factory::new(
        Arc::clone(&plugin_process),
        native_bootstrap_sources,
        store_admission
            .store()
            .unwrap_or_else(|| die("native candidate factory has no admitted Store")),
        &native,
        Arc::clone(&listener_plan),
        root::plane_node::node(),
        Arc::clone(&export_observers),
    );
    let root_rules = Arc::new(
        root_rules
            .with_native_listeners(Arc::clone(&listener_plan))
            .with_native_candidate(native_candidates),
    );
    let mut app = Arc::unwrap_or_clone(app);
    app.root_rules = root_rules.clone();
    let owners = root::min3_physical::SlotOwners {
        auth: Arc::clone(&native.auth),
        epoch: auth_epoch,
        inventories: Arc::clone(&native.inventories),
        keys: root::plane_node::node().kernel_and_keys().1,
        core: root::min3_listener_plan::core_lines(&app, &served).into(),
    };
    // THE ADMIN PLANE'S ORDER (deletion plan E5): the auth instances opened in `min3_boot::finish`
    // (admin-tokens among them), the admin chain installed above (`min3_admin_auth::install`), and
    // only now the listener slots assembled over that chain. Nothing binds until the end of `run`.
    let slots = listener_plan
        .assemble(&app, &served, &owners)
        .unwrap_or_else(|error| die(error));
    root::serve::install_native_slots(&mut app, slots).unwrap_or_else(|error| die(error));
    root::min3_candidate::install_initial(&mut app, Arc::clone(&native), Arc::clone(&services))
        .unwrap_or_else(|error| die(error));
    let app = Arc::new(app);

    tracing::info!(
        "reliability state (breakers, cooldowns, latency, hard-down) starts fresh on boot and is \
         re-learned from live traffic"
    );

    let tls_secret_resolver = app.secret_resolver.clone();

    let recovery_served = served.clone();

    let mut served = served;
    let line_served = line_serve_requested(root::cli::argv()).then(|| std::mem::take(&mut served));

    drop(served);
    let (admin_trust_decide, admin_trust_read) = root::serve::admin_trust(&services);
    let app_handle =
        Arc::new(busbar_kernel::state::AppHandle::new(app).with_trust(admin_trust_read));
    // Publication owns every reserved observer through producer shutdown. Failed construction
    // above drops the uncommitted reservation and returns its unused capacity.
    let _export_generation = observation_reservation.commit();
    // Reload carries this exact owner, including captures accepted by a retiring App.
    let export_captures = Arc::clone(&app_handle.load().exports);
    services.prepare_workers(&mut generation_workers);
    let probes = Arc::new(busbar_kernel::endpoints::ProbeState::new(
        book.as_ref().map(|book| book.runtime_journal.clone()),
    ));
    let admin_router = busbar_kernel::router::build_admin_router_on_with_dispatch_layer(
        &app_handle,
        req_body_max,
        response_headers_cfg.server_timing,
        root::listener::deferred_dispatch_layer,
    )
    .layer(axum::Extension(probes.clone()));
    export::plugin::publish_observers(&app_handle.load()).unwrap_or_else(|e| die(e));
    if let Some(publisher) = trace_publisher {
        publisher
            .publish(Arc::clone(&app_handle.load().exports))
            .unwrap_or_else(|e| die(e));
    }
    // Start serving maintenance only after the physical routes and application owner exist.
    recovery_served.spawn_ticks();
    export::plugin::start(&app_handle.load().exports)
        .unwrap_or_else(|e| die_list("config errors", [e]));
    let export_observer_retry = root::shutdown::ExportRetry::start(Arc::clone(&export_observers));
    exports.start().unwrap_or_else(|error| die(error));
    let on_host = LINKED.on_host;
    let boot_host =
        (!on_host.is_empty()).then(|| busbar_kernel::plane_driver::engine_host(&app_handle.load()));
    if let Some(host) = &boot_host {
        for spawn in on_host {
            spawn(host);
        }
    }
    let generation_workers =
        root::min3_candidate::Workers::start(&app_handle.load(), generation_workers)
            .unwrap_or_else(|error| die(error));
    generation_workers.bind(&app_handle);

    #[cfg(distribution_root)]
    if let Some(book) = &book {
        let ctx = root::linked::BookCtx {
            book,
            #[cfg(test)]
            app: &app_handle.load(),
        };
        for step in ROOT_UNITS.iter().filter_map(|u| u.on_book) {
            step(&ctx);
        }
    }

    let admin_router = match &book {
        Some(book) => root::units_admin::mount_node(
            admin_router,
            req_body_max,
            &app_handle,
            app_handle
                .load()
                .governance
                .as_ref()
                .expect("governance for admin")
                .core_store_handle()
                .unwrap_or_else(|error| die(error)),
            book,
            None,
            admin_trust_decide,
            root::adapters::BreakerPolicy::new(),
        )
        .unwrap_or_else(|error| die(format!("admin persistence admission refused: {error:?}"))),
        None => admin_router,
    };

    if let Some(host) = boot_host {
        app_handle.set_snapshot_host(host);
    }

    if let Some(&spawn) = on_host.first() {
        app_handle.attach_on_swap(spawn);
    }

    // The fixed drain starts after operator deregistration; Safety and Force bypass it.
    let drain_clock = busbar_kernel::governance::drain::DrainClock::new(
        busbar_kernel::governance::drain::DRAIN_TIMEOUT,
    );
    let drain = root::shutdown::ShutdownDrain::new(Arc::clone(&drain_clock));
    let (shutdown_tx, _keep_open) = tokio::sync::broadcast::channel::<()>(1);
    let (worker_shutdown_tx, worker_shutdown_rx) = tokio::sync::watch::channel(false);
    // Keep persistence's safety input distinct from the delayed listener/data-worker stop level.
    let shutdown_request = drain.start_deregister(
        deregister_delay,
        probes.clone(),
        root::shutdown::ShutdownSignals {
            safety: control_work.shutdown_rx.clone(),
            support: control_work.shutdown_tx.clone(),
            workers: worker_shutdown_tx,
            listeners: shutdown_tx.clone(),
        },
    );
    busbar_kernel::detached::set_worker_shutdown(worker_shutdown_rx.clone());
    let line_shutdown = line_served.as_ref().map(|_| shutdown_tx.subscribe());
    busbar_core_admin::restart::publish_shutdown(shutdown_request.clone());
    {
        tokio::spawn(async move {
            use busbar_kernel::governance::drain::ShutdownIntent;
            shutdown_signal().await;
            shutdown_request.request(ShutdownIntent::Operator);
            shutdown_signal().await;
            tracing::warn!("second shutdown signal: the drain deadline is now");
            shutdown_request.request(ShutdownIntent::Force);
        });
    }
    // The listener's handler drains on a signal from here on.
    let _ = signal_handoff.send(());

    // Governed admission keeps its fixed terminal-backlog cap
    // (`governance::drain::MAX_PENDING_CHECKPOINTS`), set when the gate is built.
    let governance = app_handle.load().governance.clone();
    let budget_flusher = governance.clone().map(|gov| {
        tokio::spawn(busbar_kernel::governance::run_budget_flusher(
            gov,
            shutdown_tx.subscribe(),
            Some(app_handle.clone()),
            Some(Arc::clone(&drain_clock)),
        ))
    });
    let work_recovery = recovery_served.spawn_work_recovery(
        app_handle.clone(),
        Arc::clone(&request_admission),
        shutdown_tx.subscribe(),
    );
    drop(recovery_served);

    busbar_kernel::boot::start_planes(&app_handle).unwrap_or_else(|e| die(e));
    let predecessor = spawn_predecessor_task(
        governance.as_ref(),
        book.as_ref(),
        control_work.shutdown_rx.clone(),
    );
    // SEALING-FIX §3.3: the audit notary, after `Ready`, on this control runtime.
    if let Some((book, audit)) = book
        .as_ref()
        .and_then(|book| book.audit.as_ref().map(|audit| (book, audit)))
    {
        // SEALING-FIX §3.9 floor (b): an Ephemeral journal's cut never passes the oldest audit
        // line a checkpoint in custody names. Weak: governance owns the book's sinks.
        let floor = governance.as_ref().map(|gov| {
            let gov = Arc::downgrade(gov);
            Arc::new(move || gov.upgrade().and_then(|gov| gov.oldest_unit_audit_seq()))
                as root::durability::notary::FloorHints
        });
        audit.start_notary(
            audit_seal_every,
            Arc::clone(&drain_clock),
            floor,
            Arc::clone(&book.durability),
        );
    }

    let mut threads: Vec<std::thread::JoinHandle<()>> = Vec::new();
    let mut admin: Option<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + '_>>> = None;
    let mut lines: Option<std::pin::Pin<Box<dyn std::future::Future<Output = i32>>>> = None;
    if let Some(served) = line_served {
        let stop = recv_shutdown(line_shutdown.unwrap_or_else(|| shutdown_tx.subscribe()));
        lines = Some(Box::pin(root::serve::lines::serve_lines(
            served,
            app_handle.clone(),
            Arc::clone(&request_admission),
            stop,
        )));
    } else {
        // Validate every physical factory before any worker starts accepting sockets.
        let mut native_listeners = Vec::with_capacity(listener_plan.binds().len());
        for bind in listener_plan.binds() {
            let supplier = listener_plan
                .supplier(&bind.at)
                .unwrap_or_else(|| die("native listener supplier disappeared"));
            let class = match bind.at.as_str() {
                "listen" => AdmissionClass::Data,
                "admin_listen" => AdmissionClass::Operator,
                _ => die("unsupported native listener slot"),
            };
            let native_alpn = supplier
                .port
                .alpn(busbar_plugin_abi::transport::ROLE_SERVER)
                .to_vec();
            let native = Arc::new(
                root::listener_native::NativeListener::new(
                    Arc::clone(&app_handle),
                    bind.at.clone().into_boxed_str(),
                    Arc::clone(&supplier.port),
                    root::listener_native::NativeAdmission {
                        budget: Arc::clone(&request_admission),
                        class,
                    },
                    Arc::new(root::serve::native_slot),
                    root::listener_native::NativeLimits {
                        max_connections: native_bind_limits(
                            bind.max_conns,
                            native_handshake_timeout,
                        )
                        .max_conns,
                        body_bytes: req_body_max,
                        stall_ms: None,
                        handshake_timeout: native_handshake_timeout,
                        request_timeout: native_request_timeout,
                        write_timeout: native_write_timeout,
                        // Shutdown may shorten the existing output deadline, never restart it.
                        drain_grace: busbar_kernel::detached::DETACHED_DRAIN_GRACE,
                    },
                    (bind.at == "admin_listen").then(|| admin_router.clone()),
                )
                .unwrap_or_else(|error| die(format!("native listener {}: {error:?}", bind.at))),
            );
            native_listeners.push((bind, native, native_alpn));
        }
        for (bind, native, native_alpn) in native_listeners {
            let addr = bind.listen.to_string();
            #[cfg(unix)]
            let limits = native_bind_limits(bind.max_conns, native_handshake_timeout);
            if bind.at == "admin_listen" {
                #[cfg(unix)]
                let listener = Listening::bind_stream(
                    root::connector::the().address_via().as_ref(),
                    &addr,
                    limits,
                )
                .unwrap_or_else(|error| die(format!("cannot bind {addr}: {error}")));
                #[cfg(not(unix))]
                let listener = root::listener::SocketAdmits::new(bind_listener(&addr).await);
                admin = Some(Box::pin(serve_listener(
                    listener,
                    native,
                    root::plane_node::node(),
                    native_alpn,
                    bind.tls.clone(),
                    Arc::clone(&tls_secret_resolver),
                    addr,
                    recv_shutdown(shutdown_tx.subscribe()),
                    None,
                    true,
                )));
            } else {
                #[cfg(unix)]
                threads.extend(serve_thread_per_core(
                    data_workers,
                    addr.clone(),
                    addr,
                    limits,
                    native,
                    native_alpn,
                    bind.tls.clone(),
                    Arc::clone(&tls_secret_resolver),
                    &shutdown_tx,
                    worker_shutdown_rx.clone(),
                ));
                #[cfg(not(unix))]
                {
                    let resolver = Arc::clone(&tls_secret_resolver);
                    let tls = bind.tls.clone();
                    let shutdown = shutdown_tx.subscribe();
                    threads.push(spawn_multithread_data(
                        data_workers,
                        worker_shutdown_rx.clone(),
                        async move {
                            let listener =
                                root::listener::SocketAdmits::new(bind_listener(&addr).await);
                            serve_listener(
                                listener,
                                native,
                                root::plane_node::node(),
                                native_alpn,
                                tls,
                                resolver,
                                addr,
                                recv_shutdown(shutdown),
                                None,
                                true,
                            )
                            .await;
                        },
                    ));
                }
            }
        }
    }

    let post = root::shutdown::PostServe {
        admin,
        lines,
        threads,
        work_recovery,
        generation_workers,
        exports,
        export_observers,
        export_observer_retry,
        export_captures,
        control_drain: Box::pin(control_work.drain()),
        node_lease: node_lease_task,
        flusher: budget_flusher,
        governance,
        late: Arc::clone(&services),
        book,
        startup: store_admission,
        predecessor,
    };
    let code = root::shutdown::finish(post, &drain).await;
    root::exit::exit(code);
}

/// The start-up predecessor task, after `Ready`, in the background and never on the request path:
/// it seals the crash tails of this host's dead predecessors (SEALING-FIX §3.6.2), then closes
/// writers whose lease expired at least one TTL ago, on any host, and records those that never
/// retired (SHUTDOWN-HANG F5). `stop` (the first shutdown broadcast) ends it at a step boundary;
/// the drain joins it and settles its fence in the seal phase.
fn spawn_predecessor_task(
    gov: Option<&Arc<busbar_kernel::governance::GovState>>,
    book: Option<&root::durability::NodeBook>,
    stop: tokio::sync::watch::Receiver<bool>,
) -> Option<(
    tokio::task::JoinHandle<()>,
    Arc<busbar_kernel::persistence::boot_identity::PredecessorFence>,
)> {
    let core = gov?.core_store_handle().ok()?;
    let host = root::durability::host_identity();
    let fence = match busbar_kernel::persistence::boot_identity::PredecessorFence::new(core, &host)
    {
        Ok(fence) => fence,
        Err(error) => {
            tracing::info!(%error, "the start-up predecessor task did not start; the next start retries");
            return None;
        }
    };
    let sealing = book
        .and_then(|book| book.audit.as_ref())
        .and_then(|audit| audit.take_predecessor());
    let book = book.map(|book| Arc::clone(&book.durability));
    let task = Arc::clone(&fence);
    let handle = tokio::spawn(async move {
        root::durability::predecessor::run(task, sealing, book, stop).await;
    });
    Some((handle, fence))
}

async fn refresh_node_lease(
    lease: Arc<busbar_kernel::persistence::boot_identity::NodeLease>,
    mut stop: tokio::sync::watch::Receiver<bool>,
    failure: tokio::sync::watch::Sender<bool>,
) -> Result<(), String> {
    let every = Duration::from_millis(busbar_kernel::persistence::boot_identity::LEASE_TTL_MS / 3);
    let mut ticks = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            biased;
            _ = stop.wait_for(|stopping| *stopping) => return Ok(()),
            _ = ticks.tick() => {}
        }
        let result = tokio::select! {
            biased;
            _ = stop.wait_for(|stopping| *stopping) => return Ok(()),
            result = tokio::time::timeout(every, lease.refresh()) => result,
        };
        let error = match result {
            Ok(Ok(true)) => continue,
            Ok(Ok(false)) => "native node lease no longer belongs to this writer".to_owned(),
            Ok(Err(error)) => format!("native node lease refresh refused: {error}"),
            Err(_) => "native node lease refresh remains unconfirmed".to_owned(),
        };
        let _ = failure.send(true);
        return Err(error);
    }
}

const ROOT_BIND_LIMITS: AcceptLimits = AcceptLimits {
    max_conns: busbar_core_connector::listen::DEFAULT_MAX_CONNS,
    handshake_timeout: busbar_core_connector::listen::DEFAULT_HANDSHAKE_TIMEOUT,
};

fn native_bind_limits(max_conns: u64, handshake_timeout: Duration) -> AcceptLimits {
    AcceptLimits {
        // Root bind declarations use u64::MAX as their unspecified cap. Preserve the
        // connector's physical bound instead of turning that declaration into unlimited IO.
        max_conns: usize::try_from(max_conns)
            .unwrap_or(usize::MAX)
            .min(ROOT_BIND_LIMITS.max_conns),
        handshake_timeout,
    }
}

#[cfg(not(unix))]
async fn bind_listener(addr: &str) -> tokio::net::TcpListener {
    tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| die(format!("cannot bind listen address '{addr}': {e}")))
}

async fn recv_shutdown(mut rx: tokio::sync::broadcast::Receiver<()>) {
    let level = busbar_kernel::detached::worker_shutdown();
    tokio::select! {
        _ = rx.recv() => {},
        () = busbar_kernel::detached::shutdown_fired(level) => {},
    }
}

/// Keep bootstrap services alive on the control runtime while the recovered data budget owns
/// a separate scheduler. All scheduler and blocking threads share custody because tasks may
/// migrate between them. Unlike pinned Unix workers, these threads have no stable worker id.
#[cfg(any(not(unix), test))]
fn spawn_multithread_data(
    workers: usize,
    shutdown: tokio::sync::watch::Receiver<bool>,
    serve: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("busbar-data-runtime".into())
        .spawn(move || {
            let detached = busbar_kernel::detached::DetachedTasks::new();
            let worker_detached = detached.clone();
            let runtime = busbar_kernel::rt::multi_thread()
                .worker_threads(workers)
                .thread_name("busbar-data")
                .on_thread_start(move || {
                    busbar_kernel::detached::set_worker_detached(worker_detached.clone());
                    busbar_kernel::detached::set_worker_shutdown(shutdown.clone());
                })
                .enable_all()
                .build()
                .unwrap_or_else(|e| die(format!("failed to build data runtime: {e}")));
            runtime
                .block_on(runtime.spawn(async move {
                    serve.await;
                    let _ = tokio::time::timeout(
                        busbar_kernel::detached::DETACHED_DRAIN_GRACE,
                        detached.drained(),
                    )
                    .await;
                }))
                .expect("data listener task panicked");
            // The owning OS thread drops the runtime only after listener and detached drain.
        })
        .unwrap_or_else(|e| die(format!("cannot spawn data runtime thread: {e}")))
}

#[cfg(unix)]
fn serve_thread_per_core(
    n: usize,
    addr: String,

    bind_at: String,
    limits: AcceptLimits,
    native: Arc<root::listener_native::NativeListener>,
    alpn: Vec<Box<str>>,
    tls_cfg: Option<busbar_kernel::config::sections::TlsCfg>,
    secret_resolver: Arc<busbar_kernel::config::secret::SecretResolver>,
    shutdown_tx: &tokio::sync::broadcast::Sender<()>,
    worker_shutdown: tokio::sync::watch::Receiver<bool>,
) -> Vec<std::thread::JoinHandle<()>> {
    if tls_cfg.is_some() {
        let protocols: Vec<_> = alpn.iter().map(|value| value.as_bytes()).collect();
        let _ = busbar_core_connector::tls::prepare_for_alpn(
            &addr,
            tls_cfg.as_ref(),
            &secret_resolver,
            true,
            &protocols,
        )
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
        let native = Arc::clone(&native);
        let alpn = alpn.clone();
        let tls = tls_cfg.clone();
        let resolver = secret_resolver.clone();
        let listen = addr.clone();
        let shutdown_rx = shutdown_tx.subscribe();
        let worker_shutdown = worker_shutdown.clone();
        let balancer = balancers[i].take();
        let bind_at = bind_at.clone();
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
                let rt = busbar_kernel::rt::current_thread()
                    .enable_all()
                    .build()
                    .unwrap_or_else(|e| {
                        die(format!("failed to build per-core data runtime {i}: {e}"))
                    });
                rt.block_on(async move {
                    let via = crate::root::connector::the().address_via();
                    let listener = Listening::bind_stream(via.as_ref(), &bind_at, limits)
                        .unwrap_or_else(|e| {
                            die(format!(
                                "cannot bind SO_REUSEPORT data listener on '{listen}' (per-core \
                             runtime {i}): {e}"
                            ))
                        });
                    tracing::debug!(listen = %listen, "data listener bound through the connector");
                    serve_listener(
                        listener,
                        native,
                        root::plane_node::node(),
                        alpn,
                        tls,
                        resolver,
                        listen,
                        recv_shutdown(shutdown_rx),
                        balancer,
                        i == 0,
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

async fn serve_listener(
    listener: impl busbar_core_connector::listen::Admits,
    native: Arc<root::listener_native::NativeListener>,
    node: Arc<root::plane_node::Node>,
    alpn: Vec<Box<str>>,
    tls_cfg: Option<busbar_kernel::config::sections::TlsCfg>,
    secret_resolver: Arc<busbar_kernel::config::secret::SecretResolver>,
    label: String,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,

    balancer: Option<root::listener::ConnBalancer>,

    log_at_info: bool,
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
            let protocols: Vec<_> = alpn.iter().map(|value| value.as_bytes()).collect();
            let security = busbar_core_connector::tls::prepare_for_alpn(
                &label,
                Some(&tls),
                &secret_resolver,
                true,
                &protocols,
            )
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
    let result =
        root::listener_native::serve_admitted(listener, native, security, node, shutdown, balancer)
            .await;
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
    tracing::info!("shutdown signal received");
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

#[cfg(test)]
#[path = "../../busbar-contract/tests/source_rules/escapes.rs"]
mod source_escapes;

#[cfg(test)]
#[path = "tests/generated_escapes.rs"]
mod generated_escapes;

#[cfg(all(test, distribution_root))]
#[path = "../../../dist/default/tests/common/root_install.rs"]
mod dist_root_install;

#[cfg(all(test, distribution_root))]
#[path = "tests/distribution.rs"]
mod distribution;

#[cfg(all(test, unix))]
#[test]
fn root_listeners_keep_the_connector_connection_bound() {
    assert_eq!(
        ROOT_BIND_LIMITS.max_conns,
        busbar_core_connector::listen::DEFAULT_MAX_CONNS,
        "root data and admin binds must not disable connection admission"
    );
    assert_eq!(
        native_bind_limits(u64::MAX, ROOT_BIND_LIMITS.handshake_timeout).max_conns,
        busbar_core_connector::listen::DEFAULT_MAX_CONNS,
        "native root declarations must retain the connector connection admission bound"
    );
    assert_eq!(
        native_bind_limits(1, ROOT_BIND_LIMITS.handshake_timeout).max_conns,
        1,
        "a stricter declared connection cap must remain effective"
    );
}
