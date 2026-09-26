// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//
// busbar — the composition root binary. It is the one place that names every wire, every
// compiled-in plane, and every unit the kernel runs, and wires them together at boot; see
// `src/root/mod.rs` for the three-axis shape (wire / plane / unit) this crate composes.
//
// The protocol, routing, and plane-specific behavior this binary boots are each owned by their own
// crate (the engine core and the individual plane crates) and are not this file's concern — see the
// linked crates' own docs and the README for what a running deployment answers on the wire and the
// `--help` output above for the CLI surface this binary exposes.
//
// See `register_protocols`/`register_planes`/`register_diagnostics`/`register_ws_arrivals` below
// for the composition root's one write into each axis: each linked crate contributes its own
// declarations here, under its own Cargo feature, and nowhere else.

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

// `preflight_plugins_and_secrets`, `validate_builtin_secrets_resolve`, `DEFAULT_CONFIG_PATH` and
// `ENV_PROVIDERS` left with the flag surface (`root::cli`): the first two are what `--validate`
// checks without booting, and the last two are the config/providers path precedence the scanners
// there answer for boot AND for every command.
use busbar_kernel::{
    build_app_from_config, build_split_routers_with_limits, load_config_from_disk, LoadedConfig,
    ENV_CONFIG,
};
use busbar_kernel::{config, config_validate, export, metrics, tls};
// Read only by the jemalloc idle-purge fallback below, which is itself
// `#[cfg(not(target_env = "msvc"))]` — windows-msvc has no jemalloc, so importing this
// unconditionally is an unused-import error there under `-D warnings`.
#[cfg(not(target_env = "msvc"))]
use busbar_kernel::REQUEST_ACTIVITY_TICKS;

/// THE BUILD-PROVENANCE STAMP, as one machine-parseable line. Every field is baked at compile time
/// by `build.rs` (see its header for what cargo does and does not expose) EXCEPT `debug-assertions`,
/// which is read here at runtime via `cfg!(debug_assertions)` — the profile it was compiled with is
/// the only reliable source for that bit.
///
/// This is the piece that would have PREVENTED the ~20% "regression" incident: a non-PGO or
/// non-release build self-reports `pgo=false` / `profile=debug` instead of masquerading as a code
/// regression. CI asserts these values (the build-provenance gate), so a mis-built binary can neither
/// be misdiagnosed nor shipped green. Format is `key=value` space-separated, stable for grep/awk.
pub(crate) fn build_info_line() -> String {
    format!(
        "profile={profile} opt-level={opt} lto={lto} debug-assertions={da} pgo={pgo} \
         target={target} target-cpu={cpu} target-features={features}",
        profile = env!("BUSBAR_BUILD_PROFILE"),
        opt = env!("BUSBAR_BUILD_OPT_LEVEL"),
        lto = env!("BUSBAR_BUILD_LTO"),
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

/// Print a clean startup error to stderr and exit non-zero. Used for misconfiguration and other
/// boot-time failures so the operator sees a one-line message instead of a Rust panic backtrace.
fn die(msg: impl std::fmt::Display) -> ! {
    eprintln!(
        "[error] {}: {msg}",
        busbar_substrate_values::diagnostics::BOOT_FATAL_ERROR.banner()
    );
    std::process::exit(1);
}

/// Whether `--safe-mode` was passed: quarantines the persisted overlay entirely (both
/// `validate_config_command` and `run()` read this the same way, so it's factored once here rather
/// than duplicated). Takes the arg iterator as a parameter (instead of calling `std::env::args()`
/// itself) so it's unit-testable against a synthetic arg list.
fn safe_mode_requested(mut args: impl Iterator<Item = String>) -> bool {
    args.any(|a| a == "--safe-mode")
}

/// Whether `--mcp-stdio` was passed: boot everything, bind NOTHING, and serve the MCP plane on the
/// process's own stdin/stdout (see `mcp::stdio_serve`). A scanner like `safe_mode_requested`
/// rather than a `handle_cli_flags` exit arm, because it modifies how `run()` serves rather than
/// replacing the run.
fn stdio_serve_requested(mut args: impl Iterator<Item = String>) -> bool {
    args.any(|a| a == "--mcp-stdio") // noun-neutrality: frozen-literal pinned-by=crates/busbar/tests/mcp_stdio_serve.rs operator CLI flag (CHANGELOG 1.6.0)
}

/// Cap on `advanced.worker_threads`/`TOKIO_WORKER_THREADS` (see the `.min(MAX_WORKER_THREADS)` call in
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
                    "[warn] {code}: {name}={v:?} is not a positive integer; ignoring it and using \
                     the default worker-thread count",
                    code = busbar_substrate_values::diagnostics::WORKER_THREADS_INVALID.banner()
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
    let config_path = root::cli::resolve_config_path(root::cli::config_path_flag().as_deref());
    let raw = std::fs::read_to_string(&config_path).ok()?;
    let mut unset = Vec::new();
    let interpolated =
        config::interpolate_env_with(&raw, config::EnvSubst::Lenient, &mut unset).ok()?;
    let deploy: config::DeployCfg = config::deploy_from_yaml_str(&interpolated).ok()?;
    match validate_worker_threads_config(deploy.advanced.worker_threads) {
        Ok(v) => v,
        Err(msg) => {
            // Consistency with `worker_threads_from_env`, which WARNS on an invalid value rather than
            // silently dropping it. Pre-tracing (`main()` runs this before the subscriber is built), so
            // it goes to STDERR like the other boot diagnostics.
            eprintln!(
                "[warn] {}: {msg}",
                busbar_substrate_values::diagnostics::WORKER_THREADS_INVALID.banner()
            );
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

// THE LINKED TABLES. `build.rs` emits them from `Cargo.toml` — `[package.metadata.busbar.linked]`
// (cargo feature → plugin crate), `linked-axes` (crate → the registration axes it fills),
// `linked-entry` and `root-units` (cargo feature → root module) — as `extern crate <crate> as _;` per
// ENABLED feature, `LINKED` (one table per registration axis over each linked crate's `linked` entry
// module, in manifest order), a `linked_*` cfg per root-bound seam an enabled entry drives, and
// `ROOT_UNITS` (each enabled root module's `ROOT_UNIT`). This file names no plugin: which plugins a
// build carries is data in the manifest, and a build with a feature off has no row for it, so every
// axis below gets nothing from it — the deletion build (`--no-default-features`, or default minus one
// feature) drops the crate edge and the registration together, exactly as the feature-gated line per
// crate this replaced did.
include!(concat!(env!("OUT_DIR"), "/linked.rs"));

/// REGISTER THE LINKED PROTOCOLS — the composition root's one write into the protocol axis, over
/// every entry in [`LINKED`] (see [`root::linked::register_protocols`]).
///
/// THE ORDER IS OPERATOR-VISIBLE. `merged_boot_decls` folds this set AHEAD of whatever built-in
/// declarations core still carries, and the resulting sequence is both the "must be one of:" tail on
/// a bad `protocol:` and the list `telemetry` indexes its per-protocol metric families by POSITION
/// in. The set is the table's order, which is the manifest's: appending a row keeps every existing
/// index; inserting one renumbers them.
fn register_protocols() {
    root::linked::register_protocols(&LINKED, ROOT_UNITS);
}

/// REGISTER THE PLANES — the composition root's one write into the plane axis
/// (`busbar_kernel::plane::registry::install_planes`), over the plane tables of [`LINKED`] (each
/// entry's contract declaration joined kernel-side to its behaviour, `PlaneDecl::assemble`, and each
/// linked HOT-lane plane) and the HOT-lane planes dropped into the configured `plugins.dir` — the
/// linked and the dropped-in ones adapted by one function (`root::linked::hot_plane_row`).
/// `merged_boot_plane_decls` normalises the installed set to canonical layering order, so each row
/// lands in its own slot regardless of the table's order. Then the two unconditional seams, then
/// every root unit's seal.
fn register_planes() {
    // The linked store and hook rows onto the kernel's cold-kind axis, before anything resolves one.
    busbar_kernel::preflight::install_linked_rows(LINKED.stores, LINKED.hooks);
    // The configured `plugins.dir`, scanned once: its planes join the plane axis here and its export
    // modules the export axis just below — the same entries a linked plugin registers through.
    let dropped = root::linked::dropped_from_config(&LINKED);
    root::linked::register_planes(&LINKED, root::linked::dropped_planes_of(dropped));
    root::linked::register_exports(dropped);

    // THE AUTHORIZATION-SERVER PLANE'S SEAM, registered UNCONDITIONALLY (no feature flag — see the
    // manifest note on the `busbar-oauth2` dependency), before any config loads. Mirrors
    // `install_planes` immediately above for the same reason: one composition root, one
    // registration, before the first `App` is built.
    busbar_oauth2::install();
    // Register the admin API service's mount seam (`busbar_kernel::admin::seam`) — the composition
    // root is the one place entitled to name `busbar-admin`, exactly as it names `busbar-oauth2`
    // above. Unconditional: the admin surface carries no feature flag at this layer; core mounts it
    // through the seam whenever this (mandatory) sibling is linked, which is every real build.
    busbar_core_admin::install();

    // THE ROOT UNITS' SEALS. Each reads what its unit composes against the axes installed above and
    // against nothing else — it binds no listener, opens no store, reads no configuration and writes
    // no line on success. A refusal is a boot refusal for the same reason a claim overlap is: a
    // composition that disagrees with itself must not bind a listener, and finding that out on the
    // first request would be finding it out from a customer.
    root::linked::seal(ROOT_UNITS);
}

/// REGISTER THE LINKED PLANES' DIAGNOSTICS — the composition root's one write into the diagnostics
/// axis (`busbar_substrate_values::diagnostics::install_diagnostics`). The neutral
/// `REGISTRY ∪ installed` fold makes these codes resolve through `by_code` and land in a rendered
/// catalog. Installed BEFORE any reader; a build with a plane compiled out contributes nothing.
fn register_diagnostics() {
    root::linked::register_diagnostics(&LINKED);
}

/// REGISTER THE LINKED DUPLEX PLANES' INBOUND WS-ACCEPT ARRIVALS — the composition root's one write
/// into the neutral WS-accept registry. Installed BEFORE the router is built (in `run()`), so
/// `take_ws_arrivals` drains a populated set; a build with no duplex plane installs nothing and the
/// router mounts no WS-accept route.
fn register_ws_arrivals() {
    root::linked::register_ws_arrivals(&LINKED);
}

fn main() {
    // PROTOCOL REGISTRATION FIRST — before the CLI flags, because `--validate` reads the protocol
    // set. This is the composition root's whole knowledge of the protocol crates: one line per
    // linked dialect, handed to the registry seam before anything reads it. A dialect absent from
    // the build (its feature off) is simply never registered, and a config that names it gets the
    // unknown-protocol refusal — the deletion test's runtime half (scripts/proto-deletion-gate.sh).
    register_protocols();
    // PLANE REGISTRATION, same slot and the same reason: `--validate` (just below) reads the plane
    // list through `plane::config::config_sections()`, so the plane axis must be installed before
    // any reader — including the CLI flags — can run.
    register_planes();
    // HOST-SELECTION SEAM INSTALL (loop unification, DECISIONS #28), after the planes are registered
    // and mirroring `busbar_admin::install()`: inject the kernel-loop runners into the neutral
    // per-capability-keyed seam. LIVE — it flips every plane in the build (mcp, a2a, llm-native,
    // voice) onto the unified kernel loop, whose runner opens a zero hold and reports no evidence, so
    // each plane's own metering inside `drive` stays what settles (item 125, measured money-neutral).
    root::gauntlet_install::install();
    // DIAGNOSTICS REGISTRATION, same slot and the same reason: a rendered catalog or a `by_code`
    // lookup must see every linked plane's owned codes, so the diagnostics axis is installed before
    // any reader. Each linked entry contributes its owned diagnostics; a no-planes build installs
    // nothing and the catalog is the neutral built-ins alone.
    register_diagnostics();
    // INBOUND WS-ACCEPT ARRIVAL REGISTRATION, same slot and the same reason as the axes above: the
    // core router drains the installed arrivals at build (`take_ws_arrivals`), which happens later in
    // `run()` — so the duplex planes' arrivals must be installed here, before the router is built. Each
    // duplex entry installs its `WsArrivalSpec`s; a build with no duplex plane installs nothing and
    // the router mounts no WS-accept route — strong-form deletable.
    register_ws_arrivals();
    // THE COMPOSITION ROOT'S OWN SEAL is NOT here, and it is the one boot step that is not: it
    // composes the transports a switched-over plane would serve through, and the http one carries
    // the operator's `limits.request_body_max_bytes`, so it cannot run before the configuration it
    // is built from has been read. It runs in `run()`, off the resolved limits, still before any
    // listener is bound. Every axis above is installed by then, which is the ordering the seal
    // needed from this slot in the first place.
    // THE ROOT-BOUND SEAMS the linked entries drive, each bound once here beside the plane axis and
    // only when some entry drives it: the hostless-egress driver and the egress-trust host (the
    // "both ends" binding of the outbound hop — a plane holds only `&dyn HostlessEgress` and never
    // names the core driver; the trust host is a byte-for-byte pass-through nothing on the shipped
    // path consults yet), the parse-time section list a cross-plane hook refusal reads (after the
    // plane axis, before the CLI flags read `--validate`), and the envelope a self-enveloping admin
    // verb builds its own reply through. A build whose entries drive none of them binds none.
    root::linked::register_seams();
    // CLI flags next — BEFORE building any runtime. They must work without a configured deployment,
    // and `--version` / `--validate` should never spin up a thread pool.
    if let Some(code) = root::cli::handle_cli_flags() {
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
    // report it (at info — it is expected on macOS/musl, not a fault) if it did not enable, so the
    // plateau-then-fall-back-to-idle behavior is an observed fact, not a silent assumption. Even when the background thread is absent, jemalloc's FOREGROUND decay purge
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
    if busbar_kernel::profile::enabled() {
        std::thread::spawn(|| loop {
            std::thread::sleep(std::time::Duration::from_secs(20));
            busbar_kernel::profile::dump();
        });
    }
    // Worker-thread count. `advanced.worker_threads` in config.yaml is the operator override; the
    // DEFAULT is one worker per available core (`available_parallelism`, which respects CPU affinity and
    // cgroup cpuset — but NOT the CFS bandwidth quota `cpu.max`, which it cannot see). So on a
    // quota-limited pod (e.g. 2 CPUs of quota on a 64-core node) this defaults to the NODE's core count,
    // oversubscribing the quota; such deployments should pin `advanced.worker_threads` to their CPU
    // limit. Uncapped-by-default is what lets throughput scale with cores: v1.3.1–1.3.3 capped the pool
    // at `min(cores, 4)`, which pinned the data plane to ~4 cores and made throughput plateau no matter
    // how big the box (v1.3.0 itself was uncapped via `#[tokio::main]`; 1.4.0 restores that default
    // explicitly). The request path is CPU-bound on JSON translate, so it genuinely uses the cores.
    // Footprint-sensitive sidecars (the ~5 MB-idle case) should set `advanced.worker_threads: 1` (or 2):
    // each worker carries a stack and its own allocator arena, so idle RSS grows with the count. Scale
    // up by default, tune down (or to your CPU quota) deliberately.
    // Resolve the worker-thread override, warning on an EXPLICITLY-SET but invalid value rather than
    // silently ignoring it. v1.3.0 ran under `#[tokio::main]`, which fail-fast panicked on a bad
    // `TOKIO_WORKER_THREADS`; 1.4.0 builds the runtime explicitly and would otherwise fall through to
    // all-cores on a `0`/garbage value — a silent footprint surprise. An UNSET var is not warned (it is
    // the normal default path). `TOKIO_WORKER_THREADS` is read as a back-compat fallback so an operator
    // who pinned it on 1.3.0 keeps the same pool size. `eprintln!` because this runs
    // before the tracing subscriber is installed.
    // See the `.min(MAX_WORKER_THREADS)` call below for why this exists.
    // `advanced.worker_threads` in config.yaml is the home for this knob. The deprecated
    // `BUSBAR_WORKER_THREADS` env var still works (deprecation-warned when it parses) and wins when
    // set, so an existing pin is honored across the upgrade; else config.yaml; else the standard
    // `TOKIO_WORKER_THREADS`; else one-per-core. The config read is a best-effort early parse (the
    // real load + error reporting happens in `run()` after the runtime is up).
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
        // capacity arguments elsewhere lean on. An unclamped `available_parallelism()` on very large
        // hardware, or an operator fat-fingering `advanced.worker_threads`, would otherwise leave that
        // bound unenforced. 128 is far above any realistic core count this process is deployed on and
        // far above what those capacity arguments need.
        .min(MAX_WORKER_THREADS);
    // RUNTIME TOPOLOGY (1.6.0). ONE design at every core count: the data plane runs on N pinned
    // single-threaded (`current_thread`) runtimes — one SO_REUSEPORT listener each, N = the
    // `worker_threads` resolution above (config knob else env else effective cores, cgroup-quota-
    // aware via `available_parallelism`) — and THIS small `current_thread` CONTROL runtime homes the
    // admin plane and every singleton background task. There is no mode and no fallback: a 1-core
    // box is the same topology with N = 1 (one data worker + the control thread — the same two
    // threads the old shape effectively ran there). `enable_all` keeps a blocking pool so
    // `spawn_blocking` keeps a home. `worker_threads` is deliberately NOT a control-runtime
    // dimension — it is the data-plane worker count, exactly what the knob has always meant.
    //
    // Non-unix has no SO_REUSEPORT (no kernel fan-out across per-core listeners), so those builds
    // keep the classic single work-stealing runtime — a compile-time platform shape, not a
    // configuration: no knob selects it and no unix deployment can end up on it.
    // Publish the data-plane worker count to core BEFORE anything builds: the egress client
    // shards (and later per-worker state stripes) size themselves to it. A process-topology fact,
    // exactly like the runtimes themselves — set once here, immutable, no config surface.
    busbar_kernel::topology::set_data_workers(worker_threads);
    #[cfg(unix)]
    {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build the tokio control runtime")
            .block_on(run(worker_threads));
    }
    #[cfg(not(unix))]
    {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(worker_threads)
            .enable_all()
            .build()
            .expect("failed to build the tokio runtime")
            .block_on(run(worker_threads));
    }
}

/// THE BOOT BOOK, COMPOSED — the extracted seam [`open_boot_book`] calls, wired against a store
/// adapter so its behaviour can be proved without a bound listener or a loaded plugin behind it.
///
/// Three decisions, made together here because they are ONE value and a caller that made them
/// separately would have a node whose halves disagree:
///
/// 1. **The journal ships to the CONFIGURED STORE'S shipper.** A batch is offered to that shipper
///    and its answer is part of the commit — committed-before-ack — and it is written to this
///    node's own disk as well when a data directory was resolved. Read
///    [`root::durability`]'s preamble for what "the store" answers with TODAY: on every store this
///    binary can load, the record verbs are answered by the adapter's node-local shim, which
///    acknowledges and never fails. So this line buys the WIRING, not new bytes at rest — the
///    moment a store speaks the record ABI the batches land in it, with no change here. The
///    durability a node gains today from this function is the on-disk half, and the honesty of the
///    other half is that the previous release kept nothing there either.
/// 2. **The ledger dual-writes onto the in-memory reconciliation rows.** That half stays memory: it
///    is the cross-check the reconciliation identity is read from, not the acknowledgement path.
/// 3. **The OPENING IS SEALED, here, before this function returns.** The previous release's rows are
///    read through the same adapter and sealed as the opening figures, with the marker written onto
///    THIS journal rather than the adapter's node-local shim — which could only ever hold it for the
///    life of a process.
///
/// **THE ORDER IS THE WHOLE POINT.** The seal happens before the composed book is handed back, so it
/// is impossible for a caller to reach a settlement path with an unopened book: the first accepted
/// connection can settle, and a settlement posted before the opening was sealed would measure its
/// residual from a checkpoint that did not exist when it happened. An opening sealed after traffic
/// has begun is worse than no opening at all, because it looks authoritative.
///
/// It returns the wired stack, the rows a view reads them back from, and what the migration did.
/// The opening is signed with the audit chain's own key (Q71(3): one keyset); a chain given no key
/// seals it unsigned, which the ledger unit accepts.
///
/// # Errors
///
/// The journal could not be opened (a configured data directory that could not be read), or the
/// opening could not be sealed — the two boot conditions [`root::migration::run`] returns where
/// continuing would be worse than refusing. A store that merely would not answer for some rows is
/// NOT one of them; see that module's preamble.
fn compose_boot_book(
    adapter: &busbar_plugin_loader::store_adapter::StoreAdapter,
    data_dir: Option<std::path::PathBuf>,
    mig: &root::migration::MigrationConfig,
    now: u64,
    token: &busbar_contract::caps::Grant<busbar_contract::caps::DurableWrite>,
) -> Result<
    (
        root::durability::Durability,
        Arc<busbar_kernel_ledger::legacy::RecordingRows>,
        root::migration::Migration,
    ),
    String,
> {
    let rows = Arc::new(busbar_kernel_ledger::legacy::RecordingRows::new());
    let mut durability = root::durability::build_for_node(
        &root::durability::DurabilityConfig { data_dir },
        mig.node,
        adapter.shipper(),
        Box::new(busbar_kernel_ledger::legacy::RecordingRows::clone(&rows)),
    )
    .map_err(|e| format!("the boot ledger's log could not be opened: {e}"))?;
    // The node amendment journal is rebuilt from the chain before anything can seal onto it, so a
    // corrected count and every recorded content access survive the restart (a node with no data
    // directory rebuilds nothing).
    durability.restore_amendments();
    // A corrupt journal segment was already logged and counted when the book was built; this puts
    // the durable record of it on the chain. A failed append is logged, never a refusal to boot.
    if let Err(lost) =
        durability.journal_quarantines(token, busbar_contract::caps::StepName::Meter, now)
    {
        tracing::error!(
            step = lost.step().as_str(),
            "the journal could not record the quarantine boot recovery made"
        );
    }
    let migration = {
        let (mut records, signer) =
            durability.migration_records_signed(token, busbar_contract::caps::StepName::Meter);
        let signer = signer
            .as_ref()
            .map(|s| s as &dyn busbar_kernel_ledger::checkpoint::CheckpointSecret);
        root::migration::run(adapter, &mut records, mig, now, signer)
            .map_err(|e| format!("the boot ledger could not seal its opening balances: {e}"))?
    };
    Ok((durability, rows, migration))
}

/// THE PROCESS'S ONE BOOK, opened over the deployment's configured store with its balances sealed.
///
/// A node with a governance store ships its book to that store and opens it from the rows the
/// previous release left there; a node with none keeps the previous release's memory-only book,
/// because a store the batches were never going to reach cannot be the one they are shipped to.
///
/// The data directory is the one [`busbar_kernel::preflight::fleet_data_dir`] resolves — the SAME
/// accessor the plugin anti-downgrade floor persists under, so the two can never disagree about
/// where this node keeps its own files. Absent, the branch in
/// [`root::durability::build_for_node`] is the unset one and nothing is probed, nothing is opened
/// and no file appears: this wiring gives a node with a CONFIGURED directory somewhere to write, and
/// deliberately does not make writing unconditional.
fn open_boot_book(app: &busbar_kernel::state::App) -> root::durability::NodeBook {
    let Some(gov) = app.governance.as_ref() else {
        return root::durability::node_book();
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let adapter = busbar_plugin_loader::store_adapter::StoreAdapter::native(gov.store());
    let mig = root::migration::config_from(&app.cost, now);
    let token = root::kernel::new_kernel().durability_token();
    let data_dir = busbar_kernel::preflight::fleet_data_dir();
    match compose_boot_book(&adapter, data_dir, &mig, now, &token) {
        Ok((durability, rows, migration)) => {
            // DEBUG, NOT INFO, and that is a neutrality decision rather than a taste one. The
            // boot log's INFO+ line set is part of what "LLM-only ≡ 1.5.5" means — it is pinned
            // by `tests/boot_lines_neutrality.rs` and recorded by the oracle's
            // `hazard|no-data-dir|logs` cell — so a new line here is a user-visible byte change
            // on a surface that must not move. The seal is an internal fact an operator can ask
            // for; it is not news a 1.5.5 deployment ever printed.
            if migration.sealed_now() {
                tracing::debug!(
                    node = mig.node,
                    rate_card_version = mig.rate_card_version,
                    "the boot ledger sealed its opening balances from the configured store"
                );
            }
            // THIS ONE STAYS A WARN, and the asymmetry is deliberate: it fires only when the store
            // would not list its key rows, which means the opening is INCOMPLETE — sealed over the
            // buckets configuration named and missing the ones the store would have. A money fact
            // that degraded silently to keep a log shape would be the wrong trade. It cannot fire
            // on the neutral shape: it takes a store that fails to answer, not a store with
            // nothing in it.
            if let Some(reason) = &migration.key_rows_unreadable {
                tracing::warn!(
                    reason = %reason,
                    "the boot ledger could not list the store's key rows, so the opening was sealed \
                     over the buckets the configuration named"
                );
            }
            let durability = Arc::new(std::sync::Mutex::new(durability));
            // Every amendment sealed from here on goes on the book it was rebuilt from.
            root::durability::bind_amendments(&durability);
            root::durability::NodeBook { durability, rows }
        }
        Err(e) => die(e),
    }
}

async fn run(data_workers: usize) {
    // Metrics are configured AFTER the config loads (below, via `metrics::configure`) because they
    // are 100% OPT-IN: `observability.metrics` absent ⇒ no recorder, no `/metrics`, nothing recorded
    // and nothing retained. Nothing may install a recorder before that decision is read.

    // Locate the two config files (env-overridable paths) and run the shared disk-load pipeline —
    // the SAME pipeline `POST /api/v1/admin/config/reload` re-runs at runtime.
    let cli_config = root::cli::config_path_flag();
    // 1.6.0 effective-source notice: only when the `--config` flag actually OVERRIDES a DIFFERENT
    // `BUSBAR_CONFIG` the operator also set (never on a bare flag / equal values), so a config value
    // that was ignored is explained rather than silent. Pre-subscriber, so it goes to stderr like the
    // other boot diagnostics.
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
        overlay_path,
        config_locked,
        config_read_only,
        overlay_doc,
        unset_env_vars: _,
    } = loaded;

    // 1.6.0 effective-source notice for the PROVIDERS catalog: the confusing case is a config.yaml
    // that declares `providers_file:` while the operator ALSO passed `--providers` — the flag wins, so
    // name both rather than let the config value silently lose. Only fires when both are set (and
    // differ); a bare `--providers` with no `providers_file:` in config is unambiguous and silent.
    if let Some(notice) = root::cli::providers_override_notice(
        root::cli::value_flag(std::env::args().skip(1), "--providers", None).as_deref(),
        deploy.providers_file(),
    ) {
        eprintln!("[info] {notice}");
    }

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
    busbar_kernel::proxy::configure_route_policy_headers(response_headers_cfg.route_policy);
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
            .recorder
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
    // `--mcp-stdio` reserves stdout for the MCP channel, so its logs move to stderr — see
    // `init_logging`'s `stdout_reserved`.
    root::otlp::init_logging(
        otlp_cfg.as_ref().map(|o| o.url.as_str()),
        stdio_serve_requested(std::env::args()),
    );

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
            diag = %busbar_substrate_values::diagnostics::CONFIG_OVERLAY_NOT_WRITABLE.banner(),
            "config is READ-ONLY (the overlay backend is not writable): busbar serves traffic \
             normally, but admin-API config mutations are refused. Set `config.locked: true` to \
             declare this deliberately, or give `config.overlay.file` a writable path."
        );
    }
    // Stamp process start for the `GET /api/v1/admin/info` uptime read.
    busbar_core_admin::mark_start();

    // Resolve deployment + definitions into resolved RootCfg (semantic validation runs inside
    // build_app_from_config — the one construction path).
    let mut cfg = config::resolve(&deploy, &defs)
        .unwrap_or_else(|errs| die(format!("config errors:\n  - {}", errs.join("\n  - "))));
    // THE EXPORT AXIS'S SINKS, opened once — before the first app is built, so the routes they
    // declare are in the boot route table (restart-to-apply, as every built-in PUSH sink is). A
    // configured sink that will not open refuses the boot.
    export::plugin::open(&cfg.export).unwrap_or_else(|e| die(format!("config errors:\n  - {e}")));
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
        tracing::warn!(
            diag = %busbar_substrate_values::diagnostics::METADATA_PROTECTION_DISABLED.banner(),
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
    // The admin plane ALWAYS runs on its own listener (`admin_listen`, default loopback 127.0.0.1:8081)
    // with its own optional TLS/mTLS — never on the data listener. The exposed-admin-requires-mTLS
    // boot-guard has already run in `config::resolve`, so by here `admin_listen` is loopback, mTLS,
    // or an explicit `admin_require_mtls: false` waiver.
    let admin_listen = cfg.admin_listen.clone();
    let admin_tls_cfg = cfg.admin_tls.clone();
    let req_body_max = cfg.limits.request_body_max_bytes;
    let max_inbound = cfg.limits.max_inbound_concurrent;
    // THE MONEY THE ROOT-DRIVEN LLM NODE PRICES WITH is not captured here and handed over once. It
    // arrives through the engine's rate-apply seam, installed a few lines down and raised by the ONE
    // place a deployment's rates are resolved — which runs at boot AND on every live apply/reload. A
    // reading taken here instead would be the boot's rates forever: the usage projection would
    // reprice on an apply and this node's ledger would not, and the identity that says the two are
    // one money would hold only until the operator changed a fee.
    // THE COMPOSITION ROOT'S OWN SEAL, in the first slot where the values it composes exist: the
    // limits are resolved (and the overlay merged onto them) one screen up, and no listener is bound
    // for another few hundred lines. The transports it composes are built from THESE limits, the
    // same `request_body_max_bytes` the line above hands the served door, so a plane's transport and
    // the door in front of it cannot disagree about which bodies exist. Every build runs it, whatever
    // planes it links; a composition that does not seal exits 2 here, and success writes nothing.
    // The rows are the linked wires and the ones dropped into `plugins.dir`, folded in one pass; the
    // sealed registry names the wire under the data door when that wire came in dropped in.
    let boot = root::registry::seal_or_exit(&LINKED, root::policy::client_settings(&cfg.limits));
    let door = boot.dropped_door();
    // THE ROOT UNITS' CONFIGURATION STEP, in the same slot: the card repricer is installed BEFORE the
    // first app build below, so the boot's own rate resolution is the history's OPENING ENTRY and
    // nothing has to read the configuration twice. From there each resolution APPENDS an entry dated
    // at the moment it landed and none is ever rewritten. A build without those units runs none and
    // is what it was, which is what the neutrality cells read.
    for step in ROOT_UNITS.iter().filter_map(|u| u.on_config) {
        step(&cfg.limits);
    }
    // EACH LINKED PLUGIN'S PROVIDER, captured off the deployment's ORDINARY provider catalog before
    // `cfg` moves into the build, and composed below once the resolver that turns a secret reference
    // into a credential exists. A deployment that pins nothing captures nothing, so nothing about it
    // changes.
    let composes: Vec<root::linked::Compose> = LINKED
        .compose
        .iter()
        .filter_map(|capture| capture(&cfg))
        .collect();

    // D38: the fleet's SEALED OPERATOR KEY reference (`auth.operator_pub`), captured from the
    // resolved `auth:` block BEFORE `cfg` is consumed by `build_app_from_config`. It is resolved to
    // its raw 32 ed25519 bytes below — once the secret resolver the build produces exists — and
    // sealed into the admin plane's production posture view. Absent (the default) it stays `None`,
    // which the posture view reads as `OperatorState::Unset`: the amend ceremony gate refuses exactly
    // as the release without this field, byte for byte.
    #[cfg(feature = "root-admin")]
    let boot_operator_auth = cfg.auth.clone();
    // The root breaker's per-pool ladders, read off the same `pools:` the build resolves each pool's
    // own dispatch cfg from, before `cfg` is consumed.
    #[cfg(feature = "root-admin")]
    let breaker_policy = root::adapters::BreakerPolicy::from_pools(&cfg.pools);

    // The secret resolver the listeners resolve TLS cert/key/CA references through - the SAME seam
    // (built-in env/file + kind:secret plugins) that resolved provider keys at build time.
    // Boot has no `prior` App, so `build_app_from_config` never resolves a credential rotation here
    // (that branch is gated on `prior.is_some()`) — the discarded closure is always `None`.
    //
    // blocking-ffi-lint: allow — BOOT. Two independent reasons, either sufficient: (1) `run()` is
    // driven by `.block_on(run())` (this file, in `main()`), so it is polled on the MAIN thread, not
    // on a Tokio worker — there is no worker to park; (2) this precedes the `tokio::join!` over
    // `serve_listener` below, so neither listener has been bound, let alone is accepting.
    //
    // The marker sits DIRECTLY above the call it exempts, and must: the lint carries an allow across
    // the comment block that starts it and no further, so the voice-credential capture that used to
    // stand between the two silently ate this exemption and left the build itself flagged.
    let (boot_app, _boot_gov_rotate, boot_limits) = build_app_from_config(
        cfg,
        plugins_cfg,
        overlay_path,
        base_hook_names,
        base_group_names,
        (Some(config_path.clone()), Some(providers_path.clone())),
        None,
    )
    .unwrap_or_else(|e| die(e));
    // BOOT KEEPS THEM IMMEDIATELY. The admin applies defer this to after their persist-and-swap,
    // because a rejected apply must leave the still-serving generation's limits alone. Boot has no
    // such caller: the config file IS the durable state, this build IS the first generation, and a
    // build that failed already `die`d above.
    boot_limits.keep();
    let app = Arc::new(boot_app);

    // COMPOSE each captured provider: the plugin resolves its credential through the deployment's own
    // secret resolver — the same seam every provider key is resolved through — so its routes serve
    // instead of answering "no provider composed". The only line this can emit is a fail-closed
    // warning when a reference the operator DID declare will not resolve.
    for compose in composes {
        compose(&*app.secret_resolver);
    }

    // Record the BOOT snapshot as version 0 so the version history always has a rollback floor
    // (the pre-any-mutation state).
    app.versions
        .record(0, "system", "boot", &app.hook_registry, &app.global_hooks);

    // DURABLE STATE HYDRATION — the audit ring, the A2A task table, the MCP per-call log and
    // the MCP demotion/spent-approval records, restored from the configured governance store
    // BEFORE a listener is bound. One boot entry point (`busbar_kernel::boot::hydrate_all`)
    // rather than four widened statics: the sinks (`AUDIT`, `TASKS`, `CALLS`) and their
    // restore verbs stay crate-private in core, so nothing outside the engine can swap a sink
    // out from under the hash chains. The narration (which restore is a hiccup, which is
    // tamper evidence) moved with the code; see busbar-core/src/boot.rs. A plane whose durable
    // state cannot be restored REFUSES BOOT — `hydrate_all` propagates the plane hook's `Err`.
    busbar_kernel::boot::hydrate_all(&app).unwrap_or_else(|e| die(e));
    // RELIABILITY STATE IS STATELESS (store-or-RAM rule): a plane's own in-memory health/backoff
    // bookkeeping lives in RAM only and is RE-LEARNED after a restart — none of it is this crate's
    // business, and nothing about it is restored from disk here. The durable config that makes "fix
    // the config and restart" the recovery path lives in the config-overlay persistence, not in a
    // health snapshot. The config version-history ring is likewise RAM-only, re-seeded here
    // at its boot floor (see `app.versions.record(0, …)` above); durable cross-restart rollback would
    // need a store seam, which does not exist over the plugin wire ABI today (see the 1.5.3 report).
    tracing::info!(
        "reliability state (breakers, cooldowns, latency, hard-down) starts fresh on boot and is \
         re-learned from live traffic"
    );

    // START the export axis's opened sinks (every request-log sink is one): each states whether it
    // takes deliveries this run and its in-flight admission — the moment the built-in request-log
    // exporters were configured, so a sink that refuses its own target at start says so here.
    export::plugin::start();

    // Spawn the active health probers (one per lane with a probing mode). No-op when every lane is
    // `mode: none` / has no `health:` block. The composition root owns THIS generation's engine host
    // (App-retype WEDGE 2f): the probers re-anchor on a `Weak<dyn EngineHost>` over it — never an
    // `Arc<App>` — so the plane's health module names no core `App` type. We hand the SAME host to the
    // `AppHandle` below (`set_snapshot_host`), which owns it for the boot generation and DROPS it on the
    // first config swap, retiring these boot probers (their `Weak` fails to upgrade) exactly as the old
    // `Weak<App>` did when the boot snapshot drained.
    // Built only when some linked entry re-anchors work on it: a build with none holds no host.
    let on_host = LINKED.on_host;
    let boot_host = (!on_host.is_empty()).then(|| busbar_kernel::plane_host::engine_host(&app));
    if let Some(host) = &boot_host {
        for spawn in on_host {
            spawn(host);
        }
    }

    // Build the two routers with the operator-configured ingress body cap + the inbound-concurrency
    // layer (installed by default; `limits.max_inbound_concurrent: 0` opts out — no layer). The admin surface is built onto its
    // OWN router (ABSENT from the data router) and served on `admin_listen` below; the data router
    // serves the protocols. Both share one `app_handle`, so config-apply hot-swaps reach both planes.
    // Grab the secret resolver before `app` is moved into the router builder - the TLS listeners
    // resolve cert/key/CA references through it below.
    let tls_secret_resolver = app.secret_resolver.clone();
    // D38: resolve the sealed operator public key to its raw 32 ed25519 bytes through the SAME secret
    // seam every key is resolved through (built-in env/file + kind:secret plugins). FAIL-CLOSED on a
    // configured-but-unresolvable / malformed key — a fleet that MEANT to seal one must not come up
    // silently ungated. `None` (absent) ⇒ `OperatorState::Unset` in the posture view below.
    #[cfg(feature = "root-admin")]
    let operator_key = busbar_kernel::preflight::resolve_operator_public_key(
        boot_operator_auth.as_ref(),
        &tls_secret_resolver,
    )
    .unwrap_or_else(|e| die(e));
    let (data_router, admin_router, app_handle) = build_split_routers_with_limits(
        app,
        req_body_max,
        max_inbound,
        response_headers_cfg.server_timing,
    );
    // THE ROOT-DRIVEN ADMIN SURFACE (composition-root switch-over S1), default-ON. The router that
    // answers the admin operations is unchanged; what the wrap adds is the path a request takes to
    // reach it — through the kernel's loop, past the auth, scope, admission, usage and audit units,
    // and out through the one exit. Off, this line does not exist and the surface is the one it was.
    // THE PROCESS'S ONE BOOK. The LLM plane's exit arm settles onto it (its root unit's book step,
    // below) and the administrative ledger views read it; no other plane binds an exit arm to it.
    // It is ONE book, and that matters: a mount that opened its own would post
    // onto books nothing serves and serve books nothing posts to, and both halves of that would look
    // healthy, because an empty ledger reconciles. Its records ship to the deployment's CONFIGURED
    // STORE (committed-before-ack, and onto this node's own disk as well when a data directory was
    // resolved) and its OPENING BALANCES are SEALED at start-of-book from the rows the previous
    // release left in that store — see `open_boot_book`. A configuration that named no data
    // directory still probes nothing and opens nothing; the branch that decides is unchanged.
    //
    // It is built HERE — before either listener binds — because the first accepted connection can
    // settle, and it must settle against a book whose opening is ALREADY sealed. `open_boot_book`
    // returns only after the seal, so there is no window in which a settlement could be measured
    // from a checkpoint that was not written yet.
    // Opened for the admin surface and for every root unit that settles onto it; a build with
    // neither opens nothing.
    let book = (cfg!(feature = "root-admin") || ROOT_UNITS.iter().any(|u| u.opens_book))
        .then(|| open_boot_book(&app_handle.load()));

    // THE CHECKPOINT CADENCE (OWNER Q71(3); ARCHITECTURE.md §4.7): armed on the one book once its
    // opening is sealed, so every serving append checks the entry half and this tick checks the
    // interval half — whichever comes first. The tick runs for the process lifetime; each pass
    // holds the book's lock only for the check (and the seal, when one is due).
    if let Some(book) = &book {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        book.durability
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .arm_checkpoints(now);
        let durability = Arc::clone(&book.durability);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(
                root::durability::CHECKPOINT_TICK_SECS,
            ));
            loop {
                tick.tick().await;
                durability
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .seal_on_cadence();
            }
        });
    }

    // THE ROOT UNITS' BOOK STEP, once the book is open and before either listener binds: the
    // root-driven exit arm is bound to the book, so a posting the loop hands back has somewhere to go.
    if let Some(book) = &book {
        let app = app_handle.load();
        let ctx = root::linked::BookCtx { book, app: &app };
        for step in ROOT_UNITS.iter().filter_map(|u| u.on_book) {
            step(&ctx);
        }
    }

    // THE CARD IT PRICES AGAINST is already in place: the app build above resolved this deployment's
    // rates and raised the rate-apply seam the hook installed before it, so the root's card holds the
    // same configured `rate_card:` and `per_request_fee:` the usage projection derives its spend
    // from. One configuration, two readings — and the next apply moves both, which is what makes the
    // node's books and the projection's rows the same money rather than two numbers that agreed once.

    // (The admin surface always opens the book, so `None` is a build without that surface's book —
    // never one with the surface.)
    #[cfg(feature = "root-admin")]
    let admin_router = match &book {
        Some(book) => root::units_admin::mount(
            admin_router,
            root::kernel::new_kernel(),
            // The same ingress cap the router below the wrap was built with, because the wrap reads the
            // body before that router's own limit can.
            req_body_max,
            |dispatch| {
                let mut units = root::kernel::ProductionUnits::admin_only_sharing(
                    dispatch,
                    std::sync::Arc::clone(&book.durability),
                    std::sync::Arc::clone(&book.rows)
                        as std::sync::Arc<dyn root::units_admin::LegacyRowsRead>,
                );
                // D38 PRODUCTION SEALING (composition-root, binding-only). Replace the assembly's
                // `UnsealedPosture` default with the posture THIS fleet sealed: `SealedPosture` carries
                // the boot-resolved operator key, so `operator.pub` present ⇒ `OperatorState::Set` (a
                // valid-signed `amend_rate_history` is now performable + ed25519-verified) and absent ⇒
                // `OperatorState::Unset` (amend refused at the ceremony gate, byte-identical to before).
                // Bound over the SAME public `posture` seam `AdminBinding::with_posture_view` sets — and
                // the same one the ledger view beside it is bound through — so this is a binding, not a
                // structural change to the units.
                units.admin.posture =
                    std::sync::Arc::new(root::units_admin::SealedPosture::new(operator_key));
                // Q64/Q67: an `adjust` names the pool its unit was dispatched through, checked against
                // the pools this node has CONFIGURED — read off the live snapshot on every call, so a
                // config apply that adds or removes a pool is what the check sees.
                let live = std::sync::Arc::clone(&app_handle);
                units.admin.pools = std::sync::Arc::new(move |pool: &str| {
                    busbar_kernel::governance::group_provision::pool_known(&live.load(), pool)
                });
                // Q71(2): `plane_facts` / `plane_record_write` read the planes this node serves off the
                // live snapshot (Law 7) and write through the configured store's plane-facing seam.
                units.admin.planes =
                    root::units_admin::live_planes(std::sync::Arc::clone(&app_handle));
                units.admin.records = Some(root::units_admin::live_records(std::sync::Arc::clone(
                    &app_handle,
                )));
                // The root breaker is the kernel's own: one cell set on the node, read through the
                // live snapshot so an apply's rebuilt store is the one it observes into.
                units.breaker = root::adapters::BreakerAdapter::over_kernel(
                    std::sync::Arc::clone(&app_handle),
                    breaker_policy,
                );
                // THE DEPLOYMENT'S OWN DOOR, in front of the authenticate step. Without these two lines
                // the assembly's open posture shipped: the step admitted every caller anonymously and
                // the only thing deciding was the surface mounted underneath — so a credential this node
                // had REVOKED was admitted at Authenticate, and the revocation the governance state
                // holds was consulted by nothing on the request path. The chain is the operator's admin
                // token and the bindings are the same governance state's directory, which is what makes
                // the revocation set the one this node actually keeps.
                match app_handle.load().governance.clone() {
                    Some(gov) => units
                        .with_auth_chain(root::kernel::auth_bindings::admin_chain(
                            std::sync::Arc::clone(&gov),
                        ))
                        .with_auth_bindings(root::kernel::auth_bindings::AuthBindings::new(
                            std::sync::Arc::new(
                                root::kernel::auth_bindings::GovernanceDirectory::new(gov),
                            ),
                        )),
                    // No governance state is no directory and no configured token, which is the open
                    // administrative posture the previous release also has. Left as the assembly built
                    // it rather than wired to an authority that does not exist.
                    None => units,
                }
            },
        ),
        None => admin_router,
    };

    // Bind the boot generation's engine host to the handle so it OWNS the only strong reference the boot
    // probers depend on (they hold a `Weak`): the first config swap drops it and retires them. See the
    // spawn_probers call above and `AppHandle::set_snapshot_host`.
    if let Some(host) = boot_host {
        app_handle.set_snapshot_host(host);
    }
    // And bind the spawner every later swap re-attaches the probers with (item 552): the swap drops
    // this generation's host and retires its probers, so without the binding the first admin
    // mutation stops active health probing for the life of the process. The seam holds one.
    if let Some(&spawn) = on_host.first() {
        app_handle.attach_on_swap(spawn);
    }

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
    busbar_core_admin::restart::publish_shutdown(shutdown_tx.clone());
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
        std::mem::drop(busbar_kernel::governance::spawn_budget_flusher(
            gov,
            shutdown_tx.subscribe(),
        ));
    }

    // START EVERY PLANE'S BACKGROUND WORK — the MCP tool-list refresh sweep and the A2A
    // re-verification job — through ONE boot entry point that folds over the plane registry and calls
    // each plane's declared `start` hook (MCP before A2A, the order they have always started in). Each
    // job MOVED into its plane's own hook beside the code it starts, so the sweeper types, the
    // live-fetch transport and the identity resolver stay crate-private in their planes rather than
    // being reached here by name. Spawned ONCE, here, rather than on apply, for the reason the flusher
    // is: a second job against the same registry would double every fetch and race every ledger stamp.
    // Fatal if an A2A outbound client identity does not resolve, exactly as before — the refusal text
    // is the plane hook's, propagated through `start_planes`.
    busbar_kernel::boot::start_planes(&app_handle).unwrap_or_else(|e| die(e));

    // THE STDIO SERVE MODE (`--mcp-stdio`). The SAME boot ran above — config load, plugin
    // preflight, governance, the flusher and the refresh jobs — and the SAME dispatch will serve
    // every frame; what changes is only the transport: busbar is somebody's CHILD PROCESS here, so
    // it binds no listener at all (a child that opened ports would be a network server its
    // supervisor never asked for) and speaks newline-delimited JSON-RPC on its own stdin/stdout.
    // EOF on stdin is the shutdown signal, and the tail below is the listener path's own shutdown
    // tail: the final budget/metering flush, then the tracer.
    // The mode exists only when a linked entry serves it. With none there is no dispatch to serve on
    // stdin/stdout, so the mode is not offered and the build falls through to its listener path.
    let stdio_serve = LINKED.stdio_serve.first().copied();
    if let Some(serve) = stdio_serve.filter(|_| stdio_serve_requested(std::env::args())) {
        // The neutral host factory, minted core-side and threaded into the stdio transport so the plane
        // re-mints the host over each frame's live snapshot without naming the core factory itself.
        let factory = busbar_kernel::plane_host::live_host_factory(app_handle.clone());
        let code = serve(factory).await;
        if let Some(gov) = app_handle.load().governance.clone() {
            let n = gov.flush_budgets();
            tracing::info!(flushed = n, "budget counters flushed on shutdown");
            let m = gov.flush_metering();
            tracing::info!(flushed = m, "metering rows flushed on shutdown");
        }
        root::otlp::shutdown_tracing();
        std::process::exit(code);
    }

    // SERVE (one topology; see `main()`). On unix the DATA plane runs on N pinned
    // `current_thread` runtimes — one SO_REUSEPORT listener per worker, kernel fanning connections
    // across them with no task migration — while the ADMIN plane and every singleton background
    // task spawned above stay on THIS control runtime. N = `data_workers` (the `worker_threads`
    // resolution: config knob else env else cgroup-aware effective cores); N = 1 is the same
    // design on a 1-core box, not a different path. Non-unix (no SO_REUSEPORT) serves both planes
    // on the single work-stealing runtime `main()` built — the compile-time platform shape.
    #[cfg(unix)]
    {
        // The WORKER-SHUTDOWN WATCH: the broadcast, refolded into a level (a `watch<bool>`) so
        // detached work spawned at any moment — including after the signal — can still observe
        // that shutdown has fired. Each data worker registers a clone
        // (`busbar_kernel::detached::set_worker_shutdown`) beside its detached tracker, and an MCP task
        // runner selects on it to write its CANCELLED terminal status within the drain grace
        // instead of being aborted with a caller left polling forever.
        let (worker_shutdown_tx, worker_shutdown_rx) = tokio::sync::watch::channel(false);
        {
            let rx = shutdown_tx.subscribe();
            tokio::spawn(async move {
                recv_shutdown(rx).await;
                let _ = worker_shutdown_tx.send(true);
            });
        }
        let data_handles = serve_thread_per_core(
            data_workers,
            listen.clone(),
            data_router,
            tls_cfg,
            tls_secret_resolver.clone(),
            &shutdown_tx,
            worker_shutdown_rx,
            door,
        );
        let admin_listener = bind_listener(&admin_listen).await;
        serve_listener(
            admin_listener,
            admin_router,
            admin_tls_cfg,
            tls_secret_resolver.clone(),
            &admin_listen,
            recv_shutdown(shutdown_tx.subscribe()),
            None,
            true,
        )
        .await;
        // The shutdown broadcast has fired (the admin serve returned), so every per-core data
        // runtime is draining too. Join their threads off the async thread via `spawn_blocking`
        // so this single control runtime keeps polling the background tasks' shutdown arms (the
        // flusher's final flush, the tracer) while the data runtimes wind down.
        let _ = tokio::task::spawn_blocking(move || {
            for h in data_handles {
                let _ = h.join();
            }
        })
        .await;
    }
    #[cfg(not(unix))]
    {
        let _ = data_workers; // sized the runtime in main(); no per-worker listeners here
        let data_listener = match door {
            None => Some(bind_listener(&listen).await),
            Some(_) => None,
        };
        let admin_listener = bind_listener(&admin_listen).await;
        tokio::join!(
            serve_data(
                data_listener,
                door,
                data_router,
                tls_cfg,
                tls_secret_resolver.clone(),
                &listen,
                recv_shutdown(shutdown_tx.subscribe()),
                None,
                true,
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
            ),
        );
    }
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
    root::otlp::shutdown_tracing();
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

/// Spawn the DATA plane: `n` OS threads, each advisorily pinned to a distinct core via
/// `core_affinity`, each running its own single-threaded (`current_thread`) tokio runtime that binds
/// its OWN SO_REUSEPORT listener on the shared data `addr` and runs the SAME `serve_listener` accept
/// loop over a clone of the (Arc-shared) `data_router`. The kernel load-balances accepted connections
/// across the per-worker listeners, and each connection is then handled entirely on its own worker
/// with no task migration. `n = 1` is the same design on a 1-core box — one worker, one listener.
///
/// Nothing here touches the request path or the app state: `data_router` is `Clone` (its `AppHandle`
/// is an `Arc`), so every worker serves the SAME app snapshot and the SAME config-swap seam. Pinning
/// is ADVISORY: if core enumeration is unavailable (some containers expose none) or `set_for_current`
/// is refused (restricted cpuset), the workers run unpinned and SO_REUSEPORT still balances — the
/// same code path, only placement differs. The admin plane and every singleton background task stay
/// on the caller's control runtime — this function spawns ONLY data listeners. Returns the join
/// handles; the caller awaits shutdown (the broadcast fans out to every per-worker `recv_shutdown`)
/// and then joins them. Unix-only (SO_REUSEPORT); see the call site.
#[cfg(unix)]
#[allow(clippy::too_many_arguments)] // the seven it had, plus the wire under the door.
fn serve_thread_per_core(
    n: usize,
    addr: String,
    data_router: Router,
    tls_cfg: Option<busbar_kernel::config::sections::TlsCfg>,
    secret_resolver: Arc<busbar_kernel::config::secret::SecretResolver>,
    shutdown_tx: &tokio::sync::broadcast::Sender<()>,
    worker_shutdown: tokio::sync::watch::Receiver<bool>,
    // The wire under the data door when it came in dropped in (`BootRegistry::dropped_door`): the
    // same `n` workers serve it, each through its OWN listener the wire binds on `addr` — the
    // per-core fan-out the kernel's SO_REUSEPORT listeners give a linked wire (ruling K8c).
    door: Option<Arc<dyn busbar_contract::Transport>>,
) -> Vec<std::thread::JoinHandle<()>> {
    // Distinct cores to pin the n workers to, when the platform exposes them. Fewer ids than
    // workers (or none) just means the tail runs unpinned — advisory, never a boot failure.
    // Validate the TLS material ONCE, here on the control thread, before any worker exists: every
    // worker builds the same server config from the same files, so a bad cert or key must be
    // reported exactly once and stop the boot (workers racing to `die` would each print it).
    // Reconciliation + fail-closed (DECISIONS #40): the built-in axum/hyper listener always
    // declares itself TLS-capable, so this can only fail on unresolvable/unparsable material —
    // exactly the boot failure `build_server_config` always reported here.
    if tls_cfg.is_some() {
        // `FailClosed`'s Display already names the listener (`TLS configuration error for '<addr>':
        // <reason>`, 1.5.5's line); wrapping it again printed that prefix twice.
        let _ = busbar_core_connsec::prepare(&addr, tls_cfg.as_ref(), &secret_resolver, true)
            .unwrap_or_else(|e| die(e.to_string()));
    }
    let core_ids = core_affinity::get_core_ids().unwrap_or_default();
    let cores: Vec<Option<core_affinity::CoreId>> =
        (0..n).map(|i| core_ids.get(i).copied()).collect();
    // DEBUG, not INFO: this is a per-worker implementation fact, not something a 1.5.5-shaped config
    // ever printed — an operator of such a config must see the SAME lines at INFO as 1.5.5 did (the
    // neutrality binding, docs/design/ARCHITECTURE.md Appendix B).
    tracing::debug!(
        runtimes = cores.len(),
        pinned = core_ids.len().min(n),
        listen = %addr,
        "thread-per-core data plane: one SO_REUSEPORT listener per worker (admin + background \
         tasks stay on the control runtime)"
    );
    // The connection-placement balancer (see `tls::ConnBalancer`): one handle per worker, fixing
    // SO_REUSEPORT's few-connection imbalance at ACCEPT time (placement only, never migration).
    let mut balancers: Vec<Option<tls::ConnBalancer>> = tls::ConnBalancer::build(cores.len())
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
        let door = door.clone();
        let spawned = std::thread::Builder::new()
            .name(format!("busbar-core-{i}"))
            .spawn(move || {
                if let Some(id) = core_id {
                    // Best-effort pin; a false return (unsupported platform / restricted cpuset) leaves
                    // the thread unpinned but still serving — the kernel still balances via SO_REUSEPORT.
                    core_affinity::set_for_current(id);
                }
                // This thread IS data-plane worker `i` for its whole lifetime: everything core
                // stripes per worker (the egress client shard today; SWRR/breaker scratch in later
                // stages) indexes by this id. Set after the pin, before the runtime serves.
                busbar_kernel::topology::set_worker_id(i);
                // Detached-work tracker (request-outliving spawns: webhook/tap deliveries, MCP
                // runners, A2A watchers) — the post-drain grace below waits on it so a graceful
                // stop gives such work a bounded window instead of an instant abort.
                let detached = busbar_kernel::detached::DetachedTasks::new();
                busbar_kernel::detached::set_worker_detached(detached.clone());
                // The shutdown level, registered beside the tracker: detached work spawned on
                // this worker captures it and can settle its own terminal state (an MCP task
                // runner writes CANCELLED) inside the drain grace below instead of being aborted
                // silently when the runtime drops.
                busbar_kernel::detached::set_worker_shutdown(worker_shutdown);
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap_or_else(|e| {
                        die(format!("failed to build per-core data runtime {i}: {e}"))
                    });
                rt.block_on(async move {
                    // A dropped-in wire under the door binds this worker's listener itself.
                    let listener = door.is_none().then(|| {
                        let std_listener = bind_reuseport_listener(&listen).unwrap_or_else(|e| {
                            die(format!(
                                "cannot bind SO_REUSEPORT data listener on '{listen}' (per-core \
                                 runtime {i}): {e}"
                            ))
                        });
                        tokio::net::TcpListener::from_std(std_listener).unwrap_or_else(|e| {
                            die(format!(
                                "cannot adopt SO_REUSEPORT data listener on '{listen}' (per-core \
                                 runtime {i}): {e}"
                            ))
                        })
                    });
                    serve_data(
                        listener,
                        door,
                        router,
                        tls,
                        resolver,
                        &listen,
                        recv_shutdown(shutdown_rx),
                        balancer,
                        // ONE "busbar listening" line per LISTENER, matching 1.5.5, not one per
                        // worker: only worker 0 logs it at INFO; every other worker's identical fact
                        // logs at DEBUG (the per-worker detail an operator can still opt into).
                        i == 0,
                    )
                    .await;
                    // Connections are drained; give this worker's detached work its bounded
                    // grace before the runtime drops (and aborts whatever remains).
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

/// Build a `TcpListener` with SO_REUSEADDR + SO_REUSEPORT set on the shared data address, for the
/// thread-per-core runtime. SO_REUSEPORT is what lets EVERY per-core runtime bind the SAME address (the
/// 2nd plain `bind` would otherwise `EADDRINUSE`) and hands the kernel the job of load-balancing accepted
/// connections across the listeners. Returned as a std listener the caller adopts into its per-core tokio
/// runtime via `TcpListener::from_std`. No `unsafe` — socket2 wraps the sockopts safely. Unix-only.
#[cfg(unix)]
fn bind_reuseport_listener(addr: &str) -> std::io::Result<std::net::TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::net::ToSocketAddrs;
    let sockaddr = addr.to_socket_addrs()?.next().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("listen address '{addr}' resolved to no socket address"),
        )
    })?;
    let domain = if sockaddr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&sockaddr.into())?;
    // Backlog 1024: matches the effective default depth tokio/mio use for a plain bind, so per-core
    // listeners accept as readily as the single multi-thread listener did.
    socket.listen(1024)?;
    Ok(socket.into())
}

/// Serve the DATA door: over `listener` (the kernel's own socket) as [`serve_listener`] does, or —
/// when the wire under the door came in dropped in (`door`) — through that wire, which binds `label`
/// itself (`root::transports::serve_door`). Same router, same TLS posture, same drain.
#[allow(clippy::too_many_arguments)] // `serve_listener`'s eight, plus the door.
async fn serve_data(
    listener: Option<tokio::net::TcpListener>,
    door: Option<Arc<dyn busbar_contract::Transport>>,
    router: Router,
    tls_cfg: Option<busbar_kernel::config::sections::TlsCfg>,
    secret_resolver: Arc<busbar_kernel::config::secret::SecretResolver>,
    label: &str,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    balancer: Option<tls::ConnBalancer>,
    log_at_info: bool,
) {
    let Some(wire) = door else {
        let listener = listener.expect("a door with no dropped-in wire has the kernel's listener");
        return serve_listener(
            listener,
            router,
            tls_cfg,
            secret_resolver,
            label,
            shutdown,
            balancer,
            log_at_info,
        )
        .await;
    };
    // blocking-ffi-lint: allow — BOOT, once, before this door accepts (see `serve_listener`).
    let security = tls_cfg.as_ref().map(|tls| {
        busbar_core_connsec::prepare(label, Some(tls), &secret_resolver, true)
            .unwrap_or_else(|e| die(e.to_string()))
    });
    // The same line per worker `serve_listener` writes: INFO once, DEBUG for every other worker.
    match (log_at_info, &tls_cfg) {
        (false, None) => tracing::debug!(listen = %label, "busbar listening"),
        (true, None) => tracing::info!(listen = %label, "busbar listening"),
        (log_at_info, Some(tls)) => {
            let mtls = tls.client_ca.is_some();
            if log_at_info {
                tracing::info!(listen = %label, mtls, "busbar listening (TLS)");
            } else {
                tracing::debug!(listen = %label, mtls, "busbar listening (TLS)");
            }
        }
    }
    if let Err(e) = root::transports::serve_door(wire, label, router, security, shutdown).await {
        die(format!(
            "cannot listen on '{label}' through the transport under it: {e:?}"
        ));
    }
}

/// Serve one listener (data OR admin plane) to graceful shutdown. Picks plain-HTTP vs native TLS/mTLS
/// from `tls_cfg` exactly as the single-listener path always has: `None` ⇒ plain HTTP over the shared
/// slow-loris-hardened hyper loop; `Some` ⇒ terminate TLS (mTLS when `client_ca_file` is set), with
/// cert/key/CA loaded and validated up front so a bad path/parse `die`s at startup, not per request.
/// `label` names the plane in log lines and error messages. Any serve error `die`s the process.
#[allow(clippy::too_many_arguments)] // one more than the default threshold for `log_at_info`, the
                                     // once-per-listener-not-once-per-worker fix (see its own doc); grouping the existing seven into a
                                     // struct is a larger refactor this fix does not need.
async fn serve_listener(
    listener: tokio::net::TcpListener,
    router: Router,
    tls_cfg: Option<busbar_kernel::config::sections::TlsCfg>,
    secret_resolver: Arc<busbar_kernel::config::secret::SecretResolver>,
    label: &str,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    // The data workers' connection-placement balancer (`None` for the admin listener and
    // non-unix builds — those accept exactly as before). See `tls::ConnBalancer`.
    balancer: Option<tls::ConnBalancer>,
    // Whether THIS call logs "busbar listening" at INFO. `true` for the admin listener and for the
    // single data listener on non-unix builds (both call this exactly once); on unix's
    // thread-per-core data plane, `serve_thread_per_core` calls this once PER WORKER on the SAME
    // listen address — only the first call logs at INFO (matching 1.5.5's once-per-listener line),
    // the rest log the identical fact at DEBUG.
    log_at_info: bool,
) {
    match tls_cfg {
        None => {
            if log_at_info {
                tracing::info!(listen = %label, "busbar listening");
            } else {
                tracing::debug!(listen = %label, "busbar listening");
            }
            if let Err(e) = tls::serve_plain(listener, router, shutdown, balancer).await {
                die(format!("server error on '{label}': {e}"));
            }
        }
        Some(tls) => {
            // blocking-ffi-lint: allow — BOOT, once per listener, before that listener accepts.
            // `serve_listener` is never spawned as a task: the admin call runs directly under
            // `run()` on the control thread, and each per-worker data call is the FIRST thing its
            // freshly-built runtime `block_on`s — in both shapes this resolve parks a thread that
            // is not yet serving anything. It also completes before `tls::serve` below is reached,
            // so no connection on this listener can be waiting on it.
            //
            // The built-in axum/hyper listener below always declares itself TLS-capable
            // (`transport_capable = true`); `prepare` still fails closed rather than silently
            // downgrading to plaintext if the material cannot be resolved/parsed (DECISIONS #40).
            // Printed as `FailClosed` renders it — it already carries the label (see above).
            let security = busbar_core_connsec::prepare(label, Some(&tls), &secret_resolver, true)
                .unwrap_or_else(|e| die(e.to_string()));
            let mtls = tls.client_ca.is_some();
            if log_at_info {
                tracing::info!(listen = %label, mtls, "busbar listening (TLS)");
            } else {
                tracing::debug!(listen = %label, mtls, "busbar listening (TLS)");
            }
            if let Err(e) = tls::serve(listener, router, security, shutdown, balancer).await {
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
            tracing::warn!(
                diag = %busbar_substrate_values::diagnostics::SHUTDOWN_SIGNAL_HANDLER_INSTALL_FAILED.banner(),
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
                    diag = %busbar_substrate_values::diagnostics::SHUTDOWN_SIGNAL_HANDLER_INSTALL_FAILED.banner(),
                    error = %e, "failed to install SIGTERM handler; SIGTERM shutdown disabled"
                );
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
                    tracing::warn!(
                        diag = %busbar_substrate_values::diagnostics::SHUTDOWN_SIGNAL_HANDLER_INSTALL_FAILED.banner(),
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
                        diag = %busbar_substrate_values::diagnostics::SHUTDOWN_SIGNAL_HANDLER_INSTALL_FAILED.banner(),
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
                        "[warn] {}: jemalloc idle-purge fallback disabled: could not read \
                         opt.dirty_decay_ms ({e})",
                        busbar_substrate_values::diagnostics::JEMALLOC_IDLE_PURGE_FALLBACK_UNAVAILABLE
                            .banner()
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
        eprintln!(
            "[warn] {}: could not spawn the jemalloc idle-purge fallback thread ({e})",
            busbar_substrate_values::diagnostics::JEMALLOC_IDLE_PURGE_FALLBACK_UNAVAILABLE.banner()
        );
    }
}

// THE COMPOSITION ROOT. The kernel, the units, the planes and the transports composed in one
// place — the only place in the tree entitled to name all four. `main()` and `run()` call into it
// to register the plane axis, seal the boot registry, open the boot book and mount the root-driven
// surfaces.
mod root;

/// The stamp's derivation half, shared VERBATIM with `build.rs` (which `include!`s the same file).
/// Mounted only under `cfg(test)` because the binary itself reads the stamp out of `env!` constants
/// build.rs already baked — the functions are here so the decisions they encode can be asserted, not
/// so main can call them. See `src/build_stamp.rs`.
#[cfg(test)]
mod build_stamp;

#[cfg(test)]
#[path = "tests/tests.rs"]
mod tests;
