// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLUGIN LOADER: discovery, trust and the registry ([`registry`], [`sign`], [`tarball`]); the
//! ONE loading path and the ONE dispatcher of the memory ABI ([`dispatch`]: `load_linked` /
//! `load_dropped`), through which every store, secret, auth, hook and export plugin loads,
//! compiled in or dropped in (`BUSBAR-1.6.0.md` THE DESIGN §11); and the HOT lane the planes and
//! transports that have not moved to their door still ride ([`plane`], [`transport`]).
//!
//! No plugin of any kind loads through a JSON lane: the COLD/JSON lane is gone. What remains of
//! its symbols here is the HOT lane's handshake ([`validate_plugin`], `abi_handshake`), deleted
//! with the HOT lane.

use busbar_contract::abi::cold::{symbol, CallFn, CloseFn, FreeFn};
use busbar_contract::abi::cold::{PluginKindFn, TRANSPORT_VERSION};
use libloading::Library;
use std::path::Path;

pub mod auth_axis;
pub mod auth_door;
/// THE BOOT STAGES the loader owns: what config uses, Discover, Select and the one load
/// (`BUSBAR-1.6.0.md` THE DESIGN, §3).
pub mod boot;
pub mod carrier;
/// THE PUBLISHED CONFORMANCE SUITE (TODO ABI-b4): what every real plugin repo runs against the busbar
/// commit it pins, linked and dropped in, through the one loader. Behind `conformance`: a plugin's
/// dev-dependency turns it on; no busbar build ships it.
#[cfg(feature = "conformance")]
pub mod conformance;
/// THE ONE DISPATCHER of the memory ABI (`BUSBAR-1.6.0.md` THE DESIGN, §11): one loader path, one
/// crossing, tickets, wakes, deadlines and the watchdog, generic over the kind.
pub mod dispatch;
pub mod export_axis;
pub mod export_door;
pub mod fetch;
mod ffi_thread;
pub mod highwater;
pub mod hook_door;
mod host;
/// THE ONE DURABLE-WRITE OWNER, named once for the whole loader: every file or directory the loader
/// publishes (fetched artifacts, the high-water marks, plugin log directories) goes through it.
pub(crate) use busbar_kernel_wal::durable;
/// NEVER SHIPPED: the framed connection-table stand-in with in-process far ends (`test-support`,
/// and the published conformance suite's `far_ends`), for a build that cannot link the process's
/// connector. No TLS library: TLS stays in the connector.
#[cfg(any(test, feature = "test-support", feature = "conformance"))]
pub mod https_conns;
pub mod observe;
pub mod plane;
pub mod registry;
/// THE SECRET AXIS over the one dispatcher: every admitted secret plugin, linked or dropped in.
pub mod secret_calls;
// The former `busbar-plugin-sign` crate, folded in whole (DECISIONS #33): signature verify +
// trust evaluation is the loader's OWN job, not a crate the loader reaches for. Pure data +
// policy, no I/O -- the I/O that acts on its verdicts is `tarball`, `fetch` and `registry`.
/// TEST ONLY: a real door restated with one `tcp` need (the bind tests' subject; no plugin).
#[cfg(test)]
#[path = "tests/needs_restated.rs"]
mod needs_restated;
pub mod sign;
mod stage;
pub mod store_adapter;
pub mod store_v3;
pub mod tarball;
/// TEST ONLY: the test connection table. Also the published conformance suite's (`conformance`):
/// a plugin repo names this crate only as a dev-dependency, so it reaches no shipped closure.
#[cfg(any(test, feature = "test-support", feature = "conformance"))]
pub mod tcp_conns;
/// TEST ONLY: a local token issuer (an ES256 key, its JWKS, signed tokens) for the tests of a host
/// that loads a token-verifying auth plugin (`test-support`).
#[cfg(any(test, feature = "test-support"))]
pub mod test_issuer;
/// TEST ONLY: the fake-call store harness the kernel's minting tests share with this crate's own.
/// Compiled for this crate's tests and under the `test-support` feature, which only
/// busbar-kernel's `[dev-dependencies]` edge turns on; never in a shipped build.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
#[path = "tests/test_support.rs"]
pub mod test_support;
pub mod transport;
pub mod transport_adapter;

/// THE REGISTRY AS THE KERNEL READS IT (the contract's `PluginRows`).
pub mod rows;

pub use sign::EgressPolicy;

impl LinkedPlugin {
    /// A FIRST-PARTY memory-ABI plugin a build links: `name` aliased `alias`, of `kind`, at this
    /// loader's one version of the kind, published by busbar — the manifest its release tarball
    /// states — over its `door` (`plugin_door!`): the same door its `cdylib` exports.
    pub fn first_party_door(
        kind: &str,
        name: &str,
        alias: &str,
        door: busbar_contract::abi::mechanism::door::DoorFn,
    ) -> Self {
        let mut row = LinkedPlugin::door_of_kind(kind, name, door);
        row.manifest.alias = alias.into();
        row
    }
}

pub use carrier::{HotReply, ReplyStream, RequestHead, MAX_PLANE_REPLY_LEN};
pub use fetch::{fetch_plugins, FetchOutcome, FetchSpec};
pub use highwater::{HighWaterMarks, HIGH_WATER_FILE};
pub use plane::{
    link_plane, load_plane, load_plane_from_bytes, DynPlane, HotClaim, HotDeclaration, ServedPlane,
};
pub use registry::{
    inventory as inventory_tarballs, scan_and_validate, supported_abi, InventoryEntry, LinkedEntry,
    LinkedPlugin, LoadablePlugin, PluginRegistry, SkippedPlugin,
};
pub use stage::sweep_dead_staging;
pub use transport::{
    host_wake, link_transport, load_transport_from_bytes, wire_settings, Built, DeclCarrier,
    DeclFramer, DynTransport, WakeToken, HOST_WAKER,
};
pub use transport_adapter::{CarrierIo, WireTransport};

/// THE LOADER RE-EXPORTS NO CONTRACT TYPE (BOOT-LOOP step 3, ruling R2). A type the contract owns
/// is named from `busbar_contract::abi::*`, the crate that owns it; the loader path to it does not
/// compile. Each block below is one former loader re-export, and each must stay a compile error.
///
/// ```compile_fail
/// use busbar_plugin_loader::EndpointRequest;
/// ```
/// ```compile_fail
/// use busbar_plugin_loader::EndpointResponse;
/// ```
/// ```compile_fail
/// use busbar_plugin_loader::Route;
/// ```
/// ```compile_fail
/// use busbar_plugin_loader::RouteAuth;
/// ```
/// ```compile_fail
/// use busbar_plugin_loader::RouteMethod;
/// ```
/// ```compile_fail
/// use busbar_plugin_loader::CheckPhase;
/// ```
/// ```compile_fail
/// use busbar_plugin_loader::ExportField;
/// ```
/// ```compile_fail
/// use busbar_plugin_loader::ExportStream;
/// ```
/// ```compile_fail
/// use busbar_plugin_loader::HostResult;
/// ```
/// ```compile_fail
/// use busbar_plugin_loader::HttpRequest;
/// ```
/// ```compile_fail
/// use busbar_plugin_loader::HttpResponse;
/// ```
/// ```compile_fail
/// use busbar_plugin_loader::ColdEntry;
/// ```
/// ```compile_fail
/// use busbar_plugin_loader::HotDeclStr;
/// ```
/// ```compile_fail
/// use busbar_plugin_loader::HotPlaneDecl;
/// ```
/// ```compile_fail
/// use busbar_plugin_loader::HotHostVtable;
/// ```
/// ```compile_fail
/// use busbar_plugin_loader::HotStatusClass;
/// ```
pub mod contract_types_are_named_from_the_contract {}

/// INTERN a plugin name into a stable `&'static str`, reusing one allocation per unique name.
///
/// The hook routing seam and `DynAuth` carry `name: &'static str`, and a name string used to be
/// `Box::leak`ed on EVERY open — but hook and auth opens run per config/plugin reload, per `push_configure`, per
/// `fetch_status` (every Prometheus `/metrics/hooks` scrape refresh), per `fetch_schema`, and per
/// `resolve_on_error_chain`, so the leak was per-CALL and unbounded over the process lifetime, driven
/// by routine external scraping. Interning bounds it to ONE leak per DISTINCT plugin name for the life
/// of the process: a repeated open of the same plugin reuses the interned `&'static str`.
pub fn intern_name(name: &str) -> &'static str {
    use std::collections::HashSet;
    use std::sync::{Mutex, OnceLock};
    static INTERNED: OnceLock<Mutex<HashSet<&'static str>>> = OnceLock::new();
    let set = INTERNED.get_or_init(|| Mutex::new(HashSet::new()));
    let mut guard = set.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(existing) = guard.get(name) {
        return existing;
    }
    // First sighting of this name: leak it ONCE, then remember it so future opens reuse this alloc.
    let leaked: &'static str = Box::leak(name.to_string().into_boxed_str());
    guard.insert(leaked);
    leaked
}

/// `dlopen` on a worker that never retires. Mapping an image RUNS ITS ELF `.init_array` — that is
/// plugin code, on whatever thread called it, and it is as capable of arming the plugin's
/// `pthread_key` TLS destructor as any ABI symbol. Routed for the same reason [`ffi_guard`] is.
pub(crate) fn dlopen_on_worker(path: &std::ffi::OsStr) -> Result<Library, String> {
    // SAFETY (unchanged from the direct call this replaces): loading an operator-placed library runs
    // its init code, which is the same trust as compiling it in. Callers apply the trust gate first.
    match ffi_thread::on_plugin_thread(|| unsafe { Library::new(path) }) {
        Ok(r) => r.map_err(|e| e.to_string()),
        // An init constructor that PANICKED into us. Vanishingly rare, but the rendezvous must
        // produce a value rather than resume an unwind on a worker whose thread must not die.
        Err(_) => Err("the library's initializer panicked while loading".to_string()),
    }
}

/// `dlclose` on a worker that never retires. Unmapping runs the image's `.fini_array` — plugin code
/// again — and doing it on a caller thread would hand that thread plugin TLS at the exact moment the
/// image is going away, which is the crash in its purest form.
pub(crate) fn dlclose_on_worker(lib: Library) {
    #[cfg(test)]
    UNLOADS_ON_WORKER.with(|n| n.set(n.get() + 1));
    let _ = ffi_thread::on_plugin_thread(move || drop(lib));
}

#[cfg(test)]
thread_local! {
    /// TEST-ONLY: how many library unloads THIS THREAD has routed through [`dlclose_on_worker`]. An
    /// unload that happens by an implicit field/local drop instead runs the image's `.fini_array` on
    /// whatever thread dropped it, and a caller thread that later retires is the crash `ffi_thread`
    /// documents — a property no assertion on a returned value can see. Counting the routed unloads
    /// is what makes it observable.
    ///
    /// THREAD-LOCAL, not a global atomic: libtest runs siblings in parallel, and a sibling that
    /// loaded and unloaded a plugin between a global counter's two samples would satisfy a "went up"
    /// assertion while the path under test unloaded on the caller's thread — a test that passes in
    /// the red state. `dlclose_on_worker` is called on the routing thread (only the drop moves to
    /// the worker), so a per-thread count sees exactly this caller's unloads and nobody else's.
    pub(crate) static UNLOADS_ON_WORKER: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Run an FFI call `f` across the plugin ABI boundary under `catch_unwind`, converting a panic that
/// unwinds out of `f` into a fail-closed `Err` string. `op` names the crossing
/// (`open`/`call`/`close`/`free`/`abi`/`kind`) for the diagnostic. Every host-side ABI call site
/// routes through this so no crossing is unguarded.
///
/// WHAT IT CAN AND CANNOT CATCH — measured, not assumed (`loader_seam_tests`):
///
/// - An unwind raised by THIS process's Rust runtime — a compiled-in module, or host code on the
///   far side of the fn pointer — is caught and becomes `Err`. The ABI fn pointers are
///   `extern "C-unwind"`, so such an unwind is defined and reaches this frame.
/// - An unwind raised by a DLOPENED plugin's own panic runtime is NOT. A plugin cdylib statically
///   links its own copy of std, and std's `catch_unwind` recognises only exceptions its own copy
///   threw: anything else is a foreign exception, and the runtime ABORTS the process ("Rust cannot
///   catch foreign exceptions"). So for a dropped-in plugin, failing closed on a panic is the
///   PLUGIN's obligation, discharged on the plugin side of the boundary — the SDK's dispatchers
///   catch every panic in plugin code and answer `STATUS_PANIC`. A plugin not built with the SDK
///   that lets a panic escape its exported fns takes the engine down with it, and nothing on this
///   side of the seam can prevent that.
fn ffi_guard<R>(path: &str, op: &str, f: impl FnOnce() -> R) -> Result<R, String> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).map_err(|_| {
        format!("plugin '{path}' panicked across the ABI boundary in {op} (treated as failure)")
    })
}

/// [`ffi_guard`], but the crossing runs on a worker thread that NEVER retires.
///
/// THE COST MODEL, which is why this is a separate function rather than the default. Confining a
/// crossing costs a synchronous thread handoff — measured at ~41 us against ~0.9 us inline on a
/// 2-vCPU VM. That is irrelevant for a crossing that happens once per LOAD and unacceptable for one
/// that happens once per REQUEST, so the rare crossings are confined and the hot ones are not.
///
/// A crossing belongs here when it can plausibly be the FIRST thing to touch a plugin-side
/// `thread_local!` with a destructor on the calling thread, because that is what arms the plugin's
/// `pthread_key` and puts a destructor inside the image on that thread. See `ffi_thread` for the
/// full mechanism and `where_the_plugin_arms_its_tls_key` for the measurement that decided the split.
/// The library's `busbar_abi` entry, or the refusal that names a library without one.
pub(crate) fn abi_symbol(
    lib: &Library,
    display: &str,
) -> Result<busbar_contract::abi::cold::AbiFn, String> {
    unsafe { lib.get::<busbar_contract::abi::cold::AbiFn>(symbol::ABI) }
        .map(|f| *f)
        .map_err(|_| format!("'{display}' is not a busbar plugin (no busbar_abi symbol)"))
}

/// THE PLUGIN-ABI HANDSHAKE, one home for every load path that still answers it: the JSON lane's
/// residue, the upload vet, the HOT plane loader and the HOT transport loader. Calls `busbar_abi()` under
/// the ffi guard (it runs plugin code, so a panic fails the load closed) and refuses a plugin whose
/// plugin-ABI version is not the engine's, answering the version it verified. `noun` is how the
/// refusal names it (`plugin`, `plane`, `transport`), so each path's text is unchanged byte for
/// byte.
pub(crate) fn abi_handshake(
    abi: busbar_contract::abi::cold::AbiFn,
    display: &str,
    noun: &str,
) -> Result<u32, String> {
    let abi_version = ffi_guard_confined(display, "abi", || unsafe { abi() })?;
    if abi_version != TRANSPORT_VERSION {
        return Err(format!(
            "{noun} '{display}' targets transport ABI v{abi_version}, engine speaks v{TRANSPORT_VERSION}"
        ));
    }
    Ok(abi_version)
}

fn ffi_guard_confined<R>(path: &str, op: &str, f: impl FnOnce() -> R) -> Result<R, String> {
    ffi_thread::on_plugin_thread(f).map_err(|_| {
        format!("plugin '{path}' panicked across the ABI boundary in {op} (treated as failure)")
    })
}

/// Read the kind a mapped library states into an owned `String`. A memory-ABI image states it in
/// its door's head ([`busbar_contract::abi::mechanism::DOOR_SYMBOL`],
/// [`dispatch::load::kind_of_door`]): the SDK's `busbar_plugin_kind` answers for no door it
/// registered (a null kind). A plane or transport image registered through its decl answers
/// `busbar_plugin_kind()`. Any other library with no door is a 1.5.5-era JSON-contract plugin: its
/// kind symbol only CLASSIFIES it, and it is REFUSED here, naming the rebuild (no legacy loading,
/// THE DESIGN §11.8, ruling C21/ABI-o1), so no upload vet, inventory or kind gate takes it as valid.
fn read_plugin_kind(lib: &Library, display: &str) -> Result<String, String> {
    // SAFETY: `DOOR_SYMBOL` is typed `DoorFn` by the mechanism; the symbol is copied out as a plain
    // fn pointer and `lib` outlives every use of it here.
    let door = unsafe {
        lib.get::<busbar_contract::abi::mechanism::door::DoorFn>(
            busbar_contract::abi::mechanism::DOOR_SYMBOL,
        )
        .map(|s| *s)
    };
    if let Ok(door) = door {
        // Guarded: the door function is plugin code; a panic fails the read CLOSED.
        let kind = ffi_guard_confined(display, "door", || dispatch::load::kind_of_door(door))?
            .map_err(|e| format!("plugin '{display}' states no kind the host has: {e}"))?;
        return Ok(kind.word().to_string());
    }
    let f = unsafe { lib.get::<PluginKindFn>(symbol::PLUGIN_KIND) }.map_err(|_| {
        format!("'{display}' is not a busbar plugin (no busbar_plugin_kind symbol)")
    })?;
    let kind = kind_from_fn(*f, display)?;
    use busbar_contract::abi::mechanism::kind::{PLANE, TRANSPORT};
    if kind != PLANE && kind != TRANSPORT {
        return Err(format!(
            "plugin '{display}' states kind '{kind}' and exports no busbar_plugin_door — a plugin \
             built against the 1.5.5 JSON contract; {}",
            dispatch::load::REBUILD
        ));
    }
    Ok(kind)
}

/// Call a plugin's `busbar_plugin_kind()` — looked up or linked — and read the kind it names.
fn kind_from_fn(f: PluginKindFn, display: &str) -> Result<String, String> {
    // Guarded: `busbar_plugin_kind()` runs plugin code; a panic fails the load CLOSED, not an abort.
    let ptr = ffi_guard_confined(display, "kind", || unsafe { f() })?;
    // SAFETY: `ptr` came from the plugin's `busbar_plugin_kind()`, whose contract is a 'static
    // string; `kind_from_ptr` reads at most `MAX_PLUGIN_KIND_LEN + 1` bytes of it.
    unsafe { kind_from_ptr(ptr, display) }
}

/// Hard cap on the `busbar_plugin_kind()` string, NUL excluded. The kind is the ONE plugin-supplied
/// buffer in this ABI that crosses without a length, so the loader cannot cap a length the way it
/// caps a response (`MAX_PLUGIN_RESPONSE_LEN`), an open error, a plane vocabulary string or a log
/// record — it caps the SCAN instead. Every kind is a short closed-set identifier (`store`,
/// `secret`, ...); a pointer with no NUL inside this many bytes is not a kind, and is refused rather
/// than walked until some zero byte or an unmapped page turns up (the hand-written
/// `kind::EXPORT.as_ptr()` trap `busbar_contract::abi::cold` warns about).
const MAX_PLUGIN_KIND_LEN: usize = 32;

/// Read a plugin kind string from `ptr`, scanning at most [`MAX_PLUGIN_KIND_LEN`] + 1 bytes for its
/// NUL. Refuses a null pointer, a string with no NUL inside the cap, and non-UTF-8 bytes.
///
/// # Safety
/// `ptr`, when non-null, must address readable bytes up to its NUL or up to
/// `MAX_PLUGIN_KIND_LEN + 1` bytes, whichever comes first.
unsafe fn kind_from_ptr(ptr: *const u8, display: &str) -> Result<String, String> {
    if ptr.is_null() {
        return Err(format!("plugin '{display}' returned a null kind string"));
    }
    let mut len = 0;
    // SAFETY: the caller's contract covers every byte up to the NUL or the cap; the loop stops at
    // the first of the two, so it never reads past either.
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
        if len > MAX_PLUGIN_KIND_LEN {
            return Err(format!(
                "plugin '{display}' kind string has no NUL terminator within \
                 {MAX_PLUGIN_KIND_LEN} bytes — refusing to load (a kind is a short \
                 NUL-terminated identifier)"
            ));
        }
    }
    // SAFETY: `len` bytes from `ptr` were just read one by one above.
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    std::str::from_utf8(bytes)
        .map(str::to_string)
        .map_err(|_| format!("plugin '{display}' kind string is not valid UTF-8"))
}

/// The platform-native filename for a store plugin built from `crate_name` (e.g. `store_sqlite_plugin`
/// → `libbusbar_store_sqlite_plugin.so` / `.dylib` / `busbar_...dll`). Used to resolve `store: <name>`
/// against the plugins directory.
pub fn plugin_library_filename(crate_snake: &str) -> String {
    #[cfg(target_os = "windows")]
    {
        format!("{crate_snake}.dll")
    }
    #[cfg(target_os = "macos")]
    {
        format!("lib{crate_snake}.dylib")
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        format!("lib{crate_snake}.so")
    }
}

/// Validate that a library is a busbar plugin the engine can speak to — it exports the TRANSPORT
/// handshake at a matching version, a supported kind, and all operational symbols — WITHOUT
/// constructing an instance (no `open`). Returns the transport ABI version. Used to vet an uploaded
/// artifact before writing it into the plugins directory, and to inventory the directory.
#[cold] // boot/admin-only — keeps hot text dense (never inlined into a warm path)
#[inline(never)]
pub fn validate_plugin(lib_path: &Path) -> Result<u32, String> {
    let display = lib_path.display().to_string();
    // SAFETY: loading runs the library's init code — the same trust as loading it to serve, which is
    // itself the trust of compiling it in. The path is operator/admin-supplied, never request data.
    let lib = dlopen_on_worker(lib_path.as_os_str())
        .map_err(|e| format!("failed to load plugin '{display}': {e}"))?;
    // UNLOAD ON A WORKER, on EVERY exit path. The handshake below has five of them, and letting
    // `lib` drop out of scope would `dlclose` — running the image's `.fini_array`, which is plugin
    // code — on the CALLER's thread. A `.fini_array` that touches a plugin-side `thread_local!` with
    // a destructor arms the plugin's `pthread_key` on that thread, and a caller that later retires
    // (a libtest harness thread, a Tokio blocking thread) then calls that destructor inside the
    // image it just unmapped. Every other unload in this crate (`RawPlugin::drop`, `LoadGuard::drop`)
    // is already routed; the admin inventory/upload-vet path is the one that was not.
    let verdict = validate_mapped(&lib, &display);
    dlclose_on_worker(lib);
    verdict
}

/// The handshake half of [`validate_plugin`], over an ALREADY-MAPPED library. Split out so its five
/// exit paths cannot each be responsible for routing the unload — the caller unloads once.
fn validate_mapped(lib: &Library, display: &str) -> Result<u32, String> {
    let display = display.to_string();
    let abi_version = abi_handshake(abi_symbol(lib, &display)?, &display, "plugin")?;
    // The exported kind must be one the engine supports (a range exists for it).
    let plugin_kind = read_plugin_kind(lib, &display)?;
    if supported_abi(&plugin_kind).is_empty() {
        return Err(format!(
            "plugin '{display}' declares unsupported kind '{plugin_kind}'"
        ));
    }
    // Confirm the operational symbols resolve too, so a half-built library is caught here rather than
    // at first use.
    unsafe {
        lib.get::<busbar_contract::abi::cold::OpenFn>(symbol::OPEN)
            .map_err(|e| format!("plugin '{display}' missing busbar_open: {e}"))?;
        lib.get::<CallFn>(symbol::CALL)
            .map_err(|e| format!("plugin '{display}' missing busbar_call: {e}"))?;
        lib.get::<FreeFn>(symbol::FREE)
            .map_err(|e| format!("plugin '{display}' missing busbar_free: {e}"))?;
        lib.get::<CloseFn>(symbol::CLOSE)
            .map_err(|e| format!("plugin '{display}' missing busbar_close: {e}"))?;
    }
    Ok(abi_version)
}

/// One entry in a plugins-directory inventory: the library filename and whether it validated as a
/// busbar store plugin (with its ABI version, or the reason it didn't). Serialized by the admin
/// `GET /admin/plugins` endpoint.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PluginInfo {
    /// The library filename (not the full path).
    pub file: String,
    /// True when the library exports the store ABI at a version the engine speaks.
    pub valid: bool,
    /// The plugin's ABI version when `valid`.
    pub abi_version: Option<u32>,
    /// Why it didn't validate, when `!valid`.
    pub error: Option<String>,
}

/// Is `file` a dynamic-library name for this platform (by extension)?
///
/// THE COMPARISON FOLLOWS THE FILESYSTEM'S OWN CASE RULE, which is not the same rule everywhere.
/// NTFS is case-INSENSITIVE: `FOO.DLL` and `foo.dll` name the same file, `LoadLibrary` opens either,
/// and an artifact arriving from a Windows build system or an unzip commonly carries an uppercase
/// extension. A case-SENSITIVE `ends_with(".dll")` therefore reports "no plugins installed" for a
/// directory that plainly holds one — a silent omission from the operator-facing inventory
/// (`GET /admin/plugins`), which is the surface an operator uses to answer "did my install land".
/// On unix the extension is part of the name and `.SO` is a DIFFERENT file from `.so`, so folding
/// case there would make this claim a file is a library on the strength of a name the loader would
/// not resolve. One question, each platform's own answer — the same shape as the absolute-path check
/// in `mcp::config`.
fn is_library_file(file: &str) -> bool {
    if cfg!(target_os = "windows") {
        // BYTES, not a `&str` slice: `file[file.len() - 4..]` panics when byte `len - 4` is not a
        // char boundary, and a filename is arbitrary UTF-8 — a plugins directory holding one
        // non-ASCII name would take down the inventory scan. `.dll` is ASCII, so the byte-suffix
        // comparison answers exactly the same question with no boundary to land inside.
        let b = file.as_bytes();
        return b.len() >= 4 && b[b.len() - 4..].eq_ignore_ascii_case(b".dll");
    }
    let ext = if cfg!(target_os = "macos") {
        ".dylib"
    } else {
        ".so"
    };
    file.ends_with(ext)
}

/// List the dynamic-library FILENAMES in `dir` (sorted), WITHOUT opening any of them - the pure,
/// side-effect-free directory scan. Unlike [`inventory`], this NEVER `dlopen`s a library, so an
/// untrusted plugin's init/constructor code cannot run just from enumerating the directory. The trust
/// gate (and only then the ABI [`validate_plugin`], which does `dlopen`) is applied by the caller,
/// per file, so no library's code runs until it passes trust. A missing directory is an empty list.
pub fn list_plugin_files(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(file) = path.file_name().and_then(|f| f.to_str()) else {
            continue;
        };
        if path.is_file() && is_library_file(file) {
            out.push(file.to_string());
        }
    }
    out.sort();
    out
}

/// Inventory the plugins directory: every dynamic library present, each validated (ABI handshake) so
/// the admin surface can show what's installed and whether it's loadable. A missing directory is an
/// empty inventory, not an error.
///
/// WARNING: this `dlopen`s (via [`validate_plugin`]) EVERY library to run the ABI handshake, which
/// executes each library's init/constructor code. It must therefore only be called on libraries that
/// have ALREADY passed the trust gate - never as an untrusted-directory inspection. The admin catalog
/// uses [`list_plugin_files`] + a per-file trust check instead, and `dlopen`s only what trust permits.
pub fn inventory(dir: &Path) -> Vec<PluginInfo> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(file) = path.file_name().and_then(|f| f.to_str()) else {
            continue;
        };
        if !path.is_file() || !is_library_file(file) {
            continue;
        }
        match validate_plugin(&path) {
            Ok(v) => out.push(PluginInfo {
                file: file.to_string(),
                valid: true,
                abi_version: Some(v),
                error: None,
            }),
            Err(e) => out.push(PluginInfo {
                file: file.to_string(),
                valid: false,
                abi_version: None,
                error: Some(e),
            }),
        }
    }
    out.sort_by(|a, b| a.file.cmp(&b.file));
    out
}

#[cfg(test)]
#[path = "tests/lib_tests.rs"]
mod tests;

/// The loader's own crossings pinned against in-test fakes: the bounded kind read, the secret
/// deadline on the wire, and what the panic guard can and cannot catch.
#[cfg(test)]
#[path = "tests/loader_seam_tests.rs"]
mod loader_seam_tests;

/// DECISIONS #11's real test: ONE crate built both ways must be observationally identical. Declared
/// at the crate root rather than under `export` because it is not a test OF the export seam — it is
/// a test of the equivalence the two build shapes are supposed to have, and the export kind is
/// merely the first one with real plugins that can prove it (ARCHITECT ruling EXP2-PROOF
/// 2026-10-03: the spec's working proof of the plugin model, on the export kind's door registries).
#[cfg(test)]
#[path = "tests/export_conformance_tests.rs"]
mod export_conformance_tests;

/// The cold kinds' both-ways harness (DECISIONS #2 rule (1)): one plugin registered through the
/// linked door and the dropped-in door, its rows and its opened instance compared.
#[cfg(test)]
#[path = "tests/both_ways.rs"]
mod both_ways;

/// No rlib the test binary links exports `busbar_plugin_door` (the fat-LTO duplicate-symbol guard).
#[cfg(test)]
#[path = "tests/door_symbol_tests.rs"]
mod door_symbol_tests;

/// `kind: auth` through both doors — the auth kind's first both-ways witness (#2, steps (1)-(5)): the
/// compiled-in twin and the `cdylib`'s `busbar_call` put one wire, and the linked and dropped-in rows
/// open one module.
#[cfg(test)]
#[path = "tests/auth_conformance_tests.rs"]
mod auth_conformance_tests;

/// `kind: auth` through both doors on the memory ABI, VERIFY VERDICTS: the token cases driven to
/// every verdict (identify, reject, pass) over a second real auth plugin, one row and one answer
/// either way.
#[cfg(test)]
#[path = "tests/auth_verify_conformance_tests.rs"]
mod auth_verify_conformance_tests;

/// The dispatcher through both doors: one script, LINKED and DROPPED, byte-identical, and a RED
/// arm per mechanism rule.
/// The dispatcher's test plugin, compiled in: the LINKED door of `dispatch_tests` (the same
/// source is the `dispatch_test_plugin` example `cdylib`, the DROPPED door).
#[cfg(test)]
#[path = "../tests/fixtures/dispatch_test_plugin.rs"]
mod dispatch_test_plugin;

#[cfg(test)]
#[path = "tests/dispatch_tests.rs"]
mod dispatch_tests;

/// The plane door's test plugin, compiled in: the LINKED door of `plane_conformance_tests` (the
/// same source is the `plane_door_plugin` example `cdylib`, the DROPPED door).
#[cfg(test)]
#[path = "../tests/fixtures/plane_door_plugin.rs"]
mod plane_door_plugin;

/// The secret and export kind's answer checks, through the dispatcher's `Kind` adapter.
#[cfg(test)]
#[path = "tests/dispatch_kind_secret_export_tests.rs"]
mod dispatch_kind_secret_export_tests;

/// The transport kind's answer checks, through the dispatcher's `Kind` adapter.
#[cfg(test)]
#[path = "tests/dispatch_kind_transport_tests.rs"]
mod dispatch_kind_transport_tests;

/// The plane kind's answer checks, through the dispatcher's `Kind` adapter.
#[cfg(test)]
#[path = "tests/dispatch_kind_plane_tests.rs"]
mod dispatch_kind_plane_tests;

/// The store kind's answer checks, through the dispatcher's `Kind` adapter.
#[cfg(test)]
#[path = "tests/dispatch_kind_store_tests.rs"]
mod dispatch_kind_store_tests;

/// The hook kind's answer checks, through the dispatcher's `Kind` adapter.
#[cfg(test)]
#[path = "tests/dispatch_kind_hook_tests.rs"]
mod dispatch_kind_hook_tests;

/// The auth kind's answer checks, through the dispatcher's `Kind` adapter.
#[cfg(test)]
#[path = "tests/dispatch_kind_auth_tests.rs"]
mod dispatch_kind_auth_tests;

/// The both-ways harness on the memory ABI (TODO ABI-b4): one door loaded LINKED and DROPPED IN
/// through the one dispatcher, one script, two transcripts compared.
#[cfg(test)]
#[path = "tests/door_both_ways.rs"]
mod door_both_ways;

/// `kind: store` through both doors on the memory ABI: get/put identical, a broken store refused.
#[cfg(test)]
#[path = "tests/store_door_conformance_tests.rs"]
mod store_door_conformance_tests;

/// `kind: secret` through both doors on the memory ABI: resolve identical, a broken one refused.
#[cfg(test)]
#[path = "tests/secret_door_conformance_tests.rs"]
mod secret_door_conformance_tests;

/// `kind: transport` over the REAL `tcp` door, both ways: the shipped linked door against the pinned
/// cdylib, one script, equal transcripts and exact crossing counts.
#[cfg(test)]
#[path = "tests/transport_door_conformance_tests.rs"]
mod transport_door_conformance_tests;

/// `kind: hook` through both doors on the memory ABI: decide identical, a broken one refused.
#[cfg(test)]
#[path = "tests/hook_door_conformance_tests.rs"]
mod hook_door_conformance_tests;
