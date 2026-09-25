// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Platform staging for loading VERIFIED library bytes - the "bytes verified == bytes loaded"
//! (TOCTOU-safe) half of the loader.
//!
//! - **Linux**: `memfd_create` - the verified bytes are written to an anonymous in-memory fd and
//!   `dlopen`ed via `/proc/self/fd/N`. ZERO disk files, nothing to sweep, nothing to swap.
//! - **macOS / Windows** (and any non-Linux unix): the verified bytes are written to a file inside
//!   a PER-PROCESS private staging directory and loaded from there. Every process stages under ONE
//!   dedicated parent, `<temp>/busbar-plugin-staging-<uid>` on unix (`<temp>/busbar-plugin-staging`
//!   elsewhere), created `0700` and refused unless it is a real directory owned by this user; the
//!   per-process directory inside it is `busbar-plugins-<pid>-<random>`, `0700` on unix, created
//!   exactly once per process. On clean shutdown the library is unloaded FIRST, then the file (and,
//!   when empty, the per-process directory) is removed - the order Windows requires, since a mapped
//!   DLL's file cannot be deleted. A crash leaves the per-process directory behind;
//!   [`sweep_dead_staging`] removes any `busbar-plugins-<pid>-*` directory INSIDE THE PARENT whose
//!   pid is no longer alive at the next boot.
//!
//! The sweep lists the dedicated parent ONLY, never the OS temp directory itself: boot cost is
//! bounded by the number of busbar staging directories, not by the size of `$TMPDIR` (a full-temp
//! scan made boot unbounded on a host with a huge temp dir). Consequence: staging directories left
//! by a pre-1.6.0 busbar (which staged at the top level, `<temp>/busbar-plugins-<pid>-*`) are NOT
//! swept; they sit in the OS temp directory, which the OS temp cleaner reaps.
//!
//! A pre-existing on-disk library is NEVER loaded: staging always regenerates the file from the
//! verified in-memory bytes; anything on disk is throwaway output, never trusted input.

use libloading::Library;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

/// Prefix for the per-process private staging directory (and the dead-pid sweep match).
const STAGING_PREFIX: &str = "busbar-plugins-";

/// Name stem of the ONE dedicated parent every per-process staging directory lives under. On unix
/// the effective uid is appended (`busbar-plugin-staging-<uid>`) so two users sharing a `/tmp`
/// each get their own owner-only parent instead of the second one failing on the first's `0700`.
const STAGING_PARENT_STEM: &str = "busbar-plugin-staging";

/// The dedicated staging parent under `temp_base` (not created; see [`ensure_staging_parent`]).
pub(crate) fn staging_parent_in(temp_base: &std::path::Path) -> PathBuf {
    #[cfg(unix)]
    {
        // SAFETY: geteuid has no preconditions and cannot fail.
        let uid = unsafe { libc::geteuid() };
        temp_base.join(format!("{STAGING_PARENT_STEM}-{uid}"))
    }
    #[cfg(not(unix))]
    {
        temp_base.join(STAGING_PARENT_STEM)
    }
}

/// Is `parent` safe to stage under / sweep: a REAL directory (inspected no-follow, so a planted
/// symlink is refused, never traversed) and, on unix, owned by this process's effective uid. A
/// directory someone else owns could have entries swapped or planted under us, so it is refused.
fn parent_is_trusted(parent: &std::path::Path) -> Result<std::fs::Metadata, String> {
    let meta = parent.symlink_metadata().map_err(|e| {
        format!(
            "cannot inspect plugin staging parent {}: {e}",
            parent.display()
        )
    })?;
    if !meta.file_type().is_dir() {
        return Err(format!(
            "plugin staging parent {} is not a real directory (a symlink or file is refused)",
            parent.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        // SAFETY: geteuid has no preconditions and cannot fail.
        let euid = unsafe { libc::geteuid() };
        if meta.uid() != euid {
            return Err(format!(
                "plugin staging parent {} is owned by uid {}, not this process's uid {euid}; \
                 refusing to stage under it",
                parent.display(),
                meta.uid()
            ));
        }
    }
    Ok(meta)
}

/// Create (or adopt, after verification) the dedicated staging parent under `temp_base`, owner-only
/// (`0700` on unix). An existing parent is adopted ONLY if [`parent_is_trusted`] accepts it; if it
/// is ours but its mode was loosened, it is tightened back to `0700`.
fn ensure_staging_parent(temp_base: &std::path::Path) -> Result<PathBuf, String> {
    let parent = staging_parent_in(temp_base);
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    match builder.create(&parent) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => {
            return Err(format!(
                "cannot create plugin staging parent {}: {e}",
                parent.display()
            ))
        }
    }
    let _meta = parent_is_trusted(&parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if _meta.permissions().mode() & 0o077 != 0 {
            std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).map_err(
                |e| {
                    format!(
                        "cannot restrict plugin staging parent {} to 0700: {e}",
                        parent.display()
                    )
                },
            )?;
        }
    }
    Ok(parent)
}

/// The staged backing that must outlive the loaded [`Library`]. Dropping it releases the staging
/// resource: the memfd closes (Linux), or the private temp file is removed (and its directory, when
/// this was the last staged file). It MUST be declared AFTER the `Library` in any holder struct so
/// the library unloads first (Rust drops fields in declaration order).
pub(crate) enum Staged {
    /// Linux memfd: the anonymous fd holding the library bytes. Kept open for the library's whole
    /// life (the dlopen'd mapping does not need it, but holding it is free and unambiguous).
    #[cfg(target_os = "linux")]
    Memfd { _fd: std::os::fd::OwnedFd },
    /// A file inside the per-process private staging directory (non-Linux, or Linux memfd
    /// fallback). Removed on drop; the (shared, per-process) directory is removed too once empty.
    TempFile { path: PathBuf },
}

impl Staged {
    /// TEST-ONLY: the private staging file backing this load, or `None` when the load touched no
    /// disk at all (the Linux memfd path). Tests assert on THIS instance's own artifact rather than
    /// counting `busbar-plugins-<pid>-*` entries process-wide: the count is both flaky (a
    /// concurrent test in the same binary stages/releases files between the two samples) and weak
    /// (`after <= before` still passes while this load's file leaks, if someone else's file went
    /// away). An exact path is immune to both.
    #[cfg(test)]
    pub(crate) fn temp_path(&self) -> Option<&std::path::Path> {
        match self {
            #[cfg(target_os = "linux")]
            Staged::Memfd { .. } => None,
            Staged::TempFile { path } => Some(path.as_path()),
        }
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        match self {
            #[cfg(target_os = "linux")]
            Staged::Memfd { .. } => {} // the OwnedFd closes itself
            Staged::TempFile { path } => {
                // Unload happened first (field order in the holder). Release under the shared
                // staging lock: remove the file, and remove the per-process directory only when
                // this was the LAST live staged file - the refcount makes release atomic with any
                // concurrent stage, so a drop can never yank the directory out from under a load.
                release_temp_file(path);
            }
        }
    }
}

/// Hex-encode `n` random bytes from the OS RNG (staging-dir suffix: a pid alone is predictable).
fn random_hex(n: usize) -> String {
    let mut buf = vec![0u8; n];
    // A failed RNG read falls back to zeroes; exclusivity still comes from `create_dir` failing
    // closed on an existing path, entropy only adds unpredictability.
    let _ = getrandom::fill(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// Shared staging state: the per-process private directory (created lazily, re-created if the
/// last release removed it) plus a LIVE-FILE REFCOUNT. All creates and releases run under this one
/// lock, so "remove the dir when the last staged file goes" can never race a concurrent stage.
struct StagingState {
    dir: Option<PathBuf>,
    live: usize,
}

fn staging_state() -> &'static Mutex<StagingState> {
    static STATE: OnceLock<Mutex<StagingState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(StagingState { dir: None, live: 0 }))
}

/// Ensure the per-process private staging directory exists (caller holds the staging lock):
/// `<temp>/busbar-plugin-staging-<uid>/busbar-plugins-<pid>-<random>`, mode `0700` on unix. `create_dir` (not
/// `create_dir_all`) fails if the path already exists, so a pre-planted directory is never adopted.
fn ensure_staging_dir(state: &mut StagingState) -> Result<PathBuf, String> {
    if let Some(dir) = &state.dir {
        if dir.is_dir() {
            return Ok(dir.clone());
        }
    }
    let name = format!("{STAGING_PREFIX}{}-{}", std::process::id(), random_hex(8));
    let dir = ensure_staging_parent(&std::env::temp_dir())?.join(name);
    // `mode()` (unix-only) is the only reason this needs to be `mut` -- `create()` itself takes
    // `&self`. Non-unix targets (Windows CI caught this) see it as genuinely unused.
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(&dir).map_err(|e| {
        format!(
            "cannot create private plugin staging dir {}: {e}",
            dir.display()
        )
    })?;
    state.dir = Some(dir.clone());
    Ok(dir)
}

/// Release one staged file (drop path): remove the file and, when it was the LAST live one, the
/// per-process directory too (clean-shutdown delete). Runs entirely under the staging lock.
fn release_temp_file(path: &PathBuf) {
    let mut state = staging_state().lock().unwrap_or_else(|p| p.into_inner());
    let _ = std::fs::remove_file(path);
    state.live = state.live.saturating_sub(1);
    if state.live == 0 {
        if let Some(dir) = state.dir.take() {
            let _ = std::fs::remove_dir(&dir);
        }
    }
}

/// Monotonic per-process staging-file sequence (concurrent loads never collide on a name).
pub(crate) fn next_seq() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    SEQ.fetch_add(1, Ordering::Relaxed)
}

/// The platform dynamic-library suffix, used only to give the staged file a plausible extension
/// (some loaders key off it). Load correctness does not depend on it.
fn dylib_suffix() -> &'static str {
    if cfg!(target_os = "windows") {
        ".dll"
    } else if cfg!(target_os = "macos") {
        ".dylib"
    } else {
        ".so"
    }
}

/// Stage `bytes` into the per-process private directory and return the created file path. The file
/// is opened `create_new` (never adopting a pre-planted file) and `0600` on unix. Runs under the
/// staging lock so a concurrent last-file release cannot remove the directory mid-create.
fn stage_temp_file(bytes: &[u8]) -> Result<PathBuf, String> {
    let mut state = staging_state().lock().unwrap_or_else(|p| p.into_inner());
    let dir = ensure_staging_dir(&mut state)?;
    let path = dir.join(format!("lib-{}{}", next_seq(), dylib_suffix()));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(&path)
        .map_err(|e| format!("cannot create staged plugin file {}: {e}", path.display()))?;
    if let Err(e) = f.write_all(bytes).and_then(|()| f.flush()) {
        drop(f);
        let _ = std::fs::remove_file(&path);
        return Err(format!(
            "cannot write staged plugin file {}: {e}",
            path.display()
        ));
    }
    // Close before dlopen (Windows dislikes an open writable handle racing the loader's read).
    drop(f);
    state.live += 1;
    Ok(path)
}

/// Load a dynamic library from EXACTLY the in-memory `bytes` supplied - the verified-bytes ==
/// loaded-bytes entrypoint. On Linux this uses `memfd_create` + `/proc/self/fd/N` (zero disk
/// files); elsewhere (or if memfd fails) the bytes are staged into the per-process private `0700`
/// directory and loaded from there. `display` labels errors. Returns the mapped [`Library`] plus
/// the [`Staged`] guard that must be dropped AFTER the library.
pub(crate) fn load_library_from_bytes(
    bytes: &[u8],
    display: &str,
) -> Result<(Library, Staged), String> {
    #[cfg(target_os = "linux")]
    {
        match load_via_memfd(bytes, display) {
            Ok(loaded) => return Ok(loaded),
            Err(e) => {
                // memfd requires a mounted /proc for the dlopen path; fall back to the private
                // temp-file staging (same verified bytes, weaker zero-disk property) rather than
                // fail a legitimate load on an exotic mount setup.
                eprintln!(
                    "[warn] memfd load unavailable for plugin '{display}' ({e}); falling back to \
                     private temp staging"
                );
            }
        }
    }
    let path = stage_temp_file(bytes)?;
    // SAFETY: running an operator-trusted plugin's init code - the same trust as compiling it in.
    // The file was created by us, in a directory we created 0700, from already-verified bytes.
    let lib = crate::dlopen_on_worker(std::ffi::OsStr::new(&path)).map_err(|e| {
        let msg = format!("failed to load plugin '{display}': {e}");
        // `stage_temp_file` already did `state.live += 1`, but no `Staged::TempFile` is
        // constructed on this error path, so `release_temp_file` (the only decrementer) would never
        // run — leaking a `live` count that keeps the clean-shutdown `live == 0` dir-removal from
        // ever firing. Release here (removes the file AND decrements `live`, reclaiming the dir when
        // it hits 0), not a bare `remove_file`.
        release_temp_file(&path);
        msg
    })?;
    Ok((lib, Staged::TempFile { path }))
}

/// Linux zero-disk load: write the verified bytes to an anonymous memfd and dlopen it via
/// `/proc/self/fd/N`. Nothing ever touches the filesystem.
#[cfg(target_os = "linux")]
fn load_via_memfd(bytes: &[u8], display: &str) -> Result<(Library, Staged), String> {
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
    // Raw `syscall(SYS_memfd_create, ...)` rather than the named `libc::memfd_create` wrapper:
    // the wrapper is only a LINK-time convenience symbol some libc.so/cross-sysroots omit even
    // though the underlying syscall (present on any real Linux 3.17+ kernel, glibc has offered
    // the wrapper since 2.27) always exists. Verified: `taiki-e/upload-rust-binary-action`'s
    // aarch64-unknown-linux-gnu cross toolchain failed to LINK `libc::memfd_create` ("undefined
    // reference to `memfd_create'") while a native x86_64 build and an independent apt-installed
    // aarch64 cross toolchain (Ubuntu 24.04, gcc-aarch64-linux-gnu + libc6-dev-arm64-cross) both
    // linked it fine -- the syscall route sidesteps this stub-symbol gap entirely, on any sysroot.
    // SAFETY: plain syscall; the name is a debugging label (NUL-terminated, no user input).
    let raw = unsafe {
        libc::syscall(
            libc::SYS_memfd_create,
            c"busbar-plugin".as_ptr(),
            libc::MFD_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(format!(
            "memfd_create failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: `raw` is a freshly created, owned fd. `libc::syscall` returns `c_long`; a real fd
    // from a successful memfd_create always fits in `RawFd` (i32) -- checked, not assumed.
    let raw_fd =
        i32::try_from(raw).map_err(|_| format!("memfd_create returned out-of-range fd: {raw}"))?;
    let fd: OwnedFd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    {
        let mut f = std::fs::File::from(fd.try_clone().map_err(|e| format!("memfd dup: {e}"))?);
        f.write_all(bytes)
            .and_then(|()| f.flush())
            .map_err(|e| format!("memfd write: {e}"))?;
    }
    let path = format!("/proc/self/fd/{}", fd.as_raw_fd());
    // SAFETY: same operator-trust as any plugin load; the fd content is exactly the verified bytes
    // and is not reachable by path from any other process's namespace.
    let lib = crate::dlopen_on_worker(std::ffi::OsStr::new(&path))
        .map_err(|e| format!("failed to load plugin '{display}' from memfd: {e}"))?;
    Ok((lib, Staged::Memfd { _fd: fd }))
}

/// Is the process with `pid` alive? Unix: `kill(pid, 0)` (EPERM still means alive). Non-unix:
/// unknown - report alive so the sweep stays conservative (Windows removal of a live dir fails
/// naturally on the locked DLL anyway).
fn pid_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        let Ok(pid_i) = i32::try_from(pid) else {
            return false;
        };
        // SAFETY: signal 0 performs error checking only; no signal is delivered.
        let rc = unsafe { libc::kill(pid_i, 0) };
        rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        true
    }
}

/// BOOT-TIME sweep of orphaned staging directories: any `busbar-plugins-<pid>-*` inside the
/// dedicated staging parent (`<temp>/busbar-plugin-staging-<uid>`) whose pid is DEAD (a prior
/// busbar crashed before its clean-shutdown cleanup) is removed - the files are unlocked once the
/// process died. The current process's own directory and any live process's directory are left
/// alone. Returns the number of directories removed.
///
/// ONLY the parent is listed, never the OS temp directory: boot cost is bounded by busbar's own
/// staging entries, not by `$TMPDIR`'s size. Pre-1.6.0 top-level `<temp>/busbar-plugins-*`
/// leftovers are therefore not swept (the OS temp cleaner reaps them). A parent that is missing,
/// a symlink, or owned by another uid is not listed at all (returns 0).
///
/// UNIX-ONLY IN EFFECT, and the consequence is stated rather than left in [`pid_alive`]'s comment.
/// The sweep's whole decision is "is this pid dead", and off unix [`pid_alive`] has no
/// implementation and answers `true` for every pid — so this function walks the directory and
/// removes NOTHING on Windows. It is a no-op there, not a weaker sweep. What that costs is disk:
/// a Windows deployment accumulates one abandoned staging directory per crash until the OS temp
/// cleaner or an operator removes it. What it does NOT cost is integrity, and that is why the
/// no-op is tolerable rather than a hole: staging always regenerates the library from the verified
/// in-memory bytes, so a leftover directory is never trusted input and can never be loaded from.
/// Closing it needs a real Windows liveness probe (`OpenProcess` + `GetExitCodeProcess`).
pub fn sweep_dead_staging() -> usize {
    sweep_dead_staging_under(&std::env::temp_dir(), &mut list_dir_names)
}

/// The production directory lister: the entry names of `dir` (one `read_dir` of that directory,
/// nothing recursive).
fn list_dir_names(dir: &std::path::Path) -> std::io::Result<Vec<std::ffi::OsString>> {
    Ok(std::fs::read_dir(dir)?
        .flatten()
        .map(|e| e.file_name())
        .collect())
}

/// [`sweep_dead_staging`] with the temp base and the directory lister injected, so a test can
/// point it at a private root and COUNT what it lists (the full-temp-scan regression is an
/// iteration count, not a timing). `list` is called on the staging parent only.
pub(crate) fn sweep_dead_staging_under(
    temp_base: &std::path::Path,
    list: &mut dyn FnMut(&std::path::Path) -> std::io::Result<Vec<std::ffi::OsString>>,
) -> usize {
    let parent = staging_parent_in(temp_base);
    // Never list (or remove under) a parent that is absent, a symlink, or someone else's.
    if parent_is_trusted(&parent).is_err() {
        return 0;
    }
    let Ok(names) = list(&parent) else {
        return 0;
    };
    let mut removed = 0usize;
    for name in names {
        let Some(name_str) = name.to_str() else {
            continue;
        };
        let Some(rest) = name_str.strip_prefix(STAGING_PREFIX) else {
            continue;
        };
        // `<pid>-<random>`: parse the pid segment.
        let Some(pid) = rest.split('-').next().and_then(|p| p.parse::<u32>().ok()) else {
            continue;
        };
        if pid == std::process::id() || pid_alive(pid) {
            continue;
        }
        let path = parent.join(&name);
        // NO-FOLLOW: `is_dir()` follows symlinks, so a symlink named `busbar-plugins-<dead-pid>-*`
        // could aim `remove_dir_all` at an ATTACKER-CHOSEN directory outside staging.
        // `symlink_metadata` inspects the entry ITSELF; a symlink is not a directory here, so it
        // is skipped, never traversed. Only a real directory is swept.
        let is_real_dir = path
            .symlink_metadata()
            .map(|m| m.file_type().is_dir())
            .unwrap_or(false);
        if is_real_dir && std::fs::remove_dir_all(&path).is_ok() {
            removed += 1;
        }
    }
    removed
}

#[cfg(test)]
#[path = "tests/stage_tests.rs"]
mod tests;
