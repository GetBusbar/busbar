// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Platform staging for loading VERIFIED library bytes - the "bytes verified == bytes loaded"
//! (TOCTOU-safe) half of the loader.
//!
//! - **Linux**: `memfd_create` - the verified bytes are written to an anonymous in-memory fd,
//!   SEALED (no write, grow or shrink, ever again), and `dlopen`ed via `/proc/self/fd/N`. ZERO disk
//!   files, nothing to sweep, nothing to swap. glibc's `dlopen` matches an already-loaded object
//!   by its NAME STRING before anything else, and an image can outlive its handle (`DF_1_NODELETE`,
//!   a thread-local destructor pinning it). So a name is never handed to a second image while an image is
//!   still registered under it: when a staged image is released but stays resident, its memfd is
//!   RETAINED for the life of the process (see [`retire_memfd`]), and `N` cannot be recycled for a
//!   replacement that would otherwise be served the old image instead of its own verified bytes.
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
//!   The staged file is PINNED: the handle that wrote it is kept (unix: made `0400`; Windows:
//!   reopened read-only, sharing no write and no delete), and the bytes, owner, mode and identity at
//!   the name are checked through it after the write and immediately before and after the load;
//!   any difference refuses the load. The loaders open by path, so this is narrower than the memfd
//!   seal: the residual risk is stated at [`load_via_staged_file`].
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
    /// Linux memfd: the sealed anonymous fd holding the library bytes, whose number is the image's
    /// `dlopen` NAME (`/proc/self/fd/N`). Kept open for the library's whole life, and past it when
    /// the image stays resident ([`retire_memfd`]). `None` only once the drop has retired it.
    #[cfg(target_os = "linux")]
    Memfd { fd: Option<std::os::fd::OwnedFd> },
    /// A file inside the per-process private staging directory (non-Linux, or Linux memfd
    /// fallback), with the handle that wrote and verified it, held for the library's life (on
    /// Windows that handle's share mode is what keeps the file from being rewritten, renamed or
    /// deleted under the mapped image). Removed on drop, the handle first; the (shared,
    /// per-process) directory is removed too once empty. `pin` is `None` only once dropped.
    TempFile {
        path: PathBuf,
        pin: Option<std::fs::File>,
    },
}

impl Drop for Staged {
    fn drop(&mut self) {
        match self {
            // Unload happened first (field order in the holder). The fd closes, unless the image
            // is still resident under its name, in which case the name stays reserved.
            #[cfg(target_os = "linux")]
            Staged::Memfd { fd } => {
                if let Some(fd) = fd.take() {
                    retire_memfd(fd);
                }
            }
            Staged::TempFile { path, pin } => {
                // The pin closes first: on Windows a file held open without delete sharing cannot
                // be removed.
                drop(pin.take());
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

/// Stage `bytes` into the per-process private directory and return the created file's path and
/// the PIN: the open handle the bytes were verified through (see [`pin_staged`]). The file is
/// opened `create_new` (never adopting a pre-planted file; on unix also `O_NOFOLLOW`, `0600`).
/// Runs under the staging lock so a concurrent last-file release cannot remove the directory
/// mid-create.
fn stage_temp_file(bytes: &[u8]) -> Result<(PathBuf, std::fs::File), String> {
    let mut state = staging_state().lock().unwrap_or_else(|p| p.into_inner());
    let dir = ensure_staging_dir(&mut state)?;
    let path = dir.join(format!("lib-{}{}", next_seq(), dylib_suffix()));
    let f = create_staged(&path)
        .map_err(|e| format!("cannot create staged plugin file {}: {e}", path.display()))?;
    // The file is ours from here (create_new): any failure removes it.
    let pin = pin_staged(f, &path, bytes).map_err(|e| {
        let _ = std::fs::remove_file(&path);
        format!("cannot stage plugin file {}: {e}", path.display())
    })?;
    state.live += 1;
    Ok((path, pin))
}

/// Create the staging file: exclusive (`create_new`), never through a symlink, owner-only.
#[cfg(unix)]
fn create_staged(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

/// Windows `FILE_SHARE_READ`: other openers may read, and nothing else (no write, no delete, so no
/// rename over or of the file) while a handle opened with only this share mode is held.
#[cfg(windows)]
const FILE_SHARE_READ: u32 = 0x0000_0001;
/// Windows `FILE_FLAG_OPEN_REPARSE_POINT`: open a symlink/junction itself, never its target, so a
/// reparse point planted at the staged name is seen (and refused) instead of followed.
#[cfg(windows)]
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

/// Create the staging file: exclusive (`create_new`), and shared with NOBODY while we write it.
#[cfg(windows)]
fn create_staged(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(0)
        .open(path)
}

/// Write the verified `bytes` through `f` and turn it into the PIN: the handle the staged file is
/// verified through, then and before and after the load.
///
/// Unix: the SAME handle that wrote the bytes is kept (no reopen, so no window between writing and
/// holding), the file is made read-only (`fchmod 0400`) through it, and the bytes are read back
/// through it and compared.
///
/// Windows: the exclusive write handle is closed and the file reopened READ-ONLY sharing only
/// read: the image loader's own open (read/execute, sharing read and delete) is compatible with
/// it, but no writer, no delete and no rename over the name can open the file while it is held.
/// A tamper in the instant between close and reopen is caught by reading the bytes back through
/// the new handle; from then on the OS holds the name to these bytes.
fn pin_staged(
    mut f: std::fs::File,
    path: &std::path::Path,
    bytes: &[u8],
) -> Result<std::fs::File, String> {
    f.write_all(bytes)
        .and_then(|()| f.flush())
        .map_err(|e| format!("write: {e}"))?;
    #[cfg(unix)]
    let pin = {
        use std::os::unix::fs::PermissionsExt as _;
        f.set_permissions(std::fs::Permissions::from_mode(0o400))
            .map_err(|e| format!("make read-only: {e}"))?;
        f
    };
    #[cfg(windows)]
    let pin = {
        use std::os::windows::fs::OpenOptionsExt as _;
        drop(f);
        std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|e| format!("reopen read-only: {e}"))?
    };
    verify_pinned(&pin, path, bytes)?;
    Ok(pin)
}

/// Does `f`, read from its start through THIS handle, hold exactly `bytes` and nothing more?
fn holds_exactly(mut f: &std::fs::File, bytes: &[u8]) -> std::io::Result<bool> {
    use std::io::{Read as _, Seek as _};
    f.seek(std::io::SeekFrom::Start(0))?;
    let mut buf = vec![0u8; 64 * 1024];
    let mut at = 0usize;
    loop {
        let n = match f.read(&mut buf) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if n == 0 {
            return Ok(at == bytes.len());
        }
        let end = at + n;
        if end > bytes.len() || buf[..n] != bytes[at..end] {
            return Ok(false);
        }
        at = end;
    }
}

/// The staged file is still EXACTLY the verified bytes, at the name the loader opens. `Err` names
/// what differs. Run after the write, immediately before the load and immediately after it.
///
/// Unix: through the pin, a regular file owned by this uid, mode `0400`, one link, the verified
/// length and bytes; and the NAME, inspected without following a symlink, is that same file
/// (device and inode equal to the pin's). Any rewrite in place, chmod, hard link, or rename over
/// the name since the last check is refused.
#[cfg(unix)]
fn verify_pinned(pin: &std::fs::File, path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;
    let held = pin.metadata().map_err(|e| format!("stat: {e}"))?;
    // SAFETY: geteuid has no preconditions and cannot fail.
    let euid = unsafe { libc::geteuid() };
    if !held.file_type().is_file() {
        return Err("is not a regular file".into());
    }
    if held.uid() != euid {
        return Err(format!("is owned by uid {}, not {euid}", held.uid()));
    }
    if held.mode() & 0o7777 != 0o400 {
        return Err(format!("has mode {:o}, not 400", held.mode() & 0o7777));
    }
    if held.nlink() != 1 {
        return Err(format!("has {} links, not 1", held.nlink()));
    }
    if held.len() != bytes.len() as u64
        || !holds_exactly(pin, bytes).map_err(|e| format!("read back: {e}"))?
    {
        return Err("does not hold the verified bytes".into());
    }
    let named = path
        .symlink_metadata()
        .map_err(|e| format!("is gone from its name: {e}"))?;
    if !named.file_type().is_file() || named.dev() != held.dev() || named.ino() != held.ino() {
        return Err("is no longer the file at its name (replaced since it was verified)".into());
    }
    Ok(())
}

/// Windows: through the pin, a regular file (not a reparse point) of the verified length and
/// bytes; and the NAME, opened afresh (not following a reparse point), holds the same bytes. While
/// the pin is held the OS refuses any writer, delete or rename, so the second read is the belt to
/// that brace: it is what binds the name the loader opens to the bytes verified.
#[cfg(windows)]
fn verify_pinned(pin: &std::fs::File, path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    use std::os::windows::fs::OpenOptionsExt as _;
    let regular_with_bytes = |f: &std::fs::File, what: &str| -> Result<(), String> {
        let m = f.metadata().map_err(|e| format!("stat {what}: {e}"))?;
        if !m.file_type().is_file() || m.file_type().is_symlink() {
            return Err(format!("{what} is not a regular file"));
        }
        if m.len() != bytes.len() as u64
            || !holds_exactly(f, bytes).map_err(|e| format!("read back {what}: {e}"))?
        {
            return Err(format!("{what} does not hold the verified bytes"));
        }
        Ok(())
    };
    regular_with_bytes(pin, "the pinned handle")?;
    let named = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|e| format!("cannot be reopened at its name: {e}"))?;
    regular_with_bytes(&named, "the file at its name")
}

#[cfg(test)]
std::thread_local! {
    /// TEST WITNESS: the libraries the calling thread staged through [`load_library_from_bytes`]
    /// (the staging is entered on the loading thread; only the `dlopen` runs on a worker).
    pub(crate) static STAGED_HERE: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Load a dynamic library from EXACTLY the in-memory `bytes` supplied - the verified-bytes ==
/// loaded-bytes entrypoint. On Linux this uses `memfd_create` + `/proc/self/fd/N` (zero disk
/// files); elsewhere (or if memfd fails) the bytes are staged into the per-process private `0700`
/// directory, pinned, and loaded from there ([`load_via_staged_file`]). `display` labels errors.
/// Returns the mapped [`Library`] plus the [`Staged`] guard that must be dropped AFTER the library.
pub(crate) fn load_library_from_bytes(
    bytes: &[u8],
    display: &str,
) -> Result<(Library, Staged), String> {
    #[cfg(test)]
    STAGED_HERE.with(|n| n.set(n.get() + 1));
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
    load_via_staged_file(bytes, display, &mut |_| {})
}

/// The staging-file load (macOS, Windows, any non-Linux unix, and Linux's memfd fallback).
/// `before_load` runs after the bytes are staged and verified, immediately before the pre-load
/// check: production passes a no-op; the tests use it to tamper with the staged file there.
///
/// The staged file is verified through its pin after the write ([`pin_staged`]), again
/// immediately before the `dlopen`, and again immediately after it ([`verify_pinned`]). Any
/// difference refuses the load; after the `dlopen` the library is unloaded first.
///
/// RESIDUAL RISK, stated, not hidden (W23; the memfd path above has none of it):
/// - The platform loaders open a library BY PATH (`dlopen`/dyld; `LoadLibraryW`). No public API
///   on macOS loads a Mach-O image from an open descriptor or from memory, so the pin cannot be
///   handed to the loader; it can only prove what sits at the name around the call.
/// - macOS / unix fallback: a process running as THIS uid (or root) can chmod, rewrite or rename
///   inside our `0700` directory. One that swaps other bytes in after the pre-load check and swaps
///   the original back before the post-load check gets them mapped, and their initialisers run,
///   with nothing left for either check to see. It can likewise reopen the file for write before
///   the load (chmod it back to 0400 in time for the checks) and rewrite it in place after: a
///   `MAP_PRIVATE` mapping does not snapshot pages not yet faulted in. No other uid can reach the
///   file: the parent and the per-process directory are owner-checked `0700`.
/// - Windows: while the pin is held (the library's whole life) the OS refuses any writer, delete
///   or rename of the file, so the bytes at the name cannot change; the one instant without a pin,
///   between the exclusive write handle's close and the read-only reopen, is covered by the
///   read-back through the new handle. What remains is what the loader itself resolves outside
///   that file (its own search for the DLL's imports), which this staging does not change.
fn load_via_staged_file(
    bytes: &[u8],
    display: &str,
    before_load: &mut dyn FnMut(&std::path::Path),
) -> Result<(Library, Staged), String> {
    let (path, pin) = stage_temp_file(bytes)?;
    // Every failure below releases the staging: the pin closes first (Windows cannot remove a file
    // held without delete sharing), then `release_temp_file` removes the file AND decrements
    // `live` (a bare `remove_file` would leak the count and keep the clean-shutdown `live == 0`
    // directory removal from ever firing).
    let abandon = |pin: std::fs::File, path: &PathBuf| {
        drop(pin);
        release_temp_file(path);
    };
    before_load(&path);
    if let Err(why) = verify_pinned(&pin, &path, bytes) {
        abandon(pin, &path);
        return Err(format!(
            "refusing to load plugin '{display}': its staged file {why}"
        ));
    }
    // SAFETY: running an operator-trusted plugin's init code - the same trust as compiling it in.
    // The file was created by us, in a directory we created 0700, from already-verified bytes,
    // and was verified at its name through the pin immediately above.
    let lib = match crate::dlopen_on_worker(std::ffi::OsStr::new(&path)) {
        Ok(lib) => lib,
        Err(e) => {
            abandon(pin, &path);
            return Err(format!("failed to load plugin '{display}': {e}"));
        }
    };
    if let Err(why) = verify_pinned(&pin, &path, bytes) {
        crate::dlclose_on_worker(lib);
        abandon(pin, &path);
        return Err(format!(
            "refusing to load plugin '{display}': its staged file changed while it was loading \
             ({why}); unloaded"
        ));
    }
    Ok((
        lib,
        Staged::TempFile {
            path,
            pin: Some(pin),
        },
    ))
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
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
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
    // SEAL before the map: from here the memfd's content can never change again, through this fd,
    // a `/proc/<pid>/fd/N` reopen, or anything else. The bytes `dlopen` maps are the verified
    // bytes, and so is every page of a MAP_PRIVATE mapping not yet copied-on-write.
    // SAFETY: plain fcntl on an fd we own; no pointers.
    let sealed = unsafe {
        libc::fcntl(
            fd.as_raw_fd(),
            libc::F_ADD_SEALS,
            libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL,
        )
    };
    if sealed < 0 {
        return Err(format!(
            "memfd seal failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let path = memfd_name(&fd);
    // SAFETY: same operator-trust as any plugin load; the fd content is exactly the verified bytes
    // and is not reachable by path from any other process's namespace. The name is not held by any
    // resident image: a released image that stays resident keeps its fd, so `N` is not free.
    let lib = crate::dlopen_on_worker(std::ffi::OsStr::new(&path))
        .map_err(|e| format!("failed to load plugin '{display}' from memfd: {e}"))?;
    Ok((lib, Staged::Memfd { fd: Some(fd) }))
}

/// The `dlopen` name of a staged memfd: `/proc/self/fd/N`.
#[cfg(target_os = "linux")]
fn memfd_name(fd: &std::os::fd::OwnedFd) -> String {
    use std::os::fd::AsRawFd as _;
    format!("/proc/self/fd/{}", fd.as_raw_fd())
}

/// Memfds whose image outlived its handle. Held for the life of the process: while an image is in
/// the link map under `/proc/self/fd/N`, `N` must never be recycled (glibc would serve that image
/// to the next `dlopen` of the same name). Costs one fd per such release; the pages are already
/// pinned by the resident mapping, so it costs no memory.
#[cfg(target_os = "linux")]
static RETAINED_MEMFDS: Mutex<Vec<std::os::fd::OwnedFd>> = Mutex::new(Vec::new());

/// Release a staged memfd AFTER its library handle was closed. If the link map still holds an
/// image under the fd's name (the image outlived its handle), the fd is retained forever so the
/// name stays reserved; otherwise it closes and the number is free for reuse, since nothing can
/// match it any more.
#[cfg(target_os = "linux")]
fn retire_memfd(fd: std::os::fd::OwnedFd) {
    if name_still_loaded(&memfd_name(&fd)) {
        RETAINED_MEMFDS
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(fd);
    }
}

/// Does the dynamic linker still hold an object under `name`? `RTLD_NOLOAD` never maps or
/// initialises anything: it only answers from the link map (a hit takes a reference, dropped at
/// once — the image stays resident, so no `.fini_array` runs). Runs on the FFI worker like every
/// other `dlopen`/`dlclose`. A probe that cannot answer counts as loaded: retaining an fd is the
/// safe mistake, recycling a name still in use is the defect.
#[cfg(target_os = "linux")]
fn name_still_loaded(name: &str) -> bool {
    let probe = crate::ffi_thread::on_plugin_thread(|| {
        // SAFETY: RTLD_NOLOAD loads nothing and runs no initialiser; see the doc comment.
        let found = unsafe {
            libloading::os::unix::Library::open(Some(name), libc::RTLD_NOLOAD | libc::RTLD_LAZY)
        };
        found.is_ok()
    });
    probe.unwrap_or(true)
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
