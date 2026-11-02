// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use libloading::Library;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

const STAGING_PREFIX: &str = "busbar-plugins-";

const STAGING_PARENT_STEM: &str = "busbar-plugin-staging";

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

pub(crate) enum Staged {
    #[cfg(target_os = "linux")]
    Memfd { fd: Option<std::os::fd::OwnedFd> },

    TempFile {
        path: PathBuf,
        pin: Option<std::fs::File>,
    },
}

impl Drop for Staged {
    fn drop(&mut self) {
        match self {
            #[cfg(target_os = "linux")]
            Staged::Memfd { fd } => {
                if let Some(fd) = fd.take() {
                    retire_memfd(fd);
                }
            }
            Staged::TempFile { path, pin } => {
                drop(pin.take());

                release_temp_file(path);
            }
        }
    }
}

fn random_hex(n: usize) -> String {
    let mut buf = vec![0u8; n];

    let _ = getrandom::fill(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

struct StagingState {
    dir: Option<PathBuf>,
    live: usize,
}

fn staging_state() -> &'static Mutex<StagingState> {
    static STATE: OnceLock<Mutex<StagingState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(StagingState { dir: None, live: 0 }))
}

fn ensure_staging_dir(state: &mut StagingState) -> Result<PathBuf, String> {
    if let Some(dir) = &state.dir {
        if dir.is_dir() {
            return Ok(dir.clone());
        }
    }
    let name = format!("{STAGING_PREFIX}{}-{}", std::process::id(), random_hex(8));
    let dir = ensure_staging_parent(&std::env::temp_dir())?.join(name);

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

pub(crate) fn next_seq() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    SEQ.fetch_add(1, Ordering::Relaxed)
}

fn dylib_suffix() -> &'static str {
    if cfg!(target_os = "windows") {
        ".dll"
    } else if cfg!(target_os = "macos") {
        ".dylib"
    } else {
        ".so"
    }
}

fn stage_temp_file(bytes: &[u8]) -> Result<(PathBuf, std::fs::File), String> {
    let mut state = staging_state().lock().unwrap_or_else(|p| p.into_inner());
    let dir = ensure_staging_dir(&mut state)?;
    let path = dir.join(format!("lib-{}{}", next_seq(), dylib_suffix()));
    let f = create_staged(&path)
        .map_err(|e| format!("cannot create staged plugin file {}: {e}", path.display()))?;

    let pin = pin_staged(f, &path, bytes).map_err(|e| {
        let _ = std::fs::remove_file(&path);
        format!("cannot stage plugin file {}: {e}", path.display())
    })?;
    state.live += 1;
    Ok((path, pin))
}

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

#[cfg(windows)]
const FILE_SHARE_READ: u32 = 0x0000_0001;

#[cfg(windows)]
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

#[cfg(windows)]
fn create_staged(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(0)
        .open(path)
}

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

pub type NativeLoadGuard = fn(&[u8], &str) -> Result<(), String>;
static NATIVE_LOAD_GUARD: OnceLock<NativeLoadGuard> = OnceLock::new();

pub fn install_native_load_guard(guard: NativeLoadGuard) -> Result<(), &'static str> {
    NATIVE_LOAD_GUARD
        .set(guard)
        .map_err(|_| "a native load guard is already installed")
}

pub(crate) fn allow_standalone_path_load() -> Result<(), String> {
    if NATIVE_LOAD_GUARD.get().is_some() {
        return Err("this host requires a retained admitted archive before native loading; direct path loading is unavailable".into());
    }
    Ok(())
}

pub(crate) fn load_library_from_bytes(
    bytes: &[u8],
    display: &str,
) -> Result<(Library, Staged), String> {
    if let Some(guard) = NATIVE_LOAD_GUARD.get() {
        guard(bytes, display)?;
    }
    #[cfg(test)]
    STAGED_HERE.with(|n| n.set(n.get() + 1));
    #[cfg(target_os = "linux")]
    {
        match load_via_memfd(bytes, display) {
            Ok(loaded) => return Ok(loaded),
            Err(e) => {
                eprintln!(
                    "[warn] memfd load unavailable for plugin '{display}' ({e}); falling back to \
                     private temp staging"
                );
            }
        }
    }
    load_via_staged_file(bytes, display, &mut |_| {})
}

fn load_via_staged_file(
    bytes: &[u8],
    display: &str,
    before_load: &mut dyn FnMut(&std::path::Path),
) -> Result<(Library, Staged), String> {
    let (path, pin) = stage_temp_file(bytes)?;

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

#[cfg(target_os = "linux")]
fn memfd_name(fd: &std::os::fd::OwnedFd) -> String {
    use std::os::fd::AsRawFd as _;
    format!("/proc/self/fd/{}", fd.as_raw_fd())
}

#[cfg(target_os = "linux")]
static RETAINED_MEMFDS: Mutex<Vec<std::os::fd::OwnedFd>> = Mutex::new(Vec::new());

#[cfg(target_os = "linux")]
fn retire_memfd(fd: std::os::fd::OwnedFd) {
    if name_still_loaded(&memfd_name(&fd)) {
        RETAINED_MEMFDS
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(fd);
    }
}

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

pub fn sweep_dead_staging() -> usize {
    sweep_dead_staging_under(&std::env::temp_dir(), &mut list_dir_names)
}

fn list_dir_names(dir: &std::path::Path) -> std::io::Result<Vec<std::ffi::OsString>> {
    Ok(std::fs::read_dir(dir)?
        .flatten()
        .map(|e| e.file_name())
        .collect())
}

pub(crate) fn sweep_dead_staging_under(
    temp_base: &std::path::Path,
    list: &mut dyn FnMut(&std::path::Path) -> std::io::Result<Vec<std::ffi::OsString>>,
) -> usize {
    let parent = staging_parent_in(temp_base);

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

        let Some(pid) = rest.split('-').next().and_then(|p| p.parse::<u32>().ok()) else {
            continue;
        };
        if pid == std::process::id() || pid_alive(pid) {
            continue;
        }
        let path = parent.join(&name);

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
