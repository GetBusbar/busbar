// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use libloading::Library;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

// THE ONE LOAD (LINT-RULES R23). Every dynamic library this process loads is opened here, by
// `dlopen_on_worker`, and libloading is busbar-plugin-loader's alone (cargo-deny). Signed images
// arrive through `load_library_from_bytes` under the native load guard; the standalone path loads
// (`dispatch::load`, `keep_door`) are refused once that guard is installed.

/// Open the library at `path` on the permanent plugin thread.
pub(crate) fn dlopen_on_worker(path: &std::ffi::OsStr) -> Result<Library, String> {
    // SAFETY: loading an operator-placed library runs its init code, which is the same trust as
    // compiling it in. Callers apply the trust gate first.
    match crate::ffi_thread::on_plugin_thread(|| {
        crate::ffi_thread::debug_assert_permanent("dlopen");
        unsafe { Library::new(path) }
    }) {
        Ok(r) => r.map_err(|e| loader_error(&e)),

        Err(_) => Err("the library's initializer panicked while loading".to_string()),
    }
}

/// A libloading error as the loader reported it. libloading's `Display` for `DlOpen`/`DlSym` is
/// only the label ("dlopen failed"); the `dlerror` text (e.g. "version `GLIBC_2.38' not found") is
/// the error's `source`, so the whole chain is joined, then made safe by [`loader_reason`].
pub(crate) fn loader_error(e: &(dyn std::error::Error + 'static)) -> String {
    let mut text = e.to_string();
    let mut next = e.source();
    while let Some(cause) = next {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        next = cause.source();
    }
    loader_reason(&text)
}

/// The most characters of a dynamic loader's reason a refusal carries.
const LOADER_REASON_CHARS: usize = 512;

/// A dynamic loader's error text (`dlerror`, e.g. "version `GLIBC_2.38' not found"), made safe to
/// log: every control character, line separator and bidirectional control is escaped so it is one
/// line (the text embeds the library's path, which an operator-placed file name can craft), and it
/// is cut to [`LOADER_REASON_CHARS`] characters with an ellipsis.
pub(crate) fn loader_reason(text: &str) -> String {
    let mut out = String::new();
    for (count, c) in text.chars().enumerate() {
        if count == LOADER_REASON_CHARS {
            out.push('\u{2026}');
            break;
        }
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if c.is_control()
                || matches!(
                    c,
                    '\u{2028}' | '\u{2029}' | '\u{200E}' | '\u{200F}'
                        | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
                ) =>
            {
                out.push_str(&format!("\\u{{{:x}}}", u32::from(c)));
            }
            c => out.push(c),
        }
    }
    out
}

/// Unload `lib` on the permanent plugin thread, so its finalizers never run on a caller thread
/// that may retire (`ffi_thread`).
pub(crate) fn dlclose_on_worker(lib: Library) {
    #[cfg(test)]
    crate::UNLOADS_ON_WORKER.with(|n| n.set(n.get() + 1));
    let _ = crate::ffi_thread::on_plugin_thread(move || {
        crate::ffi_thread::debug_assert_permanent("dlclose");
        drop(lib);
    });
}

/// Why admit step 8 opened no image.
#[cfg(unix)]
pub(crate) enum Unopened {
    /// The verified bytes could not be staged unchanged, or the native load guard refused them.
    Stage(String),
    /// busbar-ffi refused the image: dlopen failed, or a step-9 header check failed (the library, if one was
    /// loaded, has already been dropped on the permanent worker).
    Image(busbar_ffi::image::ImageError),
    /// The image's initializer or `busbar_plugin()` panicked on the worker.
    Panicked,
}

/// Admit steps 8-9 (IF §11.1): `busbar_ffi::image::Opened::open` (dlopen, `busbar_plugin()`, the H4 bounds
/// check of the header, the stamp, the kind table and `former_names`) on the permanent ffi worker, the only
/// thread that runs an image's code before admission.
#[cfg(unix)]
fn open_on_worker(
    path: &std::ffi::OsStr,
    bytes: &[u8],
) -> Result<busbar_ffi::image::Opened, Unopened> {
    match crate::ffi_thread::on_plugin_thread(|| {
        crate::ffi_thread::debug_assert_permanent("dlopen");
        busbar_ffi::image::Opened::open(path, bytes)
    }) {
        Ok(opened) => opened.map_err(Unopened::Image),
        Err(_) => Err(Unopened::Panicked),
    }
}

/// Exit b (IF §11.1, I13): a refused image's library is dropped on the permanent ffi worker.
#[cfg(unix)]
pub(crate) fn close_on_worker(opened: busbar_ffi::image::Opened) {
    #[cfg(test)]
    crate::UNLOADS_ON_WORKER.with(|n| n.set(n.get() + 1));
    let _ = crate::ffi_thread::on_plugin_thread(move || {
        crate::ffi_thread::debug_assert_permanent("dlclose");
        opened.close();
    });
}

/// Admit step 8 (IF §11.1): stage the verified bytes under the native load guard (a sealed memfd on Linux, else
/// the pinned private temp file, re-verified at its name around the open) and open them through busbar-ffi on
/// the permanent worker. The returned `Staged` is held with the image for the life of the process (I13).
#[cfg(unix)]
pub(crate) fn open_image(
    bytes: &[u8],
    display: &str,
) -> Result<(busbar_ffi::image::Opened, Staged), Unopened> {
    if let Some(guard) = NATIVE_LOAD_GUARD.get() {
        guard(bytes, display).map_err(Unopened::Stage)?;
    }
    #[cfg(test)]
    STAGED_HERE.with(|n| n.set(n.get() + 1));
    #[cfg(target_os = "linux")]
    {
        match sealed_memfd(bytes) {
            Ok(fd) => {
                let path = memfd_name(&fd);
                let staged = Staged::Memfd { fd: Some(fd) };
                match open_on_worker(std::ffi::OsStr::new(&path), bytes) {
                    Ok(opened) => return Ok((opened, staged)),
                    Err(Unopened::Image(busbar_ffi::image::ImageError::Load(e))) => {
                        eprintln!(
                            "[warn] memfd load failed for plugin '{display}' ({}); falling back to \
                             private temp staging",
                            loader_error(&e)
                        );
                    }
                    Err(refused) => return Err(refused),
                }
            }
            Err(e) => {
                eprintln!(
                    "[warn] memfd load unavailable for plugin '{display}' ({e}); falling back to \
                     private temp staging"
                );
            }
        }
    }
    let (path, pin) = stage_temp_file(bytes).map_err(Unopened::Stage)?;
    let abandon = |pin: std::fs::File, path: &PathBuf| {
        drop(pin);
        release_temp_file(path);
    };
    if let Err(why) = verify_pinned(&pin, &path, bytes) {
        abandon(pin, &path);
        return Err(Unopened::Stage(format!("its staged file {why}")));
    }
    let opened = match open_on_worker(std::ffi::OsStr::new(&path), bytes) {
        Ok(opened) => opened,
        Err(refused) => {
            abandon(pin, &path);
            return Err(refused);
        }
    };
    if let Err(why) = verify_pinned(&pin, &path, bytes) {
        close_on_worker(opened);
        abandon(pin, &path);
        return Err(Unopened::Stage(format!(
            "its staged file changed while it was loading ({why}); unloaded"
        )));
    }
    Ok((
        opened,
        Staged::TempFile {
            path,
            pin: Some(pin),
        },
    ))
}

/// The door of the library at `path`, loaded through this module and kept for the life of the
/// process: for a harness that wraps a dropped-in door itself (`dist/default` `tests/canary`).
/// Refused once the native load guard is installed, like every standalone path load.
#[cfg(any(test, feature = "test-support"))]
pub fn keep_door(
    path: &std::path::Path,
) -> Result<busbar_contract::abi::sdk::door::RawDoorFn, String> {
    allow_standalone_path_load()?;
    let lib = dlopen_on_worker(path.as_os_str())?;
    // SAFETY: `DOOR_SYMBOL` is typed `RawDoorFn` by the mechanism, and `lib` is never unloaded
    // (forgotten below), so the function pointer stays valid for the process.
    let door = unsafe {
        lib.get::<busbar_contract::abi::sdk::door::RawDoorFn>(
            busbar_contract::abi::mechanism::DOOR_SYMBOL,
        )
        .map(|s| *s)
    };
    match door {
        Ok(door) => {
            std::mem::forget(lib);
            Ok(door)
        }
        Err(e) => {
            dlclose_on_worker(lib);
            Err(e.to_string())
        }
    }
}

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

/// A directory builder that creates owner-only (0700) directories on unix.
#[cfg(unix)]
fn private_dir_builder() -> std::fs::DirBuilder {
    let mut builder = std::fs::DirBuilder::new();
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder
}

/// Windows has no mode bits; the directory inherits its parent's ACL.
#[cfg(not(unix))]
fn private_dir_builder() -> std::fs::DirBuilder {
    std::fs::DirBuilder::new()
}

fn ensure_staging_parent(temp_base: &std::path::Path) -> Result<PathBuf, String> {
    let parent = staging_parent_in(temp_base);
    match private_dir_builder().create(&parent) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => {
            return Err(format!(
                "cannot create plugin staging parent {}: {e}",
                parent.display()
            ));
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

#[cfg(target_os = "linux")]
impl Staged {
    /// Whether the dynamic loader still maps the image staged here, probed by its staged name with RTLD_NOLOAD on a
    /// permanent worker (DES-443 r3 §4): asked after `close_on_worker`, true means the image pinned itself.
    pub(crate) fn still_loaded(&self) -> bool {
        match self {
            Staged::Memfd { fd: Some(fd) } => name_still_loaded(&memfd_name(fd)),
            Staged::Memfd { fd: None } => false,
            Staged::TempFile { path, .. } => path.to_str().is_none_or(name_still_loaded),
        }
    }
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

fn random_hex(n: usize) -> Result<String, String> {
    let mut buf = vec![0u8; n];

    busbar_contract::crypto::fill(&mut buf)
        .map_err(|e| format!("cannot gather staging randomness: {e}"))?;
    Ok(hex::encode(buf))
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
    let name = format!("{STAGING_PREFIX}{}-{}", std::process::id(), random_hex(8)?);
    let dir = ensure_staging_parent(&std::env::temp_dir())?.join(name);

    private_dir_builder().create(&dir).map_err(|e| {
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
    let staged = create_staged(&path)
        .map_err(|e| format!("cannot create staged plugin file {}: {e}", path.display()))
        .and_then(|f| {
            pin_staged(f, &path, bytes).map_err(|e| {
                let _ = std::fs::remove_file(&path);
                format!("cannot stage plugin file {}: {e}", path.display())
            })
        });
    match staged {
        Ok(pin) => {
            state.live += 1;
            Ok((path, pin))
        }
        Err(e) => {
            if state.live == 0 {
                if let Some(dir) = state.dir.take() {
                    let _ = std::fs::remove_dir(&dir);
                }
            }
            Err(e)
        }
    }
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

#[cfg(any(test, feature = "test-support", feature = "pack"))]
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
    let lib = match crate::stage::dlopen_on_worker(std::ffi::OsStr::new(&path)) {
        Ok(lib) => lib,
        Err(e) => {
            abandon(pin, &path);
            return Err(format!("failed to load plugin '{display}': {e}"));
        }
    };
    if let Err(why) = verify_pinned(&pin, &path, bytes) {
        crate::stage::dlclose_on_worker(lib);
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
    let fd = sealed_memfd(bytes)?;
    let path = memfd_name(&fd);
    // SAFETY: same operator-trust as any plugin load; the fd content is exactly the verified bytes
    // and is not reachable by path from any other process's namespace. The name is not held by any
    // resident image: a released image that stays resident keeps its fd, so `N` is not free.
    let lib = crate::stage::dlopen_on_worker(std::ffi::OsStr::new(&path))
        .map_err(|e| format!("failed to load plugin '{display}' from memfd: {e}"))?;
    Ok((lib, Staged::Memfd { fd: Some(fd) }))
}

/// A memfd holding exactly `bytes`, sealed against every later write, grow and shrink.
#[cfg(target_os = "linux")]
pub(crate) fn sealed_memfd(bytes: &[u8]) -> Result<std::os::fd::OwnedFd, String> {
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
    Ok(fd)
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
