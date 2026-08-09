// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The ONE durable-write choke point. Every durable file publish in busbar goes through here:
//! `temp → write → flush → fsync(file) → rename → fsync(parent)`, with RAII tmp cleanup on EVERY
//! error path. There is no other public durable-write path in the crate (see the guard test in
//! `admin::structure` / `scripts/structure-lint.sh`): outside this module, the ephemeral
//! `plugin-loader::stage`, and `#[cfg(test)]` blocks, no source file may hand-roll a
//! `std::fs::rename` used to publish or a `sync_all` for durability. A 5th call-site that tries to
//! re-hand-roll the dance fails CI instead of compiling — the atomic-write bug class is made
//! structurally unrepresentable rather than "fixed at N sites".
//!
//! The primitive's contract makes it impossible to call it and skip a step: a caller supplies bytes
//! and gets back "durable or `Err`". The sequence is a straight line inside one private function,
//! each fallible step gated by `?`, and the temp cleanup is a `Drop` guard (not a `return` an author
//! must remember), so:
//!   * a failed write NEVER leaves a stale temp (the "cleaned only on rename failure" class),
//!   * a RELATIVE path's parent-dir fsync is NEVER skipped (an empty parent resolves to `"."`
//!     unconditionally),
//!   * the signing-key posture (0600-at-open + O_EXCL anti-pre-plant + stale-temp pre-removal)
//!     survives via `DurableOpts` with no bespoke code at the call-site.

use std::io;
use std::path::Path;

/// Options a FEW call-sites need beyond the default. `Default` = the overlay/state posture (the
/// common case): OS/umask-default mode, truncate-create the temp.
#[derive(Clone, Copy, Default)]
pub struct DurableOpts {
    /// Unix file mode for the temp (and therefore the published) file. `None` = OS/umask default.
    /// The signing key sets `Some(0o600)` so the plaintext key is never briefly world-readable
    /// (mode set AT OPEN, never via a later `chmod` TOCTOU window). Only ever READ under
    /// `#[cfg(unix)]` below, but call sites (main.rs, config/overlay.rs) construct this struct
    /// unconditionally on every platform, so the field itself can't be `#[cfg(unix)]`-gated away.
    #[cfg_attr(not(unix), allow(dead_code))]
    pub mode: Option<u32>,
    /// Refuse to adopt a pre-existing temp (`O_CREAT | O_EXCL`) — the signing-key anti-pre-plant
    /// posture. When set, the primitive still PRE-REMOVES a stale temp of its OWN about-to-use name
    /// first (so a leftover from a crashed run can't wedge retry), then creates exclusively — so it
    /// never adopts a temp it did not just clear. When unset (default) the temp is truncate-created
    /// (`File::create` semantics).
    pub exclusive: bool,
}

/// Atomically + durably publish `bytes` to `path` (default posture: overlay/state).
///
/// See [`write_with`] for the full contract. In short:
///   1. create a sibling temp in the SAME directory as `path`,
///   2. `create → write_all → flush → fsync(file)` the temp,
///   3. `rename(temp, path)` — atomic for a concurrent reader,
///   4. `fsync(parent dir)` — best-effort; makes the rename's directory entry durable.
///
/// On ANY error in steps 1–3 the temp is removed by an RAII guard before returning the error, so a
/// failed write NEVER leaves a stale temp to accumulate or to wedge a retry. Steps 1–3 failing is a
/// hard error (`Err`); step 4 failing is swallowed (contents are already durable; not every FS
/// supports opening a directory for fsync).
pub fn write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_with(path, bytes, DurableOpts::default())
}

/// Atomically + durably publish `bytes` to `path` with `opts`.
///
/// The primitive OWNS temp naming (a per-call-unique sibling in the target's directory) so no
/// call-site can pick a cross-directory temp (a cross-FS rename is not atomic and can `EXDEV`-fail)
/// or collide with a concurrent writer to the same target. Naming: the target file-name prefixed
/// `.` and suffixed `.<pid>-<seq>.tmp`, where `seq` is a process-monotonic counter. A leftover temp
/// from a crashed run has a DIFFERENT name and is simply ignored (it can't wedge us); the
/// `exclusive` posture additionally best-effort removes our own about-to-use name first.
///
/// Post-condition on `Ok(())`: a concurrent reader observes either the old file or the fully-written
/// new file, never a torn/partial one (rename atomicity); and after a power loss the surfaced file
/// is the fully-written new contents (contents fsync before rename) with its directory entry durable
/// (best-effort parent fsync after). On `Err`: no temp is left behind and `path` is untouched (still
/// the prior contents, or still absent).
/// The directory whose ENTRY a publish or an unlink of `path` mutates -- the one that has to be
/// fsynced for the change to survive a power loss. A RELATIVE `path` has an empty parent
/// (`Some("")`, which cannot be opened), so it resolves to "." -- the CWD, where the file actually
/// lives. UNCONDITIONAL and in ONE place, so no caller can pass a relative path that dodges the
/// parent fsync, and `write`/`remove` can never disagree about which directory it is.
fn holding_dir(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

/// fsync the directory that holds `path`, so a rename or an unlink of it is itself durable.
/// Best-effort by design: the file CONTENTS are already durable at every call site, and not every
/// platform/filesystem supports opening a directory for fsync.
fn sync_holding_dir(path: &Path) {
    let parent = holding_dir(path);
    #[cfg(test)]
    fault_record_parent_fsync(parent);
    if let Ok(dir) = std::fs::File::open(parent) {
        let _ = dir.sync_all();
    }
}

/// DURABLY remove `path`: unlink it, then fsync the holding directory so the REMOVAL survives a
/// power loss. The asymmetric sibling of [`write`] -- installing a file fsynced the directory entry
/// and removing one did not, so a crash after a plugin delete could resurrect the deleted artifact
/// on the next boot and load it. `Err` only if the unlink itself fails.
pub fn remove(path: &Path) -> io::Result<()> {
    std::fs::remove_file(path)?;
    sync_holding_dir(path);
    Ok(())
}

/// DURABLY create `path` and any missing ancestors: each directory that is actually created has its
/// PARENT fsynced, so the new directory entry itself survives a power loss. `std::fs::create_dir_all`
/// leaves that entry non-durable, so the very first artifact written into a freshly created directory
/// could vanish along with the directory even though the file's own contents and holding-directory
/// entry were fsynced -- the same asymmetry class as an unlink that skips the parent fsync.
///
/// Already-existing directories are left alone: their entries are durable by whoever created them.
pub fn create_dir_all(path: &Path) -> io::Result<()> {
    // Walk up collecting the missing ancestors (deepest first), then create shallowest first so each
    // `create_dir` finds its parent present.
    let mut missing: Vec<&Path> = Vec::new();
    let mut cur = Some(path);
    while let Some(p) = cur {
        if p.as_os_str().is_empty() || p.exists() {
            break;
        }
        missing.push(p);
        cur = p.parent();
    }
    for dir in missing.iter().rev() {
        match std::fs::create_dir(dir) {
            // Fsync the HOLDING directory, which is what makes `dir`'s own entry durable.
            Ok(()) => sync_holding_dir(dir),
            // A concurrent creator won the race; the entry is theirs to make durable.
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

pub fn write_with(path: &Path, bytes: &[u8], opts: DurableOpts) -> io::Result<()> {
    use std::io::Write as _;
    use std::sync::atomic::{AtomicU64, Ordering};

    // Process-monotonic sequence for a per-call-unique temp name. Two concurrent writers to the same
    // target never collide on the temp (closing a latent race the old fixed `.overlay.tmp` /
    // `.json.tmp` names allowed), and a leftover temp from a crashed run never matches our name.
    static SEQ: AtomicU64 = AtomicU64::new(0);

    // Resolve the directory that HOLDS `path`. A RELATIVE `path` has an empty parent (`Some("")`, an
    // empty path that cannot be opened) — resolve it to "." (the CWD, which is where the file lives
    // and whose directory entry the rename mutates). This resolution is UNCONDITIONAL and lives here,
    // so no caller can pass a relative path that dodges the parent fsync. The temp is created in this
    // same resolved parent, so temp + target always co-locate (same-FS rename).
    let parent = holding_dir(path);
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "durable::write: path has no file name",
        )
    })?;
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(file_name);
    tmp_name.push(format!(
        ".{}-{}.tmp",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let tmp = parent.join(tmp_name);
    // #[cfg(test)] seam: plant a decoy AT the exact about-to-use temp name. The name embeds a pid +
    // an atomic sequence, so no test can predict it from the outside -- which is why the `exclusive`
    // anti-wedge pre-removal below had no test at all until this existed.
    #[cfg(test)]
    plant_decoy_if_armed(&tmp);

    // RAII: the temp is removed on EVERY early return (every `?` below, and any future `?` an editor
    // adds) UNLESS we disarm after a successful rename. There is no manual cleanup to forget, so the
    // "cleaned only on the rename path" class cannot recur.
    struct TmpGuard<'a> {
        tmp: &'a Path,
        armed: bool,
    }
    impl Drop for TmpGuard<'_> {
        fn drop(&mut self) {
            if self.armed {
                let _ = std::fs::remove_file(self.tmp);
            }
        }
    }
    let mut guard = TmpGuard {
        tmp: &tmp,
        armed: true,
    };

    {
        let mut open_opts = std::fs::OpenOptions::new();
        open_opts.write(true);
        if opts.exclusive {
            // Anti-wedge: clear ONLY our own about-to-use name (ephemeral, never the real file), then
            // create with O_EXCL so we still refuse to ADOPT a temp we did not just clear (the
            // anti-pre-plant property). A genuine race where the temp reappears surfaces as the create
            // error below.
            let _ = std::fs::remove_file(&tmp);
            open_opts.create_new(true);
        } else {
            open_opts.create(true).truncate(true); // File::create semantics (adopts + truncates)
        }
        #[cfg(unix)]
        if let Some(m) = opts.mode {
            use std::os::unix::fs::OpenOptionsExt as _;
            open_opts.mode(m);
        }
        fault_point!(FaultStep::Create); // #[cfg(test)] injection point — no-op in release
        let mut f = open_opts.open(&tmp)?; // ? → guard drops → temp removed
        fault_point!(FaultStep::Write);
        f.write_all(bytes)?; // ? → cleaned
        fault_point!(FaultStep::Flush);
        f.flush()?; // ? → cleaned
        fault_point!(FaultStep::Fsync);
        f.sync_all()?; // ? → cleaned (fsync the CONTENTS before the rename)
                       // `f` dropped here (closed) before the rename — Windows dislikes renaming an open handle.
    }
    fault_point!(FaultStep::Rename);
    std::fs::rename(&tmp, path)?; // ? → cleaned (temp may already be consumed; remove is best-effort)
    guard.armed = false; // published: the temp was consumed by the rename; disarm.

    // fsync the parent dir so the rename's directory entry is itself durable.
    sync_holding_dir(path);
    Ok(())
}

// ── `#[cfg(test)]`-only fault-injection seam ──────────────────────────────────────────────────────
// In a release build `fault_point!` expands to nothing, so the primitive's production path carries
// ZERO indirection — no trait object, no branch. Under test it consults a thread-local so a single
// harness can inject `ENOSPC`/`EIO` at any step and observe the resolved parent that was fsync'd.
// These are module-level `#[cfg(test)]` items (not a wrapping `mod`) so the file keeps exactly ONE
// inline test-BODY (`mod tests`), satisfying the test-locality structure invariant.
#[cfg(test)]
macro_rules! fault_point {
    ($step:expr) => {
        if let Some(err) = fault_take_if($step) {
            return Err(err);
        }
    };
}
#[cfg(not(test))]
macro_rules! fault_point {
    ($step:expr) => {};
}
use fault_point;

/// The fallible steps of the primitive, in order (the fault-injection axis of the class test).
#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum FaultStep {
    Create,
    Write,
    Flush,
    Fsync,
    Rename,
}

#[cfg(test)]
thread_local! {
    /// `(step, raw_os_errno)` — the next `fault_point!(step)` on this thread returns that errno once.
    static FAULT_INJECT: std::cell::RefCell<Option<(FaultStep, i32)>> =
        const { std::cell::RefCell::new(None) };
    /// Every parent path the primitive fsync'd on this thread, in order. A Vec, not a single slot,
    /// because `create_dir_all` fsyncs one parent per directory it creates and the ancestor walk is
    /// the thing under test.
    static FAULT_PARENT_FSYNC: std::cell::RefCell<Vec<std::path::PathBuf>> =
        const { std::cell::RefCell::new(Vec::new()) };
    /// One-shot: plant a decoy file at the NEXT write's exact temp path on this thread.
    static PLANT_DECOY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Arm a one-shot fault: the next matching step returns `io::Error::from_raw_os_error(errno)`.
#[cfg(test)]
fn fault_arm(step: FaultStep, errno: i32) {
    FAULT_INJECT.with(|c| *c.borrow_mut() = Some((step, errno)));
}

/// Clear any armed fault + recorded parent fsync (call at the start of each case).
#[cfg(test)]
fn fault_reset() {
    FAULT_INJECT.with(|c| *c.borrow_mut() = None);
    FAULT_PARENT_FSYNC.with(|c| c.borrow_mut().clear());
}

/// If a fault is armed for `step`, consume it and return the injected error.
#[cfg(test)]
fn fault_take_if(step: FaultStep) -> Option<io::Error> {
    FAULT_INJECT.with(|c| {
        let mut slot = c.borrow_mut();
        match *slot {
            Some((s, errno)) if s == step => {
                *slot = None;
                Some(io::Error::from_raw_os_error(errno))
            }
            _ => None,
        }
    })
}

/// Arm a one-shot decoy: the next write on this thread finds a file ALREADY SITTING at the exact
/// temp path it is about to create. That is the crashed-previous-run state the `exclusive` posture's
/// pre-removal exists for, and the only way to reach it deterministically -- the temp name embeds a
/// pid and an atomic counter, so a test cannot name it from outside.
#[cfg(test)]
fn plant_decoy_arm() {
    PLANT_DECOY.with(|c| c.set(true));
}

#[cfg(test)]
fn plant_decoy_if_armed(tmp: &Path) {
    if PLANT_DECOY.with(|c| c.replace(false)) {
        let _ = std::fs::write(tmp, b"leftover from a crashed run");
    }
}

#[cfg(test)]
fn fault_record_parent_fsync(parent: &Path) {
    FAULT_PARENT_FSYNC.with(|c| c.borrow_mut().push(parent.to_path_buf()));
}

/// The LAST parent fsync'd, for the single-publish assertions.
#[cfg(test)]
fn fault_parent_fsynced() -> Option<std::path::PathBuf> {
    FAULT_PARENT_FSYNC.with(|c| c.borrow().last().cloned())
}

/// Every parent fsync'd, in order, for the `create_dir_all` ancestor-walk assertion.
#[cfg(test)]
fn fault_parents_fsynced() -> Vec<std::path::PathBuf> {
    FAULT_PARENT_FSYNC.with(|c| c.borrow().clone())
}

#[cfg(test)]
#[path = "tests/durable_tests.rs"]
mod tests;
