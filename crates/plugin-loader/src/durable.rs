// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The ONE durable-write choke point. Every durable file publish in busbar goes through here:
//! `temp → write → flush → fsync(file) → rename → fsync(parent)`, with RAII tmp cleanup on EVERY
//! error path. It is also the home of directory durability — the parent fsync that makes a
//! created, renamed or removed entry survive a power loss. The log's own segment files and
//! quarantine copies keep a copy of the same rule in `busbar-kernel-wal`'s backend, which takes no
//! edge onto this crate. There is no other durable-write path: the `A-persistence`
//! row of the `structure-lint` gate (`xtask/src/gates/structure_lint/choke_points.rs`) refuses a
//! hand-rolled `fs::rename(` publish, a hand-rolled `sync_all`/`sync_data`, or an
//! `fs::create_dir_all(` anywhere outside the files that row ledgers, so a call site that tries to
//! re-hand-roll the dance fails CI instead of merging — the atomic-write bug class is made
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
    ///
    /// **ON WINDOWS THIS FIELD IS A NO-OP, and that is a security property that does not carry.**
    /// There are no mode bits, so the `#[cfg(unix)]` block below never runs and the published file
    /// gets whatever ACL it inherits from its parent directory. The caller that matters is
    /// `config/overlay.rs`, whose overlay can hold operator credential material verbatim (a
    /// `scheme://user:pass@host/db` in `store.settings.url`); on unix that file is 0600, on
    /// Windows its confidentiality is exactly the confidentiality of the directory holding
    /// `config.yaml` and nothing here narrows it. An operator deploying on Windows who needs the
    /// unix guarantee must set the ACL on that directory themselves. Stated here rather than left
    /// implicit because "we write it 0600" reads as a cross-platform claim and is not one.
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
/// See [`write_with`] for the contract.
pub fn write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_with(path, bytes, DurableOpts::default())
}

/// The directory whose ENTRY a publish or an unlink of `path` mutates -- the one that has to be
/// fsynced for the change to survive a power loss. A RELATIVE `path` has an empty parent
/// (`Some("")`, which cannot be opened), so it resolves to "." -- the CWD, where the file actually
/// lives. UNCONDITIONAL and in ONE place, so no caller can pass a relative path that dodges the
/// parent fsync, and `write`/`remove` can never disagree about which directory it is.
pub(crate) fn holding_dir(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

/// fsync the directory that holds `path`, so a creation, rename or unlink of it is itself durable.
///
/// THE one home of directory durability in this crate: the publish below, [`remove`] and
/// [`create_dir_all`] all go through it (the log's segment files keep the same rule in
/// `busbar-kernel-wal`'s `backend::DirectoryFactory`).
///
/// A failure is the caller's error. Opening the directory, or fsyncing it, failing with an I/O error
/// means the entry is NOT durable, and a caller that reported success would be reporting a
/// durability the medium did not give. The one exception is a filesystem that says the operation
/// is not supported on a directory — `EINVAL`, which `fsync(2)` names for exactly that, or an error
/// the platform reports as [`io::ErrorKind::Unsupported`]: it cannot be made to promise more than it
/// does, and refusing every publish on it would trade a weaker durability story for no durability
/// at all.
///
/// **ON WINDOWS THIS IS A NO-OP, and it is worth naming because nothing in the code shape shows
/// it.** `File::open` on a DIRECTORY fails on Windows unless the handle is opened with
/// `FILE_FLAG_BACKUP_SEMANTICS`, and even with that flag `FlushFileBuffers` on a directory handle is
/// not the directory-entry barrier `fsync(dirfd)` is on unix. There is no Win32 equivalent to reach
/// for, so this is a platform gap rather than an omission: on Windows the durability of a publish
/// rests on NTFS's metadata journal ordering the rename, not on anything this function does. The
/// FILE CONTENTS half is unaffected and holds everywhere — `sync_all` on the temp runs before the
/// rename on every platform, so the failure this guards against on Windows is a lost RENAME after a
/// power loss (the old file survives, or the file is absent), never a torn or half-written one.
pub(crate) fn sync_holding_dir(path: &Path) -> io::Result<()> {
    match sync_dir(holding_dir(path)) {
        Err(e) if fsync_unsupported(&e) => Ok(()),
        other => other,
    }
}

/// fsync `dir` itself, every failure reported. [`sync_holding_dir`] decides which are the caller's.
fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(test)]
    crate::durable::hooks::parent_fsync(dir)?;
    #[cfg(unix)]
    {
        std::fs::File::open(dir)?.sync_all()
    }
    // See [`sync_holding_dir`]: there is no directory-entry barrier to reach for on this platform.
    #[cfg(not(unix))]
    {
        let _no_barrier = dir;
        Ok(())
    }
}

/// Whether `e` is a filesystem saying a directory cannot be fsynced at all, as opposed to failing
/// to do it: `EINVAL` (the descriptor does not support synchronization), or an error the platform
/// reports as unsupported.
fn fsync_unsupported(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::Unsupported | io::ErrorKind::InvalidInput
    )
}

/// DURABLY remove `path`: unlink it, then fsync the holding directory so the REMOVAL survives a
/// power loss. The asymmetric sibling of [`write()`] -- installing a file fsynced the directory entry
/// and removing one did not, so a crash after a plugin delete could resurrect the deleted artifact
/// on the next boot and load it. `Err` if the unlink fails, or if the directory fsync after it does
/// (the file is gone, but its removal may not survive a power loss).
pub fn remove(path: &Path) -> io::Result<()> {
    std::fs::remove_file(path)?;
    sync_holding_dir(path)
}

/// DURABLY create `path` and any missing ancestors: each directory that is actually created has its
/// PARENT fsynced, so the new directory entry itself survives a power loss. `std::fs::create_dir_all`
/// leaves that entry non-durable, so the very first artifact written into a freshly created directory
/// could vanish along with the directory even though the file's own contents and holding-directory
/// entry were fsynced -- the same asymmetry class as an unlink that skips the parent fsync.
///
/// Already-existing directories are left alone: their entries are durable by whoever created them.
/// A directory fsync that fails is this call's error, as `sync_holding_dir` says.
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
            Ok(()) => sync_holding_dir(dir)?,
            // A concurrent creator won the race; the entry is theirs to make durable.
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Atomically + durably publish `bytes` to `path` with `opts`.
///
///   1. create a sibling temp in the SAME directory as `path`,
///   2. `create → write_all → flush → fsync(file)` the temp,
///   3. `rename(temp, path)` — atomic for a concurrent reader,
///   4. `fsync(parent dir)` — makes the rename's directory entry durable.
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
/// (parent fsync after).
///
/// On `Err` from steps 1–3: no temp is left behind and `path` is untouched (still the prior
/// contents, or still absent) — the RAII guard removes the temp on every early return. On `Err`
/// from step 4: the rename happened, so `path` holds the new contents, but its directory entry was
/// NOT made durable and a power loss may still surface the prior contents; the caller is told
/// rather than handed an `Ok` the medium did not give. A filesystem that reports a directory fsync
/// as unsupported is not an error (see `sync_holding_dir`).
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
    // #[cfg(test)] hook: a test may plant a decoy AT the exact about-to-use temp name. The name
    // embeds a pid + an atomic sequence, so no test can predict it from the outside -- which is why
    // the `exclusive` anti-wedge pre-removal below had no test at all until this existed.
    #[cfg(test)]
    crate::durable::hooks::plant_decoy_if_armed(&tmp);

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
    sync_holding_dir(path)
}

// ── `#[cfg(test)]` hook points ─────────────────────────────────────────────────────────────────────
// In a release build `fault_point!` expands to nothing, so the primitive's production path carries
// ZERO indirection — no trait object, no branch. Under test it asks the test hooks
// (`src/tests/hooks.rs`, where the armed faults and the recorded fsyncs live) whether to fail this
// step.
#[cfg(test)]
macro_rules! fault_point {
    ($step:expr) => {
        if let Some(err) = crate::durable::hooks::fault_take_if($step) {
            return Err(err);
        }
    };
}
#[cfg(not(test))]
macro_rules! fault_point {
    ($step:expr) => {};
}
use fault_point;

#[cfg(test)]
use crate::durable::hooks::FaultStep;

/// The test side of the `#[cfg(test)]` hook points above: the armed faults, the recorded fsyncs and
/// the decoy switch.
#[cfg(test)]
#[path = "tests/durable_hooks.rs"]
pub(crate) mod hooks;

#[cfg(test)]
#[path = "tests/durable_tests.rs"]
mod tests;
