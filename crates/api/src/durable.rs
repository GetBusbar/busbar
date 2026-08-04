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
//!   * a failed write NEVER leaves a stale temp (the D4 "cleaned only on rename failure" class),
//!   * a RELATIVE path's parent-dir fsync is NEVER skipped (the D2 class — empty parent resolves to
//!     `"."` unconditionally),
//!   * the signing-key posture (0600-at-open + O_EXCL anti-pre-plant + stale-temp pre-removal, the
//!     D3 concern) survives via `DurableOpts` with no bespoke code at the call-site.

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
/// parent fsync (the D2 class), and `write`/`remove` can never disagree about which directory it is.
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
    // so no caller can pass a relative path that dodges the parent fsync (fixes the D2 class). The
    // temp is created in this same resolved parent, so temp + target always co-locate (same-FS
    // rename).
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
    // D4 class ("cleaned only on the rename path") cannot recur.
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
            // create with O_EXCL so we still refuse to ADOPT a temp we did not just clear (the D3
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
mod tests {
    use super::{
        create_dir_all, fault_arm, fault_parent_fsynced, fault_parents_fsynced, fault_reset,
        holding_dir, plant_decoy_arm, write, write_with, DurableOpts, FaultStep,
    };
    use std::path::{Path, PathBuf};

    // Linux ENOSPC=28, EIO=5; macOS shares these values. Injected via `from_raw_os_error`.
    const ENOSPC: i32 = 28;
    const EIO: i32 = 5;

    /// Serializes the ONE test in this file that mutates process-global CWD
    /// (`success_relative_path_fsyncs_dot`) against itself. MUST be module-level, not
    /// function-local — a function-local `static` is scoped to that function and contends with
    /// nothing (the bug this lock previously had). Still not sufficient on its own: no test
    /// OUTSIDE this file that resolves a relative path takes this lock. See that test's doc comment.
    static CWD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// A private scratch directory, removed on drop, so each case is hermetic and leaves nothing.
    struct Scratch {
        dir: PathBuf,
    }
    impl Scratch {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "busbar-durable-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Scratch { dir }
        }
        fn path(&self, name: &str) -> PathBuf {
            self.dir.join(name)
        }
        /// Any leftover durable temp (`.<name>.<pid>-<seq>.tmp`) for `name` in the dir?
        fn has_durable_temp(&self, name: &str) -> bool {
            let prefix = format!(".{name}.");
            std::fs::read_dir(&self.dir).unwrap().any(|e| {
                let n = e.unwrap().file_name();
                let n = n.to_string_lossy();
                n.starts_with(&prefix) && n.ends_with(".tmp")
            })
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// The injected-failure matrix — for every step × {ENOSPC, EIO}, the write returns `Err`,
    /// the target is UNCHANGED (prior contents, or still absent), and NO durable temp remains (the
    /// RAII guard ran on every early-return path). The temp assertion is the one that would have
    /// caught D4 (leaked `.tmp` on a pre-rename error); the "target unchanged" is the whole-family
    /// integrity guarantee.
    #[test]
    fn fault_matrix_returns_err_untouched_target_no_temp_leak() {
        let sc = Scratch::new("matrix");
        let steps = [
            FaultStep::Create,
            FaultStep::Write,
            FaultStep::Flush,
            FaultStep::Fsync,
            FaultStep::Rename,
        ];
        for &step in &steps {
            for &errno in &[ENOSPC, EIO] {
                // Case A: target ABSENT before the failed write → must stay absent, no temp.
                let target = sc.path("absent.json");
                let _ = std::fs::remove_file(&target);
                fault_reset();
                fault_arm(step, errno);
                let r = write(&target, b"new payload");
                assert!(
                    r.is_err(),
                    "step {step:?} errno {errno}: expected Err on injected fault"
                );
                assert_eq!(
                    r.unwrap_err().raw_os_error(),
                    Some(errno),
                    "step {step:?}: the injected errno must surface"
                );
                assert!(
                    !target.exists(),
                    "step {step:?} errno {errno}: an absent target must stay absent on failure"
                );
                assert!(
                    !sc.has_durable_temp("absent.json"),
                    "step {step:?} errno {errno}: no durable temp may leak (would have caught D4)"
                );

                // Case B: target has PRIOR contents → must be byte-for-byte unchanged, no temp.
                let target = sc.path("prior.json");
                std::fs::write(&target, b"OLD CONTENTS").unwrap();
                fault_reset();
                fault_arm(step, errno);
                let r = write(&target, b"NEW CONTENTS that must not land");
                assert!(r.is_err(), "step {step:?}: expected Err");
                assert_eq!(
                    std::fs::read(&target).unwrap(),
                    b"OLD CONTENTS",
                    "step {step:?} errno {errno}: prior contents must survive a failed write"
                );
                assert!(
                    !sc.has_durable_temp("prior.json"),
                    "step {step:?} errno {errno}: no durable temp may leak"
                );
            }
        }
    }

    /// Success on an ABSOLUTE path round-trips and leaves no temp.
    #[test]
    fn success_absolute_path_roundtrips_no_temp() {
        let sc = Scratch::new("abs");
        let target = sc.path("cfg.json");
        fault_reset();
        write(&target, b"payload-A").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"payload-A");
        // Overwrite: still atomic, still no temp, new contents win.
        write(&target, b"payload-B").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"payload-B");
        assert!(!sc.has_durable_temp("cfg.json"));
    }

    /// The primitive `holding_dir` uses to resolve a RELATIVE path's parent to "." — the pure,
    /// deterministic form of the property `success_relative_path_fsyncs_dot` below also exercises
    /// through a real CWD round-trip. Covers it with NO filesystem/CWD mutation at all, so it can
    /// never be a cross-test hazard.
    #[test]
    fn holding_dir_resolves_a_relative_path_to_dot() {
        assert_eq!(holding_dir(Path::new("relative.json")), Path::new("."));
        assert_eq!(
            holding_dir(Path::new("a/b/relative.json")),
            Path::new("a/b")
        );
        assert_eq!(
            holding_dir(Path::new("/abs/relative.json")),
            Path::new("/abs")
        );
    }

    /// Success on a RELATIVE path round-trips AND the parent fsync was attempted on the
    /// resolved "." — the assertion that would have caught D2 (relative-path parent fsync skipped).
    ///
    /// `CWD_LOCK` MUST be a module-level (not function-local) static: a `static` declared inside a
    /// function body is scoped to that function and contends with nothing, which is the same defect
    /// `store::now_for_test`'s doc (see its own "CRITICAL #1" note) documents elsewhere in this
    /// crate. Even hoisted, this lock only serializes CWD mutation AGAINST ITSELF — no OTHER test in
    /// this binary that resolves a relative path takes it, so the window between `set_current_dir`
    /// calls below is still a real (if currently unexercised) cross-file hazard. The deterministic
    /// fix is `holding_dir_resolves_a_relative_path_to_dot` above, which needs no CWD mutation at
    /// all; this test is kept because it also proves the write()/fsync ROUND TRIP that caught D2 in
    /// the first place, which the pure unit test above does not cover.
    #[test]
    fn success_relative_path_fsyncs_dot() {
        let _g = CWD_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let sc = Scratch::new("rel");
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&sc.dir).unwrap();
        fault_reset();

        // A bare file name is a relative path whose parent is empty → primitive resolves it to ".".
        let r = write(Path::new("relative.json"), b"rel-payload");
        let fsynced = fault_parent_fsynced();
        std::env::set_current_dir(&prev).unwrap(); // restore CWD before asserting

        r.unwrap();
        assert_eq!(
            fsynced.as_deref(),
            Some(Path::new(".")),
            "a relative path must fsync the parent resolved to \".\" (would have caught D2)"
        );
        assert_eq!(
            std::fs::read(sc.path("relative.json")).unwrap(),
            b"rel-payload"
        );
        assert!(!sc.has_durable_temp("relative.json"));
    }

    /// A pre-existing stale temp of a DIFFERENT (crashed-run) name is irrelevant under the
    /// primitive's per-call-unique naming — a fresh write succeeds and ignores the foreign leftover.
    /// And for the `exclusive` posture, a stale temp of our OWN about-to-use name does not wedge
    /// (pre-removed) — covering D3's wedge concern.
    #[test]
    fn stale_foreign_temp_is_ignored() {
        let sc = Scratch::new("stale");
        let target = sc.path("k.json");
        // A foreign leftover from a prior crash (a plausible old fixed name).
        std::fs::write(sc.path(".k.json.tmp"), b"crashed-run leftover").unwrap();
        fault_reset();
        write(&target, b"fresh").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"fresh");
        // The foreign temp is untouched (different name) — proves we didn't collide on it.
        assert_eq!(
            std::fs::read(sc.path(".k.json.tmp")).unwrap(),
            b"crashed-run leftover"
        );
    }

    /// The `exclusive` + `mode` posture (the signing key): the published file is 0600 on
    /// unix, and a pre-planted temp of our own name is cleared rather than wedging (anti-wedge), while
    /// O_EXCL still refuses to ADOPT a foreign temp we did not clear. Covers D3's security posture.
    #[test]
    #[cfg(unix)]
    fn exclusive_mode_publishes_0600_and_survives_stale_own_temp() {
        use std::os::unix::fs::PermissionsExt as _;
        let sc = Scratch::new("excl");
        let target = sc.path("signing.key");
        let opts = DurableOpts {
            mode: Some(0o600),
            exclusive: true,
        };
        fault_reset();
        // First write establishes the file 0600.
        write_with(&target, b"deadbeef", opts).unwrap();
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "exclusive+mode must publish 0600");
        write_with(&target, b"cafebabe", opts).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"cafebabe");
        assert!(!sc.has_durable_temp("signing.key"));
    }

    /// THE ANTI-WEDGE PRE-REMOVAL, actually exercised. `exclusive` opens the temp with `O_EXCL`, so a
    /// leftover at the exact about-to-use name from a crashed run would make every subsequent write
    /// fail `EEXIST` forever -- the signing key could never be rotated again. The `remove_file(&tmp)`
    /// that prevents it had NO test: the temp name embeds a pid and an atomic counter, so no test
    /// could name the file it needed to plant, and the old case admitted as much ("we can't predict
    /// the exact pid-seq") and then asserted only that an ordinary re-write succeeds -- which it does
    /// with the pre-removal deleted.
    ///
    /// `plant_decoy_arm` plants INSIDE the primitive, at the exact path it computed. RED with the
    /// pre-removal removed: `EEXIST`.
    #[test]
    fn exclusive_pre_removal_clears_a_temp_left_by_a_crashed_run() {
        let sc = Scratch::new("wedge");
        let target = sc.path("signing.key");
        let opts = DurableOpts {
            mode: Some(0o600),
            exclusive: true,
        };
        fault_reset();
        write_with(&target, b"first", opts).unwrap();

        plant_decoy_arm();
        write_with(&target, b"rotated", opts)
            .expect("a temp left by a crashed run must not wedge the exclusive write");
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"rotated",
            "the rotation published, and published OUR bytes -- never the decoy's"
        );
        assert!(
            !sc.has_durable_temp("signing.key"),
            "the temp was consumed by the rename; nothing leaks"
        );
    }

    /// THE REMOVE SIDE of the durability contract. Installing an artifact fsyncs the holding
    /// directory so its entry survives a power loss; removing one used to skip that (a bare
    /// `remove_file` at the plugin-delete call site), which is the asymmetric half -- a crash right
    /// after a delete could resurrect the artifact and load it on the next boot. Asserted the same
    /// way the write side is: by observing the directory the primitive actually fsync'd, including
    /// the RELATIVE-path resolution to "." that a call site cannot dodge.
    #[test]
    fn remove_unlinks_and_fsyncs_the_holding_dir() {
        let sc = Scratch::new("remove");
        let target = sc.path("plugin-1.0.0.tar.gz");
        fault_reset();
        write(&target, b"artifact").unwrap();

        super::remove(&target).expect("the unlink succeeds");
        assert!(!target.exists(), "the artifact is gone");
        assert_eq!(
            fault_parent_fsynced().as_deref(),
            Some(sc.dir.as_path()),
            "the REMOVAL's directory entry must be fsync'd, exactly as the install's is"
        );

        // A missing target is a real error, not a silent success -- the caller's 404 check is a
        // separate concern and must not be papered over here.
        assert!(
            super::remove(&target).is_err(),
            "removing nothing is an error"
        );
    }

    /// Concurrent writers to the SAME target — the final file is exactly ONE writer's payload
    /// intact (no torn interleave), and no durable temp leaks. Covers the unique-naming race the old
    /// fixed `.overlay.tmp`/`.json.tmp` names allowed.
    #[test]
    fn concurrent_writers_no_torn_file_no_temp_leak() {
        let sc = Scratch::new("concurrent");
        let target = sc.path("shared.json");
        // Distinct fixed-length payloads so a torn interleave would be detectable.
        let payloads: Vec<Vec<u8>> = (0..8u8).map(|i| vec![b'A' + i; 4096]).collect();
        std::thread::scope(|s| {
            for p in &payloads {
                let target = target.clone();
                s.spawn(move || {
                    // Each thread must clear its own thread-local fault state (none armed here).
                    fault_reset();
                    write(&target, p).unwrap();
                });
            }
        });
        let final_bytes = std::fs::read(&target).unwrap();
        assert!(
            payloads.contains(&final_bytes),
            "the final file must be exactly one writer's payload intact (no torn interleave)"
        );
        assert!(
            !sc.has_durable_temp("shared.json"),
            "no durable temp may leak after concurrent writers"
        );
    }
    /// `std::fs::create_dir_all` leaves each new directory's own ENTRY non-durable, so the first
    /// artifact written into a freshly created plugins dir could vanish along with the directory on
    /// power loss — even though the file's contents and its holding directory were both fsynced.
    /// The primitive must fsync one PARENT per directory it creates, walking the whole missing
    /// ancestry, and must leave already-existing directories alone.
    #[test]
    fn create_dir_all_fsyncs_the_parent_of_every_directory_it_creates() {
        let sc = Scratch::new("mkdir-ancestors");
        fault_reset();

        let leaf = sc.dir.join("a").join("b").join("c");
        create_dir_all(&leaf).unwrap();
        assert!(leaf.is_dir());
        assert_eq!(
            fault_parents_fsynced(),
            vec![sc.dir.clone(), sc.dir.join("a"), sc.dir.join("a").join("b"),],
            "one parent fsync per created directory, shallowest first"
        );

        // Re-running over an existing tree creates nothing, so it must fsync nothing.
        fault_reset();
        create_dir_all(&leaf).unwrap();
        assert!(
            fault_parents_fsynced().is_empty(),
            "an already-durable directory must not be re-fsynced"
        );

        // Only the MISSING suffix is created, so only its parents are fsynced.
        fault_reset();
        let deeper = leaf.join("d");
        create_dir_all(&deeper).unwrap();
        assert_eq!(fault_parents_fsynced(), vec![leaf.clone()]);
    }
}
