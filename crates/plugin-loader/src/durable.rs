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

pub fn write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_with(path, bytes, DurableOpts::default())
}

pub(crate) fn holding_dir(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

pub(crate) fn sync_holding_dir(path: &Path) -> io::Result<()> {
    match sync_dir(holding_dir(path)) {
        Err(e) if fsync_unsupported(&e) => Ok(()),
        other => other,
    }
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(test)]
    crate::durable::hooks::parent_fsync(dir)?;
    #[cfg(unix)]
    {
        std::fs::File::open(dir)?.sync_all()
    }

    #[cfg(not(unix))]
    {
        let _no_barrier = dir;
        Ok(())
    }
}

fn fsync_unsupported(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::Unsupported | io::ErrorKind::InvalidInput
    )
}

pub fn remove(path: &Path) -> io::Result<()> {
    std::fs::remove_file(path)?;
    sync_holding_dir(path)
}

pub fn create_dir_all(path: &Path) -> io::Result<()> {
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
            Ok(()) => sync_holding_dir(dir)?,

            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

pub fn write_with(path: &Path, bytes: &[u8], opts: DurableOpts) -> io::Result<()> {
    use std::io::Write as _;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);

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

    #[cfg(test)]
    crate::durable::hooks::plant_decoy_if_armed(&tmp);

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
            let _ = std::fs::remove_file(&tmp);
            open_opts.create_new(true);
        } else {
            open_opts.create(true).truncate(true);
        }
        #[cfg(unix)]
        if let Some(m) = opts.mode {
            use std::os::unix::fs::OpenOptionsExt as _;
            open_opts.mode(m);
        }
        fault_point!(FaultStep::Create);
        let mut f = open_opts.open(&tmp)?;
        fault_point!(FaultStep::Write);
        f.write_all(bytes)?;
        fault_point!(FaultStep::Flush);
        f.flush()?;
        fault_point!(FaultStep::Fsync);
        f.sync_all()?;
    }
    fault_point!(FaultStep::Rename);
    std::fs::rename(&tmp, path)?;
    guard.armed = false;

    sync_holding_dir(path)
}

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

#[cfg(test)]
#[path = "tests/durable_hooks.rs"]
pub(crate) mod hooks;

#[cfg(test)]
#[path = "tests/durable_tests.rs"]
mod tests;
