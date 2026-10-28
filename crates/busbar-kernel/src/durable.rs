// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DURABLE-WRITE SEAM, as the kernel and the surfaces it serves reach it (BUSBAR-1.6.0.md THE
//! DESIGN l.322: the kernel never names the loader). The one durable-write primitive —
//! `temp → write → flush → fsync(file) → rename → fsync(parent)`, with the temp cleaned on every
//! error path, and the parent fsync that makes a created, renamed or removed entry survive a power
//! loss — is the composition root's to install ([`crate::preflight::RootInstall::durable`]); the
//! `A-persistence` row of the `structure-lint` gate names its one home. This module is the seam the
//! overlay, the `plugins.fetch` directory and the admin plugin verbs write through, under the names
//! they always called (`durable::write`, `write_with`, `remove`, `create_dir_all`).
//!
//! A build with no root installed has no durable write: every call answers an error naming the
//! missing root, never a write that skips a step. A test build stands the kit's own in
//! ([`crate::test_support::DurableStandIn`]).

use std::io;
use std::path::Path;

/// Options a FEW call-sites need beyond the default. `Default` = the overlay/state posture (the
/// common case): OS/umask-default mode, truncate-create the temp.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DurableOpts {
    /// Unix file mode for the temp (and therefore the published) file, set AT OPEN. `None` =
    /// OS/umask default. A no-op where there are no mode bits.
    pub mode: Option<u32>,
    /// Refuse to adopt a pre-existing temp (`O_CREAT | O_EXCL`), the anti-pre-plant posture.
    pub exclusive: bool,
}

/// THE ONE DURABLE-WRITE PRIMITIVE, as the root installs it.
pub trait DurableFs: Send + Sync {
    /// Atomically and durably publish `bytes` to `path` with `opts`.
    ///
    /// # Errors
    /// Any step failed; on an error before the rename `path` is untouched and no temp is left.
    fn write_with(&self, path: &Path, bytes: &[u8], opts: DurableOpts) -> io::Result<()>;

    /// Durably remove `path`: unlink it, then fsync its holding directory.
    ///
    /// # Errors
    /// The unlink, or the directory fsync after it.
    fn remove(&self, path: &Path) -> io::Result<()>;

    /// Durably create `path` and any missing ancestors, each created entry's parent fsynced.
    ///
    /// # Errors
    /// A directory could not be created or its parent fsynced.
    fn create_dir_all(&self, path: &Path) -> io::Result<()>;
}

/// The installed primitive, or the refusal naming the missing root.
fn installed() -> io::Result<&'static dyn DurableFs> {
    crate::preflight::root_rows()
        .durable
        .ok_or_else(|| io::Error::other("no composition root installed the durable write"))
}

/// Atomically and durably publish `bytes` to `path` (default posture: overlay/state).
///
/// # Errors
/// As [`DurableFs::write_with`], or no root installed the primitive.
pub fn write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_with(path, bytes, DurableOpts::default())
}

/// Atomically and durably publish `bytes` to `path` with `opts`.
///
/// # Errors
/// As [`DurableFs::write_with`], or no root installed the primitive.
pub fn write_with(path: &Path, bytes: &[u8], opts: DurableOpts) -> io::Result<()> {
    installed()?.write_with(path, bytes, opts)
}

/// Durably remove `path`.
///
/// # Errors
/// As [`DurableFs::remove`], or no root installed the primitive.
pub fn remove(path: &Path) -> io::Result<()> {
    installed()?.remove(path)
}

/// Durably create `path` and any missing ancestors.
///
/// # Errors
/// As [`DurableFs::create_dir_all`], or no root installed the primitive.
pub fn create_dir_all(path: &Path) -> io::Result<()> {
    installed()?.create_dir_all(path)
}
