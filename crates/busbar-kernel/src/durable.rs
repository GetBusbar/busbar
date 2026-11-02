// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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

pub trait DurableFs: Send + Sync {
    fn write_with(&self, path: &Path, bytes: &[u8], opts: DurableOpts) -> io::Result<()>;

    fn remove(&self, path: &Path) -> io::Result<()>;

    fn create_dir_all(&self, path: &Path) -> io::Result<()>;
}

fn installed() -> io::Result<&'static dyn DurableFs> {
    crate::preflight::root_rows()
        .durable
        .ok_or_else(|| io::Error::other("no composition root installed the durable write"))
}

pub fn write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_with(path, bytes, DurableOpts::default())
}

pub fn write_with(path: &Path, bytes: &[u8], opts: DurableOpts) -> io::Result<()> {
    installed()?.write_with(path, bytes, opts)
}

pub fn remove(path: &Path) -> io::Result<()> {
    installed()?.remove(path)
}

pub fn create_dir_all(path: &Path) -> io::Result<()> {
    installed()?.create_dir_all(path)
}
