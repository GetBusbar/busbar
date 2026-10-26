// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE POSTER'S DURABLE PIECES (MONEY-DESIGN §3c): the spool's framing, its segments and manifest,
//! and the count records with the batch bodies derived from them.

pub mod edge;
pub mod frame;
pub mod record;
pub mod recorder;
pub mod spool;

pub use recorder::Closed;

/// A temporary directory removed on drop (the spool's own tests and the poster's).
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug)]
pub struct TmpDir(std::path::PathBuf);

#[cfg(any(test, feature = "test-support"))]
impl TmpDir {
    /// A fresh, empty directory under the system temp dir.
    #[must_use]
    pub fn new() -> Self {
        let mut raw = [0u8; 8];
        let _ = getrandom::fill(&mut raw);
        let p = std::env::temp_dir().join(format!("busbar-money-{}", hex::encode(raw)));
        std::fs::create_dir_all(&p).expect("temp dir");
        TmpDir(p)
    }

    /// Its path.
    #[must_use]
    pub fn path(&self) -> &std::path::Path {
        &self.0
    }
}

#[cfg(any(test, feature = "test-support"))]
impl Default for TmpDir {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(test, feature = "test-support"))]
impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
