// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A scratch config directory per test, removed on drop.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

pub(crate) struct Scratch {
    dir: PathBuf,
}

impl Scratch {
    pub(crate) fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "busbar-migrate-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        Self { dir }
    }

    pub(crate) fn dir(&self) -> &Path {
        &self.dir
    }

    /// Write `config.yaml` with `text` and return its path.
    pub(crate) fn config(&self, text: &str) -> PathBuf {
        let path = self.dir.join("config.yaml");
        std::fs::write(&path, text).expect("write config.yaml");
        path
    }

    /// Every file name in the directory, sorted.
    pub(crate) fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&self.dir)
            .expect("read scratch dir")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        names
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Scratch {
    /// Write `config.yaml` with `text`, and the `providers.yaml` beside it that 1.5.5 required (an
    /// empty catalog) unless one is there; return config.yaml's path.
    pub(crate) fn deployment(&self, text: &str) -> PathBuf {
        let catalog = self.dir.join("providers.yaml");
        if !catalog.exists() {
            std::fs::write(&catalog, "{}\n").expect("write providers.yaml");
        }
        self.config(text)
    }

    /// Write `name` in the directory with `text` and return its path.
    pub(crate) fn file(&self, name: &str, text: &str) -> PathBuf {
        let path = self.dir.join(name);
        std::fs::write(&path, text).expect("write a scratch file");
        path
    }
}

/// The catalog keys the tests' 1.6.0 reads.
pub(crate) const CATALOG_KEYS: [&str; 6] = [
    "protocol", "base_url", "auth", "api_key", "models", "headers",
];

/// An environment with nothing set.
pub(crate) fn no_env(_: &str) -> Option<String> {
    None
}

/// The boot's facts in a test: no open unit, [`CATALOG_KEYS`], nothing set in the environment.
pub(crate) fn facts() -> crate::Facts {
    crate::Facts {
        open_units: Vec::new(),
        catalog_keys: CATALOG_KEYS.iter().map(|key| (*key).to_owned()).collect(),
        env: no_env,
        cwd: std::env::temp_dir(),
    }
}

/// A strict parse that accepts every document.
pub(crate) fn accept(_: &str, _: Option<&str>) -> Result<(), String> {
    Ok(())
}
