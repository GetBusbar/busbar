// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SECRET SHORTHAND IS THE PLUGINS' DECLARATION, NOT THE KERNEL'S VOCABULARY (audit
//! contract-admin #10, MEDIUM; BUSBAR-1.6.0.md Part 1, Laws 0 and 1: core names kinds, never
//! instances). Which reference keys a secret source answers to, the settings key a shorthand value
//! lands under and what a refusal says that value names are stated by each secret plugin in its
//! own Statement (`REWRITE_SUGAR`, `REWRITE_SUGAR_NAMES`); config validation reads them off the
//! loaded plugins and holds no source's name, settings key or wording.

/// The configuration checks' own source, whole.
const SOURCE: &str = include_str!("../mod.rs");

/// RED before the drain: the structural secret check branched on the contract's per-source module
/// constants and called the per-source accessors, so the kernel spelled two secret instances.
#[test]
fn config_validation_names_no_secret_source() {
    let needles = ["SECRET_MODULE_", ".env_var(", ".file_path("];
    let found: Vec<(usize, &str)> = SOURCE
        .lines()
        .enumerate()
        .filter(|(_, l)| !l.trim_start().starts_with("//"))
        .filter(|(_, l)| needles.iter().any(|n| l.contains(n)))
        .map(|(i, l)| (i + 1, l.trim()))
        .collect();
    assert!(
        found.is_empty(),
        "config_validate/mod.rs names a secret source; read the declared shorthand off the loaded \
         secret plugins instead:\n{found:#?}"
    );
}
