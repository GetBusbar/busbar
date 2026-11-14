// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Decision 224: every hand-written primitive (two SHA-256s, HMAC, SHA-1, MD5, PBKDF2, BigUint
//! RSA-OAEP) is deleted for the crypto facade. A primitive needs its constants, so no first-party
//! source outside the backend may spell one, and no first-party manifest may name a bignum crate.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// Initial values and round constants of SHA-256, SHA-1 and MD5, with and without digit separators.
const CONSTANTS: &[&str] = &[
    "428a2f98", // SHA-256 K[0]
    "6a09e667", // SHA-256 H0[0]
    "5a827999", // SHA-1 K (rounds 0..20)
    "67452301", // SHA-1 / MD5 initial A
    "d76aa478", // MD5 K[0]
];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn walk(dir: &Path, ext: &str, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if p.is_dir() {
            if name != "target" && name != "busbar-crypto-backend" {
                walk(&p, ext, out);
            }
        } else if name.ends_with(ext) {
            out.push(p);
        }
    }
}

#[test]
fn no_first_party_source_spells_a_hash_constant() {
    let mut files = Vec::new();
    walk(&root().join("crates"), ".rs", &mut files);
    walk(&root().join("dist/default/tests"), ".rs", &mut files);
    assert!(files.len() > 100, "walked {} files", files.len());
    let (mut hits, mut compact, mut needle) = (String::new(), String::new(), String::new());
    for f in files {
        let text = std::fs::read_to_string(&f).unwrap_or_default();
        compact.clear();
        compact.extend(
            text.chars()
                .filter(|c| *c != '_')
                .map(|c| c.to_ascii_lowercase()),
        );
        for c in CONSTANTS {
            needle.clear();
            needle.push_str("0x");
            needle.push_str(c);
            if compact.contains(needle.as_str()) {
                writeln!(hits, "{} spells 0x{c}", f.display()).unwrap();
            }
        }
    }
    assert!(hits.is_empty(), "hand-written primitives remain:\n{hits}");
}

#[test]
fn no_first_party_manifest_names_a_bignum() {
    let mut manifests = Vec::new();
    walk(&root().join("crates"), "Cargo.toml", &mut manifests);
    manifests.push(root().join("Cargo.toml"));
    for m in manifests {
        let text = std::fs::read_to_string(&m).unwrap_or_default();
        assert!(
            !text
                .lines()
                .any(|l| l.trim_start().starts_with("num-bigint")),
            "{} names num-bigint",
            m.display()
        );
    }
}
