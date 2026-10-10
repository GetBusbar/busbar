// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE EXCEPTION TO `ring`-ONLY, CONFINED (THE DESIGN l.753, "Datagram media"): the
//! `aes`/`cipher`/`inout` crates enter the build for the SRTP key derivation alone.
//!
//! * In the resolved graph (`Cargo.lock`, every feature any member turns on): `aes` is depended on
//!   by this crate and nothing else, `cipher` by `aes` alone and `inout` by `cipher` alone.
//! * In this crate's source: `aes` is named only by `src/crypto.rs`, and there only by its import
//!   and by the two SRTP key-derivation rounds (`srtp_aes_128_ecb_round`/`srtp_aes_256_ecb_round`),
//!   the one AES block (`ecb_round`) having no other caller.
//!
//! THE RED ARMS, kept: the same checks over a graph where another crate takes `aes` (or `cipher`
//! straight), and over a source where the framing names `aes`, must refuse.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The crate the exception is granted to.
const GRANTED: &str = "busbar-transport-webrtc";

/// Each confined crate and the one crate allowed to depend on it.
const CONFINED: [(&str, &str); 3] = [("aes", GRANTED), ("cipher", "aes"), ("inout", "cipher")];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the workspace root")
        .to_path_buf()
}

/// Every package in `lock` and the names it depends on.
fn graph(lock: &str) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for block in lock.split("[[package]]").skip(1) {
        let mut name = None;
        let mut deps = Vec::new();
        let mut in_deps = false;
        for line in block.lines().map(str::trim) {
            if let Some(n) = line.strip_prefix("name = ") {
                name = Some(n.trim_matches('"').to_owned());
            } else if line.starts_with("dependencies = [") {
                in_deps = true;
            } else if in_deps && line.starts_with(']') {
                in_deps = false;
            } else if in_deps {
                // `"name"`, `"name 1.2.3"` or `"name 1.2.3 (registry+…)"`.
                let entry = line.trim_end_matches(',').trim_matches('"');
                if let Some(dep) = entry.split_whitespace().next() {
                    deps.push(dep.to_owned());
                }
            }
        }
        if let Some(n) = name {
            out.entry(n).or_default().extend(deps);
        }
    }
    out
}

/// `Err` naming the first package that depends on a confined crate it may not.
fn confined(lock: &str) -> Result<(), String> {
    let g = graph(lock);
    if !g.get(GRANTED).is_some_and(|d| d.iter().any(|x| x == "aes")) {
        return Err(format!("{GRANTED} does not depend on aes: the lock is not this tree's"));
    }
    for (krate, only) in CONFINED {
        for (from, deps) in &g {
            if deps.iter().any(|d| d == krate) && from != only {
                return Err(format!(
                    "{from} depends on {krate}: only {only} may (the SRTP key derivation's exception)"
                ));
            }
        }
    }
    Ok(())
}

/// Every non-comment line of `text` that names `needle` as code.
fn naming<'a>(text: &'a str, needle: &str) -> Vec<&'a str> {
    text.lines()
        .map(|l| l.split("//").next().unwrap_or_default().trim())
        .filter(|l| l.contains(needle))
        .collect()
}

/// The lines of the crypto file that may name `aes`: its import and the two SRTP rounds.
const CRYPTO_AES_LINES: [&str; 3] = [
    "use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};",
    "ecb_round::<aes::Aes128>(key, input, output);",
    "ecb_round::<aes::Aes256>(key, input, output);",
];

/// `Err` naming the first source line that names `aes` (or its block traits) outside the SRTP key
/// derivation. `files` are `(path relative to src, text)`.
fn source_confined(files: &[(String, String)]) -> Result<(), String> {
    let mut rounds = 0;
    for (path, text) in files {
        for needle in ["aes::", "cipher::", "inout::", "BlockEncrypt", "KeyInit", "ecb_round"] {
            for line in naming(text, needle) {
                let allowed = path == "crypto.rs"
                    && (CRYPTO_AES_LINES.contains(&line)
                        || line.starts_with("fn ecb_round<C: KeyInit + BlockEncrypt>(")
                        || line.starts_with("fn srtp_aes_128_ecb_round(")
                        || line.starts_with("fn srtp_aes_256_ecb_round("));
                if !allowed {
                    return Err(format!("src/{path} names `{needle}`: {line}"));
                }
            }
        }
        if path == "crypto.rs" {
            rounds = naming(text, "fn srtp_aes_")
                .iter()
                .filter(|l| l.contains("_ecb_round("))
                .count();
        }
    }
    if rounds != 2 {
        return Err(format!("{rounds} SRTP derivation rounds in src/crypto.rs, expected 2"));
    }
    Ok(())
}

fn sources(dir: &Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).expect("src is readable") {
        let p = e.expect("an entry").path();
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or_default().to_owned();
        if p.is_dir() {
            // The crate's own tests (`src/tests/`) name what they test; they never ship.
            if name != "tests" {
                out.extend(
                    sources(&p)
                        .into_iter()
                        .map(|(n, t)| (format!("{name}/{n}"), t)),
                );
            }
        } else if name.ends_with(".rs") {
            out.push((name, std::fs::read_to_string(&p).expect("a source file")));
        }
    }
    out
}

#[test]
fn aes_cipher_and_inout_are_confined_to_the_srtp_key_derivation_in_the_resolved_graph() {
    let lock = std::fs::read_to_string(root().join("Cargo.lock")).expect("the workspace lock");
    confined(&lock).unwrap_or_else(|e| panic!("{e}"));
}

#[test]
fn aes_is_named_only_by_the_srtp_key_derivation_in_the_source() {
    let mine = sources(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"));
    assert!(mine.iter().any(|(p, _)| p == "crypto.rs"), "src/crypto.rs is read");
    source_confined(&mine).unwrap_or_else(|e| panic!("{e}"));
}

// ── THE RED ARMS ────────────────────────────────────────────────────────────────────────────────

/// The real lock with `extra` appended as a package of its own.
fn with_package(extra: &str) -> String {
    let lock = std::fs::read_to_string(root().join("Cargo.lock")).expect("the workspace lock");
    format!("{lock}\n[[package]]\n{extra}")
}

#[test]
fn red_arm_another_crate_taking_aes_or_cipher_is_refused() {
    let aes = with_package("name = \"busbar-kernel-extra\"\nversion = \"1.6.0\"\ndependencies = [\n \"aes\",\n \"ring\",\n]\n");
    let refused = confined(&aes).expect_err("a second crate on aes is refused");
    assert!(refused.contains("busbar-kernel-extra depends on aes"), "{refused}");

    let cipher = with_package("name = \"stream-thing\"\nversion = \"0.1.0\"\ndependencies = [\n \"cipher 0.4.4\",\n]\n");
    let refused = confined(&cipher).expect_err("a crate on cipher straight is refused");
    assert!(refused.contains("stream-thing depends on cipher"), "{refused}");

    assert!(confined("").is_err(), "a lock without the grant is not this tree's");
}

#[test]
fn red_arm_the_framing_naming_aes_is_refused() {
    let mut files = sources(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"));
    files.push((
        "framing.rs".to_owned(),
        "fn key(k: &[u8]) { let _ = aes::Aes128::new_from_slice(k); }".to_owned(),
    ));
    let refused = source_confined(&files).expect_err("aes outside the derivation is refused");
    assert!(refused.contains("src/framing.rs names `aes::`"), "{refused}");

    // A third caller of the AES block, even inside the crypto file, is refused too.
    let crypto = files
        .iter()
        .position(|(p, _)| p == "crypto.rs")
        .expect("crypto.rs");
    files[crypto].1.push_str("\nfn more(k: &[u8]) { ecb_round::<aes::Aes192>(k, k, &mut []); }\n");
    files.pop();
    assert!(source_confined(&files).is_err());
}
