// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The backend contract is pinned to `busbar_crypto_backend::API` (DES crypto-seam r3 §4, I-3-353).
//!
//! The contract is src/contract.rs. Its hash is FNV-1a 64 (busbar-plugin-abi's `fp_parts`, restated
//! below) over, in order:
//! - every top-level item of a hashed kind: `use`, `type`, `const` (named or `_`) and `const fn`, each
//!   with its `#[cfg(..)]` attributes kept, every other attribute (docs included) dropped, printed by
//!   `quote` and stripped of whitespace. A plain `fn` (a start-up check such as `known_answers`) is
//!   not contract. Any other kind fails the test until it is classified here, so nothing enters or
//!   leaves the scope silently. Comments and docs never move the hash; an assert message does, on
//!   purpose (it is what a failing backend's author reads);
//! - the `rustls`, `rustls-pki-types` and `dimpl` requirement lines of busbar-crypto's
//!   `[dependencies]`, because the tls block pins their types and their meaning moves with the version.
//!
//! `ci/crypto-api.pin` is append-only, one line per released contract, `backend <API> 0x<hash>`:
//! - (a) its last line is this tree's `backend {API} 0x{hash}`;
//! - (b) its first line is API 3 and each later line raises the API by exactly one (an exact revert,
//!   API n+1 with line n-1's hash, is allowed);
//! - (c) the CHANGELOG section under the first `## [` heading names `busbar-crypto-backend API {API}`;
//! - (d) the pin file on origin's `dev` tip is a line-prefix of this one (an absent file is the empty
//!   prefix), so a released line is never edited in place.
//!
//! Every `pub use` through the backend in busbar-crypto/src must be named in contract.rs, so no backend
//! item reaches the facade's surface outside the hashed contract.
//!
//! Threat model: this stops accidental contract drift in a reviewed MR. A deliberate bypass (editing
//! this test, rewriting `dev`, deleting the pin on `dev`) is a visible change to a CODEOWNERS path.

use std::path::{Path, PathBuf};
use std::process::Command;

use quote::ToTokens;

const PIN: &str = "ci/crypto-api.pin";
const ANCHOR_REF: &str = "refs/busbar-test/crypto-api-anchor";
/// The facade's third-party contract crates (the tls block names their types).
const THIRD_PARTY: [&str; 3] = ["rustls", "rustls-pki-types", "dimpl"];
/// The first contract the pin records: 1.6.0's (CA-17: one backend contract break, 2 to 3).
const FIRST_API: u32 = 3;

fn here() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn root() -> PathBuf {
    here().join("../..")
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// `git -C <root> <args>`: stdout on success, else the exit status and stderr.
fn git(args: &[&str]) -> Result<String, String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(root())
        .args(args)
        .output()
        .map_err(|e| format!("git {}: {e}", args.join(" ")))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        Err(format!(
            "git {}: {}: {}",
            args.join(" "),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const PRIME: u64 = 0x0000_0100_0000_01b3;

/// busbar-plugin-abi's `fp_parts`, restated: FNV-1a 64 over the non-whitespace bytes of each part,
/// with a 0xFF byte folded in between two parts.
fn fp_parts(parts: &[String]) -> u64 {
    let mut hash = OFFSET;
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            hash = (hash ^ 0xFF).wrapping_mul(PRIME);
        }
        for &byte in part.as_bytes() {
            if !matches!(byte, b' ' | b'\t' | b'\n' | b'\x0C' | b'\r') {
                hash = (hash ^ u64::from(byte)).wrapping_mul(PRIME);
            }
        }
    }
    hash
}

fn strip(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

/// The start of an item's tokens, to name it in a failure.
fn head(item: &syn::Item) -> String {
    item.to_token_stream()
        .to_string()
        .chars()
        .take(80)
        .collect()
}

/// The canonical form of each hashed item of contract.rs, in file order.
fn hashed_items(contract: &str) -> Result<Vec<String>, String> {
    let file = syn::parse_file(contract).map_err(|e| format!("contract.rs does not parse: {e}"))?;
    let mut parts = Vec::new();
    for mut item in file.items {
        let attrs = match &mut item {
            syn::Item::Use(i) => &mut i.attrs,
            syn::Item::Type(i) => &mut i.attrs,
            syn::Item::Const(i) => &mut i.attrs,
            syn::Item::Fn(i) => {
                if i.sig.constness.is_none() {
                    // A start-up check, not contract.
                    continue;
                }
                &mut i.attrs
            }
            other => return Err(format!(
                "contract.rs has a top-level item of a kind the contract hash does not classify \
                     (only use, type, const, const fn and plain fn are): `{}`; classify it in \
                     tests/contract_pin.rs",
                head(other)
            )),
        };
        attrs.retain(|a| a.path().is_ident("cfg"));
        parts.push(strip(&item.to_token_stream().to_string()));
    }
    Ok(parts)
}

/// The whitespace-stripped `<name> = ...` line of each third-party crate in `[dependencies]`.
fn requirement_lines(manifest: &str) -> Result<Vec<String>, String> {
    THIRD_PARTY
        .iter()
        .map(|name| {
            let mut section = "";
            for line in manifest.lines() {
                let line = line.trim();
                if line.starts_with('[') {
                    section = line;
                } else if section == "[dependencies]" && line.starts_with(&format!("{name} =")) {
                    return Ok(strip(line));
                }
            }
            Err(format!(
                "crates/busbar-crypto/Cargo.toml [dependencies] has no `{name} =` line; the contract \
                 hash covers its requirement"
            ))
        })
        .collect()
}

/// The contract hash of `contract` (contract.rs) and `manifest` (busbar-crypto/Cargo.toml).
fn contract_hash(contract: &str, manifest: &str) -> Result<u64, String> {
    let mut parts = hashed_items(contract)?;
    parts.extend(requirement_lines(manifest)?);
    Ok(fp_parts(&parts))
}

/// The pin's lines as `(API, line)`; a line not of the form `backend <API> 0x<16 hex>` is an error.
fn pin_lines(pin: &str) -> Result<Vec<(u32, &str)>, String> {
    pin.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| {
            let mut w = line.split(' ');
            let api = match (w.next(), w.next(), w.next(), w.next()) {
                (Some("backend"), Some(api), Some(hash), None)
                    if hash.len() == 18
                        && hash.starts_with("0x")
                        && hash[2..]
                            .bytes()
                            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) =>
                {
                    api.parse::<u32>().ok()
                }
                _ => None,
            };
            api.map(|api| (api, line)).ok_or_else(|| {
                format!("{PIN}: `{line}` is not `backend <API> 0x<16 lowercase hex>`")
            })
        })
        .collect()
}

/// (a) and (b).
fn check_pin(pin: &str, api: u32, hash: u64) -> Result<(), String> {
    let want = format!("backend {api} 0x{hash:016x}");
    let changed = format!(
        "the backend contract changed: raise busbar_crypto_backend::API to {next} and the contract.rs \
         assert, append `backend {next} 0x...` to {PIN}, add a CHANGELOG line under the current release \
         heading (this tree's contract is `{want}`)",
        next = api + 1
    );
    let lines = pin_lines(pin)?;
    let Some(&(first, _)) = lines.first() else {
        return Err(format!("{PIN} records no contract; {changed}"));
    };
    if first != FIRST_API {
        return Err(format!(
            "{PIN} must start at API {FIRST_API}, the 1.6.0 contract; it starts at {first}"
        ));
    }
    for pair in lines.windows(2) {
        if pair[1].0 != pair[0].0 + 1 {
            return Err(format!(
                "{PIN}: each line raises the API by exactly one: `{}` follows `{}`",
                pair[1].1, pair[0].1
            ));
        }
    }
    let (_, last) = lines[lines.len() - 1];
    if last != want {
        return Err(format!("{PIN} ends `{last}`; {changed}"));
    }
    Ok(())
}

/// (c): the section from the first `## [` heading to the next names `busbar-crypto-backend API {api}`.
fn check_changelog(changelog: &str, api: u32) -> Result<(), String> {
    let mut lines = changelog.lines().skip_while(|l| !l.starts_with("## ["));
    let heading = lines
        .next()
        .ok_or("CHANGELOG.md has no `## [` release heading")?;
    let needle = format!("busbar-crypto-backend API {api}");
    let named = lines.take_while(|l| !l.starts_with("## [")).any(|l| {
        l.match_indices(&needle)
            .any(|(at, _)| !l[at + needle.len()..].starts_with(|c: char| c.is_ascii_digit()))
    });
    if named {
        Ok(())
    } else {
        Err(format!(
            "CHANGELOG.md's current release section (`{heading}`) must name `{needle}`"
        ))
    }
}

/// (d): `anchor` (the pin on origin's `dev`; `None` when it has none) is a line-prefix of `current`.
fn check_prefix(anchor: Option<&str>, current: &str) -> Result<(), String> {
    let anchor: Vec<&str> = anchor
        .unwrap_or("")
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect();
    let current: Vec<&str> = current.lines().filter(|l| !l.trim().is_empty()).collect();
    if current.len() >= anchor.len() && current[..anchor.len()] == anchor[..] {
        Ok(())
    } else {
        Err(format!(
            "{PIN} is append-only: dev has\n{}\nand this tree has\n{}",
            anchor.join("\n"),
            current.join("\n")
        ))
    }
}

/// Every `pub use` through the backend in `files` (`(name, source)`) that contract.rs does not name.
fn unnamed_reexports(files: &[(String, String)], contract: &str) -> Vec<String> {
    let mut unnamed = Vec::new();
    for (name, src) in files {
        for line in src.lines() {
            let t = line.trim();
            let path = ["pub use b::", "pub use busbar_crypto_backend::"]
                .iter()
                .find_map(|p| t.strip_prefix(p));
            if let Some(path) = path {
                let path = path.trim_end_matches(';').trim();
                if !contract.contains(&format!("b::{path}")) {
                    unnamed.push(format!("{name}: `{t}` (contract.rs names no `b::{path}`)"));
                }
            }
        }
    }
    unnamed
}

/// busbar-crypto/src's `.rs` files other than contract.rs, as `(path, source)`.
fn facade_sources() -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut dirs = vec![here().join("src")];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                dirs.push(path);
            } else if path.extension().is_some_and(|e| e == "rs")
                && !path.ends_with("src/contract.rs")
            {
                out.push((path.display().to_string(), read(&path)));
            }
        }
    }
    out
}

/// The pin file on origin's `dev` tip, fetched into a private ref (FETCH_HEAD untouched: the
/// architecture tests read it); `None` when `dev` has no pin file.
fn anchor_pin() -> Option<String> {
    git(&["rev-parse", "--git-dir"])
        .unwrap_or_else(|e| panic!("this guard reads core's git history: {e}"));
    let refspec = format!("+refs/heads/dev:{ANCHOR_REF}");
    let fetch = [
        "fetch",
        "-q",
        "--no-tags",
        "--no-write-fetch-head",
        "--depth=1",
        "origin",
        &refspec,
    ];
    // Another test target may be fetching into the same shallow clone at once (its shallow lock).
    let mut fetched = git(&fetch);
    for _ in 0..4 {
        if fetched.is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
        fetched = git(&fetch);
    }
    fetched.unwrap_or_else(|e| panic!("origin's dev cannot be fetched as the pin anchor: {e}"));
    git(&["cat-file", "-e", &format!("{ANCHOR_REF}:{PIN}")]).ok()?;
    Some(git(&["show", &format!("{ANCHOR_REF}:{PIN}")]).unwrap())
}

const CONTRACT: &str = include_str!("../src/contract.rs");
const MANIFEST: &str = include_str!("../Cargo.toml");

#[test]
fn the_backend_contract_is_pinned_in_ci_crypto_api_pin() {
    let api = busbar_crypto_backend_api();
    let hash = contract_hash(CONTRACT, MANIFEST).unwrap_or_else(|e| panic!("{e}"));
    let pin = std::fs::read_to_string(root().join(PIN)).unwrap_or_default();
    check_pin(&pin, api, hash).unwrap_or_else(|e| panic!("(a)/(b): {e}"));
    let changelog = read(&root().join("CHANGELOG.md"));
    check_changelog(&changelog, api).unwrap_or_else(|e| panic!("(c): {e}"));
    check_prefix(anchor_pin().as_deref(), &pin).unwrap_or_else(|e| panic!("(d): {e}"));
    let unnamed = unnamed_reexports(&facade_sources(), CONTRACT);
    assert!(
        unnamed.is_empty(),
        "the facade re-exports backend items the contract does not name:\n{}",
        unnamed.join("\n")
    );
}

/// The linked backend's `API`, as the facade states it.
fn busbar_crypto_backend_api() -> u32 {
    busbar_contract::crypto::API
}

#[test]
fn the_hash_is_busbar_plugin_abi_fp_parts() {
    assert_eq!(fp_parts(&[]), OFFSET);
    assert_eq!(fp_parts(&["foobar".into()]), 0x8594_4171_f739_67e8);
    assert_eq!(
        fp_parts(&[" f o\to\nb\ra\x0Cr ".into()]),
        0x8594_4171_f739_67e8
    );
    assert_ne!(
        fp_parts(&["foo".into(), "bar".into()]),
        fp_parts(&["fo".into(), "obar".into()])
    );
}

fn hash_of(contract: &str, manifest: &str) -> u64 {
    contract_hash(contract, manifest).unwrap()
}

#[test]
fn a_changed_signature_or_message_moves_the_hash_and_a_comment_does_not() {
    let base = hash_of(CONTRACT, MANIFEST);
    let pin = format!("backend 3 0x{base:016x}\n");
    assert_eq!(check_pin(&pin, 3, base), Ok(()));

    let sig = CONTRACT.replacen(
        "let _: fn(&[u8]) -> [u8; 32] = b::sha256;",
        "let _: fn(&[u8]) -> [u8; 33] = b::sha256;",
        1,
    );
    assert_ne!(sig, CONTRACT, "the signature edit applies");
    assert!(check_pin(&pin, 3, hash_of(&sig, MANIFEST)).is_err());

    let message = CONTRACT.replacen(
        "NAME `external` is reserved",
        "NAME `external` is kept back",
        1,
    );
    assert_ne!(message, CONTRACT, "the message edit applies");
    assert!(check_pin(&pin, 3, hash_of(&message, MANIFEST)).is_err());

    let cfg = CONTRACT.replacen("#[cfg(feature = \"tls\")]", "#[cfg(feature = \"tls2\")]", 1);
    assert_ne!(cfg, CONTRACT, "the cfg edit applies");
    assert!(check_pin(&pin, 3, hash_of(&cfg, MANIFEST)).is_err());

    let commented = CONTRACT.replacen(
        "const _: () = {",
        "// a comment\n/// a doc\n#[allow(unused)]\nconst _: () = {",
        1,
    );
    assert_eq!(hash_of(&commented, MANIFEST), base);
    let startup = CONTRACT.replacen("if a.len() != b.len()", "if a.len() != b.len() ", 1);
    assert_eq!(
        hash_of(&startup, MANIFEST),
        base,
        "whitespace never moves it"
    );
}

#[test]
fn a_moved_third_party_requirement_moves_the_hash() {
    let base = hash_of(CONTRACT, MANIFEST);
    let pin = format!("backend 3 0x{base:016x}\n");
    let dimpl = MANIFEST.replacen("version = \"=0.7.4\"", "version = \"=0.8.0\"", 1);
    assert_ne!(dimpl, MANIFEST, "the dimpl edit applies");
    assert!(check_pin(&pin, 3, hash_of(CONTRACT, &dimpl)).is_err());
    let rustls = MANIFEST.replacen(
        "rustls = { version = \"0.23\"",
        "rustls = { version = \"0.24\"",
        1,
    );
    assert_ne!(rustls, MANIFEST, "the rustls edit applies");
    assert!(check_pin(&pin, 3, hash_of(CONTRACT, &rustls)).is_err());
    let gone = MANIFEST.replacen("dimpl = {", "# dimpl = {", 1);
    assert!(
        contract_hash(CONTRACT, &gone).is_err(),
        "a missing line fails"
    );
}

#[test]
fn an_unclassified_item_kind_fails_the_classifier() {
    let with_struct = format!("{CONTRACT}\nstruct Extra;\n");
    let e = contract_hash(&with_struct, MANIFEST).unwrap_err();
    assert!(e.contains("struct Extra"), "{e}");
    let with_fn = format!("{CONTRACT}\nfn later_startup_check() {{}}\n");
    assert_eq!(hash_of(&with_fn, MANIFEST), hash_of(CONTRACT, MANIFEST));
}

#[test]
fn the_pin_rises_by_one_from_three_and_allows_an_exact_revert() {
    let h = |n: u64| format!("0x{n:016x}");
    assert!(check_pin(&format!("backend 3 {}\nbackend 5 {}\n", h(1), h(2)), 5, 2).is_err());
    assert!(check_pin(&format!("backend 4 {}\n", h(1)), 4, 1).is_err());
    assert_eq!(
        check_pin(
            &format!(
                "backend 3 {}\nbackend 4 {}\nbackend 5 {}\n",
                h(1),
                h(2),
                h(1)
            ),
            5,
            1
        ),
        Ok(())
    );
    assert!(
        check_pin("backend 3 0x12\n", 3, 0x12).is_err(),
        "16 hex digits"
    );
    assert!(check_pin("", 3, 1).is_err());
}

#[test]
fn a_released_line_is_never_edited_in_place() {
    let released = "backend 3 0x0000000000000001\n";
    let appended = "backend 3 0x0000000000000001\nbackend 4 0x0000000000000002\n";
    assert_eq!(check_prefix(Some(released), appended), Ok(()));
    assert_eq!(
        check_prefix(None, released),
        Ok(()),
        "an absent anchor file"
    );
    let edited = "backend 3 0x0000000000000009\nbackend 4 0x0000000000000002\n";
    assert!(check_prefix(Some(released), edited).is_err());
    assert!(check_prefix(Some(appended), released).is_err());
}

#[test]
fn the_changelog_line_counts_only_under_the_current_release_heading() {
    let current = "# Changelog\n\n## [1.6.0], unreleased\n\n- busbar-crypto-backend API 3: VALIDATION\n\n## [1.5.5]\n";
    assert_eq!(check_changelog(current, 3), Ok(()));
    let older = "# Changelog\n\n## [1.6.0], unreleased\n\n- other\n\n## [1.5.5]\n\n- busbar-crypto-backend API 3\n";
    assert!(check_changelog(older, 3).is_err());
    let preamble = "busbar-crypto-backend API 3\n## [1.6.0], unreleased\n";
    assert!(check_changelog(preamble, 3).is_err());
    let thirty = "## [1.6.0], unreleased\n- busbar-crypto-backend API 30\n";
    assert!(check_changelog(thirty, 3).is_err());
}

#[test]
fn a_backend_reexport_the_contract_does_not_name_fails() {
    let contract = "const _: () = { let _: Option<b::rsa::Scheme> = None; };";
    let named = [(
        "lib.rs".to_string(),
        "    pub use b::rsa::Scheme;\n".to_string(),
    )];
    assert!(unnamed_reexports(&named, contract).is_empty());
    let new = [(
        "lib.rs".to_string(),
        "pub use b::rsa::Scheme;\npub use busbar_crypto_backend::ecdh_p256::EphemeralKey;\n"
            .to_string(),
    )];
    let unnamed = unnamed_reexports(&new, contract);
    assert_eq!(unnamed.len(), 1, "{unnamed:?}");
    assert!(unnamed[0].contains("ecdh_p256::EphemeralKey"));
}
