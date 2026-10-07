// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE READER OF A DECLARES DOCUMENT ([`Declares::from_declares_json`], ARCHITECT ruling (b),
//! 2026-10-07): what it reads and refuses, and a scan of the tree that refuses any other site
//! deserializing declares bytes straight into [`Declares`] with `serde_json`.

use super::{Declares, DECLARES_NEED_SCHEMES};
use std::path::{Path, PathBuf};

/// A declares document's `needs` is checked and left out of the section: the needs belong to the
/// Statement. RED ARMS: a malformed `needs` (not a list, a non-string, a scheme no framer serves)
/// is refused, and any other unknown key beside a well-formed `needs` is still refused.
#[test]
fn the_reader_checks_and_drops_needs_and_refuses_every_other_unknown_key() {
    let with = Declares::from_declares_json(
        br#"{"destinations": ["url"], "needs": ["https", "http", "tcp"]}"#,
    )
    .expect("a well-formed `needs` reads");
    let without =
        Declares::from_declares_json(br#"{"destinations": ["url"]}"#).expect("the same, without");
    assert_eq!(with, without, "the section carries no needs");
    assert_eq!(
        serde_json::to_value(&with).unwrap(),
        serde_json::json!({"destinations": ["url"]})
    );
    for scheme in DECLARES_NEED_SCHEMES {
        let doc = format!(r#"{{"needs": ["{scheme}"]}}"#);
        assert!(
            Declares::from_declares_json(doc.as_bytes()).is_ok(),
            "{scheme}"
        );
    }
    for bad in [
        r#"{"needs": "http"}"#,
        r#"{"needs": [7]}"#,
        r#"{"needs": ["gopher"]}"#,
        r#"{"needs": ["tcp"], "series": []}"#,
        r#"{"series": []}"#,
        "not json",
    ] {
        assert!(
            Declares::from_declares_json(bad.as_bytes()).is_err(),
            "{bad} must be refused"
        );
    }
}

/// A SIGNED manifest's `declares` is not a declares document: the manifest never carries `needs`,
/// so one that states it is refused like any other unknown key.
#[test]
fn a_signed_manifest_section_stating_needs_is_refused() {
    assert!(
        serde_json::from_value::<super::Manifest>(serde_json::json!({
            "name": "n", "alias": "n", "kind": "export", "version": "1.0.0", "publisher": "p",
            "abi_version": 1, "sha256": "", "signature": "",
            "declares": {"needs": ["http"]}
        }))
        .is_err()
    );
}

/// The statement around each `serde_json::from_*` call in `text` that deserializes declares bytes
/// into [`Declares`]: the call names `Declares` (a turbofish or the binding's type) or its argument
/// names a declares document, and it does not read into a `serde_json::Value`.
fn direct_reads(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(at) = text[from..].find("serde_json::from_") {
        let at = from + at;
        from = at + 1;
        let start = text[..at].rfind([';', '{', '}']).map_or(0, |i| i + 1);
        let end = text[at..].find(';').map_or(text.len(), |i| at + i);
        let stmt = &text[start..end];
        if stmt.contains("serde_json::Value") {
            continue;
        }
        let names_type = stmt.match_indices("Declares").any(|(i, _)| {
            let word = |c: Option<char>| c.is_some_and(|c| c.is_alphanumeric() || c == '_');
            !word(stmt[..i].chars().next_back()) && !word(stmt[i + 8..].chars().next())
        });
        let arg = text[at..].find('(').map(|open| {
            let mut depth = 0;
            let body = &text[at + open..];
            let close = body
                .char_indices()
                .find(|&(_, c)| {
                    match c {
                        '(' => depth += 1,
                        ')' => depth -= 1,
                        _ => {}
                    }
                    depth == 0
                })
                .map_or(body.len(), |(i, _)| i);
            body[..close].to_ascii_lowercase()
        });
        let names_document = arg.is_some_and(|a| a.contains("declares"));
        if names_type || names_document {
            out.push(stmt.split_whitespace().collect::<Vec<_>>().join(" "));
        }
    }
    out
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            if p.file_name().is_some_and(|n| n != "target" && n != ".git") {
                rust_files(&p, out);
            }
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// NO OTHER READER: no source in the tree deserializes declares bytes into [`Declares`] with
/// `serde_json` directly; every reader goes through [`Declares::from_declares_json`], so a
/// declares file's `needs` is read the one way everywhere (pack, a linked export row, a linked
/// plane door's row). RED ARM: the scan names each direct form, and passes a read into a
/// `serde_json::Value` and the one reader itself.
#[test]
fn no_site_but_the_one_reader_deserializes_declares_bytes() {
    // RED ARM over the scanner itself.
    for direct in [
        "let d: Declares = serde_json::from_str(text).unwrap();",
        "let d = serde_json::from_slice::<sign::Declares>(bytes);",
        "let declares = serde_json::from_str(declares).map_err(f)?;",
        "fn f() -> Declares { serde_json::from_str(x::DECLARES).unwrap() }",
    ] {
        assert_eq!(direct_reads(direct).len(), 1, "{direct}");
    }
    for allowed in [
        "let v: serde_json::Value = serde_json::from_str(declares)?;",
        "let d = Declares::from_declares_json(declares.as_bytes())?;",
        "let m: Manifest = serde_json::from_slice(&raw)?;",
    ] {
        assert!(direct_reads(allowed).is_empty(), "{allowed}");
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = Vec::new();
    rust_files(&root.join("crates"), &mut files);
    rust_files(&root.join("xtask"), &mut files);
    assert!(
        files.len() > 100,
        "the scan reads the tree: {}",
        files.len()
    );
    let me = Path::new(file!()).file_name().expect("a file name");
    let offenders: Vec<String> = files
        .iter()
        .filter(|p| p.file_name() != Some(me))
        .flat_map(|p| {
            let text = std::fs::read_to_string(p).unwrap_or_default();
            direct_reads(&text)
                .into_iter()
                .map(move |s| format!("{}: {s}", p.display()))
        })
        .collect();
    assert!(
        offenders.is_empty(),
        "declares bytes are read only by Declares::from_declares_json:\n{}",
        offenders.join("\n")
    );
}
