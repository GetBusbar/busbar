// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The error pages and the code ledger: the committed `docs/errors/` tree is exactly what the
//! catalog renders, and no code is ever dropped, renumbered or reused.

use super::pages::render_all;
use super::{all_texts, REGISTRY};
use busbar_contract::diagnostic::{error_docs_version, Diagnostic, ERROR_DOCS_BASE};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

fn docs_errors() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/errors")
}

fn update() -> bool {
    std::env::var("UPDATE_ERROR_PAGES").is_ok_and(|v| v == "1")
}

/// Where the proposed pages and ledger are written for review (`target/diagnostics-generated/`).
fn generated_dir() -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target"))
        .join("diagnostics-generated")
}

const REGENERATE: &str =
    "regenerate with `UPDATE_ERROR_PAGES=1 cargo test -p busbar-kernel error_pages`";

#[test]
fn error_pages_match_the_catalog() {
    let pages = render_all(REGISTRY, &all_texts());
    let dir = docs_errors().join(error_docs_version());
    if let Ok(out) = std::env::var("ERROR_PAGES_OUT") {
        let out = PathBuf::from(out).join(error_docs_version()).join("errors");
        std::fs::create_dir_all(&out).expect("create ERROR_PAGES_OUT");
        for (name, body) in &pages {
            std::fs::write(out.join(name), body).expect("write a page to ERROR_PAGES_OUT");
        }
    }
    // The proposed tree always goes to `target/diagnostics-generated/` (CI keeps it as an artifact:
    // the exact pages to commit when this test fails). The assertions below are unchanged.
    let proposed = generated_dir().join(error_docs_version());
    std::fs::create_dir_all(&proposed).expect("create target/diagnostics-generated");
    for (name, body) in &pages {
        std::fs::write(proposed.join(name), body).expect("write a proposed page");
    }
    if update() {
        if dir.exists() {
            std::fs::remove_dir_all(&dir).expect("clear the version directory");
        }
        std::fs::create_dir_all(&dir).expect("create the version directory");
        for (name, body) in &pages {
            std::fs::write(dir.join(name), body).expect("write a page");
        }
        return;
    }
    let committed: BTreeSet<String> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}; {REGENERATE}", dir.display()))
        .map(|e| {
            e.expect("dir entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    let fresh: BTreeSet<String> = pages.iter().map(|(n, _)| n.clone()).collect();
    assert_eq!(
        committed,
        fresh,
        "docs/errors/{} holds a different page set than the catalog renders; {REGENERATE}",
        error_docs_version()
    );
    for (name, body) in &pages {
        let path = dir.join(name);
        let on_disk = std::fs::read_to_string(&path).expect("read a committed page");
        assert_eq!(&on_disk, body, "{} is stale; {REGENERATE}", path.display());
    }
}

/// THE LEDGER: `docs/errors/LEDGER.tsv` lists every code ever published (`BUSBAR-NNNN<TAB>slug<TAB>since`)
/// and is append-only. A row whose code left the catalog (deleted instead of retired), or whose
/// code now names a different slug or version (a reused number), fails here even under
/// `UPDATE_ERROR_PAGES=1`: retire a code, never delete or recycle it.
#[test]
fn error_pages_ledger_never_loses_or_reuses_a_code() {
    let path = docs_errors().join("LEDGER.tsv");
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    let by_code: BTreeMap<String, &Diagnostic> = REGISTRY
        .iter()
        .map(|d| (d.banner().to_string(), *d))
        .collect();
    let mut seen = BTreeSet::new();
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let cols: Vec<&str> = line.split('\t').collect();
        assert_eq!(
            cols.len(),
            3,
            "LEDGER.tsv row is not code<TAB>slug<TAB>since: {line}"
        );
        assert!(
            seen.insert(cols[0].to_string()),
            "LEDGER.tsv lists {} twice",
            cols[0]
        );
        let d = by_code.get(cols[0]).unwrap_or_else(|| {
            panic!("{} was published but left the catalog: retire it (retired = true), never delete it", cols[0])
        });
        assert_eq!(
            (d.slug, d.since),
            (cols[1], cols[2]),
            "{} was published as {}/{} and now names {}/{}: a code is never reused",
            cols[0],
            cols[1],
            cols[2],
            d.slug,
            d.since
        );
    }
    let mut missing: Vec<&Diagnostic> = REGISTRY
        .iter()
        .copied()
        .filter(|d| !seen.contains(&d.banner().to_string()))
        .collect();
    missing.sort_by_key(|d| d.code);
    if missing.is_empty() {
        return;
    }
    let codes: Vec<u16> = missing.iter().map(|d| d.code).collect();
    let mut text = if text.is_empty() {
        "# Every BUSBAR-NNNN code ever published: code, slug, version introduced. Append-only.\n"
            .to_string()
    } else {
        text
    };
    for d in missing {
        text.push_str(&format!("{}\t{}\t{}\n", d.banner(), d.slug, d.since));
    }
    // The appended ledger goes to `target/diagnostics-generated/LEDGER.tsv` for review either way.
    std::fs::create_dir_all(generated_dir()).expect("create target/diagnostics-generated");
    std::fs::write(generated_dir().join("LEDGER.tsv"), &text).expect("write the proposed ledger");
    assert!(
        update(),
        "{} code(s) are not in docs/errors/LEDGER.tsv: {codes:?}; {REGENERATE}",
        codes.len(),
    );
    std::fs::create_dir_all(docs_errors()).expect("create docs/errors");
    std::fs::write(&path, text).expect("append to LEDGER.tsv");
}

#[test]
fn error_pages_every_text_belongs_to_a_live_code_and_its_example_fits_the_template() {
    let mut seen = BTreeSet::new();
    for t in all_texts() {
        assert!(seen.insert(t.code), "two texts for BUSBAR-{:04}", t.code);
        let d = REGISTRY
            .iter()
            .find(|d| d.code == t.code)
            .unwrap_or_else(|| panic!("text for BUSBAR-{:04}, which is not catalogued", t.code));
        assert!(
            !d.retired,
            "{} is retired but still has a message template",
            d.banner()
        );
        assert!(
            !t.text.ends_with('.'),
            "{}'s template ends with a period",
            d.banner()
        );
        if !t.example_detail.is_empty() {
            assert!(
                t.matches(t.example_detail),
                "{}'s example_detail is not an instance of its template:\n  {}\n  {}",
                d.banner(),
                t.text,
                t.example_detail
            );
        }
    }
}

#[test]
fn error_pages_docs_base_names_this_releases_major_minor() {
    let pkg = env!("CARGO_PKG_VERSION");
    let major_minor: Vec<&str> = pkg.split('.').take(2).collect();
    assert_eq!(error_docs_version(), major_minor.join("."));
    assert_eq!(
        ERROR_DOCS_BASE,
        format!(
            "https://getbusbar.com/docs/{}/errors/",
            error_docs_version()
        )
    );
}

/// The one test that pins a rendered code string and link: everything else asserts through the
/// typed identifiers.
#[test]
fn error_pages_a_coded_message_reads_code_text_link() {
    let m = busbar_contract::section::reserved_name("pool", "hooks", "pools");
    assert_eq!(
        m.code(),
        busbar_contract::diagnostic::CONFIG_RESERVED_NAME.code
    );
    assert_eq!(
        m.to_string(),
        "BUSBAR-3101: a pool may not be named `hooks` (reserved in `pools:`). \
         See https://getbusbar.com/docs/1.6/errors/BUSBAR-3101"
    );
}

/// A coded message wrapped by another (serde's path/location frame, a family wrapper) reports the
/// inner, more specific code first and keeps exactly one link, last.
#[test]
fn error_pages_a_wrapped_coded_message_promotes_the_inner_code() {
    use busbar_contract::diagnostic::CONFIG_RESERVED_NAME;
    let inner = busbar_contract::section::reserved_name("pool", "hooks", "pools");
    let framed = format!("config.yaml: invalid YAML: pools: {inner} at line 1 column 1");
    let outer = super::CLI_VALIDATE_CONFIG_INVALID.coded(&framed);
    assert_eq!(outer.code(), CONFIG_RESERVED_NAME.code);
    assert_eq!(
        outer.detail(),
        "config.yaml: invalid YAML: pools: a pool may not be named `hooks` (reserved in `pools:`) \
         at line 1 column 1"
    );
    assert_eq!(outer.to_string().matches("See ").count(), 1);
    let plain = super::CLI_VALIDATE_CONFIG_INVALID.coded("config.yaml: not found.");
    assert_eq!(plain.code(), super::CLI_VALIDATE_CONFIG_INVALID.code);
    assert_eq!(plain.detail(), "config.yaml: not found");
}

/// A list detail keeps the code and the link on its head line; each item keeps its own.
#[test]
fn error_pages_a_list_message_links_its_head_line() {
    let item = busbar_contract::section::reserved_name("pool", "hooks", "pools").to_string();
    let m = super::BOOT_FATAL_ERROR.coded(format!("config errors:\n  - {item}"));
    let text = m.to_string();
    let (head, rest) = text.split_once('\n').expect("two lines");
    assert_eq!(
        head,
        super::BOOT_FATAL_ERROR.coded("config errors").to_string()
    );
    assert_eq!(rest, format!("  - {item}"));
}
