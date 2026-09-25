//! LAW 1 OVER THE WHOLE NEUTRAL CENSUS — a vendor name in a neutral crate is RED (item 203).
//!
//! > A neutral/core crate must name no vendor instance; a plane may name its own.
//! > — `docs/design/BUSBAR-1.6.0.md`, "the purity gate's dialect vocabulary axis STAYS"
//!
//! A red team once put `pub const VD: &str = "anthropic";` and `pub fn openai_shim() {}` into
//! `busbar-store-memory` with every gate green. It was STILL green after the matrix's `dialect`
//! column was struck (DECISIONS #4: a dialect is a thing inside a plane, not a kind): the
//! vendor-name confinement was said to be `plane-purity`'s, and `plane-purity` scans a LISTED set
//! of neutral source roots ([`crate::planes::neutral_src_roots`]) — the kernel, the contract, the
//! ABI, the cleanliness crates. `crates/store-memory` is on no list. Neither is any other store,
//! secret, auth, hooks or export plugin, nor the composition root. The rule had one owner and a
//! population that stopped where the list did.
//!
//! ## NOT A SECOND COPY OF THE RULE, AND NOT A COLUMN
//!
//! This module writes down no vendor name and no scanning policy. It hands `plane-purity`'s own
//! derived vocabulary ([`crate::gates::plane_purity::vocab::derive`] — the dialects the plane
//! crates declare, read off the tree) and `plane-purity`'s own scanner
//! ([`crate::gates::plane_purity::scanner::scan`]) the population that gate does not read: every
//! `Family::Neutral` crate of the census whose `src` is not one of its listed roots. A crate on the
//! list is `plane-purity`'s to report and is not reported twice here. A `Family::Plane` crate is
//! never scanned: a plane naming its own dialects is Law 5, not a leak.
//!
//! There is no `dialect` kind, no `[[cell]]` row and no ledger table (`dialect` is a forbidden
//! ledger kind, see `truths::FORBIDDEN_KINDS`). The ceiling is ZERO and nothing raises it — the
//! spec's "neutral-only tripwire, armed at 0 for every `Family::Neutral` crate".
//!
//! ## WHAT A HIT IS
//!
//! Exactly what `plane-purity:dialect` counts: a declared dialect name as a whole token in the
//! comment-stripped line, production and test scope alike (a neutral crate's test fixture naming a
//! vendor is that crate naming a vendor — the matrix does not exclude tests). One finding per hit
//! LINE, so a new hit is a new finding whatever the crate already carries.
//!
//! ## THE ONE CARVE-OUT THE SCANNER HONOURS, REFUSED HERE
//!
//! `plane-purity`'s scanner exempts a line carrying `// plane-purity: frozen-wire <reason>` from the
//! vocabulary rules, and `plane-purity:frozen-wire-claim` checks each such claim — over ITS roots.
//! In this population no row checks one, so a pragma here would be an unreviewed off switch: every
//! one is a finding of its own.

use std::path::PathBuf;

use crate::ctx::{Ctx, SourceFile};
use crate::gates::plane_purity::{scanner, vocab};

use super::super::{CrateInfo, Family};

/// Every vendor-name finding over the neutral population `plane-purity` does not list, sorted. An
/// `Err` is a measurement that could not run — never an empty list.
pub fn offenders(
    cx: &Ctx,
    crates: &[CrateInfo],
    files: &[(String, String)],
) -> Result<Vec<String>, String> {
    let listed = crate::planes::neutral_src_roots();
    let population: Vec<&CrateInfo> = crates
        .iter()
        .filter(|c| c.family == Family::Neutral)
        .filter(|c| c.dir.starts_with("crates/"))
        .filter(|c| !listed.contains(&format!("{}/src", c.dir)))
        .collect();

    let words = dialect_vocab(cx)?;

    let mut scanned: Vec<(String, SourceFile)> = Vec::new();
    for (rel, text) in files {
        if !rel.ends_with(".rs") {
            continue;
        }
        let Some(dir) = super::owning_dir(rel) else {
            continue;
        };
        let Some(c) = population.iter().find(|c| c.dir == dir) else {
            continue;
        };
        scanned.push((
            c.name.clone(),
            SourceFile {
                rel: PathBuf::from(rel),
                abs: cx.abs(rel),
                text: text.clone(),
            },
        ));
    }

    // THE VOCABULARY'S FINGERPRINT, once per run: the per-file reading below is keyed on it.
    let words_key = {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        format!("{words:?}").hash(&mut h);
        h.finish()
    };
    let mut out: Vec<String> = Vec::new();
    for (krate, f) in &scanned {
        let read = read_file(f, &words, words_key);
        for (scope, site, code) in &read.dialect {
            out.push(format!(
                "vendor-name\t{krate}\t{site}\t{scope}\t{code}\ta NEUTRAL crate names a dialect a plane \
                 declares (Law 1). Ceiling 0, armed, and no ledger row raises it: the vendor \
                 name belongs in the plane that owns the dialect."
            ));
        }
        for line in &read.frozen {
            out.push(format!(
                "vendor-frozen-wire\t{krate}\t{}:{line}\ta frozen-wire pragma switches the vendor \
                 scan off for its line, and outside plane-purity's listed roots no row checks \
                 its claim. Remove it, or move the crate onto plane-purity's list.",
                f.rel_str(),
            ));
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

// How many files THIS THREAD has actually put to the scanner through [`read_file`] — the exit
// test's probe for "an unchanged file is read once".
#[cfg(test)]
thread_local! {
    static FILES_READ: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// What one file says to this rule: every `DIALECT` hit as `(scope, site, code)`, and the line of
/// every frozen-wire pragma.
struct FileRead {
    dialect: Vec<(&'static str, String, String)>,
    frozen: Vec<usize>,
}

/// ONE FILE'S READING, MEMOISED on its path, its bytes and the vocabulary it was read against — the
/// whole of what the answer depends on. The rule re-ran the plane-purity scanner over every neutral
/// source file on every gate run, and a self-test case IS a gate run over a tree one plant away
/// from the last: 139 s of the `kind-isolation` battery re-read files no case had touched. Which
/// crate a file belongs to is NOT in the reading; the caller attributes it fresh on every run.
fn read_file(f: &SourceFile, words: &vocab::Vocab, words_key: u64) -> std::sync::Arc<FileRead> {
    use std::hash::{Hash, Hasher};
    static MEMO: std::sync::OnceLock<
        std::sync::Mutex<std::collections::BTreeMap<u64, std::sync::Arc<FileRead>>>,
    > = std::sync::OnceLock::new();
    let key = {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        f.rel_str().hash(&mut h);
        f.text.hash(&mut h);
        words_key.hash(&mut h);
        h.finish()
    };
    let memo = MEMO.get_or_init(Default::default);
    if let Some(found) = memo.lock().unwrap_or_else(|e| e.into_inner()).get(&key) {
        return std::sync::Arc::clone(found);
    }
    #[cfg(test)]
    FILES_READ.with(|n| n.set(n.get() + 1));
    let (prod, test) = scanner::scan(std::slice::from_ref(f), scanner::Mode::Forward, words);
    let mut dialect = Vec::new();
    for (scope, hits) in [("production", prod), ("test", test)] {
        for h in hits.iter().filter(|h| h.category == "DIALECT") {
            dialect.push((scope, h.site(), h.code.clone()));
        }
    }
    let frozen = f
        .text
        .lines()
        .enumerate()
        .filter(|(_, line)| scanner::has_frozen_wire_pragma(line))
        .map(|(idx, _)| idx + 1)
        .collect();
    let read = std::sync::Arc::new(FileRead { dialect, frozen });
    memo.lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(key, std::sync::Arc::clone(&read));
    read
}

/// `plane-purity`'s vocabulary, derived from the plane crates the census resolves — the same call
/// that gate makes. A derivation that found no dialect at all is a refusal, never a clean tree.
fn dialect_vocab(cx: &Ctx) -> Result<vocab::Vocab, String> {
    let roots = super::super::plane_kind_src_roots(cx)?;
    let present: Vec<String> = roots.iter().filter(|r| cx.exists(r)).cloned().collect();
    let plane = cx
        .walk(&crate::ctx::WalkSpec::new(present).ext("rs").allow_empty())
        .map_err(|e| e.to_string())?;
    let v = vocab::derive(cx, &roots, &plane);
    if v.dialects.is_empty() {
        return Err(
            "the plane crates declare no dialect — a vendor scan with no vendor words finds \
             nothing, which is indistinguishable from a clean tree"
                .to_string(),
        );
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// THE VENDOR SCAN READS AN UNCHANGED FILE ONCE per vocabulary. It re-ran the plane-purity
    /// scanner over every neutral source file on every gate run — 139 s of the battery.
    #[test]
    fn the_vendor_scan_reads_an_unchanged_file_once() {
        let f = SourceFile {
            rel: PathBuf::from("crates/zz-vendor-probe/src/lib.rs"),
            abs: PathBuf::from("/nonexistent/crates/zz-vendor-probe/src/lib.rs"),
            text: "pub fn f() {}\n".to_string(),
        };
        let words = vocab::Vocab::default();
        let start = FILES_READ.with(|n| n.get());
        let a = read_file(&f, &words, 1);
        let b = read_file(&f, &words, 1);
        assert_eq!(FILES_READ.with(|n| n.get()) - start, 1);
        assert!(std::sync::Arc::ptr_eq(&a, &b));
        let _ = read_file(&f, &words, 2);
        assert_eq!(
            FILES_READ.with(|n| n.get()) - start,
            2,
            "another vocabulary is another reading, never a stale one"
        );
    }
}
