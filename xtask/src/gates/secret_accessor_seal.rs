//! `cargo xtask gate secret-accessor-seal` — DECISIONS #40: NO PLUGIN REACHES A RAW SECRET
//! ACCESSOR OR THE KERNEL SEAL. (Ported from `scripts/secret-accessor-seal-witness.sh`; not to be
//! confused with `seal-witness`, the capability-proof gate.)
//!
//! THE FORBIDDEN NAMES ([`FORBIDDEN`]) are the accessors the contract defines TODAY:
//!
//! ```text
//! KernelSeal::acquire_for_kernel() -> KernelSeal   (crates/busbar-contract/src/caps/token.rs)
//! Redacted::expose_secret(&self) -> &T             (crates/busbar-contract/src/redacted.rs)
//! ```
//!
//! The first is the only way to hold the kernel seal; the second is the only way to read the
//! plaintext of a resolved secret. THE DESIGN's trust boundary: a plane never sees secret bytes.
//! There is NO dependency wall around either: the manifest allow-list lets every plugin-kind crate
//! name `busbar-contract`, and a manifest reads dependency NAMES, not module paths. So nothing in
//! the type system or the manifests stops a plugin; THIS SCAN is the wall. The list named
//! `SecretValue::expose` and `KeyMaterial::bytes` for as long as those types were gone from the
//! tree, and the wall passed while plane code read credential bytes through `expose_secret`; so
//! every forbidden name must now be DEFINED in `busbar-contract` (`:seal-home`), and a rename reds
//! instead of emptying the list.
//!
//! THE PLUGIN BOUNDARY is derived, never listed: every crate whose `[lib]` declares
//! `crate-type = ["cdylib"]` (the artefact the loader dlopens; an `[[example]]` cdylib test double
//! does not make its crate a plugin), and every crate the kind census resolves to the `plane` kind
//! ([`crate::gates::kind_isolation::plane_kind_crates`]). The `legacy` kind (`busbar-llm`,
//! `busbar-a2a`, `busbar-voice`) shares the plane family and is not in this population: it reads
//! `expose_secret` at production sites today, those crates are being deleted (row 155), and
//! `plane-secret-blindness` holds every one of those sites on its counted drain-only ledger.
//! Kernel-side crates legitimately hold caps and mint tokens and are out of the population by
//! construction.
//!
//! FORBIDDEN in a plugin crate's source, after `//` and `/* */` comments and `"..."` string bodies
//! are stripped: any [`FORBIDDEN`] name as a whole word (a call, a path, a method reference).
//!
//! Four rows:
//!
//! * `secret-accessor-seal:plugin-crates` — at least one plugin crate is found.
//! * `secret-accessor-seal:scanned` — every plugin crate contributes at least one `.rs` file under
//!   `src/` (item 526: a crate listed as scanned whose source was never read is a partial scan).
//! * `secret-accessor-seal:no-reach` — no scanned file holds a forbidden reach (and something was
//!   scanned, so an empty scan is not green).
//! * `secret-accessor-seal:seal-home` — (item 467) `busbar-contract` is a declared crate and every
//!   [`FORBIDDEN`] name is defined (`fn <name>(`) in it and nowhere else: the wall this gate
//!   documents stands where it says, and names accessors that exist.

use std::collections::BTreeMap;

use crate::ctx::{Ctx, Overlay, WalkError, WalkSpec};
use crate::gates::{prove_green, prove_red, Gate, Report};
use crate::ledger::{Row, Verdict};

pub const ROW_CRATES: &str = "secret-accessor-seal:plugin-crates";
pub const ROW_SCANNED: &str = "secret-accessor-seal:scanned";
pub const ROW_REACH: &str = "secret-accessor-seal:no-reach";
pub const ROW_HOME: &str = "secret-accessor-seal:seal-home";

/// The crate the seal and the secret accessor live in.
const SEAL_HOME_CRATE: &str = "busbar-contract";

/// The raw secret accessors and the kernel seal, as whole words. Each must be defined in
/// [`SEAL_HOME_CRATE`] (`:seal-home`).
pub const FORBIDDEN: &[&str] = &["acquire_for_kernel", "expose_secret"];

/// Strip `//` and `/* */` comments and `"..."` string bodies from one line. `inblk` carries an
/// open block comment across lines (reset per file by the caller); string state is per line.
fn strip(line: &str, inblk: &mut bool) -> String {
    let b: Vec<char> = line.chars().collect();
    let n = b.len();
    let mut res = String::new();
    let mut i = 0;
    let mut instr = false;
    while i < n {
        let c = b[i];
        let c2 = (i + 1 < n).then(|| (c, b[i + 1]));
        if *inblk {
            if c2 == Some(('*', '/')) {
                *inblk = false;
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        if instr {
            if c == '\\' {
                i += 2;
                continue;
            }
            if c == '"' {
                instr = false;
            }
            i += 1;
            continue;
        }
        if c2 == Some(('/', '*')) {
            *inblk = true;
            i += 2;
            continue;
        }
        if c2 == Some(('/', '/')) {
            break;
        }
        if c == '"' {
            instr = true;
            i += 1;
            continue;
        }
        res.push(c);
        i += 1;
    }
    res
}

/// Whether a stripped line holds a forbidden reach: any [`FORBIDDEN`] name as a whole word.
fn reaches(code: &str) -> bool {
    FORBIDDEN
        .iter()
        .any(|n| crate::gates::one_abi::has_word(code, n))
}

/// Every `(line, stripped code)` of one file that reaches for a sealed accessor.
fn scan_text(text: &str) -> Vec<(usize, String)> {
    let mut inblk = false;
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let code = strip(line, &mut inblk);
        if reaches(&code) {
            out.push((i + 1, code));
        }
    }
    out
}

/// Whether a manifest's `[lib]` section declares cdylib: a `crate-type` line naming `cdylib`
/// inside the section whose header, whitespace removed, is exactly `[lib]`.
fn lib_is_cdylib(manifest: &str) -> bool {
    let mut sec = String::new();
    for line in manifest.lines() {
        if line.trim_start().starts_with('[') {
            sec = line.chars().filter(|c| !c.is_whitespace()).collect();
        }
        if sec == "[lib]" && line.contains("crate-type") && line.contains("cdylib") {
            return true;
        }
    }
    false
}

/// `crates/<name>` for every `crates/<name>/Cargo.toml`, with the manifest text.
fn manifests(cx: &Ctx) -> Result<BTreeMap<String, String>, String> {
    let spec = WalkSpec::new(["crates"]).ext("toml").allow_empty();
    let files = cx.list(&spec).map_err(|e| format!("{e:?}"))?;
    let mut out = BTreeMap::new();
    for rel in files {
        let s = rel.to_string_lossy().replace('\\', "/");
        let parts: Vec<&str> = s.split('/').collect();
        if parts.len() == 3 && parts[2] == "Cargo.toml" {
            let text = cx.read(&rel).map_err(|e| format!("{s}: {e}"))?;
            out.insert(format!("crates/{}", parts[1]), text);
        }
    }
    Ok(out)
}

/// The `.rs` files under `<crate>/src`; a crate with no `src/` has none.
fn rs_files(cx: &Ctx, krate: &str) -> Result<Vec<String>, String> {
    let spec = WalkSpec::new([format!("{krate}/src")])
        .ext("rs")
        .allow_empty();
    match cx.list(&spec) {
        Ok(v) => Ok(v
            .into_iter()
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .collect()),
        Err(WalkError::MissingRoot { .. }) => Ok(Vec::new()),
        Err(e) => Err(format!("{krate}/src: {e:?}")),
    }
}

/// The plugin crate directories: every crate whose `[lib]` is a cdylib, and every crate the kind
/// census resolves to the `plane` kind. A census that cannot be read, or reads no plane crate, is
/// an error: an empty plane population is the passing answer to the ban.
fn plugin_crates(cx: &Ctx) -> Result<Vec<String>, String> {
    let mut out: std::collections::BTreeSet<String> = manifests(cx)?
        .into_iter()
        .filter(|(_, text)| lib_is_cdylib(text))
        .map(|(dir, _)| dir)
        .collect();
    for p in crate::gates::kind_isolation::plane_kind_crates(cx)? {
        out.insert(
            p.manifest
                .strip_suffix("/Cargo.toml")
                .unwrap_or(&p.manifest)
                .to_string(),
        );
    }
    Ok(out.into_iter().collect())
}

/// Item 467: the problems with the claim "the seal lives in `busbar-contract`".
fn seal_home_problems(cx: &Ctx) -> Result<Vec<String>, String> {
    let mans = manifests(cx)?;
    let declares = |text: &str| {
        text.lines()
            .any(|l| l.starts_with(&format!("name = \"{SEAL_HOME_CRATE}\"")))
    };
    let mut bad = Vec::new();
    if !mans.values().any(|t| declares(t)) {
        bad.push(format!(
            "the gate names crate {SEAL_HOME_CRATE}, which no crates/*/Cargo.toml declares"
        ));
    }
    let spec = WalkSpec::new(["crates"]).ext("rs").allow_empty();
    let mut homes: BTreeMap<&str, Vec<String>> =
        FORBIDDEN.iter().map(|n| (*n, Vec::new())).collect();
    for rel in cx.list(&spec).map_err(|e| format!("{e:?}"))? {
        let s = rel.to_string_lossy().replace('\\', "/");
        let parts: Vec<&str> = s.split('/').collect();
        if parts.len() < 4 || parts[2] != "src" {
            continue;
        }
        if let Ok(text) = cx.read(&rel) {
            for (name, at) in homes.iter_mut() {
                if text.contains(&format!("fn {name}(")) {
                    at.push(s.clone());
                }
            }
        }
    }
    for (name, at) in &homes {
        if at.is_empty() {
            bad.push(format!(
                "fn {name}( is defined nowhere under crates/*/src -- the accessor moved or was renamed, and the forbidden list names nothing"
            ));
        }
        for h in at {
            let dir = h.split("/src/").next().unwrap_or("").to_string();
            if !mans.get(&dir).is_some_and(|t| declares(t)) {
                bad.push(format!(
                    "fn {name}( is defined in {h}, not in crate {SEAL_HOME_CRATE}"
                ));
            }
        }
    }
    Ok(bad)
}

pub struct SecretAccessorSealGate;

impl Gate for SecretAccessorSealGate {
    fn name(&self) -> &'static str {
        "secret-accessor-seal"
    }

    fn owed(&self) -> Vec<String> {
        [ROW_CRATES, ROW_SCANNED, ROW_REACH, ROW_HOME]
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let title_err = "the plugin crates could not be listed or read";
        let crates = match plugin_crates(cx) {
            Ok(c) => c,
            Err(why) => {
                return Verdict::of(
                    self.owed()
                        .iter()
                        .map(|r| Row::fail(r.as_str(), title_err, why.clone()))
                        .collect(),
                )
            }
        };

        let crates_row = if crates.is_empty() {
            Row::fail(
                ROW_CRATES,
                "no plugin crate found to scan",
                "found no crate whose [lib] declares cdylib and no plane-kind crate under crates/ (is the tree intact?)",
            )
        } else {
            Row::pass(
                ROW_CRATES,
                "plugin crates (cdylib [lib] or plane kind) were found",
                format!("{} crate(s)", crates.len()),
            )
        };

        let mut counts: Vec<String> = Vec::new();
        let mut empty: Vec<&str> = Vec::new();
        let mut files: Vec<String> = Vec::new();
        let mut io_err: Vec<String> = Vec::new();
        for c in &crates {
            match rs_files(cx, c) {
                Ok(fs) => {
                    counts.push(format!("{c} {} file(s)", fs.len()));
                    if fs.is_empty() {
                        empty.push(c);
                    }
                    files.extend(fs);
                }
                Err(e) => io_err.push(e),
            }
        }
        let scanned_row = if !io_err.is_empty() {
            Row::fail(
                ROW_SCANNED,
                "plugin source could not be listed",
                io_err.join(" | "),
            )
        } else if !empty.is_empty() {
            Row::fail(
                ROW_SCANNED,
                "a plugin crate has ZERO .rs files under src/ (unscanned, not clean)",
                format!("{} — [{}]", empty.join(", "), counts.join("; ")),
            )
        } else {
            Row::pass(
                ROW_SCANNED,
                "every plugin crate contributes scanned source",
                format!(
                    "{} file(s) across {} crate(s): {}",
                    files.len(),
                    crates.len(),
                    counts.join("; ")
                ),
            )
        };

        let mut hits: Vec<String> = Vec::new();
        let mut read_err: Vec<String> = Vec::new();
        for f in &files {
            match cx.read(f) {
                Ok(text) => {
                    for (line, code) in scan_text(&text) {
                        hits.push(format!("{f}:{line}\t{code}"));
                    }
                }
                Err(e) => read_err.push(format!("{f}: {e}")),
            }
        }
        let reach_row = if !read_err.is_empty() {
            Row::fail(
                ROW_REACH,
                "plugin source could not be read",
                read_err.join(" | "),
            )
        } else if files.is_empty() {
            Row::fail(
                ROW_REACH,
                "nothing was scanned, so nothing is proven",
                "zero .rs files in zero plugin crates is an empty scan, not a clean one",
            )
        } else if hits.is_empty() {
            Row::pass(
                ROW_REACH,
                "no plugin crate references acquire_for_kernel / expose_secret",
                format!("{} file(s) in {} crate(s)", files.len(), crates.len()),
            )
        } else {
            Row::fail(
                ROW_REACH,
                "a plugin crate reaches a raw secret accessor or the kernel seal (a #40 finding)",
                format!("{} reach(es): {}", hits.len(), hits.join(" | ")),
            )
        };

        let home_row = match seal_home_problems(cx) {
            Err(why) => Row::fail(ROW_HOME, "the seal's home could not be derived", why),
            Ok(p) if p.is_empty() => Row::pass(
                ROW_HOME,
                "the seal and the secret accessor are defined in busbar-contract",
                format!(
                    "fn <name>( for each of {} lives only in a crate named busbar-contract",
                    FORBIDDEN.join(", ")
                ),
            ),
            Ok(p) => Row::fail(
                ROW_HOME,
                "the seal is not where the gate says",
                p.join(" | "),
            ),
        };

        Verdict::of(vec![crates_row, scanned_row, reach_row, home_row])
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();
        let manifest =
            "[package]\nname = \"zz-plant\"\n\n[lib]\ncrate-type = [\"cdylib\", \"rlib\"]\n";
        let plant = |files: &[(&str, &str)]| {
            let mut ov = Overlay::new();
            ov.set("crates/zz-plant/Cargo.toml", manifest);
            for (p, t) in files {
                ov.set(format!("crates/zz-plant/src/{p}"), *t);
            }
            ov
        };
        let at = |ov: Overlay| cx.with_overlay(ov);

        report.push(prove_green(
            cx,
            self,
            "the tree's plugin crates reach no sealed accessor, scan real files, and the seal and accessor are in busbar-contract",
            &[ROW_CRATES, ROW_SCANNED, ROW_REACH, ROW_HOME],
        ));

        // RED: a plugin that tries every forbidden reach. (These plants named `SecretValue::expose`
        // and `KeyMaterial::bytes` while neither type existed in the tree; they name the live
        // accessors now.)
        let bad = "fn sneak(v: &Redacted<String>) {\n    let _ = KernelSeal::acquire_for_kernel();\n    let _ = v.expose_secret();\n    let _ = Redacted::expose_secret(v);\n    let _ = Some(v).map(Redacted::expose_secret);\n}\n";
        report.push(prove_red(
            cx,
            self,
            "a plugin using acquire_for_kernel, .expose_secret(, Redacted::expose_secret and a method reference to it is RED",
            &[ROW_REACH],
            plant(&[("lib.rs", bad)]),
            &[
                "crates/zz-plant/src/lib.rs:2",
                "crates/zz-plant/src/lib.rs:3",
                "crates/zz-plant/src/lib.rs:4",
                "crates/zz-plant/src/lib.rs:5",
            ],
        ));
        report.push(prove_red(
            cx,
            self,
            "the seal reached through an alias of KernelSeal is RED",
            &[ROW_REACH],
            plant(&[(
                "lib.rs",
                "use busbar_contract::caps::KernelSeal as K;\nfn f() { let _ = K::acquire_for_kernel(); }\n",
            )]),
            &["crates/zz-plant/src/lib.rs:2"],
        ));

        // RED: the accessor call split across lines.
        report.push(prove_red(
            cx,
            self,
            "an .expose_secret() on the line after its receiver is RED",
            &[ROW_REACH],
            plant(&[(
                "lib.rs",
                "fn sneak2(k: &Redacted<String>) -> usize {\n    k\n        .expose_secret()\n        .len()\n}\n",
            )]),
            &["crates/zz-plant/src/lib.rs:3"],
        ));

        // RED (audit xtask H2 HIGH 1): a PLANE-KIND crate that is not a cdylib library, reading a
        // resolved secret's bytes. The old population was cdylib [lib] crates only, and the old
        // needles named only the deleted accessors, so this plant was read by nothing.
        let plane_file = "crates/busbar-plane-llm/src/zz_planted_reach.rs";
        let mut ov = Overlay::new();
        ov.set(
            plane_file,
            "pub fn sneak(k: &busbar_contract::redacted::Redacted<String>) -> usize {\n    k.expose_secret().len()\n}\n",
        );
        report.push(prove_red(
            cx,
            self,
            "a plane-kind crate calling Redacted::expose_secret is RED, though its [lib] is no cdylib",
            &[ROW_REACH],
            ov,
            &["crates/busbar-plane-llm/src/zz_planted_reach.rs:2"],
        ));

        // GREEN: zero-argument calls, and the names only in a comment / string / block comment.
        report.push(prove_green(
            &at(plant(&[(
                "lib.rs",
                "fn open(cfg: &str) -> bool { cfg.trim().bytes().all(|b| b.is_ascii_hexdigit()) }\n",
            )])),
            self,
            "a zero-argument str::bytes() is not a sealed accessor",
            &[ROW_REACH],
        ));
        report.push(prove_green(
            &at(plant(&[(
                "lib.rs",
                "// A plugin may not call v.expose_secret() or KernelSeal::acquire_for_kernel.\nfn note() { let _doc = \"Redacted::expose_secret is sealed\"; }\n/* k.expose_secret()\n   still comment acquire_for_kernel() */\nfn ok() {}\n",
            )])),
            self,
            "the same names in a comment, a string literal and a block comment are not a reach",
            &[ROW_REACH],
        ));

        // RED (item 526): a crate with no src/, and one whose src/ holds no .rs file, are UNSCANNED.
        let mut ov = plant(&[("lib.rs", "fn ok() {}\n")]);
        ov.set(
            "crates/zz-nosrc/Cargo.toml",
            manifest.replace("zz-plant", "zz-nosrc"),
        );
        report.push(prove_red(
            cx,
            self,
            "a plugin crate with no src/ is an unscanned crate and RED, though another is clean",
            &[ROW_SCANNED],
            ov,
            &["crates/zz-nosrc"],
        ));
        let mut ov = plant(&[("lib.rs", "fn ok() {}\n")]);
        ov.set(
            "crates/zz-emptysrc/Cargo.toml",
            manifest.replace("zz-plant", "zz-emptysrc"),
        );
        ov.set("crates/zz-emptysrc/src/notes.txt", "no rust here\n");
        report.push(prove_red(
            cx,
            self,
            "a plugin crate whose src/ holds no .rs file is RED",
            &[ROW_SCANNED],
            ov,
            &["crates/zz-emptysrc"],
        ));

        // RED: a zero-crate scan (every real plugin manifest removed, cdylib and plane kind) is
        // FAIL, never a clean pass: the plane census refuses an empty plane population.
        if let Ok(real) = plugin_crates(cx) {
            let mut ov = Overlay::new();
            for c in &real {
                ov.remove(format!("{c}/Cargo.toml"));
            }
            report.push(prove_red(
                cx,
                self,
                "a tree with no plugin crate is RED, not vacuously clean",
                &[ROW_CRATES, ROW_REACH],
                ov,
                &["the plane-crate population is empty"],
            ));
        }

        // RED/GREEN: only a cdylib LIBRARY makes a plugin.
        let example_only =
            "[package]\nname = \"zz-ex\"\n\n[[example]]\nname = \"t\"\ncrate-type = [\"cdylib\"]\n";
        let mut ov = Overlay::new();
        ov.set("crates/zz-ex/Cargo.toml", example_only);
        ov.set("crates/zz-ex/src/lib.rs", bad);
        report.push(prove_green(
            &at(ov),
            self,
            "a crate whose only cdylib is an [[example]] is not a plugin, so its seal use is not scanned",
            &[ROW_CRATES, ROW_SCANNED, ROW_REACH],
        ));

        // Item 467: the seal lives where the gate says.
        let token = "crates/busbar-contract/src/caps/token.rs";
        if let Ok(text) = cx.read(token) {
            let mut ov = Overlay::new();
            ov.set(
                token,
                text.replace("fn acquire_for_kernel(", "fn acquire_for_kernelx("),
            );
            report.push(prove_red(
                cx,
                self,
                "a seal defined nowhere under crates/*/src is RED",
                &[ROW_HOME],
                ov,
                &["defined nowhere"],
            ));
        }
        // RED: the forbidden-name census. Rename the secret accessor at its home and the list would
        // name an API the tree no longer has; the old row checked only the seal, so a rename of the
        // accessor emptied the list with the gate green.
        let redacted = "crates/busbar-contract/src/redacted.rs";
        if let Ok(text) = cx.read(redacted) {
            let mut ov = Overlay::new();
            ov.set(
                redacted,
                text.replace("fn expose_secret(", "fn expose_secret_renamed("),
            );
            report.push(prove_red(
                cx,
                self,
                "a forbidden accessor defined nowhere under crates/*/src is RED, naming it",
                &[ROW_HOME],
                ov,
                &["fn expose_secret( is defined nowhere"],
            ));
        }
        let mut ov = Overlay::new();
        ov.set("crates/a-fake/Cargo.toml", "[package]\nname = \"a-fake\"\n");
        ov.set(
            "crates/a-fake/src/lib.rs",
            "pub fn acquire_for_kernel() {}\n",
        );
        report.push(prove_red(
            cx,
            self,
            "a seal defined in a crate other than busbar-contract is RED",
            &[ROW_HOME],
            ov,
            &["crates/a-fake/src/lib.rs"],
        ));

        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_drops_comments_and_strings() {
        let mut b = false;
        assert_eq!(strip("let a = 1; // x.expose(s)", &mut b), "let a = 1; ");
        assert_eq!(strip("let a = \"q\\\"x.bytes(s)\";", &mut b), "let a = ;");
        assert!(!b);
        assert_eq!(strip("a /* b", &mut b), "a ");
        assert!(b);
        assert_eq!(strip("still */ c", &mut b), " c");
        assert!(!b);
    }

    #[test]
    fn word_rule() {
        assert!(reaches("k.expose_secret()"));
        assert!(reaches("Redacted::expose_secret(k)"));
        assert!(reaches(".map(Redacted::expose_secret)"));
        assert!(reaches("K::acquire_for_kernel()"));
        assert!(!reaches("k.expose_secret_len()"));
        assert!(!reaches("s.bytes()"));
        assert!(!reaches("km.bytes(seal)"));
    }

    #[test]
    fn lib_section_only() {
        assert!(lib_is_cdylib("[lib]\ncrate-type = [\"cdylib\"]\n"));
        assert!(lib_is_cdylib(
            "[ lib ]\ncrate-type = [\"rlib\", \"cdylib\"]\n"
        ));
        assert!(!lib_is_cdylib("[[example]]\ncrate-type = [\"cdylib\"]\n"));
        assert!(!lib_is_cdylib(
            "[lib]\nname = \"x\"\n[dependencies]\ncrate-type = \"cdylib\"\n"
        ));
    }
}
