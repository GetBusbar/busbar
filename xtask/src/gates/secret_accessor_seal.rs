//! `cargo xtask gate secret-accessor-seal` — DECISIONS #40: NO CDYLIB PLUGIN REACHES A RAW SECRET
//! ACCESSOR OR THE KERNEL SEAL. (Ported from `scripts/secret-accessor-seal-witness.sh`; not to be
//! confused with `seal-witness`, the capability-proof gate.)
//!
//! The two raw secret-byte accessors on the plugin-facing contract ABI are sealed behind the
//! `busbar_contract::plugin::KernelSeal` authority token:
//!
//! ```text
//! SecretValue::expose(&self, seal: &dyn KernelSeal) -> &[u8]     (Secret::resolve() output)
//! KeyMaterial::bytes(&self, seal: &dyn KernelSeal) -> &[u8]      (AuthScheme::refresh() output)
//! ```
//!
//! The only way to hold a seal is `KernelSeal::acquire_for_kernel()`, defined in `busbar-contract`
//! (`crates/busbar-contract/src/caps/token.rs`). There is NO dependency wall around it: the
//! manifest allow-list lets every plugin-kind crate name `busbar-contract`, and a manifest reads
//! dependency NAMES, not module paths. So nothing in the type system or the manifests stops a
//! plugin; THIS SCAN is the wall.
//!
//! THE PLUGIN BOUNDARY. A plugin is a crate whose `[lib]` declares `crate-type = ["cdylib"]` — the
//! artefact the loader dlopens. Only the `[lib]` section counts: a crate that builds a cdylib test
//! double as an `[[example]]` is not itself a plugin. Kernel-side crates legitimately hold caps
//! and mint tokens and are out of scope by construction.
//!
//! FORBIDDEN in a cdylib plugin crate's source, after `//` and `/* */` comments and `"..."` string
//! bodies are stripped: `KernelSeal::acquire_for_kernel`, `SecretValue::expose`,
//! `KeyMaterial::bytes`, and the method calls `.expose(` / `.bytes(` WITH an argument (a
//! zero-argument call is `str::bytes()`, a different method; an argument on the next line counts).
//!
//! Four rows:
//!
//! * `secret-accessor-seal:plugin-crates` — at least one cdylib plugin crate is found.
//! * `secret-accessor-seal:scanned` — every plugin crate contributes at least one `.rs` file under
//!   `src/` (item 526: a crate listed as scanned whose source was never read is a partial scan).
//! * `secret-accessor-seal:no-reach` — no scanned file holds a forbidden reach (and something was
//!   scanned, so an empty scan is not green).
//! * `secret-accessor-seal:seal-home` — (item 467) `busbar-contract` is a declared crate and
//!   `fn acquire_for_kernel(` is defined in it: the wall this gate documents stands where it says.

use std::collections::BTreeMap;

use crate::ctx::{Ctx, Overlay, WalkError, WalkSpec};
use crate::gates::{prove_green, prove_red, Gate, Report};
use crate::ledger::{Row, Verdict};

pub const ROW_CRATES: &str = "secret-accessor-seal:plugin-crates";
pub const ROW_SCANNED: &str = "secret-accessor-seal:scanned";
pub const ROW_REACH: &str = "secret-accessor-seal:no-reach";
pub const ROW_HOME: &str = "secret-accessor-seal:seal-home";

/// The crate the seal lives in.
const SEAL_HOME_CRATE: &str = "busbar-contract";

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

/// `.expose(` / `.bytes(` followed by anything but `)`, or by the end of the line.
fn call_with_argument(code: &str, method: &str) -> bool {
    let needle = format!(".{method}(");
    code.match_indices(&needle)
        .any(|(at, _)| !code[at + needle.len()..].starts_with(')'))
}

/// Whether a stripped line holds a forbidden reach.
fn reaches(code: &str) -> bool {
    code.contains("KernelSeal::acquire_for_kernel")
        || code.contains("SecretValue::expose")
        || code.contains("KeyMaterial::bytes")
        || call_with_argument(code, "expose")
        || call_with_argument(code, "bytes")
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

/// The plugin crate directories: every crate whose `[lib]` is a cdylib.
fn plugin_crates(cx: &Ctx) -> Result<Vec<String>, String> {
    Ok(manifests(cx)?
        .into_iter()
        .filter(|(_, text)| lib_is_cdylib(text))
        .map(|(dir, _)| dir)
        .collect())
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
    let mut home: Option<String> = None;
    for rel in cx.list(&spec).map_err(|e| format!("{e:?}"))? {
        let s = rel.to_string_lossy().replace('\\', "/");
        let parts: Vec<&str> = s.split('/').collect();
        if parts.len() < 4 || parts[2] != "src" {
            continue;
        }
        if let Ok(text) = cx.read(&rel) {
            if text.contains("fn acquire_for_kernel(") {
                home = Some(s);
                break;
            }
        }
    }
    match home {
        None => bad.push(
            "fn acquire_for_kernel( is defined nowhere under crates/*/src -- the seal moved"
                .to_string(),
        ),
        Some(h) => {
            let dir = h.split("/src/").next().unwrap_or("").to_string();
            if !mans.get(&dir).is_some_and(|t| declares(t)) {
                bad.push(format!(
                    "the seal is defined in {h}, not in crate {SEAL_HOME_CRATE}"
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
                "no cdylib plugin crate found to scan",
                "found no crate whose [lib] declares cdylib under crates/ (is the tree intact?)",
            )
        } else {
            Row::pass(
                ROW_CRATES,
                "cdylib plugin crates were found",
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
                "no cdylib plugin references acquire_for_kernel / SecretValue::expose / .expose( / KeyMaterial::bytes / .bytes(",
                format!("{} file(s) in {} crate(s)", files.len(), crates.len()),
            )
        } else {
            Row::fail(
                ROW_REACH,
                "a cdylib plugin reaches a raw secret accessor or the kernel seal (a #40 finding)",
                format!("{} reach(es): {}", hits.len(), hits.join(" | ")),
            )
        };

        let home_row = match seal_home_problems(cx) {
            Err(why) => Row::fail(ROW_HOME, "the seal's home could not be derived", why),
            Ok(p) if p.is_empty() => Row::pass(
                ROW_HOME,
                "the seal is defined in busbar-contract",
                "fn acquire_for_kernel( lives in a crate named busbar-contract",
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
            "the tree's cdylib plugins reach no sealed accessor, scan real files, and the seal is in busbar-contract",
            &[ROW_CRATES, ROW_SCANNED, ROW_REACH, ROW_HOME],
        ));

        // RED: a plugin that tries every forbidden reach.
        let bad = "fn sneak(v: &SecretValue, seal: &Seal) {\n    let _ = KernelSeal::acquire_for_kernel();\n    let _ = v.expose(seal);\n    let _ = SecretValue::expose(v, seal);\n    let _ = km.bytes(seal);\n}\n";
        report.push(prove_red(
            cx,
            self,
            "a plugin using acquire_for_kernel, .expose(, SecretValue::expose and .bytes( is RED",
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
            "KeyMaterial::bytes by path is RED",
            &[ROW_REACH],
            plant(&[("lib.rs", "fn f() { let _ = KeyMaterial::bytes(k, s); }\n")]),
            &["crates/zz-plant/src/lib.rs:1"],
        ));

        // RED: a sealed accessor call whose seal argument is on the next line.
        report.push(prove_red(
            cx,
            self,
            "a .bytes( with its seal argument on the next line is RED",
            &[ROW_REACH],
            plant(&[(
                "lib.rs",
                "fn sneak2(km: &KeyMaterial, seal: &Seal) {\n    let _ = km.bytes(\n        seal,\n    );\n}\n",
            )]),
            &["crates/zz-plant/src/lib.rs:2"],
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
                "// A plugin may not call v.expose(seal) or KernelSeal::acquire_for_kernel.\nfn note() { let _doc = \"KeyMaterial::bytes is sealed\"; }\n/* km.bytes(seal)\n   still comment v.expose(s) */\nfn ok() {}\n",
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

        // RED: a zero-crate scan (every real plugin manifest removed) is FAIL, never a clean pass.
        if let Ok(real) = plugin_crates(cx) {
            let mut ov = Overlay::new();
            for c in &real {
                ov.remove(format!("{c}/Cargo.toml"));
            }
            report.push(prove_red(
                cx,
                self,
                "a tree with no cdylib plugin crate is RED, not vacuously clean",
                &[ROW_CRATES, ROW_REACH],
                ov,
                &["no cdylib plugin crate", "nothing was scanned"],
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
    fn argument_rule() {
        assert!(reaches("km.bytes(seal)"));
        assert!(reaches("km.bytes("));
        assert!(!reaches("s.bytes()"));
        assert!(reaches("s.bytes().x(); km.bytes(seal)"));
        assert!(reaches("v.expose( )"));
        assert!(reaches("SecretValue::expose"));
        assert!(!reaches("bytes(seal)"));
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
