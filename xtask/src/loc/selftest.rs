//! FIXTURES FOR EVERY TRAP THAT ACTUALLY BIT, AND A RED PROOF FOR EACH.
//!
//! A counter whose tests cannot go red is not a counter. Every fixture below is paired with a
//! DELIBERATELY BROKEN rule — a rule one of the three instruments this replaces actually used — and
//! the case asserts twice: the real classifier gets the hand-verified answer, and the broken rule
//! does NOT. Without the second half a fixture proves only that some code ran.
//!
//! The broken rules are not inventions. Each is named after the defect it reproduces:
//!
//! * [`Flaw::CfgTestToEof`] — "from the first `#[cfg(test)]` to end of file is test". This is what
//!   produced the 2.90x growth ratio, by calling 3,897 of v1.5.5 `main.rs`'s 3,989 lines test on
//!   the strength of a one-line `mod test_support;` declaration at line 93.
//! * [`Flaw::TopLevelTestsOnly`] — "`src/tests/**` is proofs, anything deeper is surface". This is
//!   `scripts/loc-surface.py` exactly, and it billed 192,813 lines of nested test code as
//!   production.
//! * [`Flaw::FlatBlockComments`] — block comments do not nest.
//! * [`Flaw::LiteralBlind`] — braces and `#[cfg(test)]` inside string and char literals count.
//! * [`Flaw::TestSubstring`] — `\btest\b` anywhere in the cfg attribute means test, which drops
//!   `#[cfg(not(test))]` — the arm that SHIPS — and anything gated on a feature named
//!   `test-support`.
//! * [`Flaw::CommentsAreCode`] — no comment stripping at all.

use std::path::PathBuf;

use super::classify::{self, Counts};
use super::{config::Config, measure, Source};
use crate::ctx::Ctx;

/// A hand-verified fixture: the source, what each bucket must be, and the broken rule it must
/// discriminate against.
struct Case {
    name: &'static str,
    why: &'static str,
    src: &'static str,
    want: Counts,
    flaw: Flaw,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Flaw {
    CfgTestToEof,
    FlatBlockComments,
    LiteralBlind,
    TestSubstring,
    CommentsAreCode,
    TopLevelTestsOnly,
    PhantomTrailingLine,
}

impl Case {
    /// What the broken rule's answer is compared AGAINST.
    ///
    /// Every flaw but one corrupts the `code` figure, which is the number the invariant is about.
    /// [`Flaw::PhantomTrailingLine`] corrupts the LINE TOTAL instead — it invents a blank line on
    /// every file that ends in a newline — so that one case is compared on the total, or the RED
    /// half would be asserting that two identical `code` figures differ and would never pass.
    fn red_truth(&self) -> u64 {
        match self.flaw {
            Flaw::PhantomTrailingLine => self.want.total(),
            _ => self.want.code,
        }
    }
}

const fn counts(code: u64, doc: u64, comment: u64, blank: u64, test: u64) -> Counts {
    Counts {
        code,
        doc,
        comment,
        blank,
        test,
    }
}

const CASES: &[Case] = &[
    Case {
        name: "cfg-test-mod-decl-early",
        why: "a one-line `#[cfg(test)] mod x;` near the top does NOT swallow the rest of the file",
        src: "pub fn head() -> u32 { 1 }\n\
              \n\
              #[cfg(test)]\n\
              mod test_support;\n\
              \n\
              pub fn tail() -> u32 { 2 }\n",
        want: counts(2, 0, 0, 2, 2),
        flaw: Flaw::CfgTestToEof,
    },
    Case {
        name: "three-cfg-test-items",
        why: "three `#[cfg(test)]` items, one mid-file, each ending at its own item",
        src: "pub fn a() -> u32 { 1 }\n\
              #[cfg(test)]\n\
              fn t1() {}\n\
              pub fn b() -> u32 { 2 }\n\
              #[cfg(test)]\n\
              mod mid {\n\
              \x20   fn t2() {}\n\
              }\n\
              pub fn c() -> u32 { 3 }\n\
              #[cfg(test)]\n\
              mod tail {\n\
              \x20   fn t3() {}\n\
              }\n",
        want: counts(3, 0, 0, 0, 10),
        flaw: Flaw::CfgTestToEof,
    },
    Case {
        name: "cfg-test-item-inside-fn-body",
        why: "an attribute on an item NESTED in a function body is found, and ends with that item",
        src: "pub fn outer() -> u32 {\n\
              \x20   #[cfg(test)]\n\
              \x20   fn helper() {}\n\
              \x20   1\n\
              }\n\
              pub fn after() -> u32 { 2 }\n",
        want: counts(4, 0, 0, 0, 2),
        flaw: Flaw::CfgTestToEof,
    },
    Case {
        name: "cfg-all-test-feature",
        why: "`cfg(all(test, feature = \"x\"))` guards the same way a bare `cfg(test)` does",
        src: "#[cfg(all(test, feature = \"x\"))]\n\
              mod t {\n\
              \x20   fn a() {}\n\
              }\n\
              pub fn one() -> u32 { 1 }\n",
        want: counts(1, 0, 0, 0, 4),
        flaw: Flaw::CfgTestToEof,
    },
    Case {
        name: "cfg-not-test-ships",
        why: "`#[cfg(not(test))]` is the arm that SHIPS and is production code, not a test module",
        src: "#[cfg(not(test))]\n\
              pub fn only_in_prod() -> u32 { 1 }\n\
              pub fn always() -> u32 { 2 }\n",
        want: counts(3, 0, 0, 0, 0),
        flaw: Flaw::TestSubstring,
    },
    Case {
        name: "cfg-feature-named-test-support",
        why: "a FEATURE whose name contains `test` is a feature; the item ships when it is on",
        src: "#[cfg(feature = \"test-support\")]\n\
              pub fn helper() -> u32 { 1 }\n\
              pub fn always() -> u32 { 2 }\n",
        want: counts(3, 0, 0, 0, 0),
        flaw: Flaw::TestSubstring,
    },
    Case {
        name: "nested-block-comment",
        why:
            "`/* /* */ */` is legal Rust; a scanner that closes at the first `*/` resumes on prose",
        src: "/* outer /* inner */ still a comment */\n\
              pub fn one() -> u32 { 1 }\n",
        want: counts(1, 0, 1, 0, 0),
        flaw: Flaw::FlatBlockComments,
    },
    Case {
        name: "raw-string-with-cfg-test-and-open-brace",
        why: "a raw string holding `#[cfg(test)]` and an unbalanced `{` is a value, not a test mod",
        src: "pub const T: &str = r#\"\n\
              #[cfg(test)]\n\
              mod t { // not a comment\n\
              \"#;\n\
              pub fn after() -> u32 { 2 }\n",
        want: counts(5, 0, 0, 0, 0),
        flaw: Flaw::LiteralBlind,
    },
    Case {
        name: "char-literal-open-brace",
        why: "`'{'` is a char literal; counting it as a brace makes the test span eat what follows",
        src: "#[cfg(test)]\n\
              mod t {\n\
              \x20   const OPEN: char = '{';\n\
              }\n\
              pub fn after() -> u32 { 3 }\n",
        want: counts(1, 0, 0, 0, 4),
        flaw: Flaw::LiteralBlind,
    },
    Case {
        name: "doc-comment-and-comment",
        why: "`///`/`//!`/`/** */` are doc, `//`/`/* */` are comment, and neither is code",
        src: "//! module doc\n\
              /// item doc\n\
              pub fn one() -> u32 { 1 }\n\
              // a line comment\n\
              /* a block\n\
              \x20  comment */\n\
              \n\
              /** a block doc */\n\
              pub fn two() -> u32 { 2 }\n",
        want: counts(2, 3, 3, 1, 0),
        flaw: Flaw::CommentsAreCode,
    },
    Case {
        name: "trailing-newline-is-not-a-blank-line",
        why: "`\"a\\n\".split('\\n')` yields a phantom empty element; counting it is a free blank \
               line on every well-formed file",
        src: "pub fn a() -> u32 { 1 }\n",
        want: counts(1, 0, 0, 0, 0),
        flaw: Flaw::PhantomTrailingLine,
    },
    Case {
        name: "file-level-inner-cfg-test",
        why: "`#![cfg(test)]` makes the WHOLE file a proof; no inner item span can say that",
        src: "#![cfg(test)]\n\
              pub fn a() -> u32 { 1 }\n",
        want: counts(0, 0, 0, 0, 2),
        flaw: Flaw::CfgTestToEof,
    },
    Case {
        name: "comment-marker-inside-string-literal",
        why: "a `/*` inside a literal is VALUE; a scanner that opens a comment on it eats the file",
        src: "pub const A: &str =\n\
              \x20   \"/* } not a comment {\";\n\
              pub const B: char = '}';\n\
              pub fn one() -> u32 { 1 }\n",
        want: counts(4, 0, 0, 0, 0),
        flaw: Flaw::LiteralBlind,
    },
];

/// The path fixtures. `TopLevelTestsOnly` is the live bug, stated as a pair.
///
/// EVERY PATH HERE IS AN INPUT TO A STRING CLASSIFIER, NEVER A FILE. `loc` decides "is this a proof
/// or is it surface" from the SHAPE of a path — `src/tests/**`, `_tests.rs`, `benches/` — and the
/// answer must not depend on what happens to be in the tree today, or the classifier would be
/// untestable for any shape the tree does not currently contain. `crates/x` is deliberately not a
/// crate. So these are declared to `qa-names` rather than repointed at real files: repointing them
/// at live paths would silently couple this table to the roster and retire the shapes nobody has
/// written yet, which is the only reason the table exists.
// qa-names: crates/x/src/lib.rs -- xtask/src/loc/selftest.rs -- a classifier INPUT, never opened; loc decides proof-vs-surface from the path shape alone
// qa-names: crates/x/src/tests.rs -- xtask/src/loc/selftest.rs -- a classifier INPUT, never opened; the `mod tests;` file convention as a string
// qa-names: crates/x/src/tests/helper.rs -- xtask/src/loc/selftest.rs -- a classifier INPUT, never opened; the top-level tests tree as a string
// qa-names: crates/x/src/engine/tests/router_tests.rs -- xtask/src/loc/selftest.rs -- a classifier INPUT, never opened; the nested src/<module>/tests/** shape as a string
// qa-names: crates/x/src/engine/router_tests.rs -- xtask/src/loc/selftest.rs -- a classifier INPUT, never opened; the `_tests.rs`-beside-the-module shape as a string
// qa-names: crates/x/benches/throughput.rs -- xtask/src/loc/selftest.rs -- a classifier INPUT, never opened; benches are proofs, stated as a string
// qa-names: crates/x/tests/integration.rs -- xtask/src/loc/selftest.rs -- a classifier INPUT, never opened; the integration-test tree as a string
// qa-names: crates/x/src/attestation.rs -- xtask/src/loc/selftest.rs -- a classifier INPUT, never opened; the negative control, a name that SOUNDS like a test and is surface
const PATH_CASES: &[(&str, bool, &str)] = &[
    (
        "crates/x/src/lib.rs",
        false,
        "ordinary source is not a proof",
    ),
    (
        "crates/x/src/tests.rs",
        true,
        "the `mod tests;` file convention",
    ),
    (
        "crates/x/src/tests/helper.rs",
        true,
        "the top-level tests tree",
    ),
    (
        "crates/x/src/engine/tests/router_tests.rs",
        true,
        "NESTED src/<module>/tests/** — the 192,813 lines the old rule billed as production",
    ),
    (
        "crates/x/src/engine/router_tests.rs",
        true,
        "`_tests.rs` beside the module it proves, the convention this tree states",
    ),
    (
        "crates/x/benches/throughput.rs",
        true,
        "benches are proofs, not surface",
    ),
    (
        "crates/x/tests/integration.rs",
        true,
        "the integration-test tree",
    ),
    (
        "crates/x/src/attestation.rs",
        false,
        "a file whose NAME contains no test segment is surface even if it sounds like one",
    ),
];

pub fn run() -> i32 {
    println!("== cargo xtask loc SELF-TEST ==");
    let mut bad = 0usize;
    let mut say = |ok: bool, msg: String| {
        println!("{}  {msg}", if ok { "PASS" } else { "FAIL" });
        if !ok {
            bad += 1;
        }
    };

    for case in CASES {
        match classify::classify(case.src, false) {
            Err(e) => say(false, format!("{}: did not parse: {e}", case.name)),
            Ok(v) => {
                let ok = v.counts == case.want;
                say(
                    ok,
                    format!(
                        "{}: {} (wanted {}, measured {})",
                        case.name,
                        case.why,
                        show(&case.want),
                        show(&v.counts)
                    ),
                );
                // THE RED HALF. The broken rule must get this fixture WRONG, or the fixture is not
                // discriminating and its green above proves nothing.
                let broken = broken_code(case.src, case.flaw);
                say(
                    broken != case.red_truth(),
                    format!(
                        "{}: the {} rule is RED on it (broken rule says {broken}, truth is {})",
                        case.name,
                        case.flaw.label(),
                        case.red_truth()
                    ),
                );
            }
        }
    }

    for (path, want, why) in PATH_CASES {
        let got = classify::is_test_path(path);
        say(got == *want, format!("path `{path}`: {why} (test={got})"));
    }
    // The live bug, as its own row: the old rule and the new one must DISAGREE on nested tests.
    let nested = "crates/x/src/engine/tests/router_tests.rs";
    say(
        classify::is_test_path(nested) && !top_level_tests_only(nested),
        format!(
            "path `{nested}`: the {} rule is RED on it",
            Flaw::TopLevelTestsOnly.label()
        ),
    );

    // A file that is not Rust is an ERROR, never a count.
    say(
        classify::classify("pub fn (((\n", false).is_err(),
        "a file that does not parse is an ERROR, never silently counted as code".to_string(),
    );

    match tree_case() {
        Ok(msgs) => {
            for (ok, msg) in msgs {
                say(ok, msg);
            }
        }
        Err(e) => say(false, format!("fixture tree: {e}")),
    }

    println!();
    if bad > 0 {
        println!("loc selftest: RED ({bad} case(s) failed)");
        return 1;
    }
    println!("loc selftest: GREEN");
    0
}

fn show(c: &Counts) -> String {
    format!(
        "code={} doc={} comment={} blank={} test={}",
        c.code, c.doc, c.comment, c.blank, c.test
    )
}

/// The whole-tree half: discovery, per-crate aggregation, groups, and the refusal a crate that
/// measured nothing has to produce.
fn tree_case() -> Result<Vec<(bool, String)>, String> {
    let root = scratch_dir()?;
    let write = |rel: &str, body: &str| -> Result<(), String> {
        let path = root.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
        }
        std::fs::write(&path, body).map_err(|e| format!("{}: {e}", path.display()))
    };
    write("crates/alpha/src/lib.rs", "pub fn a() -> u32 { 1 }\n")?;
    write(
        "crates/alpha/src/engine/mod.rs",
        "pub fn b() -> u32 { 2 }\n",
    )?;
    // NESTED tests: the bug, as a tree rather than a path string.
    write(
        "crates/alpha/src/engine/tests/deep.rs",
        "fn t() {}\nfn u() {}\nfn v() {}\n",
    )?;
    write("crates/alpha/src/engine/mod_tests.rs", "fn w() {}\n")?;
    write("crates/beta/src/lib.rs", "pub fn c() -> u32 { 3 }\n")?;
    write(
        "qa/loc.toml",
        "[scan]\ncrate_roots = [\"crates\"]\n\n[groups.excluded]\nlabel = \"the set under test\"\n\
         crates = [\"beta\"]\n",
    )?;

    let cx = Ctx::at(&root, root.join(".scratch"))?;
    let cfg = Config::load(&root)?;
    let report = measure(&cx, &Source::Worktree, &cfg, &[])?;

    let mut out = Vec::new();
    let alpha = report.crate_counts("alpha").copied().unwrap_or_default();
    out.push((
        alpha.code == 2 && alpha.test == 4,
        format!(
            "fixture tree: alpha is 2 code + 4 test — the nested tests/ tree and the `_tests.rs` \
             file are proofs (measured {})",
            show(&alpha)
        ),
    ));
    out.push((
        report.total.code == 3,
        format!(
            "fixture tree: total code is 3 (measured {})",
            report.total.code
        ),
    ));
    let group = report.groups.iter().find(|g| g.name == "excluded").cloned();
    out.push(match group {
        Some(g) => (
            g.inside.code == 1 && g.outside.code == 2 && g.missing.is_empty(),
            format!(
                "fixture tree: the declared group is 1 code inside and 2 outside (measured {} / {})",
                g.inside.code, g.outside.code
            ),
        ),
        None => (false, "fixture tree: the declared group is missing".to_string()),
    });
    // A ceiling naming a crate with no code is refused, not reported as under every limit.
    out.push((
        measure(&cx, &Source::Worktree, &cfg, &["gamma".to_string()]).is_err(),
        "fixture tree: a crate that measured nothing is REFUSED, not reported under every ceiling"
            .to_string(),
    ));
    // A file that will not parse is an error and does not become code.
    write("crates/beta/src/broken.rs", "pub fn (((\n")?;
    let with_bad = measure(&cx, &Source::Worktree, &cfg, &[])?;
    out.push((
        with_bad.errors.len() == 1 && with_bad.total.code == 3,
        format!(
            "fixture tree: an unparseable file is ONE error and adds no code ({} error(s), code {})",
            with_bad.errors.len(),
            with_bad.total.code
        ),
    ));

    let _ = std::fs::remove_dir_all(&root);
    Ok(out)
}

fn scratch_dir() -> Result<PathBuf, String> {
    let base = std::env::temp_dir().join(format!(
        "xtask-loc-selftest-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).map_err(|e| format!("{}: {e}", base.display()))?;
    Ok(base)
}

// ── THE DELIBERATELY BROKEN RULES ────────────────────────────────────────────────────────────────

impl Flaw {
    fn label(self) -> &'static str {
        match self {
            Flaw::CfgTestToEof => "first-cfg(test)-to-EOF",
            Flaw::FlatBlockComments => "block-comments-do-not-nest",
            Flaw::LiteralBlind => "literal-blind-brace-counting",
            Flaw::TestSubstring => "`test` as a substring of the cfg attribute",
            Flaw::CommentsAreCode => "no-comment-stripping",
            Flaw::TopLevelTestsOnly => "only-top-level-src/tests",
            Flaw::PhantomTrailingLine => "count-the-empty-element-a-trailing-newline-leaves",
        }
    }
}

/// `scripts/loc-surface.py`'s path rule, verbatim: the top-level `src/tests/` tree and a top-level
/// `tests.rs`, and nothing else.
fn top_level_tests_only(rel: &str) -> bool {
    let Some(after_src) = rel.split_once("/src/").map(|(_, r)| r) else {
        return false;
    };
    after_src.starts_with("tests/") || after_src == "tests.rs"
}

/// ONE naive line scanner, with the flaw under test switched on. It exists only to be WRONG in a
/// specific, named, historically-real way; nothing reads its answer except the assertion that it
/// differs from the truth.
fn broken_code(text: &str, flaw: Flaw) -> u64 {
    // The one flaw that corrupts the LINE TOTAL rather than the code figure: `"a\n".split('\n')`
    // is `["a", ""]`, and counting that second element invents a blank line on every well-formed
    // file in the tree.
    if flaw == Flaw::PhantomTrailingLine {
        return text.split('\n').count() as u64;
    }
    let strip_comments = flaw != Flaw::CommentsAreCode;
    let honour_literals = flaw != Flaw::LiteralBlind;
    let nest_comments = flaw != Flaw::FlatBlockComments;
    let to_eof = flaw == Flaw::CfgTestToEof;
    let substring = flaw == Flaw::TestSubstring;

    let mut code = 0u64;
    let mut block: i64 = 0;
    let mut in_item = false;
    let mut depth: i64 = 0;
    let mut opened = false;
    let mut eof_test = false;

    for raw in text.strip_suffix('\n').unwrap_or(text).split('\n') {
        if eof_test {
            continue;
        }
        let mut visible = String::new();
        let chars: Vec<char> = raw.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            let c = chars[i];
            let n = chars.get(i + 1).copied().unwrap_or('\0');
            if block > 0 {
                if nest_comments && c == '/' && n == '*' {
                    block += 1;
                    i += 2;
                    continue;
                }
                if c == '*' && n == '/' {
                    block -= 1;
                    i += 2;
                    continue;
                }
                i += 1;
                continue;
            }
            if strip_comments && c == '/' && n == '*' {
                block += 1;
                i += 2;
                continue;
            }
            if strip_comments && c == '/' && n == '/' {
                break;
            }
            if honour_literals && c == '"' {
                i += 1;
                while i < chars.len() {
                    if chars[i] == '\\' {
                        i += 2;
                        continue;
                    }
                    if chars[i] == '"' {
                        break;
                    }
                    i += 1;
                }
                i += 1;
                visible.push('"');
                continue;
            }
            if honour_literals && c == '\'' && chars.get(i + 2) == Some(&'\'') {
                i += 3;
                visible.push('\'');
                continue;
            }
            visible.push(c);
            i += 1;
        }

        if in_item {
            for c in visible.chars() {
                if c == '{' {
                    depth += 1;
                    opened = true;
                } else if c == '}' {
                    depth -= 1;
                }
            }
            if (opened && depth <= 0) || (!opened && visible.contains(';')) {
                in_item = false;
            }
            continue;
        }

        // THE SUBSTRING FLAW READS THE RAW LINE, which is what makes it the flaw it is: a rule
        // spelled as "does `test` appear inside the cfg attribute" sees `feature = "test-support"`
        // as a test gate and `not(test)` as one too.
        let probe: &str = if substring { raw } else { visible.as_str() };
        if let Some(at) = probe.find("#[cfg(") {
            let is_test = if substring {
                probe[at..].contains("test")
            } else {
                let attr = &probe[at..];
                attr.contains("(test)") || attr.contains("(test,") || attr.contains(" test,")
            };
            if is_test {
                if to_eof {
                    eof_test = true;
                    continue;
                }
                in_item = true;
                depth = 0;
                opened = false;
                let from = visible.find("#[cfg(").unwrap_or(0);
                let rest: String = visible[from..].chars().skip_while(|c| *c != ']').collect();
                for c in rest.chars() {
                    if c == '{' {
                        depth += 1;
                        opened = true;
                    } else if c == '}' {
                        depth -= 1;
                    }
                }
                if (opened && depth <= 0) || (!opened && rest.contains(';')) {
                    in_item = false;
                }
                continue;
            }
        }

        if !visible.trim().is_empty() {
            code += 1;
        }
    }
    code
}

// ── THE SELF-TEST IS ALSO A `cargo test` ─────────────────────────────────────────────────────────
// `cargo xtask loc --selftest` is the human entry point; this is the one CI already runs. A proof
// that only fires when somebody remembers to type a command is a proof that stops firing.
#[cfg(test)]
mod tests {
    #[test]
    fn loc_selftest_is_green() {
        assert_eq!(
            super::run(),
            0,
            "the loc counter's own fixtures are RED — see the PASS/FAIL lines above"
        );
    }
}
