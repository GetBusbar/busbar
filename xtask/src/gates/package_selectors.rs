//! `cargo xtask gate package-selectors` — EVERY CARGO PACKAGE SELECTOR IN A WORKFLOW, A SCRIPT, A
//! QA SEGMENT OR AN XTASK COMMAND STRING NAMES A PACKAGE THIS WORKSPACE STILL HAS.
//!
//! A `-p <name>` is a STRING, and a string does not move when the crate it names is folded into
//! another. The 1.6.0 folds deleted `busbar-core`, `busbar-substrate`, `busbar-admin`,
//! `busbar-plane-admin`, `busbar-caps` and `busbar-core-config`; roughly twenty sites across
//! `.github/workflows/`, `scripts/`, `qa/` and `xtask/src/` went on naming them, and two hand
//! sweeps (`afe12ec00`, `fe689c616`) repointed them one by one. Nothing stopped it recurring.
//!
//! THE FAILURE MODE IS NOT "A JOB GOES RED". It is a check that stops checking and says nothing
//! while it stops, and the sharpest instance is `cargo xtask txn-fence`, whose PASS CONDITION IS A
//! BUILD FAILURE:
//!
//! ```text
//! out=$(cargo rustc -p busbar-core --lib -- --cfg txn_fence_red) && status=0 || status=$?
//! ```
//!
//! `busbar-core` had not existed since `673ecdaaa`, so cargo answered `package ID specification
//! 'busbar-core' did not match any packages` — a NON-ZERO exit, which is this script's green —
//! while compiling nothing at all. A pass condition satisfied by a build failure. The same shape
//! was in the release-cutting workflows, where it could only ever have been discovered at the
//! moment of cutting a release, and in the removed `ci.yml`'s feature matrix, where a `tests:` cell selected a
//! package that no longer existed and a libtest filter over zero packages exits 0.
//!
//! THE SHAPE OF THE CONTRACT is the one `qa-names` keeps: membership is DERIVED from the tree (the workspace
//! members plus `Cargo.lock`, which is the exact set `cargo -p` resolves against) and ASSERTED
//! against every covered file, and a deliberate exception is possible only IN WRITING, next to the
//! site, as a comment:
//!
//! ```text
//! # package-selector: <package> -- <covered file> -- <reason, at least MIN_REASON characters>
//! ```
//!
//! (`//` in place of `#` inside `xtask/src`.) The sibling-checkout plugin builds are the real
//! exceptions and they carry one each.
//!
//! AN EXEMPTION IS SCOPED TO THE FILE IT NAMES. A declaration excuses the dead package in the
//! `<covered file>` it writes and NOWHERE ELSE: the same dead name selected in any other file is
//! RED until that file carries a declaration of its own. Keyed on the name alone, one written
//! exception silenced every other dead selector of that spelling in the tree, and the file field
//! was checked only to be SOME covered file, never the one holding the site (X5 finding 8).
//!
//! WHICH FILES ARE READ is derived from the tree, not from an extension list: EVERY file under
//! `.github` (workflows, composite actions under `.github/actions`, `.github/scripts`), `scripts`,
//! `qa`, `xtask/src`, `.ci` (the ModernCI definitions), `bin` (the oracle shim) and `.githooks` is
//! walked, and its shape picks the reader. `.rs` is read for command
//! literals (rule 3); `.yml`/`.yaml` as commands plus matrix cells (rules 1 and 2); `.json` for its
//! command strings (rule 4); Markdown is prose and is not read; EVERYTHING ELSE — `.sh`, `.py`,
//! `.mjs`, `.toml`, a `Makefile`, an extensionless script — is read as command lines (rule 1). A
//! new script language is therefore covered the day it lands, without anyone adding its suffix.
//!
//! WHAT IS COVERED, AND WHY SO NARROWLY. Only UNAMBIGUOUS PACKAGE-SELECTOR POSITIONS:
//!
//! 1. `-p <name>` / `--package <name>` on a NON-COMMENT line, inside a command segment that names
//!    `cargo`. The `cargo` requirement is the whole discrimination: this tree runs `mkdir -p`,
//!    `docker run -p 8080:8080`, `gdb -p "$pid"` and `xxd -r -p`, and every one of them is a `-p`
//!    that means something else.
//! 2. A `tests:` or `features:` MATRIX CELL. `tests:` is passed verbatim after `cargo test`;
//!    `features:` is `<pkg>/<feature>`, so its left half is a package selector in all but spelling.
//! 3. A Rust string literal under `xtask/src` that BEGINS with `cargo ` — the command strings
//!    a runner mirrors a pipeline with. The "begins with" is load-bearing: the same tuples carry PROSE
//!    strings that quote dead selectors on purpose, and prose is not a command. And the ARRAY
//!    spelling: `"-p", "<crate>"` as adjacent string elements of a bracket group that carries a
//!    `"cargo"` element (or that follows `cargo` within three lines, as `Command::new(&cargo)
//!    .args([…])` does). `docker compose -p …` in the same file is not cargo and is not read.
//! 4. A JSON string that is the value of a `run` key — `qa/pipeline-checks.json` declares exactly
//!    those as bash, for the `dev` -> `qa` move. JSON is data, and a string in it is a command only where a
//!    consumer executes it: the audit evidence under `qa/` opens prose fields with `cargo test -p
//!    <a crate since folded away> …` as the record of what was run, and that record is not a
//!    command.
//!
//! WHAT IS DELIBERATELY NOT COVERED, stated so it is not mistaken for held: the general "no string
//! literal anywhere names a non-workspace crate". Historical crate names legitimately appear in
//! prose everywhere — commit messages, design docs, the comments that RECORD these very repointings
//! — and the removed `verify-deploy.yml` installs a real PyPI package called `busbar-admin`. That version needs
//! an allowlist, and an allowlist needs its own liveness check; this one needs neither, because a
//! comment is not an executable position.
//!
//! THE RULES, each its own ledger row:
//!
//! 1. [`ROW_UNIVERSE`] — the workspace manifests and `Cargo.lock` were read and yielded at least
//!    [`UNIVERSE_FLOOR`] package names. A reader that lost its input resolves nothing, and every
//!    selector in the tree would be reported for a defect in this gate.
//! 2. [`ROW_SITE_FLOOR`] — at least [`SITE_FLOOR`] selector sites were discovered. Zero is never
//!    clean: "every selector resolves" is vacuously true over no selectors, which is exactly what a
//!    scanner that stopped matching reports.
//! 3. [`ROW_RESOLVES`] — every discovered selector names a package in the universe, or is declared
//!    FOR THE FILE IT IS IN.
//! 4. [`ROW_DECL_LIVE`] — a declaration names a package that is still selected IN THE FILE IT
//!    NAMES AND still fails to resolve. A stale exemption outlives the site it excused and silently excuses the next
//!    selector to take the name; a declaration for a package that has since joined the workspace is
//!    an exemption nobody needs, and leaving it hides the day it leaves again.
//! 5. [`ROW_DECL_FILE`] — the file a declaration names is one of the covered files. A reference to a
//!    path that was renamed away is a claim nobody can check.
//! 6. [`ROW_DECL_REASON`] — a declaration carries a reason of at least [`MIN_REASON`] characters.
//!    An exemption without a reason becomes permanent by accident.

use std::collections::BTreeSet;

use crate::ctx::{Ctx, Overlay, WalkSpec};
use crate::gates::{prove_green, prove_rows_red, Case, Expect, Gate, Report};
use crate::ledger::{Row, Verdict};
use crate::manifest;

pub const ROOT_MANIFEST: &str = "Cargo.toml";
/// The lockfile IS the resolvable set: `cargo -p <name>` matches a package ID in the resolve graph,
/// and that graph is what `Cargo.lock` records. Reading it rather than a hand-kept list of workspace
/// members is what lets `cargo check -p rmcp` — a real external package, selected on purpose by the
/// field-inventory job — stay green without an entry anywhere.
pub const LOCKFILE: &str = "Cargo.lock";

/// The covered roots. Every file under each is walked; its shape picks the reader ([`reader_for`]).
/// `.github` whole, not `.github/workflows`: a composite action under `.github/actions` and a
/// script under `.github/scripts` run cargo with the release workflow's tokens too.
pub const GITHUB_ROOT: &str = ".github";
pub const SCRIPT_ROOT: &str = "scripts";
pub const QA_ROOT: &str = "qa";
pub const XTASK_ROOT: &str = "xtask/src";
/// The CI definitions (`.ci/*.yaml`), the oracle shim (`bin/`) and the git hooks (`.githooks/`):
/// all three run `cargo` on a contributor's or a runner's behalf and none of them was read.
pub const CI_ROOT: &str = ".ci";
pub const BIN_ROOT: &str = "bin";
pub const HOOKS_ROOT: &str = ".githooks";
/// Every covered root, in walk order.
pub const ROOTS: [&str; 7] = [
    GITHUB_ROOT,
    SCRIPT_ROOT,
    QA_ROOT,
    XTASK_ROOT,
    CI_ROOT,
    BIN_ROOT,
    HOOKS_ROOT,
];

/// The declaration, in the two comment spellings the covered files use. Matched on the TRIMMED
/// line, so indentation is free to move — and deliberately NOT matched after `//!` or `///`, which
/// is what lets this module's own header print the template without declaring anything.
pub const DECL_HASH: &str = "# package-selector:";
pub const DECL_SLASH: &str = "// package-selector:";
/// The separator between a declaration's three fields.
pub const SEP: &str = " -- ";

pub const ROW_UNIVERSE: &str = "package-selectors:universe-read";
pub const ROW_SITE_FLOOR: &str = "package-selectors:site-floor";
pub const ROW_RESOLVES: &str = "package-selectors:selector-names-a-live-package";
pub const ROW_DECL_LIVE: &str = "package-selectors:declaration-names-a-live-selector";
pub const ROW_DECL_FILE: &str = "package-selectors:declaration-names-a-live-file";
pub const ROW_DECL_REASON: &str = "package-selectors:declaration-reason";

/// The floor under the resolvable universe. Measured at 467 on the 1.6.0 integration tree (51
/// workspace members plus every distinct name in `Cargo.lock`). Set well below that because the
/// number this floor exists to reject is a universe that COLLAPSED — a reader that found nothing
/// makes every selector in the tree look dead, which is a defect in the instrument reported as a
/// defect in the tree.
pub const UNIVERSE_FLOOR: usize = 40;
/// The floor under the discovered selector sites, armed at the measured count: 55 sites across
/// 311 read files (plus 25 Markdown files walked and not read) at predev 0fd08ee75d, once the walk
/// read every file under its roots by shape rather than four suffixes (the four-suffix walk read 52
/// across 266). This is the floor that matters: an empty scan set is the one state in which "every
/// selector resolves" is true and means nothing.
pub const SITE_FLOOR: usize = 55;
/// The shortest exemption reason that is a reason rather than a shrug.
pub const MIN_REASON: usize = 30;

/// Where a selector was found, and in what shape — carried so a finding cites the line a reader has
/// to open rather than the file it is somewhere inside.
#[derive(Debug, Clone)]
struct Site {
    pkg: String,
    file: String,
    line: usize,
    kind: &'static str,
}

impl Site {
    fn cite(&self) -> String {
        format!("{}:{} `{}` ({})", self.file, self.line, self.pkg, self.kind)
    }
}

/// One `package-selector:` line.
#[derive(Debug, Clone)]
struct Decl {
    pkg: String,
    file: String,
    reason: String,
}

/// A covered file: its repo-relative path, its bytes, and which scanner reads it.
struct Covered {
    rel: String,
    text: String,
    reader: Reader,
}

/// Which scanner a covered file is read by, chosen from the file's own name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reader {
    /// `.rs`: string literals that begin with `cargo ` (rule 3).
    Rust,
    /// `.yml` / `.yaml`: command lines and matrix cells (rules 1 and 2).
    Yaml,
    /// `.json`: `run` values (rule 4).
    Json,
    /// Markdown: prose, which RECORDS deleted crates on purpose. Walked, counted, not read.
    Prose,
    /// Everything else — shell, python, node, TOML, a Makefile, an extensionless script: command
    /// lines (rule 1). The default is READ, so a file shape nobody listed is covered, not skipped.
    Commands,
}

/// The reader for one repo-relative path, from the extension of its last segment.
fn reader_for(rel: &str) -> Reader {
    let base = rel.rsplit('/').next().unwrap_or(rel);
    match base.rsplit_once('.').map(|(_, ext)| ext) {
        Some("rs") => Reader::Rust,
        Some("yml" | "yaml") => Reader::Yaml,
        Some("json") => Reader::Json,
        Some("md") => Reader::Prose,
        _ => Reader::Commands,
    }
}

// ---------------------------------------------------------------------------------------------
// the universe
// ---------------------------------------------------------------------------------------------

/// Every package name `cargo -p` could resolve in this workspace: the members' own
/// `[package] name`s, plus every `name = "…"` in the lockfile. Every way this can go wrong is an
/// `Err` carrying its own sentence — none of them may be reachable as "an empty universe".
///
/// PUBLIC because `qa-names` asks the same question of a different vocabulary: a `*_crates` list in
/// `qa/*.toml` names the same packages a `-p` does, and two readers of one universe are two answers
/// to "is this crate still here" waiting to disagree.
pub fn universe(cx: &Ctx) -> Result<BTreeSet<String>, String> {
    let root = cx.read(ROOT_MANIFEST).map_err(|e| {
        format!(
            "{ROOT_MANIFEST} is unreadable ({e}) — a reader with no workspace resolves no package, \
             and every selector in the tree would be reported for a defect in this gate"
        )
    })?;
    let members = manifest::workspace_members(&root);
    if members.is_empty() {
        return Err(format!(
            "{ROOT_MANIFEST} names no `[workspace] members` — the key was renamed or the manifest \
             changed shape, which reads as zero packages and therefore as every selector dead"
        ));
    }
    let mut out = BTreeSet::new();
    for member in &members {
        let rel = format!("{member}/Cargo.toml");
        let text = cx.read(&rel).map_err(|e| {
            format!(
                "{rel} is unreadable ({e}) — a member this gate cannot read is a member whose name \
                 it cannot resolve, so it is refused rather than skipped"
            )
        })?;
        match package_name(&text) {
            Some(name) => {
                out.insert(name);
            }
            None => {
                return Err(format!(
                    "{rel} carries no `[package] name` — a crate this gate cannot name is a crate \
                     no selector for it can be checked against"
                ))
            }
        }
    }
    let lock = cx.read(LOCKFILE).map_err(|e| {
        format!(
            "{LOCKFILE} is unreadable ({e}) — the lockfile IS the set `cargo -p` resolves against, \
             so without it an external selector like `-p rmcp` cannot be told from a dead one"
        )
    })?;
    for raw in lock.lines() {
        if let Some(v) = raw.strip_prefix("name = ") {
            out.insert(v.trim().trim_matches('"').to_string());
        }
    }
    Ok(out)
}

/// The `[package] name` of a manifest.
fn package_name(text: &str) -> Option<String> {
    let mut in_package = false;
    for raw in text.lines() {
        let t = raw.trim();
        if let Some(header) = t.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            in_package = header.trim() == "package";
            continue;
        }
        if !in_package {
            continue;
        }
        if let Some(rest) = t.strip_prefix("name") {
            if let Some(v) = rest.trim_start().strip_prefix('=') {
                return Some(v.trim().trim_matches(['"', '\'']).to_string());
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------------------------
// the scanners
// ---------------------------------------------------------------------------------------------

/// A token that could be a package name, or `None` for everything that is a VARIABLE rather than a
/// name: `"$PLUGIN_CRATE"`, `${{ matrix.tests }}`, `busbar-store-<backend>`.
///
/// The token is cleaned of the punctuation a shell line wraps it in — quotes, a closing paren, a
/// trailing comma — and then it must be a plain cargo package name WITH AT LEAST ONE LETTER IN IT.
/// The letter is not decoration: `ssh -p 22` and `docker run -p 8080:8080` are `-p` in a segment
/// that could also name cargo, and a gate that reports port 22 as a dead crate is a gate somebody
/// puts a `|| true` in front of.
fn package_token(raw: &str) -> Option<String> {
    let t = raw
        .trim()
        .trim_matches(['"', '\'', '`'])
        .trim_end_matches([')', ']', ',', ';', '.', '`', '"', '\''])
        .trim_start_matches(['(', '[', '`', '"', '\'']);
    if t.is_empty() || !t.chars().any(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    let mut chars = t.chars();
    let first = chars.next()?;
    if !(first.is_ascii_alphanumeric() || first == '_') {
        return None;
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '+' | '-')) {
        return None;
    }
    Some(t.to_string())
}

/// The package names selected by `-p` / `--package` in one already-narrowed argument string.
fn selectors(args: &str) -> Vec<String> {
    let toks: Vec<&str> = args.split_whitespace().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < toks.len() {
        // A python argv list writes the flag as `"-p",`; the quotes and the comma are spelling,
        // not part of the flag.
        let t = toks[i].trim_matches(['"', '\'', ',', '[', ']']);
        let value = if t == "-p" || t == "--package" {
            i += 1;
            toks.get(i).copied()
        } else {
            t.strip_prefix("--package=")
                .or_else(|| t.strip_prefix("-p="))
        };
        if let Some(v) = value {
            if let Some(name) = package_token(v) {
                out.push(name);
            }
        }
        i += 1;
    }
    out
}

/// Is `word` present in `seg` as a whole word? `cargo-home` is not `cargo`.
fn has_word(seg: &str, word: &str) -> bool {
    let b = seg.as_bytes();
    let w = word.as_bytes();
    let boundary = |c: u8| !(c.is_ascii_alphanumeric() || c == b'_' || c == b'-');
    let mut i = 0;
    while i + w.len() <= b.len() {
        if &b[i..i + w.len()] == w
            && (i == 0 || boundary(b[i - 1]))
            && (i + w.len() == b.len() || boundary(b[i + w.len()]))
        {
            return true;
        }
        i += 1;
    }
    false
}

/// Split a command line into the segments a shell would run separately: `;`, `|`, `&&`, `||`,
/// `$(…)` and backticks. This is what keeps `rm -rf x; mkdir -p y` from inheriting the `cargo` in
/// its neighbour, and what lets `out="$(cargo test -p busbar … | tee)"` still be seen as cargo's.
fn segments(line: &str) -> Vec<&str> {
    let b = line.as_bytes();
    let mut out = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i < b.len() {
        let next = b.get(i + 1).copied().unwrap_or(0);
        let cut = match b[i] {
            b'&' if next == b'&' => 2,
            b'$' if next == b'(' => 2,
            b';' | b'|' | b'`' => 1,
            _ => 0,
        };
        if cut > 0 {
            out.push(&line[start..i]);
            i += cut;
            start = i;
        } else {
            i += 1;
        }
    }
    out.push(&line[start..]);
    out
}

/// The file's lines with backslash continuations JOINED, each paired with the line number the
/// JOINED command STARTS on. the removed `ci.yml` spreads one `cargo build` over five lines, one `-p` each, and
/// a scanner that reads lines would see four selectors with no cargo anywhere near them.
fn logical_lines(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut buf: Option<(usize, String)> = None;
    for (idx, raw) in text.lines().enumerate() {
        let (start, joined) = match buf.take() {
            Some((s, acc)) => (s, format!("{acc} {}", raw.trim())),
            None => (idx + 1, raw.to_string()),
        };
        match joined.trim_end().strip_suffix('\\') {
            Some(head) => buf = Some((start, head.to_string())),
            None => out.push((start, joined)),
        }
    }
    if let Some((s, acc)) = buf {
        out.push((s, acc));
    }
    out
}

/// Rule 1: a `-p` in a cargo command, on a line that is not a whole-line comment.
///
/// Whole-line comments only. A shell `#` mid-line is not reliably a comment (`"$#"`, `${x#y}`, a
/// URL fragment), and the sites this gate exists for are all executable lines anyway — while the
/// PROSE that would otherwise be reported (the comments recording these very repointings, and
/// the removed `qa-gate-run.sh`'s note about what the selector used to read) is all whole-line.
fn scan_commands(rel: &str, text: &str, out: &mut Vec<Site>) {
    for (line, joined) in logical_lines(text) {
        let t = joined.trim_start();
        if t.starts_with('#') || t.starts_with("//") {
            continue;
        }
        for seg in segments(&joined) {
            if !has_word(seg, "cargo") {
                continue;
            }
            for pkg in selectors(seg) {
                out.push(Site {
                    pkg,
                    file: rel.to_string(),
                    line,
                    // NOT "cargo -p selector": this file is itself covered, and a literal that
                    // BEGINS with `cargo ` is read as a command by the very rule below. The gate
                    // reported this label as a package called `selector` on its first run.
                    kind: "-p selector in a cargo command",
                });
            }
        }
    }
}

/// Rule 2: a `tests:` or `features:` matrix cell.
///
/// `tests:` is passed verbatim after `cargo test`, so it is read as cargo arguments. `features:` is
/// a comma-separated list of `<pkg>/<feature>`; an entry with no `/` is a feature of the package the
/// command already selected and names nobody.
fn scan_matrix(rel: &str, text: &str, out: &mut Vec<Site>) {
    for (idx, raw) in text.lines().enumerate() {
        let line = idx + 1;
        let t = raw.trim();
        if t.starts_with('#') {
            continue;
        }
        let t = t.strip_prefix("- ").unwrap_or(t).trim();
        if let Some(v) = t.strip_prefix("tests:") {
            let v = v.trim().trim_matches(['"', '\'']);
            for pkg in selectors(v) {
                out.push(Site {
                    pkg,
                    file: rel.to_string(),
                    line,
                    kind: "matrix `tests:` cell",
                });
            }
        } else if let Some(v) = t.strip_prefix("features:") {
            for entry in v.trim().trim_matches(['"', '\'']).split(',') {
                let Some((pkg, _)) = entry.trim().split_once('/') else {
                    continue;
                };
                if let Some(pkg) = package_token(pkg) {
                    out.push(Site {
                        pkg,
                        file: rel.to_string(),
                        line,
                        kind: "matrix `features:` cell",
                    });
                }
            }
        }
    }
}

/// Rule 3: a Rust string literal that BEGINS with `cargo `.
///
/// A list of (command, reason) tuples on ONE line each (a command mirror) carries reasons that
/// quote dead selectors deliberately — `"(It read '-p busbar-core' here for as long as the old
/// workflow did …)"`. A literal that begins with `cargo ` is a command; one that begins with anything
/// else is prose about a command, and prose is out of scope by construction rather than by
/// allowlist.
fn scan_rust_commands(rel: &str, text: &str, out: &mut Vec<Site>) {
    for (idx, raw) in text.lines().enumerate() {
        let line = idx + 1;
        if raw.trim_start().starts_with("//") {
            continue;
        }
        let b = raw.as_bytes();
        let mut consumed = 0usize;
        for (i, _) in raw.match_indices("\"cargo ") {
            if i < consumed {
                continue;
            }
            let mut lit = String::new();
            let mut j = i + 1;
            while j < b.len() {
                if b[j] == b'\\' {
                    if let Some(&c) = b.get(j + 1) {
                        lit.push(c as char);
                    }
                    j += 2;
                    continue;
                }
                if b[j] == b'"' {
                    break;
                }
                lit.push(b[j] as char);
                j += 1;
            }
            for pkg in selectors(&lit) {
                out.push(Site {
                    pkg,
                    file: rel.to_string(),
                    line,
                    kind: "xtask cargo command string",
                });
            }
            consumed = j;
        }
    }
}

/// One lexed Rust token, for [`scan_rust_argv`]. Comments are dropped, a string keeps its decoded
/// text, and every token carries the line it starts on.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Str(String),
    Word(String),
    Punct(char),
}

/// Lex Rust source into [`Tok`]s with their 1-based lines. Not a full lexer: it knows exactly the
/// things that would otherwise make a bracket or a `"-p"` in a comment, a char literal or a raw
/// string look like code: line and block comments, `"…"` with escapes, `r#"…"#`, `'x'` against a
/// lifetime.
fn lex_rust(text: &str) -> Vec<(usize, Tok)> {
    let b: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let (mut i, mut line) = (0usize, 1usize);
    while i < b.len() {
        let c = b[i];
        match c {
            '\n' => {
                line += 1;
                i += 1;
            }
            c if c.is_whitespace() => i += 1,
            '/' if b.get(i + 1) == Some(&'/') => {
                while i < b.len() && b[i] != '\n' {
                    i += 1;
                }
            }
            '/' if b.get(i + 1) == Some(&'*') => {
                let mut depth = 1;
                i += 2;
                while i < b.len() && depth > 0 {
                    if b[i] == '/' && b.get(i + 1) == Some(&'*') {
                        depth += 1;
                        i += 2;
                    } else if b[i] == '*' && b.get(i + 1) == Some(&'/') {
                        depth -= 1;
                        i += 2;
                    } else {
                        if b[i] == '\n' {
                            line += 1;
                        }
                        i += 1;
                    }
                }
            }
            'r' if matches!(b.get(i + 1), Some('"' | '#')) && {
                let mut k = i + 1;
                while b.get(k) == Some(&'#') {
                    k += 1;
                }
                b.get(k) == Some(&'"')
            } =>
            {
                let mut hashes = 0;
                i += 1;
                while b.get(i) == Some(&'#') {
                    hashes += 1;
                    i += 1;
                }
                i += 1;
                let start_line = line;
                let mut lit = String::new();
                while i < b.len() {
                    if b[i] == '"' && (0..hashes).all(|h| b.get(i + 1 + h) == Some(&'#')) {
                        i += 1 + hashes;
                        break;
                    }
                    if b[i] == '\n' {
                        line += 1;
                    }
                    lit.push(b[i]);
                    i += 1;
                }
                out.push((start_line, Tok::Str(lit)));
            }
            '"' => {
                let start_line = line;
                let mut lit = String::new();
                i += 1;
                while i < b.len() && b[i] != '"' {
                    if b[i] == '\\' {
                        if let Some(&n) = b.get(i + 1) {
                            if n == '\n' {
                                line += 1;
                                i += 2;
                                while i < b.len() && b[i].is_whitespace() {
                                    if b[i] == '\n' {
                                        line += 1;
                                    }
                                    i += 1;
                                }
                                continue;
                            }
                            lit.push(n);
                        }
                        i += 2;
                        continue;
                    }
                    if b[i] == '\n' {
                        line += 1;
                    }
                    lit.push(b[i]);
                    i += 1;
                }
                i += 1;
                out.push((start_line, Tok::Str(lit)));
            }
            '\'' => {
                // A char literal closes within a few characters; a lifetime does not.
                if b.get(i + 1) == Some(&'\\') {
                    i += 2;
                    while i < b.len() && b[i] != '\'' {
                        i += 1;
                    }
                    i += 1;
                } else if b.get(i + 2) == Some(&'\'') {
                    i += 3;
                } else {
                    i += 1;
                }
            }
            c if c.is_alphanumeric() || c == '_' => {
                let st = i;
                while i < b.len() && (b[i].is_alphanumeric() || b[i] == '_') {
                    i += 1;
                }
                out.push((line, Tok::Word(b[st..i].iter().collect())));
            }
            c => {
                out.push((line, Tok::Punct(c)));
                i += 1;
            }
        }
    }
    out
}

/// Rule 3b: the ARRAY spelling of a cargo command in Rust, `"-p", "<crate>"` as two adjacent
/// string elements. Rule 3 reads only a single literal that begins with `cargo `; a runner that
/// builds its argv as `["cargo", "build", "-p", "busbar-gone"]` (one element per line, as
/// `rustfmt` lays out anything long) was never read.
///
/// The cargo discrimination is the same one rule 1 makes: `docker compose -p busbar-oidf` and
/// `ps -p <pid>` are also `"-p"` pairs. The pair counts only when the ENCLOSING bracket group
/// carries a `"cargo"` element, or when the three lines before that group's opening bracket name
/// `cargo` (a `Command::new(&cargo)` followed by `.args([…])`). A value that is not a string
/// literal (`"-p", CRATE`, `"-p", &name`) is a variable and is left alone, exactly as `$X` is in a
/// script.
fn scan_rust_argv(rel: &str, text: &str, out: &mut Vec<Site>) {
    let toks = lex_rust(text);
    for i in 1..toks.len().saturating_sub(2) {
        let (line, Tok::Str(flag)) = &toks[i] else {
            continue;
        };
        if flag != "-p" && flag != "--package" {
            continue;
        }
        if !matches!(&toks[i - 1].1, Tok::Punct('[' | ',' | '(')) {
            continue;
        }
        let (Tok::Punct(','), Tok::Str(value)) = (&toks[i + 1].1, &toks[i + 2].1) else {
            continue;
        };
        let Some(pkg) = package_token(value) else {
            continue;
        };
        // The opening bracket of the group this element sits in.
        let mut depth = 0i32;
        let mut open = None;
        for k in (0..i).rev() {
            match toks[k].1 {
                Tok::Punct(')' | ']' | '}') => depth += 1,
                Tok::Punct(c @ ('(' | '[' | '{')) => {
                    if depth == 0 {
                        open = Some((k, c));
                        break;
                    }
                    depth -= 1;
                }
                _ => {}
            }
        }
        let Some((open, _)) = open else { continue };
        let is_cargo = |t: &Tok| match t {
            Tok::Str(s) => s == "cargo" || s.starts_with("cargo "),
            Tok::Word(w) => w == "cargo",
            Tok::Punct(_) => false,
        };
        let in_group = toks[open..i].iter().any(|(_, t)| match t {
            Tok::Str(s) => s == "cargo" || s.starts_with("cargo "),
            _ => false,
        });
        let open_line = toks[open].0;
        let before = toks[..open]
            .iter()
            .rev()
            .take_while(|(l, _)| *l + 3 >= open_line)
            .any(|(_, t)| is_cargo(t));
        if in_group || before {
            out.push(Site {
                pkg,
                file: rel.to_string(),
                line: *line,
                kind: "xtask cargo argv array",
            });
        }
    }
}

/// Rule 4: a JSON string that is a `run` value.
///
/// A JSON string cannot span lines, so the scan is per line: the string after a `"run":` key, read
/// as a shell command line, so a `run` value that chains `m=$(…); cargo build -p x` is held to the
/// same `cargo`-in-the-segment rule as a script.
fn scan_json_commands(rel: &str, text: &str, out: &mut Vec<Site>) {
    for (idx, raw) in text.lines().enumerate() {
        let line = idx + 1;
        let b = raw.as_bytes();
        let mut starts: Vec<usize> = Vec::new();
        for (i, _) in raw.match_indices("\"run\"") {
            let rest = &raw[i + 5..];
            let after_colon = rest.trim_start().strip_prefix(':').map(str::trim_start);
            if let Some(v) = after_colon.filter(|v| v.starts_with('"')) {
                starts.push(raw.len() - v.len());
            }
        }
        for start in starts {
            let mut lit = String::new();
            let mut j = start + 1;
            while j < b.len() && b[j] != b'"' {
                if b[j] == b'\\' {
                    match b.get(j + 1) {
                        Some(b'n' | b't' | b'r') => lit.push(' '),
                        Some(&c) => lit.push(c as char),
                        None => {}
                    }
                    j += 2;
                    continue;
                }
                lit.push(b[j] as char);
                j += 1;
            }
            for seg in segments(&lit) {
                if !has_word(seg, "cargo") {
                    continue;
                }
                for pkg in selectors(seg) {
                    out.push(Site {
                        pkg,
                        file: rel.to_string(),
                        line,
                        kind: "JSON command string",
                    });
                }
            }
        }
    }
}

/// `# package-selector: pkg -- file -- reason`, in either comment spelling. A line that carries the
/// prefix and does not have this shape is NOT silently skipped: it is returned with the empty fields
/// it parsed to, so the file and reason rules report it.
fn parse_decl(trimmed: &str) -> Option<Decl> {
    let rest = trimmed
        .strip_prefix(DECL_HASH)
        .or_else(|| trimmed.strip_prefix(DECL_SLASH))?
        .trim();
    let mut parts = rest.splitn(3, SEP);
    Some(Decl {
        pkg: parts.next().unwrap_or_default().trim().to_string(),
        file: parts.next().unwrap_or_default().trim().to_string(),
        reason: parts.next().unwrap_or_default().trim().to_string(),
    })
}

// ---------------------------------------------------------------------------------------------
// discovery
// ---------------------------------------------------------------------------------------------

/// Every file under the four roots, DERIVED by walking them with NO extension filter. A hand-kept
/// list of files is the mechanism that let twenty sites rot in the first place, and a hand-kept
/// list of suffixes is the same mechanism one level up: a `.yaml` workflow, a composite action, a
/// python script or a Makefile was never opened. Markdown comes back too, as [`Reader::Prose`], so
/// the count of what was walked and not read is printed rather than implied.
fn covered(cx: &Ctx) -> Result<Vec<Covered>, String> {
    let mut out = Vec::new();
    for root in ROOTS {
        let files = cx
            .walk(&WalkSpec::new([root]))
            .map_err(|e| format!("the `{root}` walk failed: {e}"))?;
        for f in files {
            let rel = f.rel_str();
            out.push(Covered {
                reader: reader_for(&rel),
                text: f.text,
                rel,
            });
        }
    }
    out.sort_by(|a, b| a.rel.cmp(&b.rel));
    Ok(out)
}

/// Every selector site and every declaration the covered files carry.
fn scan(files: &[Covered]) -> (Vec<Site>, Vec<(String, usize, Decl)>) {
    let mut sites = Vec::new();
    let mut decls = Vec::new();
    for f in files {
        match f.reader {
            Reader::Prose => continue,
            Reader::Rust => {
                scan_rust_commands(&f.rel, &f.text, &mut sites);
                scan_rust_argv(&f.rel, &f.text, &mut sites);
            }
            Reader::Json => scan_json_commands(&f.rel, &f.text, &mut sites),
            Reader::Yaml => {
                scan_commands(&f.rel, &f.text, &mut sites);
                scan_matrix(&f.rel, &f.text, &mut sites);
            }
            Reader::Commands => scan_commands(&f.rel, &f.text, &mut sites),
        }
        for (idx, raw) in f.text.lines().enumerate() {
            if let Some(d) = parse_decl(raw.trim()) {
                decls.push((f.rel.clone(), idx + 1, d));
            }
        }
    }
    (sites, decls)
}

// ---------------------------------------------------------------------------------------------
// the gate
// ---------------------------------------------------------------------------------------------

pub struct PackageSelectorsGate;

/// The rows every rule below [`ROW_UNIVERSE`] answers on when there was nothing to read.
fn unproven(why: &str) -> Verdict {
    let detail = format!("unproven: the package universe did not load — {why}");
    Verdict::of(vec![
        Row::fail(ROW_UNIVERSE, "the package universe did not load", why),
        Row::fail(ROW_SITE_FLOOR, "no selector was counted", detail.clone()),
        Row::fail(ROW_RESOLVES, "no selector was checked", detail.clone()),
        Row::fail(ROW_DECL_LIVE, "no declaration was checked", detail.clone()),
        Row::fail(ROW_DECL_FILE, "no declaration was checked", detail.clone()),
        Row::fail(ROW_DECL_REASON, "no declaration was checked", detail),
    ])
}

impl Gate for PackageSelectorsGate {
    fn name(&self) -> &'static str {
        "package-selectors"
    }

    fn owed(&self) -> Vec<String> {
        vec![
            ROW_UNIVERSE.to_string(),
            ROW_SITE_FLOOR.to_string(),
            ROW_RESOLVES.to_string(),
            ROW_DECL_LIVE.to_string(),
            ROW_DECL_FILE.to_string(),
            ROW_DECL_REASON.to_string(),
        ]
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let packages = match universe(cx) {
            Ok(u) => u,
            Err(why) => return unproven(&why),
        };
        if packages.len() < UNIVERSE_FLOOR {
            return unproven(&format!(
                "only {} package name(s) were resolved from {ROOT_MANIFEST} and {LOCKFILE} (floor \
                 {UNIVERSE_FLOOR}). A universe that collapsed makes every live selector in the tree \
                 look dead, which is a defect in this gate reported as a defect in the tree.",
                packages.len()
            ));
        }
        let files = match covered(cx) {
            Ok(f) => f,
            Err(why) => return unproven(&why),
        };
        let (sites, decls) = scan(&files);
        let prose = files.iter().filter(|f| f.reader == Reader::Prose).count();
        let read = files.len() - prose;
        let covered_paths: BTreeSet<&str> = files
            .iter()
            .filter(|f| f.reader != Reader::Prose)
            .map(|f| f.rel.as_str())
            .collect();
        // KEYED ON (PACKAGE, FILE). A declaration excuses its package in the file it names and
        // nowhere else; a selector of the same dead name in another file is that file's defect.
        let declared: BTreeSet<(&str, &str)> = decls
            .iter()
            .map(|(_, _, d)| (d.pkg.as_str(), d.file.as_str()))
            .collect();
        let selected: BTreeSet<&str> = sites.iter().map(|s| s.pkg.as_str()).collect();
        let selected_in: BTreeSet<(&str, &str)> = sites
            .iter()
            .map(|s| (s.pkg.as_str(), s.file.as_str()))
            .collect();

        let mut rows = vec![Row::pass(
            ROW_UNIVERSE,
            "the workspace manifests and the lockfile resolved a package universe",
            format!(
                "{} resolvable package name(s) (floor {UNIVERSE_FLOOR}), from {ROOT_MANIFEST} and \
                 {LOCKFILE}",
                packages.len()
            ),
        )];

        rows.push(if sites.len() < SITE_FLOOR {
            Row::fail(
                ROW_SITE_FLOOR,
                "the selector scan collapsed below its discovery floor",
                format!(
                    "only {} selector site(s) were found across {read} read file(s) under \
                     {ROOTS:?} ({prose} Markdown \
                     file(s) walked and not read; floor {SITE_FLOOR}). An empty scan set is the \
                     one state in which 'every selector resolves' is true and means nothing.",
                    sites.len(),
                ),
            )
        } else {
            Row::pass(
                ROW_SITE_FLOOR,
                "enough selector sites were discovered for the check to mean something",
                format!(
                    "{} site(s) across {read} read file(s) under {ROOTS:?}, \
                     {prose} Markdown file(s) walked and not read \
                     (floor {SITE_FLOOR})",
                    sites.len(),
                ),
            )
        });

        // RESOLVES — in the universe, or declared FOR THIS FILE. The declaration's own validity is
        // rules 4-6; a stale declaration still discharges rule 3 in its own file, so exactly one
        // row goes red per defect.
        let dead: Vec<&Site> = sites
            .iter()
            .filter(|s| {
                !packages.contains(&s.pkg) && !declared.contains(&(s.pkg.as_str(), s.file.as_str()))
            })
            .collect();
        rows.push(if dead.is_empty() {
            Row::pass(
                ROW_RESOLVES,
                "every cargo package selector names a package this workspace resolves",
                format!(
                    "{} site(s), {} distinct package(s), {} declared exception(s)",
                    sites.len(),
                    selected.len(),
                    declared.len()
                ),
            )
        } else {
            Row::fail(
                ROW_RESOLVES,
                "a cargo package selector names a package that is not in this workspace",
                format!(
                    "{} — `cargo … -p <gone>` does not select nothing, it FAILS: `package ID \
                     specification '<gone>' did not match any packages`. Where the check's pass \
                     condition is a non-zero exit (cargo xtask txn-fence) that failure reads as a \
                     pass, and where it is a test filter it selects zero tests and exits 0. \
                     Repoint the selector, or write a `{DECL_HASH} <pkg>{SEP}<file>{SEP}<reason>` \
                     line beside it, naming THAT file: a declaration excuses only the file it \
                     names.",
                    dead.iter()
                        .map(|s| s.cite())
                        .collect::<Vec<_>>()
                        .join(" | ")
                ),
            )
        });

        let mut unused = Vec::new();
        let mut needless = Vec::new();
        let mut bad_file = Vec::new();
        let mut thin = Vec::new();
        for (rel, line, d) in &decls {
            // A declaration naming a file this gate does not read can excuse nothing and can never
            // be live: that is ONE defect, and rule 5 alone reports it.
            if !covered_paths.contains(d.file.as_str()) {
                bad_file.push(format!("{rel}:{line} `{}` names `{}`", d.pkg, d.file));
            } else if !selected_in.contains(&(d.pkg.as_str(), d.file.as_str())) {
                unused.push(format!("{rel}:{line} `{}` for `{}`", d.pkg, d.file));
            } else if packages.contains(&d.pkg) {
                needless.push(format!("{rel}:{line} `{}`", d.pkg));
            }
            if d.reason.chars().count() < MIN_REASON {
                thin.push(format!(
                    "{rel}:{line} `{}` ({} char reason)",
                    d.pkg,
                    d.reason.chars().count()
                ));
            }
        }

        rows.push(if unused.is_empty() && needless.is_empty() {
            Row::pass(
                ROW_DECL_LIVE,
                "every declared exception names a selector that is still there and still unresolvable",
                format!("{} declaration(s)", decls.len()),
            )
        } else {
            let mut detail = String::new();
            if !unused.is_empty() {
                detail.push_str(&format!(
                    "the file a declaration names does not select its package: {} — a stale \
                     exemption outlives the site it excused and then silently excuses the next \
                     selector to take the name; a selector of that name in some OTHER file is not \
                     the site it was written for. ",
                    unused.join(", ")
                ));
            }
            if !needless.is_empty() {
                detail.push_str(&format!(
                    "{} resolves fine now and needs no exemption; leaving one hides the day it \
                     stops resolving again.",
                    needless.join(", ")
                ));
            }
            Row::fail(
                ROW_DECL_LIVE,
                "a declared exception names a selector that is not there to excuse",
                detail.trim_end().to_string(),
            )
        });

        rows.push(if bad_file.is_empty() {
            Row::pass(
                ROW_DECL_FILE,
                "every declared exception names a file this gate covers",
                format!("{} covered file(s)", files.len()),
            )
        } else {
            Row::fail(
                ROW_DECL_FILE,
                "a declared exception names a file this gate does not cover",
                format!(
                    "{} — a claim pointing at a path that was renamed away is a claim nobody can \
                     check. The file must be one of the read files under {ROOTS:?}.",
                    bad_file.join(" | ")
                ),
            )
        });

        rows.push(if thin.is_empty() {
            Row::pass(
                ROW_DECL_REASON,
                "every declared exception carries a reason",
                format!(
                    "{} declaration(s), minimum {MIN_REASON} characters",
                    decls.len()
                ),
            )
        } else {
            Row::fail(
                ROW_DECL_REASON,
                "a declared exception carries no reason worth the name",
                format!(
                    "{} — minimum {MIN_REASON}. An exemption without a reason becomes permanent by \
                     accident.",
                    thin.join(" | ")
                ),
            )
        });

        Verdict::of(rows)
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();
        report.push(prove_green(
            cx,
            self,
            "every cargo package selector in this tree names a package it still resolves",
            &self.owed().iter().map(String::as_str).collect::<Vec<_>>(),
        ));
        for plant in plants(cx) {
            report.push(plant.case(cx, self));
        }
        report
    }
}

// ---------------------------------------------------------------------------------------------
// the plants
// ---------------------------------------------------------------------------------------------

struct Plant {
    label: &'static str,
    rule: &'static str,
    naming: Vec<String>,
    overlay: Option<Overlay>,
}

impl Plant {
    fn case<'a>(self, cx: &'a Ctx, gate: &'a dyn Gate) -> crate::gates::CasePlan<'a> {
        let Some(overlay) = self.overlay else {
            // NOTHING TO PLANT is a visible, counted case — never a silent green.
            return Case {
                name: self.label.to_string(),
                covers: vec![self.rule.to_string()],
                expected: Expect::Red {
                    naming: self.naming.clone(),
                },
                got: Expect::Skipped,
            }
            .into();
        };
        let naming: Vec<&str> = self.naming.iter().map(String::as_str).collect();
        prove_rows_red(cx, gate, self.label, &[self.rule], overlay, &naming)
    }
}

/// The package names planted into a real covered file — deliberately ones no manifest, lockfile,
/// workflow or script in this tree mentions.
const PLANTED_DEAD: &str = "busbar-selftest-no-such-package";
const PLANTED_EXCUSED: &str = "busbar-selftest-excused-package";
const PLANTED_NEVER: &str = "busbar-selftest-never-selected";
/// The dead name the FILE-SCOPE plants declare in one script and select in another.
const PLANTED_SCOPED: &str = "busbar-selftest-scoped-package";
/// One dead name per file shape the walk must open beyond `.yml`, `.sh`, qa `.toml` and xtask `.rs`:
/// a `.yaml` composite action, a python script, a Makefile and a JSON pipeline `run` value.
const PLANTED_YAML: &str = "busbar-selftest-yaml-action-package";
const PLANTED_PY: &str = "busbar-selftest-python-package";
const PLANTED_MAKE: &str = "busbar-selftest-makefile-package";
const PLANTED_JSON: &str = "busbar-selftest-json-run-package";
/// One dead name per root the walk gained: `.ci`, `bin`, `.githooks`, and the Rust ARRAY spelling
/// of a cargo command (`"-p", "<crate>"` as two argv elements).
const PLANTED_CI: &str = "busbar-selftest-ci-yaml-package";
const PLANTED_BIN: &str = "busbar-selftest-bin-shim-package";
const PLANTED_HOOK: &str = "busbar-selftest-githook-package";
const PLANTED_ARGV: &str = "busbar-selftest-rust-argv-package";
/// A path this gate does not cover, for the stale-file plant.
// qa-names: scripts/deleted-by-this-fixture.sh -- xtask/src/gates/package_selectors.rs -- the stale-declaration plant names a covered script that is not there on purpose; a spelling that resolved would prove nothing
const PLANTED_GONE_FILE: &str = "scripts/deleted-by-this-fixture.sh";
/// A reason long enough to satisfy [`MIN_REASON`], so a plant aimed at one rule cannot redden two.
const PLANTED_REASON: &str = "planted by this gate's own self-test, which is a reason of its own";

/// The covered shell script the plants append to, and its current text. Derived from the walk —
/// never a hard-coded path, because a plant that names a file is a plant that goes Skipped the day
/// the file moves and a Skipped case is a rule nobody proved.
fn plant_target(cx: &Ctx) -> Option<(String, String)> {
    let files = covered(cx).ok()?;
    files
        .into_iter()
        .find(|f| f.rel.starts_with(&format!("{SCRIPT_ROOT}/")) && f.rel.ends_with(".sh"))
        .map(|f| (f.rel, f.text))
}

/// TWO DISTINCT covered shell scripts, for the plants that need a declaration in one file and a
/// selector in another. Derived from the walk for the same reason [`plant_target`] is.
fn plant_pair(cx: &Ctx) -> Option<((String, String), (String, String))> {
    let mut scripts = covered(cx)
        .ok()?
        .into_iter()
        .filter(|f| f.rel.starts_with(&format!("{SCRIPT_ROOT}/")) && f.rel.ends_with(".sh"));
    let a = scripts.next()?;
    let b = scripts.next()?;
    Some(((a.rel, a.text), (b.rel, b.text)))
}

fn plants(cx: &Ctx) -> Vec<Plant> {
    let target = plant_target(cx);
    let pair = plant_pair(cx);

    // AN EXEMPTION IS SCOPED TO ITS OWN FILE. Script A selects the dead name and carries a valid
    // declaration naming A; script B selects the SAME dead name and declares nothing. A's site is
    // excused, B's is not: a declaration keyed on the name alone would silence B too, which is one
    // written exception excusing every other dead selector of that spelling in the tree.
    let scoped = pair.as_ref().map(|((a, a_text), (b, b_text))| {
        let mut ov = Overlay::new();
        ov.set(
            a,
            format!(
                "{a_text}\ncargo build --locked -p {PLANTED_SCOPED}\n\
                 {DECL_HASH} {PLANTED_SCOPED}{SEP}{a}{SEP}{PLANTED_REASON}\n"
            ),
        );
        ov.set(
            b,
            format!("{b_text}\ncargo build --locked -p {PLANTED_SCOPED}\n"),
        );
        ov
    });

    // A DECLARATION WHOSE OWN FILE NO LONGER SELECTS THE NAME. A declares the dead name for A and
    // selects nothing; B selects it and carries its own declaration. Every site is excused, so only
    // the liveness rule can move: A's exemption outlived the site it was written for, and a
    // selector of the same name in some other file is not that site.
    let scoped_stale = pair.as_ref().map(|((a, a_text), (b, b_text))| {
        let mut ov = Overlay::new();
        ov.set(
            a,
            format!("{a_text}\n{DECL_HASH} {PLANTED_SCOPED}{SEP}{a}{SEP}{PLANTED_REASON}\n"),
        );
        ov.set(
            b,
            format!(
                "{b_text}\ncargo build --locked -p {PLANTED_SCOPED}\n\
                 {DECL_HASH} {PLANTED_SCOPED}{SEP}{b}{SEP}{PLANTED_REASON}\n"
            ),
        );
        ov
    });

    // A DEAD SELECTOR IN A FILE SHAPE A FOUR-EXTENSION WALK NEVER OPENED: a composite action spelt
    // `.yaml` under `.github/actions`, a python script that builds an argv list, a Makefile recipe,
    // and the `run` value of a JSON pipeline check. Each is a new file, so the plant proves the walk
    // finds files it was never told about by name.
    let mut wider = Overlay::new();
    wider.set(
        ".github/actions/selftest-plant/action.yaml",
        format!(
            "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: cargo build --locked -p {PLANTED_YAML}\n"
        ),
    );
    wider.set(
        "scripts/selftest_plant.py",
        format!(
            "import subprocess\nsubprocess.run([\"cargo\", \"build\", \"-p\", \"{PLANTED_PY}\"], check=True)\n"
        ),
    );
    wider.set(
        "scripts/selftest-plant/Makefile",
        format!("build:\n\tcargo build --locked -p {PLANTED_MAKE}\n"),
    );
    wider.set(
        "qa/selftest-plant.json",
        format!("{{\n  \"run\": \"set -e; cargo build --locked -p {PLANTED_JSON}\"\n}}\n"),
    );

    // A DEAD SELECTOR IN EACH ROOT THE WALK USED TO MISS: a `.ci` definition, a `bin/` shim, a
    // `.githooks` hook, and a Rust argv ARRAY under `xtask/src` (one element per line, the way
    // rustfmt lays out a long command).
    let mut roots = Overlay::new();
    roots.set(
        ".ci/selftest-plant.yaml",
        format!("check:\n  run: |\n    cargo build --locked -p {PLANTED_CI}\n"),
    );
    roots.set(
        "bin/selftest-plant",
        format!("#!/usr/bin/env bash\ncargo build --locked -p {PLANTED_BIN}\n"),
    );
    roots.set(
        ".githooks/selftest-plant",
        format!("#!/usr/bin/env bash\ncargo test --locked -p {PLANTED_HOOK}\n"),
    );
    roots.set(
        "xtask/src/selftest_plant_argv.rs",
        format!(
            "fn argv() -> [&'static str; 4] {{\n    [\n        \"cargo\",\n        \"build\",\n        \"-p\",\n        \"{PLANTED_ARGV}\",\n    ]\n}}\n"
        ),
    );

    // THE DEFECT THIS GATE IS NAMED FOR, RE-PLANTED: a command selects a package the workspace does
    // not have. This is the shape `cargo xtask txn-fence` carried while reporting a compile fence as
    // holding over a crate that was never compiled.
    let dead = target.as_ref().map(|(rel, text)| {
        let mut ov = Overlay::new();
        ov.set(
            rel,
            format!("{text}\ncargo build --locked -p {PLANTED_DEAD}\n"),
        );
        ov
    });

    // A DECLARATION THAT OUTLIVED THE SELECTOR IT EXCUSED. The file field is real and the reason is
    // long, so only the liveness rule can move.
    let unused_decl = target.as_ref().map(|(rel, text)| {
        let mut ov = Overlay::new();
        ov.set(
            rel,
            format!("{text}\n{DECL_HASH} {PLANTED_NEVER}{SEP}{rel}{SEP}{PLANTED_REASON}\n"),
        );
        ov
    });

    // A DECLARATION POINTING AT A FILE THAT IS NOT COVERED. No selector is planted beside it: a
    // declaration excuses only the file it names, so a selector here would be unexcused and redden
    // rule 3 as well, and the liveness rule leaves an uncovered file to this rule alone.
    let bad_file_decl = target.as_ref().map(|(rel, text)| {
        let mut ov = Overlay::new();
        ov.set(
            rel,
            format!(
                "{text}\n{DECL_HASH} {PLANTED_EXCUSED}{SEP}{PLANTED_GONE_FILE}{SEP}{PLANTED_REASON}\n"
            ),
        );
        ov
    });

    // A DECLARATION WITH A SHRUG FOR A REASON.
    let thin_decl = target.as_ref().map(|(rel, text)| {
        let mut ov = Overlay::new();
        ov.set(
            rel,
            format!(
                "{text}\ncargo build --locked -p {PLANTED_EXCUSED}\n\
                 {DECL_HASH} {PLANTED_EXCUSED}{SEP}{rel}{SEP}because\n"
            ),
        );
        ov
    });

    // THE SCAN THAT MATCHED NOTHING. Every covered file is still THERE and still walked — it is
    // empty, which is exactly what a scanner whose pattern stopped matching reports, and the state
    // in which every other rule here passes vacuously.
    let empty_scan = covered(cx).ok().map(|files| {
        let mut ov = Overlay::new();
        for f in &files {
            ov.set(&f.rel, String::new());
        }
        ov
    });

    // THE ROOT MANIFEST GONE. Everything below rule 1 is UNPROVEN, never passed.
    let mut no_root = Overlay::new();
    no_root.remove(ROOT_MANIFEST);

    let scoped_naming = pair
        .as_ref()
        .map(|(_, (b, _))| vec![format!("{b}:"), PLANTED_SCOPED.to_string()])
        .unwrap_or_else(|| vec![PLANTED_SCOPED.to_string()]);
    let stale_naming = pair
        .as_ref()
        .map(|((a, _), _)| vec![format!("{a}:"), PLANTED_SCOPED.to_string()])
        .unwrap_or_else(|| vec![PLANTED_SCOPED.to_string()]);

    vec![
        Plant {
            label: "a cargo command selects a package this workspace does not have",
            rule: ROW_RESOLVES,
            naming: vec![PLANTED_DEAD.to_string()],
            overlay: dead,
        },
        Plant {
            label: "a declaration in one file does not excuse the same dead selector in another",
            rule: ROW_RESOLVES,
            naming: scoped_naming,
            overlay: scoped,
        },
        Plant {
            label: "a declaration whose own file no longer selects the name is stale",
            rule: ROW_DECL_LIVE,
            naming: stale_naming,
            overlay: scoped_stale,
        },
        Plant {
            label:
                "a dead selector in a .yaml action, a python script, a Makefile or a JSON run value",
            rule: ROW_RESOLVES,
            naming: vec![
                PLANTED_YAML.to_string(),
                PLANTED_PY.to_string(),
                PLANTED_MAKE.to_string(),
                PLANTED_JSON.to_string(),
            ],
            overlay: Some(wider),
        },
        Plant {
            label: "a dead selector in .ci, bin, .githooks or a Rust argv array",
            rule: ROW_RESOLVES,
            naming: vec![
                PLANTED_CI.to_string(),
                PLANTED_BIN.to_string(),
                PLANTED_HOOK.to_string(),
                PLANTED_ARGV.to_string(),
            ],
            overlay: Some(roots),
        },
        Plant {
            label: "a declared exception outlived the selector it excused",
            rule: ROW_DECL_LIVE,
            naming: vec![PLANTED_NEVER.to_string()],
            overlay: unused_decl,
        },
        Plant {
            label: "a declared exception names a file this gate does not cover",
            rule: ROW_DECL_FILE,
            naming: vec![PLANTED_GONE_FILE.to_string()],
            overlay: bad_file_decl,
        },
        Plant {
            label: "a declared exception carries a shrug for a reason",
            rule: ROW_DECL_REASON,
            naming: vec![format!("minimum {MIN_REASON}")],
            overlay: thin_decl,
        },
        Plant {
            label: "the selector scan matched nothing at all",
            rule: ROW_SITE_FLOOR,
            naming: vec![format!("floor {SITE_FLOOR}")],
            overlay: empty_scan,
        },
        Plant {
            label: "the root manifest is unreadable",
            rule: ROW_UNIVERSE,
            naming: vec!["is unreadable".to_string()],
            overlay: Some(no_root),
        },
    ]
}

#[cfg(test)]
#[path = "tests/package_selectors_tests.rs"]
mod tests;
