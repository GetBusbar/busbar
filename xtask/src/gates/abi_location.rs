//! `cargo xtask gate abi-location` — EVERY ABI SHAPE IS DEFINED IN ONE PLACE:
//! `crates/busbar-contract/src/abi/`.
//!
//! > "edit one crate to add something to abi and all those plugin kinds then can implement it"
//! > — OWNER, 2026-09-27
//!
//! That sentence is only true while the ABI has exactly one home. A `#[repr(C)]` struct written in
//! the kernel, an `extern "C"` slot body hand-typed in the loader, a version constant minted in a
//! plugin-side crate: each one is a piece of the boundary that the next kind cannot reach by
//! editing `abi/`, because it is not there. This gate names every such piece, file by file.
//!
//! ## WHAT COUNTS AS AN ABI SHAPE
//!
//! * **`repr-c`** — a `#[repr(C …)]` struct, enum or union. `#[repr(u8)]`/`#[repr(transparent)]`
//!   alone are not counted: they fix a discriminant or a wrapper, not a C layout, and the tree uses
//!   them for on-disk frames and newtypes that never meet a plugin.
//! * **`extern-fn`** — an `extern "C"` / `extern "C-unwind"` / `extern "system"` fn DEFINITION: a
//!   slot body a plugin or the host installs into a table. Where the slot's SIGNATURE lives is where
//!   the ABI lives, and a body written outside `abi/` restates it. `extern "C" { … }` import blocks
//!   are not definitions and are not counted.
//! * **`fn-ptr`** — an `extern "C…" fn(…)` pointer TYPE written outside `abi/`: a slot signature
//!   spelled a second time. Keyed by its ordinal in the file (`fn-ptr-1`, …), since a type has no
//!   name of its own and a line number rots.
//! * **`version-const`** — a `const`/`static` whose SCREAMING name has an `ABI` segment
//!   (`STORE_ABI`, `ABI_MINOR`, `UNIT_MAP_ABI`, …), is `POD_VERSION`, or whose type is
//!   `AbiVersion`. `CAPABILITIES`/`REACHABILITY` are not `ABI` segments and are not counted.
//!
//! ## WHERE A SHAPE MAY STILL BE WRITTEN OUTSIDE `abi/`
//!
//! Only as a TEST DOUBLE: under a `tests/` directory, under `benches/` (a bench harness is a test
//! target — it never links into a shipped artifact, and the kernel's host-vtable benches stub two
//! slots to time the real table), or inside `#[cfg(test)]` (via [`crate::scan::test_scope`], the one
//! answer to "is this line test code"). Comments and string literals never count: every match reads
//! the literal- and comment-blanked line.
//!
//! ## THE LEDGER — `qa/abi-location.toml`, DRAIN-ONLY (LAW 9)
//!
//! The gate was armed at the count it measured on the day it landed: one `[[offender]]` row per
//! shape outside `abi/`, keyed `(file, shape, item)` — never a line number. The rows are the work
//! list of the one-ABI kernel-side slot, and the ledger only ever shrinks:
//!
//! * a finding with no row is a NEW offender and reds its shape row (`abi-location:repr-c`,
//!   `:extern-fn`, `:version-const`) — the fix is to define it in `abi/`, not to add a row;
//! * a row with no finding is STALE and reds `abi-location:ledger` — a drain strikes its row in the
//!   SAME commit, so the count on record is always the count in the tree.
//!
//! `[[not_abi]]` names the rare `extern "C"` fn that is NOT a plugin/host slot (an `atexit(3)`
//! callback), each with a `why`; a stale one is red on the ledger row like any other.
//!
//! ## EXTERNAL PLUGIN CHECKOUTS
//!
//! Every plugin `plugins.yaml` registers is looked for as a local clone under `[external].root`
//! (default `..`, the sibling-checkout convention `release-check.sh` and qa-gate use), by its `repo`
//! name or that name without its `busbar-` prefix. A clone that exists is scanned by the same rules
//! (its `tests/`, `benches/`, `target/` skipped) and held to the ledger's rows that carry
//! `repo = "<repo>"`; one that does not exist is SKIPPED AND NAMED in the row's detail — never a
//! silent green. CI checks out no siblings, so there the row says exactly that.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::ctx::{Ctx, Overlay, WalkSpec};
use crate::gates::{prove_green, prove_rows_red, Gate, Report};
use crate::ledger::{Row, Verdict};
use crate::scan::{self, ScopeLine};

pub const ROW_REPR_C: &str = "abi-location:repr-c";
pub const ROW_EXTERN: &str = "abi-location:extern-fn";
pub const ROW_CONST: &str = "abi-location:version-const";
pub const ROW_LEDGER: &str = "abi-location:ledger";
pub const ROW_EXTERNAL: &str = "abi-location:external-plugins";

pub const LEDGER: &str = "qa/abi-location.toml";
/// THE ONE HOME. Everything under it is the ABI; nothing outside it may define a piece of it.
pub const ONE_HOME: &str = "crates/busbar-contract/src/abi/";

/// The workspace scan's floor: the tree holds well over a thousand Rust files, and a scan that saw
/// a fraction of them has gone blind rather than found a clean tree.
const MIN_FILES: usize = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Shape {
    ReprC,
    ExternFn,
    FnPtr,
    VersionConst,
}

impl Shape {
    fn label(self) -> &'static str {
        match self {
            Shape::ReprC => "repr-c",
            Shape::ExternFn => "extern-fn",
            Shape::FnPtr => "fn-ptr",
            Shape::VersionConst => "version-const",
        }
    }

    fn parse(s: &str) -> Option<Shape> {
        [
            Shape::ReprC,
            Shape::ExternFn,
            Shape::FnPtr,
            Shape::VersionConst,
        ]
        .into_iter()
        .find(|k| k.label() == s)
    }

    fn row(self) -> &'static str {
        match self {
            Shape::ReprC => ROW_REPR_C,
            Shape::ExternFn | Shape::FnPtr => ROW_EXTERN,
            Shape::VersionConst => ROW_CONST,
        }
    }
}

/// One shape found outside `abi/`.
#[derive(Debug, Clone)]
struct Finding {
    /// Empty for the workspace; the `plugins.yaml` repo name for an external checkout.
    repo: String,
    file: String,
    line: usize,
    shape: Shape,
    item: String,
}

impl Finding {
    fn key(&self) -> Key {
        (
            self.repo.clone(),
            self.file.clone(),
            self.shape,
            self.item.clone(),
        )
    }

    fn describe(&self) -> String {
        let at = if self.repo.is_empty() {
            format!("{}:{}", self.file, self.line)
        } else {
            format!("{}:{}:{}", self.repo, self.file, self.line)
        };
        format!("{} {at} {}", self.shape.label(), self.item)
    }
}

type Key = (String, String, Shape, String);

fn describe_key(k: &Key) -> String {
    let at = if k.0.is_empty() {
        k.1.clone()
    } else {
        format!("{}:{}", k.0, k.1)
    };
    format!("{} {at} {}", k.2.label(), k.3)
}

// ── THE SCANNER ─────────────────────────────────────────────────────────────────────────────────

/// Is `rel` a place a test double may live? `tests/` or `benches/` anywhere in the path.
fn is_test_path(rel: &str) -> bool {
    let p = format!("/{rel}");
    p.contains("/tests/") || p.contains("/benches/")
}

/// Every ABI shape in one file's PRODUCTION lines.
fn scan_file(repo: &str, rel: &str, text: &str) -> Vec<Finding> {
    let lines = scan::test_scope(text);
    let mut out = Vec::new();
    let mut fn_ptrs = 0usize;
    for (idx, sl) in lines.iter().enumerate() {
        if sl.gated || sl.is_comment {
            continue;
        }
        let counted = sl.counted.as_str();
        let mut push = |shape: Shape, item: String| {
            out.push(Finding {
                repo: repo.to_string(),
                file: rel.to_string(),
                line: sl.no,
                shape,
                item,
            })
        };
        if is_repr_c(counted) {
            push(Shape::ReprC, item_after(&lines, idx));
        }
        for hit in extern_hits(counted, &sl.raw) {
            match hit {
                Some(name) => push(Shape::ExternFn, name),
                None => {
                    fn_ptrs += 1;
                    push(Shape::FnPtr, format!("fn-ptr-{fn_ptrs}"));
                }
            }
        }
        if let Some(name) = version_const(counted) {
            push(Shape::VersionConst, name);
        }
    }
    out
}

/// A line that IS a `#[repr(…)]` attribute naming `C` among its representation hints.
fn is_repr_c(counted: &str) -> bool {
    let t = counted.trim_start();
    let Some(rest) = t.strip_prefix("#[repr(") else {
        return false;
    };
    let inner = rest.split(')').next().unwrap_or("");
    inner.split(',').any(|h| h.trim() == "C")
}

/// The name of the struct/enum/union a `#[repr(C)]` attribute applies to: the first
/// `struct|enum|union IDENT` in the next few lines (doc comments and further attributes between).
fn item_after(lines: &[ScopeLine], idx: usize) -> String {
    for sl in lines.iter().skip(idx).take(16) {
        let words = idents(&sl.counted);
        for w in words.windows(2) {
            if matches!(w[0].as_str(), "struct" | "enum" | "union") {
                return w[1].clone();
            }
        }
    }
    "?".to_string()
}

/// The identifier-shaped words of a line, in order.
fn idents(s: &str) -> Vec<String> {
    s.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '$'))
        .filter(|w| !w.is_empty())
        .map(str::to_string)
        .collect()
}

/// Every `extern "C…" fn` on a line: `Some(name)` for a definition, `None` for a pointer type.
///
/// Read off the BLANKED line so a comment or a string holding the words cannot match; the ABI
/// string itself is a literal, so its contents are read back from the raw line at the same
/// position (the blanker keeps every character in place).
fn extern_hits(counted: &str, raw: &str) -> Vec<Option<String>> {
    let c: Vec<char> = counted.chars().collect();
    let r: Vec<char> = raw.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 6 <= c.len() {
        if !word_at(&c, i, "extern") {
            i += 1;
            continue;
        }
        let mut j = skip_ws(&c, i + 6);
        if c.get(j) != Some(&'"') {
            i += 6;
            continue;
        }
        let open = j;
        j += 1;
        while j < c.len() && c[j] != '"' {
            j += 1;
        }
        if j >= c.len() {
            break;
        }
        let abi: String = if r.len() == c.len() {
            r[open + 1..j].iter().collect()
        } else {
            String::new()
        };
        let k = skip_ws(&c, j + 1);
        i = j + 1;
        if !matches!(abi.as_str(), "C" | "C-unwind" | "system" | "system-unwind") {
            continue;
        }
        if !word_at(&c, k, "fn") {
            // `extern "C" { … }` — an import block, not a slot.
            continue;
        }
        let n = skip_ws(&c, k + 2);
        if c.get(n) == Some(&'(') {
            out.push(None);
        } else {
            let name: String = c[n..]
                .iter()
                .take_while(|ch| ch.is_ascii_alphanumeric() || **ch == '_' || **ch == '$')
                .collect();
            out.push(Some(if name.is_empty() { "?".into() } else { name }));
        }
    }
    out
}

fn skip_ws(c: &[char], mut i: usize) -> usize {
    while i < c.len() && c[i].is_whitespace() {
        i += 1;
    }
    i
}

/// `word` at `i`, bounded by non-identifier characters on both sides.
fn word_at(c: &[char], i: usize, word: &str) -> bool {
    let w: Vec<char> = word.chars().collect();
    if i + w.len() > c.len() || c[i..i + w.len()] != w[..] {
        return false;
    }
    let ident = |ch: char| ch.is_ascii_alphanumeric() || ch == '_';
    let before = i == 0 || !ident(c[i - 1]);
    let after = i + w.len() == c.len() || !ident(c[i + w.len()]);
    before && after
}

/// The name of an ABI version constant declared on this line, if it declares one.
fn version_const(counted: &str) -> Option<String> {
    let c: Vec<char> = counted.chars().collect();
    let mut i = 0;
    while i < c.len() {
        let kw = if word_at(&c, i, "const") {
            5
        } else if word_at(&c, i, "static") {
            6
        } else {
            i += 1;
            continue;
        };
        let mut j = skip_ws(&c, i + kw);
        if word_at(&c, j, "mut") {
            j = skip_ws(&c, j + 3);
        }
        let name: String = c[j..]
            .iter()
            .take_while(|ch| ch.is_ascii_alphanumeric() || **ch == '_')
            .collect();
        let after = skip_ws(&c, j + name.chars().count());
        i += kw;
        if name.is_empty() || c.get(after) != Some(&':') || c.get(after + 1) == Some(&':') {
            continue;
        }
        if !name.chars().any(|ch| ch.is_ascii_uppercase())
            || name.chars().any(|ch| ch.is_ascii_lowercase())
        {
            continue;
        }
        let ty: String = c[after + 1..]
            .iter()
            .take_while(|ch| **ch != '=' && **ch != ';')
            .collect();
        let abi_segment = name.split('_').any(|seg| seg == "ABI");
        let pod = name == "POD_VERSION" || name.ends_with("_POD_VERSION");
        let typed = idents(&ty).iter().any(|w| w == "AbiVersion");
        if abi_segment || pod || typed {
            return Some(name);
        }
    }
    None
}

// ── THE LEDGER ──────────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
struct Ledger {
    offenders: Vec<Key>,
    /// `(file, item)` of an `extern "C"` fn that is not a plugin/host slot.
    not_abi: Vec<(String, String)>,
    external_root: String,
    errors: Vec<String>,
}

fn load_ledger(cx: &Ctx) -> Ledger {
    let text = match cx.read(LEDGER) {
        Ok(t) => t,
        Err(e) => {
            return Ledger {
                external_root: "..".into(),
                errors: vec![format!(
                    "{LEDGER} is unreadable ({e}); every shape outside {ONE_HOME} is therefore NEW"
                )],
                ..Ledger::default()
            }
        }
    };
    let doc = crate::toml_lite::parse_text(&text);
    let mut led = Ledger {
        external_root: doc
            .table("external")
            .get_one("root")
            .unwrap_or("..")
            .to_string(),
        ..Ledger::default()
    };
    for (n, t) in doc.array_table("offender").iter().enumerate() {
        let file = t.get_one("file").unwrap_or("").to_string();
        let item = t.get_one("item").unwrap_or("").to_string();
        let repo = t.get_one("repo").unwrap_or("").to_string();
        let shape = t.get_one("shape").unwrap_or("");
        match Shape::parse(shape) {
            Some(s) if !file.is_empty() && !item.is_empty() => {
                led.offenders.push((repo, file, s, item))
            }
            _ => led.errors.push(format!(
                "[[offender]] #{}: needs file, item and a shape of repr-c|extern-fn|fn-ptr|version-const (got shape `{shape}`, file `{file}`, item `{item}`)",
                n + 1
            )),
        }
    }
    for (n, t) in doc.array_table("not_abi").iter().enumerate() {
        let file = t.get_one("file").unwrap_or("").to_string();
        let item = t.get_one("item").unwrap_or("").to_string();
        let why = t.get_one("why").unwrap_or("").trim().to_string();
        if file.is_empty() || item.is_empty() || why.is_empty() {
            led.errors.push(format!(
                "[[not_abi]] #{}: needs file, item and a `why` (an extern \"C\" fn is a slot unless a reason says otherwise)",
                n + 1
            ));
        } else {
            led.not_abi.push((file, item));
        }
    }
    led
}

/// `want` minus `have`, as multisets.
fn minus(want: &[Key], have: &[Key]) -> Vec<Key> {
    let mut left: BTreeMap<&Key, usize> = BTreeMap::new();
    for k in have {
        *left.entry(k).or_default() += 1;
    }
    let mut out = Vec::new();
    for k in want {
        match left.get_mut(k) {
            Some(n) if *n > 0 => *n -= 1,
            _ => out.push(k.clone()),
        }
    }
    out
}

// ── EXTERNAL CHECKOUTS ──────────────────────────────────────────────────────────────────────────

struct External {
    findings: Vec<Finding>,
    scanned: Vec<String>,
    absent: Vec<String>,
    errors: Vec<String>,
    root: PathBuf,
}

fn scan_external(cx: &Ctx, root_decl: &str) -> External {
    let root = {
        let p = Path::new(root_decl);
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            cx.root().join(p)
        }
    };
    let mut ext = External {
        findings: Vec::new(),
        scanned: Vec::new(),
        absent: Vec::new(),
        errors: Vec::new(),
        root: root.clone(),
    };
    let fleet = match crate::fleet::registry::load(cx) {
        Ok(f) => f,
        Err(e) => {
            ext.errors.push(format!(
                "plugins.yaml could not be read as the plugin registry: {e}"
            ));
            return ext;
        }
    };
    for p in &fleet.plugins {
        let candidates = [
            p.repo.clone(),
            p.repo
                .strip_prefix("busbar-")
                .unwrap_or(&p.repo)
                .to_string(),
        ];
        let Some(dir) = candidates
            .iter()
            .map(|c| root.join(c))
            .find(|d| d.join("Cargo.toml").is_file())
        else {
            ext.absent.push(p.repo.clone());
            continue;
        };
        let mut files = Vec::new();
        collect_rs(&dir, &dir, &mut files);
        files.sort();
        ext.scanned.push(format!(
            "{} ({} files, {})",
            p.repo,
            files.len(),
            dir.display()
        ));
        for rel in files {
            if is_test_path(&rel) {
                continue;
            }
            match std::fs::read_to_string(dir.join(&rel)) {
                Ok(text) => ext.findings.extend(scan_file(&p.repo, &rel, &text)),
                Err(e) => ext.errors.push(format!("{}:{rel}: {e}", p.repo)),
            }
        }
    }
    ext
}

/// Every `.rs` under `dir`, relative, skipping build output, VCS and hidden directories.
fn collect_rs(base: &Path, dir: &Path, out: &mut Vec<String>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let path = e.path();
        let name = e.file_name().to_string_lossy().to_string();
        if path.is_dir() {
            if name == "target" || name.starts_with('.') || name == "node_modules" {
                continue;
            }
            collect_rs(base, &path, out);
        } else if name.ends_with(".rs") {
            if let Ok(rel) = path.strip_prefix(base) {
                out.push(rel.to_string_lossy().replace('\\', "/"));
            }
        }
    }
}

// ── THE GATE ────────────────────────────────────────────────────────────────────────────────────

pub struct AbiLocationGate;

impl AbiLocationGate {
    fn workspace_findings(cx: &Ctx) -> Result<Vec<Finding>, String> {
        let files = cx
            .walk(
                &WalkSpec::new(["."])
                    .ext("rs")
                    .exclude(["/target/", "/.fix/", "/.git/"])
                    .min_files(MIN_FILES),
            )
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for f in &files {
            let rel = f.rel_str();
            let rel = rel.strip_prefix("./").unwrap_or(&rel).to_string();
            if rel.starts_with(ONE_HOME) || is_test_path(&rel) {
                continue;
            }
            out.extend(scan_file("", &rel, &f.text));
        }
        Ok(out)
    }
}

impl Gate for AbiLocationGate {
    fn name(&self) -> &'static str {
        "abi-location"
    }

    fn owed(&self) -> Vec<String> {
        [ROW_REPR_C, ROW_EXTERN, ROW_CONST, ROW_LEDGER, ROW_EXTERNAL]
            .iter()
            .map(|s| (*s).to_string())
            .collect()
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let ledger = load_ledger(cx);
        let found = match Self::workspace_findings(cx) {
            Ok(f) => f,
            Err(e) => {
                let why = format!(
                    "the workspace scan did not run ({e}); an unread tree reads exactly like a clean one"
                );
                return Verdict::of(
                    self.owed()
                        .iter()
                        .map(|id| {
                            Row::fail(
                                id.clone(),
                                "the workspace could not be scanned",
                                why.clone(),
                            )
                        })
                        .collect(),
                );
            }
        };

        // The not-a-slot exclusions, each used at most once and each required to still match.
        let mut not_abi_left = ledger.not_abi.clone();
        let found: Vec<Finding> = found
            .into_iter()
            .filter(|f| {
                if f.shape != Shape::ExternFn {
                    return true;
                }
                match not_abi_left
                    .iter()
                    .position(|(file, item)| *file == f.file && *item == f.item)
                {
                    Some(i) => {
                        not_abi_left.remove(i);
                        false
                    }
                    None => true,
                }
            })
            .collect();

        let ws_ledger: Vec<Key> = ledger
            .offenders
            .iter()
            .filter(|k| k.0.is_empty())
            .cloned()
            .collect();
        let keys: Vec<Key> = found.iter().map(Finding::key).collect();
        let new_keys = minus(&keys, &ws_ledger);
        let stale = minus(&ws_ledger, &keys);

        let mut rows = Vec::new();
        for (row, shapes, what) in [
            (ROW_REPR_C, &[Shape::ReprC][..], "#[repr(C)] type"),
            (
                ROW_EXTERN,
                &[Shape::ExternFn, Shape::FnPtr][..],
                "extern \"C\" slot fn or fn-pointer type",
            ),
            (
                ROW_CONST,
                &[Shape::VersionConst][..],
                "ABI version constant",
            ),
        ] {
            let ledgered = ws_ledger.iter().filter(|k| shapes.contains(&k.2)).count();
            // New offenders, described with their line, drawn from the findings themselves.
            let mut pending = new_keys.clone();
            let mut new: Vec<String> = Vec::new();
            for f in found.iter().filter(|f| shapes.contains(&f.shape)) {
                if let Some(i) = pending.iter().position(|k| *k == f.key()) {
                    pending.remove(i);
                    new.push(f.describe());
                }
            }
            if new.is_empty() {
                rows.push(Row::pass(
                    row,
                    format!("no NEW {what} outside {ONE_HOME}"),
                    format!("{ledgered} ledgered in {LEDGER} (drain-only work list), 0 new"),
                ));
            } else {
                rows.push(Row::fail(
                    row,
                    format!("ABI shape outside {ONE_HOME}: {what}"),
                    format!(
                        "{} new: {} — define it in {ONE_HOME} (one place for every ABI shape, OWNER 2026-09-27); {ledgered} already ledgered",
                        new.len(),
                        new.join(" | ")
                    ),
                ));
            }
            debug_assert!(row == shapes[0].row());
        }

        let mut ledger_problems: Vec<String> = ledger.errors.clone();
        ledger_problems.extend(stale.iter().map(|k| {
            format!(
                "STALE row (no such shape in the tree — strike it in the draining commit): {}",
                describe_key(k)
            )
        }));
        ledger_problems.extend(not_abi_left.iter().map(|(file, item)| {
            format!("STALE [[not_abi]] {file} {item}: no such extern \"C\" fn")
        }));
        if ledger_problems.is_empty() {
            rows.push(Row::pass(
                ROW_LEDGER,
                "every ledger row names a shape still in the tree",
                format!(
                    "{} offender rows ({} workspace), {} not-a-slot exclusions; the count only drains",
                    ledger.offenders.len(),
                    ws_ledger.len(),
                    ledger.not_abi.len()
                ),
            ));
        } else {
            rows.push(Row::fail(
                ROW_LEDGER,
                format!("{LEDGER} does not match the tree"),
                ledger_problems.join(" | "),
            ));
        }

        rows.push(external_row(cx, &ledger));
        Verdict::of(rows)
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();
        report.push(prove_green(
            cx,
            self,
            "the tree matches its ledger: no new ABI shape outside abi/, no stale row",
            &self.owed().iter().map(String::as_str).collect::<Vec<_>>(),
        ));

        // A #[repr(C)] STRUCT IN A KERNEL FILE.
        let kernel = "crates/busbar-kernel/src/lib.rs";
        let mut ov = Overlay::new();
        ov.set(
            kernel,
            format!(
                "{}\n/// planted\n#[repr(C)]\n#[derive(Clone, Copy)]\npub struct PlantedKernelPod {{\n    pub a: u32,\n}}\n",
                cx.read(kernel).unwrap_or_default()
            ),
        );
        report.push(prove_rows_red(
            cx,
            self,
            "a #[repr(C)] struct added to a kernel file is RED",
            &[ROW_REPR_C],
            ov,
            &["PlantedKernelPod", kernel],
        ));

        // AN ABI VERSION CONSTANT IN THE PLUGIN LOADER.
        let loader = "crates/plugin-loader/src/lib.rs";
        let mut ov = Overlay::new();
        ov.set(
            loader,
            format!(
                "{}\npub const PLANTED_ABI_VERSION: u32 = 1;\n",
                cx.read(loader).unwrap_or_default()
            ),
        );
        report.push(prove_rows_red(
            cx,
            self,
            "an ABI version const in plugin-loader is RED",
            &[ROW_CONST],
            ov,
            &["PLANTED_ABI_VERSION"],
        ));

        // AN extern "C" SLOT BODY AND A FN-POINTER TYPE IN THE KERNEL.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-kernel/src/planted_slot.rs",
            "pub extern \"C-unwind\" fn planted_slot(x: u32) -> u32 { x }\n\
             pub type PlantedPtr = Option<unsafe extern \"C\" fn(u32) -> u32>;\n",
        );
        report.push(prove_rows_red(
            cx,
            self,
            "an extern \"C\" slot body and a fn-pointer type outside abi/ are RED",
            &[ROW_EXTERN],
            ov,
            &[
                "extern-fn crates/busbar-kernel/src/planted_slot.rs:1 planted_slot",
                "fn-ptr-1",
            ],
        ));

        // TEST DOUBLES: under tests/, and under #[cfg(test)], and in comments/strings — all GREEN.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-kernel/tests/planted_double.rs",
            "#[repr(C)]\npub struct Double { pub a: u32 }\n\
             extern \"C-unwind\" fn double_slot() {}\npub const DOUBLE_ABI: u32 = 1;\n",
        );
        ov.set(
            "crates/busbar-kernel/src/planted_cfg_test.rs",
            "/// A `#[repr(C)]` mention and an `extern \"C\" fn x` in prose.\n\
             pub const NOTE: &str = \"#[repr(C)] extern \\\"C\\\" fn y STORE_ABI\";\n\
             #[cfg(test)]\nmod tests {\n    #[repr(C)]\n    pub struct Double { pub a: u32 }\n    \
             extern \"C\" fn double_slot() {}\n    const T_ABI: u32 = 1;\n}\n\
             #[cfg(test)]\nconst ALSO_ABI: u32 = 2;\n",
        );
        report.push(prove_green(
            &cx.with_overlay(ov),
            self,
            "a repr(C) test double under tests/ or #[cfg(test)], and ABI words in prose, are GREEN",
            &[ROW_REPR_C, ROW_EXTERN, ROW_CONST],
        ));

        // THE LEDGER CANNOT OUTLIVE ITS DEBT: a row naming a shape the tree does not hold is RED.
        let ledger = cx.read(LEDGER).unwrap_or_default();
        let mut ov = Overlay::new();
        ov.set(
            LEDGER,
            format!(
                "{ledger}\n[[offender]]\nfile = \"crates/busbar-kernel/src/lib.rs\"\nshape = \"repr-c\"\nitem = \"DrainedLongAgo\"\n"
            ),
        );
        report.push(prove_rows_red(
            cx,
            self,
            "a ledger row whose shape was drained (and not struck) is RED",
            &[ROW_LEDGER],
            ov,
            &["DrainedLongAgo"],
        ));

        // AN EXTERNAL CHECKOUT is scanned when present: a fake clone of a registered plugin, with a
        // hand-written slot outside the SDK, under a scratch root the ledger is pointed at.
        let ext_root = cx.scratch().join("abi-location-external");
        let plugin = crate::fleet::registry::load(cx)
            .ok()
            .and_then(|f| f.plugins.first().map(|p| p.repo.clone()))
            .unwrap_or_else(|| "busbar-store-mysql".into());
        let clone = ext_root.join(&plugin);
        let planted = std::fs::create_dir_all(clone.join("src").join("tests"))
            .and_then(|()| std::fs::write(clone.join("Cargo.toml"), "[package]\nname = \"x\"\n"))
            .and_then(|()| {
                std::fs::write(
                    clone.join("src/lib.rs"),
                    "#[no_mangle]\npub extern \"C\" fn busbar_call() {}\n",
                )
            })
            .and_then(|()| {
                std::fs::write(
                    clone.join("src/tests/double.rs"),
                    "#[repr(C)]\npub struct Double { pub a: u32 }\n",
                )
            });
        let mut ov = Overlay::new();
        ov.set(
            LEDGER,
            ledger.replace(
                "root = \"..\"",
                &format!("root = \"{}\"", ext_root.display()),
            ),
        );
        match planted {
            Ok(()) => report.push(prove_rows_red(
                cx,
                self,
                "a hand-written slot in a local clone of a registered plugin is RED",
                &[ROW_EXTERNAL],
                ov,
                &[&format!("{plugin}:src/lib.rs:2 busbar_call")],
            )),
            Err(e) => report.push(prove_rows_red(
                cx,
                self,
                format!(
                    "external plant could not be written under {}: {e}",
                    ext_root.display()
                ),
                &[ROW_EXTERNAL],
                ov,
                &["unplantable"],
            )),
        }

        report
    }
}

fn external_row(cx: &Ctx, ledger: &Ledger) -> Row {
    let ext = scan_external(cx, &ledger.external_root);
    let present: Vec<&str> = ext
        .scanned
        .iter()
        .map(|s| s.split(' ').next().unwrap_or(""))
        .collect();
    let ext_ledger: Vec<Key> = ledger
        .offenders
        .iter()
        .filter(|k| !k.0.is_empty() && present.contains(&k.0.as_str()))
        .cloned()
        .collect();
    let keys: Vec<Key> = ext.findings.iter().map(Finding::key).collect();
    let new = minus(&keys, &ext_ledger);
    let stale = minus(&ext_ledger, &keys);

    let mut problems = ext.errors.clone();
    let mut pending = new.clone();
    for f in &ext.findings {
        if let Some(i) = pending.iter().position(|k| *k == f.key()) {
            pending.remove(i);
            problems.push(format!("NEW {}", f.describe()));
        }
    }
    problems.extend(
        stale
            .iter()
            .map(|k| format!("STALE row {}", describe_key(k))),
    );
    let skipped = if ext.absent.is_empty() {
        String::new()
    } else {
        format!(
            "; SKIPPED (no local clone under {}): {}",
            ext.root.display(),
            ext.absent.join(", ")
        )
    };
    if problems.is_empty() {
        Row::pass(
            ROW_EXTERNAL,
            "every locally-cloned registered plugin defines no ABI shape of its own",
            format!(
                "scanned {}: {}{skipped}",
                ext.scanned.len(),
                if ext.scanned.is_empty() {
                    "none".to_string()
                } else {
                    ext.scanned.join(", ")
                }
            ),
        )
    } else {
        Row::fail(
            ROW_EXTERNAL,
            "a registered plugin's local clone defines an ABI shape outside busbar-contract's abi/",
            format!("{}{skipped}", problems.join(" | ")),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extern_hits_tell_a_definition_from_a_pointer_and_an_import() {
        let l = "pub(crate) extern \"C-unwind\" fn slot(p: Option<unsafe extern \"C\" fn(u8)>) {}";
        let counted = scan::blank_literals(l);
        assert_eq!(
            extern_hits(&counted, l),
            vec![Some("slot".to_string()), None]
        );
        let imp = "extern \"C\" { fn atexit(cb: u8); }";
        assert!(extern_hits(&scan::blank_literals(imp), imp).is_empty());
        let rust = "extern \"Rust\" fn f() {}";
        assert!(extern_hits(&scan::blank_literals(rust), rust).is_empty());
    }

    #[test]
    fn version_consts_are_abi_segments_not_substrings() {
        assert_eq!(
            version_const("pub const STORE_ABI_FLOOR: u32 = 2;"),
            Some("STORE_ABI_FLOOR".into())
        );
        assert_eq!(
            version_const("pub const TRANSPORT: super::AbiVersion = x;"),
            Some("TRANSPORT".into())
        );
        assert_eq!(
            version_const("pub const POD_VERSION: u16 = 3;"),
            Some("POD_VERSION".into())
        );
        assert_eq!(
            version_const("pub const ROW_REACHABILITY: &str = \"\";"),
            None
        );
        assert_eq!(version_const("static ALL_CAPABILITIES: u8 = 1;"), None);
        assert_eq!(version_const("pub const fn abi() -> u32 { 1 }"), None);
    }

    #[test]
    fn repr_c_needs_the_c_hint() {
        assert!(is_repr_c("#[repr(C)]"));
        assert!(is_repr_c("  #[repr(C, u8)]"));
        assert!(!is_repr_c("#[repr(u8)]"));
        assert!(!is_repr_c("#[repr(transparent)]"));
    }
}
