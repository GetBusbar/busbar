//! `cargo xtask gate reachability` — EVERY PLANE IN THE LOCKED ROSTER IS SERVED BY A UNIT PATH THE
//! COMPOSITION ROOT ACTUALLY REACHES FROM `fn main()`.
//!
//! ## The failure this exists for, and why no behavioural witness could have caught it
//!
//! Three money faults were found in `crates/busbar/src/root/units_a2a.rs` on 2026-09-22: an accrual
//! in the wrong denomination, a hardcoded `rate_card_version: 0`, and a `UnitKey::new(0)` that
//! collided every audit record onto one key. The honest answer to "which corpus cell or rig leg
//! would have caught them" was **none, and none could have** — because the module does not run.
//! `A2aUnits::new` has exactly one call site in the workspace and it is under `#[cfg(test)]`.
//! **There is no behaviour to witness, so no behavioural witness can exist.** A gate is the only
//! instrument that can see this class, because the thing it measures is the ABSENCE of a caller
//! rather than the value of an answer.
//!
//! It was also the second time in one day that unreachability was mistaken for something else: two
//! findings were escalated as live vulnerabilities and were not, and this one was pre-wired
//! scaffolding that read as live. Both confusions are about the same missing fact, written down
//! nowhere: **does this code run?**
//!
//! ## WHAT "REACHABLE" MEANS HERE, AND WHY IT CAN ONLY MEAN THAT
//!
//! `crates/busbar/Cargo.toml` declares ONE `[[bin]]` and **no `[lib]`**. There is no
//! `src/lib.rs`, so nothing outside the crate can link `busbar::root::…` — not another crate, and
//! not even the crate's own integration tests under `crates/busbar/tests/`, which is why
//! `tests/plane_meter_seam_reachability.rs` resorts to scanning source text. For this crate,
//! therefore, **"reachable" can only mean "reached from `fn main()` in `crates/busbar/src/main.rs`"**,
//! and the whole scan is scoped to `crates/busbar/src/**` on exactly that ground.
//!
//! That is not an assumption the gate makes quietly: `reachability:scan-floor` READS THE MANIFEST
//! and refuses the tree if a `[lib]` ever appears, because the day it does, a construction site
//! outside this crate becomes possible and every answer below would be scoped wrong.
//!
//! ## REACHABILITY IS PROVEN, NEVER ASSERTED BY PROSE — and this tree is why
//!
//! Three doc comments in this very crate (`main.rs`'s `install()` note, `gauntlet_install.rs`,
//! `gauntlet_kernel.rs`) describe a function as DORMANT and claim it "registers ZERO planes", while
//! its body unconditionally flips mcp/a2a/llm/streaming onto the unified kernel loop. And
//! `root/vocabulary.rs` is the opposite failure: a module nothing reaches, whose doc reads as live
//! infrastructure. **A gate that trusts a comment inherits the lie**, so every verdict here is
//! computed from comment-stripped, test-stripped code and a graph walk from `fn main()`. Nothing in
//! this gate reads a doc comment for anything but the reader's benefit.
//!
//! ## What it asserts, per plane of the #48 roster (llm, mcp, a2a, streaming, decision)
//!
//! * `reachability:registered:<plane>` — the COMPOSITION ROOT registers it. The evidence is narrow
//!   on purpose: a registration token in the BODY of `register_planes()` in
//!   `crates/busbar/src/main.rs` or of `plane_claims()` in `crates/busbar/src/root/registry.rs`,
//!   read off comment-stripped code. A plane named in a doc comment is not a plane that is served.
//! * `reachability:unit-path:<plane>` — its `root/units_<plane>.rs` UNIT PATH is CONSTRUCTED IN A
//!   FUNCTION REACHED FROM `fn main()`. The unit path is derived, never listed: it is whatever type
//!   the module writes `impl … Units for T` for — the kernel's ten-step unit trait. **A
//!   `units_<plane>.rs` that declares no such type at all is RED too**, not a quiet pass: a module
//!   named for a unit path, carrying money steps, that implements no unit is the same finding in
//!   another spelling (`units_mcp.rs` is 1 884 lines of exactly that).
//! * `reachability:root-reach:<plane>` — the MODULE is reached from `fn main()` at all. It is kept
//!   separate from the row above for a reason: `units_a2a` PASSES it (main calls `scope_policy`, a
//!   boot-time table builder that constructs no unit) and FAILS the unit-path row. The two rows
//!   together say the exact true thing.
//!
//! and four rows that keep the gate honest and stop it going stale:
//!
//! * `reachability:root-module` — EVERY non-test module under `crates/busbar/src/root/` is reached
//!   from `fn main()`. This is what catches `money_book.rs` and `vocabulary.rs`, which are not plane
//!   units at all and would otherwise sit outside every row above.
//! * `reachability:roster` — every `root/units_*.rs` on disk maps to a roster plane, so a new
//!   module cannot appear beside the table and be scanned by nothing.
//! * `reachability:stale-declaration` — a declaration whose subject is reached again, or that names
//!   a subject, aspect or file that does not exist. A ledger cannot outlive the debt it tracked.
//! * `reachability:scan-floor` — the manifest, the composition root and the declaration file were
//!   all readable and the two registration sites were found. A gate that could not find its subject
//!   reports that, never zero findings.
//!
//! ## THE LINE BETWEEN "UNREACHABLE" AND "UNREACHABLE AND SAID SO"
//!
//! Some of this code is legitimately pre-wired ahead of a switch-on — `crates/busbar/src/root/mod.rs`
//! says so in prose, in a `#![allow(dead_code)]` whose comment reads *"the root is BUILT before any
//! plane is SWITCHED onto it, so for the length of that window every item here is constructed by its
//! own tests and by nothing else"*. That is a true and reasonable statement and it is also invisible
//! to everything: it is a source comment, it names no module, it carries no expiry, and it was
//! sitting directly above a file with three money bugs in it.
//!
//! So the declaration gets a machine-readable place to live — [`DECLARATIONS`], one `[[dormant]]`
//! row per (subject, aspect), each naming the module, the REASON, and the SWITCH that retires it,
//! exactly the way `qa/construction.toml`'s ceiling raises name both their numbers and their reason.
//! **An UNDECLARED unreachable unit path is RED. A DECLARED one is a tracked row that passes and
//! prints its declaration on every run.** What must never happen again is code shipping in a money
//! path with nobody aware it never runs — and the difference between those two states is exactly
//! whether somebody wrote the sentence down.
//!
//! A declaration is refused if its reason is shorter than [`MIN_REASON`]. A shrug is not a reason.
//!
//! ## WHAT THIS GATE CAN AND CANNOT SEE — stated plainly, because the limits matter
//!
//! It reads SOURCE TEXT. It does not expand macros and it does not resolve types, so:
//!
//! * **A call site reached only through MACRO EXPANSION is invisible to it.** If a `macro_rules!`
//!   body constructs a unit, or a derive generates the only caller, this gate will call that unit
//!   dormant when it is not. That direction is a FALSE RED, which someone reads and answers.
//! * **A `#[path]` include is followed for TEST-SCOPE purposes** (that is how `root/tests/*.rs` are
//!   recognised) **but a module brought in under an unusual `#[path]` outside `crates/busbar/src`
//!   would not be scanned at all.** The scan floor's `[lib]`/manifest check is the guard that keeps
//!   the scope honest; nothing else here can be.
//! * **The item graph keys on SIMPLE NAMES**, so two functions called `new` are one node. That
//!   OVER-approximates reachability — it can call something reached that is not — and the guard
//!   against it turning a dormant unit green is the own-constructor exclusion below: a
//!   `-> Self` body building its own type is never evidence that anything CALLS it. The module
//!   graph, which answers `root-reach` and `root-module`, keys on FILE STEMS, which are unique
//!   under `crates/busbar/src/root/` and carry no such collision.
//! * **`main.rs` is seeded whole**, not just `fn main`'s body. Everything in the composition root's
//!   own file is boot code by construction; drawing the line inside it would make the gate's answer
//!   depend on which helper `main` happens to have been factored into.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::ctx::{Ctx, Overlay, WalkSpec};
use crate::gates::{execute, prove_rows_red_at, Case, Expect, Gate, Report};
use crate::ledger::{Row, Status, Verdict};
use crate::scan::{test_scope, ScopeLine};

/// Where the dormancy declarations live. DATA, not a Rust table: the whole point is that a human
/// writes the sentence and a reviewer reads it in a diff.
pub const DECLARATIONS: &str = "qa/reachability.toml";

/// The per-module construction-site evidence behind whatever this gate is red about, written up
/// once so the agents folding these modules cite it instead of tracing it a third time. Named in
/// the failure details themselves, because the place a reader meets this gate is a red row.
pub const EVIDENCE: &str = "qa/reachability-evidence.md";

/// THE ONE CRATE THIS GATE MEASURES, and the manifest whose shape makes that scope sound.
pub const CRATE_SRC: &str = "crates/busbar/src";
pub const CRATE_MANIFEST: &str = "crates/busbar/Cargo.toml";
/// The composition root's entry point, and its two registration sites.
pub const MAIN_RS: &str = "crates/busbar/src/main.rs";
pub const REGISTRY_RS: &str = "crates/busbar/src/root/registry.rs";
const ROOT_DIR: &str = "crates/busbar/src/root";

/// A declaration shorter than this is a shrug, not a reason. The same figure
/// [`crate::gates::Divergence::MIN_REASON`] holds every other written excuse in this crate to.
pub const MIN_REASON: usize = 40;

const CLEAN: &str = "clean";
const DID_NOT_RUN: &str = "DID NOT RUN";

const GATE: &str = "reachability";

pub const ROW_SCAN_FLOOR: &str = "reachability:scan-floor";
pub const ROW_ROSTER: &str = "reachability:roster";
pub const ROW_STALE: &str = "reachability:stale-declaration";
pub const ROW_ROOT_MODULE: &str = "reachability:root-module";

#[must_use]
pub fn row_registered(plane: &str) -> String {
    format!("{GATE}:registered:{plane}")
}
#[must_use]
pub fn row_unit_path(plane: &str) -> String {
    format!("{GATE}:unit-path:{plane}")
}
#[must_use]
pub fn row_root_reach(plane: &str) -> String {
    format!("{GATE}:root-reach:{plane}")
}

/// The four things a `[[dormant]]` row can be about. Spelled as data because the declaration file
/// names one, and a typo there must be a STALE row rather than a row that silently excuses nothing.
pub const ASPECTS: &[&str] = &["registered", "unit-path", "root-reach", "root-module"];

/// ONE PLANE OF THE LOCKED ROSTER.
///
/// #48 (OWNER-LOCKED 2026-09-20, amending #18/#39): *"The locked plane roster becomes 5: llm, mcp,
/// a2a, streaming, decisions(jev)."* That is the DOCTRINE roster and it is what this gate measures
/// against — deliberately NOT [`crate::planes::PLANE_KEYS`], which is the ON-DISK roster of four
/// (`llm`, `mcp`, `a2a`, `voice`) and says so in its own header: every consumer of that constant
/// treats each entry as a literal `crates/busbar-<key>` directory suffix or a literal grep needle,
/// so spelling it `streaming` before `crates/busbar-voice` is renamed would make those consumers
/// open a directory that is not there. The two rosters are held in step by
/// `every_on_disk_plane_key_maps_to_a_roster_plane` below, which is the right place for a claim
/// about two Rust constants — a gate row would need a planted tree to prove a compile-time fact.
struct Plane {
    /// The #48 roster key.
    key: &'static str,
    /// The on-disk spelling, where it differs. `streaming`'s crates and modules are still spelled
    /// `voice` (the #18 rename has not landed), and pretending otherwise would scan nothing.
    on_disk: &'static str,
    /// The `root/<module>.rs` this plane's unit path would live in. Checked for existence, never
    /// assumed.
    module: &'static str,
    /// Any one of these, in the body of `register_planes()` or `plane_claims()`, IS the
    /// registration. Each is a type or a decl the root can only name in order to install it.
    register_tokens: &'static [&'static str],
    /// Why this row is spelled the way it is, for the reader who finds it red.
    note: &'static str,
}

const ROSTER: &[Plane] = &[
    Plane {
        key: "llm",
        on_disk: "llm",
        module: "units_llm",
        register_tokens: &["busbar_llm::PLANE_DECL", "LlmPlane"],
        note: "the 1.5.5 plane; `proto-llm` carries the crate edge, the protocol DECLS and the \
               plane decl together",
    },
    Plane {
        key: "mcp",
        on_disk: "mcp",
        module: "units_mcp",
        register_tokens: &["busbar_mcp::PLANE_DECL", "McpPlane"],
        note: "extracted to `busbar-mcp`; the root also seals its kernel bindings at boot behind \
               `root-mcp`",
    },
    Plane {
        key: "a2a",
        on_disk: "a2a",
        module: "units_a2a",
        register_tokens: &["busbar_a2a::PLANE_DECL", "A2aPlane"],
        note: "served by `busbar_a2a::PLANE_DECL`; `root/units_a2a.rs` is the kernel-loop sibling \
               and is the module the 2026-09-22 money findings were in",
    },
    Plane {
        key: "streaming",
        on_disk: "voice",
        module: "units_voice",
        register_tokens: &["busbar_voice::PLANE_DECL", "StreamingPlane"],
        note: "#18: streaming is the PLANE, voice is one dialect inside it. The rename has not \
               landed, so the module and the crate are still spelled `voice`",
    },
    Plane {
        key: "decision",
        on_disk: "decision",
        module: "units_decision",
        register_tokens: &[
            "busbar_decision::PLANE_DECL",
            "DecisionPlane",
            "busbar_plane_decision",
        ],
        note: "#48's fifth plane (jev). `crates/busbar-plane-decision` exists; whether the \
               composition root reaches it is exactly what this row answers",
    },
];

/// `root/units_*.rs` files that are NOT one of #48's five planes, each with the reason.
///
/// One entry. The admin surface drives the same ten steps and lives beside the plane units, but #5
/// is explicit that control (admin/oauth2) is a CLEANLINESS crate and not a plugin kind, and #48's
/// roster is five protocol planes. Scoring `units_admin` as a sixth plane would red a row about a
/// roster it is not on. It is still covered by `reachability:root-module` like every other module.
const NOT_A_PLANE_MODULE: &[(&str, &str)] = &[(
    "units_admin",
    "the admin surface is control (#5), not one of #48's five protocol planes",
)];

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE SCAN
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// One file, read once, with the two facts every rule below needs: its comment-stripped code lines
/// and whether each one is TEST SCOPE.
struct Scanned {
    rel: String,
    /// The file stem, which is its module name under `root/`. `units_admin/mod.rs` stems to
    /// `units_admin`, the directory it is the module of.
    stem: String,
    lines: Vec<ScopeLine>,
    /// The whole file is test scope by its PATH — `…/tests/…`, `…/benches/…`, a `tests.rs`. A
    /// per-line `#[cfg(test)]` cannot see this, because the attribute is in the file that DECLARES
    /// the module, not in the module.
    path_is_test: bool,
    /// The whole file is test scope because the `mod` statement that declares it is gated. This is
    /// the `#[path = "tests/units_a2a.rs"] #[cfg(test)] mod tests;` shape, and also the
    /// `#[cfg(any(test, feature = "test-harness"))] pub mod harness;` shape — without it, moving a
    /// construction into `root/harness.rs` would turn this gate green while changing nothing.
    decl_is_test: bool,
}

impl Scanned {
    fn whole_file_is_test(&self) -> bool {
        self.path_is_test || self.decl_is_test
    }
    fn is_test_line(&self, idx: usize) -> bool {
        self.whole_file_is_test() || self.lines[idx].gated
    }
}

/// A `#[cfg(feature = "test-…")]` line, rewritten to the one spelling [`test_scope`] knows.
///
/// [`crate::scan::test_scope`] already answers `#[cfg(test)]` and `#[cfg(any(test, …))]` and
/// already refuses `#[cfg(not(test))]` — that is the shared scanner and it is not re-implemented
/// here. What it does not know is a feature whose whole purpose is to be off in a shipped build.
/// Rewriting the line in place (never dropping it: the line count is the line numbering every
/// finding is reported in) is the smallest change that routes those through the one scanner.
fn normalize_test_cfgs(src: &str) -> String {
    const TEST_FEATURES: &[&str] = &["test-harness", "test-support", "test-util", "test-kit"];
    let mut out = String::with_capacity(src.len());
    for line in src.lines() {
        let t = line.trim_start();
        let is_cfg = t.starts_with("#[cfg(") || t.starts_with("#[cfg_attr(");
        if is_cfg && !t.contains("not(") && TEST_FEATURES.iter().any(|f| t.contains(f)) {
            let indent = &line[..line.len() - t.len()];
            out.push_str(indent);
            out.push_str("#[cfg(test)]");
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    out
}

fn path_is_test(rel: &str) -> bool {
    rel.contains("/tests/")
        || rel.contains("/benches/")
        || rel.contains("/examples/")
        || rel.ends_with("/tests.rs")
        || rel.contains("/fixtures/")
}

/// `crates/busbar/src/root/units_a2a.rs` → `units_a2a`; `…/units_admin/mod.rs` → `units_admin`.
fn stem_of(rel: &str) -> String {
    let (dir, name) = rel.rsplit_once('/').unwrap_or(("", rel));
    let name = name.trim_end_matches(".rs");
    if name == "mod" {
        dir.rsplit_once('/').map_or(dir, |(_, d)| d).to_string()
    } else {
        name.to_string()
    }
}

/// Walk the binary crate's `src/`, once, and carry both facts per line.
fn scan(cx: &Ctx) -> Result<Vec<Scanned>, String> {
    let files = cx
        .walk(&WalkSpec::new([CRATE_SRC]).ext("rs").min_files(1))
        .map_err(|e| e.to_string())?;
    let mut out: Vec<Scanned> = files
        .iter()
        .map(|f| {
            let rel = f.rel_str();
            Scanned {
                path_is_test: path_is_test(&rel),
                stem: stem_of(&rel),
                rel,
                lines: test_scope(&normalize_test_cfgs(&f.text)),
                decl_is_test: false,
            }
        })
        .collect();

    // THE SECOND PASS: a module whose `mod` statement is gated is test scope in its entirety.
    let gated: BTreeSet<String> = test_scoped_module_files(&out);
    for s in &mut out {
        if gated.contains(&s.rel) {
            s.decl_is_test = true;
        }
    }
    Ok(out)
}

/// Every file reached only through a GATED `mod` statement, resolved to its path.
///
/// Both spellings are resolved: `#[path = "tests/units_a2a.rs"] mod tests;` names its file outright,
/// and a bare `mod harness;` resolves against the declaring file's directory as `harness.rs` or
/// `harness/mod.rs`. A module this cannot resolve is simply not marked — the gate then reads it as
/// production, which is the direction that reds rather than the direction that passes.
fn test_scoped_module_files(files: &[Scanned]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for f in files {
        let dir = match f.rel.rsplit_once('/') {
            Some((d, name)) if name == "mod.rs" || name == "lib.rs" || name == "main.rs" => {
                d.to_string()
            }
            Some((d, name)) => format!("{d}/{}", name.trim_end_matches(".rs")),
            None => continue,
        };
        let mut path_attr: Option<String> = None;
        for l in &f.lines {
            let code = l.code.trim();
            if let Some(p) = path_attribute(code) {
                path_attr = Some(p);
                continue;
            }
            let Some(name) = mod_statement(code) else {
                if !code.is_empty() && !code.starts_with("#[") {
                    path_attr = None;
                }
                continue;
            };
            if l.gated {
                match &path_attr {
                    Some(p) => {
                        let base = f.rel.rsplit_once('/').map_or("", |(d, _)| d);
                        out.insert(normalize_rel(&format!("{base}/{p}")));
                    }
                    None => {
                        out.insert(format!("{dir}/{name}.rs"));
                        out.insert(format!("{dir}/{name}/mod.rs"));
                    }
                }
            }
            path_attr = None;
        }
    }
    out
}

/// `#[path = "tests/units_a2a.rs"]` → `tests/units_a2a.rs`.
fn path_attribute(code: &str) -> Option<String> {
    let rest = code.strip_prefix("#[path")?;
    let rest = rest.trim_start().strip_prefix('=')?;
    let rest = rest.trim_start().strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// `pub mod harness;` / `mod tests;` → the module name, for the BRACE-LESS form only. A `mod x { … }`
/// is inline and declares no file.
fn mod_statement(code: &str) -> Option<String> {
    let rest = code.strip_suffix(';')?;
    let rest = rest.trim();
    let rest = rest
        .strip_prefix("pub(crate) ")
        .or_else(|| rest.strip_prefix("pub(super) "))
        .or_else(|| rest.strip_prefix("pub "))
        .unwrap_or(rest);
    let name = rest.strip_prefix("mod ")?.trim();
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    Some(name.to_string())
}

fn normalize_rel(p: &str) -> String {
    p.split('/')
        .filter(|s| !s.is_empty() && *s != ".")
        .collect::<Vec<_>>()
        .join("/")
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE MODULE GRAPH — WHICH FILES ARE REACHED FROM `main.rs`
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// Which modules under `crates/busbar/src/` `main.rs` can reach, transitively.
///
/// The node key is the FILE STEM, which is unique under `crates/busbar/src/root/` and therefore
/// carries none of the collision risk the item graph below is explicit about. The edge is: a
/// non-test line of module A names module B's stem as a word. Rust paths name the module they
/// traverse (`root::units_a2a::scope_policy`), so a stem mention is what a use of the module looks
/// like in text.
///
/// **A `mod B;` DECLARATION IS NOT AN EDGE.** That distinction is the whole row: `root/mod.rs`
/// declares `pub mod money_book;` and nothing in the tree names `money_book` anywhere else, so the
/// module is dead — and a graph that counted its own declaration as a use would call every module
/// in the tree reached and prove nothing.
fn reached_modules(files: &[Scanned]) -> BTreeSet<String> {
    let live: Vec<&Scanned> = files.iter().filter(|f| !f.whole_file_is_test()).collect();
    let names: BTreeSet<&str> = live.iter().map(|f| f.stem.as_str()).collect();

    let mut mentions: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for f in &live {
        let mut hit: BTreeSet<&str> = BTreeSet::new();
        for l in &f.lines {
            if l.gated {
                continue;
            }
            let code = l.code.trim();
            if mod_statement(code).is_some() {
                continue;
            }
            // `counted`, NEVER `code`: the blanked copy drops literal CONTENTS, so a module
            // name mentioned inside a string is not an edge. `code` deliberately keeps them.
            for w in words(&l.counted) {
                if let Some(n) = names.get(w.as_str()) {
                    if *n != f.stem {
                        hit.insert(n);
                    }
                }
            }
        }
        mentions.insert(f.stem.as_str(), hit);
    }

    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut queue: VecDeque<&str> = VecDeque::new();
    if names.contains("main") {
        seen.insert("main".to_string());
        queue.push_back("main");
    }
    while let Some(n) = queue.pop_front() {
        let Some(next) = mentions.get(n) else {
            continue;
        };
        for m in next {
            if seen.insert((*m).to_string()) {
                queue.push_back(m);
            }
        }
    }
    seen
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE ITEM GRAPH — WHICH FUNCTIONS ARE REACHED FROM `main.rs`
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// One named item and the span of lines it owns.
struct Item {
    name: String,
    file: usize,
    /// Indices into `files[file].lines`, inclusive.
    start: usize,
    end: usize,
}

/// Every named item declared in non-test code, with its body span.
///
/// Brace-counted off [`ScopeLine::counted`], which is the blanked copy — a `{` inside a string
/// literal must not open a scope, and that is the exact bug that used to drop every production line
/// after one.
fn items(files: &[Scanned]) -> Vec<Item> {
    let mut out = Vec::new();
    for (fi, f) in files.iter().enumerate() {
        if f.whole_file_is_test() {
            continue;
        }
        for (i, l) in f.lines.iter().enumerate() {
            if l.gated {
                continue;
            }
            let Some(name) = declared_name(&l.code) else {
                continue;
            };
            let end = span_end(&f.lines, i);
            out.push(Item {
                name,
                file: fi,
                start: i,
                end,
            });
        }
    }
    out
}

/// The name an item declaration introduces, or `None` for a line that declares nothing.
fn declared_name(code: &str) -> Option<String> {
    let t = code.trim_start();
    // `fn` first: `const fn`/`async fn`/`unsafe fn` must read as functions, not as a `const`.
    if is_fn_decl(code) {
        let at = t.find("fn ")? + 3;
        return ident_at(&t[at..]);
    }
    for kw in [
        "static mut ",
        "static ",
        "const ",
        "struct ",
        "enum ",
        "union ",
    ] {
        let rest = strip_visibility(t).strip_prefix(kw);
        if let Some(rest) = rest {
            return ident_at(rest);
        }
    }
    None
}

fn strip_visibility(t: &str) -> &str {
    let t = t.trim_start();
    for v in ["pub(crate) ", "pub(super) ", "pub(self) ", "pub "] {
        if let Some(r) = t.strip_prefix(v) {
            return r.trim_start();
        }
    }
    t
}

fn ident_at(s: &str) -> Option<String> {
    let s = s.trim_start();
    let name: String = s
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    (!name.is_empty() && !name.chars().next()?.is_ascii_digit()).then_some(name)
}

/// The last line of the item that starts at `start`: the matching close brace, or the line that
/// ends the statement with `;` for a brace-less `const`/`static`.
fn span_end(lines: &[ScopeLine], start: usize) -> usize {
    // ALL THREE BRACKET CLASSES, not just braces. `const NOUNS: &[Noun] = &[ … ];` opens with a
    // square bracket and its elements are brace-delimited, so a brace-only count closes the span on
    // the FIRST element and reads a table of thirty entries as a table of one — which under-counts
    // edges and turns reachable things into false reds.
    let mut depth: i32 = 0;
    let mut opened = false;
    for (i, l) in lines.iter().enumerate().skip(start).take(4000) {
        let opens = l.counted.chars().filter(|c| "{[(".contains(*c)).count() as i32;
        let closes = l.counted.chars().filter(|c| "}])".contains(*c)).count() as i32;
        if opens > 0 {
            opened = true;
        }
        depth += opens - closes;
        if opened && depth <= 0 {
            return i;
        }
        if !opened && l.counted.trim_end().ends_with(';') {
            return i;
        }
    }
    (start + 1).min(lines.len().saturating_sub(1))
}

/// Which items `main.rs` reaches, transitively, keyed on SIMPLE NAMES.
///
/// The collision is real and declared in the header: two functions called `new` are one node, so
/// this OVER-approximates. It is used for exactly one thing — deciding whether the function that
/// builds a unit is reached — and the own-constructor exclusion is what stops the over-approximation
/// from turning a dormant unit green.
fn reached_items(files: &[Scanned], items: &[Item]) -> BTreeSet<String> {
    let names: BTreeSet<&str> = items.iter().map(|i| i.name.as_str()).collect();
    let mut mentions: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for it in items {
        let f = &files[it.file];
        let entry = mentions.entry(it.name.as_str()).or_default();
        for l in &f.lines[it.start..=it.end] {
            if l.gated {
                continue;
            }
            if mod_statement(l.code.trim()).is_some() {
                continue;
            }
            for w in words(&l.counted) {
                if let Some(n) = names.get(w.as_str()) {
                    if *n != it.name {
                        entry.insert(n);
                    }
                }
            }
        }
    }

    // THE SEED IS `main.rs`, WHOLE. Everything in the composition root's own file is boot code by
    // construction; drawing the line at `fn main`'s body would make the answer depend on which
    // helper `main` happens to have been factored into, which is not a property of the tree.
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut queue: VecDeque<&str> = VecDeque::new();
    for it in items.iter().filter(|i| files[i.file].rel == MAIN_RS) {
        if seen.insert(it.name.clone()) {
            queue.push_back(it.name.as_str());
        }
    }
    while let Some(n) = queue.pop_front() {
        let Some(next) = mentions.get(n) else {
            continue;
        };
        for m in next {
            if seen.insert((*m).to_string()) {
                queue.push_back(m);
            }
        }
    }
    seen
}

/// The identifier words of a line of code.
fn words(code: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for c in code.chars() {
        if is_word_char(c) {
            cur.push(c);
        } else if !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE UNIT PATH
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// The type a module writes `impl … Units for T` for. DERIVED, never listed: the point of the gate
/// is that a module cannot acquire — or lose — a unit path the table does not know about.
fn unit_types(module: &Scanned) -> Vec<String> {
    let mut out = Vec::new();
    for l in &module.lines {
        if l.gated {
            continue;
        }
        let code = l.code.trim();
        if !code.starts_with("impl") {
            continue;
        }
        // `Units for `, WITH AN IDENTIFIER BOUNDARY IN FRONT OF IT. The trait is written both ways
        // in this tree — `impl Units for LlmUnit<'_>` beside a fully-qualified
        // `impl busbar_kernel::teller::Units for …` — and requiring a SPACE before `Units` reads
        // the first and silently misses the second, which is the shape that reports a module with a
        // unit path as a module with none. The boundary keeps `RouteUnits for` from matching.
        const TRAIT: &str = "Units for ";
        let Some(at) = code
            .match_indices(TRAIT)
            .map(|(i, _)| i)
            .find(|i| *i == 0 || !is_word_char(code[..*i].chars().next_back().unwrap_or(' ')))
        else {
            continue;
        };
        let rest = code[at + TRAIT.len()..].trim();
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if !name.is_empty() && !out.contains(&name) {
            out.push(name);
        }
    }
    out
}

/// ONE PLACE THE TYPE IS BUILT, and why it did or did not count.
struct Site {
    rel: String,
    line: usize,
    why: SiteKind,
}

#[derive(PartialEq, Eq)]
enum SiteKind {
    /// Under `#[cfg(test)]`, in a `tests/` file, or behind a test-only feature.
    Test,
    /// Inside the type's OWN constructor — a function whose return type is `Self` or the type
    /// itself. `A2aUnits::new` building an `A2aUnits` is the constructor doing its job; it is not
    /// evidence that anything CALLS the constructor.
    OwnConstructor,
    /// Production code, but in a function `fn main()` does not reach.
    NotReached,
    /// The real thing: production code, not a constructor, reached from `fn main()`.
    Live,
}

impl SiteKind {
    fn label(&self) -> &'static str {
        match self {
            SiteKind::Test => "test",
            SiteKind::OwnConstructor => "its own constructor",
            SiteKind::NotReached => "not reached from fn main()",
            SiteKind::Live => "LIVE",
        }
    }
}

/// Every construction of `tname` anywhere under `crates/busbar/src/`.
///
/// Two spellings are counted, because both are used in this tree: `T::new(` (the call) and `T {`
/// (the struct literal, which is how `LlmUnit`, `VoiceUnit` and `A2aUnits` are all actually built
/// inside their own modules). Declaration lines are excluded by shape — `impl T {`, `struct T {`,
/// `enum T {` — so a type's own definition is never read as a construction of it.
fn construction_sites(
    files: &[Scanned],
    items: &[Item],
    reached: &BTreeSet<String>,
    tname: &str,
) -> Vec<Site> {
    let needle_call = format!("{tname}::new");
    let needle_lit = format!("{tname} {{");
    let mut out = Vec::new();
    for (fi, f) in files.iter().enumerate() {
        if !f.lines.iter().any(|l| l.code.contains(tname)) {
            continue;
        }
        for (i, l) in f.lines.iter().enumerate() {
            let code = &l.code;
            if !code.contains(&needle_call) && !code.contains(&needle_lit) {
                continue;
            }
            let t = code.trim_start();
            if t.starts_with("impl")
                || t.starts_with("struct ")
                || t.starts_with("pub struct ")
                || t.starts_with("enum ")
                || t.starts_with("pub enum ")
                || t.starts_with("use ")
            {
                continue;
            }
            let why = if f.is_test_line(i) {
                SiteKind::Test
            } else if in_own_constructor(&f.lines, i, tname) {
                SiteKind::OwnConstructor
            } else if enclosing_item(items, fi, i).is_some_and(|n| reached.contains(n)) {
                SiteKind::Live
            } else {
                SiteKind::NotReached
            };
            out.push(Site {
                rel: f.rel.clone(),
                line: l.no,
                why,
            });
        }
    }
    out
}

/// The name of the innermost non-test item whose span contains this line.
fn enclosing_item(items: &[Item], file: usize, line: usize) -> Option<&str> {
    items
        .iter()
        .filter(|it| it.file == file && it.start <= line && line <= it.end)
        .min_by_key(|it| it.end - it.start)
        .map(|it| it.name.as_str())
}

/// Is this construction inside a function that RETURNS the type — i.e. the type's own constructor?
///
/// The distinction is the whole gate. `A2aUnits::new` contains the only non-test `A2aUnits { … }`
/// in the crate; reading that as "a2a's unit path is constructed" would report the constructor
/// existing as though it were the constructor being called. `LlmUnit`'s non-test literal sits in
/// `LlmNode::answer_arriving_at`, which returns a `Response` — a caller, not a constructor.
fn in_own_constructor(lines: &[ScopeLine], idx: usize, tname: &str) -> bool {
    let Some(decl) = enclosing_fn(lines, idx) else {
        return false;
    };
    let sig = signature_text(lines, decl);
    returns(&sig, "Self") || returns(&sig, tname)
}

fn indent_of(code: &str) -> usize {
    code.len() - code.trim_start().len()
}

/// `fn`, with only visibility and qualifier words before it. The word `fn` inside a literal does
/// not match, because the head has to parse as qualifiers.
fn is_fn_decl(code: &str) -> bool {
    let t = code.trim_start();
    let Some(at) = t.find("fn ") else {
        return false;
    };
    t[..at].split_whitespace().all(|w| {
        matches!(
            w,
            "pub" | "async" | "const" | "unsafe" | "default" | "extern"
        ) || w.starts_with("pub(")
            || w.starts_with('"')
    })
}

/// The nearest enclosing `fn` declaration: the closest preceding one at strictly smaller
/// indentation. A construction on the declaration line itself (`fn f() -> Self { T { } }`) is its
/// own enclosing fn.
fn enclosing_fn(lines: &[ScopeLine], idx: usize) -> Option<usize> {
    if is_fn_decl(&lines[idx].code) {
        return Some(idx);
    }
    let want = indent_of(&lines[idx].code);
    (0..idx)
        .rev()
        .find(|&j| is_fn_decl(&lines[j].code) && indent_of(&lines[j].code) < want)
}

/// The declaration line plus however many it takes to reach the opening brace — because a return
/// type lives after the parameter list and this tree writes long parameter lists one per line.
fn signature_text(lines: &[ScopeLine], decl: usize) -> String {
    let mut sig = String::new();
    for l in lines.iter().skip(decl).take(48) {
        sig.push_str(&l.code);
        sig.push(' ');
        if l.counted.contains('{') {
            break;
        }
    }
    sig
}

/// `-> Self`, `-> A2aUnits`, `-> Option<Self>`, `-> Result<VoiceUnit<'n>, E>` — the arrow, then the
/// name as a word somewhere in the return position.
fn returns(sig: &str, tname: &str) -> bool {
    let Some(at) = sig.find("->") else {
        return false;
    };
    word_hit(&sig[at..], tname)
}

/// A whole-word hit where the identifier boundary is `[^A-Za-z0-9_]`.
fn word_hit(hay: &str, needle: &str) -> bool {
    let h: Vec<char> = hay.chars().collect();
    let n: Vec<char> = needle.chars().collect();
    if n.is_empty() || n.len() > h.len() {
        return false;
    }
    (0..=(h.len() - n.len())).any(|i| {
        h[i..i + n.len()] == n[..]
            && (i == 0 || !is_word_char(h[i - 1]))
            && (i + n.len() == h.len() || !is_word_char(h[i + n.len()]))
    })
}

fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE COMPOSITION ROOT'S REGISTRATION SITES
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// The body of a top-level `fn <name>` — from its declaration to the closing brace at column zero.
///
/// The registration rows are scoped to the two function bodies rather than to the whole file,
/// because the whole file is where a plane gets NAMED and the function body is where it gets
/// INSTALLED. `main.rs` mentions every plane in prose and in ingress tables; only
/// `register_planes()` pushes a decl.
fn fn_body<'a>(lines: &'a [ScopeLine], name: &str) -> Option<&'a [ScopeLine]> {
    let want = format!("fn {name}(");
    let start = lines
        .iter()
        .position(|l| l.code.contains(&want) && is_fn_decl(&l.code))?;
    let end = lines
        .iter()
        .skip(start + 1)
        .position(|l| l.code.starts_with('}'))
        .map(|p| start + 1 + p)?;
    Some(&lines[start..=end])
}

fn body_names(body: &[ScopeLine], tokens: &[&str]) -> Vec<String> {
    body.iter()
        .filter(|l| !l.gated)
        .filter_map(|l| {
            tokens
                .iter()
                .find(|t| l.code.contains(**t))
                .map(|t| format!("{}:{t}", l.no))
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE DECLARATIONS
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// ONE `[[dormant]]` ROW — a module somebody has said, in writing, does not run yet.
pub struct Declaration {
    pub subject: String,
    pub aspect: String,
    pub module: String,
    pub reason: String,
    pub switch: String,
}

/// Read the declaration file. An ABSENT or UNPARSEABLE file is an ERROR, never zero declarations:
/// zero declarations is the GOAL state and reads exactly like a file somebody deleted.
fn declarations(cx: &Ctx) -> Result<Vec<Declaration>, String> {
    let text = cx.read(DECLARATIONS).map_err(|e| {
        format!("{DECLARATIONS} could not be read ({e}). An absent declaration file reads exactly like a tree with nothing to declare; it is not one.")
    })?;
    let doc = crate::toml_doc::parse_str(&text)
        .map_err(|e| format!("{DECLARATIONS} does not parse: {e}"))?;
    Ok(doc
        .array_of_tables("dormant")
        .into_iter()
        .map(|t| Declaration {
            subject: t.str_of("subject").unwrap_or_default().to_string(),
            aspect: t.str_of("aspect").unwrap_or_default().to_string(),
            module: t.str_of("module").unwrap_or_default().to_string(),
            reason: t.str_of("reason").unwrap_or_default().to_string(),
            switch: t.str_of("switch").unwrap_or_default().to_string(),
        })
        .collect())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE VERDICT
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// What the three per-plane rules found, before the declarations are applied.
struct Finding {
    registered: Result<String, String>,
    unit_path: Result<String, String>,
    root_reach: Result<String, String>,
}

fn all_rows_did_not_run(why: &str) -> Verdict {
    let mut rows = vec![Row::fail(
        ROW_SCAN_FLOOR,
        "the composition root could not be measured",
        format!("{why} — {DID_NOT_RUN}"),
    )];
    for p in ROSTER {
        for id in [
            row_registered(p.key),
            row_unit_path(p.key),
            row_root_reach(p.key),
        ] {
            rows.push(Row::fail(id, "the scan did not run", DID_NOT_RUN));
        }
    }
    for id in [ROW_ROOT_MODULE, ROW_ROSTER, ROW_STALE] {
        rows.push(Row::fail(id, "the scan did not run", DID_NOT_RUN));
    }
    Verdict::of(rows)
}

pub struct ReachabilityGate;

impl Gate for ReachabilityGate {
    fn name(&self) -> &'static str {
        GATE
    }

    fn owed(&self) -> Vec<String> {
        let mut ids = vec![
            ROW_SCAN_FLOOR.to_string(),
            ROW_ROOT_MODULE.to_string(),
            ROW_ROSTER.to_string(),
            ROW_STALE.to_string(),
        ];
        for p in ROSTER {
            ids.push(row_registered(p.key));
            ids.push(row_unit_path(p.key));
            ids.push(row_root_reach(p.key));
        }
        ids
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        // THE SCOPE CLAIM, CHECKED BEFORE ANYTHING IS MEASURED. Everything below is scoped to
        // `crates/busbar/src/**` because the crate has no `[lib]` and therefore no construction
        // site can exist outside it. The day that stops being true, this gate's answers are scoped
        // wrong — so it refuses the tree rather than answering it.
        match cx.read(CRATE_MANIFEST) {
            Err(e) => return all_rows_did_not_run(&format!("{CRATE_MANIFEST}: {e}")),
            Ok(m) => {
                if m.lines().any(|l| l.trim() == "[lib]") {
                    return all_rows_did_not_run(&format!(
                        "{CRATE_MANIFEST} now declares a `[lib]`. This gate scopes every answer to \
                         `{CRATE_SRC}` on the ground that a binary-only crate can have no \
                         construction site outside itself, and a library target makes that false. \
                         Widen the scan before trusting another verdict from it"
                    ));
                }
            }
        }
        let files = match scan(cx) {
            Ok(f) => f,
            Err(e) => return all_rows_did_not_run(&format!("{CRATE_SRC} was not scanned: {e}")),
        };
        let decls = match declarations(cx) {
            Ok(d) => d,
            Err(e) => return all_rows_did_not_run(&e),
        };
        let by_rel: BTreeMap<&str, &Scanned> = files.iter().map(|f| (f.rel.as_str(), f)).collect();

        let Some(main_rs) = by_rel.get(MAIN_RS) else {
            return all_rows_did_not_run(&format!("{MAIN_RS} is not in the scanned tree"));
        };
        let Some(registry_rs) = by_rel.get(REGISTRY_RS) else {
            return all_rows_did_not_run(&format!("{REGISTRY_RS} is not in the scanned tree"));
        };
        let Some(register_planes) = fn_body(&main_rs.lines, "register_planes") else {
            return all_rows_did_not_run(&format!(
                "{MAIN_RS} declares no `fn register_planes()` — the one write into the plane axis \
                 is not where this gate reads it, so every registration row would be a false red"
            ));
        };
        let Some(plane_claims) = fn_body(&registry_rs.lines, "plane_claims") else {
            return all_rows_did_not_run(&format!(
                "{REGISTRY_RS} declares no `fn plane_claims()` — the boot seal's plane list is not \
                 where this gate reads it"
            ));
        };

        let mods = reached_modules(&files);
        let all_items = items(&files);
        let reached = reached_items(&files, &all_items);

        let mut rows = vec![Row::pass(
            ROW_SCAN_FLOOR,
            "the manifest, the composition root, its two registration sites and the declarations were read",
            format!(
                "{CLEAN} — {CRATE_MANIFEST} declares no `[lib]`, so `{CRATE_SRC}` is the whole \
                 reachable surface; {} file(s) scanned, {} item(s), {} reached from fn main(), {} \
                 declaration(s)",
                files.len(),
                all_items.len(),
                reached.len(),
                decls.len()
            ),
        )];

        // ── the three rules, per plane ───────────────────────────────────────────────────────
        let mut findings: BTreeMap<&str, Finding> = BTreeMap::new();
        for p in ROSTER {
            let module_rel = format!("{ROOT_DIR}/{}.rs", p.module);
            let module = by_rel.get(module_rel.as_str());

            // 1. REGISTERED.
            let mut hits = body_names(register_planes, p.register_tokens);
            hits.extend(
                body_names(plane_claims, p.register_tokens)
                    .into_iter()
                    .map(|h| format!("registry.rs:{h}")),
            );
            let registered = if hits.is_empty() {
                Err(format!(
                    "no registration token {:?} appears in `register_planes()` ({MAIN_RS}) or \
                     `plane_claims()` ({REGISTRY_RS}). The composition root does not install this \
                     plane, so nothing it declares is served. ({})",
                    p.register_tokens, p.note
                ))
            } else {
                Ok(format!(
                    "registered by the composition root at {}",
                    hits.join(", ")
                ))
            };

            // 2. THE UNIT PATH.
            let unit_path = match module {
                None => Ok(format!(
                    "no `{module_rel}` in this tree — there is no unit path to reach"
                )),
                Some(m) => {
                    let types = unit_types(m);
                    if types.is_empty() {
                        Err(format!(
                            "NO UNIT PATH AT ALL: `{module_rel}` is {} line(s) of a module named \
                             for a unit path and declares no `impl … Units for` — there is no \
                             ten-step unit here for anything to reach. Its siblings each declare \
                             one. Give it a unit path, fold it into whatever does the work, or \
                             declare it in {DECLARATIONS} with the reason and the switch. The \
                             site-by-site evidence is written up in {EVIDENCE}.",
                            m.lines.len()
                        ))
                    } else {
                        let mut live: Vec<String> = Vec::new();
                        let mut dormant: Vec<String> = Vec::new();
                        for t in &types {
                            let sites = construction_sites(&files, &all_items, &reached, t);
                            let lives: Vec<&Site> =
                                sites.iter().filter(|s| s.why == SiteKind::Live).collect();
                            if lives.is_empty() {
                                dormant.push(format!(
                                    "`{t}` built at {} — none of them in a function `fn main()` \
                                     reaches",
                                    describe(&sites)
                                ));
                            } else {
                                live.push(format!(
                                    "`{t}` built from fn main() at {}",
                                    describe_live(&lives)
                                ));
                            }
                        }
                        if dormant.is_empty() {
                            Ok(live.join("; "))
                        } else {
                            Err(format!(
                                "UNREACHED UNIT PATH: {}. The module compiles and ships and \
                                 nothing `fn main()` reaches builds its unit — code in a money \
                                 path that nobody is aware never runs. Switch it onto the serving \
                                 path, or declare it in {DECLARATIONS} with the reason and the \
                                 switch that retires it. The site-by-site evidence is written up \
                                 in {EVIDENCE}.",
                                dormant.join("; ")
                            ))
                        }
                    }
                }
            };

            // 3. ROOT REACH — the MODULE, from `fn main()`, transitively.
            let root_reach = match module {
                None => Ok(format!("no `{module_rel}` in this tree")),
                Some(_) if mods.contains(p.module) => {
                    Ok(format!("`{module_rel}` is reached from {MAIN_RS}"))
                }
                Some(_) => Err(format!(
                    "`{module_rel}` is reached from no chain starting at {MAIN_RS}. The \
                     composition root cannot get to this module at all."
                )),
            };

            findings.insert(
                p.key,
                Finding {
                    registered,
                    unit_path,
                    root_reach,
                },
            );
        }

        // ── the declarations, applied ────────────────────────────────────────────────────────
        let declared: BTreeMap<(String, String), &Declaration> = decls
            .iter()
            .map(|d| ((d.subject.clone(), d.aspect.clone()), d))
            .collect();
        let resolve = |id: String,
                       title: String,
                       subject: &str,
                       aspect: &str,
                       outcome: &Result<String, String>|
         -> Row {
            match outcome {
                Ok(detail) => Row::pass(id, title, format!("{CLEAN} — {detail}")),
                Err(detail) => match declared.get(&(subject.to_string(), aspect.to_string())) {
                    Some(d) if d.reason.len() >= MIN_REASON => Row::pass(
                        id,
                        title,
                        format!(
                            "DECLARED DORMANT in {DECLARATIONS} — reason: {} | switch: {} | \
                             measured: {detail}",
                            d.reason,
                            if d.switch.is_empty() {
                                "(none named)"
                            } else {
                                d.switch.as_str()
                            }
                        ),
                    ),
                    Some(d) => Row::fail(
                        id,
                        title,
                        format!(
                            "the declaration in {DECLARATIONS} carries a {}-character reason and \
                             {MIN_REASON} is the floor — a shrug is not a reason. Measured: {detail}",
                            d.reason.len()
                        ),
                    ),
                    None => Row::fail(id, title, detail.clone()),
                },
            }
        };

        for p in ROSTER {
            let f = &findings[p.key];
            // THE ON-DISK SPELLING IS IN THE TITLE WHENEVER IT DIFFERS. A reader who finds
            // `reachability:unit-path:streaming` red has to know, without opening this file, that
            // the module it is about is `units_voice.rs` — the #18 rename has not landed and a row
            // naming a file that is not there is a row nobody can act on.
            let who = if p.key == p.on_disk {
                format!("plane `{}`", p.key)
            } else {
                format!("plane `{}` (on disk: `{}`)", p.key, p.on_disk)
            };
            for (aspect, id, outcome) in [
                ("registered", row_registered(p.key), &f.registered),
                ("unit-path", row_unit_path(p.key), &f.unit_path),
                ("root-reach", row_root_reach(p.key), &f.root_reach),
            ] {
                rows.push(resolve(
                    id,
                    format!("{who} — {aspect}"),
                    p.key,
                    aspect,
                    outcome,
                ));
            }
        }

        // ── EVERY module of the composition root, not just the plane units ───────────────────
        //
        // `money_book.rs` and `vocabulary.rs` are not plane units and would sit outside every row
        // above; both are reached by nothing. This row is what sees them, and it is the same
        // instrument: a module the composition root cannot get to is code that ships and does not
        // run, whatever it is about.
        let mut orphaned: Vec<String> = files
            .iter()
            .filter(|f| !f.whole_file_is_test())
            .filter(|f| f.rel.starts_with(&format!("{ROOT_DIR}/")))
            .filter(|f| f.rel != format!("{ROOT_DIR}/mod.rs"))
            .filter(|f| !mods.contains(&f.stem))
            .map(|f| f.stem.clone())
            .collect();
        orphaned.sort();
        orphaned.dedup();
        let undeclared: Vec<&String> = orphaned
            .iter()
            .filter(|s| {
                !declared
                    .get(&((*s).clone(), "root-module".to_string()))
                    .is_some_and(|d| d.reason.len() >= MIN_REASON)
            })
            .collect();
        rows.push(if undeclared.is_empty() {
            Row::pass(
                ROW_ROOT_MODULE,
                "every module of the composition root is reached from fn main()",
                format!(
                    "{CLEAN} — {} module(s) reached; {} declared dormant",
                    mods.len(),
                    orphaned.len()
                ),
            )
        } else {
            Row::fail(
                ROW_ROOT_MODULE,
                "a module of the composition root is reached by nothing",
                format!(
                    "{} unreached and undeclared module(s) under {ROOT_DIR}/: {} — each ships, \
                     compiles, and no chain from `fn main()` arrives at it. Wire it up, delete it, \
                     or declare it in {DECLARATIONS} (aspect `root-module`) with the reason and \
                     the switch. The reference-by-reference evidence is written up in {EVIDENCE}.",
                    undeclared.len(),
                    undeclared
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            )
        });

        // ── the roster cannot go stale ───────────────────────────────────────────────────────
        let known: BTreeSet<&str> = ROSTER
            .iter()
            .map(|p| p.module)
            .chain(NOT_A_PLANE_MODULE.iter().map(|(m, _)| *m))
            .collect();
        let mut orphans: Vec<String> = files
            .iter()
            .filter(|f| !f.whole_file_is_test())
            .filter(|f| {
                f.rel.starts_with(&format!("{ROOT_DIR}/"))
                    && f.stem.starts_with("units_")
                    && !known.contains(f.stem.as_str())
            })
            .map(|f| f.stem.clone())
            .collect();
        orphans.sort();
        orphans.dedup();
        rows.push(if orphans.is_empty() {
            Row::pass(
                ROW_ROSTER,
                "every root unit module maps to a roster plane",
                format!(
                    "{CLEAN} — the roster names {} plane module(s) and {} declared non-plane \
                     module(s); every `{ROOT_DIR}/units_*` on disk is one of them",
                    ROSTER.len(),
                    NOT_A_PLANE_MODULE.len()
                ),
            )
        } else {
            Row::fail(
                ROW_ROSTER,
                "a root unit module maps to no plane in the #48 roster",
                format!(
                    "{}: {} — a `{ROOT_DIR}/units_*.rs` the roster does not name is a module this \
                     gate scans NOTHING of, and zero findings is the passing answer to every rule. \
                     Add it to `ROSTER`, or to `NOT_A_PLANE_MODULE` with the reason it is not a \
                     plane.",
                    orphans.len(),
                    orphans.join(", ")
                ),
            )
        });

        // ── a declaration cannot outlive what it declared ────────────────────────────────────
        let mut stale: Vec<String> = Vec::new();
        for d in &decls {
            let named = format!("`{}`/`{}`", d.subject, d.aspect);
            if !ASPECTS.contains(&d.aspect.as_str()) {
                stale.push(format!(
                    "{named} names no aspect this gate measures (want one of {ASPECTS:?})"
                ));
                continue;
            }
            if !d.module.is_empty() && !cx.exists(&d.module) {
                stale.push(format!(
                    "{named} names module `{}`, which does not exist",
                    d.module
                ));
                continue;
            }
            let still = if d.aspect == "root-module" {
                orphaned.contains(&d.subject)
            } else {
                match ROSTER.iter().find(|p| p.key == d.subject) {
                    None => {
                        stale.push(format!("{named} names no plane in the #48 roster"));
                        continue;
                    }
                    Some(p) => {
                        let f = &findings[p.key];
                        match d.aspect.as_str() {
                            "registered" => f.registered.is_err(),
                            "unit-path" => f.unit_path.is_err(),
                            _ => f.root_reach.is_err(),
                        }
                    }
                }
            };
            if !still {
                stale.push(format!(
                    "{named} is declared dormant and is REACHED again — strike the row in the same \
                     commit that switched it on"
                ));
            }
        }
        stale.sort();
        rows.push(if stale.is_empty() {
            Row::pass(
                ROW_STALE,
                "every declaration still names something that is dormant",
                format!("{CLEAN} — {} declaration(s)", decls.len()),
            )
        } else {
            Row::fail(
                ROW_STALE,
                "a declaration no longer names a dormant subject",
                format!(
                    "{} stale row(s) in {DECLARATIONS}: {}",
                    stale.len(),
                    stale.join(" | ")
                ),
            )
        });

        Verdict::of(rows)
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();

        // THE SELF-TEST RUNS OVER TINY FIXTURE TREES, NOT THE REAL CRATE — the same reason
        // `instance-noun-neutrality` does: a census gate that planted into the real workspace and
        // re-scanned it per case is exactly the "grew a whole-tree scan per plant" regression the
        // selftest budget exists to catch. `FIX_RED` carries every failure shape at once;
        // `FIX_GREEN` carries the same five planes fully wired from `fn main()`, which is what
        // stops every RED below from being a gate that is simply red about everything.
        //
        // THE REAL RED-BEFORE-GREEN PROOF IS NOT HERE — it is `cargo xtask gate reachability` over
        // this repository, where the gate reds on `units_a2a.rs`, `units_voice.rs`, `units_mcp.rs`,
        // `money_book.rs` and `vocabulary.rs` and passes `units_llm.rs`. The fixtures exist so the
        // rules can be proven RED-able hermetically and cheaply; the tree is what proves they are
        // about something.
        const FIX_RED: &str = "xtask/fixtures/reachability";
        const FIX_GREEN: &str = "xtask/fixtures/reachability-green";
        const FIX_EMPTY: &str = "xtask/fixtures/reachability-empty";
        const FIX_LIB: &str = "xtask/fixtures/reachability-lib";

        for p in ROSTER {
            report.push(prove_rows_red_at(
                cx,
                self,
                format!(
                    "`{}` registered by nothing reds its registration row",
                    p.key
                ),
                &[&row_registered(p.key)],
                FIX_RED,
                &["no registration token"],
            ));
            report.push(prove_rows_red_at(
                cx,
                self,
                format!(
                    "`{}`'s unit built in nothing main reaches reds its unit-path row",
                    p.key
                ),
                &[&row_unit_path(p.key)],
                FIX_RED,
                &["UNREACHED UNIT PATH"],
            ));
            report.push(prove_rows_red_at(
                cx,
                self,
                format!(
                    "`{}`'s module unreached from fn main() reds its reach row",
                    p.key
                ),
                &[&row_root_reach(p.key)],
                FIX_RED,
                &["is reached from no chain starting at"],
            ));
        }

        // THE `units_mcp.rs` SHAPE: a module named for a unit path that declares none — REACHED
        // from `fn main()`, so the root-reach row stays green and only the unit-path row moves. A
        // gate that passed this would be useless on the real tree, where it is 1 884 lines of
        // money steps with no ten-step unit under any of them.
        report.push(red_over(
            self,
            cx,
            FIX_GREEN,
            "a units_* module that is reached but declares no `impl Units for` reds its unit-path row",
            &[row_unit_path("mcp")],
            {
                let mut ov = Overlay::new();
                ov.set("crates/busbar/src/root/units_mcp.rs", FIXTURE_NO_UNIT_MCP);
                ov
            },
            "NO UNIT PATH AT ALL",
        ));

        report.push(prove_rows_red_at(
            cx,
            self,
            "a root module no chain from fn main() arrives at reds the root-module row",
            &[ROW_ROOT_MODULE],
            FIX_RED,
            &["money_book"],
        ));
        report.push(prove_rows_red_at(
            cx,
            self,
            "a units_* module the roster does not name reds the roster row",
            &[ROW_ROSTER],
            FIX_RED,
            &["units_orphan"],
        ));
        report.push(prove_rows_red_at(
            cx,
            self,
            "a declaration naming no roster plane reds the stale row",
            &[ROW_STALE],
            FIX_RED,
            &["names no plane in the #48 roster"],
        ));
        report.push(prove_rows_red_at(
            cx,
            self,
            "a tree with no composition root reds the scan floor",
            &[ROW_SCAN_FLOOR],
            FIX_EMPTY,
            &[DID_NOT_RUN],
        ));
        // THE SCOPE CLAIM, PROVEN REFUSABLE. The whole scan is scoped to one binary crate's `src/`
        // because that crate has no `[lib]`; a tree where it grows one must be refused, not
        // answered from the old scope.
        report.push(prove_rows_red_at(
            cx,
            self,
            "a `[lib]` in the binary crate's manifest reds the scan floor",
            &[ROW_SCAN_FLOOR],
            FIX_LIB,
            &["now declares a `[lib]`"],
        ));

        // GREEN CONTROL 1 — THE WHOLE GATE IS GREEN OVER A TREE THAT SATISFIES IT. Without this
        // every RED above is satisfiable by a gate that is red about everything, which is not a gate.
        report.push(green_over(
            self,
            cx,
            FIX_GREEN,
            "a fully wired roster is green",
            Overlay::new(),
        ));

        // GREEN CONTROL 2 — THE DECLARED/UNDECLARED LINE, BOTH WAYS, ON ONE PLANT. The same edit
        // that makes a2a's unit dormant is made twice: once with a declaration and once without.
        // Together they are the whole of the gate's central claim — an undeclared unreachable unit
        // path is RED, a declared one is a tracked row — and neither half proves it alone.
        report.push(green_over(
            self,
            cx,
            FIX_GREEN,
            "a dormant unit path WITH a declaration is a tracked row, not a red",
            {
                let mut ov = Overlay::new();
                ov.set("crates/busbar/src/root/units_a2a.rs", FIXTURE_DORMANT_A2A);
                ov.set(DECLARATIONS, FIXTURE_DECLARED_A2A);
                ov
            },
        ));
        // THE EXPIRY, WHICH IS THE HALF THAT STOPS THE LIST ONLY EVER GROWING. The same declaration
        // as the case above, over the UNPLANTED green fixture — where a2a's unit path is reached —
        // must red the stale row. Without this, a declaration written once would excuse its subject
        // forever, which is the blanket waiver every other list in this tree had to be rescued from.
        report.push(red_over(
            self,
            cx,
            FIX_GREEN,
            "a declaration whose subject is REACHED again reds the stale row",
            &[ROW_STALE.to_string()],
            {
                let mut ov = Overlay::new();
                ov.set(DECLARATIONS, FIXTURE_DECLARED_A2A);
                ov
            },
            "is declared dormant and is REACHED again",
        ));

        report.push(red_over(
            self,
            cx,
            FIX_GREEN,
            "the same dormant unit path WITHOUT a declaration is RED",
            &[row_unit_path("a2a")],
            {
                let mut ov = Overlay::new();
                ov.set("crates/busbar/src/root/units_a2a.rs", FIXTURE_DORMANT_A2A);
                ov
            },
            "UNREACHED UNIT PATH",
        ));

        report
    }
}

/// The a2a module of the GREEN fixture with its one reached caller removed — the exact shape
/// `crates/busbar/src/root/units_a2a.rs` is in today.
const FIXTURE_DORMANT_A2A: &str = r#"pub struct A2aUnits {
    n: u64,
}

impl A2aUnits {
    pub fn new(n: u64) -> Self {
        A2aUnits { n }
    }
}

impl busbar_kernel::teller::Units for A2aUnits {
    fn drive(&self) -> u64 {
        self.n
    }
}

pub fn scope_policy() -> u64 {
    0
}
"#;

/// The `units_mcp.rs` shape: a module the composition root reaches (its `answer` is called from
/// `main.rs`'s `serve`) that declares no `impl … Units for` at all.
const FIXTURE_NO_UNIT_MCP: &str = r#"pub struct McpRecords {
    n: u64,
}

impl McpRecords {
    pub fn new(n: u64) -> Self {
        McpRecords { n }
    }
}

pub fn answer() -> u64 {
    let records = McpRecords::new(1);
    records.n
}
"#;

const FIXTURE_DECLARED_A2A: &str = r#"[[dormant]]
subject = "a2a"
aspect  = "unit-path"
module  = "crates/busbar/src/root/units_a2a.rs"
reason  = "pre-wired ahead of the switch-on; the kernel-loop sibling is proven against the real traits while the serving path is untouched"
switch  = "the commit that mounts the loop in place of PLANE_DECL's own dispatch"
"#;

/// Run the gate over `fixture` with `plant` applied and report GREEN iff the WHOLE verdict is green.
///
/// The whole verdict, not a narrowed row set: a green control that reads only the rows it is about
/// cannot tell a gate that is satisfied from a gate that is red everywhere else, and being red
/// everywhere else is the specific failure a three-rule-per-plane census invites.
fn green_over(
    gate: &ReachabilityGate,
    cx: &Ctx,
    fixture: &str,
    name: &str,
    plant: Overlay,
) -> Case {
    let covers: Vec<String> = gate.owed();
    let Ok(fcx) = Ctx::at(cx.abs(fixture), cx.scratch().to_path_buf()) else {
        return Case {
            name: name.to_string(),
            covers,
            expected: Expect::Green,
            got: Expect::Skipped,
        };
    };
    let verdict = execute(gate, &fcx.with_overlay(plant));
    let offenders: Vec<String> = verdict
        .rows
        .iter()
        .filter(|r| r.status != Status::Pass)
        .map(|r| format!("{} {}", r.id, r.detail))
        .chain(verdict.problems.iter().cloned())
        .collect();
    Case {
        name: name.to_string(),
        covers,
        expected: Expect::Green,
        got: if offenders.is_empty() {
            Expect::Green
        } else {
            Expect::Red { naming: offenders }
        },
    }
}

/// The RED twin of [`green_over`]: the same fixture, the same plant mechanism, narrowed to the rows
/// the case is about. It exists because [`crate::gates::prove_red`] overlays onto the Ctx it is
/// handed — the workspace — and the claim this proves is about a plant on the GREEN FIXTURE.
fn red_over(
    gate: &ReachabilityGate,
    cx: &Ctx,
    fixture: &str,
    name: &str,
    covers: &[String],
    plant: Overlay,
    naming: &str,
) -> Case {
    let covers: Vec<String> = covers.to_vec();
    let expected = Expect::Red {
        naming: vec![naming.to_string()],
    };
    let Ok(fcx) = Ctx::at(cx.abs(fixture), cx.scratch().to_path_buf()) else {
        return Case {
            name: name.to_string(),
            covers,
            expected,
            got: Expect::Skipped,
        };
    };
    let verdict = execute(gate, &fcx.with_overlay(plant));
    let offenders: Vec<String> = verdict
        .rows
        .iter()
        .filter(|r| r.status != Status::Pass && covers.iter().any(|c| c == &r.id))
        .map(|r| format!("{} {}", r.id, r.detail))
        .collect();
    Case {
        name: name.to_string(),
        covers,
        expected,
        got: if offenders.is_empty() {
            Expect::Green
        } else {
            Expect::Red { naming: offenders }
        },
    }
}

/// The site list, CAPPED. `VoiceUnit` has forty-eight construction sites and every one of them is
/// in one test file; a ledger row that prints all forty-eight is a row a reader scrolls past, and
/// the count plus a sample is the whole of what anybody acts on. The NON-TEST sites are listed
/// first and never elided — they are the ones a reader has to look at.
fn describe(sites: &[Site]) -> String {
    const SHOWN: usize = 6;
    if sites.is_empty() {
        return "nowhere at all".to_string();
    }
    let render = |s: &Site| format!("{}:{} [{}]", s.rel, s.line, s.why.label());
    let mut ordered: Vec<&Site> = sites.iter().filter(|s| s.why != SiteKind::Test).collect();
    let tests: Vec<&Site> = sites.iter().filter(|s| s.why == SiteKind::Test).collect();
    let room = SHOWN.saturating_sub(ordered.len());
    let elided = tests.len().saturating_sub(room);
    ordered.extend(tests.iter().take(room));
    let mut out: Vec<String> = ordered.iter().map(|s| render(s)).collect();
    if elided > 0 {
        out.push(format!("+{elided} more test site(s)"));
    }
    format!("{} site(s): {}", sites.len(), out.join(", "))
}

fn describe_live(sites: &[&Site]) -> String {
    sites
        .iter()
        .map(|s| format!("{}:{}", s.rel, s.line))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// THE TWO ROSTERS, HELD IN STEP. `crate::planes::PLANE_KEYS` is the ON-DISK roster of four and
    /// `ROSTER` is #48's locked roster of five; the gap between them is real and named in both
    /// headers. What must never happen is a key in one that maps to nothing in the other — an
    /// on-disk plane this gate has no row for is a plane it scans nothing of, and zero findings is
    /// the passing answer to every rule. This is a claim about two Rust constants, which is why it
    /// is a unit test and not a gate row: a gate row would need a planted tree to prove a fact that
    /// is fixed at compile time.
    #[test]
    fn every_on_disk_plane_key_maps_to_a_roster_plane() {
        for key in crate::planes::PLANE_KEYS {
            assert!(
                ROSTER.iter().any(|p| p.key == key || p.on_disk == key),
                "on-disk plane key `{key}` maps to no plane in the #48 roster — add it to ROSTER \
                 (or to its `on_disk` spelling) or this gate scans nothing of it"
            );
        }
    }

    /// Every roster row is distinct in both spellings, and every aspect the declaration file may
    /// name is one this gate actually measures.
    #[test]
    fn the_roster_and_the_aspect_vocabulary_are_well_formed() {
        let keys: BTreeSet<&str> = ROSTER.iter().map(|p| p.key).collect();
        assert_eq!(keys.len(), ROSTER.len(), "two roster rows under one key");
        let modules: BTreeSet<&str> = ROSTER.iter().map(|p| p.module).collect();
        assert_eq!(modules.len(), ROSTER.len(), "two planes claim one module");
        assert_eq!(ASPECTS.len(), 4, "four rules, four aspects");
        for p in ROSTER {
            assert!(
                p.module.starts_with("units_"),
                "`{}` names a module the roster row cannot find",
                p.key
            );
            assert!(
                !p.register_tokens.is_empty(),
                "`{}` declares no token",
                p.key
            );
            assert!(p.note.len() >= 20, "`{}` carries no written note", p.key);
        }
    }

    /// The constructor discriminator, which is the whole gate, on the two real shapes.
    #[test]
    fn a_constructors_own_body_is_not_a_reach_and_a_callers_is() {
        let ctor = test_scope(
            "impl A2aUnits {\n    pub fn new(n: u64) -> Self {\n        A2aUnits { n }\n    }\n}\n",
        );
        assert!(
            in_own_constructor(&ctor, 2, "A2aUnits"),
            "a `-> Self` body building the type IS the constructor"
        );
        let caller = test_scope(
            "impl Node {\n    pub async fn answer(\n        &self,\n    ) -> Response {\n        let u = LlmUnit { a: 1 };\n        u.go()\n    }\n}\n",
        );
        assert!(
            !in_own_constructor(&caller, 4, "LlmUnit"),
            "a fn returning something else is a CALLER, however it spells the construction"
        );
    }

    /// A test-only feature is test scope. Without this, moving a construction into a
    /// `#[cfg(feature = "test-harness")]` module turns the gate green while changing nothing.
    #[test]
    fn a_test_only_feature_gate_is_test_scope() {
        let src =
            "#[cfg(feature = \"test-harness\")]\nfn h() {\n    let u = VoiceUnit::new(1);\n}\n";
        let lines = test_scope(&normalize_test_cfgs(src));
        assert!(lines[2].gated, "a test-harness feature body is test scope");
        let prod =
            "#[cfg(feature = \"plane-voice\")]\nfn h() {\n    let u = VoiceUnit::new(1);\n}\n";
        let lines = test_scope(&normalize_test_cfgs(prod));
        assert!(!lines[2].gated, "a shipping feature body is production");
    }

    /// A MODULE'S OWN `mod` DECLARATION IS NOT A USE OF IT. This is the single line that separates
    /// `money_book.rs` — declared by `root/mod.rs` and named nowhere else — from a module something
    /// actually calls; without it the module graph calls every file in the tree reached.
    #[test]
    fn a_mod_declaration_is_not_an_edge() {
        assert_eq!(
            mod_statement("pub mod money_book;").as_deref(),
            Some("money_book")
        );
        assert_eq!(mod_statement("mod tests;").as_deref(), Some("tests"));
        assert_eq!(mod_statement("root::money_book::build();"), None);
        assert_eq!(mod_statement("mod inline {"), None);
    }
}
