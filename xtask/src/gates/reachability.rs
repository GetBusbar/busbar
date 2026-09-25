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
//!   on purpose: the plane's crate is a row of the manifest's LINKED TABLE
//!   (`[package.metadata.busbar.linked]` in `crates/busbar/Cargo.toml` — the data `build.rs` turns
//!   into the `LINKED` tables `main.rs` includes) whose `linked-axes` row puts it on the `plane`
//!   axis, AND the BODY of `register_planes()` in `crates/busbar/src/main.rs` folds that table; or a
//!   plane type token in the body of
//!   `plane_claims()` in `crates/busbar/src/root/registry.rs`. Read off comment-stripped code and
//!   the manifest's own rows. A plane named in a doc comment is not a plane that is served.
//! * `reachability:unit-path:<plane>` — the plane's LIVE UNIT PATH is CONSTRUCTED IN A FUNCTION
//!   REACHED FROM `fn main()` (R1, 2026-09-25). A plane's unit path is one of two things, both
//!   derived, never listed:
//!   - **the kernel-loop runner registered for its capability key** — the #28 rider: a runner
//!     handed to `register_gauntlet_runner`/`register_session_runner` (directly, or by the function
//!     that wraps the call) that arrives at a construction of a type the crate writes `impl … Units
//!     for` for (`GauntletKernelUnit`, built in `run_gauntlet_via_kernel`/`open_gauntlet_via_kernel`),
//!     with this plane's key — spelled through its linked crate (`busbar_mcp::PLANE_KEY`), or flipped
//!     by a fold over `LINKED` whose `linked-axes` row carries the gauntlet axis — routed onto it by a
//!     non-test line in a function reached from `fn main()` (`gauntlet_install::install()`);
//!   - **or a `Units` impl its linked entry exports** — a type the entry module (the `linked-entry`
//!     row's `crate::root::<module>`, else the plugin crate's `linked` module) declares and builds
//!     in an item its `linked-axes` row puts in the generated table, or one that item reaches.
//!
//!   `root/units_<plane>.rs` IS NOT THE TEST. That module predates the unification; on `fc4900bbe`
//!   three of the four were rustc-dead while the rider served their planes (K2-0 §2, §5), so a row
//!   that asked about the module was asking about the wrong code. A green row still names a
//!   superseded module beside the live path when one is on disk, so green never reads as a statement
//!   about it. **A plane with neither is RED** (item 180), however many modules it has.
//! * `reachability:root-reach:<plane>` — a MODULE `fn main()` reaches, over the module graph,
//!   routes the plane onto its unit path: it carries a non-test flip of the plane's key, or it is
//!   the plane's linked entry and declares a `Units` impl. Kept separate from the row above for a
//!   reason: a flip in a reached module can sit in a function nothing calls, or be flipped onto a
//!   runner that builds no unit — root-reach PASSES and unit-path FAILS. The two rows together say
//!   the exact true thing.
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
//! * **The item graph is PRECISE, and under-approximates.** Each mention is resolved to the file
//!   that declares it before it becomes an edge — `stem::name` into that module, a bare name into
//!   its own file or the file a `use` imports it from, a method or `Type::name` into its own file
//!   only, any other crate path to nothing. It used to key on simple names, which over-approximated:
//!   on `fc4900bbe` it called 52 of the 96 rustc-dead items of `units_mcp.rs` reached (K2-0 §0).
//!   An edge this cannot resolve (a method call through a type in another file) is MISSING — a FALSE
//!   RED somebody reads and answers, never a dead function read as live. The own-constructor
//!   exclusion still applies: a `-> Self` body building its own type is never evidence that anything
//!   CALLS it. The module graph, which answers `root-reach` and `root-module`, keys on FILE STEMS,
//!   which are unique under `crates/busbar/src/root/`.
//! * **A plugin crate's linked entry module is read, and only that file.** A plane whose unit path
//!   is a `Units` impl its own crate's `linked` module exports is credited from that one file (found
//!   through the dependency's `path` in the manifest); nothing else outside `crates/busbar/src` is
//!   scanned.
//! * **`main.rs` is seeded whole**, not just `fn main`'s body. Everything in the composition root's
//!   own file is boot code by construction; drawing the line inside it would make the gate's answer
//!   depend on which helper `main` happens to have been factored into.
//! * **The generated linked tables are part of `main.rs`.** `main.rs` `include!`s
//!   `$OUT_DIR/linked.rs`, which is not in the tree; its contents are DATA in the manifest
//!   (`[package.metadata.busbar.root-units]` and `[package.metadata.busbar.linked-entry]` name the
//!   root modules it references, and `linked-axes` which of an entry module's items). So each row
//!   there seeds its module and its items as reached from `main.rs` — read from the manifest, never
//!   assumed.

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
/// THE CITED EVIDENCE IS READ, AND NOT MERELY NAMED.
///
/// Three of this gate's failure details end with the sentence "the site-by-site evidence is written
/// up in `qa/reachability-evidence.md`". For as long as that sentence has existed, those three
/// `format!` strings were the file's ONLY appearance anywhere in this tree. Nothing opened it.
/// Nothing checked it was there. Nothing noticed when a module it writes up was folded away, and
/// nothing noticed when a new module went dormant that it says nothing about. A file we write and
/// never read is evidence of nothing, and a citation nobody checks is a citation that can be wrong
/// for a year without anyone learning that it is.
///
/// This row reads it, in BOTH directions, because only one of them expires on its own:
///
/// * **FORWARD** — every module this run reports dormant or unreached is written up there. A red
///   row that sends its reader to a document which does not discuss its subject is a dead end with
///   a footnote. Forward is what makes the evidence keep up with the gate.
/// * **BACKWARD** — every module the evidence writes up is still in the tree. Evidence about a file
///   somebody deleted is an archive, and an archive that reads as current is worse than no document
///   at all: it is the fold already done, described as still owed. Backward is what makes the
///   evidence expire.
pub const ROW_EVIDENCE: &str = "reachability:evidence";

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
    /// The pre-unification `root/<module>.rs` named for this plane. NOT its unit path (R1): it is
    /// what `reachability:roster` maps `root/units_*` onto, and what a green unit-path row names as
    /// superseded while it is still on disk. Checked for existence, never assumed.
    module: &'static str,
    /// The plugin crate whose row in the manifest's linked table registers this plane (folded by
    /// `register_planes()` over the generated `LINKED` table). Its crate path is how a flip spells
    /// this plane's capability key (`busbar_mcp::PLANE_KEY`), and its entry module is where a
    /// `Units` export is looked for.
    linked_crate: &'static str,
    /// Any one of these, in the body of `plane_claims()`, IS the registration. Each is a type the
    /// root can only name in order to install it.
    register_tokens: &'static [&'static str],
    /// Why this row is spelled the way it is, for the reader who finds it red.
    note: &'static str,
}

const ROSTER: &[Plane] = &[
    Plane {
        key: "llm",
        on_disk: "llm",
        module: "units_llm",
        linked_crate: "busbar-llm",
        register_tokens: &["LlmPlane"],
        note: "the 1.5.5 plane; `proto-llm` carries the crate edge, the protocol DECLS and the \
               plane decl together",
    },
    Plane {
        key: "mcp",
        on_disk: "mcp",
        module: "units_mcp",
        linked_crate: "busbar-mcp",
        register_tokens: &["McpPlane"],
        note: "extracted to `busbar-mcp`; served on the kernel loop by the #28 rider, and \
               `root/units_mcp.rs` is the superseded pre-unification module",
    },
    Plane {
        key: "a2a",
        on_disk: "a2a",
        module: "units_a2a",
        linked_crate: "busbar-a2a",
        register_tokens: &["A2aPlane"],
        note: "served by `busbar_a2a::LINKED` on the kernel loop through the #28 rider; \
               `root/units_a2a.rs` is the superseded sibling the 2026-09-22 money findings were in",
    },
    Plane {
        key: "streaming",
        on_disk: "voice",
        module: "units_voice",
        linked_crate: "busbar-voice",
        register_tokens: &["StreamingPlane"],
        note: "#18: streaming is the PLANE, voice is one dialect inside it. The rename has not \
               landed, so the module and the crate are still spelled `voice`",
    },
    Plane {
        key: "decision",
        on_disk: "decision",
        module: "units_decision",
        linked_crate: "busbar-plane-decision",
        register_tokens: &["DecisionPlane", "busbar_plane_decision"],
        note:
            "#48's fifth plane (jev). Its linked entry is `root/plane_decision.rs`, a declaration \
               with no served door; whether 1.6.0 serves it is owner question Q72(3)",
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
fn reached_modules(files: &[Scanned], generated: &BTreeSet<(String, String)>) -> BTreeSet<String> {
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
        // The generated table `main.rs` includes is `main.rs`'s text too (see the header).
        if f.rel == MAIN_RS {
            hit.extend(generated.iter().filter_map(|(m, _)| names.get(m.as_str())));
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

/// ONE IDENTIFIER ON A LINE, with the one fact about its spelling the call graph resolves by: the
/// path segment written in front of it (`root::gauntlet_install::install` is `install` qualified by
/// `gauntlet_install`), or that it is a method (`.drive(`). `end` is the byte offset just past it.
struct Token {
    word: String,
    qual: Option<String>,
    method: bool,
    end: usize,
}

/// The identifier tokens of a line of code, each with its qualifier.
fn tokens(code: &str) -> Vec<Token> {
    let mut out: Vec<Token> = Vec::new();
    let bytes = code.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if !is_word_char(bytes[i] as char) {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && is_word_char(bytes[i] as char) {
            i += 1;
        }
        let word = &code[start..i];
        let before = code[..start].trim_end();
        let (qual, method) = if let Some(head) = before.strip_suffix("::") {
            let head = head.trim_end();
            let q: String = head
                .chars()
                .rev()
                .take_while(|c| is_word_char(*c))
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            ((!q.is_empty()).then_some(q), false)
        } else {
            (None, before.ends_with('.'))
        };
        out.push(Token {
            word: word.to_string(),
            qual,
            method,
            end: i,
        });
    }
    out
}

/// THE PRECISE ITEM GRAPH — every edge RESOLVED to the file that declares its target.
///
/// The graph this gate used to answer "is the function that builds the unit reached?" keyed on
/// SIMPLE NAMES, so every `new`, `settle`, `verify` and `fmt` in the crate was one node: measured on
/// `fc4900bbe` (K2-0), it called 52 of the 96 rustc-dead items of `units_mcp.rs` REACHED. A unit-path
/// answer read off that graph is an answer about names, not about calls. This one resolves each
/// mention before it draws an edge:
///
/// * `stem::name` — a path through a module of this crate — resolves into THAT file only;
/// * a bare `name` resolves into the same file, or into the file a `use …::stem::{name}` in this
///   file imports it from;
/// * `.name(` (a method) and `Type::name` resolve into the same file only — a method call names no
///   receiver type this scan can see, so it never becomes a cross-file edge;
/// * any other qualified path (`busbar_kernel::…`, `std::…`) names another crate: no edge.
///
/// Every rule UNDER-approximates rather than over: an edge this cannot resolve is missing, which
/// reads a reached function as unreached — a FALSE RED somebody reads and answers — never a dead
/// function as live.
struct Graph<'a> {
    items: &'a [Item],
    by_name: BTreeMap<(usize, &'a str), Vec<usize>>,
    stems: BTreeMap<&'a str, Vec<usize>>,
    imports: Vec<BTreeMap<String, Vec<usize>>>,
    edges: Vec<BTreeSet<usize>>,
}

impl<'a> Graph<'a> {
    fn new(files: &'a [Scanned], items: &'a [Item]) -> Self {
        let mut by_name: BTreeMap<(usize, &str), Vec<usize>> = BTreeMap::new();
        for (i, it) in items.iter().enumerate() {
            by_name
                .entry((it.file, it.name.as_str()))
                .or_default()
                .push(i);
        }
        let mut stems: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
        for (fi, f) in files.iter().enumerate() {
            if !f.whole_file_is_test() {
                stems.entry(f.stem.as_str()).or_default().push(fi);
            }
        }
        let imports = files.iter().map(|f| use_imports(f, &stems)).collect();
        let mut g = Graph {
            items,
            by_name,
            stems,
            imports,
            edges: Vec::new(),
        };
        let mut edges: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); items.len()];
        for (i, it) in items.iter().enumerate() {
            let f = &files[it.file];
            for l in &f.lines[it.start..=it.end] {
                if l.gated || mod_statement(l.code.trim()).is_some() {
                    continue;
                }
                for t in tokens(&l.counted) {
                    for j in g.resolve(it.file, &t) {
                        if j != i {
                            edges[i].insert(j);
                        }
                    }
                }
            }
        }
        g.edges = edges;
        g
    }

    /// The items a token written in `file` can name.
    fn resolve(&self, file: usize, t: &Token) -> Vec<usize> {
        let named_in = |fs: &[usize]| -> Vec<usize> {
            fs.iter()
                .filter_map(|f| self.by_name.get(&(*f, t.word.as_str())))
                .flatten()
                .copied()
                .collect()
        };
        if t.method {
            return named_in(&[file]);
        }
        match t.qual.as_deref() {
            Some(q) if self.stems.contains_key(q) => named_in(&self.stems[q]),
            Some(q) if q == "Self" || q == "self" || q.starts_with(|c: char| c.is_uppercase()) => {
                named_in(&[file])
            }
            Some(_) => Vec::new(),
            None => {
                let mut out = named_in(&[file]);
                if let Some(fs) = self.imports[file].get(&t.word) {
                    out.extend(named_in(fs));
                }
                out
            }
        }
    }

    /// Every item reachable from `seeds` along resolved edges, the seeds included.
    fn closure(&self, seeds: impl IntoIterator<Item = usize>) -> BTreeSet<usize> {
        let mut seen: BTreeSet<usize> = BTreeSet::new();
        let mut queue: VecDeque<usize> = VecDeque::new();
        for s in seeds {
            if seen.insert(s) {
                queue.push_back(s);
            }
        }
        while let Some(n) = queue.pop_front() {
            for m in &self.edges[n] {
                if seen.insert(*m) {
                    queue.push_back(*m);
                }
            }
        }
        seen
    }

    /// The items named `name` that `file` declares.
    fn declared(&self, file: usize, name: &str) -> Vec<usize> {
        self.by_name.get(&(file, name)).cloned().unwrap_or_default()
    }
}

/// What the `use` statements of one file import from modules of this crate: `name → the files of
/// the module it is imported from`. `use crate::root::gauntlet_kernel::{open_gauntlet_via_kernel,
/// run_gauntlet_via_kernel};` imports both names from `gauntlet_kernel.rs`. A brace list is read
/// whole (nested lists included) — a module name read as an imported item resolves to no item and
/// draws no edge.
fn use_imports(f: &Scanned, stems: &BTreeMap<&str, Vec<usize>>) -> BTreeMap<String, Vec<usize>> {
    let mut out: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    let mut stmt: Option<String> = None;
    for l in &f.lines {
        if l.gated {
            continue;
        }
        let code = l.counted.trim();
        let opens = strip_visibility(code).starts_with("use ");
        if stmt.is_none() && !opens {
            continue;
        }
        let s = stmt.get_or_insert_with(String::new);
        s.push_str(code);
        s.push(' ');
        if !code.ends_with(';') {
            continue;
        }
        let s = stmt.take().unwrap_or_default();
        let toks = tokens(&s);
        for (k, t) in toks.iter().enumerate() {
            let Some(files) = stems.get(t.word.as_str()) else {
                continue;
            };
            let rest = s[t.end..].trim_start();
            let Some(rest) = rest.strip_prefix("::") else {
                continue;
            };
            let rest = rest.trim_start();
            let imported: Vec<String> = if rest.starts_with('{') {
                let mut depth = 0i32;
                let mut end = rest.len();
                for (i, c) in rest.char_indices() {
                    match c {
                        '{' => depth += 1,
                        '}' => {
                            depth -= 1;
                            if depth == 0 {
                                end = i;
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                words(&rest[..end])
            } else {
                toks.get(k + 1)
                    .map(|n| vec![n.word.clone()])
                    .unwrap_or_default()
            };
            for name in imported {
                out.entry(name).or_default().extend(files.iter().copied());
            }
        }
    }
    out
}

/// Which items `main.rs` reaches, transitively, over the PRECISE graph.
///
/// THE SEED IS `main.rs`, WHOLE. Everything in the composition root's own file is boot code by
/// construction; drawing the line at `fn main`'s body would make the answer depend on which helper
/// `main` happens to have been factored into, which is not a property of the tree. The items the
/// generated table it includes names are seeded too (see the header).
fn reached_items(
    files: &[Scanned],
    graph: &Graph<'_>,
    generated: &BTreeSet<(String, String)>,
) -> BTreeSet<usize> {
    let seeds = graph.items.iter().enumerate().filter_map(|(i, it)| {
        let f = &files[it.file];
        (f.rel == MAIN_RS || generated.contains(&(f.stem.clone(), it.name.clone()))).then_some(i)
    });
    graph.closure(seeds)
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
    /// The item the construction is written in, when it is inside one.
    item: Option<String>,
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
    /// Production code, but in a function the question's chain does not arrive at.
    NotReached,
    /// The real thing: production code, not a constructor, in a function the chain arrives at.
    Live,
}

impl SiteKind {
    fn label(&self) -> &'static str {
        match self {
            SiteKind::Test => "test",
            SiteKind::OwnConstructor => "its own constructor",
            SiteKind::NotReached => "not reached",
            SiteKind::Live => "LIVE",
        }
    }
}

/// Every construction of `tname` in `files`, each classified against `live` — the set of items
/// counted as reached for the question being asked (from `fn main()`, or from a registered runner).
///
/// Two spellings are counted, because both are used in this tree: `T::new(` (the call) and `T {`
/// (the struct literal, which is how `GauntletKernelUnit`, `LlmUnit` and `A2aUnits` are all actually
/// built). Declaration lines are excluded by shape — `impl T {`, `struct T {`, `enum T {` — so a
/// type's own definition is never read as a construction of it.
fn construction_sites(
    files: &[Scanned],
    items: &[Item],
    live: &BTreeSet<usize>,
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
            if !word_hit(code, tname)
                || (!code.contains(&needle_call) && !code.contains(&needle_lit))
            {
                continue;
            }
            let t = code.trim_start();
            if t.starts_with("impl")
                || t.starts_with("struct ")
                || t.starts_with("pub struct ")
                || t.starts_with("pub(crate) struct ")
                || t.starts_with("enum ")
                || t.starts_with("pub enum ")
                || t.starts_with("use ")
            {
                continue;
            }
            let enclosing = enclosing_item(items, fi, i);
            let why = if f.is_test_line(i) {
                SiteKind::Test
            } else if in_own_constructor(&f.lines, i, tname) {
                SiteKind::OwnConstructor
            } else if enclosing.is_some_and(|n| live.contains(&n)) {
                SiteKind::Live
            } else {
                SiteKind::NotReached
            };
            out.push(Site {
                rel: f.rel.clone(),
                line: l.no,
                item: enclosing.map(|n| items[n].name.clone()),
                why,
            });
        }
    }
    out
}

/// The innermost non-test item whose span contains this line.
fn enclosing_item(items: &[Item], file: usize, line: usize) -> Option<usize> {
    items
        .iter()
        .enumerate()
        .filter(|(_, it)| it.file == file && it.start <= line && line <= it.end)
        .min_by_key(|(_, it)| it.end - it.start)
        .map(|(i, _)| i)
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
// THE LIVE UNIT PATH (R1) — the kernel-loop runner registered for a plane's key, or a `Units`
// impl its linked entry exports
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// The kernel's two runner registrations (`busbar_kernel::plane_host`), each with the
/// `linked-axes` axis a fold over the linked table flips a plane onto it by. These are the names of
/// the kernel API a runner is registered THROUGH — the one place this gate names an API rather than
/// deriving it, exactly as it names the `Units` trait.
const RUNNER_REGISTRATIONS: &[(&str, &str)] = &[
    ("register_gauntlet_runner", "gauntlet-one-shot"),
    ("register_session_runner", "gauntlet-session"),
];

/// One call into a runner registration, and the `Units` constructions the runner it registers
/// arrives at over the precise graph.
struct Registration {
    rel: String,
    line: usize,
    /// The innermost item the call is written in.
    item: Option<usize>,
    gated: bool,
    api: &'static str,
    axis: &'static str,
    runner: String,
    builds: Vec<(String, Site)>,
}

/// One place a capability key is routed onto a registration: the registration itself when its key
/// argument names a plane crate, or a call of the function that wraps it
/// (`flip_one_shot_to_kernel(busbar_mcp::PLANE_KEY)`).
struct Flip {
    rel: String,
    line: usize,
    file: usize,
    item: Option<usize>,
    gated: bool,
    reg: usize,
    /// The crate paths the key argument is spelled through (`busbar_mcp` for
    /// `busbar_mcp::PLANE_KEY`).
    quals: Vec<String>,
    /// The key is not spelled at all, and the function the call is written in folds `LINKED`: the
    /// planes it flips are the linked rows whose axes carry the registration's axis.
    fold: bool,
}

/// The text between the parentheses of the call whose name ends at byte `from` of line `li` — across
/// lines, because this tree writes long argument lists one per line. `None` when no `(` follows.
fn call_args(lines: &[ScopeLine], li: usize, from: usize) -> Option<String> {
    let first = &lines[li].counted;
    let rest = first.get(from..)?.trim_start();
    if !rest.starts_with('(') {
        return None;
    }
    let mut out = String::new();
    let mut depth = 0i32;
    let mut text: Vec<&str> = vec![rest];
    text.extend(
        lines
            .iter()
            .skip(li + 1)
            .take(16)
            .map(|l| l.counted.as_str()),
    );
    for chunk in text {
        for c in chunk.chars() {
            match c {
                '(' | '[' | '{' => {
                    depth += 1;
                    if depth == 1 && c == '(' {
                        continue;
                    }
                }
                ')' | ']' | '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(out);
                    }
                }
                _ => {}
            }
            out.push(c);
        }
        out.push(' ');
    }
    None
}

/// `a, f(b, c), d` → `["a", "f(b, c)", "d"]`.
fn split_top(args: &str) -> Vec<String> {
    let mut out = vec![String::new()];
    let mut depth = 0i32;
    for c in args.chars() {
        match c {
            '(' | '[' | '{' | '<' => depth += 1,
            ')' | ']' | '}' | '>' => depth -= 1,
            ',' if depth == 0 => {
                out.push(String::new());
                continue;
            }
            _ => {}
        }
        if let Some(last) = out.last_mut() {
            last.push(c);
        }
    }
    out.into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// The crate paths an expression spells (`busbar_llm::PLANE_DECLARATION.key` → `busbar_llm`).
fn path_quals(expr: &str) -> Vec<String> {
    tokens(expr).into_iter().filter_map(|t| t.qual).collect()
}

/// Every `Units` type declared in the non-test code of `files`.
fn all_unit_types(files: &[Scanned]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for f in files.iter().filter(|f| !f.whole_file_is_test()) {
        for t in unit_types(f) {
            if !out.contains(&t) {
                out.push(t);
            }
        }
    }
    out
}

/// The live `Units` constructions `from` arrives at.
fn builds_from(
    files: &[Scanned],
    items: &[Item],
    graph: &Graph<'_>,
    units: &[String],
    from: impl IntoIterator<Item = usize>,
) -> Vec<(String, Site)> {
    let closure = graph.closure(from);
    let mut out = Vec::new();
    for t in units {
        for s in construction_sites(files, items, &closure, t) {
            if s.why == SiteKind::Live {
                out.push((t.clone(), s));
            }
        }
    }
    out
}

/// Every call into a runner registration under the crate's `src/`.
fn registrations(
    files: &[Scanned],
    items: &[Item],
    graph: &Graph<'_>,
    units: &[String],
) -> Vec<Registration> {
    let mut out = Vec::new();
    for (fi, f) in files.iter().enumerate() {
        if f.whole_file_is_test() {
            continue;
        }
        for (li, l) in f.lines.iter().enumerate() {
            if is_fn_decl(&l.code) {
                continue;
            }
            for t in tokens(&l.counted) {
                let Some((api, axis)) = RUNNER_REGISTRATIONS
                    .iter()
                    .find(|(a, _)| *a == t.word && !t.method)
                else {
                    continue;
                };
                let Some(args) = call_args(&f.lines, li, t.end) else {
                    continue;
                };
                let parts = split_top(&args);
                let Some(runner) = parts.last().filter(|_| parts.len() >= 2) else {
                    continue;
                };
                let runner_items: Vec<usize> = tokens(runner)
                    .last()
                    .map(|rt| graph.resolve(fi, rt))
                    .unwrap_or_default();
                out.push(Registration {
                    rel: f.rel.clone(),
                    line: l.no,
                    item: enclosing_item(items, fi, li),
                    gated: f.is_test_line(li),
                    api,
                    axis,
                    runner: runner.clone(),
                    builds: builds_from(files, items, graph, units, runner_items),
                });
            }
        }
    }
    out
}

/// Every place a key is routed onto a registration — the registration itself when its key names a
/// crate path, else each call of the function it is written in.
fn flips(files: &[Scanned], items: &[Item], graph: &Graph<'_>, regs: &[Registration]) -> Vec<Flip> {
    let mut out = Vec::new();
    for (ri, r) in regs.iter().enumerate() {
        // The registration's own key argument, re-read from its line.
        let Some((fi, f)) = files.iter().enumerate().find(|(_, f)| f.rel == r.rel) else {
            continue;
        };
        let Some(li) = f.lines.iter().position(|l| l.no == r.line) else {
            continue;
        };
        let key = tokens(&f.lines[li].counted)
            .into_iter()
            .find(|t| t.word == r.api)
            .and_then(|t| call_args(&f.lines, li, t.end))
            .and_then(|a| split_top(&a).into_iter().next())
            .unwrap_or_default();
        let quals = path_quals(&key);
        if !quals.is_empty() {
            out.push(Flip {
                rel: r.rel.clone(),
                line: r.line,
                file: fi,
                item: r.item,
                gated: r.gated,
                reg: ri,
                quals,
                fold: false,
            });
            continue;
        }
        let Some(wrapper) = r.item else {
            continue;
        };
        let wname = items[wrapper].name.as_str();
        for (fi2, f2) in files.iter().enumerate() {
            if f2.whole_file_is_test() || !f2.lines.iter().any(|l| word_hit(&l.counted, wname)) {
                continue;
            }
            for (li2, l2) in f2.lines.iter().enumerate() {
                if is_fn_decl(&l2.code) {
                    continue;
                }
                for t in tokens(&l2.counted) {
                    if t.word != wname || !graph.resolve(fi2, &t).contains(&wrapper) {
                        continue;
                    }
                    let Some(args) = call_args(&f2.lines, li2, t.end) else {
                        continue;
                    };
                    let first = split_top(&args).into_iter().next().unwrap_or_default();
                    let quals = path_quals(&first);
                    let item = enclosing_item(items, fi2, li2);
                    let fold = quals.is_empty()
                        && item.is_some_and(|h| {
                            f2.lines[items[h].start..=items[h].end]
                                .iter()
                                .any(|l| !l.gated && word_hit(&l.counted, "LINKED"))
                        });
                    if quals.is_empty() && !fold {
                        continue;
                    }
                    out.push(Flip {
                        rel: f2.rel.clone(),
                        line: l2.no,
                        file: fi2,
                        item,
                        gated: f2.is_test_line(li2),
                        reg: ri,
                        quals,
                        fold,
                    });
                }
            }
        }
    }
    out
}

/// What a plane's linked entry module exports on the unit path.
struct Export {
    /// Where the entry module was looked for (the file, when it exists).
    rel: String,
    exists: bool,
    /// The root module stem, when the entry module is inside the composition root.
    in_root: Option<String>,
    units: Vec<String>,
    /// The items the linked-axes row makes the generated table name.
    exported: Vec<String>,
    builds: Vec<(String, Site)>,
}

/// `crates/busbar/../busbar-llm` → `crates/busbar-llm`.
fn resolve_rel(p: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    out.join("/")
}

/// The directory of dependency `krate`, read off its `path = "…"` in the binary crate's manifest.
fn dep_dir(manifest: &str, krate: &str) -> Option<String> {
    for line in manifest.lines() {
        let code = line.split('#').next().unwrap_or("").trim();
        let Some(rest) = code.strip_prefix(krate) else {
            continue;
        };
        if !rest.trim_start().starts_with('=') {
            continue;
        }
        let at = rest.find("path")?;
        let rest = rest[at + 4..].trim_start().strip_prefix('=')?.trim_start();
        let rest = rest.strip_prefix('"')?;
        let end = rest.find('"')?;
        let dir = CRATE_MANIFEST.rsplit_once('/').map_or("", |(d, _)| d);
        return Some(resolve_rel(&format!("{dir}/{}", &rest[..end])));
    }
    None
}

/// The plane's linked entry module and the `Units` impl it exports, if any: a type it declares,
/// built LIVE in an item its `linked-axes` row puts in the generated table (or one that item
/// reaches). The entry is the `linked-entry` row's `crate::root::<module>` when there is one, else
/// the crate's `linked` module — the same resolution `linked_gen.rs` gives `build.rs`.
fn linked_export(
    cx: &Ctx,
    manifest: &str,
    files: &[Scanned],
    items: &[Item],
    graph: &Graph<'_>,
    krate: &str,
) -> Export {
    let exported: Vec<String> = axes_of(manifest, krate)
        .iter()
        .flat_map(|a| {
            AXIS_ITEMS
                .iter()
                .filter(move |(x, _)| x == a)
                .flat_map(|(_, it)| it.iter().map(|s| (*s).to_string()))
        })
        .collect();
    let entry = manifest_table(manifest, "package.metadata.busbar.linked-entry")
        .into_iter()
        .find(|(k, _)| k == krate)
        .map(|(_, v)| v);
    if let Some(module) = entry
        .as_deref()
        .and_then(|v| v.strip_prefix("crate::root::"))
    {
        let found = files.iter().enumerate().find(|(_, f)| {
            !f.whole_file_is_test()
                && f.rel.starts_with(&format!("{ROOT_DIR}/"))
                && f.stem == module
        });
        let Some((fi, f)) = found else {
            return Export {
                rel: format!("{ROOT_DIR}/{module}.rs"),
                exists: false,
                in_root: Some(module.to_string()),
                units: Vec::new(),
                exported,
                builds: Vec::new(),
            };
        };
        let units = unit_types(f);
        let seeds: Vec<usize> = exported
            .iter()
            .flat_map(|n| graph.declared(fi, n))
            .collect();
        let builds = builds_from(files, items, graph, &units, seeds);
        return Export {
            rel: f.rel.clone(),
            exists: true,
            in_root: Some(module.to_string()),
            units,
            exported,
            builds,
        };
    }
    // A plugin crate's own entry module: `<crate>::<module>` (`linked` unless the row says otherwise).
    let module = entry
        .as_deref()
        .and_then(|v| v.rsplit_once("::").map(|(_, m)| m.to_string()))
        .unwrap_or_else(|| "linked".to_string());
    let Some(dir) = dep_dir(manifest, krate) else {
        return Export {
            rel: format!("(no `path` for `{krate}` in {CRATE_MANIFEST})"),
            exists: false,
            in_root: None,
            units: Vec::new(),
            exported,
            builds: Vec::new(),
        };
    };
    let candidates = [
        format!("{dir}/src/{module}.rs"),
        format!("{dir}/src/{module}/mod.rs"),
    ];
    let Some((rel, text)) = candidates
        .iter()
        .find_map(|c| cx.read(c).ok().map(|t| (c.clone(), t)))
    else {
        return Export {
            rel: candidates[0].clone(),
            exists: false,
            in_root: None,
            units: Vec::new(),
            exported,
            builds: Vec::new(),
        };
    };
    let one = vec![Scanned {
        path_is_test: false,
        stem: stem_of(&rel),
        rel: rel.clone(),
        lines: test_scope(&normalize_test_cfgs(&text)),
        decl_is_test: false,
    }];
    let its_items = self::items(&one);
    let g = Graph::new(&one, &its_items);
    let units = unit_types(&one[0]);
    let seeds: Vec<usize> = exported.iter().flat_map(|n| g.declared(0, n)).collect();
    let builds = builds_from(&one, &its_items, &g, &units, seeds);
    Export {
        rel,
        exists: true,
        in_root: None,
        units,
        exported,
        builds,
    }
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

/// The `key = "value"` rows of one `[table]` of the binary crate's manifest, in file order — the
/// same reading `crates/busbar/src/linked_gen.rs` gives `build.rs` (one row per line, both sides
/// optionally quoted, `#` starts a comment). An absent table is no rows.
fn manifest_table(manifest: &str, table: &str) -> Vec<(String, String)> {
    let header = format!("[{table}]");
    let mut inside = false;
    let mut rows = Vec::new();
    for line in manifest.lines() {
        let code = line.split('#').next().unwrap_or("").trim();
        if code.starts_with('[') {
            inside = code == header;
            continue;
        }
        if let (true, Some((k, v))) = (inside, code.split_once('=')) {
            rows.push((
                k.trim().trim_matches('"').to_string(),
                v.trim().trim_matches('"').to_string(),
            ));
        }
    }
    rows
}

/// The items a linked entry module exports per registration axis — the same table
/// `crates/busbar/src/linked_gen.rs` generates `LINKED` from (the plane axis is its two items).
const AXIS_ITEMS: &[(&str, &[&str])] = &[
    ("plane", &["PLANE_DECLARATION", "PLANE_HOOKS"]),
    ("protocols", &["PROTOCOLS"]),
    ("path-ingress", &["PATH_INGRESS"]),
    ("body-ingress", &["BODY_INGRESS"]),
    ("protocol-seams", &["install_protocol_seams"]),
    ("diagnostics", &["DIAGNOSTICS"]),
    ("ws-arrivals", &["install_ws_arrivals"]),
    ("on-host", &["on_host"]),
    ("compose", &["compose"]),
    ("stdio-serve", &["stdio_serve"]),
];

/// The registration axes the manifest's `[package.metadata.busbar.linked-axes]` row lists for the
/// linked feature that links `krate` (space-separated; the axes row is keyed by the feature, as the
/// linked row is), or none.
fn axes_of(manifest: &str, krate: &str) -> Vec<String> {
    let features: Vec<String> = manifest_table(manifest, "package.metadata.busbar.linked")
        .into_iter()
        .filter(|(_, k)| k == krate)
        .map(|(f, _)| f)
        .collect();
    manifest_table(manifest, "package.metadata.busbar.linked-axes")
        .into_iter()
        .find(|(f, _)| features.contains(f))
        .map(|(_, v)| v.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default()
}

/// What the generated `$OUT_DIR/linked.rs` that `main.rs` includes references in THIS crate, read
/// off the manifest: each root-unit row's module and its `ROOT_UNIT`, and each linked-entry row that
/// points into the root (`crate::root::<module>`) with the items its axes put in the tables. Returned
/// as `(module stem, item name)` pairs.
fn generated_table_refs(manifest: &str) -> BTreeSet<(String, String)> {
    let mut refs = BTreeSet::new();
    for (_, module) in manifest_table(manifest, "package.metadata.busbar.root-units") {
        refs.insert((module, "ROOT_UNIT".to_string()));
    }
    for (krate, path) in manifest_table(manifest, "package.metadata.busbar.linked-entry") {
        let Some(module) = path.strip_prefix("crate::root::") else {
            continue;
        };
        for axis in axes_of(manifest, &krate) {
            for (_, items) in AXIS_ITEMS.iter().filter(|(a, _)| *a == axis) {
                for item in *items {
                    refs.insert((module.to_string(), (*item).to_string()));
                }
            }
        }
    }
    refs
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
    /// The plane's linked entry module, when it is on the tree — what a red unit-path row cites.
    cites: Option<String>,
}

/// Every backtick-quoted `…/…` path on one line. The evidence's section headings name their subject
/// that way (`## 1. `crates/busbar/src/root/units_a2a.rs` — 1 784 lines, UNIT PATH DORMANT`), so
/// this is how the document says which file a section is about without a second index to drift.
fn backticked_paths(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = line;
    while let Some(open) = rest.find('`') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('`') else { break };
        let inner = &after[..close];
        if inner.contains('/') && !inner.contains(char::is_whitespace) {
            out.push(inner.to_string());
        }
        rest = &after[close + 1..];
    }
    out
}

/// [`ROW_EVIDENCE`] — the document the failure details cite, read forward and backward.
fn evidence_row(
    cx: &Ctx,
    findings: &BTreeMap<&str, Finding>,
    undeclared_root_modules: &[&String],
) -> Row {
    let text = match cx.read(EVIDENCE) {
        Ok(t) => t,
        Err(e) => {
            return Row::fail(
                ROW_EVIDENCE,
                "the evidence document this gate cites by name cannot be read",
                format!(
                    "{EVIDENCE}: {e} — three of this gate's failure details send their reader to \
                     that path. A citation to a document that is not there is worse than no \
                     citation: it reads like the work was done. Restore it, or strike the sentence \
                     from the three details in the same diff."
                ),
            );
        }
    };

    let mut problems: Vec<String> = Vec::new();

    // FORWARD — everything the citing details are about. A red unit-path row cites the plane's
    // linked entry module (the place its unit path would be exported from, and the file a reader
    // opens first); an entry module the tree has not got is cited by nothing and cannot be written up
    // (the backward half would red a section about a path the tree has not got).
    let mut owed: Vec<String> = Vec::new();
    for p in ROSTER {
        if let Some(Finding {
            unit_path: Err(_),
            cites: Some(m),
            ..
        }) = findings.get(p.key)
        {
            owed.push(m.clone());
        }
    }
    for stem in undeclared_root_modules {
        owed.push(format!("{ROOT_DIR}/{stem}.rs"));
    }
    owed.sort();
    owed.dedup();
    for m in &owed {
        if !text.contains(m.as_str()) {
            problems.push(format!(
                "this run reports `{m}` dormant or unreached and sends the reader to {EVIDENCE}, \
                 which does not write it up"
            ));
        }
    }

    // BACKWARD — everything the document is about is still here.
    let mut written_up = 0usize;
    for (i, line) in text.lines().enumerate() {
        if !line.starts_with("## ") {
            continue;
        }
        for path in backticked_paths(line) {
            written_up += 1;
            if !cx.exists(&path) {
                problems.push(format!(
                    "{EVIDENCE}:{} writes up `{path}`, which is not in the tree — strike the \
                     section in the commit that folded it, or the document describes work as owed \
                     that is already done",
                    i + 1
                ));
            }
        }
    }

    if problems.is_empty() {
        Row::pass(
            ROW_EVIDENCE,
            "the cited evidence covers every module this run names, and nothing it has lost",
            format!(
                "{EVIDENCE}: {} module(s) written up, {} module(s) cited by this run",
                written_up,
                owed.len()
            ),
        )
    } else {
        Row::fail(
            ROW_EVIDENCE,
            "the cited evidence and the tree disagree about what is dormant",
            format!("{} problem(s): {}", problems.len(), problems.join(" | ")),
        )
    }
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
    for id in [ROW_ROOT_MODULE, ROW_ROSTER, ROW_STALE, ROW_EVIDENCE] {
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
            ROW_EVIDENCE.to_string(),
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
        let manifest = match cx.read(CRATE_MANIFEST) {
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
                m
            }
        };
        // What the generated table `main.rs` includes names, and the linked rows it is built from —
        // DATA in the manifest (see the header), read here rather than assumed.
        let generated = generated_table_refs(&manifest);
        let linked_rows = manifest_table(&manifest, "package.metadata.busbar.linked");
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

        let mods = reached_modules(&files, &generated);
        let all_items = items(&files);
        let graph = Graph::new(&files, &all_items);
        let reached = reached_items(&files, &graph, &generated);
        // THE LIVE UNIT PATH'S RAW FACTS, once for every plane: every `Units` type the crate
        // declares, every runner registration and the constructions its runner arrives at, and
        // every place a key is routed onto one.
        let units = all_unit_types(&files);
        let regs = registrations(&files, &all_items, &graph, &units);
        let flips = flips(&files, &all_items, &graph, &regs);
        // `register_planes()` folds the generated `LINKED` table — the one write into the plane axis.
        let folds_linked = register_planes
            .iter()
            .any(|l| !l.gated && word_hit(&l.code, "LINKED"));

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

            // 1. REGISTERED — a linked-table row for the plane's crate that `register_planes()`
            // folds, or a plane type in `plane_claims()`.
            let mut hits: Vec<String> = linked_rows
                .iter()
                .filter(|(_, krate)| {
                    folds_linked
                        && krate == p.linked_crate
                        && axes_of(&manifest, krate).iter().any(|a| a == "plane")
                })
                .map(|(feature, krate)| {
                    format!(
                        "{CRATE_MANIFEST} [package.metadata.busbar.linked] `{feature} = \"{krate}\"` \
                         on the `plane` axis, folded by `register_planes()` over `LINKED`"
                    )
                })
                .collect();
            hits.extend(
                body_names(plane_claims, p.register_tokens)
                    .into_iter()
                    .map(|h| format!("registry.rs:{h}")),
            );
            let registered = if hits.is_empty() {
                Err(format!(
                    "no linked-table row for `{}` on the `plane` axis in {CRATE_MANIFEST} that \
                     `register_planes()` ({MAIN_RS}) folds over `LINKED`, and no registration token {:?} appears in \
                     `plane_claims()` ({REGISTRY_RS}). The composition root does not install this \
                     plane, so nothing it declares is served. ({})",
                    p.linked_crate, p.register_tokens, p.note
                ))
            } else {
                Ok(format!(
                    "registered by the composition root at {}",
                    hits.join(", ")
                ))
            };

            // 2. THE UNIT PATH — THE LIVE ONE (R1, 2026-09-25).
            //
            // A plane's unit path is the kernel-loop runner registered for its capability key —
            // `GauntletKernelUnit`, built in `run_gauntlet_via_kernel`/`open_gauntlet_via_kernel` and
            // flipped per key by `gauntlet_install::install()` from `fn main()` (the #28 rider) — or a
            // `Units` impl its linked entry exports. `root/units_<plane>.rs` is not the test: it
            // predates the unification, and three of the four were rustc-dead while the rider served
            // their planes (K2-0 §5). Every link is read off CONSTRUCTION SITES and the precise graph
            // — never off simple names — and an absent unit path is still a finding (item 180).
            let ident = p.linked_crate.replace('-', "_");
            let axes = axes_of(&manifest, p.linked_crate);
            let export = linked_export(cx, &manifest, &files, &all_items, &graph, p.linked_crate);
            // The key is spelled through the plane's linked crate (`busbar_mcp::PLANE_KEY`), or
            // through its entry module when that module is in the root
            // (`plane_decision::PLANE_DECLARATION.key`).
            let spells_key = |q: &String| *q == ident || export.in_root.as_ref() == Some(q);
            let mine: Vec<&Flip> = flips
                .iter()
                .filter(|f| {
                    f.quals.iter().any(spells_key)
                        || (f.fold && axes.iter().any(|a| a == regs[f.reg].axis))
                })
                .collect();
            let flip_live = |f: &Flip| {
                let r = &regs[f.reg];
                !f.gated
                    && !r.gated
                    && f.item.is_some_and(|i| reached.contains(&i))
                    && !r.builds.is_empty()
            };
            let item_name = |i: Option<usize>| {
                i.map_or_else(|| "(no item)".to_string(), |i| all_items[i].name.clone())
            };
            let describe_build = |(t, s): &(String, Site)| {
                format!(
                    "`{t}` at {}:{} (in `{}`)",
                    s.rel,
                    s.line,
                    s.item.as_deref().unwrap_or("?")
                )
            };
            let mut live_paths: Vec<String> = mine
                .iter()
                .filter(|f| flip_live(f))
                .map(|f| {
                    let r = &regs[f.reg];
                    format!(
                        "the kernel-loop runner `{}` ({} at {}:{}) builds {}, and this plane's key \
                         is flipped onto it at {}:{} (in `{}`, reached from fn main())",
                        r.runner,
                        r.api,
                        r.rel,
                        r.line,
                        r.builds
                            .iter()
                            .map(describe_build)
                            .collect::<Vec<_>>()
                            .join(", "),
                        f.rel,
                        f.line,
                        item_name(f.item)
                    )
                })
                .collect();
            if !export.builds.is_empty() {
                live_paths.push(format!(
                    "its linked entry `{}` exports {} through {:?}",
                    export.rel,
                    export
                        .builds
                        .iter()
                        .map(describe_build)
                        .collect::<Vec<_>>()
                        .join(", "),
                    export.exported
                ));
            }
            let rider_why = if mine.is_empty() {
                format!(
                    "no non-test line routes a `{ident}::…` key into {} (directly, or through the \
                     function that calls one), and no fold over `LINKED` flips it by a `linked-axes` \
                     axis",
                    RUNNER_REGISTRATIONS
                        .iter()
                        .map(|(a, _)| format!("`{a}`"))
                        .collect::<Vec<_>>()
                        .join("/")
                )
            } else {
                mine.iter()
                    .map(|f| {
                        let r = &regs[f.reg];
                        let why = if f.gated || r.gated {
                            "test scope".to_string()
                        } else if !f.item.is_some_and(|i| reached.contains(&i)) {
                            format!(
                                "`{}` is reached by nothing from fn main()",
                                item_name(f.item)
                            )
                        } else {
                            format!("its runner `{}` builds no `Units` type", r.runner)
                        };
                        format!("flip at {}:{} [{why}]", f.rel, f.line)
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            let export_why = if !export.exists {
                format!("`{}` is not in the tree", export.rel)
            } else if export.units.is_empty() {
                format!("`{}` declares no `impl … Units for`", export.rel)
            } else {
                format!(
                    "`{}` declares {:?} and builds none of them in anything its exported items {:?} \
                     reach",
                    export.rel, export.units, export.exported
                )
            };
            let unit_path = if live_paths.is_empty() {
                Err(format!(
                    "NO LIVE UNIT PATH: roster plane `{}` has no kernel-loop runner registered for its \
                     capability key and no `Units` impl its linked entry exports, so nothing `fn \
                     main()` reaches drives its ten steps. Rider: {rider_why}. Linked entry: \
                     {export_why}. Give it a unit path, or declare it in {DECLARATIONS} with the \
                     reason and the switch. The evidence is written up in {EVIDENCE}.",
                    p.key
                ))
            } else {
                let mut detail = live_paths.join("; ");
                // The superseded module, when it is still on disk beside the live path: named, so a
                // green row never reads as a statement about it.
                if let Some(m) = module {
                    for t in unit_types(m) {
                        let sites = construction_sites(&files, &all_items, &reached, &t);
                        if !sites.iter().any(|s| s.why == SiteKind::Live) {
                            detail.push_str(&format!(
                                "; beside it `{module_rel}` declares `{t}`, which nothing `fn main()` \
                                 reaches builds ({}) — superseded, see {EVIDENCE}",
                                describe(&sites)
                            ));
                        }
                    }
                }
                Ok(detail)
            };

            // 3. ROOT REACH — the MODULE that routes the plane onto its unit path, from `fn main()`,
            // over the module graph. Kept apart from the row above for the reason it always was:
            // the module can be reached while nothing in it drives a unit (a flip in a function
            // nothing calls, a runner that builds no `Units` type), and the two rows together say
            // the exact true thing.
            let mut reach_hits: Vec<String> = mine
                .iter()
                .filter(|f| !f.gated && mods.contains(&files[f.file].stem))
                .map(|f| {
                    format!(
                        "`{}` routes this plane's key onto a kernel-loop runner ({}:{}) and is \
                         reached from {MAIN_RS}",
                        f.rel, f.rel, f.line
                    )
                })
                .collect();
            let entry_reached = match &export.in_root {
                Some(stem) => mods.contains(stem),
                None => linked_rows.iter().any(|(_, k)| k == p.linked_crate),
            };
            if export.exists && !export.units.is_empty() && entry_reached {
                reach_hits.push(format!(
                    "its linked entry `{}` declares {:?} and is reached through the generated table",
                    export.rel, export.units
                ));
            }
            let root_reach = if reach_hits.is_empty() {
                Err(format!(
                    "NO UNIT PATH REACHED: no module a chain from {MAIN_RS} arrives at routes plane \
                     `{}`'s capability key onto a kernel-loop runner, and its linked entry exports no \
                     `Units` impl. Rider: {rider_why}. Linked entry: {export_why}.",
                    p.key
                ))
            } else {
                Ok(reach_hits.join("; "))
            };

            findings.insert(
                p.key,
                Finding {
                    registered,
                    unit_path,
                    root_reach,
                    cites: export.exists.then(|| export.rel.clone()),
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

        // ── the cited evidence is READ ───────────────────────────────────────────────────────
        rows.push(evidence_row(cx, &findings, &undeclared));

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
        // this repository, where the gate reds on the decision plane (no runner flipped for its key,
        // a linked entry that exports no unit) and on `money_book.rs`/`vocabulary.rs`, and passes
        // the four planes the rider serves. The fixtures exist so the rules can be proven RED-able
        // hermetically and cheaply; the tree is what proves they are about something.
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
                    "`{}` with no runner flipped for its key and no linked Units export reds its unit-path row",
                    p.key
                ),
                &[&row_unit_path(p.key)],
                FIX_RED,
                &["NO LIVE UNIT PATH"],
            ));
            report.push(prove_rows_red_at(
                cx,
                self,
                format!(
                    "`{}` routed onto no runner by any module fn main() reaches reds its reach row",
                    p.key
                ),
                &[&row_root_reach(p.key)],
                FIX_RED,
                &["NO UNIT PATH REACHED"],
            ));
        }

        // ── THE LIVE UNIT PATH (R1): each link of the rider, and the linked export, planted away ────
        //
        // Every case below is the GREEN fixture — where all five planes have a live unit path — with
        // ONE link broken, so the transition is the plant's.

        // A PLANE WHOSE KEY IS NEVER FLIPPED. The runner is registered and builds its unit; the
        // install just never routes this plane's key onto it.
        report.push(red_over(
            self,
            cx,
            FIX_GREEN,
            "a plane whose key is never flipped reds its unit-path and root-reach rows",
            &[row_unit_path("a2a"), row_root_reach("a2a")],
            {
                let mut ov = Overlay::new();
                ov.set(INSTALL_RS, FIXTURE_GREEN_INSTALL.replace(A2A_FLIP_LINE, ""));
                ov
            },
            "no non-test line routes a `busbar_a2a::…` key",
        ));
        // A PLANE WITH NEITHER A RIDER NOR A UNITS EXPORT — the real tree's decision plane: a linked
        // entry that is declaration only.
        report.push(red_over(
            self,
            cx,
            FIX_GREEN,
            "a plane with neither a rider nor a Units export reds its unit-path and root-reach rows",
            &[row_unit_path("decision"), row_root_reach("decision")],
            decision_without_unit_path(),
            "declares no `impl … Units for`",
        ));
        // THE FLIP IS TEST SCOPE. A flip only a test performs is no flip in the shipped binary.
        report.push(red_over(
            self,
            cx,
            FIX_GREEN,
            "a key flipped only under #[cfg(test)] reds its unit-path and root-reach rows",
            &[row_unit_path("streaming"), row_root_reach("streaming")],
            {
                let mut ov = Overlay::new();
                ov.set(
                    INSTALL_RS,
                    FIXTURE_GREEN_INSTALL.replace(
                        VOICE_FLIP_LINE,
                        &format!("    #[cfg(test)]\n{VOICE_FLIP_LINE}"),
                    ),
                );
                ov
            },
            "test scope",
        ));
        // THE RUNNER BUILDS NO UNIT. The key is flipped, the module is reached, and the runner the
        // key is flipped onto constructs no `Units` type — so the unit-path row reds while the
        // root-reach row (module level) stays green; the unit test below holds the green half.
        report.push(red_over(
            self,
            cx,
            FIX_GREEN,
            "a key flipped onto a runner that builds no Units type reds its unit-path row",
            &[row_unit_path("llm")],
            runner_builds_no_unit(),
            "builds no `Units` type",
        ));
        // THE INSTALL IS NEVER CALLED. Every flip is written, in a module no chain reaches.
        report.push(red_over(
            self,
            cx,
            FIX_GREEN,
            "flips in a module fn main() never reaches red the unit-path and root-reach rows",
            &[row_unit_path("mcp"), row_root_reach("mcp")],
            {
                let mut ov = Overlay::new();
                ov.set(MAIN_RS, FIXTURE_GREEN_MAIN.replace(INSTALL_CALL_LINE, ""));
                ov
            },
            "is reached by nothing from fn main()",
        ));
        // THE SIMPLE-NAME COLLISION, PROVEN NOT TO CREDIT A UNIT PATH. The flips move into a
        // function called `answer` that nothing calls — while `main.rs` calls five OTHER functions
        // called `answer`. The graph this gate used to read keyed on simple names and called that
        // function reached; the precise graph does not.
        report.push(red_over(
            self,
            cx,
            FIX_GREEN,
            "flips in a function nothing calls, whose NAME collides with a reached one, red the unit-path row",
            &[row_unit_path("mcp")],
            flips_in_a_colliding_uncalled_fn(),
            "`answer` is reached by nothing from fn main()",
        ));
        // A KEY SPELLED THROUGH THE PLANE'S IN-ROOT ENTRY MODULE is this plane's key: the decision
        // plane with no Units export, flipped onto the runner by `plane_decision::PLANE_DECLARATION.key`.
        report.push(green_over(
            self,
            cx,
            FIX_GREEN,
            "a plane flipped by the key its in-root linked entry declares is green",
            evidenced({
                let mut ov = decision_without_unit_path();
                ov.set(
                    INSTALL_RS,
                    FIXTURE_GREEN_INSTALL.replace(
                        VOICE_FLIP_LINE,
                        &format!(
                            "{VOICE_FLIP_LINE}    flip_one_shot_to_kernel(crate::root::plane_decision::PLANE_DECLARATION.key);\n"
                        ),
                    ),
                );
                ov
            }),
        ));
        // A UNITS IMPL THE ENTRY DECLARES BUT DOES NOT EXPORT. The type is there; nothing the
        // generated table names builds it.
        report.push(red_over(
            self,
            cx,
            FIX_GREEN,
            "a linked entry whose Units impl no exported item builds reds its unit-path row",
            &[row_unit_path("decision")],
            {
                let mut ov = Overlay::new();
                ov.set(
                    DECISION_ENTRY_RS,
                    FIXTURE_GREEN_DECISION.replace(
                        "pub const PLANE_HOOKS: fn() -> u64 = serve_decision;",
                        "pub const PLANE_HOOKS: u64 = 0;",
                    ),
                );
                ov
            },
            "builds none of them",
        ));
        // A PLUGIN CRATE'S OWN ENTRY MODULE, both ways: mcp's flip removed, and its `linked`
        // module exporting a Units impl — built in an exported item (green), or not (red).
        report.push(green_over(
            self,
            cx,
            FIX_GREEN,
            "a plane served by a Units impl its plugin crate's linked entry exports is green",
            evidenced(mcp_by_linked_export(true)),
        ));
        report.push(red_over(
            self,
            cx,
            FIX_GREEN,
            "the same plugin entry building its Units impl in nothing it exports reds its unit-path row",
            &[row_unit_path("mcp")],
            mcp_by_linked_export(false),
            "builds none of them",
        ));
        // THE FOLD (K2d's shape): the install folds the linked table and flips each row whose
        // `linked-axes` carry a gauntlet axis. Green when every plane's row carries its axis; the
        // plane whose row does not is red.
        report.push(green_over(
            self,
            cx,
            FIX_GREEN,
            "flips folded over the linked table by gauntlet axis are green",
            evidenced(folded_install(true)),
        ));
        report.push(red_over(
            self,
            cx,
            FIX_GREEN,
            "a plane whose linked-axes row carries no gauntlet axis is not flipped by the fold",
            &[row_unit_path("streaming"), row_root_reach("streaming")],
            folded_install(false),
            "no fold over `LINKED` flips it",
        ));
        // AN ABSENT `root/units_<plane>.rs` IS NOT THE TEST. The superseded module deleted, the
        // live unit path untouched: the whole gate stays green.
        report.push(green_over(
            self,
            cx,
            FIX_GREEN,
            "a plane with no root/units_<plane>.rs and a live rider is green",
            evidenced({
                let mut ov = Overlay::new();
                ov.remove("crates/busbar/src/root/units_mcp.rs");
                ov.remove("crates/busbar/src/root/tests/units_mcp.rs");
                ov.set(
                    MAIN_RS,
                    FIXTURE_GREEN_MAIN.replace("        + root::units_mcp::answer()\n", ""),
                );
                ov
            }),
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
            evidenced(Overlay::new()),
        ));

        // GREEN CONTROL 2 — THE DECLARED/UNDECLARED LINE, BOTH WAYS, ON ONE PLANT. The same edit
        // that takes the decision plane's unit path away is made twice: once with a declaration and
        // once without. Together they are the whole of the gate's central claim — an undeclared
        // absent unit path is RED, a declared one is a tracked row — and neither half proves it alone.
        report.push(green_over(
            self,
            cx,
            FIX_GREEN,
            "a plane with no unit path WITH a declaration is a tracked row, not a red",
            evidenced(dormant_declared_decision()),
        ));

        // ── THE EVIDENCE ROW, RED THREE WAYS ──────────────────────────────────────────────────
        //
        // Each is the green control above with ONE thing about the evidence document changed, so
        // the transition is the plant's: the document gone, the document silent about the module
        // this run cites, and the document writing up a module the tree no longer has.
        report.push(red_over(
            self,
            cx,
            FIX_GREEN,
            "the evidence document the failure details cite, missing, reds the evidence row",
            &[ROW_EVIDENCE.to_string()],
            dormant_declared_decision(),
            "A citation to a document that is not there",
        ));
        report.push(red_over(
            self,
            cx,
            FIX_GREEN,
            "an evidence document silent about a module this run cites reds the evidence row",
            &[ROW_EVIDENCE.to_string()],
            {
                let mut ov = dormant_declared_decision();
                ov.set(EVIDENCE, FIXTURE_EVIDENCE_SILENT);
                ov
            },
            "which does not write it up",
        ));
        report.push(red_over(
            self,
            cx,
            FIX_GREEN,
            "an evidence document writing up a module the tree has lost reds the evidence row",
            &[ROW_EVIDENCE.to_string()],
            evidenced_with(Overlay::new(), FIXTURE_EVIDENCE_LOST),
            "which is not in the tree",
        ));
        // THE EXPIRY, WHICH IS THE HALF THAT STOPS THE LIST ONLY EVER GROWING. The same declaration
        // as the case above, over the UNPLANTED green fixture — where the decision plane's unit
        // path is live — must red the stale row. Without this, a declaration written once would
        // excuse its subject forever, which is the blanket waiver every other list in this tree had
        // to be rescued from.
        report.push(red_over(
            self,
            cx,
            FIX_GREEN,
            "a declaration whose subject is REACHED again reds the stale row",
            &[ROW_STALE.to_string()],
            {
                let mut ov = Overlay::new();
                ov.set(DECLARATIONS, FIXTURE_DECLARED_DECISION);
                ov
            },
            "is declared dormant and is REACHED again",
        ));

        report.push(red_over(
            self,
            cx,
            FIX_GREEN,
            "the same absent unit path WITHOUT a declaration is RED",
            &[row_unit_path("decision")],
            evidenced(decision_without_unit_path()),
            "NO LIVE UNIT PATH",
        ));

        // ── THE LINKED TABLE (K1): each registration route, and the generated table's reach ──────
        //
        // The green fixture registers every plane twice over — a linked-table row folded by
        // `register_planes()`, and a plane type in `plane_claims()`. Each route is taken away in
        // turn so each is proven load-bearing on its own, and a root-units row stands in for a direct
        // call from `main.rs` to prove the generated table's reach is read, not assumed.
        report.push(green_over(
            self,
            cx,
            FIX_GREEN,
            "planes registered ONLY through the linked table `register_planes()` folds are green",
            evidenced(claims_name_no_plane()),
        ));
        report.push(red_over(
            self,
            cx,
            FIX_GREEN,
            "a plane whose crate has no linked-table row, and no plane_claims token, reds its registration row",
            &[row_registered("a2a")],
            {
                let mut ov = claims_name_no_plane();
                ov.set(
                    CRATE_MANIFEST,
                    FIXTURE_LINKED_MANIFEST.replace("plane-a2a = \"busbar-a2a\"\n", ""),
                );
                ov
            },
            "no linked-table row for `busbar-a2a` on the `plane` axis",
        ));
        report.push(red_over(
            self,
            cx,
            FIX_GREEN,
            "a crate linked but not on the plane axis, and no plane_claims token, reds its registration row",
            &[row_registered("streaming")],
            {
                let mut ov = claims_name_no_plane();
                ov.set(
                    CRATE_MANIFEST,
                    FIXTURE_LINKED_MANIFEST
                        .replace("plane-voice = \"plane diagnostics\"", "plane-voice = \"diagnostics\""),
                );
                ov
            },
            "no linked-table row for `busbar-voice` on the `plane` axis",
        ));
        report.push(red_over(
            self,
            cx,
            FIX_GREEN,
            "a linked table `register_planes()` does not fold registers nothing",
            &[row_registered("llm")],
            {
                let mut ov = claims_name_no_plane();
                ov.set(
                    MAIN_RS,
                    FIXTURE_GREEN_MAIN.replace("Vec::from(LINKED)", "Vec::new()"),
                );
                ov
            },
            "no registration token",
        ));
        report.push(green_over(
            self,
            cx,
            FIX_GREEN,
            "a module `main.rs` reaches only through a root-units row of the generated table is reached",
            evidenced(voice_reached_only_through_root_units(true)),
        ));
        report.push(red_over(
            self,
            cx,
            FIX_GREEN,
            "the same module with no root-units row reds the root-module row",
            &[ROW_ROOT_MODULE.to_string()],
            voice_reached_only_through_root_units(false),
            "units_voice",
        ));

        report
    }
}

/// The green fixture's `plane_claims()` naming no plane type, so the linked table is the only
/// registration route left.
fn claims_name_no_plane() -> Overlay {
    let mut ov = Overlay::new();
    ov.set(
        REGISTRY_RS,
        "pub fn plane_claims() -> Vec<&'static str> {\n    Vec::new()\n}\n",
    );
    ov
}

/// The green fixture with `main.rs` no longer calling into `units_voice` — reached, if at all, only
/// through a root-units row of the manifest (planted when `listed`).
fn voice_reached_only_through_root_units(listed: bool) -> Overlay {
    let mut ov = Overlay::new();
    ov.set(
        MAIN_RS,
        FIXTURE_GREEN_MAIN.replace("        + root::units_voice::answer()\n", ""),
    );
    if listed {
        ov.set(
            CRATE_MANIFEST,
            format!(
                "{FIXTURE_LINKED_MANIFEST}\n[package.metadata.busbar.root-units]\nroot-voice = \"units_voice\"\n"
            ),
        );
    }
    ov
}

/// The green fixture's manifest, verbatim (the planted variants edit a copy of it).
const FIXTURE_LINKED_MANIFEST: &str =
    include_str!("../../fixtures/reachability-green/crates/busbar/Cargo.toml");

/// The green fixture's `main.rs`, verbatim (the planted variants edit a copy of it).
const FIXTURE_GREEN_MAIN: &str =
    include_str!("../../fixtures/reachability-green/crates/busbar/src/main.rs");

/// The green fixture's rider, runner and decision entry, verbatim (the planted variants edit a copy).
const INSTALL_RS: &str = "crates/busbar/src/root/gauntlet_install.rs";
const KERNEL_RS: &str = "crates/busbar/src/root/gauntlet_kernel.rs";
const DECISION_ENTRY_RS: &str = "crates/busbar/src/root/plane_decision.rs";
const FIXTURE_GREEN_INSTALL: &str =
    include_str!("../../fixtures/reachability-green/crates/busbar/src/root/gauntlet_install.rs");
const FIXTURE_GREEN_KERNEL: &str =
    include_str!("../../fixtures/reachability-green/crates/busbar/src/root/gauntlet_kernel.rs");
const FIXTURE_GREEN_DECISION: &str =
    include_str!("../../fixtures/reachability-green/crates/busbar/src/root/plane_decision.rs");
const A2A_FLIP_LINE: &str = "    flip_one_shot_to_kernel(busbar_a2a::PLANE_KEY);\n";
const MCP_FLIP_LINE: &str = "    flip_one_shot_to_kernel(busbar_mcp::PLANE_KEY);\n";
const VOICE_FLIP_LINE: &str = "    flip_session_to_kernel(busbar_voice::PLANE_KEY);\n";
const INSTALL_CALL_LINE: &str = "    root::gauntlet_install::install();\n";

/// The decision plane's entry as it is on the real tree: a declaration and hooks, no `Units` impl —
/// and no key flipped onto a runner either. Neither kind of unit path.
fn decision_without_unit_path() -> Overlay {
    let mut ov = Overlay::new();
    ov.set(
        DECISION_ENTRY_RS,
        "pub const PLANE_DECLARATION: &str = \"decision\";\n\npub const PLANE_HOOKS: u64 = 0;\n",
    );
    ov
}

/// The runner the keys are flipped onto, with its type no longer a `Units` impl.
fn runner_builds_no_unit() -> Overlay {
    let mut ov = Overlay::new();
    ov.set(
        KERNEL_RS,
        FIXTURE_GREEN_KERNEL.replace(
            "impl busbar_kernel::teller::Units for GauntletKernelUnit {",
            "impl GauntletKernelUnit {",
        ),
    );
    ov
}

/// `install()` emptied, and the flips moved into a function called `answer` that nothing calls —
/// the name `main.rs` reaches five times over in the `units_*` modules.
fn flips_in_a_colliding_uncalled_fn() -> Overlay {
    let mut ov = Overlay::new();
    ov.set(
        INSTALL_RS,
        FIXTURE_GREEN_INSTALL.replace(
            "pub fn install() {\n",
            "pub fn install() {}\n\npub fn answer() {\n",
        ),
    );
    ov
}

/// mcp's flip removed, and `crates/busbar-mcp/src/linked.rs` exporting a `Units` impl — built in its
/// `PLANE_HOOKS` (on mcp's plane axis) when `built`, in a function nothing exported calls otherwise.
fn mcp_by_linked_export(built: bool) -> Overlay {
    let hooks = if built {
        "pub const PLANE_HOOKS: fn() -> u64 = serve_mcp;\n"
    } else {
        "pub const PLANE_HOOKS: u64 = 0;\n"
    };
    let mut ov = Overlay::new();
    ov.set(INSTALL_RS, FIXTURE_GREEN_INSTALL.replace(MCP_FLIP_LINE, ""));
    ov.set(
        "crates/busbar-mcp/src/linked.rs",
        format!(
            "pub struct McpLinkedUnit {{\n    n: u64,\n}}\n\n\
             impl busbar_kernel::teller::Units for McpLinkedUnit {{\n    fn drive(&self) -> u64 {{\n        self.n\n    }}\n}}\n\n\
             fn serve_mcp() -> u64 {{\n    let unit = McpLinkedUnit {{ n: 1 }};\n    unit.drive()\n}}\n\n\
             pub const PLANE_DECLARATION: &str = \"mcp\";\n\n{hooks}"
        ),
    );
    ov
}

/// K2d's shape: `install()` folds the linked table and flips each row by its gauntlet axis. With
/// `all`, every rider plane's `linked-axes` row carries its axis; without, the streaming row does not.
fn folded_install(all: bool) -> Overlay {
    let install = FIXTURE_GREEN_INSTALL
        .split("pub fn install() {\n")
        .next()
        .unwrap_or_default()
        .to_string()
        + "pub fn install() {\n    for row in LINKED {\n        if row.one_shot {\n            \
           flip_one_shot_to_kernel(row.key);\n        } else {\n            \
           flip_session_to_kernel(row.key);\n        }\n    }\n}\n";
    let mut manifest = FIXTURE_LINKED_MANIFEST
        .replace(
            "proto-llm = \"plane protocols\"",
            "proto-llm = \"plane protocols gauntlet-one-shot\"",
        )
        .replace(
            "plane-mcp = \"plane protocols diagnostics\"",
            "plane-mcp = \"plane protocols diagnostics gauntlet-one-shot\"",
        )
        .replace(
            "plane-a2a = \"plane diagnostics\"",
            "plane-a2a = \"plane diagnostics gauntlet-one-shot\"",
        );
    if all {
        manifest = manifest.replace(
            "plane-voice = \"plane diagnostics\"",
            "plane-voice = \"plane diagnostics gauntlet-session\"",
        );
    }
    let mut ov = Overlay::new();
    ov.set(INSTALL_RS, &install);
    ov.set(CRATE_MANIFEST, &manifest);
    ov
}

/// THE GREEN FIXTURE'S EVIDENCE DOCUMENT, planted rather than committed under `xtask/fixtures/`.
///
/// ITEM 88. `7e27cdc11` made the gate READ [`EVIDENCE`] instead of merely naming it, and the green
/// fixture was never given one: both green controls then went RED on `reachability:evidence` alone
/// ("No such file or directory"), so the fixture that proves the gate CAN be satisfied proved the
/// opposite. The document writes up the one module the declared-decision control makes the run cite
/// (the plane's linked entry), and that module is on the fixture tree, so it holds forward and
/// backward over both controls.
const FIXTURE_EVIDENCE: &str = "# Reachability evidence (self-test fixture)\n\n\
## `crates/busbar/src/root/plane_decision.rs`\n\n\
The decision plane's linked entry exports no `Units` impl and no runner is flipped for its key.\n";

/// The same document with no module written up at all: every module the run cites is owed and
/// absent.
const FIXTURE_EVIDENCE_SILENT: &str = "# Reachability evidence (self-test fixture)\n\n\
Nothing is written up here.\n";

/// The fixture document plus a section for a module the fixture tree does not have.
const FIXTURE_EVIDENCE_LOST: &str = "# Reachability evidence (self-test fixture)\n\n\
## `crates/busbar/src/root/plane_decision.rs`\n\n\
The decision plane's linked entry exports no `Units` impl.\n\n\
## `crates/busbar/src/root/units_folded_away.rs`\n\n\
Folded in the commit that switched it on; this section should have gone with it.\n";

/// `plant`, over a green fixture that carries its evidence document.
fn evidenced(plant: Overlay) -> Overlay {
    evidenced_with(plant, FIXTURE_EVIDENCE)
}

fn evidenced_with(mut plant: Overlay, doc: &str) -> Overlay {
    plant.set(EVIDENCE, doc);
    plant
}

/// The decision plane's unit path taken away, AND declared: a tree the gate is satisfied by once the
/// evidence document writes the entry module up.
fn dormant_declared_decision() -> Overlay {
    let mut ov = decision_without_unit_path();
    ov.set(DECLARATIONS, FIXTURE_DECLARED_DECISION);
    ov
}

const FIXTURE_DECLARED_DECISION: &str = r#"[[dormant]]
subject = "decision"
aspect  = "unit-path"
module  = "crates/busbar/src/root/plane_decision.rs"
reason  = "declared only: the plane registers a declaration and no served door, so there is nothing to put a unit on yet"
switch  = "the commit that gives the plane a served door and a unit path"

[[dormant]]
subject = "decision"
aspect  = "root-reach"
module  = "crates/busbar/src/root/plane_decision.rs"
reason  = "declared only: the plane registers a declaration and no served door, so there is nothing to put a unit on yet"
switch  = "the commit that gives the plane a served door and a unit path"
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

    /// The green fixture with `plant` applied, run once; `(status, detail)` per row id.
    fn run_green_with(plant: Overlay) -> BTreeMap<String, (Status, String)> {
        let cx = Ctx::workspace().expect("workspace context");
        let fcx = Ctx::at(
            cx.abs("xtask/fixtures/reachability-green"),
            cx.scratch().to_path_buf(),
        )
        .expect("green fixture");
        crate::gates::execute(&ReachabilityGate, &fcx.with_overlay(plant))
            .rows
            .into_iter()
            .map(|r| (r.id.clone(), (r.status, r.detail.clone())))
            .collect()
    }

    /// ITEM 180, RE-SCOPED TO THE LIVE PATH (R1): A ROSTER PLANE WITH NO UNIT PATH IS RED ON BOTH ROWS
    /// ABOUT IT, NOT GREEN. The real tree's decision plane has a linked entry that is declaration
    /// only and no key flipped onto a runner; both rows must be RED naming that, and the evidence row
    /// must stay green, because the evidence writes the entry module up.
    #[test]
    fn a_plane_with_no_live_unit_path_reds_both_of_its_rows() {
        let rows = run_green_with(evidenced(decision_without_unit_path()));
        for id in [row_unit_path("decision"), row_root_reach("decision")] {
            let (st, detail) = &rows[&id];
            assert!(
                *st != Status::Pass && detail.contains("declares no `impl … Units for`"),
                "`{id}` must be RED naming the missing export, got {st:?}: {detail}"
            );
        }
        let (st, detail) = &rows[ROW_EVIDENCE];
        assert!(
            *st == Status::Pass,
            "the evidence writes the entry up: {detail}"
        );
    }

    /// THE TWO RIDER ROWS SAY DIFFERENT THINGS. A key flipped, in a reached module, onto a runner that
    /// builds no `Units` type: the unit-path row is RED and the root-reach row (module level) GREEN.
    /// And the simple-name collision: flips in an uncalled `answer` red unit-path while the module
    /// stays reached.
    #[test]
    fn unit_path_and_root_reach_split_where_the_module_is_reached_and_no_unit_is_built() {
        for plant in [runner_builds_no_unit(), flips_in_a_colliding_uncalled_fn()] {
            let rows = run_green_with(evidenced(plant));
            let (st, detail) = &rows[&row_unit_path("mcp")];
            assert!(*st != Status::Pass, "unit-path must be RED: {detail}");
            let (st, detail) = &rows[&row_root_reach("mcp")];
            assert!(*st == Status::Pass, "root-reach must stay GREEN: {detail}");
        }
    }

    /// The precise graph resolves `stem::name` into that module only, and a bare name through the
    /// file's `use` of it — never by name alone across files.
    #[test]
    fn the_precise_graph_resolves_paths_and_imports_not_names() {
        let t = tokens("root::gauntlet_install::install(); x.drive(); busbar_mcp::PLANE_KEY");
        let install = t.iter().find(|t| t.word == "install").expect("install");
        assert_eq!(install.qual.as_deref(), Some("gauntlet_install"));
        assert!(t
            .iter()
            .find(|t| t.word == "drive")
            .is_some_and(|t| t.method));
        assert_eq!(
            path_quals("busbar_llm::PLANE_DECLARATION.key"),
            vec!["busbar_llm"]
        );
        assert_eq!(
            split_top("capability_key, kernel_one_shot"),
            vec!["capability_key", "kernel_one_shot"]
        );
        assert_eq!(
            resolve_rel("crates/busbar/../busbar-mcp"),
            "crates/busbar-mcp"
        );
    }

    /// ITEM 88: THE SELF-TEST SCORES EVERY PLANTED CASE AS EXPECTED. Both green controls went RED on
    /// `reachability:evidence` alone because the green fixture carried no evidence document, and
    /// the evidence row had no RED case at all; either is a selftest that cannot pass, and a
    /// selftest that cannot pass proves no rule in this gate.
    #[test]
    fn the_selftest_proves_every_owed_row() {
        let cx = Ctx::workspace().expect("workspace context");
        let report = ReachabilityGate.selftest(&cx);
        crate::gates::verify_report(&ReachabilityGate, &report)
            .unwrap_or_else(|errs| panic!("reachability selftest: {errs:#?}"));
        assert_eq!(report.skipped(), 0, "a case had nothing to plant");
    }
}
