//! `cargo xtask gate workspace-deps` — ONE VERSION REQUIREMENT PER EXTERNAL DEPENDENCY, STATED
//! ONCE, IN THE WORKSPACE TABLE.
//!
//! The Rust successor to `scripts/workspace-deps-lint.py`. `[workspace.dependencies]` makes a
//! single source of truth POSSIBLE; it does not make it TRUE. Nothing in Cargo stops a member from
//! writing `serde = "1"` and quietly opening a second opinion, and nothing stops the workspace
//! table from accumulating entries no member uses. Before the table existed, `hex`, `sha2` and
//! `tracing` were each declared two different ways and all three happened to resolve identically —
//! a property everyone believed, asserted nowhere, checked by nothing. Moving that property into a
//! table without a lint relocates the defect instead of removing it.
//!
//! Eight rules, eight ledger rows. The Python returned one flat list of failure strings, which
//! meant a floor and the rule it protects were indistinguishable in the output and a floor could be
//! deleted with the self-test still green:
//!
//! 1. `workspace-deps:table` — `[workspace.dependencies]` exists and is non-empty. An absent table
//!    is not a clean tree; it is no source of truth to check.
//! 2. `workspace-deps:inheritance` — every external dependency in every member inherits
//!    (`workspace = true`). A literal version string in a member is a failure, in `dependencies`,
//!    `dev-dependencies`, `build-dependencies` AND the per-target forms of all three: a rule
//!    enforced on one table only is a rule scoped to where the bug was first seen.
//! 3. `workspace-deps:inherit-target-exists` — a dependency that inherits has an entry to inherit
//!    FROM. Cargo errors on this too, but a gate that defers to the build has not checked anything.
//! 4. `workspace-deps:no-orphans` — every `[workspace.dependencies]` entry is used by at least one
//!    member. An unused pin is a version requirement nothing obeys.
//! 5. `workspace-deps:set-equality` — the members this gate inspected are exactly the members the
//!    workspace declares, AND exactly the crates on disk. A manifest that is skipped is a manifest
//!    that is UNCHECKED, which is not the same as clean. The third set is the one that was missing:
//!    `inspected` is DERIVED from `declared`, so deleting a member line shrank both and the row
//!    stayed green at 60 where it had been green at 61 — a live, path-depended crate dropped out of
//!    every `--workspace` test, clippy and deny run with nothing red anywhere. The manifests that
//!    are not crates of this tree come off `kind-isolation`'s own off-tree list, so the two gates
//!    give one answer.
//! 6. `workspace-deps:member-floor` — at least [`MIN_MEMBERS`] member manifests were inspected.
//! 7. `workspace-deps:inherited-floor` — at least [`MIN_INHERITED`] inheriting declarations were
//!    seen. Either the table is not actually in use or the walk is broken; both are RED.
//! 8. `workspace-deps:discovery` — the `crates/` tree still holds at least
//!    [`MIN_CRATE_MANIFESTS`] manifests. Rules 6 and 7 are counted off the DECLARED member list, so
//!    a `crates/` layout change that the root manifest was edited to match would leave them both
//!    satisfied; this row walks the directory itself, through [`WalkSpec::min_files`], so an
//!    emptied or moved `crates/` cannot read as a clean tree.
//!
//! Every count has a floor because "for each X, assert Y" is vacuously true when X is empty, and a
//! discovery step that finds nothing is RED, never a pass.
//!
//! GIT DEPENDENCIES ARE EXTERNAL — and, exactly as the Python has it, they are not routed through
//! the workspace table and are therefore handled by the same arm that excuses path dependencies:
//! neither carries a version requirement the table could hold, so neither is counted as inheriting,
//! as using a pin, or as restating a version. See [`DepSpec::is_path_or_git`].

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::ctx::{Ctx, Overlay, SourceFile, WalkSpec};
use crate::gates::{prove_green, prove_red, Gate, Report};
use crate::ledger::{Row, Verdict};
use crate::toml_lite;

pub const ROW_TABLE: &str = "workspace-deps:table";
pub const ROW_INHERITANCE: &str = "workspace-deps:inheritance";
pub const ROW_INHERIT_TARGET: &str = "workspace-deps:inherit-target-exists";
pub const ROW_ORPHANS: &str = "workspace-deps:no-orphans";
pub const ROW_SET_EQUALITY: &str = "workspace-deps:set-equality";
pub const ROW_MEMBER_FLOOR: &str = "workspace-deps:member-floor";
pub const ROW_INHERITED_FLOOR: &str = "workspace-deps:inherited-floor";
pub const ROW_DISCOVERY: &str = "workspace-deps:discovery";

/// Floors. Deliberately well under today's counts (63 members, ~200 inherited declarations, 62
/// manifests under `crates/`) so ordinary work never trips them, but far enough above zero that a
/// discovery bug cannot pass. They are `const`s with no environment override: the only way to lower
/// one is a reviewable source edit.
pub const MIN_MEMBERS: usize = 8;
pub const MIN_INHERITED: usize = 40;
pub const MIN_CRATE_MANIFESTS: usize = 40;

const SECTIONS: &[&str] = &["dependencies", "dev-dependencies", "build-dependencies"];

pub struct WorkspaceDepsGate;

/// A dependency's right-hand side, in the two shapes a manifest can write it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum DepSpec {
    /// `serde = "1.0"`.
    Version(String),
    /// `serde = { workspace = true }`, or a `[dependencies.serde]` sub-table.
    Table(BTreeMap<String, String>),
}

impl DepSpec {
    /// A path or git dependency. NEITHER carries an external version requirement the workspace
    /// table could hold — a path dependency is workspace-internal, and a git dependency pins its
    /// source by revision rather than by a semver requirement — so both are excused from the
    /// inheritance, orphan and count arms together, which is the rule the Python states.
    fn is_path_or_git(&self) -> bool {
        match self {
            DepSpec::Version(_) => false,
            DepSpec::Table(t) => t.contains_key("path") || t.contains_key("git"),
        }
    }

    fn inherits(&self) -> bool {
        match self {
            DepSpec::Version(_) => false,
            DepSpec::Table(t) => t.get("workspace").map(String::as_str) == Some("true"),
        }
    }

    /// What the FAIL text shows for a dependency that states its own version.
    fn shown(&self) -> String {
        match self {
            DepSpec::Version(v) => format!("{v:?}"),
            DepSpec::Table(t) => match t.get("version") {
                Some(v) => format!("{v:?}"),
                None => format!("{t:?}"),
            },
        }
    }
}

fn unquote(tok: &str) -> String {
    let t = tok.trim();
    if t.len() >= 2
        && ((t.starts_with('"') && t.ends_with('"')) || (t.starts_with('\'') && t.ends_with('\'')))
    {
        t[1..t.len() - 1].to_string()
    } else {
        t.to_string()
    }
}

/// Split an inline table's body on the commas that are not inside a nested array, a nested table or
/// a string. A naive `split(',')` would cut `features = ["a", "b"]` in half and lose the key.
fn split_top_level(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut depth = 0i32;
    let mut in_str = false;
    for c in body.chars() {
        if in_str {
            cur.push(c);
            if c == '"' {
                in_str = false;
            }
            continue;
        }
        match c {
            '"' => {
                in_str = true;
                cur.push(c);
            }
            '[' | '{' => {
                depth += 1;
                cur.push(c);
            }
            ']' | '}' => {
                depth -= 1;
                cur.push(c);
            }
            ',' if depth == 0 => {
                out.push(std::mem::take(&mut cur));
            }
            _ => cur.push(c),
        }
    }
    out.push(cur);
    out.into_iter().filter(|s| !s.trim().is_empty()).collect()
}

/// `toml_lite` hands an inline table back as the raw text between the braces, because nothing else
/// in the tree needed it decomposed. Decomposing it here rather than in the shared reader keeps the
/// reader's "deliberately small" contract intact.
fn parse_spec(raw: &str) -> DepSpec {
    let t = raw.trim();
    match t.strip_prefix('{') {
        Some(body) => {
            let body = body.trim_end().strip_suffix('}').unwrap_or(body);
            let mut map = BTreeMap::new();
            for item in split_top_level(body) {
                if let Some((k, v)) = item.split_once('=') {
                    map.insert(unquote(k.trim()), unquote(v.trim()));
                }
            }
            DepSpec::Table(map)
        }
        None => DepSpec::Version(t.to_string()),
    }
}

/// True for `dependencies`, `dev-dependencies`, `build-dependencies` and every
/// `target.<cfg>.<section>` form of the three.
fn is_dep_section(path: &str) -> bool {
    SECTIONS.contains(&path)
        || (path.starts_with("target.")
            && SECTIONS.iter().any(|s| path.ends_with(&format!(".{s}"))))
}

/// Every declared dependency in a manifest, as `(section label, name, spec)`.
///
/// Both spellings are read. `[dependencies]` with an inline table is the common one; the
/// `[dependencies.serde]` sub-table form is rare in this tree, and a reader that skipped it would
/// let a member state a version in a shape the gate is blind to — the same class of bypass the
/// scanner-scope audit findings are all about.
fn dep_entries(doc: &toml_lite::Document) -> Vec<(String, String, DepSpec)> {
    let mut out = Vec::new();
    for (path, table) in &doc.tables {
        if is_dep_section(path) {
            for (name, values) in &table.values {
                let raw = values.first().cloned().unwrap_or_default();
                out.push((path.clone(), name.clone(), parse_spec(&raw)));
            }
            continue;
        }
        let Some((section, name)) = path.rsplit_once('.') else {
            continue;
        };
        if !is_dep_section(section) {
            continue;
        }
        let map: BTreeMap<String, String> = table
            .values
            .iter()
            .map(|(k, v)| (k.clone(), v.first().cloned().unwrap_or_default()))
            .collect();
        out.push((section.to_string(), name.to_string(), DepSpec::Table(map)));
    }
    out.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
    out
}

/// Staging counter, so two manifests parsed in the same process (or two tests in the same run)
/// never collide on a scratch file name.
static STAGE_SEQ: AtomicUsize = AtomicUsize::new(0);

/// Read a manifest THROUGH the context, then parse it with the shared `toml_lite` reader.
///
/// `toml_lite::parse` takes a path because every other caller reads a file that is really on disk.
/// A gate whose self-test plants a manifest cannot use that directly without bypassing the overlay
/// and grading the real tree instead of the planted one, so the overlaid bytes are staged into the
/// context's own proven-writable scratch directory and parsed from there. One reader, one set of
/// TOML quirks, for planted and real manifests alike.
fn read_manifest(cx: &Ctx, rel: &str) -> Result<toml_lite::Document, String> {
    let text = cx.read(rel)?;
    let staged = cx.scratch().join(format!(
        "workspace-deps-{}-{}.toml",
        std::process::id(),
        STAGE_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&staged, &text).map_err(|e| format!("{}: {e}", staged.display()))?;
    let doc = toml_lite::parse(&staged);
    let _ = std::fs::remove_file(&staged);
    Ok(doc)
}

/// The `crates/` walk, with its floor. Separate from the declared member list on purpose: the two
/// instruments fail for different reasons and must be able to fail apart.
fn rule_discovery(cx: &Ctx) -> Row {
    let spec = WalkSpec::new(["crates"])
        .ext("toml")
        .min_files(MIN_CRATE_MANIFESTS);
    let files = match cx.walk(&spec) {
        Ok(f) => f,
        Err(e) => {
            return Row::fail(
                ROW_DISCOVERY,
                "the crates/ manifest walk could not run or collapsed",
                e.to_string(),
            )
        }
    };
    let manifests: Vec<String> = files
        .iter()
        .map(|f| f.rel_str())
        .filter(|p| p.ends_with("/Cargo.toml"))
        .collect();
    if manifests.len() < MIN_CRATE_MANIFESTS {
        return Row::fail(
            ROW_DISCOVERY,
            "the crates/ manifest walk collapsed below its floor",
            format!(
                "only {} Cargo.toml file(s) under crates/ (floor {MIN_CRATE_MANIFESTS}). A walk \
                 that finds almost nothing passes almost everything.",
                manifests.len()
            ),
        );
    }
    Row::pass(
        ROW_DISCOVERY,
        "the crates/ tree still holds the manifests this gate is a gate over",
        format!(
            "{} Cargo.toml file(s) under crates/ (floor {MIN_CRATE_MANIFESTS})",
            manifests.len()
        ),
    )
}

/// Everything rules 1-7 are computed from, in one pass over the declared members.
struct Survey {
    declared: Vec<String>,
    inspected: Vec<String>,
    unreadable: Vec<String>,
    table: BTreeSet<String>,
    used: BTreeSet<String>,
    inherited_count: usize,
    version_offenders: Vec<String>,
    inherit_target_offenders: Vec<String>,
}

fn survey(cx: &Ctx, root: &toml_lite::Document) -> Survey {
    let ws = root.table("workspace");
    let mut declared = ws.get_list("members");
    declared.sort();
    let table: BTreeSet<String> = root
        .table("workspace.dependencies")
        .values
        .keys()
        .cloned()
        .collect();

    let mut s = Survey {
        declared,
        inspected: Vec::new(),
        unreadable: Vec::new(),
        table,
        used: BTreeSet::new(),
        inherited_count: 0,
        version_offenders: Vec::new(),
        inherit_target_offenders: Vec::new(),
    };

    for member in s.declared.clone() {
        let rel = format!("{member}/Cargo.toml");
        let doc = match read_manifest(cx, &rel) {
            Ok(d) => d,
            Err(e) => {
                s.unreadable.push(format!(
                    "{member}: declared in [workspace] members but has no Cargo.toml ({e}). A \
                     member that cannot be read is UNCHECKED, which is not the same as clean."
                ));
                continue;
            }
        };
        s.inspected.push(member.clone());

        for (label, name, spec) in dep_entries(&doc) {
            if spec.is_path_or_git() {
                // Workspace-internal, or pinned by git revision: carries no external version.
                continue;
            }
            if spec.inherits() {
                s.inherited_count += 1;
                s.used.insert(name.clone());
                if !s.table.contains(&name) {
                    s.inherit_target_offenders.push(format!(
                        "{member} [{label}]: `{name}` inherits, but there is no `{name}` entry in \
                         [workspace.dependencies] to inherit FROM."
                    ));
                }
                continue;
            }
            s.version_offenders.push(format!(
                "{member} [{label}]: `{name} = {}` states its own version. Move the version to \
                 [workspace.dependencies] and inherit with `{name} = {{ workspace = true }}` \
                 (features may still be added per-member).",
                spec.shown()
            ));
        }
    }
    s
}

/// EVERY CRATE ON DISK THAT NO MEMBER LINE DECLARES.
///
/// The walk is the whole repository, because a crate outside `crates/` is exactly the one a member
/// list can silently drop. The manifests that are NOT crates of this tree — the runner, the gate
/// fixtures, the standalone documentation example — are read off
/// [`crate::gates::kind_isolation::off_tree_manifest_reason`], which is the same list
/// `kind-isolation:registry` scores its own `off-tree-crate` finding against: two lists would be
/// two answers to one question.
///
/// THE WALK IS SCOPED TO THE ROOTS THE MEMBER LIST ITSELF CLAIMS — the top-level directory of every
/// declared member, which in this tree is `crates/` and `xtask/`. That is not a softening: it is
/// the difference between "a member line was deleted", which is this row's question, and "a crate
/// appeared somewhere nobody declared", which is `kind-isolation:registry`'s `off-tree-crate` and
/// is refused there with no scoping at all. Without it this row would also grade the real
/// repository whenever a self-test plants a SYNTHETIC workspace over it, and a row that reds on
/// its neighbour's fixtures is a row nobody can read.
fn on_disk_unmembered(cx: &Ctx, declared: &[String]) -> Vec<String> {
    let claimed: BTreeSet<&str> = declared
        .iter()
        .filter_map(|m| m.split('/').next())
        .filter(|s| !s.is_empty())
        .collect();
    let Ok(files) = cx.walk(&WalkSpec::new(["."]).ext("toml")) else {
        return vec![
            "the manifest walk did not run, so no crate on disk could be compared with the member \
             list — a walk that did not read is not a walk that found nothing."
                .to_string(),
        ];
    };
    let mut out = Vec::new();
    for f in &files {
        let rel = f.rel_str();
        // The workspace root declares the members; it is not one of them.
        if rel == "Cargo.toml" || !rel.ends_with("/Cargo.toml") {
            continue;
        }
        if crate::gates::kind_isolation::off_tree_manifest_reason(&rel).is_some() {
            continue;
        }
        if !rel
            .split('/')
            .next()
            .is_some_and(|top| claimed.contains(top))
        {
            continue;
        }
        if !f.text.contains("[package]") {
            continue;
        }
        let dir = rel.trim_end_matches("/Cargo.toml").to_string();
        if !declared.iter().any(|d| d.trim_end_matches('/') == dir) {
            out.push(format!(
                "{dir}: a crate on disk that no [workspace] members entry declares. --workspace \
                 compiles, tests, clippies and denies every crate BUT this one, and a path \
                 dependency reaches it regardless — so it ships unchecked. Add the member line or \
                 delete the crate."
            ));
        }
    }
    out
}

impl Gate for WorkspaceDepsGate {
    fn name(&self) -> &'static str {
        "workspace-deps"
    }

    fn owed(&self) -> Vec<String> {
        vec![
            ROW_TABLE.to_string(),
            ROW_INHERITANCE.to_string(),
            ROW_INHERIT_TARGET.to_string(),
            ROW_ORPHANS.to_string(),
            ROW_SET_EQUALITY.to_string(),
            ROW_MEMBER_FLOOR.to_string(),
            ROW_INHERITED_FLOOR.to_string(),
            ROW_DISCOVERY.to_string(),
        ]
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let mut rows = vec![rule_discovery(cx)];

        let root = match read_manifest(cx, "Cargo.toml") {
            Ok(d) => d,
            Err(e) => {
                rows.extend(unproven(&format!(
                    "the workspace root manifest is unreadable ({e}) — nothing can be checked \
                     against a source of truth that could not be read"
                )));
                return Verdict::of(rows);
            }
        };

        let s = survey(cx, &root);

        if s.table.is_empty() {
            rows.push(Row::fail(
                ROW_TABLE,
                "[workspace.dependencies] is missing or empty",
                "there is no source of truth to check.",
            ));
            rows.extend(unproven(
                "unproven: [workspace.dependencies] is missing or empty, so every rule below it \
                 would hold vacuously",
            ));
            return Verdict::of(rows);
        }
        rows.push(Row::pass(
            ROW_TABLE,
            "[workspace.dependencies] is the source of truth and is populated",
            format!("{} pin(s)", s.table.len()),
        ));

        rows.push(if s.version_offenders.is_empty() {
            Row::pass(
                ROW_INHERITANCE,
                "every external dependency in every member inherits from the workspace table",
                format!(
                    "{} inheriting declaration(s) across {} member(s)",
                    s.inherited_count,
                    s.inspected.len()
                ),
            )
        } else {
            Row::fail(
                ROW_INHERITANCE,
                "a member states its own version instead of inheriting",
                s.version_offenders.join(" | "),
            )
        });

        rows.push(if s.inherit_target_offenders.is_empty() {
            Row::pass(
                ROW_INHERIT_TARGET,
                "every inheriting dependency has a workspace entry to inherit from",
                format!("{} pin(s) available", s.table.len()),
            )
        } else {
            Row::fail(
                ROW_INHERIT_TARGET,
                "a dependency inherits from an entry that is not in the workspace table",
                s.inherit_target_offenders.join(" | "),
            )
        });

        let orphans: Vec<String> = s.table.difference(&s.used).cloned().collect();
        rows.push(if orphans.is_empty() {
            Row::pass(
                ROW_ORPHANS,
                "every workspace pin is inherited by at least one member",
                format!("{} pin(s), all used", s.table.len()),
            )
        } else {
            Row::fail(
                ROW_ORPHANS,
                "a workspace pin is declared but no member inherits it",
                format!(
                    "{} — an unused pin is a version requirement nothing obeys: delete it, or wire \
                     up the member that was supposed to use it.",
                    orphans
                        .iter()
                        .map(|n| format!(
                            "[workspace.dependencies] `{n}` is declared but no member inherits it."
                        ))
                        .collect::<Vec<_>>()
                        .join(" | ")
                ),
            )
        });

        // THE THIRD SET, AND IT IS THE ONE THAT WAS MISSING: what is ON DISK.
        //
        // This row compared `inspected` with `declared`, and `inspected` is DERIVED from `declared`
        // — so deleting a member line shrinks both and the row stays green at 60 where it was green
        // at 61. A red-team pass struck `crates/busbar-plane-llm` from the list, left the path
        // dependency that reaches it in place, and dropped a live crate out of every `--workspace`
        // test, clippy and deny run with nothing red anywhere in the tree. A set-equality row that
        // reads one set twice is not a set-equality row.
        let unmembered = on_disk_unmembered(cx, &s.declared);
        rows.push(
            if s.unreadable.is_empty()
                && s.inspected.len() == s.declared.len()
                && unmembered.is_empty()
            {
                Row::pass(
                    ROW_SET_EQUALITY,
                    "the members inspected are exactly the members the workspace declares, and \
                     exactly the crates on disk",
                    format!("{} member(s)", s.inspected.len()),
                )
            } else {
                let missing: Vec<&String> = s
                    .declared
                    .iter()
                    .filter(|m| !s.inspected.contains(m))
                    .collect();
                let mut detail = s.unreadable.clone();
                detail.extend(unmembered.iter().cloned());
                detail.push(format!(
                    "inspected {} members but the workspace declares {}; unreadable: {missing:?}",
                    s.inspected.len(),
                    s.declared.len()
                ));
                Row::fail(
                    ROW_SET_EQUALITY,
                    "the inspected member set is not the declared member set, or a crate on disk \
                     is on no member list",
                    detail.join(" | "),
                )
            },
        );

        rows.push(if s.inspected.len() < MIN_MEMBERS {
            Row::fail(
                ROW_MEMBER_FLOOR,
                "the member walk collapsed below its floor",
                format!(
                    "only {} member manifests were discovered (floor {MIN_MEMBERS}). A discovery \
                     step that finds almost nothing passes almost everything.",
                    s.inspected.len()
                ),
            )
        } else {
            Row::pass(
                ROW_MEMBER_FLOOR,
                "enough member manifests were inspected for the rules above to mean anything",
                format!("{} member(s) (floor {MIN_MEMBERS})", s.inspected.len()),
            )
        });

        rows.push(if s.inherited_count < MIN_INHERITED {
            Row::fail(
                ROW_INHERITED_FLOOR,
                "too few inheriting declarations were found",
                format!(
                    "only {} inherited declarations were found (floor {MIN_INHERITED}). Either the \
                     table is not actually in use or the walk is broken; both are RED.",
                    s.inherited_count
                ),
            )
        } else {
            Row::pass(
                ROW_INHERITED_FLOOR,
                "the workspace table is actually in use",
                format!(
                    "{} inherited declaration(s) (floor {MIN_INHERITED})",
                    s.inherited_count
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
            "every dependency in the real workspace goes through the table",
            &self.owed().iter().map(String::as_str).collect::<Vec<_>>(),
        ));
        // THE MEMBER LINE, DELETED. This is the one case that has to run against the REAL tree:
        // the hole was that `inspected` is derived from `declared`, so a synthetic workspace whose
        // member list is the whole truth cannot show it. Strike one line from the real root
        // manifest and the crate is still on disk, still path-depended, and no longer in a single
        // `--workspace` run.
        let mut ov = Overlay::new();
        ov.set(
            "Cargo.toml",
            cx.read("Cargo.toml").unwrap_or_default().replacen(
                "    \"crates/busbar-plane-llm\",\n",
                "",
                1,
            ),
        );
        report.push(crate::gates::prove_rows_red(
            cx,
            self,
            "a member line deleted leaves a live crate on disk and out of every --workspace run",
            &[ROW_SET_EQUALITY],
            ov,
            &["crates/busbar-plane-llm", "no [workspace] members entry"],
        ));
        for plant in plants(cx) {
            report.push(plant.case(cx, self));
        }
        report
    }

    /// THE SAME PLANTED WORKSPACES, DRIVEN THROUGH BOTH IMPLEMENTATIONS.
    ///
    /// One probe per planted violation, reusing [`plants`] rather than a second set of fixtures: a
    /// parity probe built from an overlay the self-test never drove is comparing something neither
    /// side has proven.
    ///
    /// The legacy script takes `--root`, so the harness points it at a scratch tree holding exactly
    /// the paths named in `materialize` — the synthetic root manifest and one manifest per declared
    /// member. That list is derived from the plant itself, not written out again, because a member
    /// left off it is a member the Python reads out of the REAL repository, and the probe would
    /// then grade a tree nobody planted.
    fn parity_probes(&self, cx: &Ctx) -> Vec<crate::gates::ParityProbe> {
        plants(cx)
            .into_iter()
            .map(|p| {
                let probe = crate::gates::ParityProbe::red(
                    p.label,
                    p.overlay,
                    p.materialize,
                    p.rule.to_string(),
                );
                match legacy_wording(p.rule) {
                    Some(w) => probe.named_by(w),
                    // The one rule with no legacy counterpart at all. The Python walks the DECLARED
                    // member list and never looks at `crates/`, so a layout change the root
                    // manifest was edited to match is invisible to it — there is no denominator
                    // floor to fall below because there is no denominator.
                    None => probe.diverges(crate::gates::Divergence::LegacyGreen {
                        reason: "the legacy walks the declared member list and never reads \
                                 `crates/`, so a directory that moved out from under the workspace \
                                 is not something it can see. This gate's walk carries a floor, and \
                                 a scan that collapsed is a named failure rather than a clean tree."
                            .to_string(),
                    }),
                }
            })
            .collect()
    }
}

/// What the LEGACY script calls each rule this gate owes.
///
/// The two vocabularies differ because the row ids here are namespaced and the Python prints prose,
/// so a parity probe that compared only this gate's id would be asserting nothing about the legacy
/// half. `None` means the rule has no legacy counterpart at all, which is a declared divergence
/// rather than a missing mapping — the difference matters, so it is a distinct return value and not
/// an empty string.
fn legacy_wording(rule: &str) -> Option<&'static str> {
    match rule {
        ROW_TABLE => Some("there is no source of truth to check"),
        ROW_INHERITANCE => Some("states its own version"),
        ROW_INHERIT_TARGET => Some("to inherit FROM"),
        ROW_ORPHANS => Some("no member inherits it"),
        ROW_SET_EQUALITY => Some("has no Cargo.toml"),
        ROW_MEMBER_FLOOR => Some("member manifests were discovered (floor 8)"),
        ROW_INHERITED_FLOOR => Some("inherited declarations were found (floor 40)"),
        _ => None,
    }
}

/// One planted workspace: the overlay, the owed row it must be reported by, the substring the RED
/// report has to contain, and every path the legacy script must be shown. Shared by
/// [`Gate::selftest`] and [`Gate::parity_probes`] so the two cannot drift apart.
struct Plant {
    label: String,
    rule: &'static str,
    naming: Vec<String>,
    overlay: Overlay,
    materialize: Vec<String>,
}

impl Plant {
    fn case<'a>(self, cx: &'a Ctx, gate: &'a dyn Gate) -> crate::gates::CasePlan<'a> {
        let naming: Vec<&str> = self.naming.iter().map(String::as_str).collect();
        prove_red(cx, gate, self.label, &[self.rule], self.overlay, &naming)
    }
}

/// Build one plant out of a member list and a workspace table, with `absent` naming the manifests
/// the plant deliberately removes — those are dropped from `materialize`, because the harness
/// writes the overlaid view of every path it is given and a file the overlay says is gone cannot be
/// written.
fn planted(
    label: &str,
    rule: &'static str,
    naming: &[&str],
    members: &[(String, String)],
    table: &str,
    absent: &[&str],
) -> Plant {
    let mut overlay = plant(members, table);
    let mut materialize = vec!["Cargo.toml".to_string()];
    for (path, _) in members {
        materialize.push(format!("{path}/Cargo.toml"));
    }
    for gone in absent {
        overlay.remove(gone);
        materialize.retain(|p| p != gone);
    }
    Plant {
        label: label.to_string(),
        rule,
        naming: naming.iter().map(|s| (*s).to_string()).collect(),
        overlay,
        materialize,
    }
}

/// The nine planted violations, one per rule this gate enforces.
fn plants(cx: &Ctx) -> Vec<Plant> {
    let mut out = Vec::new();

    // Rule 2, three plants, because "dependencies" is three tables plus their per-target forms and
    // a rule enforced on one of them is scoped to where the bug was first seen.
    let mut restated = clean_members();
    restated[3].1 = member_body(&["dep0", "dep1", "dep3", "dep4", "dep5"], "dep2 = \"1\"");
    out.push(planted(
        "a member restates a version",
        ROW_INHERITANCE,
        &["states its own version"],
        &restated,
        &clean_table(),
        &[],
    ));

    let mut dev = clean_members();
    dev[5].1 = format!(
        "{}\n\n[dev-dependencies]\ndep9 = \"3\"",
        member_body(CLEAN_DEPS, "")
    );
    out.push(planted(
        "a dev-dependency restates a version",
        ROW_INHERITANCE,
        &["states its own version", "[dev-dependencies]"],
        &dev,
        &clean_table(),
        &[],
    ));

    let mut per_target = clean_members();
    per_target[6].1 = format!(
        "{}\n\n[target.'cfg(unix)'.dependencies]\ndep9 = \"3\"",
        member_body(CLEAN_DEPS, "")
    );
    out.push(planted(
        "a per-target dependency restates a version",
        ROW_INHERITANCE,
        &["states its own version", "target."],
        &per_target,
        &clean_table(),
        &[],
    ));

    // Rule 3, alone.
    let mut orphaned_inherit = clean_members();
    orphaned_inherit[1].1 = format!(
        "{}\nnot_in_table = {{ workspace = true }}",
        member_body(CLEAN_DEPS, "")
    );
    out.push(planted(
        "a dependency inherits from an entry that is not there",
        ROW_INHERIT_TARGET,
        &["no `not_in_table` entry"],
        &orphaned_inherit,
        &clean_table(),
        &[],
    ));

    // Rule 4, alone: a pin nothing obeys — it looks like governance and governs nothing.
    out.push(planted(
        "an orphaned workspace entry",
        ROW_ORPHANS,
        &["no member inherits it"],
        &clean_members(),
        &format!("{}\nunused_dep = \"9\"", clean_table()),
        &[],
    ));

    // Rule 5, alone: a declared member with no manifest. Eight members still inspect, so neither
    // floor moves.
    let mut ghost = clean_members();
    ghost.push(("ws-plant/never-existed".to_string(), String::new()));
    out.push(planted(
        "a declared member has no manifest",
        ROW_SET_EQUALITY,
        &["has no Cargo.toml"],
        &ghost,
        &clean_table(),
        &["ws-plant/never-existed/Cargo.toml"],
    ));

    // Rule 6 gets its OWN discriminating fixture: two members carrying TWENTY inherited
    // declarations apiece, so the inherited-declaration floor is comfortably clear and only the
    // member floor can go red. A floor proven alongside its neighbour is a floor that could be
    // deleted with this self-test still green.
    let wide: Vec<String> = (0..20).map(|i| format!("dep{i}")).collect();
    let wide_refs: Vec<&str> = wide.iter().map(String::as_str).collect();
    let few_members: Vec<(String, String)> = (0..2)
        .map(|j| (format!("ws-plant/w{j}"), member_body(&wide_refs, "")))
        .collect();
    out.push(planted(
        "too few members discovered",
        ROW_MEMBER_FLOOR,
        &[&format!("floor {MIN_MEMBERS}")],
        &few_members,
        &table_of(&wide_refs),
        &[],
    ));

    // Rule 7 gets its own the other way round: eight members — clear of the member floor — each
    // carrying four inherited declarations, so only the inherited-declaration floor can fire.
    let narrow = ["dep0", "dep1", "dep2", "dep3"];
    let thin_members: Vec<(String, String)> = (0..8)
        .map(|j| (format!("ws-plant/t{j}"), member_body(&narrow, "")))
        .collect();
    out.push(planted(
        "too few inherited declarations",
        ROW_INHERITED_FLOOR,
        &[&format!("floor {MIN_INHERITED}")],
        &thin_members,
        &table_of(&narrow),
        &[],
    ));

    // Rule 1, alone: the table the whole gate reads against is gone.
    out.push(planted(
        "the workspace table is missing",
        ROW_TABLE,
        &["no source of truth to check"],
        &clean_members(),
        "",
        &[],
    ));

    // Rule 8, alone: a workspace whose declared members are all present and clean, over a `crates/`
    // tree that has collapsed. Rules 1-7 read the ROOT MANIFEST's member list, so they are all
    // green here and only the directory walk can name this.
    //
    // THE LEGACY SCRIPT CANNOT SEE THIS ONE. It never looks at `crates/` — it walks the declared
    // member list and nothing else — so the plant is invisible to it by construction. The probe
    // stays: a rule the Rust gate enforces and the Python never did is a finding to report at the
    // call-site switch, not a probe to drop so the run comes out quiet.
    if let Ok(real) = cx.walk(&WalkSpec::new(["crates"]).ext("toml")) {
        let removed: Vec<String> = real.iter().skip(2).map(SourceFile::rel_str).collect();
        let refs: Vec<&str> = removed.iter().map(String::as_str).collect();
        out.push(planted(
            "the crates/ manifest walk collapsed",
            ROW_DISCOVERY,
            &["walk over [crates]"],
            &clean_members(),
            &clean_table(),
            &refs,
        ));
    }

    out
}

/// The FAIL rows every rule downstream of an unreadable root manifest or an absent workspace table
/// must still emit. Silence is DID NOT RUN and a PASS would be a claim nothing checked.
fn unproven(why: &str) -> Vec<Row> {
    [
        (ROW_INHERITANCE, "inheritance is unproven"),
        (ROW_INHERIT_TARGET, "inherit targets are unproven"),
        (ROW_ORPHANS, "the orphan check is unproven"),
        (ROW_SET_EQUALITY, "the member set is unproven"),
        (ROW_MEMBER_FLOOR, "the member count is unknown"),
        (ROW_INHERITED_FLOOR, "the inherited count is unknown"),
    ]
    .iter()
    .map(|(id, title)| Row::fail(*id, *title, why))
    .collect()
}

// ── fixture construction for the self-test ───────────────────────────────────────────────────────
//
// Every RED case below is a WHOLE synthetic workspace planted into the overlay: a root manifest and
// its members, none of which touch the real tree. That is deliberate. Editing one real member to
// plant one violation moves several counts at once, and a case that reds three rules cannot tell
// you which rule is still alive.

const CLEAN_DEPS: &[&str] = &["dep0", "dep1", "dep2", "dep3", "dep4", "dep5"];

fn table_of(names: &[&str]) -> String {
    names
        .iter()
        .map(|n| format!("{n} = \"1\""))
        .collect::<Vec<_>>()
        .join("\n")
}

fn clean_table() -> String {
    table_of(CLEAN_DEPS)
}

/// A `[dependencies]` table inheriting `names`, plus one optional extra raw line.
fn member_body(names: &[&str], extra: &str) -> String {
    let mut body = String::from("[dependencies]");
    for n in names {
        body.push_str(&format!("\n{n} = {{ workspace = true }}"));
    }
    if !extra.is_empty() {
        body.push('\n');
        body.push_str(extra);
    }
    body
}

/// Eight members, six inherited declarations apiece: forty-eight, clear of both floors, so a case
/// that moves ONE of them still moves only the rule it is aimed at.
fn clean_members() -> Vec<(String, String)> {
    (0..8)
        .map(|j| (format!("ws-plant/m{j}"), member_body(CLEAN_DEPS, "")))
        .collect()
}

/// The overlay: a synthetic root manifest plus one manifest per member.
fn plant(members: &[(String, String)], table: &str) -> Overlay {
    let mut ov = Overlay::new();
    let list = members
        .iter()
        .map(|(path, _)| format!("    \"{path}\",\n"))
        .collect::<String>();
    ov.set(
        "Cargo.toml",
        format!("[workspace]\nresolver = \"2\"\nmembers = [\n{list}]\n\n[workspace.dependencies]\n{table}\n"),
    );
    for (path, body) in members {
        let name = path.rsplit('/').next().unwrap_or(path);
        ov.set(
            format!("{path}/Cargo.toml"),
            format!("[package]\nname = \"{name}\"\nversion = \"0.0.0\"\n\n{body}\n"),
        );
    }
    ov
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cx() -> Ctx {
        Ctx::workspace().expect("workspace context")
    }

    #[test]
    fn an_inline_table_decomposes_into_its_keys() {
        assert_eq!(
            parse_spec("{ workspace = true }"),
            DepSpec::Table(BTreeMap::from([(
                "workspace".to_string(),
                "true".to_string()
            )]))
        );
        assert!(parse_spec("{ workspace = true }").inherits());
        assert!(!parse_spec("\"1.0\"").inherits());
        assert_eq!(parse_spec("1.0"), DepSpec::Version("1.0".to_string()));
    }

    /// A features array holds commas. A reader that split on every comma would drop the keys after
    /// it and read a version-restating dependency as an inheriting one.
    #[test]
    fn a_features_array_does_not_hide_the_keys_after_it() {
        let spec =
            parse_spec(r#"{ version = "0.27", features = ["a", "b"], default-features = false }"#);
        assert!(!spec.inherits());
        assert!(!spec.is_path_or_git());
        assert!(spec.shown().contains("0.27"));
    }

    /// Path AND git are the same arm: neither is routed through the workspace table.
    #[test]
    fn path_and_git_dependencies_are_both_external_to_the_table() {
        assert!(parse_spec(r#"{ path = "../busbar-core" }"#).is_path_or_git());
        assert!(
            parse_spec(r#"{ git = "https://example.invalid/x", rev = "abc" }"#).is_path_or_git()
        );
        assert!(!parse_spec(r#"{ version = "1" }"#).is_path_or_git());
    }

    #[test]
    fn every_dependency_table_spelling_is_a_dependency_table() {
        assert!(is_dep_section("dependencies"));
        assert!(is_dep_section("dev-dependencies"));
        assert!(is_dep_section("build-dependencies"));
        assert!(is_dep_section("target.'cfg(unix)'.dependencies"));
        assert!(is_dep_section(
            "target.'cfg(not(target_env = \"msvc\"))'.dev-dependencies"
        ));
        assert!(!is_dep_section("workspace.dependencies"));
        assert!(!is_dep_section("package"));
    }

    /// The `[dependencies.serde]` sub-table spelling must not be a blind spot: a member could state
    /// a version there and a reader that only knows inline tables would call the tree clean.
    #[test]
    fn a_dependency_sub_table_is_read_like_an_inline_one() {
        let ov = {
            let mut ov = Overlay::new();
            ov.set(
                "ws-plant/sub/Cargo.toml",
                "[package]\nname = \"sub\"\n\n[dependencies.serde]\nversion = \"1\"\n",
            );
            ov
        };
        let planted = cx().with_overlay(ov);
        let doc = read_manifest(&planted, "ws-plant/sub/Cargo.toml").expect("planted manifest");
        let entries = dep_entries(&doc);
        assert_eq!(entries.len(), 1, "{entries:?}");
        assert_eq!(entries[0].0, "dependencies");
        assert_eq!(entries[0].1, "serde");
        assert!(!entries[0].2.inherits());
    }

    /// The control case, in the Python's words: if a clean synthetic tree fails, every rejection
    /// the self-test makes proves nothing, because a lint that fails everything is as useless as
    /// one that passes everything.
    #[test]
    fn the_clean_synthetic_workspace_passes() {
        let planted = cx().with_overlay(plant(&clean_members(), &clean_table()));
        let verdict = crate::gates::execute(&WorkspaceDepsGate, &planted);
        assert!(
            !verdict.red,
            "the control fixture is RED: {:?}",
            verdict.problems
        );
    }

    /// The ids that went FAIL under a planted overlay.
    fn failed_ids(ov: Overlay) -> Vec<String> {
        let planted = cx().with_overlay(ov);
        crate::gates::execute(&WorkspaceDepsGate, &planted)
            .rows
            .iter()
            .filter(|r| r.status != crate::ledger::Status::Pass)
            .map(|r| r.id.clone())
            .collect()
    }

    /// THE TWO FLOORS MUST FAIL APART. A fixture that trips both proves neither: either one could
    /// be deleted and the self-test would stay green on the other. This is the defect the audit
    /// found in the shell gates' floors, asserted here rather than assumed.
    #[test]
    fn each_floor_has_a_fixture_that_only_it_rejects() {
        let wide: Vec<String> = (0..20).map(|i| format!("dep{i}")).collect();
        let wide_refs: Vec<&str> = wide.iter().map(String::as_str).collect();
        let few: Vec<(String, String)> = (0..2)
            .map(|j| (format!("ws-plant/w{j}"), member_body(&wide_refs, "")))
            .collect();
        assert_eq!(
            failed_ids(plant(&few, &table_of(&wide_refs))),
            vec![ROW_MEMBER_FLOOR.to_string()],
            "the member-floor fixture must reject on the member floor and nothing else"
        );

        let narrow = ["dep0", "dep1", "dep2", "dep3"];
        let thin: Vec<(String, String)> = (0..8)
            .map(|j| (format!("ws-plant/t{j}"), member_body(&narrow, "")))
            .collect();
        assert_eq!(
            failed_ids(plant(&thin, &table_of(&narrow))),
            vec![ROW_INHERITED_FLOOR.to_string()],
            "the inherited-floor fixture must reject on the inherited floor and nothing else"
        );
    }

    /// The directory floor is the third one, and it is counted off a different instrument than the
    /// other two — so it too needs a fixture the other seven rules pass.
    #[test]
    fn the_crates_walk_floor_rejects_alone() {
        let real = cx()
            .walk(&WalkSpec::new(["crates"]).ext("toml"))
            .expect("the real crates/ walk");
        let mut ov = plant(&clean_members(), &clean_table());
        for f in real.iter().skip(2) {
            ov.remove(&f.rel);
        }
        assert_eq!(
            failed_ids(ov),
            vec![ROW_DISCOVERY.to_string()],
            "an emptied crates/ must be named by the walk and by nothing else"
        );
    }

    #[test]
    fn the_gate_is_green_on_the_workspace() {
        let verdict = crate::gates::execute(&WorkspaceDepsGate, &cx());
        assert!(
            !verdict.red,
            "workspace-deps is RED on the real tree: {:?}",
            verdict.problems
        );
    }

    #[test]
    fn the_selftest_proves_every_owed_row() {
        let cx = cx();
        let report = WorkspaceDepsGate.selftest(&cx);
        crate::gates::verify_report(&WorkspaceDepsGate, &report)
            .unwrap_or_else(|errs| panic!("workspace-deps selftest: {errs:#?}"));
        assert_eq!(report.skipped(), 0, "a case had nothing to plant");
    }
}
