//! THE CONFORMANCE CLAIM-SYNC GATE — the manifest is the only truth, and a stale or false claim is
//! made structurally impossible.
//!
//! A "we're certified" claim that outlives the green that earned it is a company-killer. The claim
//! lives in a human-visible surface — the README badge row (`README.md`) — and today that is a
//! hand-authored string, exactly the "hand-maintained enumeration that silently stops covering what
//! came after it" busbar's own tooling already treats as a defect class
//! (`scripts/release-gate/expected-ids.sh:11-14`).
//!
//! The fix is the shape busbar already trusts three times over (the config-schema drift model,
//! `config_schema/mod.rs:8`, `:11`): a single machine-readable manifest regenerated from real
//! verdicts and never hand-edited, both surfaces GENERATED from it, and a snapshot-drift gate that
//! fails CI when a rendered surface asserts anything the manifest does not. Fail-closed: a suite that
//! did not run, or ran against a stale commit, CANNOT render green ([`render`]).
//!
//! | row | asserts |
//! |---|---|
//! | `conformance:registry` | `registry.toml` parses; every suite names a standard, plan, label, a tier in the fixed enum and a verdict artifact; no duplicate id. |
//! | `conformance:manifest-drift` | `conformance/manifest.json` byte-equals a fresh render from the registry + verdicts. `--write` rewrites; otherwise diff. (The config-schema `snapshot-drift` rule, `config_schema/mod.rs:11`.) |
//! | `conformance:coverage` | every registered suite appears in the committed manifest and every manifest suite is registered — SET EQUALITY (`verdict-covers-every-leg.py:12-18` applied to suites). |
//! | `conformance:readme-drift` | the README badge block between the markers byte-equals a fresh render from the manifest. |
//! | `conformance:freshness` | every armed passing verdict's `commit` equals the release commit — `git rev-parse HEAD` of the checkout under judgement, resolved from OUTSIDE the verdicts, never elected by them — so a pass carried over from an older sha is RED however many verdicts share that sha (§5.2). |
//! | `conformance:no-orphan-claim` | no human-visible claim string outside the marker block lacks a backing manifest entry: neither a registered suite's badge string nor any claim word ([`render::CLAIM_WORDS`]) for a standard no registry names (the grep backstop, §5). |
//!
//! ## Why the website page is not a row here
//!
//! The certifications page fetches the PUBLISHED manifest pinned to a release tag and renders
//! client-side from the shared `claim_for` logic (design §6.2, shape B) — it is out of the release
//! build's tree, so there is no in-tree byte to diff. Its "cannot overstate" property is the same
//! one this gate enforces on the manifest it renders from.

use crate::ctx::Ctx;
use crate::gates::{Gate, Report};
use crate::ledger::{Row, Verdict};

pub mod render;
mod selftest;

use render::{
    manifest_with_labels, marked_span, no_orphan_claims, render_manifest, render_readme_block,
    MANIFEST_PATH, README_PATH,
};

pub const ROW_REGISTRY: &str = "conformance:registry";
pub const ROW_MANIFEST_DRIFT: &str = "conformance:manifest-drift";
pub const ROW_COVERAGE: &str = "conformance:coverage";
pub const ROW_README_DRIFT: &str = "conformance:readme-drift";
pub const ROW_FRESHNESS: &str = "conformance:freshness";
pub const ROW_NO_ORPHAN: &str = "conformance:no-orphan-claim";

pub const OWED: &[&str] = &[
    ROW_REGISTRY,
    ROW_MANIFEST_DRIFT,
    ROW_COVERAGE,
    ROW_README_DRIFT,
    ROW_FRESHNESS,
    ROW_NO_ORPHAN,
];

/// Spelled once so every row that suggests it suggests the same thing (the config-schema `REGEN`
/// idiom, `config_schema/mod.rs:65`).
const REGEN: &str = "cargo xtask gate conformance-sync --write";

fn unproven(id: &str, why: &str) -> Row {
    Row::skip(
        id,
        "unproven — a check above this one refused",
        why.to_string(),
    )
}

/// Every owed row except `first`, as SKIP: a refusal at the top of the derivation makes every row
/// under it DID NOT RUN, and reporting them as passes is the false green the harness refuses.
fn refuse(first: &str, why: String) -> Verdict {
    let mut rows = vec![Row::fail(
        first,
        "the input the manifest is built from was refused",
        why,
    )];
    for id in OWED {
        if *id != first {
            rows.push(unproven(id, "the registry or the render refused above"));
        }
    }
    Verdict::of(rows)
}

pub struct ConformanceSyncGate;

impl Gate for ConformanceSyncGate {
    fn name(&self) -> &'static str {
        "conformance-sync"
    }

    fn owed(&self) -> Vec<String> {
        OWED.iter().map(|s| (*s).to_string()).collect()
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        // ── :registry — the one hand-authored input, parsed and validated first.
        let suites = match render::parse_registry(cx) {
            Ok(s) => s,
            Err(why) => return refuse(ROW_REGISTRY, why),
        };
        let mut rows = vec![Row::pass(
            ROW_REGISTRY,
            "the registry parses and every suite is well-formed",
            format!(
                "{} suite(s), every one names a standard, plan, label, tier and verdict artifact",
                suites.len()
            ),
        )];

        // ── :manifest-drift — the fresh render from the registry + verdicts. One derivation, two
        //    arms: write it, or diff it against the committed manifest.
        let fresh = match render_manifest(cx, &suites) {
            Ok(s) => s,
            Err(why) => {
                rows.push(Row::fail(
                    ROW_MANIFEST_DRIFT,
                    "the manifest could not be generated",
                    why,
                ));
                for id in [ROW_COVERAGE, ROW_README_DRIFT, ROW_FRESHNESS, ROW_NO_ORPHAN] {
                    rows.push(unproven(id, "the manifest render refused above"));
                }
                return Verdict::of(rows);
            }
        };

        rows.push(if cx.env().write {
            match std::fs::write(cx.abs(MANIFEST_PATH), &fresh) {
                Ok(()) => Row::pass(
                    ROW_MANIFEST_DRIFT,
                    "the committed manifest IS the fresh render (rewritten by --write)",
                    format!("{MANIFEST_PATH} rewritten"),
                ),
                Err(e) => Row::fail(
                    ROW_MANIFEST_DRIFT,
                    "the manifest could not be written",
                    format!("{MANIFEST_PATH}: {e}"),
                ),
            }
        } else {
            match cx.read(MANIFEST_PATH) {
                Err(_) => Row::fail(
                    ROW_MANIFEST_DRIFT,
                    "the committed manifest is MISSING",
                    format!("{MANIFEST_PATH} does not exist. Seed it with:  {REGEN}"),
                ),
                Ok(committed) if committed != fresh => Row::fail(
                    ROW_MANIFEST_DRIFT,
                    "the committed manifest is STALE",
                    format!(
                        "{MANIFEST_PATH} does not match a fresh render of the registry + verdicts. \
                         {}  Regenerate with:  {REGEN}",
                        first_difference(&committed, &fresh)
                    ),
                ),
                Ok(_) => Row::pass(
                    ROW_MANIFEST_DRIFT,
                    "the committed manifest byte-equals a fresh render",
                    format!("{MANIFEST_PATH} is current"),
                ),
            }
        });

        // The manifest the README is rendered FROM. In write mode it is the fresh render just
        // written (so both surfaces move together); otherwise it is the committed manifest, so
        // readme-drift is about README-vs-manifest and manifest-drift is about manifest-vs-verdicts.
        let manifest_text = if cx.env().write {
            fresh.clone()
        } else {
            cx.read(MANIFEST_PATH).unwrap_or_default()
        };

        // ── :coverage — SET EQUALITY between the registry and the committed manifest.
        rows.push(row_coverage(cx, &suites));

        // ── :readme-drift — the badge block, rendered from the manifest.
        rows.push(row_readme(cx, &suites, &manifest_text));

        // ── :freshness — every armed passing verdict about the release commit, which is resolved
        //    from OUTSIDE the verdicts (item 165), never elected by them.
        rows.push(row_freshness(cx, &suites));

        // ── :no-orphan-claim — the grep backstop over the README.
        rows.push(row_no_orphan(cx, &suites));

        Verdict::of(rows)
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        selftest::run(self, cx)
    }
}

fn row_coverage(cx: &Ctx, suites: &[render::Suite]) -> Row {
    use std::collections::BTreeSet;
    let registered: BTreeSet<String> = suites.iter().map(|s| s.id.clone()).collect();
    let manifest_text = match cx.read(MANIFEST_PATH) {
        Ok(t) => t,
        Err(_) => {
            return Row::fail(
                ROW_COVERAGE,
                "the committed manifest is MISSING, so coverage cannot be reconciled",
                format!("{MANIFEST_PATH} does not exist. Seed it with:  {REGEN}"),
            )
        }
    };
    let v: serde_json::Value = match serde_json::from_str(&manifest_text) {
        Ok(v) => v,
        Err(e) => {
            return Row::fail(
                ROW_COVERAGE,
                "the committed manifest is not readable JSON",
                format!("{MANIFEST_PATH}: {e}"),
            )
        }
    };
    let in_manifest: BTreeSet<String> = v
        .get("suites")
        .and_then(serde_json::Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|s| s.get("suite").and_then(serde_json::Value::as_str))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let missing: Vec<&String> = registered.difference(&in_manifest).collect();
    let extra: Vec<&String> = in_manifest.difference(&registered).collect();
    if missing.is_empty() && extra.is_empty() {
        Row::pass(
            ROW_COVERAGE,
            "every registered suite appears in the manifest, and every manifest suite is registered",
            format!("{} suite(s), set-equal", registered.len()),
        )
    } else {
        Row::fail(
            ROW_COVERAGE,
            "the manifest and the registry name a different set of suites",
            format!(
                "registered but ABSENT from the manifest: {missing:?}; in the manifest but NOT \
                 registered: {extra:?}. A suite that vanishes from the manifest is RED, not silently \
                 un-claimed. Regenerate with:  {REGEN}"
            ),
        )
    }
}

fn row_readme(cx: &Ctx, suites: &[render::Suite], manifest_text: &str) -> Row {
    let manifest = match manifest_with_labels(manifest_text, suites) {
        Ok(m) => m,
        Err(why) => {
            return Row::fail(
                ROW_README_DRIFT,
                "the manifest the README renders from is unreadable",
                why,
            )
        }
    };
    let block = render_readme_block(&manifest);
    let readme = cx.read(README_PATH).unwrap_or_default();
    if cx.env().write {
        return match render::rewrite_readme(&readme, &block) {
            Some(next) => match std::fs::write(cx.abs(README_PATH), next) {
                Ok(()) => Row::pass(
                    ROW_README_DRIFT,
                    "the README badge block IS the fresh render (rewritten by --write)",
                    format!("{README_PATH} badge block rewritten"),
                ),
                Err(e) => Row::fail(
                    ROW_README_DRIFT,
                    "the README could not be written",
                    format!("{README_PATH}: {e}"),
                ),
            },
            None => Row::fail(
                ROW_README_DRIFT,
                "the README carries no conformance-badges markers to write between",
                format!(
                    "add the BEGIN/END conformance-badges markers to {README_PATH} first, then \
                     {REGEN}"
                ),
            ),
        };
    }
    match marked_span(&readme) {
        None => Row::fail(
            ROW_README_DRIFT,
            "the README carries no conformance-badges markers",
            format!(
                "{README_PATH} has no BEGIN/END conformance-badges markers — there is nothing to \
                 diff, so the badges are unguarded. Seed them with:  {REGEN}"
            ),
        ),
        Some((begin, end)) => {
            let committed = &readme[begin..end];
            if committed == block {
                Row::pass(
                    ROW_README_DRIFT,
                    "the README badge block byte-equals a fresh render from the manifest",
                    format!("{README_PATH} badge block is current"),
                )
            } else {
                Row::fail(
                    ROW_README_DRIFT,
                    "the README badge block is STALE",
                    format!(
                        "the badge block in {README_PATH} does not match a fresh render from the \
                         manifest. {}  Regenerate with:  {REGEN}",
                        first_difference(committed, &block)
                    ),
                )
            }
        }
    }
}

fn row_freshness(cx: &Ctx, suites: &[render::Suite]) -> Row {
    let release = match render::release_commit(cx) {
        Ok(c) => c,
        Err(why) => {
            return Row::fail(
                ROW_FRESHNESS,
                "the release commit could not be resolved",
                format!("{why} — freshness cannot be judged against an unknown commit"),
            )
        }
    };
    let a = match render::assess(cx, suites) {
        Ok(a) => a,
        Err(why) => return Row::fail(ROW_FRESHNESS, "the verdicts could not be read", why),
    };
    let stale = render::stale_against(&a, &release);
    let short: String = release.chars().take(9).collect();
    if stale.is_empty() {
        Row::pass(
            ROW_FRESHNESS,
            "every armed passing verdict is about the release commit",
            format!(
                "release commit {short} (the checkout under judgement), {} armed pass(es), none \
                 stale",
                a.resolved
                    .iter()
                    .filter(|r| r
                        .verdict
                        .as_ref()
                        .is_some_and(|v| v.armed && v.status == "pass"))
                    .count()
            ),
        )
    } else {
        Row::fail(
            ROW_FRESHNESS,
            "a passing verdict is STALE — not about the release commit",
            format!(
                "{} suite(s) claim a green on a commit that is not the release commit {short}: {} \
                 — a pass carried over from an older sha is refused, however many other verdicts \
                 agree on that older sha. Re-run the suite(s) on this sha.",
                stale.len(),
                stale.join(", ")
            ),
        )
    }
}

fn row_no_orphan(cx: &Ctx, suites: &[render::Suite]) -> Row {
    let readme = cx.read(README_PATH).unwrap_or_default();
    let orphans = no_orphan_claims(&readme, suites);
    if orphans.is_empty() {
        Row::pass(
            ROW_NO_ORPHAN,
            "no conformance claim appears outside the generated badge block",
            "every human-visible claim string is backed by the manifest render".to_string(),
        )
    } else {
        let named: Vec<String> = orphans
            .iter()
            .map(|o| match o {
                render::Orphan::Registered { id, token } => format!("`{token}` (suite {id})"),
                render::Orphan::Unbacked { line, word, text } => format!(
                    "`{text}` (line {line}: claim word `{word}`, and no registered suite backs it)"
                ),
            })
            .collect();
        Row::fail(
            ROW_NO_ORPHAN,
            "a conformance claim appears with no backing manifest entry",
            format!(
                "these claim string(s) appear in {README_PATH} OUTSIDE the generated badge block: \
                 {}. A claim the manifest render did not put there is a hand-added claim; delete it \
                 or earn it. {REGEN} renders only what the manifest currently asserts.",
                named.join(", ")
            ),
        )
    }
}

/// The first line two renders disagree on, so a stale surface says WHERE rather than only THAT.
fn first_difference(committed: &str, fresh: &str) -> String {
    for (i, (a, b)) in committed.lines().zip(fresh.lines()).enumerate() {
        if a != b {
            return format!(
                "first difference at line {}: committed {:?} vs fresh {:?}.",
                i + 1,
                a.trim(),
                b.trim()
            );
        }
    }
    format!(
        "the two agree for {} line(s) and then differ in length (committed {}, fresh {}).",
        committed.lines().count().min(fresh.lines().count()),
        committed.lines().count(),
        fresh.lines().count()
    )
}
