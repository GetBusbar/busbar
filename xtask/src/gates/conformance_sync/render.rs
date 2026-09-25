//! THE GENERATOR AND THE RENDERERS — the manifest is the only truth, and both human-visible
//! surfaces are DERIVED from it.
//!
//! Modelled on `config_schema::schema`: a fresh render assembled from committed inputs, canonicalised
//! by the same sorted two-space emitter, so a `--write` arm and a drift arm are the SAME derivation
//! and cannot disagree about the answer (`config_schema/mod.rs:8`, `:11`).
//!
//! ## The inputs, all committed
//!
//! * `conformance/registry.toml` — the ONE hand-authored file (P4, DERIVED-never-typed:
//!   `scripts/release-gate/expected-ids.sh:11-14`). It lists which suites EXIST and their claim
//!   TYPE, never their status.
//! * `conformance/verdicts/<id>.json` — one per suite that ran, the arm-or-red fact each conformance
//!   workflow already computes (`mcp-conformance.yml:486-559`), written to disk. In CI the release
//!   pipeline drops the downloaded artifacts here before `--write`; a suite that did not run leaves
//!   no file and is `not-run`, never absent, never green (P2: `fleet-fixtures/verdict.sh:164-172`).
//!
//! ## The reconciliation (a ledger, exactly like `fleet-fixtures/verdict.sh:91-128`)
//!
//! OWED = the registry. GOT = the verdicts present. Every registered suite resolves to `pass`,
//! `fail`, or `not-run`; a registered suite with no verdict is `not-run`; a verdict whose `commit`
//! is not the release commit is downgraded to `not-run(stale)`. `claim` is `null` for anything but
//! `pass`, so there is no code path that renders a non-green suite as anything but absent.

use std::collections::BTreeMap;

use serde_json::{json, Map, Value};

use crate::ctx::Ctx;
use crate::gates::config_schema::schema::canonical;
use crate::toml_lite;

/// The release this manifest is about. A constant, so the render depends only on committed inputs and
/// never on the wall clock — a manifest whose bytes moved every run could not be drift-checked.
pub const RELEASE: &str = "1.6.0";

pub const REGISTRY_PATH: &str = "conformance/registry.toml";
pub const MANIFEST_PATH: &str = "conformance/manifest.json";
pub const README_PATH: &str = "README.md";

/// The verdict directory. The pipeline drops one `<id>.json` per suite that ran.
pub const VERDICT_DIR: &str = "conformance/verdicts";

const MANIFEST_SCHEMA: &str = "busbar.conformance.manifest/1";
const GENERATED_BANNER: &str =
    "by `cargo xtask gate conformance-sync --write`; DO NOT EDIT — the drift gate is fatal";

/// The README badge region markers. `render-conformance` (the `--write` arm) replaces only the span
/// between them; the drift gate diffs the whole span. A hand-edit inside, or a badge added outside,
/// both go RED — the second via [`no_orphan_claims`].
pub const BADGE_BEGIN: &str =
    "<!-- BEGIN conformance-badges (generated from conformance/manifest.json — do not edit; regenerate with `cargo xtask gate conformance-sync --write`) -->";
pub const BADGE_END: &str = "<!-- END conformance-badges -->";

// ── TIERS — the CEILING a suite may ever claim, baked into the type, not the copy ─────────────

/// The honesty tiers, from `CONFORMANCE-MATRIX-RULING.md`. The `tier` is a registry constant and is
/// the ceiling; the rendered claim string is a pure function of `(tier, status)` in [`claim_for`], so
/// the page can never phrase a claim above its tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// A third-party body ISSUED a cert. Requires `cert_id`/`issuer`/`expires` in the verdict.
    Certified,
    /// Passes an official/authoritative suite (MCP TCK, A2A a2a-tck).
    Conformant,
    /// Validated against a published spec, no vendor cert program exists (LLM planes).
    SpecConformant,
    /// Implements the mechanism; not externally validated (FIPS = "capable", never "validated").
    Capable,
    /// busbar supplies audit EVIDENCE; never busbar's own cert (SOC2/ISO/PCI/FedRAMP).
    EvidenceOnly,
}

impl Tier {
    pub fn parse(s: &str) -> Result<Tier, String> {
        match s {
            "certified" => Ok(Tier::Certified),
            "conformant" => Ok(Tier::Conformant),
            "spec-conformant" => Ok(Tier::SpecConformant),
            "capable" => Ok(Tier::Capable),
            "evidence-only" => Ok(Tier::EvidenceOnly),
            other => Err(format!(
                "unknown tier `{other}` — the fixed enum is certified | conformant | \
                 spec-conformant | capable | evidence-only"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Certified => "certified",
            Tier::Conformant => "conformant",
            Tier::SpecConformant => "spec-conformant",
            Tier::Capable => "capable",
            Tier::EvidenceOnly => "evidence-only",
        }
    }

    /// The single word a badge/affordance shows for this tier when green.
    pub fn word(self) -> &'static str {
        match self {
            Tier::Certified => "certified",
            Tier::Conformant => "conformant",
            Tier::SpecConformant => "spec-conformant",
            Tier::Capable => "capable",
            Tier::EvidenceOnly => "evidence",
        }
    }
}

/// THE CLAIM STRING — a pure function of `(tier, status)` and the suite's descriptors. The ONLY way
/// `claim` is ever set. A verdict cannot raise its own tier; only the registry sets tier. `None` (a
/// `null` claim) is the rendered answer for anything that is not a green `pass`, so a spec-conformant
/// suite never renders as "certified" and a not-run suite never renders at all.
pub fn claim_for(tier: Tier, status: &str, suite: &Suite, issuer: Option<&str>) -> Option<String> {
    if status != "pass" {
        return None;
    }
    Some(match tier {
        Tier::Certified => match issuer {
            Some(body) => format!("Certified — {body}"),
            None => format!("Certified — {}", suite.standard),
        },
        Tier::Conformant => format!("Conformant — passes {}", suite.plan),
        Tier::SpecConformant => format!("Spec-conformant — {}", suite.standard),
        Tier::Capable => format!("{}-capable", suite.label),
        Tier::EvidenceOnly => format!("Provides evidence for {}", suite.standard),
    })
}

/// The badge alt text — `<label> <word>` — the human-visible claim string [`no_orphan_claims`]
/// forbids anywhere it was not put by the manifest render.
pub fn alt_text(suite: &Suite) -> String {
    format!("{} {}", suite.label, suite.tier.word())
}

// ── THE REGISTRY — the only hand-authored input, and it holds NO status ─────────────────────

/// One registered suite. `tier` is the CEILING; `public` decides whether it renders when green.
#[derive(Debug, Clone)]
pub struct Suite {
    pub id: String,
    pub standard: String,
    pub plan: String,
    pub tier: Tier,
    /// The short badge label (e.g. `MCP`, `LLM Anthropic`).
    pub label: String,
    /// The verdict artifact name the pipeline downloads; recorded for provenance.
    pub verdict: String,
    pub public: bool,
    /// The reason a suite is legitimately not covered yet, surfaced in the manifest when not-run.
    pub not_run_reason: Option<String>,
}

/// Parse and VALIDATE the registry. Every suite must name a standard, plan, label, a tier in the
/// fixed enum and a verdict artifact; no duplicate id. A registry that does not parse un-freezes
/// every claim it should govern, so this is a hard error, never a narrower scan.
pub fn parse_registry(cx: &Ctx) -> Result<Vec<Suite>, String> {
    let text = cx
        .read(REGISTRY_PATH)
        .map_err(|e| format!("{REGISTRY_PATH}: {e}"))?;
    let doc = toml_lite::parse_text(&text);
    let tables = doc.array_table("suite");
    if tables.is_empty() {
        return Err(format!(
            "{REGISTRY_PATH} declares no [[suite]] entries. An empty registry reads exactly like a \
             tree with no claims to keep in sync; it is not one."
        ));
    }
    let mut suites: Vec<Suite> = Vec::new();
    let mut seen: BTreeMap<String, ()> = BTreeMap::new();
    for t in &tables {
        let id = t.get_one("id").unwrap_or_default().to_string();
        if id.is_empty() {
            return Err("a [[suite]] entry has no `id`".to_string());
        }
        if seen.insert(id.clone(), ()).is_some() {
            return Err(format!(
                "duplicate suite id `{id}` — a claim with two homes is a claim nobody can reconcile"
            ));
        }
        let need = |key: &str| -> Result<String, String> {
            let v = t.get_one(key).unwrap_or_default().to_string();
            if v.is_empty() {
                Err(format!("suite `{id}` is missing `{key}`"))
            } else {
                Ok(v)
            }
        };
        let standard = need("standard")?;
        let plan = need("plan")?;
        let label = need("label")?;
        let verdict = need("verdict")?;
        let tier = Tier::parse(&need("tier")?).map_err(|e| format!("suite `{id}`: {e}"))?;
        let public = matches!(t.get_one("public"), Some("true"));
        let not_run_reason = t.get_one("not_run_reason").map(str::to_string);
        suites.push(Suite {
            id,
            standard,
            plan,
            tier,
            label,
            verdict,
            public,
            not_run_reason,
        });
    }
    suites.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(suites)
}

// ── THE VERDICT ARTIFACT ──────────────────────────────────────────────────────────────────

/// One suite's arm-or-red fact, as the pipeline serialises it. Absent fields fail closed: no
/// `armed` is unarmed, no `status` is not-run.
#[derive(Debug, Clone)]
pub struct VerdictDoc {
    pub status: String,
    pub armed: bool,
    pub commit: String,
    pub spec_version: String,
    pub evidence: String,
    pub run_id: String,
    pub generated_at: String,
    pub reason: Option<String>,
    pub issuer: Option<String>,
    pub expires: Option<String>,
}

fn read_verdict(cx: &Ctx, suite: &Suite) -> Result<Option<VerdictDoc>, String> {
    let path = format!("{VERDICT_DIR}/{}.json", suite.id);
    let text = match cx.read(&path) {
        Ok(t) => t,
        Err(_) => return Ok(None),
    };
    let v: Value = serde_json::from_str(&text).map_err(|e| format!("{path}: not JSON: {e}"))?;
    let s = |k: &str| {
        v.get(k)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let opt = |k: &str| {
        v.get(k)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    Ok(Some(VerdictDoc {
        status: {
            let st = s("status");
            if st.is_empty() {
                "not-run".to_string()
            } else {
                st
            }
        },
        armed: v.get("armed").and_then(Value::as_bool).unwrap_or(false),
        commit: s("commit"),
        spec_version: s("spec_version"),
        evidence: s("evidence"),
        run_id: s("run_id"),
        generated_at: s("generated_at"),
        reason: opt("reason"),
        issuer: opt("issuer"),
        expires: opt("expires"),
    }))
}

/// The resolved state of one suite AFTER reconciliation and the staleness downgrade.
pub struct Resolved {
    pub suite: Suite,
    pub verdict: Option<VerdictDoc>,
    /// `pass` | `fail` | `not-run`.
    pub status: String,
    pub reason: Option<String>,
}

/// The whole reconciliation: the MANIFEST ANCHOR (the sha the manifest's entries are recorded
/// against) and every suite's resolved state. The anchor is the one the armed passing verdicts
/// AGREE on — the mode — so a lone verdict from a stale sha cannot drag the manifest's record with
/// it; it is downgraded against the anchor instead.
///
/// THE ANCHOR IS NOT THE RELEASE COMMIT, and the freshness row must never be judged against it.
/// A commit derived from the verdicts is a commit the verdicts agree with by construction: ten
/// verdicts all carried over from the same old sha elect that old sha, and every one of them is
/// then "about the anchor". Only the minority could ever be caught (item 165 — the sibling of the
/// config-schema `HEAD`-as-baseline circularity, `config_schema/mod.rs:26-32`). The release commit
/// is resolved from OUTSIDE the verdicts, by [`release_commit`], and [`stale_against`] is the
/// freshness judgement.
pub struct Assessment {
    /// The manifest anchor — the mode of the armed passing verdicts' commits. NOT the release commit.
    pub commit: String,
    pub generated_at: String,
    pub resolved: Vec<Resolved>,
    /// Suites whose verdict claims a green on a commit that is NOT the manifest anchor — the ones
    /// the manifest render downgrades to `not-run(stale)`. The freshness row does not read this; it
    /// reads [`stale_against`] the release commit.
    pub stale: Vec<String>,
}

pub fn assess(cx: &Ctx, suites: &[Suite]) -> Result<Assessment, String> {
    let mut verdicts: Vec<(Suite, Option<VerdictDoc>)> = Vec::new();
    for s in suites {
        verdicts.push((s.clone(), read_verdict(cx, s)?));
    }

    // The release commit: the mode of the armed passing verdicts' commits. Ties break to the
    // lexicographically smallest, so the anchor is deterministic.
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for (_, v) in &verdicts {
        if let Some(v) = v {
            if v.armed && v.status == "pass" && !v.commit.is_empty() {
                *counts.entry(v.commit.clone()).or_default() += 1;
            }
        }
    }
    let commit = counts
        .iter()
        .max_by_key(|(_, n)| **n)
        .map(|(c, _)| c.clone())
        .unwrap_or_default();

    let generated_at = verdicts
        .iter()
        .filter_map(|(_, v)| v.as_ref().map(|v| v.generated_at.clone()))
        .filter(|s| !s.is_empty())
        .max()
        .unwrap_or_default();

    let mut resolved = Vec::new();
    let mut stale = Vec::new();
    for (suite, verdict) in verdicts {
        let (status, reason) = match &verdict {
            None => (
                "not-run".to_string(),
                Some(
                    suite
                        .not_run_reason
                        .clone()
                        .unwrap_or_else(|| "no verdict artifact for this commit".to_string()),
                ),
            ),
            Some(v) if !v.armed => (
                "not-run".to_string(),
                Some(v.reason.clone().unwrap_or_else(|| {
                    "subject unarmed — a probe that could not run is not a pass".to_string()
                })),
            ),
            Some(v) if v.status != "pass" => (
                v.status.clone(),
                v.reason
                    .clone()
                    .or(Some(format!("verdict status `{}`", v.status))),
            ),
            Some(v) if v.commit != commit => {
                stale.push(suite.id.clone());
                (
                    "not-run".to_string(),
                    Some(format!(
                        "stale: verdict commit {} is not the release commit {}",
                        short(&v.commit),
                        short(&commit)
                    )),
                )
            }
            Some(_) => ("pass".to_string(), None),
        };
        resolved.push(Resolved {
            suite,
            verdict,
            status,
            reason,
        });
    }

    Ok(Assessment {
        commit,
        generated_at,
        resolved,
        stale,
    })
}

/// The overlay key a self-test plants the release commit under. The real run asks git.
pub const RELEASE_COMMIT_KEY: &str = "conformance-release-commit";

/// THE RELEASE COMMIT — the sha of the checkout under judgement (`git rev-parse HEAD`), resolved
/// from OUTSIDE the verdicts it judges. The release pipeline drops the verdicts it downloaded into
/// a checkout OF the release sha before running this gate, so there `HEAD` is the release commit;
/// on any other commit every carried-over pass is stale, which is the rule: every commit
/// invalidates every conformance pass. An unresolvable commit is an error, never a pass —
/// an empty anchor would make "stale" unanswerable.
pub fn release_commit(cx: &Ctx) -> Result<String, String> {
    let sha = match cx.overlay_command(RELEASE_COMMIT_KEY) {
        Some(planted) => planted,
        None => cx
            .git(&["rev-parse", "HEAD"])
            .map_err(|e| format!("`git rev-parse HEAD` failed: {e}"))?,
    };
    let sha = sha.trim().to_string();
    if sha.is_empty() {
        return Err(
            "the release commit resolved to an empty sha — no pass can be judged fresh \
                    against nothing"
                .to_string(),
        );
    }
    Ok(sha)
}

/// Every suite whose verdict is an ARMED PASS on a commit that is not `release` — the stale passes
/// the freshness row refuses. Judged over every armed pass the tree holds, whatever the manifest
/// anchor made of it: a pass is honoured only if its commit IS the release commit.
pub fn stale_against(a: &Assessment, release: &str) -> Vec<String> {
    a.resolved
        .iter()
        .filter_map(|r| {
            let v = r.verdict.as_ref()?;
            (v.armed && v.status == "pass" && v.commit != release).then(|| {
                format!(
                    "{} (verdict commit {})",
                    r.suite.id,
                    if v.commit.is_empty() {
                        "<none>".to_string()
                    } else {
                        short(&v.commit)
                    }
                )
            })
        })
        .collect()
}

fn short(sha: &str) -> String {
    sha.chars().take(9).collect()
}

// ── THE MANIFEST RENDER ─────────────────────────────────────────────────────────────────

/// Assemble the manifest from the registry and the verdicts present. Byte-for-byte reproducible from
/// committed inputs. A `certified` suite that is green but carries no `issuer`/`expires`/`cert_id` in
/// its verdict is a HARD ERROR: you cannot claim "certified" without the issued artifact.
pub fn render_manifest(cx: &Ctx, suites: &[Suite]) -> Result<String, String> {
    let a = assess(cx, suites)?;
    let mut entries: Vec<Value> = Vec::new();
    for r in &a.resolved {
        let s = &r.suite;
        let mut e = Map::new();
        e.insert("suite".into(), json!(s.id));
        e.insert("standard".into(), json!(s.standard));
        e.insert("plan".into(), json!(s.plan));
        e.insert("tier".into(), json!(s.tier.as_str()));
        e.insert("public".into(), json!(s.public));
        e.insert("status".into(), json!(r.status));
        if r.status == "pass" {
            let v = r
                .verdict
                .as_ref()
                .expect("a resolved pass carries the verdict it resolved from");
            if s.tier == Tier::Certified && (v.issuer.is_none() || v.expires.is_none()) {
                return Err(format!(
                    "suite `{}` is tier=certified and green, but its verdict carries no \
                     issuer/expires — a certified claim without the issued artifact is refused",
                    s.id
                ));
            }
            let claim = claim_for(s.tier, "pass", s, v.issuer.as_deref());
            e.insert("claim".into(), json!(claim));
            e.insert("spec_version".into(), json!(v.spec_version));
            e.insert("evidence".into(), json!(v.evidence));
            e.insert("commit".into(), json!(v.commit));
            e.insert("verified_at".into(), json!(v.generated_at));
            if let Some(exp) = &v.expires {
                e.insert("expires".into(), json!(exp));
            }
        } else {
            // claim:null ⇒ NOTHING renders. The whole fail-closed property rests on this.
            e.insert("claim".into(), Value::Null);
            if let Some(reason) = &r.reason {
                e.insert("reason".into(), json!(reason));
            }
        }
        entries.push(Value::Object(e));
    }

    let mut doc = Map::new();
    doc.insert("schema".into(), json!(MANIFEST_SCHEMA));
    doc.insert("_generated".into(), json!(GENERATED_BANNER));
    doc.insert("release".into(), json!(RELEASE));
    doc.insert("commit".into(), json!(a.commit));
    doc.insert("generated_at".into(), json!(a.generated_at));
    doc.insert("suites".into(), Value::Array(entries));
    Ok(canonical(&Value::Object(doc)))
}

// ── THE README RENDER ─────────────────────────────────────────────────────────────────────────

/// The badge block, rendered from a parsed MANIFEST. A badge appears ONLY for a public suite whose
/// `status == "pass"` and whose `claim` is non-null. Color and label are a pure function of
/// `(tier, status)`, so a badge can never say "certified" for a conformant suite.
pub fn render_readme_block(manifest: &Value) -> String {
    let mut lines = vec![BADGE_BEGIN.to_string()];
    if let Some(suites) = manifest.get("suites").and_then(Value::as_array) {
        for s in suites {
            let public = s.get("public").and_then(Value::as_bool).unwrap_or(false);
            let status = s.get("status").and_then(Value::as_str).unwrap_or("");
            let claim = s.get("claim").and_then(Value::as_str);
            if !public || status != "pass" || claim.is_none() {
                continue;
            }
            let label = s.get("label").and_then(Value::as_str).unwrap_or("");
            let label = if label.is_empty() {
                s.get("suite").and_then(Value::as_str).unwrap_or("")
            } else {
                label
            };
            let tier = s
                .get("tier")
                .and_then(Value::as_str)
                .and_then(|t| Tier::parse(t).ok())
                .unwrap_or(Tier::Conformant);
            let evidence = s.get("evidence").and_then(Value::as_str).unwrap_or("");
            lines.push(badge_line(label, tier, evidence));
        }
    }
    lines.push(BADGE_END.to_string());
    lines.join("\n")
}

/// The manifest carries no `label` (the label is a registry field). The README render needs it, so
/// this stitches the registry labels onto a parsed manifest before rendering.
pub fn manifest_with_labels(manifest_text: &str, suites: &[Suite]) -> Result<Value, String> {
    let mut v: Value = serde_json::from_str(manifest_text)
        .map_err(|e| format!("{MANIFEST_PATH}: not JSON: {e}"))?;
    let labels: BTreeMap<&str, &str> = suites
        .iter()
        .map(|s| (s.id.as_str(), s.label.as_str()))
        .collect();
    if let Some(arr) = v.get_mut("suites").and_then(Value::as_array_mut) {
        for s in arr {
            if let Some(id) = s.get("suite").and_then(Value::as_str) {
                if let Some(label) = labels.get(id) {
                    if let Some(obj) = s.as_object_mut() {
                        obj.insert("label".into(), json!(label));
                    }
                }
            }
        }
    }
    Ok(v)
}

fn badge_line(label: &str, tier: Tier, evidence: &str) -> String {
    let color = match tier {
        Tier::EvidenceOnly => "9f9f9f",
        _ => "2ea44f",
    };
    let href = if evidence.is_empty() {
        "https://github.com/GetBusbar/busbar/tree/main/conformance".to_string()
    } else {
        evidence.to_string()
    };
    format!(
        "<a href=\"{href}\"><img src=\"https://img.shields.io/badge/{}-{}-{color}\" alt=\"{} {}\"></a>",
        shields_encode(label),
        shields_encode(tier.word()),
        label,
        tier.word()
    )
}

/// shields.io path encoding: a literal dash is `--`, a literal underscore `__`, a space `_`.
fn shields_encode(s: &str) -> String {
    s.replace('-', "--").replace('_', "__").replace(' ', "_")
}

// ── THE README MARKED SPAN ───────────────────────────────────────────────────────────────────────

/// The exact substring of `readme` from the BEGIN marker line through the END marker line, or `None`
/// when the markers are absent or out of order.
pub fn marked_span(readme: &str) -> Option<(usize, usize)> {
    let begin = readme.find(BADGE_BEGIN)?;
    let end_marker = readme.find(BADGE_END)?;
    if end_marker < begin {
        return None;
    }
    let end = end_marker + BADGE_END.len();
    Some((begin, end))
}

/// The README with its marked span REPLACED by a fresh render. `None` when the markers are absent —
/// the drift gate refuses to invent a region rather than guessing where the badges belong.
pub fn rewrite_readme(readme: &str, block: &str) -> Option<String> {
    let (begin, end) = marked_span(readme)?;
    let mut out = String::with_capacity(readme.len());
    out.push_str(&readme[..begin]);
    out.push_str(block);
    out.push_str(&readme[end..]);
    Some(out)
}

// ── THE NO-ORPHAN-CLAIM BACKSTOP (`conformance:no-orphan-claim`) ──────────────────────────────

/// THE CLAIM VOCABULARY — the words a human-visible conformance/certification claim is made of.
/// Outside the generated badge block NONE of them may appear: the block is the only place a claim
/// is allowed to exist, because it is the only place the manifest render put one.
///
/// WHY A VOCABULARY AND NOT ONLY THE REGISTRY (item 188). Searching only for each REGISTERED suite's
/// badge string makes a claim for a standard that is in NO registry — "SOC 2 certified", "HIPAA
/// compliant", "FIPS 140-3 validated", the purest unbacked claim there is — structurally invisible:
/// the token set it is checked against is derived from the very registry that lacks it. Matched as
/// whole words, case-insensitively, so `certificate` (TLS vocabulary) is not a claim.
pub const CLAIM_WORDS: &[&str] = &[
    "certified",
    "certification",
    "certifications",
    "conformant",
    "compliant",
    "compliance",
    "validated",
    "accredited",
    "accreditation",
    "attested",
];

/// One claim found outside the generated badge block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Orphan {
    /// A registered suite's badge alt string, hand-placed where the render did not put it.
    Registered { id: String, token: String },
    /// A claim word on a line that names no registered suite at all — a claim no registry entry,
    /// and so no manifest entry, could ever back.
    Unbacked {
        line: usize,
        word: String,
        text: String,
    },
}

/// The README with the marked span excised — everything the render did NOT write.
fn outside_block(readme: &str) -> String {
    match marked_span(readme) {
        Some((begin, end)) => {
            let mut s = String::with_capacity(readme.len());
            s.push_str(&readme[..begin]);
            s.push_str(&readme[end..]);
            s
        }
        None => readme.to_string(),
    }
}

/// Every claim in the README OUTSIDE the marked span. The belt to the render's braces: a
/// hand-pasted "MCP conformant" is caught even though the marker-render never put it there, a claim
/// for a suite that is not green is caught wherever it sits, and a claim for a standard no registry
/// names is caught by its vocabulary ([`CLAIM_WORDS`]). A line already reported for a registered
/// token is not reported a second time for its claim word.
pub fn no_orphan_claims(readme: &str, suites: &[Suite]) -> Vec<Orphan> {
    let outside = outside_block(readme);
    let tokens: Vec<(String, String)> =
        suites.iter().map(|s| (s.id.clone(), alt_text(s))).collect();
    let mut out = Vec::new();
    for (id, token) in &tokens {
        if outside.contains(token.as_str()) {
            out.push(Orphan::Registered {
                id: id.clone(),
                token: token.clone(),
            });
        }
    }
    for (i, line) in outside.lines().enumerate() {
        if tokens.iter().any(|(_, t)| line.contains(t.as_str())) {
            continue;
        }
        let lower = line.to_lowercase();
        let hit = lower
            .split(|c: char| !c.is_alphanumeric())
            .find(|w| CLAIM_WORDS.contains(w));
        if let Some(word) = hit {
            out.push(Orphan::Unbacked {
                line: i + 1,
                word: word.to_string(),
                text: line.trim().chars().take(120).collect(),
            });
        }
    }
    out
}
