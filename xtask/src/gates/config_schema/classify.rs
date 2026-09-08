//! ADDITIVE (green) vs BREAKING (red), node by node — and the narrow, committed escape hatch.
//!
//! 1.5.3 was the LAST config-breaking release. After it the grammar is FROZEN and every future
//! feature may add only NEW OPTIONAL keys, sections and enum variants. This module is the half that
//! ENFORCES that, and the half the openapi drift guard does not have: a snapshot that merely differs
//! is a diff, a snapshot that differs BREAKINGLY is a boot failure in somebody's deployment.
//!
//! Three verdicts, not two. A RELOCATION — the same type in a new module path — is neither. Read as
//! a string, `agents: crate::a2a::config::AgentsCfg` becoming
//! `agents: busbar_a2a::config::AgentsCfg` is a retype, and a gate that reds on a change that alters
//! no operator-visible grammar teaches reviewers to wave it through, which is how a stability gate
//! dies. It is printed on its own line, loudly, every run; it does not red the gate; and NOTHING
//! else is relaxed — the type's own fields are fingerprinted in their own right, by bare name.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

pub const FROZEN_MSG: &str = "the config grammar is FROZEN after 1.5.3 — additive-only (new \
    OPTIONAL key / section / enum variant). 1.5.3 was the LAST config-breaking release. \
    Regenerating the snapshot does NOT launder a break: the additive check reads the committed \
    baseline, not your working tree.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Additive,
    Relocated,
    Breaking,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub severity: Severity,
    pub path: String,
    pub reason: String,
}

fn add(out: &mut Vec<Finding>, severity: Severity, path: String, reason: impl Into<String>) {
    out.push(Finding {
        severity,
        path,
        reason: reason.into(),
    });
}

// ── relocation ───────────────────────────────────────────────────────────────────────────────────

/// Reduce every IN-TREE module path in a type expression to its final segment.
///
/// `crate::…`, `super::…`, `self::…` and a `busbar…` crate root are the paths that MOVE when a type
/// moves; `std::`, `indexmap::` and `serde_json::` are foreign and their qualification is part of
/// their identity, so they are left exactly as written. This is a COMPARISON aid only — the
/// snapshot keeps the path exactly as the source writes it.
pub fn strip_in_tree_paths(t: &str) -> String {
    let c: Vec<char> = t.chars().collect();
    let n = c.len();
    let word = |i: usize| c.get(i).copied().is_some_and(super::scan::is_word);
    let mut out = String::new();
    let mut i = 0usize;
    while i < n {
        let boundary = i == 0 || !word(i - 1);
        let head = boundary.then(|| head_len(&c, i)).flatten();
        let Some(hlen) = head else {
            out.push(c[i]);
            i += 1;
            continue;
        };
        // `(?:::[A-Za-z_][A-Za-z0-9_]*)+` — at least one segment, then `\b`.
        let mut j = i + hlen;
        let mut last: Option<(usize, usize)> = None;
        while j + 2 < n && c[j] == ':' && c[j + 1] == ':' {
            let s = j + 2;
            if !c
                .get(s)
                .copied()
                .is_some_and(|x| x.is_ascii_alphabetic() || x == '_')
            {
                break;
            }
            let mut e = s;
            while e < n && super::scan::is_word(c[e]) {
                e += 1;
            }
            last = Some((s, e));
            j = e;
        }
        match last {
            Some((s, e)) => {
                out.extend(&c[s..e]);
                i = j;
            }
            None => {
                out.extend(&c[i..i + hlen]);
                i += hlen;
            }
        }
    }
    out
}

/// `(?:crate|super|self|busbar[a-z0-9_]*)` at `i`, and its length.
fn head_len(c: &[char], i: usize) -> Option<usize> {
    for word in ["crate", "super", "self"] {
        if super::scan::starts_with(c, i, word)
            && !c
                .get(i + word.len())
                .copied()
                .is_some_and(super::scan::is_word)
        {
            return Some(word.len());
        }
    }
    if super::scan::starts_with(c, i, "busbar") {
        let mut e = i + 6;
        while e < c.len() && (c[e].is_ascii_lowercase() || c[e].is_ascii_digit() || c[e] == '_') {
            e += 1;
        }
        return Some(e - i);
    }
    None
}

/// True when two type expressions name the same type and differ ONLY in module path.
pub fn relocated_only(before: &str, after: &str) -> bool {
    before != after && strip_in_tree_paths(before) == strip_in_tree_paths(after)
}

// ── the per-node classifiers ─────────────────────────────────────────────────────────────────────

fn str_of(v: &Value, key: &str) -> String {
    v.get(key).and_then(Value::as_str).unwrap_or("").to_string()
}

fn py_repr(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    format!("{quote}{s}{quote}")
}

fn field_findings(tname: &str, bf: &Value, ff: &Value, out: &mut Vec<Finding>) {
    let empty = serde_json::Map::new();
    let b = bf.as_object().unwrap_or(&empty);
    let f = ff.as_object().unwrap_or(&empty);
    let names: BTreeSet<&String> = b.keys().chain(f.keys()).collect();
    for fld in names {
        let path = format!("{tname}.{fld}");
        let bv = b.get(fld);
        let fv = f.get(fld);
        match (bv, fv) {
            (None, Some(fv)) => {
                if fv.get("optional").and_then(Value::as_bool).unwrap_or(false) {
                    add(out, Severity::Additive, path, "new OPTIONAL field added");
                } else {
                    add(
                        out,
                        Severity::Breaking,
                        path,
                        "new REQUIRED field added (breaks a config that omits it)",
                    );
                }
            }
            (Some(_), None) => add(
                out,
                Severity::Breaking,
                path,
                "field REMOVED (breaks a config that sets it)",
            ),
            (Some(bv), Some(fv)) => {
                let bt = str_of(bv, "type");
                let ft = str_of(fv, "type");
                if bt != ft {
                    if relocated_only(&bt, &ft) {
                        add(
                            out,
                            Severity::Relocated,
                            path.clone(),
                            format!(
                                "field type MOVED {} -> {} (same type, new module path; the \
                                 grammar it declares is unchanged and is fingerprinted in its own \
                                 right)",
                                py_repr(&bt),
                                py_repr(&ft)
                            ),
                        );
                    } else {
                        add(
                            out,
                            Severity::Breaking,
                            path.clone(),
                            format!(
                                "field RETYPED {} -> {} (shape change)",
                                py_repr(&bt),
                                py_repr(&ft)
                            ),
                        );
                    }
                }
                let bo = bv.get("optional").and_then(Value::as_bool).unwrap_or(false);
                let fo = fv.get("optional").and_then(Value::as_bool).unwrap_or(false);
                if bo && !fo {
                    add(
                        out,
                        Severity::Breaking,
                        path,
                        "field made REQUIRED (was optional; breaks a config that omits it)",
                    );
                } else if !bo && fo {
                    add(
                        out,
                        Severity::Additive,
                        path,
                        "field relaxed required -> optional (widens accepted set)",
                    );
                }
            }
            (None, None) => {}
        }
    }
}

fn set_of(v: Option<&Value>) -> BTreeSet<String> {
    v.and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn variant_findings(
    tname: &str,
    bvar: Option<&Value>,
    fvar: Option<&Value>,
    what: &str,
    out: &mut Vec<Finding>,
) {
    let b = set_of(bvar);
    let f = set_of(fvar);
    for v in f.difference(&b) {
        add(
            out,
            Severity::Additive,
            format!("{tname}::{v}"),
            format!("{what} APPENDED"),
        );
    }
    for v in b.difference(&f) {
        add(
            out,
            Severity::Breaking,
            format!("{tname}::{v}"),
            format!("{what} REMOVED/RENAMED (breaks a config using the old value)"),
        );
    }
}

/// THE STRICTER ARM: the set of refused input forms is frozen in BOTH directions.
///
/// A BASELINE THAT PREDATES THIS ARM IS NOT A BASELINE WITH NO REFUSALS. `refused` is absent from
/// every snapshot rendered before it existed, and absent there means "never recorded", not "the
/// empty set" — treating the two the same would report all six of `SecretRef`'s refusals as newly
/// ADDED and red the gate on the commit that introduced the check. An empty LIST is different and
/// does compare, because a type that genuinely refuses nothing has been measured and said so.
fn refusal_findings(
    tname: &str,
    bref: Option<&Value>,
    fref: Option<&Value>,
    out: &mut Vec<Finding>,
) {
    let (Some(bref), Some(fref)) = (bref, fref) else {
        return;
    };
    if bref.is_null() || fref.is_null() {
        return;
    }
    let b = set_of(Some(bref));
    let f = set_of(Some(fref));
    for v in b.difference(&f) {
        add(
            out,
            Severity::Breaking,
            format!("{tname}::visit_{v}"),
            "a REFUSED input form is no longer refused (the hand-written impl now accepts it). \
             This widens the grammar, which additive-only would wave through -- and for a secret \
             reference the widened form is an inline literal, the exact shape the type exists to \
             reject and the one that ends up in a boot log",
        );
    }
    for v in f.difference(&b) {
        add(
            out,
            Severity::Breaking,
            format!("{tname}::visit_{v}"),
            "an input form that PARSED is now refused (breaks a config using it). Deliberate \
             tightening is legitimate and goes in the waiver register, where it is a reviewed line \
             rather than a silent narrowing",
        );
    }
}

/// The container knobs that decide WHICH DOCUMENTS PARSE. Both were once extracted and thrown away,
/// so both could be flipped with zero delta. A key ABSENT from the baseline means that snapshot
/// predates flag recording; it is not evidence of the flag being off, so it yields no finding.
fn container_flag_findings(tname: &str, b: &Value, f: &Value, out: &mut Vec<Finding>) {
    for flag in ["deny_unknown_fields", "transparent"] {
        let bv = b.get(flag).and_then(Value::as_bool);
        let fv = f.get(flag).and_then(Value::as_bool);
        let (Some(bv), Some(fv)) = (bv, fv) else {
            continue;
        };
        if bv == fv {
            continue;
        }
        if flag == "deny_unknown_fields" && !bv {
            add(
                out,
                Severity::Breaking,
                format!("{tname}[deny_unknown_fields]"),
                "deny_unknown_fields turned ON (a config carrying any extra key under this section \
                 parsed before and is a hard error now)",
            );
        } else if flag == "deny_unknown_fields" {
            add(
                out,
                Severity::Additive,
                format!("{tname}[deny_unknown_fields]"),
                "deny_unknown_fields turned OFF (widens the accepted set)",
            );
        } else {
            add(
                out,
                Severity::Breaking,
                format!("{tname}[transparent]"),
                format!(
                    "serde(transparent) {bv} -> {fv} (the wire form changes between a map and the \
                     bare inner value; configs written for either spelling break)"
                ),
            );
        }
    }
}

/// Walk baseline-vs-fresh fingerprint trees and classify every delta.
pub fn classify(baseline: &Value, fresh: &Value) -> Vec<Finding> {
    let empty = serde_json::Map::new();
    let bt = baseline
        .get("types")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let ft = fresh
        .get("types")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let names: BTreeSet<&String> = bt.keys().chain(ft.keys()).collect();

    let mut out = Vec::new();
    for tname in names {
        let b = bt.get(tname);
        let f = ft.get(tname);
        let (Some(b), Some(f)) = (b, f) else {
            match (b, f) {
                (None, _) => add(
                    &mut out,
                    Severity::Additive,
                    tname.clone(),
                    "new type/section added",
                ),
                _ => add(
                    &mut out,
                    Severity::Breaking,
                    tname.clone(),
                    "type/section REMOVED (a config referencing it now fails)",
                ),
            }
            continue;
        };
        let bk = str_of(b, "kind");
        let fk = str_of(f, "kind");
        if bk != fk {
            add(
                &mut out,
                Severity::Breaking,
                tname.clone(),
                format!("kind changed {bk} -> {fk} (shape change)"),
            );
            continue;
        }
        if bk == "alias" {
            let bta = str_of(b, "target");
            let fta = str_of(f, "target");
            if bta != fta {
                if relocated_only(&bta, &fta) {
                    add(
                        &mut out,
                        Severity::Relocated,
                        tname.clone(),
                        format!(
                            "alias target MOVED {} -> {} (same type, new module path; the map \
                             shape is unchanged)",
                            py_repr(&bta),
                            py_repr(&fta)
                        ),
                    );
                } else {
                    add(
                        &mut out,
                        Severity::Breaking,
                        tname.clone(),
                        format!(
                            "type alias RETARGETED {} -> {} (the definition-map shape changed)",
                            py_repr(&bta),
                            py_repr(&fta)
                        ),
                    );
                }
            }
            continue;
        }
        container_flag_findings(tname, b, f, &mut out);
        let null = Value::Null;
        if bk == "manual" {
            field_findings(
                tname,
                b.get("fields").unwrap_or(&null),
                f.get("fields").unwrap_or(&null),
                &mut out,
            );
            variant_findings(
                tname,
                b.get("wire_keys"),
                f.get("wire_keys"),
                "accepted wire key",
                &mut out,
            );
            refusal_findings(tname, b.get("refused"), f.get("refused"), &mut out);
        } else if bk == "struct" {
            field_findings(
                tname,
                b.get("fields").unwrap_or(&null),
                f.get("fields").unwrap_or(&null),
                &mut out,
            );
        } else if bk == "enum" {
            variant_findings(
                tname,
                b.get("variants"),
                f.get("variants"),
                "enum variant",
                &mut out,
            );
        } else {
            // AN UNRECOGNISED KIND IS NOT AN ENUM, AND THE HOLE WAS THAT IT WAS TREATED AS ONE.
            //
            // The Python's last arm is a bare `else: # enum`, so ANY node whose `kind` is not
            // `alias`/`manual`/`struct` — a missing key, a typo, a `"kind": "object"` written by a
            // hand-edit or by a future generator — was handed to the variant comparison. That
            // reads `variants` on both sides, finds the key absent on both, computes the empty set
            // against the empty set, and reports NOTHING. The node's fields were never compared,
            // so every field under it could be removed, retyped or made required at zero delta.
            //
            // It is a break rather than a refusal because it is a break: the two sides are the same
            // unrecognised shape, so the gate cannot say the grammar is unchanged, and "cannot say"
            // must never render as "additive".
            add(
                &mut out,
                Severity::Breaking,
                tname.clone(),
                format!(
                    "unrecognised node kind {} — this node was NOT compared. The classifier knows \
                     `struct`, `enum`, `alias` and `manual`; anything else falls through every \
                     rule, so its fields and variants would be free to change at zero delta. \
                     Regenerate the snapshot with the current generator, or teach the classifier \
                     this kind.",
                    py_repr(&bk)
                ),
            );
        }
    }
    out
}

// ── the waiver register ──────────────────────────────────────────────────────────────────────────

/// Parse the committed break-waiver file.
///
/// The hatch is a COMMITTED FILE, never an env var: an env var can be flipped in a workflow edit
/// and reviewed by nobody, whereas every waiver shows up as an added line in the PR diff, next to
/// the break it excuses. Each waiver must name an EXACT path plus a reason — no globs, no wildcards
/// — and every applied waiver is printed LOUDLY with its reason.
pub fn load_waivers(path: &str, text: &str) -> Result<BTreeMap<String, String>, String> {
    let mut out = BTreeMap::new();
    for (i, raw) in text.lines().enumerate() {
        let lineno = i + 1;
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let Some((key, reason)) = line.split_once('=') else {
            return Err(format!(
                "{path}:{lineno}: malformed waiver {} — expected `path = reason`",
                py_repr(raw.trim())
            ));
        };
        let (key, reason) = (key.trim(), reason.trim());
        if key.is_empty() || reason.is_empty() {
            return Err(format!(
                "{path}:{lineno}: a waiver must name BOTH an exact path AND a reason"
            ));
        }
        if key.contains('*') || key.contains('?') {
            return Err(format!(
                "{path}:{lineno}: waiver path {} contains a wildcard — waivers must be EXACT paths \
                 so each excused break is individually reviewable",
                py_repr(key)
            ));
        }
        out.insert(key.to_string(), reason.to_string());
    }
    Ok(out)
}

/// What the classifier's findings amount to once the waiver register is applied.
pub struct Outcome {
    pub additive: Vec<Finding>,
    pub relocated: Vec<Finding>,
    /// Each excused break, with the reason that excused it.
    pub waived: Vec<(Finding, String)>,
    pub breaking: Vec<Finding>,
    /// A waiver matching nothing. Dead standing permission to break that path later.
    pub stale: Vec<String>,
}

impl Outcome {
    /// The Python's exit codes, kept: 0 green, 3 a break, 4 a stale waiver.
    pub fn code(&self) -> i32 {
        if !self.stale.is_empty() {
            4
        } else if !self.breaking.is_empty() {
            3
        } else {
            0
        }
    }
}

pub fn judge(findings: Vec<Finding>, waivers: &BTreeMap<String, String>) -> Outcome {
    let mut additive = Vec::new();
    let mut relocated = Vec::new();
    let mut waived = Vec::new();
    let mut breaking = Vec::new();
    for f in findings {
        match f.severity {
            Severity::Additive => additive.push(f),
            Severity::Relocated => relocated.push(f),
            // A waiver matches ONE exact path. Everything else stays RED.
            Severity::Breaking => match waivers.get(&f.path) {
                Some(why) => {
                    let why = why.clone();
                    waived.push((f, why));
                }
                None => breaking.push(f),
            },
        }
    }
    // An unused waiver is dead weight that would silently pre-authorize a FUTURE break.
    let used: BTreeSet<&str> = waived.iter().map(|(f, _)| f.path.as_str()).collect();
    let stale: Vec<String> = waivers
        .keys()
        .filter(|k| !used.contains(k.as_str()))
        .cloned()
        .collect();
    Outcome {
        additive,
        relocated,
        waived,
        breaking,
        stale,
    }
}
