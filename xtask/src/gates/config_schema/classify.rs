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
    /// A REMOVED TYPE AND AN ADDED TYPE THAT ARE ONE TYPE UNDER A NEW NAME. See [`rename_map`].
    Renamed,
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

fn field_findings(
    tname: &str,
    bf: &Value,
    ff: &Value,
    renames: &BTreeMap<String, String>,
    out: &mut Vec<Finding>,
) {
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
                    if rename_equivalent(&bt, &ft, renames) {
                        // A FIELD RETYPED TO A RENAME-EQUIVALENT TYPE IS NOT A RETYPE. The type it
                        // names was proven — by [`rename_map`], against the same rules that judge
                        // every other node — to be the OLD TYPE UNDER A NEW NAME, and the grammar
                        // this field declares is whatever that type's own node says it is. Reading
                        // the spelling instead would make every private Rust rename a config break.
                        add(
                            out,
                            Severity::Renamed,
                            path.clone(),
                            format!(
                                "field type RENAMED {} -> {} (the same type under a new name; its \
                                 wire shape is compared in its own right)",
                                py_repr(&bt),
                                py_repr(&ft)
                            ),
                        );
                    } else if relocated_only(&bt, &ft) {
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

// ── rename-equivalence ───────────────────────────────────────────────────────────────────────────

/// A REMOVED TYPE AND AN ADDED TYPE OF THE SAME WIRE SHAPE ARE ONE TYPE RENAMED.
///
/// A Rust type name is not config grammar. `OnExhaust` becoming `OnExhaustWord` renames nothing an
/// operator can write: the accepted words, the accepted keys, the refusals and the optionality are
/// where the grammar lives, and a rename leaves every one of them where it was. Read by NAME, that
/// rename is a type REMOVED plus a type ADDED, and "removed" is a break — so a gate that reads
/// names teaches reviewers that its breaks are usually spelling, which is how a stability gate dies.
///
/// THE PAIRING IS JUDGED BY THE SAME RULES AS EVERYTHING ELSE, and that is the whole of the design.
/// Two nodes pair when comparing them head-on produces NO BREAKING FINDING — the old node as the
/// baseline, the new node as the fresh render, through [`node_findings`] itself. So a rename that
/// also drops a variant, removes a key, retypes a field or makes one required does NOT pair: the
/// removal stays BREAKING and is reported as one, because that is what it is. A rename that also
/// APPENDS a variant does pair, and the appended variant is reported additively under the new name,
/// which is exactly what the same change without the rename would have said.
///
/// THE MATCH MUST BE UNAMBIGUOUS. Two removed types of identical shape and one added type of that
/// shape is not evidence of which one was renamed — it is evidence that the gate cannot tell — so a
/// name that has more than one candidate on either side pairs with nothing and stays a removal. A
/// guess here would launder a real removal behind an unrelated addition.
pub fn rename_map(
    bt: &serde_json::Map<String, Value>,
    ft: &serde_json::Map<String, Value>,
) -> BTreeMap<String, String> {
    let removed: Vec<&String> = bt.keys().filter(|k| !ft.contains_key(*k)).collect();
    let added: Vec<&String> = ft.keys().filter(|k| !bt.contains_key(*k)).collect();
    let none = BTreeMap::new();
    let mut cands: Vec<(&String, &String)> = Vec::new();
    for old in &removed {
        for new in &added {
            let mut probe = Vec::new();
            // The pairing probe runs with NO rename map: a rename proven by a rename it is itself
            // proving is a circle, and the fixed point that circle settles on is not one anybody
            // reviewed.
            node_findings(new, &bt[*old], &ft[*new], &none, &mut probe);
            if !probe.iter().any(|f| f.severity == Severity::Breaking) {
                cands.push((old, new));
            }
        }
    }
    let mut out = BTreeMap::new();
    for (old, new) in &cands {
        let one_old = cands.iter().filter(|(o, _)| o == old).count() == 1;
        let one_new = cands.iter().filter(|(_, n)| n == new).count() == 1;
        if one_old && one_new {
            out.insert((*old).clone(), (*new).clone());
        }
    }
    out
}

/// True when `after` is `before` with every renamed type substituted — including inside a generic,
/// which is where these names mostly appear (`Option<OnExhaust>`).
///
/// Substitution is by WHOLE WORD on the path-stripped spelling, so `OnExhaust` never rewrites the
/// `OnExhaustWord` it is a prefix of, and a relocation on top of a rename still reads as the rename.
pub fn rename_equivalent(before: &str, after: &str, renames: &BTreeMap<String, String>) -> bool {
    if renames.is_empty() {
        return false;
    }
    let subbed = substitute(&strip_in_tree_paths(before), renames);
    subbed != strip_in_tree_paths(before) && subbed == strip_in_tree_paths(after)
}

fn substitute(t: &str, renames: &BTreeMap<String, String>) -> String {
    let c: Vec<char> = t.chars().collect();
    let mut out = String::new();
    let mut i = 0usize;
    while i < c.len() {
        if i == 0 || !super::scan::is_word(c[i - 1]) {
            let mut e = i;
            while e < c.len() && super::scan::is_word(c[e]) {
                e += 1;
            }
            if e > i {
                let word: String = c[i..e].iter().collect();
                out.push_str(renames.get(&word).unwrap_or(&word));
                i = e;
                continue;
            }
        }
        out.push(c[i]);
        i += 1;
    }
    out
}

/// One node against its counterpart: the kind, the container flags, and whichever of fields,
/// variants, wire keys and refusals that kind carries.
fn node_findings(
    tname: &str,
    b: &Value,
    f: &Value,
    renames: &BTreeMap<String, String>,
    out: &mut Vec<Finding>,
) {
    let bk = str_of(b, "kind");
    let fk = str_of(f, "kind");
    if bk != fk {
        add(
            out,
            Severity::Breaking,
            tname.to_string(),
            format!("kind changed {bk} -> {fk} (shape change)"),
        );
        return;
    }
    if bk == "alias" {
        let bta = str_of(b, "target");
        let fta = str_of(f, "target");
        if bta != fta {
            if rename_equivalent(&bta, &fta, renames) {
                add(
                    out,
                    Severity::Renamed,
                    tname.to_string(),
                    format!(
                        "alias target RENAMED {} -> {} (the same type under a new name; the map \
                         shape is unchanged)",
                        py_repr(&bta),
                        py_repr(&fta)
                    ),
                );
            } else if relocated_only(&bta, &fta) {
                add(
                    out,
                    Severity::Relocated,
                    tname.to_string(),
                    format!(
                        "alias target MOVED {} -> {} (same type, new module path; the map \
                         shape is unchanged)",
                        py_repr(&bta),
                        py_repr(&fta)
                    ),
                );
            } else {
                add(
                    out,
                    Severity::Breaking,
                    tname.to_string(),
                    format!(
                        "type alias RETARGETED {} -> {} (the definition-map shape changed)",
                        py_repr(&bta),
                        py_repr(&fta)
                    ),
                );
            }
        }
        return;
    }
    container_flag_findings(tname, b, f, out);
    let null = Value::Null;
    if bk == "manual" {
        field_findings(
            tname,
            b.get("fields").unwrap_or(&null),
            f.get("fields").unwrap_or(&null),
            renames,
            out,
        );
        variant_findings(
            tname,
            b.get("wire_keys"),
            f.get("wire_keys"),
            "accepted wire key",
            out,
        );
        refusal_findings(tname, b.get("refused"), f.get("refused"), out);
    } else if bk == "struct" {
        field_findings(
            tname,
            b.get("fields").unwrap_or(&null),
            f.get("fields").unwrap_or(&null),
            renames,
            out,
        );
    } else if bk == "enum" {
        variant_findings(
            tname,
            b.get("variants"),
            f.get("variants"),
            "enum variant",
            out,
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
            out,
            Severity::Breaking,
            tname.to_string(),
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
    let renames = rename_map(bt, ft);
    let renamed_to: BTreeSet<&String> = renames.values().collect();

    let mut out = Vec::new();
    for tname in names {
        let b = bt.get(tname);
        let f = ft.get(tname);
        let (Some(b), Some(f)) = (b, f) else {
            match (b, f) {
                (None, _) => {
                    // The ADDED half of a rename is not a new type; it is the old one, already
                    // reported under its old name with every delta the pair carries.
                    if !renamed_to.contains(tname) {
                        add(
                            &mut out,
                            Severity::Additive,
                            tname.clone(),
                            "new type/section added",
                        );
                    }
                }
                _ => match renames.get(tname) {
                    Some(new) => {
                        add(
                            &mut out,
                            Severity::Renamed,
                            tname.clone(),
                            format!(
                                "type/section RENAMED {} -> {} (the wire shape is unchanged: the \
                                 same keys, variants, refusals and optionality, under a new Rust \
                                 name)",
                                py_repr(tname),
                                py_repr(new)
                            ),
                        );
                        // Whatever the pair DOES differ by is reported under the new name, exactly
                        // as the same change without the rename would have reported it.
                        node_findings(new, &bt[tname], &ft[new], &renames, &mut out);
                    }
                    None => add(
                        &mut out,
                        Severity::Breaking,
                        tname.clone(),
                        "type/section REMOVED (a config referencing it now fails)",
                    ),
                },
            }
            continue;
        };
        node_findings(tname, b, f, &renames, &mut out);
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
    /// Each type that is one the baseline carried under another name. Informational, and printed
    /// on its own line every run: a reviewer must see the rename and ask whether it was intended.
    pub renamed: Vec<Finding>,
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
    let mut renamed = Vec::new();
    let mut waived = Vec::new();
    let mut breaking = Vec::new();
    for f in findings {
        match f.severity {
            Severity::Additive => additive.push(f),
            Severity::Relocated => relocated.push(f),
            Severity::Renamed => renamed.push(f),
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
        renamed,
        waived,
        breaking,
        stale,
    }
}

#[cfg(test)]
mod rename_tests {
    use super::*;
    use serde_json::json;

    fn enum_node(variants: &[&str]) -> Value {
        json!({"kind": "enum", "deny_unknown_fields": false, "transparent": false,
               "variants": variants})
    }

    fn tree(types: Value) -> Value {
        json!({ "types": types })
    }

    fn severities(before: &Value, after: &Value, sev: Severity) -> Vec<String> {
        classify(before, after)
            .into_iter()
            .filter(|f| f.severity == sev)
            .map(|f| format!("{}: {}", f.path, f.reason))
            .collect()
    }

    /// THE RULING. A removed type and an added type of the SAME WIRE SHAPE are one type renamed:
    /// informational, never a break. Nothing an operator writes has moved.
    #[test]
    fn a_type_renamed_with_the_same_shape_is_not_a_break() {
        let before = tree(json!({ "OnExhaust": enum_node(&["block", "downgrade"]) }));
        let after = tree(json!({ "OnExhaustWord": enum_node(&["block", "downgrade"]) }));
        let breaks = severities(&before, &after, Severity::Breaking);
        assert!(
            breaks.is_empty(),
            "a pure rename must not break: {breaks:?}"
        );
        let renamed = severities(&before, &after, Severity::Renamed);
        assert!(
            renamed.iter().any(|f| f.contains("OnExhaustWord")),
            "the rename must be REPORTED, not swallowed: {renamed:?}"
        );
    }

    /// A RENAME THAT ALSO APPENDS A VARIANT is the same change the rename-free tree would have
    /// made: additive, and reported under the NEW name so the appended word is visible.
    #[test]
    fn a_rename_that_appends_a_variant_is_additive_under_the_new_name() {
        let before = tree(json!({ "OnExhaust": enum_node(&["block", "downgrade"]) }));
        let after = tree(json!({ "OnExhaustWord": enum_node(&["block", "cut", "downgrade"]) }));
        let breaks = severities(&before, &after, Severity::Breaking);
        assert!(
            breaks.is_empty(),
            "an appended variant is additive: {breaks:?}"
        );
        let additive = severities(&before, &after, Severity::Additive);
        assert!(
            additive
                .iter()
                .any(|f| f.contains("OnExhaustWord::cut") && f.contains("APPENDED")),
            "the appended variant must still be reported: {additive:?}"
        );
    }

    /// RED-FIRST, THE OTHER WAY. A rename that also DROPS a variant is a break and stays one — the
    /// config that spelled the dropped word does not parse, whatever the type is now called.
    #[test]
    fn a_rename_that_drops_a_variant_is_breaking() {
        let before = tree(json!({ "OnExhaust": enum_node(&["block", "downgrade"]) }));
        let after = tree(json!({ "OnExhaustWord": enum_node(&["block"]) }));
        let breaks = severities(&before, &after, Severity::Breaking);
        assert!(
            breaks.iter().any(|f| f.starts_with("OnExhaust:")),
            "a shape-changing rename must stay BREAKING: {breaks:?}"
        );
    }

    /// A TYPE REALLY REMOVED, with nothing of its shape added, is the break the rule exists for.
    #[test]
    fn a_removed_type_with_no_counterpart_is_breaking() {
        let before = tree(json!({ "OnExhaust": enum_node(&["block", "downgrade"]) }));
        let after = tree(json!({}));
        let breaks = severities(&before, &after, Severity::Breaking);
        assert!(
            breaks.iter().any(|f| f.contains("REMOVED")),
            "a removal is a removal: {breaks:?}"
        );
    }

    /// AN AMBIGUOUS MATCH IS NO MATCH. Two removed types of one shape and one addition of that
    /// shape is not evidence of which was renamed; guessing would launder the other removal.
    #[test]
    fn an_ambiguous_pairing_pairs_with_nothing() {
        let before = tree(json!({
            "OnExhaust": enum_node(&["block", "downgrade"]),
            "OnExhaustToo": enum_node(&["block", "downgrade"]),
        }));
        let after = tree(json!({ "OnExhaustWord": enum_node(&["block", "downgrade"]) }));
        let breaks = severities(&before, &after, Severity::Breaking);
        assert_eq!(
            breaks.len(),
            2,
            "neither removal may be excused by one ambiguous addition: {breaks:?}"
        );
    }

    /// A FIELD RETYPED TO A RENAME-EQUIVALENT TYPE IS NOT A RETYPE — and one retyped to anything
    /// else still is.
    #[test]
    fn a_field_retyped_to_a_renamed_type_is_not_a_retype() {
        let before = tree(json!({
            "OnExhaust": enum_node(&["block", "downgrade"]),
            "LimitCfg": json!({"kind": "struct", "deny_unknown_fields": false,
                               "transparent": false,
                               "fields": {"on_exhaust": {"type": "Option<OnExhaust>",
                                                         "optional": true}}}),
        }));
        let after = tree(json!({
            "OnExhaustWord": enum_node(&["block", "downgrade"]),
            "LimitCfg": json!({"kind": "struct", "deny_unknown_fields": false,
                               "transparent": false,
                               "fields": {"on_exhaust": {"type": "Option<OnExhaustWord>",
                                                         "optional": true}}}),
        }));
        let breaks = severities(&before, &after, Severity::Breaking);
        assert!(
            breaks.is_empty(),
            "the field follows the rename: {breaks:?}"
        );

        let unrelated = tree(json!({
            "OnExhaustWord": enum_node(&["block", "downgrade"]),
            "LimitCfg": json!({"kind": "struct", "deny_unknown_fields": false,
                               "transparent": false,
                               "fields": {"on_exhaust": {"type": "Option<u64>",
                                                         "optional": true}}}),
        }));
        let breaks = severities(&before, &unrelated, Severity::Breaking);
        assert!(
            breaks.iter().any(|f| f.contains("RETYPED")),
            "a field retyped to an UNRELATED type is still a break: {breaks:?}"
        );
    }
}
