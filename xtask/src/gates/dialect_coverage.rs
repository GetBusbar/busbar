//! THE LLM DIALECT COVERAGE GATES (design DIALECT FIDELITY F4; spec Part 2 #76, "an un-looked-at
//! field is a MAJOR violation"). Both read the hand-written mapping files
//! (`crates/busbar-plane-llm/dialects/<d>.toml`, [`crate::dialect::load_maps`]) against the wire locks
//! generated from the pinned provider specs (`testing/llm-conformance/wire/<lock>.wire.json`).
//!
//! | gate | row | the refusal |
//! | --- | --- | --- |
//! | `dialect-map-in-lock` | `:paths` | a mapped path or a `no-equivalent` mark that is not in its dialect's lock (a typo, or spec drift on a re-pin); an `off_wire` row whose path IS in the lock |
//! | `dialect-candidates` | `:unclassified` | a CANDIDATE that is neither mapped nor marked |
//! | `dialect-candidates` | `:stale-marks` | a `no-equivalent` mark on a path that is not a candidate (it classifies nothing: strike it) |
//!
//! A CANDIDATE is a path in dialect B's lock whose leaf AND structural node name a field some OTHER
//! dialect maps in the same direction, which B neither maps nor marks `no-equivalent` (ARCHITECT
//! 2026-10-02: a bare generic leaf such as `id`, `text` or `name` never qualifies on its own). It is how "provider B ships a
//! field provider A already has" is caught: the spec re-pin regenerates B's lock, the new path is a
//! candidate, and this gate names it until B's map file maps it (one line) or marks it.
//!
//! * A path's LEAF is its last segment: a member's name (`[]`/`{}` dropped), or an arm's tag value
//!   (`content[].type=thinking` is `thinking`). A union's tag member (`type`, `role`: every `tag` the
//!   locks record) is structure, never a leaf. Leaves compare lowercased with `_` removed, so a
//!   camelCase wire (`topK`) and a snake_case one (`top_k`) name the same field.
//! * A path's STRUCTURAL NODE is the innermost array item or union arm above its leaf (`input[]`,
//!   `type=mcp_call`), named as its leaf is; a path with none sits at the body's root. A plain member
//!   container is not a node: Gemini's `generationConfig.topK` sits at the root, as `top_k` does.
//! * A mapped row names two leaves, each at its own node: its path's, and its concept's (the slot, or
//!   the `prim` name): the slot registry is the declared alias (`p` maps `top_p`).
//! * B maps a path when a row of B names it or a path beneath it (a row on `serviceTier.type` maps
//!   `serviceTier`).

use std::collections::{BTreeMap, BTreeSet};

use crate::ctx::{Ctx, Overlay};
use crate::dialect::{load_maps, segments, MapFile, Seg, DIALECT_DIR};
use crate::gates::{prove_green, prove_red, prove_rows_green, Gate, Report};
use crate::ledger::{Row, Verdict};
use crate::wire_lock::{self, Lock};

pub const ROW_IN_LOCK: &str = "dialect-map-in-lock:paths";
pub const ROW_UNCLASSIFIED: &str = "dialect-candidates:unclassified";
pub const ROW_STALE_MARKS: &str = "dialect-candidates:stale-marks";

/// The mapping files and the lock each one names, or the reason they cannot be read together.
fn load(cx: &Ctx) -> Result<Vec<(MapFile, Lock)>, String> {
    let maps = load_maps(cx)?;
    maps.into_iter()
        .map(|m| {
            let path = wire_lock::lock_path(&m.wire);
            let lock = Lock::parse(&cx.read(&path)?).map_err(|e| format!("{path}: {e}"))?;
            Ok((m, lock))
        })
        .collect()
}

/// Whether `lock` holds `path` in direction `dir`.
fn in_lock(lock: &Lock, dir: &str, path: &str) -> bool {
    lock.dirs.get(dir).is_some_and(|d| d.contains_key(path))
}

/// `<lock>/<direction>/<path>`: the id a finding names, as the wire locks spell it.
fn id(wire: &str, dir: &str, path: &str) -> String {
    format!("{wire}/{dir}/{path}")
}

pub struct DialectMapInLockGate;

impl Gate for DialectMapInLockGate {
    fn name(&self) -> &'static str {
        "dialect-map-in-lock"
    }

    fn owed(&self) -> Vec<String> {
        vec![ROW_IN_LOCK.to_string()]
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let loaded = match load(cx) {
            Ok(l) => l,
            Err(why) => {
                return Verdict::of(vec![Row::fail(
                    ROW_IN_LOCK,
                    "the mapping files or their wire locks cannot be read",
                    why,
                )])
            }
        };
        let mut bad: BTreeMap<String, &str> = BTreeMap::new();
        let mut checked = 0usize;
        for (m, lock) in &loaded {
            for r in &m.rows {
                checked += 1;
                let here = in_lock(lock, r.dir, &r.path);
                match (&r.off_wire, here) {
                    (None, false) => {
                        bad.insert(id(&m.wire, r.dir, &r.path), "mapped, not in the lock");
                    }
                    (Some(_), true) => {
                        bad.insert(
                            id(&m.wire, r.dir, &r.path),
                            "marked off_wire, but the lock has it",
                        );
                    }
                    _ => {}
                }
            }
            for k in &m.marks {
                checked += 1;
                if !in_lock(lock, k.dir, &k.path) {
                    bad.insert(
                        id(&m.wire, k.dir, &k.path),
                        "marked no-equivalent, not in the lock",
                    );
                }
            }
        }
        let row = if bad.is_empty() {
            Row::pass(
                ROW_IN_LOCK,
                "every mapped path and every no-equivalent mark is in its dialect's wire lock",
                format!("{checked} path(s) over {} mapping file(s)", loaded.len()),
            )
        } else {
            Row::fail(
                ROW_IN_LOCK,
                "a mapping file names a path its dialect's wire lock does not have",
                format!(
                    "{} — fix the path (notation A, as the lock spells it), or re-pin and \
                     regenerate the lock (`cargo xtask dialect wire --write`)",
                    bad.iter()
                        .map(|(p, why)| format!("{p} ({why})"))
                        .collect::<Vec<_>>()
                        .join(" | ")
                ),
            )
        };
        Verdict::of(vec![row])
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();
        report.push(prove_green(
            cx,
            self,
            "every mapped path of the committed files is in its lock",
            &[ROW_IN_LOCK],
        ));

        // A TYPO in a nested row: Gemini spells it topK, not topQ.
        let gemini = format!("{DIALECT_DIR}/gemini.toml");
        let mut typo = Overlay::new();
        typo.set(
            &gemini,
            cx.read(&gemini)
                .unwrap_or_default()
                .replace("\"generationConfig.topK\"", "\"generationConfig.topQ\""),
        );
        report.push(prove_red(
            cx,
            self,
            "a mapped path the lock lacks is RED, naming it",
            &[ROW_IN_LOCK],
            typo,
            &["gemini/request/generationConfig.topQ"],
        ));

        // SPEC DRIFT: a re-pin dropped a path a dialect maps.
        let lock = wire_lock::lock_path("cohere");
        let mut drift = Overlay::new();
        drift.set(
            &lock,
            cx.read(&lock)
                .unwrap_or_default()
                .replace("\n    \"p\": ", "\n    \"p_renamed\": "),
        );
        report.push(prove_red(
            cx,
            self,
            "a lock that lost a mapped path is RED, naming it",
            &[ROW_IN_LOCK],
            drift,
            &["cohere/request/p"],
        ));

        report
    }
}

/// A leaf as candidates compare it: lowercased, `_` removed.
fn norm(s: &str) -> String {
    s.chars()
        .filter(|c| *c != '_')
        .flat_map(char::to_lowercase)
        .collect()
}

/// The leaf `path` names, or `None` when it ends in a union's tag member (structure).
fn leaf(path: &str, tags: &BTreeSet<String>) -> Option<String> {
    match segments(path).ok()?.last()? {
        Seg::Arm(_, arm) => Some(norm(arm)),
        Seg::Key(n) | Seg::Each(n) if !tags.contains(*n) => Some(norm(n)),
        _ => None,
    }
}

/// The structural node above `path`'s leaf: the innermost `[]`/`{}` item or union arm before the
/// last segment, named as a leaf is; `""` for the body's root.
fn node(path: &str) -> String {
    let Ok(segs) = segments(path) else {
        return String::new();
    };
    segs.split_last()
        .and_then(|(_, above)| {
            above.iter().rev().find_map(|s| match s {
                Seg::Arm(_, arm) => Some(norm(arm)),
                Seg::Each(n) => Some(norm(n)),
                Seg::Key(_) => None,
            })
        })
        .unwrap_or_default()
}

/// One candidate: `<lock>/<direction>/<path>`, whether its own file marks it, and the dialects that
/// map its leaf.
struct Candidate {
    id: String,
    marked: bool,
    leaf: String,
    mapped_by: Vec<String>,
}

/// Every candidate of the mapping files over their locks (marked or not), in lock and path order.
fn candidates(loaded: &[(MapFile, Lock)]) -> Vec<Candidate> {
    let tags: BTreeSet<String> = loaded
        .iter()
        .flat_map(|(_, l)| l.dirs.values())
        .flat_map(|d| d.values())
        .filter_map(|e| e.tag.clone())
        .collect();
    // (direction, structural node, leaf) -> the dialects whose rows name it.
    let mut names: BTreeMap<(&str, String, String), BTreeSet<&str>> = BTreeMap::new();
    for (m, _) in loaded {
        for r in &m.rows {
            let at = node(&r.path);
            let concept = (!r.concept.is_empty()).then(|| norm(&r.concept));
            for n in [leaf(&r.path, &tags), concept].into_iter().flatten() {
                names
                    .entry((r.dir, at.clone(), n))
                    .or_default()
                    .insert(m.name.as_str());
            }
        }
    }
    let mut out = Vec::new();
    for (m, lock) in loaded {
        // A row maps its own path and every path above it.
        let mut covered: BTreeSet<(&str, String)> = BTreeSet::new();
        for r in &m.rows {
            let mut prefix = String::new();
            for seg in r.path.split('.') {
                if !prefix.is_empty() {
                    prefix.push('.');
                }
                prefix.push_str(seg);
                covered.insert((r.dir, prefix.clone()));
            }
        }
        let marked: BTreeSet<(&str, &str)> =
            m.marks.iter().map(|k| (k.dir, k.path.as_str())).collect();
        for (dir, paths) in &lock.dirs {
            for path in paths.keys() {
                if covered.contains(&(dir.as_str(), path.clone())) {
                    continue;
                }
                let Some(l) = leaf(path, &tags) else {
                    continue;
                };
                let Some(by) = names.get(&(dir.as_str(), node(path), l.clone())) else {
                    continue;
                };
                let mapped_by: Vec<String> = by
                    .iter()
                    .filter(|d| **d != m.name)
                    .map(|d| d.to_string())
                    .collect();
                if !mapped_by.is_empty() {
                    out.push(Candidate {
                        id: id(&m.wire, dir, path),
                        marked: marked.contains(&(dir.as_str(), path.as_str())),
                        leaf: l,
                        mapped_by,
                    });
                }
            }
        }
    }
    out
}

pub struct DialectCandidatesGate;

impl Gate for DialectCandidatesGate {
    fn name(&self) -> &'static str {
        "dialect-candidates"
    }

    fn owed(&self) -> Vec<String> {
        vec![ROW_UNCLASSIFIED.to_string(), ROW_STALE_MARKS.to_string()]
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let loaded = match load(cx) {
            Ok(l) => l,
            Err(why) => {
                return Verdict::of(
                    [ROW_UNCLASSIFIED, ROW_STALE_MARKS]
                        .map(|r| {
                            Row::fail(
                                r,
                                "the mapping files or their wire locks cannot be read",
                                why.clone(),
                            )
                        })
                        .to_vec(),
                )
            }
        };
        let all = candidates(&loaded);
        let candidate_ids: BTreeSet<&str> = all.iter().map(|c| c.id.as_str()).collect();
        let stale: Vec<String> = loaded
            .iter()
            .flat_map(|(m, _)| m.marks.iter().map(move |k| id(&m.wire, k.dir, &k.path)))
            .filter(|i| !candidate_ids.contains(i.as_str()))
            .collect();
        let stale_row = if stale.is_empty() {
            Row::pass(
                ROW_STALE_MARKS,
                "every no-equivalent mark classifies a candidate",
                "0 stale mark(s)".to_string(),
            )
        } else {
            Row::fail(
                ROW_STALE_MARKS,
                "a no-equivalent mark sits on a path that is not a candidate",
                format!(
                    "{} — strike the mark: it classifies nothing, and a mark nobody needs is a \
                     reason nobody re-reads",
                    stale.join(" | ")
                ),
            )
        };
        let found: Vec<&Candidate> = all.iter().filter(|c| !c.marked).collect();
        let row = {
            {
                if found.is_empty() {
                    Row::pass(
                        ROW_UNCLASSIFIED,
                        "every cross-dialect candidate is mapped or marked no-equivalent",
                        format!("0 unclassified over {} mapping file(s)", loaded.len()),
                    )
                } else {
                    Row::fail(
                        ROW_UNCLASSIFIED,
                        "a wire path names a field another dialect maps, and its own map file \
                         neither maps nor marks it",
                        format!(
                            "{} unclassified: {} — map it in that dialect's \
                             crates/busbar-plane-llm/dialects/<d>.toml (one row) or mark it \
                             [unmapped.<direction>] \"<path>\" = {{ no-equivalent = \"<reason>\" }}",
                            found.len(),
                            found
                                .iter()
                                .map(|c| format!(
                                    "{} (`{}`, mapped by {})",
                                    c.id,
                                    c.leaf,
                                    c.mapped_by.join(", ")
                                ))
                                .collect::<Vec<_>>()
                                .join(" | ")
                        ),
                    )
                }
            }
        };
        Verdict::of(vec![row, stale_row])
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();
        report.push(prove_green(
            cx,
            self,
            "every candidate of the committed files is classified, by no stale mark",
            &[ROW_UNCLASSIFIED, ROW_STALE_MARKS],
        ));

        // THE OWNER'S CASE. OpenAI ships `top_k`, a field Anthropic, Cohere and Gemini already map:
        // the spec re-pin regenerates openai.wire.json with the new path, and the gate names it.
        let lock = wire_lock::lock_path("openai");
        let gained = cx.read(&lock).unwrap_or_default().replacen(
            "\n    \"tool_choice\": ",
            "\n    \"top_k\": {\"type\":\"integer|null\"},\n    \"tool_choice\": ",
            1,
        );
        let mut repin = Overlay::new();
        repin.set(&lock, gained.clone());
        report.push(prove_red(
            cx,
            self,
            "a re-pinned lock that gains a field another dialect maps is RED, naming it",
            &[ROW_UNCLASSIFIED],
            repin,
            &["openai/request/top_k"],
        ));

        // ...and the change that answers it is ONE LINE in openai_chat.toml.
        let chat = format!("{DIALECT_DIR}/openai_chat.toml");
        let mapped = cx.read(&chat).unwrap_or_default().replacen(
            "\"top_p\" = { ir = \"top_p\" }\n",
            "\"top_p\" = { ir = \"top_p\" }\n\"top_k\" = { ir = \"top_k\" }\n",
            1,
        );
        let mut answered = Overlay::new();
        answered.set(&lock, gained);
        answered.set(&chat, mapped);
        report.push(prove_rows_green(
            cx,
            self,
            "the same re-pin plus one mapping line is GREEN",
            &[ROW_UNCLASSIFIED],
            answered,
        ));

        // THE SAME LEAF UNDER ANOTHER STRUCTURAL NODE is not a candidate: a `top_k` inside a tool
        // definition is that tool's own member, not the sampling `top_k`.
        let elsewhere = cx.read(&lock).unwrap_or_default().replacen(
            "\n    \"tool_choice\": ",
            "\n    \"tools[].top_k\": {\"type\":\"integer\"},\n    \"tool_choice\": ",
            1,
        );
        let mut nested = Overlay::new();
        nested.set(&lock, elsewhere);
        report.push(prove_rows_green(
            cx,
            self,
            "the same leaf under a different structural node (`tools[].top_k`) is not a candidate",
            &[ROW_UNCLASSIFIED],
            nested,
        ));

        // A mark withdrawn: the path it classified is a candidate again.
        let unmarked = cx
            .read(&chat)
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.starts_with("\"moderation.model\""))
            .collect::<Vec<_>>()
            .join("\n");
        let mut withdrawn = Overlay::new();
        withdrawn.set(&chat, unmarked);
        report.push(prove_red(
            cx,
            self,
            "a withdrawn no-equivalent mark is RED, naming the path",
            &[ROW_UNCLASSIFIED],
            withdrawn,
            &["openai/request/moderation.model"],
        ));

        // A mark on a path no other dialect's field matches classifies nothing.
        let stale_mark = cx.read(&chat).unwrap_or_default().replacen(
            "[unmapped.request]\n",
            "[unmapped.request]\n\"messages[].role=user.name\" = { no-equivalent = \"plant\" }\n",
            1,
        );
        let mut stale = Overlay::new();
        stale.set(&chat, stale_mark);
        report.push(prove_red(
            cx,
            self,
            "a no-equivalent mark on a path that is not a candidate is RED, naming it",
            &[ROW_STALE_MARKS],
            stale,
            &["openai/request/messages[].role=user.name"],
        ));

        report
    }
}
