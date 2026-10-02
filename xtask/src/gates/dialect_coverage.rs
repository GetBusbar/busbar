//! THE LLM DIALECT COVERAGE GATES (design DIALECT FIDELITY F4; spec Part 2 #76, "an un-looked-at
//! field is a MAJOR violation"). Both read the hand-written mapping files
//! (`crates/busbar-plane-llm/dialects/<d>.toml`, [`crate::dialect::load_maps`]) against the wire locks
//! generated from the pinned provider specs (`testing/llm-conformance/wire/<lock>.wire.json`).
//!
//! | gate | row | the refusal |
//! | --- | --- | --- |
//! | `dialect-map-in-lock` | `:paths` | a mapped path or a `no-equivalent` mark that is not in its dialect's lock (a typo, or spec drift on a re-pin); an `off_wire` row whose path IS in the lock |

use std::collections::BTreeMap;

use crate::ctx::{Ctx, Overlay};
use crate::dialect::{load_maps, MapFile, DIALECT_DIR};
use crate::gates::{prove_green, prove_red, Gate, Report};
use crate::ledger::{Row, Verdict};
use crate::wire_lock::{self, Lock};

pub const ROW_IN_LOCK: &str = "dialect-map-in-lock:paths";

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
