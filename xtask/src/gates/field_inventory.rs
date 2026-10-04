//! `cargo xtask gate field-inventory` — THE WIRE LOCKS ARE WHOLE, PINNED AND REGISTERED.
//!
//! Every request, response and stream path of every chat dialect lives in one place: the wire lock
//! `testing/llm-conformance/wire/<dialect>.wire.json`, which `cargo xtask dialect wire --write`
//! GENERATES from the provider specs pinned in `testing/llm-conformance/spec-digests.tsv` (see
//! [`crate::wire_lock`]). The `dialect-map-in-lock` and `dialect-candidates` gates read those locks.
//! This gate holds the locks to what a denominator must be, reading only committed files
//! (no network, no spec cache), so it runs in the fast tier:
//!
//! | row | the refusal |
//! | --- | --- |
//! | `:provenance` | every lock names its spec and carries the digest `spec-digests.tsv` pins today; a re-pin that skipped the regeneration is red |
//! | `:schema-identity` | a lock's `dialect` agrees with its filename and its spec with the register |
//! | `:no-duplicate-fields` | no direction lists a path twice (JSON would silently keep one) |
//! | `:registration` | the registered dialects and the lock files are the same set, both ways |
//! | `:both-directions` | every declared direction is present and at or above its armed path floor |
//! | `:audited-fields` | the eleven fields the 1.6.0 audit found BY HAND are all in the locks |
//! | `:artifact-drift` | the generated `qa/field-inventory.json` IS the projection of the locks |
//!
//! Whether a committed lock is what its pinned spec generates needs the spec bytes, so that check is
//! `cargo xtask dialect wire all` (it fetches and verifies through `vendor.sh`). The hand-copied
//! `qa/field-schemas/*.json` lists this gate used to enumerate from are retired: they listed 412
//! paths where the specs hold several thousand.

use std::collections::BTreeSet;

use crate::ctx::{Ctx, Overlay, WalkSpec};
use crate::gates::{prove_green, prove_red, Gate, Report};
use crate::ledger::{Row, Verdict};
use crate::wire_lock::{self, Lock, DIALECTS, INVENTORY, LOCK_DIR};

pub const ROW_PROVENANCE: &str = "field-inventory:provenance";
pub const ROW_SCHEMA_IDENTITY: &str = "field-inventory:schema-identity";
pub const ROW_NO_DUPLICATE_FIELDS: &str = "field-inventory:no-duplicate-fields";
pub const ROW_REGISTRATION: &str = "field-inventory:registration";
pub const ROW_BOTH_DIRECTIONS: &str = "field-inventory:both-directions";
pub const ROW_AUDITED_FIELDS: &str = "field-inventory:audited-fields";
pub const ROW_ARTIFACT_DRIFT: &str = "field-inventory:artifact-drift";

const LOCK_SUFFIX: &str = ".wire.json";

/// THE FLOOR EVERY (dialect, direction) PAIR IS HELD TO, armed 2026-10-01 at the count each lock
/// holds (WIRE-GEN). A spec that GAINS paths clears it without an edit; a floor falls only in a
/// reviewed diff that removes paths on purpose, so a trimmed lock cannot shrink the coverage
/// denominator in silence.
const PAIR_FLOORS: [(&str, &str, usize); 17] = [
    ("anthropic", "request", 1030),
    ("anthropic", "response", 200),
    ("anthropic", "stream", 246),
    ("openai", "request", 178),
    ("openai", "response", 100),
    ("openai", "stream", 84),
    ("responses", "request", 1005),
    ("responses", "response", 1772),
    ("responses", "stream", 1836),
    ("gemini", "request", 318),
    ("gemini", "response", 247),
    ("bedrock", "request", 211),
    ("bedrock", "response", 567),
    ("bedrock", "stream", 490),
    ("cohere", "request", 81),
    ("cohere", "response", 43),
    ("cohere", "stream", 86),
];

/// The fields the 1.6.0 IR-losslessness audit found BY HAND, in wire-lock notation. If the
/// enumeration cannot see a defect that was found by hand, it cannot see the ones that were not.
const AUDITED: [&str; 11] = [
    "openai/request/messages[].role=user.content[].type=input_audio.input_audio.data",
    "openai/request/messages[].role=user.content[].type=file.file.file_id",
    "openai/response/usage.completion_tokens_details.reasoning_tokens",
    "openai/response/choices[].message.annotations",
    "anthropic/request/messages[].content[].type=document.source.type=base64.data",
    "anthropic/response/usage.cache_creation.ephemeral_1h_input_tokens",
    "bedrock/request/messages[].content[].video.source.bytes",
    "cohere/response/message.tool_plan",
    "cohere/response/usage.billed_units.search_units",
    "responses/request/input[].type=message.content[].type=input_file.file_data",
    "gemini/request/contents[].parts[].inlineData.mimeType",
];

/// Which check refused, so every row below it reports unproven rather than passing.
struct Refusal {
    row: &'static str,
    why: String,
}

struct Loaded {
    locks: Vec<Lock>,
    texts: Vec<(String, String)>,
}

// ── THE LOADER ───────────────────────────────────────────────────────────────────────────────────

fn load(cx: &Ctx) -> Result<Loaded, Refusal> {
    let files = cx
        .list(&WalkSpec::new([LOCK_DIR]).ext("json").min_files(1))
        .map_err(|e| Refusal {
            row: ROW_REGISTRATION,
            why: format!("the lock directory could not be read: {e}"),
        })?;
    let have: BTreeSet<String> = files
        .iter()
        .filter_map(|p| p.file_name()?.to_str()?.strip_suffix(LOCK_SUFFIX))
        .map(str::to_string)
        .collect();
    let want: BTreeSet<String> = DIALECTS.iter().map(|d| d.name.to_string()).collect();
    let missing: Vec<&String> = want.difference(&have).collect();
    if !missing.is_empty() {
        return Err(Refusal {
            row: ROW_REGISTRATION,
            why: format!(
                "no wire lock for registered dialect(s) {missing:?}; run cargo xtask dialect wire \
                 --write all"
            ),
        });
    }
    let extra: Vec<&String> = have.difference(&want).collect();
    if !extra.is_empty() {
        return Err(Refusal {
            row: ROW_REGISTRATION,
            why: format!(
                "wire lock present for unregistered dialect(s) {extra:?}; register them in \
                 wire_lock::DIALECTS or the coverage denominator silently excludes a surface"
            ),
        });
    }
    let mut locks = Vec::new();
    let mut texts = Vec::new();
    for d in &DIALECTS {
        let path = wire_lock::lock_path(d.name);
        let text = cx.read(&path).map_err(|e| Refusal {
            row: ROW_PROVENANCE,
            why: format!("{path}: unreadable: {e}"),
        })?;
        let lock = Lock::parse(&text).map_err(|e| Refusal {
            row: ROW_PROVENANCE,
            why: format!("{path}: {e}"),
        })?;
        locks.push(lock);
        texts.push((path, text));
    }
    Ok(Loaded { locks, texts })
}

// ── THE CHECKS ───────────────────────────────────────────────────────────────────────────────────

fn provenance(cx: &Ctx, locks: &[Lock]) -> Vec<String> {
    let pins = match wire_lock::spec::pins(cx) {
        Ok(p) => p,
        Err(e) => return vec![e],
    };
    let mut bad = Vec::new();
    for (d, l) in DIALECTS.iter().zip(locks) {
        match pins.get(d.spec) {
            Some(pin) if pin.sha256 == l.sha256 && l.spec == d.spec => {}
            Some(pin) => bad.push(format!(
                "{} carries spec `{}` at {} but {} pins `{}` at {}; run cargo xtask dialect wire \
                 --write {}",
                wire_lock::lock_path(d.name),
                l.spec,
                l.sha256,
                wire_lock::spec::DIGESTS,
                d.spec,
                pin.sha256,
                d.name
            )),
            None => bad.push(format!(
                "{} pins no `{}` spec",
                wire_lock::spec::DIGESTS,
                d.spec
            )),
        }
    }
    bad
}

fn identity(locks: &[Lock]) -> Vec<String> {
    DIALECTS
        .iter()
        .zip(locks)
        .filter(|(d, l)| l.dialect != d.name || l.format != d.format.label())
        .map(|(d, l)| {
            format!(
                "{}: `dialect` '{}' / format '{}' does not match the filename and the register \
                 ('{}', '{}')",
                wire_lock::lock_path(d.name),
                l.dialect,
                l.format,
                d.name,
                d.format.label()
            )
        })
        .collect()
}

/// A path written twice in one direction. JSON parsing keeps one silently, so the TEXT is read:
/// the lock writes one path per line, four spaces in, beneath a two-space direction key.
fn duplicates(texts: &[(String, String)]) -> Vec<String> {
    let mut out = Vec::new();
    for (path, text) in texts {
        let mut dir = String::new();
        let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
        for line in text.lines() {
            if let Some(k) = line
                .strip_prefix("  \"")
                .and_then(|r| r.split_once("\": {"))
            {
                dir = k.0.to_string();
            } else if let Some((key, _)) = line
                .strip_prefix("    \"")
                .and_then(|r| r.split_once("\": {"))
            {
                if !seen.insert((dir.clone(), key.to_string())) {
                    out.push(format!("{path}: {dir} path '{key}' appears twice"));
                }
            }
        }
    }
    out
}

/// Every (dialect, direction) pair below its armed floor, absent though the register declares a
/// root for it, or with no floor at all.
fn short_pairs(locks: &[Lock]) -> Vec<String> {
    let mut short = Vec::new();
    for (d, l) in DIALECTS.iter().zip(locks) {
        for (dir, root) in wire_lock::DIRECTIONS.iter().zip(d.roots.iter()) {
            if root.is_none() {
                continue;
            }
            let got = l.dirs.get(*dir).map_or(0, |p| p.len());
            match PAIR_FLOORS
                .iter()
                .find(|(n, x, _)| *n == d.name && x == dir)
            {
                Some((_, _, floor)) if got >= *floor => {}
                Some((_, _, floor)) => {
                    short.push(format!("{}/{dir} ({got} path(s), floor {floor})", d.name))
                }
                None => short.push(format!("{}/{dir} (no floor is armed)", d.name)),
            }
        }
    }
    short
}

fn audited_missing(locks: &[Lock]) -> Vec<String> {
    AUDITED
        .iter()
        .filter(|id| {
            let mut parts = id.splitn(3, '/');
            let (Some(d), Some(dir), Some(p)) = (parts.next(), parts.next(), parts.next()) else {
                return true;
            };
            !locks
                .iter()
                .any(|l| l.dialect == d && l.dirs.get(dir).is_some_and(|m| m.contains_key(p)))
        })
        .map(|s| (*s).to_string())
        .collect()
}

fn row(id: &str, ok: &str, bad: &str, problems: &[String], green: String) -> Row {
    if problems.is_empty() {
        Row::pass(id, ok, green)
    } else {
        Row::fail(id, bad, problems.join("; "))
    }
}

// ── THE GATE ─────────────────────────────────────────────────────────────────────────────────────

pub struct FieldInventoryGate;

impl Gate for FieldInventoryGate {
    fn name(&self) -> &'static str {
        "field-inventory"
    }

    fn owed(&self) -> Vec<String> {
        [
            ROW_PROVENANCE,
            ROW_SCHEMA_IDENTITY,
            ROW_NO_DUPLICATE_FIELDS,
            ROW_REGISTRATION,
            ROW_BOTH_DIRECTIONS,
            ROW_AUDITED_FIELDS,
            ROW_ARTIFACT_DRIFT,
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect()
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let loaded = match load(cx) {
            Ok(l) => l,
            Err(refusal) => {
                let mut rows = vec![Row::fail(
                    refusal.row,
                    "the wire locks were refused",
                    refusal.why.clone(),
                )];
                for id in self.owed() {
                    if id != refusal.row {
                        rows.push(Row::skip(
                            &id,
                            "unproven — the lock set was refused above this check",
                            "the lock set was refused, so nothing was read from it".to_string(),
                        ));
                    }
                }
                return Verdict::of(rows);
            }
        };
        let locks = &loaded.locks;
        let paths: usize = locks
            .iter()
            .flat_map(|l| l.dirs.values())
            .map(|d| d.len())
            .sum();
        let drift = match cx.read(INVENTORY) {
            Ok(t) if t == wire_lock::render_inventory(locks) => Vec::new(),
            Ok(_) => vec![format!(
                "{INVENTORY} is STALE; run cargo xtask dialect wire --write all"
            )],
            Err(_) => vec![format!(
                "{INVENTORY} is missing; run cargo xtask dialect wire --write all"
            )],
        };
        Verdict::of(vec![
            row(
                ROW_PROVENANCE,
                "every wire lock carries the digest its spec is pinned at",
                "a wire lock is not generated from the spec pinned today",
                &provenance(cx, locks),
                format!("{} lock(s), each at its pinned digest", locks.len()),
            ),
            row(
                ROW_SCHEMA_IDENTITY,
                "every lock's dialect agrees with its filename and the register",
                "a lock names a dialect its filename does not",
                &identity(locks),
                "each lock names its own dialect and format".to_string(),
            ),
            row(
                ROW_NO_DUPLICATE_FIELDS,
                "no direction lists a path twice",
                "a lock lists a path twice",
                &duplicates(&loaded.texts),
                "every direction's paths are a set".to_string(),
            ),
            row(
                ROW_REGISTRATION,
                "the registered dialects and the lock files are the same set",
                "the lock set and the register disagree",
                &[],
                format!("{} dialect(s), matched both ways", DIALECTS.len()),
            ),
            row(
                ROW_BOTH_DIRECTIONS,
                "every declared direction is at or above its armed path floor",
                "a dialect enumerates a direction below its floor",
                &short_pairs(locks),
                format!("{paths} path(s) across every dialect/direction pair"),
            ),
            row(
                ROW_AUDITED_FIELDS,
                "every field the audit found by hand is in the locks",
                "the locks cannot see a defect that was found by hand",
                &audited_missing(locks),
                format!("{} audited field(s) present", AUDITED.len()),
            ),
            row(
                ROW_ARTIFACT_DRIFT,
                "the generated inventory is the projection of the locks",
                "the generated inventory is not what the locks project",
                &drift,
                format!("{INVENTORY} is up to date"),
            ),
        ])
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();
        let owed = self.owed();
        let all: Vec<&str> = owed.iter().map(String::as_str).collect();
        report.push(prove_green(
            cx,
            self,
            "the six committed wire locks are pinned, registered and whole",
            &all,
        ));
        report.push(prove_red(
            cx,
            self,
            "a lock generated from a digest the tsv no longer pins is refused",
            &[ROW_PROVENANCE],
            edit(cx, "anthropic", &|l| l.sha256 = "0".repeat(64)),
            &["dialect wire --write anthropic"],
        ));
        report.push(prove_red(
            cx,
            self,
            "a lock whose dialect disagrees with its filename is refused",
            &[ROW_SCHEMA_IDENTITY],
            edit(cx, "openai", &|l| l.dialect = "not-openai".into()),
            &["does not match the filename"],
        ));
        let path = wire_lock::lock_path("cohere");
        let mut ov = Overlay::new();
        let text = cx.read(&path).unwrap_or_default();
        let doubled = text.replacen(
            "    \"model\": ",
            "    \"model\": {\"type\":\"string\"},\n    \"model\": ",
            1,
        );
        ov.set(&path, doubled);
        report.push(prove_red(
            cx,
            self,
            "a path written twice in one direction is a named finding",
            &[ROW_NO_DUPLICATE_FIELDS],
            ov,
            &["path 'model' appears twice"],
        ));
        let mut ov = Overlay::new();
        ov.remove(wire_lock::lock_path("openai"));
        report.push(prove_red(
            cx,
            self,
            "a registered dialect whose lock is gone is refused",
            &[ROW_REGISTRATION],
            ov,
            &["no wire lock for registered dialect"],
        ));
        let mut ov = Overlay::new();
        ov.set(
            wire_lock::lock_path("mistral"),
            cx.read(wire_lock::lock_path("cohere")).unwrap_or_default(),
        );
        report.push(prove_red(
            cx,
            self,
            "a lock for an unregistered dialect is refused, not silently excluded",
            &[ROW_REGISTRATION],
            ov,
            &["unregistered dialect"],
        ));
        report.push(prove_red(
            cx,
            self,
            "a direction trimmed below its floor is a named finding",
            &[ROW_BOTH_DIRECTIONS],
            edit(cx, "gemini", &|l| {
                if let Some(r) = l.dirs.get_mut("response") {
                    let keep = r.keys().next().cloned();
                    r.retain(|k, _| Some(k) == keep.as_ref());
                }
            }),
            &["gemini/response (1 path(s)"],
        ));
        report.push(prove_red(
            cx,
            self,
            "a declared direction missing from its lock is a named finding",
            &[ROW_BOTH_DIRECTIONS],
            edit(cx, "bedrock", &|l| {
                l.dirs.remove("stream");
            }),
            &["bedrock/stream (0 path(s)"],
        ));
        report.push(prove_red(
            cx,
            self,
            "an audited field dropped from its lock is a named finding",
            &[ROW_AUDITED_FIELDS],
            edit(cx, "cohere", &|l| {
                if let Some(r) = l.dirs.get_mut("response") {
                    r.remove("message.tool_plan");
                }
            }),
            &["cohere/response/message.tool_plan"],
        ));
        let mut ov = Overlay::new();
        ov.set(
            INVENTORY,
            cx.read(INVENTORY)
                .unwrap_or_default()
                .replace("\"gemini\",", "\"gemini\", \"planted\","),
        );
        report.push(prove_red(
            cx,
            self,
            "a generated inventory that is not the projection of the locks is STALE",
            &[ROW_ARTIFACT_DRIFT],
            ov,
            &["is STALE"],
        ));
        report
    }
}

/// One lock, edited through its own reader and writer, so a case is expressed against the real
/// committed file.
fn edit(cx: &Ctx, dialect: &str, f: &dyn Fn(&mut Lock)) -> Overlay {
    let mut ov = Overlay::new();
    let path = wire_lock::lock_path(dialect);
    let mut lock = cx
        .read(&path)
        .ok()
        .and_then(|t| Lock::parse(&t).ok())
        .unwrap_or_default();
    f(&mut lock);
    ov.set(path, lock.render());
    ov
}

#[cfg(test)]
#[path = "tests/field_inventory_tests.rs"]
mod tests;
