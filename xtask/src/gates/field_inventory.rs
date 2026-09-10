//! `cargo xtask gate field-inventory` — THE FIELD INVENTORY AND ITS PROVENANCE REFUSAL. The
//! successor to `scripts/field-inventory.py`, claim for claim.
//!
//! Every request and response field of every chat dialect busbar speaks, enumerated from the
//! VENDORED schemas in `qa/field-schemas/` and written to `qa/field-inventory.json`, which
//! `crates/busbar/tests/field_coverage.rs` turns into a build failure for any field that is neither
//! CARRIED by a named test nor explicitly WAIVED.
//!
//! ## The provenance refusal is the whole file
//!
//! The schemas are TRANSCRIBED from published references, not derived from busbar's own readers —
//! a derivation from the reader would report perfect coverage of exactly the fields the reader
//! already knows about, which is the failure mode. What keeps a transcription honest is that each
//! one carries a `source` URL and a `retrieved` date, and that a schema missing either is REFUSED
//! rather than quietly derived from. That single refusal is all that stands between "a vendored
//! schema" and "a hand-written list wearing a filename", and the Python self-test that claimed to
//! prove it re-implemented its condition instead of driving it:
//!
//! ```text
//! probe = dict(schemas["openai"]); probe.pop(key)
//! if all(probe.get(k) for k in REQUIRED_SCHEMA_KEYS): ...
//! ```
//!
//! That is a property of a dict comprehension. Cut the real guard out of the loader and the
//! self-test stayed green. Here a selftest reaches the gate only through [`Gate::run`], so the
//! refusal is driven, one planted mutation at a time, and cannot be restated.
//!
//! ## Every claim is a row, including the four the Python only made in `--selftest`
//!
//! | row | the refusal |
//! | --- | --- |
//! | `:provenance` | every schema carries all six required keys, non-empty |
//! | `:schema-identity` | `dialect` agrees with the filename, and no dialect appears twice |
//! | `:no-duplicate-fields` | a direction lists no field twice |
//! | `:registration` | the registered dialect set and the schema set are EQUAL, both ways |
//! | `:both-directions` | every dialect enumerates BOTH directions; an empty one reports full |
//! | `:audited-fields` | the eleven fields the audit found BY HAND are all in the enumeration |
//! | `:artifact-drift` | the committed `qa/field-inventory.json` IS the fresh derivation |
//!
//! The last three were assertions only `--selftest` made, and the self-test is not the mode CI
//! blocks on. They are on the run path here, which is the same fix the discovery floor got.
//!
//! ## The row that was removed: `:id-uniqueness`
//!
//! It asserted that no two derived rows share an id. An id is `{dialect}/{direction}/{field}`, so a
//! collision needs the same field listed twice in one direction of one dialect — and
//! `:no-duplicate-fields` REFUSES the schema set on exactly that, before a single id is built. The
//! FAIL arm was unreachable on every input: no tree could make it red, its selftest coverage came
//! from the whole-tree green, and it was deletable with `cargo xtask selftest` still passing. A row
//! that cannot fail is not a rule; it is a row a reader counts as a proof and receives nothing for.
//! The property it named is still enforced — one row earlier, where the input can actually carry
//! the defect.
//!
//! ## Byte parity with the Python's `json.dumps(indent=2)`
//!
//! A generated artefact is compared against a committed one, so the emitter reproduces Python's
//! `json.dumps(obj, indent=2)` exactly — insertion order (NOT sorted keys, which is what
//! `serde_json`'s default `Map` would give), two-space indent, `": "` between key and value, `[]`
//! for an empty list, and `\uXXXX` for every non-ASCII character. Regenerating and committing is
//! how a drift signal gets destroyed, so the emitter is written to match rather than the file
//! rewritten to match the emitter.

use std::collections::{BTreeMap, BTreeSet};

use crate::ctx::{Ctx, Overlay, WalkSpec};
use crate::gates::{prove_green, prove_red, Gate, Report};
use crate::ledger::{Row, Verdict};
use crate::parity::LegacyRun;

pub const ROW_PROVENANCE: &str = "field-inventory:provenance";
pub const ROW_SCHEMA_IDENTITY: &str = "field-inventory:schema-identity";
pub const ROW_NO_DUPLICATE_FIELDS: &str = "field-inventory:no-duplicate-fields";
pub const ROW_REGISTRATION: &str = "field-inventory:registration";
pub const ROW_BOTH_DIRECTIONS: &str = "field-inventory:both-directions";
pub const ROW_AUDITED_FIELDS: &str = "field-inventory:audited-fields";
pub const ROW_ARTIFACT_DRIFT: &str = "field-inventory:artifact-drift";

const SCHEMA_DIR: &str = "qa/field-schemas";
const OUT: &str = "qa/field-inventory.json";

const DIRECTIONS: [&str; 2] = ["request", "response"];

/// The six chat dialects. Listed here so a schema file ADDED without being registered, or a dialect
/// registered with no schema file, is a hard error rather than a silently smaller inventory.
const DIALECTS: [&str; 6] = [
    "anthropic",
    "openai",
    "responses",
    "gemini",
    "bedrock",
    "cohere",
];

const REQUIRED_SCHEMA_KEYS: [&str; 6] = [
    "dialect",
    "surface",
    "source",
    "retrieved",
    "request",
    "response",
];

/// The fields the 1.6.0 IR-losslessness audit found BY HAND. If the enumeration cannot even see a
/// defect that was found by hand, it cannot see the ones that were not.
const AUDITED: [&str; 11] = [
    "openai/request/content[].type=input_audio.input_audio.data",
    "openai/request/content[].type=file.file.file_id",
    "openai/response/usage.completion_tokens_details.reasoning_tokens",
    "openai/response/choices[].message.annotations",
    "anthropic/request/content[].type=document.source.data",
    "anthropic/response/usage.cache_creation.ephemeral_1h_input_tokens",
    "bedrock/request/content[].video.source.bytes",
    "cohere/response/message.tool_plan",
    "cohere/response/usage.billed_units.search_units",
    "responses/request/content[].type=input_file.file_data",
    "gemini/request/parts[].inlineData.mimeType",
];

/// The artefact's own header, byte for byte. It names the generator, so it moves in the commit
/// that retires the generator it names — never in the one that rewrites it, where a `--write` would
/// bury the drift signal for this release under a diff nobody could review separately.
const COMMENT: [&str; 12] = [
    "GENERATED by cargo xtask gate field-inventory. Do not edit by hand.",
    "Regenerate:  cargo xtask gate field-inventory --write",
    "",
    "Every request and response field of every chat dialect busbar speaks.",
    "crates/busbar/tests/field_coverage.rs reads this and FAILS the build for any",
    "field that is neither CARRIED (naming a test that proves it survives the hop)",
    "nor WAIVED with a dated reason in qa/field-coverage.status.",
    "",
    "A field is CARRIED when a test proves it survives, NOT when a struct has a",
    "member for it. That distinction is the entire point: the audited losses were",
    "all in fields nothing read and nothing emitted, where there was nothing for a",
    "mutation test to break.",
];

/// One vendored schema, in the order its claims are checked.
struct Schema {
    dialect: String,
    source: String,
    retrieved: String,
    request: Vec<String>,
    response: Vec<String>,
}

impl Schema {
    fn direction(&self, d: &str) -> &[String] {
        if d == "request" {
            &self.request
        } else {
            &self.response
        }
    }
}

/// Which check refused, so the run can stop where the Python's `sys.exit` stops and report every
/// row below it as unproven rather than as a pass.
struct Refusal {
    row: &'static str,
    why: String,
}

// ── THE LOADER ───────────────────────────────────────────────────────────────────────────────────

/// Read every vendored schema, refusing anything without provenance. The order of the refusals is
/// the order the Python takes them in, per file in sorted path order, so a tree with two problems
/// reports the same one from both implementations.
fn load_schemas(cx: &Ctx) -> Result<Vec<Schema>, Refusal> {
    let files = cx
        .walk(&WalkSpec::new([SCHEMA_DIR]).ext("json").min_files(1))
        .map_err(|e| Refusal {
            row: ROW_PROVENANCE,
            why: format!("the schema directory could not be read: {e}"),
        })?;

    let mut out: Vec<Schema> = Vec::new();
    for f in &files {
        let path = f.rel_str();
        let doc: serde_json::Value = serde_json::from_str(&f.text).map_err(|e| Refusal {
            row: ROW_PROVENANCE,
            why: format!("{path}: is not JSON: {e}"),
        })?;

        for key in REQUIRED_SCHEMA_KEYS {
            if !truthy(doc.get(key)) {
                return Err(Refusal {
                    row: ROW_PROVENANCE,
                    why: format!(
                        "{path}: missing required key '{key}'. A schema without provenance is a \
                         hand-written list wearing a filename; refusing to derive from it."
                    ),
                });
            }
        }

        let dialect = doc["dialect"].as_str().unwrap_or_default().to_string();
        let stem = path
            .rsplit('/')
            .next()
            .unwrap_or_default()
            .trim_end_matches(".json")
            .to_string();
        if dialect != stem {
            return Err(Refusal {
                row: ROW_SCHEMA_IDENTITY,
                why: format!("{path}: `dialect` '{dialect}' does not match the filename"),
            });
        }
        if out.iter().any(|s| s.dialect == dialect) {
            return Err(Refusal {
                row: ROW_SCHEMA_IDENTITY,
                why: format!("{path}: duplicate dialect '{dialect}'"),
            });
        }

        let mut lists: BTreeMap<&str, Vec<String>> = BTreeMap::new();
        for direction in DIRECTIONS {
            let fields = string_list(doc.get(direction)).map_err(|why| Refusal {
                row: ROW_PROVENANCE,
                why: format!("{path}: {direction}: {why}"),
            })?;
            let mut dupes: Vec<String> = Vec::new();
            for (i, f) in fields.iter().enumerate() {
                if fields[..i].contains(f) && !dupes.contains(f) {
                    dupes.push(f.clone());
                }
            }
            if !dupes.is_empty() {
                dupes.sort();
                return Err(Refusal {
                    row: ROW_NO_DUPLICATE_FIELDS,
                    why: format!(
                        "{path}: duplicate {direction} field(s) [{}]",
                        dupes
                            .iter()
                            .map(|d| format!("'{d}'"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                });
            }
            lists.insert(direction, fields);
        }

        out.push(Schema {
            dialect,
            source: doc["source"].as_str().unwrap_or_default().to_string(),
            retrieved: doc["retrieved"].as_str().unwrap_or_default().to_string(),
            request: lists.remove("request").unwrap_or_default(),
            response: lists.remove("response").unwrap_or_default(),
        });
    }

    // SET EQUALITY, BOTH WAYS. A registered dialect with no schema loses a whole surface; a schema
    // for no registered dialect invents one.
    let have: BTreeSet<&str> = out.iter().map(|s| s.dialect.as_str()).collect();
    let want: BTreeSet<&str> = DIALECTS.into_iter().collect();
    let missing: Vec<&&str> = want.difference(&have).collect();
    if !missing.is_empty() {
        return Err(Refusal {
            row: ROW_REGISTRATION,
            why: format!("no schema for registered dialect(s): {missing:?}"),
        });
    }
    let extra: Vec<&&str> = have.difference(&want).collect();
    if !extra.is_empty() {
        return Err(Refusal {
            row: ROW_REGISTRATION,
            why: format!(
                "schema present for unregistered dialect(s) {extra:?}; add them to DIALECTS so the \
                 gate covers them, or the inventory silently excludes a whole surface"
            ),
        });
    }
    Ok(out)
}

/// Python's `if not doc.get(key)`: absent, null, `false`, `0`, `""` and `[]` are all falsy, and
/// every one of them is a schema with no provenance.
fn truthy(v: Option<&serde_json::Value>) -> bool {
    match v {
        None | Some(serde_json::Value::Null) => false,
        Some(serde_json::Value::Bool(b)) => *b,
        Some(serde_json::Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0),
        Some(serde_json::Value::String(s)) => !s.is_empty(),
        Some(serde_json::Value::Array(a)) => !a.is_empty(),
        Some(serde_json::Value::Object(o)) => !o.is_empty(),
    }
}

fn string_list(v: Option<&serde_json::Value>) -> Result<Vec<String>, String> {
    let Some(serde_json::Value::Array(items)) = v else {
        return Err("is not a list of field names".to_string());
    };
    items
        .iter()
        .map(|i| {
            i.as_str()
                .map(str::to_string)
                .ok_or_else(|| "holds a non-string entry".to_string())
        })
        .collect()
}

// ── THE DERIVATION ───────────────────────────────────────────────────────────────────────────────

struct Field {
    id: String,
    dialect: String,
    direction: &'static str,
    field: String,
    streaming: bool,
}

fn derive(schemas: &[Schema]) -> Vec<Field> {
    let mut out = Vec::new();
    for dialect in DIALECTS {
        let Some(doc) = schemas.iter().find(|s| s.dialect == dialect) else {
            continue;
        };
        for direction in DIRECTIONS {
            for field in doc.direction(direction) {
                out.push(Field {
                    id: format!("{dialect}/{direction}/{field}"),
                    dialect: dialect.to_string(),
                    direction,
                    field: field.clone(),
                    // A `stream:` prefix marks a field that exists only on the streaming surface.
                    // Its own row, not merged: "survives at stream:false and vanishes at
                    // stream:true" is a real and separately-observed defect class.
                    streaming: field.starts_with("stream:"),
                });
            }
        }
    }
    out
}

/// The artefact, byte for byte as `json.dumps(inv, indent=2) + "\n"` writes it.
fn render(schemas: &[Schema], fields: &[Field]) -> String {
    let mut s = String::from("{\n  \"_comment\": [\n");
    for (i, line) in COMMENT.iter().enumerate() {
        s.push_str("    ");
        s.push_str(&json_string(line));
        s.push_str(if i + 1 == COMMENT.len() { "\n" } else { ",\n" });
    }
    s.push_str("  ],\n  \"derived_from\": {\n");
    for (i, dialect) in DIALECTS.iter().enumerate() {
        let doc = schemas
            .iter()
            .find(|x| x.dialect == *dialect)
            .expect("every registered dialect has a schema by the time the artefact is rendered");
        s.push_str("    ");
        s.push_str(&json_string(dialect));
        s.push_str(": ");
        s.push_str(&json_string(&format!(
            "{} (retrieved {})",
            doc.source, doc.retrieved
        )));
        s.push_str(if i + 1 == DIALECTS.len() { "\n" } else { ",\n" });
    }
    s.push_str("  },\n  \"dialects\": [\n");
    for (i, d) in DIALECTS.iter().enumerate() {
        s.push_str("    ");
        s.push_str(&json_string(d));
        s.push_str(if i + 1 == DIALECTS.len() { "\n" } else { ",\n" });
    }
    s.push_str("  ],\n  \"directions\": [\n");
    for (i, d) in DIRECTIONS.iter().enumerate() {
        s.push_str("    ");
        s.push_str(&json_string(d));
        s.push_str(if i + 1 == DIRECTIONS.len() {
            "\n"
        } else {
            ",\n"
        });
    }
    s.push_str("  ],\n");
    s.push_str(&format!("  \"field_count\": {},\n", fields.len()));
    s.push_str("  \"fields\": [\n");
    for (i, f) in fields.iter().enumerate() {
        s.push_str("    {\n");
        s.push_str(&format!("      \"id\": {},\n", json_string(&f.id)));
        s.push_str(&format!(
            "      \"dialect\": {},\n",
            json_string(&f.dialect)
        ));
        s.push_str(&format!(
            "      \"direction\": {},\n",
            json_string(f.direction)
        ));
        s.push_str(&format!("      \"field\": {},\n", json_string(&f.field)));
        s.push_str(&format!("      \"streaming\": {}\n", f.streaming));
        s.push_str(if i + 1 == fields.len() {
            "    }\n"
        } else {
            "    },\n"
        });
    }
    s.push_str("  ]\n}\n");
    s
}

/// A JSON string literal the way Python's `json.dumps` writes one: `ensure_ascii=True`, so every
/// character above U+007F becomes a `\uXXXX` escape (a surrogate pair above U+FFFF).
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c if (c as u32) < 0x7f => out.push(c),
            c => {
                let mut buf = [0u16; 2];
                for unit in c.encode_utf16(&mut buf) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
        }
    }
    out.push('"');
    out
}

// ── THE ROWS ─────────────────────────────────────────────────────────────────────────────────────

fn row_ok(id: &str, title: &str, detail: String) -> Row {
    Row::pass(id, title, detail)
}

fn unproven(id: &str, why: &str) -> Row {
    Row::skip(
        id,
        "unproven — the derivation refused above this check",
        why.to_string(),
    )
}

fn row_provenance(schemas: usize) -> Row {
    row_ok(
        ROW_PROVENANCE,
        "every vendored schema carries its source and its retrieval date",
        format!("{schemas} schema(s) loaded, each with all six required keys"),
    )
}

fn row_schema_identity() -> Row {
    row_ok(
        ROW_SCHEMA_IDENTITY,
        "every schema's dialect agrees with its filename, and none repeats",
        "the schema set names each dialect exactly once".to_string(),
    )
}

fn row_no_duplicate_fields() -> Row {
    row_ok(
        ROW_NO_DUPLICATE_FIELDS,
        "no direction lists a field twice",
        "every schema's request and response lists are sets".to_string(),
    )
}

fn row_registration() -> Row {
    row_ok(
        ROW_REGISTRATION,
        "the registered dialects and the schema files are the same set",
        format!("{} dialect(s), matched both ways", DIALECTS.len()),
    )
}

fn row_both_directions(empty: &[String]) -> Row {
    if empty.is_empty() {
        row_ok(
            ROW_BOTH_DIRECTIONS,
            "every dialect enumerates both of its directions",
            "no dialect/direction pair came back empty".to_string(),
        )
    } else {
        Row::fail(
            ROW_BOTH_DIRECTIONS,
            "a dialect enumerates one of its directions as nothing",
            format!(
                "{} enumerates no fields — an enumeration of nothing reports full coverage of a \
                 surface nobody listed",
                empty.join(", ")
            ),
        )
    }
}

fn row_audited(missing: &[String]) -> Row {
    if missing.is_empty() {
        row_ok(
            ROW_AUDITED_FIELDS,
            "every field the audit found by hand is in the enumeration",
            format!("{} audited field(s) present", AUDITED.len()),
        )
    } else {
        Row::fail(
            ROW_AUDITED_FIELDS,
            "the enumeration cannot see a defect that was found by hand",
            format!(
                "audited field(s) not in the enumeration: {} — if it cannot see those, it cannot \
                 see the ones nobody found",
                missing.join(", ")
            ),
        )
    }
}

fn row_artifact(count: Option<usize>, why: Option<&str>) -> Row {
    match why {
        None => row_ok(
            ROW_ARTIFACT_DRIFT,
            "the committed inventory is the fresh derivation",
            format!("{OUT} is up to date ({} fields)", count.unwrap_or_default()),
        ),
        Some(why) => Row::fail(
            ROW_ARTIFACT_DRIFT,
            "the committed inventory is not what the schemas derive",
            why.to_string(),
        ),
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
        let schemas = match load_schemas(cx) {
            Ok(s) => s,
            Err(refusal) => {
                // The loader refuses at its FIRST problem, exactly where the Python's `sys.exit`
                // stops, so every row below it DID NOT RUN rather than passing over a schema set
                // nobody managed to read.
                let mut rows = vec![Row::fail(
                    refusal.row,
                    "the vendored schema set was refused",
                    refusal.why.clone(),
                )];
                for id in self.owed() {
                    if id != refusal.row {
                        rows.push(unproven(
                            &id,
                            "the schema set was refused, so nothing was derived from it",
                        ));
                    }
                }
                return Verdict::of(rows);
            }
        };

        let fields = derive(&schemas);

        let mut empty: Vec<String> = Vec::new();
        for dialect in DIALECTS {
            for direction in DIRECTIONS {
                if !fields
                    .iter()
                    .any(|f| f.dialect == dialect && f.direction == direction)
                {
                    empty.push(format!("{dialect}/{direction}"));
                }
            }
        }

        let have: BTreeSet<&str> = fields.iter().map(|f| f.id.as_str()).collect();
        let missing: Vec<String> = AUDITED
            .iter()
            .filter(|a| !have.contains(*a))
            .map(|a| (*a).to_string())
            .collect();

        let text = render(&schemas, &fields);
        let artifact = if cx.env().write {
            match std::fs::write(cx.abs(OUT), &text) {
                Ok(()) => row_ok(
                    ROW_ARTIFACT_DRIFT,
                    "the committed inventory is the fresh derivation",
                    format!("{OUT} is up to date ({} fields)", fields.len()),
                ),
                Err(e) => row_artifact(None, Some(&format!("{OUT} could not be written: {e}"))),
            }
        } else {
            match cx.read(OUT) {
                Err(_) => row_artifact(
                    None,
                    Some(&format!(
                        "{OUT} is missing; run cargo xtask gate field-inventory --write"
                    )),
                ),
                Ok(current) if current != text => row_artifact(
                    None,
                    Some(&format!(
                        "{OUT} is STALE; run cargo xtask gate field-inventory --write"
                    )),
                ),
                Ok(_) => row_artifact(Some(fields.len()), None),
            }
        };

        Verdict::of(vec![
            row_provenance(schemas.len()),
            row_schema_identity(),
            row_no_duplicate_fields(),
            row_registration(),
            row_both_directions(&empty),
            row_audited(&missing),
            artifact,
        ])
    }

    fn has_legacy_adapter(&self) -> bool {
        true
    }

    fn legacy_rows(&self, _cx: &Ctx, runs: &[LegacyRun]) -> Option<Result<Vec<Row>, String>> {
        let run = &runs[0];
        Some(translate(run))
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();
        let owed = self.owed();
        let all: Vec<&str> = owed.iter().map(String::as_str).collect();

        report.push(prove_green(
            cx,
            self,
            "the six vendored schemas derive the committed inventory exactly",
            &all,
        ));

        // ── THE PROVENANCE REFUSAL, ONE DROPPED KEY AT A TIME, THROUGH THE REAL LOADER. This is
        //    the case whose Python ancestor restated the guard's condition and stayed green with
        //    the guard cut out.
        for key in REQUIRED_SCHEMA_KEYS {
            report.push(prove_red(
                cx,
                self,
                format!("a schema with no '{key}' is refused, not derived from"),
                &[ROW_PROVENANCE],
                mutate(cx, "openai", &|doc| {
                    doc.as_object_mut().map(|o| o.remove(key));
                }),
                &[&format!("missing required key '{key}'")],
            ));
        }

        // ── AN EMPTY LIST IS NOT A SCHEMA. An enumeration of nothing reports full coverage of a
        //    surface nobody listed, and it is `if not doc.get(key)` — not a separate rule — that
        //    catches it, which is why it is proven here rather than assumed.
        for key in ["request", "response"] {
            report.push(prove_red(
                cx,
                self,
                format!("a schema whose '{key}' list is EMPTY is refused"),
                &[ROW_PROVENANCE, ROW_BOTH_DIRECTIONS],
                mutate(cx, "openai", &|doc| {
                    doc[key] = serde_json::Value::Array(Vec::new());
                }),
                &[&format!("missing required key '{key}'")],
            ));
        }

        report.push(prove_red(
            cx,
            self,
            "a duplicated field in a schema is refused",
            &[ROW_NO_DUPLICATE_FIELDS],
            mutate(cx, "openai", &|doc| {
                let first = doc["request"][0].clone();
                doc["request"].as_array_mut().expect("a list").push(first);
            }),
            &["duplicate request field"],
        ));

        report.push(prove_red(
            cx,
            self,
            "a schema whose dialect disagrees with its filename is refused",
            &[ROW_SCHEMA_IDENTITY],
            mutate(cx, "openai", &|doc| {
                doc["dialect"] = serde_json::Value::String("not-openai".to_string());
            }),
            &["does not match the filename"],
        ));

        // ── A REGISTERED DIALECT WHOSE SCHEMA WENT MISSING. The whole surface would leave the
        //    inventory, and an absent surface looks exactly like a covered one.
        let mut ov = Overlay::new();
        ov.remove(format!("{SCHEMA_DIR}/openai.json"));
        report.push(prove_red(
            cx,
            self,
            "a registered dialect whose schema file is gone is refused",
            &[ROW_REGISTRATION],
            ov,
            &["no schema for registered dialect"],
        ));

        // ── AND THE OTHER DIRECTION: a schema file for a dialect nobody registered.
        let mut ov = Overlay::new();
        ov.set(
            format!("{SCHEMA_DIR}/mistral.json"),
            "{\"dialect\":\"mistral\",\"surface\":\"POST /v1/chat\",\"source\":\"https://example\
             .invalid\",\"retrieved\":\"2026-09-07\",\"request\":[\"model\"],\"response\":\
             [\"id\"]}\n",
        );
        report.push(prove_red(
            cx,
            self,
            "a schema for an unregistered dialect is refused, not silently excluded",
            &[ROW_REGISTRATION],
            ov,
            &["unregistered dialect"],
        ));

        // ── THE AUDITED FIELDS. Deleting one from its schema must be a named finding: the eleven
        //    are the only proof the enumeration can see what a human found.
        report.push(prove_red(
            cx,
            self,
            "an audited field dropped from its schema is a named finding",
            &[ROW_AUDITED_FIELDS, ROW_ARTIFACT_DRIFT],
            mutate(cx, "cohere", &|doc| {
                let keep: Vec<serde_json::Value> = doc["response"]
                    .as_array()
                    .expect("a list")
                    .iter()
                    .filter(|v| v.as_str() != Some("message.tool_plan"))
                    .cloned()
                    .collect();
                doc["response"] = serde_json::Value::Array(keep);
            }),
            &["cohere/response/message.tool_plan"],
        ));

        // ── THE DRIFT SIGNAL ITSELF. A committed artefact that is not the derivation is the whole
        //    reason this file is generated rather than maintained.
        let mut ov = Overlay::new();
        ov.set(
            OUT,
            cx.read(OUT)
                .unwrap_or_default()
                .replace("\"field_count\": ", "\"field_count\": 1, \"_planted\": "),
        );
        report.push(prove_red(
            cx,
            self,
            "a committed inventory that is not the derivation is STALE",
            &[ROW_ARTIFACT_DRIFT],
            ov,
            &["is STALE"],
        ));

        report
    }
}

/// One schema, mutated. Built from what the gate would otherwise READ, so the case is expressed
/// against the real file rather than against a hand-written copy of it.
fn mutate(cx: &Ctx, dialect: &str, f: &dyn Fn(&mut serde_json::Value)) -> Overlay {
    let mut ov = Overlay::new();
    let path = format!("{SCHEMA_DIR}/{dialect}.json");
    let mut doc: serde_json::Value = match cx.read(&path).map(|t| serde_json::from_str(&t)) {
        Ok(Ok(v)) => v,
        _ => serde_json::Value::Null,
    };
    f(&mut doc);
    ov.set(path, serde_json::to_string(&doc).unwrap_or_default());
    ov
}

// ── THE LEGACY TRANSLATOR ────────────────────────────────────────────────────────────────────────

/// Read `scripts/field-inventory.py`'s own output into the rows this gate would emit for the same
/// tree. The Python makes four of these claims only in `--selftest` and the other four only in
/// `--check`, so the parity run is given BOTH — which is also exactly how `ci.yml` invokes it.
fn translate(run: &LegacyRun) -> Result<Vec<Row>, String> {
    let lines: Vec<&str> = run.lines().collect();
    let says = |needle: &str| lines.iter().any(|l| l.contains(needle));

    // A refusal in the loader stops the Python before anything else runs; the first one that
    // matches is the one both sides report.
    let refusal = lines.iter().find_map(|l| {
        for (needle, row) in [
            ("missing required key", ROW_PROVENANCE),
            ("does not match the filename", ROW_SCHEMA_IDENTITY),
            ("duplicate dialect", ROW_SCHEMA_IDENTITY),
            ("duplicate request field", ROW_NO_DUPLICATE_FIELDS),
            ("duplicate response field", ROW_NO_DUPLICATE_FIELDS),
            ("no schema for registered dialect", ROW_REGISTRATION),
            ("schema present for unregistered dialect", ROW_REGISTRATION),
        ] {
            if l.contains(needle) {
                return Some((row, (*l).to_string()));
            }
        }
        None
    });

    let mut rows = Vec::new();
    if let Some((row, why)) = refusal {
        rows.push(Row::fail(
            row,
            "the vendored schema set was refused",
            why.replace("\"", "'"),
        ));
        for id in [
            ROW_PROVENANCE,
            ROW_SCHEMA_IDENTITY,
            ROW_NO_DUPLICATE_FIELDS,
            ROW_REGISTRATION,
            ROW_BOTH_DIRECTIONS,
            ROW_AUDITED_FIELDS,
            ROW_ARTIFACT_DRIFT,
        ] {
            if id != row {
                rows.push(unproven(
                    id,
                    "the schema set was refused, so nothing was derived from it",
                ));
            }
        }
        return Ok(rows);
    }

    let selftest_ran = says("selftest: PASS") || says("selftest: FAIL");
    let check_line = lines
        .iter()
        .find(|l| l.contains(OUT) && l.contains("is up to date"));
    if !selftest_ran || (check_line.is_none() && !says("is STALE") && !says("is missing")) {
        return Err(format!(
            "the legacy translator recognised neither a self-test verdict nor a drift verdict in \
             `{}`'s output. Silence read as eight passing claims is the defect this gate exists \
             for. stdout: {}",
            run.argv.join(" "),
            run.stdout.trim()
        ));
    }

    // The schema count the Python never prints: it loaded every registered dialect, or one of the
    // refusals above would have fired.
    rows.push(row_provenance(DIALECTS.len()));
    rows.push(row_schema_identity());
    rows.push(row_no_duplicate_fields());
    rows.push(row_registration());

    let empty: Vec<String> = lines
        .iter()
        .filter(|l| l.contains("enumerates no fields"))
        .filter_map(|l| l.split_whitespace().nth(2).map(str::to_string))
        .collect();
    rows.push(row_both_directions(&empty));

    let missing: Vec<String> = lines
        .iter()
        .filter(|l| l.contains("is not in the enumeration"))
        .filter_map(|l| {
            l.split('\'')
                .nth(1)
                .map(str::to_string)
                .or_else(|| l.split('"').nth(1).map(str::to_string))
        })
        .collect();
    rows.push(row_audited(&missing));

    match check_line {
        Some(line) => {
            let count = line
                .split('(')
                .nth(1)
                .and_then(|t| t.split_whitespace().next())
                .and_then(|n| n.parse::<usize>().ok());
            rows.push(row_artifact(count, None));
        }
        None => rows.push(row_artifact(
            None,
            Some(&format!(
                "{OUT} is STALE; run cargo xtask gate field-inventory --write"
            )),
        )),
    }
    Ok(rows)
}
