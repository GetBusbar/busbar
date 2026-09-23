//! JSON first, table second.
//!
//! A gate reads the JSON; a person reads the table; NEITHER reads a single number. Every scope
//! prints all five buckets, because "surface = 63,070" with no `test` figure beside it is exactly
//! how a crate that is 64% proofs got sized in a design document as though it were production.

use serde_json::{json, Map, Value};

use super::{Counts, Report};

fn counts_json(c: &Counts) -> Value {
    json!({
        "code": c.code,
        "doc": c.doc,
        "comment": c.comment,
        "blank": c.blank,
        "test": c.test,
        "total": c.total(),
    })
}

/// The whole report, as one deterministic JSON document.
///
/// `serde_json::Map` is a `BTreeMap` in this build, and every vector below is already sorted, so
/// the same tree gives byte-identical bytes — which is the only thing that makes a checked-in
/// baseline worth having.
pub fn json(report: &Report, per_file: bool) -> String {
    let mut definition = Map::new();
    for (bucket, meaning) in super::classify::DEFINITION {
        definition.insert(bucket.to_string(), Value::String(meaning.to_string()));
    }

    let crates: Vec<Value> = report
        .crates
        .iter()
        .map(|(name, c)| {
            let mut o = Map::new();
            o.insert("crate".into(), Value::String(name.clone()));
            merge(&mut o, counts_json(c));
            Value::Object(o)
        })
        .collect();

    let groups: Vec<Value> = report
        .groups
        .iter()
        .map(|g| {
            json!({
                "group": g.name,
                "label": g.label,
                "crates": g.crates,
                "missing": g.missing,
                "inside": counts_json(&g.inside),
                "outside": counts_json(&g.outside),
            })
        })
        .collect();

    let errors: Vec<Value> = report
        .errors
        .iter()
        .map(|e| json!({ "path": e.path, "crate": e.krate, "error": e.error }))
        .collect();

    let mut doc = Map::new();
    doc.insert("source".into(), Value::String(report.source.clone()));
    doc.insert(
        "definition".into(),
        Value::Object({
            let mut m = Map::new();
            m.insert(
                "order".into(),
                json!(["blank", "doc", "comment", "test", "code"]),
            );
            m.insert("buckets".into(), Value::Object(definition));
            m
        }),
    );
    doc.insert("total".into(), counts_json(&report.total));
    doc.insert("crates".into(), Value::Array(crates));
    doc.insert("groups".into(), Value::Array(groups));
    doc.insert("errors".into(), Value::Array(errors));
    if per_file {
        doc.insert(
            "files".into(),
            Value::Array(
                report
                    .files
                    .iter()
                    .map(|f| {
                        let mut o = Map::new();
                        o.insert("path".into(), Value::String(f.path.clone()));
                        o.insert("crate".into(), Value::String(f.krate.clone()));
                        merge(&mut o, counts_json(&f.counts));
                        Value::Object(o)
                    })
                    .collect(),
            ),
        );
    }
    serde_json::to_string_pretty(&Value::Object(doc))
        .unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
}

fn merge(into: &mut Map<String, Value>, from: Value) {
    if let Value::Object(m) = from {
        for (k, v) in m {
            into.insert(k, v);
        }
    }
}

/// The human render. Same numbers, same order, no extra opinion.
pub fn table(report: &Report, per_file: bool) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "== cargo xtask loc — source {} ==\n",
        report.source
    ));
    out.push_str("buckets, in precedence order (every line lands in exactly one):\n");
    for (bucket, meaning) in super::classify::DEFINITION {
        out.push_str(&format!("  {bucket:<8} {meaning}\n"));
    }
    out.push('\n');

    let width = report
        .crates
        .iter()
        .map(|(n, _)| n.len())
        .chain(std::iter::once("crate".len()))
        .max()
        .unwrap_or(10);
    out.push_str(&header(width, "crate"));
    for (name, c) in &report.crates {
        out.push_str(&row(width, name, c));
        if per_file {
            for f in report.files.iter().filter(|f| &f.krate == name) {
                out.push_str(&row(width, &format!("  {}", f.path), &f.counts));
            }
        }
    }
    out.push_str(&rule(width));
    out.push_str(&row(width, "TOTAL", &report.total));

    for g in &report.groups {
        out.push('\n');
        out.push_str(&format!("group `{}` — {}\n", g.name, g.label));
        if !g.missing.is_empty() {
            out.push_str(&format!(
                "  NAMES CRATES THIS TREE DOES NOT HAVE: {}\n",
                g.missing.join(", ")
            ));
        }
        out.push_str(&header(width, "scope"));
        out.push_str(&row(width, "inside", &g.inside));
        out.push_str(&row(width, "excluding", &g.outside));
    }

    if !report.errors.is_empty() {
        out.push_str(&format!("\n{} FILE(S) NOT COUNTED:\n", report.errors.len()));
        for e in &report.errors {
            out.push_str(&format!("  {} — {}\n", e.path, e.error));
        }
    }
    out
}

fn header(width: usize, first: &str) -> String {
    format!(
        "{first:<width$}  {:>9}  {:>7}  {:>7}  {:>7}  {:>9}  {:>9}\n{}",
        "code",
        "doc",
        "comment",
        "blank",
        "test",
        "total",
        rule(width)
    )
}

fn rule(width: usize) -> String {
    format!(
        "{}  {}  {}  {}  {}  {}  {}\n",
        "-".repeat(width),
        "-".repeat(9),
        "-".repeat(7),
        "-".repeat(7),
        "-".repeat(7),
        "-".repeat(9),
        "-".repeat(9)
    )
}

fn row(width: usize, name: &str, c: &Counts) -> String {
    format!(
        "{name:<width$}  {:>9}  {:>7}  {:>7}  {:>7}  {:>9}  {:>9}\n",
        c.code,
        c.doc,
        c.comment,
        c.blank,
        c.test,
        c.total()
    )
}
