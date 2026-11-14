//! busbar-yaml reads the product's YAML exactly as serde_yaml_ng 0.10.0 (libyaml) did.
//!
//! `fixtures/serde_yaml_ng-0.10.0-config-surface.jsonl` was recorded with serde_yaml_ng 0.10.0 on
//! unsafe-libyaml 0.2.11, the YAML stack busbar 1.5.5 and 1.6.0 shipped, before it was replaced.
//! Its inputs are the 1.5.5 oracle's whole config surface (every config, providers file and admin
//! body in `testing/shadow-oracle/cells.json` and its fixtures, the boot refusal mutations
//! included), every YAML file the repository reads or ships (configs, examples, the migration and
//! back-compat corpora, test fixtures), and 400 seeded random corruptions of oracle configs, so
//! invalid YAML is covered too. For each input it holds what `from_str::<Value>` returned (a
//! SHA-256 of the value's `Debug` form and of its `to_string` re-serialization) or the error's
//! full text and location, and the same for every document `Deserializer::from_str` yields when
//! there are several.
//!
//! The inputs are stored in the fixture, not read from the tree, so the record stays valid when
//! the repository's own files change.

use serde::Deserialize;
use sha2::{Digest, Sha256};

fn digest(s: &str) -> String {
    Sha256::digest(s.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn outcome(r: Result<busbar_yaml::Value, busbar_yaml::Error>) -> serde_json::Value {
    match r {
        Ok(v) => serde_json::json!({
            "value": digest(&format!("{v:?}")),
            "yaml": match busbar_yaml::to_string(&v) {
                Ok(y) => serde_json::Value::String(digest(&y)),
                Err(e) => serde_json::json!({ "error": e.to_string() }),
            },
        }),
        Err(e) => serde_json::json!({
            "error": e.to_string(),
            "location": e.location().map(|l| vec![l.line(), l.column(), l.index()]),
        }),
    }
}

#[test]
fn every_recorded_input_reads_as_serde_yaml_ng_0_10_read_it() {
    let fixture = include_str!("fixtures/serde_yaml_ng-0.10.0-config-surface.jsonl");
    let mut checked = 0;
    let mut refusals = 0;
    let mut failures = Vec::new();
    for line in fixture.lines() {
        let record: serde_json::Value = serde_json::from_str(line).expect("a fixture record");
        let name = record["name"].as_str().expect("a name");
        let input = record["input"].as_str().expect("an input");
        let whole = outcome(busbar_yaml::from_str::<busbar_yaml::Value>(input));
        if whole != record["whole"] {
            failures.push(format!(
                "{name}: from_str: expected {} got {whole}",
                record["whole"]
            ));
        }
        if whole.get("error").is_some() {
            refusals += 1;
        }
        let mut documents = Vec::new();
        for (i, de) in busbar_yaml::Deserializer::from_str(input).enumerate() {
            if i >= 64 {
                break;
            }
            let r = outcome(busbar_yaml::Value::deserialize(de));
            let failed = r.get("error").is_some();
            documents.push(r);
            if failed {
                break;
            }
        }
        let expected = match record.get("documents") {
            Some(d) => d.clone(),
            None => serde_json::Value::Array(vec![record["whole"].clone()]),
        };
        if serde_json::Value::Array(documents.clone()) != expected {
            failures.push(format!(
                "{name}: documents: expected {expected} got {documents:?}"
            ));
        }
        checked += 1;
    }
    assert!(
        checked > 1000,
        "the fixture holds the config surface ({checked} records)"
    );
    assert!(refusals > 300, "and refusals of invalid YAML ({refusals})");
    assert!(
        failures.is_empty(),
        "{} of {checked} inputs differ:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
