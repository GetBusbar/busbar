//! THE PINNED SPECS, read through the one home that already fetches and verifies them:
//! `testing/llm-conformance/vendor.sh`. Its `--check` measures every cached file's digest against
//! `spec-digests.tsv` (raw sha256, or the canonical-JSON digest for the vendored Gemini document)
//! and its `--paths` names the cache file, so this module neither re-implements a digest format nor
//! learns the cache layout. When the cache is cold, plain `vendor.sh` fetches (or copies the
//! committed vendored copy) and refuses any digest mismatch; nothing here reads an unverified byte.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::ctx::Ctx;

pub const DIGESTS: &str = "testing/llm-conformance/spec-digests.tsv";
const VENDOR: &str = "testing/llm-conformance/vendor.sh";

/// One `spec-digests.tsv` row: the spec name, its digest format and the pinned digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pin {
    pub format: String,
    pub sha256: String,
}

/// Every pinned spec, by name. Rows are tab-separated; `#` lines are prose.
pub fn pins(cx: &Ctx) -> Result<BTreeMap<String, Pin>, String> {
    let text = cx.read(DIGESTS)?;
    let mut out = BTreeMap::new();
    for line in text.lines().filter(|l| !l.starts_with('#')) {
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() < 4 {
            continue;
        }
        out.insert(
            cols[0].to_string(),
            Pin {
                format: cols[1].to_string(),
                sha256: cols[2].to_string(),
            },
        );
    }
    if out.is_empty() {
        return Err(format!("{DIGESTS} pins no spec"));
    }
    Ok(out)
}

fn vendor(cx: &Ctx, arg: Option<&str>) -> Result<String, String> {
    let mut args = vec![VENDOR.to_string()];
    args.extend(arg.map(str::to_string));
    cx.run_checked("bash", &args)
}

/// The verified cache file of every pinned spec. Fetches when the cache is cold or wrong.
pub fn verified_paths(cx: &Ctx) -> Result<BTreeMap<String, String>, String> {
    if vendor(cx, Some("--check")).is_err() {
        vendor(cx, None).map_err(|e| {
            format!("the pinned provider specs could not be fetched and verified: {e}")
        })?;
    }
    let listing = vendor(cx, Some("--paths"))?;
    Ok(listing
        .lines()
        .filter_map(|l| l.split_once('\t'))
        .map(|(s, p)| (s.to_string(), p.to_string()))
        .collect())
}

/// Parse a spec document: JSON as-is, YAML through `serde_yaml` into the same value shape.
pub fn parse(path: &str, text: &str) -> Result<Value, String> {
    if path.ends_with(".json") {
        return serde_json::from_str(text).map_err(|e| format!("{path}: {e}"));
    }
    let y: serde_yaml::Value = serde_yaml::from_str(text).map_err(|e| format!("{path}: {e}"))?;
    yaml_to_json(y).map_err(|e| format!("{path}: {e}"))
}

fn yaml_key(k: serde_yaml::Value) -> Result<String, String> {
    match k {
        serde_yaml::Value::String(s) => Ok(s),
        serde_yaml::Value::Number(n) => Ok(n.to_string()),
        serde_yaml::Value::Bool(b) => Ok(b.to_string()),
        other => Err(format!("unsupported mapping key {other:?}")),
    }
}

fn yaml_to_json(y: serde_yaml::Value) -> Result<Value, String> {
    Ok(match y {
        serde_yaml::Value::Null => Value::Null,
        serde_yaml::Value::Bool(b) => Value::Bool(b),
        serde_yaml::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::from(i)
            } else if let Some(u) = n.as_u64() {
                Value::from(u)
            } else {
                n.as_f64()
                    .and_then(serde_json::Number::from_f64)
                    .map_or(Value::Null, Value::Number)
            }
        }
        serde_yaml::Value::String(s) => Value::String(s),
        serde_yaml::Value::Sequence(seq) => Value::Array(
            seq.into_iter()
                .map(yaml_to_json)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        serde_yaml::Value::Mapping(m) => {
            let mut out = serde_json::Map::new();
            for (k, v) in m {
                out.insert(yaml_key(k)?, yaml_to_json(v)?);
            }
            Value::Object(out)
        }
        serde_yaml::Value::Tagged(t) => {
            let t = *t;
            yaml_to_json(t.value)?
        }
    })
}
