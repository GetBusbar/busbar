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
    serde_yaml::from_str::<Json>(text)
        .map(|j| j.0)
        .map_err(|e| format!("{path}: {e}"))
}

/// A YAML document read straight into a JSON value. Not through `serde_yaml::Value`: that type
/// refuses an integer outside i64/u64, and the OpenAI spec writes `seed.minimum` as
/// -9223372036854776000. A JSON number cannot hold that without rounding, so an integer outside
/// i64/u64 is kept as the string of its exact digits; nothing is ever rounded.
struct Json(Value);

impl<'de> serde::Deserialize<'de> for Json {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Json, D::Error> {
        d.deserialize_any(JsonVisitor).map(Json)
    }
}

struct JsonVisitor;

fn float(f: f64) -> Value {
    serde_json::Number::from_f64(f).map_or(Value::Null, Value::Number)
}

impl<'de> serde::de::Visitor<'de> for JsonVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("any YAML value")
    }
    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(Value::from(v))
    }
    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(Value::from(v))
    }
    fn visit_i128<E>(self, v: i128) -> Result<Value, E> {
        Ok(i64::try_from(v).map_or_else(|_| Value::String(v.to_string()), Value::from))
    }
    fn visit_u128<E>(self, v: u128) -> Result<Value, E> {
        Ok(u64::try_from(v).map_or_else(|_| Value::String(v.to_string()), Value::from))
    }
    fn visit_f64<E>(self, v: f64) -> Result<Value, E> {
        Ok(float(v))
    }
    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_string()))
    }
    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }
    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_some<D: serde::Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        d.deserialize_any(JsonVisitor)
    }
    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut out = Vec::new();
        while let Some(Json(v)) = seq.next_element()? {
            out.push(v);
        }
        Ok(Value::Array(out))
    }
    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut out = serde_json::Map::new();
        while let Some((Json(k), Json(v))) = map.next_entry()? {
            let key = match k {
                Value::String(s) => s,
                other => other.to_string(),
            };
            out.insert(key, v);
        }
        Ok(Value::Object(out))
    }
}
