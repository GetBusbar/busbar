//! `cargo xtask dialect wire` — THE WIRE LOCKS (DIALECT-SCHEMA design C, stage S1).
//!
//! Every request, response and stream path of every chat dialect, with its type, enum values,
//! union tags and stream event names, GENERATED from the provider specs pinned by digest in
//! `testing/llm-conformance/spec-digests.tsv` and committed as
//! `testing/llm-conformance/wire/<dialect>.wire.json`. The lock is the one home of "what the
//! provider's wire has": the hand-written mapping files check their rows against it, and the
//! field-coverage gate reads its denominator from it.
//!
//! ```text
//! cargo xtask dialect wire [--write | --diff] <dialect|all>
//! cargo xtask dialect wire --diff-files <old.wire.json> <new.wire.json>
//! ```
//!
//! * default: regenerate in memory and require the committed locks (and the generated
//!   `qa/field-inventory.json`) to be byte-identical; a stale lock prints its diff and exits 1.
//! * `--write`: regenerate, print the diff against the committed lock, write.
//! * `--diff`: print the diff only. This is the maintenance tool after `vendor.sh --repin`:
//!   REMOVED, ADDED, probable RENAME (same parent, same type) and enum/tag values gained or lost.
//!
//! Output is deterministic: paths sort, values sort, one path per line.

mod adapters;
pub mod diff;
pub mod spec;
mod walk;

use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::ctx::Ctx;
pub use diff::Change;
pub use walk::Entry;
use walk::{Adapter, Handle};

pub const LOCK_DIR: &str = "testing/llm-conformance/wire";
/// The oracle corpus's view of the locks (ARCHITECT ruling 2026-10-01): which dialects exist and
/// which of them stream. GENERATED from the locks; the paths live only in the locks.
pub const INVENTORY: &str = "qa/field-inventory.json";

pub const DIRECTIONS: [&str; 3] = ["request", "response", "stream"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    OpenApi,
    Discovery,
    Botocore,
}

impl Format {
    pub fn label(self) -> &'static str {
        match self {
            Format::OpenApi => "openapi-3.1",
            Format::Discovery => "google-discovery",
            Format::Botocore => "botocore",
        }
    }
}

/// One dialect: the spec row it reads and the root of each direction in that document.
pub struct Dialect {
    pub name: &'static str,
    pub spec: &'static str,
    pub format: Format,
    /// request, response, stream (absent: the dialect streams frames of its response schema).
    pub roots: [Option<&'static str>; 3],
}

macro_rules! oas {
    ($n:literal) => {
        Some(concat!("#/components/schemas/", $n))
    };
}

/// THE DIALECT REGISTER. Order is the order of `qa/field-inventory.json`'s `dialects`.
pub const DIALECTS: [Dialect; 6] = [
    Dialect {
        name: "anthropic",
        spec: "anthropic",
        format: Format::OpenApi,
        roots: [
            oas!("CreateMessageParams"),
            oas!("Message"),
            oas!("MessageStreamEvent"),
        ],
    },
    Dialect {
        name: "openai",
        spec: "openai",
        format: Format::OpenApi,
        roots: [
            oas!("CreateChatCompletionRequest"),
            oas!("CreateChatCompletionResponse"),
            oas!("CreateChatCompletionStreamResponse"),
        ],
    },
    Dialect {
        name: "responses",
        spec: "openai",
        format: Format::OpenApi,
        roots: [
            oas!("CreateResponse"),
            oas!("Response"),
            oas!("ResponseStreamEvent"),
        ],
    },
    Dialect {
        name: "gemini",
        spec: "gemini",
        format: Format::Discovery,
        // streamGenerateContent frames are GenerateContentResponse: no stream section.
        roots: [
            Some("GenerateContentRequest"),
            Some("GenerateContentResponse"),
            None,
        ],
    },
    Dialect {
        name: "bedrock",
        spec: "bedrock",
        format: Format::Botocore,
        roots: [
            Some("ConverseRequest"),
            Some("ConverseResponse"),
            Some("ConverseStreamOutput"),
        ],
    },
    Dialect {
        name: "cohere",
        spec: "cohere",
        format: Format::OpenApi,
        // /v2/chat's request body is inline in the path item, not a named component.
        roots: [
            Some("#/paths/~1v2~1chat/post/requestBody/content/application~1json/schema"),
            oas!("ChatResponseV2"),
            oas!("StreamedChatResponseV2"),
        ],
    },
];

pub fn dialect(name: &str) -> Option<&'static Dialect> {
    DIALECTS.iter().find(|d| d.name == name)
}

pub fn lock_path(name: &str) -> String {
    format!("{LOCK_DIR}/{name}.wire.json")
}

/// One dialect's lock, in memory.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Lock {
    pub dialect: String,
    pub spec: String,
    pub format: String,
    pub sha256: String,
    pub roots: BTreeMap<String, String>,
    pub dirs: BTreeMap<String, BTreeMap<String, Entry>>,
}

fn entry_json(e: &Entry) -> Value {
    let mut m = serde_json::Map::new();
    m.insert("type".into(), Value::String(e.ty.clone()));
    if !e.enums.is_empty() {
        m.insert("enum".into(), Value::Array(e.enums.clone()));
    }
    if !e.tags.is_empty() {
        m.insert("tags".into(), json!(e.tags));
    }
    if let Some(t) = &e.tag {
        m.insert("tag".into(), Value::String(t.clone()));
    }
    if e.arm {
        m.insert("arm".into(), Value::Bool(true));
    }
    Value::Object(m)
}

fn q(s: &str) -> String {
    Value::String(s.to_string()).to_string()
}

impl Lock {
    /// The committed bytes: header members first, then one path per line per direction.
    pub fn render(&self) -> String {
        let mut spec = serde_json::Map::new();
        spec.insert("format".into(), Value::String(self.format.clone()));
        spec.insert("name".into(), Value::String(self.spec.clone()));
        spec.insert("sha256".into(), Value::String(self.sha256.clone()));
        for (k, v) in &self.roots {
            spec.insert(k.clone(), Value::String(v.clone()));
        }
        let mut s = String::from("{\n");
        s.push_str(&format!("  \"dialect\": {},\n", q(&self.dialect)));
        s.push_str(&format!(
            "  \"generated_by\": {},\n",
            q("cargo xtask dialect wire --write; do not edit by hand")
        ));
        s.push_str(&format!("  \"spec\": {}", Value::Object(spec)));
        for dir in DIRECTIONS {
            let Some(paths) = self.dirs.get(dir) else {
                continue;
            };
            s.push_str(&format!(",\n  {}: {{\n", q(dir)));
            let n = paths.len();
            for (i, (p, e)) in paths.iter().enumerate() {
                s.push_str(&format!(
                    "    {}: {}{}\n",
                    q(p),
                    entry_json(e),
                    if i + 1 == n { "" } else { "," }
                ));
            }
            s.push_str("  }");
        }
        s.push_str("\n}\n");
        s
    }

    pub fn parse(text: &str) -> Result<Lock, String> {
        let v: Value = serde_json::from_str(text).map_err(|e| format!("not JSON: {e}"))?;
        let s = |k: &str| {
            v.get(k)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        let spec = v.get("spec").cloned().unwrap_or(Value::Null);
        let ss = |k: &str| {
            spec.get(k)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        let mut lock = Lock {
            dialect: s("dialect"),
            spec: ss("name"),
            format: ss("format"),
            sha256: ss("sha256"),
            ..Lock::default()
        };
        for dir in DIRECTIONS {
            if let Some(r) = spec.get(dir).and_then(Value::as_str) {
                lock.roots.insert(dir.to_string(), r.to_string());
            }
            let Some(paths) = v.get(dir).and_then(Value::as_object) else {
                continue;
            };
            let mut out = BTreeMap::new();
            for (p, e) in paths {
                let strs = |k: &str| -> Vec<String> {
                    e.get(k)
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                };
                out.insert(
                    p.clone(),
                    Entry {
                        ty: e
                            .get("type")
                            .and_then(Value::as_str)
                            .ok_or_else(|| format!("{dir} path `{p}` has no type"))?
                            .to_string(),
                        enums: e
                            .get("enum")
                            .and_then(Value::as_array)
                            .cloned()
                            .unwrap_or_default(),
                        tags: strs("tags"),
                        tag: e.get("tag").and_then(Value::as_str).map(str::to_string),
                        arm: e.get("arm") == Some(&Value::Bool(true)),
                    },
                );
            }
            lock.dirs.insert(dir.to_string(), out);
        }
        Ok(lock)
    }

    /// Does this lock have a stream section (the dialect's stream is not its response schema)?
    pub fn streams(&self) -> bool {
        self.dirs.get("stream").is_some_and(|d| !d.is_empty())
    }
}

/// `qa/field-inventory.json`, derived from the locks in [`DIALECTS`] order.
pub fn render_inventory(locks: &[Lock]) -> String {
    let streaming: Vec<Value> = locks
        .iter()
        .filter(|l| l.streams())
        .map(|l| json!({"dialect": l.dialect, "streaming": true}))
        .collect();
    let doc = json!({
        "_comment": [
            "GENERATED by cargo xtask dialect wire --write from testing/llm-conformance/wire/*.wire.json. Do not edit by hand.",
            "The shadow-oracle corpus reads `dialects` and which dialects stream; every wire path lives in the locks."
        ],
        "derived_from": format!("{LOCK_DIR}/*.wire.json"),
        "dialects": locks.iter().map(|l| l.dialect.clone()).collect::<Vec<_>>(),
        "fields": streaming,
    });
    let mut s = serde_json::to_string_pretty(&doc).unwrap_or_default();
    s.push('\n');
    s
}

/// Read every committed lock, in [`DIALECTS`] order.
pub fn committed(cx: &Ctx) -> Result<Vec<Lock>, String> {
    DIALECTS
        .iter()
        .map(|d| {
            let path = lock_path(d.name);
            Lock::parse(&cx.read(&path)?).map_err(|e| format!("{path}: {e}"))
        })
        .collect()
}

/// Generate the locks named, from the verified spec cache.
pub fn generate(cx: &Ctx, names: &[&str]) -> Result<Vec<Lock>, String> {
    let paths = spec::verified_paths(cx)?;
    let pins = spec::pins(cx)?;
    let mut docs: BTreeMap<&str, Value> = BTreeMap::new();
    let mut out = Vec::new();
    for name in names {
        let d = dialect(name).ok_or_else(|| format!("unknown dialect `{name}`"))?;
        if !docs.contains_key(d.spec) {
            let path = paths
                .get(d.spec)
                .ok_or_else(|| format!("vendor.sh --paths names no `{}` spec", d.spec))?;
            let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
            docs.insert(d.spec, spec::parse(path, &text)?);
        }
        let pin = pins
            .get(d.spec)
            .ok_or_else(|| format!("{} pins no `{}` spec", spec::DIGESTS, d.spec))?;
        out.push(lock_of(d, &docs[d.spec], &pin.sha256)?);
    }
    Ok(out)
}

/// One dialect's lock from its parsed spec document. Pure: the unit tests drive it on planted
/// documents.
pub fn lock_of(d: &Dialect, doc: &Value, sha256: &str) -> Result<Lock, String> {
    let oa;
    let di;
    let bo;
    let ad: &dyn Adapter = match d.format {
        Format::OpenApi => {
            oa = adapters::OpenApi { doc };
            &oa
        }
        Format::Discovery => {
            di = adapters::Discovery { doc };
            &di
        }
        Format::Botocore => {
            bo = adapters::Botocore { doc };
            &bo
        }
    };
    let mut lock = Lock {
        dialect: d.name.to_string(),
        spec: d.spec.to_string(),
        format: d.format.label().to_string(),
        sha256: sha256.to_string(),
        ..Lock::default()
    };
    let response = d.roots[1].unwrap_or_default().to_string();
    for (dir, root) in DIRECTIONS.iter().zip(d.roots.iter()) {
        let Some(root) = root else { continue };
        // The stream walk treats the response schema as already entered: an event carrying the
        // whole response object is cut at `ref:<Response>` instead of repeating that direction.
        let seed = if *dir == "stream" {
            vec![response.clone()]
        } else {
            Vec::new()
        };
        let paths = walk::generate(ad, Handle::Ref((*root).to_string()), &seed)
            .map_err(|e| format!("{} {dir}: {e}", d.name))?;
        if paths.is_empty() {
            return Err(format!("{} {dir}: `{root}` yields no path", d.name));
        }
        lock.roots.insert((*dir).to_string(), (*root).to_string());
        lock.dirs.insert((*dir).to_string(), paths);
    }
    Ok(lock)
}

// ── THE COMMAND ──────────────────────────────────────────────────────────────────────────────────

const USAGE: &str = "usage: cargo xtask dialect wire [--write | --diff] <dialect|all>\n       \
                     cargo xtask dialect wire --diff-files <old.wire.json> <new.wire.json>";

/// `cargo xtask dialect …`. Only `wire` lives here.
pub fn main(cx: &Ctx, args: &[String]) -> i32 {
    if args.first().map(String::as_str) != Some("wire") {
        eprintln!("{USAGE}");
        return 2;
    }
    let args = &args[1..];
    if args.first().map(String::as_str) == Some("--diff-files") {
        return match args {
            [_, a, b] => diff_files(a, b),
            _ => {
                eprintln!("{USAGE}");
                2
            }
        };
    }
    let mut mode = "check";
    let mut target: Option<&str> = None;
    for a in args {
        match a.as_str() {
            "--write" if mode == "check" => mode = "write",
            "--diff" if mode == "check" => mode = "diff",
            w if !w.starts_with('-') && target.is_none() => target = Some(w),
            other => {
                eprintln!("xtask dialect wire: unexpected argument `{other}`\n{USAGE}");
                return 2;
            }
        }
    }
    let names: Vec<&str> = match target {
        Some("all") => DIALECTS.iter().map(|d| d.name).collect(),
        Some(n) if dialect(n).is_some() => vec![n],
        _ => {
            eprintln!("{USAGE}");
            return 2;
        }
    };
    let fresh = match generate(cx, &names) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("xtask dialect wire: {e}");
            return 3;
        }
    };
    let mut stale = 0;
    for lock in &fresh {
        let path = lock_path(&lock.dialect);
        let text = lock.render();
        let old = cx.read(&path).ok();
        let changes = match old.as_deref().map(Lock::parse) {
            Some(Ok(o)) => diff::diff(&o, lock),
            _ => Vec::new(),
        };
        let counts: Vec<String> = lock
            .dirs
            .iter()
            .map(|(d, p)| format!("{d} {}", p.len()))
            .collect();
        for c in &changes {
            println!("{c}");
        }
        let same = old.as_deref() == Some(text.as_str());
        match mode {
            "write" => {
                if let Err(e) = cx.write_file(&path, &text) {
                    eprintln!("xtask dialect wire: {path}: {e}");
                    return 3;
                }
                println!("wrote    {path}  ({})", counts.join(", "));
            }
            _ if same => println!("current  {path}  ({})", counts.join(", ")),
            "diff" => println!("differs  {path}  ({} change(s))", changes.len()),
            _ => {
                println!(
                    "STALE    {path}: not what the pinned spec generates; run cargo xtask dialect \
                     wire --write {}",
                    lock.dialect
                );
                stale += 1;
            }
        }
    }
    // The generated inventory follows the locks on disk (all six, whichever were regenerated).
    if mode != "diff" {
        let locks = match committed(cx) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("xtask dialect wire: {e}");
                return 3;
            }
        };
        let text = render_inventory(&locks);
        if mode == "write" {
            if let Err(e) = cx.write_file(INVENTORY, &text) {
                eprintln!("xtask dialect wire: {INVENTORY}: {e}");
                return 3;
            }
            println!("wrote    {INVENTORY}");
        } else if cx.read(INVENTORY).ok().as_deref() != Some(text.as_str()) {
            println!("STALE    {INVENTORY}; run cargo xtask dialect wire --write all");
            stale += 1;
        }
    }
    i32::from(stale > 0)
}

fn diff_files(a: &str, b: &str) -> i32 {
    let read = |p: &str| -> Result<Lock, String> {
        let t = std::fs::read_to_string(p).map_err(|e| format!("{p}: {e}"))?;
        Lock::parse(&t).map_err(|e| format!("{p}: {e}"))
    };
    match (read(a), read(b)) {
        (Ok(x), Ok(y)) => {
            for c in diff::diff(&x, &y) {
                println!("{c}");
            }
            0
        }
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("xtask dialect wire: {e}");
            3
        }
    }
}

#[cfg(test)]
#[path = "tests/wire_lock_tests.rs"]
mod tests;
