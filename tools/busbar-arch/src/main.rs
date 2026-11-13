//! `busbar-arch`: the architecture policy of GetBusbar/busbar and its plugins.
//!
//! A port, rule by rule, of `scripts/architecture/check.py` (and the native
//! capability table of `native_policy.py`). Refusal messages are identical to
//! the Python ones while the two run side by side (`ci/jobs/arch-differential.sh`);
//! each refusal also names its rule and why the rule exists.
//!
//! ```text
//! busbar-arch check --policy P --repository R --checkout C --trusted T --scratch S [--output F] [--sdk D]
//! busbar-arch plan --repository R [--policy P] [--trusted T] [--checkout C]
//! busbar-arch lock-align [--checkout C]
//! busbar-arch witnesses [--write] [--checkout C]
//! busbar-arch repositories [--checkout C]
//! busbar-arch rules
//! ```

mod c;
mod declared;
mod graph;
mod plan;
mod policy;
mod probe;
mod py;
mod refuse;
mod sources;
mod vector;
mod witness;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde_json::{json, Map, Value as Json};
use sha2::{Digest, Sha256};

use policy::{Policy, CORE};
use refuse::{Result, Rule, Violation};

const USAGE: &str = "usage: busbar-arch <check|plan|lock-align|witnesses|rules> [options]
  check      --policy P --repository R --checkout C --trusted T --scratch S [--output F] [--sdk D]
  plan       --repository R [--policy P] [--trusted T] [--checkout C]
  lock-align [--checkout C]
  witnesses  [--write] [--checkout C] [--policy P]
  repositories [--checkout C] [--policy P]
  rules      list every rule and why it exists";

struct Args {
    values: BTreeMap<String, String>,
    flags: Vec<String>,
}

impl Args {
    fn parse(raw: &[String]) -> std::result::Result<Args, String> {
        let mut values = BTreeMap::new();
        let mut flags = Vec::new();
        let mut i = 0;
        while i < raw.len() {
            let arg = &raw[i];
            let Some(name) = arg.strip_prefix("--") else {
                return Err(format!("unexpected argument {arg}"));
            };
            if let Some((key, value)) = name.split_once('=') {
                values.insert(key.to_string(), value.to_string());
            } else if name == "write" {
                flags.push(name.to_string());
            } else {
                let value = raw
                    .get(i + 1)
                    .ok_or_else(|| format!("--{name} needs a value"))?;
                values.insert(name.to_string(), value.clone());
                i += 1;
            }
            i += 1;
        }
        Ok(Args { values, flags })
    }

    fn path(&self, key: &str) -> Option<PathBuf> {
        self.values.get(key).map(PathBuf::from)
    }

    fn required(&self, key: &str) -> std::result::Result<String, String> {
        self.values
            .get(key)
            .cloned()
            .ok_or_else(|| format!("--{key} is required"))
    }
}

fn source_revision(checkout: &Path) -> Result<String> {
    let output = std::process::Command::new("git")
        .args(["-C", &py::s(checkout), "rev-parse", "HEAD"])
        .output()
        .map_err(|e| py::os_error(&e, Path::new("git")))?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).trim().to_string());
    }
    generated_revision(checkout)
}

/// `generated_revision`: a bounded content fingerprint of a non-Git tree (the
/// generator job's generated plugins).
fn generated_revision(checkout: &Path) -> Result<String> {
    let unsafe_root = !checkout.is_absolute()
        || !checkout.is_dir()
        || checkout
            .symlink_metadata()
            .is_ok_and(|m| m.file_type().is_symlink())
        || py::resolve(checkout) != checkout
        || checkout.components().count() <= 2
        || checkout.to_string_lossy().contains(',');
    if unsafe_root {
        return Err(Violation::new(
            Rule::GeneratedSource,
            "unsafe execution root",
        ));
    }
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            out.push(path.clone());
            let meta = path.symlink_metadata()?;
            if meta.is_dir() {
                walk(&path, out)?;
            }
        }
        Ok(())
    }
    let mut paths = Vec::new();
    walk(checkout, &mut paths).map_err(|e| py::os_error(&e, checkout))?;
    let mut inventory = Vec::new();
    let mut total: u64 = 0;
    for (count, path) in paths.iter().enumerate() {
        if count + 1 > 10000 {
            return Err(Violation::new(
                Rule::GeneratedSource,
                "generated architecture source exceeds entry count",
            ));
        }
        let meta = path
            .symlink_metadata()
            .map_err(|e| py::os_error(&e, path))?;
        let relative = path.strip_prefix(checkout).unwrap_or(path);
        if !(meta.is_dir() || meta.is_file())
            || relative.components().any(|c| c.as_os_str() == ".git")
        {
            return Err(Violation::new(
                Rule::GeneratedSource,
                "generated architecture source contains indirect or Git control files",
            ));
        }
        #[cfg(unix)]
        let (mode, nlink) = {
            use std::os::unix::fs::MetadataExt;
            (meta.mode() & 0o7777, meta.nlink())
        };
        #[cfg(not(unix))]
        let (mode, nlink) = (0u32, 1u64);
        let mut row = Map::new();
        row.insert("path".into(), json!(relative.to_string_lossy()));
        row.insert("permissions".into(), json!(mode));
        if meta.is_file() {
            total += meta.len();
            if nlink != 1 || meta.len() > 16 * 1024 * 1024 || total > 128 * 1024 * 1024 {
                return Err(Violation::new(
                    Rule::GeneratedSource,
                    "generated architecture source exceeds collection bounds",
                ));
            }
            let payload = py::read_bytes(path)?;
            if payload.len() as u64 != meta.len() {
                return Err(Violation::new(
                    Rule::GeneratedSource,
                    "generated architecture source changed while fingerprinting",
                ));
            }
            row.insert("kind".into(), json!("file"));
            row.insert("size".into(), json!(meta.len()));
            row.insert(
                "sha256".into(),
                json!(vector::hex(&Sha256::digest(&payload))),
            );
        } else {
            row.insert("kind".into(), json!("directory"));
            row.insert("size".into(), json!(0));
            row.insert("sha256".into(), Json::Null);
        }
        inventory.push(row);
    }
    inventory.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
    // json.dumps(sort_keys=True, separators=(',', ':')) with ASCII escapes.
    let encoded: Vec<String> = inventory
        .iter()
        .map(|row| {
            let mut keys: Vec<&String> = row.keys().collect();
            keys.sort();
            let fields: Vec<String> = keys
                .iter()
                .map(|k| {
                    format!(
                        "{}:{}",
                        python_json(&json!(k)),
                        python_json(&row[k.as_str()])
                    )
                })
                .collect();
            format!("{{{}}}", fields.join(","))
        })
        .collect();
    let encoded = format!("[{}]", encoded.join(","));
    Ok(format!(
        "generated-sha256:{}",
        vector::hex(&Sha256::digest(encoded.as_bytes()))
    ))
}

/// `json.dumps` with `ensure_ascii=True` for scalars.
fn python_json(value: &Json) -> String {
    match value {
        Json::String(s) => {
            let mut out = String::from("\"");
            for c in s.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    '\u{8}' => out.push_str("\\b"),
                    '\u{c}' => out.push_str("\\f"),
                    c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                        let mut buf = [0u16; 2];
                        for unit in c.encode_utf16(&mut buf) {
                            out.push_str(&format!("\\u{unit:04x}"));
                        }
                    }
                    c => out.push(c),
                }
            }
            out.push('"');
            out
        }
        other => other.to_string(),
    }
}

fn to_json<T: serde::Serialize>(value: &T) -> Json {
    serde_json::to_value(value).expect("receipt serializes")
}

fn check(args: &Args) -> std::result::Result<Json, Failure> {
    let policy_path = PathBuf::from(args.required("policy")?);
    let repository = args.required("repository")?;
    let checkout = py::resolve(&PathBuf::from(args.required("checkout")?));
    let trusted = py::resolve(&PathBuf::from(args.required("trusted")?));
    let scratch = py::resolve(&PathBuf::from(args.required("scratch")?));
    let policy = Policy::new(py::read_toml(&policy_path)?)?;
    if repository != CORE && !policy.repositories().contains_key(&repository) {
        return Err(Violation::new(
            Rule::UnclassifiedRepository,
            format!("unclassified repository {repository}"),
        )
        .into());
    }
    std::fs::create_dir_all(&scratch).map_err(|e| py::os_error(&e, &scratch))?;
    let c_language = policy
        .repositories()
        .get(&repository)
        .and_then(toml::Value::as_table)
        .and_then(|e| e.get("language"))
        .and_then(toml::Value::as_str)
        == Some("c");
    let mut receipt = Map::new();
    if c_language {
        let Some(sdk) = args.path("sdk") else {
            return Err(Violation::new(
                Rule::CRequiresSdk,
                "C verification requires the pinned SDK checkout",
            )
            .into());
        };
        let c = c::check_c(
            &policy,
            &repository,
            &checkout,
            &py::resolve(&sdk),
            &scratch,
        )?;
        receipt.extend(to_json(&c).as_object().cloned().unwrap_or_default());
    } else {
        eprintln!("busbar-arch: shipping graph");
        let entries = declared::check_declared(&policy, &repository, &checkout)?;
        let metadata = probe::resolve_shipping(&checkout, &entries, &scratch, false)?;
        let graph = graph::check_graph(&metadata, &policy, &repository, &checkout)?;
        receipt.extend(to_json(&graph).as_object().cloned().unwrap_or_default());
        if repository == CORE {
            eprintln!("busbar-arch: assembly graph");
            let vector = vector::check_vector(&policy, &checkout, &entries)?;
            receipt.insert("dependency_vector".into(), to_json(&vector));
            let assembled = probe::resolve_shipping(&checkout, &entries, &scratch, true)?;
            let assembly = graph::check_graph(&assembled, &policy, &repository, &checkout)?;
            receipt.insert("assembly".into(), to_json(&assembly));
            let cases = witness::extract(&policy, &trusted)?;
            let verified = witness::verify(&checkout, &cases)?;
            receipt.insert("compiler_witnesses_trybuild".into(), json!(verified));
        }
        eprintln!("busbar-arch: source check");
        let sources = sources::check_sources(
            &policy,
            &repository,
            &checkout,
            &metadata,
            &trusted,
            &scratch,
        )?;
        receipt.extend(to_json(&sources).as_object().cloned().unwrap_or_default());
    }
    receipt.insert("repository".into(), json!(repository));
    let policy_bytes = py::read_bytes(&policy_path)?;
    receipt.insert(
        "policy_sha256".into(),
        json!(vector::hex(&Sha256::digest(&policy_bytes))),
    );
    receipt.insert("source".into(), json!(source_revision(&checkout)?));
    Ok(Json::Object(receipt))
}

fn default_checkout(args: &Args) -> PathBuf {
    py::resolve(&args.path("checkout").unwrap_or_else(|| PathBuf::from(".")))
}

fn lock_align(args: &Args) -> Result<Json> {
    let checkout = default_checkout(args);
    let shared = vector::check_shared_core_resolution(
        &py::read_toml(&py::join(&checkout, "Cargo.lock"))?,
        &py::read_toml(&py::join(&checkout, "dist/default/Cargo.lock"))?,
    )?;
    Ok(json!({"shared_core_packages": shared}))
}

fn plan_command(args: &Args) -> std::result::Result<Json, Failure> {
    let repository = args.required("repository")?;
    let trusted = py::resolve(&args.path("trusted").unwrap_or_else(|| PathBuf::from(".")));
    let policy_path = args
        .path("policy")
        .unwrap_or_else(|| trusted.join("ci/architecture.toml"));
    let policy = Policy::new(py::read_toml(&policy_path)?)?;
    Ok(plan::plan(
        &policy,
        &repository,
        &trusted,
        args.path("checkout").as_deref(),
    )?)
}

fn witnesses(args: &Args) -> std::result::Result<Json, Failure> {
    let checkout = default_checkout(args);
    let policy_path = args
        .path("policy")
        .unwrap_or_else(|| checkout.join("ci/architecture.toml"));
    let policy = Policy::new(py::read_toml(&policy_path)?)?;
    let cases = witness::extract(&policy, &checkout)?;
    let count = if args.flags.iter().any(|f| f == "write") {
        witness::write(&checkout, &cases)?
    } else {
        witness::verify(&checkout, &cases)?
    };
    let positive = cases.iter().filter(|c| c.expected.is_empty()).count();
    Ok(
        json!({"compiler_witnesses": count, "positive": positive, "negative": count - positive,
              "loader": cases.iter().filter(|c| c.needs_loader).count()}),
    )
}

/// Every classified repository with its language and visibility (for the fleet differential).
fn repositories(args: &Args) -> std::result::Result<Json, Failure> {
    let checkout = default_checkout(args);
    let policy_path = args
        .path("policy")
        .unwrap_or_else(|| checkout.join("ci/architecture.toml"));
    let policy = Policy::new(py::read_toml(&policy_path)?)?;
    let rows: Vec<Json> = policy
        .repositories()
        .iter()
        .map(|(name, entry)| {
            let language = entry
                .get("language")
                .and_then(toml::Value::as_str)
                .unwrap_or("rust");
            let private = policy::truthy(entry.get("private"));
            json!({"repository": name, "language": language, "private": private})
        })
        .collect();
    Ok(Json::Array(rows))
}

enum Failure {
    Usage(String),
    Refused(Violation),
}

impl From<Violation> for Failure {
    fn from(v: Violation) -> Self {
        Failure::Refused(v)
    }
}

impl From<String> for Failure {
    fn from(v: String) -> Self {
        Failure::Usage(v)
    }
}

fn main() -> ExitCode {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let Some((command, rest)) = raw.split_first() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let args = match Args::parse(rest) {
        Ok(args) => args,
        Err(e) => {
            eprintln!("busbar-arch: {e}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let result: std::result::Result<Json, Failure> = match command.as_str() {
        "check" => check(&args),
        "plan" => plan_command(&args),
        "lock-align" => lock_align(&args).map_err(Failure::from),
        "witnesses" => witnesses(&args),
        "repositories" => repositories(&args),
        "rules" => Ok(Json::Array(
            Rule::ALL
                .iter()
                .map(|r| json!({"rule": r.name(), "why": r.why()}))
                .collect(),
        )),
        "-h" | "--help" | "help" => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        other => Err(Failure::Usage(format!("unknown command {other}"))),
    };
    match result {
        Ok(receipt) => {
            let text = serde_json::to_string_pretty(&receipt).expect("json");
            if let Some(output) = args.path("output") {
                if let Err(e) = std::fs::write(&output, format!("{text}\n")) {
                    let v = py::os_error(&e, &output);
                    eprintln!("architecture: {v}");
                    return ExitCode::from(1);
                }
            }
            println!("{}", serde_json::to_string(&receipt).expect("json"));
            ExitCode::SUCCESS
        }
        Err(Failure::Usage(message)) => {
            eprintln!("busbar-arch: {message}\n{USAGE}");
            ExitCode::from(2)
        }
        Err(Failure::Refused(violation)) => {
            eprintln!("architecture: {violation}");
            eprintln!(
                "  refused by rule {}: {}",
                violation.rule.name(),
                violation.rule.why()
            );
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A temporary directory removed on drop.
    pub struct TempDir(PathBuf);

    impl TempDir {
        pub fn new(label: &str) -> Self {
            use std::sync::atomic::{AtomicUsize, Ordering};
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "busbar-arch-{label}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).unwrap();
            TempDir(py::resolve(&path))
        }

        pub fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The policy of `test_check.py`.
    pub fn test_policy() -> Policy {
        let text = r#"
version = 1
forbidden_shipping_features = ["test-support", "test-seal"]
[core.busbar-contract]
manifest = "crates/contract/Cargo.toml"
allows = []
[core.busbar-kernel]
manifest = "crates/kernel/Cargo.toml"
allows = ["busbar-contract"]
[[repositories."GetBusbar/busbar-auth-alpha".packages]]
name = "busbar-auth-alpha"
manifest = "auth-alpha/Cargo.toml"
role = "implementation"
[[repositories."GetBusbar/busbar-auth-alpha".packages]]
name = "busbar-auth-alpha-plugin"
manifest = "auth-alpha-plugin/Cargo.toml"
role = "wrapper"
[[repositories."GetBusbar/busbar-store-beta".packages]]
name = "busbar-store-beta"
manifest = "store-beta/Cargo.toml"
role = "implementation"
[assembly]
package = "busbar-default"
repository = "GetBusbar/busbar"
manifest = "dist/default/Cargo.toml"
"#;
        Policy::new(text.parse().unwrap()).unwrap()
    }

    #[test]
    fn unsupported_policy_is_refused() {
        let e = Policy::new("version = 2\n".parse().unwrap()).err().unwrap();
        assert_eq!(e.message, "unsupported architecture policy");
    }

    #[test]
    fn generated_revision_matches_python_encoding() {
        assert_eq!(python_json(&json!("a\u{e9}")), "\"a\\u00e9\"");
        assert_eq!(python_json(&json!(null)), "null");
    }
}
