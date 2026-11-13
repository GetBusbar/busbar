//! C plugins: the recipe is bounded data read from committed Git bytes, the
//! plugin includes only the public header, and exports only the ABI door.

use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

use serde_json::Value as Json;

use crate::policy::{Policy, PUBLIC_C_HEADER};
use crate::py::{self, Cmd};
use crate::refuse::{Result, Rule, Violation};

fn recipe_error(message: &str) -> Violation {
    Violation::new(Rule::CRecipe, message)
}

fn source_error(message: &str) -> Violation {
    Violation::new(Rule::CSource, message)
}

/// `product_artifacts.relative_path`.
pub fn relative_path(value: &Json) -> Result<&str> {
    let value = value
        .as_str()
        .filter(|v| {
            !v.is_empty()
                && v.chars().count() <= 512
                && v.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'/' | b'-'))
        })
        .ok_or_else(|| recipe_error("invalid product source path"))?;
    if value.starts_with('/') || value.split('/').any(|p| matches!(p, "" | "." | "..")) {
        return Err(recipe_error(
            "product source path must be relative and confined",
        ));
    }
    Ok(value)
}

/// `product_artifacts.regular_under`.
pub fn regular_under(path: &Path, root: &Path) -> Result<PathBuf> {
    let confined = path.is_absolute()
        && root.is_absolute()
        && path.starts_with(root)
        && !path.components().any(|c| c == Component::ParentDir);
    if !confined {
        return Err(source_error("product input escapes candidate workspace"));
    }
    for current in path.ancestors() {
        if current
            .symlink_metadata()
            .is_ok_and(|m| m.file_type().is_symlink())
        {
            return Err(source_error("indirect product input"));
        }
    }
    if !path.is_file() || !py::resolve(path).starts_with(py::resolve(root)) {
        return Err(source_error("missing or nonregular product input"));
    }
    Ok(path.to_path_buf())
}

/// JSON with duplicate keys refused (`object_pairs_hook=pairs`).
pub fn parse_unique_json(data: &[u8]) -> Result<Json> {
    use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};

    struct Unique(Json);
    impl<'de> serde::Deserialize<'de> for Unique {
        fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
            struct V;
            impl<'de> Visitor<'de> for V {
                type Value = Unique;
                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    f.write_str("JSON")
                }
                fn visit_bool<E>(self, v: bool) -> std::result::Result<Unique, E> {
                    Ok(Unique(Json::Bool(v)))
                }
                fn visit_i64<E>(self, v: i64) -> std::result::Result<Unique, E> {
                    Ok(Unique(Json::from(v)))
                }
                fn visit_u64<E>(self, v: u64) -> std::result::Result<Unique, E> {
                    Ok(Unique(Json::from(v)))
                }
                fn visit_f64<E>(self, v: f64) -> std::result::Result<Unique, E> {
                    Ok(Unique(Json::from(v)))
                }
                fn visit_str<E>(self, v: &str) -> std::result::Result<Unique, E> {
                    Ok(Unique(Json::String(v.to_string())))
                }
                fn visit_unit<E>(self) -> std::result::Result<Unique, E> {
                    Ok(Unique(Json::Null))
                }
                fn visit_seq<A: SeqAccess<'de>>(
                    self,
                    mut seq: A,
                ) -> std::result::Result<Unique, A::Error> {
                    let mut out = Vec::new();
                    while let Some(Unique(v)) = seq.next_element()? {
                        out.push(v);
                    }
                    Ok(Unique(Json::Array(out)))
                }
                fn visit_map<A: MapAccess<'de>>(
                    self,
                    mut map: A,
                ) -> std::result::Result<Unique, A::Error> {
                    let mut out = serde_json::Map::new();
                    while let Some(key) = map.next_key::<String>()? {
                        let Unique(value) = map.next_value()?;
                        if out.insert(key, value).is_some() {
                            return Err(de::Error::custom("duplicate product input"));
                        }
                    }
                    Ok(Unique(Json::Object(out)))
                }
            }
            d.deserialize_any(V)
        }
    }
    let text = std::str::from_utf8(data).map_err(|e| Violation::new(Rule::Parse, e.to_string()))?;
    match serde_json::from_str::<Unique>(text) {
        Ok(Unique(v)) => Ok(v),
        Err(e) if e.to_string().starts_with("duplicate product input") => {
            Err(recipe_error("duplicate product input"))
        }
        Err(e) => Err(Violation::new(Rule::Parse, e.to_string())),
    }
}

fn git(source: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let mut argv = vec![
        "git".to_string(),
        "--no-pager".into(),
        "--no-replace-objects".into(),
        "-c".into(),
        "core.fsmonitor=false".into(),
        "-C".into(),
        py::s(source),
    ];
    argv.extend(args.iter().map(|a| a.to_string()));
    let output = std::process::Command::new(&argv[0])
        .args(&argv[1..])
        .output()
        .map_err(|e| py::os_error(&e, Path::new("git")))?;
    if !output.status.success() {
        return Err(source_error("cannot read exact artifact owner Git source"));
    }
    Ok(output.stdout)
}

/// `product_artifacts.blob`: a regular committed blob, size bounded.
fn blob(source: &Path, revision: &str, relative: &str, limit: usize) -> Result<Vec<u8>> {
    relative_path(&Json::String(relative.to_string()))?;
    if !py::is_hex(revision, 40) {
        return Err(source_error("immutable artifact owner revision required"));
    }
    if !source.is_dir()
        || source.ancestors().any(|p| {
            p.symlink_metadata()
                .is_ok_and(|m| m.file_type().is_symlink())
        })
    {
        return Err(source_error("indirect or missing artifact owner source"));
    }
    let entry = String::from_utf8_lossy(&git(source, &["ls-tree", revision, "--", relative])?)
        .trim_end_matches('\n')
        .to_string();
    let fields: Vec<&str> = entry.split('\t').collect();
    if fields.len() != 2 || fields[1] != relative {
        return Err(source_error("missing declared owner source"));
    }
    let meta: Vec<&str> = fields[0].split_whitespace().collect();
    if meta.len() != 3 || meta[0] != "100644" || meta[1] != "blob" {
        return Err(source_error("owner metadata must be a regular Git blob"));
    }
    let size: usize = String::from_utf8_lossy(&git(source, &["cat-file", "-s", meta[2]])?)
        .trim()
        .parse()
        .unwrap_or(usize::MAX);
    if size > limit {
        return Err(source_error("owner metadata exceeds limit"));
    }
    let data = git(source, &["cat-file", "blob", meta[2]])?;
    if data.len() > limit {
        return Err(source_error("owner metadata exceeds limit"));
    }
    Ok(data)
}

fn bounded_sources(values: &Json) -> Result<Vec<String>> {
    let items = values
        .as_array()
        .filter(|v| (1..=16).contains(&v.len()) && v.iter().all(Json::is_string))
        .ok_or_else(|| recipe_error("C witness source count or duplicates"))?;
    let unique: BTreeSet<&str> = items.iter().filter_map(Json::as_str).collect();
    if unique.len() != items.len() {
        return Err(recipe_error("C witness source count or duplicates"));
    }
    for value in items {
        if !relative_path(value)?.ends_with(".c") {
            return Err(recipe_error("C witness source must be a relative C file"));
        }
    }
    Ok(items
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect())
}

fn keys(value: &Json) -> BTreeSet<&str> {
    value
        .as_object()
        .map(|o| o.keys().map(String::as_str).collect())
        .unwrap_or_default()
}

/// `validate_c_recipe`.
pub fn validate_c_recipe(recipe: &Json, entry: &toml::Table) -> Result<()> {
    if !recipe.is_object()
        || keys(recipe) != BTreeSet::from(["sources", "test-root", "unit", "schema"])
    {
        return Err(recipe_error("C witness recipe has missing or unknown keys"));
    }
    let (unit, schema) = (&recipe["unit"], &recipe["schema"]);
    if !unit.is_object()
        || keys(unit) != BTreeSet::from(["sources", "defines"])
        || !schema.is_object()
        || keys(schema) != BTreeSet::from(["source", "driver"])
    {
        return Err(recipe_error(
            "C witness requires bounded unit and schema recipes",
        ));
    }
    let mut sources = bounded_sources(&recipe["sources"])?;
    let unit_sources = bounded_sources(&unit["sources"])?;
    bounded_sources(&Json::Array(vec![schema["source"].clone()]))?;
    let mut classified = crate::policy::strings(entry.get("sources"))?;
    sources.sort();
    classified.sort();
    if sources != classified {
        return Err(recipe_error(
            "C witness sources differ from trusted classification",
        ));
    }
    if !relative_path(&schema["driver"])?.ends_with(".py") {
        return Err(recipe_error(
            "C schema driver must be a relative Python file",
        ));
    }
    let test_root = PathBuf::from(relative_path(&recipe["test-root"])?);
    let all_sources = bounded_sources(&recipe["sources"])?;
    let leaves = all_sources
        .iter()
        .any(|s| Path::new(s).parent() != Some(test_root.as_path()))
        || unit_sources
            .iter()
            .map(String::as_str)
            .chain([
                schema["source"].as_str().unwrap_or(""),
                schema["driver"].as_str().unwrap_or(""),
            ])
            .any(|s| !Path::new(s).starts_with(&test_root));
    if leaves {
        return Err(recipe_error(
            "C witness test paths leave their declared source root",
        ));
    }
    let defines = &unit["defines"];
    let valid = defines.as_array().is_some_and(|d| {
        d.len() <= 8
            && d.iter().all(|v| {
                v.as_str().is_some_and(|s| {
                    s.len() > 7
                        && s.len() <= 7 + 96
                        && s.starts_with("BUSBAR_")
                        && s[7..]
                            .bytes()
                            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
                })
            })
            && d.iter()
                .filter_map(Json::as_str)
                .collect::<BTreeSet<_>>()
                .len()
                == d.len()
    });
    if !valid {
        return Err(recipe_error(
            "C witness permits bounded macro names, never compiler arguments",
        ));
    }
    Ok(())
}

/// `load_c_recipe`.
pub fn load_c_recipe(policy: &Policy, repository: &str, checkout: &Path) -> Result<Json> {
    let entry = policy
        .repositories()
        .get(repository)
        .and_then(toml::Value::as_table)
        .cloned()
        .unwrap_or_default();
    if entry.get("language").and_then(toml::Value::as_str) != Some("c") {
        return Err(recipe_error("C witness owner is not classified as C"));
    }
    let head = String::from_utf8_lossy(&git(checkout, &["rev-parse", "HEAD"])?)
        .trim()
        .to_string();
    let relative = "testing/c-witness.json";
    let data = blob(checkout, &head, relative, 16 * 1024)?;
    let on_disk = regular_under(&py::join(checkout, relative), checkout)?;
    if py::read_bytes(&on_disk)? != data {
        return Err(source_error(
            "C witness recipe differs from its committed bytes",
        ));
    }
    let recipe = parse_unique_json(&data)?;
    validate_c_recipe(&recipe, &entry)?;
    let mut paths: Vec<String> = recipe["sources"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();
    paths.extend(
        recipe["unit"]["sources"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_str().map(str::to_string)),
    );
    paths.push(
        recipe["schema"]["source"]
            .as_str()
            .unwrap_or("")
            .to_string(),
    );
    paths.push(
        recipe["schema"]["driver"]
            .as_str()
            .unwrap_or("")
            .to_string(),
    );
    for relative in paths {
        let expected = blob(checkout, &head, &relative, 2 * 1024 * 1024)?;
        let on_disk = regular_under(&py::join(checkout, &relative), checkout)?;
        if py::read_bytes(&on_disk)? != expected {
            return Err(source_error(
                "C witness source differs from its committed bytes",
            ));
        }
    }
    Ok(recipe)
}

/// The operands of every `#include` directive, line by line.
pub fn includes(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.split('\n') {
        let Some(rest) = line.trim_start().strip_prefix('#') else {
            continue;
        };
        let Some(rest) = rest.trim_start().strip_prefix("include") else {
            continue;
        };
        let operand = rest.trim_start();
        if operand.len() < rest.len() && !operand.is_empty() {
            out.push(operand.to_string());
        }
    }
    out
}

#[derive(Debug, serde::Serialize)]
pub struct CReceipt {
    pub source_roots: usize,
    pub c_header_revision: String,
    pub c_exports: Vec<String>,
}

/// `check_c`.
pub fn check_c(
    policy: &Policy,
    repository: &str,
    checkout: &Path,
    sdk: &Path,
    scratch: &Path,
) -> Result<CReceipt> {
    let fields_text = py::read_text(&py::join(checkout, ".busbar-ref"))?;
    let fields: Vec<&str> = fields_text.split_whitespace().collect();
    let revision = Cmd::new([
        "git".to_string(),
        "-C".into(),
        py::s(sdk),
        "rev-parse".into(),
        "HEAD".into(),
    ])
    .output()?
    .trim()
    .to_string();
    if fields != [revision.as_str(), "1.6.0"] {
        return Err(Violation::new(
            Rule::BusbarRef,
            "C plugin/header SDK pin mismatch",
        ));
    }
    let recipe = load_c_recipe(policy, repository, checkout)?;
    let sources: Vec<PathBuf> = recipe["sources"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Json::as_str)
        .map(|p| py::join(checkout, p))
        .collect();
    for source in &sources {
        if includes(&py::read_text(source)?) != ["\"busbar_plugin.h\""] {
            return Err(Violation::new(
                Rule::CSource,
                format!(
                    "C plugin must include only the public ABI header: {}",
                    source.display()
                ),
            ));
        }
    }
    let darwin = cfg!(target_os = "macos");
    std::fs::create_dir_all(scratch).map_err(|e| py::os_error(&e, scratch))?;
    let library = scratch.join(if darwin { "plugin.dylib" } else { "plugin.so" });
    let include = py::join(sdk, PUBLIC_C_HEADER);
    let mut argv: Vec<String> = [
        "cc",
        "-std=c11",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-fvisibility=hidden",
        "-fPIC",
        if darwin { "-dynamiclib" } else { "-shared" },
        "-I",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    argv.push(py::s(include.parent().unwrap_or(Path::new("/"))));
    argv.extend(sources.iter().map(|s| py::s(s)));
    argv.push("-o".into());
    argv.push(py::s(&library));
    Cmd::new(argv).run()?;
    let output = Cmd::new([
        "nm".to_string(),
        if darwin { "-gU" } else { "--defined-only" }.into(),
        py::s(&library),
    ])
    .output()?;
    let exported: BTreeSet<String> = output
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let kind = fields.len().checked_sub(2).map(|i| fields[i])?;
            let upper =
                kind.chars().any(char::is_alphabetic) && !kind.chars().any(char::is_lowercase);
            (fields.len() >= 3 && upper).then(|| {
                fields[fields.len() - 1]
                    .strip_prefix('_')
                    .unwrap_or(fields[fields.len() - 1])
                    .to_string()
            })
        })
        .collect();
    let exports: Vec<String> = exported.iter().cloned().collect();
    if exports != ["busbar_plugin_door"] {
        return Err(Violation::new(
            Rule::CExports,
            format!(
                "C runtime exports are not the sole ABI door: {}",
                py::repr_list(&exports)
            ),
        ));
    }
    Ok(CReceipt {
        source_roots: sources.len(),
        c_header_revision: revision,
        c_exports: exports,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    type Mutation = Box<dyn Fn(&mut Json)>;

    fn entry() -> toml::Table {
        "language = \"c\"\nsources = [\"secret-c/a.c\"]\n"
            .parse()
            .unwrap()
    }

    fn recipe() -> Json {
        json!({"sources": ["secret-c/a.c"], "test-root": "secret-c",
               "unit": {"sources": ["secret-c/test/unit.c"], "defines": ["BUSBAR_TEST"]},
               "schema": {"source": "secret-c/test/schema.c", "driver": "secret-c/test/schema.py"}})
    }

    #[test]
    fn recipe_is_bounded_data() {
        validate_c_recipe(&recipe(), &entry()).unwrap();
        let cases: Vec<(&str, Mutation)> = vec![
            (
                "C witness recipe has missing or unknown keys",
                Box::new(|r| r["extra"] = json!(1)),
            ),
            (
                "C witness requires bounded unit and schema recipes",
                Box::new(|r| r["unit"]["cflags"] = json!([])),
            ),
            (
                "C witness source must be a relative C file",
                Box::new(|r| r["unit"]["sources"] = json!(["secret-c/x.h"])),
            ),
            (
                "product source path must be relative and confined",
                Box::new(|r| r["unit"]["sources"] = json!(["secret-c/../x.c"])),
            ),
            (
                "C witness sources differ from trusted classification",
                Box::new(|r| r["sources"] = json!(["secret-c/b.c"])),
            ),
            (
                "C schema driver must be a relative Python file",
                Box::new(|r| r["schema"]["driver"] = json!("secret-c/x.sh")),
            ),
            (
                "C witness test paths leave their declared source root",
                Box::new(|r| r["unit"]["sources"] = json!(["other/u.c"])),
            ),
            (
                "C witness permits bounded macro names, never compiler arguments",
                Box::new(|r| r["unit"]["defines"] = json!(["-fplugin=x"])),
            ),
            (
                "C witness source count or duplicates",
                Box::new(|r| r["unit"]["sources"] = json!(["secret-c/u.c", "secret-c/u.c"])),
            ),
        ];
        for (message, mutate) in cases {
            let mut r = recipe();
            mutate(&mut r);
            assert_eq!(
                validate_c_recipe(&r, &entry()).unwrap_err().message,
                message
            );
        }
    }

    #[test]
    fn duplicate_recipe_keys_are_refused() {
        assert_eq!(
            parse_unique_json(br#"{"a": 1, "a": 2}"#)
                .unwrap_err()
                .message,
            "duplicate product input"
        );
    }

    #[test]
    fn include_scan_finds_every_directive() {
        let text =
            "#include \"busbar_plugin.h\"\n  #  include <stdio.h>\n#includex\n// #include \"no\"\n";
        assert_eq!(includes(text), ["\"busbar_plugin.h\"", "<stdio.h>"]);
    }
}
