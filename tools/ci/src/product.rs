//! Owner product declarations read independently from exact canonical Git
//! commits (former `product_artifacts` and `native_product_inputs`), and the
//! policy readers shared by `native-qualify` and `architecture` (former
//! `check.vector_revisions`, `load_c_recipe`, `generated_revision`).
use crate::confine::checked_directory;
use crate::json::Value;
use crate::native::sp::{self, Dict, Io, R, at, need, value_error};
use crate::sha256;
use std::path::{Path, PathBuf};

pub const PUBLIC_C_HEADER: &str = "crates/busbar-contract/include/busbar_plugin.h";

fn hex(text: &str, n: usize) -> bool {
    text.len() == n
        && text
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

pub fn is_revision(text: &str) -> bool {
    hex(text, 40)
}

/// `relative_path(value)`.
pub fn relative_path(value: &Value) -> R<String> {
    let text = value.as_str().unwrap_or("");
    need(
        !text.is_empty()
            && text.chars().count() <= 512
            && text
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_./-".contains(&c)),
        "invalid product source path",
    )?;
    need(
        !text.starts_with('/') && text.split('/').all(|p| !matches!(p, "" | "." | "..")),
        "product source path must be relative and confined",
    )?;
    Ok(text.to_owned())
}

/// `confined_path(path, root)`.
pub fn confined_path(path: &Path, root: &Path) -> R<PathBuf> {
    need(
        path.is_absolute()
            && root.is_absolute()
            && path.starts_with(root)
            && !path.components().any(|c| c.as_os_str() == ".."),
        "product input escapes candidate workspace",
    )?;
    for current in sp::self_and_parents(path) {
        need(!sp::is_symlink(&current), "indirect product input")?;
    }
    Ok(path.to_owned())
}

/// `regular_under(path, root)`.
pub fn regular_under(path: &Path, root: &Path) -> R<PathBuf> {
    let path = confined_path(path, root)?;
    need(
        path.is_file() && sp::resolve(&path).starts_with(sp::resolve(root)),
        "missing or nonregular product input",
    )?;
    Ok(path)
}

/// `product_artifacts.git(source, *args)`.
pub fn git(source: &Path, args: &[&str]) -> R<Vec<u8>> {
    let mut argv = sp::strings(&[
        "git",
        "--no-pager",
        "--no-replace-objects",
        "-c",
        "core.fsmonitor=false",
        "-C",
    ]);
    argv.push(sp::text(source));
    argv.extend(args.iter().map(|a| (*a).to_owned()));
    let mut spec = sp::Spec::new(argv);
    spec.stderr = sp::Output::Capture;
    match sp::check_output(spec) {
        Ok(out) => Ok(out),
        Err(error) if error.kind == sp::Kind::Called => {
            Err(sp::violation("cannot read exact artifact owner Git source"))
        }
        Err(error) => Err(error),
    }
}

pub type GitReader<'a> = &'a dyn Fn(&Path, &[&str]) -> R<Vec<u8>>;

/// `blob(source, revision, relative, limit)`: one regular committed blob.
pub fn blob(
    source: &Path,
    revision: &str,
    relative: &str,
    limit: u64,
    reader: GitReader,
) -> R<Vec<u8>> {
    relative_path(&relative.into())?;
    need(
        is_revision(revision),
        "immutable artifact owner revision required",
    )?;
    need(
        source.is_dir()
            && !sp::self_and_parents(source)
                .iter()
                .any(|p| sp::is_symlink(p)),
        "indirect or missing artifact owner source",
    )?;
    let listing = reader(source, &["ls-tree", revision, "--", relative])?;
    let entry = String::from_utf8_lossy(&listing);
    let entry = entry.trim_end_matches('\n');
    let fields: Vec<&str> = entry.split('\t').collect();
    need(
        fields.len() == 2 && fields[1] == relative,
        "missing declared owner source",
    )?;
    let header: Vec<&str> = fields[0].split_whitespace().collect();
    let [mode, kind, oid] = header.as_slice() else {
        return Err(value_error(format!(
            "not enough values to unpack (expected 3, got {})",
            header.len()
        )));
    };
    need(
        *mode == "100644" && *kind == "blob",
        "owner metadata must be a regular Git blob",
    )?;
    let size = reader(source, &["cat-file", "-s", oid])?;
    need(
        sp::py_int(&String::from_utf8_lossy(&size))? <= limit as i128,
        "owner metadata exceeds limit",
    )?;
    let data = reader(source, &["cat-file", "blob", oid])?;
    need(data.len() as u64 <= limit, "owner metadata exceeds limit")?;
    Ok(data)
}

/// `json.loads(text, object_pairs_hook=pairs)`: duplicate keys refuse.
pub fn loads_unique(data: &[u8]) -> R<Value> {
    let value = sp::loads(data)?;
    need(!duplicate_keys(data), "duplicate product input")?;
    Ok(value)
}

/// Any object with a repeated key, scanning already-valid JSON.
fn duplicate_keys(data: &[u8]) -> bool {
    struct Scan<'a> {
        s: &'a [u8],
        i: usize,
    }
    impl Scan<'_> {
        fn ws(&mut self) {
            while self.i < self.s.len() && matches!(self.s[self.i], b' ' | b'\t' | b'\n' | b'\r') {
                self.i += 1;
            }
        }
        fn string(&mut self) -> Vec<u8> {
            let start = self.i;
            self.i += 1;
            while self.i < self.s.len() && self.s[self.i] != b'"' {
                if self.s[self.i] == b'\\' {
                    self.i += 1;
                }
                self.i += 1;
            }
            self.i += 1;
            self.s[start..self.i.min(self.s.len())].to_vec()
        }
        fn value(&mut self) -> bool {
            self.ws();
            match self.s.get(self.i) {
                Some(b'{') => {
                    self.i += 1;
                    let mut keys: Vec<Value> = Vec::new();
                    loop {
                        self.ws();
                        match self.s.get(self.i) {
                            Some(b'}') => {
                                self.i += 1;
                                return false;
                            }
                            Some(b',') => self.i += 1,
                            Some(b'"') => {
                                let raw = self.string();
                                let key = crate::json::parse(&raw).unwrap_or(Value::Null);
                                if keys.contains(&key) {
                                    return true;
                                }
                                keys.push(key);
                                self.ws();
                                self.i += 1;
                                if self.value() {
                                    return true;
                                }
                            }
                            _ => return false,
                        }
                    }
                }
                Some(b'[') => {
                    self.i += 1;
                    loop {
                        self.ws();
                        match self.s.get(self.i) {
                            Some(b']') | None => {
                                self.i += 1;
                                return false;
                            }
                            Some(b',') => self.i += 1,
                            _ => {
                                if self.value() {
                                    return true;
                                }
                            }
                        }
                    }
                }
                Some(b'"') => {
                    self.string();
                    false
                }
                _ => {
                    while self.i < self.s.len() && !b",]} \t\r\n".contains(&self.s[self.i]) {
                        self.i += 1;
                    }
                    false
                }
            }
        }
    }
    let start = usize::from(data.starts_with(b"\xef\xbb\xbf")) * 3;
    Scan { s: data, i: start }.value()
}

/// `tomllib.loads(text)`.
pub fn toml(text: &[u8]) -> R<Value> {
    let text =
        std::str::from_utf8(text).map_err(|_| value_error("'utf-8' codec can't decode bytes"))?;
    crate::toml::parse(text).map_err(value_error)
}

fn repositories(policy: &Value) -> R<&Value> {
    at(policy, "repositories")
}

/// `check.vector_revisions(policy, vector)`.
pub fn vector_revisions(policy: &Value, vector: &Value) -> R<Vec<(String, String)>> {
    let sdk = sp::at_str(vector, "sdk")?;
    need(is_revision(sdk), "assembled SDK pin is not immutable")?;
    let repos = repositories(policy)?;
    let expected: Vec<&str> = repos
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(_, e)| {
            !e.at("private").truthy()
                && !e.at("standalone").truthy()
                && e.at("language").as_str() != Some("c")
        })
        .map(|(n, _)| n.as_str())
        .collect();
    let mut revisions = vec![("GetBusbar/busbar".to_owned(), sdk.to_owned())];
    for row in at(vector, "products")?.as_array().unwrap_or(&[]) {
        let repo = format!("GetBusbar/{}", sp::at_str(row, "repo")?);
        if !expected.contains(&repo.as_str()) || revisions.iter().any(|(r, _)| *r == repo) {
            return Err(sp::violation(format!(
                "unclassified or duplicate assembly product: {repo}"
            )));
        }
        let entry = repos.at(&repo);
        let wrappers: Vec<&str> = at(entry, "packages")?
            .as_array()
            .unwrap_or(&[])
            .iter()
            .filter(|p| p.at("role").as_str() == Some("wrapper"))
            .filter_map(|p| p.at("name").as_str())
            .collect();
        let url = sp::at_str(row, "url")?;
        let ok = wrappers.contains(&sp::at_str(row, "package")?)
            && at(row, "kind")? == at(entry, "kind")?
            && url.strip_suffix(".git").unwrap_or(url) == format!("https://github.com/{repo}")
            && is_revision(sp::at_str(row, "commit")?)
            && hex(sp::at_str(row, "lock_sha256")?, 64);
        if !ok {
            return Err(sp::violation(format!(
                "assembly product identity mismatch: {repo}"
            )));
        }
        revisions.push((repo, sp::at_str(row, "commit")?.to_owned()));
    }
    let mut actual: Vec<&str> = revisions.iter().map(|(r, _)| r.as_str()).collect();
    actual.sort();
    let mut wanted: Vec<&str> = expected.clone();
    wanted.push("GetBusbar/busbar");
    wanted.sort();
    wanted.dedup();
    need(actual == wanted, "assembly product vector is incomplete")?;
    let witness = at(vector, "c_witness")?;
    let allowed = ["repo", "url", "commit", "sdk", "kind", "language", "header"];
    need(
        witness.is_object()
            && ["repo", "url", "commit", "sdk"]
                .iter()
                .all(|k| witness.get(k).is_some())
            && witness.keys().iter().all(|k| allowed.contains(k))
            && witness
                .as_object()
                .is_some_and(|rows| rows.iter().all(|(_, v)| v.as_str().is_some())),
        "C witness vector has missing or unknown keys",
    )?;
    let repo = format!("GetBusbar/{}", witness.at("repo").as_str().unwrap_or(""));
    let owner = repos
        .get(&repo)
        .cloned()
        .unwrap_or(Value::Object(Vec::new()));
    let url = witness.at("url").as_str().unwrap_or("");
    let ok = owner.at("language").as_str() == Some("c")
        && !owner.at("private").truthy()
        && witness.at("sdk").as_str() == Some(sdk)
        && is_revision(witness.at("commit").as_str().unwrap_or(""))
        && url.strip_suffix(".git").unwrap_or(url) == format!("https://github.com/{repo}")
        && witness
            .get("language")
            .and_then(Value::as_str)
            .unwrap_or("c")
            == "c"
        && witness.get("kind").unwrap_or(owner.at("kind")) == owner.at("kind")
        && witness
            .get("header")
            .and_then(Value::as_str)
            .unwrap_or(PUBLIC_C_HEADER)
            == PUBLIC_C_HEADER;
    need(ok, "C witness source/SDK mismatch")?;
    Ok(revisions)
}

/// `ENV_KEY.fullmatch(key)[1]`.
fn env_key_kind(key: &str) -> Option<&str> {
    let tokens: Vec<&str> = key.split('_').collect();
    let (first, rest) = tokens.split_first()?;
    let (last, middle) = rest.split_last()?;
    let alnum = |t: &&str| {
        !t.is_empty()
            && t.bytes()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    };
    (*first == "BUSBAR"
        && ["CDYLIB", "PLUGIN", "MANIFEST", "DECLARES", "SETTINGS"].contains(last)
        && middle.iter().all(alnum)
        && middle.contains(&"TEST"))
    .then_some(*last)
}

/// `declarations(metadata)`.
fn declarations(metadata: &Value) -> R<Value> {
    let kinds = |kind: &str| -> &'static [&'static str] {
        match kind {
            "cdylib" => &["CDYLIB", "PLUGIN"],
            "manifest" => &["MANIFEST"],
            "declares" => &["DECLARES"],
            "empty-settings" => &["SETTINGS"],
            _ => &[],
        }
    };
    need(
        metadata.is_object() && metadata.keys().iter().all(|k| !kinds(k).is_empty()),
        "unknown artifact declaration fields",
    )?;
    let mut seen: Vec<&str> = Vec::new();
    for (kind, keys) in metadata.as_object().into_iter().flatten() {
        let keys = keys.as_array();
        need(
            keys.is_some_and(|k| !k.is_empty() && k.len() <= 16),
            "artifact binding count exceeds limit",
        )?;
        for key in keys.unwrap_or(&[]) {
            let text = key.as_str().filter(|t| t.chars().count() <= 128);
            let kind_ok = text
                .and_then(env_key_kind)
                .is_some_and(|k| kinds(kind).contains(&k));
            need(kind_ok, "unknown or mistyped artifact environment key")?;
            let text = text.unwrap_or("");
            need(!seen.contains(&text), "duplicate artifact environment key")?;
            seen.push(text);
        }
    }
    Ok(metadata.clone())
}

fn ident(value: &Value) -> bool {
    value.as_str().is_some_and(|t| {
        let mut chars = t.chars();
        t.len() <= 128
            && chars.next().is_some_and(|c| c.is_ascii_lowercase())
            && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
    })
}

fn get<'a>(value: &'a Value, key: &str) -> &'a Value {
    value.get(key).unwrap_or(&crate::json::NULL)
}

/// `plan(policy, vector, sources, target, cache, revision)`: the expected
/// owner-declared environment bindings.
pub fn plan(
    policy: &Value,
    vector: &Value,
    sources: &dyn Fn(&Value) -> PathBuf,
    target: &Path,
    cache: &Path,
    revision: &str,
    reader: GitReader,
) -> R<Dict> {
    plan_images(policy, vector, sources, target, cache, revision, reader).map(|(values, _)| values)
}

/// `plan` plus every product the script builds, in order, with the exact
/// image path Cargo writes (Python `plan()`'s item list).
pub fn plan_images(
    policy: &Value,
    vector: &Value,
    sources: &dyn Fn(&Value) -> PathBuf,
    target: &Path,
    cache: &Path,
    revision: &str,
    reader: GitReader,
) -> R<(Dict, Vec<(Value, PathBuf)>)> {
    let mut built: Vec<(Value, PathBuf)> = Vec::new();
    need(
        vector.is_object()
            && vector
                .at("products")
                .as_array()
                .is_some_and(|p| !p.is_empty() && p.len() <= 128),
        "invalid product vector size",
    )?;
    vector_revisions(policy, vector)?;
    need(
        is_revision(revision),
        "immutable assembly revision required",
    )?;
    let suffix = if cfg!(target_os = "macos") {
        ".dylib"
    } else {
        ".so"
    };
    let work = cache.join("ci-product-inputs").join(revision);
    let mut images: Vec<String> = Vec::new();
    let mut values = Dict::default();
    for row in vector.at("products").as_array().unwrap_or(&[]) {
        need(
            ["repo", "package", "kind", "alias"]
                .iter()
                .all(|k| ident(row.at(k))),
            "invalid artifact identity",
        )?;
        let declares = relative_path(at(row, "declares")?)?;
        let repo = row.at("repo").as_str().unwrap_or("");
        let package = row.at("package").as_str().unwrap_or("");
        let entries = at(
            at(repositories(policy)?, &format!("GetBusbar/{repo}"))?,
            "packages",
        )?;
        let wrappers: Vec<&Value> = entries
            .as_array()
            .unwrap_or(&[])
            .iter()
            .filter(|e| {
                e.at("name").as_str() == Some(package) && e.at("role").as_str() == Some("wrapper")
            })
            .collect();
        need(
            wrappers.len() == 1,
            "artifact package is not its classified wrapper",
        )?;
        let source = sources(row);
        let commit = sp::at_str(row, "commit")?;
        let lock = blob(&source, commit, "Cargo.lock", 16 << 20, reader)?;
        need(
            sha256::hex(&lock) == sp::at_str(row, "lock_sha256")?,
            "artifact owner lock differs from vector",
        )?;
        let manifest_path = sp::at_str(wrappers[0], "manifest")?;
        let manifest = toml(&blob(&source, commit, manifest_path, 256 << 10, reader)?)?;
        need(
            at(at(&manifest, "package")?, "name")?.as_str() == Some(package),
            "artifact wrapper package mismatch",
        )?;
        let empty = Value::Object(Vec::new());
        let package_table = at(&manifest, "package")?;
        let metadata = package_table.get("metadata").unwrap_or(&empty);
        let metadata = metadata.get("busbar").unwrap_or(&empty);
        let metadata = declarations(metadata.get("test-artifacts").unwrap_or(&empty))?;
        if !metadata.truthy() {
            continue;
        }
        let library = manifest.get("lib").cloned().unwrap_or(empty.clone());
        let default_name = package.replace('-', "_");
        let name = library
            .get("name")
            .cloned()
            .unwrap_or(default_name.as_str().into());
        let name_ok = name.as_str().is_some_and(|t| {
            let mut chars = t.chars();
            t.len() <= 128
                && chars.next().is_some_and(|c| c.is_ascii_lowercase())
                && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        });
        let name = name.as_str().unwrap_or("").to_owned();
        let crate_types = get(&library, "crate-type")
            .as_array()
            .unwrap_or(&[])
            .to_vec();
        need(
            name_ok
                && crate_types.iter().any(|t| t.as_str() == Some("cdylib"))
                && at(row, "image")?.as_str() == Some(format!("lib{name}.so").as_str()),
            "artifact image differs from wrapper target",
        )?;
        let checkout = work.join("sources").join(format!("{repo}-{commit}"));
        let cdylib = sp::text(&target.join("debug").join(format!("lib{name}{suffix}")));
        let manifest_out = sp::text(&work.join(repo).join("manifest.json"));
        let declares_path = sp::text(&checkout.join(&declares));
        let paths = [
            ("cdylib", cdylib.clone()),
            ("manifest", manifest_out),
            ("declares", declares_path),
            ("empty-settings", "{}".to_owned()),
        ];
        for (kind, path) in &paths {
            if *kind != "empty-settings" {
                confined_path(
                    Path::new(path),
                    if *kind == "cdylib" { target } else { cache },
                )?;
            }
        }
        need(
            !images.contains(&cdylib),
            "artifact owners collide on image path",
        )?;
        if metadata.get("declares").is_some() || metadata.get("manifest").is_some() {
            blob(&source, commit, &declares, 1 << 20, reader)?;
        }
        for (kind, keys) in metadata.as_object().into_iter().flatten() {
            let path = &paths
                .iter()
                .find(|(k, _)| k == kind)
                .map(|(_, p)| p.clone())
                .unwrap_or_default();
            for key in keys.as_array().unwrap_or(&[]) {
                let key = key.as_str().unwrap_or("");
                need(
                    !values.contains(key),
                    "artifact owners collide on environment key",
                )?;
                values.set(key, path.clone());
            }
        }
        need(
            values.0.len() <= 256,
            "total artifact bindings exceed limit",
        )?;
        built.push((row.clone(), PathBuf::from(&cdylib)));
        images.push(cdylib);
    }
    need(!values.0.is_empty(), "no owner-declared product inputs")?;
    Ok((values, built))
}

/// The controller's own image plan, read from the exact canonical commits.
pub fn canonical_images(
    work: &Path,
    policy: &Value,
    vector: &Value,
    revision: &str,
) -> R<Vec<(Value, PathBuf)>> {
    let work = sp::resolve(work);
    let canonical = work.join("canonical-inputs");
    let reader = |source: &Path, args: &[&str]| -> R<Vec<u8>> {
        need(
            source.parent() == Some(canonical.as_path()),
            "unexpected canonical owner source",
        )?;
        let trust = format!("safe.directory={}", sp::text(source));
        let mut full = vec!["-c", "safe.directory=", "-c", trust.as_str()];
        full.extend_from_slice(args);
        git(source, &full)
    };
    plan_images(
        policy,
        vector,
        &|row: &Value| canonical.join(row.at("repo").as_str().unwrap_or("")),
        &work.join("target"),
        &work.join("cache"),
        revision,
        &reader,
    )
    .map(|(_, built)| built)
}

/// `load_product_inputs(stdout, work, policy, vector, revision)`.
pub fn load_product_inputs(
    stdout: &Path,
    work: &Path,
    policy: &Value,
    vector: &Value,
    revision: &str,
) -> R<Dict> {
    let work = sp::resolve(work);
    let size = std::fs::metadata(stdout).at(stdout)?.len();
    need(size <= 4096, "product input map filename exceeds limit")?;
    let filename = sp::read_text(stdout)?;
    let path = regular_under(Path::new(filename.trim()), &work.join("cache"))?;
    need(
        path == work
            .join("cache/ci-product-inputs")
            .join(revision)
            .join("environment.json"),
        "unexpected product input map path",
    )?;
    need(
        std::fs::metadata(&path).at(&path)?.len() <= 128 << 10,
        "product input map exceeds limit",
    )?;
    let canonical = work.join("canonical-inputs");
    let reader = |source: &Path, args: &[&str]| -> R<Vec<u8>> {
        need(
            source.parent() == Some(canonical.as_path()),
            "unexpected canonical owner source",
        )?;
        let trust = format!("safe.directory={}", sp::text(source));
        let mut full = vec!["-c", "safe.directory=", "-c", trust.as_str()];
        full.extend_from_slice(args);
        git(source, &full)
    };
    let expected = plan(
        policy,
        vector,
        &|row: &Value| canonical.join(row.at("repo").as_str().unwrap_or("")),
        &work.join("target"),
        &work.join("cache"),
        revision,
        &reader,
    )?;
    let values = loads_unique(&sp::read(&path)?)?;
    let expected_value = Value::Object(
        expected
            .0
            .iter()
            .map(|(k, v)| (k.clone(), Value::from(v.as_str())))
            .collect(),
    );
    need(
        values.is_object() && values == expected_value,
        "product input map has missing, unexpected or mismatched bindings",
    )?;
    let mut bindings = Dict::default();
    for (key, value) in values.as_object().into_iter().flatten() {
        if value.as_str() == Some("{}") {
            bindings.set(key, "{}");
            continue;
        }
        let text = value.as_str();
        need(text.is_some(), "product path must be a string")?;
        let path = PathBuf::from(text.unwrap_or(""));
        let roots: Vec<PathBuf> = ["target", "cache"]
            .iter()
            .map(|n| work.join(n))
            .filter(|root| path.starts_with(root))
            .collect();
        need(
            roots.len() == 1,
            "product path is outside candidate build/cache outputs",
        )?;
        regular_under(&path, &roots[0])?;
        bindings.set(key, text.unwrap_or(""));
    }
    Ok(bindings)
}

/// `check.validate_c_recipe(recipe, entry)`.
pub fn validate_c_recipe(recipe: &Value, entry: &Value) -> R<()> {
    need(
        recipe.has_keys(&["sources", "test-root", "unit", "schema"]),
        "C witness recipe has missing or unknown keys",
    )?;
    let unit = recipe.at("unit");
    let schema = recipe.at("schema");
    need(
        unit.has_keys(&["sources", "defines"]) && schema.has_keys(&["source", "driver"]),
        "C witness requires bounded unit and schema recipes",
    )?;
    let sources = |values: &Value| -> R<Vec<String>> {
        let rows = values.as_array();
        let texts: Option<Vec<&str>> = rows
            .map(|r| r.iter().map(Value::as_str).collect())
            .unwrap_or(None);
        need(
            texts.as_ref().is_some_and(|t| {
                (1..=16).contains(&t.len())
                    && t.iter().enumerate().all(|(i, v)| !t[..i].contains(v))
            }),
            "C witness source count or duplicates",
        )?;
        let mut out = Vec::new();
        for value in rows.unwrap_or(&[]) {
            let path = relative_path(value)?;
            need(
                path.ends_with(".c"),
                "C witness source must be a relative C file",
            )?;
            out.push(path);
        }
        Ok(out)
    };
    let mut recipe_sources = sources(recipe.at("sources"))?;
    let unit_sources = sources(unit.at("sources"))?;
    sources(&Value::Array(vec![schema.at("source").clone()]))?;
    let mut classified: Vec<String> = entry
        .at("sources")
        .as_array()
        .unwrap_or(&[])
        .iter()
        .map(|v| v.as_str().unwrap_or("").to_owned())
        .collect();
    recipe_sources.sort();
    classified.sort();
    need(
        recipe_sources == classified,
        "C witness sources differ from trusted classification",
    )?;
    need(
        relative_path(schema.at("driver"))?.ends_with(".py"),
        "C schema driver must be a relative Python file",
    )?;
    let test_root = PathBuf::from(relative_path(recipe.at("test-root"))?);
    let others = unit_sources.iter().cloned().chain([
        schema.at("source").as_str().unwrap_or("").to_owned(),
        schema.at("driver").as_str().unwrap_or("").to_owned(),
    ]);
    let leaves = recipe_sources
        .iter()
        .any(|s| Path::new(s).parent() != Some(test_root.as_path()))
        || others
            .into_iter()
            .any(|s| !Path::new(&s).starts_with(&test_root));
    need(
        !leaves,
        "C witness test paths leave their declared source root",
    )?;
    let defines = unit.at("defines").as_array();
    let names: Option<Vec<&str>> = defines
        .map(|d| d.iter().map(Value::as_str).collect())
        .unwrap_or(None);
    need(
        names.as_ref().is_some_and(|names| {
            names.len() <= 8
                && names.iter().all(|d| {
                    d.strip_prefix("BUSBAR_").is_some_and(|rest| {
                        (1..=96).contains(&rest.len())
                            && rest
                                .bytes()
                                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_')
                    })
                })
                && names
                    .iter()
                    .enumerate()
                    .all(|(i, v)| !names[..i].contains(v))
        }),
        "C witness permits bounded macro names, never compiler arguments",
    )
}

/// `check.load_c_recipe(policy, repository, checkout, revision)`.
pub fn load_c_recipe(
    policy: &Value,
    repository: &str,
    checkout: &Path,
    revision: Option<&str>,
) -> R<Value> {
    let empty = Value::Object(Vec::new());
    let entry = repositories(policy)?.get(repository).unwrap_or(&empty);
    need(
        entry.at("language").as_str() == Some("c"),
        "C witness owner is not classified as C",
    )?;
    let reader = |source: &Path, args: &[&str]| git(source, args);
    let head = String::from_utf8_lossy(&git(checkout, &["rev-parse", "HEAD"])?)
        .trim()
        .to_owned();
    if let Some(revision) = revision {
        need(
            head == revision,
            "C witness checkout differs from admitted commit",
        )?;
    }
    let revision = revision.unwrap_or(&head).to_owned();
    let relative = "testing/c-witness.json";
    let data = blob(checkout, &revision, relative, 16 << 10, &reader)?;
    need(
        sp::read(&regular_under(&checkout.join(relative), checkout)?)? == data,
        "C witness recipe differs from its committed bytes",
    )?;
    let recipe = loads_unique(&data)?;
    validate_c_recipe(&recipe, entry)?;
    let mut paths: Vec<String> = Vec::new();
    paths.extend(
        recipe
            .at("sources")
            .as_array()
            .unwrap_or(&[])
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned)),
    );
    paths.extend(
        recipe
            .at("unit")
            .at("sources")
            .as_array()
            .unwrap_or(&[])
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned)),
    );
    for key in ["source", "driver"] {
        paths.push(
            recipe
                .at("schema")
                .at(key)
                .as_str()
                .unwrap_or("")
                .to_owned(),
        );
    }
    for relative in paths {
        let expected = blob(checkout, &revision, &relative, 2 << 20, &reader)?;
        need(
            sp::read(&regular_under(&checkout.join(&relative), checkout)?)? == expected,
            "C witness source differs from its committed bytes",
        )?;
    }
    Ok(recipe)
}

/// `check.generated_revision(checkout)`: the exact registered generated source.
pub fn generated_revision(checkout: &Path) -> R<String> {
    use std::os::unix::fs::MetadataExt;
    let checkout = checked_directory(checkout)?;
    let mut inventory: Vec<(String, Value)> = Vec::new();
    let mut total = 0u64;
    for (count, path) in sp::rglob(&checkout).into_iter().enumerate() {
        need(
            count < 10000,
            "generated architecture source exceeds entry count",
        )?;
        let info = std::fs::symlink_metadata(&path).at(&path)?;
        let relative = path.strip_prefix(&checkout).unwrap_or(&path).to_owned();
        let kind = info.file_type();
        need(
            (kind.is_dir() || kind.is_file())
                && !relative.components().any(|c| c.as_os_str() == ".git"),
            "generated architecture source contains indirect or Git control files",
        )?;
        let text = sp::text(&relative);
        let mut row = crate::json::object([
            ("path", text.as_str().into()),
            ("permissions", u64::from(info.mode() & 0o7777).into()),
            ("kind", "directory".into()),
            ("size", 0u64.into()),
            ("sha256", Value::Null),
        ]);
        if kind.is_file() {
            total += info.len();
            need(
                info.nlink() == 1 && info.len() <= 16 << 20 && total <= 128 << 20,
                "generated architecture source exceeds collection bounds",
            )?;
            let payload = sp::read(&path)?;
            need(
                payload.len() as u64 == info.len(),
                "generated architecture source changed while fingerprinting",
            )?;
            row.set("kind", "file".into());
            row.set("size", info.len().into());
            row.set("sha256", sha256::hex(&payload).into());
        }
        inventory.push((text, row));
    }
    inventory.sort_by(|a, b| a.0.cmp(&b.0));
    let encoded = crate::json::encoded(&Value::Array(
        inventory.into_iter().map(|(_, r)| r).collect(),
    ));
    Ok(format!(
        "generated-sha256:{}",
        sha256::hex(&encoded[..encoded.len() - 1])
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_keys_and_paths_follow_the_owner_contract() {
        assert_eq!(env_key_kind("BUSBAR_TEST_PLUGIN"), Some("PLUGIN"));
        assert_eq!(env_key_kind("BUSBAR_AUTH_TEST_LDAP_CDYLIB"), Some("CDYLIB"));
        assert_eq!(env_key_kind("BUSBAR_AUTH_CDYLIB"), None);
        assert_eq!(env_key_kind("BUSBAR__TEST_CDYLIB"), None);
        assert_eq!(relative_path(&"a/b.c".into()).unwrap(), "a/b.c");
        assert_eq!(
            relative_path(&"a/../b".into()).unwrap_err().message,
            "product source path must be relative and confined"
        );
        assert_eq!(
            relative_path(&"a b".into()).unwrap_err().message,
            "invalid product source path"
        );
        let metadata = crate::json::parse(br#"{"cdylib": ["BUSBAR_TEST_MANIFEST"]}"#).unwrap();
        assert_eq!(
            declarations(&metadata).unwrap_err().message,
            "unknown or mistyped artifact environment key"
        );
    }

    #[test]
    fn duplicate_bindings_refuse() {
        assert!(duplicate_keys(br#"{"a": 1, "b": {"c": 1, "c": 2}}"#));
        assert!(duplicate_keys(br#"[{"a": "x", "a": "y"}]"#));
        assert!(!duplicate_keys(
            br#"{"a": {"a": [1, {"a": "}"}]}, "b": "a"}"#
        ));
        assert!(duplicate_keys(br#"{"a": 1, "a": 2}"#));
        assert_eq!(
            loads_unique(br#"{"K": "1", "K": "2"}"#)
                .unwrap_err()
                .message,
            "duplicate product input"
        );
    }

    #[test]
    fn generated_revision_binds_modes_and_bytes() {
        let root = sp::resolve(&std::env::temp_dir())
            .join(format!("busbar-ci-generated-{}", sp::uuid_hex()));
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/lib.rs"), "fn x() {}\n").unwrap();
        let first = generated_revision(&root).unwrap();
        assert!(first.starts_with("generated-sha256:"));
        std::fs::write(root.join("src/lib.rs"), "fn y() {}\n").unwrap();
        assert_ne!(generated_revision(&root).unwrap(), first);
        std::fs::create_dir_all(root.join(".git")).unwrap();
        assert_eq!(
            generated_revision(&root).unwrap_err().message,
            "generated architecture source contains indirect or Git control files"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }
}
