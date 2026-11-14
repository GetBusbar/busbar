//! The trusted syn source scan over candidate sources (with generated OUT_DIR
//! Rust materialized by the exact candidate build), and the C plugin checks.
use super::graph::PUBLIC_C_HEADER;
use super::{CORE, Call, Ctx, Policy, elapsed, key, key_str, loads, read, str_list, strings};
use crate::confine::{self, Env};
use crate::json::{self, Value};
use crate::pathx::{self, join, text};
use crate::proc::{Result, require};
use crate::py;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Every Rust source in each trusted core member, including SDK, tests and
/// build scripts. The candidate cannot remove a member from this inventory by
/// editing its own policy.
pub fn core_source_inventory(policy: &Policy, checkout: &Path) -> Result<Vec<String>> {
    let checkout = pathx::resolve(checkout);
    let mut paths = BTreeSet::new();
    for (_, entry) in policy.core() {
        let manifest = join(&checkout, key_str(entry, "manifest")?);
        let root = pathx::resolve(manifest.parent().unwrap_or(Path::new("/")));
        if !root.starts_with(&checkout) || !root.is_dir() {
            return Err(format!("invalid core source root: {}", text(&root)));
        }
        let mut member = BTreeSet::new();
        for path in pathx::rglob(&root, "*.rs") {
            let resolved = pathx::resolve(&path);
            if !resolved.starts_with(&checkout) {
                return Err(format!(
                    "core source escapes candidate checkout: {}",
                    text(&path)
                ));
            }
            member.insert(text(&resolved));
        }
        if member.is_empty() {
            return Err(format!("core member has no Rust sources: {}", text(&root)));
        }
        paths.extend(member);
    }
    Ok(paths.into_iter().collect())
}

/// Use the actual workspace targets, never binary-only resolution stubs.
pub fn core_target_roots(
    policy: &Policy,
    checkout: &Path,
    metadata: &Value,
) -> Result<Vec<String>> {
    let checkout = pathx::resolve(checkout);
    let mut roots = BTreeSet::new();
    let mut found = BTreeSet::new();
    for package in key(metadata, "packages")?.as_array().unwrap_or(&[]) {
        let name = key_str(package, "name")?;
        let Some(entry) = policy.data.at("core").get(name) else {
            continue;
        };
        let expected = pathx::resolve(&join(&checkout, key_str(entry, "manifest")?));
        if pathx::resolve(Path::new(key_str(package, "manifest_path")?)) != expected {
            return Err(format!(
                "core target metadata does not name its actual manifest: {name}"
            ));
        }
        found.insert(name.to_owned());
        for target in key(package, "targets")?.as_array().unwrap_or(&[]) {
            let path = pathx::resolve(Path::new(key_str(target, "src_path")?));
            if !path.starts_with(&checkout) || !path.is_file() {
                return Err(format!(
                    "core target source escapes or is missing: {}",
                    text(&path)
                ));
            }
            roots.insert(text(&path));
        }
    }
    let core: BTreeSet<String> = policy.core().iter().map(|(n, _)| n.clone()).collect();
    if found != core {
        let missing: Vec<String> = core.difference(&found).cloned().collect();
        return Err(format!(
            "missing actual core target metadata: {}",
            pathx::repr_list(&missing)
        ));
    }
    Ok(roots.into_iter().collect())
}

/// `inventory.write_text(json.dumps(sorted(set(roots))))`.
fn json_list(values: &[String]) -> String {
    json::dumps(&str_list(values), false)
}

/// Run trusted syn checks as a small test harness, independent of candidate tests.
pub fn check_sources(
    ctx: &mut Ctx,
    policy: &Policy,
    repository: &str,
    checkout: &Path,
    metadata: &Value,
    trusted: &Path,
    scratch: &Path,
) -> Result<Value> {
    let mut roots = Vec::new();
    for package in key(metadata, "packages")?.as_array().unwrap_or(&[]) {
        let Some(entry) = package.at("name").as_str().and_then(|n| policy.package(n)) else {
            continue;
        };
        if entry.at("repository").as_str() == Some(repository)
            && matches!(
                entry.at("role").as_str(),
                Some("implementation" | "wrapper")
            )
        {
            for target in key(package, "targets")?.as_array().unwrap_or(&[]) {
                let kinds = key(target, "kind")?.as_array().unwrap_or(&[]);
                if kinds
                    .iter()
                    .any(|k| matches!(k.as_str(), Some("lib" | "rlib" | "cdylib")))
                {
                    roots.push(key_str(target, "src_path")?.to_owned());
                }
            }
        }
    }
    require(
        repository == CORE || !roots.is_empty(),
        "no classified plugin source roots",
    )?;
    let unique: Vec<String> = roots
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let harness = scratch.join("source-check");
    pathx::mkdirs(&harness.join("tests"))?;
    pathx::write(
        &harness.join("tests/architecture_surface.rs"),
        pathx::read(&join(
            trusted,
            "crates/busbar-contract/tests/architecture_surface.rs",
        ))?,
    )?;
    let manifest = read(&join(trusted, "Cargo.toml"))?;
    let deps = key(key(&manifest, "workspace")?, "dependencies")?;
    let mut lines = strings(&[
        "[workspace]",
        "[package]",
        "name=\"architecture-source-check\"",
        "version=\"0.0.0\"",
        "edition=\"2021\"",
        "[dev-dependencies]",
    ]);
    for name in ["syn", "quote", "proc-macro2", "serde_json"] {
        let cfg = key(deps, name)?;
        let mut cfg = match cfg {
            Value::String(_) => Value::Object(vec![("version".into(), cfg.clone())]),
            other => other.clone(),
        };
        if name == "syn" {
            let mut features: BTreeSet<String> = cfg
                .at("features")
                .as_array()
                .unwrap_or(&[])
                .iter()
                .filter_map(|f| f.as_str().map(str::to_owned))
                .collect();
            features.extend(["full".to_owned(), "visit".to_owned()]);
            cfg.set(
                "features",
                str_list(&features.into_iter().collect::<Vec<_>>()),
            );
        }
        let values: Vec<String> = cfg
            .as_object()
            .map(|rows| {
                rows.iter()
                    .map(|(k, v)| format!("{k} = {}", json::dumps(v, false)))
                    .collect()
            })
            .unwrap_or_default();
        lines.push(format!("{name} = {{ {} }}", values.join(", ")));
    }
    pathx::write(&harness.join("Cargo.toml"), lines.join("\n") + "\n")?;
    let mut env: Env = confine::process_env();
    for name in [
        "BUSBAR_ARCHITECTURE_SOURCES",
        "BUSBAR_ARCHITECTURE_POLICY_SOURCES",
        "BUSBAR_ARCHITECTURE_GENERATED",
        "BUSBAR_ARCHITECTURE_GENERATED_DIRS",
    ] {
        env.remove(name);
    }
    if !roots.is_empty() {
        let inventory = scratch.join("source-roots.json");
        pathx::write(&inventory, json_list(&unique))?;
        env.insert("BUSBAR_ARCHITECTURE_SOURCES".into(), text(&inventory));
    }
    let mut mapping: Vec<(String, String)> = Vec::new();
    let mut crate_roots = Vec::new();
    let source_metadata;
    let metadata_used = if repository == CORE {
        // Shipping resolution substitutes empty libraries for binary-only crates. Those
        // stubs cannot identify real custom binary roots or produce their generated Rust.
        let argv = strings(&[
            "cargo",
            "metadata",
            "--no-deps",
            "--format-version",
            "1",
            "--manifest-path",
            &text(&join(checkout, "Cargo.toml")),
        ]);
        source_metadata = loads(&ctx.output(Call::new(&argv).cwd(checkout))?)?;
        crate_roots = core_target_roots(policy, checkout, &source_metadata)?;
        &source_metadata
    } else {
        metadata
    };
    let candidate = ctx.engine.as_deref().map(|e| e.candidate());
    if !roots.is_empty() || repository == CORE {
        // Resolve generated OUT_DIR includes from this exact candidate invocation.
        // Never use a candidate-supplied map or filename search for stale output.
        let mut build_command = if repository == CORE {
            strings(&[
                "cargo",
                "check",
                "--workspace",
                "--manifest-path",
                &text(&join(checkout, "Cargo.toml")),
            ])
        } else {
            strings(&[
                "cargo",
                "build",
                "--manifest-path",
                &text(&scratch.join("shipping-probe/Cargo.toml")),
            ])
        };
        // The global one-job limit protects optimized builds. This workspace
        // check, like the witnesses, can use the existing bounded check budget.
        let jobs = if build_command[1] == "check" {
            ctx.check_jobs()
        } else {
            None
        };
        if let Some(jobs) = jobs {
            build_command.extend(["--jobs".into(), jobs.to_string()]);
        }
        if let (Some(seed), Some(candidate)) = (super::dependency_units(), candidate.as_ref())
            && repository != CORE
        {
            // A private writable copy of trusted dependency units; the seed itself
            // is never mounted. Any failure leaves the probe on a fresh target.
            let probe_target = candidate.join(format!("probe-target-{}", pathx::uuid4()));
            match crate::native::depcache::install(seed, &probe_target, None) {
                Ok(()) => build_command.extend(["--target-dir".into(), text(&probe_target)]),
                Err(reason) => {
                    let _ = std::fs::remove_dir_all(&probe_target);
                    ctx.progress(
                        "dependency-units",
                        "fallback",
                        vec![("reason", Value::str(reason))],
                    );
                }
            }
        }
        let jobs_value = jobs.map_or(Value::Null, Value::int);
        ctx.progress(
            "source-materialization",
            "start",
            vec![
                ("cargo_command", Value::str(build_command[1].clone())),
                ("build_jobs", jobs_value.clone()),
            ],
        );
        let started = std::time::Instant::now();
        let mut argv = build_command.clone();
        argv.push("--message-format=json".into());
        let build = ctx.output(Call::new(&argv).cwd(checkout))?;
        ctx.progress(
            "source-materialization",
            "finish",
            vec![
                ("cargo_command", Value::str(build_command[1].clone())),
                ("elapsed_seconds", elapsed(started)),
                ("build_jobs", jobs_value),
            ],
        );
        for line in super::splitlines(&build) {
            let row = loads(line)?;
            if row.at("reason").as_str() != Some("build-script-executed") {
                continue;
            }
            for package in key(metadata_used, "packages")?.as_array().unwrap_or(&[]) {
                if py::eq(key(package, "id")?, key(&row, "package_id")?)
                    && package
                        .at("name")
                        .as_str()
                        .is_some_and(|n| policy.package(n).is_some())
                {
                    let output = PathBuf::from(key_str(&row, "out_dir")?);
                    if let Some(candidate) = &candidate
                        && (!output.is_absolute()
                            || output != pathx::resolve(&output)
                            || !output.starts_with(candidate))
                    {
                        return Err(
                            "candidate generated source path escapes its build output".into()
                        );
                    }
                    let manifest = PathBuf::from(key_str(package, "manifest_path")?);
                    let directory = text(&pathx::norm(manifest.parent().unwrap_or(Path::new("/"))));
                    let output = text(&pathx::norm(&output));
                    match mapping.iter_mut().find(|(k, _)| *k == directory) {
                        Some(row) => row.1 = output,
                        None => mapping.push((directory, output)),
                    }
                }
            }
        }
        let generated = scratch.join("generated-directories.json");
        let value = Value::Object(
            mapping
                .iter()
                .map(|(k, v)| (k.clone(), Value::str(v.clone())))
                .collect(),
        );
        pathx::write(&generated, json::dumps(&value, false))?;
        env.insert(
            "BUSBAR_ARCHITECTURE_GENERATED_DIRS".into(),
            text(&generated),
        );
    }
    let mut core_files = 0;
    if repository == CORE {
        let inventory = scratch.join("policy-sources.json");
        let raw_paths = core_source_inventory(policy, checkout)?;
        let mut paths: BTreeSet<String> = raw_paths.iter().cloned().collect();
        for (_, output) in &mapping {
            for path in pathx::rglob(Path::new(output), "*.rs") {
                if let Some(candidate) = &candidate
                    && (pathx::is_symlink(&path) || !pathx::resolve(&path).starts_with(candidate))
                {
                    return Err("indirect generated source file".into());
                }
                paths.insert(text(&pathx::resolve(&path)));
            }
        }
        // Handwritten core must not know concrete owners. Generated assembly may
        // link those owners, but remains subject to the short-name selector check.
        let plugin_packages: BTreeSet<String> = policy
            .packages
            .iter()
            .filter(|(_, e)| matches!(e.at("role").as_str(), Some("implementation" | "wrapper")))
            .map(|(n, _)| n.clone())
            .collect();
        let mut names = BTreeSet::new();
        for (repository, _) in policy
            .data
            .at("repositories")
            .as_object()
            .map(Vec::as_slice)
            .unwrap_or(&[])
        {
            let name = repository
                .split_once('/')
                .map(|(_, n)| n)
                .ok_or("IndexError: list index out of range")?;
            let short = name
                .splitn(3, '-')
                .nth(2)
                .ok_or("IndexError: list index out of range")?;
            names.insert(short.to_owned());
        }
        let paths: Vec<String> = paths.into_iter().collect();
        core_files = paths.len();
        let document = Value::Object(vec![
            ("paths".into(), str_list(&paths)),
            ("raw_paths".into(), str_list(&raw_paths)),
            ("roots".into(), str_list(&crate_roots)),
            (
                "plugin_packages".into(),
                str_list(&plugin_packages.into_iter().collect::<Vec<_>>()),
            ),
            (
                "names".into(),
                str_list(&names.into_iter().collect::<Vec<_>>()),
            ),
        ]);
        pathx::write(&inventory, json::dumps(&document, false))?;
        env.insert(
            "BUSBAR_ARCHITECTURE_POLICY_SOURCES".into(),
            text(&inventory),
        );
    }
    let argv = strings(&[
        "cargo",
        "test",
        "--manifest-path",
        &text(&harness.join("Cargo.toml")),
        "--test",
        "architecture_surface",
    ]);
    let mut call = Call::new(&argv).cwd(scratch);
    call.env = Some(env);
    call.check = true;
    ctx.run(call)?;
    Ok(Value::Object(vec![
        ("source_roots".into(), Value::int(unique.len() as i64)),
        ("core_source_files".into(), Value::int(core_files as i64)),
        ("trusted_source_check".into(), true.into()),
    ]))
}

// ---- C plugins ----------------------------------------------------------------

pub fn load_c_recipe(
    policy: &Policy,
    repository: &str,
    checkout: &Path,
    revision: Option<&str>,
) -> Result<Value> {
    Ok(crate::product::load_c_recipe(
        &policy.data,
        repository,
        checkout,
        revision,
    )?)
}

/// `re.findall(r'^\s*#\s*include\s+(.+)$', text, re.MULTILINE)`.
pub fn includes(source: &str) -> Vec<String> {
    let chars: Vec<char> = source.chars().collect();
    let space = |c: char| confine::py_space(c);
    let mut out = Vec::new();
    let mut i = 0;
    while i <= chars.len() {
        if i == 0 || chars[i - 1] == '\n' {
            let mut j = i;
            while j < chars.len() && space(chars[j]) {
                j += 1;
            }
            let word: Vec<char> = "include".chars().collect();
            if j < chars.len() && chars[j] == '#' {
                let mut k = j + 1;
                while k < chars.len() && space(chars[k]) {
                    k += 1;
                }
                if chars.len() >= k + word.len() && chars[k..k + word.len()] == word[..] {
                    let start = k + word.len();
                    let mut end = start;
                    while end < chars.len() && space(chars[end]) {
                        end += 1;
                    }
                    // Greedy \s+, then (.+)$: back off until a non-newline follows.
                    let mut found = None;
                    let mut cut = end;
                    while cut > start {
                        if cut < chars.len() && chars[cut] != '\n' {
                            let mut stop = cut;
                            while stop < chars.len() && chars[stop] != '\n' {
                                stop += 1;
                            }
                            found = Some((cut, stop));
                            break;
                        }
                        cut -= 1;
                    }
                    if let Some((from, to)) = found {
                        out.push(chars[from..to].iter().collect());
                        i = to;
                        // The next ^ can only follow a newline at or after `to`.
                        while i < chars.len() && chars[i] != '\n' {
                            i += 1;
                        }
                        i += 1;
                        continue;
                    }
                }
            }
        }
        i += 1;
    }
    out
}

pub fn check_c(
    ctx: &mut Ctx,
    policy: &Policy,
    repository: &str,
    checkout: &Path,
    sdk: &Path,
    scratch: &Path,
) -> Result<Value> {
    let fields_text = pathx::read_text(&join(checkout, ".busbar-ref"))?;
    let fields = super::split_ws(&fields_text);
    let argv = strings(&["git", "-C", &text(sdk), "rev-parse", "HEAD"]);
    let (code, stdout, _, _) = confine::spawn(&argv, None, None, true, false, None)?;
    if code != 0 {
        return Err(pathx::called_process_error(&argv, code));
    }
    let revision = pathx::text_mode(&stdout)?
        .trim_matches(confine::py_space)
        .to_owned();
    require(
        fields == [revision.as_str(), "1.6.0"],
        "C plugin/header SDK pin mismatch",
    )?;
    let recipe = load_c_recipe(policy, repository, checkout, None)?;
    let sources: Vec<PathBuf> = recipe
        .at("sources")
        .as_array()
        .unwrap_or(&[])
        .iter()
        .map(|v| join(checkout, v.as_str().unwrap_or("")))
        .collect();
    for source in &sources {
        if includes(&pathx::read_text(source)?) != ["\"busbar_plugin.h\""] {
            return Err(format!(
                "C plugin must include only the public ABI header: {}",
                text(source)
            ));
        }
    }
    let confined = ctx.engine.is_some();
    let darwin = !confined && cfg!(target_os = "macos");
    let output_directory = match ctx.engine.as_deref() {
        Some(engine) => engine.candidate().join("architecture"),
        None => scratch.to_path_buf(),
    };
    if !output_directory.is_dir() {
        pathx::mkdir(&output_directory, 0o777)?;
    }
    let library = output_directory.join(if darwin { "plugin.dylib" } else { "plugin.so" });
    let include = join(
        sdk,
        Path::new(PUBLIC_C_HEADER).parent().unwrap_or(Path::new("")),
    );
    let mut argv = strings(&[
        "cc",
        "-std=c11",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-fvisibility=hidden",
        "-fPIC",
        if darwin { "-dynamiclib" } else { "-shared" },
        "-I",
        &text(&include),
    ]);
    argv.extend(sources.iter().map(|s| text(s)));
    argv.extend(["-o".into(), text(&library)]);
    let mut call = Call::new(&argv);
    call.check = true;
    ctx.run(call)?;
    let nm = strings(&[
        "nm",
        if darwin { "-gU" } else { "--defined-only" },
        &text(&library),
    ]);
    let output = ctx.output(Call::new(&nm))?;
    let mut exported = BTreeSet::new();
    for line in super::splitlines(&output) {
        let parts = super::split_ws(line);
        if parts.len() >= 3 {
            let kind = parts[parts.len() - 2];
            if kind.to_uppercase() == kind && kind.to_lowercase() != kind {
                let name = parts[parts.len() - 1];
                exported.insert(name.strip_prefix('_').unwrap_or(name).to_owned());
            }
        }
    }
    let exported: Vec<String> = exported.into_iter().collect();
    if exported != ["busbar_plugin_door"] {
        return Err(format!(
            "C runtime exports are not the sole ABI door: {}",
            pathx::repr_list(&exported)
        ));
    }
    Ok(Value::Object(vec![
        ("source_roots".into(), Value::int(sources.len() as i64)),
        ("c_header_revision".into(), Value::str(revision)),
        ("c_exports".into(), str_list(&exported)),
    ]))
}
