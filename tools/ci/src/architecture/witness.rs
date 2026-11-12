//! Approved positive/negative SDK examples compiled against the candidate
//! APIs. Unlike a bare compile_fail result, each negative must fail with its
//! intended rustc error category. The confined pool path seeds the harness
//! dependency closure once; a failed seed falls back to fresh targets.
use super::graph::inline;
use super::{
    Call, Case, Ctx, Log, Policy, Slot, elapsed, key, key_str, loads, progress, read, splitlines,
    str_list, strings,
};
use crate::confine::Done;
use crate::json::Value;
use crate::pathx::{self, join, text};
use crate::proc::{Result, require};
use crate::py;
use crate::sha256;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

pub const WITNESS_SEED: &str = "witness_seed";
const SEED_LOG_TAIL_LINES: usize = 200;
const HARNESS_UNIT_PREFIXES: [&str; 3] = [
    "architecture-compiler-witnesses-",
    "architecture_compiler_witnesses-",
    "witness_",
];

/// The optional dependency seed failed (cases fall back), or a fatal error.
pub enum SeedError {
    Fallback(String, Option<PathBuf>),
    Fatal(String),
}

impl From<String> for SeedError {
    fn from(error: String) -> SeedError {
        SeedError::Fatal(error)
    }
}

fn fallback<T>(message: impl Into<String>) -> std::result::Result<T, SeedError> {
    Err(SeedError::Fallback(message.into(), None))
}

/// Snapshot disposed candidate output into a new controller-owned tree. Only
/// directories and regular files are accepted; contents are copied, so no link
/// or inode is shared with anything a later candidate can write.
pub fn copy_candidate_tree(
    source: &Path,
    destination: &Path,
) -> std::result::Result<(), SeedError> {
    let metadata = pathx::io(fs::symlink_metadata(source), source)?;
    if !metadata.is_dir() {
        let name = source
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        return fallback(format!(
            "compiler dependency seed output is not a directory: {name}"
        ));
    }
    pathx::mkdir(destination, 0o755)?;
    let mut pending = vec![PathBuf::new()];
    while let Some(relative) = pending.pop() {
        let directory = source.join(&relative);
        let mut entries: Vec<_> = pathx::io(fs::read_dir(&directory), &directory)?
            .filter_map(|e| e.ok())
            .collect();
        entries.sort_by_key(|e| e.file_name());
        let mut children = Vec::new();
        for entry in entries {
            let path = entry.path();
            let child = relative.join(entry.file_name());
            let kind = pathx::io(fs::symlink_metadata(&path), &path)?.file_type();
            if kind.is_dir() {
                pathx::mkdir(&destination.join(&child), 0o755)?;
                children.push(child);
            } else if kind.is_file() {
                pathx::copy2(&path, &destination.join(&child))?;
            } else {
                return fallback(format!(
                    "compiler dependency seed contains a non-regular entry: {}",
                    text(&child)
                ));
            }
        }
        pending.extend(children.into_iter().rev());
    }
    Ok(())
}

/// Re-emit Cargo's vendor replacement table with the controller-owned directory.
pub fn vendor_source_config(
    config: &str,
    directory: &Path,
) -> std::result::Result<String, SeedError> {
    let sources = match crate::toml::parse(config) {
        Ok(value) => value,
        Err(error) => return fallback(format!("unreadable cargo vendor configuration: {error}")),
    };
    let table = sources.at("source");
    if sources.keys() != ["source"] || !table.is_object() {
        return fallback("unexpected cargo vendor configuration");
    }
    let quoted = |s: &str| crate::json::dumps(&Value::str(s), false);
    let mut lines = Vec::new();
    for (name, row) in table.as_object().unwrap() {
        if name == "vendored-sources" {
            if row.keys() != ["directory"] {
                return fallback("unexpected vendored source table");
            }
            continue;
        }
        let permitted = ["replace-with", "git", "rev", "branch", "tag", "registry"];
        let rows = row.as_object().map(Vec::as_slice).unwrap_or(&[]);
        if row.at("replace-with").as_str() != Some("vendored-sources")
            || !rows.iter().all(|(k, _)| permitted.contains(&k.as_str()))
            || !rows.iter().all(|(_, v)| v.as_str().is_some())
        {
            return fallback(format!("unexpected cargo vendor replacement: {name}"));
        }
        lines.push(format!("[source.{}]", quoted(name)));
        for (k, v) in rows {
            lines.push(format!(
                "{} = {}",
                quoted(k),
                quoted(v.as_str().unwrap_or(""))
            ));
        }
    }
    if table.get("vendored-sources").is_none() {
        return fallback("cargo vendor emitted no vendored source");
    }
    lines.push("[source.vendored-sources]".into());
    lines.push(format!("directory = {}", quoted(&text(directory))));
    Ok(lines.join("\n") + "\n")
}

pub struct Seed {
    pub target: PathBuf,
    pub config: PathBuf,
    pub receipt: Value,
}

fn rendered_messages(stdout: &str) -> Vec<String> {
    let mut rendered = Vec::new();
    for line in splitlines(stdout) {
        let row = if line.starts_with('{') {
            match py::loads(line.as_bytes()) {
                Ok(row) => row,
                Err(_) => continue,
            }
        } else {
            Value::Object(Vec::new())
        };
        if row.is_object() && row.at("reason").as_str() == Some("compiler-message") {
            let message = row.at("message");
            let value = if py::truthy(message) {
                message.at("rendered")
            } else {
                &Value::Null
            };
            rendered.push(if py::truthy(value) {
                py::str(value)
            } else {
                String::new()
            });
        }
    }
    rendered
}

fn remove(path: &Path) -> Result<()> {
    if pathx::is_symlink(path) || !path.is_dir() {
        pathx::io(fs::remove_file(path), path)
    } else {
        pathx::rmtree(path)
    }
}

/// Build the witness harness's dependency closure once, before any case runs.
///
/// The seed is a trusted harness example with no candidate-selected code of its
/// own, compiled from the same manifest, features and toolchain as every case.
/// Its outputs are snapshotted after the seed container is disposed. Cases
/// receive a private copy; none can alter it. Dependency sources are vendored
/// to one stable path because each isolate's private CARGO_HOME differs and
/// Cargo fingerprints registry source paths.
fn seed_compiler_dependencies(
    ctx: &mut Ctx,
    harness: &Path,
    scratch: &Path,
    cases: &[Case],
) -> std::result::Result<Seed, SeedError> {
    let started = Instant::now();
    ctx.progress("compiler-seed", "start", vec![]);
    let root = scratch.join("compiler-witness-seed");
    if fs::symlink_metadata(&root).is_ok() {
        return Err(SeedError::Fatal(
            "compiler dependency seed must be fresh".into(),
        ));
    }
    pathx::mkdir(&root, 0o777)?;
    pathx::write(
        &harness.join("examples").join(format!("{WITNESS_SEED}.rs")),
        "fn main() {}\n",
    )?;
    let manifest = text(&harness.join("Cargo.toml"));
    let candidate = ctx
        .engine
        .as_deref()
        .map(|e| e.candidate())
        .ok_or("confined seed requires an engine".to_owned())?;
    let confined =
        |ctx: &mut Ctx, name: &str, command: Vec<String>| -> std::result::Result<Done, SeedError> {
            let mut call = Call::new(&command).cwd(scratch);
            call.capture = true;
            call.discard = true;
            let result = ctx.run(call)?;
            // rustc diagnostics arrive as JSON on stdout; Cargo's own errors on stderr.
            let log = root.join(format!("{name}.log"));
            pathx::write(
                &log,
                format!(
                    "{}\n{}",
                    result.stderr,
                    rendered_messages(&result.stdout).join("\n")
                ),
            )?;
            if result.code != 0 {
                // No case has run yet; the caller falls back to the unseeded path.
                return Err(SeedError::Fallback(
                    format!("compiler dependency seed failed: {name}"),
                    Some(log),
                ));
            }
            Ok(result)
        };
    let output = candidate.join(format!("witness-vendor-{}", pathx::uuid4()));
    // Directory sources need a lockfile for git (patched) dependencies; keep
    // the vendor resolution and give it to every later seeded invocation.
    let lock = candidate
        .join(format!("witness-lock-{}", pathx::uuid4()))
        .join("Cargo.lock");
    let setting = format!(
        "resolver.lockfile-path={}",
        crate::json::dumps(&Value::str(text(&lock)), false)
    );
    let vendored = confined(
        ctx,
        "vendor",
        strings(&[
            "cargo",
            "vendor",
            "--manifest-path",
            &manifest,
            "--versioned-dirs",
            "--config",
            &setting,
            &text(&output),
        ]),
    )?;
    let lock_parent = lock.parent().unwrap().to_path_buf();
    if pathx::is_symlink(&lock) || !lock.is_file() || pathx::is_symlink(&lock_parent) {
        return fallback("cargo vendor produced no regular lockfile");
    }
    let lock_text = pathx::read_text(&lock)?;
    if let Err(error) = crate::toml::parse(&lock_text) {
        return fallback(format!("unreadable cargo vendor lockfile: {error}"));
    }
    pathx::copyfile(&lock, &harness.join("Cargo.lock"))?;
    pathx::rmtree(&lock_parent)?;
    copy_candidate_tree(&output, &root.join("vendor"))?;
    pathx::rmtree(&output)?;
    let config = root.join("vendor.toml");
    pathx::write(
        &config,
        vendor_source_config(&vendored.stdout, &root.join("vendor"))?,
    )?;
    let output = candidate.join(format!("witness-seed-target-{}", pathx::uuid4()));
    // Superset first; the contract-only resolution may unify fewer features.
    let mut configurations: Vec<bool> = cases.iter().map(|c| c.needs_loader).collect();
    configurations.sort();
    configurations.dedup();
    configurations.reverse();
    for needs_loader in &configurations {
        let mut command = strings(&[
            "cargo",
            "check",
            "--manifest-path",
            &manifest,
            "--example",
            WITNESS_SEED,
            "--message-format=json",
            "--config",
            &text(&config),
            "--target-dir",
            &text(&output),
        ]);
        if *needs_loader {
            command.extend(strings(&["--features", "busbar-plugin-loader"]));
        }
        if let Some(jobs) = ctx.check_jobs() {
            command.extend(["--jobs".into(), jobs.to_string()]);
        }
        confined(
            ctx,
            if *needs_loader {
                "seed-loader"
            } else {
                "seed-contract"
            },
            command,
        )?;
    }
    let target = root.join("target");
    copy_candidate_tree(&output, &target)?;
    pathx::rmtree(&output)?;
    // Never ship a cached result for any harness unit: each case's own crate is
    // always compiled by its own rustc invocation.
    let mut profiles: Vec<PathBuf> = fs::read_dir(&target)
        .map(|it| {
            it.flatten()
                .map(|e| e.path())
                .filter(|p| p.is_dir())
                .collect()
        })
        .unwrap_or_default();
    profiles.sort();
    for profile in profiles {
        for name in ["examples", "incremental"] {
            if profile.join(name).exists() {
                pathx::rmtree(&profile.join(name))?;
            }
        }
        for name in [".fingerprint", "deps", "build"] {
            let directory = profile.join(name);
            if !directory.is_dir() {
                continue;
            }
            for entry in pathx::io(fs::read_dir(&directory), &directory)?.flatten() {
                let file = entry.file_name().to_string_lossy().into_owned();
                if HARNESS_UNIT_PREFIXES.iter().any(|p| file.starts_with(p)) {
                    let path = entry.path();
                    if path.is_dir() {
                        pathx::rmtree(&path)?;
                    } else {
                        pathx::io(fs::remove_file(&path), &path)?;
                    }
                }
            }
        }
    }
    let files: Vec<PathBuf> = pathx::rglob(&target, "*")
        .into_iter()
        .filter(|p| p.is_file())
        .collect();
    let bytes: u64 = files
        .iter()
        .map(|p| fs::metadata(p).map(|m| m.len()).unwrap_or(0))
        .sum();
    let receipt = Value::Object(vec![
        (
            "configurations".into(),
            Value::int(configurations.len() as i64),
        ),
        ("target_files".into(), Value::int(files.len() as i64)),
        ("target_bytes".into(), Value::int(bytes)),
        (
            "vendor_config_sha256".into(),
            Value::str(sha256::hex(&pathx::read(&config)?)),
        ),
    ]);
    let mut details = vec![("elapsed_seconds", elapsed(started))];
    for (k, v) in receipt.as_object().unwrap() {
        details.push((k.as_str(), v.clone()));
    }
    ctx.progress("compiler-seed", "finish", details);
    Ok(Seed {
        target,
        config,
        receipt,
    })
}

/// Report a failed seed and remove everything it added before any case runs.
fn abandon_compiler_seed(
    ctx: &mut Ctx,
    harness: &Path,
    scratch: &Path,
    reason: &str,
    log: Option<&Path>,
) -> Result<Value> {
    let mut record = vec![
        ("status".to_owned(), Value::str("failed")),
        ("reason".to_owned(), Value::str(reason)),
        ("fallback".to_owned(), Value::str("unseeded")),
    ];
    if let Some(log) = log.filter(|l| l.is_file()) {
        let content = pathx::read_lossy(log)?;
        let lines = splitlines(&content);
        let tail = &lines[lines.len().saturating_sub(SEED_LOG_TAIL_LINES)..];
        for line in tail {
            ctx.log
                .line(format!("compiler-seed-log: {}", py::prefix(line, 4000)));
        }
        record.push(("log_tail_lines".into(), Value::int(tail.len() as i64)));
        record.push((
            "log_sha256".into(),
            Value::str(sha256::hex(&pathx::read(log)?)),
        ));
        if let Some(evidence) = &ctx.evidence {
            let name = format!(
                "architecture-compiler-seed-{}",
                log.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default()
            );
            pathx::copyfile(log, &evidence.join(&name))?;
            record.push(("log".into(), Value::str(name)));
        }
    }
    let details: Vec<(&str, Value)> = record
        .iter()
        .map(|(k, v)| (k.as_str(), v.clone()))
        .collect();
    ctx.progress("compiler-seed", "fallback", details);
    // Seed containers are disposed (candidate_run returned). Unseeded cases must
    // see the original harness: no lockfile, seed example, vendor or target.
    for path in [
        harness.join("Cargo.lock"),
        harness.join("examples").join(format!("{WITNESS_SEED}.rs")),
    ] {
        if fs::symlink_metadata(&path).is_ok() {
            pathx::io(fs::remove_file(&path), &path)?;
        }
    }
    let root = scratch.join("compiler-witness-seed");
    for name in ["vendor", "target"] {
        if root.join(name).exists() {
            pathx::rmtree(&root.join(name))?;
        }
    }
    let candidate = ctx
        .engine
        .as_deref()
        .map(|e| e.candidate())
        .unwrap_or_default();
    for pattern in [
        "witness-vendor-*",
        "witness-lock-*",
        "witness-seed-target-*",
    ] {
        for path in pathx::glob(&candidate, pattern) {
            remove(&path)?;
        }
    }
    Ok(Value::Object(record))
}

/// `docs`: the doc-comment text of a trusted source, prefixes removed.
pub(super) fn doc_text(source: &str) -> String {
    let mut docs = Vec::new();
    for line in splitlines(source) {
        let trimmed = line.trim_start_matches(crate::confine::py_space);
        if trimmed.starts_with("///") || trimmed.starts_with("//!") {
            let mut rest = &trimmed[3..];
            if let Some(stripped) = rest.strip_prefix(' ') {
                rest = stripped;
            }
            docs.push(rest.to_owned());
        }
    }
    docs.join("\n")
}

/// `re.findall(r'```([^\n]*)\n(.*?)```', docs, re.DOTALL)`.
pub(super) fn code_blocks(docs: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut at = 0;
    while let Some(found) = docs[at..].find("```") {
        let start = at + found;
        let flags_start = start + 3;
        let Some(newline) = docs[flags_start..].find('\n') else {
            break;
        };
        let body_start = flags_start + newline + 1;
        let Some(end) = docs[body_start..].find("```") else {
            // No closing fence: retry one character later, as findall scans.
            at = start + 1;
            continue;
        };
        out.push((
            docs[flags_start..flags_start + newline].to_owned(),
            docs[body_start..body_start + end].to_owned(),
        ));
        at = body_start + end + 3;
    }
    out
}

fn word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// `re.search(r'\bfn\s+main\s*\(', code)`.
pub(super) fn has_main(code: &str) -> bool {
    let chars: Vec<char> = code.chars().collect();
    let space = crate::confine::py_space;
    for i in 0..chars.len() {
        if chars[i] != 'f' || chars.get(i + 1) != Some(&'n') || (i > 0 && word(chars[i - 1])) {
            continue;
        }
        let mut j = i + 2;
        let spaced = j;
        while j < chars.len() && space(chars[j]) {
            j += 1;
        }
        if j == spaced
            || chars.len() < j + 4
            || chars[j..j + 4].iter().collect::<String>() != "main"
        {
            continue;
        }
        j += 4;
        while j < chars.len() && space(chars[j]) {
            j += 1;
        }
        if chars.get(j) == Some(&'(') {
            return true;
        }
    }
    false
}

/// `re.findall(r'E[0-9]{4}', flags)`.
pub(super) fn error_codes(flags: &str) -> Vec<String> {
    let bytes = flags.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 5 <= bytes.len() {
        if bytes[i] == b'E' && bytes[i + 1..i + 5].iter().all(u8::is_ascii_digit) {
            out.push(flags[i..i + 5].to_owned());
            i += 5;
        } else {
            i += 1;
        }
    }
    out
}

/// The trusted witness inventory: harness manifest, example sources, cases.
pub fn prepare_cases(
    policy: &Policy,
    candidate: &Path,
    trusted: &Path,
    harness: &Path,
) -> Result<Vec<Case>> {
    pathx::mkdirs(&harness.join("examples"))?;
    let mut lines = strings(&[
        "[workspace]",
        "[package]",
        "name=\"architecture-compiler-witnesses\"",
        "version=\"0.0.0\"",
        "edition=\"2021\"",
        "[dependencies]",
    ]);
    let core = key(&policy.data, "core")?;
    for name in ["busbar-contract", "busbar-plugin-loader"] {
        let manifest = join(candidate, key_str(key(core, name)?, "manifest")?);
        let directory = manifest.parent().unwrap_or(Path::new("/")).to_path_buf();
        let optional = if name == "busbar-plugin-loader" {
            ", optional=true"
        } else {
            ""
        };
        lines.push(format!(
            "{name}={{path={}{optional}}}",
            inline(&Value::str(text(&directory)))
        ));
    }
    let root = read(&join(candidate, "Cargo.toml"))?;
    for (source, table) in root
        .at("patch")
        .as_object()
        .map(Vec::as_slice)
        .unwrap_or(&[])
    {
        lines.push(format!("[patch.{}]", inline(&Value::str(source.clone()))));
        for (name, cfg) in table.as_object().map(Vec::as_slice).unwrap_or(&[]) {
            let mut cfg = cfg.clone();
            if let Some(relative) = cfg.get("path").and_then(Value::as_str).map(str::to_owned) {
                cfg.set(
                    "path",
                    Value::str(text(&pathx::resolve(&join(candidate, relative)))),
                );
            }
            lines.push(format!(
                "{}={}",
                inline(&Value::str(name.clone())),
                inline(&cfg)
            ));
        }
    }
    pathx::write(&harness.join("Cargo.toml"), lines.join("\n") + "\n")?;
    let contract_root = PathBuf::from(key_str(key(core, "busbar-contract")?, "manifest")?)
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default();
    let mut cases: Vec<Case> = Vec::new();
    for row in policy
        .data
        .at("compiler_witnesses")
        .as_array()
        .unwrap_or(&[])
    {
        let source_name = key_str(row, "source")?;
        let source = pathx::read_text(&join(trusted, source_name))?;
        let markers: Vec<&str> = key(row, "markers")?
            .as_array()
            .unwrap_or(&[])
            .iter()
            .filter_map(Value::as_str)
            .collect();
        let selected: Vec<(String, String)> = code_blocks(&doc_text(&source))
            .into_iter()
            .filter(|(_, code)| markers.iter().any(|m| code.contains(m)))
            .collect();
        if !py::eq(&Value::int(selected.len() as i64), key(row, "count")?) {
            return Err(format!(
                "trusted compiler witness inventory changed: {source_name}"
            ));
        }
        for (flags, code) in selected {
            let mut code = splitlines(&code)
                .into_iter()
                .map(|line| line.strip_prefix("# ").unwrap_or(line))
                .collect::<Vec<_>>()
                .join("\n");
            if !has_main(&code) {
                code = format!("fn main() {{\n{code}\n}}\n");
            }
            let expected = error_codes(&flags);
            if flags.contains("compile_fail") && expected.is_empty() {
                return Err("negative witness must name its expected compiler error".into());
            }
            let name = format!("witness_{:02}", cases.len());
            pathx::write(&harness.join("examples").join(format!("{name}.rs")), &code)?;
            // Contract-only witnesses need no loader build. Keep the loader for
            // every other source owner and any explicit reference, including
            // forbidden/private imports whose intended error needs its presence.
            let needs_loader = !Path::new(source_name).starts_with(&contract_root)
                || code.contains("busbar_plugin_loader");
            cases.push(Case {
                name,
                expected,
                needs_loader,
            });
        }
    }
    require(
        !cases.is_empty() && cases.iter().any(|c| c.expected.is_empty()),
        "compiler witnesses require a positive control",
    )?;
    Ok(cases)
}

struct Shared<'a> {
    harness: &'a Path,
    seed: Option<&'a Seed>,
    jobs: Option<i128>,
    total: usize,
}

/// One witness verdict; `run` executes its confined compiler command.
fn compile_case(
    log: &Log,
    shared: &Shared,
    case: &Case,
    candidate: Option<PathBuf>,
    run: &mut dyn FnMut(&[String]) -> Result<Done>,
) -> Result<()> {
    let name = &case.name;
    // Each confined case still gets fresh artifacts. They are no longer needed
    // once its process exits; retaining all cases exhausts the bounded job disk.
    let mut command = strings(&[
        "cargo",
        "check",
        "--manifest-path",
        &text(&shared.harness.join("Cargo.toml")),
        "--example",
        name,
        "--message-format=json",
    ]);
    if case.needs_loader {
        command.extend(strings(&["--features", "busbar-plugin-loader"]));
    }
    if let Some(jobs) = shared.jobs {
        command.extend(["--jobs".into(), jobs.to_string()]);
    }
    if let Some(seed) = shared.seed {
        // A private copy inside this case's own isolate root, never the seed
        // itself. The pool removes it with the isolate after disposal.
        let target = candidate
            .unwrap_or_default()
            .join(format!("witness-target-{}", pathx::uuid4()));
        pathx::copytree(&seed.target, &target)?;
        command.extend([
            "--config".into(),
            text(&seed.config),
            "--target-dir".into(),
            text(&target),
        ]);
    }
    let jobs = shared.jobs.map_or(Value::Null, Value::int);
    let total = Value::int(shared.total as i64);
    progress(
        log,
        "compiler-witnesses",
        "start",
        vec![
            ("case", Value::str(name.clone())),
            ("total", total.clone()),
            ("expected", str_list(&case.expected)),
            ("build_jobs", jobs.clone()),
        ],
    );
    let started = Instant::now();
    let result = run(&command)?;
    let mut messages = Vec::new();
    for line in splitlines(&result.stdout) {
        if line.starts_with('{') {
            messages.push(loads(line)?);
        }
    }
    let target_name = |row: &Value| row.at("target").at("name").as_str().map(str::to_owned);
    let errors: Vec<&Value> = messages
        .iter()
        .filter(|row| {
            row.at("reason").as_str() == Some("compiler-message")
                && target_name(row).as_deref() == Some(name.as_str())
                && row.at("message").at("level").as_str() == Some("error")
        })
        .map(|row| row.at("message"))
        .collect();
    let mut codes: Vec<Value> = Vec::new();
    for error in &errors {
        if py::truthy(error.at("code")) {
            let code = error.at("code").at("code").clone();
            if !codes.iter().any(|c| py::eq(c, &code)) {
                codes.push(code);
            }
        }
    }
    codes.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
    let rendered: Vec<String> = errors
        .iter()
        .map(|e| e.get("rendered").map_or(String::new(), py::str))
        .collect();
    let log_text = format!("{}\n{}", result.stderr, rendered.join("\n"));
    let log_path = shared.harness.join(format!("{name}.log"));
    pathx::write(&log_path, &log_text)?;
    let intersects = codes.iter().any(|c| {
        c.as_str()
            .is_some_and(|c| case.expected.iter().any(|e| e == c))
    });
    let mut passed = (case.expected.is_empty() && result.code == 0)
        || (!case.expected.is_empty() && result.code != 0 && intersects);
    let mut details = Vec::new();
    if shared.seed.is_some() {
        let artifacts: Vec<&Value> = messages
            .iter()
            .filter(|row| row.at("reason").as_str() == Some("compiler-artifact"))
            .collect();
        // A seeded positive must prove rustc checked this case's own crate now;
        // a fresh (cached) result for it is never accepted as success.
        let fresh_false = |row: &Value| matches!(row.at("fresh"), Value::Bool(false));
        let compiled = artifacts
            .iter()
            .any(|row| target_name(row).as_deref() == Some(name.as_str()) && fresh_false(row));
        passed = passed && (!case.expected.is_empty() || compiled);
        let rebuilt = artifacts
            .iter()
            .filter(|row| fresh_false(row) && target_name(row).as_deref() != Some(name.as_str()))
            .count();
        details.push(("dependency_units_rebuilt", Value::int(rebuilt as i64)));
    }
    let received = Value::Array(codes.clone());
    let mut finish = vec![
        ("case", Value::str(name.clone())),
        ("total", total),
        ("expected", str_list(&case.expected)),
        ("received", received.clone()),
        ("build_jobs", jobs),
        ("passed", passed.into()),
        ("exit_code", Value::int(result.code)),
        ("elapsed_seconds", elapsed(started)),
        ("log_sha256", Value::str(sha256::hex(log_text.as_bytes()))),
    ];
    finish.extend(details);
    progress(log, "compiler-witnesses", "finish", finish);
    if !passed {
        let expected = if case.expected.is_empty() {
            "successful positive control".to_owned()
        } else {
            pathx::repr_list(&case.expected)
        };
        return Err(format!(
            "{name}: expected {expected}, received {}; see {}",
            py::repr(&received),
            text(&log_path)
        ));
    }
    Ok(())
}

pub fn check_compiler_witnesses(
    ctx: &mut Ctx,
    policy: &Policy,
    candidate: &Path,
    trusted: &Path,
    scratch: &Path,
    parallel: bool,
) -> Result<Value> {
    let harness = scratch.join("compiler-witnesses");
    let cases = prepare_cases(policy, candidate, trusted, &harness)?;
    if parallel && ctx.engine.is_none() {
        return Err("parallel compiler witnesses require confinement".into());
    }
    if parallel {
        ctx.engine.as_deref_mut().unwrap().pool_check()?;
    }
    let jobs = if parallel {
        Some(crate::confine::COMPILER_POOL_JOBS as i128)
    } else {
        ctx.check_jobs()
    };
    // Only the isolated pool path is seeded; the serial fallback is unchanged.
    let mut seed = None;
    let mut fallback_record = None;
    if parallel {
        match seed_compiler_dependencies(ctx, &harness, scratch, &cases) {
            Ok(value) => seed = Some(value),
            Err(SeedError::Fatal(error)) => return Err(error),
            Err(SeedError::Fallback(reason, log)) => {
                // The seed is an optimisation only: restore exactly the unseeded
                // inputs and run every case on its own fresh target as before.
                fallback_record = Some(abandon_compiler_seed(
                    ctx,
                    &harness,
                    scratch,
                    &reason,
                    log.as_deref(),
                )?);
            }
        }
    }
    let shared = Shared {
        harness: &harness,
        seed: seed.as_ref(),
        jobs,
        total: cases.len(),
    };
    if parallel {
        let log = ctx.log;
        let engine = ctx.engine.as_deref_mut().unwrap();
        engine.pool_map(&cases, &|slot: &mut dyn Slot, case: &Case| {
            let candidate = slot.candidate();
            compile_case(log, &shared, case, Some(candidate), &mut |argv| {
                slot.run(argv, scratch, shared.seed.is_some())
            })
        })?;
    } else {
        for case in &cases {
            let log = ctx.log;
            let candidate = ctx.engine.as_deref().map(|e| e.candidate());
            compile_case(log, &shared, case, candidate, &mut |argv| {
                let mut call = Call::new(argv).cwd(scratch);
                call.capture = true;
                call.discard = true;
                ctx.run(call)
            })?;
        }
    }
    let mut receipt = Value::Object(vec![
        ("compiler_witnesses".into(), Value::int(cases.len() as i64)),
        ("production_features".into(), true.into()),
    ]);
    if let Some(seed) = &seed {
        let mut record = seed.receipt.clone();
        record.set("status", "seeded".into());
        receipt.set("compiler_dependency_seed", record);
        // Every case container is disposed; release the bounded job disk.
        pathx::rmtree(&seed.target)?;
        pathx::rmtree(&seed.config.parent().unwrap().join("vendor"))?;
    } else if let Some(record) = fallback_record {
        receipt.set("compiler_dependency_seed", record);
    }
    Ok(receipt)
}
