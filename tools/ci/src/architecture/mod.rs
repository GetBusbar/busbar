//! `busbar-ci architecture`: check the shipping Cargo graph against an
//! admission-owned kind boundary policy (former scripts/architecture/check.py).
//!
//! The caller supplies the repository identity and policy from the trusted CI
//! checkout. Candidate metadata never grants a role. A separate probe resolves
//! production roots without unifying their dev features; declared inactive
//! edges are checked as well. Core additionally binds its assembly vector and
//! graph and compiles the trusted compiler witnesses against candidate APIs.
//!
//! The CLI, `architecture.json` bytes, `architecture-progress:` lines, verdicts
//! and exit codes are those of the former script. Candidate commands run through
//! the protected execution context exactly as before (see `confine`).
mod graph;
mod sources;
mod witness;

#[cfg(test)]
mod tests;

use crate::confine::{self, Done, Env, Execution, Hooks};
use crate::json::{self, Value};
use crate::pathx::{self, text};
use crate::proc::{Result, require};
use crate::py;
use crate::sha256;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub use graph::Policy;

pub const CORE: &str = "GetBusbar/busbar";

/// One candidate command (`candidate_run` / `candidate_output` arguments).
#[derive(Clone, Debug, Default)]
pub struct Call {
    pub argv: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub env: Option<Env>,
    pub capture: bool,
    pub check: bool,
    pub discard: bool,
}

impl Call {
    pub fn new(argv: &[String]) -> Call {
        Call {
            argv: argv.to_vec(),
            ..Default::default()
        }
    }
    pub fn cwd(mut self, cwd: &Path) -> Call {
        self.cwd = Some(cwd.to_path_buf());
        self
    }
}

/// A compiler witness case: example name, expected rustc codes, loader feature.
#[derive(Clone, Debug, PartialEq)]
pub struct Case {
    pub name: String,
    pub expected: Vec<String>,
    pub needs_loader: bool,
}

/// One compiler isolate of the confined pool.
pub trait Slot {
    fn candidate(&self) -> PathBuf;
    fn run(&mut self, argv: &[String], cwd: &Path) -> Result<Done>;
}

pub type CaseFn<'a> = dyn Fn(&mut dyn Slot, &Case) -> Result<()> + Sync + 'a;

/// The protected execution context (`EXECUTION`) as the checks use it.
pub trait Engine {
    fn candidate(&self) -> PathBuf;
    fn config(&self) -> &Value;
    /// `EXECUTION.run`: returns the completed process; `check` raises.
    fn run(&mut self, call: &Call) -> Result<Done>;
    /// `EXECUTION.check_output`.
    fn output(&mut self, call: &Call) -> Result<String>;
    /// `EXECUTION.compiler_pool()` construction (its budget check).
    fn pool_check(&mut self) -> Result<()>;
    /// `pool.map(compile_case, cases)`.
    fn pool_map(&mut self, cases: &[Case], case: &CaseFn) -> Result<()>;
}

/// Progress and diagnostic lines (stderr); tests capture them.
#[derive(Default)]
pub struct Log(pub Option<Mutex<Vec<String>>>);

impl Log {
    pub fn line(&self, line: String) {
        match &self.0 {
            Some(lines) => lines.lock().unwrap().push(line),
            None => {
                let mut err = std::io::stderr().lock();
                let _ = writeln!(err, "{line}");
                let _ = err.flush();
            }
        }
    }
    #[cfg(test)]
    pub fn lines(&self) -> Vec<String> {
        self.0
            .as_ref()
            .map(|l| l.lock().unwrap().clone())
            .unwrap_or_default()
    }
}

/// `architecture_progress`: the parent retains stderr even if its bounded
/// controller timeout interrupts this process before the receipt is written.
pub fn progress(log: &Log, stage: &str, event: &str, details: Vec<(&str, Value)>) {
    let mut row = vec![
        ("stage".to_owned(), Value::str(stage)),
        ("event".to_owned(), Value::str(event)),
    ];
    row.extend(details.into_iter().map(|(k, v)| (k.to_owned(), v)));
    log.line(format!(
        "architecture-progress: {}",
        json::dumps(&Value::Object(row), false)
    ));
}

pub struct Ctx<'a> {
    pub engine: Option<&'a mut dyn Engine>,
    /// The --output directory; failed seed logs are retained there.
    pub evidence: Option<PathBuf>,
    pub log: &'a Log,
    /// `os.environ.get('CI_SERVER_HOST')`.
    pub ci_host: Option<String>,
}

impl Ctx<'_> {
    pub fn progress(&self, stage: &str, event: &str, details: Vec<(&str, Value)>) {
        progress(self.log, stage, event, details);
    }

    /// `candidate_run`: confined when an execution context exists, never a
    /// host fallback; the host path inherits cwd/env unless given.
    pub fn run(&mut self, call: Call) -> Result<Done> {
        match self.engine.as_deref_mut() {
            Some(engine) => engine.run(&call),
            None => host_run(&call),
        }
    }

    pub fn output(&mut self, call: Call) -> Result<String> {
        match self.engine.as_deref_mut() {
            Some(engine) => engine.output(&call),
            None => host_output(&call),
        }
    }

    /// `compiler_check_jobs()`.
    pub fn check_jobs(&self) -> Option<i128> {
        let resources = self.engine.as_deref()?.config().at("resources");
        let cpus = resources.at("cpus").as_int().unwrap_or(0);
        let memory = resources.at("memory_bytes").as_int().unwrap_or(0);
        // These compiler checks completed all 52 cases under the 4 CPU / 6 GiB
        // boundary before optimized-build scheduling was reduced to one job.
        Some(if memory >= 6 << 30 { cpus.min(4) } else { 1 })
    }

    /// `compiler_witness_parallel()`: only the disk-backed aggregate budget
    /// exercised by job 5374.
    pub fn witness_parallel(&self) -> bool {
        let Some(engine) = self.engine.as_deref() else {
            return false;
        };
        let config = engine.config();
        let resources = config.at("resources");
        let storage = config.at("isolation");
        let n = |v: &Value, k: &str| v.at(k).as_int().unwrap_or(0);
        n(resources, "cpus") >= 4
            && n(resources, "memory_bytes") >= 6 << 30
            && n(resources, "pids") >= 1024
            && storage.at("storage_kind").as_str() == Some("loop-ext4")
            && n(storage, "storage_bytes") >= 24 << 30
    }
}

fn host_run(call: &Call) -> Result<Done> {
    let env: Option<Vec<(String, String)>> = call
        .env
        .as_ref()
        .map(|e| e.iter().map(|(k, v)| (k.clone(), v.clone())).collect());
    let (code, stdout, stderr, _) = confine::spawn(
        &call.argv,
        env.as_deref(),
        call.cwd.as_deref(),
        call.capture,
        call.capture,
        None,
    )?;
    if call.check && code != 0 {
        return Err(pathx::called_process_error(&call.argv, code));
    }
    Ok(Done {
        code,
        stdout: pathx::text_mode(&stdout)?,
        stderr: pathx::text_mode(&stderr)?,
    })
}

fn host_output(call: &Call) -> Result<String> {
    let env: Option<Vec<(String, String)>> = call
        .env
        .as_ref()
        .map(|e| e.iter().map(|(k, v)| (k.clone(), v.clone())).collect());
    let (code, stdout, _, _) = confine::spawn(
        &call.argv,
        env.as_deref(),
        call.cwd.as_deref(),
        true,
        false,
        None,
    )?;
    if code != 0 {
        return Err(pathx::called_process_error(&call.argv, code));
    }
    pathx::text_mode(&stdout)
}

impl Engine for Execution {
    fn candidate(&self) -> PathBuf {
        self.roots.candidate.clone()
    }
    fn config(&self) -> &Value {
        &self.config
    }
    fn run(&mut self, call: &Call) -> Result<Done> {
        let cwd = call
            .cwd
            .clone()
            .unwrap_or_else(|| self.roots.checkout.clone());
        let env = call.env.clone().unwrap_or_else(confine::process_env);
        self.invocation(
            &call.argv,
            &cwd,
            &env,
            call.discard,
            |command, client_env| {
                let (code, stdout, stderr, _) = confine::spawn(
                    command,
                    Some(client_env),
                    None,
                    call.capture,
                    call.capture,
                    None,
                )?;
                if call.check && code != 0 {
                    return Err(pathx::called_process_error(command, code));
                }
                Ok(Done {
                    code,
                    stdout: pathx::text_mode(&stdout)?,
                    stderr: pathx::text_mode(&stderr)?,
                })
            },
        )
    }
    fn output(&mut self, call: &Call) -> Result<String> {
        let cwd = call
            .cwd
            .clone()
            .unwrap_or_else(|| self.roots.checkout.clone());
        let env = call.env.clone().unwrap_or_else(confine::process_env);
        self.invocation(&call.argv, &cwd, &env, false, |command, client_env| {
            let (code, stdout, _, _) =
                confine::spawn(command, Some(client_env), None, true, false, None)?;
            if code != 0 {
                return Err(pathx::called_process_error(command, code));
            }
            pathx::text_mode(&stdout)
        })
    }
    fn pool_check(&mut self) -> Result<()> {
        self.compiler_pool().map(|_| ())
    }
    fn pool_map(&mut self, cases: &[Case], case: &CaseFn) -> Result<()> {
        struct Isolate<'a>(&'a mut confine::Slot);
        impl Slot for Isolate<'_> {
            fn candidate(&self) -> PathBuf {
                self.0.execution.roots.candidate.clone()
            }
            fn run(&mut self, argv: &[String], cwd: &Path) -> Result<Done> {
                self.0.run(argv, cwd)
            }
        }
        self.compiler_pool()?
            .map(cases, &|slot: &mut confine::Slot, _, row: &Case| {
                case(&mut Isolate(slot), row)
            })
            .map(|_| ())
    }
}

// ---- Python text semantics --------------------------------------------------

/// `str.splitlines()`.
pub fn splitlines(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut chars = text.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        let breaks = matches!(
            c,
            '\n' | '\r'
                | '\u{b}'
                | '\u{c}'
                | '\u{1c}'
                | '\u{1d}'
                | '\u{1e}'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        );
        if breaks {
            out.push(&text[start..i]);
            let mut end = i + c.len_utf8();
            if c == '\r'
                && let Some((j, '\n')) = chars.peek().copied()
            {
                chars.next();
                end = j + 1;
            }
            start = end;
        }
    }
    if start < text.len() {
        out.push(&text[start..]);
    }
    out
}

/// `str.split()`.
pub fn split_ws(text: &str) -> Vec<&str> {
    text.split(confine::py_space)
        .filter(|s| !s.is_empty())
        .collect()
}

/// `round(seconds, 3)` as `json.dumps` writes it.
pub fn elapsed(started: std::time::Instant) -> Value {
    let seconds = started.elapsed().as_secs_f64();
    let rounded: f64 = format!("{seconds:.3}").parse().unwrap_or(seconds);
    Value::Number(py::float_repr(rounded))
}

pub fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|s| (*s).to_owned()).collect()
}

pub fn str_list(values: &[String]) -> Value {
    Value::Array(values.iter().map(|s| Value::str(s.clone())).collect())
}

pub fn hex40(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

pub fn hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

/// `dict[key]` with Python's KeyError text.
pub fn key<'v>(value: &'v Value, name: &str) -> Result<&'v Value> {
    value
        .get(name)
        .ok_or_else(|| format!("KeyError: {}", py::repr_str(name)))
}

pub fn key_str<'v>(value: &'v Value, name: &str) -> Result<&'v str> {
    key(value, name)?
        .as_str()
        .ok_or_else(|| format!("TypeError: {name} is not a str"))
}

/// `tomllib.load(path)`.
pub fn read(path: &Path) -> Result<Value> {
    crate::toml::parse(&pathx::read_text(path)?)
}

/// `json.loads(text)`.
pub fn loads(text: &str) -> Result<Value> {
    py::loads(text.as_bytes()).map_err(|e| e.message)
}

// ---- generated subjects and execution paths --------------------------------

/// Bound the exact controller-registered generated source, without Git fallback.
pub fn generated_revision(checkout: &Path) -> Result<String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let checkout = confine::checked_directory(checkout)?;
    let mut inventory = Vec::new();
    let mut total = 0u64;
    for (index, path) in pathx::rglob(&checkout, "*").into_iter().enumerate() {
        require(
            index < 10000,
            "generated architecture source exceeds entry count",
        )?;
        let info = pathx::io(std::fs::symlink_metadata(&path), &path)?;
        let relative = path.strip_prefix(&checkout).unwrap_or(&path).to_path_buf();
        let kind = info.file_type();
        require(
            (kind.is_dir() || kind.is_file())
                && !relative.components().any(|c| c.as_os_str() == ".git"),
            "generated architecture source contains indirect or Git control files",
        )?;
        let mut row = vec![
            ("path".to_owned(), Value::str(text(&relative))),
            (
                "permissions".to_owned(),
                Value::int(info.permissions().mode() & 0o7777),
            ),
            ("kind".to_owned(), Value::str("directory")),
            ("size".to_owned(), Value::int(0)),
            ("sha256".to_owned(), Value::Null),
        ];
        if kind.is_file() {
            total += info.len();
            require(
                info.nlink() == 1 && info.len() <= 16 << 20 && total <= 128 << 20,
                "generated architecture source exceeds collection bounds",
            )?;
            let payload = pathx::read(&path)?;
            require(
                payload.len() as u64 == info.len(),
                "generated architecture source changed while fingerprinting",
            )?;
            row[2].1 = Value::str("file");
            row[3].1 = Value::int(info.len());
            row[4].1 = Value::str(sha256::hex(&payload));
        }
        inventory.push(Value::Object(row));
    }
    inventory.sort_by(|a, b| a.at("path").as_str().cmp(&b.at("path").as_str()));
    let encoded = json::encoded(&Value::Array(inventory));
    Ok(format!(
        "generated-sha256:{}",
        sha256::hex(&encoded[..encoded.len() - 1])
    ))
}

pub struct Args {
    pub policy: PathBuf,
    pub repository: String,
    pub checkout: PathBuf,
    pub scratch: PathBuf,
    pub output: PathBuf,
    pub trusted: PathBuf,
    pub sdk: Option<PathBuf>,
    pub execution_context: Option<PathBuf>,
    pub execution_context_sha256: Option<String>,
}

pub fn validate_execution_paths(
    args: &Args,
    execution: &Execution,
    context: &Value,
) -> Result<Option<String>> {
    let mut checkout = execution.roots.checkout.clone();
    let generated = context.get("architecture_checkout");
    if let Some(generated) = generated {
        require(
            generated.has_keys(&["path", "source"]),
            "invalid generated architecture checkout context",
        )?;
        checkout = PathBuf::from(generated.at("path").as_str().unwrap_or(""));
        let valid = checkout.is_absolute()
            && checkout == pathx::resolve(&checkout)
            && execution.extra_readonly.contains(&checkout)
            && checkout.starts_with(execution.roots.candidate.join("generated"))
            && generated_revision(&checkout)? == generated.at("source").as_str().unwrap_or("\0");
        require(
            valid,
            "generated architecture checkout differs from protected context",
        )?;
    }
    let output = pathx::resolve(&args.output);
    require(
        pathx::resolve(&args.checkout) == checkout
            && pathx::resolve(&args.trusted) == execution.roots.trusted
            && pathx::resolve(&args.scratch).starts_with(&execution.roots.harness)
            && output.starts_with(&execution.control)
            && !execution
                .roots
                .all()
                .iter()
                .any(|(_, p)| output.starts_with(p)),
        "architecture controller paths differ from confined execution context",
    )?;
    Ok(generated.map(|g| g.at("source").as_str().unwrap_or("").to_owned()))
}

pub fn source_revision(checkout: &Path) -> Result<String> {
    let argv = strings(&["git", "-C", &text(checkout), "rev-parse", "HEAD"]);
    let (code, stdout, _, _) = confine::spawn(&argv, None, None, true, true, None)?;
    if code != 0 {
        // The native generator job retains its own source/SDK revisions and content hashes.
        return generated_revision(checkout);
    }
    Ok(pathx::text_mode(&stdout)?
        .trim_matches(confine::py_space)
        .to_owned())
}

// ---- command line ------------------------------------------------------------

const USAGE: &str = "usage: busbar-ci architecture [-h] --policy POLICY --repository REPOSITORY\n                               --checkout CHECKOUT --scratch SCRATCH --output\n                               OUTPUT --trusted TRUSTED [--sdk SDK]\n                               [--execution-context EXECUTION_CONTEXT]\n                               [--execution-context-sha256 EXECUTION_CONTEXT_SHA256]";

const OPTIONS: [&str; 9] = [
    "--policy",
    "--repository",
    "--checkout",
    "--scratch",
    "--output",
    "--trusted",
    "--sdk",
    "--execution-context",
    "--execution-context-sha256",
];

fn usage_error(message: &str) -> ! {
    // The former argparse contract: usage on stderr, exit 2.
    eprintln!("{USAGE}\nbusbar-ci architecture: error: {message}");
    std::process::exit(2);
}

fn negative_number(value: &str) -> bool {
    let digits = &value[1..];
    !digits.is_empty()
        && digits.bytes().filter(|c| *c == b'.').count() <= 1
        && digits.bytes().all(|c| c.is_ascii_digit() || c == b'.')
        && digits != "."
}

/// argparse semantics: `--name VALUE`, `--name=VALUE`, unique prefixes, the
/// last occurrence wins, option-like values are refused.
pub fn parse_args(args: &[String]) -> Args {
    let mut values: [Option<String>; 9] = Default::default();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "-h" || arg == "--help" {
            println!(
                "{USAGE}\n\nCheck the shipping Cargo graph against an admission-owned kind boundary policy."
            );
            std::process::exit(0);
        }
        let (name, inline) = match arg.split_once('=') {
            Some((name, value)) if name.starts_with("--") => (name, Some(value.to_owned())),
            _ => (arg.as_str(), None),
        };
        let exact = OPTIONS.iter().position(|o| *o == name);
        let matched: Vec<usize> = match exact {
            Some(i) => vec![i],
            None => (0..OPTIONS.len())
                .filter(|i| {
                    name.len() > 2 && name.starts_with("--") && OPTIONS[*i].starts_with(name)
                })
                .collect(),
        };
        let [option] = matched.as_slice() else {
            if matched.len() > 1 {
                usage_error(&format!("ambiguous option: {arg}"));
            }
            usage_error(&format!("unrecognized arguments: {arg}"));
        };
        let value = match inline {
            Some(value) => value,
            None => {
                index += 1;
                match args.get(index) {
                    Some(value) if !value.starts_with('-') || negative_number(value) => {
                        value.clone()
                    }
                    _ => usage_error(&format!(
                        "argument {}: expected one argument",
                        OPTIONS[*option]
                    )),
                }
            }
        };
        values[*option] = Some(value);
        index += 1;
    }
    let missing: Vec<_> = (0..6)
        .filter(|i| values[*i].is_none())
        .map(|i| OPTIONS[i])
        .collect();
    if !missing.is_empty() {
        usage_error(&format!(
            "the following arguments are required: {}",
            missing.join(", ")
        ));
    }
    let path = |v: &Option<String>| v.as_ref().map(|s| pathx::norm(Path::new(s)));
    Args {
        policy: path(&values[0]).unwrap(),
        repository: values[1].clone().unwrap(),
        checkout: path(&values[2]).unwrap(),
        scratch: path(&values[3]).unwrap(),
        output: path(&values[4]).unwrap(),
        trusted: path(&values[5]).unwrap(),
        sdk: path(&values[6]),
        execution_context: path(&values[7]),
        execution_context_sha256: values[8].clone(),
    }
}

/// The checks after argument parsing (`check.main`), against an optional
/// confined engine. Returns the receipt written to --output.
pub fn check(
    args: &Args,
    mut engine: Option<&mut Execution>,
    generated_source: Option<String>,
    log: &Log,
) -> Result<Value> {
    let policy = Policy::new(read(&args.policy)?)?;
    let checkout = pathx::resolve(&args.checkout);
    require(
        args.repository == CORE
            || policy
                .data
                .at("repositories")
                .get(&args.repository)
                .is_some(),
        &format!("unclassified repository {}", args.repository),
    )?;
    pathx::mkdirs(&args.scratch)?;
    let scratch = pathx::resolve(&args.scratch);
    let trusted = pathx::resolve(&args.trusted);
    let mut ctx = Ctx {
        engine: engine.as_deref_mut().map(|e| e as &mut dyn Engine),
        evidence: pathx::resolve(&args.output).parent().map(Path::to_path_buf),
        log,
        ci_host: std::env::var("CI_SERVER_HOST").ok(),
    };
    let language = policy
        .data
        .at("repositories")
        .at(&args.repository)
        .at("language");
    let receipt = if language.as_str() == Some("c") {
        let sdk = args
            .sdk
            .as_ref()
            .ok_or("C verification requires the pinned SDK checkout")?;
        sources::check_c(
            &mut ctx,
            &policy,
            &args.repository,
            &checkout,
            &pathx::resolve(sdk),
            &scratch,
        )?
    } else {
        ctx.progress("shipping-graph", "start", vec![]);
        let entries =
            graph::check_declared(&policy, &args.repository, &checkout, ctx.ci_host.as_deref())?;
        let metadata = graph::resolve_shipping(&mut ctx, &checkout, &entries, &scratch, false)?;
        let mut receipt = graph::check_graph(
            &metadata,
            &policy,
            &args.repository,
            &checkout,
            ctx.ci_host.as_deref(),
        )?;
        ctx.progress("shipping-graph", "finish", vec![]);
        if args.repository == CORE {
            ctx.progress("assembly-graph", "start", vec![]);
            receipt.set(
                "dependency_vector",
                graph::check_vector(&policy, &checkout, &entries)?,
            );
            let assembled = graph::resolve_shipping(&mut ctx, &checkout, &entries, &scratch, true)?;
            receipt.set(
                "assembly",
                graph::check_graph(
                    &assembled,
                    &policy,
                    &args.repository,
                    &checkout,
                    ctx.ci_host.as_deref(),
                )?,
            );
            ctx.progress("assembly-graph", "finish", vec![]);
            let parallel = ctx.witness_parallel();
            let witnesses = witness::check_compiler_witnesses(
                &mut ctx, &policy, &checkout, &trusted, &scratch, parallel,
            )?;
            extend(&mut receipt, witnesses);
        }
        ctx.progress("source-check", "start", vec![]);
        let sources = sources::check_sources(
            &mut ctx,
            &policy,
            &args.repository,
            &checkout,
            &metadata,
            &trusted,
            &scratch,
        )?;
        extend(&mut receipt, sources);
        ctx.progress("source-check", "finish", vec![]);
        receipt
    };
    drop(ctx);
    finish(args, receipt, engine.as_deref(), generated_source)
}

/// Bind the receipt to the exact checked source, policy and observations.
pub fn finish(
    args: &Args,
    mut receipt: Value,
    engine: Option<&Execution>,
    generated_source: Option<String>,
) -> Result<Value> {
    let checkout = pathx::resolve(&args.checkout);
    let source = if generated_source.is_some() {
        generated_revision(&checkout)?
    } else {
        source_revision(&checkout)?
    };
    if let Some(expected) = &generated_source {
        require(
            source == *expected,
            "generated architecture source changed during qualification",
        )?;
    }
    receipt.set("repository", Value::str(args.repository.clone()));
    receipt.set(
        "policy_sha256",
        Value::str(sha256::hex(&pathx::read(&args.policy)?)),
    );
    receipt.set("source", Value::str(source));
    if let Some(engine) = engine {
        receipt.set(
            "candidate_execution",
            Value::Array(engine.observations.clone()),
        );
        receipt.set("release_eligible", false.into());
    }
    Ok(receipt)
}

pub fn extend(receipt: &mut Value, other: Value) {
    if let Value::Object(rows) = other {
        for (key, value) in rows {
            receipt.set(&key, value);
        }
    }
}

fn run(args: &Args) -> Result<()> {
    let log = Log::default();
    let mut execution = None;
    let mut generated_source = None;
    if let Some(context) = &args.execution_context {
        let expected = args.execution_context_sha256.clone().unwrap_or_default();
        let engine = Execution::from_context(context, &expected, Hooks::default())?;
        let data = loads(&pathx::read_text(context)?)?;
        generated_source = validate_execution_paths(args, &engine, &data)?;
        execution = Some(engine);
    } else if args.execution_context_sha256.is_some() {
        return Err("execution context digest requires its context".into());
    }
    let receipt = check(args, execution.as_mut(), generated_source, &log)?;
    pathx::write(&args.output, json::dumps_indent(&receipt) + "\n")?;
    println!("{}", json::dumps(&receipt, false));
    Ok(())
}

pub fn main(args: Vec<String>) -> i32 {
    let args = parse_args(&args);
    // Cargo metadata and Docker inspection nest deeply; parse on a large stack.
    let worker = std::thread::Builder::new()
        .stack_size(256 << 20)
        .spawn(move || run(&args));
    match worker.map(|handle| handle.join()) {
        Ok(Ok(Ok(()))) => 0,
        Ok(Ok(Err(error))) => {
            eprintln!("architecture: {error}");
            1
        }
        _ => {
            eprintln!("architecture: internal controller failure");
            1
        }
    }
}
