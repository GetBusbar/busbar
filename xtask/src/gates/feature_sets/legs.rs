//! THE LEG: one CI job's (or one matrix row's) cargo invocations, and the FEATURE SET THEY ACTUALLY
//! ENABLE — resolved by cargo, not read off a comment.
//!
//! `# feature-covered: <pkg>/<feature> -- <job> -- <reason>` is a CLAIM about a job. Until this
//! module existed the gate took the claim on its word, and the claim it most often carries is the
//! most fragile one in the tree: "`check` builds it, because `--all-targets` pulls a dev-dependency
//! that turns it on". That coverage is real, and it is one dev-dependency edit away from
//! evaporating with every row still green — the feature stops being compiled and the comment goes
//! on saying it is.
//!
//! So a claim is CHECKED here: the named job's cargo invocations are derived FROM `ci.yml` (and
//! from the scripts those invocations run), each is handed to cargo's own resolver, and the claimed
//! feature has to be in the answer.
//!
//! ## Why `cargo tree`, and not `cargo metadata`
//!
//! `cargo metadata` reports a manifest's DECLARED feature table and the whole dependency graph; it
//! does not report which features a particular `--features`/`--no-default-features`/package
//! selection actually turns on. Reproducing that from the metadata means reimplementing the feature
//! resolver — including the v2 resolver's rule that dev-dependency features unify into a build only
//! when dev targets are built, which is the ONE rule every incidental declaration in this tree
//! rests on. A gate that reimplements the resolver is a gate that disagrees with cargo the first
//! time cargo changes.
//!
//! `cargo tree -e <edges> -f '{p}|{f}'` is cargo's resolver answering the question directly: one
//! line per resolved package, with the features it ended up with. It is a RESOLVE, not a build — no
//! codegen, no target directory writes, about 0.2 s per invocation on the development host.
//!
//! ## Determinism
//!
//! Every resolve runs `--locked --offline`:
//!
//! * `--locked` pins dependency versions to the committed `Cargo.lock`, so the answer is a function
//!   of files that are in the repository and reviewed with the change that moves them.
//! * `--offline` turns "did not need the network" from a hope into a REFUSAL. Without it a resolve
//!   that reaches a registry index answers from whatever that index says today, which is not a
//!   property of this repository and not the same on the next box.
//!
//! Given the same manifests and the same lockfile, every leg resolves to the same bytes on every
//! machine. The resolutions are memoised per process ([`resolve_leg`]) because the tree on disk
//! cannot change while one `xtask` process runs, and a self-test runs the same gate seventeen times
//! over overlays that never touch a manifest.
//!
//! ## What is deliberately NOT derived
//!
//! An invocation carrying an unexpanded `${…}`/`${{…}}` or a `--manifest-path` is out of this
//! workspace's reach: the first names a value only the runner has, the second names a manifest that
//! is not this one (the plugin-pack builds against a checkout of a different repository). Those are
//! REPORTED as out of reach and contribute NOTHING, which is the conservative direction — an
//! invocation this gate cannot read can only make a claim harder to satisfy, never easier.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, OnceLock};

use crate::ctx::Ctx;

/// The cargo subcommands that RESOLVE A BUILD. `fmt`, `metadata` and friends are not builds and
/// enable nothing; `rustc` is, and `scripts/txn-fence.sh` uses it.
pub const BUILD_VERBS: &[&str] = &[
    "build", "check", "clippy", "test", "rustc", "bench", "run", "doc",
];

/// The edge kinds that carry DEV-DEPENDENCY feature unification, and the ones that do not. The
/// whole point of the row is the difference between these two strings.
pub const EDGES_WITH_DEV: &str = "features";
pub const EDGES_NO_DEV: &str = "features,no-dev";

/// One cargo invocation, reduced to what decides a feature resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    /// The command as written, for the report. A row that says "this claim fails" without saying
    /// which command it resolved is a row nobody can act on.
    pub command: String,
    pub packages: Vec<String>,
    pub workspace: bool,
    pub features: Vec<String>,
    pub no_default: bool,
    /// Dev targets are built — `--all-targets`/`--tests`/`--benches`, or `cargo test`/`cargo bench`
    /// which build them by definition. This is the switch that decides whether a dev-dependency's
    /// features unify into the resolution.
    pub dev_targets: bool,
    /// Why this invocation cannot be resolved against this repository alone, if it cannot.
    pub out_of_reach: Option<String>,
}

impl Invocation {
    pub fn edges(&self) -> &'static str {
        if self.dev_targets {
            EDGES_WITH_DEV
        } else {
            EDGES_NO_DEV
        }
    }

    /// The `cargo tree` argument list this invocation resolves under.
    pub fn tree_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        if self.workspace {
            args.push("--workspace".to_string());
        }
        for p in &self.packages {
            args.push("-p".to_string());
            args.push(p.clone());
        }
        if self.no_default {
            args.push("--no-default-features".to_string());
        }
        if !self.features.is_empty() {
            args.push("--features".to_string());
            args.push(self.features.join(","));
        }
        args
    }

    /// The overlay key a self-test plants this invocation's resolution under.
    pub fn overlay_key(&self) -> String {
        Ctx::cargo_tree_resolved_key(self.edges(), &self.tree_args())
    }
}

/// One CI leg: a job, or one matrix row of a job, with the invocations it issues.
#[derive(Debug, Clone)]
pub struct Leg {
    /// The job key as `ci.yml` spells it.
    pub job: String,
    /// The job, plus the matrix row when the job has one. What the report names.
    pub label: String,
    pub invocations: Vec<Invocation>,
}

/// One `matrix.include` row of a job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatrixRow {
    pub name: String,
    pub features: String,
    pub tests: String,
}

// ---------------------------------------------------------------------------------------------
// reading the workflow
// ---------------------------------------------------------------------------------------------

/// The lines of one job's block, by the same two-space indentation rule the rest of this gate uses.
pub fn job_block(text: &str, job: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut inside = false;
    for raw in text.lines() {
        if let Some(name) = super::job_key(raw) {
            inside = name == job;
            continue;
        }
        if inside {
            out.push(raw.to_string());
        }
    }
    out
}

/// The `matrix.include` rows of a job: everything between `include:` and the job's `steps:`.
///
/// Bounded by `steps:` deliberately. A step is also a `- name:` entry, and a reader that ran past
/// `steps:` would mint a matrix row per step — rows with no `features:` at all, which is exactly the
/// shape that reads as "nothing to check".
pub fn matrix_rows(text: &str, job: &str) -> Vec<MatrixRow> {
    let block = job_block(text, job);
    let mut rows: Vec<MatrixRow> = Vec::new();
    let mut inside = false;
    let mut cur: Option<MatrixRow> = None;
    for raw in &block {
        let t = raw.trim();
        if t == "steps:" {
            break;
        }
        if t == "include:" {
            inside = true;
            continue;
        }
        if !inside || t.starts_with('#') {
            continue;
        }
        if let Some(rest) = t.strip_prefix("- name:") {
            if let Some(done) = cur.take() {
                rows.push(done);
            }
            cur = Some(MatrixRow {
                name: rest.trim().trim_matches(['"', '\'']).to_string(),
                features: String::new(),
                tests: String::new(),
            });
            continue;
        }
        let Some(row) = cur.as_mut() else { continue };
        if let Some(v) = t.strip_prefix("features:") {
            row.features = v.trim().trim_matches(['"', '\'']).to_string();
        } else if let Some(v) = t.strip_prefix("tests:") {
            row.tests = v.trim().trim_matches(['"', '\'']).to_string();
        }
    }
    if let Some(done) = cur.take() {
        rows.push(done);
    }
    rows.retain(|r| !r.features.is_empty());
    rows
}

/// `${{ matrix.<key> }}` replaced with this row's value, so a matrix job's steps read as the
/// concrete commands one row runs.
fn substitute(line: &str, row: &MatrixRow) -> String {
    let mut out = line.to_string();
    for (key, value) in [
        ("name", &row.name),
        ("features", &row.features),
        ("tests", &row.tests),
    ] {
        // The spelling in this workflow is `${{ matrix.key }}`; the tolerant forms cost nothing.
        for form in [
            format!("${{{{ matrix.{key} }}}}"),
            format!("${{{{matrix.{key}}}}}"),
        ] {
            out = out.replace(&form, value);
        }
    }
    out
}

/// Repo-relative shell scripts an invocation-bearing block runs. A job whose cargo line lives in a
/// script it calls (`txn-guards` -> `scripts/loom.sh`) is a job whose feature set is in that script.
fn script_refs(cx: &Ctx, lines: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in lines {
        if line.trim_start().starts_with('#') {
            continue;
        }
        let mut rest = line.as_str();
        while let Some(i) = rest.find("scripts/") {
            let tail = &rest[i..];
            let end = tail
                .find(|c: char| !(c.is_ascii_alphanumeric() || "._/-".contains(c)))
                .unwrap_or(tail.len());
            let candidate = &tail[..end];
            if candidate.ends_with(".sh") && cx.exists(candidate) {
                out.push(candidate.to_string());
            }
            rest = &tail[end.max(1)..];
        }
    }
    out.sort();
    out.dedup();
    out
}

/// A backslash-continued command, joined into one line.
fn join_continuations(lines: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut buf = String::new();
    for raw in lines {
        let trimmed = raw.trim_end();
        if let Some(head) = trimmed.strip_suffix('\\') {
            buf.push_str(head);
            buf.push(' ');
            continue;
        }
        buf.push_str(trimmed);
        out.push(std::mem::take(&mut buf));
    }
    if !buf.is_empty() {
        out.push(buf);
    }
    out
}

/// The byte offset of a `cargo ` that BEGINS A COMMAND, or `None`.
///
/// The state machine exists because this file is full of prose that quotes cargo. Two shapes had to
/// be told apart, and a naive `line.contains("cargo ")` gets both wrong:
///
/// * `echo "  phase-0-build (cargo build --release …)"` — inside a double-quoted string. Not a
///   command; it is a message about one. A reader that takes it resolves a package selection that
///   does not exist and reports a red nobody can fix.
/// * `out="$(cargo test -p busbar …)"` — inside a double-quoted string, but inside a COMMAND
///   SUBSTITUTION within it. That one really runs, and it is the `openapi-schema` job's whole test
///   step.
///
/// So `$(` pushes a fresh quoting context and `)` pops it, which is what the shell itself does.
pub fn cargo_start(line: &str) -> Option<usize> {
    let bytes: Vec<char> = line.chars().collect();
    let mut stack: Vec<Option<char>> = vec![None];
    let mut i = 0usize;
    let mut byte = 0usize;
    while i < bytes.len() {
        let c = bytes[i];
        let width = c.len_utf8();
        if c == '\\' {
            i += 1;
            byte += width;
            if i < bytes.len() {
                byte += bytes[i].len_utf8();
                i += 1;
            }
            continue;
        }
        if c == '$' && bytes.get(i + 1) == Some(&'(') {
            stack.push(None);
            i += 2;
            byte += 2;
            continue;
        }
        if c == ')' && stack.len() > 1 {
            stack.pop();
            i += 1;
            byte += width;
            continue;
        }
        let quote = *stack.last().expect("the base context is never popped");
        if let Some(q) = quote {
            if c == q {
                *stack.last_mut().expect("base context") = None;
            }
            i += 1;
            byte += width;
            continue;
        }
        if c == '"' || c == '\'' || c == '`' {
            *stack.last_mut().expect("base context") = Some(c);
            i += 1;
            byte += width;
            continue;
        }
        if line[byte..].starts_with("cargo ") {
            let prev = if i == 0 { None } else { Some(bytes[i - 1]) };
            let attached = prev.is_some_and(|p| p.is_alphanumeric() || "-_/.".contains(p));
            if !attached {
                return Some(byte);
            }
        }
        i += 1;
        byte += width;
    }
    None
}

/// The argument tokens of a command, honouring quotes, stopping at the `--` that hands the rest to
/// the test/lint binary.
fn tokens(segment: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut any = false;
    for c in segment.chars() {
        match quote {
            Some(q) if c == q => {
                quote = None;
            }
            Some(_) => cur.push(c),
            None if c == '"' || c == '\'' => {
                quote = Some(c);
                any = true;
            }
            None if c.is_whitespace() => {
                if any || !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                    any = false;
                }
            }
            None => cur.push(c),
        }
    }
    if any || !cur.is_empty() {
        out.push(cur);
    }
    // Everything after a bare `--` belongs to the invoked binary, not to cargo. Also drop shell
    // tails (`2>&1`, `>file`, `&`, `|`) — they are not cargo arguments and never name a feature.
    if let Some(i) = out.iter().position(|t| t == "--") {
        out.truncate(i);
    }
    // …and everything from the first SHELL OPERATOR or REDIRECTION on belongs to the shell. Without
    // this the `check` job's `cargo test --workspace … > "$RUNNER_TEMP/unix-test.log" 2>&1 &` hands
    // `$RUNNER_TEMP/…` to the argument reader, which sees a runner-only value and declares the
    // workspace test leg unreadable — the single most load-bearing invocation in this workflow.
    if let Some(i) = out.iter().position(|t| {
        matches!(t.as_str(), "|" | "&" | "&&" | "||" | ";") || t.contains('>') || t.contains('<')
    }) {
        out.truncate(i);
    }
    out
}

/// Every cargo invocation in a block of shell/YAML lines.
pub fn invocations(lines: &[String]) -> Vec<Invocation> {
    let live: Vec<String> = lines
        .iter()
        .filter(|l| !l.trim_start().starts_with('#'))
        .cloned()
        .collect();
    let mut out = Vec::new();
    for line in join_continuations(&live) {
        let Some(at) = cargo_start(&line) else {
            continue;
        };
        let toks = tokens(&line[at + "cargo ".len()..]);
        let Some(verb) = toks.first() else { continue };
        if !BUILD_VERBS.contains(&verb.as_str()) {
            continue;
        }
        let mut inv = Invocation {
            command: line.trim().to_string(),
            packages: Vec::new(),
            workspace: false,
            features: Vec::new(),
            no_default: false,
            dev_targets: verb == "test" || verb == "bench",
            out_of_reach: None,
        };
        let mut i = 1usize;
        while i < toks.len() {
            let t = toks[i].as_str();
            if t.contains("${") || t.starts_with('$') {
                inv.out_of_reach = Some(format!(
                    "`{t}` is a value only the runner has, so the resolution this leg performs is \
                     not a function of this repository"
                ));
            }
            if t == "--manifest-path" {
                inv.out_of_reach = Some(
                    "`--manifest-path` names a manifest outside this workspace (the plugin-pack \
                     builds a different checkout), whose features are that repository's to cover"
                        .to_string(),
                );
            }
            match t {
                "-p" | "--package" => {
                    if let Some(v) = toks.get(i + 1) {
                        inv.packages.push(v.clone());
                    }
                    i += 2;
                    continue;
                }
                "--workspace" | "--all" => inv.workspace = true,
                "--features" | "-F" => {
                    if let Some(v) = toks.get(i + 1) {
                        inv.features.extend(
                            v.split(',')
                                .map(str::trim)
                                .filter(|s| !s.is_empty())
                                .map(str::to_string),
                        );
                    }
                    i += 2;
                    continue;
                }
                "--no-default-features" => inv.no_default = true,
                "--all-targets" | "--tests" | "--benches" => inv.dev_targets = true,
                _ => {
                    if let Some(v) = t.strip_prefix("--features=") {
                        inv.features.extend(
                            v.split(',')
                                .map(str::trim)
                                .filter(|s| !s.is_empty())
                                .map(str::to_string),
                        );
                    } else if let Some(v) = t.strip_prefix("--package=") {
                        inv.packages.push(v.to_string());
                    }
                }
            }
            i += 1;
        }
        out.push(inv);
    }
    out
}

/// The leg one job (optionally one matrix row of it) runs.
pub fn leg(cx: &Ctx, workflow: &str, job: &str, row: Option<&MatrixRow>) -> Leg {
    let mut lines = job_block(workflow, job);
    for script in script_refs(cx, &lines) {
        if let Ok(text) = cx.read(&script) {
            lines.extend(text.lines().map(str::to_string));
        }
    }
    if let Some(row) = row {
        lines = lines.iter().map(|l| substitute(l, row)).collect();
    }
    Leg {
        job: job.to_string(),
        label: match row {
            Some(r) => format!("{job} / {}", r.name),
            None => job.to_string(),
        },
        invocations: invocations(&lines),
    }
}

/// What one leg resolved to.
#[derive(Debug, Clone, Default)]
pub struct LegResolution {
    /// Every `pkg/feature` any of the leg's invocations turns on.
    pub features: BTreeSet<String>,
    /// The commands that resolved, for the report.
    pub resolved: Vec<String>,
    /// Commands that could not be resolved from this repository alone, with the reason.
    pub out_of_reach: Vec<String>,
    /// A resolve that FAILED. Never silently dropped: a leg this gate cannot resolve is a leg whose
    /// claims it cannot check, and an unchecked claim is the defect this row exists for.
    pub errors: Vec<String>,
}

/// `pkg/feature` for every package line of a `-f '{p}|{f}'` tree.
pub fn features_of(tree: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for line in tree.lines() {
        let Some(bar) = line.find('|') else { continue };
        let (head, tail) = line.split_at(bar);
        // `├── busbar-core v1.6.0 (/path)` — the package name is the token before the version.
        let Some(vpos) = version_at(head) else {
            continue;
        };
        let Some(pkg) = head[..vpos].split_whitespace().next_back() else {
            continue;
        };
        for f in tail[1..]
            .replace("(*)", " ")
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect::<Vec<_>>()
        {
            out.insert(format!("{pkg}/{f}"));
        }
    }
    out
}

/// The offset of the ` v<digit>` that separates a package name from its version.
fn version_at(head: &str) -> Option<usize> {
    let bytes = head.as_bytes();
    let mut i = 0usize;
    while i + 2 < bytes.len() {
        if bytes[i] == b' ' && bytes[i + 1] == b'v' && bytes[i + 2].is_ascii_digit() {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// The per-process memo. The tree on disk cannot change while one `xtask` process runs, and a
/// self-test runs this gate seventeen times over overlays that edit `ci.yml` and manifests IN
/// MEMORY — neither of which cargo can see. So the same argument list has the same answer for the
/// life of the process, and paying 0.2 s for it once rather than seventeen times is the difference
/// between a row that fits the self-test budget and one that does not.
///
/// A resolution an OVERLAY plants is never memoised and never read from the memo: it is keyed to a
/// plant, not to the tree.
type Memo = BTreeMap<String, Result<String, String>>;
fn memo() -> &'static Mutex<Memo> {
    static MEMO: OnceLock<Mutex<Memo>> = OnceLock::new();
    MEMO.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// The resolver's raw answer for one invocation — memoised, except when an overlay plants it.
pub fn tree_of(cx: &Ctx, inv: &Invocation) -> Result<String, String> {
    let args = inv.tree_args();
    let key = inv.overlay_key();
    if cx.overlay_command(&key).is_some() {
        return cx.cargo_tree_resolved(inv.edges(), &args);
    }
    let memo_key = format!("{}|{key}", cx.root().display());
    if let Some(hit) = memo().lock().expect("feature-set memo").get(&memo_key) {
        return hit.clone();
    }
    let answer = cx.cargo_tree_resolved(inv.edges(), &args);
    memo()
        .lock()
        .expect("feature-set memo")
        .insert(memo_key, answer.clone());
    answer
}

/// Resolve every invocation of a leg and union the features they enable.
pub fn resolve_leg(cx: &Ctx, leg: &Leg) -> LegResolution {
    let mut out = LegResolution::default();
    for inv in &leg.invocations {
        if let Some(why) = &inv.out_of_reach {
            out.out_of_reach.push(format!("`{}` — {why}", inv.command));
            continue;
        }
        match tree_of(cx, inv) {
            Ok(tree) => {
                out.features.extend(features_of(&tree));
                out.resolved.push(inv.command.clone());
            }
            Err(e) => out.errors.push(format!("`{}`: {e}", inv.command)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cargo_line_is_found_only_where_a_command_actually_starts() {
        assert_eq!(
            cargo_start("        run: cargo clippy --workspace"),
            Some(13)
        );
        assert_eq!(cargo_start("out=\"$(cargo test -p busbar)\""), Some(7));
        // The two shapes that must NOT be read as commands.
        assert_eq!(
            cargo_start("echo \"  phase-0-build (cargo build --release -p busbar): 3s\""),
            None
        );
        // Inside backticks is prose too — `invocations` drops `#` lines before it gets here,
        // and the quoting rule agrees with it.
        assert_eq!(
            cargo_start("      # `cargo test -p busbar-core` never runs"),
            None
        );
        assert_eq!(cargo_start("# a comment about cargo build"), Some(18));
        assert_eq!(cargo_start("no cargoes here"), None);
    }

    #[test]
    fn an_invocation_carries_the_four_things_that_decide_a_resolution() {
        let inv = &invocations(&[
            "run: cargo clippy --workspace --all-targets --features \"a/b,c/d\" --locked -- -D warnings"
                .to_string(),
        ])[0];
        assert!(inv.workspace && inv.dev_targets && !inv.no_default);
        assert_eq!(inv.features, vec!["a/b", "c/d"]);
        assert_eq!(inv.edges(), EDGES_WITH_DEV);

        // `cargo test` builds dev targets whether or not anybody wrote `--all-targets`.
        let t = &invocations(&["cargo test -p busbar-voice --features runtime".to_string()])[0];
        assert!(t.dev_targets && t.packages == vec!["busbar-voice"]);

        // A plain build does not, and that difference is the whole row.
        let b = &invocations(&["cargo build -p busbar-core --no-default-features".to_string()])[0];
        assert!(!b.dev_targets && b.no_default);
        assert_eq!(b.edges(), EDGES_NO_DEV);

        // A runner-only value is out of reach, not silently resolved.
        let m = &invocations(&[
            "cargo build --release --manifest-path \"${SRC}/Cargo.toml\" -p other".to_string(),
        ])[0];
        assert!(m.out_of_reach.is_some());

        // A `#` line is prose, never a command.
        assert!(invocations(&["      # cargo test -p busbar-core".to_string()]).is_empty());
    }

    #[test]
    fn a_continued_command_is_one_command() {
        let invs = invocations(&[
            "cargo build --locked \\".to_string(),
            "  -p busbar-store-example-plugin \\".to_string(),
            "  -p busbar-hook-test-plugin".to_string(),
        ]);
        assert_eq!(invs.len(), 1);
        assert_eq!(
            invs[0].packages,
            vec!["busbar-store-example-plugin", "busbar-hook-test-plugin"]
        );
    }

    #[test]
    fn the_feature_column_reads_back_as_pkg_slash_feature() {
        let tree = "busbar v1.6.0 (/w/crates/busbar)|default,root-llm\n\
                    ├── busbar-core v1.6.0 (/w/crates/busbar-core)|duplex-ws,test-support (*)\n\
                    │   ├── serde v1.0.0|derive,std\n\
                    │   └── once_cell feature \"default\"\n";
        let f = features_of(tree);
        assert!(f.contains("busbar/root-llm"));
        assert!(f.contains("busbar-core/duplex-ws") && f.contains("busbar-core/test-support"));
        assert!(f.contains("serde/derive"));
        // A feature-edge line names no package and contributes nothing.
        assert!(!f.iter().any(|s| s.starts_with("once_cell/")));
    }
}
