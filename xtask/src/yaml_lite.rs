//! The WORKFLOW subset of YAML, and nothing else.
//!
//! No `serde_yaml`: the gates that read YAML are the ones asserting things ABOUT the YAML text, and
//! a general parser that normalises the document is the wrong tool for a gate whose subject is what
//! a human wrote. What is needed is jobs, steps, `run:` block scalars (`|` vs `>`), `needs:` lists
//! and `env:` maps — plus the logical-line folding `full-gate.sh`'s `ci_logical_lines()` awk does,
//! which is what makes a three-line backslash-continued `cargo test` one discoverable invocation.
//!
//! [`logical_lines`] ports that awk and the two `sed`/`grep` filters the caller wraps it in, so the
//! continuation fixture's five assertions hold here: a continued command is joined; a command
//! quoted inside an `echo` is NOT discovered; a command in a `#` comment is NOT discovered; a
//! command in a step `name:` is NOT discovered; a nested script path IS discovered.
//!
//! [`parse_structure`] is the second reader, and it answers a different question. `parse_workflow`
//! above models the few keys a gate asks ABOUT; `parse_structure` models the whole document as the
//! STRUCTURE the runner executes — the thing that is compared when a gate's subject is "did the run
//! graph move", where any key going missing matters and none of them can be enumerated in advance.
//! It is still the workflow subset and nothing else: block mappings, block sequences, flow
//! sequences and maps, quoted and plain scalars, and the two block-scalar styles with their
//! chomping indicators. What it deliberately does NOT model is everything a workflow never
//! contains — anchors, aliases, tags, multiple documents, complex keys — each of which is a named
//! error rather than a value quietly dropped, because a dropped key reads exactly like a key that
//! matches.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start_matches([' ', '\t']).len()
}

fn is_droppable(s: &str) -> bool {
    let t = s.trim_start();
    t.starts_with('#')
        || t.starts_with("echo ")
        || t.starts_with("echo\t")
        || t == "echo"
        || is_name_label(t)
}

/// A step `name:` label is documentation, not a command. `- name: cargo test …` in a step title
/// must never be discovered as an invocation.
fn is_name_label(t: &str) -> bool {
    let t = t.strip_prefix("- ").unwrap_or(t).trim_start();
    t.starts_with("name:")
}

/// The logical lines of a workflow: `run:` block scalars folded into one line per command,
/// everything else passed through, comments / `echo` lines / `name:` labels dropped.
pub fn logical_lines(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut pending = String::new();
    let mut in_run = false;
    let mut run_indent = 0usize;
    let mut fold = false;

    fn emit(out: &mut Vec<String>, pending: &mut String) {
        if pending.is_empty() {
            return;
        }
        let s = std::mem::take(pending);
        let s = s.trim().to_string();
        if s.is_empty() || is_droppable(&s) {
            return;
        }
        out.push(s);
    }

    for line in text.lines() {
        if in_run {
            if line.trim().is_empty() {
                emit(&mut out, &mut pending);
                continue;
            }
            if indent_of(line) <= run_indent {
                emit(&mut out, &mut pending);
                in_run = false;
            }
        }

        if !in_run {
            let t = line.trim_start();
            let after_dash = t.strip_prefix("- ").unwrap_or(t).trim_start();
            if let Some(rest) = after_dash.strip_prefix("run:") {
                let rest = rest.trim();
                if rest == "|" || rest == ">" || rest.starts_with('|') || rest.starts_with('>') {
                    run_indent = indent_of(line);
                    fold = rest.starts_with('>');
                    pending.clear();
                    in_run = true;
                    continue;
                }
            }
            let s = line.trim_start().to_string();
            if !s.is_empty() && !is_droppable(&s) {
                out.push(s);
            }
            continue;
        }

        let mut body = line.trim_start().to_string();
        if body.starts_with('#') {
            continue;
        }
        if fold || body.trim_end().ends_with('\\') {
            let trimmed = body.trim_end();
            body = trimmed
                .strip_suffix('\\')
                .unwrap_or(trimmed)
                .trim_end()
                .to_string();
            pending.push_str(&body);
            pending.push(' ');
            continue;
        }
        pending.push_str(&body);
        emit(&mut out, &mut pending);
    }
    emit(&mut out, &mut pending);
    out
}

/// Every `cargo xtask gate <name>` (and the pre-registry `cargo xtask <name>`) call site in a
/// workflow, in first-seen order, deduplicated. Set equality against the registry is what retires
/// `full-gate.sh`'s `MIN_GATES` floor: a registered gate absent from `ci.yml` is a failure a floor
/// could only approximate.
pub fn xtask_gate_invocations(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in logical_lines(text) {
        let mut rest = line.as_str();
        while let Some(i) = rest.find("cargo xtask ") {
            rest = &rest[i + "cargo xtask ".len()..];
            let mut tokens = rest.split_whitespace();
            let mut name = tokens.next().unwrap_or("");
            if name == "gate" || name == "selftest" {
                name = tokens.next().unwrap_or("");
            }
            // The dispatcher's two non-gate subcommands. Everything else after `cargo xtask` is a
            // gate name — `denylist` and `teller-steps` are registry names in their pre-registry
            // spelling — so without this the runner and the register read as gates the registry
            // cannot answer to, which is the shape this reader exists to report.
            if crate::cli::NON_GATE_SUBCOMMANDS.contains(&name) {
                continue;
            }
            if !name.is_empty() && !name.starts_with('-') && !out.iter().any(|n| n == name) {
                out.push(name.to_string());
            }
        }
    }
    out
}

#[derive(Debug, Clone, Default)]
pub struct Step {
    pub name: Option<String>,
    pub run: Option<String>,
    pub uses: Option<String>,
    pub cond: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Job {
    pub name: String,
    pub needs: Vec<String>,
    /// The job's own `env:` map, block scalars included. The `ci-umbrella` job keeps its whole
    /// scoring ledger in one `RESULTS: |` block, so a reader that stopped at `needs:` could see
    /// which jobs are waited for and never see which of them are actually counted.
    pub env: BTreeMap<String, String>,
    /// The job-level `if:` guard, verbatim. Whether a job is expected to run on a fast-tier push is
    /// a property of this string and of nothing else.
    pub cond: Option<String>,
    pub steps: Vec<Step>,
}

#[derive(Debug, Clone, Default)]
pub struct Workflow {
    pub env: BTreeMap<String, String>,
    jobs: Vec<Job>,
}

impl Workflow {
    pub fn job_names(&self) -> Vec<String> {
        self.jobs.iter().map(|j| j.name.clone()).collect()
    }

    pub fn job(&self, name: &str) -> Option<&Job> {
        self.jobs.iter().find(|j| j.name == name)
    }

    pub fn jobs(&self) -> &[Job] {
        &self.jobs
    }
}

fn unquote(s: &str) -> String {
    let s = s.trim();
    let s = s
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(s);
    let s = s
        .strip_prefix('\'')
        .and_then(|s| s.strip_suffix('\''))
        .unwrap_or(s);
    s.to_string()
}

/// The body of a block scalar opened on `lines[key_line]` at indent `key_indent`, plus the index of
/// the first line after it. `folded` is the `>` style: lines joined with a space rather than kept.
fn block_scalar(
    lines: &[&str],
    key_line: usize,
    key_indent: usize,
    folded: bool,
) -> (String, usize) {
    let mut collected: Vec<String> = Vec::new();
    let mut j = key_line + 1;
    while j < lines.len() {
        let l = lines[j];
        if l.trim().is_empty() {
            collected.push(String::new());
            j += 1;
            continue;
        }
        if indent_of(l) <= key_indent {
            break;
        }
        collected.push(l.trim_start().to_string());
        j += 1;
    }
    let text = if folded {
        collected.join(" ").trim().to_string()
    } else {
        collected.join("\n").trim_end().to_string()
    };
    (text, j)
}

/// Parse the workflow subset. An EMPTY document, or one with no jobs, is an ERROR — the
/// `full-gate.sh` floor that an empty `ci.yml` must be refused rather than read as a workflow with
/// nothing to run.
pub fn parse_workflow(text: &str) -> Result<Workflow, String> {
    if text.trim().is_empty() {
        return Err(
            "empty workflow: a document with no bytes is not a workflow with no gates".to_string(),
        );
    }
    let mut wf = Workflow::default();
    let lines: Vec<&str> = text.lines().collect();
    let mut section = String::new();
    // The key one level inside the current job (`needs`, `env`, `steps`, …). Without it a job's
    // `env:` values and its steps' keys are the same shape at the same depth.
    let mut job_key = String::new();
    let mut i = 0usize;

    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim_end();
        let t = trimmed.trim_start();
        if t.is_empty() || t.starts_with('#') {
            i += 1;
            continue;
        }
        let ind = indent_of(trimmed);

        if ind == 0 {
            section = t.split(':').next().unwrap_or("").to_string();
            // `env: { A: b }` inline form is not used by this tree's workflows; block form only.
            i += 1;
            continue;
        }

        if section == "env" && ind == 2 {
            if let Some((k, v)) = t.split_once(':') {
                wf.env.insert(k.trim().to_string(), unquote(v));
            }
            i += 1;
            continue;
        }

        if section == "jobs" && ind == 2 && t.ends_with(':') {
            wf.jobs.push(Job {
                name: t.trim_end_matches(':').to_string(),
                ..Job::default()
            });
            job_key.clear();
            i += 1;
            continue;
        }

        if section == "jobs" && !wf.jobs.is_empty() && ind >= 4 {
            let job_idx = wf.jobs.len() - 1;
            if ind == 4 {
                job_key = t.split(':').next().unwrap_or("").trim().to_string();
                if let Some(rest) = t.strip_prefix("if:") {
                    wf.jobs[job_idx].cond = Some(unquote(rest));
                    i += 1;
                    continue;
                }
                if let Some(rest) = t.strip_prefix("needs:") {
                    let rest = rest.trim();
                    if rest.starts_with('[') {
                        wf.jobs[job_idx].needs = rest
                            .trim_matches(['[', ']'])
                            .split(',')
                            .map(unquote)
                            .filter(|s| !s.is_empty())
                            .collect();
                    } else if rest.is_empty() {
                        let mut j = i + 1;
                        while j < lines.len() {
                            let nt = lines[j].trim_start();
                            // A COMMENT INSIDE THE LIST IS NOT THE END OF THE LIST. `ci.yml`
                            // explains its last dependency in three comment lines sitting between
                            // the entries above it and the entry itself; a reader that stopped at
                            // the first `#` dropped that job from `needs` silently, and a job
                            // missing from the needs a gate READS is indistinguishable from a job
                            // missing from the needs the workflow RUNS.
                            if nt.is_empty() || nt.starts_with('#') {
                                j += 1;
                                continue;
                            }
                            if !nt.starts_with("- ") {
                                break;
                            }
                            wf.jobs[job_idx].needs.push(unquote(&nt[2..]));
                            j += 1;
                        }
                        i = j;
                        continue;
                    } else {
                        wf.jobs[job_idx].needs = vec![unquote(rest)];
                    }
                    i += 1;
                    continue;
                }
                i += 1;
                continue;
            }

            // A job's own `env:` block. Its values are read by name, so the block-scalar form has
            // to survive: the umbrella's whole scoring ledger is one `RESULTS: |` value.
            if job_key == "env" {
                let Some((key, value)) = t.split_once(':') else {
                    i += 1;
                    continue;
                };
                let (key, value) = (key.trim().to_string(), value.trim());
                if value == "|" || value == ">" || value.starts_with('|') || value.starts_with('>')
                {
                    let (text, next) = block_scalar(&lines, i, ind, value.starts_with('>'));
                    wf.jobs[job_idx].env.insert(key, text);
                    i = next;
                    continue;
                }
                wf.jobs[job_idx].env.insert(key, unquote(value));
                i += 1;
                continue;
            }

            // Inside `steps:` — a step opens on `- ` and its keys sit one level deeper.
            if t.starts_with("- ") {
                wf.jobs[job_idx].steps.push(Step::default());
            }
            if wf.jobs[job_idx].steps.is_empty() {
                i += 1;
                continue;
            }
            let step_idx = wf.jobs[job_idx].steps.len() - 1;
            let body = t.strip_prefix("- ").unwrap_or(t);
            let Some((key, value)) = body.split_once(':') else {
                i += 1;
                continue;
            };
            let key = key.trim();
            let value = value.trim();
            let step = &mut wf.jobs[job_idx].steps[step_idx];
            match key {
                "name" => step.name = Some(unquote(value)),
                "uses" => step.uses = Some(unquote(value)),
                "if" => step.cond = Some(unquote(value)),
                "run" => {
                    if value == "|"
                        || value == ">"
                        || value.starts_with('|')
                        || value.starts_with('>')
                    {
                        let (text, next) = block_scalar(&lines, i, ind, value.starts_with('>'));
                        step.run = Some(text);
                        i = next;
                        continue;
                    }
                    step.run = Some(unquote(value));
                }
                _ => {}
            }
            i += 1;
            continue;
        }
        i += 1;
    }

    if wf.jobs.is_empty() {
        return Err(
            "workflow declares no jobs: a `jobs:` key with nothing under it runs nothing, \
                    and a gate set discovered from it would be vacuously satisfied"
                .to_string(),
        );
    }
    Ok(wf)
}

// ---------------------------------------------------------------------------------------------
// THE WHOLE-DOCUMENT READER.
//
// A gate whose subject is "does this run graph still match the one that was promoted" cannot ask
// about a fixed list of keys: the interesting change is always the key nobody thought to name. So
// the document is read into a generic value and compared whole. `serde_json::Value` is that value
// type rather than a bespoke enum because the artifact this feeds is JSON on disk, and one value
// type across the parse, the comparison and the write is one place a spelling can drift instead of
// three.
// ---------------------------------------------------------------------------------------------

/// Parse a workflow document into the structure the runner executes.
///
/// Comments and formatting are DROPPED, which is the entire point: a reader that compared bytes
/// would fail on a prose edit, and a prose edit to a workflow is not a change to what runs.
///
/// An empty document is an ERROR, never an empty mapping. "The file said nothing" and "the file
/// said nothing runs" are the two readings every zero-is-not-clean rule exists to keep apart, and
/// a caller that got `{}` back would have no way to tell them apart afterwards.
pub fn parse_structure(text: &str) -> Result<Value, String> {
    if text.trim().is_empty() {
        return Err(
            "empty document: a file with no bytes is not a workflow that declares nothing"
                .to_string(),
        );
    }
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    for (n, line) in lines.iter().enumerate() {
        let t = line.trim_end();
        if t == "---" || t == "..." {
            return Err(format!(
                "line {}: multi-document YAML is not part of the workflow subset — a second \
                 document would be parsed by nobody and compare as absent",
                n + 1
            ));
        }
    }
    let mut i = 0usize;
    skip_insignificant(&lines, &mut i);
    if i >= lines.len() {
        return Err(
            "document is nothing but comments: it declares no keys, which is not a workflow"
                .to_string(),
        );
    }
    let base = indent_of(&lines[i]);
    let value = parse_block(&mut lines, &mut i, base)?;
    skip_insignificant(&lines, &mut i);
    if i < lines.len() {
        return Err(format!(
            "line {}: `{}` sits outside the document's top-level block and would be read by nobody",
            i + 1,
            lines[i].trim()
        ));
    }
    Ok(value)
}

fn is_insignificant(line: &str) -> bool {
    let t = line.trim();
    t.is_empty() || t.starts_with('#')
}

fn skip_insignificant(lines: &[String], i: &mut usize) {
    while *i < lines.len() && is_insignificant(&lines[*i]) {
        *i += 1;
    }
}

/// One block at `indent`: a sequence, a mapping, or a bare scalar.
fn parse_block(lines: &mut Vec<String>, i: &mut usize, indent: usize) -> Result<Value, String> {
    skip_insignificant(lines, i);
    if *i >= lines.len() {
        return Ok(Value::Null);
    }
    let t = lines[*i].trim_start().to_string();
    if t == "-" || t.starts_with("- ") {
        return Ok(Value::Array(parse_sequence(lines, i, indent)?));
    }
    if split_key(&t).is_some() {
        return Ok(Value::Object(parse_mapping(lines, i, indent)?));
    }
    let value = scalar(strip_comment(t.trim_end()))?;
    *i += 1;
    Ok(value)
}

fn parse_mapping(
    lines: &mut Vec<String>,
    i: &mut usize,
    indent: usize,
) -> Result<Map<String, Value>, String> {
    let mut map = Map::new();
    loop {
        skip_insignificant(lines, i);
        if *i >= lines.len() {
            break;
        }
        let here = indent_of(&lines[*i]);
        if here < indent {
            break;
        }
        if here > indent {
            return Err(format!(
                "line {}: indented {here} where the enclosing mapping is at {indent} — an \
                 unreadable nesting is refused rather than guessed at",
                *i + 1
            ));
        }
        let t = lines[*i].trim_start().to_string();
        if t == "-" || t.starts_with("- ") {
            break;
        }
        let Some((key, rest)) = split_key(&t) else {
            return Err(format!(
                "line {}: `{t}` is neither a `key: value` nor a sequence item",
                *i + 1
            ));
        };
        let lineno = *i + 1;
        let rest = rest.trim_end();
        let value = if rest.starts_with('|') || rest.starts_with('>') {
            Value::String(parse_block_scalar(lines, i, indent, rest)?)
        } else if rest.trim().is_empty() {
            parse_nested(lines, i, indent)?
        } else {
            *i += 1;
            scalar(strip_comment(rest))?
        };
        if map.insert(key.clone(), value).is_some() {
            return Err(format!(
                "line {lineno}: duplicate key `{key}` — the later value would silently win and \
                 half the document would compare against something nobody wrote"
            ));
        }
    }
    Ok(map)
}

/// The value of a `key:` with nothing after the colon: whatever block follows, or null.
fn parse_nested(lines: &mut Vec<String>, i: &mut usize, indent: usize) -> Result<Value, String> {
    *i += 1;
    let mut j = *i;
    skip_insignificant(lines, &mut j);
    if j >= lines.len() {
        return Ok(Value::Null);
    }
    let child = indent_of(&lines[j]);
    let is_item = {
        let t = lines[j].trim_start();
        t == "-" || t.starts_with("- ")
    };
    // A block sequence may sit at the KEY's own indent — `needs:` followed by `- build` in the
    // same column is a spelling this tree's workflows use, and reading it as "the key has no
    // value" would drop a whole dependency edge.
    if child > indent || (child == indent && is_item) {
        *i = j;
        return parse_block(lines, i, child);
    }
    Ok(Value::Null)
}

fn parse_sequence(
    lines: &mut Vec<String>,
    i: &mut usize,
    indent: usize,
) -> Result<Vec<Value>, String> {
    let mut out = Vec::new();
    loop {
        skip_insignificant(lines, i);
        if *i >= lines.len() || indent_of(&lines[*i]) != indent {
            break;
        }
        let t = lines[*i].trim_start().to_string();
        let content = if t == "-" {
            String::new()
        } else if let Some(rest) = t.strip_prefix("- ") {
            rest.to_string()
        } else {
            break;
        };
        if content.trim().is_empty() {
            out.push(Value::Null);
            *i += 1;
            continue;
        }
        // The dash is rewritten to spaces so the item's body is an ordinary block two columns in.
        // Doing it this way means an item's keys go through the SAME mapping code as every other
        // mapping — a second, item-only key parser is a second place the two can disagree.
        lines[*i] = format!("{}  {content}", " ".repeat(indent));
        out.push(parse_block(lines, i, indent + 2)?);
    }
    Ok(out)
}

/// `key: rest`, where the colon must be followed by a space or end the line — so
/// `group: qa-gate-${{ a || b }}` splits at the first colon and a value that itself contains a
/// colon is not re-split.
fn split_key(t: &str) -> Option<(String, String)> {
    let chars: Vec<char> = t.chars().collect();
    let mut in_single = false;
    let mut in_double = false;
    for (n, c) in chars.iter().enumerate() {
        match c {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            ':' if !in_single && !in_double => {
                let next = chars.get(n + 1);
                if next.is_none() || next == Some(&' ') || next == Some(&'\t') {
                    let key: String = chars[..n].iter().collect();
                    let rest: String = chars[n + 1..].iter().collect();
                    let key = unquote(key.trim());
                    if key.is_empty() {
                        return None;
                    }
                    return Some((key, rest.trim_start().to_string()));
                }
            }
            _ => {}
        }
    }
    None
}

/// Drop a trailing `# …` comment. A `#` only opens a comment at the start of the value or after
/// whitespace, and never inside quotes — `retention-days: 1 # v4` is a 1, and a `#` inside a shell
/// string stays a `#`.
fn strip_comment(s: &str) -> &str {
    let mut in_single = false;
    let mut in_double = false;
    let mut prev = ' ';
    for (n, c) in s.char_indices() {
        match c {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '#' if !in_single && !in_double && (n == 0 || prev.is_whitespace()) => {
                return s[..n].trim_end();
            }
            _ => {}
        }
        prev = c;
    }
    s.trim_end()
}

/// A block scalar: `|` keeps the line breaks, `>` folds them, `-`/`+` strip or keep the trailing
/// ones. The folding rule is the one that matters here, because a workflow's `if:` is written as
/// `>-` with continuation lines indented for readability: a line indented DEEPER than the block
/// keeps the break before it, which is what makes a hand-wrapped condition read back as the same
/// string every time instead of moving whenever someone re-wraps it.
fn parse_block_scalar(
    lines: &mut [String],
    i: &mut usize,
    indent: usize,
    header: &str,
) -> Result<String, String> {
    let mut chars = header.chars();
    let style = chars.next().unwrap_or('|');
    let mut chomp = ' ';
    for c in chars {
        match c {
            '-' | '+' => chomp = c,
            ' ' | '#' => break,
            d if d.is_ascii_digit() => {
                return Err(format!(
                    "line {}: an explicit block-scalar indentation indicator is not part of the \
                     workflow subset",
                    *i + 1
                ))
            }
            other => {
                return Err(format!(
                    "line {}: `{other}` is not a block-scalar chomping indicator",
                    *i + 1
                ))
            }
        }
    }

    *i += 1;
    let mut body: Vec<String> = Vec::new();
    while *i < lines.len() {
        let line = &lines[*i];
        if line.trim().is_empty() {
            body.push(String::new());
            *i += 1;
            continue;
        }
        if indent_of(line) <= indent {
            break;
        }
        body.push(line.clone());
        *i += 1;
    }

    let mut trailing_blanks = 0usize;
    while body.last().map(String::is_empty).unwrap_or(false) {
        body.pop();
        trailing_blanks += 1;
    }
    if body.is_empty() {
        return Ok(String::new());
    }
    // The block's own indentation is the first content line's, and every line is measured against
    // it: the extra columns on a deeper line are CONTENT — for `|` they are the shell script's own
    // indentation, and for `>` they are what suppresses the fold.
    // THE CUT IS A COLUMN OF WHITESPACE, NEVER A COUNT OF BYTES. `base` is the first content
    // line's indent, but the body loop above admits every line more indented than the PARENT KEY —
    // so a later line may sit between the two, and cutting it at `base` cuts into its content. If
    // a multibyte character straddles that offset the slice panics outright: exit 101, which is
    // neither "the gate failed" nor "the gate could not run", and it takes every other batched gate
    // with it. Cutting at `min(base, this line's own indent)` is a boundary by construction —
    // `indent_of` counts spaces and tabs, both ASCII — and it strips exactly the indentation the
    // line has, which is what a shorter-indented line always meant.
    let base = indent_of(&body[0]);
    let dedented: Vec<String> = body
        .iter()
        .map(|l| l[base.min(indent_of(l))..].to_string())
        .collect();

    let text = if style == '>' {
        fold_lines(&dedented)
    } else {
        dedented.join("\n")
    };

    Ok(match chomp {
        '-' => text,
        '+' => format!("{text}{}", "\n".repeat(1 + trailing_blanks)),
        _ => format!("{text}\n"),
    })
}

/// Fold a `>` scalar: a break between two lines that both sit at the block's own indentation
/// becomes a space, and a break next to a MORE-indented line stays a break.
fn fold_lines(lines: &[String]) -> String {
    let more = |s: &String| s.starts_with(' ') || s.starts_with('\t');
    let mut out = String::new();
    for (n, line) in lines.iter().enumerate() {
        if n == 0 {
            out.push_str(line);
            continue;
        }
        let keep_break =
            line.is_empty() || lines[n - 1].is_empty() || more(line) || more(&lines[n - 1]);
        out.push(if keep_break { '\n' } else { ' ' });
        out.push_str(line);
    }
    out
}

/// A flow scalar: quoted, a flow sequence, a flow mapping, or plain.
fn scalar(s: &str) -> Result<Value, String> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(Value::Null);
    }
    if s.starts_with('&') || s.starts_with('*') || s.starts_with("!!") {
        return Err(format!(
            "`{s}`: YAML anchors, aliases and tags are not part of the workflow subset — resolving \
             one wrongly would compare a value nobody wrote"
        ));
    }
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        return Ok(Value::String(unescape_double(&s[1..s.len() - 1])));
    }
    if s.len() >= 2 && s.starts_with('\'') && s.ends_with('\'') {
        return Ok(Value::String(s[1..s.len() - 1].replace("''", "'")));
    }
    if s.starts_with('[') {
        let inner = s
            .strip_prefix('[')
            .and_then(|r| r.strip_suffix(']'))
            .ok_or_else(|| format!("unterminated flow sequence `{s}`"))?;
        let mut out = Vec::new();
        for item in split_flow(inner) {
            if item.trim().is_empty() {
                continue;
            }
            out.push(scalar(&item)?);
        }
        return Ok(Value::Array(out));
    }
    if s.starts_with('{') {
        let inner = s
            .strip_prefix('{')
            .and_then(|r| r.strip_suffix('}'))
            .ok_or_else(|| format!("unterminated flow mapping `{s}`"))?;
        let mut map = Map::new();
        for item in split_flow(inner) {
            if item.trim().is_empty() {
                continue;
            }
            let Some((k, v)) = split_key(item.trim()) else {
                return Err(format!("flow mapping entry `{item}` is not `key: value`"));
            };
            map.insert(k, scalar(&v)?);
        }
        return Ok(Value::Object(map));
    }
    Ok(plain(s))
}

/// A plain scalar's type. The YAML 1.1 quirk that turns a workflow's top-level `on:` into the
/// BOOLEAN true — the same rule that turns `no` into false — is deliberately NOT reproduced: a
/// workflow's `on:` is the word `on`, and a reader of the derived artifact must find `"on"` there
/// rather than a boolean spelled back out as one.
fn plain(s: &str) -> Value {
    match s {
        "true" | "True" | "TRUE" => return Value::Bool(true),
        "false" | "False" | "FALSE" => return Value::Bool(false),
        "null" | "Null" | "NULL" | "~" => return Value::Null,
        _ => {}
    }
    if let Ok(n) = s.parse::<i64>() {
        return Value::from(n);
    }
    if (s.contains('.') || s.contains('e') || s.contains('E')) && !s.starts_with('.') {
        if let Ok(f) = s.parse::<f64>() {
            if f.is_finite() {
                if let Some(n) = serde_json::Number::from_f64(f) {
                    return Value::Number(n);
                }
            }
        }
    }
    Value::String(s.to_string())
}

/// Split a flow collection's body on its top-level commas.
fn split_flow(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut depth = 0usize;
    let mut in_single = false;
    let mut in_double = false;
    for c in s.chars() {
        match c {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '[' | '{' if !in_single && !in_double => depth += 1,
            ']' | '}' if !in_single && !in_double => depth = depth.saturating_sub(1),
            ',' if depth == 0 && !in_single && !in_double => {
                out.push(std::mem::take(&mut cur));
                continue;
            }
            _ => {}
        }
        cur.push(c);
    }
    out.push(cur);
    out
}

fn unescape_double(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('0') => out.push('\0'),
            Some('"') => out.push('"'),
            Some('\\') => out.push('\\'),
            Some('u') => {
                let hex: String = chars.by_ref().take(4).collect();
                match u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                    Some(u) => out.push(u),
                    None => {
                        out.push_str("\\u");
                        out.push_str(&hex);
                    }
                }
            }
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

#[cfg(test)]
mod structure_tests {
    use super::*;

    #[test]
    fn empty_and_comment_only_documents_are_errors_not_empty_mappings() {
        assert!(parse_structure("").is_err());
        assert!(parse_structure("   \n\n").is_err());
        assert!(parse_structure("# nothing but prose\n").is_err());
    }

    #[test]
    fn scalars_carry_their_types() {
        let v = parse_structure(
            "a: true\nb: false\nc: 0\nd: 180\ne: ubuntu-latest\nf: /tmp\ng: 1 # a comment\n",
        )
        .unwrap();
        assert_eq!(v["a"], Value::Bool(true));
        assert_eq!(v["b"], Value::Bool(false));
        assert_eq!(v["c"], Value::from(0));
        assert_eq!(v["d"], Value::from(180));
        assert_eq!(v["e"], Value::from("ubuntu-latest"));
        assert_eq!(v["f"], Value::from("/tmp"));
        assert_eq!(v["g"], Value::from(1));
    }

    #[test]
    fn the_on_key_stays_the_word_it_was_written_as() {
        let v = parse_structure("on:\n  workflow_dispatch: {}\n").unwrap();
        assert!(v.get("on").is_some(), "got {v}");
    }

    #[test]
    fn flow_collections_and_the_empty_mapping() {
        let v = parse_structure(
            "on:\n  workflow_run:\n    workflows: [\"CI\"]\n    types: [completed]\n  \
             workflow_dispatch: {}\n",
        )
        .unwrap();
        assert_eq!(v["on"]["workflow_run"]["workflows"][0], Value::from("CI"));
        assert_eq!(
            v["on"]["workflow_run"]["types"][0],
            Value::from("completed")
        );
        assert_eq!(v["on"]["workflow_dispatch"], Value::Object(Map::new()));
    }

    #[test]
    fn a_sequence_of_mappings_is_read_by_the_mapping_parser() {
        let v = parse_structure(
            "steps:\n  - uses: actions/checkout@abc # v7\n    with:\n      path: here\n  \
             - name: second\n    run: echo hi\n",
        )
        .unwrap();
        assert_eq!(v["steps"][0]["uses"], Value::from("actions/checkout@abc"));
        assert_eq!(v["steps"][0]["with"]["path"], Value::from("here"));
        assert_eq!(v["steps"][1]["name"], Value::from("second"));
        assert_eq!(v["steps"].as_array().map(Vec::len), Some(2));
    }

    #[test]
    fn needs_reads_the_same_in_all_three_spellings() {
        let flow = parse_structure("jobs:\n  slow:\n    needs: [build, fast]\n").unwrap();
        let block =
            parse_structure("jobs:\n  slow:\n    needs:\n      - build\n      - fast\n").unwrap();
        let same_column =
            parse_structure("jobs:\n  slow:\n    needs:\n    - build\n    - fast\n").unwrap();
        assert_eq!(flow, block);
        assert_eq!(flow, same_column);
    }

    #[test]
    fn a_literal_block_keeps_its_lines_and_one_trailing_newline() {
        let v = parse_structure("run: |\n  set -u\n  check() {\n    echo hi\n  }\n").unwrap();
        assert_eq!(v["run"], Value::from("set -u\ncheck() {\n  echo hi\n}\n"));
        let stripped = parse_structure("run: |-\n  one\n  two\n").unwrap();
        assert_eq!(stripped["run"], Value::from("one\ntwo"));
    }

    #[test]
    fn a_folded_block_keeps_the_break_beside_a_more_indented_line() {
        let v = parse_structure("if: >-\n  a ||\n  (b &&\n   c)\n").unwrap();
        assert_eq!(v["if"], Value::from("a || (b &&\n c)"));
    }

    #[test]
    fn a_hash_inside_quotes_is_not_a_comment() {
        let v = parse_structure("run: echo \"a # b\"\n").unwrap();
        assert_eq!(v["run"], Value::from("echo \"a # b\""));
    }

    #[test]
    fn a_duplicate_key_is_refused_rather_than_resolved() {
        assert!(parse_structure("a: 1\na: 2\n").is_err());
    }

    #[test]
    fn anchors_and_multiple_documents_are_named_errors() {
        assert!(parse_structure("a: &anchor 1\n").is_err());
        assert!(parse_structure("---\na: 1\n").is_err());
    }

    /// A BLOCK SCALAR IS DEDENTED BY COLUMNS OF WHITESPACE, NEVER BY A COUNT OF BYTES.
    ///
    /// The block's base indent is the FIRST content line's, but the body loop admits every line
    /// more indented than the parent key — so a later line may sit between the two. Cutting such a
    /// line at the base OFFSET cuts into its content, and if a multibyte character straddles that
    /// offset the slice panics, which is exit 101: not "the gate failed", not "the gate could not
    /// run", and it takes every other batched gate down with it. The house prose style puts em
    /// dashes (three bytes each) inside `run: |` blocks constantly.
    #[test]
    fn a_block_scalar_line_less_indented_than_the_first_keeps_its_multibyte_content() {
        let doc = "jobs:\n  a:\n    run: |\n        first line, deeply indented\n       \
                   — an em dash on a line the block did not start at\n";
        let v = parse_structure(doc).expect("a valid workflow must parse, not abort the process");
        let run = v["jobs"]["a"]["run"].as_str().expect("the block scalar");
        assert!(
            run.contains("— an em dash"),
            "the dedent must strip that line's own indentation and nothing else: {run:?}"
        );
        assert!(run.starts_with("first line, deeply indented"));
    }
}

#[cfg(test)]
mod workflow_shape_tests {
    use super::*;

    const JOB_ENV_AND_GUARD: &str = r#"
name: CI
on: [push]
jobs:
  alpha:
    if: github.event_name != 'push' || contains(fromJSON('["refs/heads/main"]'), github.ref)
    runs-on: ubuntu-latest
    steps:
      - run: true
  umbrella:
    needs:
      - alpha
      # A comment BETWEEN two entries, which is where ci.yml explains its last dependency.
      - bravo
    runs-on: ubuntu-latest
    env:
      FLAG: 'true'
      RESULTS: |
        alpha|fast|${{ needs.alpha.result }}
        bravo|full|${{ needs.bravo.result }}
    steps:
      - run: echo done
"#;

    #[test]
    fn a_job_env_block_scalar_is_read_whole() {
        let wf = parse_workflow(JOB_ENV_AND_GUARD).expect("parses");
        let umbrella = wf.job("umbrella").expect("umbrella job");
        assert_eq!(umbrella.env.get("FLAG").map(String::as_str), Some("true"));
        let results = umbrella.env.get("RESULTS").expect("RESULTS");
        assert_eq!(
            results.lines().collect::<Vec<_>>(),
            vec![
                "alpha|fast|${{ needs.alpha.result }}",
                "bravo|full|${{ needs.bravo.result }}"
            ]
        );
    }

    #[test]
    fn a_comment_inside_a_needs_list_does_not_end_the_list() {
        let wf = parse_workflow(JOB_ENV_AND_GUARD).expect("parses");
        assert_eq!(
            wf.job("umbrella").expect("umbrella job").needs,
            vec!["alpha".to_string(), "bravo".to_string()],
            "an entry explained by a comment above it must still be a dependency"
        );
    }

    #[test]
    fn a_job_level_if_guard_is_kept_verbatim() {
        let wf = parse_workflow(JOB_ENV_AND_GUARD).expect("parses");
        let cond = wf.job("alpha").expect("alpha job").cond.clone();
        assert!(
            cond.as_deref().unwrap_or("").contains("github.event_name"),
            "the guard is the only thing that says which tier a job runs in: {cond:?}"
        );
        assert!(wf.job("umbrella").expect("umbrella job").cond.is_none());
    }

    #[test]
    fn a_job_env_value_is_not_mistaken_for_a_step() {
        let wf = parse_workflow(JOB_ENV_AND_GUARD).expect("parses");
        let umbrella = wf.job("umbrella").expect("umbrella job");
        assert_eq!(
            umbrella.steps.len(),
            1,
            "the `env:` map sits at the same depth as a step's keys; reading it as a step would \
             both invent steps and lose the map"
        );
    }
}
