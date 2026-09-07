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

use std::collections::BTreeMap;

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
            if name == "gate" {
                name = tokens.next().unwrap_or("");
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
            i += 1;
            continue;
        }

        if section == "jobs" && !wf.jobs.is_empty() && ind >= 4 {
            let job_idx = wf.jobs.len() - 1;
            if ind == 4 {
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
                        let fold = value.starts_with('>');
                        let mut collected: Vec<String> = Vec::new();
                        let block_indent = ind;
                        let mut j = i + 1;
                        while j < lines.len() {
                            let l = lines[j];
                            if l.trim().is_empty() {
                                collected.push(String::new());
                                j += 1;
                                continue;
                            }
                            if indent_of(l) <= block_indent {
                                break;
                            }
                            collected.push(l.trim_start().to_string());
                            j += 1;
                        }
                        step.run = Some(if fold {
                            collected.join(" ").trim().to_string()
                        } else {
                            collected.join("\n").trim_end().to_string()
                        });
                        i = j;
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
