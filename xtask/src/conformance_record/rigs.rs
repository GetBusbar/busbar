//! The five rigs, each run as the subprocess CI ran it, and the PURE deciders that turn what a rig
//! left behind (exit codes, its ledger, its report) into one [`Outcome`] per suite.
//!
//! The deciders hold one rule in common: a rig that did not judge busbar — a red self-test, a red
//! control, a leg that never finished, a report it never wrote — is `not-run`, never `pass`. A
//! control leg judges the INSTRUMENT (a known-good or a deliberately broken third-party peer), so a
//! red there says nothing about busbar and is `not-run` too; only a red SUBJECT leg is a `fail`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

use serde_json::Value;

use super::{Outcome, Status};

/// The llm dialects, one `llm-<dialect>` suite each, keyed by cells.json's `ingress_dialect`.
pub const LLM_DIALECTS: &[&str] = &[
    "anthropic",
    "bedrock",
    "cohere",
    "gemini",
    "openai",
    "responses",
];

/// The voice suites by the dialect name the voice legs use for their slices.
const VOICE_SUITES: &[(&str, &str)] = &[
    ("openai", "voice-openai-realtime"),
    ("gemini", "voice-gemini-live"),
];

/// The llm rig's own bookkeeping row (testing/llm-conformance/run.sh `GAP_ID`): it reconciles the
/// named gaps of the WHOLE battery, so a red there is every dialect's.
const LLM_GAPS_ROW: &str = "gate|llm-conformance|named-gaps";

/// Variables that would point a rig at something other than this checkout's build, or pre-seed
/// its bookkeeping. Removed from every leg's environment.
const SCRUBBED_ENV: &[&str] = &[
    "MCP_SUBJECT_SERVER_CMD",
    "MCP_SUBJECT_CLIENT_CMD",
    "MCP_SUBJECT_UPSTREAM_CONFIG_CMD",
    "MCP_CONFORMANCE_SUBJECT_URL",
    "MCP_SUBJECT_BUSBAR_BIN",
    "MCP_BATTERY_DIR",
    "VOICE_CONFORM_BIN",
    "VOICE_LEGS_DIR",
    "VOICE_MIN_LEGS",
    "VOICE_SELFTEST_DROP",
    "VOICE_RESULT_LOG",
    "LEDGER",
    "EXPECTED_IDS",
    "JEV_RUN_ID",
    "GITHUB_SHA",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Rig {
    Llm,
    Mcp,
    Voice,
    Ws,
    Jev,
}

impl Rig {
    pub fn name(self) -> &'static str {
        match self {
            Rig::Llm => "llm",
            Rig::Mcp => "mcp",
            Rig::Voice => "voice",
            Rig::Ws => "ws",
            Rig::Jev => "jev",
        }
    }
}

/// The rig that judges a registered suite, or `None` for a suite with no rig in the five dirs.
pub fn rig_for(id: &str) -> Option<Rig> {
    if let Some(d) = id.strip_prefix("llm-") {
        return LLM_DIALECTS.contains(&d).then_some(Rig::Llm);
    }
    if VOICE_SUITES.iter().any(|(_, s)| *s == id) {
        return Some(Rig::Voice);
    }
    match id {
        "mcp" => Some(Rig::Mcp),
        "ws" => Some(Rig::Ws),
        "jev" => Some(Rig::Jev),
        _ => None,
    }
}

fn llm_suite(dialect: &str) -> String {
    format!("llm-{dialect}")
}

fn rc(code: Option<i32>) -> String {
    match code {
        Some(c) => format!("exit {c}"),
        None => "did not finish".to_string(),
    }
}

/// The same outcome for every suite in `ids`.
fn fan<I: IntoIterator<Item = String>>(ids: I, o: &Outcome) -> BTreeMap<String, Outcome> {
    ids.into_iter().map(|id| (id, o.clone())).collect()
}

fn first_few(ids: &[String]) -> String {
    let shown: Vec<&str> = ids.iter().take(5).map(String::as_str).collect();
    if ids.len() > shown.len() {
        format!("{} (+{} more)", shown.join(", "), ids.len() - shown.len())
    } else {
        shown.join(", ")
    }
}

// ── llm ──────────────────────────────────────────────────────────────────────────────────────

/// What `testing/llm-conformance/run.sh` left in its `--out` dir, plus the cell universe it judged.
#[derive(Debug, Clone)]
pub struct LlmRun {
    pub exit: Option<i32>,
    /// `ledger.tsv`: `id \t PASS|FAIL|SKIP \t title \t detail`, appended, last row wins.
    pub ledger: Option<String>,
    /// `owed.txt`: the ids the rig's own verdict owed (named gaps already removed).
    pub owed: Option<String>,
    /// `stale-gaps.txt`: non-empty stops the rig before its verdict.
    pub stale_gaps: Option<String>,
    /// `testing/shadow-oracle/cells.json`, for each cell's `ingress_dialect`.
    pub cells: String,
    pub evidence: String,
}

/// One rig run, six verdicts: each owed ledger id belongs to the dialect of its cell.
pub fn decide_llm(run: &LlmRun) -> BTreeMap<String, Outcome> {
    let ids = || LLM_DIALECTS.iter().map(|d| llm_suite(d));
    let dialect_of: BTreeMap<String, String> = match serde_json::from_str::<Value>(&run.cells) {
        Ok(doc) => doc
            .get("cells")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|c| {
                c.get("plane").and_then(Value::as_str) == Some("llm")
                    && c.get("family").and_then(Value::as_str) == Some("llm.wire")
            })
            .filter_map(|c| {
                Some((
                    c.get("id")?.as_str()?.to_string(),
                    c.get("ingress_dialect")?.as_str()?.to_string(),
                ))
            })
            .collect(),
        Err(e) => {
            return fan(
                ids(),
                &Outcome::not_run(format!(
                    "cells.json is not JSON ({e}), so no ledger row can be given a dialect"
                )),
            )
        }
    };

    if let Some(stale) = run.stale_gaps.as_deref().filter(|s| !s.trim().is_empty()) {
        let rows: Vec<String> = stale.lines().map(str::to_string).collect();
        return fan(
            ids(),
            &Outcome::fail(
                format!(
                    "testing/llm-conformance/named-gaps.json has stale entries the rig refused \
                     before its verdict: {}",
                    first_few(&rows)
                ),
                run.evidence.clone(),
            ),
        );
    }

    let mut rows: BTreeMap<&str, &str> = BTreeMap::new();
    for line in run.ledger.as_deref().unwrap_or_default().lines() {
        let mut f = line.split('\t');
        if let (Some(id), Some(st)) = (f.next(), f.next()) {
            if !id.is_empty() {
                rows.insert(id, st);
            }
        }
    }
    if run.exit.is_none() || rows.is_empty() {
        return fan(
            ids(),
            &Outcome::not_run(format!(
                "the llm rig judged nothing ({}, {} ledger row(s))",
                rc(run.exit),
                rows.len()
            )),
        );
    }
    if let Some(st) = rows.get(LLM_GAPS_ROW).filter(|s| **s != "PASS") {
        return fan(
            ids(),
            &Outcome::fail(
                format!("`{LLM_GAPS_ROW}` is {st}: the named gaps are not the declared ones"),
                run.evidence.clone(),
            ),
        );
    }
    let Some(owed) = run.owed.as_deref() else {
        return fan(
            ids(),
            &Outcome::not_run(format!(
                "the llm rig wrote no owed list ({}): it stopped before its verdict",
                rc(run.exit)
            )),
        );
    };

    let mut out = BTreeMap::new();
    for d in LLM_DIALECTS {
        let owed_d: Vec<&str> = owed
            .lines()
            .map(str::trim)
            .filter(|id| {
                let cell = id.split('#').next().unwrap_or_default();
                dialect_of.get(cell).map(String::as_str) == Some(*d)
            })
            .collect();
        let outcome = if owed_d.is_empty() {
            Outcome::not_run(format!(
                "no {d} cell was owed by this recording, so the rig judged nothing for this dialect"
            ))
        } else {
            let red: Vec<String> = owed_d
                .iter()
                .filter_map(|id| match rows.get(id) {
                    Some(&"PASS") => None,
                    Some(st) => Some(format!("{id} {st}")),
                    None => Some(format!("{id} DID NOT RUN")),
                })
                .collect();
            if red.is_empty() {
                Outcome::pass(run.evidence.clone())
            } else {
                Outcome::fail(
                    format!(
                        "{} of {} owed {d} row(s) red: {}",
                        red.len(),
                        owed_d.len(),
                        first_few(&red)
                    ),
                    run.evidence.clone(),
                )
            }
        };
        out.insert(llm_suite(d), outcome);
    }
    unattributed_red(&mut out, run.exit, "llm", &run.evidence);
    out
}

/// A rig whose own verdict is red while no suite it split into is red: the red belongs to nobody
/// in particular, so it is everybody's — no pass survives it.
fn unattributed_red(out: &mut BTreeMap<String, Outcome>, exit: Option<i32>, rig: &str, ev: &str) {
    if exit == Some(0) || out.values().any(|o| o.status == Status::Fail) {
        return;
    }
    for o in out.values_mut() {
        if o.status == Status::Pass {
            *o = Outcome::fail(
                format!(
                    "the {rig} rig's own verdict is red ({}) but no row of this suite is; an \
                     unattributed red is no suite's pass",
                    rc(exit)
                ),
                ev.to_string(),
            );
        }
    }
}

// ── voice ────────────────────────────────────────────────────────────────────────────────────

/// What the voice battery left: its self-test, CI's boot-validate leg, the `--verdict` run and the
/// `VOICE_RESULT_LOG` rows (`leg \t slice \t PASS|FAIL|NORESULT \t detail`).
#[derive(Debug, Clone)]
pub struct VoiceRun {
    pub selftest: Option<i32>,
    pub boot_validate: Option<i32>,
    pub verdict: Option<i32>,
    pub results: Option<String>,
    pub evidence: String,
}

/// Whether one result row speaks for `dialect`. The irregular legs are named; every other leg is
/// dialect-neutral and speaks for both. Governance is never a conformance result.
fn voice_row_applies(leg: &str, slice: &str, dialect: &str) -> bool {
    match leg {
        "governance" => false,
        "spec-per-dialect" => slice == dialect,
        "gemini-live-route" => dialect == "gemini",
        // The ordered pairs: oo is openai's alone, gg gemini's alone, a cross pair is both.
        "cross-parity" => match slice {
            "oo" => dialect == "openai",
            "gg" => dialect == "gemini",
            _ => true,
        },
        _ => true,
    }
}

pub fn decide_voice(run: &VoiceRun) -> BTreeMap<String, Outcome> {
    let ids = || VOICE_SUITES.iter().map(|(_, s)| s.to_string());
    if run.selftest != Some(0) {
        return fan(
            ids(),
            &Outcome::not_run(format!(
                "the voice battery's self-test is red ({}): its accounting cannot be believed",
                rc(run.selftest)
            )),
        );
    }
    if run.boot_validate.is_none() || run.verdict.is_none() {
        return fan(
            ids(),
            &Outcome::not_run(format!(
                "a voice leg did not finish (boot-validate {}, verdict {})",
                rc(run.boot_validate),
                rc(run.verdict)
            )),
        );
    }
    let rows: Vec<(&str, &str, &str)> = run
        .results
        .as_deref()
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let mut f = l.split('\t');
            Some((f.next()?, f.next()?, f.next()?))
        })
        .filter(|(leg, _, _)| *leg != "governance")
        .collect();
    if rows.is_empty() {
        return fan(
            ids(),
            &Outcome::not_run(format!(
                "the voice battery judged nothing (verdict {}, no conformance result rows)",
                rc(run.verdict)
            )),
        );
    }
    if run.boot_validate != Some(0) {
        return fan(
            ids(),
            &Outcome::fail(
                format!(
                    "boot-validate is red ({}): the streams: section does not parse or the \
                     plane is not reached at boot",
                    rc(run.boot_validate)
                ),
                run.evidence.clone(),
            ),
        );
    }
    let mut out = BTreeMap::new();
    for (dialect, suite) in VOICE_SUITES {
        let mine: Vec<&(&str, &str, &str)> = rows
            .iter()
            .filter(|(leg, slice, _)| voice_row_applies(leg, slice, dialect))
            .collect();
        let red: Vec<String> = mine
            .iter()
            .filter(|(_, _, v)| *v != "PASS")
            .map(|(leg, slice, v)| format!("{leg}/{slice} {v}"))
            .collect();
        let outcome = if !red.is_empty() {
            Outcome::fail(
                format!("{} {dialect} result(s) red: {}", red.len(), first_few(&red)),
                run.evidence.clone(),
            )
        } else if mine.is_empty() {
            Outcome::not_run(format!("no voice leg judged the {dialect} dialect"))
        } else {
            Outcome::pass(run.evidence.clone())
        };
        out.insert(suite.to_string(), outcome);
    }
    unattributed_red(&mut out, run.verdict, "voice", &run.evidence);
    out
}

// ── ws ───────────────────────────────────────────────────────────────────────────────────────

/// The four legs of testing/ws-conformance/scripts/run.sh and the subject's parsed verdict.
#[derive(Debug, Clone)]
pub struct WsRun {
    pub selftest: Option<i32>,
    pub control: Option<i32>,
    pub negative_control: Option<i32>,
    pub subject: Option<i32>,
    /// `reports/subject/verdict.json`, as `bin/parse-autobahn-report.mjs` wrote it.
    pub subject_verdict: Option<String>,
    /// The subject leg's output; its `ws-conformance: N case(s) judged ...` line is the reason.
    pub subject_log: String,
    pub evidence: String,
}

pub fn decide_ws(run: &WsRun) -> Outcome {
    // run.sh's exit 3: Docker is not available, so Autobahn never ran.
    if [run.control, run.negative_control, run.subject].contains(&Some(3)) {
        return Outcome::not_run("Docker is unavailable: the Autobahn legs could not run");
    }
    for (leg, code, why) in [
        (
            "selftest",
            run.selftest,
            "the parser or the arm-state check does not bite",
        ),
        (
            "control",
            run.control,
            "the suite cannot pass a known-good reference peer",
        ),
        (
            "negative-control",
            run.negative_control,
            "the suite cannot catch a deliberately broken peer",
        ),
    ] {
        if code != Some(0) {
            return Outcome::not_run(format!(
                "ws {leg} leg is red ({}): {why}, so nothing about busbar was judged",
                rc(code)
            ));
        }
    }
    let Some(code) = run.subject else {
        return Outcome::not_run("the ws subject leg did not finish");
    };
    let Some(v) = run
        .subject_verdict
        .as_deref()
        .and_then(|t| serde_json::from_str::<Value>(t).ok())
    else {
        return Outcome::not_run(format!(
            "the ws subject leg wrote no readable verdict (exit {code})"
        ));
    };
    if v.get("armed").and_then(Value::as_bool) != Some(true) {
        return Outcome::not_run(
            "the ws subject was not armed: ws-conformance-subject did not build or boot",
        );
    }
    let summary = run
        .subject_log
        .lines()
        .rev()
        .find(|l| l.starts_with("ws-conformance: "))
        .map(str::to_string);
    match v.get("status").and_then(Value::as_str) {
        Some("pass") if code == 0 => Outcome::pass(run.evidence.clone()),
        Some("pass") => Outcome::fail(
            format!("the report reads pass but the subject leg exited {code}"),
            run.evidence.clone(),
        ),
        Some("fail") => Outcome::fail(
            summary.unwrap_or_else(|| "Autobahn graded the subject red".to_string()),
            run.evidence.clone(),
        ),
        other => Outcome::not_run(format!(
            "the ws subject verdict carries status {other:?}, not pass or fail"
        )),
    }
}

// ── mcp ──────────────────────────────────────────────────────────────────────────────────────

/// Legs judged the way the removed `qa-conformance-mcp.yml` verdict job judged them: every leg
/// must have executed and passed. A red control is `not-run` (it judges the instrument); a red
/// subject leg is `fail`; a subject leg that never finished is `not-run`.
pub fn decide_legs(
    controls: &[(&str, Option<i32>)],
    subjects: &[(&str, Option<i32>)],
    evidence: &str,
) -> Outcome {
    for (leg, code) in controls {
        if *code != Some(0) {
            return Outcome::not_run(format!(
                "control leg `{leg}` is red ({}): the instruments are red, so nothing about \
                 busbar was judged",
                rc(*code)
            ));
        }
    }
    let red: Vec<String> = subjects
        .iter()
        .filter(|(_, c)| c.is_some_and(|c| c != 0))
        .map(|(leg, c)| format!("{leg} ({})", rc(*c)))
        .collect();
    if !red.is_empty() {
        return Outcome::fail(
            format!("subject leg(s) red: {}", red.join(", ")),
            evidence.to_string(),
        );
    }
    if let Some((leg, _)) = subjects.iter().find(|(_, c)| c.is_none()) {
        return Outcome::not_run(format!("subject leg `{leg}` did not run to an exit"));
    }
    if subjects.is_empty() {
        return Outcome::not_run("no subject leg ran");
    }
    Outcome::pass(evidence.to_string())
}

// ── jev ──────────────────────────────────────────────────────────────────────────────────────

/// The jev rig judges itself and writes its judgement to `--out`; that file's status and reason
/// are carried, its `commit` is not (the producer stamps HEAD).
pub fn decide_jev(
    selftest: Option<i32>,
    rig_exit: Option<i32>,
    rig_verdict: Option<&str>,
    evidence: &str,
) -> Outcome {
    if selftest != Some(0) {
        return Outcome::not_run(format!(
            "the jev rig's self-test is red ({}): its judge cannot be believed",
            rc(selftest)
        ));
    }
    if rig_exit != Some(0) {
        return Outcome::not_run(format!("the jev rig wrote no verdict ({})", rc(rig_exit)));
    }
    let Some(v) = rig_verdict.and_then(|t| serde_json::from_str::<Value>(t).ok()) else {
        return Outcome::not_run(
            "the jev rig exited 0 but its verdict file is missing or not JSON",
        );
    };
    let reason = v
        .get("reason")
        .and_then(Value::as_str)
        .filter(|r| !r.is_empty());
    if v.get("armed").and_then(Value::as_bool) != Some(true) {
        return Outcome::not_run(reason.unwrap_or("the jev rig did not judge (armed=false)"));
    }
    match v.get("status").and_then(Value::as_str) {
        Some("pass") => Outcome::pass(evidence),
        Some("fail") => Outcome::fail(reason.unwrap_or("the jev rig judged red"), evidence),
        other => Outcome::not_run(format!(
            "the jev rig's verdict carries status {other:?}, not pass or fail"
        )),
    }
}

// ── running the rigs ─────────────────────────────────────────────────────────────────────────

fn on_path(tool: &str) -> bool {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join(tool).is_file()))
        .unwrap_or(false)
}

fn read_opt(p: &Path) -> Option<String> {
    std::fs::read_to_string(p).ok()
}

fn fresh_dir(p: &Path) {
    let _ = std::fs::remove_dir_all(p);
    let _ = std::fs::create_dir_all(p);
}

pub struct Runner {
    root: PathBuf,
    work: PathBuf,
    target: PathBuf,
    recording: Option<PathBuf>,
}

impl Runner {
    pub fn new(root: &Path, recording: Option<&Path>) -> Runner {
        let target = std::env::var_os("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .map(|t| if t.is_absolute() { t } else { root.join(t) })
            .unwrap_or_else(|| root.join("target"));
        Runner {
            root: root.to_path_buf(),
            work: target.join("conformance-record"),
            target,
            recording: recording.map(Path::to_path_buf),
        }
    }

    pub fn run(&self, rig: Rig) -> BTreeMap<String, Outcome> {
        fresh_dir(&self.work.join(rig.name()));
        match rig {
            Rig::Llm => self.run_llm(),
            Rig::Voice => self.run_voice(),
            Rig::Mcp => BTreeMap::from([("mcp".to_string(), self.run_mcp())]),
            Rig::Ws => BTreeMap::from([("ws".to_string(), self.run_ws())]),
            Rig::Jev => BTreeMap::from([("jev".to_string(), self.run_jev())]),
        }
    }

    /// A path as the verdict's `evidence`: relative to the checkout when it lies inside it.
    fn rel(&self, p: &Path) -> String {
        p.strip_prefix(&self.root)
            .unwrap_or(p)
            .to_string_lossy()
            .into_owned()
    }

    /// `not-run` naming every tool the rig needs that is not on PATH.
    fn missing(&self, rig: Rig, tools: &[&str]) -> Option<Outcome> {
        let gone: Vec<&str> = tools.iter().copied().filter(|t| !on_path(t)).collect();
        (!gone.is_empty()).then(|| {
            Outcome::not_run(format!(
                "the {} rig cannot run here: not on PATH: {}",
                rig.name(),
                gone.join(", ")
            ))
        })
    }

    /// Run one leg with its output in `<work>/<rig>/<leg>.log`; its exit code, or `None` when it
    /// could not be started or was killed by a signal.
    fn leg(
        &self,
        rig: Rig,
        leg: &str,
        cmd: &[&str],
        cwd: Option<&Path>,
        env: &[(&str, String)],
    ) -> Option<i32> {
        let log = self.work.join(rig.name()).join(format!("{leg}.log"));
        let Ok(file) = std::fs::File::create(&log) else {
            eprintln!("  {}: {leg}: cannot create {}", rig.name(), log.display());
            return None;
        };
        let Ok(err) = file.try_clone() else {
            return None;
        };
        let mut c = Command::new(cmd[0]);
        c.args(&cmd[1..])
            .current_dir(cwd.unwrap_or(&self.root))
            .stdin(Stdio::null())
            .stdout(file)
            .stderr(err);
        for k in SCRUBBED_ENV {
            c.env_remove(k);
        }
        for (k, v) in env {
            c.env(k, v);
        }
        let t = Instant::now();
        let code = c.status().ok().and_then(|s| s.code());
        eprintln!(
            "  {}: {leg}: {} in {}s (log {})",
            rig.name(),
            rc(code),
            t.elapsed().as_secs(),
            self.rel(&log)
        );
        code
    }

    fn run_llm(&self) -> BTreeMap<String, Outcome> {
        let ids = || LLM_DIALECTS.iter().map(|d| llm_suite(d));
        let rig = Rig::Llm;
        if let Some(o) = self.missing(rig, &["bash", "python3", "curl"]) {
            return fan(ids(), &o);
        }
        let Some(rec) = &self.recording else {
            return fan(
                ids(),
                &Outcome::not_run(
                    "no --recording: the llm rig judges the oracle's candidate recording and none \
                     was named",
                ),
            );
        };
        let has_rows = read_opt(&rec.join("ledger.tsv")).is_some_and(|l| !l.trim().is_empty());
        if !has_rows {
            return fan(
                ids(),
                &Outcome::not_run(format!(
                    "the recording {} has no ledger rows: the oracle recorded nothing to judge",
                    rec.display()
                )),
            );
        }
        if self.leg(rig, "pyyaml", &["python3", "-c", "import yaml"], None, &[]) != Some(0) {
            return fan(
                ids(),
                &Outcome::not_run(
                    "PyYAML is not importable by python3 (the rig parses the YAML specs; CI pinned \
                     pyyaml==6.0.2)",
                ),
            );
        }
        let selftest = self.leg(
            rig,
            "selftest",
            &["bash", "testing/llm-conformance/selftest.sh"],
            None,
            &[],
        );
        if selftest != Some(0) {
            return fan(
                ids(),
                &Outcome::not_run(format!(
                    "the llm rig's self-test is red ({}): its verdict cannot be believed",
                    rc(selftest)
                )),
            );
        }
        let out = self.work.join(rig.name()).join("report");
        fresh_dir(&out);
        let rec_s = rec.to_string_lossy().into_owned();
        let out_s = out.to_string_lossy().into_owned();
        let exit = self.leg(
            rig,
            "run",
            &[
                "bash",
                "testing/llm-conformance/run.sh",
                "--recording",
                &rec_s,
                "--out",
                &out_s,
            ],
            None,
            &[],
        );
        let Some(cells) = read_opt(&self.root.join("testing/shadow-oracle/cells.json")) else {
            return fan(
                ids(),
                &Outcome::not_run("testing/shadow-oracle/cells.json is unreadable"),
            );
        };
        decide_llm(&LlmRun {
            exit,
            ledger: read_opt(&out.join("ledger.tsv")),
            owed: read_opt(&out.join("owed.txt")),
            stale_gaps: read_opt(&out.join("stale-gaps.txt")),
            cells,
            evidence: self.rel(&out.join("report.json")),
        })
    }

    fn run_voice(&self) -> BTreeMap<String, Outcome> {
        let rig = Rig::Voice;
        if let Some(o) = self.missing(rig, &["bash", "cargo"]) {
            return fan(VOICE_SUITES.iter().map(|(_, s)| s.to_string()), &o);
        }
        let script = "testing/voice-conformance/voice-conformance.sh";
        let results = self.work.join(rig.name()).join("results.tsv");
        let selftest = self.leg(rig, "selftest", &["bash", script, "--selftest"], None, &[]);
        let (mut boot_validate, mut verdict) = (None, None);
        if selftest == Some(0) {
            // CI's boot-validate job, as it ran: the owned `streams:` section parses at boot.
            boot_validate = Some(0);
            for (leg, cmd) in [
                (
                    "boot-validate-build",
                    &[
                        "cargo",
                        "build",
                        "-p",
                        "busbar",
                        "--features",
                        "plane-streaming",
                    ][..],
                ),
                (
                    "boot-validate-config",
                    &[
                        "cargo",
                        "test",
                        "-p",
                        "busbar-voice",
                        "--features",
                        "runtime",
                        "config::",
                    ][..],
                ),
                (
                    "boot-validate-voice-boot",
                    &[
                        "cargo",
                        "test",
                        "-p",
                        "busbar",
                        "--features",
                        "plane-streaming",
                        "--test",
                        "voice_boot",
                    ][..],
                ),
            ] {
                let c = self.leg(rig, leg, cmd, None, &[]);
                if c != Some(0) {
                    boot_validate = c;
                    break;
                }
            }
            verdict = self.leg(
                rig,
                "verdict",
                &["bash", script, "--verdict"],
                None,
                &[("VOICE_RESULT_LOG", results.to_string_lossy().into_owned())],
            );
        }
        decide_voice(&VoiceRun {
            selftest,
            boot_validate,
            verdict,
            results: read_opt(&results),
            evidence: self.rel(&results),
        })
    }

    fn run_mcp(&self) -> Outcome {
        let rig = Rig::Mcp;
        if let Some(o) = self.missing(
            rig,
            &["bash", "node", "npx", "pnpm", "python3", "cargo", "curl"],
        ) {
            return o;
        }
        let build = self.leg(
            rig,
            "build-busbar",
            &["cargo", "build", "--bin", "busbar"],
            None,
            &[],
        );
        let bin = self.target.join("debug").join("busbar");
        if build != Some(0) || !bin.is_file() {
            return Outcome::not_run(format!(
                "`cargo build --bin busbar` gave no subject ({}): nothing to arm the subject legs with",
                rc(build)
            ));
        }
        // Reports from an earlier run must not stand in for this one's.
        let _ = std::fs::remove_dir_all(self.root.join("testing/mcp-conformance/reports"));
        let _ = std::fs::remove_dir_all(self.root.join(".mcp-conformance/subject"));
        let gate = "scripts/mcp-conformance.sh";
        let battery = self.root.join("testing/mcp-conformance");
        let controls = [
            (
                "selftest",
                self.leg(rig, "selftest", &["bash", gate, "--selftest"], None, &[]),
            ),
            (
                "official-control",
                self.leg(
                    rig,
                    "official-control",
                    &["bash", gate, "--official-control"],
                    None,
                    &[],
                ),
            ),
            (
                "battery-control",
                self.leg(
                    rig,
                    "battery-control",
                    &["bash", gate, "--battery-control"],
                    None,
                    &[],
                ),
            ),
            (
                "battery-negative-control",
                self.leg(
                    rig,
                    "battery-negative-control",
                    &["bash", "scripts/negative-control.sh"],
                    Some(&battery),
                    &[],
                ),
            ),
        ];
        let armed = controls.iter().all(|(_, c)| *c == Some(0));
        let arm = [("MCP_SUBJECT_BUSBAR_BIN", bin.to_string_lossy().into_owned())];
        let subject = |leg: &'static str, cmd: &[&str]| {
            let code = if armed {
                self.leg(rig, leg, cmd, None, &arm)
            } else {
                None
            };
            (leg, code)
        };
        let subjects = [
            subject("official-subject", &["bash", gate, "--official-subject"]),
            subject("battery-subject", &["bash", gate, "--battery-subject"]),
            subject(
                "fixture-absence",
                &["bash", "scripts/mcp-fixture-absence-gate.sh", "--run"],
            ),
        ];
        decide_legs(
            &controls,
            &subjects,
            &self.rel(&self.root.join(".mcp-conformance/subject")),
        )
    }

    fn run_ws(&self) -> Outcome {
        let rig = Rig::Ws;
        if let Some(o) = self.missing(rig, &["bash", "node", "npm", "cargo", "docker"]) {
            return o;
        }
        let dir = self.root.join("testing/ws-conformance");
        let npm = self.leg(rig, "npm-ci", &["npm", "ci"], Some(&dir), &[]);
        if npm != Some(0) {
            return Outcome::not_run(format!(
                "`npm ci` in testing/ws-conformance failed ({})",
                rc(npm)
            ));
        }
        let reports = dir.join("reports");
        let _ = std::fs::remove_dir_all(&reports);
        let script = "testing/ws-conformance/scripts/run.sh";
        let leg = |name: &str| {
            self.leg(
                rig,
                name,
                &["bash", script, &format!("--{name}")],
                None,
                &[],
            )
        };
        let selftest = leg("selftest");
        let control = leg("control");
        let negative_control = leg("negative-control");
        let subject = leg("subject");
        let verdict = reports.join("subject").join("verdict.json");
        decide_ws(&WsRun {
            selftest,
            control,
            negative_control,
            subject,
            subject_verdict: read_opt(&verdict),
            subject_log: read_opt(&self.work.join(rig.name()).join("subject.log"))
                .unwrap_or_default(),
            evidence: self.rel(&verdict),
        })
    }

    fn run_jev(&self) -> Outcome {
        let rig = Rig::Jev;
        if let Some(o) = self.missing(rig, &["bash", "cargo", "curl", "python3"]) {
            return o;
        }
        let script = "testing/jev-conformance/jev-conformance.sh";
        let selftest = self.leg(rig, "selftest", &["bash", script, "--selftest"], None, &[]);
        let out = self.work.join(rig.name()).join("rig-verdict.json");
        let out_s = out.to_string_lossy().into_owned();
        let exit = if selftest == Some(0) {
            self.leg(
                rig,
                "verdict",
                &[
                    "bash",
                    script,
                    "--out",
                    &out_s,
                    "--run-id",
                    "xtask conformance record",
                ],
                None,
                &[],
            )
        } else {
            None
        };
        decide_jev(selftest, exit, read_opt(&out).as_deref(), &self.rel(&out))
    }
}
