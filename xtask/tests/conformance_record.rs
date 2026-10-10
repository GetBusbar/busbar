//! `cargo xtask conformance record` — the PRODUCER of `conformance/verdicts/<id>.json`.
//!
//! What these cases pin (ARCHITECT ruling 2026-10-02 W): a verdict's `commit` is `git rev-parse
//! HEAD` of the judged checkout, resolved by the writer itself and never taken from a caller; a rig
//! that did not judge can never be written as a pass; the llm rig's one ledger splits into the six
//! `llm-<dialect>` suites by the dialect of each owed cell; and every file the writer emits carries
//! exactly the fields `conformance/verdicts/verdict.schema.json` requires and no field it forbids.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::Value;
use xtask::conformance_record::{
    decide_legs, decide_llm, decide_voice, decide_ws, head_commit, render_verdict, write_verdict,
    LlmRun, Outcome, Status, VoiceRun, WsRun, LLM_DIALECTS,
};
use xtask::gates::conformance_sync::render::{Suite, Tier};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask/ has a parent")
        .to_path_buf()
}

fn tmpdir(tag: &str) -> PathBuf {
    let d = repo_root().join(".fix").join(format!(
        "xtask-test-{tag}-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).expect("scratch dir");
    d
}

fn git(dir: &Path, args: &[&str]) -> String {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args([
            "-c",
            "user.name=fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .output()
        .expect("git runs");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

/// A throwaway repository with one commit, so HEAD is a real sha nobody passed in.
fn fixture_repo(tag: &str) -> PathBuf {
    let d = tmpdir(tag);
    git(&d, &["init", "-q"]);
    std::fs::write(d.join("a.txt"), "one\n").unwrap();
    git(&d, &["add", "a.txt"]);
    git(&d, &["commit", "-q", "-m", "one"]);
    d
}

fn suite(id: &str) -> Suite {
    Suite {
        id: id.to_string(),
        standard: format!("{id} standard"),
        plan: format!("{id} plan"),
        tier: Tier::parse("conformant").unwrap(),
        label: id.to_string(),
        verdict: format!("conformance-verdict-{id}"),
        public: true,
        not_run_reason: None,
        plane: None,
    }
}

fn read_json(p: &Path) -> Value {
    serde_json::from_str(&std::fs::read_to_string(p).expect("verdict written")).expect("JSON")
}

// ── the writer stamps HEAD ─────────────────────────────────────────────────────────────────────

#[test]
fn the_writer_stamps_the_checkouts_own_head_and_follows_it_when_it_moves() {
    let repo = fixture_repo("record-head");
    let out = repo.join("out");
    let first = git(&repo, &["rev-parse", "HEAD"]);
    assert_eq!(head_commit(&repo).unwrap(), first);

    let path = write_verdict(
        &repo,
        &out,
        &suite("mcp"),
        &Outcome::pass("rig/report.json"),
    )
    .expect("a judged pass is written");
    assert_eq!(path, out.join("mcp.json"));
    let v = read_json(&path);
    assert_eq!(v["commit"], Value::String(first.clone()));
    assert_eq!(v["status"], "pass");
    assert_eq!(v["armed"], true);
    assert_eq!(v["suite"], "mcp");
    assert_eq!(v["standard"], "mcp standard");
    assert_eq!(v["plan"], "mcp plan");
    assert_eq!(v["evidence"], "rig/report.json");

    // A new commit is a new judged checkout: the next verdict names IT, not the first sha.
    std::fs::write(repo.join("a.txt"), "two\n").unwrap();
    git(&repo, &["commit", "-q", "-am", "two"]);
    let second = git(&repo, &["rev-parse", "HEAD"]);
    assert_ne!(first, second);
    let v = read_json(
        &write_verdict(&repo, &out, &suite("mcp"), &Outcome::pass("x")).expect("written"),
    );
    assert_eq!(v["commit"], Value::String(second));
    let _ = std::fs::remove_dir_all(&repo);
}

#[test]
fn a_tree_with_no_head_writes_nothing() {
    let d = tmpdir("record-nohead");
    git(&d, &["init", "-q"]);
    let out = d.join("out");
    assert!(head_commit(&d).is_err());
    assert!(write_verdict(&d, &out, &suite("ws"), &Outcome::fail("red", "x")).is_err());
    assert!(!out.join("ws.json").exists());
    let _ = std::fs::remove_dir_all(&d);
}

// ── a rig that did not judge is never a pass ───────────────────────────────────────────────────

#[test]
fn the_writer_refuses_a_pass_the_rig_did_not_judge() {
    let repo = fixture_repo("record-unarmed");
    let out = repo.join("out");
    let unjudged = Outcome {
        status: Status::Pass,
        armed: false,
        reason: None,
        evidence: None,
    };
    assert!(render_verdict(&suite("ws"), &unjudged, "abc", "2026-10-02T00:00:00Z").is_err());
    assert!(write_verdict(&repo, &out, &suite("ws"), &unjudged).is_err());
    assert!(
        !out.join("ws.json").exists(),
        "a refused pass leaves no file"
    );

    // not-run is always unarmed and always says why.
    let nr = Outcome::not_run("docker is not on PATH");
    assert_eq!(nr.status, Status::NotRun);
    assert!(!nr.armed);
    let v = read_json(&write_verdict(&repo, &out, &suite("ws"), &nr).unwrap());
    assert_eq!(v["status"], "not-run");
    assert_eq!(v["armed"], false);
    assert_eq!(v["reason"], "docker is not on PATH");

    // An armed not-run and a reasonless fail are both incoherent and refused.
    let armed_nr = Outcome {
        status: Status::NotRun,
        armed: true,
        reason: Some("x".into()),
        evidence: None,
    };
    assert!(render_verdict(&suite("ws"), &armed_nr, "abc", "t").is_err());
    let bare_fail = Outcome {
        status: Status::Fail,
        armed: true,
        reason: None,
        evidence: None,
    };
    assert!(render_verdict(&suite("ws"), &bare_fail, "abc", "t").is_err());
    let _ = std::fs::remove_dir_all(&repo);
}

#[test]
fn every_rig_decider_answers_not_run_when_its_self_test_or_controls_are_red() {
    // voice: a red self-test means no verdict about busbar can be believed.
    let v = decide_voice(&VoiceRun {
        selftest: Some(1),
        boot_validate: Some(0),
        verdict: Some(0),
        results: Some("replay\tdefault\tPASS\tok\n".into()),
        evidence: "e".into(),
    });
    for id in ["voice-openai-realtime", "voice-gemini-live"] {
        assert_eq!(v[id].status, Status::NotRun, "{id}");
        assert!(!v[id].armed);
    }

    // ws: Docker missing (exit 3) is not-run, and so is a red control.
    let ws = |selftest, control, neg, subject, json: Option<&str>| {
        decide_ws(&WsRun {
            selftest,
            control,
            negative_control: neg,
            subject,
            subject_verdict: json.map(str::to_string),
            subject_log: String::new(),
            evidence: "e".into(),
        })
    };
    let good = r#"{"status":"pass","armed":true}"#;
    assert_eq!(
        ws(Some(0), Some(3), Some(3), Some(3), None).status,
        Status::NotRun
    );
    assert_eq!(
        ws(Some(0), Some(1), Some(0), Some(0), Some(good)).status,
        Status::NotRun
    );
    assert_eq!(
        ws(
            Some(0),
            Some(0),
            Some(0),
            Some(0),
            Some(r#"{"status":"pass","armed":false}"#)
        )
        .status,
        Status::NotRun
    );
    assert_eq!(
        ws(
            Some(0),
            Some(0),
            Some(0),
            Some(1),
            Some(r#"{"status":"fail","armed":true}"#)
        )
        .status,
        Status::Fail
    );
    let pass = ws(Some(0), Some(0), Some(0), Some(0), Some(good));
    assert_eq!(pass.status, Status::Pass);
    assert!(pass.armed);
    // A pass the parser wrote while the leg itself exited red is not believed.
    assert_eq!(
        ws(Some(0), Some(0), Some(0), Some(1), Some(good)).status,
        Status::Fail
    );

    // mcp: a red control is not-run; a red subject is fail; all green is pass.
    let controls_ok = [("selftest", Some(0)), ("official-control", Some(0))];
    let subj = |rc| [("official-subject", rc), ("battery-subject", Some(0))];
    assert_eq!(
        decide_legs(&[("selftest", Some(1))], &subj(Some(0)), "e").status,
        Status::NotRun
    );
    assert_eq!(
        decide_legs(&controls_ok, &subj(None), "e").status,
        Status::NotRun
    );
    assert_eq!(
        decide_legs(&controls_ok, &subj(Some(1)), "e").status,
        Status::Fail
    );
    assert_eq!(
        decide_legs(&controls_ok, &subj(Some(0)), "e").status,
        Status::Pass
    );
}

// ── the llm ledger splits by dialect ───────────────────────────────────────────────────────────

fn cells_json() -> String {
    let cell = |id: &str, d: &str| serde_json::json!({"id": id, "plane": "llm", "family": "llm.wire", "ingress_dialect": d});
    serde_json::json!({"cells": [
        cell("llm|openai|a", "openai"),
        cell("llm|openai|b", "openai"),
        cell("llm|anthropic|a", "anthropic"),
        cell("llm|responses|a", "responses"),
        // Not an llm.wire cell: never owed to any dialect.
        {"id": "teller|x", "plane": "llm", "family": "teller"},
    ]})
    .to_string()
}

const OWED: &str = "llm|openai|a#request\nllm|openai|a#response\nllm|openai|b#response\n\
llm|anthropic|a#request\nllm|anthropic|a#response\nllm|responses|a#response\n\
gate|llm-conformance|named-gaps\n";

fn ledger(rows: &[(&str, &str)]) -> String {
    rows.iter()
        .map(|(id, st)| format!("{id}\t{st}\ttitle\tdetail\n"))
        .collect()
}

fn llm(
    exit: Option<i32>,
    ledger_text: Option<String>,
) -> std::collections::BTreeMap<String, Outcome> {
    decide_llm(&LlmRun {
        exit,
        ledger: ledger_text,
        owed: Some(OWED.to_string()),
        stale_gaps: None,
        cells: cells_json(),
        evidence: "target/conformance-record/llm/report.json".into(),
    })
}

#[test]
fn the_llm_report_maps_to_six_suites_by_each_cells_dialect() {
    assert_eq!(
        LLM_DIALECTS,
        &[
            "anthropic",
            "bedrock",
            "cohere",
            "gemini",
            "openai",
            "responses"
        ]
    );
    let rows = ledger(&[
        ("llm|openai|a#request", "PASS"),
        ("llm|openai|a#response", "PASS"),
        ("llm|openai|b#response", "PASS"),
        ("llm|anthropic|a#request", "PASS"),
        ("llm|anthropic|a#response", "FAIL"),
        ("llm|responses|a#response", "FAIL"),
        // last row wins, as verdict.sh resolves it
        ("llm|responses|a#response", "PASS"),
        ("gate|llm-conformance|named-gaps", "PASS"),
    ]);
    let m = llm(Some(1), Some(rows));
    let ids: BTreeSet<&str> = m.keys().map(String::as_str).collect();
    assert_eq!(
        ids,
        BTreeSet::from([
            "llm-anthropic",
            "llm-bedrock",
            "llm-cohere",
            "llm-gemini",
            "llm-openai",
            "llm-responses"
        ])
    );
    assert_eq!(m["llm-openai"].status, Status::Pass);
    assert!(m["llm-openai"].armed);
    assert_eq!(m["llm-responses"].status, Status::Pass);
    assert_eq!(m["llm-anthropic"].status, Status::Fail);
    assert!(m["llm-anthropic"]
        .reason
        .as_deref()
        .unwrap()
        .contains("llm|anthropic|a#response"));
    // A dialect with no owed cell in this recording judged nothing.
    assert_eq!(m["llm-bedrock"].status, Status::NotRun);
    assert!(!m["llm-bedrock"].armed);
    assert_eq!(
        m["llm-openai"].evidence.as_deref(),
        Some("target/conformance-record/llm/report.json")
    );
}

#[test]
fn an_owed_llm_row_that_never_ran_is_red_for_its_dialect_only() {
    let rows = ledger(&[
        ("llm|openai|a#request", "PASS"),
        // llm|openai|a#response: DID NOT RUN
        ("llm|openai|b#response", "PASS"),
        ("llm|anthropic|a#request", "PASS"),
        ("llm|anthropic|a#response", "PASS"),
        ("llm|responses|a#response", "PASS"),
        ("gate|llm-conformance|named-gaps", "PASS"),
    ]);
    let m = llm(Some(1), Some(rows));
    assert_eq!(m["llm-openai"].status, Status::Fail);
    assert_eq!(m["llm-anthropic"].status, Status::Pass);
}

#[test]
fn a_red_llm_rig_is_never_split_into_passes() {
    let all_pass = ledger(&[
        ("llm|openai|a#request", "PASS"),
        ("llm|openai|a#response", "PASS"),
        ("llm|openai|b#response", "PASS"),
        ("llm|anthropic|a#request", "PASS"),
        ("llm|anthropic|a#response", "PASS"),
        ("llm|responses|a#response", "PASS"),
        ("gate|llm-conformance|named-gaps", "PASS"),
    ]);
    // Every dialect clean and the rig green: every judged dialect passes.
    let m = llm(Some(0), Some(all_pass.clone()));
    assert_eq!(m["llm-openai"].status, Status::Pass);
    // The same rows under a red rig exit: the red is unattributed, so no dialect is a pass.
    let m = llm(Some(1), Some(all_pass));
    for d in ["llm-openai", "llm-anthropic", "llm-responses"] {
        assert_eq!(m[d].status, Status::Fail, "{d}");
    }
    // The named-gaps paperwork row is the whole battery's: red there is red everywhere.
    let gaps_red = ledger(&[
        ("llm|openai|a#request", "PASS"),
        ("llm|openai|a#response", "PASS"),
        ("llm|openai|b#response", "PASS"),
        ("gate|llm-conformance|named-gaps", "FAIL"),
    ]);
    assert_eq!(
        llm(Some(1), Some(gaps_red))["llm-openai"].status,
        Status::Fail
    );
    // No ledger (the rig stopped before validating) and an empty ledger both judged nothing.
    for led in [None, Some(String::new())] {
        let m = llm(Some(1), led);
        for d in LLM_DIALECTS {
            let o = &m[&format!("llm-{d}")];
            assert_eq!(o.status, Status::NotRun);
            assert!(!o.armed);
        }
    }
    // Stale named gaps stop the rig before its verdict: every dialect is red, none passes.
    let m = decide_llm(&LlmRun {
        exit: Some(1),
        ledger: Some(ledger(&[("llm|openai|a#request", "PASS")])),
        owed: None,
        stale_gaps: Some("llm|openai|a#response\n".into()),
        cells: cells_json(),
        evidence: "e".into(),
    });
    assert_eq!(m["llm-openai"].status, Status::Fail);
}

#[test]
fn voice_rows_are_attributed_to_the_dialect_they_judge() {
    let rows = "spec-per-dialect\topenai\tPASS\tok\n\
spec-per-dialect\tgemini\tFAIL\tboom\n\
replay\tdefault\tPASS\tok\n\
cross-parity\too\tPASS\tok\n\
cross-parity\tgg\tPASS\tok\n\
gemini-live-route\tgemini-live-route\tPASS\tok\n\
governance\tV1-barge-in-preemption\tFAIL\tobserved\n";
    let m = decide_voice(&VoiceRun {
        selftest: Some(0),
        boot_validate: Some(0),
        verdict: Some(1),
        results: Some(rows.into()),
        evidence: "e".into(),
    });
    assert_eq!(m["voice-openai-realtime"].status, Status::Pass);
    assert_eq!(m["voice-gemini-live"].status, Status::Fail);
    // A shared leg's red is red for both; governance never counts.
    let shared = "spec-per-dialect\topenai\tPASS\tok\nspec-per-dialect\tgemini\tPASS\tok\n\
replay\tdefault\tNORESULT\tnothing\ngovernance\tV1\tFAIL\tobserved\n";
    let m = decide_voice(&VoiceRun {
        selftest: Some(0),
        boot_validate: Some(0),
        verdict: Some(1),
        results: Some(shared.into()),
        evidence: "e".into(),
    });
    assert_eq!(m["voice-openai-realtime"].status, Status::Fail);
    assert_eq!(m["voice-gemini-live"].status, Status::Fail);
}

// ── the written file is the schema's shape ─────────────────────────────────────────────────────

#[test]
fn every_written_verdict_carries_the_schemas_required_fields_and_nothing_else() {
    let schema: Value = serde_json::from_str(
        &std::fs::read_to_string(repo_root().join("conformance/verdicts/verdict.schema.json"))
            .unwrap(),
    )
    .unwrap();
    let required: Vec<&str> = schema["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    let allowed: BTreeSet<&str> = schema["properties"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(schema["additionalProperties"], false);
    let statuses: Vec<&str> = schema["properties"]["status"]["enum"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();

    let repo = fixture_repo("record-schema");
    let out = repo.join("out");
    for (id, o) in [
        ("a", Outcome::pass("ev")),
        ("b", Outcome::fail("a finding", "ev")),
        ("c", Outcome::not_run("no toolchain")),
    ] {
        let v = read_json(&write_verdict(&repo, &out, &suite(id), &o).unwrap());
        let obj = v.as_object().unwrap();
        for k in &required {
            assert!(obj.contains_key(*k), "{id}: missing required `{k}`");
        }
        for k in obj.keys() {
            assert!(
                allowed.contains(k.as_str()),
                "{id}: `{k}` is not a schema property"
            );
        }
        assert_eq!(v["schema"], schema["properties"]["schema"]["const"]);
        assert!(statuses.contains(&v["status"].as_str().unwrap()));
        assert!(v["armed"].is_boolean());
        assert!(v["commit"].as_str().is_some_and(|c| c.len() == 40));
        let at = v["generated_at"].as_str().unwrap();
        assert_eq!(at.len(), 20, "RFC 3339 UTC seconds: {at}");
        assert!(at.ends_with('Z') && at.as_bytes()[10] == b'T');
        if v["status"] != "pass" {
            assert!(v["reason"].as_str().is_some_and(|r| !r.is_empty()));
        }
    }
    let _ = std::fs::remove_dir_all(&repo);
}

// ── the CLI refuses what it cannot produce ─────────────────────────────────────────────────────

fn run(args: &[&str]) -> i32 {
    let owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    xtask::cli::main(&owned)
}

#[test]
fn a_suite_with_no_registry_entry_is_an_argument_error() {
    assert_eq!(run(&["conformance", "record"]), 2);
    assert_eq!(
        run(&["conformance", "record", "--suite", "no-such-suite"]),
        2
    );
    assert_eq!(
        run(&["conformance", "record", "--suite", "mcp", "--all"]),
        2
    );
    assert_eq!(run(&["conformance", "record", "--bogus"]), 2);
    // HEAD is never an argument.
    assert_eq!(
        run(&["conformance", "record", "--suite", "mcp", "--sha", "0000"]),
        2
    );
}

// ── the producer reconciles the manifest from the verdicts it wrote ────────────────────────────

/// `conformance:manifest-drift` over `repo` as the gate judges it (no write): PASS only when
/// `conformance/manifest.json` byte-equals a fresh render of the registry + verdicts on disk.
fn manifest_drift(repo: &Path) -> xtask::ledger::Status {
    use xtask::gates::conformance_sync::{ConformanceSyncGate, ROW_MANIFEST_DRIFT};
    let cx = xtask::ctx::Ctx::new(repo).expect("a context over the fixture");
    let verdict = xtask::gates::execute(&ConformanceSyncGate, &cx);
    verdict
        .rows
        .iter()
        .find(|r| r.id == ROW_MANIFEST_DRIFT)
        .map(|r| r.status)
        .expect("the gate owes its manifest-drift row")
}

#[test]
fn the_verdicts_the_producer_writes_rebuild_the_manifest_in_process() {
    let repo = fixture_repo("record-manifest");
    let registry = repo.join("conformance/registry.toml");
    std::fs::create_dir_all(registry.parent().unwrap()).unwrap();
    std::fs::copy(repo_root().join("conformance/registry.toml"), &registry)
        .expect("the tree's registry copies into the fixture");
    // The registry's plane floor is derived from the planes the build ships.
    let roster = repo.join("qa/construction.toml");
    std::fs::create_dir_all(roster.parent().unwrap()).unwrap();
    std::fs::copy(repo_root().join("qa/construction.toml"), &roster)
        .expect("the tree's plane roster copies into the fixture");
    let suites = xtask::gates::conformance_sync::render::parse_registry(
        &xtask::ctx::Ctx::new(&repo).expect("a context over the fixture"),
    )
    .expect("the tree's registry parses");
    let mcp = suites
        .iter()
        .find(|s| s.id == "mcp")
        .expect("mcp is a registered suite");
    let verdicts = repo.join("conformance/verdicts");

    // No manifest yet: the gate reads it as drift, so a passing reconcile below is the
    // reconcile's own work.
    write_verdict(
        &repo,
        &verdicts,
        mcp,
        &Outcome::fail("the rig judged red", "rig/report.json"),
    )
    .expect("written");
    assert_ne!(manifest_drift(&repo), xtask::ledger::Status::Pass);
    xtask::conformance_record::reconcile_manifest(&repo).expect("the manifest is written");
    assert!(repo.join("conformance/manifest.json").is_file());
    assert_eq!(manifest_drift(&repo), xtask::ledger::Status::Pass);

    // A new verdict makes the manifest stale again, and the next reconcile carries it.
    write_verdict(&repo, &verdicts, mcp, &Outcome::pass("rig/report.json")).expect("written");
    assert_ne!(manifest_drift(&repo), xtask::ledger::Status::Pass);
    xtask::conformance_record::reconcile_manifest(&repo).expect("the manifest is rewritten");
    assert_eq!(manifest_drift(&repo), xtask::ledger::Status::Pass);
    let _ = std::fs::remove_dir_all(&repo);
}

#[test]
fn the_records_own_reconciled_outputs_are_not_drift_but_any_other_tracked_edit_is() {
    let repo = fixture_repo("record-drift");
    std::fs::create_dir_all(repo.join("conformance/verdicts")).unwrap();
    std::fs::write(repo.join("conformance/manifest.json"), "{}\n").unwrap();
    std::fs::write(repo.join("README.md"), "readme\n").unwrap();
    git(&repo, &["add", "conformance/manifest.json", "README.md"]);
    git(&repo, &["commit", "-q", "-m", "manifest"]);
    let out = repo.join("conformance/verdicts");
    let drift = |r: &Path| xtask::conformance_record::tracked_drift(r, &out).expect("git status");

    // What one `conformance record --suite <id>` writes: a verdict, the reconciled manifest and
    // the README badge block. A second `--suite` run in the same checkout must still judge HEAD.
    std::fs::write(out.join("mcp.json"), "{}\n").unwrap();
    std::fs::write(repo.join("conformance/manifest.json"), "{\"suites\": []}\n").unwrap();
    std::fs::write(repo.join("README.md"), "readme, badges re-rendered\n").unwrap();
    assert_eq!(drift(&repo), Vec::<String>::new());

    // Any other tracked edit means HEAD does not name the judged tree.
    std::fs::write(repo.join("a.txt"), "two\n").unwrap();
    assert_eq!(drift(&repo), vec!["a.txt".to_string()]);
}
