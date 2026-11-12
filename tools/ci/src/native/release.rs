//! Core-only development classification; raw conformance verdicts never
//! change (former `native_release_stage`).
use super::sp::{self, Dict, R, at, need, violation};
use super::{CORE, Q, pysteps};
use crate::json::{Value, object};
use crate::sha256;
use std::path::{Path, PathBuf};

pub const MODULES: [&str; 11] = [
    "test_build_closure",
    "test_cargo_capture",
    "test_release_producer",
    "test_release_verifier",
    "test_oci_provenance",
    "test_release_monitor",
    "test_audit_verifier_packaging",
    "test_security_gate",
    "test_artifacts",
    "test_scanner_retrieval",
    "test_development_stage",
];
pub const MISSING: &str = "release-stage subject absent: ModernCI builder key or exact-source attestation delivery not supplied";

// The release-engineering input inventory shared with the website collector
// (marketing RELEASE_INPUTS) and scripts/release/development_checks.py. The two
// scripts/architecture entries are no longer executed by CI (this module and
// `native-qualify` are); they stay hashed until the collector's inventory and
// test_development_stage move to the Rust sources in one coordinated change.
const FIXED_INPUTS: [&str; 8] = [
    "scripts/release-build.sh",
    "scripts/pgo-build.sh",
    "Dockerfile",
    "release/release-targets.json",
    "scripts/architecture/native_release_stage.py",
    "scripts/architecture/native.py",
    "testing/conformance/sigstore.py",
    "testing/conformance/slsa-verifier.sh",
];

/// `stage_context(env)`: controller CI context, never candidate output.
pub fn stage_context(env: &Dict) -> Value {
    let source = env.get("CI_PIPELINE_SOURCE");
    let branch = env.get("CI_COMMIT_BRANCH");
    let target = env.get("CI_MERGE_REQUEST_TARGET_BRANCH_NAME");
    let project = env.get("CI_PROJECT_ID");
    let same_project = project.is_some_and(|p| !p.is_empty())
        && env.get("CI_MERGE_REQUEST_SOURCE_PROJECT_ID") == project;
    let development = (matches!(source, Some("push" | "api")) && branch == Some("dev"))
        || (source == Some("merge_request_event") && target == Some("dev") && same_project);
    let optional = |v: Option<&str>| v.map_or(Value::Null, Value::from);
    object([
        ("stage", if development { "dev" } else { "release" }.into()),
        ("pipeline_source", optional(source)),
        ("commit_branch", optional(branch)),
        (
            "commit_ref_protected",
            (env.get("CI_COMMIT_REF_PROTECTED") == Some("true")).into(),
        ),
        ("merge_request_target", optional(target)),
        (
            "same_project_merge_request",
            (source == Some("merge_request_event") && same_project).into(),
        ),
    ])
}

fn sha(path: &Path) -> R<String> {
    Ok(sha256::hex(&sp::read(path)?))
}

fn load(path: &Path) -> R<Value> {
    let ok = path.is_file()
        && !sp::is_symlink(path)
        && std::fs::metadata(path).is_ok_and(|m| m.len() <= 1 << 20);
    need(ok, "missing or nonregular release-stage evidence")?;
    sp::read_json(path)
}

fn zero(report: &Value, key: &str) -> bool {
    report
        .get(key)
        .is_some_and(|v| v.is_int() && v.as_int() == Some(0))
}

/// The approved release-engineering source inventory, in directory order.
fn inventory(trusted: &Path) -> R<Vec<(String, String)>> {
    let mut expected = Vec::new();
    for directory in ["scripts/release", "scripts/security"] {
        let base = trusted.join(directory);
        let Ok(entries) = std::fs::read_dir(&base) else {
            continue;
        };
        for entry in entries.filter_map(|e| e.ok()) {
            let name = entry.file_name().to_string_lossy().into_owned();
            if sp::fnmatch(&name, "*.py") {
                expected.push((format!("{directory}/{name}"), sha(&entry.path())?));
            }
        }
    }
    for name in FIXED_INPUTS {
        let digest = sha(&trusted.join(name))?;
        match expected.iter_mut().find(|(n, _)| n == name) {
            Some(row) => row.1 = digest,
            None => expected.push((name.to_owned(), digest)),
        }
    }
    Ok(expected)
}

/// `engineering(q, report_path)`.
pub fn engineering(q: &Q, report_path: &Path) -> R<Value> {
    let report = load(report_path)?;
    let modules = Value::Array(MODULES.iter().map(|m| Value::from(*m)).collect());
    let ok = report.at("schema").as_str() == Some("busbar.release-engineering/1")
        && report.at("status").as_str() == Some("pass")
        && report.get("source") == q.receipt.get("source")
        && report.get("policy_revision") == q.receipt.get("policy_revision")
        && report.at("modules") == &modules
        && report.at("tests").is_int()
        && report.at("tests").as_int().is_some_and(|t| t >= 60)
        && ["failures", "errors", "skipped"]
            .iter()
            .all(|k| zero(&report, k))
        && report.at("production_signing").as_bool() == Some(false)
        && report.at("release_attestation_verified").as_bool() == Some(false);
    need(ok, "required release engineering tests did not pass")?;
    let empty = Value::Object(Vec::new());
    let runtime = report.get("runtime").unwrap_or(&empty);
    let qualified = runtime.at("mode").as_str() == Some("protected-offline")
        && runtime.at("manifest_sha256")
            == at(
                at(&q.receipt, "conformance_inputs")?,
                "mounted_manifest_sha256",
            )?;
    need(
        qualified,
        "release engineering used unqualified instruments",
    )?;
    let expected = inventory(&q.trusted)?;
    let expected_value = Value::Object(
        expected
            .iter()
            .map(|(k, v)| (k.clone(), Value::from(v.as_str())))
            .collect(),
    );
    need(
        report.get("inputs") == Some(&expected_value),
        "release engineering source inventory differs",
    )?;
    for (name, digest) in &expected {
        if sha(&q.root.join(name))? != *digest {
            return Err(violation(format!(
                "release engineering candidate differs from approved policy: {name}"
            )));
        }
    }
    Ok(report)
}

/// `run_engineering(q, collect)`.
pub fn run_engineering(q: &mut Q) -> R<PathBuf> {
    let output = q.work.join("release-engineering");
    sp::mkdir(&output, 0o777, false)?;
    let report = output.join("result.json");
    let source = q.source();
    let policy = q
        .receipt
        .at("policy_revision")
        .as_str()
        .unwrap_or("")
        .to_owned();
    let command = pysteps::release_engineering(&q.trusted, &source, &policy, &report);
    let ran = q.run_timeout("release-engineering", command, 1800);
    let collected = (|| -> R<()> {
        if report.exists() {
            let destination = q.evidence.join("release-engineering");
            sp::mkdir(&destination, 0o777, false)?;
            q.collect_output(&report, &destination.join("result.json"), 1 << 20, false)?;
        }
        Ok(())
    })();
    collected?;
    ran?;
    let report = q.evidence.join("release-engineering/result.json");
    engineering(q, &report)?;
    q.receipt.set(
        "release_engineering",
        object([
            ("path", "release-engineering/result.json".into()),
            ("sha256", sha(&report)?.into()),
            ("required_for_stage", "dev".into()),
        ]),
    );
    Ok(report)
}

/// `classify(q, report_path)`: only unattempted QA artifact readiness may be
/// nonblocking for development.
pub fn classify(q: &mut Q, report_path: &Path) -> R<Value> {
    let context = q
        .receipt
        .get("conformance_stage")
        .cloned()
        .unwrap_or(Value::Object(Vec::new()));
    if context.at("stage").as_str() != Some("dev") {
        return Err(violation(
            "release-stage evidence cannot use development classification",
        ));
    }
    let report = engineering(q, report_path)?;
    let source = q.evidence.join("conformance");
    let invocation = load(&source.join("invocation.json"))?;
    let subject = q.receipt.at("source");
    need(
        invocation.at("repo").as_str() == Some(CORE)
            && invocation.at("commit") == subject
            && invocation.at("core_pin") == subject
            && invocation.at("exit_code").equals_int(1),
        "development classification requires complete exact-source failed invocation",
    )?;
    for name in [
        "testing/conformance/suites.tsv",
        "testing/conformance/slsa-verifier.sh",
    ] {
        if sha(&q.root.join(name))? != sha(&q.trusted.join(name))? {
            return Err(violation(
                "core release-stage controls differ from approved policy",
            ));
        }
    }
    let empty = Value::Object(Vec::new());
    let inputs = invocation.get("inputs").unwrap_or(&empty);
    let required = [
        "testing/conformance/run.sh",
        "testing/conformance/tools.sh",
        "testing/conformance/suites.tsv",
    ];
    need(
        required.iter().all(|k| inputs.get(k).is_some()),
        "conformance invocation input set is incomplete",
    )?;
    let mut suites: Vec<(String, String)> = Vec::new();
    for line in sp::read_text(&q.root.join("testing/conformance/suites.tsv"))?.lines() {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let (name, command) = line
            .split_once('\t')
            .ok_or_else(|| sp::value_error("not enough values to unpack (expected 2, got 1)"))?;
        if suites.iter().any(|(n, _)| n == name) {
            return Err(violation("duplicate core suite"));
        }
        suites.push((name.to_owned(), command.to_owned()));
    }
    need(
        suites.iter().any(|(n, _)| n == "slsa-verifier"),
        "core conformance verdict set is incomplete",
    )?;
    let verdicts = at(&invocation, "verdicts")?;
    let mut listed = verdicts.keys();
    listed.sort();
    listed.dedup();
    let mut wanted: Vec<String> = suites.iter().map(|(n, _)| format!("{n}.json")).collect();
    wanted.sort();
    need(
        listed == wanted.iter().map(String::as_str).collect::<Vec<_>>(),
        "core conformance verdict set is incomplete",
    )?;
    for (name, _) in &suites {
        let file = format!("{name}.json");
        let path = source.join("verdicts").join(&file);
        let result = load(&path)?;
        let expected = at(verdicts, &file)?;
        need(
            expected.as_str() == Some(sha(&path)?.as_str())
                && result.at("repo").as_str() == Some(CORE)
                && result.at("commit") == subject
                && result.at("core_pin") == subject,
            "core conformance subject or digest differs",
        )?;
        if name == "slsa-verifier" {
            need(
                result.at("status").as_str() == Some("not-run")
                    && result.at("armed").as_bool() == Some(false)
                    && result.at("reason").as_str() == Some(MISSING),
                "attempted or malformed provenance cannot be deferred",
            )?;
        } else if result.at("status").as_str() != Some("pass")
            || result.at("armed").as_bool() != Some(true)
        {
            return Err(violation(format!(
                "required development conformance suite did not pass: {name}"
            )));
        }
    }
    let coverage = load(&q.trusted.join("conformance/ci-coverage.json"))?;
    let rows = coverage
        .get("suites")
        .or_else(|| coverage.get("coverage"))
        .unwrap_or(&empty);
    // The current source contract places artifact attestation at QA, Sigstore at main.
    need(
        rows.at("slsa-verifier").at("stage").as_str() == Some("qa")
            && rows.at("sigstore").at("stage").as_str() == Some("main"),
        "release-stage classification differs from approved coverage",
    )?;
    for (name, expected) in inputs.as_object().into_iter().flatten() {
        let path = Path::new(name);
        if path.is_absolute()
            || path.components().any(|c| c.as_os_str() == "..")
            || expected.as_str() != Some(sha(&q.root.join(path))?.as_str())
        {
            return Err(violation("conformance invocation inputs differ"));
        }
    }
    let mut required_suites: Vec<&str> = suites
        .iter()
        .map(|(n, _)| n.as_str())
        .filter(|n| *n != "slsa-verifier")
        .collect();
    required_suites.sort();
    required_suites.dedup();
    Ok(object([
        ("schema", "busbar.development-conformance/1".into()),
        ("status", "pass".into()),
        ("stage", "dev".into()),
        ("stage_context", context),
        ("source", subject.clone()),
        ("policy_revision", q.receipt.at("policy_revision").clone()),
        (
            "coverage_sha256",
            sha(&q.trusted.join("conformance/ci-coverage.json"))?.into(),
        ),
        (
            "invocation_sha256",
            sha(&source.join("invocation.json"))?.into(),
        ),
        (
            "engineering",
            object([
                ("path", "release-engineering/result.json".into()),
                ("sha256", sha(report_path)?.into()),
                ("tests", report.at("tests").clone()),
            ]),
        ),
        (
            "required_suites",
            Value::Array(required_suites.into_iter().map(Value::from).collect()),
        ),
        (
            "release_readiness",
            object([(
                "slsa-verifier",
                object([
                    ("stage", "qa".into()),
                    ("status", "not-run".into()),
                    ("armed", false.into()),
                ]),
            )]),
        ),
        ("raw_invocation_exit_code", Value::int(1)),
        ("release_attestation_verified", false.into()),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn development_stage_comes_only_from_controller_context() {
        let mut env = Dict::default();
        env.set("CI_PIPELINE_SOURCE", "merge_request_event");
        env.set("CI_MERGE_REQUEST_TARGET_BRANCH_NAME", "dev");
        env.set("CI_PROJECT_ID", "3");
        env.set("CI_MERGE_REQUEST_SOURCE_PROJECT_ID", "3");
        let context = stage_context(&env);
        assert_eq!(
            crate::json::dumps(&context, false),
            "{\"stage\": \"dev\", \"pipeline_source\": \"merge_request_event\", \"commit_branch\": null, \"commit_ref_protected\": false, \"merge_request_target\": \"dev\", \"same_project_merge_request\": true}"
        );
        env.set("CI_MERGE_REQUEST_SOURCE_PROJECT_ID", "9");
        assert_eq!(stage_context(&env).at("stage").as_str(), Some("release"));
        let mut push = Dict::default();
        push.set("CI_PIPELINE_SOURCE", "push");
        push.set("CI_COMMIT_BRANCH", "dev");
        assert_eq!(
            stage_context(&push)
                .at("same_project_merge_request")
                .as_bool(),
            Some(false)
        );
        assert_eq!(stage_context(&push).at("stage").as_str(), Some("dev"));
    }
}
