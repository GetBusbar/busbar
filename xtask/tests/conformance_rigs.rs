//! The MUST-set rigs `cargo xtask conformance record` gained so that every registered suite has a
//! producer that can PASS a correct busbar (BUSBAR-1.6.0.md #68): a2a, h2, tls, slsa-verifier,
//! oidf-oauth2 + fapi2, and the jev rig rebuilt in Rust with a pass arm.
//!
//! What these cases pin, per decider: a correct measurement is a `pass`; every way the subject can
//! be wrong is a `fail` naming it; every way the INSTRUMENT (or the rig's own inputs) can fail is a
//! `not-run`, never a pass and never a fail charged to busbar.

use serde_json::{json, Value};
use xtask::conformance_record::{
    as_signing_key, base64_std, idp_reply, oidf_plan_config, oidf_subject_config,
    rsa_jwk_from_pkcs8, suite_client_key, OidfClient, OidfSubject, AS_KEY_ID, OIDF_RESOURCE_PATH,
};
use xtask::conformance_record::{
    b64url, decide_h2, decide_jev, decide_oidf, decide_slsa, decide_tls, discriminates, es256_jwk,
    governance_observed, is_jev_refusal, jev_battery_command, judge_jev_ledger, junit_cases,
    module_results, provenance_commit, rig_for, tests_passed, CaseResult, H2Run, JevRun, OidfRun,
    SlsaRun, Status, TlsRun, JEV_PLANE, NEGATIVE_PAIRS, OIDF_SUITES, REPORTED_UNITS,
};
use xtask::conformance_record::{voice_config_command, VOICE_PLANE};

fn registry_ids() -> Vec<String> {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask/ has a parent")
        .to_path_buf();
    let text = std::fs::read_to_string(root.join("conformance/registry.toml")).unwrap();
    text.lines()
        .filter_map(|l| l.trim().strip_prefix("id = \""))
        .map(|l| l.trim_end_matches('"').to_string())
        .collect()
}

// ── every MUST has a producer ──────────────────────────────────────────────────────────────────

#[test]
fn every_registered_suite_has_a_rig() {
    let ids = registry_ids();
    // 18: #885 (row 132, piece 6) registered `webrtc-browser`, judged by `Rig::Webrtc`.
    assert_eq!(ids.len(), 18, "the registry is the MUST set: {ids:?}");
    let orphans: Vec<&String> = ids.iter().filter(|id| rig_for(id).is_none()).collect();
    assert!(
        orphans.is_empty(),
        "registered suites with no rig: {orphans:?}"
    );
    for p in OIDF_SUITES {
        assert!(
            ids.iter().any(|i| i == p.suite),
            "{} is not registered",
            p.suite
        );
        assert!(p.arg().starts_with(p.plan) && p.arg().contains("[openid=plain_oauth]"));
    }
    assert!(rig_for("no-such-suite").is_none());
}

// ── jev ───────────────────────────────────────────────────────────────────────────────────────

fn jev_green() -> JevRun {
    let mut r = JevRun::new("target/conformance-record/jev");
    r.battery = Some(0);
    r.battery_tests = 57;
    r.build = Ok(());
    r.boot = Ok(());
    r.absent = Some(404);
    r.served = Some(200);
    r.checks = [
        "relay.request",
        "relay.credential",
        "relay.client-headers",
        "relay.response",
        "relay.error",
        "refusal.unauthenticated",
        "usage.billable-success-only",
    ]
    .iter()
    .map(|n| (n.to_string(), Ok(())))
    .collect();
    r
}

#[test]
fn a_correctly_served_decisions_plane_passes() {
    let o = decide_jev(&jev_green());
    assert_eq!(o.status, Status::Pass, "{o:?}");
    assert!(o.armed);
}

/// The decisions plane lives in its own repo (BUSBAR-1.6.0.md #68: the MUST set covers every plane
/// wherever its crate lives): its battery runs in the workspace the lock pins it at, never as `-p`
/// of this workspace, which holds no such member. RED ARM: `cargo test -p busbar-plane-decisions`
/// in this workspace exited 101 in 0s (ModernCI conformance on dev 68df8203a9).
#[test]
fn the_jev_battery_runs_in_the_pinned_planes_own_workspace() {
    let manifest = std::path::Path::new("/git/checkouts/busbar-plane-decisions/2f5a9d9/Cargo.toml");
    let cmd = jev_battery_command(manifest, std::path::Path::new("/work/target"));
    assert_eq!(
        cmd,
        [
            "cargo",
            "test",
            "--locked",
            "--manifest-path",
            "/git/checkouts/busbar-plane-decisions/2f5a9d9/Cargo.toml",
            "-p",
            JEV_PLANE,
            "--target-dir",
            "/work/target",
        ]
    );
}

/// The streaming plane lives in its own repo (row 106; BUSBAR-1.6.0.md #68: the MUST set covers
/// every plane wherever its crate lives): the voice rig's `streams:` grammar leg runs in the
/// workspace the lock pins it at, never as `-p` of this workspace, which holds no such member. RED
/// ARM: `cargo test -p busbar-plane-streaming --lib config::` in this workspace names a package it
/// does not have, and the leg exits 101.
#[test]
fn the_voice_config_leg_runs_in_the_pinned_planes_own_workspace() {
    assert_eq!(VOICE_PLANE, "busbar-plane-streaming");
    let manifest = std::path::Path::new("/git/checkouts/busbar-plane-streaming/4d88a2b/Cargo.toml");
    let cmd = voice_config_command(manifest, std::path::Path::new("/work/target"));
    assert_eq!(
        cmd,
        [
            "cargo",
            "test",
            "--locked",
            "--manifest-path",
            "/git/checkouts/busbar-plane-streaming/4d88a2b/Cargo.toml",
            "-p",
            VOICE_PLANE,
            "--lib",
            "config::",
            "--target-dir",
            "/work/target",
        ]
    );
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask/ has a parent");
    let members = std::fs::read_to_string(root.join("Cargo.toml")).expect("the root manifest");
    assert!(
        !members.contains("\"crates/busbar-plane-streaming\""),
        "RED ARM: the plane is a workspace member again, and `-p` would find it here"
    );
}

#[test]
fn every_jev_red_is_named_and_none_is_a_pass() {
    let mut r = jev_green();
    r.battery = Some(101);
    assert_eq!(decide_jev(&r).status, Status::Fail);

    let mut r = jev_green();
    r.battery_tests = 0;
    let o = decide_jev(&r);
    assert_eq!(o.status, Status::Fail);
    assert!(o.reason.unwrap().contains("0 tests"));

    let mut r = jev_green();
    r.build = Err("cargo build exited 101".into());
    assert_eq!(decide_jev(&r).status, Status::NotRun);

    let mut r = jev_green();
    r.boot = Err("exited during boot".into());
    assert_eq!(decide_jev(&r).status, Status::Fail);

    let mut r = jev_green();
    r.served = Some(404);
    let o = decide_jev(&r);
    assert_eq!(o.status, Status::Fail);
    assert!(o.reason.unwrap().starts_with("not served"));

    // Absence is measured, not assumed: a 401 boot that answers 401 is not served either.
    let mut r = jev_green();
    r.absent = Some(401);
    r.served = Some(401);
    assert!(decide_jev(&r).reason.unwrap().starts_with("not served"));

    let mut r = jev_green();
    r.absent = None;
    assert_eq!(decide_jev(&r).status, Status::Fail);

    let mut r = jev_green();
    r.checks.clear();
    assert_eq!(decide_jev(&r).status, Status::Fail);

    let mut r = jev_green();
    r.checks[0].1 = Err("the far end received `{}`".into());
    let o = decide_jev(&r);
    assert_eq!(o.status, Status::Fail);
    assert!(o.reason.unwrap().contains("relay.request"));

    // Nothing measured is never a pass.
    assert_ne!(decide_jev(&JevRun::new("e")).status, Status::Pass);
}

#[test]
fn the_battery_counter_reads_cargos_summary_lines() {
    assert_eq!(tests_passed("test result: ok. 0 passed; 0 failed"), 0);
    assert_eq!(
        tests_passed(
            "test result: ok. 3 passed; 0 failed\nfoo\ntest result: ok. 2 passed; 0 failed"
        ),
        5
    );
    assert_eq!(tests_passed("test result: FAILED. 3 passed; 1 failed"), 0);
}

#[test]
fn the_jev_refusal_shape_is_exactly_code_and_message() {
    let good = br#"{"error":{"code":"invalid_request","message":"the request did not carry usable authority"}}"#;
    assert!(is_jev_refusal(good, "invalid_request").is_ok());
    assert!(is_jev_refusal(good, "internal").is_err());
    // The kernel's unclaimed-route body is NOT jev's shape.
    let not_found = br#"{"error":{"code":null,"message":"the requested resource was not found","param":null,"type":"not_found_error"}}"#;
    assert!(is_jev_refusal(not_found, "invalid_request").is_err());
    assert!(is_jev_refusal(
        br#"{"error":{"code":"invalid_request","message":""}}"#,
        "invalid_request"
    )
    .is_err());
    assert!(is_jev_refusal(
        br#"{"error":{"code":"invalid_request","message":"x"},"extra":1}"#,
        "invalid_request"
    )
    .is_err());
    assert!(is_jev_refusal(b"not json", "invalid_request").is_err());
}

fn totals(rows: &[(&str, &str, u64, &str)]) -> Vec<u8> {
    bucketed(
        &rows
            .iter()
            .map(|&(l, p, f, m)| ("k", l, p, f, m))
            .collect::<Vec<_>>(),
    )
}

fn bucketed(rows: &[(&str, &str, &str, u64, &str)]) -> Vec<u8> {
    json!({"rows": rows.iter().map(|(bucket, lane, provider, fees, micros)| json!({
        "bucket": bucket, "day": 0, "lane": lane, "provider": provider,
        "fee_count": fees, "priced_nanos": "0", "priced_micros": micros,
    })).collect::<Vec<_>>()})
    .to_string()
    .into_bytes()
}

#[test]
fn the_jev_ledger_shows_one_fee_carrying_the_reported_units() {
    assert_eq!(REPORTED_UNITS, 42);
    // One billable success at 42 units; another lane's rows are not read.
    assert!(judge_jev_ledger(
        &totals(&[("jev-1", "typesafe", 1, "42"), ("gpt", "openai", 9, "100")]),
        "vk_caller"
    )
    .is_ok());
    // The 422 billed too.
    assert!(judge_jev_ledger(&totals(&[("jev-1", "typesafe", 2, "42")]), "vk_caller").is_err());
    // A fee with no units: the reported usage did not reach the ledger.
    assert!(judge_jev_ledger(&totals(&[("jev-1", "typesafe", 1, "0")]), "vk_caller").is_err());
    // Nothing billed at all.
    assert!(judge_jev_ledger(&totals(&[]), "vk_caller").is_err());
    assert!(judge_jev_ledger(b"{}", "vk_caller").is_err());
}

/// AT THE WIDTH THE 1.6.0 NODE KEEPS (no lane, no provider: every row a bucket-day), the jev lane's
/// figures are the rig's caller's own bucket; another caller's row is never read.
#[test]
fn at_the_node_width_the_jev_ledger_is_the_callers_bucket() {
    assert!(judge_jev_ledger(
        &bucketed(&[
            ("vk_caller", "", "", 1, "42"),
            ("vk_other", "", "", 7, "900")
        ]),
        "vk_caller"
    )
    .is_ok());
    // RED ARMS: another caller's figures are not the jev lane's, and the caller's own still judge.
    assert!(judge_jev_ledger(&bucketed(&[("vk_other", "", "", 1, "42")]), "vk_caller").is_err());
    assert!(judge_jev_ledger(&bucketed(&[("vk_caller", "", "", 0, "42")]), "vk_caller").is_err());
    assert!(judge_jev_ledger(&bucketed(&[("vk_caller", "", "", 1, "41")]), "vk_caller").is_err());
}

/// THE MODEL-RESOLUTION BOOT (THE DESIGN §2, the decisions bullet): two models, the second with an
/// `upstream_model`, each priced.
#[test]
fn the_models_subject_configures_two_models_one_with_an_upstream_model() {
    use xtask::conformance_record::{jev_models_config, UPSTREAM_MODEL, UPSTREAM_NAME};
    let text = jev_models_config(41000, 41001, std::path::Path::new("/tmp/signing.key"));
    let doc: serde_yaml::Value = serde_yaml::from_str(&text).expect("the config is YAML");
    let models = &doc["decisions"]["models"];
    assert_eq!(models["jev-1"]["provider"].as_str(), Some("typesafe"));
    assert!(models["jev-1"]["upstream_model"].is_null());
    assert_eq!(
        models[UPSTREAM_MODEL]["upstream_model"].as_str(),
        Some(UPSTREAM_NAME)
    );
    for m in ["jev-1", UPSTREAM_MODEL] {
        assert_eq!(
            doc["decisions"]["rate_card"][m]["units"]["decision"].as_u64(),
            Some(1),
            "{m}"
        );
    }
    // THE DESIGN §7: the card prices `decision`, `input_tokens` and `output_tokens`, all three
    // required (0 = free), on both subjects.
    let main = xtask::conformance_record::jev_subject_config(
        41000,
        41001,
        std::path::Path::new("/tmp/signing.key"),
    );
    let main: serde_yaml::Value = serde_yaml::from_str(&main).expect("the config is YAML");
    for (doc, m) in [(&doc, "jev-1"), (&doc, UPSTREAM_MODEL), (&main, "jev-1")] {
        for class in ["input_tokens", "output_tokens"] {
            assert_eq!(
                doc["decisions"]["rate_card"][m]["units"][class].as_u64(),
                Some(0),
                "{m} {class}"
            );
        }
    }
    assert_eq!(doc["store"]["module"].as_str(), Some("memory"));
}

fn call(status: u16, body: &[u8], hops: usize) -> xtask::conformance_record::Call {
    xtask::conformance_record::Call {
        status,
        body: body.to_vec(),
        hops,
    }
}

/// `models.unnamed-400` / `models.unknown-404`: the status in jev's shape, before any hop.
#[test]
fn an_unrouted_request_is_refused_in_jev_shape_before_any_hop() {
    use xtask::conformance_record::judge_unrouted;
    let bad = br#"{"error":{"code":"invalid_request","message":"name one"}}"#;
    assert!(judge_unrouted(&call(400, bad, 0), 400, "invalid_request").is_ok());
    // RED ARMS: another status, a hop, another shape.
    assert!(judge_unrouted(&call(404, bad, 0), 400, "invalid_request").is_err());
    assert!(judge_unrouted(&call(400, bad, 1), 400, "invalid_request").is_err());
    assert!(judge_unrouted(&call(400, b"{}", 0), 400, "invalid_request").is_err());
}

/// `models.upstream-model`: served, and the far end saw the top-level `model` value alone spliced.
#[test]
fn the_upstream_model_is_spliced_into_what_the_far_end_receives() {
    use xtask::conformance_record::{
        judge_upstream_model, models_request, JEV_SUCCESS, UPSTREAM_MODEL, UPSTREAM_NAME,
    };
    let sent = models_request(Some(UPSTREAM_MODEL));
    let spliced = String::from_utf8(sent.clone())
        .unwrap()
        .replace(UPSTREAM_MODEL, UPSTREAM_NAME);
    let ok = call(200, JEV_SUCCESS, 1);
    assert!(judge_upstream_model(&ok, &sent, spliced.as_bytes()).is_ok());
    // RED ARMS: the caller's own name relayed, the far end not reached, another answer.
    assert!(judge_upstream_model(&ok, &sent, &sent).is_err());
    assert!(judge_upstream_model(&call(200, JEV_SUCCESS, 0), &sent, spliced.as_bytes()).is_err());
    assert!(judge_upstream_model(&call(400, b"{}", 1), &sent, spliced.as_bytes()).is_err());
    // The unnamed request names no model.
    assert!(!String::from_utf8(models_request(None))
        .unwrap()
        .contains("\"model\""));
}

/// THE `nanojev` BOOT (THE DESIGN §2, the decisions bullet): a NanoJev model on a `nanojev`
/// provider beside the jev one, each priced.
#[test]
fn the_nanojev_subject_configures_a_nanojev_provider_and_model() {
    use xtask::conformance_record::{
        jev_nanojev_config, nanojev_providers, NANOJEV_MODEL, NANOJEV_PROVIDER,
    };
    let text = jev_nanojev_config(41000, 41001, std::path::Path::new("/tmp/signing.key"));
    let doc: serde_yaml::Value = serde_yaml::from_str(&text).expect("the config is YAML");
    assert_eq!(
        doc["decisions"]["models"][NANOJEV_MODEL]["provider"].as_str(),
        Some(NANOJEV_PROVIDER)
    );
    assert_eq!(
        doc["decisions"]["models"]["jev-1"]["provider"].as_str(),
        Some("typesafe")
    );
    assert!(!doc["providers"][NANOJEV_PROVIDER].is_null());
    for m in ["jev-1", NANOJEV_MODEL] {
        assert_eq!(
            doc["decisions"]["rate_card"][m]["units"]["decision"].as_u64(),
            Some(1),
            "{m}"
        );
    }
    let providers: serde_yaml::Value =
        serde_yaml::from_str(&nanojev_providers(9)).expect("the providers are YAML");
    assert_eq!(
        providers[NANOJEV_PROVIDER]["protocol"].as_str(),
        Some("nanojev")
    );
    assert_eq!(providers["typesafe"]["protocol"].as_str(), Some("jev"));
}

/// `nanojev.served` and `nanojev.no-count-refused`.
#[test]
fn a_nanojev_unit_is_served_at_evaluate_and_a_missing_count_refused() {
    use xtask::conformance_record::{
        judge_nanojev_no_count, judge_nanojev_served, NANOJEV_NO_COUNT, NANOJEV_REQUEST,
        NANOJEV_SUCCESS, PATH_EVALUATE,
    };
    let ok = call(200, NANOJEV_SUCCESS, 1);
    assert!(judge_nanojev_served(&ok, PATH_EVALUATE, NANOJEV_REQUEST).is_ok());
    // RED ARMS: another path, other bytes, another answer, no dial.
    assert!(judge_nanojev_served(&ok, "/v1/systemone", NANOJEV_REQUEST).is_err());
    assert!(judge_nanojev_served(&ok, PATH_EVALUATE, b"{}").is_err());
    assert!(judge_nanojev_served(&call(200, b"{}", 1), PATH_EVALUATE, NANOJEV_REQUEST).is_err());
    assert!(judge_nanojev_served(
        &call(200, NANOJEV_SUCCESS, 0),
        PATH_EVALUATE,
        NANOJEV_REQUEST
    )
    .is_err());

    let refused = br#"{"error":{"code":"internal","message":"plane fault"}}"#;
    assert!(judge_nanojev_no_count(&call(502, refused, 1)).is_ok());
    // RED ARMS: the far end's bytes relayed, a success, an extra dial, another shape.
    assert!(judge_nanojev_no_count(&call(200, NANOJEV_NO_COUNT, 1)).is_err());
    assert!(judge_nanojev_no_count(&call(502, NANOJEV_NO_COUNT, 1)).is_err());
    assert!(judge_nanojev_no_count(&call(502, refused, 2)).is_err());
    assert!(judge_nanojev_no_count(&call(502, b"oops", 1)).is_err());
}

// ── a2a ───────────────────────────────────────────────────────────────────────────────────────

fn report(rows: &[(&str, &str)]) -> String {
    json!({"results": rows.iter().map(|(i, o)| json!({"id": i, "outcome": o})).collect::<Vec<_>>()})
        .to_string()
}

#[test]
fn the_negative_control_must_discriminate_every_injected_violation() {
    let broken = report(
        &NEGATIVE_PAIRS
            .iter()
            .map(|(i, _)| (*i, "FAIL"))
            .collect::<Vec<_>>(),
    );
    let honest = report(
        &NEGATIVE_PAIRS
            .iter()
            .map(|(i, _)| (*i, "PASS"))
            .collect::<Vec<_>>(),
    );
    assert!(discriminates(Some(1), Some(1), Some(&broken), Some(&honest)).is_ok());
    // A battery that blesses the broken peer, or never reaches it, proves nothing.
    assert!(discriminates(Some(0), Some(1), Some(&broken), Some(&honest)).is_err());
    assert!(discriminates(Some(3), Some(1), Some(&broken), Some(&honest)).is_err());
    assert!(discriminates(Some(1), Some(3), Some(&broken), Some(&honest)).is_err());
    // A test red against both peers is not detecting its violation.
    assert!(discriminates(Some(1), Some(1), Some(&broken), Some(&broken)).is_err());
    // A violation whose test is absent is not discriminated.
    let partial = report(&[(NEGATIVE_PAIRS[0].0, "FAIL")]);
    assert!(discriminates(Some(1), Some(1), Some(&partial), Some(&honest)).is_err());
    assert!(discriminates(Some(1), Some(1), None, Some(&honest)).is_err());
}

#[test]
fn the_governance_probe_must_observe_and_disclaim() {
    let ok = json!({"results": [1, 2, 3], "meta": {"not_a_conformance_result": true}}).to_string();
    assert!(governance_observed(Some(&ok)).is_ok());
    let few = json!({"results": [1], "meta": {"not_a_conformance_result": true}}).to_string();
    assert!(governance_observed(Some(&few)).is_err());
    let claims = json!({"results": [1, 2, 3], "meta": {}}).to_string();
    assert!(governance_observed(Some(&claims)).is_err());
    assert!(governance_observed(None).is_err());
}

// ── h2 ────────────────────────────────────────────────────────────────────────────────────────

const JUNIT_GREEN: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<testsuites>
  <testsuite name="3.5. HTTP/2 Connection Preface" package="http2/3.5" id="3.5" tests="2" skipped="0" failures="0" errors="0">
    <testcase package="http2/3.5" classname="Sends client connection preface" time="0.0010"></testcase>
    <testcase package="http2/3.5" classname="Sends invalid connection preface" time="0.0010"/>
  </testsuite>
</testsuites>"#;

fn h2(report: Option<&str>, exit: Option<i32>) -> H2Run {
    H2Run {
        subject: Ok(()),
        boot_failed: false,
        exit,
        report: report.map(str::to_string),
        evidence: "h2spec.xml".into(),
    }
}

#[test]
fn h2spec_cases_are_read_one_by_one() {
    let cases = junit_cases(JUNIT_GREEN);
    assert_eq!(cases.len(), 2);
    assert!(cases.iter().all(|c| c.result == CaseResult::Passed));
    assert_eq!(cases[0].name, "http2/3.5 Sends client connection preface");
    let red = JUNIT_GREEN.replace(
        r#"time="0.0010"></testcase>"#,
        r#"time="0.0010"><failure>Expected GOAWAY</failure></testcase>"#,
    );
    assert_eq!(junit_cases(&red)[0].result, CaseResult::Failed);
    let skipped = JUNIT_GREEN.replace(
        r#"time="0.0010"></testcase>"#,
        r#"time="0.0010"><skipped/></testcase>"#,
    );
    assert_eq!(junit_cases(&skipped)[0].result, CaseResult::Skipped);
    assert_eq!(junit_cases(&skipped)[1].result, CaseResult::Passed);
}

#[test]
fn h2_passes_only_when_every_case_passed() {
    assert_eq!(
        decide_h2(&h2(Some(JUNIT_GREEN), Some(0))).status,
        Status::Pass
    );
    let red = JUNIT_GREEN.replace("></testcase>", "><failure>x</failure></testcase>");
    assert_eq!(decide_h2(&h2(Some(&red), Some(1))).status, Status::Fail);
    // A skipped requirement is an unchecked requirement.
    let skipped = JUNIT_GREEN.replace("></testcase>", "><skipped/></testcase>");
    assert_eq!(decide_h2(&h2(Some(&skipped), Some(0))).status, Status::Fail);
    // An unattributed red is no pass.
    assert_eq!(
        decide_h2(&h2(Some(JUNIT_GREEN), Some(1))).status,
        Status::Fail
    );
    assert_eq!(decide_h2(&h2(None, Some(1))).status, Status::NotRun);
    assert_eq!(
        decide_h2(&h2(Some("<testsuites/>"), Some(0))).status,
        Status::NotRun
    );
    let mut r = h2(None, None);
    r.subject = Err("no binary".into());
    assert_eq!(decide_h2(&r).status, Status::NotRun);
    r.boot_failed = true;
    assert_eq!(decide_h2(&r).status, Status::Fail);
}

// ── tls ───────────────────────────────────────────────────────────────────────────────────────

fn tls(rows: Value) -> TlsRun {
    TlsRun {
        subject: Ok(()),
        boot_failed: false,
        exit: Some(0),
        report: Some(rows.to_string()),
        evidence: "testssl.json".into(),
    }
}

fn row(id: &str, severity: &str, finding: &str) -> Value {
    json!({"id": id, "ip": "localhost/127.0.0.1", "port": "443", "severity": severity, "finding": finding})
}

#[test]
fn tls_passes_on_an_a_with_nothing_severe() {
    let green = json!([
        row("TLS1_3", "OK", "offered"),
        row("overall_grade", "OK", "A+")
    ]);
    assert_eq!(decide_tls(&tls(green)).status, Status::Pass);
    let a = json!([row("overall_grade", "OK", "A")]);
    assert_eq!(decide_tls(&tls(a)).status, Status::Pass);
}

#[test]
fn tls_reds_name_the_grade_and_the_findings() {
    let b = json!([
        row("overall_grade", "MEDIUM", "B"),
        row(
            "grade_cap_reason_1",
            "INFO",
            "Grade capped to B. TLS 1.1 offered"
        )
    ]);
    let o = decide_tls(&tls(b));
    assert_eq!(o.status, Status::Fail);
    assert!(o.reason.unwrap().contains("TLS 1.1 offered"));
    let severe = json!([
        row("overall_grade", "OK", "A"),
        row("heartbleed", "CRITICAL", "VULNERABLE")
    ]);
    assert_eq!(decide_tls(&tls(severe)).status, Status::Fail);
    // The instrument failing is not busbar failing.
    let fatal = json!([row("scanProblem", "FATAL", "can't connect")]);
    assert_eq!(decide_tls(&tls(fatal)).status, Status::NotRun);
    assert_eq!(
        decide_tls(&tls(json!([row("TLS1_3", "OK", "offered")]))).status,
        Status::NotRun
    );
    let mut none = tls(json!([]));
    none.report = None;
    assert_eq!(decide_tls(&none).status, Status::NotRun);
}

// ── slsa-verifier ─────────────────────────────────────────────────────────────────────────────

const HEAD: &str = "0123456789abcdef0123456789abcdef01234567";

fn statement_v1(commit: &str) -> String {
    json!({"_type": "https://in-toto.io/Statement/v1", "predicate": {"buildDefinition": {
        "resolvedDependencies": [{"uri": "git+https://github.com/GetBusbar/busbar@refs/heads/predev",
                                  "digest": {"gitCommit": commit}}]}}})
    .to_string()
}

fn slsa(exit: Option<i32>, output: String) -> SlsaRun {
    SlsaRun {
        inputs: Ok(()),
        exit,
        output,
        head: HEAD.into(),
        evidence: "verify.log".into(),
    }
}

#[test]
fn slsa_passes_only_a_verified_provenance_of_head() {
    let ok = format!("{}\nPASSED: SLSA verification passed\n", statement_v1(HEAD));
    assert_eq!(decide_slsa(&slsa(Some(0), ok)).status, Status::Pass);
    let other = format!(
        "{}\nPASSED\n",
        statement_v1("ffffffffffffffffffffffffffffffffffffffff")
    );
    let o = decide_slsa(&slsa(Some(0), other));
    assert_eq!(o.status, Status::Fail);
    assert!(o.reason.unwrap().contains("not HEAD"));
    assert_eq!(
        decide_slsa(&slsa(Some(1), "FAILED: invalid signature".into())).status,
        Status::Fail
    );
    assert_eq!(
        decide_slsa(&slsa(Some(0), "PASSED".into())).status,
        Status::Fail
    );
    assert_eq!(
        decide_slsa(&slsa(None, String::new())).status,
        Status::NotRun
    );
    let mut none = slsa(None, String::new());
    none.inputs = Err("no attested artifact".into());
    assert_eq!(decide_slsa(&none).status, Status::NotRun);
}

#[test]
fn the_provenance_commit_is_read_from_both_slsa_shapes() {
    let v1: Value = serde_json::from_str(&statement_v1(HEAD)).unwrap();
    assert_eq!(provenance_commit(&v1).as_deref(), Some(HEAD));
    let v02 = json!({"predicate": {"invocation": {"configSource": {"digest": {"sha1": HEAD}}}}});
    assert_eq!(provenance_commit(&v02).as_deref(), Some(HEAD));
    assert_eq!(provenance_commit(&json!({"predicate": {}})), None);
}

// ── oidf-oauth2 + fapi2 ───────────────────────────────────────────────────────────────────────

fn oidf(log: &str, exit: Option<i32>) -> OidfRun {
    OidfRun {
        instrument: Ok(()),
        subject: Ok(()),
        boot_failed: false,
        exit,
        log: log.into(),
        evidence: "oidf".into(),
    }
}

const OIDF_LOG: &str = "\
3 modules to test:
  [1:1] fapi2-security-profile-final-happy-flow
  [1:2] fapi2-security-profile-final-ensure-redirect-uri-in-authorization-request
  [1:3] fapi2-security-profile-final-refresh-token

Test [1:1] fapi2-security-profile-final-happy-flow abc123 FINISHED - result \u{1b}[32mPASSED\u{1b}[0m. 120 log entries - 100 SUCCESS 0 FAILURE, 0 WARNING, 12.3 seconds
Test [1:2] fapi2-security-profile-final-ensure-redirect-uri-in-authorization-request def456 FINISHED - result REVIEW. 40 log entries - 30 SUCCESS 0 FAILURE, 0 WARNING, 4.0 seconds
Test [1:3] fapi2-security-profile-final-refresh-token ghi789 FINISHED - result WARNING. 50 log entries - 40 SUCCESS 0 FAILURE, 1 WARNING, 5.0 seconds";

#[test]
fn oidf_module_results_are_read_from_the_runner_summary() {
    let r = module_results(OIDF_LOG);
    assert_eq!(r.len(), 3);
    assert_eq!(
        r[0],
        (
            "fapi2-security-profile-final-happy-flow".into(),
            "FINISHED".into(),
            "PASSED".into()
        )
    );
    assert_eq!(r[1].2, "REVIEW");
}

#[test]
fn oidf_passes_only_when_every_module_finished_without_failure() {
    assert_eq!(decide_oidf(&oidf(OIDF_LOG, Some(0))).status, Status::Pass);
    let failed = format!(
        "{OIDF_LOG}\nTest [1:4] fapi2-security-profile-final-dpop-negative-tests jkl FINISHED - result FAILED. 9 log entries - 1 SUCCESS 1 FAILURE, 0 WARNING, 1.0 seconds"
    );
    let o = decide_oidf(&oidf(&failed, Some(1)));
    assert_eq!(o.status, Status::Fail);
    assert!(o.reason.unwrap().contains("dpop-negative-tests"));
    let interrupted = OIDF_LOG.replace("abc123 FINISHED", "abc123 INTERRUPTED");
    assert_eq!(
        decide_oidf(&oidf(&interrupted, Some(1))).status,
        Status::Fail
    );
    let skipped = OIDF_LOG.replace("result WARNING", "result SKIPPED");
    assert_eq!(decide_oidf(&oidf(&skipped, Some(0))).status, Status::Fail);
    assert_eq!(
        decide_oidf(&oidf("Failed to create plan", Some(1))).status,
        Status::NotRun
    );
    let mut down = oidf(OIDF_LOG, Some(0));
    down.instrument = Err("compose up failed".into());
    assert_eq!(decide_oidf(&down).status, Status::NotRun);
    let mut refused = oidf("", None);
    refused.subject = Err("the subject refused the plan's client registration".into());
    refused.boot_failed = true;
    assert_eq!(decide_oidf(&refused).status, Status::Fail);
}

/// The plan's own module list (`N modules to test:`) is the denominator, and the runner's exit is
/// its own verdict: a green set of parsed lines is no pass when either disagrees.
#[test]
fn oidf_holds_the_parsed_modules_to_the_plan_and_the_runners_exit() {
    // Every listed module PASSED, but the runner exited 1: an unattributed red is no pass.
    let all_passed = OIDF_LOG
        .replace("result REVIEW", "result PASSED")
        .replace("result WARNING", "result PASSED");
    assert_eq!(
        decide_oidf(&oidf(&all_passed, Some(0))).status,
        Status::Pass
    );
    let o = decide_oidf(&oidf(&all_passed, Some(1)));
    assert_eq!(o.status, Status::Fail, "{o:?}");
    assert!(o.reason.unwrap().contains("exit 1"));
    assert_ne!(decide_oidf(&oidf(&all_passed, None)).status, Status::Pass);

    // The plan owns four modules; three printed a result and the fourth `did not run`.
    let short = all_passed.replace("3 modules to test:", "4 modules to test:").replace(
        "  [1:3] fapi2-security-profile-final-refresh-token\n",
        "  [1:3] fapi2-security-profile-final-refresh-token\n  [1:4] fapi2-security-profile-final-par-attempt-reuse-request_uri\n",
    ) + "\nTest [1:4] fapi2-security-profile-final-par-attempt-reuse-request_uri did not run";
    let o = decide_oidf(&oidf(&short, Some(0)));
    assert_eq!(o.status, Status::Fail, "{o:?}");
    let why = o.reason.unwrap();
    assert!(why.contains("par-attempt-reuse-request_uri"), "{why}");

    // The same short run with the unread line gone: three results for a four-module plan.
    let silent = short.replace(
        "\nTest [1:4] fapi2-security-profile-final-par-attempt-reuse-request_uri did not run",
        "",
    );
    let o = decide_oidf(&oidf(&silent, Some(0)));
    assert_eq!(o.status, Status::Fail, "{o:?}");
    assert!(o.reason.unwrap().contains("3 of the plan's 4"));

    // No module list at all: the denominator is unknown, so nothing is judged.
    let unlisted: String = all_passed
        .lines()
        .filter(|l| l.starts_with("Test ["))
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(
        decide_oidf(&oidf(&unlisted, Some(0))).status,
        Status::NotRun
    );
}

#[test]
fn the_plan_clients_get_real_p256_jwks() {
    let (private, public) = es256_jwk("k1").unwrap();
    assert_eq!(public["kty"], "EC");
    assert_eq!(public["crv"], "P-256");
    assert!(public.get("d").is_none());
    for k in ["x", "y", "d"] {
        let v = if k == "d" { &private[k] } else { &public[k] };
        assert_eq!(
            v.as_str().unwrap().len(),
            43,
            "{k} is a 32-byte base64url member"
        );
    }
    let (other, _) = es256_jwk("k2").unwrap();
    assert_ne!(private["d"], other["d"]);
}

#[test]
fn base64url_is_rfc4648_section_5_unpadded() {
    assert_eq!(b64url(b""), "");
    assert_eq!(b64url(b"f"), "Zg");
    assert_eq!(b64url(b"fo"), "Zm8");
    assert_eq!(b64url(b"foo"), "Zm9v");
    assert_eq!(b64url(b"foob"), "Zm9vYg");
    assert_eq!(b64url(&[0xfb, 0xff]), "-_8");
}

// ── oidf subject and plan (ARCHITECT FAPI2 rulings 2026-10-02) ───────────────────────────────

fn oidf_clients() -> Vec<OidfClient> {
    (1..=2)
        .map(|n| {
            let (private, public) = suite_client_key(n).unwrap();
            OidfClient::new(
                n,
                "https://localhost.emobix.co.uk:8443/test/a/x/callback",
                private,
                public,
            )
        })
        .collect()
}

/// The subject runs the FAPI 2.0 posture, provisions the plan's two clients by config with their
/// PUBLIC keys only (client2 on the query-carrying redirect URI the happy flow's second leg sends),
/// and puts its token-requiring resource behind an IdP that trusts this AS's JWKS.
#[test]
fn the_oidf_subject_is_the_fapi2_posture_with_static_clients() {
    let clients = oidf_clients();
    let cfg = oidf_subject_config(
        &OidfSubject {
            issuer: "https://h:1",
            base: "BASE\n",
            cert: "/c.pem",
            key: "/k.pem",
            ca_pem: "PEM",
            plugins: "/plugins",
            as_key_file: "/as.key",
            jwks_url: "https://127.0.0.1:9/jwks",
        },
        &clients,
    );
    let doc: serde_json::Value =
        serde_yaml::from_str(&cfg.replacen("BASE\n", "", 1)).expect("the subject config is YAML");
    assert_eq!(doc["oauth_as"]["fapi2"], serde_json::json!(true));
    let declared = doc["oauth_as"]["clients"].as_array().expect("clients");
    assert_eq!(declared.len(), 2);
    for (c, d) in clients.iter().zip(declared) {
        assert_eq!(d["client_id"], serde_json::json!(c.id));
        assert!(
            d["jwks"]["keys"][0].get("d").is_none(),
            "public halves only: {d}"
        );
    }
    assert!(declared[1]["redirect_uris"][0]
        .as_str()
        .unwrap()
        .ends_with("?dummy1=lorem&dummy2=ipsum"));
    assert_eq!(doc["auth"]["chain"], serde_json::json!(["fapi-as"]));
    assert_eq!(doc["auth"]["admin_auth"], serde_json::json!([]));
    assert_eq!(doc["identity-providers"]["fapi-as"]["module"], "oidc");
    // The module is the dropped-in plugin (no shipped binary links it), loaded from the rig's own
    // unsigned tarball, and its JWKS destination is declared the way an operator declares one.
    assert_eq!(doc["plugins"]["dir"], "/plugins");
    assert_eq!(
        doc["plugins"]["trust"]["allow_unsigned"],
        serde_json::json!(true)
    );
    assert_eq!(
        doc["advanced"]["allow_destinations"],
        serde_json::json!(["127.0.0.1"])
    );
    assert_eq!(
        declared[0]["jwks"]["keys"][0]["kty"], "RSA",
        "the suite's clients are PS256 so the RS256 refusal module runs"
    );
    // The JWKS comes from the rig's IdP stub on its OWN port (DEST-GUARD keeps the node's own ports
    // off-limits), and it is the JWKS of the signing key the rig hands the AS.
    assert_eq!(
        doc["identity-providers"]["fapi-as"]["settings"]["jwks_url"],
        "https://127.0.0.1:9/jwks"
    );
    assert_eq!(
        doc["oauth_as"]["signing_key"],
        serde_json::json!({ "file": "/as.key" })
    );
    assert_eq!(doc["oauth_as"]["key_id"], serde_json::json!(AS_KEY_ID));
}

/// The two suite clients hold DISTINCT PS256 keys (a module signs one client's assertion with the
/// other's key and expects a refusal), pinned so the runner needs no key-generation tool.
#[test]
fn the_suite_clients_hold_two_distinct_pinned_ps256_keys() {
    let (one_private, one) = suite_client_key(1).unwrap();
    let (_, two) = suite_client_key(2).unwrap();
    assert_eq!(one["kty"], "RSA");
    assert_eq!(one["alg"], "PS256");
    assert_ne!(one["n"], two["n"], "two clients, two keys");
    assert!(one.get("d").is_none() && one_private.get("d").is_some());
    assert!(suite_client_key(3).is_err());
}

/// The AS signing key the rig mints and the JWKS its IdP stub serves describe ONE key.
#[test]
fn the_as_signing_key_and_its_jwks_agree() {
    use ring::signature::KeyPair as _;
    let (der, jwks) = as_signing_key().unwrap();
    let pair = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        &der,
        &ring::rand::SystemRandom::new(),
    )
    .unwrap();
    let point = pair.public_key().as_ref();
    let key = &jwks["keys"][0];
    assert_eq!(key["kid"], serde_json::json!(AS_KEY_ID));
    assert_eq!(key["x"], serde_json::json!(b64url(&point[1..33])));
    assert_eq!(key["y"], serde_json::json!(b64url(&point[33..65])));
}

/// busbar reads `oauth_as.signing_key` as STANDARD (padded, `+/`) base64, RFC 4648 s4.
#[test]
fn base64_std_is_rfc4648_section_4_padded() {
    assert_eq!(base64_std(b""), "");
    assert_eq!(base64_std(b"f"), "Zg==");
    assert_eq!(base64_std(b"fo"), "Zm8=");
    assert_eq!(base64_std(b"foo"), "Zm9v");
    assert_eq!(base64_std(&[0xfb, 0xff]), "+/8=");
}

/// The IdP stub answers `/jwks` with the key set and nothing else.
#[test]
fn the_idp_stub_serves_only_the_jwks() {
    assert_eq!(
        idp_reply("/jwks", "{\"keys\":[]}"),
        (200, "{\"keys\":[]}".to_string())
    );
    assert_eq!(idp_reply("/other", "{}").0, 404);
}

/// The plan config: the two static clients with their PRIVATE keys, the token-requiring resource,
/// browser tasks that click by id and fill the error-page placeholder, and the two per-module
/// overrides (deny for user-rejects; approve only on the repeat showing for the reused request_uri).
#[test]
fn the_oidf_plan_config_drives_the_consent_screen_by_id() {
    let clients = oidf_clients();
    let plan = oidf_plan_config("https://h:1", "busbar test", &clients);
    assert_eq!(
        plan["client"]["client_id"],
        serde_json::json!(clients[0].id)
    );
    assert!(plan["client2"]["jwks"]["keys"][0].get("d").is_some());
    assert_eq!(
        plan["resource"]["resourceUrl"],
        serde_json::json!(format!("https://h:1{OIDF_RESOURCE_PATH}"))
    );
    let text = plan.to_string();
    assert!(text.contains("Authorization error") && text.contains("update-image-placeholder"));
    assert!(text.contains(r#"["click","id","approve"]"#), "{text}");
    let over = &plan["override"];
    assert!(
        over["fapi2-security-profile-final-user-rejects-authentication"]
            .to_string()
            .contains(r#"["click","id","deny"]"#)
    );
    assert!(over["fapi2-security-profile-final-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds"]
        .to_string()
        .contains("revisit"));
}

/// TEST-ONLY RSA-2048 PKCS#8 DER (hex), minted once with `openssl genpkey`; it signs nothing.
const RSA_FIXTURE_HEX: &str = concat!(
    "308204bd020100300d06092a864886f70d0101010500048204a7308204a30201000282010100bbc981a6e415055b27bb",
    "93a54a272496ce84529c37fe26ebf87bf605ee37ac5bce8ba6aa50eca2e1045e2858c62d28f2bd6a27d0374dc6ff3bfd",
    "39d43672e30bb616d5a77a44e4cda142f92777af88245a21081b1a5c42a8f1c3e8abfd08325408ebfa4bea9401e94e95",
    "182b103c4e446cd451ebc8bee07d775137774a7be2b359ea76d224704bc4fef54106151e16ae949a4cc1fef7316f1cb9",
    "ffdae307fc068cafb2875a6ea18d4e5dbccfb2969c63e8931d9d252ed7dd90846e2b705c176768c059ba91455e1def11",
    "930b4945a546b75ed10edd818c04a1ce34f13e01072363c264d17c03add6e0cdf82bb7093e0154fd656c10a983db8386",
    "6503aff0066d020301000102820100552b839e49fc2ebdb53ba22f697e6f5de6b4a5332d421c2d123a46cf51c7f6687d",
    "39619205ba0df5b8a16bf3378eebef8c7145356e9fdc0d8f0bbedabd07466add5f65efdbc8bb6d782284169e76026d5a",
    "6378e5b202fe48d9be5d1d045a5f5935e2b1571541a3cc4953ddee4a22cfecc0df5b78714801516678738bab409d04ab",
    "2f3a5acd217085484cf771d4e72a76b6e18b0c3fb28a69aa8d9f259191ebc57daab017473208ded1af81c2d3d94cb065",
    "c4bdbcd8ab9c0f3825dd7cb3d7995d2da047c82e5e24c759288e5aabe8c347d815f03fc45dd5b3b63a0b9190bbb6feee",
    "025bdf64bc9b6fce6af422ea0b96c4355bc4017b6a6c4f1c9d0c0249ccd09102818100f5745fa92c1612bd5b42070ccc",
    "4ac3c5d9863fa528ae5cdba8f0b744797fdfc241fc94936cf1a3f97f6d5fdb4fc513dee5df7c68beefc297050135649f",
    "60d31304d40808d3ddcc1b1063b7cfd06e193704da0d9c9db50728047eed37f22c5212f9172971817f1ee594da45ea34",
    "8839327dbd423e64385004686c13072d5f357b02818100c3dae0f3c8888b4ee02416774421b42562d954d29b85d2da08",
    "578c6d57617ae81ffad3cc85d0e92ceaf61efe30c2da5309573d0275d06359981caf05b609eeadf840e1e63069fd3df8",
    "46c90c99a4bd6c5fc0f1f952cd398175ad3ebc5342d8dea09b5e5c7e6d8b498ad59966b28190206b020bd846beecb8bf",
    "4a9d3b4349cb370281803bf9244a84901c2212432ecfccb6d3e0eac66794a63cfc495b9cfd5a88c95ad5ef2394f5f49f",
    "922e2b19815b67c1429aaad61162d28c68a257c1b4d7122e2944b3604f5a40d227c5d11a5c56359a4124f555860fe764",
    "cd0bd5156246d2304c1980ad4d1e03c318bc85c35363e754058db5b56193370f9f5584622bc00c310033028181008269",
    "e1b692c65134d14d56644e4abf00d2047355d5d7536279818a7158690185459e28a01c4ed2a5654343b9f0d01ebe820e",
    "c4023a5eeb78c22fff5f272b0ff269c71264cbc217adc6ffa36a2f78a1e56311404ecb92fa02b95005e132f3e522c101",
    "13e135124e5847091a1f67279cc7e9593077f00bbbe6fd017b16f624521b02818039945e5b5cf2a6730bd153200e91e6",
    "b9554fcb0fce9f384bcf371b8d6e05cd4c4d2e8a44691b12d22bca8a0f2cf368f10e1d1f000ad242e9c70f7be8693b4e",
    "1d10689620736aa24e6614c6fb639243c56f2386fefd9d251a56f8412799bf56bb142e27be6b61dc6e253b559c9c09a5",
    "51aa38499f6274694d8f98a6aeaa883b2b",
);

fn rsa_fixture() -> Vec<u8> {
    (0..RSA_FIXTURE_HEX.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&RSA_FIXTURE_HEX[i..i + 2], 16).unwrap())
        .collect()
}

/// The suite's PS256 clients: an RSA private key as the RFC 7518 s6.3 JWK the suite signs with, and
/// its public half (no private member) for the subject's config.
#[test]
fn an_rsa_pkcs8_key_becomes_a_ps256_jwk_pair() {
    let (private, public) = rsa_jwk_from_pkcs8(&rsa_fixture(), "r1").unwrap();
    assert_eq!(public["kty"], "RSA");
    assert_eq!(public["alg"], "PS256");
    assert_eq!(public["e"], "AQAB");
    assert_eq!(
        public["n"].as_str().unwrap().len(),
        342,
        "a 2048-bit modulus is 256 bytes, 342 unpadded base64url characters"
    );
    for member in ["d", "p", "q", "dp", "dq", "qi"] {
        assert!(
            public.get(member).is_none(),
            "public half carries no `{member}`"
        );
        assert!(
            private[member].as_str().is_some_and(|v| !v.is_empty()),
            "private carries `{member}`"
        );
    }
    assert_eq!(private["n"], public["n"]);
    assert!(rsa_jwk_from_pkcs8(b"not der", "x").is_err());
}

/// The jev subject's far end is a loopback port the rig owns, and the connector's destination guard
/// refuses loopback by default (`advanced.block_private_addresses`, QUESTIONS Q130/Q131): the rig
/// declares it as an allowed destination the way an operator would, as the oidf rig does.
#[test]
fn the_jev_subject_declares_its_loopback_far_end_as_an_allowed_destination() {
    let text = xtask::conformance_record::jev_subject_config(
        41000,
        41001,
        std::path::Path::new("/tmp/signing.key"),
    );
    let doc: serde_yaml::Value = serde_yaml::from_str(&text).expect("the config is YAML");
    assert_eq!(
        doc["advanced"]["allow_destinations"],
        serde_yaml::from_str::<serde_yaml::Value>("[\"127.0.0.1\"]").unwrap()
    );
    assert_eq!(doc["listen"].as_str(), Some("127.0.0.1:41000"));
    assert_eq!(
        doc["decisions"]["models"]["jev-1"]["provider"].as_str(),
        Some("typesafe")
    );
    assert_eq!(
        doc["decisions"]["rate_card"]["jev-1"]["units"]["decision"].as_u64(),
        Some(1)
    );
    assert_eq!(
        doc["auth"]["signing_key"]["file"].as_str(),
        Some("/tmp/signing.key")
    ); // A config names its store (Q-STORE = (B), #465): without it the subject refuses to boot.
    assert_eq!(doc["store"]["module"].as_str(), Some("memory"));
}

/// The config the plain subjects boot on (the h2, tls and oidf rigs) names its store: a config with
/// no `store:` block is refused at boot (Q-STORE = (B), #465, BUSBAR-9007), so a rig that omits it
/// measures a refusal instead of the subject.
#[test]
fn the_plain_subject_config_names_its_store() {
    let doc: serde_yaml::Value = serde_yaml::from_str(&xtask::conformance_record::base_config(
        "127.0.0.1:41000",
        41001,
    ))
    .expect("the config is YAML");
    assert_eq!(doc["store"]["module"].as_str(), Some("memory"));
    assert_eq!(doc["listen"].as_str(), Some("127.0.0.1:41000"));
}

/// The oidf rig builds the dropped-in oidc plugin over ITS OWN REPO's workspace (the pinned git
/// checkout), never `cargo build -p` in this one, where the plugin is a dev-only edge and cargo's
/// feature resolver panics. The workspace is the nearest manifest above the crate that declares
/// `[workspace]`, so a two-crate fleet repo resolves to its root, not to the plugin crate.
#[test]
fn the_oidc_plugin_is_built_over_its_own_repo_workspace() {
    let d = std::env::temp_dir().join(format!("xtask-ws-above-{}", std::process::id()));
    let crate_dir = d.join("auth-oidc-plugin");
    std::fs::create_dir_all(&crate_dir).unwrap();
    std::fs::write(
        d.join("Cargo.toml"),
        "[workspace]\nmembers = [\"auth-oidc-plugin\"]\n",
    )
    .unwrap();
    std::fs::write(crate_dir.join("Cargo.toml"), "[package]\nname = \"p\"\n").unwrap();
    assert_eq!(
        xtask::conformance_record::workspace_above(&crate_dir.join("Cargo.toml")),
        Some(d.join("Cargo.toml"))
    );
    // A crate with no workspace above it within the tree resolves to nothing rather than to itself.
    let lone = d.join("lone");
    std::fs::create_dir_all(&lone).unwrap();
    std::fs::remove_file(d.join("Cargo.toml")).unwrap();
    std::fs::write(lone.join("Cargo.toml"), "[package]\nname = \"l\"\n").unwrap();
    assert!(
        xtask::conformance_record::workspace_above(&lone.join("Cargo.toml"))
            .is_none_or(|m| !m.starts_with(&d))
    );
    let _ = std::fs::remove_dir_all(&d);
}

/// The mcp rig runs on a PINNED node, never the runner's: the control peer's bundler ships its native
/// binding as an optional dependency gated on node `^20.19.0 || >=22.12.0`, which pnpm skips silently
/// outside that range, and the official suite needs node 22. Every runner platform has a digest, and
/// the pin is inside both ranges.
#[test]
fn the_mcp_rig_pins_a_node_its_toolchain_accepts_on_every_runner_platform() {
    use xtask::conformance_record::{mcp_node_platform, MCP_NODE_VERSION};
    for (os, arch) in [
        ("linux", "x86_64"),
        ("linux", "aarch64"),
        ("macos", "x86_64"),
        ("macos", "aarch64"),
    ] {
        let (_, digest) = mcp_node_platform(os, arch).expect("a pinned tarball for this runner");
        assert!(
            digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()),
            "{os}/{arch}: {digest}"
        );
    }
    assert!(mcp_node_platform("windows", "x86_64").is_none());
    let v: Vec<u32> = MCP_NODE_VERSION
        .trim_start_matches('v')
        .split('.')
        .map(|n| n.parse().unwrap())
        .collect();
    assert!(
        v[0] == 22 && v[1] >= 12,
        "{MCP_NODE_VERSION} is outside >=22.12 <23"
    );
}

/// THE ATTESTED BUILD THE RIG FETCHES (ARCHITECT rulings 2026-10-17 A1 and 2026-10-20): busbar's
/// own `slsa-dev-provenance` run on each push to dev hands the binary and its in-toto provenance off
/// as the run's own artifacts under these names; the rig asks for exactly HEAD's pair on its own
/// architecture, and verifies it against busbar's repository and branch.
#[test]
fn the_slsa_rig_fetches_heads_attested_pair_from_its_own_run() {
    use xtask::conformance_record::{
        hand_off, HandOff, PROVENANCE_ARTIFACT, RUN_POLL_SECS, RUN_WAIT_CAP_SECS, SIGNER_REPO,
        SIGNER_WORKFLOW,
    };
    assert_eq!(
        hand_off("aarch64", HEAD),
        HandOff {
            binary_artifact: "busbar-linux-aarch64".into(),
            binary_file: format!("busbar-linux-aarch64-{HEAD}"),
            provenance_artifact: "busbar-slsa-provenance".into(),
            provenance_file: format!("busbar-linux-{HEAD}.intoto.jsonl"),
        }
    );
    assert_eq!(SIGNER_REPO, "GetBusbar/busbar");
    assert_eq!(SIGNER_WORKFLOW, "slsa-dev-provenance.yml");
    // The workflow uploads exactly the names the rig asks for, with an explicit retention.
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    let wf =
        std::fs::read_to_string(root.join(".github/workflows/slsa-dev-provenance.yml")).unwrap();
    assert!(wf.contains("name: busbar-linux-${{ matrix.arch }}\n"));
    assert!(wf.contains("path: out/busbar-linux-${{ matrix.arch }}-${{ github.sha }}\n"));
    assert!(wf.contains(&format!("name: {PROVENANCE_ARTIFACT}\n")));
    assert!(wf.contains("path: prov/busbar-linux-${{ github.sha }}.intoto.jsonl\n"));
    assert_eq!(
        wf.matches("retention-days: ${{ env.RETENTION_DAYS }}")
            .count(),
        2
    );
    assert!(!wf.contains("BUSBAR_DEV_BIN_TOKEN") && !wf.contains("busbar-release"));
    // The wait is bounded and polls at a stated interval.
    assert_eq!((RUN_POLL_SECS, RUN_WAIT_CAP_SECS), (60, 3600));
    assert_eq!(
        xtask::conformance_record::SOURCE_URI,
        "github.com/GetBusbar/busbar"
    );
    assert_eq!(xtask::conformance_record::SOURCE_BRANCH, "dev");
}

fn wf_run(id: u64, head: &str, status: &str, conclusion: Option<&str>) -> Value {
    json!({"id": id, "head_sha": head, "status": status, "conclusion": conclusion})
}

/// GREEN: a successful run for HEAD is fetched, even beside an older failed attempt.
#[test]
fn slsa_run_state_fetches_heads_successful_run() {
    use xtask::conformance_record::{next_step, run_state, RunState, Step};
    let runs = json!({"workflow_runs": [
        wf_run(9, HEAD, "completed", Some("failure")),
        wf_run(7, HEAD, "completed", Some("success")),
    ]});
    assert_eq!(run_state(&runs, HEAD), RunState::Ready(7));
    assert_eq!(next_step(RunState::Ready(7), 0, HEAD), Step::Fetch(7));
}

/// RED (not-run): no run for HEAD; a run of another commit is not HEAD's.
#[test]
fn slsa_no_run_for_head_is_not_run() {
    use xtask::conformance_record::{next_step, run_state, RunState, Step};
    let other = "ffffffffffffffffffffffffffffffffffffffff";
    for runs in [
        json!({"workflow_runs": []}),
        json!({"total_count": 0}),
        json!({"workflow_runs": [wf_run(3, other, "completed", Some("success"))]}),
    ] {
        let s = run_state(&runs, HEAD);
        let RunState::Refused(why) = &s else {
            panic!("{s:?}")
        };
        assert!(
            why.contains("no slsa-dev-provenance.yml run for HEAD"),
            "{why}"
        );
        assert!(matches!(next_step(s, 0, HEAD), Step::Stop(_)));
    }
}

/// RED (not-run): HEAD's run failed or was cancelled.
#[test]
fn slsa_failed_run_is_not_run() {
    use xtask::conformance_record::{run_state, RunState};
    for c in ["failure", "cancelled", "startup_failure"] {
        let runs = json!({"workflow_runs": [wf_run(5, HEAD, "completed", Some(c))]});
        let RunState::Refused(why) = run_state(&runs, HEAD) else {
            panic!("{c}")
        };
        assert!(why.contains(&format!("concluded `{c}`")), "{why}");
    }
}

/// An unfinished run is waited for up to the cap; RED (not-run) at the cap.
#[test]
fn slsa_unfinished_run_waits_then_times_out_to_not_run() {
    use xtask::conformance_record::{next_step, run_state, RunState, Step, RUN_WAIT_CAP_SECS};
    let runs = json!({"workflow_runs": [wf_run(4, HEAD, "in_progress", None)]});
    let s = run_state(&runs, HEAD);
    assert_eq!(s, RunState::Pending(4, "in_progress".into()));
    assert_eq!(next_step(s.clone(), 0, HEAD), Step::Wait);
    assert_eq!(
        next_step(s.clone(), RUN_WAIT_CAP_SECS - 1, HEAD),
        Step::Wait
    );
    let Step::Stop(why) = next_step(s, RUN_WAIT_CAP_SECS, HEAD) else {
        panic!("the wait is not bounded")
    };
    assert!(
        why.contains("still `in_progress`") && why.contains("60-minute"),
        "{why}"
    );
}

/// GREEN: both named artifacts are found; RED (not-run): one is missing or expired.
#[test]
fn slsa_artifacts_missing_or_expired_are_not_run() {
    use xtask::conformance_record::{artifact_urls, hand_off};
    let want = hand_off("x86_64", HEAD);
    let art = |name: &str, expired: bool| {
        json!({"name": name, "expired": expired,
               "archive_download_url": format!("https://api.github.com/{name}/zip")})
    };
    let both = json!({"artifacts": [
        art("busbar-linux-x86_64", false),
        art("busbar-linux-aarch64", false),
        art("busbar-slsa-provenance", false),
    ]});
    assert_eq!(
        artifact_urls(&both, &want, 7).unwrap(),
        (
            "https://api.github.com/busbar-linux-x86_64/zip".to_string(),
            "https://api.github.com/busbar-slsa-provenance/zip".to_string()
        )
    );
    let no_prov = json!({"artifacts": [art("busbar-linux-x86_64", false)]});
    let e = artifact_urls(&no_prov, &want, 7).unwrap_err();
    assert!(e.contains("no artifact `busbar-slsa-provenance`"), "{e}");
    let no_bin = json!({"artifacts": [art("busbar-slsa-provenance", false)]});
    let e = artifact_urls(&no_bin, &want, 7).unwrap_err();
    assert!(e.contains("no artifact `busbar-linux-x86_64`"), "{e}");
    let expired = json!({"artifacts": [
        art("busbar-linux-x86_64", true),
        art("busbar-slsa-provenance", false),
    ]});
    let e = artifact_urls(&expired, &want, 7).unwrap_err();
    assert!(e.contains("expired"), "{e}");
}

/// RED (not-run): no token, and a token the API refuses (401/403), each name the need.
#[test]
fn slsa_token_absent_or_refused_is_not_run() {
    use xtask::conformance_record::{http_answer, token_from, TOKEN_NEED};
    assert_eq!(TOKEN_NEED, "a token with actions:read on GetBusbar/busbar");
    let e = token_from(|_| None).unwrap_err();
    assert!(e.contains(TOKEN_NEED), "{e}");
    let e = token_from(|_| Some(String::new())).unwrap_err();
    assert!(e.contains(TOKEN_NEED), "{e}");
    assert_eq!(
        token_from(|k| (k == "GH_TOKEN").then(|| "t".to_string())).unwrap(),
        ("GH_TOKEN", "t".to_string())
    );
    assert_eq!(
        token_from(|_| Some("t".to_string())).unwrap().0,
        "BUSBAR_RELEASE_TOKEN"
    );
    assert!(http_answer(200, "BUSBAR_RELEASE_TOKEN", "x").is_ok());
    for code in [401, 403] {
        let e = http_answer(code, "BUSBAR_RELEASE_TOKEN", "x").unwrap_err();
        assert!(
            e.contains("BUSBAR_RELEASE_TOKEN") && e.contains("Actions: read on GetBusbar/busbar"),
            "{e}"
        );
    }
    assert!(http_answer(404, "BUSBAR_RELEASE_TOKEN", "x").is_err());
    assert!(http_answer(0, "BUSBAR_RELEASE_TOKEN", "x").is_err());
}
