//! The MUST-set rigs `cargo xtask conformance record` gained so that every registered suite has a
//! producer that can PASS a correct busbar (BUSBAR-1.6.0.md #68): a2a, h2, tls, slsa-verifier,
//! oidf-oauth2 + fapi2, and the jev rig rebuilt in Rust with a pass arm.
//!
//! What these cases pin, per decider: a correct measurement is a `pass`; every way the subject can
//! be wrong is a `fail` naming it; every way the INSTRUMENT (or the rig's own inputs) can fail is a
//! `not-run`, never a pass and never a fail charged to busbar.

use serde_json::{json, Value};
use xtask::conformance_record::{
    b64url, decide_h2, decide_jev, decide_oidf, decide_slsa, decide_tls, discriminates, es256_jwk,
    governance_observed, is_jev_refusal, jev_fee_count, junit_cases, module_results,
    provenance_commit, rig_for, tests_passed, CaseResult, H2Run, JevRun, OidfRun, SlsaRun, Status,
    TlsRun, NEGATIVE_PAIRS, OIDF_SUITES,
};

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
    assert_eq!(ids.len(), 17, "the registry is the MUST set: {ids:?}");
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

#[test]
fn the_fee_count_is_read_off_the_jev_lane_only() {
    let totals = json!({"rows": [
        {"bucket": "k", "day": 0, "lane": "jev-1", "provider": "typesafe", "fee_count": 1, "priced_nanos": "0", "priced_micros": "0"},
        {"bucket": "k", "day": 0, "lane": "gpt", "provider": "openai", "fee_count": 9, "priced_nanos": "0", "priced_micros": "0"},
    ]});
    assert_eq!(jev_fee_count(totals.to_string().as_bytes()), Ok(1));
    assert_eq!(jev_fee_count(br#"{"rows":[]}"#), Ok(0));
    assert!(jev_fee_count(b"{}").is_err());
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
