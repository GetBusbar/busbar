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
    governance_observed, is_jev_refusal, judge_jev_ledger, junit_cases, module_results,
    provenance_commit, rig_for, tests_passed, CaseResult, H2Run, JevRun, OidfRun, SlsaRun, Status,
    TlsRun, NEGATIVE_PAIRS, OIDF_SUITES, REPORTED_UNITS,
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

fn totals(rows: &[(&str, &str, u64, &str)]) -> Vec<u8> {
    json!({"rows": rows.iter().map(|(lane, provider, fees, micros)| json!({
        "bucket": "k", "day": 0, "lane": lane, "provider": provider,
        "fee_count": fees, "priced_nanos": "0", "priced_micros": micros,
    })).collect::<Vec<_>>()})
    .to_string()
    .into_bytes()
}

#[test]
fn the_jev_ledger_shows_one_fee_carrying_the_reported_units() {
    assert_eq!(REPORTED_UNITS, 42);
    // One billable success at 42 units; another lane's rows are not read.
    assert!(judge_jev_ledger(&totals(&[
        ("jev-1", "typesafe", 1, "42"),
        ("gpt", "openai", 9, "100"),
    ]))
    .is_ok());
    // The 422 billed too.
    assert!(judge_jev_ledger(&totals(&[("jev-1", "typesafe", 2, "42")])).is_err());
    // A fee with no units: the reported usage did not reach the ledger.
    assert!(judge_jev_ledger(&totals(&[("jev-1", "typesafe", 1, "0")])).is_err());
    // Nothing billed at all.
    assert!(judge_jev_ledger(&totals(&[])).is_err());
    assert!(judge_jev_ledger(b"{}").is_err());
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
