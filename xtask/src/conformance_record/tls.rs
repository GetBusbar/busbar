//! THE tls RIG — busbar's inbound TLS (rustls, no OpenSSL) graded by `testssl.sh`, the upstream
//! scanner, against a busbar built from this checkout on a loopback `tls:` listener.
//!
//! THE SUBJECT'S CERTIFICATE is minted per run by a throwaway CA ([`super::subject::mint_pki`]) and
//! the CA is handed to testssl with `--add-ca`, so the chain is TRUSTED and the grade measures
//! busbar's TLS stack (protocols, ciphers, key exchange, renegotiation, the known
//! vulnerabilities), never the absence of a public CA on a loopback name.
//!
//! THE JUDGEMENT, from testssl's own JSON findings:
//!   * a scan problem testssl itself reports (`scanProblem`, severity `FATAL`) ⇒ `not-run`;
//!   * no `overall_grade` row ⇒ `not-run` (testssl rated nothing);
//!   * a pass is an overall grade of `A` or `A+` AND no finding of severity `HIGH` or `CRITICAL`;
//!     anything else is `fail`, naming the grade, its cap reasons and the severe findings.
//!
//! The A floor is this rig's reading of "testssl grade" in the registry plan; it is stated to the
//! ARCHITECT in the lane handoff as the proposed bar.

use serde_json::Value;

use super::rigs::{rc, read_opt, Rig, Runner};
use super::subject;
use super::Outcome;

/// drwetter/testssl.sh 3.2, by digest.
pub const TESTSSL_IMAGE: &str =
    "drwetter/testssl.sh@sha256:4959267aacbb400b0dd126e55a4671ed2b3b460465254837a2eebbedfbec5e8f";

/// Grades that pass.
const PASSING_GRADES: &[&str] = &["A+", "A"];
/// Severities that are red whatever the grade.
const RED_SEVERITIES: &[&str] = &["HIGH", "CRITICAL"];

/// What the tls rig measured.
#[derive(Debug, Clone)]
pub struct TlsRun {
    /// `Err` = no subject, and why; `boot_failed` says whether it is busbar's (a boot) or not.
    pub subject: Result<(), String>,
    pub boot_failed: bool,
    pub exit: Option<i32>,
    /// testssl's `--jsonfile` (flat) output.
    pub report: Option<String>,
    pub evidence: String,
}

pub fn decide_tls(run: &TlsRun) -> Outcome {
    if let Err(why) = &run.subject {
        return if run.boot_failed {
            Outcome::fail(
                format!("the subject did not boot on its tls: listener: {why}"),
                run.evidence.clone(),
            )
        } else {
            Outcome::not_run(format!("no subject: {why}"))
        };
    }
    let Some(rows) = run
        .report
        .as_deref()
        .and_then(|t| serde_json::from_str::<Value>(t).ok())
        .and_then(|v| v.as_array().cloned())
    else {
        return Outcome::not_run(format!(
            "testssl wrote no readable JSON report ({})",
            rc(run.exit)
        ));
    };
    let field = |r: &Value, k: &str| r.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    if let Some(p) = rows
        .iter()
        .find(|r| field(r, "id") == "scanProblem" && field(r, "severity") == "FATAL")
    {
        return Outcome::not_run(format!(
            "testssl could not scan the subject: {}",
            field(p, "finding")
        ));
    }
    let Some(grade) = rows
        .iter()
        .find(|r| field(r, "id") == "overall_grade")
        .map(|r| field(r, "finding"))
    else {
        return Outcome::not_run("testssl's report carries no overall_grade: it rated nothing");
    };
    let caps: Vec<String> = rows
        .iter()
        .filter(|r| field(r, "id").starts_with("grade_cap_reason"))
        .map(|r| field(r, "finding"))
        .collect();
    let severe: Vec<String> = rows
        .iter()
        .filter(|r| RED_SEVERITIES.contains(&field(r, "severity").as_str()))
        .map(|r| {
            format!(
                "{} [{}]: {}",
                field(r, "id"),
                field(r, "severity"),
                field(r, "finding")
            )
        })
        .collect();
    if PASSING_GRADES.contains(&grade.as_str()) && severe.is_empty() {
        return Outcome::pass(run.evidence.clone());
    }
    let mut why = vec![format!("overall grade {grade} (passing: A+, A)")];
    if !caps.is_empty() {
        why.push(format!("capped by: {}", caps.join("; ")));
    }
    if !severe.is_empty() {
        why.push(format!(
            "{} HIGH/CRITICAL finding(s): {}",
            severe.len(),
            super::rigs::first_few(&severe)
        ));
    }
    Outcome::fail(why.join("; "), run.evidence.clone())
}

impl Runner {
    pub(super) fn run_tls(&self) -> Outcome {
        let rig = Rig::Tls;
        if let Some(o) = self.missing(rig, &["cargo", "curl"]) {
            return o;
        }
        let local = super::rigs::on_path("testssl.sh");
        if !local {
            if let Some(o) = self.missing(rig, &["docker"]) {
                return o;
            }
        }
        let dir = self.work_dir(rig);
        let report = dir.join("testssl.json");
        let mut run = TlsRun {
            subject: Ok(()),
            boot_failed: false,
            exit: None,
            report: None,
            evidence: self.rel(&report),
        };
        let bin = match self.busbar() {
            Ok(b) => b,
            Err(e) => {
                run.subject = Err(e);
                return decide_tls(&run);
            }
        };
        let pki = match subject::mint_pki(&dir, &["localhost", "127.0.0.1"]) {
            Ok(p) => p,
            Err(e) => return Outcome::not_run(e),
        };
        let ports = match subject::free_ports(2) {
            Ok(p) => p,
            Err(e) => return Outcome::not_run(e),
        };
        let config = format!(
            "{}tls:\n  cert: {{ file: {} }}\n  key: {{ file: {} }}\n",
            subject::base_config(&format!("127.0.0.1:{}", ports[0]), ports[1]),
            pki.cert.display(),
            pki.key.display()
        );
        let booted = match subject::boot(
            &bin,
            &dir.join("subject"),
            &config,
            subject::NO_PROVIDERS,
            &[],
            &format!("https://127.0.0.1:{}/stats", ports[0]),
            &["-k"],
        ) {
            Ok(b) => b,
            Err(e) => {
                run.subject = Err(e);
                run.boot_failed = true;
                return decide_tls(&run);
            }
        };
        let target = format!("https://localhost:{}", ports[0]);
        let (ca, out) = if local {
            (
                pki.ca.to_string_lossy().into_owned(),
                report.to_string_lossy().into_owned(),
            )
        } else {
            ("/work/ca.pem".to_string(), "/work/testssl.json".to_string())
        };
        let args = [
            "--quiet",
            "--color",
            "0",
            "--warnings",
            "off",
            "--add-ca",
            ca.as_str(),
            "--jsonfile",
            out.as_str(),
            target.as_str(),
        ];
        let argv: Vec<String> = if local {
            std::iter::once("testssl.sh")
                .chain(args)
                .map(str::to_string)
                .collect()
        } else {
            // The image runs unprivileged; the report directory must take its write.
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777));
            subject::docker_run(TESTSSL_IMAGE, &dir, &args)
        };
        let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
        run.exit = self.leg(rig, "testssl", &argv, None, &[]);
        drop(booted);
        run.report = read_opt(&report);
        decide_tls(&run)
    }
}
