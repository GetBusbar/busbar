//! THE h2 RIG — HTTP/2 (RFC 9113 / RFC 7541) by `h2spec`, the upstream conformance tool, against a
//! busbar built from this checkout.
//!
//! WHICH LISTENER. busbar's inbound TLS listener advertises `http/1.1` alone over ALPN
//! (`busbar-core-connector/src/tls/mod.rs`, pinned by its own test), so HTTP/2 reaches busbar as
//! cleartext prior-knowledge h2c on the plain listener, which the shared
//! `hyper_util::server::conn::auto` builder serves (`busbar-kernel/src/tls.rs`). That is the
//! listener h2spec is pointed at. If busbar ever advertises `h2` over TLS, the TLS leg joins here.
//!
//! THE JUDGEMENT. h2spec's own JUnit report, read case by case: a pass is every case run and
//! passed. A failed or errored case is red, and so is a SKIPPED one — a skipped case is a
//! requirement h2spec did not get to check, and the MUST set is not met by requirements nobody
//! checked. A report with no case at all is `not-run`: h2spec judged nothing.
//!
//! THE INSTRUMENT. `h2spec` on PATH when the runner has it; otherwise the pinned image below, run
//! with the host's network so loopback is the subject's.

use super::rigs::{rc, read_opt, Rig, Runner};
use super::subject;
use super::Outcome;

/// summerwind/h2spec 2.6.0, by digest.
pub const H2SPEC_IMAGE: &str =
    "summerwind/h2spec@sha256:5f4a65c30cae8569558ced048b4bfe0dcf01a221e36767ae504ccd8348a7aeb0";

/// One JUnit case: its name (`package` + `classname`) and how it ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Case {
    pub name: String,
    pub result: CaseResult,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaseResult {
    Passed,
    Failed,
    Errored,
    Skipped,
}

fn attr(tag: &str, name: &str) -> Option<String> {
    let key = format!(" {name}=\"");
    let at = tag.find(&key)? + key.len();
    let end = tag[at..].find('"')? + at;
    Some(
        tag[at..end]
            .replace("&quot;", "\"")
            .replace("&apos;", "'")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&amp;", "&"),
    )
}

/// Every `<testcase>` of a JUnit document, in order.
pub fn junit_cases(xml: &str) -> Vec<Case> {
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(at) = rest.find("<testcase") {
        rest = &rest[at..];
        let open_end = rest.find('>').unwrap_or(rest.len());
        let open = &rest[..open_end];
        let (body, next) = if open.ends_with('/') {
            ("", &rest[open_end.min(rest.len())..])
        } else {
            match rest.find("</testcase>") {
                Some(close) => (&rest[open_end..close], &rest[close..]),
                None => (&rest[open_end..], ""),
            }
        };
        let name = [
            attr(open, "package"),
            attr(open, "classname"),
            attr(open, "name"),
        ]
        .into_iter()
        .flatten()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
        let result = if body.contains("<failure") {
            CaseResult::Failed
        } else if body.contains("<error") {
            CaseResult::Errored
        } else if body.contains("<skipped") {
            CaseResult::Skipped
        } else {
            CaseResult::Passed
        };
        out.push(Case { name, result });
        rest = if next.is_empty() { "" } else { &next[1..] };
    }
    out
}

/// What the h2 rig measured.
#[derive(Debug, Clone)]
pub struct H2Run {
    /// `Err` = no subject (no binary, or it did not boot), and why.
    pub subject: Result<(), String>,
    /// Whether the subject failed to BOOT (a fail) rather than to build (not-run).
    pub boot_failed: bool,
    pub exit: Option<i32>,
    /// h2spec's JUnit report.
    pub report: Option<String>,
    pub evidence: String,
}

pub fn decide_h2(run: &H2Run) -> Outcome {
    if let Err(why) = &run.subject {
        return if run.boot_failed {
            Outcome::fail(
                format!("the subject did not boot: {why}"),
                run.evidence.clone(),
            )
        } else {
            Outcome::not_run(format!("no subject: {why}"))
        };
    }
    let Some(xml) = &run.report else {
        return Outcome::not_run(format!("h2spec wrote no report ({})", rc(run.exit)));
    };
    let cases = junit_cases(xml);
    if cases.is_empty() {
        return Outcome::not_run(format!(
            "h2spec's report holds no case ({}): it judged nothing",
            rc(run.exit)
        ));
    }
    let red: Vec<String> = cases
        .iter()
        .filter(|c| c.result != CaseResult::Passed)
        .map(|c| format!("{} [{:?}]", c.name, c.result))
        .collect();
    if !red.is_empty() {
        return Outcome::fail(
            format!(
                "{} of {} h2spec case(s) not passed: {}",
                red.len(),
                cases.len(),
                super::rigs::first_few(&red)
            ),
            run.evidence.clone(),
        );
    }
    if run.exit != Some(0) {
        return Outcome::fail(
            format!(
                "every case in the report passed but h2spec {}; an unattributed red is no pass",
                rc(run.exit)
            ),
            run.evidence.clone(),
        );
    }
    Outcome::pass(run.evidence.clone())
}

impl Runner {
    pub(super) fn run_h2(&self) -> Outcome {
        let rig = Rig::H2;
        if let Some(o) = self.missing(rig, &["cargo", "curl"]) {
            return o;
        }
        let local = super::rigs::on_path("h2spec");
        if !local {
            if let Some(o) = self.missing(rig, &["docker"]) {
                return o;
            }
        }
        let dir = self.work_dir(rig);
        let report = dir.join("h2spec.xml");
        let mut run = H2Run {
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
                return decide_h2(&run);
            }
        };
        let ports = match subject::free_ports(2) {
            Ok(p) => p,
            Err(e) => return Outcome::not_run(e),
        };
        let booted = match subject::boot(
            &bin,
            &dir.join("subject"),
            &subject::base_config(&format!("127.0.0.1:{}", ports[0]), ports[1]),
            subject::NO_PROVIDERS,
            &[],
            &format!("http://127.0.0.1:{}/stats", ports[0]),
            &[],
        ) {
            Ok(b) => b,
            Err(e) => {
                run.subject = Err(e);
                run.boot_failed = true;
                return decide_h2(&run);
            }
        };
        let port = ports[0].to_string();
        // `-P /stats`: a path the plain subject answers with a body, so the flow-control cases have
        // DATA to window. `-o 5`: h2spec's per-case timeout.
        let args = |out: &str| -> Vec<String> {
            [
                "-h",
                "127.0.0.1",
                "-p",
                &port,
                "-P",
                "/stats",
                "-o",
                "5",
                "-j",
                out,
            ]
            .iter()
            .map(|s| s.to_string())
            .collect()
        };
        let argv: Vec<String> = if local {
            let mut v = vec!["h2spec".to_string()];
            v.extend(args(&report.to_string_lossy()));
            v
        } else {
            let a = args("/work/h2spec.xml");
            let a: Vec<&str> = a.iter().map(String::as_str).collect();
            subject::docker_run(H2SPEC_IMAGE, &dir, &a)
        };
        let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
        run.exit = self.leg(rig, "h2spec", &argv, None, &[]);
        drop(booted);
        run.report = read_opt(&report);
        decide_h2(&run)
    }
}
