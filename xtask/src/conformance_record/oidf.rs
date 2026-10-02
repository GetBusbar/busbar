//! THE oidf RIG — `oidf-oauth2` and `fapi2`, judged by the OpenID Foundation's own conformance
//! suite, SELF-HOSTED at a pinned release and driven by the suite's own runner
//! (`scripts/run-test-plan.py`), against a busbar built from this checkout acting as the
//! authorization server (`oauth_as:`).
//!
//! The claim this rig can support is "passes the suite", never "certified" (owner ruling
//! 2026-09-19, `conformance/registry.toml`): a self-hosted run is the suite's verdict, not the
//! Foundation's listing, which is paid and owner-owned.
//!
//! WHAT RUNS, in order — every step before the subject's is the INSTRUMENT, and a red there is
//! `not-run`:
//!   1. the suite at [`SUITE_TAG`] (checked against [`SUITE_COMMIT`]), cached between runs;
//!   2. its jar, built by its own `builder-compose.yml` (maven image pinned by digest);
//!   3. its server, nginx front and mongodb by its own `docker-compose.yml`, with mongodb pinned by
//!      digest and the server given `host.docker.internal` so it can reach the subject;
//!   4. the SUBJECT: busbar on a TLS listener with an `oauth_as:` block whose issuer is the name the
//!      suite reaches it by; two clients registered through busbar's own RFC 7591 endpoint with
//!      the plan's client authentication and freshly minted ES256 keys;
//!   5. `run-test-plan.py` for each plan in [`SUITES`], its per-module results read back.
//!
//! THE JUDGEMENT ([`decide_oidf`]): every module FINISHED with result PASSED, WARNING or REVIEW
//! (REVIEW is the suite's "no failure; a human looks at the screenshot" result) ⇒ `pass`. Any
//! FAILED, INTERRUPTED, SKIPPED or unfinished module ⇒ `fail` naming it. busbar refusing to boot,
//! to publish its metadata or to register the plan's clients ⇒ `fail`. A run that produced no
//! module result at all ⇒ `not-run`.
//!
//! ARCHITECT RULINGS 2026-10-02 (handoff CONFORMANCE-RIGS.md). `oidf-oauth2` is the plan under
//! `openid=plain_oauth` (the registry's words); `fapi2` is the FAPI2 Security Profile plan under the
//! variant the FAPI2 design note (aba9904696, `oauth_as` FAPI knobs) names for busbar's claimed
//! profile: `plain_oauth` + `private_key_jwt` + `dpop` + `plain_fapi`. The two are identical, so the
//! plan runs ONCE and both verdicts are written from that run ([`SUITES`]; [`Runner::run_oidf`]
//! deduplicates on the plan argument). The empty admin chain (so the suite's browser can approve on
//! the consent screen) and the `0.0.0.0` data listener (so the suite's container reaches the
//! subject) live ONLY in this rig's generated subject config and change no product default; the
//! suite tests the issued token against a served route ([`RESOURCE_PATH`]).

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::rigs::{fan, Rig, Runner};
use super::subject::{self, b64url, curl};
use super::Outcome;

/// The OpenID Foundation conformance suite, pinned.
pub const SUITE_REPO: &str = "https://gitlab.com/openid/conformance-suite.git";
pub const SUITE_TAG: &str = "release-v5.3.1";
pub const SUITE_COMMIT: &str = "440eec8bac7b12b7389d7ca9cbc459b53507a443";
/// The suite's own compose files name these by floating tag; the rig pins them by digest.
pub const MONGO_IMAGE: &str =
    "mongo@sha256:b415b12f638e2685d06c58ab7fb5943577c50fadec6d9340ef67d21aeac72070";
pub const MAVEN_IMAGE: &str =
    "maven@sha256:c0bfb7e25e0bbe9a1852ffc67e61236e5f80f1eac3dc54e20b9398cea1453fec";
/// Where the suite's own base URL resolves (the suite's docker-compose `base_url`).
pub const SUITE_URL: &str = "https://localhost.emobix.co.uk:8443/";
/// The name the suite's server reaches the subject by.
const SUBJECT_HOST: &str = "host.docker.internal";
/// The test alias, which fixes the suite's callback URL.
const ALIAS: &str = "busbar-conformance";
/// The scope the plan asks for, and the subject grants self-registered clients.
const SCOPE: &str = "conformance";
/// The served subject route the suite calls with an issued access token (see the module docs).
pub const RESOURCE_PATH: &str = "/mcp";

/// One suite id: the plan it runs and the variant it runs under.
pub struct Plan {
    pub suite: &'static str,
    pub plan: &'static str,
    pub variant: &'static [(&'static str, &'static str)],
}

/// The FAPI 2.0 Security Profile OP posture for an authorization server that is not an OpenID
/// provider: plain OAuth, private_key_jwt client authentication, DPoP sender-constraining, the
/// plain profile, unsigned requests, plain responses.
const FAPI2SP_PLAIN_OAUTH: &[(&str, &str)] = &[
    ("openid", "plain_oauth"),
    ("client_auth_type", "private_key_jwt"),
    ("sender_constrain", "dpop"),
    ("fapi_profile", "plain_fapi"),
    ("fapi_request_method", "unsigned"),
    ("fapi_response_mode", "plain_response"),
    ("authorization_request_type", "simple"),
];

/// Every suite id this rig judges. Two ids naming the same plan and variant are ONE run.
pub const SUITES: &[Plan] = &[
    Plan {
        suite: "oidf-oauth2",
        plan: "fapi2-security-profile-final-test-plan",
        variant: FAPI2SP_PLAIN_OAUTH,
    },
    Plan {
        suite: "fapi2",
        plan: "fapi2-security-profile-final-test-plan",
        variant: FAPI2SP_PLAIN_OAUTH,
    },
];

impl Plan {
    /// `plan[k=v][k=v]`, the runner's spelling.
    pub fn arg(&self) -> String {
        let mut s = self.plan.to_string();
        for (k, v) in self.variant {
            s.push_str(&format!("[{k}={v}]"));
        }
        s
    }
}

/// One module's result as `run-test-plan.py` printed it: `(module, status, result)`.
pub fn module_results(log: &str) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for raw in log.lines() {
        let line = strip_ansi(raw);
        let Some(at) = line.find("Test [") else {
            continue;
        };
        let rest = &line[at..];
        let Some((head, tail)) = rest.split_once(" - result ") else {
            continue;
        };
        let result = tail
            .split(['.', ' '])
            .next()
            .unwrap_or_default()
            .to_string();
        let words: Vec<&str> = head.split_whitespace().collect();
        // `Test [p:m] <module> <id> <status>`
        if words.len() < 5 {
            continue;
        }
        out.push((
            words[2].to_string(),
            words[words.len() - 1].to_string(),
            result,
        ));
    }
    out
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\u{1b}' {
            for d in it.by_ref() {
                if d.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// What the rig measured for one plan run.
#[derive(Debug, Clone)]
pub struct OidfRun {
    /// `Err` = the suite itself never came up, and why.
    pub instrument: Result<(), String>,
    /// `Err` = no subject; `boot_failed` says whether busbar failed (a boot, its metadata, its
    /// registration endpoint) or the rig never got that far (no binary).
    pub subject: Result<(), String>,
    pub boot_failed: bool,
    pub exit: Option<i32>,
    /// `run-test-plan.py`'s output.
    pub log: String,
    pub evidence: String,
}

const GOOD_RESULTS: &[&str] = &["PASSED", "WARNING", "REVIEW"];

pub fn decide_oidf(run: &OidfRun) -> Outcome {
    if let Err(why) = &run.instrument {
        return Outcome::not_run(format!("the OIDF suite is not up: {why}"));
    }
    if let Err(why) = &run.subject {
        return if run.boot_failed {
            Outcome::fail(why.clone(), run.evidence.clone())
        } else {
            Outcome::not_run(format!("no subject: {why}"))
        };
    }
    let results = module_results(&run.log);
    if results.is_empty() {
        let tail: Vec<&str> = run.log.lines().rev().take(5).collect();
        return Outcome::not_run(format!(
            "the plan produced no module result ({}): {}",
            super::rigs::rc(run.exit),
            tail.into_iter().rev().collect::<Vec<_>>().join(" | ")
        ));
    }
    let red: Vec<String> = results
        .iter()
        .filter(|(_, status, result)| {
            status != "FINISHED" || !GOOD_RESULTS.contains(&result.as_str())
        })
        .map(|(m, status, result)| format!("{m} {status}/{result}"))
        .collect();
    if red.is_empty() {
        Outcome::pass(run.evidence.clone())
    } else {
        Outcome::fail(
            format!(
                "{} of {} module(s) not passed: {}",
                red.len(),
                results.len(),
                super::rigs::first_few(&red)
            ),
            run.evidence.clone(),
        )
    }
}

/// A fresh ES256 key as a private JWK and its public half.
pub fn es256_jwk(kid: &str) -> Result<(Value, Value), String> {
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING as ALG};
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ALG, &rng).map_err(|_| "ES256 keygen failed")?;
    let pair = EcdsaKeyPair::from_pkcs8(&ALG, pkcs8.as_ref(), &rng)
        .map_err(|_| "ES256 key did not reparse")?;
    let point = pair.public_key().as_ref();
    if point.len() != 65 || point[0] != 4 {
        return Err("ES256 public key is not an uncompressed P-256 point".into());
    }
    // RFC 5915 ECPrivateKey inside the PKCS#8: version 1 (`02 01 01`), then the 32-byte scalar.
    let der = pkcs8.as_ref();
    let marker = [0x02, 0x01, 0x01, 0x04, 0x20];
    let at = der
        .windows(marker.len())
        .position(|w| w == marker)
        .ok_or("the PKCS#8 document carries no ECPrivateKey scalar")?
        + marker.len();
    let d = der
        .get(at..at + 32)
        .ok_or("the ECPrivateKey scalar is short")?;
    let public = json!({
        "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": kid,
        "x": b64url(&point[1..33]), "y": b64url(&point[33..65]),
    });
    let mut private = public.clone();
    private["d"] = json!(b64url(d));
    Ok((private, public))
}

impl Runner {
    pub(super) fn run_oidf(&self) -> BTreeMap<String, Outcome> {
        let rig = Rig::Oidf;
        let ids = || SUITES.iter().map(|p| p.suite.to_string());
        if let Some(o) = self.missing(rig, &["docker", "git", "python3", "curl", "cargo"]) {
            return fan(ids(), &o);
        }
        let dir = self.work_dir(rig);
        let evidence = self.rel(&dir);
        let blank = |instrument: Result<(), String>| OidfRun {
            instrument,
            subject: Ok(()),
            boot_failed: false,
            exit: None,
            log: String::new(),
            evidence: evidence.clone(),
        };
        let suite = match self.oidf_suite_up() {
            Ok(s) => s,
            Err(e) => return fan(ids(), &decide_oidf(&blank(Err(e)))),
        };
        let out = self.oidf_runs(&suite, &dir, &blank);
        let _ = self.compose(&suite, &["down"], "suite-down");
        out
    }

    /// `docker compose -p busbar-oidf -f docker-compose.yml -f <pins>` in the suite checkout.
    fn compose(&self, suite: &Path, args: &[&str], leg: &str) -> Option<i32> {
        let pins = suite
            .join("docker-compose.busbar.yml")
            .to_string_lossy()
            .into_owned();
        let mut argv: Vec<&str> = vec![
            "docker",
            "compose",
            "-p",
            "busbar-oidf",
            "-f",
            "docker-compose.yml",
            "-f",
            pins.as_str(),
        ];
        argv.extend_from_slice(args);
        self.leg(Rig::Oidf, leg, &argv, Some(suite), &[])
    }

    /// Fetch (or reuse), build and start the pinned suite; the checkout's path when it answers.
    fn oidf_suite_up(&self) -> Result<std::path::PathBuf, String> {
        let rig = Rig::Oidf;
        let cache = self.cache.join("oidf");
        let suite = cache.join(format!("suite-{SUITE_TAG}"));
        let _ = std::fs::create_dir_all(&cache);
        let have = crate::gitp::git(&suite, &["rev-parse", "HEAD"])
            .map(|h| h.trim() == SUITE_COMMIT)
            .unwrap_or(false);
        if !have {
            let _ = std::fs::remove_dir_all(&suite);
            let s = suite.to_string_lossy().into_owned();
            let c = self.leg(
                rig,
                "suite-fetch",
                &[
                    "git", "clone", "--depth", "1", "--branch", SUITE_TAG, SUITE_REPO, &s,
                ],
                None,
                &[],
            );
            let head = crate::gitp::git(&suite, &["rev-parse", "HEAD"]).unwrap_or_default();
            if c != Some(0) || head.trim() != SUITE_COMMIT {
                return Err(format!(
                    "{SUITE_TAG} could not be fetched at {SUITE_COMMIT} (got `{}`)",
                    head.trim()
                ));
            }
        }
        let write = |name: &str, text: String| {
            std::fs::write(suite.join(name), text).map_err(|e| format!("{name}: {e}"))
        };
        write(
            "builder-compose.busbar.yml",
            format!("services:\n  builder:\n    image: {MAVEN_IMAGE}\n"),
        )?;
        write(
            "docker-compose.busbar.yml",
            format!(
                "services:\n  mongodb:\n    image: {MONGO_IMAGE}\n  server:\n    extra_hosts:\n      - \"{SUBJECT_HOST}:host-gateway\"\n"
            ),
        )?;
        if !suite.join("target/fapi-test-suite.jar").is_file() {
            let m2 = cache.join("m2");
            let _ = std::fs::create_dir_all(&m2);
            let c = self.leg(
                rig,
                "suite-build",
                &[
                    "docker",
                    "compose",
                    "-f",
                    "builder-compose.yml",
                    "-f",
                    "builder-compose.busbar.yml",
                    "run",
                    "--rm",
                    "builder",
                ],
                Some(&suite),
                &[("MAVEN_CACHE", m2.to_string_lossy().into_owned())],
            );
            if c != Some(0) || !suite.join("target/fapi-test-suite.jar").is_file() {
                return Err(format!(
                    "the suite's jar did not build ({})",
                    super::rigs::rc(c)
                ));
            }
        }
        let venv = cache.join("venv");
        if !venv.join("bin/python").is_file() {
            let v = venv.to_string_lossy().into_owned();
            let req = suite
                .join("scripts/requirements.txt")
                .to_string_lossy()
                .into_owned();
            let pip = venv.join("bin/pip").to_string_lossy().into_owned();
            if self.leg(
                rig,
                "runner-venv",
                &["python3", "-m", "venv", &v],
                None,
                &[],
            ) != Some(0)
                || self.leg(
                    rig,
                    "runner-deps",
                    &[&pip, "install", "-q", "-r", &req],
                    None,
                    &[],
                ) != Some(0)
            {
                let _ = std::fs::remove_dir_all(&venv);
                return Err("the suite runner's Python environment could not be built".into());
            }
        }
        if self.compose(&suite, &["up", "-d", "--build"], "suite-up") != Some(0) {
            return Err("`docker compose up` of the suite failed".into());
        }
        let deadline = Instant::now() + Duration::from_secs(300);
        let scratch = self.work_dir(rig).join("http");
        while Instant::now() < deadline {
            if curl(
                &scratch,
                "GET",
                "https://localhost:8443/api/runner/available",
                &[],
                None,
                &["-k"],
            )
            .is_ok_and(|r| r.status == 200)
            {
                return Ok(suite);
            }
            std::thread::sleep(Duration::from_secs(3));
        }
        Err("the suite's API never answered on https://localhost:8443 within 300s".into())
    }

    fn oidf_runs(
        &self,
        suite: &Path,
        dir: &Path,
        blank: &dyn Fn(Result<(), String>) -> OidfRun,
    ) -> BTreeMap<String, Outcome> {
        let rig = Rig::Oidf;
        let mut out = BTreeMap::new();
        let mut done: BTreeMap<String, Outcome> = BTreeMap::new();
        for plan in SUITES {
            let arg = plan.arg();
            if let Some(o) = done.get(&arg) {
                out.insert(plan.suite.to_string(), o.clone());
                continue;
            }
            let mut run = blank(Ok(()));
            match self.busbar() {
                Err(e) => run.subject = Err(e),
                Ok(bin) => {
                    let pdir = dir.join(plan.suite);
                    match self.oidf_subject(&bin, &pdir) {
                        Err(e) => {
                            run.subject = Err(e);
                            run.boot_failed = true;
                        }
                        Ok((booted, config)) => {
                            let venv_py = self.cache.join("oidf/venv/bin/python");
                            let py = venv_py.to_string_lossy().into_owned();
                            let cfg = config.to_string_lossy().into_owned();
                            let export = pdir.join("export").to_string_lossy().into_owned();
                            let leg = format!("run-{}", plan.suite);
                            run.exit = self.leg(
                                rig,
                                &leg,
                                &[
                                    &py,
                                    "scripts/run-test-plan.py",
                                    "--export-dir",
                                    &export,
                                    "--no-parallel",
                                    &arg,
                                    &cfg,
                                ],
                                Some(suite),
                                &[
                                    ("CONFORMANCE_SERVER", SUITE_URL.to_string()),
                                    ("CONFORMANCE_DEV_MODE", "1".to_string()),
                                    ("DISABLE_SSL_VERIFY", "1".to_string()),
                                    ("CI", "1".to_string()),
                                ],
                            );
                            run.log = self.log_text(rig, &leg);
                            run.evidence = self.rel(&pdir);
                            drop(booted);
                        }
                    }
                }
            }
            let o = decide_oidf(&run);
            done.insert(arg, o.clone());
            out.insert(plan.suite.to_string(), o);
        }
        out
    }

    /// Boot the authorization-server subject, register the plan's two clients through its own
    /// registration endpoint, and write the suite's plan configuration. `Err` is busbar's.
    fn oidf_subject(
        &self,
        bin: &Path,
        pdir: &Path,
    ) -> Result<(subject::Booted, std::path::PathBuf), String> {
        let ports = subject::free_ports(2)?;
        let (data, admin) = (ports[0], ports[1]);
        let issuer = format!("https://{SUBJECT_HOST}:{data}");
        let pki = subject::mint_pki(pdir, &[SUBJECT_HOST, "localhost", "127.0.0.1"])?;
        // The data listener is reachable from the suite's container; the admin listener is not.
        let config = format!(
            "{}tls:\n  cert: {{ file: {} }}\n  key: {{ file: {} }}\noauth_as:\n  issuer: \"{issuer}\"\n  default_grant: [{SCOPE}]\n",
            subject::base_config(&format!("0.0.0.0:{data}"), admin),
            pki.cert.display(),
            pki.key.display()
        );
        let booted = subject::boot(
            bin,
            &pdir.join("subject"),
            &config,
            subject::NO_PROVIDERS,
            &[],
            &format!("https://127.0.0.1:{data}/stats"),
            &["-k"],
        )
        .map_err(|e| format!("the authorization-server subject did not boot: {e}"))?;
        let resolve = format!("{SUBJECT_HOST}:{data}:127.0.0.1");
        let via = ["-k", "--resolve", resolve.as_str()];
        let scratch = pdir.join("http");
        let meta = curl(
            &scratch,
            "GET",
            &format!("{issuer}/.well-known/oauth-authorization-server"),
            &[],
            None,
            &via,
        )
        .map_err(|e| format!("the subject published no authorization-server metadata: {e}"))?;
        let meta: Value = serde_json::from_slice(&meta.body).map_err(|_| {
            format!(
                "the subject's authorization-server metadata ({}) is not JSON",
                meta.status
            )
        })?;
        let register = meta
            .get("registration_endpoint")
            .and_then(Value::as_str)
            .ok_or("the subject's metadata advertises no registration_endpoint")?
            .to_string();
        let callback = format!("{SUITE_URL}test/a/{ALIAS}/callback");
        let mut clients = Vec::new();
        for n in 1..=2 {
            let (private, public) = es256_jwk(&format!("{ALIAS}-{n}"))?;
            let body = json!({
                // Not the deployment's name: busbar's open registration refuses a client that
                // names itself after the gateway (busbar-core-oauth2 policy.rs, consent phishing).
                "client_name": format!("oidf-suite-client-{n}"),
                "redirect_uris": [callback],
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "private_key_jwt",
                "jwks": {"keys": [public]},
                "scope": SCOPE,
            });
            let r = curl(
                &scratch,
                "POST",
                &register,
                &[("content-type", "application/json")],
                Some(body.to_string().as_bytes()),
                &via,
            )
            .map_err(|e| format!("client registration got no answer: {e}"))?;
            let id = serde_json::from_slice::<Value>(&r.body)
                .ok()
                .and_then(|v| {
                    v.get("client_id")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                })
                .ok_or_else(|| {
                    format!(
                        "the subject refused the plan's client registration ({}): {}",
                        r.status,
                        String::from_utf8_lossy(&r.body)
                    )
                })?;
            clients.push(json!({"client_id": id, "scope": SCOPE, "jwks": {"keys": [private]}}));
        }
        let plan_config = json!({
            "alias": ALIAS,
            "description": format!("busbar {}", super::head_commit(&self.root).unwrap_or_default()),
            "server": {"discoveryUrl": format!("{issuer}/.well-known/oauth-authorization-server")},
            "client": clients[0],
            "client2": clients[1],
            "resource": {"resourceUrl": format!("{issuer}{RESOURCE_PATH}")},
            "browser": [{
                "match": format!("{issuer}/*"),
                "tasks": [
                    {
                        "task": "Approve on the consent screen",
                        "match": format!("{issuer}/*consent*"),
                        "commands": [["click", "xpath", "//button[@type='submit']"]]
                    },
                    {
                        "task": "Verify the callback",
                        "match": format!("{SUITE_URL}test/a/{ALIAS}/callback*"),
                        "commands": [["wait", "id", "submission_complete", 10]]
                    }
                ]
            }]
        });
        let path = pdir.join("plan-config.json");
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&plan_config).unwrap_or_default(),
        )
        .map_err(|e| format!("{}: {e}", path.display()))?;
        Ok((booted, path))
    }
}
