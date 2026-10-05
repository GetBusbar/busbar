//! THE jev (DECISIONS PLANE) RIG — the decisions plane's MUST-set coverage (BUSBAR-1.6.0.md #12,
//! #68: "conformance (mcp/a2a/streaming/decisions rigs)"), in Rust.
//!
//! Two legs, one verdict:
//!
//! * BATTERY — `cargo test -p busbar-plane-decisions`: the codec, the fixtures, the PII witness,
//!   purity and invariance, and the both-ways door. It says the plane reads and writes jev. It
//!   cannot say busbar SERVES jev, and a battery that selected zero tests says nothing at all.
//! * SERVED — a busbar built from this checkout, booted with exactly one `decisions.models` entry
//!   (the one shape that mounts `POST /v1/systemone`, `busbar-plane-decisions/src/driven.rs`),
//!   whose provider is a far end this rig owns ([`super::upstream::FarEnd`]). The leg judges the
//!   SERVED BYTES from both ends of the relay:
//!
//!   | check | what a correct busbar does | where it is ruled |
//!   |---|---|---|
//!   | `relay.request` | the far end receives `POST /v1/systemone` with the caller's body byte for byte | driven.rs `attempt`; codec.rs "byte-identity passthrough" |
//!   | `relay.credential` | the far end sees the provider's credential, never the caller's | plane.rs `authenticate`; HARD RULE "credential headers replaced from config" |
//!   | `relay.client-headers` | a caller header outside the deny-set reaches the far end unchanged | ARCHITECT ruling 2026-10-02 DEC-SERVE Q2 (DIALECT-FIDELITY F2) |
//!   | `relay.response` | the caller receives the far end's status and body byte for byte | plane.rs `encode_response`; driven.rs `FarEndReading::piece` |
//!   | `relay.error` | a far-end 422 reaches the caller as the far end's own 422 bytes | the same passthrough, on the error arm |
//!   | `refusal.unauthenticated` | no credential: refused before any far-end hop, `401`, body exactly `{"error":{"code":"invalid_request","message":<text>}}` | driven.rs `refusal_body`; plane.rs `authenticate` (no anonymous surface) |
//!   | `usage.billable-success-only` | the success posts one fee on the jev lane carrying the 42 units the far end reported, and the 422 posts nothing | meta.rs `CLASS_DECISION` + plane.rs `meter` (signed design C-3); ARCHITECT ruling 2026-10-02 (CONFORMANCE-RIGS Q4) |
//!
//!   `usage.billable-success-only` is read off `GET /api/v1/admin/ledger/totals` (ARCHITECT ruling
//!   2026-10-02): on the jev lane `fee_count` must be exactly 1 AND the reported units must show.
//!   The 1.6.0 node keeps its rows at bucket-day width (no lane, no provider), so there the jev
//!   lane's row is the rig's caller's own bucket ([`judge_jev_ledger`]).
//!   The subject's own card prices the `decision` class at 1 micro-unit per unit
//!   (`decisions.rate_card.<model>.units.decision: 1`, in the rig's generated config only), so the
//!   lane's `priced_micros` IS the unit count: 42.
//!
//! The rules, in order: battery red or empty ⇒ `fail`; no subject binary ⇒ `not-run` (nothing was
//! booted); a subject that does not boot ⇒ `fail`; `POST /v1/systemone` answering the absence code
//! measured on the same boot ⇒ `fail` "not served"; any served check red ⇒ `fail` naming it; every
//! check green ⇒ `pass`. `GET /v1/models` is not judged: that path keeps its 1.5.5 bytes.

use std::path::Path;

use serde_json::Value;

use super::rigs::{Rig, Runner};
use super::subject::{self, curl};
use super::upstream::FarEnd;
use super::Outcome;

/// The model name, provider name and the one path the decisions plane serves.
const MODEL: &str = "jev-1";
const PROVIDER: &str = "typesafe";
const PATH: &str = "/v1/systemone";
/// The header outside the deny-set the caller sends and the far end must receive unchanged.
const PROBE_HEADER: &str = "x-jev-conformance-probe";

/// The caller's request: odd whitespace and member order on purpose, so a relay that re-serialises
/// the document instead of forwarding its bytes is caught.
const REQUEST: &[u8] =
    b"{ \"state\" : {\"session\":\"conformance-state\",\"n\":[1, 2 ,3]},\n  \"context\":{} }";
/// The far end's success: the usage count the plane meters, the same odd spacing.
const SUCCESS: &[u8] =
    b"{\"request_id\" : \"req_conformance\", \"usage\":{\"units\":42},\"answers\":{\"decision\":\"approve\"}}";
/// The far end's 422, echoing state and answers (the PII witness fixture's shape).
const UNPROCESSABLE: &[u8] = b"{\"error\":{\"code\":\"invalid_state\",\"message\":\"bad transition\"},\"state\":{\"session\":\"conformance-state\"},\"answers\":{\"leaked\":\"never\"}}";

/// What the jev rig measured.
#[derive(Debug, Clone)]
pub struct JevRun {
    /// `cargo test -p busbar-plane-decisions`'s exit.
    pub battery: Option<i32>,
    /// The tests cargo says passed, summed over every test binary.
    pub battery_tests: u64,
    /// `Err` = there is no subject binary, and why.
    pub build: Result<(), String>,
    /// `Err` = the subject did not boot, and why.
    pub boot: Result<(), String>,
    /// The status a path no plane can own answers on this boot.
    pub absent: Option<u16>,
    /// The status `POST /v1/systemone` answered.
    pub served: Option<u16>,
    /// Each served check by name: `Ok` or the finding.
    pub checks: Vec<(String, Result<(), String>)>,
    pub evidence: String,
}

impl JevRun {
    /// Nothing measured yet: no battery, no subject, no served answer.
    pub fn new(evidence: impl Into<String>) -> JevRun {
        JevRun {
            battery: None,
            battery_tests: 0,
            build: Err("the battery is red, so no subject was built".to_string()),
            boot: Err("no subject was booted".to_string()),
            absent: None,
            served: None,
            checks: Vec::new(),
            evidence: evidence.into(),
        }
    }
}

/// The sum of cargo's `test result: ok. N passed` lines.
pub fn tests_passed(cargo_output: &str) -> u64 {
    cargo_output
        .lines()
        .filter_map(|l| l.trim().strip_prefix("test result: ok. "))
        .filter_map(|r| r.split_whitespace().next()?.parse::<u64>().ok())
        .sum()
}

pub fn decide_jev(run: &JevRun) -> Outcome {
    let ev = run.evidence.clone();
    if run.battery != Some(0) {
        return Outcome::fail(
            format!(
                "battery: cargo test -p busbar-plane-decisions {}",
                match run.battery {
                    Some(c) => format!("exited {c}"),
                    None => "did not finish".to_string(),
                }
            ),
            ev,
        );
    }
    if run.battery_tests == 0 {
        return Outcome::fail(
            "battery: cargo test -p busbar-plane-decisions passed 0 tests; a battery that selects \
             nothing proves nothing",
            ev,
        );
    }
    if let Err(why) = &run.build {
        return Outcome::not_run(format!(
            "served: no subject binary ({why}), so nothing was booted"
        ));
    }
    if let Err(why) = &run.boot {
        return Outcome::fail(
            format!("served: the subject did not boot with one decisions model: {why}"),
            ev,
        );
    }
    let Some(absent) = run.absent.filter(|a| *a != 0) else {
        return Outcome::fail(
            "served: the absence code was never measured on this boot, so nothing was judged",
            ev,
        );
    };
    let Some(code) = run.served.filter(|c| *c != 0) else {
        return Outcome::fail("served: POST /v1/systemone got no answer", ev);
    };
    if code == absent {
        return Outcome::fail(
            format!(
                "not served: POST /v1/systemone answers {code}, the absence code on this boot; one \
                 decisions model is configured and no route serves its operation"
            ),
            ev,
        );
    }
    if run.checks.is_empty() {
        return Outcome::fail("served: the served battery judged nothing", ev);
    }
    let red: Vec<String> = run
        .checks
        .iter()
        .filter_map(|(name, r)| r.as_ref().err().map(|e| format!("{name}: {e}")))
        .collect();
    if red.is_empty() {
        Outcome::pass(ev)
    } else {
        Outcome::fail(
            format!(
                "{} of {} served check(s) red: {}",
                red.len(),
                run.checks.len(),
                red.join("; ")
            ),
            ev,
        )
    }
}

/// The refusal shape driven.rs `refusal_body` writes: exactly `{"error":{"code","message"}}`,
/// both strings, the message non-empty, and nothing else at either level.
pub fn is_jev_refusal(body: &[u8], code: &str) -> Result<(), String> {
    let v: Value =
        serde_json::from_slice(body).map_err(|e| format!("the refusal body is not JSON ({e})"))?;
    let top = v.as_object().ok_or("the refusal body is not an object")?;
    let err = top
        .get("error")
        .and_then(Value::as_object)
        .ok_or("the refusal body has no `error` object")?;
    if top.len() != 1 || err.len() != 2 {
        return Err(format!(
            "the refusal body carries members beyond {{\"error\":{{\"code\",\"message\"}}}}: {v}"
        ));
    }
    match (
        err.get("code").and_then(Value::as_str),
        err.get("message").and_then(Value::as_str),
    ) {
        (Some(c), Some(m)) if c == code && !m.is_empty() => Ok(()),
        _ => Err(format!(
            "the refusal body is not {{\"error\":{{\"code\":\"{code}\",\"message\":<text>}}}}: {v}"
        )),
    }
}

/// The units the far end reports on the success (`SUCCESS`'s `/usage/units`).
pub const REPORTED_UNITS: u64 = 42;

/// THE BILLING JUDGEMENT over `GET /api/v1/admin/ledger/totals` after one success and one 422: on
/// the jev lane exactly one fee, priced at exactly [`REPORTED_UNITS`] micro-units (the card prices
/// one unit at one micro-unit). A row is the jev lane's when it names it (`lane`/`provider`), or,
/// at the width the 1.6.0 node keeps (no lane, no provider: every row is a bucket-day), when it is
/// the rig's caller's own bucket (`bucket`, the key the rig minted and served under). Every other
/// row is another lane's or another caller's and is not read.
pub fn judge_jev_ledger(totals: &[u8], bucket: &str) -> Result<(), String> {
    let v: Value =
        serde_json::from_slice(totals).map_err(|e| format!("ledger/totals is not JSON ({e})"))?;
    let rows = v
        .get("rows")
        .and_then(Value::as_array)
        .ok_or("ledger/totals has no `rows`")?;
    let mine: Vec<&Value> = rows
        .iter()
        .filter(|r| {
            let (lane, provider) = (
                r.get("lane").and_then(Value::as_str),
                r.get("provider").and_then(Value::as_str),
            );
            (lane == Some(MODEL) && provider == Some(PROVIDER))
                || (lane == Some("")
                    && provider == Some("")
                    && r.get("bucket").and_then(Value::as_str) == Some(bucket))
        })
        .collect();
    let fees: u64 = mine
        .iter()
        .filter_map(|r| r.get("fee_count").and_then(Value::as_u64))
        .sum();
    let mut micros: u128 = 0;
    for r in &mine {
        let text = r
            .get("priced_micros")
            .and_then(Value::as_str)
            .ok_or("a jev ledger row carries no priced_micros text")?;
        micros += text
            .parse::<u128>()
            .map_err(|_| format!("priced_micros `{text}` is not a non-negative integer"))?;
    }
    if fees != 1 {
        return Err(format!(
            "ledger/totals counts {fees} fee(s) on lane {MODEL}/{PROVIDER} after one success and \
             one 422; billable-success-only is exactly 1"
        ));
    }
    if micros != u128::from(REPORTED_UNITS) {
        return Err(format!(
            "the jev lane is priced at {micros} micro-unit(s); the far end reported \
             {REPORTED_UNITS} units at 1 micro-unit each, so the ledger must show {REPORTED_UNITS}"
        ));
    }
    Ok(())
}

/// The subject's generated config: one decisions model on the rig's far end, a data-plane key
/// chain, the admin token, the decision class priced at 1 micro-unit per unit, and the far end's
/// loopback address declared as an allowed destination (`advanced.allow_destinations`), as an
/// operator declares one, so the connector's default destination guard (private, loopback and
/// metadata addresses refused, QUESTIONS Q130/Q131) admits the dial. The oidf rig declares its IdP
/// stub the same way. It names its store (`store: {module: memory}`), as every config must (owner ruling Q-STORE (B)).
pub fn jev_subject_config(data: u16, admin: u16, key_file: &Path) -> String {
    format!(
        "listen: \"127.0.0.1:{data}\"\n\
         store: {{ module: memory }}\n\
         admin_listen: \"127.0.0.1:{admin}\"\n\
         providers:\n  {PROVIDER}:\n    api_key: {{ env: JEV_CONFORMANCE_PROVIDER_KEY }}\n\
         models: {{}}\n\
         identity-providers:\n  admin-tokens: {{ module: admin-tokens, token: {{ env: BUSBAR_ADMIN_TOKEN }} }}\n\
         auth:\n  chain: [keys]\n  admin_auth: [admin-tokens]\n  signing_key: {{ file: {} }}\n\
         advanced:\n  allow_destinations: [\"127.0.0.1\"]\n\
         decisions:\n  models:\n    {MODEL}:\n      provider: {PROVIDER}\n\
         \x20 rate_card:\n    {MODEL}: {{ units: {{ decision: 1 }} }}\n",
        key_file.display()
    )
}

fn check(ok: bool, finding: impl FnOnce() -> String) -> Result<(), String> {
    if ok {
        Ok(())
    } else {
        Err(finding())
    }
}

fn show(b: &[u8]) -> String {
    let s = String::from_utf8_lossy(b);
    if s.len() > 160 {
        format!(
            "{}…",
            &s[..s.char_indices().nth(160).map(|(i, _)| i).unwrap_or(s.len())]
        )
    } else {
        s.into_owned()
    }
}

impl Runner {
    pub(super) fn run_jev(&self) -> Outcome {
        let rig = Rig::Jev;
        if let Some(o) = self.missing(rig, &["cargo", "curl"]) {
            return o;
        }
        let dir = self.work_dir(rig);
        let mut run = JevRun::new(self.rel(&dir));
        run.battery = self.leg(
            rig,
            "battery",
            &["cargo", "test", "-p", "busbar-plane-decisions"],
            None,
            &[],
        );
        run.battery_tests = tests_passed(&self.log_text(rig, "battery"));
        if run.battery == Some(0) && run.battery_tests > 0 {
            match self.busbar() {
                Ok(bin) => {
                    run.build = Ok(());
                    run.boot = Ok(());
                    self.served(&bin, &dir, &mut run);
                }
                Err(e) => run.build = Err(e),
            }
        }
        decide_jev(&run)
    }

    fn served(&self, bin: &Path, dir: &Path, run: &mut JevRun) {
        let scratch = dir.join("http");
        let far = match FarEnd::start() {
            Ok(f) => f,
            Err(e) => {
                run.boot = Err(e);
                return;
            }
        };
        let (ports, admin_token, provider_key) = match (
            subject::free_ports(2),
            subject::random_hex(24),
            subject::random_hex(16),
        ) {
            (Ok(p), Ok(a), Ok(k)) => (p, a, k),
            (p, a, k) => {
                run.boot = Err([p.err(), a.err(), k.err()]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>()
                    .join("; "));
                return;
            }
        };
        let (data, admin) = (ports[0], ports[1]);
        let key_file = match subject::signing_key(bin, dir) {
            Ok(k) => k,
            Err(e) => {
                run.boot = Err(e);
                return;
            }
        };
        let config = jev_subject_config(data, admin, &key_file);
        let providers = format!(
            "{PROVIDER}:\n  protocol: jev\n  base_url: http://127.0.0.1:{}\n  error_map: {{}}\n",
            far.port
        );
        let booted = match subject::boot(
            bin,
            dir,
            &config,
            &providers,
            &[
                ("BUSBAR_ADMIN_TOKEN", admin_token.clone()),
                ("JEV_CONFORMANCE_PROVIDER_KEY", provider_key.clone()),
            ],
            &format!("http://127.0.0.1:{data}/stats"),
            &[],
        ) {
            Ok(b) => b,
            Err(e) => {
                run.boot = Err(e);
                return;
            }
        };
        let base = format!("http://127.0.0.1:{data}");
        run.absent = curl(
            &scratch,
            "POST",
            &format!("{base}/.jev-conformance/no-such-route-any-plane-could-own"),
            &[("content-type", "application/json")],
            Some(b"{}"),
            &[],
        )
        .ok()
        .map(|r| r.status);
        let (client_key, client_id) =
            match subject::mint_key(&scratch, admin, &admin_token, "jev-conformance") {
                Ok(k) => k,
                Err(e) => {
                    run.boot = Err(format!("{e}: {}", booted.log_tail()));
                    return;
                }
            };
        let bearer = format!("Bearer {client_key}");
        let nonce = subject::random_hex(8).unwrap_or_else(|_| "probe".to_string());
        let send = |auth: bool| {
            let mut h: Vec<(&str, &str)> = vec![
                ("content-type", "application/json"),
                (PROBE_HEADER, nonce.as_str()),
            ];
            if auth {
                h.push(("authorization", bearer.as_str()));
            }
            curl(
                &scratch,
                "POST",
                &format!("{base}{PATH}"),
                &h,
                Some(REQUEST),
                &[],
            )
        };

        // 1. A success, relayed both ways.
        far.reply(200, SUCCESS);
        let ok = send(true);
        run.served = ok.as_ref().ok().map(|r| r.status);
        if run.served.is_none() || run.served == run.absent {
            return;
        }
        let seen = far.seen();
        let first = seen.first();
        run.checks.push((
            "relay.request".into(),
            match first {
                None => Err("the far end received nothing".into()),
                Some(s) => check(
                    seen.len() == 1 && s.method == "POST" && s.path == PATH && s.body == REQUEST,
                    || {
                        format!(
                        "the far end received {} request(s); the first was {} {} with body `{}`, \
                         not POST {PATH} with the caller's bytes",
                        seen.len(),
                        s.method,
                        s.path,
                        show(&s.body)
                    )
                    },
                ),
            },
        ));
        run.checks.push((
            "relay.credential".into(),
            match first {
                None => Err("the far end received nothing".into()),
                Some(s) => {
                    let auth = s.header("authorization");
                    let leaked = s
                        .headers
                        .iter()
                        .any(|(_, v)| v.contains(client_key.as_str()));
                    check(
                        auth == [format!("Bearer {provider_key}").as_str()] && !leaked,
                        || {
                            format!(
                                "the far end saw {} authorization value(s){}; it must see the \
                                 provider's credential alone",
                                auth.len(),
                                if leaked {
                                    ", one carrying the caller's key"
                                } else {
                                    ""
                                }
                            )
                        },
                    )
                }
            },
        ));
        run.checks.push((
            "relay.client-headers".into(),
            match first {
                None => Err("the far end received nothing".into()),
                Some(s) => check(s.header(PROBE_HEADER) == [nonce.as_str()], || {
                    format!(
                        "the caller's `{PROBE_HEADER}` reached the far end as {:?}",
                        s.header(PROBE_HEADER)
                    )
                }),
            },
        ));
        run.checks.push((
            "relay.response".into(),
            match &ok {
                Ok(r) => check(r.status == 200 && r.body == SUCCESS, || {
                    format!(
                        "the caller got {} `{}`, not the far end's 200 bytes",
                        r.status,
                        show(&r.body)
                    )
                }),
                Err(e) => Err(e.clone()),
            },
        ));

        // 2. A far-end 422, relayed as the far end's own bytes.
        far.reply(422, UNPROCESSABLE);
        run.checks.push((
            "relay.error".into(),
            match send(true) {
                Ok(r) => check(r.status == 422 && r.body == UNPROCESSABLE, || {
                    format!(
                        "the caller got {} `{}`, not the far end's 422 bytes",
                        r.status,
                        show(&r.body)
                    )
                }),
                Err(e) => Err(e),
            },
        ));

        // 3. No credential: refused in jev's shape, before any hop.
        let before = far.seen().len();
        run.checks.push((
            "refusal.unauthenticated".into(),
            match send(false) {
                Ok(r) => {
                    let hops = far.seen().len() - before;
                    if r.status != 401 {
                        Err(format!(
                            "an unauthenticated call answered {}, not 401",
                            r.status
                        ))
                    } else if hops != 0 {
                        Err(format!(
                            "an unauthenticated call reached the far end ({hops} hop(s))"
                        ))
                    } else {
                        is_jev_refusal(&r.body, "invalid_request")
                    }
                }
                Err(e) => Err(e),
            },
        ));

        // 4. One billable success, one 422: one fee on the jev lane, carrying the 42 units.
        let admin_bearer = format!("Bearer {admin_token}");
        run.checks.push((
            "usage.billable-success-only".into(),
            curl(
                &scratch,
                "GET",
                &format!("http://127.0.0.1:{admin}/api/v1/admin/ledger/totals"),
                &[("authorization", admin_bearer.as_str())],
                None,
                &[],
            )
            .and_then(|r| {
                if r.status != 200 {
                    return Err(format!("ledger/totals answered {}", r.status));
                }
                judge_jev_ledger(&r.body, &client_id)
            }),
        ));
        drop(booted);
    }
}
