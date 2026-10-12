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
//!   THE GATING CHECKS (BUSBAR-1.6.0.md THE DESIGN §1, H2: "conformance rigs carry one cell per
//!   Teller step per plane"), each named as its cell is in `qa/teller-steps.json`
//!   (`matrix.decision.<step>.cell` = `jev.rig|<check>`), each judging DELTAS it reads itself on the
//!   same boot, after the checks above:
//!
//!   | check | step | what a correct busbar does |
//!   |---|---|---|
//!   | `h2-authenticate-refusal` | authenticate | a forged bearer: `401` in jev's shape, no far-end hop, the ledger unmoved |
//!   | `h2-meter-row` | meter | one success moves the jev lane by exactly one fee priced at the 42 units it reported |
//!   | `h2-audit-record` | audit | one success seals exactly one `systemone` record, `Completed` (`GET /api/v1/admin/audit/head` + `/range`) |
//!   | `h2-exit-terminal` | encode (exit) | two successes: two answers each the far end's bytes over one dial, exactly two fees, exactly two records |
//!   | `h2-verify-refusal` | verify | a key granted only another pool (`allowed_pools`): `403` before Admit, no hop, nothing charged, no request counted |
//!   | `h2-admit-refusal` | admit | a key whose group allows one request a day: served once, then `429` before the dial, nothing charged, no request counted |
//!   | `h2-route-terminal` | route | the sole member answers `503`: the unit ends in a terminal 5xx in jev's shape, never the far end's bytes, nothing charged |
//!
//!   The route check runs last: the down lane benches the sole member for its cooldown. On this
//!   plane a key's grant over the routed provider is judged over Verify's sealed set, so the verify
//!   check's refusal is the kernel's answer before Admit draws (door_steps.rs `approve`).
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
use std::time::{Duration, Instant};

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
pub const SUCCESS: &[u8] =
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
/// both strings, the message non-empty, and nothing else at either level. Answers the code word.
pub fn jev_refusal_code(body: &[u8]) -> Result<String, String> {
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
        (Some(c), Some(m)) if !c.is_empty() && !m.is_empty() => Ok(c.to_string()),
        _ => Err(format!(
            "the refusal body is not {{\"error\":{{\"code\":<word>,\"message\":<text>}}}}: {v}"
        )),
    }
}

/// [`jev_refusal_code`], holding the code word to `code`.
pub fn is_jev_refusal(body: &[u8], code: &str) -> Result<(), String> {
    let got = jev_refusal_code(body)?;
    if got == code {
        Ok(())
    } else {
        Err(format!(
            "the refusal body is not {{\"error\":{{\"code\":\"{code}\",\"message\":<text>}}}}: \
             its code is `{got}`"
        ))
    }
}

/// The units the far end reports on the success (`SUCCESS`'s `/usage/units`).
pub const REPORTED_UNITS: u64 = 42;

/// What a set of ledger rows adds up to: the fees counted and the micro-units priced.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Spend {
    pub fees: u64,
    pub micros: u128,
}

/// The rows of `GET /api/v1/admin/ledger/totals`, summed. `bucket: Some(b)` reads the jev lane's
/// rows only: a row that names the lane (`lane`/`provider`), or, at the width the 1.6.0 node keeps
/// (no lane, no provider: every row is a bucket-day), the caller `b`'s own bucket. `None` reads
/// every row on the node: what "nothing was charged to anyone" is judged over.
pub fn ledger_spend(totals: &[u8], bucket: Option<&str>) -> Result<Spend, String> {
    let v: Value =
        serde_json::from_slice(totals).map_err(|e| format!("ledger/totals is not JSON ({e})"))?;
    let rows = v
        .get("rows")
        .and_then(Value::as_array)
        .ok_or("ledger/totals has no `rows`")?;
    let mut spend = Spend::default();
    for r in rows.iter().filter(|r| {
        let Some(bucket) = bucket else {
            return true;
        };
        let (lane, provider) = (
            r.get("lane").and_then(Value::as_str),
            r.get("provider").and_then(Value::as_str),
        );
        (lane == Some(MODEL) && provider == Some(PROVIDER))
            || (lane == Some("")
                && provider == Some("")
                && r.get("bucket").and_then(Value::as_str) == Some(bucket))
    }) {
        spend.fees += r.get("fee_count").and_then(Value::as_u64).unwrap_or(0);
        let text = r
            .get("priced_micros")
            .and_then(Value::as_str)
            .ok_or("a ledger row carries no priced_micros text")?;
        spend.micros += text
            .parse::<u128>()
            .map_err(|_| format!("priced_micros `{text}` is not a non-negative integer"))?;
    }
    Ok(spend)
}

/// THE BILLING JUDGEMENT over `GET /api/v1/admin/ledger/totals` after one success and one 422: on
/// the jev lane ([`ledger_spend`] with the rig's caller's bucket) exactly one fee, priced at
/// exactly [`REPORTED_UNITS`] micro-units (the card prices one unit at one micro-unit). Every other
/// row is another lane's or another caller's and is not read.
pub fn judge_jev_ledger(totals: &[u8], bucket: &str) -> Result<(), String> {
    let Spend { fees, micros } = ledger_spend(totals, Some(bucket))?;
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

// ── THE GATING CHECKS: one per Teller step H2 gates (qa/teller-steps.json `matrix.decision`) ──
//
// Each check's name is its cell's id in the teller-steps matrix, `jev.rig|<name>`, and the gate
// resolves the cell to this file only while it still declares the name. Each is judged by a pure
// function over what the rig observed, so its red arm is a test over a bad observation
// (xtask/tests/conformance_rigs.rs), and the served leg only gathers.

/// AUTHENTICATE: a bad credential is refused before Verify, with zero egress.
pub const H2_AUTHENTICATE: &str = "h2-authenticate-refusal";
/// VERIFY: a credential holding no grant for the decision provider is refused before Admit draws.
pub const H2_VERIFY: &str = "h2-verify-refusal";
/// ADMIT: a key past its group's request budget is refused before Route dials, and charged nothing.
pub const H2_ADMIT: &str = "h2-admit-refusal";
/// ROUTE: the sole member down, the unit ends terminal within itself.
pub const H2_ROUTE: &str = "h2-route-terminal";
/// METER: the usage delta of exactly one request, priced.
pub const H2_METER: &str = "h2-meter-row";
/// AUDIT: the audit chain gains exactly one entry, the right operation and outcome.
pub const H2_AUDIT: &str = "h2-audit-record";
/// ENCODE (THE DESIGN's exit): one terminal per unit, never a double post.
pub const H2_EXIT: &str = "h2-exit-terminal";

/// The seven gating checks, in the Teller's order.
pub const H2_CHECKS: [&str; 7] = [
    H2_AUTHENTICATE,
    H2_VERIFY,
    H2_ADMIT,
    H2_ROUTE,
    H2_METER,
    H2_AUDIT,
    H2_EXIT,
];

/// The operation class every unit on `POST /v1/systemone` is sealed under on the audit chain
/// (`busbar-plane-decisions` ops.rs `OP_SYSTEMONE`).
pub const AUDIT_OP_CLASS: &str = "systemone";

/// The far end's transient failure: the down lane the route check dials.
pub const UNAVAILABLE: &[u8] =
    b"{\"error\":{\"code\":\"unavailable\",\"message\":\"the decision service is down\"}}";

/// One call as the rig saw it from both ends: what the caller got, and how many requests reached
/// the far end while it was in flight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    pub status: u16,
    pub body: Vec<u8>,
    pub hops: usize,
}

fn unchanged(before: Spend, after: Spend) -> Result<(), String> {
    check(before == after, || {
        format!(
            "the ledger moved from {} fee(s) / {} micro-unit(s) to {} / {}; a refused unit is \
             charged nothing",
            before.fees, before.micros, after.fees, after.micros
        )
    })
}

/// A unit refused before its dial: the `status` refusal in jev's shape with `code`, no request at
/// the far end, nothing on the ledger, and (where the key's usage was read) no request counted.
pub fn judge_refused_before_dial(
    call: &Call,
    status: u16,
    code: &str,
    spend: (Spend, Spend),
    requests: Option<(u64, u64)>,
) -> Result<(), String> {
    if call.status != status {
        return Err(format!(
            "answered {} `{}`, not the {status} refusal",
            call.status,
            show(&call.body)
        ));
    }
    if call.hops != 0 {
        return Err(format!(
            "the refused unit reached the far end ({} hop(s)); it must be refused before the dial",
            call.hops
        ));
    }
    is_jev_refusal(&call.body, code)?;
    unchanged(spend.0, spend.1)?;
    match requests {
        Some((was, now)) if was != now => Err(format!(
            "the key's usage counts {was} request(s) before the refusal and {now} after; a \
             refused unit counts none"
        )),
        _ => Ok(()),
    }
}

/// ADMIT: the key's one budgeted request is served, then the next is refused `429` before its dial
/// and charged nothing.
pub fn judge_admit(
    first: &Call,
    second: &Call,
    spend: (Spend, Spend),
    requests: (u64, u64),
) -> Result<(), String> {
    if first.status != 200 || first.hops != 1 {
        return Err(format!(
            "the key's one budgeted request answered {} with {} hop(s), not a served 200; the \
             refusal after it judges nothing",
            first.status, first.hops
        ));
    }
    judge_refused_before_dial(second, 429, "unsupported_operation", spend, Some(requests))
}

/// One served success, relayed byte for byte through exactly one dial.
fn served_once(call: &Call) -> Result<(), String> {
    check(
        call.status == 200 && call.body == SUCCESS && call.hops == 1,
        || {
            format!(
                "a success answered {} `{}` over {} hop(s), not the far end's 200 bytes over one",
                call.status,
                show(&call.body),
                call.hops
            )
        },
    )
}

/// The ledger moved by exactly `n` fees and `n` × [`REPORTED_UNITS`] micro-units.
fn moved_by(spend: (Spend, Spend), n: u64) -> Result<(), String> {
    let (before, after) = spend;
    let fees = after.fees.checked_sub(before.fees);
    let micros = after.micros.checked_sub(before.micros);
    let want = u128::from(n * REPORTED_UNITS);
    check(fees == Some(n) && micros == Some(want), || {
        format!(
            "the jev lane moved from {} fee(s) / {} micro-unit(s) to {} / {} over {n} served \
             request(s); exactly {n} fee(s) and {want} micro-unit(s) are owed",
            before.fees, before.micros, after.fees, after.micros
        )
    })
}

/// METER: one served request moves the jev lane by exactly one fee priced at the units it reported.
pub fn judge_meter(call: &Call, spend: (Spend, Spend)) -> Result<(), String> {
    served_once(call)?;
    moved_by(spend, 1)
}

/// The window of the audit chain the rig read (`GET /api/v1/admin/audit/range`): exactly `want`
/// records under [`AUDIT_OP_CLASS`], each `Completed`. Records of any other operation class (an
/// admin read is a unit of its own) are not this plane's and are not counted.
pub fn judge_audit_window(range: &[u8], want: usize) -> Result<(), String> {
    let v: Value =
        serde_json::from_slice(range).map_err(|e| format!("the audit range is not JSON ({e})"))?;
    let records = v
        .get("records")
        .and_then(Value::as_array)
        .ok_or("the audit range has no `records`")?;
    let mine: Vec<&Value> = records
        .iter()
        .filter(|r| r.get("op_class").and_then(Value::as_str) == Some(AUDIT_OP_CLASS))
        .collect();
    if mine.len() != want {
        return Err(format!(
            "the audit chain gained {} `{AUDIT_OP_CLASS}` record(s) over {want} served unit(s); \
             exactly {want} is owed",
            mine.len()
        ));
    }
    match mine
        .iter()
        .find(|r| r.get("outcome").and_then(Value::as_str) != Some("Completed"))
    {
        Some(r) => Err(format!(
            "a served unit's record carries outcome {}, not Completed",
            r.get("outcome").unwrap_or(&Value::Null)
        )),
        None => Ok(()),
    }
}

/// AUDIT: one served request, one `Completed` record under the plane's operation class.
pub fn judge_audit(call: &Call, range: &[u8]) -> Result<(), String> {
    served_once(call)?;
    judge_audit_window(range, 1)
}

/// ENCODE: two served units leave through one terminal each: two answers each the far end's bytes
/// over one dial, exactly two fees on the lane and exactly two records on the chain.
pub fn judge_exit(calls: &[Call], spend: (Spend, Spend), range: &[u8]) -> Result<(), String> {
    if calls.len() != 2 {
        return Err(format!("{} call(s) were judged, not two", calls.len()));
    }
    for call in calls {
        served_once(call)?;
    }
    moved_by(spend, 2)?;
    judge_audit_window(range, 2)
}

/// ROUTE: the sole member answers a transient failure; the unit ends terminal within itself: a 5xx
/// in jev's refusal shape (the walk's terminal, never the far end's own bytes relayed), the down
/// lane having been dialled, and nothing charged.
pub fn judge_route(call: &Call, far: &[u8], spend: (Spend, Spend)) -> Result<(), String> {
    if !(500..=599).contains(&call.status) {
        return Err(format!(
            "the down lane's unit answered {} `{}`, not a terminal 5xx",
            call.status,
            show(&call.body)
        ));
    }
    if call.hops == 0 {
        return Err("the unit never dialled the lane it was routed to".to_string());
    }
    if call.body == far {
        return Err(
            "the far end's own failure bytes were relayed; a transient failure ends in the \
             walk's terminal"
                .to_string(),
        );
    }
    jev_refusal_code(&call.body)?;
    unchanged(spend.0, spend.1)
}

/// The group whose keys may make one request a day: the admit check's budget.
pub const ONE_REQUEST_GROUP: &str = "jev-conformance-one-request";

/// The only pool the verify check's key is granted: not the decision provider.
pub const ELSEWHERE: &str = "jev-conformance-elsewhere";

/// The subject's generated config: one decisions model on the rig's far end, a data-plane key
/// chain, the admin token, the [`ONE_REQUEST_GROUP`], the decision class priced at 1 micro-unit per
/// unit, and the far end's loopback address declared as an allowed destination
/// (`advanced.allow_destinations`), as an operator declares one, so the connector's default
/// destination guard (private, loopback and metadata addresses refused, QUESTIONS Q130/Q131) admits
/// the dial. The oidf rig declares its IdP stub the same way. It names its store (`store: {module:
/// memory}`), as every config must (owner ruling Q-STORE (B)).
pub fn jev_subject_config(data: u16, admin: u16, key_file: &Path) -> String {
    format!(
        "listen: \"127.0.0.1:{data}\"\n\
         admin_listen: \"127.0.0.1:{admin}\"\n\
         store: {{ module: memory }}\n\
         providers:\n  {PROVIDER}:\n    api_key: {{ env: JEV_CONFORMANCE_PROVIDER_KEY }}\n\
         models: {{}}\n\
         identity-providers:\n  admin-tokens: {{ module: admin-tokens, token: {{ env: BUSBAR_ADMIN_TOKEN }} }}\n\
         auth:\n  chain: [keys]\n  admin_auth: [admin-tokens]\n  signing_key: {{ file: {} }}\n\
         advanced:\n  allow_destinations: [\"127.0.0.1\"]\n\
         groups:\n  {ONE_REQUEST_GROUP}:\n    limits:\n      - {{ requests: 1, per: day }}\n\
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

        // 5. THE GATING CHECKS, one per Teller step, each judged over deltas it reads itself.
        let gate = Gate {
            scratch: &scratch,
            far: &far,
            data_url: format!("{base}{PATH}"),
            admin_url: format!("http://127.0.0.1:{admin}"),
            admin_bearer: &admin_bearer,
            nonce: &nonce,
        };
        let client = format!("Bearer {client_key}");
        let minted = |body: Value| {
            subject::mint_key_with(&scratch, admin, &admin_token, &body)
                .map(|(token, id)| (format!("Bearer {token}"), id))
        };
        run.checks.extend([
            (H2_AUTHENTICATE.to_string(), gate.authenticate(&client_key)),
            (H2_METER.to_string(), gate.meter(&client, &client_id)),
            (H2_AUDIT.to_string(), gate.audit(&client)),
            (H2_EXIT.to_string(), gate.exit(&client, &client_id)),
            (
                H2_VERIFY.to_string(),
                minted(serde_json::json!({ "name": ELSEWHERE, "allowed_pools": [ELSEWHERE] }))
                    .and_then(|(bearer, id)| gate.verify(&bearer, &id)),
            ),
            (
                H2_ADMIT.to_string(),
                minted(serde_json::json!({
                    "name": ONE_REQUEST_GROUP,
                    "group": ONE_REQUEST_GROUP,
                }))
                .and_then(|(bearer, id)| gate.admit(&bearer, &id)),
            ),
            // Last: the down lane benches the sole member for its cooldown.
            (H2_ROUTE.to_string(), gate.route(&client)),
        ]);
        drop(booted);
    }
}

/// How long a read waits for the node's postings and seals to land before it is final.
const SETTLE: Duration = Duration::from_millis(300);
/// How long a read waits for a posting or a seal the rig is owed.
const OWED_WITHIN: Duration = Duration::from_secs(5);

/// Read until `done` holds (or [`OWED_WITHIN`] passes), then once more after [`SETTLE`]: the final
/// read is the one judged, so a late second posting is seen rather than raced past.
fn settled<T>(
    mut read: impl FnMut() -> Result<T, String>,
    done: impl Fn(&T) -> bool,
) -> Result<T, String> {
    let deadline = Instant::now() + OWED_WITHIN;
    loop {
        let v = read()?;
        if done(&v) || Instant::now() >= deadline {
            std::thread::sleep(SETTLE);
            return read();
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// The records under [`AUDIT_OP_CLASS`] in an audit range body (0 for one that does not read).
fn op_records(range: &[u8]) -> usize {
    serde_json::from_slice::<Value>(range)
        .ok()
        .and_then(|v| {
            v.get("records").and_then(Value::as_array).map(|r| {
                r.iter()
                    .filter(|r| r.get("op_class").and_then(Value::as_str) == Some(AUDIT_OP_CLASS))
                    .count()
            })
        })
        .unwrap_or(0)
}

/// The caller's key with its last character changed: a credential of the right shape that no key
/// on the node holds.
fn forged(key: &str) -> String {
    let mut k = key.to_string();
    let swap = if k.ends_with('a') { 'b' } else { 'a' };
    k.pop();
    k.push(swap);
    k
}

/// What the gating checks read through: the far end, the data path and the admin reads.
struct Gate<'a> {
    scratch: &'a Path,
    far: &'a FarEnd,
    data_url: String,
    admin_url: String,
    admin_bearer: &'a str,
    nonce: &'a str,
}

impl Gate<'_> {
    /// One call on the decisions path as `bearer` (`None`: no credential), and the far-end hops it
    /// made.
    fn call(&self, bearer: Option<&str>) -> Result<Call, String> {
        let before = self.far.seen().len();
        let mut h: Vec<(&str, &str)> = vec![
            ("content-type", "application/json"),
            (PROBE_HEADER, self.nonce),
        ];
        if let Some(b) = bearer {
            h.push(("authorization", b));
        }
        let r = curl(self.scratch, "POST", &self.data_url, &h, Some(REQUEST), &[])?;
        Ok(Call {
            status: r.status,
            body: r.body,
            hops: self.far.seen().len() - before,
        })
    }

    /// One served call: the far end queued with exactly one success first.
    fn success(&self, bearer: &str) -> Result<Call, String> {
        self.far.clear_replies();
        self.far.reply(200, SUCCESS);
        self.call(Some(bearer))
    }

    fn admin_get(&self, path: &str) -> Result<Vec<u8>, String> {
        let r = curl(
            self.scratch,
            "GET",
            &format!("{}{path}", self.admin_url),
            &[("authorization", self.admin_bearer)],
            None,
            &[],
        )?;
        if r.status != 200 {
            return Err(format!(
                "GET {path} answered {} `{}`",
                r.status,
                show(&r.body)
            ));
        }
        Ok(r.body)
    }

    fn spend(&self, bucket: Option<&str>) -> Result<Spend, String> {
        ledger_spend(&self.admin_get("/api/v1/admin/ledger/totals")?, bucket)
    }

    /// The spend once the node has had time to post anything it was going to.
    fn spend_settled(&self, bucket: Option<&str>) -> Result<Spend, String> {
        settled(|| self.spend(bucket), |_| true)
    }

    /// The spend once at least `fees` fees are on it.
    fn spend_reaching(&self, bucket: Option<&str>, fees: u64) -> Result<Spend, String> {
        settled(|| self.spend(bucket), |s| s.fees >= fees)
    }

    fn requests(&self, key: &str) -> Result<u64, String> {
        let body = self.admin_get(&format!("/api/v1/admin/keys/{key}/usage"))?;
        serde_json::from_slice::<Value>(&body)
            .ok()
            .and_then(|v| v.get("requests").and_then(Value::as_u64))
            .ok_or_else(|| {
                format!(
                    "the key's usage carries no `requests` count: {}",
                    show(&body)
                )
            })
    }

    /// The position the next audit record takes.
    fn next_seq(&self) -> Result<u64, String> {
        let body = self.admin_get("/api/v1/admin/audit/head")?;
        serde_json::from_slice::<Value>(&body)
            .ok()
            .and_then(|v| v.get("next_seq").and_then(Value::as_u64))
            .ok_or_else(|| format!("the audit head carries no `next_seq`: {}", show(&body)))
    }

    /// Every record sealed from position `from` on, once at least `want` of the plane's are there.
    fn sealed_since(&self, from: u64, want: usize) -> Result<Vec<u8>, String> {
        settled(
            || {
                let next = self.next_seq()?;
                if next <= from {
                    return Ok(b"{\"records\":[]}".to_vec());
                }
                self.admin_get(&format!(
                    "/api/v1/admin/audit/range?from={from}&to={}",
                    next - 1
                ))
            },
            |w| op_records(w) >= want,
        )
    }

    fn authenticate(&self, client_key: &str) -> Result<(), String> {
        self.far.clear_replies();
        let before = self.spend(None)?;
        let call = self.call(Some(&format!("Bearer {}", forged(client_key))))?;
        let after = self.spend_settled(None)?;
        judge_refused_before_dial(&call, 401, "invalid_request", (before, after), None)
    }

    fn meter(&self, client: &str, bucket: &str) -> Result<(), String> {
        let before = self.spend(Some(bucket))?;
        let call = self.success(client)?;
        let after = self.spend_reaching(Some(bucket), before.fees + 1)?;
        judge_meter(&call, (before, after))
    }

    fn audit(&self, client: &str) -> Result<(), String> {
        let from = self.next_seq()?;
        let call = self.success(client)?;
        judge_audit(&call, &self.sealed_since(from, 1)?)
    }

    fn exit(&self, client: &str, bucket: &str) -> Result<(), String> {
        let from = self.next_seq()?;
        let before = self.spend(Some(bucket))?;
        let calls = vec![self.success(client)?, self.success(client)?];
        let after = self.spend_reaching(Some(bucket), before.fees + 2)?;
        judge_exit(&calls, (before, after), &self.sealed_since(from, 2)?)
    }

    fn verify(&self, bearer: &str, key: &str) -> Result<(), String> {
        self.far.clear_replies();
        let (before, was) = (self.spend(None)?, self.requests(key)?);
        let call = self.call(Some(bearer))?;
        let after = self.spend_settled(None)?;
        judge_refused_before_dial(
            &call,
            403,
            "unsupported_operation",
            (before, after),
            Some((was, self.requests(key)?)),
        )
    }

    fn admit(&self, bearer: &str, key: &str) -> Result<(), String> {
        let start = self.spend(None)?;
        let first = self.success(bearer)?;
        let before = self.spend_reaching(None, start.fees + 1)?;
        let was = self.requests(key)?;
        self.far.clear_replies();
        let second = self.call(Some(bearer))?;
        let after = self.spend_settled(None)?;
        judge_admit(&first, &second, (before, after), (was, self.requests(key)?))
    }

    fn route(&self, client: &str) -> Result<(), String> {
        self.far.clear_replies();
        // Twice: a walk that retries the sole member within the unit meets the same failure.
        self.far.reply(503, UNAVAILABLE);
        self.far.reply(503, UNAVAILABLE);
        let before = self.spend(None)?;
        let call = self.call(Some(client))?;
        let after = self.spend_settled(None)?;
        judge_route(&call, UNAVAILABLE, (before, after))
    }
}
