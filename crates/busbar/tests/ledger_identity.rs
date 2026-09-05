// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RECONCILIATION IDENTITY, proven on the shipped binary: the ledger's postings against the
//! rows the previous release keeps, over a mix of admitted, refused and failed-transfer requests.
//!
//! ## Why this needs a real boot and not a fixture
//!
//! The identity's whole claim is that two independently-written pieces of arithmetic land on the
//! same number: the ledger unit prices a settled unit line by line, with the flat fee as a line of
//! its own and one tier divide over the sum, and stores nano-units; the legacy usage projection
//! reprices the row's accumulated token counts at read time, sums nano-units across the row and
//! divides once. A fixture that fed both sides the same hand-written quantities would prove the two
//! functions agree on a table somebody typed. What it would NOT prove is that the quantities the
//! binary actually records — after admission, after the codec, after the metering tap decided which
//! requests count — are the quantities the ledger would have priced. That is a property of the
//! process, so the process is what is driven here.
//!
//! ## What the mix is for
//!
//! Three outcome classes, because the identity's hardest claim is about the requests that produce
//! NOTHING. PB-16: a legacy metering row is written only by the delivered-response tap. A refusal at
//! the door (over-budget, out-of-scope) and a failed transfer (the upstream is down) must therefore
//! leave the rows untouched — and the ledger must post nothing for them either. If either side
//! disagreed about which requests are billable, the residual would name the row; if BOTH sides made
//! the same mistake the request counts below would not add up. So the test pins both.
//!
//! ## What is NOT proven here, and why
//!
//! The composition root's `Ledger` is built dual-writing (`root::durability::build`) but no plane is
//! switched onto the root yet at this revision — `crates/busbar/src/root/mod.rs` says so in its own
//! words, and carries the `allow(dead_code)` that says it. There is consequently NO root-side ledger
//! readout to query, and mounting one would report an empty book however much traffic ran through
//! the binary: it would assert nothing. So the ledger side here is reconstructed from the figures
//! the run actually produced, priced through the real `busbar_unit_cost::price`, and the check is
//! the one that has content today — that the ledger's pricing and the legacy projection agree
//! exactly on the binary's own traffic. When a plane is switched onto the root, this test's ledger
//! snapshot is the thing that gets replaced by a readout, and nothing else about it changes.
#![cfg(unix)]
// Needs a bootable server with an LLM route: the money path is what is being reconciled.
#![cfg(feature = "proto-llm")]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use busbar_caps::{KernelSeal, MeterClassId, QuantitySource, Usage, UsageLine, UsageToken};
use busbar_unit_cost::{price, LaneClass, RateCard, RateCardVersion, STANDARD_TIER_BP};

// The binary has no library target, so the composition root's identity check is reached the only
// way an integration test can reach it: by compiling the same source file into this test binary.
// That is not a copy — it is the file the shipped binary compiles, at the same revision — so a
// change to the check that broke this test could not be papered over by editing the test.
#[path = "../src/root/ledger_identity.rs"]
mod ledger_identity;

use ledger_identity::{
    accumulate, describe, holds, reconcile, LedgerSnapshot, LegacyRow, LegacySnapshot, RowKey,
};

// ── the pinned figures ───────────────────────────────────────────────────────────────────────────
//
// Every number below is fixed by the fixture, not observed from the run, so a change in any of them
// fails here rather than quietly re-deriving itself on both sides of the identity.

/// The oracle's own ports for this cell.
const DATA_PORT: u16 = 49951;
const ADMIN_PORT: u16 = 49952;
const MOCK_PORT: u16 = 49961;

/// The one lane and its provider — the oracle's `m-<dialect>` naming.
const LANE: &str = "m-openai-chat";
const PROVIDER: &str = "openai-chat";

/// The mock upstream answers with a FIXED usage on every delivered response. This is the mock's own
/// documented invariant ("fixed usage (11 in / 7 out) … no clocks, no randomness"), and the test
/// asserts the rows carry exactly it rather than trusting it.
const IN_TOK: u64 = 11;
const OUT_TOK: u64 = 7;

/// The rate card, in the config's micro-units per token — the oracle's own priced card.
const INPUT_UTOK: f64 = 100_000.0;
const OUTPUT_UTOK: f64 = 200_000.0;
/// The flat per-request fee, in cents. NOT zero, and that is the point: with no fee the
/// `Σ fee_count == billable_requests` half of the identity is `0 == 0` on every row and would pass
/// with the fee line unimplemented on either side.
const FEE_CENTS: i64 = 3;

/// One delivered response, in nano-units: `11 × 100_000_000 + 7 × 200_000_000` for the tokens, plus
/// `3 × 10_000_000` for the fee line.
const NANOS_PER_RESPONSE: u128 = 2_530_000_000;
/// The same figure in micro-units, which is what the legacy projection reports.
const MICROS_PER_RESPONSE: i64 = 2_530_000;

/// The traffic mix.
const ADMITTED: usize = 4;
const REFUSED_OVER_BUDGET: usize = 2;
const REFUSED_OUT_OF_SCOPE: usize = 1;
const FAILED_TRANSFER: usize = 2;

const ADMIN_TOKEN: &str = "ledger-identity-admin";

#[test]
fn the_ledger_and_the_legacy_rows_reconcile_on_the_shipped_binary() {
    let rig = Rig::boot();

    // ── the mix ─────────────────────────────────────────────────────────────────────────────────
    //
    // Admitted first, refusals second, failed transfers LAST. The order is load-bearing: a failed
    // transfer trips the lane's breaker, and a cooldown running while an admitted request was still
    // to come would turn a delivered response into a refusal and move the figures for a reason that
    // has nothing to do with the identity.
    let mut delivered = 0usize;
    for _ in 0..ADMITTED {
        let r = rig.chat(&rig.key_ok);
        assert_eq!(
            r.status,
            200,
            "an admitted request must be served: {}\nlog:\n{}",
            r.body,
            rig.log()
        );
        delivered += 1;
    }

    for _ in 0..REFUSED_OVER_BUDGET {
        let r = rig.chat(&rig.key_broke);
        assert!(
            r.status == 429 || r.status == 200,
            "the over-budget key must be refused or (on its priming request) served, got {}: {}",
            r.status,
            r.body
        );
        if r.status == 200 {
            delivered += 1;
        }
    }
    let over_budget_refusals = REFUSED_OVER_BUDGET - (delivered - ADMITTED);
    assert!(
        over_budget_refusals >= 1,
        "the `broke` group's one-cent daily budget must refuse at least one request; \
         all {REFUSED_OVER_BUDGET} were served"
    );

    for _ in 0..REFUSED_OUT_OF_SCOPE {
        let r = rig.chat(&rig.key_noscope);
        assert_eq!(
            r.status, 403,
            "a key allowed only an unused pool must be refused at approve: {}",
            r.body
        );
    }

    rig.upstream_down(true);
    for _ in 0..FAILED_TRANSFER {
        let r = rig.chat(&rig.key_ok);
        assert!(
            (500..600).contains(&r.status),
            "a request whose transfer failed must not be answered 2xx, got {}: {}",
            r.status,
            r.body
        );
    }
    rig.upstream_down(false);

    // ── the readout ─────────────────────────────────────────────────────────────────────────────
    let first = rig.settled_usage(delivered);
    let second = rig.usage_bytes();
    assert_eq!(
        first, second,
        "two reads of the legacy usage projection with no traffic between them differ"
    );
    let usage: serde_json::Value =
        serde_json::from_slice(&first).expect("the usage response is JSON");

    // PB-16, the additive half: the legacy response carries the 1.5.5 shape and nothing the ledger
    // put there. Checked as a key set rather than by eye, because an additive field is exactly the
    // kind of change that reads as harmless in a diff and breaks somebody's export script.
    let top: Vec<&str> = usage
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        top,
        // Sorted, because that is the order a parser hands them back; the ON-THE-WIRE order is
        // asserted separately below, over the bytes, where it actually lives.
        vec![
            "as_of",
            "by_key",
            "by_key_truncated",
            "by_model",
            "currency",
            "total",
            "window"
        ],
        "the legacy usage response grew or lost a top-level field"
    );
    let body = String::from_utf8_lossy(&first);
    let positions: Vec<usize> = [
        "\"window\"",
        "\"as_of\"",
        "\"currency\"",
        "\"total\"",
        "\"by_model\"",
        "\"by_key\"",
        "\"by_key_truncated\"",
    ]
    .iter()
    .map(|k| {
        body.find(k)
            .unwrap_or_else(|| panic!("the response has no {k}"))
    })
    .collect();
    let mut sorted = positions.clone();
    sorted.sort_unstable();
    assert_eq!(
        positions, sorted,
        "the legacy usage response's field ORDER moved; a consumer reading it as a byte stream sees that"
    );
    for forbidden in [
        "priced_amount",
        "pre_tier_amount",
        "tier_bp",
        "fee_count",
        "ledger",
        "residual",
        "posting",
        "nanos",
        "rate_card_version",
    ] {
        assert!(
            !body.contains(forbidden),
            "the legacy usage response names `{forbidden}`; it reads the legacy rows only"
        );
    }

    // ── the identity ────────────────────────────────────────────────────────────────────────────
    let day = usage["window"]["start"].as_u64().expect("a window start");
    let total_requests = usage["total"]["requests"].as_u64().expect("a total");
    assert_eq!(
        total_requests as usize, delivered,
        "only a DELIVERED response may write a legacy metering row: {delivered} were delivered, \
         but the rows carry {total_requests} — {over_budget_refusals} over-budget refusal(s), \
         {REFUSED_OUT_OF_SCOPE} out-of-scope refusal(s) and {FAILED_TRANSFER} failed transfer(s) \
         must contribute nothing"
    );
    assert!(
        delivered >= ADMITTED,
        "the admitted requests must have landed"
    );

    let card = card();
    let pinned = card.pin();
    let mut ledger = LedgerSnapshot::new();
    let mut legacy = LegacySnapshot::new();

    // The by_key × by_model cross is not on the wire, so the identity is checked at the two widths
    // the legacy projection actually publishes: per (day, lane, provider), and per (day, bucket).
    // Both are projections of the same rows, so a ledger that disagreed with either disagrees.
    for row in usage["by_model"].as_array().expect("by_model") {
        let lane = row["model"].as_str().expect("a model").to_string();
        let provider = row["provider"].as_str().expect("a provider").to_string();
        // The breakdown is flattened onto the row, so the counts are the row's own fields.
        let u = row;
        let requests = u["requests"].as_u64().expect("requests");

        assert_eq!(
            u["tokens_input"].as_u64(),
            Some(IN_TOK * requests),
            "the mock's fixed input usage is what the rows must carry for {lane}"
        );
        assert_eq!(
            u["tokens_output"].as_u64(),
            Some(OUT_TOK * requests),
            "the mock's fixed output usage is what the rows must carry for {lane}"
        );
        assert_eq!(u["tokens_cache_read"].as_u64(), Some(0));
        assert_eq!(u["tokens_cache_creation"].as_u64(), Some(0));

        let key = RowKey::new("", day, &lane, &provider);
        // ONE POSTING PER DELIVERED RESPONSE, not one per row. That is what a settlement is, and it
        // is the shape that exercises the single-truncation rule: the ledger accumulates nano-units
        // and projects once, so a per-posting remainder that would floor away on its own survives
        // into the row's figure.
        for _ in 0..requests {
            let posting = price(&pinned, &lane, &one_response(), 1, STANDARD_TIER_BP);
            assert_eq!(
                posting.priced_amount(),
                NANOS_PER_RESPONSE,
                "one delivered response prices at a pinned figure"
            );
            assert_eq!(posting.fee_count(), 1);
            accumulate(&mut ledger, key.clone(), &posting);
        }
        legacy.insert(
            key,
            LegacyRow {
                spend_micros: u["spend_micros"].as_i64().expect("spend_micros"),
                // PB-99: the legacy row's billable count is what `flush_metering` wrote, and the
                // usage projection charges the flat fee on the same figure it reports as
                // `requests`. That figure is the fee base, so it is what the fee count is checked
                // against.
                billable_requests: requests,
            },
        );
    }

    let out = reconcile(&ledger, &legacy);
    assert!(
        out.is_empty(),
        "the ledger and the previous release's rows do not reconcile: {}",
        describe(&out)
    );
    assert!(
        holds(&ledger, &legacy),
        "the boolean and the list must agree"
    );

    // The pinned figure, stated once more as an absolute rather than as an agreement between two
    // computations — so a change that moved BOTH sides identically still fails here.
    let expected_micros = MICROS_PER_RESPONSE * i64::try_from(delivered).expect("small");
    let total_spend = usage["total"]["spend_micros"].as_i64().expect("spend");
    assert_eq!(
        total_spend, expected_micros,
        "{delivered} delivered responses at {MICROS_PER_RESPONSE} micro-units each"
    );
    let ledger_micros: i64 = ledger.values().map(|r| r.micros()).sum();
    assert_eq!(ledger_micros, expected_micros);
    let fee_total: u64 = ledger.values().map(|r| r.fee_count).sum();
    assert_eq!(
        fee_total, total_requests,
        "one flat fee per billable request, and no other"
    );

    // The second width: the same rows aggregated by key. `total == Σ by_key` is the legacy
    // projection's own completeness claim, and a ledger that reconciles at the lane width while the
    // key width does not add up would mean the rows themselves are inconsistent.
    let by_key_spend: i64 = usage["by_key"]
        .as_array()
        .expect("by_key")
        .iter()
        .map(|r| r["spend_micros"].as_i64().expect("spend"))
        .sum();
    let by_key_requests: u64 = usage["by_key"]
        .as_array()
        .expect("by_key")
        .iter()
        .map(|r| r["requests"].as_u64().expect("requests"))
        .sum();
    assert_eq!(by_key_spend, expected_micros);
    assert_eq!(by_key_requests, total_requests);
    assert_eq!(usage["by_key_truncated"], serde_json::Value::Bool(false));
}

// ── the ledger side's inputs ─────────────────────────────────────────────────────────────────────

/// The card the binary was configured with, rebuilt in the ledger unit's own terms. Not read back
/// off the binary: the point is that two descriptions of the same card produce the same money, so
/// asking the binary for its card would be asking one side of the comparison to supply the other.
fn card() -> RateCard {
    RateCard::from_micro_rates(
        RateCardVersion::new("ledger-identity-1"),
        [
            (LaneClass::new(LANE, "input"), INPUT_UTOK),
            (LaneClass::new(LANE, "output"), OUTPUT_UTOK),
        ],
        FEE_CENTS,
    )
}

/// One delivered response's usage report, as the mock fixes it.
fn one_response() -> Usage {
    let token = UsageToken::mint(&KernelSeal::acquire_for_kernel());
    Usage::report(
        &token,
        [("input", IN_TOK), ("output", OUT_TOK)]
            .into_iter()
            .map(|(class, quantity)| UsageLine {
                class: MeterClassId::new(class),
                quantity,
                source: QuantitySource::Count,
                estimated: false,
            })
            .collect(),
    )
    .expect("two lines are within the limit")
}

// ── the rig ──────────────────────────────────────────────────────────────────────────────────────

struct Rig {
    dir: PathBuf,
    log_path: PathBuf,
    control: PathBuf,
    child: Child,
    mock: Child,
    key_ok: String,
    key_broke: String,
    key_noscope: String,
}

impl Drop for Rig {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = self.mock.kill();
        let _ = self.mock.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Rig {
    fn boot() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "busbar-ledger-identity-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let control = dir.join("mock.control");

        // The oracle's own multi-dialect mock: a byte-deterministic upstream with fixed usage, and
        // a control file the rig flips to take it down without busbar ever seeing a control header.
        let mock_py = repo_root().join("testing/shadow-oracle/mock-upstream.py");
        assert!(
            mock_py.exists(),
            "the oracle's mock upstream is missing at {mock_py:?}"
        );
        let mock_log = std::fs::File::create(dir.join("mock.log")).unwrap();
        let mock = Command::new("python3")
            .arg(&mock_py)
            .arg(MOCK_PORT.to_string())
            .arg("oracle-marker")
            .arg(&control)
            .stdout(mock_log.try_clone().unwrap())
            .stderr(mock_log)
            .spawn()
            .expect("python3 is needed to run the oracle's mock upstream");
        wait_until(Duration::from_secs(15), || {
            TcpStream::connect(("127.0.0.1", MOCK_PORT)).is_ok()
        })
        .expect("the mock upstream did not come up");

        write_configs(&dir);

        let log_path = dir.join("out.log");
        let log = std::fs::File::create(&log_path).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_busbar"))
            .env("BUSBAR_CONFIG", dir.join("config.yaml"))
            .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
            .env("BUSBAR_ADMIN_TOKEN", ADMIN_TOKEN)
            .env("ORACLE_UPSTREAM_KEY", "unused")
            .env("RUST_LOG", "warn")
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .expect("spawn busbar");

        let mut rig = Rig {
            dir,
            log_path,
            control,
            child,
            mock,
            key_ok: String::new(),
            key_broke: String::new(),
            key_noscope: String::new(),
        };

        // A boot may take a while on a loaded machine before it reads as a failure.
        let booted = wait_until(Duration::from_secs(60), || {
            if let Some(status) = rig.child.try_wait().expect("try_wait") {
                panic!(
                    "busbar exited before listening (status {status:?}); log:\n{}",
                    read_to_string(&rig.log_path)
                );
            }
            get(DATA_PORT, "/healthz", None).status == 200
        });
        assert!(
            booted.is_some(),
            "busbar did not answer on {DATA_PORT}; log:\n{}",
            read_to_string(&rig.log_path)
        );

        rig.key_ok = rig.mint(r#"{"name":"identity-ok","group":"oracle"}"#);
        rig.key_broke = rig.mint(r#"{"name":"identity-broke","group":"broke"}"#);
        rig.key_noscope = rig.mint(
            r#"{"name":"identity-noscope","group":"oracle","allowed_pools":["oracle-unused"]}"#,
        );
        rig
    }

    fn mint(&self, body: &str) -> String {
        let r = request(
            ADMIN_PORT,
            "POST",
            "/api/v1/admin/keys",
            Some(ADMIN_TOKEN),
            Some(body),
        );
        assert_eq!(
            r.status, 201,
            "minting a key failed: {} {}",
            r.status, r.body
        );
        let v: serde_json::Value = serde_json::from_str(&r.body).expect("a key response");
        v["token"]
            .as_str()
            .expect("a minted key carries its token once")
            .to_string()
    }

    fn chat(&self, token: &str) -> Response {
        let body =
            format!(r#"{{"model":"{LANE}","messages":[{{"role":"user","content":"ping"}}]}}"#);
        request(
            DATA_PORT,
            "POST",
            "/v1/chat/completions",
            Some(token),
            Some(&body),
        )
    }

    /// Flip the mock's control file. busbar sees a plain 503 from the upstream and nothing else.
    fn upstream_down(&self, down: bool) {
        if down {
            std::fs::write(&self.control, b"down").unwrap();
        } else {
            let _ = std::fs::remove_file(&self.control);
        }
    }

    /// The legacy usage projection, as bytes. Bytes rather than a parsed value because PB-16's
    /// claim is about the response and not about what a lenient parser makes of it.
    fn usage_bytes(&self) -> Vec<u8> {
        let r = get(ADMIN_PORT, "/api/v1/admin/usage", Some(ADMIN_TOKEN));
        assert_eq!(r.status, 200, "reading /usage failed: {}", r.body);
        r.body.into_bytes()
    }

    /// The projection once the write-behind flush has caught up.
    ///
    /// Metering rows post write-behind (`usage_flush_interval_ms`, 100 ms by default), so a read
    /// taken at a fixed delay after the last request races the flusher — the same race the oracle's
    /// recorder settles by polling to a fixed point rather than by sleeping and hoping. Two
    /// conditions, both required: the rows carry the expected count, and two consecutive reads
    /// agree. The deadline is generous because a loaded machine is slow, not wrong; falling out of
    /// it returns the last read so the assertion that follows reports the real figures rather than
    /// a timeout.
    fn settled_usage(&self, expected_requests: usize) -> Vec<u8> {
        let mut last = self.usage_bytes();
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(150));
            let next = self.usage_bytes();
            let settled = next == last
                && serde_json::from_slice::<serde_json::Value>(&next)
                    .ok()
                    .and_then(|v| v["total"]["requests"].as_u64())
                    == Some(expected_requests as u64);
            last = next;
            if settled {
                break;
            }
        }
        last
    }

    fn log(&self) -> String {
        read_to_string(&self.log_path)
    }
}

fn repo_root() -> PathBuf {
    // `crates/busbar` -> the workspace root.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the manifest lives two levels below the workspace root")
        .to_path_buf()
}

/// The oracle's configuration, narrowed to the one dialect this cell needs: the same auth chain,
/// the same two budget groups, the same priced card, and the same unused pool the out-of-scope key
/// is confined to. A flat fee is added, for the reason `FEE_CENTS` gives.
fn write_configs(dir: &Path) {
    std::fs::write(
        dir.join("providers.yaml"),
        format!("{PROVIDER}:\n  protocol: openai\n  base_url: \"http://127.0.0.1:{MOCK_PORT}\"\n"),
    )
    .unwrap();

    let key = Command::new(env!("CARGO_BIN_EXE_busbar"))
        .arg("--generate-signing-key")
        .output()
        .expect("generate a signing key");
    assert!(
        !key.stdout.is_empty(),
        "--generate-signing-key produced no key"
    );
    std::fs::write(dir.join("signing.key"), &key.stdout).unwrap();

    std::fs::write(
        dir.join("config.yaml"),
        format!(
            r#"listen: "127.0.0.1:{DATA_PORT}"
admin_listen: "127.0.0.1:{ADMIN_PORT}"
admin_require_mtls: false
identity-providers:
  admin-tokens:
    module: admin-tokens
    token: {{ env: BUSBAR_ADMIN_TOKEN }}
auth:
  chain:
    - keys
  signing_key: {{ file: "{key_file}" }}
  admin_auth: [admin-tokens]
per_request_fee: {FEE_CENTS}
groups:
  oracle:
    limits:
      - {{ budget: 1000000, per: day }}
  broke:
    limits:
      - {{ requests: 1, per: day }}
      - {{ budget: 1, per: day }}
providers:
  {PROVIDER}:
    api_key: {{ env: ORACLE_UPSTREAM_KEY }}
models:
  {LANE}:
    provider: {PROVIDER}
rate_card:
  {LANE}: {{ input_utok: {INPUT_UTOK}, output_utok: {OUTPUT_UTOK} }}
pools:
  oracle-unused:
    members:
      - model: {LANE}
"#,
            key_file = dir.join("signing.key").display(),
        ),
    )
    .unwrap();
}

fn wait_until(budget: Duration, mut cond: impl FnMut() -> bool) -> Option<()> {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        if cond() {
            return Some(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

fn read_to_string(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

// ── raw HTTP ─────────────────────────────────────────────────────────────────────────────────────
//
// Hand-rolled for the same reason `inbound_concurrency_shed.rs` hand-rolls its own: the test is
// about the bytes a shipped process produced, and a client that retries, redirects or re-encodes on
// the way is a client that can hide the thing being asserted.

struct Response {
    status: u16,
    body: String,
}

fn get(port: u16, path: &str, bearer: Option<&str>) -> Response {
    request(port, "GET", path, bearer, None)
}

fn request(
    port: u16,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    body: Option<&str>,
) -> Response {
    let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) else {
        return Response {
            status: 0,
            body: String::new(),
        };
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n");
    if let Some(t) = bearer {
        head.push_str(&format!("Authorization: Bearer {t}\r\n"));
    }
    match body {
        Some(b) => head.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            b.len()
        )),
        None => head.push_str("\r\n"),
    }
    if stream.write_all(head.as_bytes()).is_err() {
        return Response {
            status: 0,
            body: String::new(),
        };
    }
    if let Some(b) = body {
        let _ = stream.write_all(b.as_bytes());
    }
    let _ = stream.flush();

    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    let text = String::from_utf8_lossy(&raw);
    let Some(split) = text.find("\r\n\r\n") else {
        return Response {
            status: 0,
            body: String::new(),
        };
    };
    let (headline, rest) = text.split_at(split);
    let status = headline
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    Response {
        status,
        body: rest[4..].to_string(),
    }
}
