//! Tests for the node (`plane_node.rs`). Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use super::*`
//! reaches the private items it always did.
//!
//! The node's money machinery, read without a plane: the arrival readings, the card history a unit
//! is priced against, the lane interner, the second book, the sweep and the late arm. A door plane's
//! units are driven on the node through its borrowed drive; those are proven where the door is
//! served (`root::serve`'s door cells).

use super::*;

use axum::body::Bytes;
use busbar_kernel::teller::{Ended, Kernel};
use busbar_kernel::test_support::{MockResponse, MockServer, MockServerState};
const POOL: &str = "p";
const LANE: &str = "m0";
/// The token figures the scripted upstream reports on a delivered answer.
const INPUT: u64 = 11;
const OUTPUT: u64 = 7;

/// The six ends these fixtures name. Each is an END a client reaches, not a step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fixture {
    /// The whole loop, delivered, buffered.
    BufferedOk,
    /// The same loop with the accrual landing at stream end rather than at the buffered tap.
    StreamedOk,
    /// A body that is not JSON: the arrival step's own parse refusal, before a model exists.
    Malformed,
    /// A key whose group budget is spent: the door refuses and nothing is charged.
    OverBudget,
    /// A key that may not reach the pool it named: the pre-admission guard, before pricing.
    PoolAcl,
    /// A model that resolves to no pool and no lane: refused AFTER the door, so it is charged.
    UnknownModel,
}

impl Fixture {
    fn model(self) -> &'static str {
        match self {
            Fixture::UnknownModel => "no-such-model",
            _ => POOL,
        }
    }

    fn streamed(self) -> bool {
        matches!(self, Fixture::StreamedOk)
    }

    fn key_scopes(self) -> Option<Vec<String>> {
        match self {
            Fixture::PoolAcl => Some(vec!["some-other-pool".to_string()]),
            _ => None,
        }
    }

    fn seeded_group_requests(self) -> Option<u64> {
        matches!(self, Fixture::OverBudget).then_some(250)
    }

    fn upstream(self) -> MockResponse {
        match self {
            Fixture::StreamedOk => MockResponse::Sse {
                events: sse_events(),
                abort_at_index: None,
            },
            _ => MockResponse::Ok {
                status: reqwest::StatusCode::OK,
                body: serde_json::json!({
                    "id": "chatcmpl-root", "object": "chat.completion", "created": 0,
                    "model": LANE,
                    "choices": [{"index": 0, "finish_reason": "stop",
                                 "message": {"role": "assistant", "content": "hello"}}],
                    "usage": {"prompt_tokens": INPUT, "completion_tokens": OUTPUT,
                              "total_tokens": INPUT + OUTPUT}
                }),
            },
        }
    }

    /// The bytes the caller sends.
    fn body(self) -> Bytes {
        if self == Fixture::Malformed {
            return Bytes::from_static(b"{not json");
        }
        let mut v = serde_json::json!({
            "model": self.model(),
            "messages": [{"role": "user", "content": "hi"}],
        });
        if self.streamed() {
            v["stream"] = serde_json::Value::Bool(true);
        }
        Bytes::from(serde_json::to_vec(&v).expect("the fixture body serializes"))
    }
}

fn sse_events() -> Vec<String> {
    vec![
        serde_json::json!({"id": "chatcmpl-root", "object": "chat.completion.chunk",
                           "created": 0, "model": LANE,
                           "choices": [{"index": 0, "delta": {"role": "assistant",
                                                              "content": "hello"}}]})
        .to_string(),
        serde_json::json!({"id": "chatcmpl-root", "object": "chat.completion.chunk",
                           "created": 0, "model": LANE,
                           "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                           "usage": {"prompt_tokens": INPUT, "completion_tokens": OUTPUT,
                                     "total_tokens": INPUT + OUTPUT}})
        .to_string(),
        "[DONE]".to_string(),
    ]
}

/// One deployment: a governed key, a one-lane pool, and a scripted upstream.
struct Rig {
    app: Arc<busbar_kernel::state::App>,
    key: Arc<busbar_contract::records::VirtualKey>,
    /// The BEARER the deployment's own door will resolve back to [`Rig::key`]. Minted rather
    /// than synthesized, so a fixture that presents it is presenting the thing a client sends.
    token: String,
    /// A bearer for a SECOND key on the same deployment whose lifetime has already run out.
    /// It verifies against the same signer and names a live, enabled binding — the only thing
    /// wrong with it is the clock, which is what makes it an expiry fixture rather than a
    /// forgery fixture.
    expired_token: String,
    server: MockServer,
    /// The scripted upstream's own state, kept so a fixture can ask whether the upstream was
    /// dialled at all — "the unit stopped before the route step" is not a fact any counter on
    /// this side of the loop reports.
    upstream: Arc<MockServerState>,
    charged_at: u64,
    group: String,
}

impl Rig {
    fn gov(&self) -> busbar_contract::records::PlaneRequestCtx {
        busbar_contract::records::PlaneRequestCtx {
            key: Some(self.key.clone()),
        }
    }

    fn host(&self) -> Arc<dyn busbar_kernel::plane_host::EngineHost> {
        busbar_kernel::plane_host::engine_host(&self.app)
    }
}

/// Blank the values a response synthesizes per run — ids and clocks.
fn normalize(s: &str) -> String {
    fn blank(v: &mut serde_json::Value) {
        match v {
            serde_json::Value::Object(map) => {
                for (k, val) in map.iter_mut() {
                    let is_id = k.ends_with("id") || k.ends_with("Id") || k.ends_with("ID");
                    let is_clock = matches!(k.as_str(), "created" | "created_at" | "createTime");
                    if is_id && val.is_string() {
                        *val = serde_json::Value::String("<id>".to_string());
                    } else if (is_clock || k == "latencyMs") && val.is_number() {
                        *val = serde_json::Value::from(0);
                    } else {
                        blank(val);
                    }
                }
            }
            serde_json::Value::Array(items) => items.iter_mut().for_each(blank),
            _ => {}
        }
    }
    if s.contains("data:") {
        return s
            .lines()
            .map(|line| match line.strip_prefix("data: ") {
                Some(rest) => format!("data: {}", normalize(rest)),
                None => line.to_string(),
            })
            .collect::<Vec<_>>()
            .join("\n");
    }
    match serde_json::from_str::<serde_json::Value>(s) {
        Ok(mut v) => {
            blank(&mut v);
            v.to_string()
        }
        Err(_) => s.to_string(),
    }
}

/// Blank the per-run values in a response body, whatever its framing.
///
/// A bedrock stream is binary event-stream framing, not text: its `metadata` frame carries a
/// wall-clock `metrics.latencyMs`, and every frame ends in a CRC over its own bytes. Read as one
/// lossy string, [`normalize`] can neither parse nor blank it, so two legs whose streams took 0 ms
/// and 1 ms compared as different bodies under load. Each frame is decoded here instead: its
/// headers are kept byte for byte, its JSON payload goes through [`normalize`], and the two CRCs,
/// which only restate the bytes compared beside them, are dropped. Anything that is not a clean
/// run of frames is compared exactly as before.
fn normalize_body(body: &[u8]) -> String {
    match event_stream_frames(body) {
        Some(frames) => frames
            .into_iter()
            .map(|(headers, payload)| {
                format!(
                    "{}|{}",
                    String::from_utf8_lossy(headers),
                    normalize(&String::from_utf8_lossy(payload))
                )
            })
            .collect::<Vec<_>>()
            .join("\n"),
        None => normalize(&String::from_utf8_lossy(body)),
    }
}

/// Split an event-stream body into `(headers, payload)` per frame. Each frame is a 12-byte
/// prelude (total length, headers length, prelude CRC; big-endian u32s), the headers, the
/// payload and a 4-byte message CRC. `None` unless the whole body is one or more such frames.
fn event_stream_frames(mut body: &[u8]) -> Option<Vec<(&[u8], &[u8])>> {
    let be = |b: &[u8]| u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize;
    let mut frames = Vec::new();
    while !body.is_empty() {
        if body.len() < 16 {
            return None;
        }
        let (total, headers_len) = (be(&body[0..4]), be(&body[4..8]));
        if total < 16 + headers_len || total > body.len() {
            return None;
        }
        frames.push((
            &body[12..12 + headers_len],
            &body[12 + headers_len..total - 4],
        ));
        body = &body[total..];
    }
    (!frames.is_empty()).then_some(frames)
}

/// The event-stream normalizer blanks the clock and nothing else: two streams that differ only in
/// `metrics.latencyMs` (and so in their CRCs) compare equal, and two that differ in a delta's text
/// still diverge.
#[test]
fn event_stream_bodies_compare_without_their_clock() {
    fn frame(payload: &str) -> Vec<u8> {
        let headers = b":event-type metadata";
        let total = 12 + headers.len() + payload.len() + 4;
        let mut out = Vec::new();
        out.extend_from_slice(&(total as u32).to_be_bytes());
        out.extend_from_slice(&(headers.len() as u32).to_be_bytes());
        out.extend_from_slice(&[0xAA; 4]);
        out.extend_from_slice(headers);
        out.extend_from_slice(payload.as_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out
    }
    let stream = |ms: u32, text: &str| {
        let mut body = frame(&format!(r#"{{"delta":{{"text":"{text}"}}}}"#));
        body.extend(frame(&format!(r#"{{"metrics":{{"latencyMs":{ms}}}}}"#)));
        body
    };
    assert_eq!(
        normalize_body(&stream(0, "hello")),
        normalize_body(&stream(137, "hello"))
    );
    assert_ne!(
        normalize_body(&stream(0, "hello")),
        normalize_body(&stream(0, "hellp"))
    );
}

/// **One arrival is one reading, and both figures come out of it.**
///
/// The pure half of the straddle. A unit arriving at the last millisecond of a window has its
/// seconds in that window and its milliseconds one tick short of the next: read the clock twice
/// there and the second read is already over the line, so the table stamps the unit in one
/// window and the books bill it in another. Read once and the two figures are two spellings of
/// one instant, which is the property asserted here.
#[test]
fn one_arrival_reading_spells_both_the_figures_the_loop_asks_for() {
    const LAST_MILLISECOND: u64 = 1_700_000_000_999;
    let arrived = Arrived::at(LAST_MILLISECOND, 0);
    assert_eq!(arrived.ms(), LAST_MILLISECOND, "the reading, unmodified");
    assert_eq!(
        arrived.secs(),
        1_700_000_000,
        "and the window it lands in, which is the second that has not ended yet"
    );
    assert_eq!(
        arrived.ms() / 1_000,
        arrived.secs(),
        "the two figures are one instant: neither can be on the far side of a boundary the \
         other is on the near side of"
    );
}

/// **Two units of one second are ordered by the monotonic stamp, not by the wall clock.**
///
/// The node's two clocks answer two different questions and the audit record and the posting
/// stamp each want both. The wall clock DATES: it says which window a unit belongs to, and it is
/// steppable, so an operator, an NTP correction or a leap second can hand two events timestamps
/// that run backwards. The monotonic reading ORDERS: it only goes up, whatever the wall clock
/// does.
///
/// So: units taken from one node inside one second — indistinguishable by the wall reading, and
/// on a stepped clock possibly backwards by it — still come out of the monotonic reading in the
/// order they were taken. Stamped from the wall clock twice, as this leg's postings were, the
/// second field is a copy of the first and this ordering does not exist.
#[test]
fn two_units_of_one_second_are_ordered_by_the_monotonic_stamp() {
    let node = Node::new();
    let taken: Vec<Arrived> = (0..4).map(|_| node.arrived()).collect();

    for pair in taken.windows(2) {
        let (before, after) = (pair[0], pair[1]);
        assert!(
            after.mono() > before.mono(),
            "the reading that orders them only goes up: {} then {}",
            before.mono(),
            after.mono()
        );
    }
    // Four units off one node inside one second is the ordinary case, not a contrived one — and
    // it is exactly the case a wall clock cannot resolve, whichever direction it was stepped.
    assert!(
        taken
            .iter()
            .all(|a| a.secs() == taken[0].secs() || a.secs() == taken[0].secs() + 1),
        "the four were taken within a second of each other"
    );
    // Two readings, not one written twice: a monotonic counter is a SEQUENCE and an epoch is a
    // date, so the day they compare equal is the day one of them stopped being what it is.
    assert_ne!(taken[0].mono(), taken[0].secs());

    // AND THE STAMP CARRIES IT. Two postings settled at one wall second, taken through the real
    // settle path onto a real journal, come back off it in the order they were written — which
    // is the ordering the record is FOR, and which does not exist if the second field is the
    // first one copied.
    let durability = crate::root::durability::build(
        &crate::root::durability::DurabilityConfig { data_dir: None },
        Box::new(busbar_kernel_wal::NullShipper::new()),
        Box::new(busbar_kernel_ledger::legacy::RecordingRows::new()),
    )
    .expect("a memory-buffered journal cannot fail to open");
    // Both settlements through the ONE money-book seam over the shared book — the pass-through the
    // live exit arm now takes, and what a second exit arm settling behind the first takes too.
    let book = std::sync::Arc::new(std::sync::Mutex::new(durability));
    let seam = crate::root::durability::SharedBook::over(std::sync::Arc::clone(&book));
    let who = PrincipalId::new("acct:node");
    for arrived in [Arrived::at(EPOCH * 1_000, 7), Arrived::at(EPOCH * 1_000, 8)] {
        let ledger_token =
            busbar_kernel::test_support::tokens::grant::<busbar_contract::caps::WriteMoney>();
        let accrual =
            busbar_contract::caps::HoldAccrual::after_terminal(who.clone(), 0, &ledger_token);
        let posted = busbar_contract::caps::Posted::settle_late(accrual, &ledger_token);
        settle(
            &seam,
            &who,
            arrived,
            None,
            &busbar_kernel::test_support::tokens::grant::<busbar_contract::caps::DurableWrite>(),
            posted,
        )
        .expect("the memory-buffered journal takes it");
    }
    let durability = book.lock().unwrap_or_else(|p| p.into_inner());
    let replayed = durability
        .journal
        .replay()
        .expect("reads back")
        .expect("verifies");
    assert_eq!(replayed.len(), 2, "two postings, two records");
    assert_eq!(
        replayed[0].wall, replayed[1].wall,
        "settled at one wall second, so the date cannot separate them"
    );
    assert!(
        replayed[1].mono > replayed[0].mono,
        "and the stamp that can does: {} then {}",
        replayed[0].mono,
        replayed[1].mono
    );
}

/// The unit-arrival epoch this proof pins, so the window a posting lands in is a fixed one.
const EPOCH: u64 = 1_700_000_000;

// -----------------------------------------------------------------------------------------
// The lookup at the door
// -----------------------------------------------------------------------------------------

/// A history of one entry per `(effective_from_ms, output rate)`, built OUTSIDE the process
/// holder so these proofs name their own instants instead of racing the wall clock.
///
/// The first entry is effective from zero for the same reason the holder's is: an instant before
/// the first entry is a hole and a hole is a refusal.
fn history_of(entries: &[(u64, f64)]) -> crate::root::kernel::PinnedHistory {
    let mut history = busbar_kernel_ledger::cost::History::new();
    for (n, (from, output)) in entries.iter().enumerate() {
        let card = crate::root::kernel::card_from_config(
            [(
                "lane",
                busbar_contract::billing::RawTierRates {
                    input: 0.0,
                    output: *output,
                    cache_read: 0.0,
                    cache_write: 0.0,
                },
            )],
            0,
            true,
        );
        history.append(busbar_kernel_ledger::cost::CardEntryDraft {
            effective_from: if n == 0 { 0 } else { *from },
            effective_until: None,
            card,
            appended_at: *from,
            author: busbar_kernel_ledger::cost::Author::Config {
                policy_epoch: n as u64,
            },
        });
    }
    crate::root::kernel::PinnedHistory::for_test(
        std::sync::Arc::new(history),
        busbar_kernel_ledger::cost::HistorySeq((entries.len() - 1) as u64),
    )
}

/// A report of `output` tokens on the lane the histories above price.
fn report_of(output: u64) -> Report {
    Report {
        usage: busbar_contract::billing::Usage {
            usage_units: std::collections::BTreeMap::from([(
                busbar_contract::records::UNIT_OUTPUT.to_string(),
                output,
            )]),
        },
        fee_count: 0,
        lane: "lane".to_string(),
    }
}

/// **THE UNIT PRICES AT THE INSTANT IT ARRIVED**, not at the instant the question is asked.
///
/// Two units, one snapshot, one call each: the one that arrived before the second entry took
/// effect prices at the first entry's rate and the one that arrived after prices at the
/// second's. Both readings are taken from the SAME history at the SAME moment, so the only thing
/// that can be producing two answers is the arrival instant — which is the whole of rule 3.
///
/// A node that priced against "the current card" answers the later figure for both, which is
/// exactly the recorded 1.5.5 behaviour and exactly what this replaces.
#[test]
fn a_unit_prices_at_the_entry_in_force_when_it_arrived_and_not_at_the_head() {
    let kernel = Kernel::new();
    let token = kernel.usage_token();
    let history = history_of(&[(0, 1.0), (5_000, 100.0)]);

    let early = priced_amount(&history, Arrived::at(4_999, 1), &token, &report_of(1_000));
    let late = priced_amount(&history, Arrived::at(5_000, 2), &token, &report_of(1_000));

    assert_eq!(
        early,
        Ok(1_000_000),
        "a unit that arrived before the appended entry was re-priced at it"
    );
    assert_eq!(
        late,
        Ok(100_000_000),
        "a unit that arrived after the appended entry was priced at the entry it superseded"
    );
}

/// **THE PIN HOLDS.** A snapshot taken at admission cannot see an entry appended after it, so an
/// apply landing mid-body does not reprice a request halfway through.
///
/// The pinned reader and the head are both asked about the SAME instant, and they answer
/// differently — which is only possible because the pin stops the snapshot's slice short of the
/// later entry. A holder that handed out the whole history and a live head would answer the new
/// figure to a request that was admitted under the old one.
#[test]
fn a_snapshot_pinned_at_admission_cannot_see_an_entry_appended_behind_it() {
    let kernel = Kernel::new();
    let token = kernel.usage_token();
    let holder = crate::root::kernel::RootHistory::default();
    holder.apply(
        crate::root::kernel::card_from_config(
            [(
                "lane",
                busbar_contract::billing::RawTierRates {
                    input: 0.0,
                    output: 1.0,
                    cache_read: 0.0,
                    cache_write: 0.0,
                },
            )],
            0,
            true,
        ),
        1_000,
    );
    let admitted = holder
        .pin()
        .expect("the boot resolution put an entry in place");

    // The apply that lands while the body is still draining.
    holder.apply(
        crate::root::kernel::card_from_config(
            [(
                "lane",
                busbar_contract::billing::RawTierRates {
                    input: 0.0,
                    output: 100.0,
                    cache_read: 0.0,
                    cache_write: 0.0,
                },
            )],
            0,
            true,
        ),
        2_000,
    );
    let next = holder.pin().expect("the apply put a second entry in place");

    let at = Arrived::at(9_000, 1);
    assert_eq!(
        priced_amount(&admitted, at, &token, &report_of(1_000)),
        Ok(1_000_000),
        "the pinned snapshot saw an entry appended after the unit was admitted"
    );
    assert_eq!(
        priced_amount(&next, at, &token, &report_of(1_000)),
        Ok(100_000_000),
        "the next admission did not see the appended entry"
    );
}

/// **THE PIN IS A SEQ, NOT ONLY AN `Arc`.** A reader holding the same history at a lower
/// snapshot reads it as it stood at that snapshot.
///
/// The `Arc` alone is not the pin: an amendment, and a copy-on-write apply that a second reader
/// already took, both leave one history holding entries a reader was never admitted under. The
/// seq is what stops the slice short of them, and this asks the SAME history at two snapshots to
/// prove the stopping is real rather than an accident of when the `Arc` was cloned.
#[test]
fn a_pin_below_the_head_reads_the_history_as_it_stood_at_that_seq() {
    let kernel = Kernel::new();
    let token = kernel.usage_token();
    let head = history_of(&[(0, 1.0), (5_000, 100.0)]);
    let earlier = crate::root::kernel::PinnedHistory::for_test_at(
        &head,
        busbar_kernel_ledger::cost::HistorySeq(0),
    );

    let at = Arrived::at(9_000, 1);
    assert_eq!(
        priced_amount(&earlier, at, &token, &report_of(1_000)),
        Ok(1_000_000),
        "a snapshot at seq 0 resolved an entry that was appended after it"
    );
    assert_eq!(
        priced_amount(&head, at, &token, &report_of(1_000)),
        Ok(100_000_000),
        "the head snapshot did not resolve the entry appended onto it"
    );
}

/// **THE CACHE IS WRITTEN AND IS NEVER AUTHORITATIVE.**
///
/// The posting the pricing builds carries a cache — the head it settled at, the entry it
/// resolved to, and both figures — so a reader has something to compare a
/// re-derivation against. Corrupt every one of those figures and ask again: the answer is
/// unchanged, because the lookup does not read them. A node that fell back to the cache would
/// answer the corrupted number and call it money.
#[test]
fn the_cached_price_rides_the_posting_and_is_never_read_back_for_money() {
    let kernel = Kernel::new();
    let token = kernel.usage_token();
    let history = history_of(&[(0, 1.0)]);
    let at = Arrived::at(4_000, 7);

    let (mut posting, priced) = priced_posting(&history, at, &token, &report_of(1_000));
    let priced = priced.expect("a card in force at the instant prices the report");
    let cached = posting
        .cached
        .expect("the pricing left its cache on the posting");
    assert_eq!(cached.priced_nanos, priced.priced_nanos);
    assert_eq!(cached.card_seq, priced.card_seq);
    assert_eq!(cached.history_seq, history.seq());
    assert_eq!(cached.pre_tier_nanos, priced.pre_tier_nanos);
    assert_eq!(
        posting.arrived_ms, 4_000,
        "the posting kept its own instant"
    );
    assert_eq!(posting.arrived_mono, 7);

    // The tamper. Every figure a reader could be tempted to trust, made a lie.
    posting.cached = Some(busbar_kernel_ledger::cost::CachedPrice {
        history_seq: busbar_kernel_ledger::cost::HistorySeq(u64::MAX),
        card_seq: busbar_kernel_ledger::cost::HistorySeq(u64::MAX),
        pre_tier_nanos: 1,
        priced_nanos: 1,
    });
    assert_eq!(
        posting
            .priced_nanos(&history.view())
            .expect("the lookup still answers"),
        priced.priced_nanos,
        "the money moved when the cache was corrupted, so the cache was on the money path"
    );
    assert!(
        posting.cache_diverges(&priced),
        "a corrupted cache went unnoticed"
    );
}

/// A route whose plane SCREENS every unit before the door and stops it with `reason` (a gate-first
/// plane's veto, SEAM-4j), its leg otherwise the plane's own.
struct Screening<'r> {
    inner: &'r (dyn RouteAwait + Send + Sync),
    reason: busbar_contract::caps::ReasonCode,
}

impl RouteAwait for Screening<'_> {
    fn route_leg<'a>(
        &'a self,
        token: &'a Pass<Route>,
        ctx: &'a UnitCtx,
        destinations: &'a [VerifiedDestination],
    ) -> RouteLeg<'a> {
        self.inner.route_leg(token, ctx, destinations)
    }

    fn abandoned(&self, ctx: &UnitCtx, ended: Ended) {
        self.inner.abandoned(ctx, ended);
    }

    fn screen<'a>(&'a self, _ctx: &'a UnitCtx) -> busbar_kernel::teller::Screen<'a> {
        let reason = self.reason;
        Box::pin(async move { Err(Refusal::new(reason)) })
    }
}

/// THE INTERNER IS THE NODE'S, and it is idempotent.
///
/// A lane name is leaked to become the borrowed static one the priced axis is written in, so
/// interning the same name twice must yield the same pointer: a leak per request would be a
/// leak per request whatever it was called.
#[test]
fn the_nodes_interner_leaks_a_lane_name_once() {
    let node = Node::new();
    let lanes = node.lanes();
    let first = lanes
        .lock()
        .expect("the node's interner is never poisoned")
        .lane(LANE);
    let again = lanes
        .lock()
        .expect("the node's interner is never poisoned")
        .lane(LANE);
    assert_eq!(first, again);
    let first = first.expect("an unfrozen image interns a configured lane");
    let again = again.expect("a repeated lane is the same lane");
    assert!(std::ptr::eq(first.as_str(), again.as_str()));
}

/// AND THE INTERNER IS REACHED ONCE PER NAME, not once per request.
///
/// The interner is one mutex for the whole image, and the Verify step resolves a name per
/// candidate lane, per request — so a node that asks it every time makes every plane in the
/// process queue behind one lock for an answer that was settled the first time. The count is
/// per distinct name and does not grow with how often the name is asked for.
#[test]
fn a_lane_name_reaches_the_interner_once_however_often_it_is_resolved() {
    let node = Node::new();
    let mut names = node
        .lane_names
        .lock()
        .expect("the node's lane table is never poisoned");

    let first = names
        .resolve(LANE)
        .expect("an unfrozen image interns a lane");
    for _ in 0..64 {
        let again = names
            .resolve(LANE)
            .expect("a repeated lane is the same lane");
        assert!(std::ptr::eq(first.as_str(), again.as_str()));
    }
    assert_eq!(names.consulted(), 1);

    let _ = names.resolve("a-second-configured-lane");
    assert_eq!(
        names.consulted(),
        2,
        "a name the node has not resolved still reaches the interner, exactly once"
    );
}

/// THE PROVENANCE STAMP NAMES THE CARD IN FORCE WHEN THE UNIT ARRIVED (#79), not the newest card
/// ever published and not a literal.
///
/// This stamp used to be a hardcoded `0`, and `0` is not a neutral placeholder: it is
/// `HistorySeq::OPENING`, a REAL entry number. So every posting this plane made claimed the opening
/// card had priced it — and the node (`plane_node`) is the root unit module that is live on the
/// serving path, so this was a confident wrong answer on shipped traffic, which is worse than none.
///
/// THE CANARY IS THE POINT. Three dated entries over one history and three arrivals, one in each
/// window. Two of the three expected values are NON-ZERO, so the pre-fix code — which answered `0`
/// for every unit — fails this test on those two. A test whose expectations were all `0` would have
/// passed against the bug it was written for.
///
/// It also pins the MILLISECOND binding: `effective_from` is written on the millisecond scale
/// (`root/kernel.rs:435`), so a resolution handed the seconds reading matches only the from-zero
/// opening entry and reports it forever. The `_at_seconds` assertion below is that hazard made
/// visible — it is the bug wearing a different hat, and it would pass a "reads a history" review.
#[test]
fn the_node_provenance_stamp_names_the_card_in_force_when_the_unit_arrived() {
    // Dated on the MILLISECOND scale the history is written on. The first is effective from instant
    // zero however it is dated — one entry has to cover every instant, or an early arrival falls in
    // a hole and is reported as OPENING for a different reason.
    const SECOND_CARD_MS: u64 = 1_700_000_500_000;
    const THIRD_CARD_MS: u64 = 1_700_000_900_000;

    let holder = crate::root::kernel::RootHistory::default();
    holder.apply(busbar_kernel_ledger::cost::RateCard::absent(3), 1_000);
    holder.apply(
        busbar_kernel_ledger::cost::RateCard::absent(11),
        SECOND_CARD_MS,
    );
    holder.apply(
        busbar_kernel_ledger::cost::RateCard::absent(29),
        THIRD_CARD_MS,
    );
    let pinned = holder.pin().expect("three applies put entries in place");
    assert_eq!(
        pinned.seq().get(),
        2,
        "the snapshot's head is the third entry — the figure a stamp must NOT be for a unit that \
         arrived before it, and the one a `read the head` implementation would answer every time"
    );

    let stamped_ms = |ms: u64| card_in_force(Some(&pinned), ms);

    assert_eq!(
        stamped_ms(1_700_000_100_000),
        0,
        "a unit that arrived before the second card was published is priced by the opening entry"
    );
    assert_eq!(
        stamped_ms(1_700_000_600_000),
        1,
        "a unit that arrived in the second card's window names the SECOND entry — not the third, \
         which had not been published when it arrived (#79: publishing never reprices backwards)"
    );
    assert_eq!(
        stamped_ms(1_700_001_000_000),
        2,
        "a unit that arrived after the third card names the third entry"
    );

    // NO HISTORY PINNED — a build with no root ledger. The opening entry is the only one that
    // covers every instant by construction, so it is the honest fallback rather than a silent hole.
    assert_eq!(
        card_in_force(None, 1_700_000_600_000),
        0,
        "no pinned history falls back to the opening entry"
    );

    // THE SECONDS/MILLISECONDS HAZARD, made visible. Handed the SECONDS reading of the same instant
    // that resolves to entry 1 above, every arrival collapses onto the opening entry — the original
    // bug with a lookup in front of it. `Arrived::ms()` is what the settle path passes, and this is
    // why.
    assert_eq!(
        stamped_ms(1_700_000_600),
        0,
        "a seconds-valued instant matches only the from-zero opening entry — which is why the \
         settle path resolves at `Arrived::ms()` and never at `Arrived::secs()`"
    );
}

// ---------------------------------------------------------------------------------------------
// ITEM 126 — TWO BOOKS OVER ONE EVENT: WHICH ONE IS THE INVOICE, AND A DISAGREEMENT IS RED
// ---------------------------------------------------------------------------------------------

/// A dated history of `(effective_from_ms, input rate, output rate, flat fee)` entries over the one
/// lane `"lane"`, built outside the process holder so the proof names its own instants. `present`
/// is the #42 switch: `false` builds the ABSENT card (billing off — every class at nothing, the flat
/// fee still carried, `card_from_config`'s documented shape).
fn fee_history_of(
    entries: &[(u64, f64, f64, i64)],
    present: bool,
) -> crate::root::kernel::PinnedHistory {
    let mut history = busbar_kernel_ledger::cost::History::new();
    for (n, (from, input, output, fee)) in entries.iter().enumerate() {
        let card = crate::root::kernel::card_from_config(
            [(
                "lane",
                busbar_contract::billing::RawTierRates {
                    input: *input,
                    output: *output,
                    cache_read: 0.0,
                    cache_write: 0.0,
                },
            )],
            *fee,
            present,
        );
        history.append(busbar_kernel_ledger::cost::CardEntryDraft {
            effective_from: if n == 0 { 0 } else { *from },
            effective_until: None,
            card,
            appended_at: *from,
            author: busbar_kernel_ledger::cost::Author::Config {
                policy_epoch: n as u64,
            },
        });
    }
    crate::root::kernel::PinnedHistory::for_test(
        std::sync::Arc::new(history),
        busbar_kernel_ledger::cost::HistorySeq((entries.len() - 1) as u64),
    )
}

/// A late report of `input`/`output` tokens and `fee_count` billable requests on `"lane"`.
fn split_report(input: u64, output: u64, fee_count: u32) -> Report {
    let mut units = std::collections::BTreeMap::new();
    if input != 0 {
        units.insert(busbar_contract::records::UNIT_INPUT.to_string(), input);
    }
    if output != 0 {
        units.insert(busbar_contract::records::UNIT_OUTPUT.to_string(), output);
    }
    Report {
        usage: busbar_contract::billing::Usage { usage_units: units },
        fee_count,
        lane: "lane".to_string(),
    }
}

/// **THE INVOICE'S FIGURE for one unit** — what `GET /api/v1/admin/usage` serves for the metering
/// row this unit lands on, computed by the admin read's OWN function (`read_path_money`, a `pub use`
/// of the served derivation, never a copy) at the instant that read resolves the row at:
/// `row_priced_at_ms(bucket start, era start)`, where the era is the `effective_from` of the entry
/// in force when the unit accrued (what `record_metering` stamps as `priced_from_ms`).
fn invoice_micros(
    history: &crate::root::kernel::PinnedHistory,
    arrived_ms: u64,
    report: &Report,
) -> i64 {
    use busbar_core_admin::v1::service::read_path_money as invoice;
    let view = history.view();
    let era = view
        .entry_at(arrived_ms)
        .map_or(0, busbar_kernel_ledger::cost::CardEntry::effective_from);
    let bucket_start_secs = arrived_ms / 1_000 / 86_400 * 86_400;
    let at = invoice::row_priced_at_ms(bucket_start_secs, era);
    let (_, card) = view.card_at(at).expect("a card covers every instant");
    let unit = |k: &str| report.usage.usage_units.get(k).copied().unwrap_or(0);
    let row = invoice::UsageBreakdown {
        tokens_input: unit(busbar_contract::records::UNIT_INPUT),
        tokens_output: unit(busbar_contract::records::UNIT_OUTPUT),
        tokens_cache_read: unit(busbar_contract::records::UNIT_CACHE_READ),
        tokens_cache_creation: unit(busbar_contract::records::UNIT_CACHE_WRITE),
        requests: u64::from(report.fee_count),
        spend_micros: 0,
        classes: Default::default(),
    };
    let cost =
        busbar_kernel::cost::CostModel::resolve_parts(None, 0, &std::collections::BTreeMap::new());
    invoice::derive_spend_micros_row_at_card(&view, at, card, &cost, &report.lane, &row)
        .expect("the invoice's card prices every lane the fixture serves")
}

/// The second book's figure (nano-units) through the CHECKED micro-projection — the one money type,
/// which refuses a figure it cannot hold rather than pinning it at the ceiling (item 28).
fn second_book_micros(
    second_book: Result<u64, busbar_kernel_ledger::cost::Unpriceable>,
) -> Result<i64, String> {
    let nanos = second_book.map_err(|refusal| format!("the second book refused: {refusal:?}"))?;
    busbar_kernel_ledger::cost::Money::of_nanos(u128::from(nanos))
        .and_then(busbar_kernel_ledger::cost::Money::micros_i64)
        .map_err(|refusal| format!("{nanos} nano-units do not project: {refusal:?}"))
}

/// The reconciliation: the second book's posting (nano-units) projected through the ONE checked
/// micro-projection must equal the invoice's figure. A second book that REFUSED where the invoice
/// served a figure disagrees with it. `Err` names the cell and both figures.
fn books_agree(
    label: &str,
    second_book: Result<u64, busbar_kernel_ledger::cost::Unpriceable>,
    invoice: i64,
) -> Result<(), String> {
    let projected = second_book_micros(second_book.clone());
    if projected == Ok(invoice) {
        Ok(())
    } else {
        Err(format!(
            "{label}: the kernel-loop book posted {second_book:?} nano-units ({projected:?} micro) \
             but the invoice (/admin/usage over the governance ledger) serves {invoice} micro"
        ))
    }
}

/// **TWO BOOKS, ONE EVENT — THE INVOICE IS THE GOVERNANCE LEDGER, AND THE SECOND BOOK MUST AGREE WITH
/// IT CELL BY CELL.**
///
/// A delivered LLM unit leaves two records. The walk's completion tap accrues its counts onto the
/// GOVERNANCE LEDGER (the metering series + usage ledger) — raw counts, no price, which is what
/// `/usage` serves and what 1.5.5 billed. Then [`LateAccrual`] PRICES the same reading and posts
/// the priced amount onto the kernel-loop Durability book. By the money model (BUSBAR-1.6.0.md
/// Part 0: *money = f(ledger, ratecard), derived at read time*; #43/#71: the ledger stores counts;
/// #77(3): a price is NEVER stored) only the first can be the invoice: it holds the facts and the
/// served figure is the read-time view over them. The Durability posting carries a priced figure,
/// so it is a derived reading — sound exactly while it agrees with the invoice, and a defect the
/// moment it does not.
///
/// The cells mirror `billing|rate-card|history-mid-window`: a boot card, a 10x card, then a 100x card
/// with a 3-unit flat fee, and a unit arriving in each window — plus a fee-only unit (a failed
/// billing that still carries its request), a token-only provider-origin unit (fee count 0), and a
/// billing-OFF deployment (absent card, #42: tokens at nothing, fee still carried).
///
/// THE NEGATIVE CONTROL is inside the test: the same comparator fed a PLANTED divergence — the
/// second book priced against the head card instead of the card in force at arrival, and the second
/// book dropping the fee — must report RED. A comparator that could not see those would make the
/// green above meaningless.
#[test]
fn the_second_book_agrees_with_the_invoice_cell_by_cell_and_a_divergence_is_red() {
    let kernel = Kernel::new();
    let token = kernel.usage_token();
    let billed = fee_history_of(
        &[
            (0, 0.5, 1.0, 0),
            (5_000, 5.0, 10.0, 0),
            (9_000, 50.0, 100.0, 3),
        ],
        true,
    );
    let billing_off = fee_history_of(&[(0, 0.0, 0.0, 1)], false);

    let cells: [(&str, &crate::root::kernel::PinnedHistory, u64, Report); 7] = [
        (
            "boot card, before A",
            &billed,
            1_000,
            split_report(11, 7, 1),
        ),
        (
            "card A, between A and B",
            &billed,
            6_000,
            split_report(11, 7, 1),
        ),
        (
            "card B + fee, after B",
            &billed,
            10_000,
            split_report(11, 7, 1),
        ),
        (
            "fee only (billing failed)",
            &billed,
            10_000,
            split_report(0, 0, 1),
        ),
        (
            "provider origin (no fee)",
            &billed,
            10_000,
            split_report(11, 7, 0),
        ),
        (
            "billing off, tokens + fee",
            &billing_off,
            10_000,
            split_report(11, 7, 1),
        ),
        (
            "billing off, fee only",
            &billing_off,
            10_000,
            split_report(0, 0, 1),
        ),
    ];

    let mut failures = Vec::new();
    for (label, history, at, report) in &cells {
        let second = priced_amount(history, Arrived::at(*at, 1), &token, report);
        let invoice = invoice_micros(history, *at, report);
        if let Err(e) = books_agree(label, second, invoice) {
            failures.push(e);
        }
    }
    assert!(
        failures.is_empty(),
        "the second book disagrees with the invoice on {} cell(s):\n{}",
        failures.len(),
        failures.join("\n")
    );

    // A NON-VACUITY FLOOR: the billed cells are not all zero, so agreement is not 0 == 0.
    assert_eq!(
        Ok(invoice_micros(&billed, 10_000, &split_report(11, 7, 1))),
        // 11 x 50 + 7 x 100 + the 3-unit fee at the one scale.
        second_book_micros(priced_amount(
            &billed,
            Arrived::at(10_000, 1),
            &token,
            &split_report(11, 7, 1)
        )),
    );
    assert_ne!(invoice_micros(&billed, 10_000, &split_report(11, 7, 1)), 0);

    // THE PLANTED DIVERGENCES — each must go RED.
    // (1) the second book prices a unit that arrived under the boot card at the HEAD card.
    let early = split_report(11, 7, 1);
    let at_head = priced_amount(&billed, Arrived::at(10_000, 1), &token, &early);
    assert!(
        books_agree(
            "planted: priced at head",
            at_head,
            invoice_micros(&billed, 1_000, &early)
        )
        .is_err(),
        "a second book priced at the head card was NOT caught disagreeing with the invoice"
    );
    // (2) the second book drops the flat fee.
    let fee_dropped = priced_amount(
        &billed,
        Arrived::at(10_000, 1),
        &token,
        &split_report(11, 7, 0),
    );
    assert!(
        books_agree(
            "planted: fee dropped",
            fee_dropped,
            invoice_micros(&billed, 10_000, &split_report(11, 7, 1))
        )
        .is_err(),
        "a second book that dropped the fee was NOT caught disagreeing with the invoice"
    );
}

/// A PRESENT card (#42) that prices `"lane"`'s input and output and is SILENT about cache reads.
fn cache_silent_history() -> crate::root::kernel::PinnedHistory {
    use busbar_kernel_ledger::cost::{History, HistorySeq, LaneClass, RateCard};
    let card = RateCard::from_micro_rates(
        [
            (
                LaneClass::new("lane", busbar_contract::records::UNIT_INPUT),
                3.0,
            ),
            (
                LaneClass::new("lane", busbar_contract::records::UNIT_OUTPUT),
                16.0,
            ),
        ],
        0,
    );
    crate::root::kernel::PinnedHistory::for_test(
        std::sync::Arc::new(History::opening(card, 0)),
        HistorySeq(0),
    )
}

/// **A FIGURE THE RECORD CANNOT HOLD REFUSES; IT IS NEVER PINNED AT THE CEILING** (item 28).
///
/// 10^17 output tokens at 1,000 micro-units each is 10^23 nano-units: inside the one function's
/// arithmetic, past a `u64`. The narrowing used to answer `u64::MAX` — a bill nobody posted.
#[test]
fn a_settled_figure_past_the_record_refuses_and_is_never_pinned() {
    let kernel = Kernel::new();
    let token = kernel.usage_token();
    let history = history_of(&[(0, 1_000.0)]);
    let (_, priced) = priced_posting(
        &history,
        Arrived::at(4_000, 7),
        &token,
        &report_of(100_000_000_000_000_000),
    );
    assert!(
        priced.is_ok_and(|p| p.priced_nanos > u128::from(u64::MAX)),
        "the fixture must price past the record, or this pins nothing"
    );
    assert_eq!(
        priced_amount(
            &history,
            Arrived::at(4_000, 7),
            &token,
            &report_of(100_000_000_000_000_000)
        ),
        Err(busbar_kernel_ledger::cost::Unpriceable::Overflow),
    );
}

/// ITEM 129: THE DROP GUARD MARKS, AND THE SWEEP SETTLES WHAT IT MARKED.
///
/// A unit whose task goes away before its end is reached leaves its hold in its cell. The guard used
/// to REMOVE the slot on every way out, so the sweep — the second holder of a key to that cell —
/// could never see it, and nothing in production called the sweep anyway: the hold stayed in a cell
/// nothing would ever take it out of and the unit posted nothing. Now the guard marks and leaves the
/// slot, and the next arrival's sweep takes the hold, posts it onto the node's book, and gives the
/// slot back.
#[test]
fn a_unit_whose_task_went_away_is_marked_and_the_sweep_posts_its_hold() {
    let node = Node::new();
    let book = Arc::new(Mutex::new(
        crate::root::durability::build(
            &crate::root::durability::DurabilityConfig { data_dir: None },
            Box::new(busbar_kernel_wal::NullShipper::new()),
            Box::new(busbar_kernel_ledger::legacy::RecordingRows::new()),
        )
        .expect("a memory-buffered journal cannot fail to open"),
    ));
    node.bind_book(Arc::clone(&book));

    let who = PrincipalId::new("acct:swept");
    let key = UnitKey::new(41);
    let slot = node
        .inflight
        .insert(busbar_kernel::inflight::Enter {
            key,
            origin: OriginKind::Client,
            session: None,
            admin_listener: false,
            zero_hold_tick: false,
            arrival: busbar_kernel::inflight::arrival_hold(&node.kernel, &node.door, who),
            now: EPOCH * 1_000,
        })
        .expect("the uncapped table takes the unit");

    // The task goes away with its hold still in the cell: an end nobody reached.
    drop(Occupied {
        node: &node,
        slot: Arc::clone(&slot),
        arrived: Arrived::at(EPOCH * 1_000, 7),
        reached_end: false,
    });
    assert!(
        slot.is_marked(),
        "the guard MARKS the slot it could not end"
    );
    assert!(
        node.inflight.get(key).is_some(),
        "and leaves it in the table, where the sweep can see it"
    );
    assert_ne!(
        slot.cell().state(),
        busbar_contract::caps::HoldCellState::Taken,
        "the hold is still in the cell: nobody has settled it"
    );

    // The next arrival sweeps.
    assert_eq!(node.sweep(Arrived::at(EPOCH * 1_000 + 5, 99)), 1);
    assert_eq!(
        slot.cell().state(),
        busbar_contract::caps::HoldCellState::Taken,
        "the sweep took the hold out of the cell"
    );
    assert!(node.inflight.get(key).is_none(), "and gave the slot back");
    {
        let durability = book.lock().unwrap_or_else(|p| p.into_inner());
        let replayed = durability
            .journal
            .replay()
            .expect("reads back")
            .expect("verifies");
        assert_eq!(
            replayed
                .iter()
                .filter(|r| r.class == busbar_kernel_wal::RecordClass::Transaction)
                .count(),
            1,
            "the swept hold's posting is on the journal"
        );
        assert_eq!(durability.ledger.book().len(), 1, "and on the book");
    }
    // Nothing marked is left, so the next arrival's sweep walks nothing.
    assert_eq!(node.sweep(Arrived::at(EPOCH * 1_000 + 6, 100)), 0);

    // A unit that reached its own end gives its slot straight back, unmarked.
    let key = UnitKey::new(42);
    let slot = node
        .inflight
        .insert(busbar_kernel::inflight::Enter {
            key,
            origin: OriginKind::Client,
            session: None,
            admin_listener: false,
            zero_hold_tick: false,
            arrival: busbar_kernel::inflight::arrival_hold(
                &node.kernel,
                &node.door,
                PrincipalId::new("acct:finished"),
            ),
            now: EPOCH * 1_000,
        })
        .expect("the uncapped table takes the unit");
    drop(Occupied {
        node: &node,
        slot: Arc::clone(&slot),
        arrived: Arrived::at(EPOCH * 1_000, 8),
        reached_end: true,
    });
    assert!(!slot.is_marked());
    assert!(node.inflight.get(key).is_none());
}

// ---------------------------------------------------------------------------------------------
// P2A-books (#71/#43/#42; follows items 126 and 71): THE SECOND BOOK CARRIES THE COUNTS, AND THE
// TWO BOOKS AGREE ON EVERY CLASS CELL
// ---------------------------------------------------------------------------------------------

/// The open class a rerank's search units are ledgered under (`busbar-llm-codec`'s
/// `SEARCH_UNITS_CLASS`, which `record_resp_usage` ledgers verbatim — item 134). Spelled here because
/// this crate does not depend on the codec.
const SEARCH_UNITS: &str = "search_units";

/// The classes the units these tests drive report are DECLARED — what the boot's registration
/// (`register_classes`: the reserved four, the llm plane's declared `search_units`) makes true in a
/// real process. The vocabulary is the process's, so registering them again is idempotent.
fn declare_test_classes() {
    let mut registration = crate::root::kernel::new_registration();
    for class in busbar_contract::records::RESERVED_UNITS {
        let _ = registration.key(class);
    }
    let _ = registration.key(SEARCH_UNITS);
}

/// Run the late arm's posting for one drained `report` onto a fresh node book, and hand the book
/// back.
fn late_post(
    history: &crate::root::kernel::PinnedHistory,
    at: Arrived,
    principal: &str,
    report: &Report,
) -> crate::root::durability::NodeBook {
    declare_test_classes();
    // The book prices its chain against the same history the arm priced the unit against.
    let pinned = history.clone();
    let node = crate::root::durability::node_book_over(Box::new(move || Some(pinned.clone())));
    let kernel = Kernel::new();
    let (durability, ledger, usage) = (
        kernel.durability_token(),
        kernel.ledger_token(),
        kernel.usage_token(),
    );
    post_late(
        &crate::root::durability::SharedBook::over(Arc::clone(&node.durability)),
        &LateTokens {
            durability: &durability,
            ledger: &ledger,
            usage: &usage,
        },
        history,
        &PrincipalId::new(principal),
        at,
        report,
        None,
    );
    node
}

/// The unit records the second book's chain holds (settlements and counts rows), read back off the
/// journal — each with the figure the book derives from its counts at its epoch (the chain itself
/// holds no money, #71).
fn second_book_rows(
    node: &crate::root::durability::NodeBook,
) -> Vec<crate::root::durability::Posting> {
    let durability = node.durability.lock().expect("unpoisoned");
    durability
        .read_back()
        .into_iter()
        // The overdraft CARRY beside a late settlement repeats its unreserved part and carries no
        // counts; it is the same unit's second record, not a second unit.
        .filter(|p| p.kind != crate::root::durability::PostingKind::Carry)
        .collect()
}

/// THE GOVERNANCE LEDGER'S ROW for one unit — the invoice's facts: the class map the tap ledgers
/// VERBATIM (`meter_ledger`; for a rerank `record_resp_usage` ledgers `{search_units: n}`), the
/// serving lane, and the billable count the fee is charged on.
fn governance_row(report: &Report) -> crate::root::durability::UnitCounts {
    crate::root::durability::UnitCounts {
        lane: report.lane.clone(),
        fee_count: u64::from(report.fee_count),
        classes: report
            .usage
            .usage_units
            .iter()
            .filter(|(_, count)| **count > 0)
            .map(|(class, count)| (class.clone(), *count))
            .collect(),
    }
}

/// **THE AGREEMENT CHECK, EVERY CLASS CELL** — the second book's record of one unit against the
/// governance ledger's, cell by cell over the UNION of their classes (reserved and open alike), the
/// lane and the fee count; then the money: the invoice is the one function over the governance row
/// at the unit's arrival (`price_exact`, which every served read prices through), and the second
/// book must hold that figure as a settlement — or, where the invoice is nothing or REFUSES, a
/// counts row with no figure (a refused one where it refuses). `Err` names every cell that differs.
///
/// 21f725601's comparator priced the TOKEN cells alone (`UsageBreakdown`), so a class outside the
/// reserved four could differ between the books and both sides of it would still read equal.
fn every_cell_agrees(
    label: &str,
    second: &[crate::root::durability::Posting],
    governance: &crate::root::durability::UnitCounts,
    history: &crate::root::kernel::PinnedHistory,
    arrived_ms: u64,
) -> Result<(), String> {
    use crate::root::durability::PostingKind;
    let [row] = second else {
        return Err(format!(
            "{label}: the second book holds {} records for one unit, not one",
            second.len()
        ));
    };
    let Some(counts) = row.counts.as_ref() else {
        return Err(format!(
            "{label}: the second book's record carries no counts"
        ));
    };
    let mut cells = Vec::new();
    let classes: std::collections::BTreeSet<&String> = counts
        .classes
        .keys()
        .chain(governance.classes.keys())
        .collect();
    for class in classes {
        let (second_book, invoice) = (counts.classes.get(class), governance.classes.get(class));
        if second_book != invoice {
            cells.push(format!(
                "class {class}: second book {second_book:?}, governance ledger {invoice:?}"
            ));
        }
    }
    if counts.lane != governance.lane {
        cells.push(format!("lane: {:?} vs {:?}", counts.lane, governance.lane));
    }
    if counts.fee_count != governance.fee_count {
        cells.push(format!(
            "fee count: {} vs {}",
            counts.fee_count, governance.fee_count
        ));
    }
    let invoice =
        busbar_kernel_ledger::cost::price_exact(&[governance.entry(arrived_ms)], &history.view())
            .and_then(busbar_kernel_ledger::cost::nanos_of_exact);
    let money_agrees = match (&invoice, row.kind, row.refusal.as_ref()) {
        (Ok(nanos), PostingKind::Settlement, None) => {
            u128::try_from(row.settled).is_ok_and(|settled| settled == *nanos) && *nanos != 0
        }
        (Ok(0), PostingKind::Counted, None) => true,
        (Err(_), PostingKind::Counted, Some(_)) => true,
        _ => false,
    };
    if !money_agrees {
        cells.push(format!(
            "money: second book {:?} settled {} (refusal {:?}), invoice {invoice:?} nano-units",
            row.kind, row.settled, row.refusal
        ));
    }
    if cells.is_empty() {
        Ok(())
    } else {
        Err(format!("{label}: {}", cells.join("; ")))
    }
}

/// A PRESENT card over `"lane"` pricing input 3 / output 16 micro-units, a fee of `fee`, and — when
/// `search_units` is `Some` — the open class `search_units` at that many nano-units per unit
/// (the `units:` grammar, item 123). `None` is a present card SILENT about search units.
fn rerank_history(fee: i64, search_units: Option<u64>) -> crate::root::kernel::PinnedHistory {
    rerank_history_on("lane", fee, search_units)
}

/// [`rerank_history`], over the lane named `lane`.
fn rerank_history_on(
    lane: &str,
    fee: i64,
    search_units: Option<u64>,
) -> crate::root::kernel::PinnedHistory {
    use busbar_kernel_ledger::cost::{History, HistorySeq, LaneClass, RateCard};
    let card = RateCard::from_micro_rates(
        [
            (
                LaneClass::new(lane, busbar_contract::records::UNIT_INPUT),
                3.0,
            ),
            (
                LaneClass::new(lane, busbar_contract::records::UNIT_OUTPUT),
                16.0,
            ),
        ],
        fee,
    )
    .with_unit_rates(search_units.map(|nanos| (LaneClass::new(lane, SEARCH_UNITS), nanos)));
    crate::root::kernel::PinnedHistory::for_test(
        std::sync::Arc::new(History::opening(card, 0)),
        HistorySeq(0),
    )
}

/// A rerank's drained report: `units` search units and one billable request, no tokens.
fn rerank_report(units: u64) -> Report {
    Report {
        usage: busbar_contract::billing::Usage {
            usage_units: std::collections::BTreeMap::from([(SEARCH_UNITS.to_string(), units)]),
        },
        fee_count: 1,
        lane: "lane".to_string(),
    }
}

/// **AN UNPRICED CLASS ON A PRESENT CARD LEAVES A DURABLE COUNTS ROW, AND THE READ REFUSES**
/// (#71/#43/#42).
///
/// The card prices input and output and is silent about cache reads; the unit read all three. The
/// late arm used to post NO row at all — it warned with the counts and returned, so the second book
/// held nothing for a unit the node served. Now it posts the counts row: every class, whole, with
/// the money UNPRICED (no figure, no zero, no partial), the balance unmoved, and the read over it
/// refusing. Rows posted per refused unit: 0 -> 1.
#[test]
fn an_unpriced_class_on_a_present_card_leaves_a_durable_counts_row_and_the_read_refuses() {
    use crate::root::durability::PostingKind;
    let history = cache_silent_history();
    let mut report = split_report(1_000, 250, 1);
    report.usage.usage_units.insert(
        busbar_contract::records::UNIT_CACHE_READ.to_string(),
        10_000_000,
    );
    let at = Arrived::at(4_000, 7);
    let node = late_post(&history, at, "vk_refused", &report);

    let rows = second_book_rows(&node);
    assert_eq!(rows.len(), 1, "one counts row per refused unit: {rows:?}");
    let row = &rows[0];
    assert_eq!(row.kind, PostingKind::Counted);
    let counts = row.counts.as_ref().expect("the row carries the counts");
    assert_eq!(
        counts.classes,
        std::collections::BTreeMap::from([
            (busbar_contract::records::UNIT_INPUT.to_string(), 1_000),
            (busbar_contract::records::UNIT_OUTPUT.to_string(), 250),
            (
                busbar_contract::records::UNIT_CACHE_READ.to_string(),
                10_000_000
            ),
        ]),
        "every count, whole — not zeroed, not trimmed to the priced classes"
    );
    assert_eq!((counts.lane.as_str(), counts.fee_count), ("lane", 1));
    assert!(
        row.refusal
            .as_deref()
            .is_some_and(|why| why.contains("ClassUnpriced") && why.contains("cache_read")),
        "the money is refused and says which class: {:?}",
        row.refusal
    );
    assert_eq!(
        (row.reserved, row.settled, row.overdraft),
        (0, 0, 0),
        "no figure: no zero posted as a price, no partial"
    );

    let durability = node.durability.lock().expect("unpoisoned");
    let key = balance(&PrincipalId::new("vk_refused"));
    let window =
        busbar_kernel::governance::budget_window(busbar_kernel::governance::WINDOW_DAY, at.secs());
    assert_eq!(
        durability.ledger.book().get(&key, window).settled,
        0,
        "a refused unit moves no balance"
    );
    assert!(
        durability.settled_read(&key, window).is_err(),
        "the read over a refused counts row refuses (#42), never the priced remainder"
    );
    assert_eq!(durability.refused_rows().len(), 1);

    // And the two books agree on it cell by cell: the governance read refuses the same class.
    every_cell_agrees(
        "refused",
        &rows,
        &governance_row(&report),
        &history,
        at.ms(),
    )
    .expect("both books refuse the same unit");
}

/// **A RERANK'S SEARCH UNITS AGREE ACROSS BOTH BOOKS** (items 123/134 on the governance ledger; this
/// book now carries and prices them too). Priced: the settlement carries `{search_units: 50}` and
/// the figure the invoice derives from it. A present card silent about search units: both REFUSE.
/// And the 21f725601 token cells, through the every-cell check, still agree.
#[test]
fn a_reranks_search_units_agree_across_both_books() {
    let at = Arrived::at(4_000, 7);
    // 2,000 micro-units = 2,000,000 nano-units per search unit, and a 3-unit fee.
    let priced = rerank_history(3, Some(2_000_000));
    let report = rerank_report(50);
    let node = late_post(&priced, at, "vk_rerank", &report);
    let rows = second_book_rows(&node);
    every_cell_agrees(
        "rerank, priced",
        &rows,
        &governance_row(&report),
        &priced,
        at.ms(),
    )
    .expect("the books agree on the rerank");
    // NON-VACUITY: the search units are in the figure, not only the fee.
    let fee_only = late_post(&priced, at, "vk_fee", &rerank_report(0));
    let fee_only = second_book_rows(&fee_only);
    assert_eq!(
        rows[0].settled - fee_only[0].settled,
        50 * 2_000_000,
        "the second book priced the 50 search units"
    );

    let silent = rerank_history(3, None);
    let node = late_post(&silent, at, "vk_silent", &report);
    let rows = second_book_rows(&node);
    every_cell_agrees(
        "rerank, card silent about search units",
        &rows,
        &governance_row(&report),
        &silent,
        at.ms(),
    )
    .expect("both books refuse a rerank the card is silent about");
    assert!(
        rows[0]
            .refusal
            .as_deref()
            .is_some_and(|w| w.contains(SEARCH_UNITS)),
        "{:?}",
        rows[0].refusal
    );

    // The token cells of 21f725601, every class cell compared.
    let billed = fee_history_of(
        &[
            (0, 0.5, 1.0, 0),
            (5_000, 5.0, 10.0, 0),
            (9_000, 50.0, 100.0, 3),
        ],
        true,
    );
    let mut failures = Vec::new();
    for (label, at_ms, report) in [
        ("boot card", 1_000, split_report(11, 7, 1)),
        ("card A", 6_000, split_report(11, 7, 1)),
        ("card B + fee", 10_000, split_report(11, 7, 1)),
        ("fee only", 10_000, split_report(0, 0, 1)),
        ("no fee", 10_000, split_report(11, 7, 0)),
    ] {
        let at = Arrived::at(at_ms, 1);
        let node = late_post(&billed, at, "vk_tokens", &report);
        if let Err(e) = every_cell_agrees(
            label,
            &second_book_rows(&node),
            &governance_row(&report),
            &billed,
            at_ms,
        ) {
            failures.push(e);
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// **A PLANTED OPEN-CLASS DIVERGENCE GOES RED.** The second book's rerank row, planted three ways —
/// the open class under-counted, the open class dropped, and the figure priced without it (the
/// shape this book had: fee only, no counts) — each is named by the every-cell check.
#[test]
fn a_planted_open_class_divergence_goes_red() {
    let at = Arrived::at(4_000, 7);
    let priced = rerank_history(3, Some(2_000_000));
    let report = rerank_report(50);
    let governance = governance_row(&report);
    let rows = second_book_rows(&late_post(&priced, at, "vk_rerank", &report));
    every_cell_agrees("unplanted", &rows, &governance, &priced, at.ms())
        .expect("the unplanted rows agree, so a red below is the plant's");

    let mut undercounted = rows.clone();
    if let Some(counts) = undercounted[0].counts.as_mut() {
        counts.classes.insert(SEARCH_UNITS.to_string(), 49);
    }
    let red = every_cell_agrees("planted: 49", &undercounted, &governance, &priced, at.ms());
    assert!(
        red.as_ref()
            .is_err_and(|e| e.contains("class search_units")),
        "an under-counted open class was NOT caught: {red:?}"
    );

    let mut dropped = rows.clone();
    if let Some(counts) = dropped[0].counts.as_mut() {
        counts.classes.remove(SEARCH_UNITS);
    }
    assert!(
        every_cell_agrees("planted: dropped", &dropped, &governance, &priced, at.ms()).is_err(),
        "a dropped open class was NOT caught"
    );

    // The pre-change second book: priced at the fee alone, with no counts on the record.
    let fee_only = second_book_rows(&late_post(&priced, at, "vk_fee", &rerank_report(0)));
    let mut head_shaped = rows.clone();
    head_shaped[0].settled = fee_only[0].settled;
    assert!(
        every_cell_agrees(
            "planted: fee only",
            &head_shaped,
            &governance,
            &priced,
            at.ms()
        )
        .is_err_and(|e| e.contains("money")),
        "a second book that priced the rerank at the fee alone was NOT caught"
    );
    head_shaped[0].counts = None;
    assert!(
        every_cell_agrees(
            "planted: no counts",
            &head_shaped,
            &governance,
            &priced,
            at.ms()
        )
        .is_err(),
        "a second book with no counts was NOT caught"
    );
}

/// The serving lane of the served-rerank fixture: a Cohere lane, the one dialect whose rerank reader
/// reads `meta.billed_units.search_units`.
const RERANK_LANE: &str = "rerank-v3.5";

/// **THE LLM PLANE'S BOOK BINDING JOURNALS THE APPLIED CARDS** (#79): a build with this plane and no
/// admin surface binds the dated rate-card history to the book here or nowhere, so a card applied
/// after the boot must land on the chain through this binding alone. Before, only the admin
/// assembly bound it: this plane's node settled onto the book while every live apply stayed in
/// memory, and a restart repriced the node's postings at the boot card.
#[test]
fn binding_the_node_to_the_book_journals_every_card_applied_after_it() {
    use crate::root::kernel::{CardApplied, RootHistory};
    fn apply(holder: &RootHistory, input: f64, at: u64) {
        let lanes = [(
            "gpt".to_string(),
            busbar_contract::billing::RawTierRates {
                input,
                output: 0.0,
                cache_read: 0.0,
                cache_write: 0.0,
            },
        )];
        let _ = holder.apply_rates(
            &busbar_kernel::rate_apply::RawRates {
                lanes: &lanes,
                units: &[],
                flat_minor: 0,
                present: true,
                plane_fees: &busbar_kernel::config::PlaneFeesMap::new(),
            },
            at,
        );
    }
    let dir = std::env::temp_dir().join(format!(
        "busbar-node-book-cards-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch directory");

    // The production boot's holder: armed, resolved at boot, its history rebuilt by the book.
    let holder: &'static RootHistory = Box::leak(Box::default());
    holder.arm_journal();
    apply(holder, 3.0, 1_000);
    let book = Arc::new(Mutex::new(
        crate::root::durability::build_with_cards(
            &crate::root::durability::DurabilityConfig {
                data_dir: Some(dir.clone()),
            },
            7,
            Box::new(busbar_kernel_wal::NullShipper::new()),
            Box::new(busbar_kernel_ledger::legacy::RecordingRows::new()),
            Box::new(move || holder.pin()),
            Some(holder),
        )
        .expect("the journal opens"),
    ));

    // THE LLM PLANE'S BINDING, and nothing else — no admin assembly.
    super::bind_node_book(&Node::new(), holder, Arc::clone(&book));
    apply(holder, 5.0, 20_000);

    let cards = book
        .lock()
        .expect("the book")
        .journal
        .replay()
        .expect("reads")
        .expect("verifies")
        .iter()
        .filter(|r| r.class == busbar_kernel_wal::RecordClass::Policy)
        .filter_map(|r| CardApplied::from_body(&r.body))
        .map(|applied| applied.effective_from)
        .collect::<Vec<_>>();
    assert_eq!(
        cards,
        vec![0, 20_000],
        "the boot card and the card applied after the binding are both on the chain"
    );
    drop(book);
    let _ = std::fs::remove_dir_all(&dir);
}

/// ONE LINE PER UNIT, WHEN THE LATE READING NEVER ARRIVES (KERNEL<>PLUGINS step 14).
///
/// The exit hands its posting to the late arm and writes none itself. A body that drains with no
/// reading behind it (the tap never filled) must still leave the unit's line: the exit's own
/// posting, written by the arm, closing the reservation. An arm that dropped it would leave the
/// unit with no line at all.
#[test]
fn a_late_arm_with_no_reading_writes_the_exits_own_line() {
    let history = rerank_history_on(RERANK_LANE, 3, Some(2_000_000));
    let pinned = history.clone();
    let book = crate::root::durability::node_book_over(Box::new(move || Some(pinned.clone())));
    let kernel = Kernel::new();
    let who = PrincipalId::new("acct:late-none");
    let hold = busbar_contract::caps::Hold::open(&kernel.admit_token(), who.clone(), 0);
    let usage = busbar_contract::caps::Usage::report(&kernel.usage_token(), Vec::new())
        .expect("an empty report fits");
    let exit = busbar_contract::caps::Posted::settle(hold, 0, &usage, &kernel.ledger_token());
    let arm = LateAccrual {
        book: Arc::clone(&book.durability),
        history,
        durability_token: kernel.durability_token(),
        ledger_token: kernel.ledger_token(),
        usage_token: kernel.usage_token(),
        principal: who,
        arrived: Arrived::at(EPOCH * 1_000, 3),
        late: Box::new(|| None),
        exit: Some(exit),
        outcome: None,
        seal: None,
    };
    arm.post();
    let rows = second_book_rows(&book);
    assert_eq!(rows.len(), 1, "the unit keeps its one line: {rows:?}");
    assert_eq!(
        rows[0].kind,
        crate::root::durability::PostingKind::Settlement,
        "and it is the exit's settlement: {rows:?}"
    );
    assert_eq!(rows[0].settled, 0);
}

/// **A CLASS NO PLANE DECLARED IS REFUSED FAIL-CLOSED, NEVER BILLED AT ZERO**
/// (`BUSBAR-1.6.0.md` §7). The unit read 1,000 input tokens and 40 units of a class nothing
/// declares or configures. The line is still written with EVERY count, its money is refused
/// (`UndeclaredClass`), no balance moves, and the read over it refuses — even on a card that prices
/// input.
#[test]
fn a_class_no_plane_declared_is_refused_and_keeps_its_counts() {
    let history = cache_silent_history();
    let mut report = split_report(1_000, 0, 1);
    report
        .usage
        .usage_units
        .insert("units_nobody_declared".to_string(), 40);
    let at = Arrived::at(4_000, 7);
    let node = late_post(&history, at, "vk_undeclared", &report);

    let rows = second_book_rows(&node);
    assert_eq!(rows.len(), 1, "one line per unit: {rows:?}");
    let row = &rows[0];
    let counts = row.counts.as_ref().expect("the line carries the counts");
    assert_eq!(counts.classes.get("units_nobody_declared"), Some(&40));
    assert_eq!(
        counts.classes.get(busbar_contract::records::UNIT_INPUT),
        Some(&1_000)
    );
    assert!(
        row.refusal.as_deref().is_some_and(
            |why| why.contains("UndeclaredClass") && why.contains("units_nobody_declared")
        ),
        "the money is refused and names the class: {:?}",
        row.refusal
    );
    assert_eq!((row.reserved, row.settled, row.overdraft), (0, 0, 0));
    let durability = node.durability.lock().expect("unpoisoned");
    let key = balance(&PrincipalId::new("vk_undeclared"));
    let window =
        busbar_kernel::governance::budget_window(busbar_kernel::governance::WINDOW_DAY, at.secs());
    assert_eq!(durability.ledger.book().get(&key, window).settled, 0);
    assert!(durability.settled_read(&key, window).is_err());
    drop(durability);

    // And on a node with NO card, where a declared class would post at nothing, the undeclared one
    // is still refused — the written line and every replay of it (`read_back` re-derives the chain).
    let absent = fee_history_of(&[(0, 0.0, 0.0, 0)], false);
    let node = late_post(&absent, at, "vk_undeclared_absent", &report);
    let rows = second_book_rows(&node);
    assert_eq!(rows.len(), 1, "one line per unit: {rows:?}");
    assert!(
        rows[0]
            .refusal
            .as_deref()
            .is_some_and(|why| why.contains("UndeclaredClass")),
        "never billed at zero, and a replay keeps the refusal: {:?}",
        rows[0].refusal
    );
}

/// **A DECLARED OPEN CLASS ON AN ABSENT CARD IS NOT REFUSED** — 1.5.5's billing-off shape is
/// unchanged: a rerank's declared `search_units` on a node with no card posts its counts row at
/// nothing, with no refusal, exactly as before the undeclared-class rule.
#[test]
fn a_declared_open_class_on_an_absent_card_posts_its_counts_unrefused() {
    let absent = fee_history_of(&[(0, 0.0, 0.0, 0)], false);
    let mut report = split_report(0, 0, 0);
    report
        .usage
        .usage_units
        .insert(SEARCH_UNITS.to_string(), 50);
    let node = late_post(&absent, Arrived::at(4_000, 7), "vk_absent", &report);
    let rows = second_book_rows(&node);
    assert_eq!(rows.len(), 1, "one line per unit: {rows:?}");
    assert_eq!(rows[0].refusal, None, "a declared class is never refused");
    assert_eq!(
        rows[0]
            .counts
            .as_ref()
            .and_then(|c| c.classes.get(SEARCH_UNITS)),
        Some(&50)
    );
}

/// THE WALK'S DISPATCH RECORD, ON THE BOOK (ARCHITECT P3 (c), 2026-10-02): a write-ahead record the
/// egress walk makes for a unit whose facts are open is written onto the node's book under that
/// unit's balance, window and arrival before the dial; one for a unit with no open facts is refused,
/// so its dial never happens.
#[test]
fn a_dispatch_record_is_written_on_the_book_under_its_units_facts() {
    use busbar_kernel_egress::ports::{Dispatched, DurabilityUnavailable, Journal};
    let node = Arc::new(Node::new());
    let durability = crate::root::durability::build(
        &crate::root::durability::DurabilityConfig { data_dir: None },
        Box::new(busbar_kernel_wal::NullShipper::new()),
        Box::new(busbar_kernel_ledger::legacy::RecordingRows::new()),
    )
    .expect("a memory-buffered journal cannot fail to open");
    let book = Arc::new(std::sync::Mutex::new(durability));
    node.bind_book(Arc::clone(&book));
    let written = || {
        book.lock()
            .unwrap_or_else(|p| p.into_inner())
            .journal
            .replay()
            .expect("reads back")
            .expect("verifies")
            .len()
    };
    let site = NodeEndPost::new(Arc::clone(&node));
    let record = |unit: u64| Dispatched {
        leg: 0,
        attempt: 1,
        pool: String::new(),
        destination: busbar_contract::DestinationId::new(0),
        lane: None,
        unit: UnitKey::new(unit),
    };
    site.open(
        UnitKey::new(51),
        PrincipalId::new("acct:dispatch"),
        Arrived::at(EPOCH * 1_000, 0),
        None,
    );
    let before = written();
    assert_eq!(site.dispatched(&record(51)), Ok(()));
    assert_eq!(written(), before + 1, "the dispatch is on the book");
    assert_eq!(
        site.dispatched(&record(52)),
        Err(DurabilityUnavailable),
        "no open facts, no record, no dial"
    );
    assert_eq!(written(), before + 1);
    site.close(UnitKey::new(51));
}
