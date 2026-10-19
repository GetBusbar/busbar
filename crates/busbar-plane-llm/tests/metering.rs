//! What the door counts of an answer, by class, and that the counts are already normalized.
//!
//! Two things are asserted here and they are the two that decide a bill, on the path the plane's
//! door serves (the arrival, the far end's answer read through the reply, and the counts it reports
//! to the kernel, `plane_door::counts`).
//!
//! The door reports the far end's own counts by class and nothing else: no total, no price and no
//! decision. And the four token classes partition the input once. Some dialects report a cached
//! count INSIDE their input total and some report it beside; a plane that added the two families
//! together for the first kind would bill the cached prefix twice. The case below is the one where
//! getting it wrong is worth eighty tokens a request.

use busbar_contract::plane::PlaneMeta;
use busbar_plane_llm::exchange::arrive::arrive;
use busbar_plane_llm::exchange::attempt::stream_intent;
use busbar_plane_llm::exchange::handler_of;
use busbar_plane_llm::exchange::reply::{At, Reply, ReplyCtx};
use busbar_plane_llm::exchange::shaping::Shaping;
use busbar_plane_llm::plane_door::{counts, TOKEN_CLASSES};
use busbar_plane_llm::LlmPlane;

/// The host the door is handed: a fixed entropy pattern and no clock.
struct FixedHost;

impl busbar_contract::codec::CodecHost for FixedHost {
    fn fill_entropy(&self, out: &mut [u8]) -> bool {
        out.fill(7);
        true
    }

    fn wall_clock_now(&self) -> Option<u64> {
        None
    }
}

const HOST: &dyn busbar_contract::codec::CodecHost = &FixedHost;

/// The generation the door holds: one far end speaking `dialect`, under the pool `p`.
fn generation(dialect: &str) -> Shaping {
    Shaping::from_settings(&serde_json::json!({
        "providers": { "far": { "protocol": dialect, "base_url": "https://far.invalid" } },
        "models": { "m": { "provider": "far" } },
        "pools": { "p": { "members": ["m"] } }
    }))
    .expect("a well-formed generation reads")
}

/// One caller of `dialect` at `path` with `request`, answered by a far end of the same dialect with
/// `answer` under `content_type`: the counts the door reports at the answer's end, by class name.
fn metered(
    dialect: &str,
    path: &str,
    request: &[u8],
    content_type: &[u8],
    answer: &[u8],
) -> Vec<(&'static str, u64)> {
    let shaping = generation(dialect);
    let caller: &[(&[u8], &[u8])] = &[(b"content-type", b"application/json")];
    let arrived = arrive("POST", path, caller, request, &shaping).expect("the request arrives");
    let lane = shaping.lane("m").expect("the member's lane");
    let ctx = ReplyCtx {
        arrived: &arrived,
        lane,
        intent: handler_of(&arrived)
            .map(|h| stream_intent(h, arrived.parsed.as_ref()))
            .unwrap_or_default(),
        passthrough: false,
        translate_cap: busbar_contract::codec::TRANSLATE_BODY_MAX_BYTES_DEFAULT,
    };
    let head: &[(&[u8], &[u8])] = &[(b"content-type", content_type)];
    let mut reply = Reply::new(HOST, &ctx, 200, head);
    let at = At {
        now_s: 1_752_000_000,
        elapsed_ms: Some(1),
    };
    let piece = reply.feed(HOST, &ctx, answer, true, at);
    assert!(piece.done, "a whole answer ends on its last piece");
    counts(&piece.units)
        .iter()
        .map(|c| {
            let class = usize::try_from(c.class).expect("a class index");
            (
                *TOKEN_CLASSES
                    .get(class)
                    .unwrap_or_else(|| panic!("a token answer reports a token class, got {class}")),
                c.amount,
            )
        })
        .collect()
}

const OPENAI_REQUEST: &[u8] =
    br#"{"model":"p","max_tokens":32,"messages":[{"role":"user","content":"Hello"}]}"#;

/// A cached prefix is counted once, not twice.
///
/// This dialect's wire total INCLUDES the cached count: a hundred prompt tokens of which eighty
/// were served from a cache. Input and cache read must be twenty and eighty, not a hundred and
/// eighty.
#[test]
fn a_cached_prefix_is_counted_once() {
    let answer = br#"{"id":"chatcmpl-1","object":"chat.completion","created":1752000000,"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":100,"completion_tokens":10,"total_tokens":110,"prompt_tokens_details":{"cached_tokens":80}}}"#;
    assert_eq!(
        metered(
            "openai",
            "/v1/chat/completions",
            OPENAI_REQUEST,
            b"application/json",
            answer
        ),
        vec![
            ("input", 20),
            ("output", 10),
            ("cache_read", 80),
            ("cache_write", 0)
        ],
        "the cached prefix was not subtracted from the wire input total"
    );
}

/// A streamed answer bills the tokens its usage frame reports, partitioned the same way.
#[test]
fn a_streamed_usage_frame_meters_the_tokens_it_reports() {
    let request = br#"{"model":"p","max_tokens":32,"stream":true,"messages":[{"role":"user","content":"Hello"}]}"#;
    let answer = concat!(
        "data: ",
        r#"{"id":"chatcmpl-4","object":"chat.completion.chunk","created":1752000000,"model":"m","choices":[{"index":0,"delta":{"content":"ok"},"finish_reason":null}]}"#,
        "\n\n",
        "data: ",
        r#"{"id":"chatcmpl-4","object":"chat.completion.chunk","created":1752000000,"model":"m","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":100,"completion_tokens":10,"total_tokens":110,"prompt_tokens_details":{"cached_tokens":80}}}"#,
        "\n\n",
        "data: [DONE]\n\n",
    )
    .as_bytes();
    assert_eq!(
        metered(
            "openai",
            "/v1/chat/completions",
            request,
            b"text/event-stream",
            answer
        ),
        vec![
            ("input", 20),
            ("output", 10),
            ("cache_read", 80),
            ("cache_write", 0)
        ],
        "a streamed answer did not meter the tokens its usage frame reports"
    );
}

/// Every class the plane DECLARES is a class the door reports, and it reports no other.
///
/// The direction that costs money: a declared class is what an operator prices in the rate card;
/// a class the door never reports posts nothing, so the class prices at nothing and the invoice is
/// short by whatever it was worth. The dialect below states its two cache counts BESIDE its input
/// total, so one answer of its shape exercises every class the plane can name.
#[test]
fn every_declared_class_is_a_class_the_door_reports() {
    let request =
        br#"{"model":"p","max_tokens":32,"messages":[{"role":"user","content":"Hello"}]}"#;
    let answer = br#"{"id":"msg_1","type":"message","role":"assistant","model":"m","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":20,"output_tokens":10,"cache_read_input_tokens":80,"cache_creation_input_tokens":40}}"#;
    let reported = metered(
        "anthropic",
        "/v1/messages",
        request,
        b"application/json",
        answer,
    );
    assert_eq!(
        reported,
        vec![
            ("input", 20),
            ("output", 10),
            ("cache_read", 80),
            ("cache_write", 40)
        ]
    );
    let mut emitted: Vec<&str> = reported.iter().map(|(class, _)| *class).collect();
    emitted.sort_unstable();
    let mut declared: Vec<&str> = <LlmPlane as PlaneMeta>::METER_CLASSES
        .iter()
        .map(|class| class.key.as_str())
        .collect();
    declared.sort_unstable();
    assert_eq!(
        declared, emitted,
        "a class is declared that no answer can make the door report, or reported that none declares"
    );
}

/// ONE DECLARATION, ONE SOURCE (ARCHITECT, `$` meter classes: "Money is ledger x ratecard, so there
/// must be ONE declaration and one source. The door's billable classes, which are what the
/// dispatcher checks, are the source; MeterClassDecl derives from them").
///
/// Every class the plane's `MeterClassDecl` list names is the door tail's billable class at the same
/// index, in the same family, and each is 1.5.5's own name for the tier, byte for byte: the
/// `rate_card:` tiers `input_utok`/`output_utok`/`cache_read_utok`/`cache_write_utok`, the ledger's
/// `TierTokens { input, output, cache_read, cache_write }` and the spend metrics' `tier` label. RED
/// while the list spelled its own `tokens_in`/`tokens_out`, names no card prices and no tier carries.
#[test]
fn the_meter_classes_are_the_doors_billable_classes_by_their_1_5_5_names() {
    use busbar_plane_llm::plane_door::TAIL;
    let declared: Vec<(&str, &str)> = <LlmPlane as PlaneMeta>::METER_CLASSES
        .iter()
        .map(|c| (c.key.as_str(), c.family))
        .collect();
    // SAFETY: the tail's billable classes are a `'static` list of `billable_classes_len` entries.
    let stated =
        unsafe { std::slice::from_raw_parts(TAIL.billable_classes, TAIL.billable_classes_len) };
    let door: Vec<(&str, &str)> = stated[..declared.len()]
        .iter()
        .map(|b| {
            // SAFETY: each `AbiStr` names a `'static` string of `len` bytes.
            let (c, f) = unsafe {
                (
                    std::slice::from_raw_parts(b.class.ptr, b.class.len),
                    std::slice::from_raw_parts(b.family.ptr, b.family.len),
                )
            };
            (
                std::str::from_utf8(c).expect("a class is UTF-8"),
                std::str::from_utf8(f).expect("a family is UTF-8"),
            )
        })
        .collect();
    assert_eq!(
        declared, door,
        "the meter classes and the door's billable classes are one list"
    );
    assert_eq!(
        declared,
        vec![
            ("input", "token"),
            ("output", "token"),
            ("cache_read", "token"),
            ("cache_write", "token"),
        ],
        "1.5.5's tier names, byte for byte"
    );
    assert_eq!(TOKEN_CLASSES.len(), declared.len());
}
