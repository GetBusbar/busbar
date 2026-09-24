//! WHAT A DELIVERED LLM RESPONSE LEAVES ON THE BOOKS WHEN IT DOES NOT END CLEANLY, OR WHEN NO CARD
//! PRICES IT.
//!
//! ITEM 367 — a SAME-PROTOCOL NON-STREAM body (`!is_sse`, `translate == None`) the client stops
//! reading mid-relay. A non-streamed completion is generated WHOLE before its first byte is sent, so
//! every token was spent upstream; the drop arm read usage only from a streaming translator and billed
//! 0 for it. That is a LEDGER fault (the book says no work happened). It now bills what the
//! truncated-tail path bills when the document cannot be read whole — the usage recovered from the
//! bytes in hand, else the floor over them — and the report-back carries the same figure (#71).
//!
//! DECISION #43 / #42 (architect-carried, same as item 36) — with NO `rate_card:` the delivered
//! response still writes its metering row: the plane always ledgers, and billing off is the money
//! VIEW reading 0, never a missing row.
use super::*;
use busbar_kernel::governance::NewKeySpec;
use busbar_kernel::test_support::engine_kit::EngineTestKit as _;
use bytes::Bytes;
use futures::StreamExt as _;

const CHARGED_AT: u64 = 1_700_000_000;

fn message_with_usage(usage: &str) -> String {
    format!(
        r#"{{"id":"msg_1","type":"message","role":"assistant","model":"claude-x","content":[{{"type":"text","text":"a long enough answer that the client stopped reading part way through"}}],"stop_reason":"end_turn","stop_sequence":null,"usage":{usage}}}"#
    )
}

/// A same-protocol, non-stream anthropic `FirstByteBody` over `inner`, billed against a fresh key on
/// a BILLING-OFF pin (`cost_flat(0)`: no card). Returns the body, the governance, the cost, the key
/// id and the tap cell.
#[allow(clippy::type_complexity)]
fn body_over<S>(
    inner: S,
) -> (
    FirstByteBody<S, ()>,
    Arc<dyn busbar_kernel::test_support::engine_kit::GovKit>,
    Arc<dyn busbar_kernel::test_support::engine_kit::CostKit>,
    String,
    TapCell,
)
where
    S: futures::Stream<Item = Result<Bytes, hyper::Error>> + Send + 'static,
{
    crate::testkit::install_test_seams();
    busbar_kernel::metrics::init();
    let store = Arc::new(busbar_store_memory::MemoryStore::new());
    let gov = crate::test_support::engine_kit::CORE_ENGINE_KIT
        .governance(store, None, None)
        .expect("gov");
    let cost = crate::test_support::engine_kit::CORE_ENGINE_KIT.cost_flat(0);
    let (key, _secret) = gov
        .create_key(
            NewKeySpec {
                name: "k".to_string(),
                ..Default::default()
            },
            CHARGED_AT,
        )
        .expect("create key");
    let sink = Some(UsageSink {
        pin: busbar_kernel::plane_host::MeterPin::new(
            busbar_kernel::plane_host::GovHandle(gov.clone()),
            busbar_kernel::plane_host::CostHandle(cost.clone()),
        ),
        key: Arc::new(key.clone()),
        pool: Arc::from(""),
        charged_at: CHARGED_AT,
        admit: None,
    });
    let app = crate::test_support::TestApp::new()
        .lane(crate::test_support::LaneSpec::new(
            "claude-x",
            crate::proto_codec::PROTO_ANTHROPIC,
            "http://127.0.0.1:1",
        ))
        .pool("pa", &[(0, 1)])
        .build();
    let (host, rt) = crate::engine::test_host_rt(&app);
    let tap = TapCell::new();
    let fbb = FirstByteBody::new(
        inner,
        false, // same-protocol NON-STREAM application/json
        "anthropic",
        crate::test_support::CHAT,
        (),
        tokio::time::Instant::now() + std::time::Duration::from_secs(300),
        host,
        rt,
        0,
        Arc::new(busbar_kernel::store::BreakerCfg::default()),
        "pa",
        None,
        None,
        sink,
        false,
        tap.clone(),
    );
    (fbb, gov, cost, key.id, tap)
}

/// The tokens on the key's ledger, waited for (the accrual is write-behind).
async fn ledgered_tokens(
    gov: &Arc<dyn busbar_kernel::test_support::engine_kit::GovKit>,
    cost: &Arc<dyn busbar_kernel::test_support::engine_kit::CostKit>,
    key_id: &str,
) -> u64 {
    let mut tokens = 0;
    for _ in 0..200 {
        tokio::task::yield_now().await;
        tokens = gov
            .usage_for(cost.as_ref(), key_id, CHARGED_AT)
            .expect("usage read")
            .map(|u| u.tokens)
            .unwrap_or(0);
        if tokens != 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    }
    tokens
}

/// ITEM 367. The client read the first chunk of a non-streamed completion and went away; the body
/// was DROPPED mid-relay. It bills the floor over the bytes it relayed — never 0 — and the tap reports
/// exactly that figure as a `Partial` end, so both books hold one number.
#[tokio::test]
async fn a_same_protocol_nonstream_body_dropped_mid_relay_bills_what_it_relayed_not_zero() {
    let whole = message_with_usage(r#"{"input_tokens":1500,"output_tokens":90}"#);
    // The prefix stops before the `usage` object: what the client had when it left.
    let cut = whole
        .find(r#""stop_reason""#)
        .expect("the body names a stop reason");
    let prefix = whole[..cut].to_string();
    let inner = futures::stream::iter(vec![Ok::<Bytes, hyper::Error>(Bytes::from(prefix.clone()))])
        .chain(futures::stream::pending());
    let (mut fbb, gov, cost, key_id, tap) = body_over(inner);

    let first = fbb.next().await.expect("a chunk").expect("relayed");
    assert_eq!(
        first.as_ref(),
        prefix.as_bytes(),
        "the prefix relays verbatim"
    );
    // THE DISCONNECT: the server drops the body before its end.
    drop(fbb);

    let floor = estimate_usage_from_truncated_tail(prefix.len());
    let billed = ledgered_tokens(&gov, &cost, &key_id).await;
    assert_ne!(
        billed, 0,
        "a non-streamed completion dropped mid-relay was generated whole: it never bills 0"
    );
    assert_eq!(
        billed, floor.output,
        "it bills the no-usage-recovered floor over the relayed bytes"
    );
    let report = tap.get().expect("the drop reports its end");
    assert_eq!(report.finish, TapFinish::Partial);
    assert_eq!(
        report.usage,
        Some(floor),
        "the report-back carries the figure the ledger accrued (#71: both books agree)"
    );
}

/// ITEM 367, THE CONTROL: the same body relayed to its END bills its own `usage` exactly — the drop
/// arm adds nothing to a clean end (the sink was already taken).
#[tokio::test]
async fn a_same_protocol_nonstream_body_relayed_whole_bills_its_own_usage_once() {
    let whole = message_with_usage(r#"{"input_tokens":1500,"output_tokens":90}"#);
    let inner = futures::stream::iter(vec![Ok::<Bytes, hyper::Error>(Bytes::from(whole.clone()))]);
    let (fbb, gov, cost, key_id, tap) = body_over(inner);
    let served: Vec<_> = fbb.collect().await;
    assert_eq!(served.len(), 1);
    assert_eq!(ledgered_tokens(&gov, &cost, &key_id).await, 1590);
    assert_eq!(tap.get().expect("reported").finish, TapFinish::Complete);
}

/// DECISION #43 / #42 (architect-carried, the LLM twin of item 36). With NO `rate_card:` a delivered
/// response still writes its metering row with the plane's own counts, and the money view of that
/// row reads 0. The row used to be dropped kernel-side whenever the pinned card was absent.
#[tokio::test]
async fn a_billing_off_delivery_still_writes_its_metering_row_and_the_view_reads_zero() {
    let whole = message_with_usage(r#"{"input_tokens":1500,"output_tokens":90}"#);
    let inner = futures::stream::iter(vec![Ok::<Bytes, hyper::Error>(Bytes::from(whole.clone()))]);
    let (fbb, gov, cost, key_id, _tap) = body_over(inner);
    let _: Vec<_> = fbb.collect().await;
    assert_eq!(ledgered_tokens(&gov, &cost, &key_id).await, 1590);

    gov.flush_metering();
    let rows: Vec<String> = gov
        .metering_for(busbar_kernel::governance::metering_bucket(CHARGED_AT))
        .expect("metering read")
        .into_iter()
        .filter(|r| r.key_id == key_id)
        .map(|r| {
            format!(
                "{} in={} out={} req={}",
                r.model, r.tokens_input, r.tokens_output, r.requests
            )
        })
        .collect();
    assert_eq!(
        rows,
        vec!["claude-x in=1500 out=90 req=1".to_string()],
        "billing off still writes the plane's counts: the ledger is what the plane did (#43)"
    );
    let spend = gov
        .usage_for(cost.as_ref(), &key_id, CHARGED_AT)
        .expect("usage read")
        .expect("the key exists")
        .spend_cents;
    assert_eq!(spend, 0, "billing off is the VIEW reading 0 (#42)");
}
