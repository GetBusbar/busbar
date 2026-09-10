//! Tests for `units_llm_leg.rs`. Lifted out of the implementation file so its line count measures
//! implementation and nothing else; still a direct child module, so `use super::*` reaches the
//! private items it always did.
//!
//! What is here is the RESOLUTION — the one question this leg answers that nothing else in the tree
//! answers for it. Everything downstream of it (the walk, the money, the streamed body) is asserted
//! through the mount, where a client can see it.

use super::*;
use busbar_api::PlaneRequestCtx;

/// One arrival over these facts and these bytes, composed the way the mount composes one.
fn probe<T>(
    method: &str,
    uri: &str,
    headers: &[(&str, &str)],
    body: &[u8],
    f: impl FnOnce(&busbar_contract::transport::Arrival<'_>) -> T,
) -> T {
    let mut builder = axum::http::Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let request = builder
        .body(axum::body::Body::empty())
        .expect("the probe always builds");
    let (parts, _) = request.into_parts();
    let facts = plane_mount::test_facts(&parts);
    let pairs = plane_mount::test_pairs(&facts);
    f(&plane_mount::test_arrival(&pairs, body))
}

/// **THE LADDER IS WHAT NAMES THE DIALECT, and it names it off a HEADER.**
///
/// The rung that could not have been read before the mount published every header as a fact: two
/// requests to the same address, distinguished only by a vendor header, resolve to two different
/// dialects. A leg that read only the reserved keys would answer both the same, and the one it
/// answered would be a dialect a caller never used.
#[test]
fn the_dialect_is_the_ladders_answer_and_a_vendor_header_decides_it() {
    let named = probe(
        "POST",
        "/v1/messages",
        &[("anthropic-version", "2023-06-01")],
        br#"{"model":"m","messages":[]}"#,
        |a| {
            let leg = a_leg();
            leg.named(a).map(|n| n.dialect)
        },
    );
    assert_eq!(named, Some(busbar_llm::proto_codec::PROTO_ANTHROPIC));

    // The widely-copied chat surface, with no vendor header at all: rung 7, by path alone.
    let named = probe(
        "POST",
        "/v1/chat/completions",
        &[],
        br#"{"model":"m","messages":[]}"#,
        |a| {
            let leg = a_leg();
            leg.named(a).map(|n| n.dialect)
        },
    );
    assert_eq!(named, Some(busbar_llm::proto_codec::PROTO_OPENAI));
}

/// **A QUERY STRING IS NOT PART OF THE ADDRESS THE LADDER READS.**
///
/// The mount publishes the request target WHOLE — path and query — because that is what the request
/// line carried. The ladder matches on the path, and most of this plane's rungs are suffixes: a
/// suffix rung tested against `/v1/chat/completions?stream=true` matches nothing at all, so the same
/// request would go around the loop for a reason the caller chose by typing a query string.
#[test]
fn a_query_string_does_not_move_a_request_off_this_planes_ladder() {
    let with_query = probe(
        "POST",
        "/v1/chat/completions?stream=true",
        &[],
        br#"{"model":"m","messages":[]}"#,
        |a| {
            let leg = a_leg();
            leg.named(a).map(|n| n.dialect)
        },
    );
    assert_eq!(with_query, Some(busbar_llm::proto_codec::PROTO_OPENAI));
}

/// **A CLAIMED ADDRESS THE DIALECT NAMES NO OPERATION FOR IS NOT A UNIT**, and the mount's second
/// question is what sends it to the surface that already answers it.
///
/// The two halves are resolved together for exactly this case: the ladder claims the address (it is
/// this vendor's model-scoped surface) and the dialect's own endpoint resolution names nothing for
/// it. Answering "yes, a unit" on the strength of the first half alone would hand the loop a request
/// with no operation to run.
#[test]
fn an_address_the_dialect_names_no_operation_for_is_not_a_unit_of_this_plane() {
    let recognised = probe("GET", "/v1/models/gemini-2.0-flash", &[], b"", |a| {
        a_leg().recognises(a)
    });
    assert!(!recognised);

    // And a path no rung of the ladder names at all is not this plane's either.
    let recognised = probe("POST", "/healthz", &[], b"{}", |a| a_leg().recognises(a));
    assert!(!recognised);
}

/// A leg over a bare node and a source that resolves every caller to nobody. Enough for the
/// resolution cells above, which never reach the walk.
fn a_leg() -> LlmLeg {
    // THE PROTOCOL, IN THE PROCESS REGISTRY. The dialect's own `resolve_operation` is reached
    // through the registry the composition root installs at boot, so a cell that has not installed
    // it is asking a node that speaks no dialect at all. Idempotent.
    busbar_llm::testkit::install_test_seams();
    LlmLeg::assemble(
        LlmNode::new(),
        Arc::new(crate::root::mount_ingress::BootIngress::new(
            crate::root::mount_ingress::tests::minted(crate::root::mount_ingress::tests::a_host()),
            |_| PlaneRequestCtx { key: None },
        )),
    )
}

/// **THE MOUNTED AND THE DRIVEN READING OF A URL-NAMED MODEL ARE ONE READING.**
///
/// The driven path reads the model through the dialect's own `RequestHandler::path_model`, reached
/// on the protocol registry the composition root installs; a mounted arrival reads it through the
/// plane's own [`busbar_plane_llm::url`], because that is the reading a caller with no arrival host
/// can make. Two spellings of one cut is exactly the drift a mounted request would show and a driven
/// one would not — a model routed one way here and another way there, on the same address — so they
/// are asserted equal over the shapes both dialects answer, in the one place that can see both.
#[test]
fn the_mounted_and_driven_readings_of_a_url_named_model_are_one_reading() {
    busbar_llm::testkit::install_test_seams();
    let driven = |dialect: &'static str, path: &str| {
        busbar_substrate::handlers::request_handler(dialect)
            .expect("the dialect is registered")
            .path_model(path)
    };
    let mounted = |dialect: &'static str, path: &str| {
        busbar_plane_llm::url::url_model(dialect, path, None).map(|u| u.model)
    };
    for (dialect, path) in [
        ("gemini", "/v1beta/models/gemini-2.0-flash:generateContent"),
        (
            "gemini",
            "/v1beta/models/gemini-2.0-flash:streamGenerateContent",
        ),
        ("gemini", "/v1/models/text-embedding-004:embedContent"),
        ("bedrock", "/model/anthropic.claude-3-5-sonnet/converse"),
        (
            "bedrock",
            "/model/anthropic.claude-3-5-sonnet/converse-stream",
        ),
    ] {
        assert_eq!(
            driven(dialect, path),
            mounted(dialect, path),
            "the two readings of `{path}` are one reading"
        );
    }

    // And the addresses that name no model on the mounted side are the addresses the driven side
    // has no model for either — including the one that names a model and leaves the OPERATION to the
    // body, whose model is a routing hint rather than the arrival's own.
    assert_eq!(mounted("gemini", "/v1/models/gemini-2.0-flash"), None);
    assert_eq!(mounted("bedrock", "/model/amazon.titan-text/invoke"), None);
    assert_eq!(mounted("openai", "/v1/chat/completions"), None);
}
