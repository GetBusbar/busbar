//! Tests for `units_llm_leg.rs`. Lifted out of the implementation file so its line count measures
//! implementation and nothing else; still a direct child module, so `use super::*` reaches the
//! private items it always did.
//!
//! What is here is the RESOLUTION — the one question this leg answers that nothing else in the tree
//! answers for it. Everything downstream of it (the walk, the money, the streamed body) is asserted
//! through the mount, where a client can see it.

use super::*;

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
            crate::root::mount_ingress::tests::minted(busbar_core::plane_host::engine_host(
                &busbar_core::test_support::TestApp::new().build(),
            )),
            |_| busbar_api::PlaneRequestCtx { key: None },
        )),
    )
}
