//! Tests for `plane_mount.rs`. Lifted out of the implementation file so its line count measures
//! implementation and nothing else; still a direct child module, so `use super::*` reaches the
//! private items it always did.
//!
//! The two planes' own mount cells drive this body end to end through their own legs. What is here
//! is the part that belongs to NEITHER plane: the path walk over the closed grammar's shapes, and
//! the trailing-slash reading, which is the one normalisation this file makes and therefore the one
//! that has to be stated rather than assumed.

use super::*;

use busbar_contract::{
    grammar::{PathSeg, Selector},
    ids::OpClassId,
    transport::facts,
    transport::Outcome as O,
};

/// One claim over an exact path, for a walk that is about the matcher and not about any plane.
const fn exact(path: &'static str) -> Claim {
    Claim {
        transport: "http",
        selector: Selector::ExactPath(path),
        scheme: None,
        scheme_alternatives: &[],
        idempotency: None,
    }
}

/// **A trailing slash is the same address.**
///
/// `/mcp` and `/mcp/` are one address to every router in this tree and to every client of either
/// protocol. A mount that took the first and handed the second straight through would run one of
/// them past the loop and the other around it — the same request, gated or not depending on a
/// character — which is a hole an attacker types rather than finds.
#[test]
fn a_trailing_slash_names_the_same_address_and_a_prefix_does_not() {
    static CLAIMS: &[Claim] = &[exact("/mcp")];

    assert!(claims_a_path(CLAIMS, "/mcp"));
    assert!(claims_a_path(CLAIMS, "/mcp/"), "the same address");

    // And the near misses, which are the cell. A prefix is somebody else's path, a deeper path is a
    // different address, and a doubled slash is neither.
    assert!(!claims_a_path(CLAIMS, "/mcpx"));
    assert!(!claims_a_path(CLAIMS, "/mcp/x"));
    assert!(!claims_a_path(CLAIMS, "/mcp//"));
    assert!(!claims_a_path(CLAIMS, "/"));
    assert!(!claims_a_path(CLAIMS, ""));
}

/// **A declaration written with a trailing slash names the same address too.**
///
/// The normalisation is applied to BOTH sides, so a plane that declared `/mcp/` and a caller that
/// asked for `/mcp` meet. One-sided normalisation is the same hole with the character on the other
/// foot.
#[test]
fn the_normalisation_is_applied_to_the_declaration_as_well_as_the_request() {
    static CLAIMS: &[Claim] = &[exact("/mcp/")];
    assert!(claims_a_path(CLAIMS, "/mcp"));
    assert!(claims_a_path(CLAIMS, "/mcp/"));
    assert!(!claims_a_path(CLAIMS, "/mcpx"));
}

/// **The root is an address of its own and is never trimmed away.**
///
/// Trimming `/` would leave the empty string, which is not an address at all — and a claim on `/`
/// would then match nothing while looking like it matched everything.
#[test]
fn the_root_path_survives_normalisation() {
    assert_eq!(normalise("/"), "/");
    assert_eq!(normalise("/mcp/"), "/mcp");
    assert_eq!(normalise("/mcp"), "/mcp");
    static ROOT: &[Claim] = &[exact("/")];
    assert!(claims_a_path(ROOT, "/"));
}

/// **A selector that is not a path matches no path.**
///
/// A locally launched server's claim is made on a named stream, and a stream name is not an address
/// this listener carries. Matching one here would take a request off the mounted router because a
/// completely different carrier happened to use the same word.
#[test]
fn a_selector_that_is_not_a_path_matches_no_path() {
    static STREAM: &[Claim] = &[Claim {
        transport: "stdio",
        selector: Selector::StreamName("mcp"),
        scheme: None,
        scheme_alternatives: &[],
        idempotency: None,
    }];
    assert!(!claims_a_path(STREAM, "/mcp"));
    assert!(!claims_a_path(STREAM, "mcp"));
}

/// **A segment pattern is an address, not a prefix of one**, and a variable segment is never empty.
///
/// The empty-segment case is the one worth naming: `/a2a/agents/` would otherwise name an agent
/// whose identifier is the empty string, which is an address no router below serves.
#[test]
fn a_pattern_matches_one_address_and_not_its_prefixes() {
    static PATTERN: &[Claim] = &[Claim {
        transport: "http",
        selector: Selector::PathPattern(&[
            PathSeg::Lit("a2a"),
            PathSeg::Lit("agents"),
            PathSeg::Var,
        ]),
        scheme: None,
        scheme_alternatives: &[],
        idempotency: None,
    }];
    assert!(claims_a_path(PATTERN, "/a2a/agents/one"));
    assert!(
        claims_a_path(PATTERN, "/a2a/agents/one/"),
        "and the same address with a trailing slash"
    );
    assert!(!claims_a_path(PATTERN, "/a2a/agents"), "a collection");
    assert!(
        !claims_a_path(PATTERN, "/a2a/agents/"),
        "an identifier that is the empty string is not an identifier"
    );
    assert!(!claims_a_path(PATTERN, "/a2a/agents/one/two"), "deeper");
}

/// **Every ending is a status, and the two credential doors stay apart.**
///
/// A caller refused at Authenticate is told its credential was not accepted; one refused at Approve
/// or Verify is told the credential was accepted and does not cover this. Collapsing them sends a
/// caller with a bad token away to fix its permissions.
#[test]
fn the_two_credential_doors_are_two_statuses() {
    assert_eq!(status_of(O::Unauthenticated), 401);
    assert_eq!(status_of(O::Forbidden), 403);
    assert_ne!(status_of(O::Unauthenticated), status_of(O::Forbidden));
    assert_eq!(status_of(O::Completed), 200);
    for refused in [
        O::Unauthenticated,
        O::Forbidden,
        O::NotFound,
        O::Throttled,
        O::TimedOut,
        O::Unavailable,
    ] {
        assert!(
            status_of(refused) >= 400,
            "{refused:?} is not an answer a caller should read as success"
        );
    }
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   WHAT THE SEAM CARRIES, AND WHAT IT MAY NOT FLATTEN
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// Something a surface attaches to its own response, of a type this file invents for the cell.
///
/// A response extension is how everything in this tree that has to say something ABOUT an answer
/// says it — the thing that reports what a body spent, the thing that has to run when the last byte
/// leaves. None of that is nameable here and none of it needs to be: what the cell asserts is that
/// an extension the surface put on SURVIVES, whatever it happens to be, so a marker of a private
/// type is a stronger instrument than any real one. If this reaches the far side, so does anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SurfaceMark(&'static str);

/// The chunks one surface writes, each a frame of its own.
///
/// Three, and of different lengths, so "the boundaries survived" cannot be satisfied by accident: a
/// seam that buffered and re-emitted would hand back one frame carrying the same bytes, which is not
/// the same answer to a client reading a stream.
const CHUNKS: [&[u8]; 3] = [b"one", b"two-two", b"three-three-three"];

/// A surface that answers with a chunked body and an extension of its own.
fn a_chunking_surface() -> axum::Router {
    axum::Router::new().fallback(axum::routing::any(|| async {
        let frames = futures::stream::iter(
            CHUNKS.map(|chunk| Ok::<_, std::io::Error>(bytes::Bytes::from_static(chunk))),
        );
        let mut response = axum::http::Response::new(axum::body::Body::from_stream(frames));
        response
            .extensions_mut()
            .insert(SurfaceMark("the surface's own"));
        response
    }))
}

/// Every data frame of one body, in order, read one at a time rather than collected.
///
/// `to_bytes` would answer the question the cell is asking — it flattens, which is the very thing
/// being measured — so the body is pulled frame by frame instead.
async fn frames_of(body: axum::body::Body) -> Vec<Vec<u8>> {
    use http_body_util::BodyExt;

    let mut body = body;
    let mut frames = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.expect("the probe's own body does not fail mid-stream");
        if let Ok(data) = frame.into_data() {
            frames.push(data.to_vec());
        }
    }
    frames
}

/// **A chunked body and its response extension cross the seam intact.**
///
/// RED FIRST: the seam handed back a status, a header list and a `Vec<u8>`. Neither half of this
/// cell could be written against that shape — a three-field struct has nowhere to put an extension,
/// so `reply.extensions()` did not compile, and the body had already been read to its end inside the
/// mount, so there were no boundaries left to ask about. Both assertions were unreachable rather
/// than merely failing, which is the strongest red a shape change gets.
///
/// The mount CHOOSES THE PATH AND NEVER THE BYTES, and this is that sentence made checkable at the
/// one place it was not true. A plane whose answer is a run of events was handed back as one buffer;
/// a plane that attached something to its response to be read as the body drained found it gone.
/// Neither was a decision anyone made — both were consequences of a reply channel typed as three
/// fields.
///
/// Nothing here names a protocol. The surface is an `axum::Router`, the marker is a type this file
/// declared, and the operation class is a word. Every plane that mounts rides this channel, and a
/// cell that named one of them would be measuring that plane rather than the seam.
#[tokio::test(flavor = "multi_thread")]
async fn a_chunked_body_and_its_extension_cross_the_seam_intact() {
    let errands = drive(a_chunking_surface(), &tokio::runtime::Handle::current());
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/anything")
        .body(axum::body::Body::empty())
        .expect("the probe always builds");
    let dispatch = RequestDispatch::new(errands, request);

    // Driven from a BLOCKING context, because that is where the loop that drives it runs: the seam's
    // whole reason for existing is that a synchronous walk cannot await.
    let reply = tokio::task::spawn_blocking(move || dispatch.execute(OpClassId::new("probe")))
        .await
        .expect("the blocking probe ran");

    assert_eq!(
        reply.extensions().get::<SurfaceMark>(),
        Some(&SurfaceMark("the surface's own")),
        "the extension the surface attached reached the far side of the seam"
    );
    assert_eq!(
        frames_of(reply.into_body()).await,
        CHUNKS.map(<[u8]>::to_vec),
        "and so did every chunk boundary it chose, rather than one buffer with the same bytes"
    );
}

/// **Every PATH-shaped selector of the closed grammar is walked, not only the two written first.**
///
/// The walk was written against the two shapes the first two mounted planes declare — an exact
/// address and a segment pattern — and every other shape fell into one arm that answers "not a
/// path". Two of the shapes it answered that way ARE paths: a suffix and a contained substring are
/// declarations about the request target and nothing else. A plane that declares its surface that
/// way was therefore mounted and never reached: every one of its addresses walked around the loop
/// to the router underneath, silently and with nothing failing.
///
/// So the arm is narrowed to the shapes that genuinely are not addresses, and the two that are get
/// the same normalisation the other two get. Asserted here rather than in a plane's own cell because
/// the grammar is the grammar's and no plane's.
#[test]
fn a_suffix_and_a_contained_segment_are_addresses_this_walk_reads() {
    static SUFFIX: &[Claim] = &[Claim {
        transport: "http",
        selector: Selector::PathSuffix("/v1/embeddings"),
        scheme: None,
        scheme_alternatives: &[],
        idempotency: None,
    }];
    assert!(claims_a_path(SUFFIX, "/v1/embeddings"));
    assert!(
        claims_a_path(SUFFIX, "/v1/embeddings/"),
        "the same address, by the one normalisation this file makes"
    );
    assert!(
        claims_a_path(SUFFIX, "/openai/v1/embeddings"),
        "a prefixed \
        deployment of the same surface"
    );
    assert!(
        !claims_a_path(SUFFIX, "/v1/embeddings/x"),
        "deeper is elsewhere"
    );
    assert!(!claims_a_path(SUFFIX, "/v1/embed"));

    static CONTAINS: &[Claim] = &[Claim {
        transport: "http",
        selector: Selector::PathContains("/v1/messages"),
        scheme: None,
        scheme_alternatives: &[],
        idempotency: None,
    }];
    assert!(claims_a_path(CONTAINS, "/v1/messages"));
    assert!(claims_a_path(
        CONTAINS,
        "/anthropic/v1/messages/count_tokens"
    ));
    assert!(!claims_a_path(CONTAINS, "/v1/models"));
}

/// **A selector about the CONNECTION is still not a path**, and the narrowing above did not widen
/// into one.
///
/// The arm that answers "no path matches this" is now written over the shapes it means rather than
/// as a wildcard, so a shape the grammar gains has to be considered here instead of quietly
/// answering no.
#[test]
fn a_header_selector_is_not_an_address() {
    static HEADER: &[Claim] = &[Claim {
        transport: "http",
        selector: Selector::HeaderPresent("anthropic-version"),
        scheme: None,
        scheme_alternatives: &[],
        idempotency: None,
    }];
    assert!(!claims_a_path(HEADER, "/anthropic-version"));
    assert!(!claims_a_path(HEADER, "/v1/messages"));
}

/// **EVERY HEADER CROSSES THE SEAM, and the reserved keys keep their own vocabulary.**
///
/// RED FIRST: `mount_facts` published six readings and no header, so a plane whose surface is
/// identified by a vendor header — `anthropic-version`, `x-goog-api-key`, `x-api-key` — could be
/// mounted, could be claimed, and could not tell one dialect from another. The four rungs that name
/// a header had nothing to read.
///
/// The assertion is about the transport axis and names no plane: a header the mount was never told
/// about reaches the arrival, under this transport's own prefix, and the reserved readings are
/// unchanged beside it.
#[test]
fn every_header_crosses_as_a_fact_of_this_transport_and_never_as_a_reserved_key() {
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/messages?beta=true")
        .header("host", "node.example")
        .header("accept", "text/event-stream")
        .header("content-type", "application/json")
        .header("authorization", "Bearer sk-live")
        .header("anthropic-version", "2023-06-01")
        .header("X-Goog-Api-Key", "goog-secret")
        .header("x-vendor-nobody-declared", "and it still arrives")
        .body(axum::body::Body::empty())
        .expect("a request builds");
    let (parts, _) = request.into_parts();
    let facts = mount_facts(&parts);
    let pairs = fact_pairs(&facts);
    let arrival = arrival_over(&pairs, b"{}");

    // The six reserved readings, exactly as before: the seam widened beside them, not over them.
    assert_eq!(arrival.fact(facts::PATH), Some("/v1/messages?beta=true"));
    assert_eq!(arrival.fact(facts::METHOD), Some("POST"));
    assert_eq!(arrival.fact(facts::AUTHORITY), Some("node.example"));
    assert_eq!(arrival.fact(facts::CREDENTIAL), Some("Bearer sk-live"));
    assert_eq!(arrival.fact(facts::ACCEPTS), Some("text/event-stream"));
    assert_eq!(arrival.fact(facts::MEDIA), Some("application/json"));

    // And every header, including the two nothing in this tree declares and the one no protocol
    // here has ever named. Read through `header_of`, because the prefix is spelled in one place.
    assert_eq!(header_of(&arrival, "anthropic-version"), Some("2023-06-01"));
    assert_eq!(
        header_of(&arrival, "X-Goog-Api-Key"),
        Some("goog-secret"),
        "the read normalises case exactly as the map did on the way in"
    );
    assert_eq!(
        header_of(&arrival, "x-vendor-nobody-declared"),
        Some("and it still arrives")
    );
    assert_eq!(header_of(&arrival, "authorization"), Some("Bearer sk-live"));

    // THE TWO VOCABULARIES DO NOT MEET. No header is published under a bare name, so nothing a
    // caller can send can shadow a reserved key — `accept` next to `accepts`, `host` next to
    // `authority`, and a wire that invented a header called `path` over the request target.
    for (key, _) in &facts {
        assert!(
            !facts::is_reserved(key) || !key.starts_with(HEADER_FACT_PREFIX),
            "a fact is one vocabulary or the other, never both: {key}"
        );
    }
    assert_eq!(
        arrival.fact("accept"),
        None,
        "a header is not published under its bare name"
    );
    assert_eq!(arrival.fact("host"), None);
}

/// **EVERY header goes back the way it came**, for a leg whose plane's walk takes a map.
///
/// The read half of the cell above, and it exists because a leg is now allowed to want the WHOLE of
/// what arrived rather than one fact at a time. Two properties, and both are the ones a curation
/// would break: every header that arrived comes back — including the ones this tree declares nothing
/// about — and a name sent TWICE comes back twice, in the order it was sent, because a header that
/// arrived as two values and left as one is a request nobody made.
///
/// The reserved keys stay out of it. They are the kernel's vocabulary, they were never headers, and
/// a read-back that put `unit.path` on the wire would be inventing a header out of a fact.
#[test]
fn the_whole_header_map_comes_back_off_the_facts_it_was_published_as() {
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/messages")
        .header("host", "node.example")
        .header("content-type", "application/json")
        .header("anthropic-version", "2023-06-01")
        .header("accept-encoding", "gzip")
        .header("accept-encoding", "br")
        .body(axum::body::Body::empty())
        .expect("a request builds");
    let (parts, _) = request.into_parts();
    let sent = parts.headers.clone();
    let facts = mount_facts(&parts);
    let pairs = fact_pairs(&facts);
    let arrival = arrival_over(&pairs, b"{}");

    let back = headers_of(&arrival);
    assert_eq!(
        back, sent,
        "the map a mounted leg reads is the map the caller sent"
    );
    assert_eq!(
        back.get_all("accept-encoding")
            .iter()
            .map(|v| v.to_str().expect("ascii"))
            .collect::<Vec<_>>(),
        vec!["gzip", "br"],
        "a header sent twice arrived twice and goes back twice, in order"
    );

    // AND NOT ONE RESERVED KEY. Six of them are published beside the headers and none of them is a
    // header; a read-back that took them would hand a plane a request target as a header value.
    assert!(back.get(facts::PATH).is_none());
    assert!(back.get(facts::METHOD).is_none());
    assert!(back.get("credential").is_none());
}
