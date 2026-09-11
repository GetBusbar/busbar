//! Tests for `units_mcp.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;
use busbar_unit_admission::ChainWalk;

/// A resolver that answers every name with one public address.
///
/// These tests are about which question the catalogue asks, not about what a live resolver would
/// say today; a fixed answer is what keeps them from depending on somebody's DNS.
struct FixedResolver;

impl Resolver for FixedResolver {
    fn resolve(&self, _host: &str) -> Result<Vec<std::net::IpAddr>, String> {
        Ok(vec!["93.184.216.34".parse().expect("a fixture address")])
    }
}

/// The guard seam these tests bind: the fixed resolver, a policy that admits the loopback
/// registrations the fixtures use, and an empty denylist.
fn seam() -> NetSeam<'static> {
    static RESOLVER: FixedResolver = FixedResolver;
    static DENYLIST: std::sync::LazyLock<Denylist> = std::sync::LazyLock::new(Denylist::default);
    NetSeam {
        resolver: &RESOLVER,
        policy: GuardPolicy {
            allow_private: true,
            ..GuardPolicy::default()
        },
        denylist: &DENYLIST,
    }
}

/// A store that keeps nothing.
///
/// Every record operation the published protocol declares carries a default that accepts and
/// keeps nothing, which is exactly the shape a backend with no durable rows has. That makes it
/// the right double here: these tests are about which call the root makes for which leg, and a
/// store that answered from real rows would be testing the store instead.
struct SilentStore;

impl AbiStore for SilentStore {
    fn put_key(&self, _key: &busbar_api::VirtualKey) -> busbar_api::StoreResult<()> {
        Ok(())
    }

    fn get_key(&self, _id: &str) -> busbar_api::StoreResult<Option<busbar_api::VirtualKey>> {
        Ok(None)
    }

    fn list_keys(&self) -> busbar_api::StoreResult<Vec<busbar_api::VirtualKey>> {
        Ok(Vec::new())
    }

    fn delete_key(&self, _id: &str) -> busbar_api::StoreResult<()> {
        Ok(())
    }

    fn get_usage(
        &self,
        _bucket_id: &str,
        _window_start: u64,
    ) -> busbar_api::StoreResult<busbar_api::UsageLedger> {
        Ok(busbar_api::UsageLedger::default())
    }

    fn put_usage(
        &self,
        _bucket_id: &str,
        _window_start: u64,
        _ledger: &busbar_api::UsageLedger,
    ) -> busbar_api::StoreResult<()> {
        Ok(())
    }

    fn add_metering(&self, _delta: &busbar_api::MeteringDelta) -> busbar_api::StoreResult<()> {
        Ok(())
    }

    fn list_metering(&self, _bucket: u64) -> busbar_api::StoreResult<Vec<busbar_api::MeteringRow>> {
        Ok(Vec::new())
    }
}

/// The connection's own facts reach the loop, and a claim that names a transport this stack is
/// not carrying does not.
///
/// Arrival is the kernel's gate and no plane's decision, so what a plane's binding owes here is
/// not a second gate: it is the honest handover of what the transport recorded. The two ways
/// that handover can be dishonest are both driven. A claim naming a transport this plane never
/// claimed would put a unit of this plane on a layer no claim of its selects, and a claim whose
/// transport is not the layer the stack actually ended on would carry forward a record
/// describing a connection other than the one that arrived — the scheme narrowing, the audience
/// and every location the later steps resolve are all read off exactly these bytes.
#[test]
fn the_arrival_facts_are_the_stack_the_claim_was_matched_on() {
    use busbar_caps::KernelSeal;

    let seal = KernelSeal::acquire_for_kernel();
    let over_tls = |chain: Vec<&'static str>| ArrivalRecord {
        source: "198.51.100.7:52344".to_string(),
        port: 8443,
        alpn: Some("h2".to_string()),
        sni: Some("mcp.example".to_string()),
        peer_cert: None,
        transport_chain: chain,
    };

    // The document surface: composed tcp → tls → http, matched by the claim that names http.
    let record = over_tls(vec!["tcp", "tls", "http"]);
    let decision = arrival(
        &Arrived {
            record: &record,
            claim_transport: claims::TRANSPORT_HTTP,
        },
        &UnitToken::mint(&seal),
    );
    let carried = decision
        .into_result(&seal)
        .expect("the claim names the layer the stack ended on");
    // Carried forward unchanged: the arrival step of a plane binding adds nothing to what the
    // transport wrote, and a record that gained or lost a field here would be the root
    // describing a connection rather than reporting one.
    assert_eq!(carried, record);

    // The streamed surface is one layer further up, and the locally launched one is a stack of
    // one. Both are claims this plane makes, and both are the top of their own chain.
    for (chain, transport) in [
        (vec!["tcp", "tls", "http", "sse"], claims::TRANSPORT_SSE),
        (vec!["stdio"], claims::TRANSPORT_STDIO),
    ] {
        let record = over_tls(chain);
        assert!(
            arrival(
                &Arrived {
                    record: &record,
                    claim_transport: transport,
                },
                &UnitToken::mint(&seal),
            )
            .into_result(&seal)
            .is_ok(),
            "{transport} is claimed and is the top of its own chain"
        );
    }

    // A transport no claim of this plane names. The registry may well carry it — the node
    // composes seven — but a unit of THIS plane arriving on it was matched by nothing, and a
    // binding that shrugged and carried the record forward would have this plane answering
    // bytes it never claimed.
    let ws = over_tls(vec!["tcp", "tls", "http", "ws"]);
    let refusal = arrival(
        &Arrived {
            record: &ws,
            claim_transport: "ws",
        },
        &UnitToken::mint(&seal),
    )
    .into_result(&seal)
    .expect_err("this plane claims no socket surface");
    assert_eq!(refusal.reason(), ReasonCode::HandoffMismatch);
    assert_eq!(refusal.step(), Some(busbar_caps::StepName::Arrival));

    // Claimed, but not the layer this connection ended on: an sse stack matched as a document
    // request. Nothing is wrong with the bytes and nothing is wrong with the claim — the two
    // simply do not describe the same connection.
    let sse = over_tls(vec!["tcp", "tls", "http", "sse"]);
    let refusal = arrival(
        &Arrived {
            record: &sse,
            claim_transport: claims::TRANSPORT_HTTP,
        },
        &UnitToken::mint(&seal),
    )
    .into_result(&seal)
    .expect_err("http is below the layer this stack ended on, not the layer itself");
    assert_eq!(refusal.reason(), ReasonCode::HandoffMismatch);
}

// ── the decode step's own scaffolding ──────────────────────────────────────────────────────
//
// Driving the decode step means driving the plane's own ingress decoder, and that takes the
// four borrowed views and the one resource a plugin call is given. They are built here rather
// than mocked away, because a decode cell that did not hand the plane a real arena would not be
// driving the step that can run out of one.

/// A leaking arena. Test-only, run a bounded number of times per process: the trait's
/// allocators hand back borrowed slices, so an honest double either leaks or is unsafe, and
/// this crate's tests do not reach for unsafe.
struct CellArena;

impl busbar_contract::bounded::Arena for CellArena {
    fn alloc_bytes<'a>(
        &'a self,
        src: &[u8],
    ) -> Result<busbar_contract::bounded::ArenaBytes<'a>, busbar_contract::bounded::ArenaBudget>
    {
        let leaked: &'static [u8] = Box::leak(src.to_vec().into_boxed_slice());
        Ok(busbar_contract::bounded::ArenaBytes::new(leaked))
    }

    fn alloc_str<'a>(
        &'a self,
        src: &str,
    ) -> Result<&'a str, busbar_contract::bounded::ArenaBudget> {
        Ok(Box::leak(src.to_string().into_boxed_str()))
    }

    fn alloc_spans<'a>(
        &'a self,
        src: &[(&'a str, busbar_contract::bounded::Span)],
    ) -> Result<
        &'a [(&'a str, busbar_contract::bounded::Span)],
        busbar_contract::bounded::ArenaBudget,
    > {
        Ok(Box::leak(src.to_vec().into_boxed_slice()))
    }

    fn remaining(&self) -> usize {
        usize::MAX
    }
}

struct CellConfig;

impl busbar_contract::unit::ConfigView for CellConfig {
    fn get_str(&self, _key: &str) -> Option<&str> {
        None
    }
    fn get_int(&self, _key: &str) -> Option<i64> {
        None
    }
    fn get_bool(&self, _key: &str) -> Option<bool> {
        None
    }
}

/// The document surface, composed the way the node composes it.
struct CellTransport;

impl busbar_contract::unit::TransportView for CellTransport {
    fn key(&self) -> &'static str {
        claims::TRANSPORT_HTTP
    }
    fn chain(&self) -> &[&'static str] {
        &["tcp", "tls", "http"]
    }
    fn fact(&self, _key: &str) -> Option<&str> {
        None
    }
}

/// One inbound frame carrying `body`.
fn one_frame(body: &str) -> Vec<busbar_contract::wire::Frame> {
    vec![busbar_contract::wire::Frame {
        direction: busbar_contract::wire::Direction::Inbound,
        stream: busbar_contract::ids::StreamId(0),
        bytes: busbar_contract::bounded::SlabBytes::new(std::sync::Arc::from(body.as_bytes())),
        meta: busbar_contract::wire::FrameMeta::default(),
    }]
}

/// A JSON-RPC envelope resolves to the operation the plane's own method table names; a body
/// that is not this protocol's shape is refused at the step that read it; and the caller's
/// metadata block is read one level down and no further.
///
/// The metadata walk is the part that cannot be done by pointer at all, and that is why it is
/// driven here rather than assumed. This protocol's metadata keys carry `/` in them, and a
/// pointer reads a `/` as a level, so `/params/_meta/io.modelcontextprotocol/protocolVersion`
/// names a nesting that does not exist. The block is located by pointer and its members are
/// read by name out of it — one level down, never deeper — which is what makes the protocol
/// version and the progress token reachable as the facts the later steps read.
#[test]
fn an_envelope_resolves_to_an_operation_and_a_malformed_one_is_refused() {
    use busbar_caps::KernelSeal;
    use busbar_contract::bounded::{FactValue, Labels};
    use busbar_contract::unit::{Clock, Ctx};
    use busbar_contract::wire::FrameCursor;
    use busbar_plane_mcp::facts as f;

    let seal = KernelSeal::acquire_for_kernel();
    let arena = CellArena;
    let config = CellConfig;
    let transport = CellTransport;
    let labels = Labels::new();
    let clock = Clock {
        unix_secs: 1_700_000_000,
        monotonic_nanos: 0,
    };
    let plane = McpPlane::EMPTY;

    // A well-formed call, carrying the caller's own metadata block. Both members the loop reads
    // are keyed with a separator in the name, which is the whole reason the walk exists.
    let body = r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"grep","_meta":{"io.modelcontextprotocol/protocolVersion":"2025-06-18","progressToken":"p-42"}}}"#;
    let frames = one_frame(body);
    let mut cursor = FrameCursor::new(&frames);
    let ctx = Ctx::new(clock, &config, None, &transport, &labels, &arena);
    let read = read_ingress(&plane, &mut cursor, &ctx);
    let Ok(Read::Unit(decoded)) = &read else {
        panic!("a well-formed call is a unit: {read:?}");
    };
    let facts = decoded.facts;
    assert_eq!(decoded.op, ops::OP_TOOL_CALL);
    // A call is answered once and does not hold the direction open.
    assert!(!decoded.streaming);
    // The depth-1 walk: located by pointer, members read by name out of the block.
    assert_eq!(
        facts.get(f::FACT_PROTOCOL_VERSION),
        Some(FactValue::Str("2025-06-18"))
    );
    assert_eq!(
        facts.get(f::FACT_PROGRESS_TOKEN),
        Some(FactValue::Str("p-42"))
    );
    // And the subject the method's own row points at, which is what approve names a resource
    // from — proof the same read served the whole pointer table and not just the envelope.
    assert_eq!(facts.get(f::FACT_SUBJECT), Some(FactValue::Str("grep")));
    assert_eq!(
        decode(&read, &UnitToken::mint(&seal))
            .into_result(&seal)
            .expect("a resolved operation proceeds"),
        ops::OP_TOOL_CALL
    );

    // Why the block is walked at all, stated against the pointer grammar itself: the BLOCK is
    // reachable by pointer and its members are not, because their names carry the separator a
    // pointer reads as a level. So the same two facts asked for by pointer resolve to nothing,
    // and a binding that read them that way would report a caller who sent both as a caller who
    // sent neither.
    assert!(matches!(
        busbar_contract::spans::resolve_pointer(
            body.as_bytes(),
            busbar_plane_mcp::jsonrpc::PTR_PARAMS_META
        ),
        busbar_contract::spans::Resolved::Found(_)
    ));
    assert!(!matches!(
        busbar_contract::spans::resolve_pointer(
            body.as_bytes(),
            "/params/_meta/io.modelcontextprotocol/protocolVersion"
        ),
        busbar_contract::spans::Resolved::Found(_)
    ));

    // Every way the bytes can fail to be this protocol, refused at this step. A version member
    // that is not this protocol's version, a method member that is not a string, an identifier
    // that is neither a string nor a number, and a method the table does not name: none of them
    // is guessed at, and none of them reaches a later step under a class nobody decoded.
    for malformed in [
        r#"{"jsonrpc":"1.0","id":1,"method":"tools/list"}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":7}"#,
        r#"{"jsonrpc":"2.0","id":{},"method":"tools/list"}"#,
        r#"{"id":1,"method":"tools/list"}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/obliterate"}"#,
    ] {
        let frames = one_frame(malformed);
        let mut cursor = FrameCursor::new(&frames);
        let ctx = Ctx::new(clock, &config, None, &transport, &labels, &arena);
        let read = read_ingress(&plane, &mut cursor, &ctx);
        assert_eq!(read, Err(ReasonCode::DecodeFailed), "{malformed} was read");
        let refusal = decode(&read, &UnitToken::mint(&seal))
            .into_result(&seal)
            .expect_err("a body this plane cannot read is refused");
        assert_eq!(refusal.reason(), ReasonCode::DecodeFailed);
        assert_eq!(refusal.step(), Some(busbar_caps::StepName::Decode));
    }

    // A notice nobody recognises is DROPPED, never refused: a refusal is an answer, and this
    // protocol forbids answering a message that carries no identifier.
    let frames = one_frame(r#"{"jsonrpc":"2.0","method":"notifications/unheard-of"}"#);
    let mut cursor = FrameCursor::new(&frames);
    let ctx = Ctx::new(clock, &config, None, &transport, &labels, &arena);
    assert_eq!(read_ingress(&plane, &mut cursor, &ctx), Ok(Read::Dropped));
}

/// The plane declares one scheme with two alternatives, and the authenticate binding offers the
/// auth unit exactly those two.
///
/// The auth unit refuses a narrowing outside the declared set before it looks at a credential, so
/// a root that offered a smaller set than the claims declare would refuse a caller the deployment
/// meant to admit — and one that offered a larger set would let the plane pick a scheme the claim
/// never made.
#[test]
fn the_declared_schemes_are_the_claims_own() {
    assert_eq!(declared_schemes(), vec!["bearer", "environment"]);
}

/// The bound form reaches the node's own seams, and the signed key it resolves is the one the
/// directory holds.
///
/// The gap this closes is not that the seams could not be passed — the form above always took
/// them — but that nothing passed them: a dispatch could hand three `None`s and get a chain that
/// verified no signed key at all, which on a plane whose every credentialed claim carries an
/// audience means the audience was declared and never checked. So what is asserted is the
/// composition: a chain that names the signed-key arm, a directory that holds one key, and a
/// principal that came back carrying that key's id.
#[test]
fn the_bound_form_authenticates_through_the_nodes_own_seams() {
    use crate::root::kernel::auth_bindings::AuthBindings;
    use busbar_caps::{Authenticated, KernelSeal};
    use busbar_contract::{KeyFacts, VirtualKeyDirectory};
    use busbar_unit_auth::{AuthChain, ChainVerdict};

    struct OneKey;

    impl VirtualKeyDirectory for OneKey {
        fn operator_token_hash(&self) -> Option<String> {
            None
        }

        fn verify(
            &self,
            credential: &str,
            _now: u64,
            expected_aud: Option<&str>,
        ) -> Option<KeyFacts> {
            // The audience is the plane boundary, and the verifier is where it is enforced. Pinned
            // to the literal, not to <McpPlane as PlaneMeta>::KEY: production supplies the audience
            // from that identical expression, so comparing against it here would let both sides
            // drift together if the plane's key string ever changed.
            (credential == "tok" && expected_aud == Some("mcp")).then(|| KeyFacts {
                id: "key-mcp-1".to_string(),
                name: "an approved key".to_string(),
                scopes: None,
                enabled: true,
                expires_at: None,
                deleted_at: None,
            })
        }

        fn is_revoked(&self, _credential: &str) -> bool {
            false
        }
    }

    // A chain naming the signed-key arm and no boxed module: the door stays shut and the arm is
    // the one thing that can open it, which is what makes this test about the arm.
    let auth = Auth::new(AuthChain::new(Vec::new(), true));
    assert!(!auth.chain().is_open());
    assert!(matches!(
        auth.chain().run_chain(Some("tok")),
        ChainVerdict::Denied
    ));

    let bindings = AuthBindings::new(std::sync::Arc::new(OneKey));
    let arriving = Arriving {
        presented: Some("tok"),
        transport: claims::TRANSPORT_HTTP,
        under_scheme: true,
        now: 100,
        new_unit: true,
    };
    let seal = KernelSeal::acquire_for_kernel();
    let decision = authenticate_bound(&auth, &arriving, &bindings, &UnitToken::mint(&seal));

    match decision.into_result(&seal) {
        Ok(Authenticated::Principal(p)) => assert_eq!(p.as_str(), "key-mcp-1"),
        other => panic!("the bound seams did not reach the arm: {other:?}"),
    }
}

/// A locally launched server is narrowed to the credential it was handed at start; everything on
/// the document transports presents a bearer.
#[test]
fn the_narrowing_follows_the_transport() {
    assert_eq!(narrowed_scheme(claims::TRANSPORT_STDIO), "environment");
    assert_eq!(narrowed_scheme(claims::TRANSPORT_HTTP), "bearer");
    assert_eq!(narrowed_scheme(claims::TRANSPORT_SSE), "bearer");
}

/// Every narrowing the root can produce is inside the set the claims declare.
///
/// This is the property the auth unit's first check tests for, asserted here so a transport added
/// to the claim list without an alternative is a red test rather than a refused request.
#[test]
fn every_narrowing_is_within_the_declared_set() {
    let declared = declared_schemes();
    for transport in [
        claims::TRANSPORT_HTTP,
        claims::TRANSPORT_SSE,
        claims::TRANSPORT_STDIO,
    ] {
        assert!(
            declared.contains(&narrowed_scheme(transport)),
            "{transport} narrows outside the declared set"
        );
    }
}

/// A record leg the plane declares passes the trust unit's per-kind rule; one it does not
/// declare fails it.
#[test]
fn a_record_leg_is_judged_against_the_planes_own_declaration() {
    let declared = Catalogue::new(
        McpPlane::EMPTY,
        records::SCHEMA_CALL,
        records::OP_APPEND,
        seam(),
    );
    assert!(declared.plane_record_ok());

    // The call log is append-and-read: an answer whose middle can be replaced is not an answer.
    let rewritten = Catalogue::new(
        McpPlane::EMPTY,
        records::SCHEMA_CALL,
        records::OP_PUT,
        seam(),
    );
    assert!(!rewritten.plane_record_ok());

    let stranger = Catalogue::new(
        McpPlane::EMPTY,
        RecordSchemaId::new("ledger"),
        records::OP_GET,
        seam(),
    );
    assert!(!stranger.plane_record_ok());
}

/// A deployment with nothing registered has nowhere to send a hop, and says so.
///
/// The plane answers with an empty host rather than panicking or inventing one, precisely so this
/// refusal happens at the step that owns it.
#[test]
fn an_unregistered_hop_is_not_allow_listed() {
    let facts = Catalogue::upstream_only(McpPlane::EMPTY, seam());
    let nowhere = DestinationFacts::Upstream {
        transport: claims::TRANSPORT_HTTP,
        address: busbar_contract::UpstreamAddress::socket(""),
        lane: LaneId::new(""),
    };
    assert!(!facts.allow_listed(&nowhere));
}

/// A registered server's own hop is allow-listed, and its lane is permitted.
#[test]
fn a_registered_hop_is_allow_listed() {
    static SERVERS: &[Server] = &[Server {
        id: "fs",
        lane: LaneId::new("fs-lane"),
        host: "127.0.0.1:9",
        transport: claims::TRANSPORT_HTTP,
    }];
    let plane = McpPlane::new(SERVERS);
    let facts = Catalogue::upstream_only(plane, seam());
    let hop = DestinationFacts::Upstream {
        transport: claims::TRANSPORT_HTTP,
        address: busbar_contract::UpstreamAddress::socket("127.0.0.1:9"),
        lane: LaneId::new("fs-lane"),
    };
    assert!(facts.allow_listed(&hop));
    assert!(facts.transport_key_resolves(&hop));
    assert!(facts.lane_permitted_for_op_class("fs-lane"));
    assert!(!facts.lane_permitted_for_op_class("some-other-lane"));
}

/// A registered server whose name answers with the metadata address is refused by the guard the
/// catalogue asks, and the ordinary one is not.
#[test]
fn a_registered_hop_answering_with_the_metadata_address_does_not_pass_the_guard() {
    struct Metadata;
    impl Resolver for Metadata {
        fn resolve(&self, _host: &str) -> Result<Vec<std::net::IpAddr>, String> {
            Ok(vec!["169.254.169.254".parse().expect("a fixture address")])
        }
    }
    static SERVERS: &[Server] = &[Server {
        id: "fs",
        lane: LaneId::new("fs-lane"),
        host: "fs.internal:443",
        transport: claims::TRANSPORT_HTTP,
    }];
    let hop = DestinationFacts::Upstream {
        transport: claims::TRANSPORT_HTTP,
        address: busbar_contract::UpstreamAddress::socket("fs.internal:443"),
        lane: LaneId::new("fs-lane"),
    };
    let plane = McpPlane::new(SERVERS);

    static RESOLVER: Metadata = Metadata;
    static DENYLIST: std::sync::LazyLock<Denylist> = std::sync::LazyLock::new(Denylist::default);
    let hostile = Catalogue::upstream_only(
        plane,
        NetSeam {
            resolver: &RESOLVER,
            policy: GuardPolicy::default(),
            denylist: &DENYLIST,
        },
    );
    assert!(hostile.allow_listed(&hop), "the deployment registered it");
    assert!(
        !hostile.net_guard_passes(&hop),
        "and it answers with the address whose whole value is handing out credentials"
    );

    assert!(Catalogue::upstream_only(plane, seam()).net_guard_passes(&hop));
}

/// The breaker's answer at the seal is the breaker's answer about that lane's position.
#[test]
fn the_catalogue_asks_the_breaker_about_the_registered_lanes_position() {
    struct Open(usize);
    impl BreakerView for Open {
        fn ready(&self, _pool: &str, lane: usize, _now: u64) -> bool {
            lane != self.0
        }
        fn try_admit(
            &self,
            _pool: &str,
            _lane: usize,
            _now: u64,
        ) -> Result<(), busbar_unit_trust::Unavailable> {
            Ok(())
        }
    }
    static SERVERS: &[Server] = &[
        Server {
            id: "first",
            lane: LaneId::new("first-lane"),
            host: "127.0.0.1:9",
            transport: claims::TRANSPORT_HTTP,
        },
        Server {
            id: "second",
            lane: LaneId::new("second-lane"),
            host: "127.0.0.1:10",
            transport: claims::TRANSPORT_HTTP,
        },
    ];
    let facts = Catalogue::upstream_only(McpPlane::new(SERVERS), seam());
    let second = DestinationFacts::Upstream {
        transport: claims::TRANSPORT_HTTP,
        address: busbar_contract::UpstreamAddress::socket("127.0.0.1:10"),
        lane: LaneId::new("second-lane"),
    };

    let open = Open(1);
    let at = BreakerQuery {
        breaker: &open,
        pool: "second",
        now: 7,
    };
    assert!(
        !facts.breaker_admits(&second, &at),
        "the second registration is at position one, and that is the open cell"
    );

    let elsewhere = Open(0);
    let at = BreakerQuery {
        breaker: &elsewhere,
        pool: "second",
        now: 7,
    };
    assert!(facts.breaker_admits(&second, &at));
}

/// An explicitly empty scope list denies every registration; an absent one denies none.
///
/// The two are different answers to different questions and the rig's verify cell turns on the
/// difference: a key scoped to nothing is refused before the door draws anything.
#[test]
fn an_explicit_empty_scope_list_denies_every_pool() {
    static SERVERS: &[Server] = &[Server {
        id: "fs",
        lane: LaneId::new("fs-lane"),
        host: "127.0.0.1:9",
        transport: claims::TRANSPORT_HTTP,
    }];
    let plane = McpPlane::new(SERVERS);

    let empty = Pools::new(plane, Some(Vec::new()), true, false);
    assert!(!empty.pool_allowed(&pool_key("fs")));

    let unrestricted = Pools::new(plane, None, true, false);
    assert!(unrestricted.pool_allowed(&pool_key("fs")));

    let named = Pools::new(plane, Some(vec!["fs".to_string()]), true, false);
    assert!(named.pool_allowed(&pool_key("fs")));
    assert!(!named.pool_allowed(&pool_key("other")));
}

/// A call names both resource kinds; everything else names only the server.
///
/// The coarse grant never stands in for the fine one, which is the whole reason there are two.
#[test]
fn a_call_names_the_tool_as_well_as_the_server() {
    static SERVERS: &[Server] = &[Server {
        id: "fs",
        lane: LaneId::new("fs-lane"),
        host: "127.0.0.1:9",
        transport: claims::TRANSPORT_HTTP,
    }];
    let plane = McpPlane::new(SERVERS);

    let call = resources(&plane, ops::OP_TOOL_CALL);
    assert_eq!(call.len(), 2);
    assert_eq!(call[0].kind, SCOPE_KIND_SERVER);
    assert_eq!(call[1].kind, SCOPE_KIND_TOOL);

    let listing = resources(&plane, ops::OP_TOOLS_LIST);
    assert_eq!(listing.len(), 1);
    assert_eq!(listing[0].kind, SCOPE_KIND_SERVER);
}

/// A deployment with nothing registered names no resource, and that is a refusal.
#[test]
fn nothing_registered_is_a_refusal_and_not_a_pass() {
    let policy = crate::root::policy::ScopePolicy::new().declaring(
        claim_key(),
        ops::OP_TOOL_CALL,
        Scope::Full,
    );
    let refusal = approve(
        &McpPlane::EMPTY,
        ops::OP_TOOL_CALL,
        Grants::of(Scope::Full),
        &policy,
    )
    .expect_err("a plane with no server authorizes nothing");
    assert_eq!(refusal, ApproveRefusal::NoResource);
}

/// A pair the policy says nothing about is refused, even when the caller holds every grant.
///
/// Authorization by omission is the failure this shape exists to make impossible: the scope unit
/// answers `None` for silence and `None` is a refusal.
#[test]
fn silence_is_a_refusal() {
    static SERVERS: &[Server] = &[Server {
        id: "fs",
        lane: LaneId::new("fs-lane"),
        host: "127.0.0.1:9",
        transport: claims::TRANSPORT_HTTP,
    }];
    let plane = McpPlane::new(SERVERS);
    let silent = crate::root::policy::ScopePolicy::new();
    let refusal = approve(&plane, ops::OP_TOOL_CALL, Grants::of(Scope::Full), &silent)
        .expect_err("an unwritten policy entry authorizes nothing");
    assert_eq!(refusal, ApproveRefusal::NoPolicyEntry);
}

/// A caller holding only the read-only grant may list and may not call.
#[test]
fn a_read_only_grant_lists_and_does_not_call() {
    static SERVERS: &[Server] = &[Server {
        id: "fs",
        lane: LaneId::new("fs-lane"),
        host: "127.0.0.1:9",
        transport: claims::TRANSPORT_HTTP,
    }];
    let plane = McpPlane::new(SERVERS);
    let mut policy = crate::root::policy::ScopePolicy::new();
    for (op, scope) in required_scopes() {
        policy = policy.declaring(claim_key(), op, scope);
    }

    assert!(approve(
        &plane,
        ops::OP_TOOLS_LIST,
        Grants::of(Scope::ReadOnly),
        &policy
    )
    .is_ok());

    let refusal = approve(
        &plane,
        ops::OP_TOOL_CALL,
        Grants::of(Scope::ReadOnly),
        &policy,
    )
    .expect_err("a read-only grant does not call a tool");
    assert!(matches!(refusal, ApproveRefusal::Insufficient(_)));
}

/// Every operation class the plane declares has a required scope, so no class is authorized by
/// silence for want of an entry the root forgot to write.
#[test]
fn every_operation_class_has_a_required_scope() {
    let declared = required_scopes();
    assert_eq!(declared.len(), <McpPlane as PlaneMeta>::OP_CLASSES.len());
    for op in <McpPlane as PlaneMeta>::OP_CLASSES {
        assert!(
            declared.iter().any(|(o, _)| o == op),
            "{op} has no required scope"
        );
    }
}

/// A call is estimated as one call plus the request document; everything else is the document
/// alone.
#[test]
fn a_call_is_estimated_flat_plus_its_document() {
    let prices = ClassPrices {
        tool_calls: 7,
        bytes: 2,
    };
    let call = estimate(ops::OP_TOOL_CALL, 10, &prices, 100);
    assert_eq!(call.per_class.len(), 2);
    assert_eq!(call.per_class[0].class, CLASS_TOOL_CALLS.as_str());
    assert_eq!(call.per_class[0].quantity, 1);
    // 100 fee + 1 call at 7 + 10 bytes at 2.
    assert_eq!(call.pre_tier_nanos(), 127);

    let listing = estimate(ops::OP_TOOLS_LIST, 10, &prices, 100);
    assert_eq!(listing.per_class.len(), 1);
    assert_eq!(listing.per_class[0].class, CLASS_BYTES.as_str());
}

/// Every kind the plane's plans name classifies to something the root can service, and no plan
/// of this plane yields the unsupported arm.
#[test]
fn every_planned_kind_classifies() {
    assert_eq!(
        classify(&DestinationFacts::PlaneRecord {
            schema: records::SCHEMA_CALL,
            op: records::OP_APPEND,
        }),
        LegKind::Record {
            schema: records::SCHEMA_CALL,
            op: records::OP_APPEND,
        }
    );
    assert_eq!(
        classify(&DestinationFacts::NestedPlane {
            plane: "llm",
            op: OpClassId::new("chat"),
        }),
        LegKind::Nested {
            plane: "llm",
            op: OpClassId::new("chat"),
        }
    );
    assert_eq!(
        classify(&DestinationFacts::Client {
            selector: "opener",
            mode: busbar_contract::dest::ClientMode::Deliver,
        }),
        LegKind::Client { selector: "opener" }
    );
    assert!(matches!(
        classify(&DestinationFacts::Upstream {
            transport: claims::TRANSPORT_HTTP,
            address: busbar_contract::UpstreamAddress::socket("127.0.0.1:9"),
            lane: LaneId::new("fs-lane"),
        }),
        LegKind::Upstream { .. }
    ));
    assert_eq!(
        classify(&DestinationFacts::KernelVerb { verb: "restart" }),
        LegKind::Unsupported
    );
}

/// Every leg the plane's own plans reach is one its schema declares.
///
/// This is the boot check's subject, asserted directly: a leg naming an operation its schema does
/// not declare would be refused by the trust unit at run time, and a plane whose every plan
/// depended on that refusal would be a plane that never worked.
#[test]
fn every_planned_leg_is_declared() {
    for (schema, op) in planned_legs() {
        assert!(
            records::operations_for(*schema).contains(op),
            "{schema} declares no {op}"
        );
    }
}

/// The plane's route plans reach exactly the legs the table names — no more, and no fewer.
///
/// Reaching the plan itself needs a request, so the two sides are compared through the
/// declarations both are built from: every pair in the table is declared, and every schema the
/// plane declares appears in the table at least once. A schema nothing plans to reach is a
/// schema that will never hold anything.
#[test]
fn every_declared_schema_is_reached_by_some_plan() {
    for schema in <McpPlane as PlaneMeta>::RECORD_SCHEMAS {
        assert!(
            planned_legs().iter().any(|(s, _)| s == schema),
            "{schema} is declared and never reached"
        );
    }
}

/// The metering binding posts a completed call under the class the plane declares, once.
#[test]
fn a_completed_call_is_counted_once() {
    let values = located_values(ops::OP_TOOL_CALL, 40);
    assert_eq!(values.len(), 2);
    assert_eq!(values[0].class, CLASS_TOOL_CALLS);
    assert_eq!(values[0].quantity, 1);
    assert_eq!(values[1].class, CLASS_BYTES);
    assert_eq!(values[1].quantity, 40);

    let listing = located_values(ops::OP_TOOLS_LIST, 40);
    assert_eq!(listing.len(), 1);
    assert_eq!(listing[0].class, CLASS_BYTES);
}

/// The plane declares one lane leg and disclaims the other two.
///
/// Declaring a leg the plane never produces turns every settled unit into a dispute over evidence
/// that was never going to arrive, which is the loudest way to be wrong about metering.
#[test]
fn only_the_verified_lane_leg_is_declared() {
    let declared = leg_declaration();
    assert!(declared.verified);
    assert!(!declared.admit_locator);
    assert!(!declared.response);
}

/// A served call leaves exactly one administrative entry, under the codec's own action and
/// resource; nothing else leaves one at all.
#[test]
fn only_a_served_call_leaves_an_administrative_entry() {
    let entry = legacy_entry(ops::OP_TOOL_CALL, "probe_ping", "k-7", true, 100)
        .expect("a call is recorded");
    assert_eq!(entry.action, "mcp_tool.call");
    assert_eq!(entry.resource, "mcp_tool:probe_ping");
    assert_eq!(entry.outcome, OUTCOME_APPLIED);
    assert_eq!(entry.principal, "k-7");
    assert_eq!(entry.ts, 100);

    let refused = legacy_entry(ops::OP_TOOL_CALL, "probe_ping", "k-7", false, 100)
        .expect("a refused call is recorded too");
    assert_eq!(refused.outcome, OUTCOME_REJECTED);

    assert!(legacy_entry(ops::OP_TOOLS_LIST, "probe_ping", "k-7", true, 100).is_none());
    assert!(legacy_entry(ops::OP_NOTIFICATION, "probe_ping", "k-7", true, 100).is_none());
}

/// The action and the resource prefix are the codec's own strings.
///
/// Both live in the half of this protocol that still holds the verb body, where they are visible
/// to that crate only. This reads them out of its source, so a rename there is a red test here
/// rather than an audit surface that answers under a name the rig does not look for.
#[test]
fn the_audit_strings_are_the_codecs_own() {
    let codec = include_str!("../../../../busbar-mcp/src/mcp/method.rs");
    assert!(
        codec.contains(&format!("\"{AUDIT_ACTION_TOOL_CALL}\"")),
        "the codec no longer records under {AUDIT_ACTION_TOOL_CALL}"
    );
    assert!(
        codec.contains(&format!("\"{AUDIT_RESOURCE_PREFIX_TOOL}{{}}\"")),
        "the codec no longer names the {AUDIT_RESOURCE_PREFIX_TOOL} resource prefix"
    );
}

/// The two scope kinds are the ones the I/O half declares on its own plane row.
#[test]
fn the_scope_kinds_are_the_codecs_own() {
    let codec = include_str!("../../../../busbar-mcp/src/mcp/mod.rs");
    assert!(
        codec.contains(&format!(
            "scope_kinds: &[\"{SCOPE_KIND_SERVER}\", \"{SCOPE_KIND_TOOL}\"]"
        )),
        "the codec no longer declares the two scope kinds"
    );
}

/// The pool prefix is the substrate's own, single-sourced there.
#[test]
fn the_pool_prefix_is_the_substrates_own() {
    let substrate = include_str!("../../../../busbar-substrate/src/store.rs");
    assert!(
        substrate.contains(&format!("format!(\"{POOL_PREFIX_TOOL}{{server}}\")")),
        "the substrate no longer keys this plane's cells under {POOL_PREFIX_TOOL}"
    );
    assert_eq!(pool_key("fs"), "tool:fs");
}

/// A refusal message tells the caller nothing about the deployment's money.
#[test]
fn the_unpriced_message_leaks_nothing() {
    for leak in ["budget", "bucket", "price", "card", "cost", "spend"] {
        assert!(
            !UNPRICED_MESSAGE.to_ascii_lowercase().contains(leak),
            "the unpriced message leaks {leak}"
        );
    }
}

/// The mount's four checks pass on the plane as it is declared today.
#[test]
fn the_plane_mounts() {
    let store = StoreAdapter::native(Arc::new(SilentStore));
    let mounted = mount(McpPlane::EMPTY, &store).expect("the declared plane mounts");
    assert_eq!(
        mounted.scopes.len(),
        <McpPlane as PlaneMeta>::OP_CLASSES.len()
    );
}

/// A record leg the plane does not declare is refused before the store is asked.
///
/// The trust unit refuses such a leg first; this is the second door, and it is here because a
/// store reached by any other route would otherwise hold a record under a schema nothing reads
/// back.
#[test]
fn an_undeclared_record_leg_never_reaches_the_store() {
    let store = StoreAdapter::native(Arc::new(SilentStore));
    let records_binding = Records::new(&store);
    let leg = RecordLeg {
        schema: records::SCHEMA_CALL,
        op: records::OP_PUT,
        key: "k",
        parent: None,
        seq: 1,
        body: b"{}",
        terminal: false,
        now: 100,
        expires_at: 0,
    };
    let refusal = records_binding
        .run(&leg)
        .expect_err("the call log cannot be rewritten");
    assert!(matches!(refusal, RecordRefusal::Undeclared { .. }));
}

/// Every operation the plane declares has an arm, and each answers in the shape its schema means.
#[test]
fn every_declared_operation_has_an_arm() {
    let store = StoreAdapter::native(Arc::new(SilentStore));
    let binding = Records::new(&store);
    let leg = |schema, op| RecordLeg {
        schema,
        op,
        key: "k",
        parent: None,
        seq: 1,
        body: b"{}",
        terminal: false,
        now: 100,
        expires_at: 200,
    };

    for schema in <McpPlane as PlaneMeta>::RECORD_SCHEMAS {
        for op in records::operations_for(*schema) {
            let answer = binding
                .run(&leg(*schema, op))
                .unwrap_or_else(|e| panic!("{schema}/{op} has no arm: {e}"));
            match *op {
                records::OP_GET => assert!(matches!(answer, RecordAnswer::One(_))),
                records::OP_SCAN => assert!(matches!(answer, RecordAnswer::Many(_))),
                records::OP_REDEEM => assert!(matches!(answer, RecordAnswer::Redeemed(_))),
                _ => assert_eq!(answer, RecordAnswer::Written),
            }
        }
    }
}

/// A grant is spent atomically, and the spend is the store's own test-and-set rather than a read
/// followed by a write.
///
/// The two-step version is the race the operation exists to close: between the read and the write
/// a second caller spends the same grant, and a retry of a failed hop becomes a second free call.
#[test]
fn a_grant_is_spent_by_a_test_and_set() {
    let ops = records::operations_for(records::SCHEMA_APPROVAL);
    assert!(ops.contains(&records::OP_REDEEM));
    assert!(!ops.contains(&records::OP_GET));
    assert!(!ops.contains(&records::OP_SCAN));
}

/// The balance names the CALLER, which is the bucket every other plane settles into and the
/// bucket a principal's own usage is read out of. A registration-shaped one would put this
/// plane's spend somewhere no principal's figures ever look.
#[test]
fn the_balance_names_the_caller_and_not_the_registration() {
    let key = balance(&PrincipalId::new("vk_mcp"));
    assert_eq!(key.bucket.as_str(), "vk_mcp");
    assert_ne!(
        key.bucket.as_str(),
        pool_key("fs"),
        "the server's own key is the breaker's and the pool table's, never the books'"
    );
    assert_eq!(key.dimension, CapDimension::NanoUnits, "money, not calls");
    assert_eq!(
        key.scope,
        BucketScope::All,
        "an attribution bucket is not a budget"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// The fee, decided once
// ─────────────────────────────────────────────────────────────────────────

/// A unit of this plane, ended, with everything the money is decided from.
fn ended(shape: Shape, origin: busbar_caps::OriginKind, answered: bool) -> Ended<'static> {
    Ended {
        shape,
        origin,
        finish: if answered {
            busbar_contract::unit::FinishClass::Complete
        } else {
            busbar_contract::unit::FinishClass::Error
        },
        request_bytes: 10,
        metered: answered.then_some(40),
        dispatched: true,
        principal: None,
        resource: Some(Resource {
            kind: SCOPE_KIND_TOOL,
            name: "fs",
        }),
    }
}

/// The shape's upstream fact is read off the plan the plane returned, not off a list of classes
/// kept here — which is what stops it from drifting the day a plan changes.
#[test]
fn the_shape_reads_the_hop_off_the_plan() {
    let hops = [
        LegKind::Record {
            schema: records::SCHEMA_CATALOGUE,
            op: records::OP_GET,
        },
        LegKind::Upstream {
            transport: claims::TRANSPORT_HTTP,
            lane: LaneId::new("fs-lane"),
        },
    ];
    assert!(Shape::of(ops::OP_TOOL_CALL, &hops).hops_upstream);

    let from_the_node_alone = [LegKind::Record {
        schema: records::SCHEMA_CATALOGUE,
        op: records::OP_SCAN,
    }];
    assert!(!Shape::of(ops::OP_TOOLS_LIST, &from_the_node_alone).hops_upstream);
    assert!(!Shape::of(ops::OP_TOOLS_LIST, &[]).hops_upstream);
}

/// **The flat fee is posted for a delivered client call and for nothing else.** The estimate
/// takes a fee into the hold; a leg with no way to POST one reserves money against a charge that
/// cannot happen, and every unit of this plane over-reserves for the life of the deployment.
#[test]
fn the_flat_fee_is_posted_for_a_delivered_client_call_and_for_nothing_else() {
    use busbar_caps::OriginKind as CameFrom;
    use busbar_kernel::teller::fee_count;

    let called = Shape {
        op: ops::OP_TOOL_CALL,
        hops_upstream: true,
    };
    let fee = |origin, answered| fee_count(&evidence(&ended(called, origin, answered)).fee).0;
    assert_eq!(fee(CameFrom::Client, true), 1, "a delivered call pays once");
    assert_eq!(
        fee(CameFrom::Client, false),
        0,
        "a call that never got an answer to hand back pays nothing"
    );
    assert_eq!(
        fee(CameFrom::Provider, true),
        0,
        "what the server pushed is not a caller's request"
    );

    let listed = Shape {
        op: ops::OP_TOOLS_LIST,
        hops_upstream: false,
    };
    assert_eq!(
        fee_count(&evidence(&ended(listed, CameFrom::Client, true)).fee).0,
        0,
        "a listing answered from this node's own records reaches no server and pays no hop"
    );
}

/// **One decision, two readers.** The settlement's evidence and the audit record count the same
/// fee, because both read it through the same function. A posting that charged one and a row
/// that says none is a discrepancy nothing downstream can resolve, and this is what makes it
/// unrepresentable rather than merely unlikely.
#[test]
fn the_settlement_and_the_record_read_one_fee_decision() {
    use busbar_caps::OriginKind as CameFrom;
    use busbar_kernel::teller::fee_count;
    let origin = Kernel::new().origin(CameFrom::Client);
    let at = Clocks {
        wall: 1_700_000_000,
        mono: Mono::new().tick(),
    };
    let called = Shape {
        op: ops::OP_TOOL_CALL,
        hops_upstream: true,
    };

    for (who, answered) in [
        (CameFrom::Client, true),
        (CameFrom::Client, false),
        (CameFrom::Provider, true),
    ] {
        let unit = ended(called, who, answered);
        let record = audit_inputs(&unit, busbar_caps::Outcome::Completed, origin, at);
        assert_eq!(
            record.amount.fee_count,
            fee_count(&evidence(&unit).fee).0,
            "the row and the posting agree about the fee"
        );
    }
}

/// The record names the caller, the operation class the plane declares and the resource it acted
/// on, and it is stamped with the unit's own two clocks rather than a fresh read at the exit.
#[test]
fn the_record_names_the_caller_the_class_and_the_resource() {
    let who = PrincipalId::new("vk_mcp");
    let origin = Kernel::new().origin(busbar_caps::OriginKind::Client);
    let at = Clocks {
        wall: 1_700_000_000,
        mono: 7,
    };
    let mut unit = ended(
        Shape {
            op: ops::OP_TOOL_CALL,
            hops_upstream: true,
        },
        busbar_caps::OriginKind::Client,
        true,
    );
    unit.principal = Some(&who);

    let record = audit_inputs(&unit, busbar_caps::Outcome::Completed, origin, at);
    assert_eq!(
        record.subject,
        busbar_unit_audit::Subject::PrincipalId("vk_mcp".to_string())
    );
    assert_eq!(
        record.what.op_class,
        busbar_unit_audit::record::OpClassId::new("tool_call"),
        "the record must file under the plane's own literal op-class name, not a re-derivation \
         of whatever record_op_class happens to produce today"
    );
    assert_eq!(
        record.what.destination.as_deref(),
        Some("mcp_tool:fs"),
        "the resource pair the approve step judged"
    );
    assert_eq!(record.wall, 1_700_000_000);
    assert_eq!(record.mono, 7, "the unit's own reading, not the wall clock");
    assert_eq!(record.amount.fee_count, 1);
}

// ─────────────────────────────────────────────────────────────────────────
// The reservation, from the door to the exit
// ─────────────────────────────────────────────────────────────────────────

fn memory_durability() -> crate::root::durability::Durability {
    crate::root::durability::build(
        &crate::root::durability::DurabilityConfig { data_dir: None },
        Box::new(busbar_unit_wal::NullShipper::new()),
        Box::new(busbar_unit_ledger::legacy::RecordingRows::new()),
    )
    .expect("a memory-buffered journal cannot fail to open")
}

/// The door opens the reservation, sized off the estimate this plane's two classes produce, and
/// it opens it only because the decision said yes. Nothing about the size is a decision.
#[test]
fn the_door_opens_a_reservation_sized_off_this_planes_estimate() {
    use busbar_caps::{step::Admit as AdmitStep, AdmitToken, KernelSeal, UnitToken};
    let seal = KernelSeal::acquire_for_kernel();
    let door = Door::new(InMemoryCells::new());
    let pricer = Pricer::flat(0);
    let chain = BucketChain::unchecked(Vec::new(), Vec::new());
    let prices = ClassPrices {
        tool_calls: 7,
        bytes: 2,
    };
    let est = estimate(ops::OP_TOOL_CALL, 10, &prices, 100);
    let who = PrincipalId::new("vk_mcp");
    let unit = Admitting {
        door: &door,
        pricer: &pricer,
        pool: "fs",
        arrival_epoch: 1_700_000_000,
        estimate: &est,
        principal: &who,
        chain: &chain,
    };
    let decision = admit(
        &unit,
        &AdmitToken::<AdmitStep>::mint(&seal),
        &UnitToken::<AdmitStep>::mint(&seal),
        &GroupLeaseSlip::new(),
    );
    let busbar_caps::Admission::Own(hold) = decision
        .into_result(&seal)
        .expect("an empty chain refuses nothing")
    else {
        panic!("a priced unit opens a hold of its own");
    };
    assert_eq!(
        hold.reserved(),
        127,
        "100 fee + one call at 7 + ten bytes at 2"
    );
    let _ = busbar_caps::Posted::settle(
        hold,
        // The unit is only admitted here, never run, so it priced at nothing.
        0,
        &busbar_caps::Usage::report(&busbar_caps::UsageToken::mint(&seal), Vec::new())
            .expect("empty"),
        &busbar_caps::LedgerToken::mint(&seal),
    );
}

/// A group table with one group in it, capped at one unit in flight.
///
/// Built through the interner the root uses at boot, so the name the slot records is the same
/// static the vocabulary holds rather than one this fixture invented.
fn one_call_at_a_time(group: &str) -> busbar_unit_admission::GroupTable {
    let groups = BTreeMap::from([(
        group.to_string(),
        busbar_substrate::config::groups::GroupCfg {
            parent: None,
            enabled: true,
            limits: vec![busbar_substrate::config::groups::LimitCfg {
                metric: busbar_substrate::config::groups::LimitMetric::Concurrent,
                amount: 1,
                per: None,
                scope: None,
                on_exhaust: None,
                downgrade_to: None,
            }],
            child_default: None,
        },
    )]);
    let mut vocabulary = crate::root::vocabulary::Vocabulary::new();
    let ids = vocabulary.group_ids(&crate::root::vocabulary::ConfigKeys {
        groups: vec![group.to_string()],
        ..crate::root::vocabulary::ConfigKeys::default()
    });
    crate::root::policy::group_table(&groups, &ids)
}

/// Ask the door for one call, keeping what its yes counted.
fn ask_the_door(
    door: &Door<InMemoryCells>,
    chain: &BucketChain,
    who: &PrincipalId,
) -> (Result<busbar_caps::Admission, Refusal>, GroupLeaseSlip) {
    use busbar_caps::{step::Admit as AdmitStep, AdmitToken, KernelSeal, UnitToken};
    let seal = KernelSeal::acquire_for_kernel();
    let pricer = Pricer::flat(0);
    let est = estimate(ops::OP_TOOL_CALL, 10, &ClassPrices::default(), 0);
    let unit = Admitting {
        door,
        pricer: &pricer,
        pool: "fs",
        arrival_epoch: 1_700_000_000,
        estimate: &est,
        principal: who,
        chain,
    };
    let slip = GroupLeaseSlip::new();
    let decision = admit(
        &unit,
        &AdmitToken::<AdmitStep>::mint(&seal),
        &UnitToken::<AdmitStep>::mint(&seal),
        &slip,
    );
    (decision.into_result(&seal), slip)
}

/// **The cap is a cap.** A deployment that wrote `concurrent: 1` against a group gets one MCP
/// call in the air at a time: the second is refused while the first is still running, and it is
/// admitted once the first has ended.
///
/// The count is what makes that true. Left to die with the call that asked, the gauge is lowered
/// before the unit it admitted has done anything, and a limit an operator wrote down admits
/// every unit that ever arrives with nothing on any surface to say so.
#[test]
fn an_mcp_group_capped_at_one_call_refuses_the_second_and_admits_it_after_the_first_ends() {
    const GROUP: &str = "mcp-team";
    let door = Door::new(InMemoryCells::new());
    let who = PrincipalId::new("vk_mcp");
    // Resolved once, where the root resolves the caller. Every unit below reads this one value.
    let chain = one_call_at_a_time(GROUP)
        .chain_for(who.as_str(), Some(GROUP))
        .expect("the group is configured");

    let (admitted, held) = ask_the_door(&door, &chain, &who);
    assert!(admitted.is_ok(), "the first call of a group capped at one");
    assert_eq!(
        held.taken().len(),
        1,
        "and the yes names the one capped group it counted"
    );
    // The count itself, taken onto the slot as the loop takes it. Held for as long as the unit
    // it admitted is running, which is what makes the next line a refusal rather than a second
    // yes.
    let running = held.grant_taken().expect("the yes is holding a count");

    let (refused, _) = ask_the_door(&door, &chain, &who);
    assert_eq!(
        refused.expect_err("the group is full").reason(),
        ReasonCode::RateLimited,
        "an in-flight gauge is a count cap, not a spend cap"
    );

    // The unit ends: the slot gives back what it held, and the group has room again.
    drop(running);
    let (after, _) = ask_the_door(&door, &chain, &who);
    assert!(
        after.is_ok(),
        "the cap is instantaneous — it gates what is running, never what has run"
    );
}

/// And the exit closes it: the books move on the key this plane already declares, the residual
/// is released, and the posting lands on the journal. Before the exit arm was bound the last two
/// happened nowhere at all.
#[test]
fn the_exit_settles_the_reservation_onto_the_books_and_the_journal() {
    use busbar_caps::{
        step::Admit as AdmitStep, AdmitToken, DurabilityToken, Hold, KernelSeal, LedgerToken,
        MeterClassId, QuantitySource, Usage, UsageLine, UsageToken,
    };
    let seal = KernelSeal::acquire_for_kernel();
    let mut durability = memory_durability();
    let who = PrincipalId::new("vk_mcp");

    let mut hold = Hold::open(&AdmitToken::<AdmitStep>::mint(&seal), who.clone(), 1_000);
    // The slice had room, so the reservation grows rather than the unit carrying anything.
    assert_eq!(hold.spend(400, u64::MAX).overdraft, 0);
    let usage = Usage::report(
        &UsageToken::mint(&seal),
        vec![UsageLine {
            class: MeterClassId::new("nano_units"),
            quantity: 400,
            source: QuantitySource::Count,
            estimated: false,
        }],
    )
    .expect("one line");
    // The line's class is `nano_units`, so its quantity IS the money — the same shape the
    // kernel's exit path builds, and the same figure passed on both sides.
    let posted = busbar_caps::Posted::settle(hold, 400, &usage, &LedgerToken::mint(&seal));

    let mono = Mono::new();
    let settled = settle(
        &mut durability,
        &who,
        Clocks {
            wall: 1_700_000_000,
            mono: mono.tick(),
        },
        &DurabilityToken::mint(&seal),
        posted,
    )
    .expect("the memory-buffered journal takes it");
    assert_eq!(settled.settlement.released, 600);
    assert!(settled.overdraft.is_none());

    let key = balance(&who);
    let window = busbar_unit_admission::budget_window(
        busbar_unit_admission::window::WINDOW_DAY,
        1_700_000_000,
    );
    let figures = durability.ledger.book().get(&key, window);
    assert_eq!(figures.settled, 400);
    assert_eq!(figures.open_slice_remainders, 600, "the residual goes back");
    assert_eq!(figures.overdraft_carried_out, 0);
    // The identity, over this plane's own unit: what was reserved is what was spent plus what
    // came back plus what nothing could back. It only closes because the three figures are all
    // read out of ONE bucket — the caller's. Posted into a bucket keyed by the registration,
    // every one of them would be missing from the principal the money was taken from, and the
    // difference would sit on the reconciliation permanently.
    assert_eq!(
        figures.settled + figures.open_slice_remainders + figures.overdraft_carried_out,
        1_000,
        "the reservation is accounted for, in the caller's own bucket"
    );
    let replayed = durability
        .journal
        .replay()
        .expect("reads back")
        .expect("verifies");
    assert_eq!(replayed.len(), 1, "one posting, one record");
}

/// **Two clocks, and the second one is a clock.** Two units that arrived in the same second are
/// stamped with the same wall clock and with DIFFERENT monotonic readings, in the order they
/// arrived — which is the whole of what the second stamp is for. Set equal to the wall clock it
/// keeps none of that: the chain cannot say which of the two came first, and a node whose clock
/// stepped backwards writes records that read as having happened in an order they did not.
#[test]
fn two_units_of_one_second_are_ordered_by_the_monotonic_stamp_and_not_the_wall_clock() {
    use busbar_caps::{
        step::Admit as AdmitStep, AdmitToken, DurabilityToken, Hold, KernelSeal, LedgerToken,
        Usage, UsageToken,
    };
    const SAME_SECOND: u64 = 1_700_000_000;
    let seal = KernelSeal::acquire_for_kernel();
    let mut durability = memory_durability();
    let who = PrincipalId::new("vk_mcp");
    // One clock for the node, read once per unit — where the unit arrives, as the loop reads it.
    let clock = Mono::new();

    let mut stamps = Vec::new();
    for _ in 0..2 {
        let at = Clocks {
            wall: SAME_SECOND,
            mono: clock.tick(),
        };
        let hold = Hold::open(&AdmitToken::<AdmitStep>::mint(&seal), who.clone(), 0);
        let posted = busbar_caps::Posted::settle(
            hold,
            0,
            &Usage::report(&UsageToken::mint(&seal), Vec::new()).expect("empty"),
            &LedgerToken::mint(&seal),
        );
        let settled = settle(
            &mut durability,
            &who,
            at,
            &DurabilityToken::mint(&seal),
            posted,
        )
        .expect("the memory-buffered journal takes it");
        stamps.push((settled.posting.wall, settled.posting.mono));
    }

    assert_eq!(
        stamps[0].0, stamps[1].0,
        "the wall clock is the arrival second, and both arrived in it"
    );
    assert_ne!(
        stamps[0].1, stamps[1].1,
        "and the monotonic stamp is not a second copy of it"
    );
    assert!(
        stamps[0].1 < stamps[1].1,
        "the reading advances in the order the units arrived"
    );
}

/// A unit that outran everything reservable is not refused, not trimmed, and leaves a carry of
/// its own on the chain beside the posting it came out of.
#[test]
fn a_unit_that_outran_its_reservation_carries_the_rest_onto_the_chain() {
    use busbar_caps::{
        step::Admit as AdmitStep, AdmitToken, DurabilityToken, Hold, KernelSeal, LedgerToken,
        MeterClassId, PostingFlags, QuantitySource, Usage, UsageLine, UsageToken,
    };
    let seal = KernelSeal::acquire_for_kernel();
    let mut durability = memory_durability();
    let mut hold = Hold::open(
        &AdmitToken::<AdmitStep>::mint(&seal),
        PrincipalId::new("vk_mcp"),
        1_000,
    );
    let spend = hold.spend(4_000, 0);
    assert_eq!(spend.accrued, 4_000, "the spend is never trimmed");
    assert_eq!(spend.overdraft, 3_000);
    let usage = Usage::report(
        &UsageToken::mint(&seal),
        vec![UsageLine {
            class: MeterClassId::new("nano_units"),
            quantity: 4_000,
            source: QuantitySource::Count,
            estimated: false,
        }],
    )
    .expect("one line");
    // Money on both sides again: the spend ran 3_000 past a 1_000 reservation with no slice to
    // draw on, so the hold's own counter raises the flag and the settlement agrees with it.
    let posted = busbar_caps::Posted::settle(hold, 4_000, &usage, &LedgerToken::mint(&seal));
    assert!(posted.flags().contains(PostingFlags::OVERDRAFT));

    let settled = settle(
        &mut durability,
        &PrincipalId::new("vk_mcp"),
        Clocks {
            wall: 1_700_000_000,
            mono: Mono::new().tick(),
        },
        &DurabilityToken::mint(&seal),
        posted,
    )
    .expect("the journal takes both records");
    assert_eq!(
        settled
            .settlement
            .overdraft
            .as_ref()
            .expect("the ledger noted the carry")
            .amount,
        3_000
    );
    let record = settled.overdraft.as_ref().expect("and journalled it");
    assert_eq!(record.reserved, 0);
    assert_eq!(record.settled, 0);
    assert_eq!(record.overdraft, 3_000);
    let replayed = durability
        .journal
        .replay()
        .expect("reads back")
        .expect("verifies");
    assert_eq!(replayed.len(), 2, "the posting, then the carry");
}

// ─────────────────────────────────────────────────────────────────────────
// THE LEG — an MCP request, answered through the loop every plane is answered by
// ─────────────────────────────────────────────────────────────────────────

use busbar_caps::{Canary, Hold, HoldCell};
use busbar_kernel::slice::{ConcurrencyGauge, LeaseCell};
use busbar_kernel::teller::{run_unit, Ended as LoopEnd, Kernel, Run};

/// One request, built the way the conformance rig's own request builder builds one.
///
/// The rig is the oracle for this plane until the recorder can drive it, so the fixture is the
/// rig's shape rather than a convenient one: the metadata block is always sent, and a cell that
/// omitted it would be exercising a body no run ever produces.
fn rig_request(id: &str, method: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":{id},"method":"{method}","params":{{"_meta":{{"{}":"2026-07-28"}}}}}}"#,
        busbar_plane_mcp::facts::META_PROTOCOL_VERSION
    )
}

/// The scope table a deployment that permits this plane's classes declares.
fn permissive_scopes() -> crate::root::policy::ScopePolicy {
    let mut policy = crate::root::policy::ScopePolicy::new();
    for (op, scope) in required_scopes() {
        policy = policy.declaring(claim_key(), op, scope);
    }
    policy
}

/// The one catalogue leg every listing of this plane reaches.
fn catalogue_leg() -> Leg {
    Leg {
        destination: DestinationFacts::PlaneRecord {
            schema: records::SCHEMA_CATALOGUE,
            op: records::OP_GET,
        },
    }
}

/// Read one rig-shaped request into the owned draft the loop's steps are answered from.
///
/// This is the production read: [`McpDraft::read`] drives `read_ingress`, which drives the plane's
/// own ingress decoder. Nothing in this cell parses this protocol.
fn draft_for(method: &str, id: &str, legs: &[Leg]) -> McpDraft {
    use busbar_contract::bounded::Labels;
    use busbar_contract::unit::{Clock, Ctx};
    use busbar_contract::wire::FrameCursor;

    let body = rig_request(id, method);
    let frames = one_frame(&body);
    let arena = CellArena;
    let config = CellConfig;
    let transport = CellTransport;
    let labels = Labels::new();
    let ctx = Ctx::new(
        Clock {
            unix_secs: 1_700_000_000,
            monotonic_nanos: 0,
        },
        &config,
        None,
        &transport,
        &labels,
        &arena,
    );
    let mut cursor = FrameCursor::new(&frames);
    let record = ArrivalRecord {
        source: "198.51.100.7:52344".to_string(),
        port: 8443,
        alpn: Some("h2".to_string()),
        sni: Some("mcp.example".to_string()),
        peer_cert: None,
        transport_chain: vec!["tcp", "tls", claims::TRANSPORT_HTTP],
    };
    McpDraft::read(
        &McpPlane::EMPTY,
        &mut cursor,
        &ctx,
        Wire {
            arrival: &record,
            claim_transport: claims::TRANSPORT_HTTP,
            // The document surface declares a scheme; the chain these cells run is the empty one,
            // which is the open front door, so the unit authenticates as the anonymous principal.
            under_scheme: false,
            from_session: false,
            credential: None,
            destination: legs
                .first()
                .map_or(catalogue_leg().destination, |l| l.destination),
            legs,
            record_keys: &[""],
            record_body: &[],
            request_bytes: body.len() as u64,
        },
    )
}

/// Everything one MCP unit is driven against, as a node assembles it once at boot.
struct LegNode {
    /// The registrations this node's operator configured.
    ///
    /// `EMPTY` is the default and it is a REFUSING node: the scope step reads "no resource" off a
    /// plane with nothing registered and refuses at approve, which is the honest answer for a
    /// deployment that registered nothing. A cell that needs the loop to reach the exit with an
    /// ANSWER hands in a plane with a server on it.
    plane: McpPlane,
    auth: Auth,
    auth_bindings: crate::root::kernel::auth_bindings::AuthBindings,
    trust: Trust,
    pools: Pools,
    kinds: Catalogue<'static>,
    breaker: AlwaysReady,
    door: Door<InMemoryCells>,
    pricer: Pricer,
    chain: BucketChain,
    records: Records,
    meter_policy: crate::root::policy::MeterPolicyHandle,
    scope_policy: crate::root::policy::ScopePolicy,
    durability: Mutex<crate::root::durability::Durability>,
    origin: busbar_caps::Origin,
}

/// A breaker with every position open.
struct AlwaysReady;

impl BreakerView for AlwaysReady {
    fn ready(&self, _pool: &str, _lane: usize, _now: u64) -> bool {
        true
    }
    fn try_admit(
        &self,
        _pool: &str,
        _lane: usize,
        _now: u64,
    ) -> Result<(), busbar_unit_trust::Unavailable> {
        Ok(())
    }
}

/// The one registration a node that answers has.
///
/// The name is the pool key the bindings are built against, because the breaker, the pool view and
/// the scope resource are all keyed on it and a node whose registration and whose pool disagreed
/// would be judging one server and charging another.
static ONE_SERVER: &[Server] = &[Server {
    id: "fs",
    lane: LaneId::new("fs-lane"),
    host: "mcp.example",
    transport: claims::TRANSPORT_HTTP,
}];

impl LegNode {
    fn new(store: &StoreAdapter) -> Self {
        Self::registering(store, McpPlane::EMPTY)
    }

    /// The same node, over a plane that has the operator's registrations on it.
    fn registering(store: &StoreAdapter, plane: McpPlane) -> Self {
        LegNode {
            plane,
            auth: Auth::new(busbar_unit_auth::AuthChain::new(Vec::new(), false)),
            auth_bindings: crate::root::kernel::auth_bindings::AuthBindings::without_directory(),
            trust: Trust,
            pools: Pools::new(plane, None, true, false),
            kinds: Catalogue::new(plane, records::SCHEMA_CATALOGUE, records::OP_GET, seam()),
            breaker: AlwaysReady,
            door: Door::new(InMemoryCells::new()),
            pricer: Pricer::flat(0),
            // A deployment that configured no group: every caller is attributed and none is capped.
            chain: busbar_unit_admission::GroupTable::default()
                .chain_for("vk_mcp", None)
                .expect("a caller bound to no group always resolves"),
            records: Records::new(store),
            meter_policy: crate::root::policy::build(
                &crate::root::policy::MeterPolicyConfig::default(),
            ),
            scope_policy: permissive_scopes(),
            durability: Mutex::new(memory_durability()),
            origin: Kernel::new().origin(busbar_caps::OriginKind::Client),
        }
    }

    fn bindings(&self) -> McpBindings<'_> {
        McpBindings {
            plane: self.plane,
            auth: &self.auth,
            auth_bindings: &self.auth_bindings,
            trust: &self.trust,
            views: Views {
                pools: &self.pools,
                facts: &self.kinds,
                breaker: &self.breaker,
            },
            door: &self.door,
            pricer: &self.pricer,
            chain: Some(&self.chain),
            prices: ClassPrices::default(),
            fee_nanos: 0,
            records: &self.records,
            meter_policy: &self.meter_policy,
            scope_policy: &self.scope_policy,
            durability: &self.durability,
            pool: "fs",
            at: Clocks {
                wall: 1_700_000_000,
                mono: 7,
            },
            origin: self.origin,
            expires_at: 1_700_000_060,
        }
    }
}

/// Drive one unit through the REAL loop.
fn run_leg(kernel: &Kernel, unit: &McpUnits<'_>) -> LoopEnd {
    let cell = HoldCell::new(Hold::open(
        &kernel.admit_token(),
        PrincipalId::new("vk_mcp"),
        0,
    ));
    let gauge = ConcurrencyGauge::new();
    let canary = Canary::new();
    let leases = LeaseCell::new();
    let meter = AccrualMeter::new();
    run_unit(
        kernel,
        unit,
        &UnitCtx {
            key: busbar_caps::UnitKey::new(1),
            origin: busbar_caps::OriginKind::Client,
            session: None,
            generation: busbar_kernel::registry::Generation::FIRST,
            admin_listener: false,
            kernel_verb_only: false,
        },
        Run {
            cell: &cell,
            parent: None,
            leases: &leases,
            gauge: &gauge,
            canary: &canary,
            meter: &meter,
        },
    )
}

/// **AN MCP REQUEST ENTERS THE TELLER LOOP.**
///
/// The whole of what "the MCP plane is on the kernel" means, stated as a run rather than as a
/// sentence: a request the rig's own builder would send is read by the plane, and then the ten
/// steps are answered by the node's units — authenticate, verify, approve, admit, route, meter,
/// audit — in the loop's order and by nothing else. `Settled` is the exit path having taken the
/// hold, and there is no second taker in this run.
///
/// The head is the second assertion and it is not a detail: it is recorded at the AUDIT step,
/// which is the step that sees it. Before this plane entered the loop there was no step that saw
/// one at all.
#[test]
fn an_mcp_request_is_answered_through_the_loop_by_the_units() {
    let store = StoreAdapter::native(Arc::new(SilentStore));
    let node = LegNode::new(&store);
    let kernel = Kernel::new();
    let legs = [catalogue_leg()];
    let unit = McpUnits::new(
        node.bindings(),
        draft_for("tools/list", "1", &legs),
        Grants::default(),
    );

    assert_eq!(
        unit.draft().op,
        Ok(ops::OP_TOOLS_LIST),
        "the plane's own method table named the class"
    );

    let ended = run_leg(&kernel, &unit);
    assert!(
        matches!(ended, LoopEnd::Settled { .. }),
        "the unit reached the exit and settled exactly once: {ended:?}"
    );
    assert!(
        unit.head().is_some(),
        "the audit step is the step that sees the head, and it recorded one"
    );
}

/// **THE BYTES ARE THE RIG'S, BYTE FOR BYTE.**
///
/// A caller the deployment's policy has not authorized is refused by the SCOPE UNIT at the approve
/// step of the real loop, and the refusal a caller reads is that refusal rendered by the PLANE —
/// never an envelope this file writes out by hand. The literal below is the conformance rig's own
/// expected error envelope for a policy refusal on this protocol: member order, the always-written
/// identifier echoed off the caller's own request, the code table's own number and the dialect's
/// own words. A single byte's difference here is a wire change, and a wire change is a release
/// that breaks every peer that already works.
#[test]
fn a_refused_mcp_request_is_answered_in_the_rigs_own_bytes() {
    use busbar_contract::bounded::Labels;
    use busbar_contract::plane::Plane as _;
    use busbar_contract::unit::{Clock, Ctx};
    use busbar_contract::wire::FrameCursor;

    let store = StoreAdapter::native(Arc::new(SilentStore));
    let mut node = LegNode::new(&store);
    // Silence is a refusal: a deployment whose policy says nothing about this plane's classes has
    // authorized none of them.
    node.scope_policy = crate::root::policy::ScopePolicy::new();
    let kernel = Kernel::new();
    let legs = [catalogue_leg()];
    let unit = McpUnits::new(
        node.bindings(),
        draft_for("tools/call", "8", &legs),
        Grants::default(),
    );

    let ended = run_leg(&kernel, &unit);
    let refusal = refusal_of(&ended).expect("the loop refused this unit");
    assert_eq!(
        refusal.step,
        busbar_contract::unit::Step::Approve,
        "the scope unit is what said no, and the envelope names the step it said it at"
    );
    assert_eq!(
        refusal.reason,
        busbar_contract::unit::RefusalReason::ScopeMissing
    );

    // And the plane renders it, over the caller's own request, into the caller's own dialect.
    let body = rig_request("8", "tools/call");
    let frames = one_frame(&body);
    let arena = CellArena;
    let config = CellConfig;
    let transport = CellTransport;
    let labels = Labels::new();
    let ctx = Ctx::new(
        Clock {
            unix_secs: 1_700_000_000,
            monotonic_nanos: 0,
        },
        &config,
        None,
        &transport,
        &labels,
        &arena,
    );
    let mut cursor = FrameCursor::new(&frames);
    let plane = McpPlane::EMPTY;
    let busbar_contract::plane::Ingress::OneShot(draft) = plane
        .decode_ingress(&mut cursor, None, &ctx)
        .expect("the rig's own request decodes")
    else {
        panic!("a call is one shot");
    };
    let out = plane
        .encode_refusal(&refusal, Some(&draft), None, &ctx)
        .expect("a refusal renders");

    assert_eq!(
        core::str::from_utf8(out.as_slice()).expect("the dialect is text"),
        r#"{"error":{"code":-32000,"message":"the caller may not perform this operation"},"id":8,"jsonrpc":"2.0"}"#,
        "the refusal a caller reads is the rig's own envelope, byte for byte"
    );
    // And the number in those bytes is the code table's own, never a literal that drifted from it.
    assert_eq!(busbar_plane_mcp::jsonrpc::CODE_REFUSED, -32000);
}

/// **A SETTLED UNIT'S BYTES ARE ITS ANSWER, AND THE PLANE WRITES THEM.**
///
/// The refusal half of this pair already ran: a unit the scope unit says no to is rendered by
/// [`McpPlane::encode_refusal`] into the rig's own error envelope. The other half was the open
/// question, and it is the one that decides whether the mounted leg can answer anything at all —
/// [`refusal_of`] returns `None` for a unit that SETTLED, on the stated ground that a settled
/// unit's bytes are its answer and the PLANE writes them from the unit's own arena. Nothing in the
/// tree did that. This cell is that write, end to end, for the smallest of the thirteen
/// client-sent classes.
///
/// THE THREE THINGS IT PINS, in the order they have to hold:
///
/// 1. **The loop settles it.** `completion/complete` goes through the ten steps against the node's
///    own units and comes out `Settled`, and `refusal_of` answers `None` — so this is the branch
///    with no refusal envelope to render, which is exactly the branch that had no byte source.
/// 2. **The face carries the document.** The bare result comes off
///    [`busbar_plane_mcp::ops::settled_document`], the plane's own vocabulary table, and not out of
///    this file. A cell that wrote the completion set by hand would prove that this file can spell
///    a document, which is not the property in question.
/// 3. **The plane frames it, into the legacy path's bytes.** The framing is
///    `Plane::encode_response`'s already-existing second branch — the one whose comment says an
///    answer this node composed itself arrives as a bare result and is wrapped here, with the
///    identifier the decode step recorded. The literal below is what `busbar-mcp`'s
///    `method::completion_complete` puts on the wire today, and `busbar-mcp`'s own cell asserts
///    that from the other side of the wall, so the two are pinned to one string without this crate
///    naming that one.
#[test]
fn a_settled_mcp_unit_is_answered_in_the_plane_s_own_bytes() {
    use busbar_contract::bounded::{Facts, Ir, Labels};
    use busbar_contract::plane::{Plane as _, Response};
    use busbar_contract::unit::FinishClass;
    use busbar_contract::unit::{Clock, Ctx};
    use busbar_contract::wire::FrameCursor;

    let store = StoreAdapter::native(Arc::new(SilentStore));
    // A node with a registration on it: the scope step judges a RESOURCE, and a plane with nothing
    // registered names none, which is a refusal before the caller's grants are even read.
    let node = LegNode::registering(&store, McpPlane::new(ONE_SERVER));
    let kernel = Kernel::new();
    let legs = [catalogue_leg()];
    let unit = McpUnits::new(
        node.bindings(),
        draft_for("completion/complete", "9", &legs),
        // The caller holds the read scope this class requires. `Grants::default` holds NOTHING, and
        // a caller holding nothing is refused at approve before any answer is composed.
        Grants::of(busbar_unit_scope::Scope::ReadOnly),
    );
    assert_eq!(
        unit.draft().op,
        Ok(ops::OP_COMPLETION),
        "the plane's own method table named the class"
    );

    let ended = run_leg(&kernel, &unit);
    assert!(
        matches!(ended, LoopEnd::Settled { .. }),
        "the unit reached the exit and settled exactly once: {ended:?}"
    );
    assert!(
        refusal_of(&ended).is_none(),
        "a settled unit is owed an ANSWER, not a refusal envelope: {:?}",
        refusal_of(&ended)
    );

    // The document is the FACE's, read off the class the plane itself named.
    let document = ops::settled_document(ops::OP_COMPLETION)
        .expect("the plane's face carries this class's settled document");

    // And the plane frames it, over the caller's own identifier, into the caller's own dialect.
    let body = rig_request("9", "completion/complete");
    let frames = one_frame(&body);
    let arena = CellArena;
    let config = CellConfig;
    let transport = CellTransport;
    let labels = Labels::new();
    let ctx = Ctx::new(
        Clock {
            unix_secs: 1_700_000_000,
            monotonic_nanos: 0,
        },
        &config,
        None,
        &transport,
        &labels,
        &arena,
    );
    let mut cursor = FrameCursor::new(&frames);
    let plane = McpPlane::EMPTY;
    let busbar_contract::plane::Ingress::OneShot(draft) = plane
        .decode_ingress(&mut cursor, None, &ctx)
        .expect("the rig's own request decodes")
    else {
        panic!("a completion is one shot");
    };
    // The identifier is the DECODE STEP'S, carried on the draft the plane built — never one this
    // cell echoes back out of the request it wrote.
    let mut facts = Facts::new();
    let id = draft
        .facts
        .get(busbar_plane_mcp::facts::FACT_RPC_ID)
        .expect("the decode step recorded the caller's identifier");
    facts
        .set(busbar_plane_mcp::facts::FACT_RPC_ID, id)
        .expect("one fact fits");
    let response = Response {
        ir: Ir::new(document, &[]),
        finish: FinishClass::Complete,
        facts,
    };
    let out = plane
        .encode_response(&response, None, &ctx)
        .expect("a settled answer renders");

    assert_eq!(
        core::str::from_utf8(out.as_slice()).expect("the dialect is text"),
        r#"{"id":9,"jsonrpc":"2.0","result":{"completion":{"hasMore":false,"total":0,"values":[]},"resultType":"complete"}}"#,
        "the answer a caller reads off the MOUNTED leg is the serve path's own envelope, byte for byte"
    );
}
