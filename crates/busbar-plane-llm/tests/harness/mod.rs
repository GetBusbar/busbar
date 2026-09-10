//! The smallest thing that can call a plane.
//!
//! The loop hands a plane an arena, a clock, a configuration view, a transport view and a label
//! set, and it hands the kernel-built values — a unit, a verified destination — through a seal. All
//! of that is here, at the minimum size that lets the plane be called for real. Nothing here is
//! shipped; it exists so the tests exercise the same entry points the kernel does rather than a
//! private back door.
//!
//! Each test binary includes this module and uses the part of it that it needs, so the unused-item
//! warning is turned off here rather than in each of them: an item unused by one test file is used
//! by another, and splitting the harness per file would mean maintaining several harnesses.

#![allow(dead_code)]

use busbar_contract::bounded::SlabBytes;
use busbar_contract::bounded::{Arena, ArenaBudget, ArenaBytes, Facts, Ir, Labels, Span};
use busbar_contract::dest::{DestinationFacts, VerifiedDestination};
use busbar_contract::grammar::{ArrivalLocation, Location, Selector};
use busbar_contract::ids::{LaneId, OpClassId, StreamId};
use busbar_contract::plugin::KernelSeal;
use busbar_contract::unit::{Clock, ConfigView, Ctx, Origin, TransportView, Unit};
use busbar_contract::wire::{Direction, Frame, FrameMeta};
use busbar_plane_llm::claims::{claim, LadderClaim};
use busbar_plane_llm::dialect::Dialect;
use busbar_plane_llm::registry::{DialectEntry, DialectRegistry};
use busbar_plane_llm::{LlmPlane, Upstream};
use std::sync::Arc;

/// An arena that never reuses a byte.
///
/// The shipped arena is a bump allocator the kernel resets per unit; a test does not need the reset
/// and does need the borrow to outlive the call, so this one hands out memory it never reclaims.
/// A test process is short.
#[derive(Debug, Default)]
pub struct LeakArena;

impl Arena for LeakArena {
    fn alloc_bytes<'a>(&'a self, src: &[u8]) -> Result<ArenaBytes<'a>, ArenaBudget> {
        Ok(ArenaBytes::new(Box::leak(src.to_vec().into_boxed_slice())))
    }

    fn alloc_str<'a>(&'a self, src: &str) -> Result<&'a str, ArenaBudget> {
        Ok(Box::leak(src.to_string().into_boxed_str()))
    }

    fn alloc_spans<'a>(
        &'a self,
        src: &[(&'a str, Span)],
    ) -> Result<&'a [(&'a str, Span)], ArenaBudget> {
        Ok(Box::leak(src.to_vec().into_boxed_slice()))
    }

    fn remaining(&self) -> usize {
        usize::MAX
    }
}

/// A configuration block with nothing in it, so every default is the declared one.
#[derive(Debug, Default)]
pub struct EmptyConfig;

impl ConfigView for EmptyConfig {
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

/// A transport stack that publishes a request target and a header set as facts.
#[derive(Debug)]
pub struct HttpStack {
    facts: Vec<(String, String)>,
}

impl HttpStack {
    /// A stack that saw this request target and these headers.
    #[must_use]
    pub fn new(path: &str, headers: &[(&str, &str)]) -> Self {
        let mut facts = vec![("path".to_string(), path.to_string())];
        for (name, value) in headers {
            facts.push(((*name).to_string(), (*value).to_string()));
        }
        Self { facts }
    }
}

impl TransportView for HttpStack {
    fn key(&self) -> &'static str {
        "http"
    }
    fn chain(&self) -> &[&'static str] {
        &["tcp", "tls", "http"]
    }
    fn fact(&self, key: &str) -> Option<&str> {
        self.facts
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

/// The marker the kernel-built constructors take.
///
/// A plugin cannot name the crate that provides the real one; a test is not a plugin, and it needs
/// a unit and a verified destination to hand the plane. The design says as much: what stops a
/// plugin fabricating one is the manifest allow-list, not the type system.
#[derive(Debug)]
pub struct TestSeal;

impl KernelSeal for TestSeal {
    fn seal_origin(&self) -> &'static str {
        "busbar-plane-llm tests"
    }
}

/// Build a context over the pieces above.
#[must_use]
pub fn ctx<'u>(
    arena: &'u LeakArena,
    config: &'u EmptyConfig,
    transport: &'u HttpStack,
    labels: &'u Labels<'u>,
) -> Ctx<'u> {
    ctx_at(arena, config, transport, labels, 1_752_000_000)
}

/// The same context, with the clock reading chosen by the caller.
///
/// A test that asks whether an answer follows the values it was handed needs two readings to hand
/// over; every other test wants the one fixed reading, which is what `ctx` supplies.
#[must_use]
pub fn ctx_at<'u>(
    arena: &'u LeakArena,
    config: &'u EmptyConfig,
    transport: &'u HttpStack,
    labels: &'u Labels<'u>,
    unix_secs: u64,
) -> Ctx<'u> {
    Ctx::new(
        Clock {
            unix_secs,
            monotonic_nanos: 0,
        },
        config,
        None,
        transport,
        labels,
        arena,
    )
}

/// One inbound frame carrying a whole body.
#[must_use]
pub fn frame(bytes: &[u8]) -> Frame {
    Frame {
        direction: Direction::Inbound,
        stream: StreamId(0),
        bytes: SlabBytes::new(Arc::from(bytes.to_vec().into_boxed_slice())),
        meta: FrameMeta::default(),
    }
}

/// A unit built the way the kernel builds one, over a decoded body.
#[must_use]
pub fn unit<'u>(op: OpClassId, body: Ir<'u>, facts: Facts<'u>) -> Unit<'u> {
    Unit::new(
        &TestSeal,
        busbar_contract::UnitKey::new(1),
        Origin::Client,
        None,
        Some(StreamId(0)),
        Direction::Inbound,
        None,
        op,
        body,
        facts,
        None,
    )
}

/// A destination sealed the way the trust unit seals one.
#[must_use]
pub fn destination(host: &'static str, lane: LaneId) -> VerifiedDestination {
    VerifiedDestination::seal(
        &TestSeal,
        DestinationFacts::Upstream {
            transport: "http",
            address: busbar_contract::UpstreamAddress::socket(host),
            lane,
        },
        "http",
        None,
    )
}

/// The request target that names each dialect on the detection ladder.
#[must_use]
pub fn path_for(dialect: &str) -> &'static str {
    match dialect {
        "anthropic" => "/v1/messages",
        "openai" => "/v1/chat/completions",
        "gemini" => "/v1beta/models/gemini-2.0-flash:generateContent",
        "bedrock" => "/model/claude/converse",
        "cohere" => "/v2/chat",
        "responses" => "/v1/responses",
        other => panic!("no request target is declared for the dialect {other}"),
    }
}

// ------------------------------------------------------------------------------------------------
// THE CARVED-OUT DIALECTS, AS FIXTURES
// ------------------------------------------------------------------------------------------------

/// The `openai` row and rungs, AS A TEST FIXTURE, because the real ones live in another crate.
///
/// WHY THIS IS A COPY AND NOT AN IMPORT. `busbar-plane-llm-openai` depends on this crate; this crate
/// may not depend on it back, in a test target or anywhere else — `kind-isolation:deps` refuses a
/// plane naming a dialect, and that refusal is the whole point of the split. So the plane's own
/// battery, which needs SOME registered dialect to exercise the registered path with, registers a
/// copy of the real one.
///
/// WHY A COPY IS SAFE HERE, stated rather than assumed. This fixture is never the authority on what
/// `openai` is. It is a stand-in that lets the plane's cases be about the PLANE — that a registered
/// row resolves, that a registered rung is walked at its number, that the codec bodies read the row
/// they are handed. The authority is the dialect crate's own battery, which drives the REAL `ENTRY`
/// through these same codec bodies and reproduces the frozen golden cells byte for byte. A copy
/// that drifted from the real row would not make a false claim about `openai` here; it would make
/// this crate's fixture stop matching the frozen bytes those cases also read, which is how the
/// existing request-body copies in `golden_parity.rs` have always been checked.
pub const OPENAI: Dialect = Dialect {
    name: "openai",
    model_location: Location::Arrival(ArrivalLocation::FirstFrameJsonPointer("/model")),
    max_response_pointers: &["/max_tokens", "/max_completion_tokens"],
    input_pointer: "/messages",
    tokens_in_pointer: "/usage/prompt_tokens",
    tokens_out_pointer: "/usage/completion_tokens",
    cache_read_pointer: Some("/usage/prompt_tokens_details/cached_tokens"),
    cache_write_pointer: None,
    scheme_alt: "bearer",
    egress_scheme: "bearer",
    requires_max_response: false,
};

/// The fixture's rungs, at the numbers the real crate declares them.
///
/// Seven and fourteen, because a rung is a statement about a CONTEST and a fixture registered at
/// the wrong number would have the plane's cases winning and losing contests the shipped tree does
/// not.
pub const OPENAI_LADDER: &[LadderClaim] = &[
    LadderClaim {
        rung: 7,
        dialect: "openai",
        claim: claim(Selector::PathSuffix("/v1/chat/completions")),
    },
    LadderClaim {
        rung: 14,
        dialect: "openai",
        claim: claim(Selector::PathSuffix("/v1/embeddings")),
    },
    LadderClaim {
        rung: 14,
        dialect: "openai",
        claim: claim(Selector::PathSuffix("/v1/moderations")),
    },
    LadderClaim {
        rung: 14,
        dialect: "openai",
        claim: claim(Selector::PathContains("/v1/images/")),
    },
    LadderClaim {
        rung: 14,
        dialect: "openai",
        claim: claim(Selector::PathSuffix("/v1/audio/translations")),
    },
];

/// The `responses` row and rung, AS A TEST FIXTURE, for the same reason the row above is one.
///
/// It is a SECOND fixture and not a variant of the first, because the two dialects differ in every
/// field a row has to offer: the conversation is at `/input` rather than `/messages`, the client's
/// ceiling is one member name rather than two, and the written-to-cache quantity is REPORTED here
/// and not reported there. A fixture that shared a row with its sibling would be this file making
/// the mistake the split exists to prevent.
pub const RESPONSES: Dialect = Dialect {
    name: "responses",
    model_location: Location::Arrival(ArrivalLocation::FirstFrameJsonPointer("/model")),
    max_response_pointers: &["/max_output_tokens"],
    input_pointer: "/input",
    tokens_in_pointer: "/usage/input_tokens",
    tokens_out_pointer: "/usage/output_tokens",
    cache_read_pointer: Some("/usage/input_tokens_details/cached_tokens"),
    cache_write_pointer: Some("/usage/input_tokens_details/cache_write_tokens"),
    scheme_alt: "bearer",
    egress_scheme: "bearer",
    requires_max_response: false,
};

/// The fixture's rung, at the number the real crate declares it.
///
/// Ten, because a rung is a statement about a CONTEST and a fixture registered at the wrong number
/// would have the plane's cases winning and losing contests the shipped tree does not.
pub const RESPONSES_LADDER: &[LadderClaim] = &[LadderClaim {
    rung: 10,
    dialect: "responses",
    claim: claim(Selector::PathSuffix("/v1/responses")),
}];

/// Every carved-out dialect this crate's battery registers, as a boot would.
///
/// The order is the order the root's own table declares them in, because registration order is what
/// breaks a tie between two dialects that declare the SAME rung — and a battery whose fixtures were
/// ordered differently from the boot would be answering a contest the shipped tree answers the
/// other way.
pub const REGISTERED: &[DialectEntry] = &[
    DialectEntry {
        locations: OPENAI,
        ladder: OPENAI_LADDER,
    },
    DialectEntry {
        locations: RESPONSES,
        ladder: RESPONSES_LADDER,
    },
];

/// A plane configured the way a boot configures one: upstreams, and the dialects that registered.
///
/// EVERY CASE IN THIS BATTERY BUILDS ITS PLANE HERE, so no case can accidentally be about a plane
/// with nothing registered. A case that wants the bare plane says `LlmPlane::new` itself and says
/// why.
#[must_use]
pub fn plane(upstreams: &'static [Upstream]) -> LlmPlane {
    LlmPlane::new(upstreams).with_dialects(DialectRegistry::sealed(REGISTERED))
}
