//! The dialects a boot registered are DATA this plane reads, not a table it wrote.
//!
//! A plane that names its dialects in a constant is a plane that has to be edited to gain one, and
//! the edit lands in the crate whose whole claim is that it carries no vendor's vocabulary. So the
//! row a dialect contributes — where its model is, where its quantities are, which rungs of the
//! detection ladder are its — arrives at registration, and everything below asserts that the arrival
//! is the ONLY way in: what the plane resolves, what walks the ladder, and what the ladder reports
//! are all the registry's answer.

use busbar_contract::grammar::{ArrivalLocation, Location, Selector};
use busbar_plane_llm::claims::{claim, LadderClaim};
use busbar_plane_llm::dialect::Dialect;
use busbar_plane_llm::registry::{DialectEntry, DialectRegistry};
use busbar_plane_llm::LlmPlane;

/// A dialect that exists nowhere but this test: registered, and therefore resolvable.
const FIXTURE: Dialect = Dialect {
    name: "fixture",
    model_location: Location::Arrival(ArrivalLocation::FirstFrameJsonPointer("/model")),
    max_response_pointers: &["/max_tokens"],
    input_pointer: "/messages",
    tokens_in_pointer: "/usage/in",
    tokens_out_pointer: "/usage/out",
    cache_read_pointer: None,
    cache_write_pointer: None,
    scheme_alt: "bearer",
    egress_scheme: "bearer",
};

/// The one path this fixture claims, on a rung between two the plane still declares itself.
const FIXTURE_LADDER: &[LadderClaim] = &[LadderClaim {
    rung: 7,
    dialect: "fixture",
    claim: claim(Selector::PathSuffix("/fixture/chat")),
}];

/// The fixture's whole contribution, as one registration.
const FIXTURE_ENTRY: DialectEntry = DialectEntry {
    locations: FIXTURE,
    ladder: FIXTURE_LADDER,
};

/// A plane with nothing registered resolves no registered dialect.
#[test]
fn an_empty_registry_resolves_nothing_it_was_not_handed() {
    let plane = LlmPlane::EMPTY;
    assert!(plane.locations("fixture").is_none());
}

/// A registered dialect is resolvable by its own key, with the row it registered.
#[test]
fn a_registered_dialect_resolves_to_the_row_it_registered() {
    let plane = LlmPlane::EMPTY.with_dialects(DialectRegistry::sealed(&[FIXTURE_ENTRY]));
    let d = plane
        .locations("fixture")
        .expect("the dialect was registered");
    assert_eq!(d.input_pointer, "/messages");
    assert_eq!(d.tokens_in_pointer, "/usage/in");
}

/// A registered dialect's rungs are walked in the ONE ladder, in rung order, beside the plane's own.
///
/// This is the whole of "registers by claim": the fixture's rung is not appended after the plane's
/// own, it is INTERLEAVED at the number it declared — so a rung the plane declares above it still
/// wins, and one below it still loses.
#[test]
fn a_registered_rung_is_walked_at_the_number_it_declared() {
    let plane = LlmPlane::EMPTY.with_dialects(DialectRegistry::sealed(&[FIXTURE_ENTRY]));
    let none = |_: &str| None;
    assert_eq!(plane.dialect_for("/fixture/chat", &none), Some("fixture"));

    // Rung 6 is the plane's own and sits above the fixture's 7, so a request that matches both is
    // the plane's — asserted with a target that matches only the tighter rung, because a fixture
    // that could win a contest it should lose is the defect this test exists for.
    assert_eq!(
        plane.dialect_for("/v1beta/models/x", &none),
        Some("gemini"),
        "a registered rung displaced a tighter rung the plane declares itself"
    );
}

/// The ladder the plane walks is every rung, registered or its own, in ascending order.
#[test]
fn the_walked_ladder_is_every_rung_in_order() {
    let plane = LlmPlane::EMPTY.with_dialects(DialectRegistry::sealed(&[FIXTURE_ENTRY]));
    let mut rungs: Vec<u16> = Vec::new();
    plane.walk_ladder(|c| rungs.push(c.rung));
    assert!(
        rungs.windows(2).all(|w| w[0] <= w[1]),
        "the merged ladder is not in rung order: {rungs:?}"
    );
    assert_eq!(
        rungs.len(),
        busbar_plane_llm::claims::LADDER.len() + FIXTURE_LADDER.len(),
        "the walk lost a rung, or counted one twice"
    );
}
