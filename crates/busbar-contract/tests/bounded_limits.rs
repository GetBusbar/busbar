//! The bounded types hold their bounds, and the constants are the design's numbers.
//!
//! Two things are asserted here. First, that each pinned number is what the crate-graph section of
//! the design pins it at — a constant that drifts is a bound nobody is enforcing. Second, that the
//! types built on those numbers actually refuse at them: a ceiling that is only in a comment is a
//! ceiling the first busy afternoon removes.

use busbar_contract::bounded::{
    ArenaBytes, BoundedVec, FactValue, Facts, Labels, SlabBytes, ARENA_BYTES, MAX_CURSOR_BYTES,
    MAX_KEYS, MAX_LEGS, MAX_LEG_REPLIES, MAX_NEEDMORE_FRAMES, MAX_RECORD_BYTES,
    MAX_SESSION_UPSTREAMS, MAX_STEPS, MAX_USAGE_LINES,
};
use busbar_contract::kinds::RecordBytes;
use busbar_contract::unit::Step;

/// Every pinned number is the number the design pins.
#[test]
fn the_constants_are_the_designs_numbers() {
    assert_eq!(MAX_KEYS, 32);
    assert_eq!(MAX_STEPS, 16);
    assert_eq!(MAX_USAGE_LINES, 16);
    assert_eq!(MAX_RECORD_BYTES, 512);
    assert_eq!(MAX_CURSOR_BYTES, 64 * 1024);
    assert_eq!(MAX_NEEDMORE_FRAMES, 256);
    assert_eq!(MAX_SESSION_UPSTREAMS, 8);
    assert_eq!(MAX_LEGS, 8);
    assert_eq!(MAX_LEG_REPLIES, 2);
    assert_eq!(ARENA_BYTES, 4 * 1024);
}

/// The ten steps of the loop fit inside the step ceiling, with room for the amendment rows.
#[test]
fn the_loop_fits_inside_the_step_ceiling() {
    assert_eq!(Step::ALL.len(), 10);
    assert!(Step::ALL.len() <= MAX_STEPS);
}

/// The kernel seals the draft's facts onto the unit, and a later step reads them back unchanged.
///
/// This is what stops a step after decode re-deriving from the same bytes what decode already
/// determined. The map is the draft's, key for key: nothing is dropped and nothing is invented.
#[test]
fn a_unit_carries_the_drafts_facts() {
    struct Seal;
    impl busbar_contract::plugin::KernelSeal for Seal {
        fn seal_origin(&self) -> &'static str {
            "busbar-contract::tests"
        }
    }

    let mut facts = Facts::new();
    facts.set("verb", FactValue::Str("get_status")).expect("set");
    facts.set("stream", FactValue::Bool(true)).expect("set");

    let unit = busbar_contract::unit::Unit::new(
        &Seal,
        busbar_contract::UnitKey::new(1),
        busbar_contract::unit::Origin::Client,
        None,
        None,
        busbar_contract::wire::Direction::Inbound,
        None,
        busbar_contract::ids::OpClassId::new("op"),
        busbar_contract::bounded::Ir::new(b"{}", &[]),
        facts,
        None,
    );

    assert_eq!(unit.draft_facts().len(), 2);
    assert_eq!(
        unit.draft_facts().get("verb"),
        Some(FactValue::Str("get_status"))
    );
    assert_eq!(unit.draft_facts().get("stream"), Some(FactValue::Bool(true)));
    assert_eq!(unit.draft_facts().get("absent"), None);
}

/// A fact map refuses the thirty-third distinct key and keeps the thirty-two it has.
#[test]
fn a_fact_map_refuses_past_its_key_ceiling() {
    // The keys have to outlive the map, which is exactly the arena's job in production.
    let keys: Vec<String> = (0..=MAX_KEYS).map(|i| format!("key-{i}")).collect();
    let mut facts = Facts::new();
    for key in keys.iter().take(MAX_KEYS) {
        facts
            .set(key.as_str(), FactValue::Int(1))
            .expect("a key inside the ceiling is accepted");
    }
    assert_eq!(facts.len(), MAX_KEYS);

    let refused = facts.set(keys[MAX_KEYS].as_str(), FactValue::Int(1));
    assert!(refused.is_err(), "the map accepted a key past its ceiling");
    assert_eq!(facts.len(), MAX_KEYS, "a refused write changed the map");
}

/// Writing a key twice replaces it rather than consuming a second slot.
#[test]
fn a_fact_map_is_last_write_wins() {
    let mut facts = Facts::new();
    facts
        .set("lane", FactValue::Str("first"))
        .expect("accepted");
    facts
        .set("lane", FactValue::Str("second"))
        .expect("accepted");
    assert_eq!(facts.len(), 1);
    assert_eq!(facts.get("lane"), Some(FactValue::Str("second")));
}

/// Labels are bounded the same way, because an unbounded label set is an unbounded time series.
#[test]
fn labels_are_bounded_like_facts() {
    let keys: Vec<String> = (0..=MAX_KEYS).map(|i| format!("label-{i}")).collect();
    let mut labels = Labels::new();
    for key in keys.iter().take(MAX_KEYS) {
        labels.set(key.as_str(), "v").expect("accepted");
    }
    assert!(labels.set(keys[MAX_KEYS].as_str(), "v").is_err());
    assert_eq!(labels.get("label-0"), Some("v"));
}

/// A bounded list refuses past its capacity and hands the item back rather than dropping it.
#[test]
fn a_bounded_list_refuses_past_its_capacity() {
    let mut legs: BoundedVec<u8, MAX_LEGS> = BoundedVec::new();
    for i in 0..MAX_LEGS {
        legs.push(u8::try_from(i).expect("small"))
            .expect("accepted");
    }
    assert!(legs.is_full());
    let refused = legs.push(99).expect_err("the list accepted a ninth leg");
    assert_eq!(refused.item, 99, "the refused item was not handed back");
    assert_eq!(refused.capacity, MAX_LEGS);
    assert_eq!(legs.len(), MAX_LEGS);
}

/// A journal record refuses past the record ceiling and hands back the length it was given.
#[test]
fn a_journal_record_refuses_past_the_record_ceiling() {
    let ok = RecordBytes::new(vec![0u8; MAX_RECORD_BYTES]).expect("at the ceiling is accepted");
    assert_eq!(ok.as_slice().len(), MAX_RECORD_BYTES);

    let too_big = RecordBytes::new(vec![0u8; MAX_RECORD_BYTES + 1]);
    assert_eq!(too_big.unwrap_err(), MAX_RECORD_BYTES + 1);
}

/// Arena bytes borrow and slab bytes own, and neither is the banned reference-counted buffer.
#[test]
fn the_two_byte_handles_do_what_they_say() {
    let owned = [1u8, 2, 3, 4];
    let borrowed = ArenaBytes::new(&owned);
    assert_eq!(borrowed.as_slice(), &owned);
    assert_eq!(borrowed.len(), 4);
    assert!(!borrowed.is_empty());

    let slab = SlabBytes::window(std::sync::Arc::from(&owned[..]), 1, 3);
    assert_eq!(slab.as_slice(), &[2, 3]);
    assert_eq!(slab.len(), 2);

    // A window past the end of the slab is clamped, never a panic and never a read past the end.
    let clamped = SlabBytes::window(std::sync::Arc::from(&owned[..]), 3, 99);
    assert_eq!(clamped.as_slice(), &[4]);
    let inverted = SlabBytes::window(std::sync::Arc::from(&owned[..]), 3, 1);
    assert!(inverted.is_empty());
}

/// The banned buffer type is not on this crate's surface.
///
/// The check is a source scan rather than a type assertion, because the property is "this name
/// appears nowhere", which no type can state about itself.
#[test]
fn the_banned_buffer_type_is_absent_from_the_surface() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders = Vec::new();
    walk(&src, &mut |path, text| {
        if text.contains("bytes::Bytes") || text.contains("use bytes::") {
            offenders.push(path.display().to_string());
        }
    });
    assert!(
        offenders.is_empty(),
        "the reference-counted buffer type appears in {offenders:?}"
    );

    let manifest = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"),
    )
    .expect("the manifest is readable");
    let deps = manifest
        .split("[dependencies]")
        .nth(1)
        .expect("the manifest has a dependency section");
    assert!(
        !deps.contains("\nbytes"),
        "the crate depends on the banned buffer crate"
    );
}

/// Walk every source file under a directory.
fn walk(dir: &std::path::Path, f: &mut impl FnMut(&std::path::Path, &str)) {
    let entries = std::fs::read_dir(dir).expect("the source directory is readable");
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, f);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let text = std::fs::read_to_string(&path).expect("a source file is readable");
            f(&path, &text);
        }
    }
}

/// A plane may name two places for the response ceiling, and the FIRST that resolves is the one.
///
/// The case is one dialect accepting the ceiling under an older member name and a newer one.
/// Declaration order is precedence order, so a request carrying both means the older, and a request
/// carrying only the newer is still read instead of sizing a hold off a key nobody sent.
#[test]
fn the_first_response_ceiling_pointer_that_resolves_is_the_one() {
    use busbar_contract::bounded::{BoundedVec, Ir, Span, MAX_RESPONSE_PTRS};
    use busbar_contract::grammar::{ArrivalLocation, Location};
    use busbar_contract::unit::AdmitFacts;

    assert_eq!(MAX_RESPONSE_PTRS, 2);

    let older = Location::Arrival(ArrivalLocation::FirstFrameJsonPointer("/max_tokens"));
    let newer = Location::Arrival(ArrivalLocation::FirstFrameJsonPointer(
        "/max_completion_tokens",
    ));
    let mut ptrs: BoundedVec<Location, MAX_RESPONSE_PTRS> = BoundedVec::new();
    ptrs.push(older).expect("the first fits");
    ptrs.push(newer).expect("the second fits");
    ptrs.push(older).expect_err("a third does not");

    let facts = AdmitFacts {
        max_response_ptrs: ptrs,
        ..AdmitFacts::default()
    };

    // Only the newer spelling arrived: the older misses, the newer answers.
    let only_newer = br#"{"max_completion_tokens":256}"#;
    let ir = Ir::new(only_newer, &[("/max_completion_tokens", Span { start: 25, end: 28 })]);
    assert_eq!(facts.max_response_bytes(&ir), Some(&b"256"[..]));

    // Both arrived: the first declared wins.
    let both = br#"{"max_tokens":1,"max_completion_tokens":2}"#;
    let ir = Ir::new(
        both,
        &[
            ("/max_tokens", Span { start: 14, end: 15 }),
            ("/max_completion_tokens", Span { start: 39, end: 40 }),
        ],
    );
    assert_eq!(facts.max_response_bytes(&ir), Some(&b"1"[..]));

    // Neither arrived: no ceiling, which is a missing value and not a refusal.
    let ir = Ir::new(b"{}", &[]);
    assert_eq!(facts.max_response_bytes(&ir), None);

    // A plane that names no place at all answers nothing, exactly as before.
    assert_eq!(AdmitFacts::default().max_response_bytes(&ir), None);
}
