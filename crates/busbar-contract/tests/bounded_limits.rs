//! The bounded types hold their bounds, and the constants are the design's numbers.
//!
//! Two things are asserted here. First, that each pinned number is what the crate-graph section of
//! the design pins it at — a constant that drifts is a bound nobody is enforcing. Second, that the
//! types built on those numbers actually refuse at them: a ceiling that is only in a comment is a
//! ceiling the first busy afternoon removes.
//!
//! The two bounds asserted on a sealed unit (its draft facts and its leg replies) need a minted
//! token to build that unit, so they live in the kernel
//! (`busbar-kernel/src/tests/caps_tests/bounded_limits.rs`), where a token constructor may be
//! spelled (construction `token-sealed`).

use busbar_contract::bounded::{
    BoundedVec, FactValue, Facts, Labels, PlaneAlloc, PlaneAllocBudget, ScratchBytes, SlabBytes,
    Span, MAX_CURSOR_BYTES, MAX_KEYS, MAX_LEGS, MAX_LEG_REPLIES, MAX_NEEDMORE_FRAMES,
    MAX_RECORD_BYTES, MAX_SESSION_UPSTREAMS, MAX_USAGE_LINES, SCRATCH_BASE_BYTES,
};
use busbar_contract::kinds::RecordBytes;

/// Every pinned number is the number the design pins.
#[test]
fn the_constants_are_the_designs_numbers() {
    assert_eq!(MAX_KEYS, 32);
    assert_eq!(MAX_USAGE_LINES, 16);
    assert_eq!(MAX_RECORD_BYTES, 512);
    assert_eq!(MAX_CURSOR_BYTES, 64 * 1024);
    assert_eq!(MAX_NEEDMORE_FRAMES, 256);
    assert_eq!(MAX_SESSION_UPSTREAMS, 8);
    assert_eq!(MAX_LEGS, 8);
    assert_eq!(MAX_LEG_REPLIES, 2);
    assert_eq!(SCRATCH_BASE_BYTES, 4 * 1024);
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

/// PlaneAlloc bytes borrow and slab bytes own, and neither is the banned reference-counted buffer.
#[test]
fn the_two_byte_handles_do_what_they_say() {
    let owned = [1u8, 2, 3, 4];
    let borrowed = ScratchBytes::new(&owned);
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

/// A plane may name two places for the response ceiling, and the FIRST that resolves is the one.
///
/// The case is one dialect accepting the ceiling under an older member name and a newer one.
/// Declaration order is precedence order, so a request carrying both means the older, and a request
/// carrying only the newer is still read instead of sizing a hold off a key nobody sent.
#[test]
fn the_first_response_ceiling_pointer_that_resolves_is_the_one() {
    use busbar_contract::bounded::{BoundedVec, Ir, MAX_RESPONSE_PTRS};
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
    let ir = Ir::new(
        only_newer,
        &[("/max_completion_tokens", Span { start: 25, end: 28 })],
    );
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

/// An arena that leaks, because a span table handed back from `spans::resolve` borrows the arena
/// for as long as the caller holds it and a test's own local buffer does not live that long. A
/// short-lived leak in a test process is the honest double; this crate forbids unsafe code.
struct LeakPlaneAlloc;

static PLANE_ALLOC: LeakPlaneAlloc = LeakPlaneAlloc;

impl PlaneAlloc for LeakPlaneAlloc {
    fn alloc_bytes<'a>(&'a self, src: &[u8]) -> Result<ScratchBytes<'a>, PlaneAllocBudget> {
        Ok(ScratchBytes::new(Box::leak(
            src.to_vec().into_boxed_slice(),
        )))
    }

    fn alloc_str<'a>(&'a self, src: &str) -> Result<&'a str, PlaneAllocBudget> {
        Ok(Box::leak(src.to_string().into_boxed_str()))
    }

    fn alloc_spans<'a>(
        &'a self,
        src: &[(&'a str, Span)],
    ) -> Result<&'a [(&'a str, Span)], PlaneAllocBudget> {
        Ok(Box::leak(src.to_vec().into_boxed_slice()))
    }

    fn remaining(&self) -> usize {
        usize::MAX
    }
}

/// A pointer the body does not carry is ABSENT from the table, not present and empty.
///
/// The two are different facts and the loop settles them differently: "the client sent nothing"
/// and "the client sent something empty" are not the same request. A table that carried a row for
/// every declared pointer would make them indistinguishable to every reader downstream.
#[test]
fn only_the_declared_pointers_the_body_carries_reach_the_table() {
    let body = br#"{"model":"model-1"}"#;
    let table = busbar_contract::spans::resolve(body, &["/model", "/stream"], &PLANE_ALLOC)
        .expect("the arena has room");

    assert_eq!(table.len(), 1, "one of the two pointers resolved");
    assert_eq!(table[0].0, "/model");
    assert_eq!(table[0].1.of(body), br#""model-1""#);
    assert!(
        !table.iter().any(|(name, _)| *name == "/stream"),
        "a pointer the body does not carry has no row at all"
    );
}

/// The table stops at the same ceiling the fact map does.
///
/// A plane that declared more places than the kernel can hold facts about is describing a body no
/// unit could be settled against, so the extra pointers are not considered rather than silently
/// overrunning a fixed table.
#[test]
fn a_plane_that_declares_more_pointers_than_the_ceiling_is_capped_at_it() {
    let declared = MAX_KEYS + 2;
    let mut body = String::from("{");
    let mut pointers: Vec<&'static str> = Vec::new();
    for i in 0..declared {
        if i > 0 {
            body.push(',');
        }
        body.push_str(&format!("\"k{i}\":{i}"));
        pointers.push(Box::leak(format!("/k{i}").into_boxed_str()));
    }
    body.push('}');

    // Every one of them resolves, so nothing but the ceiling can shorten the table.
    for pointer in &pointers {
        assert!(matches!(
            busbar_contract::spans::resolve_pointer(body.as_bytes(), pointer),
            busbar_contract::spans::Resolved::Found(_)
        ));
    }

    let table = busbar_contract::spans::resolve(body.as_bytes(), &pointers, &PLANE_ALLOC)
        .expect("the arena has room");
    assert_eq!(table.len(), MAX_KEYS);
    assert_eq!(table[MAX_KEYS - 1].0, pointers[MAX_KEYS - 1]);
}

/// The cursor stops at the ceiling its own documentation claims.
///
/// It counted what a plane had consumed and handed over every frame regardless, so the sentence
/// "it never exposes more than the per-connection ceiling" was true of nothing. A plane that kept
/// calling was handed as much as the connection had produced, which is the unbounded prefix the
/// bound exists to refuse.
#[test]
fn the_frame_cursor_stops_at_the_per_connection_ceiling() {
    use busbar_contract::wire::{Frame, FrameCursor, FrameMeta};
    use busbar_contract::{Direction, StreamId};

    // Sixteen frames of 8 KiB is 128 KiB — twice the ceiling, so exactly eight are readable.
    let chunk: std::sync::Arc<[u8]> = std::sync::Arc::from(vec![0u8; 8 * 1024].into_boxed_slice());
    let frames: Vec<Frame> = (0..16)
        .map(|i| Frame {
            direction: Direction::Inbound,
            stream: StreamId(i),
            bytes: SlabBytes::new(chunk.clone()),
            meta: FrameMeta {
                bytes: 8 * 1024,
                transport_units: None,
                status: None,
                status_code: None,
                retry_after_secs: None,
                text: false,
            },
        })
        .collect();

    let mut cursor = FrameCursor::new(&frames);
    let mut read = 0;
    while cursor.next_frame().is_some() {
        read += 1;
        assert!(read <= frames.len(), "the cursor never stopped");
    }

    assert_eq!(read, MAX_CURSOR_BYTES / (8 * 1024));
    assert_eq!(cursor.scanned_bytes(), MAX_CURSOR_BYTES);
    // And it stays stopped: the frames are still there, and it still says no.
    assert!(cursor.peek().is_none());
    assert!(cursor.next_frame().is_none());
    assert!(cursor.remaining() > 0);
}
