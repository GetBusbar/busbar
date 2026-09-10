//! THE DIALECT BATTERY — what every `busbar-plane-<plane>-<dialect>` crate owes, on the fourth
//! crate of the kind.
//!
//! This file is the third COPY of the pattern, and the copy is itself part of the proof: if the
//! fifteen cases had to be re-argued for a fourth vendor, the pattern would not be one. Every
//! assertion here is about the KIND rather than about this vendor. Where a case has to name a
//! concrete spelling it names it in one place inside the case and says why the case needs a
//! concrete value at all.
//!
//! The cases divide into four groups, and the division is the argument for the shape:
//!
//! 1. THE DECLARATION IS WELL-FORMED — the key, the plane, the kind, the ABI, and the fact that the
//!    crate implements the kind's one trait exactly once.
//! 2. THE LADDER IS A LADDER — ascending, and every rung's claim is in the declaration constant.
//! 3. THE DECLARATION AGREES WITH ITSELF — the row's name is the key, the meter locators are
//!    positioned against the plane's class list, and every claimed surface has a verb.
//! 4. THE DIALECT IS PURE — no interior mutability, and its entry is a constant.
//!
//! WHAT DIFFERS FROM THE EARLIER BATTERIES, AND WHY. Case 13 asserts the model rides the REQUEST
//! TARGET, because this is the first carved-out dialect whose row names a path segment rather than
//! a body pointer — and asserts a cache-WRITE locator that is the empty "not reported" string,
//! because this vendor reports none. Case 11 counts PATH rungs, as the sibling with a header rung
//! does, and there are two of them here (the action suffixes and the bare model-scoped surface).

use busbar_contract::dialect::{Dialect, DialectMeta};
use busbar_contract::grammar::{ArrivalLocation, Location, Selector};
use busbar_contract::plugin::{Kind, Plugin, DIALECT_ABI};
use busbar_plane_llm::registry::{DialectEntry, DialectRegistry};
use busbar_plane_llm::LlmPlane;
use busbar_plane_llm_gemini::dialect::{ENTRY, LOCATIONS};
use busbar_plane_llm_gemini::Gemini;

/// The dialect, translating for a plane with nothing configured.
///
/// A dialect's DECLARATIONS do not depend on what the operator configured, so the battery's subject
/// is the dialect over an empty plane — and a case that needed a configured upstream would be a
/// case about the plane rather than about the dialect.
fn subject() -> Gemini {
    Gemini::new(LlmPlane::EMPTY)
}

// ------------------------------------------------------------------------------------------------
// 1. the declaration is well-formed
// ------------------------------------------------------------------------------------------------

/// THE KIND'S ONE TRAIT, IMPLEMENTED ONCE AND OBJECT-SAFELY.
#[test]
fn implements_the_dialect_trait_object_safely() {
    let d = subject();
    let _: &dyn Dialect = &d;
    let _: &dyn Plugin = &d;
}

/// A DIALECT DECLARES THE DIALECT KIND.
#[test]
fn declares_the_dialect_kind_and_its_abi() {
    let d = subject();
    assert_eq!(d.kind(), Kind::Dialect);
    assert_eq!(d.abi(), DIALECT_ABI);
}

/// THE KEY IS ONE STRING, NOT THREE SPELLINGS THAT AGREE TODAY.
#[test]
fn the_key_is_one_string_everywhere_it_appears() {
    let d = subject();
    assert_eq!(d.key(), <Gemini as DialectMeta>::KEY);
    assert_eq!(LOCATIONS.name, <Gemini as DialectMeta>::KEY);
    assert_eq!(ENTRY.locations.name, <Gemini as DialectMeta>::KEY);
}

/// A DIALECT NAMES EXACTLY ONE PLANE, AND IT IS THE ONE IT REGISTERS INTO.
#[test]
fn names_its_own_plane_and_no_other() {
    assert_eq!(
        <Gemini as DialectMeta>::PLANE,
        <LlmPlane as busbar_contract::plane::PlaneMeta>::KEY
    );
}

// ------------------------------------------------------------------------------------------------
// 2. the ladder is a ladder
// ------------------------------------------------------------------------------------------------

/// THE RUNGS ASCEND.
///
/// Required, not tidy: the plane's merged walk takes the smallest unvisited rung from each source
/// and stops scanning a source the moment it can no longer win, which is only sound for a source
/// that is itself ordered. Eight claims over three numbers, so the case has real work here.
#[test]
fn the_ladder_ascends() {
    let mut previous = 0u16;
    for c in ENTRY.ladder {
        assert!(
            c.rung >= previous,
            "rung {} follows rung {previous}; a registered ladder must ascend",
            c.rung
        );
        previous = c.rung;
    }
    assert!(
        !ENTRY.ladder.is_empty(),
        "a dialect that claims nothing is a crate no request can reach"
    );
}

/// EVERY RUNG NAMES THIS DIALECT.
#[test]
fn every_rung_names_this_dialect() {
    for c in ENTRY.ladder {
        assert_eq!(c.dialect, <Gemini as DialectMeta>::KEY);
    }
}

/// THE LADDER AND THE DECLARATION CONSTANT ARE THE SAME LIST.
#[test]
fn the_ladder_and_the_claims_constant_agree() {
    let claims = <Gemini as DialectMeta>::CLAIMS;
    assert_eq!(claims.len(), ENTRY.ladder.len());
    for (claim, rung) in claims.iter().zip(ENTRY.ladder) {
        assert_eq!(*claim, rung.claim);
    }
}

/// EVERY CLAIM IS BUILT WITH THE PLANE'S BUILDER, so the transport and the credential scheme are
/// the plane's answer and not a second one — for the header claim, the substring claims and the
/// pattern claims alike, which is every selector form a dialect of this plane has used so far.
#[test]
fn every_claim_carries_the_planes_transport_and_scheme() {
    let reference = busbar_plane_llm::claims::claim(Selector::PathSuffix("/probe"));
    for claim in <Gemini as DialectMeta>::CLAIMS {
        assert_eq!(claim.transport, reference.transport);
        assert_eq!(claim.scheme, reference.scheme);
        assert_eq!(claim.scheme_alternatives, reference.scheme_alternatives);
    }
}

/// THE NARROWED ALTERNATIVE IS ONE THE PLANE DECLARED.
///
/// This dialect's clients present a key header rather than a bearer token, so the narrowing is to
/// the key-header form and the case asks a question whose answer is not the default.
#[test]
fn the_scheme_alternative_is_one_the_plane_declared() {
    let alt = <Gemini as DialectMeta>::SCHEME_ALT.expect("this dialect narrows its plane's scheme");
    let reference = busbar_plane_llm::claims::claim(Selector::PathSuffix("/probe"));
    assert!(
        reference
            .scheme_alternatives
            .iter()
            .any(|a| *a == alt.as_str()),
        "the narrowed alternative {alt:?} is not one the plane declares"
    );
    assert_ne!(
        alt.as_str(),
        "bearer",
        "this dialect's clients present a key header, not a bearer token"
    );
}

// ------------------------------------------------------------------------------------------------
// 3. the declaration agrees with itself
// ------------------------------------------------------------------------------------------------

/// ONE METER LOCATOR PER CLASS THE PLANE DECLARES, IN THE PLANE'S ORDER.
#[test]
fn one_meter_locator_per_class_the_plane_declares() {
    let classes = <LlmPlane as busbar_contract::plane::PlaneMeta>::METER_CLASSES;
    assert_eq!(
        <Gemini as DialectMeta>::METER_LOCATORS.len(),
        classes.len(),
        "the locators are positional against the plane's class list"
    );
}

/// THE LOCATORS AND THE ROW POINT AT THE SAME PLACES — AND THE MODEL IS IN THE REQUEST TARGET.
///
/// Three locators are pointers and the fourth is EMPTY: this vendor reports no written-to-cache
/// quantity, and the empty string is the declared way of saying so. A pointer here would resolve to
/// nothing and meter zero as if the upstream had reported it.
///
/// The model location is asserted in the same case because it is the other place this row differs
/// from every row carved out before it: a path segment, not a body pointer. The segment is zero
/// because the model is the first variable segment of the pattern the rung-6 claim matched.
#[test]
fn the_locators_and_the_row_name_the_same_places() {
    let locators = <Gemini as DialectMeta>::METER_LOCATORS;
    assert_eq!(locators[0], LOCATIONS.tokens_in_pointer);
    assert_eq!(locators[1], LOCATIONS.tokens_out_pointer);
    assert_eq!(Some(locators[2]), LOCATIONS.cache_read_pointer);
    assert_eq!(
        LOCATIONS.cache_write_pointer, None,
        "this vendor reports no written-to-cache quantity"
    );
    assert!(
        locators[3].is_empty(),
        "the class the row does not report is declared as the empty locator, not a pointer"
    );
    assert_eq!(
        LOCATIONS.model_location,
        Location::Arrival(ArrivalLocation::PathSegment(0)),
        "this vendor's model rides the request target, and the row must name the segment"
    );
}

/// A DIALECT THAT CLAIMS A SURFACE CAN NAME IT.
///
/// Every PATH rung is a surface this crate says it answers for, and `VERBS` is what it calls them.
/// A header rung is not a surface: it is evidence about the client and claims every path, so the
/// surface it routes to is one the path rungs already name. Two path rungs here — the action
/// suffixes and the bare model-scoped surface — and six verbs, one per action plus the surface.
#[test]
fn every_claimed_surface_has_a_verb() {
    assert!(
        !<Gemini as DialectMeta>::VERBS.is_empty(),
        "a dialect that claims a rung names at least one verb"
    );
    assert!(
        <Gemini as DialectMeta>::VERBS.len() >= distinct_path_rungs(),
        "there are more claimed path surfaces than named verbs"
    );
    assert!(
        ENTRY.ladder.iter().any(|c| !is_path(&c.claim.selector)),
        "this battery's verb count is written for a ladder with a header rung, and this ladder \
         has none; use the path-only form of the case"
    );
}

/// Whether a selector is a statement about the request target rather than about a header.
fn is_path(s: &Selector) -> bool {
    matches!(
        s,
        Selector::ExactPath(_)
            | Selector::PrefixOneLevel(_)
            | Selector::PathPattern(_)
            | Selector::PathSuffix(_)
            | Selector::PathContains(_)
    )
}

/// How many distinct rung NUMBERS this dialect declares over the request target.
fn distinct_path_rungs() -> usize {
    let mut seen: Vec<u16> = ENTRY
        .ladder
        .iter()
        .filter(|c| is_path(&c.claim.selector))
        .map(|c| c.rung)
        .collect();
    seen.dedup();
    seen.len()
}

/// THE RESPONSE-CEILING POINTERS ARE IN PRECEDENCE ORDER AND NON-EMPTY.
///
/// This dialect declares exactly ONE, nested under the generation configuration rather than at the
/// top level, and it does not REQUIRE one: its upstreams accept a request with no ceiling, so the
/// crossing adds none.
#[test]
fn the_response_ceiling_is_declared_in_precedence_order() {
    assert!(!LOCATIONS.max_response_pointers.is_empty());
    assert_eq!(
        LOCATIONS.max_response_pointers,
        &["/generationConfig/maxOutputTokens"],
        "this vendor accepts the ceiling under one member name and only one"
    );
    assert!(
        !std::hint::black_box(LOCATIONS).requires_max_response,
        "this vendor's upstreams accept a request with no ceiling"
    );
}

// ------------------------------------------------------------------------------------------------
// 4. the dialect is pure
// ------------------------------------------------------------------------------------------------

/// A DIALECT HOLDS NOTHING ACROSS CALLS.
#[test]
fn the_dialect_holds_nothing_across_calls() {
    fn assert_pure<T: Copy + Send + Sync + 'static>() {}
    assert_pure::<Gemini>();
    assert_pure::<busbar_plane_llm::dialect::Dialect>();
    assert_pure::<DialectEntry>();
    assert_pure::<DialectRegistry>();
}

/// THE ENTRY IS `const`-CONSTRUCTIBLE, which is what lets a composition root seal the whole registry
/// without reaching the heap.
#[test]
fn the_entry_is_a_constant() {
    const SEALED: DialectRegistry = DialectRegistry::sealed(&[ENTRY]);
    assert_eq!(SEALED.entries().len(), 1);
    assert_eq!(SEALED.entries()[0].locations.name, "gemini");
}
