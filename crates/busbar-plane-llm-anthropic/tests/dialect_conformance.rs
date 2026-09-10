//! THE DIALECT BATTERY — what every `busbar-plane-<plane>-<dialect>` crate owes, on the third
//! crate of the kind.
//!
//! This file is the second COPY of the pattern, and the copy is itself part of the proof: if the
//! fifteen cases had to be re-argued for a third vendor, the pattern would not be one. Every
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
//! WHAT DIFFERS FROM THE FIRST TWO BATTERIES, AND WHY. This is the first dialect with HEADER rungs,
//! so two cases earn their keep for the first time: `the_ladder_ascends` has three distinct numbers
//! to order rather than one, and `every_claimed_surface_has_a_verb` counts PATH rungs, because a
//! header rung is evidence about the client and claims every path rather than naming a surface —
//! three rungs routing to one surface is one verb, not three. And `the_scheme_alternative_is_one_
//! the_plane_declared` is asked of an alternative that is NOT `bearer` for the first time. The
//! fifteenth case asserts the ceiling is REQUIRED as well as declared, because this is the one
//! dialect of the six that requires it.

use busbar_contract::dialect::{Dialect, DialectMeta};
use busbar_contract::grammar::Selector;
use busbar_contract::plugin::{Kind, Plugin, DIALECT_ABI};
use busbar_plane_llm::registry::{DialectEntry, DialectRegistry};
use busbar_plane_llm::LlmPlane;
use busbar_plane_llm_anthropic::dialect::{ENTRY, LOCATIONS};
use busbar_plane_llm_anthropic::Anthropic;

/// The dialect, translating for a plane with nothing configured.
///
/// A dialect's DECLARATIONS do not depend on what the operator configured, so the battery's subject
/// is the dialect over an empty plane — and a case that needed a configured upstream would be a
/// case about the plane rather than about the dialect.
fn subject() -> Anthropic {
    Anthropic::new(LlmPlane::EMPTY)
}

// ------------------------------------------------------------------------------------------------
// 1. the declaration is well-formed
// ------------------------------------------------------------------------------------------------

/// THE KIND'S ONE TRAIT, IMPLEMENTED ONCE AND OBJECT-SAFELY.
///
/// The coercion is the assertion: the kernel holds every plugin behind a pointer, so a dialect
/// trait that stopped being object-safe would stop being loadable, and this line is what fails
/// first if an associated type or a generic method is ever added to it.
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
///
/// `Plugin::key` is what the registry files the dialect under and `DialectMeta::KEY` is what the
/// declaration says it is; the location row carries the name a third time because the plane's own
/// lookups are by row. All three are the same constant, and this case is what keeps them so.
#[test]
fn the_key_is_one_string_everywhere_it_appears() {
    let d = subject();
    assert_eq!(d.key(), <Anthropic as DialectMeta>::KEY);
    assert_eq!(LOCATIONS.name, <Anthropic as DialectMeta>::KEY);
    assert_eq!(ENTRY.locations.name, <Anthropic as DialectMeta>::KEY);
}

/// A DIALECT NAMES EXACTLY ONE PLANE, AND IT IS THE ONE IT REGISTERS INTO.
#[test]
fn names_its_own_plane_and_no_other() {
    assert_eq!(
        <Anthropic as DialectMeta>::PLANE,
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
/// that is itself ordered. This is the first battery where the case has three distinct numbers to
/// order rather than one, so it is the first time it could have failed.
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
///
/// A rung naming a neighbour would put this crate's registration in the middle of a contest between
/// two other vendors — and the plane would resolve to a dialect that had not declared the claim.
#[test]
fn every_rung_names_this_dialect() {
    for c in ENTRY.ladder {
        assert_eq!(c.dialect, <Anthropic as DialectMeta>::KEY);
    }
}

/// THE LADDER AND THE DECLARATION CONSTANT ARE THE SAME LIST.
///
/// `CLAIMS` is what the kernel reads at boot to prove the claim set disjoint; `LADDER` is what the
/// plane walks per request. A rung present in one and not the other is a claim that is either
/// proved and never walked or walked and never proved.
#[test]
fn the_ladder_and_the_claims_constant_agree() {
    let claims = <Anthropic as DialectMeta>::CLAIMS;
    assert_eq!(claims.len(), ENTRY.ladder.len());
    for (claim, rung) in claims.iter().zip(ENTRY.ladder) {
        assert_eq!(*claim, rung.claim);
    }
}

/// EVERY CLAIM IS BUILT WITH THE PLANE'S BUILDER, so the transport and the credential scheme are
/// the plane's answer and not a second one — and that holds for a HEADER claim exactly as it does
/// for a path claim, which is the first time a battery has had a header claim to say it of.
#[test]
fn every_claim_carries_the_planes_transport_and_scheme() {
    let reference = busbar_plane_llm::claims::claim(Selector::PathSuffix("/probe"));
    for claim in <Anthropic as DialectMeta>::CLAIMS {
        assert_eq!(claim.transport, reference.transport);
        assert_eq!(claim.scheme, reference.scheme);
        assert_eq!(claim.scheme_alternatives, reference.scheme_alternatives);
    }
}

/// THE NARROWED ALTERNATIVE IS ONE THE PLANE DECLARED.
///
/// A plane may only be narrowed WITHIN the set it declares; an alternative this dialect invented
/// would be a credential form the authenticate step has no answer for. The first two dialect crates
/// narrowed to `bearer`, which every plane declares; this one narrows to the key-header form, so
/// this is the first time the case asks a question whose answer was not already obvious.
#[test]
fn the_scheme_alternative_is_one_the_plane_declared() {
    let alt =
        <Anthropic as DialectMeta>::SCHEME_ALT.expect("this dialect narrows its plane's scheme");
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
        "this dialect's clients present a key header, not a bearer token; a bearer narrowing here \
         would be the sibling's row copied rather than this vendor's declared"
    );
}

// ------------------------------------------------------------------------------------------------
// 3. the declaration agrees with itself
// ------------------------------------------------------------------------------------------------

/// ONE METER LOCATOR PER CLASS THE PLANE DECLARES, IN THE PLANE'S ORDER.
///
/// The locators are read POSITIONALLY against the plane's class list, so a list one entry short
/// does not fail to compile — it shifts every class after the gap onto the pointer of its
/// neighbour, and the request is metered on a number that belongs to another class.
#[test]
fn one_meter_locator_per_class_the_plane_declares() {
    let classes = <LlmPlane as busbar_contract::plane::PlaneMeta>::METER_CLASSES;
    assert_eq!(
        <Anthropic as DialectMeta>::METER_LOCATORS.len(),
        classes.len(),
        "the locators are positional against the plane's class list"
    );
}

/// THE LOCATORS AND THE ROW POINT AT THE SAME PLACES.
///
/// ALL FOUR ARE REPORTED HERE: this vendor reports both cache quantities as siblings of the plain
/// counts under `usage`, so every locator is a pointer and none is the empty "not reported" string.
#[test]
fn the_locators_and_the_row_name_the_same_places() {
    let locators = <Anthropic as DialectMeta>::METER_LOCATORS;
    assert_eq!(locators[0], LOCATIONS.tokens_in_pointer);
    assert_eq!(locators[1], LOCATIONS.tokens_out_pointer);
    assert_eq!(Some(locators[2]), LOCATIONS.cache_read_pointer);
    assert_eq!(Some(locators[3]), LOCATIONS.cache_write_pointer);
    assert!(
        locators.iter().all(|l| !l.is_empty()),
        "this dialect reports every class the plane declares, so no locator is the empty \
         'not reported' string"
    );
}

/// A DIALECT THAT CLAIMS A SURFACE CAN NAME IT.
///
/// Every PATH rung is a surface this crate says it answers for, and `VERBS` is what it calls them.
/// A header rung is not a surface: it is evidence about the client, and it claims every path a
/// request could arrive on, so the surface it routes to is one the path rungs already name. Three
/// rungs and one verb is therefore the honest count here, and the case counts path rungs so that
/// the day this crate claims a second path is the day it must name a second verb.
#[test]
fn every_claimed_surface_has_a_verb() {
    assert!(
        !<Anthropic as DialectMeta>::VERBS.is_empty(),
        "a dialect that claims a rung names at least one verb"
    );
    assert!(
        <Anthropic as DialectMeta>::VERBS.len() >= distinct_path_rungs(),
        "there are more claimed path surfaces than named verbs"
    );
    assert!(
        ENTRY.ladder.iter().any(|c| !is_path(&c.claim.selector)),
        "this battery's verb count is written for a ladder with header rungs, and this ladder \
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

/// THE RESPONSE-CEILING POINTERS ARE IN PRECEDENCE ORDER, NON-EMPTY, AND REQUIRED.
///
/// The admit step takes the FIRST that resolves, so the order is a decision and not a list. This
/// dialect declares exactly ONE spelling, and it is the one dialect of the six that REQUIRES it:
/// its upstreams refuse a request with no ceiling, so the row says so and the plane's crossing
/// fills one in without naming this vendor. A row that declared the pointer and not the
/// requirement would have the crossing forward a request the upstream is documented to refuse.
#[test]
fn the_response_ceiling_is_declared_in_precedence_order() {
    assert!(!LOCATIONS.max_response_pointers.is_empty());
    assert_eq!(
        LOCATIONS.max_response_pointers,
        &["/max_tokens"],
        "this vendor accepts the ceiling under one member name and only one"
    );
    assert!(
        std::hint::black_box(LOCATIONS).requires_max_response,
        "this vendor's upstreams refuse a request with no ceiling, and the row must say so"
    );
}

// ------------------------------------------------------------------------------------------------
// 4. the dialect is pure
// ------------------------------------------------------------------------------------------------

/// A DIALECT HOLDS NOTHING ACROSS CALLS.
///
/// Asserted by WALKING THE TYPE rather than by trusting a sentence: a `Copy` type whose every field
/// is `Copy` cannot hold a cell, a lock or an atomic, because none of those is `Copy`.
#[test]
fn the_dialect_holds_nothing_across_calls() {
    fn assert_pure<T: Copy + Send + Sync + 'static>() {}
    assert_pure::<Anthropic>();
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
    assert_eq!(SEALED.entries()[0].locations.name, "anthropic");
}
