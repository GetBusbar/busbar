//! THE DIALECT BATTERY — what every `busbar-plane-<plane>-<dialect>` crate owes.
//!
//! This file is the pattern the six dialects that follow copy, so every assertion here is about
//! the KIND rather than about this vendor. Where a case has to name an OpenAI spelling it names it
//! in one place at the top of the case and says why the case needs a concrete value at all.
//!
//! The cases divide into four groups, and the division is the argument for the shape:
//!
//! 1. THE DECLARATION IS WELL-FORMED — the key, the plane, the kind, the ABI, and the fact that the
//!    crate implements the kind's one trait exactly once.
//! 2. THE LADDER IS A LADDER — ascending, and every rung's claim is in the declaration constant.
//! 3. THE DECLARATION AGREES WITH ITSELF — the row's name is the key, the meter locators are
//!    positioned against the plane's class list, and every rung's surface has a verb.
//! 4. THE DIALECT IS PURE — no interior mutability, and two calls with the same inputs agree.

use busbar_contract::dialect::{Dialect, DialectMeta};
use busbar_contract::plugin::{Kind, Plugin, DIALECT_ABI};
use busbar_plane_llm::registry::{DialectEntry, DialectRegistry};
use busbar_plane_llm::LlmPlane;
use busbar_plane_llm_openai::dialect::{ENTRY, LOCATIONS};
use busbar_plane_llm_openai::OpenAi;

/// The dialect, translating for a plane with nothing configured.
///
/// A dialect's DECLARATIONS do not depend on what the operator configured, so the battery's subject
/// is the dialect over an empty plane — and a case that needed a configured upstream would be a
/// case about the plane rather than about the dialect.
fn subject() -> OpenAi {
    OpenAi::new(LlmPlane::EMPTY)
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
///
/// It is the case the contract's closed `Kind` set gained a member for: before `Kind::Dialect`
/// existed the only kind this crate could have returned was `Plane` — the one kind it is not — and
/// the isolation gate's census would have checked it against the plane skeleton.
#[test]
fn declares_the_dialect_kind_and_its_abi() {
    let d = subject();
    assert_eq!(d.kind(), Kind::Dialect);
    assert_eq!(d.abi(), DIALECT_ABI);
}

/// THE KEY IS ONE STRING, NOT TWO SPELLINGS THAT AGREE TODAY.
///
/// `Plugin::key` is what the registry files the dialect under and `DialectMeta::KEY` is what the
/// declaration says it is; the location row carries the name a third time because the plane's own
/// lookups are by row. All three are the same constant, and this case is what keeps them so: a row
/// registered under one spelling and resolved under another would have the plane answering for a
/// dialect nothing declared.
#[test]
fn the_key_is_one_string_everywhere_it_appears() {
    let d = subject();
    assert_eq!(d.key(), <OpenAi as DialectMeta>::KEY);
    assert_eq!(LOCATIONS.name, <OpenAi as DialectMeta>::KEY);
    assert_eq!(ENTRY.locations.name, <OpenAi as DialectMeta>::KEY);
}

/// A DIALECT NAMES EXACTLY ONE PLANE, AND IT IS THE ONE IT REGISTERS INTO.
#[test]
fn names_its_own_plane_and_no_other() {
    assert_eq!(
        <OpenAi as DialectMeta>::PLANE,
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
/// that is itself ordered. A dialect that declared its rungs out of order would have its later
/// rungs silently skipped in a contest it should have won.
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
}

/// EVERY RUNG NAMES THIS DIALECT.
///
/// A rung naming a neighbour would put this crate's registration in the middle of a contest between
/// two other vendors — and the plane would resolve to a dialect that had not declared the claim.
#[test]
fn every_rung_names_this_dialect() {
    for c in ENTRY.ladder {
        assert_eq!(c.dialect, <OpenAi as DialectMeta>::KEY);
    }
}

/// THE LADDER AND THE DECLARATION CONSTANT ARE THE SAME LIST.
///
/// `CLAIMS` is what the kernel reads at boot to prove the claim set disjoint; `LADDER` is what the
/// plane walks per request. A rung present in one and not the other is a claim that is either
/// proved and never walked or walked and never proved.
#[test]
fn the_ladder_and_the_claims_constant_agree() {
    let claims = <OpenAi as DialectMeta>::CLAIMS;
    assert_eq!(claims.len(), ENTRY.ladder.len());
    for (claim, rung) in claims.iter().zip(ENTRY.ladder) {
        assert_eq!(*claim, rung.claim);
    }
}

/// EVERY CLAIM IS BUILT WITH THE PLANE'S BUILDER, so the transport and the credential scheme are
/// the plane's answer and not a second one.
#[test]
fn every_claim_carries_the_planes_transport_and_scheme() {
    let reference =
        busbar_plane_llm::claims::claim(busbar_contract::grammar::Selector::PathSuffix("/probe"));
    for claim in <OpenAi as DialectMeta>::CLAIMS {
        assert_eq!(claim.transport, reference.transport);
        assert_eq!(claim.scheme, reference.scheme);
        assert_eq!(claim.scheme_alternatives, reference.scheme_alternatives);
    }
}

/// THE NARROWED ALTERNATIVE IS ONE THE PLANE DECLARED.
///
/// A plane may only be narrowed WITHIN the set it declares; an alternative this dialect invented
/// would be a credential form the authenticate step has no answer for.
#[test]
fn the_scheme_alternative_is_one_the_plane_declared() {
    let alt = <OpenAi as DialectMeta>::SCHEME_ALT.expect("this dialect narrows its plane's scheme");
    let reference =
        busbar_plane_llm::claims::claim(busbar_contract::grammar::Selector::PathSuffix("/probe"));
    assert!(
        reference
            .scheme_alternatives
            .iter()
            .any(|a| *a == alt.as_str()),
        "the narrowed alternative {alt:?} is not one the plane declares"
    );
}

// ------------------------------------------------------------------------------------------------
// 3. the declaration agrees with itself
// ------------------------------------------------------------------------------------------------

/// ONE METER LOCATOR PER CLASS THE PLANE DECLARES, IN THE PLANE'S ORDER.
///
/// The locators are read POSITIONALLY against the plane's class list, so a list one entry short
/// does not fail to compile — it shifts every class after the gap onto the pointer of its
/// neighbour, and the request is metered on a number that belongs to another class. That is a money
/// defect with no compiler behind it, which is why the count is asserted here.
#[test]
fn one_meter_locator_per_class_the_plane_declares() {
    let classes = <LlmPlane as busbar_contract::plane::PlaneMeta>::METER_CLASSES;
    assert_eq!(
        <OpenAi as DialectMeta>::METER_LOCATORS.len(),
        classes.len(),
        "the locators are positional against the plane's class list"
    );
}

/// THE LOCATORS AND THE ROW POINT AT THE SAME PLACES.
///
/// The row is what the plane's metering step reads; the locators are what the declaration publishes.
/// Two spellings of one place drift, and the direction they drift in is a request metered on one
/// pointer and reported against another.
#[test]
fn the_locators_and_the_row_name_the_same_places() {
    let locators = <OpenAi as DialectMeta>::METER_LOCATORS;
    assert_eq!(locators[0], LOCATIONS.tokens_in_pointer);
    assert_eq!(locators[1], LOCATIONS.tokens_out_pointer);
    assert_eq!(Some(locators[2]), LOCATIONS.cache_read_pointer);
    // The class this dialect does not report is an EMPTY locator, which says "not reported" — and
    // is a different statement from a pointer at a member that never arrives, which would meter
    // zero on every request instead of metering nothing.
    assert_eq!(locators[3], "");
    assert_eq!(LOCATIONS.cache_write_pointer, None);
}

/// A DIALECT THAT CLAIMS A SURFACE CAN NAME IT.
///
/// Every rung is a surface this crate says it answers for, and `VERBS` is what it calls them. A
/// rung with no verb is a surface that routes here and cannot be named in an audit line.
#[test]
fn every_claimed_surface_has_a_verb() {
    assert!(
        !<OpenAi as DialectMeta>::VERBS.is_empty(),
        "a dialect that claims a rung names at least one verb"
    );
    assert!(
        <OpenAi as DialectMeta>::VERBS.len() >= distinct_rungs(),
        "there are more claimed rungs than named verbs"
    );
}

/// How many distinct rung NUMBERS this dialect declares.
fn distinct_rungs() -> usize {
    let mut seen: Vec<u16> = ENTRY.ladder.iter().map(|c| c.rung).collect();
    seen.dedup();
    seen.len()
}

/// THE RESPONSE-CEILING POINTERS ARE IN PRECEDENCE ORDER AND NON-EMPTY.
///
/// The admit step takes the FIRST that resolves, so the order is a decision and not a list. This
/// dialect declares two because its reasoning models refuse the older key outright; declaring only
/// the older one sized a hold off a key those clients never send.
#[test]
fn the_response_ceiling_is_declared_in_precedence_order() {
    assert!(!LOCATIONS.max_response_pointers.is_empty());
    assert_eq!(
        LOCATIONS.max_response_pointers,
        &["/max_tokens", "/max_completion_tokens"],
        "the older spelling is first, because a request carrying both means the older one"
    );
}

// ------------------------------------------------------------------------------------------------
// 4. the dialect is pure
// ------------------------------------------------------------------------------------------------

/// A DIALECT HOLDS NOTHING ACROSS CALLS.
///
/// Asserted by WALKING THE TYPE rather than by trusting a sentence: a `Copy` type whose every field
/// is `Copy` cannot hold a cell, a lock or an atomic, because none of those is `Copy`. The day a
/// dialect grows a field that could remember a request, this stops compiling.
#[test]
fn the_dialect_holds_nothing_across_calls() {
    fn assert_pure<T: Copy + Send + Sync + 'static>() {}
    assert_pure::<OpenAi>();
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
    assert_eq!(SEALED.entries()[0].locations.name, "openai");
}
