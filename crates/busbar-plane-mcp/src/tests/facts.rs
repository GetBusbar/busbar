//! Tests for `facts.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::{correlation_for, correlation_value, FACT_RPC_ID};
use busbar_contract::bounded::{Arena, ArenaBudget, ArenaBytes, Span};
use busbar_contract::ids::CorrelationValue;
use busbar_mcp_codec::{codec::META_CLIENT_CAPABILITIES, codec::META_PROTOCOL_VERSION};

/// An arena that hands out leaked bytes, which is what a test arena is.
struct TestArena;

impl Arena for TestArena {
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

/// A bare counter is the number it is, so a journal row reads as the caller wrote it.
///
/// Every request the conformance battery sends is numbered, so this is the case that matters
/// most: the battery's own identifiers arrive in a journal as the battery wrote them.
#[test]
fn a_bare_number_is_itself() {
    let arena = TestArena;
    for n in 0u64..64 {
        assert_eq!(
            correlation_value(n.to_string().as_bytes(), &arena),
            Some(CorrelationValue::Num(n))
        );
    }
}

/// A quoted identifier is the text it is, not a number standing in for it.
#[test]
fn a_named_identifier_is_carried_as_itself() {
    let arena = TestArena;
    assert_eq!(
        correlation_value(br#""req-1""#, &arena),
        Some(CorrelationValue::Str("req-1"))
    );
}

/// Two string identifiers of ONE principal on ONE session never answer to each other.
///
/// This is the collision the digest could not rule out, and the reason the digest is gone: the
/// kernel correlates on (session, principal, fact key, value), so two values that compare equal
/// are one hold. Checked over every pair of a set chosen to include the near misses.
#[test]
fn two_string_identifiers_of_one_principal_never_collide() {
    let arena = TestArena;
    let raw: [&[u8]; 8] = [
        br#""req-1""#,
        br#""req-2""#,
        br#""a""#,
        br#""b""#,
        br#""0""#,
        br#""7""#,
        br#""req-1 ""#,
        br#""REQ-1""#,
    ];
    let values: Vec<_> = raw
        .iter()
        .map(|r| correlation_value(r, &arena).expect("it is carried"))
        .collect();
    for (i, left) in values.iter().enumerate() {
        for (j, right) in values.iter().enumerate() {
            if i != j {
                assert_ne!(left, right, "{:?} and {:?} collided", raw[i], raw[j]);
            }
        }
    }
}

/// A string that reads like a counter is still a string, and never equals the counter.
#[test]
fn a_quoted_seven_is_not_the_number_seven() {
    let arena = TestArena;
    assert_ne!(
        correlation_value(br#""7""#, &arena),
        correlation_value(b"7", &arena)
    );
}

/// Anything that is not a CANONICAL run of digits is carried as text, including the near misses.
///
/// The leading-zero rows are the ones that matter and the ones this test used to miss: it named
/// a single twenty-digit run, which was carried as text because it was too long to be a number
/// rather than because it began with a zero, so the guard it appeared to test was the length
/// guard. `007` is short enough to be a number and must still not BE one — it is different bytes
/// from `7`, the identifier is compared as a JSON value, and folding the two together makes two
/// open calls of one principal on one session answer to each other.
#[test]
fn the_near_misses_are_carried_as_text() {
    let arena = TestArena;
    for raw in [
        &b"-1"[..],
        &b"1.0"[..],
        &b"1e3"[..],
        &b"007"[..],
        &b"00"[..],
        &b"0123"[..],
        &b"01234567890123456789"[..],
    ] {
        assert!(
            matches!(
                correlation_value(raw, &arena),
                Some(CorrelationValue::Str(_))
            ),
            "{raw:?} was not carried as text"
        );
    }
}

/// A leading zero makes a DIFFERENT identifier, and the two never answer to each other.
///
/// The one zero that is a number is the number zero written by itself.
#[test]
fn a_padded_identifier_is_not_the_number_it_pads() {
    let arena = TestArena;
    assert_eq!(
        correlation_value(b"007", &arena),
        Some(CorrelationValue::Str("007"))
    );
    assert_ne!(
        correlation_value(b"007", &arena),
        correlation_value(b"7", &arena)
    );
    assert_eq!(
        correlation_value(b"0", &arena),
        Some(CorrelationValue::Num(0))
    );
}

/// The EMPTY identifier correlates with nothing.
///
/// This protocol spells "the request could not be read" as the empty value, so an answer
/// carrying it answers no request of anyone's. It used to be carried as the four letters it is
/// written with, which is a text identifier a caller can send for itself — and then that
/// caller's own answer and an answer to a request nobody could read land on one hold. A QUOTED
/// one is a caller's identifier and is carried as itself.
#[test]
fn the_empty_identifier_correlates_with_nothing() {
    let arena = TestArena;
    assert_eq!(correlation_value(b"null", &arena), None);
    assert!(correlation_for(b"null", &arena).is_none());
    assert_eq!(
        correlation_value(br#""null""#, &arena),
        Some(CorrelationValue::Str("null"))
    );
}

/// The same bytes always give the same value.
#[test]
fn the_value_is_deterministic() {
    let arena = TestArena;
    for raw in [&b"42"[..], &br#""abc""#[..], &b"null"[..]] {
        assert_eq!(
            correlation_value(raw, &arena),
            correlation_value(raw, &arena)
        );
    }
}

/// The correlation carries the declared key and the identifier's value.
#[test]
fn the_correlation_carries_the_declared_key() {
    let arena = TestArena;
    let c = correlation_for(b"7", &arena).expect("it is carried");
    assert_eq!(c.fact_key, FACT_RPC_ID);
    assert_eq!(c.value, CorrelationValue::Num(7));
}

/// The metadata keys are spelled the way the codec spells them.
///
/// A VALUE comparison. This read the server half's SOURCE once, with `include_str!` over
/// `../../busbar-mcp/src/…` — a coupling to a sibling crate the manifest does not name, which
/// left this plane unable to be built or deleted on its own. Both keys are the codec's now, so
/// a spelling can no longer differ between the side that requires it inbound and the side that
/// writes it outbound. The same keys stay pinned against the conformance battery's own table in
/// the integration tests.
#[test]
fn the_metadata_keys_are_the_codecs_own() {
    assert_eq!(super::META_PROTOCOL_VERSION, META_PROTOCOL_VERSION);
    assert_eq!(super::META_CLIENT_CAPABILITIES, META_CLIENT_CAPABILITIES);
}

/// Each quoted needle is its own key, in quotes, and nothing else.
///
/// The quoted forms exist so no request has to build one. That is only safe while they say the
/// same thing as the names they were written from, and this is what says so: change one
/// spelling without the other and this test names the pair that disagree.
#[test]
fn the_quoted_needles_are_the_keys_in_quotes() {
    for (name, quoted) in [
        (
            super::META_PROTOCOL_VERSION,
            super::META_PROTOCOL_VERSION_QUOTED,
        ),
        (
            super::META_PROGRESS_TOKEN,
            super::META_PROGRESS_TOKEN_QUOTED,
        ),
    ] {
        assert_eq!(
            quoted,
            format!("\"{name}\"").as_bytes(),
            "the quoted needle for {name} is not that key in quotes"
        );
    }
}
