//! The fact keys this plane writes, and how a request identifier becomes a correlation.
//!
//! A fact is evidence. It is never an amount, never a decision and never a credential. Everything
//! here is something the plane READ off the bytes, reported under a key it declared up front so the
//! kernel's fact maps can be sized before the first frame arrives.

use busbar_contract::bounded::Arena;
use busbar_contract::ids::{CorrelationRef, CorrelationValue};

/// The method name the request carried, exactly as it was spelled.
pub const FACT_METHOD: &str = "method";

/// Which of the two vocabularies the method name came from.
pub const FACT_WORDING: &str = "wording";

/// The request identifier, as the raw bytes it arrived as.
///
/// This is also the correlation's declared key. The bytes are kept as well as the reference because
/// the reference cannot carry them: see [`correlation_for`].
pub const FACT_RPC_ID: &str = "rpc_id";

/// Which revision of the protocol the caller asked to be answered under.
pub const FACT_VERSION: &str = "a2a_version";

/// Which agent of the catalogue the unit is for.
pub const FACT_AGENT_ID: &str = "agent_id";

/// Whether the answer is a stream of events rather than one reply.
pub const FACT_STREAMING: &str = "streaming";

/// The task the answer is about.
pub const FACT_TASK_ID: &str = "task_id";

/// The conversation the task belongs to.
pub const FACT_CONTEXT_ID: &str = "context_id";

/// The state the answer says the task is in.
pub const FACT_TASK_STATE: &str = "task_state";

/// The error code the answer carried, where it carried one.
pub const FACT_ERROR_CODE: &str = "error_code";

/// The session fact keys this plane writes.
///
/// The protocol revision and the agent are session facts because a session that changed either
/// mid-flight would be a different priced thing, and the kernel needs to see that from the outside
/// rather than infer it.
pub const SESSION_FACTS: &[&str] = &[FACT_VERSION, FACT_AGENT_ID];

/// The content fact keys this plane produces.
///
/// This is what the record and the export path receive: what the answer was ABOUT and how it ended.
/// Never the message content itself, and never a credential.
pub const CONTENT_FACTS: &[&str] = &[
    FACT_TASK_ID,
    FACT_CONTEXT_ID,
    FACT_TASK_STATE,
    FACT_ERROR_CODE,
];

/// The correlation reference for one request identifier.
///
/// The identifier travels as ITSELF. This protocol's request identifier is a JSON scalar the shared
/// reader accepts as either a string or a number and refuses in every other shape, and the
/// contract's correlation value has an arm for each: a run of decimal digits written the one way a
/// number can be written is the number it is, and anything else is the string it is, copied into the
/// unit's own arena so it lives exactly as long as the unit correlating on it.
///
/// It used to be a sixty-four-bit digest, because the correlation value used to be a whole number
/// and a string had no whole number to be. Two identifiers of one principal on one session could
/// digest to one value, and the kernel's correlation key is precisely (session, principal, fact
/// key, value), so that collision decided which hold a provider frame accrued into. That is money
/// moving between two units, so the digest is gone rather than documented.
///
/// Answers nothing when the arena is full or the identifier is not text: a correlation that cannot
/// be carried honestly is better absent than approximated.
#[must_use]
pub fn correlation_for<'u>(raw_id: &[u8], arena: &'u dyn Arena) -> Option<CorrelationRef<'u>> {
    Some(CorrelationRef {
        fact_key: FACT_RPC_ID,
        value: correlation_value(raw_id, arena)?,
    })
}

/// Whether a run of bytes is a whole number written the ONE way it can be written.
///
/// A leading zero is the case this exists for. `007` and `7` are different bytes and the identifier
/// they name is compared as a JSON VALUE, so reading them both as the number seven makes two open
/// requests of one principal on one session answer to each other — the collision the digest was
/// removed for, arriving by a different road. The canonical spelling is the number; every other
/// spelling of it is carried as the text it is, and text never equals a number.
fn is_canonical_number(raw: &[u8]) -> bool {
    match raw.first() {
        // A single zero is the only number that may begin with one.
        Some(b'0') => raw.len() == 1,
        Some(b'1'..=b'9') => raw.len() <= 19 && raw.iter().all(u8::is_ascii_digit),
        _ => false,
    }
}

/// The value one raw request identifier stands for.
fn correlation_value<'u>(raw_id: &[u8], arena: &'u dyn Arena) -> Option<CorrelationValue<'u>> {
    if is_canonical_number(raw_id) {
        let mut n: u64 = 0;
        for byte in raw_id {
            n = n * 10 + u64::from(byte - b'0');
        }
        return Some(CorrelationValue::Num(n));
    }
    // The EMPTY value is not an identifier. This protocol writes it on an answer whose request
    // could not be read at all, so it names no request; carrying it as the four letters it is spelled
    // with makes it a text identifier that a caller could send — and then two unrelated answers, one
    // to that caller and one to a request nobody could read, correlate onto one hold. A quoted
    // "null" is a caller's own identifier and is unaffected: these are the bare bytes.
    if raw_id == b"null" {
        return None;
    }
    // A quoted identifier is the text between the quotes; anything else is the bytes as they are.
    let inner = match (raw_id.first(), raw_id.last(), raw_id.len()) {
        (Some(b'"'), Some(b'"'), n) if n >= 2 => &raw_id[1..n - 1],
        _ => raw_id,
    };
    let text = core::str::from_utf8(inner).ok()?;
    arena.alloc_str(text).ok().map(CorrelationValue::Str)
}

#[cfg(test)]
mod tests {
    use super::{correlation_for, correlation_value, FACT_RPC_ID};
    use busbar_contract::bounded::{Arena, ArenaBudget, ArenaBytes, Span};
    use busbar_contract::ids::CorrelationValue;

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
    /// open requests of one principal on one session answer to each other.
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
}
