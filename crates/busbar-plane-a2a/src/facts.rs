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
/// contract's correlation value has an arm for each: a bare run of decimal digits is the number it
/// is, and anything else is the string it is, copied into the unit's own arena so it lives exactly
/// as long as the unit correlating on it.
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

/// The value one raw request identifier stands for.
fn correlation_value<'u>(raw_id: &[u8], arena: &'u dyn Arena) -> Option<CorrelationValue<'u>> {
    if !raw_id.is_empty() && raw_id.len() <= 19 && raw_id.iter().all(u8::is_ascii_digit) {
        let mut n: u64 = 0;
        for byte in raw_id {
            n = n * 10 + u64::from(byte - b'0');
        }
        return Some(CorrelationValue::Num(n));
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
    use busbar_contract::bounded::{Arena, ArenaBudget, ArenaBytes};
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

    /// Anything that is not a bare run of digits is carried as text, including the near misses.
    #[test]
    fn the_near_misses_are_carried_as_text() {
        let arena = TestArena;
        for raw in [
            &b"-1"[..],
            &b"1.0"[..],
            &b"1e3"[..],
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
