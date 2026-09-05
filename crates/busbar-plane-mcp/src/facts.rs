//! The fact keys this plane writes, and how a request identifier becomes a correlation.
//!
//! A fact is evidence. It is never an amount, never a decision and never a credential. Everything
//! here is something the plane READ off the bytes, reported under a key it declared up front so the
//! kernel's fact maps can be sized before the first frame arrives.

use busbar_contract::bounded::Arena;
use busbar_contract::ids::{CorrelationRef, CorrelationValue};

/// The method name the request carried, exactly as it was spelled.
pub const FACT_METHOD: &str = "method";

/// The request identifier, as the raw bytes it arrived as.
///
/// This is also the correlation's declared key. The bytes are kept as well as the reference because
/// the reference cannot carry them: see [`correlation_for`].
pub const FACT_RPC_ID: &str = "rpc_id";

/// Which revision of the protocol the caller asked to be answered under.
pub const FACT_PROTOCOL_VERSION: &str = "protocol_version";

/// Which registered server the unit is for.
pub const FACT_SERVER: &str = "server";

/// Which tool, prompt or resource the request named.
pub const FACT_SUBJECT: &str = "subject";

/// Which discriminator the answer carried.
pub const FACT_RESULT_TYPE: &str = "result_type";

/// Whether the answer said the tool itself failed.
pub const FACT_IS_ERROR: &str = "is_error";

/// The protocol-level error code the answer carried, where it carried one.
pub const FACT_ERROR_CODE: &str = "error_code";

/// The token a caller asked progress to be reported under.
pub const FACT_PROGRESS_TOKEN: &str = "progress_token";

/// The session fact keys this plane writes.
///
/// The revision and the server are session facts because a session that changed either mid-flight
/// would be a different priced thing, and the kernel needs to see that from the outside rather than
/// infer it.
pub const SESSION_FACTS: &[&str] = &[FACT_PROTOCOL_VERSION, FACT_SERVER];

/// The content fact keys this plane produces.
///
/// This is what the record and the export path receive: what the answer was FOR and how it ended.
/// Never the tool's output itself, and never anything the caller presented as authority.
pub const CONTENT_FACTS: &[&str] = &[
    FACT_RESULT_TYPE,
    FACT_SUBJECT,
    FACT_SERVER,
    FACT_IS_ERROR,
    FACT_ERROR_CODE,
];

/// The member every modern request of this protocol carries its own metadata under.
pub const META_MEMBER: &str = "_meta";

/// The metadata key naming the revision a caller is speaking.
pub const META_PROTOCOL_VERSION: &str = "io.modelcontextprotocol/protocolVersion";

/// The metadata key naming what the caller can answer if asked.
pub const META_CLIENT_CAPABILITIES: &str = "io.modelcontextprotocol/clientCapabilities";

/// The metadata key naming a token progress should be reported under.
pub const META_PROGRESS_TOKEN: &str = "progressToken";

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

    /// The metadata keys are spelled the way the codec spells them.
    ///
    /// The codec's own constants are visible to its crate only, so this reads its source. The same
    /// keys are pinned against the conformance battery's own table in the integration tests, which
    /// is where a test may read a file.
    #[test]
    fn the_metadata_keys_are_the_codecs_own() {
        let source = include_str!("../../busbar-mcp/src/mcp/envelope.rs");
        for key in [
            super::META_PROTOCOL_VERSION,
            super::META_CLIENT_CAPABILITIES,
        ] {
            assert!(source.contains(key), "the codec no longer names {key}");
        }
    }
}
