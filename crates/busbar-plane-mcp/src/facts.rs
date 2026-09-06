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

/// The metadata key naming the revision a caller is speaking. The CODEC's, read by identity: the
/// server half requires it inbound and writes it outbound, and a key this plane merely copied is a
/// key the two spellings can drift apart on while each side stays consistent with itself.
pub const META_PROTOCOL_VERSION: &str = busbar_mcp_codec::codec::META_PROTOCOL_VERSION;

/// The metadata key naming what the caller can answer if asked. The codec's, for the reason
/// [`META_PROTOCOL_VERSION`] states.
pub const META_CLIENT_CAPABILITIES: &str = busbar_mcp_codec::codec::META_CLIENT_CAPABILITIES;

/// The metadata key naming a token progress should be reported under.
pub const META_PROGRESS_TOKEN: &str = "progressToken";

/// The same key as it appears on the wire, quoted, ready to be looked for.
///
/// A member is found in a document by its QUOTED name, and the quoted form of a constant is itself
/// a constant. Building it per request — once per metadata key, on every request that carries a
/// metadata block — spends a heap allocation to spell out something that was known when the crate
/// was compiled. The pair below is checked against the unquoted names by a test in this module, so
/// the two spellings cannot drift apart without the drift being said out loud.
pub const META_PROTOCOL_VERSION_QUOTED: &[u8] = b"\"io.modelcontextprotocol/protocolVersion\"";

/// The progress-token key as it appears on the wire, quoted. See
/// [`META_PROTOCOL_VERSION_QUOTED`].
pub const META_PROGRESS_TOKEN_QUOTED: &[u8] = b"\"progressToken\"";

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
    /// A VALUE comparison. This read the server half's SOURCE once, with `include_str!` over
    /// `../../busbar-mcp/src/…` — a coupling to a sibling crate the manifest does not name, which
    /// left this plane unable to be built or deleted on its own. Both keys are the codec's now, so
    /// a spelling can no longer differ between the side that requires it inbound and the side that
    /// writes it outbound. The same keys stay pinned against the conformance battery's own table in
    /// the integration tests.
    #[test]
    fn the_metadata_keys_are_the_codecs_own() {
        assert_eq!(
            super::META_PROTOCOL_VERSION,
            busbar_mcp_codec::codec::META_PROTOCOL_VERSION
        );
        assert_eq!(
            super::META_CLIENT_CAPABILITIES,
            busbar_mcp_codec::codec::META_CLIENT_CAPABILITIES
        );
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
}
