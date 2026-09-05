//! The fact keys this plane writes, and how a request identifier becomes a correlation.
//!
//! A fact is evidence. It is never an amount, never a decision and never a credential. Everything
//! here is something the plane READ off the bytes, reported under a key it declared up front so the
//! kernel's fact maps can be sized before the first frame arrives.

use busbar_contract::ids::CorrelationRef;

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
/// ## The mismatch this function exists to bridge, stated plainly
///
/// The contract's correlation reference carries a whole number. This protocol's request identifier
/// is a JSON scalar, which the codec accepts as EITHER a string OR a number and refuses in every
/// other shape. A string identifier therefore has no whole number to be.
///
/// So the reference carries a whole number DERIVED from the identifier's raw bytes, and the raw
/// bytes travel beside it as a fact under the same key. The kernel correlates on the number; the
/// encoder echoes the bytes. Nothing reconstructs an identifier from the number, because nothing
/// can.
///
/// A number that fits is used as itself, so the overwhelmingly common case — a small counter — is
/// exact and readable in a journal row. Anything else is digested.
///
/// ## The exposure, stated rather than hidden
///
/// Two different identifiers can digest to one number. The kernel's correlation key is the session,
/// the principal, the fact key and the value together, so the exposure is bounded to two in-flight
/// requests of ONE principal on ONE session colliding on a sixty-four-bit digest. That is a finding
/// about the contract's correlation type, not a property of this protocol, and it is written down
/// in the crate's notes.
#[must_use]
pub fn correlation_for(raw_id: &[u8]) -> CorrelationRef {
    CorrelationRef {
        fact_key: FACT_RPC_ID,
        value: id_value(raw_id),
    }
}

/// The whole number that stands for one request identifier's raw bytes.
///
/// Deterministic over the bytes and over nothing else: no clock, no address, no seed. The
/// determinism test depends on that.
#[must_use]
pub fn id_value(raw_id: &[u8]) -> u64 {
    // A bare run of decimal digits IS a whole number, and using it as itself keeps the common case
    // exact. Anything with a sign, a point, an exponent, quotes or more digits than fit is digested.
    if !raw_id.is_empty() && raw_id.len() <= 19 && raw_id.iter().all(u8::is_ascii_digit) {
        let mut n: u64 = 0;
        for byte in raw_id {
            n = n * 10 + u64::from(byte - b'0');
        }
        return n;
    }
    digest(raw_id)
}

/// A sixty-four-bit digest of some bytes.
///
/// The multiply-and-mix construction is written out rather than taken from a dependency, because a
/// plane's dependency list is a surface and a hash is four lines. It is not a cryptographic hash and
/// nothing here treats it as one: it stands in for an identifier the contract's correlation type
/// cannot hold, and the identifier itself travels beside it.
#[must_use]
pub fn digest(bytes: &[u8]) -> u64 {
    // The offset and the prime are the published constants of the standard sixty-four-bit variant.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    // A digested identifier must never collide with a small counter used as itself, or a request
    // numbered seven and a request named something that digests to seven would be one request. The
    // top bit is set to move every digest above the range a bare decimal run can reach.
    hash | (1 << 63)
}

#[cfg(test)]
mod tests {
    use super::{correlation_for, digest, id_value, FACT_RPC_ID};

    /// A small counter is used as itself, so a journal row reads as the caller wrote it.
    #[test]
    fn a_bare_number_is_itself() {
        assert_eq!(id_value(b"1"), 1);
        assert_eq!(id_value(b"7"), 7);
        assert_eq!(id_value(b"9007199254740993"), 9_007_199_254_740_993);
    }

    /// A quoted identifier is digested, and the digest is above every bare counter.
    ///
    /// This is the property the digest's top-bit set exists for: a named request can never be taken
    /// for a numbered one.
    #[test]
    fn a_named_identifier_cannot_collide_with_a_numbered_one() {
        let named = id_value(br#""a2a-http-json""#);
        assert!(named >= 1 << 63);
        for n in 0u64..1000 {
            assert_ne!(named, n);
        }
    }

    /// Anything that is not a bare run of digits is digested, including the near misses.
    #[test]
    fn the_near_misses_are_digested() {
        for raw in [
            &b"-1"[..],
            &b"1.0"[..],
            &b"1e3"[..],
            &b""[..],
            &b"01234567890123456789"[..],
        ] {
            assert!(id_value(raw) >= 1 << 63, "{raw:?} was not digested");
        }
    }

    /// The same bytes always give the same value.
    #[test]
    fn the_value_is_deterministic() {
        for raw in [&b"42"[..], &br#""abc""#[..], &b"null"[..]] {
            assert_eq!(id_value(raw), id_value(raw));
            assert_eq!(digest(raw), digest(raw));
        }
    }

    /// Different identifiers give different values, over the identifiers the rigs actually send.
    #[test]
    fn the_identifiers_the_rigs_send_do_not_collide() {
        let seen: Vec<u64> = [
            &b"1"[..],
            &b"2"[..],
            &br#""a2a-http-json""#[..],
            &br#""a2asup-ver-declared""#[..],
            &br#""r1""#[..],
        ]
        .iter()
        .map(|r| id_value(r))
        .collect();
        for (i, v) in seen.iter().enumerate() {
            assert!(!seen[..i].contains(v), "two rig identifiers collide on {v}");
        }
    }

    /// The correlation carries the declared key and the identifier's value.
    #[test]
    fn the_correlation_carries_the_declared_key() {
        let c = correlation_for(b"7");
        assert_eq!(c.fact_key, FACT_RPC_ID);
        assert_eq!(c.value, 7);
    }
}
