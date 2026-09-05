//! The fact keys this plane writes, and how a request identifier becomes a correlation.
//!
//! A fact is evidence. It is never an amount, never a decision and never a credential. Everything
//! here is something the plane READ off the bytes, reported under a key it declared up front so the
//! kernel's fact maps can be sized before the first frame arrives.

use busbar_contract::ids::CorrelationRef;

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
/// ## The mismatch this function exists to bridge, stated plainly
///
/// The contract's correlation reference carries a whole number. This protocol's request identifier
/// is a JSON scalar, which the shared reader accepts as EITHER a string OR a number and refuses in
/// every other shape. A string identifier therefore has no whole number to be.
///
/// So the reference carries a whole number DERIVED from the identifier's raw bytes, and the raw
/// bytes travel beside it as a fact under the same key. The kernel correlates on the number; the
/// encoder echoes the bytes. Nothing reconstructs an identifier from the number, because nothing
/// can.
///
/// A number that fits is used as itself, so the overwhelmingly common case — a small counter, which
/// is what every fixture in the conformance battery sends — is exact and readable in a journal row.
/// Anything else is digested.
///
/// ## The exposure, stated rather than hidden
///
/// Two different identifiers can digest to one number. The kernel's correlation key is the session,
/// the principal, the fact key and the value together, so the exposure is bounded to two in-flight
/// requests of ONE principal on ONE session colliding on a sixty-four-bit digest. That is a finding
/// about the contract's correlation type, not a property of this protocol, and it is written down in
/// the crate's notes.
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
    ///
    /// Every request the conformance battery sends is numbered, so this is the case that matters
    /// most: the battery's own identifiers arrive in a journal as the battery wrote them.
    #[test]
    fn a_bare_number_is_itself() {
        for n in 0u64..64 {
            assert_eq!(id_value(n.to_string().as_bytes()), n);
        }
    }

    /// A quoted identifier is digested, and the digest is above every bare counter.
    #[test]
    fn a_named_identifier_cannot_collide_with_a_numbered_one() {
        let named = id_value(br#""req-1""#);
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

    /// The correlation carries the declared key and the identifier's value.
    #[test]
    fn the_correlation_carries_the_declared_key() {
        let c = correlation_for(b"7");
        assert_eq!(c.fact_key, FACT_RPC_ID);
        assert_eq!(c.value, 7);
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
