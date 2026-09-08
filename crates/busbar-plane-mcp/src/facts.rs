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
/// calls of one principal on one session answer to each other — the collision the digest was removed
/// for, arriving by a different road. The canonical spelling is the number; every other spelling of
/// it is carried as the text it is, and text never equals a number.
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
#[path = "tests/facts.rs"]
mod tests;
