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
#[path = "tests/facts.rs"]
mod tests;
