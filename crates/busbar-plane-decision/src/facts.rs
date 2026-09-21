//! The fact keys this plane writes, and the ones it deliberately never does.
//!
//! A fact is evidence. It is never an amount, never a decision and never a credential — and here it
//! is never the decision CONTENT either. jev's `systemone` request carries a caller-supplied
//! `state`; its response (success or 422) carries the provider's `answers`. Both are the payload a
//! `decision` plane exists to move, not evidence a fact map should carry forward into a record or
//! an export. So this module declares metadata keys ONLY, and `codec.rs`'s declared-pointer list —
//! the only pointers this plane ever resolves — has no entry for either member. A key that is never
//! declared here cannot leak through `Facts::set`, because nothing in this crate ever builds the
//! value to set it to.

/// Which of the two operations a request was, as the wire spelled the path.
pub const FACT_OP: &str = "op";

/// The request identifier the caller or the provider's answer carried, where either did.
///
/// jev correlates on `x-typesafe-request-id` where the transport surfaces it as a fact, or on a
/// body-level `id`/`request_id` member — plain metadata, never the decision content.
pub const FACT_REQUEST_ID: &str = "request_id";

/// Whether the response carried a top-level `error` member.
///
/// This is how the metering step tells a billable success from a 4xx without reading the decision
/// content: `error` present means nothing is metered; absent means the usage pointer (if the
/// response carried one) is read.
pub const FACT_HAS_ERROR: &str = "has_error";

/// The provider's own billing unit count for a `systemone` call, where a success response reports
/// one. Metadata about HOW MUCH was billed, never WHAT was decided.
pub const FACT_USAGE_UNITS: &str = "usage_units";

/// The session fact keys this plane writes.
///
/// jev has no session-scoped identity of its own beyond the provider it was dialled against — the
/// provider name IS the session-scoped fact, because a session's provider changing mid-flight would
/// be a different priced thing.
pub const SESSION_FACTS: &[&str] = &[FACT_REQUEST_ID];

/// The content fact keys this plane produces.
///
/// What the record and the export path receive: which operation this was, whether it errored, and
/// how much was billed. Never the `state` a caller sent and never the `answers` a provider
/// returned — see the module note.
pub const CONTENT_FACTS: &[&str] = &[FACT_OP, FACT_HAS_ERROR, FACT_USAGE_UNITS];

/// The literal member names this plane forbids itself from ever resolving a pointer at.
///
/// Not read anywhere in this crate's decode/encode path — listed here once, so the PII witness test
/// (`tests/pii_witness.rs`) and a reviewer both have one place that names the two members a
/// `decision` plane's whole design exists to keep off the fact/record surface.
pub const NEVER_READ_MEMBERS: &[&str] = &["state", "answers"];

#[cfg(test)]
#[path = "tests/facts.rs"]
mod tests;
