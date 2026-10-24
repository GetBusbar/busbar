//! The statuses this plane's refusals wear where they are not the kernel's defaults.
//!
//! The kernel chooses a refusal's status from the plane's statement: the row for the unit's
//! dialect, else the row for every dialect, else its own default. What is stated here is what the
//! previous release answered and the kernel's default does not, each proved against the previous
//! release's recorded answer (the root's `tests/llm_refusal_statuses.rs`) or, where the oracle has
//! no cell yet, pinned from its source as noted below.
//!
//! | reason | dialect | status | the recorded answer |
//! |---|---|---|---|
//! | unauthenticated | bedrock | 403 | `AccessDeniedException` |
//! | unauthenticated | gemini | 400 | `API_KEY_INVALID` |
//! | scheme not declared | every dialect | 400 | none: this plane's status before the one classification |
//! | challenge exhausted | every dialect | 503 | none: this plane's status before the one classification |
//! | cursor budget | every dialect | 503 | none: this plane's status before the one classification |
//! | credential budget | every dialect | 503 | none: this plane's status before the one classification |
//!
//! The first two are proved against recorded cells.
//!
//! Over budget is NOT stated: it answers the class default, 429, on every dialect. 1.5.5 answered
//! 400 `ServiceQuotaExceededException` on bedrock, an exception Converse does not declare; the
//! bedrock refusal is now 429 `ThrottlingException`, a declared one (OWNER rule 22, 2026-10-14,
//! named conformance gaps are zero; accepted difference "C-22 bedrock budget refusal is a declared
//! Converse error").
//!
//! The kernel's default is a status per refusal CLASS (`busbar_contract::abi::plane::RefusalClass`,
//! the one classification; the P-item "refusal-reason collapse"). Four rows this plane used to state
//! are now the class default and are gone: destination unreachable answers 503 (its class,
//! `Unreachable`; proved against the recorded `upstream_down` cells), a frozen group 403 (its
//! class, `Forbidden`; 1.5.5's limit refusal for a disabled group), and, since a policy refusal
//! answers its 4xx rather than 503 (ARCHITECT ruling: a policy refusal is a refusal, not a server
//! fault), no rate 400 (its class, `Rejected`; proved against the recorded
//! `http.crosscut|unknown-path|openai-suffix` cell, `invalid_request_error`, "no configured rate for
//! model 'X'") and no destination 404 (its class, `NotFound`; 1.5.5's not-found envelope with the
//! dialect's model-not-found sentence, pinned from 1.5.5's source, ARCHITECT ruling Q-FL3,
//! 2026-10-02). The last four rows go the other way: their reasons joined a class whose default
//! differs from what this plane answered, and no 1.5.5 cell records them, so each keeps this
//! plane's answer and no llm byte moves.
//!
//! The policy-refusal ruling moved the rest of the `Rejected` and `Busy` classes off 503 (unpriced,
//! replayed, superseded and method-not-allowed now 400; in-flight cap and in-flight 429). No row
//! keeps 503 for any of them: no 1.5.5 cell records one (1.5.5 answered an unbillable name 400
//! `invalid_request_error` and its in-flight limit 429 `rate_limit_error`, the kinds this plane
//! already renders those classes in; its wrong-method 405 is the kernel's own stated status, and
//! its node-wide inbound shed 503 is the router's, neither a class default).
//!
//! A hook's veto is not stated here: the hook's own status rides the refusal.

use busbar_contract::abi::plane::{RefusalStatus, REFUSAL_ANY_DIALECT};

use crate::dialect::DIALECTS;

/// The place of `name` in [`DIALECTS`], the order the plane states its dialects in.
const fn dialect_index(name: &str) -> u32 {
    let mut i = 0;
    while i < DIALECTS.len() {
        if same(DIALECTS[i].name.as_bytes(), name.as_bytes()) {
            return i as u32;
        }
        i += 1;
    }
    panic!("a refusal status names a dialect the plane does not state");
}

const fn same(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// The reason codes this plane states a status for: each a reason's place in the plane ABI's
/// refusal vocabulary (`busbar_contract::abi::plane::reason_of`), pinned to its spelling by
/// `tests/refusal_statuses.rs`.
pub mod reason {
    /// `unauthenticated`: no credential resolved to a principal.
    pub const UNAUTHENTICATED: u32 = 12;
    /// `over_budget`: a spend cap blocked the unit.
    pub const OVER_BUDGET: u32 = 20;
    /// `destination_unreachable`: no member of the pool answered.
    pub const DESTINATION_UNREACHABLE: u32 = 31;
    /// `group_frozen`: the caller's group is disabled.
    pub const GROUP_FROZEN: u32 = 21;
    /// `no_rate`: a rate card is configured and the model it would bill names no rate.
    pub const NO_RATE: u32 = 17;
    /// `no_destination`: the arrival's model names no pool and no configured model.
    pub const NO_DESTINATION: u32 = 19;
    /// `scheme_not_declared`: the plane narrowed to an auth scheme its claim never declared.
    pub const SCHEME_NOT_DECLARED: u32 = 10;
    /// `challenge_exhausted`: a challenge exchange ran past its round or byte bound.
    pub const CHALLENGE_EXHAUSTED: u32 = 13;
    /// `cursor_budget`: the node-global connection-cursor budget is exhausted.
    pub const CURSOR_BUDGET: u32 = 1;
    /// `credential_budget`: the per-connection credential slab could not hold the credential.
    pub const CREDENTIAL_BUDGET: u32 = 2;
}

const fn row(dialect: u32, reason: u32, status: u32) -> RefusalStatus {
    RefusalStatus {
        dialect,
        reason,
        status,
        _reserved: 0,
    }
}

/// The plane's refusal statuses, in its statement's order.
pub const REFUSAL_STATUSES: [RefusalStatus; 6] = [
    row(dialect_index("bedrock"), reason::UNAUTHENTICATED, 403),
    row(dialect_index("gemini"), reason::UNAUTHENTICATED, 400),
    row(REFUSAL_ANY_DIALECT, reason::SCHEME_NOT_DECLARED, 400),
    row(REFUSAL_ANY_DIALECT, reason::CHALLENGE_EXHAUSTED, 503),
    row(REFUSAL_ANY_DIALECT, reason::CURSOR_BUDGET, 503),
    row(REFUSAL_ANY_DIALECT, reason::CREDENTIAL_BUDGET, 503),
];
