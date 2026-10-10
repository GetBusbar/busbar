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
//! | over budget | bedrock | 400 | `ServiceQuotaExceededException` |
//! | no rate | every dialect | 400 | `invalid_request_error`, "no configured rate for model 'X'" |
//! | no destination | every dialect | 404 | `not_found_error`, the dialect's model-not-found sentence |
//! | scheme not declared | every dialect | 400 | none: this plane's status before the one classification |
//! | challenge exhausted | every dialect | 503 | none: this plane's status before the one classification |
//! | cursor budget | every dialect | 503 | none: this plane's status before the one classification |
//! | credential budget | every dialect | 503 | none: this plane's status before the one classification |
//!
//! The no-destination row is pinned from 1.5.5's source (a model that names no pool and no
//! configured model answers the dialect's not-found envelope, 404) until the oracle records its cell
//! (ARCHITECT ruling Q-FL3, 2026-10-02). The rest of the first four are proved against recorded
//! cells.
//!
//! The kernel's default is a status per refusal CLASS (`busbar_contract::abi::plane::RefusalClass`,
//! the one classification; the P-item "refusal-reason collapse"). Two rows this plane used to state
//! are now the class default and are gone: destination unreachable answers 503 (its class,
//! `Unreachable`; proved against the recorded `upstream_down` cells) and a frozen group 403 (its
//! class, `Forbidden`; 1.5.5's limit refusal for a disabled group). The last four rows go the other
//! way: their reasons joined a class whose default differs from what this plane answered, and no
//! 1.5.5 cell records them, so each keeps this plane's answer and no llm byte moves.
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
pub const REFUSAL_STATUSES: [RefusalStatus; 9] = [
    row(dialect_index("bedrock"), reason::UNAUTHENTICATED, 403),
    row(dialect_index("gemini"), reason::UNAUTHENTICATED, 400),
    row(dialect_index("bedrock"), reason::OVER_BUDGET, 400),
    row(REFUSAL_ANY_DIALECT, reason::NO_RATE, 400),
    row(REFUSAL_ANY_DIALECT, reason::NO_DESTINATION, 404),
    row(REFUSAL_ANY_DIALECT, reason::SCHEME_NOT_DECLARED, 400),
    row(REFUSAL_ANY_DIALECT, reason::CHALLENGE_EXHAUSTED, 503),
    row(REFUSAL_ANY_DIALECT, reason::CURSOR_BUDGET, 503),
    row(REFUSAL_ANY_DIALECT, reason::CREDENTIAL_BUDGET, 503),
];
