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
//! | destination unreachable | every dialect | 503 | the overloaded envelope |
//! | group frozen | every dialect | 403 | `permission_error`, "... group 'X' is disabled" |
//!
//! The last row is pinned from 1.5.5's source (its limit refusal for a disabled group: 403, the
//! permission kind) until the oracle records the cell (ARCHITECT ruling, 2026-09-30); the rest are
//! proved against recorded cells.
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
pub const REFUSAL_STATUSES: [RefusalStatus; 5] = [
    row(dialect_index("bedrock"), reason::UNAUTHENTICATED, 403),
    row(dialect_index("gemini"), reason::UNAUTHENTICATED, 400),
    row(dialect_index("bedrock"), reason::OVER_BUDGET, 400),
    row(REFUSAL_ANY_DIALECT, reason::DESTINATION_UNREACHABLE, 503),
    row(REFUSAL_ANY_DIALECT, reason::GROUP_FROZEN, 403),
];
