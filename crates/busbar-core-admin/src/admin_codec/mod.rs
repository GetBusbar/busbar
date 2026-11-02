//! The admin surface's own declarations: its closed verb table, its one claim, and the frozen

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod claims;
pub mod refusal;
#[cfg(test)]
mod tests;
pub mod verbs;

/// The key the admin surface's one claimant line is sealed under in the claim-precedence table
pub const KEY: &str = "admin";
