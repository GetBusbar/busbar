//! What this control surface declares about itself.
//!
//! A control surface is not a plane: it declares no meter classes, no session facts, no record
//! schemas, no egress pacing and no plane config block — it has no data path for any of those to
//! describe. All that remains is the registry key it is known by and the one content-fact key its
//! codec stamps. Both are plain constants; there is no `PlaneMeta` here, because there is no plane.

/// The key this control surface is known by. The unit-side seam
/// (`busbar::root::units_admin`) registers its verb-execution under the same word.
pub const KEY: &str = "admin";

/// The fact key under which the codec records which verb a response answered, and reads it back off
/// the sealed draft facts at `verify`/`approve`.
pub(crate) const FACT_VERB: &str = "verb";
