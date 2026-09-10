//! What this control surface declares about itself.
//!
//! Everything here is a constant, because everything here is read once at registration and sealed
//! into policy — the same rule every declaration in this workspace states.

use busbar_contract::control::{ControlMeta, ControlRoute};
use busbar_contract::ids::OpClassId;

use crate::claims;
use crate::verbs::{OP_READ, OP_WRITE};
use crate::AdminControl;

/// The two operation classes a unit of this surface can be: a read that reaches nothing but the
/// journal, and a mutation. See [`crate::verbs::OP_READ`]/[`crate::verbs::OP_WRITE`] for why the
/// declared table collapses to two classes rather than one per operation: a control surface prices
/// nothing at all, so the only thing an operation class needs to preserve here is the design's own
/// `ReadOnly`/`Full` split, for the audit call's dispute check to mean something.
///
/// AND THAT IS ALSO WHY THIS FACE HAS NO METER DECLARATION TO MAKE. The kind is unmetered by
/// definition: every operation posts zero, `count` is kernel-reserved and the registry would refuse
/// it from a surface that tried to declare one. The plane face made that a constant a surface had to
/// spell as empty; the control face does not have the field, which is the same fact stated once.
const OP_CLASSES: &[OpClassId] = &[OP_READ, OP_WRITE];

/// The fact key the loop stamps the resolved operation under, going in and coming back.
pub(crate) const FACT_VERB: &str = "verb";

/// This surface's configuration schema: an empty object.
///
/// The admin surface's claim (one prefix, one credential scheme) needs no operator-configured
/// knob distinct from the credential and scope machinery `busbar-unit-verbs`/the scope unit already
/// own; there is nothing to configure and no secret ref a surface config could smuggle in.
const CONFIG_SCHEMA: &str = r#"{"type":"object","additionalProperties":false,"properties":{}}"#;

impl ControlMeta for AdminControl {
    const KEY: &'static str = "admin";
    const CLAIMS: &'static [busbar_contract::grammar::Claim] = claims::CLAIMS;
    // THE ONE DECLARED CLAIM. The route table as data is this kind's whole open vocabulary, and
    // this is where the surface says it: every `(method, path)` pair it answers, which operation
    // each one is, and which side of the closed read-only/full split it falls on. The loop resolves
    // an arriving request against exactly this, so there is no second reading anywhere for it to
    // drift from.
    const ROUTES: &'static [ControlRoute] = crate::verbs::declared();
    const OP_CLASSES: &'static [OpClassId] = OP_CLASSES;
    const CONFIG_SCHEMA: &'static str = CONFIG_SCHEMA;
}
