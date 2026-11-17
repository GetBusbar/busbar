// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! 1d, the open posture 1.5.5 implied (#358). 1.5.5 ran a config with no `auth:` block, or a null
//! one, as an open relay: every caller that reached the listener spent the configured provider
//! credentials. 1.6.0 refuses that omission (BUSBAR-8014, PRD-5: refuse rather than default open).
//! The 1.5.5 -> 1 step writes the posture 1.5.5 ran explicitly, [`OPEN_POSTURE`], so the upgraded
//! config still boots (PRD-4) and its open relay is the operator's written acknowledgement:
//! bannered at every boot and named `open_relay` in the `node.boot` audit event. A config stamped
//! for 1.6.0 that omits `auth:` is refused by validation; nothing writes the posture for it.

use busbar_contract::yaml::{MappingExt, Pairs, Value, ValueExt};

use crate::patch::schema_insert;

/// The explicit open-relay acknowledgement 1.6.0 reads: an `auth:` block whose data-plane `chain`
/// is written empty. It is the one key every reader of the operator's open posture uses.
pub(crate) const OPEN_POSTURE: &str = "auth: { chain: [] }";

/// Write `auth: { chain: [] }` where 1.5.5 ran the open relay by omission, decided on the resolved
/// document as 1.5.5 decided it. A written `auth:` block, open or not, is kept as written.
pub(crate) fn write_open_posture(root: &mut Pairs, resolved: &Value, report: &mut Vec<String>) {
    if resolved.get("auth").is_some_and(|auth| !auth.is_null()) {
        return;
    }
    let posture = Value::Map(vec![(Value::from("chain"), Value::Array(Vec::new()))]);
    match root.get_key_mut("auth") {
        Some(slot) => *slot = posture,
        None => schema_insert(root, "auth", posture),
    }
    report.push(format!(
        "auth: added `{OPEN_POSTURE}`, the open relay 1.5.5 ran a config with no `auth:` block \
         as (every caller that can reach the listener spends the configured provider credentials); \
         1.6.0 refuses that omission, so the block writes the posture down and every boot banners \
         it. Replace it with `auth: {{ chain: [keys] }}` and mint virtual keys through the admin \
         API before exposing busbar"
    ));
}
