// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE SCRIPT'S HOST (`conformance.json`'s `plane.host`): the kernel services a plane asks
//! on its crossings, served the way the kernel serves them, from tables the plugin's inputs state.
//!
//! * `entitlement.check` answers ENTITLED when the crossing serves a unit and a grant names the
//!   target (`"<scope kind>:<name>"`), for every unit or for the units it lists; a crossing that
//!   serves no unit is entitled to nothing (`KernelServices::entitled`'s rule).
//! * `trust.serves` answers the verdict a row states for `(counterparty, item)`; an item no row
//!   names is `DISTRUST_UNKNOWN_ITEM`.
//! * `clock.now` reads `0`, so what a plane stamps with the host's clock folds the same on both legs.
//! * Every other service is refused UNSERVED, as a host that serves none of it.
//!
//! ```json
//! "host": {
//!   "entitled": [ { "target": "<scope kind>:<name>", "units": [<unit>, ...] }, ... ],  // units optional
//!   "trusted":  [ ["<counterparty>", "<item>", "none" | "not_approved" | ...], ... ] }
//! ```

use busbar_contract::abi::host::service::{
    DISTRUST_CHANGED, DISTRUST_NONE, DISTRUST_NOT_APPROVED, DISTRUST_QUARANTINED, DISTRUST_UNKNOWN,
    DISTRUST_UNKNOWN_ITEM, DISTRUST_UNSIGHTED, ENTITLED, NOT_ENTITLED,
};
use busbar_contract::services::{
    Caller, DiskDest, HookAsk, NestAsk, RecordsList, Snapshot, UNSERVED,
};
use serde_json::Value;

use crate::dispatch::{HostServices, Ran, Reading, Stored};

/// The completion a pending service answer is handed (the services' own callback type): never
/// called here, every service this host does not serve is refused at once.
type Pended = Box<dyn FnOnce(Stored) + Send>;

/// One grant: its target, and the units it holds for (`None` = every unit).
struct Grant {
    target: String,
    units: Option<Vec<u64>>,
}

/// The host the inputs state.
pub(super) struct Host {
    entitled: Vec<Grant>,
    trusted: Vec<(String, String, u64)>,
}

/// A `trust.serves` verdict by its name.
fn verdict(name: &str) -> u64 {
    match name {
        "none" => DISTRUST_NONE,
        "unknown" => DISTRUST_UNKNOWN,
        "unsighted" => DISTRUST_UNSIGHTED,
        "quarantined" => DISTRUST_QUARANTINED,
        "not_approved" => DISTRUST_NOT_APPROVED,
        "changed" => DISTRUST_CHANGED,
        "unknown_item" => DISTRUST_UNKNOWN_ITEM,
        other => panic!("conformance.json: plane.host.trusted names no verdict `{other}`"),
    }
}

impl Host {
    /// The host `v` (`plane.host`) states; `None` when the inputs state none.
    pub(super) fn of(v: &Value) -> Option<Self> {
        if v.is_null() {
            return None;
        }
        let entitled = v["entitled"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|g| Grant {
                target: g["target"]
                    .as_str()
                    .unwrap_or_else(|| {
                        panic!("conformance.json: plane.host.entitled[].target must be a string")
                    })
                    .to_string(),
                units: g["units"].as_array().map(|u| {
                    u.iter()
                        .map(|n| {
                            n.as_u64().unwrap_or_else(|| {
                                panic!("conformance.json: plane.host.entitled[].units holds a non-number")
                            })
                        })
                        .collect()
                }),
            })
            .collect();
        let trusted = v["trusted"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|row| match row.as_array().map(Vec::as_slice) {
                Some([Value::String(c), Value::String(i), Value::String(v)]) => {
                    (c.clone(), i.clone(), verdict(v))
                }
                _ => panic!(
                    "conformance.json: plane.host.trusted rows are [\"<counterparty>\", \"<item>\", \"<verdict>\"]"
                ),
            })
            .collect();
        Some(Self { entitled, trusted })
    }
}

impl HostServices for Host {
    fn now(&self) -> Reading {
        Reading {
            wall_ns: 0,
            mono_ns: 0,
        }
    }

    fn entitlement_check(&self, _: &Caller, unit: Option<u64>, target: &str) -> Stored {
        let entitled = unit.is_some_and(|u| {
            self.entitled.iter().any(|g| {
                g.target == target && g.units.as_ref().is_none_or(|units| units.contains(&u))
            })
        });
        Stored::ready(if entitled { ENTITLED } else { NOT_ENTITLED })
    }

    fn trust_serves(
        &self,
        _: &Caller,
        counterparty: &str,
        item: Option<&str>,
        _: Option<&str>,
    ) -> Stored {
        let found = self
            .trusted
            .iter()
            .find(|(c, i, _)| c == counterparty && Some(i.as_str()) == item);
        Stored::ready(found.map_or(DISTRUST_UNKNOWN_ITEM, |(_, _, v)| *v))
    }

    fn dest_judge(&self, _: &str, _: u32, _: u32, _: Option<Pended>) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn records_get(&self, _: &Caller, _: &str, _: &[u8], _: Pended) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn records_list(&self, _: &Caller, _: RecordsList, _: Pended) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn records_claim(&self, _: &Caller, _: &str, _: &[u8], _: u64, _: Pended) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn sign(&self, _: &Caller, _: &[u8]) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn trust_sight(&self, _: &Caller, _: &str, _: &str, _: Pended) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn trust_due(&self, _: &Caller) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn trust_verify(&self, _: &Caller, _: &str, _: &[u8], _: &[u8]) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn random_fill(&self, _: u64) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn records_secret(&self, _: &str, _: &str, _: Pended) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn unit_nest(&self, _: &Caller, _: Option<u64>, _: NestAsk, _: Pended) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn work_open(&self, _: &Caller, _: Option<u64>, _: &str, _: &[u8], _: Pended) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn work_find(&self, _: &Caller, _: Option<u64>, _: &[u8], _: Pended) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn work_settle(&self, _: &Caller, _: Option<u64>, _: u64, _: &[u8], _: Pended) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn work_resume(&self, _: &Caller, _: Option<u64>, _: u64, _: Pended) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn disk_append(&self, _: &DiskDest, _: Vec<u8>, _: Pended) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn verify_lookup(&self, _: &Caller, _: &[u8], _: Pended) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn verify_store(&self, _: &Caller, _: &[u8], _: &[u8], _: u64) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn content_scan(&self, _: &Caller, _: Option<u64>, _: &[u8], _: Pended) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn hook_call(&self, _: &Caller, _: Option<u64>, _: HookAsk, _: Pended) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn snapshot_read(&self, _: &Caller, _: u32) -> Snapshot {
        Snapshot::Refused(UNSERVED)
    }
}
