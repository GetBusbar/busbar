// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE REFERENCE HOOK (hook 3.0): the smallest image that names every hook element the revision keeps and none
//! it removes. It declares the sync `on` for the three decision points and no `FB_*` fact (it reads no prompt;
//! `FB_WANTS_BODY` is gone from the contract and `FB_WANTS_IDENTITY` is not asked for).
//!
//! `on(point, view)` crosses by the one call shape: head `point u32`, `blobs[0]` = the view's records. It
//! answers:
//! - POINT_ROUTE: PREFER with the candidates in the order the view lists them (an identity ORDER), so a host
//!   that hands candidates over wrongly indexed gets an ORDER it refuses;
//! - POINT_REWRITE: ABSTAIN;
//! - POINT_NOTIFY: ABSTAIN, after HOLDING THE HOST TO THE STAGE VOCABULARY: a stage tap's `S_STAGE` must be one
//!   of `STAGE_CANDIDATE`, `STAGE_ROUTING`, `STAGE_RESPONSE`; any other number is REFUSED R_INVALID naming it.
//!
//! It records what it was called with (`SEEN`), so the boundary test reads back the point and the stage.

use std::sync::Mutex;

use busbar_plugin_abi::fail::refused::{R_CONFIG, R_INVALID};
use busbar_plugin_abi::fail::Fail;
use busbar_plugin_abi::hook::{self, CandidateRec, Verdict};
use busbar_plugin_abi::host::Host;
use busbar_plugin_abi::need::ChainBytes;
use busbar_plugin_abi::plugin::{Describe, Endpoints, Open};
use busbar_plugin_abi::records::{tag as record, FactRec, Out, Records, Writer};
use busbar_plugin_abi::types::Bytes;
use busbar_plugin_abi::Hook;

/// One `on` call as the plugin read it: the point, the stage of a stage tap, the candidates counted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Seen {
    pub point: u32,
    pub stage: Option<u64>,
    pub candidates: u32,
}

/// Every call to any instance of this image, in order.
pub static SEEN: Mutex<Vec<Seen>> = Mutex::new(Vec::new());

/// The reference hook.
pub struct RefHook;

/// What the view holds that this hook reads: the stage fact and the candidate indices, in view order.
fn read(view: &[u8]) -> Result<(Option<u64>, Vec<u32>), Fail> {
    let (mut stage, mut order) = (None, Vec::new());
    for rec in Records::new(view) {
        let rec = rec.map_err(|_| Fail::refused_because(R_INVALID, "the view does not frame"))?;
        if rec.tag == record::FACT {
            let fact = rec
                .pod::<FactRec>()
                .map_err(|_| Fail::refused_because(R_INVALID, "a FACT is not a FactRec"))?;
            if fact.key == hook::S_STAGE {
                stage = Some(fact.value);
            }
        } else if rec.tag == hook::tag::CANDIDATE {
            let (candidate, _tail) = rec.pod_tail::<CandidateRec>().map_err(|_| {
                Fail::refused_because(R_INVALID, "a CANDIDATE is not a CandidateRec")
            })?;
            order.push(candidate.index);
        }
    }
    Ok((stage, order))
}

fn verdict(out: &mut Out<'_>, verb: u32) -> Result<(), Fail> {
    out.put_pod(
        hook::tag::VERDICT,
        &Verdict {
            verb,
            reject_status: 0,
        },
    )
    .map_err(Fail::from)
}

impl Open for RefHook {
    async fn open(_h: &'static Host, config: ChainBytes) -> Result<Self, Fail> {
        config.with(check_config)?;
        Ok(RefHook)
    }

    fn check(_h: &Host, config: &[u8], _ends: &mut Endpoints<'_>) -> Result<(), Fail> {
        check_config(config)
    }

    fn describe(d: &mut Describe<'_>) {
        // Points { mask, _r }: the three decision points, little-endian, eight bytes.
        let mask: u32 =
            (1 << hook::POINT_ROUTE) | (1 << hook::POINT_REWRITE) | (1 << hook::POINT_NOTIFY);
        let mut points = [0u8; 8];
        points[..4].copy_from_slice(&mask.to_le_bytes());
        d.schema(r#"{"type":"object"}"#);
        d.methods(hook::M_ON);
        d.item(hook::tag::D_POINTS, &points);
    }
}

fn check_config(config: &[u8]) -> Result<(), Fail> {
    busbar_contract::json::parse::<std::collections::HashMap<String, String>>(config)
        .map(|_| ())
        .map_err(|_| Fail::refused_because(R_CONFIG, "config must be an object"))
}

impl Hook for RefHook {
    fn on(&self, _h: &Host, point: u32, view: Bytes<'_>, out: &mut Out<'_>) -> Result<(), Fail> {
        let (stage, order) = read(view.get())?;
        if let Ok(mut seen) = SEEN.lock() {
            seen.push(Seen {
                point,
                stage,
                candidates: order.len() as u32,
            });
        }
        match point {
            hook::POINT_ROUTE if !order.is_empty() => {
                verdict(out, hook::VERB_PREFER)?;
                let mut indices = Vec::with_capacity(order.len() * 4);
                for index in &order {
                    indices.extend_from_slice(&index.to_le_bytes());
                }
                out.put(hook::tag::ORDER, &indices).map_err(Fail::from)
            }
            hook::POINT_NOTIFY => {
                match stage {
                    None
                    | Some(hook::STAGE_CANDIDATE | hook::STAGE_ROUTING | hook::STAGE_RESPONSE) => {}
                    Some(other) => {
                        return Err(Fail::refused_because(
                            R_INVALID,
                            format!("stage {other} is no stage of hook 3"),
                        ))
                    }
                }
                verdict(out, hook::VERB_ABSTAIN)
            }
            _ => verdict(out, hook::VERB_ABSTAIN),
        }
    }
}

busbar_plugin_abi::plugin!(Hook, RefHook, name: "reference-hook");
