// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The settled part of an `open` answer, every kind (IF §8.8, round 31 §47, round 33 §49): INSTANCE, then an
//! optional CONFIG and CORE_CFG*. The decoder is kind-blind. It stops before a last record tagged
//! `export::tag::CUSTODY`, which A9's `decode_ceiling` reads; any other record there is `RecErr::Unknown`.

use busbar_contract::json::{self, JsonContainerTrait, JsonValueTrait};
use busbar_plugin_abi::host_side::answer::Answer;
use busbar_plugin_abi::host_side::caller::InstanceLimits;
use busbar_plugin_abi::kinds::export::export::tag::CUSTODY;
use busbar_plugin_abi::records::{core_cfg, tag, CoreCfgRec, Rec, RecErr, Records};

use crate::SettledOut;

pub fn decode_settled<'o>(a: &Answer<'o>) -> Result<Option<SettledOut<'o>>, RecErr> {
    settled_records(a.records())
}

/// The longest any limits duration may be (IF §12.22), in milliseconds.
pub const MAX_LIMIT_MS: u32 = 600_000;
/// The most concurrent port calls an instance may be held to (IF §12.22).
pub const MAX_INFLIGHT: u32 = 65_535;

/// `base` with the answer's LIMITS fragment (the old bag's timeout and concurrency, handed back by a migrating
/// `open`) applied in memory: every number the kind default left unset (0) takes the plugin's value, clamped to
/// [`MAX_LIMIT_MS`] and [`MAX_INFLIGHT`]. Nothing is filed into config.yaml; a boot that migrates nothing carries no
/// fragment and the instance runs at the kind's defaults.
pub fn settled_limits(base: InstanceLimits, a: &Answer<'_>) -> InstanceLimits {
    let Ok(Some(out)) = decode_settled(a) else {
        return base;
    };
    for rec in out.core_cfg {
        let Ok(rec) = rec else { continue };
        let Ok((head, tail)) = rec.pod_tail::<CoreCfgRec>() else {
            continue;
        };
        if head.section != core_cfg::LIMITS {
            continue;
        }
        let value = usize::try_from(head.name_len)
            .ok()
            .and_then(|name_len| tail.get(name_len..));
        return value.map_or(base, |json| with_limits_json(base, json));
    }
    base
}

/// [`settled_limits`] over one LIMITS value (a JSON object): unknown keys and non-numbers are ignored.
pub fn with_limits_json(mut base: InstanceLimits, json: &[u8]) -> InstanceLimits {
    let Ok(value) = json::parse_value(json) else {
        return base;
    };
    let Some(map) = value.as_object() else {
        return base;
    };
    let pick = |key: &str, cap: u32| {
        map.get(key)
            .and_then(json::Value::as_u64)
            .map(|v| u32::try_from(v).unwrap_or(cap).min(cap))
    };
    if base.timeout_ms == 0 {
        base.timeout_ms = pick("timeout_ms", MAX_LIMIT_MS).unwrap_or(0);
    }
    if base.connect_timeout_ms == 0 {
        base.connect_timeout_ms = pick("connect_timeout_ms", MAX_LIMIT_MS).unwrap_or(0);
    }
    if base.max_inflight == 0 {
        base.max_inflight = pick("max_inflight", MAX_INFLIGHT).unwrap_or(0);
    }
    base
}

/// `[a-z0-9_.-]{1,64}`, except LIMITS and LIFT, which are always the opening instance's own (empty name).
fn name_ok(section: u32, name: &[u8]) -> bool {
    if matches!(section, core_cfg::LIMITS | core_cfg::LIFT) {
        return name.is_empty();
    }
    (1..=64).contains(&name.len())
        && name
            .iter()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-'))
}

/// One CORE_CFG record: its name follows the grammar and its value is UTF-8 (JSON is core's to parse).
fn core_cfg_ok(rec: &Rec<'_>) -> Result<(), RecErr> {
    let (head, tail) = rec.pod_tail::<CoreCfgRec>()?;
    let name_len = usize::try_from(head.name_len).map_err(|_| RecErr::Size)?;
    let (name, value) = tail.split_at_checked(name_len).ok_or(RecErr::Size)?;
    if !name_ok(head.section, name) {
        return Err(RecErr::Size);
    }
    core::str::from_utf8(value).map_err(|_| RecErr::Utf8)?;
    Ok(())
}

/// The grammar behind [`decode_settled`], over the answer's records (TOKEN already excluded).
fn settled_records(mut recs: Records<'_>) -> Result<Option<SettledOut<'_>>, RecErr> {
    match recs.next_rec().transpose()? {
        Some(rec) if rec.tag == tag::INSTANCE => {}
        Some(rec) => return Err(RecErr::Unknown(rec.tag)),
        None => return Err(RecErr::Truncated),
    }
    let mut config = None;
    // The answer's bytes from the first CORE_CFG on, and how many of them the CORE_CFG run takes.
    let mut core: Option<(&[u8], usize)> = None;
    loop {
        let before = recs.rest();
        let Some(rec) = recs.next_rec().transpose()? else {
            break;
        };
        match rec.tag {
            tag::CONFIG if config.is_none() && core.is_none() => {
                core::str::from_utf8(rec.body).map_err(|_| RecErr::Utf8)?;
                config = Some(rec.body);
            }
            tag::CORE_CFG if config.is_some() => {
                core_cfg_ok(&rec)?;
                let used = before.len() - recs.rest().len();
                core = Some(match core {
                    Some((start, taken)) => (start, taken + used),
                    None => (before, used),
                });
            }
            other if other == CUSTODY && recs.rest().is_empty() => break,
            other => return Err(RecErr::Unknown(other)),
        }
    }
    Ok(config.map(|config| SettledOut {
        config,
        core_cfg: match core {
            Some((start, taken)) => Records::new(start.get(..taken).unwrap_or_default()),
            None => Records::new(&[]),
        },
    }))
}

#[cfg(test)]
#[path = "settled_tests.rs"]
mod tests;
