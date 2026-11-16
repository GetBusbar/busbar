// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The settled part of an `open` answer, every kind (IF §8.8, round 31 §47, round 33 §49): INSTANCE, then an
//! optional CONFIG and CORE_CFG*. The decoder is kind-blind. It stops before a last record tagged
//! `export::tag::CUSTODY`, which A9's `decode_ceiling` reads; any other record there is `RecErr::Unknown`.

use busbar_plugin_abi::host_side::answer::Answer;
use busbar_plugin_abi::kinds::export::export::tag::CUSTODY;
use busbar_plugin_abi::records::{core_cfg, tag, CoreCfgRec, Rec, RecErr, Records};

use crate::SettledOut;

pub fn decode_settled<'o>(a: &Answer<'o>) -> Result<Option<SettledOut<'o>>, RecErr> {
    settled_records(a.records())
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
