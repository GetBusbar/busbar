// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Direct Bootstrap evidence only. Delegated authority requires the separate ordered proof.

use super::*;
use busbar_kernel_audit::{BreakNotice, BreakReason, Stamp, StampKind};

fn signature(value: &Value) -> Result<Vec<u8>> {
    let signature = text(value, "signature")?;
    if !hex(signature, 64) {
        return Err("a stamp or break signature is not canonical lowercase hex");
    }
    hex::decode(signature).map_err(|_| "invalid signature")
}

fn stamp(value: &Value) -> Result<Stamp> {
    let fingerprint = text(value, "fingerprint")?;
    if !hex(fingerprint, 32) {
        return Err("a stamp fingerprint is not canonical lowercase hex");
    }
    let stamp = Stamp {
        node: number(value, "node")?,
        from: number(value, "from")?,
        to: number(value, "to")?,
        fingerprint: Fingerprint::from_hex(fingerprint).ok_or("invalid stamp fingerprint")?,
        kind: StampKind::from_tag(text(value, "kind")?).ok_or("invalid stamp kind")?,
        sealer: number(value, "sealer")?,
        host: text(value, "host")?.to_owned(),
        every: number(value, "every")?,
        stamped_ms: number(value, "stamped_ms")?,
        down_from_ms: number(value, "down_from_ms")?,
        down_to_ms: number(value, "down_to_ms")?,
        crypto: text(value, "crypto")?.to_owned(),
        sig_alg: text(value, "sig_alg")?.to_owned(),
        key_id: text(value, "key_id")?.to_owned(),
        key_cert: number(value, "key_cert")?,
        signature: signature(value)?,
    };
    if (value.get("seq").is_some() && number(value, "seq")? != stamp.to)
        || (value.get("wall").is_some() && number(value, "wall")? != stamp.stamped_ms / 1000)
        || (value.get("hash").is_some() && text(value, "hash")? != fingerprint)
    {
        return Err("a stamp alias contradicts its signed field");
    }
    Ok(stamp)
}

fn notice(value: &Value) -> Result<BreakNotice> {
    Ok(BreakNotice {
        node: number(value, "node")?,
        sealer: number(value, "sealer")?,
        last_good: number(value, "last_good")?,
        unsealed_from: number(value, "unsealed_from")?,
        unsealed_to: number(value, "unsealed_to")?,
        journal_from: number(value, "journal_from")?,
        journal_to: number(value, "journal_to")?,
        reason: BreakReason::from_tag(text(value, "reason")?).ok_or("invalid break reason")?,
        detected_ms: number(value, "detected_ms")?,
        host: text(value, "host")?.to_owned(),
        crypto: text(value, "crypto")?.to_owned(),
        sig_alg: text(value, "sig_alg")?.to_owned(),
        key_id: text(value, "key_id")?.to_owned(),
        signature: signature(value)?,
    })
}

fn overlaps(a: u64, b: u64, c: u64, d: u64) -> bool {
    a <= b && c <= d && a <= d && c <= b
}

fn explained_gap(from: u64, to: u64, breaks: &BTreeMap<u64, BreakNotice>) -> bool {
    let mut next = from;
    for notice in breaks.values() {
        if notice.unsealed_to < next || notice.unsealed_from > notice.unsealed_to {
            continue;
        }
        if notice.unsealed_from > next {
            return false;
        }
        if notice.unsealed_to >= to {
            return true;
        }
        let Some(after) = notice.unsealed_to.checked_add(1) else {
            return false;
        };
        next = after;
    }
    false
}

pub(super) fn verify(
    keys: &BTreeMap<String, AuditVerifyingKey>,
    range: &Value,
    head: Option<&Value>,
) -> Result<Value> {
    if keys.len() != 1 {
        return Err(
            "linked verification requires one independently trusted deployment Bootstrap key",
        );
    }
    let key = keys.values().next().ok_or("the trusted key set is empty")?;
    let from = number(range, "from")?;
    let to = number(range, "to")?;
    if from == 0 || to < from {
        return Err("requested range must start at one or later and end at or after its start");
    }
    let records = range
        .get("records")
        .and_then(Value::as_array)
        .ok_or("records are absent")?;
    if u64::try_from(records.len()).ok() != Some(to - from + 1) {
        return Err("the requested fetch is incomplete or contains extra records");
    }
    let cover = range
        .get("cover")
        .and_then(Value::as_array)
        .ok_or("cover is absent")?;
    let walked: Vec<_> = records.iter().chain(cover).collect();
    let mut previous = None;
    let node = record_number(&records[0], "node")?;
    let mut authenticated = vec![false; records.len()];
    let mut legacy_signed = 0;
    for (index, line) in walked.iter().enumerate() {
        let seq = record_number(line, "seq")?;
        if from.checked_add(u64::try_from(index).map_err(|_| "record position overflow")?)
            != Some(seq)
        {
            return Err("records and cover are not consecutive");
        }
        if record_number(line, "node")? != node {
            return Err("a line names another node");
        }
        let prev = text(line, "prev_hash")?;
        if let Some(expected) = previous {
            if prev != expected {
                return Err("a record does not link to its predecessor");
            }
        } else if (seq == 1 && !prev.is_empty()) || (seq > 1 && !hex(prev, 32)) {
            return Err("the first record's predecessor is invalid");
        }
        let hash = text(line, "hash")?;
        if !hex(hash, 32) || record_digest(line, LINK_RECIPE)? != hash {
            return Err("a record does not hash to its published fields");
        }
        if text(line, "recipe")? != LINK_RECIPE {
            signed(line, keys)?;
            if let Some(checked) = authenticated.get_mut(index) {
                *checked = true;
                legacy_signed += 1;
            }
        }
        previous = Some(hash);
    }
    let values = range
        .get("stamps")
        .and_then(Value::as_array)
        .ok_or("stamps are absent")?;
    let mut pages: Vec<Stamp> = Vec::new();
    let mut breaks: BTreeMap<u64, BreakNotice> = BTreeMap::new();
    let mut break_rows = Vec::new();
    for value in values {
        if text(value, "kind")? == "break" {
            let notice = notice(value)?;
            let empty = notice.unsealed_to.checked_add(1) == Some(notice.unsealed_from);
            if notice.node != node
                || notice.unsealed_from == 0
                || notice.last_good >= notice.unsealed_from
                || (notice.unsealed_to < notice.unsealed_from && !empty)
                || (!empty && notice.journal_from > notice.journal_to)
            {
                return Err("invalid break range or node");
            }
            notice
                .verify(key)
                .map_err(|_| "a break signature is invalid")?;
            if breaks.values().any(|prior| {
                overlaps(
                    prior.unsealed_from,
                    prior.unsealed_to,
                    notice.unsealed_from,
                    notice.unsealed_to,
                )
            }) {
                return Err("break intervals overlap");
            }
            break_rows.push(json::json!({"node": notice.node, "sealer": notice.sealer,
                "last_good": notice.last_good, "unsealed_from": notice.unsealed_from,
                "unsealed_to": notice.unsealed_to, "journal_from": notice.journal_from,
                "journal_to": notice.journal_to, "reason": notice.reason.as_str(),
                "detected_ms": notice.detected_ms, "host": notice.host,
                "crypto": notice.crypto, "sig_alg": notice.sig_alg, "key_id": notice.key_id}));
            // Empty intervals remain reported, but cannot account for any missing position.
            if !empty {
                breaks.insert(notice.unsealed_from, notice);
            }
            continue;
        }
        let page = stamp(value)?;
        if page.from == 0 || page.to < page.from || page.node != node {
            return Err("invalid stamp range or node");
        }
        if page.kind != StampKind::AfterRestart && page.sealer != page.node {
            return Err("a live or final stamp names another sealer");
        }
        if pages.last().is_some_and(|last| page.from <= last.to) {
            return Err("stamp pages overlap or are out of order");
        }
        if page.key_cert != 0 {
            return Err(
                "delegated stamps require an ordered authority proof; unsupported by this verifier",
            );
        }
        page.verify(key)
            .map_err(|_| "a stamp signature is invalid")?;
        pages.push(page);
    }
    for page in &pages {
        if breaks
            .values()
            .any(|notice| overlaps(page.from, page.to, notice.unsealed_from, notice.unsealed_to))
        {
            return Err("a break overlaps a signed page");
        }
    }
    for pair in pages.windows(2) {
        let next = pair[0].to.checked_add(1).ok_or("page position overflow")?;
        if next < pair[1].from && !explained_gap(next, pair[1].from - 1, &breaks) {
            return Err("a gap between stamp pages has no signed break");
        }
    }
    let anchor = range.get("anchor").ok_or("range anchor member is absent")?;
    if !anchor.is_null() {
        stamp(anchor)?;
        if !values.iter().any(|value| value == anchor) {
            return Err("the source anchor is not an exact supplied page stamp");
        }
    }
    let mut accepted = Vec::new();
    let mut live = 0;
    let mut finals = 0;
    let mut restarts = Vec::new();
    let mut unchecked = 0;
    let mut crypto = std::collections::BTreeSet::new();
    for page in pages {
        let endpoint = page
            .to
            .checked_sub(from)
            .and_then(|index| usize::try_from(index).ok())
            .and_then(|index| walked.get(index));
        let Some(endpoint) = endpoint else {
            unchecked += 1;
            continue;
        };
        if text(endpoint, "hash")? != page.fingerprint.to_string() {
            return Err("a stamp fingerprint differs from its endpoint");
        }
        for (index, line) in walked.iter().enumerate() {
            let seq = record_number(line, "seq")?;
            if page.from <= seq && seq <= page.to {
                if text(line, "recipe")? != LINK_RECIPE {
                    return Err("a page covers a legacy line");
                }
                if let Some(checked) = authenticated.get_mut(index) {
                    *checked = true;
                }
            }
        }
        if overlaps(from, to, page.from, page.to) {
            match page.kind {
                StampKind::Live => live += 1,
                StampKind::Final => finals += 1,
                StampKind::AfterRestart => restarts.push(json::json!({"from": page.from.max(from), "to": page.to.min(to),
                    "down_from_ms": page.down_from_ms, "down_to_ms": page.down_to_ms, "sealer": page.sealer})),
            }
            crypto.insert(page.crypto.clone());
        }
        accepted.push(page);
    }
    let last_authenticated = accepted.last().map_or(0, |page| page.to);
    let mut tail_from = None;
    let mut authenticated_records = 0;
    for (index, checked) in authenticated.iter().enumerate() {
        if *checked {
            authenticated_records += 1;
            continue;
        }
        let seq = record_number(&records[index], "seq")?;
        if breaks
            .values()
            .any(|notice| notice.unsealed_from <= seq && seq <= notice.unsealed_to)
        {
            continue;
        }
        if seq <= last_authenticated {
            return Err("an interior line is covered by neither a stamp nor a signed break");
        }
        tail_from.get_or_insert(seq);
    }
    let complete = authenticated.iter().all(|checked| *checked)
        && !breaks
            .values()
            .any(|notice| overlaps(from, to, notice.unsealed_from, notice.unsealed_to))
        && unchecked == 0;
    let trusted = if let Some(head) = head {
        if envelope(head)? != LINK_RECIPE {
            return Err("a linked window requires a stamp head");
        }
        let terminal = stamp(head.get("head").ok_or("trusted head is empty")?)?;
        if terminal.to != to
            || number(head, "next_seq")? != to.checked_add(1).ok_or("head position overflow")?
        {
            return Err("the requested range does not end at the independently trusted head");
        }
        if !complete || !accepted.iter().any(|page| page == &terminal) {
            return Err("trusted head has incomplete coverage or is not a checked covering stamp");
        }
        true
    } else {
        false
    };
    let result = if trusted {
        Some("complete-through-trusted-head")
    } else if authenticated_records != 0 {
        Some("signed-consistent-window")
    } else {
        None
    };
    Ok(
        json::json!({"result": result, "from": from, "to": to, "records": records.len(),
        "starts_at_genesis": from == 1, "trusted_terminal_head": trusted,
        "source_anchor_is_external_trust": false, "freshness_verified": false,
        "pages": live, "final_pages": finals, "restart_sealed": restarts, "breaks": break_rows,
        "unauthenticated_tail": tail_from.map(|start| json::json!({"from": start, "to": to})),
        "unchecked_stamps": unchecked, "legacy_signed_lines": legacy_signed, "crypto": crypto,
        "authenticated_records": authenticated_records, "all_requested_records_authenticated": complete,
        "authority_mode": "caller-trusted-deployment-bootstrap-for-node", "delegated_authority_supported": false}),
    )
}
