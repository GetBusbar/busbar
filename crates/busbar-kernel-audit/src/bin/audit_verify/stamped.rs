// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! LINKED WINDOWS (SEALING-FIX r20 §3.7): the walked lines, the page stamps and break notices, the
//! notary key certificates and the node's seal row, checked under one independently trusted
//! deployment Bootstrap key.

use super::*;
use busbar_contract::crypto::{self, PublicKey, SigAlg};
use busbar_kernel_audit::{
    BreakNotice, BreakReason, NotaryKeyCertificate, NotaryKeyRecord, Stamp, StampKind,
    NOTARY_KEY_RECORD_DOMAIN,
};

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

/// The WAL position a stamp or certificate was read at; `None` for evidence read elsewhere (the
/// seal row).
fn node_seq(value: &Value) -> Result<Option<u64>> {
    match value.get("node_seq") {
        None => Ok(None),
        Some(at) => at
            .as_u64()
            .map(Some)
            .ok_or("a journal position is not an unsigned integer"),
    }
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

/// Lowercase hex of one of the `lengths` (in bytes), decoded.
fn hex_bytes(value: &Value, member: &str, lengths: &[usize]) -> Result<Vec<u8>> {
    let raw = text(value, member)?;
    if !lengths.iter().any(|&bytes| hex(raw, bytes)) {
        return Err("a certificate field is not canonical lowercase hex of its length");
    }
    hex::decode(raw).map_err(|_| "a certificate field is not hex")
}

/// ONE `notary_key` LINE as the range read prints it (`certs`, or among the walked lines), with
/// the WAL position a stamp's `key_cert` names.
fn certificate(value: &Value) -> Result<(u64, NotaryKeyRecord)> {
    if text(value, "recipe")? != NOTARY_KEY_RECORD_DOMAIN {
        return Err("a certificate line names another recipe");
    }
    let prev = text(value, "prev_hash")?;
    if !prev.is_empty() && !hex(prev, 32) {
        return Err("a certificate predecessor is not canonical lowercase hex");
    }
    let hash = text(value, "hash")?;
    if !hex(hash, 32) {
        return Err("a certificate fingerprint is not canonical lowercase hex");
    }
    let at = node_seq(value)?.ok_or("a certificate line has no journal position")?;
    Ok((
        at,
        NotaryKeyRecord {
            node: record_number(value, "node")?,
            seq: record_number(value, "seq")?,
            linked_ms: record_number(value, "linked_ms")?,
            prev_link: Fingerprint::from_hex(prev).ok_or("invalid certificate predecessor")?,
            fingerprint: Fingerprint::from_hex(hash).ok_or("invalid certificate fingerprint")?,
            certificate: NotaryKeyCertificate {
                key_id: text(value, "key_id")?.to_owned(),
                sig_alg: text(value, "sig_alg")?.to_owned(),
                public_key: hex_bytes(value, "public_key", &[32, 65])?,
                signed_by: text(value, "signed_by")?.to_owned(),
                signature: hex_bytes(value, "signature", &[64])?,
            },
        },
    ))
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

/// The break notices seen so far: by `unsealed_from` (non-empty ranges only, which can account
/// for a missing position) and as reported.
#[derive(Default)]
struct Breaks {
    ranges: BTreeMap<u64, BreakNotice>,
    rows: Vec<Value>,
}

impl Breaks {
    /// RULE 4: a break notice is signed by the Bootstrap key, names this node and a sane range,
    /// and overlaps no other.
    fn add(&mut self, notice: BreakNotice, node: u64, key: &AuditVerifyingKey) -> Result<()> {
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
        if self.ranges.values().any(|prior| {
            overlaps(
                prior.unsealed_from,
                prior.unsealed_to,
                notice.unsealed_from,
                notice.unsealed_to,
            )
        }) {
            return Err("break intervals overlap");
        }
        self.rows
            .push(json::json!({"node": notice.node, "sealer": notice.sealer,
            "last_good": notice.last_good, "unsealed_from": notice.unsealed_from,
            "unsealed_to": notice.unsealed_to, "journal_from": notice.journal_from,
            "journal_to": notice.journal_to, "reason": notice.reason.as_str(),
            "detected_ms": notice.detected_ms, "host": notice.host,
            "crypto": notice.crypto, "sig_alg": notice.sig_alg, "key_id": notice.key_id}));
        // Empty intervals remain reported, but cannot account for any missing position.
        if !empty {
            self.ranges.insert(notice.unsealed_from, notice);
        }
        Ok(())
    }
}

/// RULE 3, which key may sign which page (decision 159; CRYPTO-SEAM §2.5 key map), applied in
/// journal order. A page with `key_cert = 0` verifies under the Bootstrap key. Only a `live` or
/// `final` page may name a certificate, and then only the current one: the newest valid
/// certificate read before the page, not ended by a valid `final` or `after_restart` page read
/// between them. Its key id and algorithm are the certificate's, the certificate's line is at or
/// before the page's `to`, and the page verifies under the certified key. Evidence with no journal
/// position (the seal row) comes after every journal row. Returns how many pages a certified key
/// signed.
fn check_keys(
    pages: &[(Option<u64>, Stamp)],
    certs: &BTreeMap<u64, NotaryKeyRecord>,
    key: &AuditVerifyingKey,
) -> Result<usize> {
    #[derive(Clone, Copy)]
    enum Event {
        Cert(u64),
        Page(usize),
    }
    let mut events: Vec<(u64, u8, Event)> = certs
        .keys()
        .map(|&at| (at, 0, Event::Cert(at)))
        .chain(
            pages
                .iter()
                .enumerate()
                .map(|(index, (at, _))| (at.unwrap_or(u64::MAX), 1, Event::Page(index))),
        )
        .collect();
    events.sort_by_key(|&(at, rank, _)| (at, rank));
    let mut current = None;
    let mut certified = 0;
    for (_, _, event) in events {
        let index = match event {
            Event::Cert(at) => {
                current = Some(at);
                continue;
            }
            Event::Page(index) => index,
        };
        let (at, page) = &pages[index];
        if page.key_cert == 0 {
            page.verify(key)
                .map_err(|_| "a stamp signature is invalid")?;
        } else {
            let cert = certs
                .get(&page.key_cert)
                .filter(|_| current == Some(page.key_cert))
                .filter(|_| at.is_some_and(|at| at > page.key_cert))
                .filter(|cert| {
                    matches!(page.kind, StampKind::Live | StampKind::Final)
                        && cert.seq <= page.to
                        && page.key_id == cert.certificate.key_id
                        && page.sig_alg == cert.certificate.sig_alg
                })
                .ok_or("stamp key not certified")?;
            let delegated = cert
                .certificate
                .key()
                .map_err(|_| "stamp key not certified")?;
            crypto::verify(&delegated, &page.preimage(), &page.signature)
                .map_err(|_| "a stamp signature is invalid")?;
            certified += 1;
        }
        if matches!(page.kind, StampKind::Final | StampKind::AfterRestart) {
            current = None;
        }
    }
    Ok(certified)
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
    let bootstrap = PublicKey::new(
        SigAlg::Ed25519,
        &hex::decode(key.public_key_hex()).map_err(|_| "invalid audit public key")?,
    );
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

    // RULE 1: every walked line recomputes by its own recipe and links to its predecessor.
    let mut previous = None;
    let node = record_number(&records[0], "node")?;
    let mut authenticated = vec![false; records.len()];
    let mut legacy_signed = 0;
    let mut walked_certs: BTreeMap<u64, (u64, Fingerprint)> = BTreeMap::new();
    let mut certs: BTreeMap<u64, NotaryKeyRecord> = BTreeMap::new();
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
        let recipe = text(line, "recipe")?;
        if recipe == NOTARY_KEY_RECORD_DOMAIN {
            let (at, cert) = certificate(line)?;
            if cert.fingerprint != cert.recompute_fingerprint() {
                return Err("a record does not hash to its published fields");
            }
            walked_certs.insert(seq, (at, cert.fingerprint));
            if certs
                .insert(at, cert.clone())
                .is_some_and(|prior| prior != cert)
            {
                return Err("a certificate line is reported twice with different content");
            }
        } else {
            if !hex(hash, 32) || record_digest(line, LINK_RECIPE)? != hash {
                return Err("a record does not hash to its published fields");
            }
            if recipe != LINK_RECIPE {
                signed(line, keys)?;
                if let Some(checked) = authenticated.get_mut(index) {
                    *checked = true;
                    legacy_signed += 1;
                }
            }
        }
        previous = Some(hash);
    }
    let walked_from = from;
    let walked_to = from + (walked.len() as u64) - 1;

    // The certificates the stamps name. One that fails its own checks certifies nothing: a stamp
    // naming it is "stamp key not certified", and it ends no other key.
    if let Some(values) = range.get("certs") {
        for value in values.as_array().ok_or("certs is not an array")? {
            let (at, cert) = certificate(value)?;
            if certs
                .insert(at, cert.clone())
                .is_some_and(|prior| prior != cert)
            {
                return Err("a certificate line is reported twice with different content");
            }
        }
    }
    certs.retain(|at, cert| {
        let in_place = if (walked_from..=walked_to).contains(&cert.seq) {
            walked_certs.get(&cert.seq) == Some(&(*at, cert.fingerprint))
        } else {
            true
        };
        in_place && cert.node == node && cert.verify(&bootstrap).is_ok()
    });

    // RULES 3 AND 4: the stamps and break notices, from the journal and from the seal row.
    let values = range
        .get("stamps")
        .and_then(Value::as_array)
        .ok_or("stamps are absent")?;
    let mut pages: Vec<(Option<u64>, Stamp)> = Vec::new();
    let mut breaks = Breaks::default();
    let mut admit = |at: Option<u64>, page: Stamp| -> Result<()> {
        if page.from == 0 || page.to < page.from || page.node != node {
            return Err("invalid stamp range or node");
        }
        if page.kind != StampKind::AfterRestart && page.sealer != page.node {
            return Err("a live or final stamp names another sealer");
        }
        if page.kind == StampKind::AfterRestart && page.key_cert != 0 {
            return Err("stamp key not certified");
        }
        pages.push((at, page));
        Ok(())
    };
    for value in values {
        if text(value, "kind")? == "break" {
            breaks.add(notice(value)?, node, key)?;
            continue;
        }
        admit(node_seq(value)?, stamp(value)?)?;
    }
    let mut seal_row = None;
    if let Some(row) = range.get("seal_row").filter(|row| !row.is_null()) {
        let outcome = text(row, "outcome")?;
        match outcome {
            "clean" => {
                number(row, "sealer")?;
                number(row, "through")?;
            }
            "stamp" => {
                let sealer = number(row, "sealer")?;
                let page = stamp(row.get("stamp").ok_or("the seal row's stamp is absent")?)?;
                if page.kind != StampKind::AfterRestart || page.sealer != sealer {
                    return Err("the node's seal row does not verify");
                }
                admit(None, page)?;
            }
            "break" => {
                let sealer = number(row, "sealer")?;
                let notice = notice(row.get("break").ok_or("the seal row's break is absent")?)?;
                if notice.sealer != sealer {
                    return Err("the node's seal row does not verify");
                }
                breaks.add(notice, node, key)?;
            }
            _ => return Err("the node's seal row does not decode"),
        }
        seal_row = Some(outcome);
    }
    let certified = check_keys(&pages, &certs, key)?;
    let mut pages: Vec<Stamp> = pages.into_iter().map(|(_, page)| page).collect();
    pages.sort_by_key(|page| (page.from, page.to));
    if pages.windows(2).any(|pair| pair[1].from <= pair[0].to) {
        return Err("stamp pages overlap");
    }
    let breaks_by_from = breaks.ranges;
    for page in &pages {
        if breaks_by_from
            .values()
            .any(|notice| overlaps(page.from, page.to, notice.unsealed_from, notice.unsealed_to))
        {
            return Err("a break overlaps a signed page");
        }
    }
    for pair in pages.windows(2) {
        let next = pair[0].to.checked_add(1).ok_or("page position overflow")?;
        if next < pair[1].from && !explained_gap(next, pair[1].from - 1, &breaks_by_from) {
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

    // RULE 3 (coverage) AND RULE 5: a page authenticates the walked lines from its `from` to its
    // `to` when its fingerprint is line `to`'s hash; a page whose `to` is not walked is unchecked.
    let mut accepted = Vec::new();
    let mut live = 0;
    let mut finals = 0;
    let mut restarts = Vec::new();
    let mut unchecked = 0;
    let mut crypto_backends = std::collections::BTreeSet::new();
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
                let recipe = text(line, "recipe")?;
                if recipe != LINK_RECIPE && recipe != NOTARY_KEY_RECORD_DOMAIN {
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
            crypto_backends.insert(page.crypto.clone());
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
        if breaks_by_from
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
        && !breaks_by_from
            .values()
            .any(|notice| overlaps(from, to, notice.unsealed_from, notice.unsealed_to))
        && unchecked == 0;

    // RULE 6: the independently retained head.
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
        "pages": live, "final_pages": finals, "restart_sealed": restarts, "breaks": breaks.rows,
        "unauthenticated_tail": tail_from.map(|start| json::json!({"from": start, "to": to})),
        "unchecked_stamps": unchecked, "legacy_signed_lines": legacy_signed, "crypto": crypto_backends,
        "authenticated_records": authenticated_records, "all_requested_records_authenticated": complete,
        "certified_pages": certified, "seal_row": seal_row,
        "authority_mode": "caller-trusted-deployment-bootstrap-for-node", "delegated_authority_supported": true}),
    )
}
