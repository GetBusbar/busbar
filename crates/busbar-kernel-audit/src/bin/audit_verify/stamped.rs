// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! LINKED WINDOWS (SEALING-FIX r20 §3.7): the published range read through the source traits of
//! [`busbar_kernel_audit::linked_walk`], which holds every rule, and its verdict rendered as the
//! report. The walked lines, the page stamps and break notices, the notary key certificates and the
//! node's seal row are checked under one independently trusted deployment Bootstrap key.

use super::*;
use busbar_kernel_audit::linked_walk::{
    self, Evidence, LinkedRange, SealRow, TrustedHead, Verdict, WalkedLine,
};
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

/// One member of the published range: a walked line, a certificate line, a stamp or a break.
/// Equality is exact JSON equality.
#[derive(Clone, Copy, PartialEq)]
struct Json<'a>(&'a Value);

impl WalkedLine for Json<'_> {
    fn seq(&self) -> Result<u64> {
        record_number(self.0, "seq")
    }
    fn node(&self) -> Result<u64> {
        record_number(self.0, "node")
    }
    fn prev_hash(&self) -> Result<&str> {
        text(self.0, "prev_hash")
    }
    fn hash(&self) -> Result<&str> {
        text(self.0, "hash")
    }
    fn recipe(&self) -> Result<&str> {
        text(self.0, "recipe")
    }
    fn certificate(&self) -> Result<(u64, NotaryKeyRecord)> {
        certificate(self.0)
    }
    fn digest(&self) -> Result<String> {
        record_digest(self.0, LINK_RECIPE)
    }
    fn signature(&self) -> Result<&str> {
        text(self.0, "signature")
    }
    fn key_id(&self) -> Result<&str> {
        text(self.0, "key_id")
    }
}

impl Evidence for Json<'_> {
    fn is_break(&self) -> Result<bool> {
        Ok(text(self.0, "kind")? == "break")
    }
    fn notice(&self) -> Result<BreakNotice> {
        notice(self.0)
    }
    fn node_seq(&self) -> Result<Option<u64>> {
        node_seq(self.0)
    }
    fn stamp(&self) -> Result<Stamp> {
        stamp(self.0)
    }
}

/// An array member of the range, as its members.
fn members<'a>(range: &'a Value, member: &str, absent: &'static str) -> Result<Vec<Json<'a>>> {
    Ok(range
        .get(member)
        .and_then(Value::as_array)
        .ok_or(absent)?
        .iter()
        .map(Json)
        .collect())
}

/// The published range of one node.
struct Range<'a>(&'a Value);

impl<'a> LinkedRange for Range<'a> {
    type Line = Json<'a>;
    type Evidence = Json<'a>;

    fn from(&self) -> Result<u64> {
        number(self.0, "from")
    }
    fn to(&self) -> Result<u64> {
        number(self.0, "to")
    }
    fn records(&self) -> Result<Vec<Json<'a>>> {
        members(self.0, "records", "records are absent")
    }
    fn cover(&self) -> Result<Vec<Json<'a>>> {
        members(self.0, "cover", "cover is absent")
    }
    fn certs(&self) -> Result<Option<Vec<Json<'a>>>> {
        let range: &'a Value = self.0;
        match range.get("certs") {
            None => Ok(None),
            Some(values) => Ok(Some(
                values
                    .as_array()
                    .ok_or("certs is not an array")?
                    .iter()
                    .map(Json)
                    .collect(),
            )),
        }
    }
    fn stamps(&self) -> Result<Vec<Json<'a>>> {
        members(self.0, "stamps", "stamps are absent")
    }
    fn seal_row(&self) -> Result<Option<SealRow>> {
        let Some(row) = self.0.get("seal_row").filter(|row| !row.is_null()) else {
            return Ok(None);
        };
        Ok(Some(match text(row, "outcome")? {
            "clean" => SealRow::Clean {
                sealer: number(row, "sealer")?,
                through: number(row, "through")?,
            },
            "stamp" => SealRow::Stamp {
                sealer: number(row, "sealer")?,
                stamp: stamp(row.get("stamp").ok_or("the seal row's stamp is absent")?)?,
            },
            "break" => SealRow::Break {
                sealer: number(row, "sealer")?,
                notice: notice(row.get("break").ok_or("the seal row's break is absent")?)?,
            },
            _ => return Err("the node's seal row does not decode"),
        }))
    }
    fn anchor(&self) -> Result<Option<Json<'a>>> {
        let range: &'a Value = self.0;
        let anchor = range.get("anchor").ok_or("range anchor member is absent")?;
        Ok((!anchor.is_null()).then_some(Json(anchor)))
    }
}

/// The independently retained head file.
struct Head<'a>(&'a Value);

impl TrustedHead for Head<'_> {
    fn recipe(&self) -> Result<&str> {
        envelope(self.0)
    }
    fn head(&self) -> Result<Stamp> {
        stamp(self.0.get("head").ok_or("trusted head is empty")?)
    }
    fn next_seq(&self) -> Result<u64> {
        number(self.0, "next_seq")
    }
}

/// The report of a verified linked window.
fn report(verdict: Verdict) -> Value {
    let to = verdict.to;
    let restarts: Vec<Value> = verdict
        .restart_sealed
        .iter()
        .map(|page| {
            json::json!({"from": page.from, "to": page.to,
            "down_from_ms": page.down_from_ms, "down_to_ms": page.down_to_ms, "sealer": page.sealer})
        })
        .collect();
    let breaks: Vec<Value> = verdict
        .breaks
        .iter()
        .map(|notice| {
            json::json!({"node": notice.node, "sealer": notice.sealer,
            "last_good": notice.last_good, "unsealed_from": notice.unsealed_from,
            "unsealed_to": notice.unsealed_to, "journal_from": notice.journal_from,
            "journal_to": notice.journal_to, "reason": notice.reason.as_str(),
            "detected_ms": notice.detected_ms, "host": notice.host,
            "crypto": notice.crypto, "sig_alg": notice.sig_alg, "key_id": notice.key_id})
        })
        .collect();
    json::json!({"result": verdict.standing.map(linked_walk::Standing::as_str),
    "from": verdict.from, "to": to, "records": verdict.records,
    "starts_at_genesis": verdict.from == 1, "trusted_terminal_head": verdict.trusted_terminal_head,
    "source_anchor_is_external_trust": false, "freshness_verified": false,
    "pages": verdict.live_pages, "final_pages": verdict.final_pages, "restart_sealed": restarts,
    "breaks": breaks,
    "unauthenticated_tail": verdict.unauthenticated_tail.map(|start| json::json!({"from": start, "to": to})),
    "unchecked_stamps": verdict.unchecked_stamps, "legacy_signed_lines": verdict.legacy_signed_lines,
    "crypto": verdict.crypto,
    "authenticated_records": verdict.authenticated_records,
    "all_requested_records_authenticated": verdict.all_requested_records_authenticated,
    "certified_pages": verdict.certified_pages,
    "seal_row": verdict.seal_row.map(linked_walk::SealOutcome::as_str),
    "authority_mode": "caller-trusted-deployment-bootstrap-for-node", "delegated_authority_supported": true})
}

pub(super) fn verify(
    keys: &BTreeMap<String, AuditVerifyingKey>,
    range: &Value,
    head: Option<&Value>,
) -> Result<Value> {
    let head = head.map(Head);
    linked_walk::verify(keys, &Range(range), head.as_ref()).map(report)
}
