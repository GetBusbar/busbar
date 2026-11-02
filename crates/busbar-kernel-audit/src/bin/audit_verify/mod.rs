// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel_audit::digest::{Digest, Framing};
use busbar_kernel_audit::sign::{SIGNATURE_ALGORITHM, SIGNATURE_DOMAIN};
use busbar_kernel_audit::{AuditVerifyingKey, DIGEST_RECIPE, DIGEST_RECIPE_V2, DIGEST_RECIPE_V4};
use serde_json::{json, Value};
use std::collections::BTreeMap;

const V2: &str = include_str!("../../../../../docs/audit-chain-digest-v2.md");
const V4: &str = include_str!("../../../../../docs/audit-chain-digest-v4.md");
const V5: &str = include_str!("../../../../../docs/audit-chain-digest-v5.md");
type Result<T> = std::result::Result<T, &'static str>;

#[derive(Clone, Copy)]
enum Kind {
    Text,
    Number,
}

fn text<'a>(value: &'a Value, member: &str) -> Result<&'a str> {
    value
        .get(member)
        .and_then(Value::as_str)
        .ok_or("a required text member is absent or is not a string")
}

fn number(value: &Value, member: &str) -> Result<u64> {
    value
        .get(member)
        .and_then(Value::as_u64)
        .ok_or("an envelope position or clock is not an unsigned integer")
}

fn decimal(value: &Value) -> Result<u64> {
    let s = value
        .as_str()
        .ok_or("a recipe number is not a decimal string")?;
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0'))
    {
        return Err("a recipe number is not canonical decimal");
    }
    s.parse().map_err(|_| "a recipe number exceeds u64")
}

fn record_number(value: &Value, member: &str) -> Result<u64> {
    decimal(value.get(member).ok_or("a recipe member is absent")?)
}

fn recipe(name: &str) -> Result<&'static str> {
    match name {
        DIGEST_RECIPE_V2 => Ok(V2),
        DIGEST_RECIPE_V4 => Ok(V4),
        DIGEST_RECIPE => Ok(V5),
        _ => Err("unsupported audit digest recipe"),
    }
}

fn envelope(value: &Value) -> Result<&str> {
    let name = text(value, "recipe")?;
    recipe(name)?;
    if text(value, "signature_domain")? != SIGNATURE_DOMAIN {
        return Err("unsupported audit signature domain");
    }
    if text(value, "algorithm")? != SIGNATURE_ALGORITHM {
        return Err("unsupported audit signature algorithm");
    }
    Ok(name)
}

fn fields(page: &str) -> Result<Vec<(&str, Kind)>> {
    let mut fields = Vec::new();
    for line in page.lines() {
        let cells: Vec<_> = line
            .trim()
            .trim_matches('|')
            .split('|')
            .map(str::trim)
            .collect();
        if cells.len() != 3 {
            continue;
        }
        let Ok(position) = cells[0].parse::<usize>() else {
            continue;
        };
        let kind = match cells[2] {
            "text" => Kind::Text,
            "number" => Kind::Number,
            _ => return Err("the embedded digest field table is invalid"),
        };
        if position != fields.len() + 1 {
            return Err("the embedded digest field table is not consecutive");
        }
        fields.push((cells[1].trim_matches('`'), kind));
    }
    if fields.is_empty() {
        return Err("the embedded digest field table is empty");
    }
    Ok(fields)
}

fn feed(digest: &mut Digest, value: &Value, kind: Kind) -> Result<()> {
    match kind {
        Kind::Text => {
            digest.text(
                value
                    .as_str()
                    .ok_or("a recipe text field is not a string")?,
            );
        }
        Kind::Number => {
            digest.num(decimal(value)?);
        }
    }
    Ok(())
}

fn record_digest(record: &Value, default_recipe: &str) -> Result<String> {
    let name = match record.get("recipe") {
        Some(value) => value.as_str().ok_or("a record recipe is not a string")?,
        None if default_recipe == DIGEST_RECIPE_V2 => DIGEST_RECIPE_V2,
        None => return Err("a record recipe is absent"),
    };
    if name == DIGEST_RECIPE {
        let present = text(record, "rate_card_key_present")?;
        let key = text(record, "rate_card_version")?;
        let valid_key = key.len() == 40
            && key
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        let valid = match present {
            "0" => key.is_empty(),
            "1" => valid_key,
            _ => false,
        };
        if !valid {
            return Err("a keyed rate-card boundary has invalid presence or spelling");
        }
    }
    let order = fields(recipe(name)?)?;
    let mut digest = Digest::new(Framing::LengthPrefixed);
    let mut index = 0;
    while index < order.len() {
        let (name, kind) = order[index];
        if let Some((group, _)) = name.split_once("[]") {
            let start = index;
            while index < order.len()
                && order[index].0.split_once("[]").map(|(g, _)| g) == Some(group)
            {
                index += 1;
            }
            let array = record
                .get(group)
                .and_then(Value::as_array)
                .ok_or("a recipe group is absent or is not an array")?;
            let count = record_number(record, &format!("{group}_count"))?;
            if u64::try_from(array.len()).ok() != Some(count) {
                return Err("a recipe group's count differs from its array length");
            }
            for element in array {
                for &(name, kind) in &order[start..index] {
                    let member = &name[group.len() + 2..];
                    let value = if member.is_empty() {
                        element
                    } else {
                        element
                            .get(
                                member
                                    .strip_prefix('.')
                                    .ok_or("invalid embedded group field")?,
                            )
                            .ok_or("a recipe group member is absent")?
                    };
                    feed(&mut digest, value, kind)?;
                }
            }
        } else {
            feed(
                &mut digest,
                record.get(name).ok_or("a recipe member is absent")?,
                kind,
            )?;
            index += 1;
        }
    }
    Ok(digest.finish())
}

fn hex(text: &str, bytes: usize) -> bool {
    text.len() == bytes * 2
        && text
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn trusted_keys(body: &Value) -> Result<BTreeMap<String, AuditVerifyingKey>> {
    envelope(body)?;
    let rows = body
        .get("keys")
        .and_then(Value::as_array)
        .ok_or("key set is absent")?;
    let mut keys = BTreeMap::new();
    for row in rows {
        if text(row, "algorithm")? != SIGNATURE_ALGORITHM {
            return Err("unsupported key algorithm");
        }
        let public_key = text(row, "public_key")?;
        if !hex(public_key, 32) {
            return Err("a public key is not canonical lowercase hex");
        }
        let key =
            AuditVerifyingKey::from_hex(public_key).map_err(|_| "invalid audit public key")?;
        if key.key_id() != text(row, "key_id")? {
            return Err("a key identifier does not match its public key");
        }
        if keys.insert(key.key_id().to_owned(), key).is_some() {
            return Err("the trusted key set repeats an identifier");
        }
    }
    if keys.is_empty() {
        return Err("the trusted key set is empty");
    }
    Ok(keys)
}

fn signed(body: &Value, keys: &BTreeMap<String, AuditVerifyingKey>) -> Result<()> {
    let hash = text(body, "hash")?;
    let signature = text(body, "signature")?;
    if !hex(hash, 32) || !hex(signature, 64) {
        return Err("a digest or signature is not canonical lowercase hex");
    }
    let key = keys
        .get(text(body, "key_id")?)
        .ok_or("a signing key is not trusted")?;
    key.verify_digest(hash, signature)
        .map_err(|_| "an audit signature is invalid")
}

fn matches_head(head: &Value, record: &Value) -> Result<()> {
    if number(head, "seq")? != record_number(record, "seq")?
        || number(head, "wall")? != record_number(record, "wall")?
        || text(head, "hash")? != text(record, "hash")?
        || text(head, "signature")? != text(record, "signature")?
        || text(head, "key_id")? != text(record, "key_id")?
    {
        return Err("a head does not match the record at its position");
    }
    Ok(())
}

pub(super) fn verify(keys: &Value, range: &Value, head: Option<&Value>) -> Result<Value> {
    let keys = trusted_keys(keys)?;
    let default_recipe = envelope(range)?;
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
    let mut previous = None;
    for (index, record) in records.iter().enumerate() {
        let seq = record_number(record, "seq")?;
        if seq != from + u64::try_from(index).map_err(|_| "record position overflow")? {
            return Err("records are not in consecutive requested order");
        }
        let prev = text(record, "prev_hash")?;
        if let Some(expected) = previous {
            if prev != expected {
                return Err("a record does not link to its predecessor");
            }
        } else if (seq == 1 && !prev.is_empty()) || (seq > 1 && !hex(prev, 32)) {
            return Err("the first record's predecessor is invalid");
        }
        let hash = text(record, "hash")?;
        if record_digest(record, default_recipe)? != hash {
            return Err("a record does not hash to its published fields");
        }
        signed(record, &keys)?;
        previous = Some(hash);
    }

    let anchor = range.get("anchor").ok_or("range anchor member is absent")?;
    if !anchor.is_null() {
        signed(anchor, &keys)?;
        let seq = number(anchor, "seq")?;
        number(anchor, "wall")?;
        if seq == 0 || seq > to {
            return Err("the source anchor is outside its permitted range");
        }
        if seq >= from {
            let index = usize::try_from(seq - from).map_err(|_| "anchor position overflow")?;
            matches_head(anchor, &records[index])?;
        }
    }
    if let Some(body) = head {
        envelope(body)?;
        let terminal = body
            .get("head")
            .filter(|v| !v.is_null())
            .ok_or("trusted head is empty")?;
        signed(terminal, &keys)?;
        if number(terminal, "seq")? != to {
            return Err("the requested range does not end at the independently trusted head");
        }
        if number(body, "next_seq")? != to.checked_add(1).ok_or("head position overflow")? {
            return Err("trusted head next_seq is inconsistent");
        }
        matches_head(
            terminal,
            records.last().ok_or("the requested fetch is empty")?,
        )?;
    }
    Ok(json!({
        "result": if head.is_some() { "complete-through-trusted-head" } else { "signed-consistent-window" },
        "from": from,
        "to": to,
        "records": records.len(),
        "starts_at_genesis": from == 1,
        "trusted_terminal_head": head.is_some(),
        "source_anchor_is_external_trust": false,
        "freshness_verified": false
    }))
}

#[cfg(test)]
mod tests;
