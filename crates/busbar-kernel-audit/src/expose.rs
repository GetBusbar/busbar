// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE THREE READS. What the node answers with; it never asks anyone anything.

use crate::heads::SignedHead;
use crate::recipe::{digest_fields, DigestField, DigestValue, DIGEST_RECIPE};
use crate::record::{AuditChain, AuditRecord};
use crate::sign::{AuditKeySet, SIGNATURE_ALGORITHM, SIGNATURE_DOMAIN};

/// Append one JSON string literal, escaped.

fn push_json_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// `"name":"value"`, escaped.
fn member_str(out: &mut String, name: &str, value: &str) {
    push_json_string(out, name);
    out.push(':');
    push_json_string(out, value);
}

/// `"name":<number>` — envelope positions and whole seconds only, never a recipe number.
fn member_num(out: &mut String, name: &str, value: u64) {
    push_json_string(out, name);
    out.push(':');
    out.push_str(&value.to_string());
}

/// `"name":"value"` or `"name":null` — the shape every optional member takes.

fn member_opt(out: &mut String, name: &str, value: Option<&str>) {
    push_json_string(out, name);
    out.push(':');
    match value {
        Some(v) => push_json_string(out, v),
        None => out.push_str("null"),
    }
}

/// The repeated groups, as `(count field, group name)`.

const GROUPS: &[(&str, &str)] = &[
    ("lines_count", "lines"),
    ("hooks_count", "hooks"),
    ("children_count", "children"),
];

/// ONE RECORD, rendered as the fields its digest ate, plus the digest and the signature.

fn push_record(out: &mut String, record: &AuditRecord) {
    out.push('{');
    let fields = digest_fields(record);
    let mut i = 0;
    let mut first = true;
    while i < fields.len() {
        let field = &fields[i];
        if !first {
            out.push(',');
        }
        first = false;
        push_json_string(out, field.name);
        out.push(':');
        push_value(out, &field.value);
        i += 1;

        if let Some((_, group)) = GROUPS.iter().find(|(count, _)| *count == field.name) {
            out.push(',');
            push_json_string(out, group);
            out.push(':');
            i = push_group(out, &fields, i, group);
        }
    }
    out.push(',');
    member_str(out, "hash", &record.hash);
    out.push(',');
    member_opt(out, "signature", record.signature.as_deref());
    out.push(',');
    member_opt(out, "key_id", record.key_id.as_deref());

    out.push(',');
    member_str(out, "recipe", record.recipe.name());
    out.push('}');
}

/// One repeated group as a JSON array, from the flat recipe. Returns where the group ended.

fn push_group(out: &mut String, fields: &[DigestField], mut i: usize, group: &str) -> usize {
    let scalar = format!("{group}[]");
    let member_prefix = format!("{group}[].");
    out.push('[');
    let mut elements = 0;
    let first_member = fields
        .get(i)
        .map(|f| f.name)
        .filter(|n| *n == scalar || n.starts_with(&member_prefix));
    while let Some(field) = fields.get(i) {
        if Some(field.name) != first_member {
            break;
        }
        if elements > 0 {
            out.push(',');
        }
        elements += 1;
        if field.name == scalar {
            push_value(out, &field.value);
            i += 1;
            continue;
        }
        out.push('{');
        let mut members = 0;
        while let Some(member) = fields.get(i) {
            if !member.name.starts_with(&member_prefix)
                || (members > 0 && Some(member.name) == first_member)
            {
                break;
            }
            if members > 0 {
                out.push(',');
            }
            members += 1;
            push_json_string(out, &member.name[member_prefix.len()..]);
            out.push(':');
            push_value(out, &member.value);
            i += 1;
        }
        out.push('}');
    }
    out.push(']');
    i
}

/// One recipe value, as JSON. Text is a string; a number is its canonical decimal text in a string

fn push_value(out: &mut String, value: &DigestValue) {
    match value {
        DigestValue::Text(s) => push_json_string(out, s),
        DigestValue::Num(n) => push_json_string(out, &n.to_string()),
    }
}

/// One head, as JSON.
fn push_head(out: &mut String, head: &SignedHead) {
    out.push('{');
    member_num(out, "seq", head.seq);
    out.push(',');
    member_str(out, "hash", &head.hash);
    out.push(',');
    member_opt(out, "signature", head.signature.as_deref());
    out.push(',');
    member_opt(out, "key_id", head.key_id.as_deref());
    out.push(',');
    member_num(out, "wall", head.wall);
    out.push('}');
}

/// THE HEAD READ: where the chain is now.

#[must_use]
pub fn head_body(chain: &AuditChain) -> String {
    let mut out = String::new();
    out.push('{');
    member_str(&mut out, "recipe", DIGEST_RECIPE);
    out.push(',');
    member_str(&mut out, "signature_domain", SIGNATURE_DOMAIN);
    out.push(',');
    member_str(&mut out, "algorithm", SIGNATURE_ALGORITHM);
    out.push(',');
    member_num(&mut out, "next_seq", chain.next_seq());
    out.push(',');
    push_json_string(&mut out, "head");
    out.push(':');
    match chain.heads().tip() {
        Some(head) => push_head(&mut out, head),
        None => out.push_str("null"),
    }
    out.push('}');
    out
}

/// THE RANGE READ: records by position, `from` through `to` inclusive.

#[must_use]
pub fn range_body(chain: &AuditChain, records: &[AuditRecord], from: u64, to: u64) -> String {
    let mut out = String::new();
    out.push('{');
    member_str(&mut out, "recipe", DIGEST_RECIPE);
    out.push(',');
    member_str(&mut out, "signature_domain", SIGNATURE_DOMAIN);
    out.push(',');
    member_str(&mut out, "algorithm", SIGNATURE_ALGORITHM);
    out.push(',');
    member_num(&mut out, "from", from);
    out.push(',');
    member_num(&mut out, "to", to);
    out.push(',');
    push_json_string(&mut out, "anchor");
    out.push(':');
    match chain.heads().anchor_at(to) {
        Some(head) => push_head(&mut out, &head),
        None => out.push_str("null"),
    }
    out.push(',');
    push_json_string(&mut out, "records");
    out.push_str(":[");
    let mut first = true;
    for record in records.iter().filter(|r| r.seq >= from && r.seq <= to) {
        if !first {
            out.push(',');
        }
        first = false;
        push_record(&mut out, record);
    }
    out.push_str("]}");
    out
}

/// THE KEY-SET READ: the public keys, so nothing is taken on trust out of band.

#[must_use]
pub fn keys_body(keys: &AuditKeySet) -> String {
    let mut out = String::new();
    out.push('{');
    member_str(&mut out, "recipe", DIGEST_RECIPE);
    out.push(',');
    member_str(&mut out, "signature_domain", SIGNATURE_DOMAIN);
    out.push(',');
    member_str(&mut out, "algorithm", SIGNATURE_ALGORITHM);
    out.push(',');
    push_json_string(&mut out, "keys");
    out.push_str(":[");
    for (i, key) in keys.keys().iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        member_str(&mut out, "key_id", key.key_id());
        out.push(',');
        member_str(&mut out, "algorithm", SIGNATURE_ALGORITHM);
        out.push(',');
        member_str(&mut out, "public_key", &key.public_key_hex());
        out.push('}');
    }
    out.push_str("]}");
    out
}
