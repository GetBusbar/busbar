// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE THREE READS. What the node answers with; it never asks anyone anything.

use std::fmt::Write as _;

use crate::heads::SignedHead;
use crate::recipe::{visit_fields, FieldSink, DIGEST_RECIPE_V7};
use crate::record::{AuditChain, AuditRecord};
use crate::sign::{AuditKeySet, SIGNATURE_ALGORITHM, SIGNATURE_DOMAIN};

/// Escapes text into a JSON string body as it is written.
struct JsonEscaped<'a>(&'a mut String);

impl std::fmt::Write for JsonEscaped<'_> {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        for c in s.chars() {
            match c {
                '"' => self.0.push_str("\\\""),
                '\\' => self.0.push_str("\\\\"),
                '\n' => self.0.push_str("\\n"),
                '\r' => self.0.push_str("\\r"),
                '\t' => self.0.push_str("\\t"),
                '\u{08}' => self.0.push_str("\\b"),
                '\u{0c}' => self.0.push_str("\\f"),
                c if (c as u32) < 0x20 => {
                    write!(self.0, "\\u{:04x}", c as u32)?;
                }
                c => self.0.push(c),
            }
        }
        Ok(())
    }
}

/// A JSON string, escaped.
fn push_json_string(out: &mut String, s: &str) {
    push_json_fmt(out, format_args!("{s}"));
}

/// A JSON string whose text is `value`, formatted and escaped as it is written.
fn push_json_fmt(out: &mut String, value: std::fmt::Arguments<'_>) {
    out.push('"');
    let _ = JsonEscaped(out).write_fmt(value);
    out.push('"');
}

/// `"name":"value"`.
fn member_str(out: &mut String, name: &str, value: &str) {
    push_json_string(out, name);
    out.push(':');
    push_json_string(out, value);
}

/// `"name":value`, the number bare.
fn member_num(out: &mut String, name: &str, value: u64) {
    push_json_string(out, name);
    out.push(':');
    let _ = write!(out, "{value}");
}

/// `"name":"value"` or `"name":null`.
fn member_opt(out: &mut String, name: &str, value: Option<&str>) {
    push_json_string(out, name);
    out.push(':');
    match value {
        Some(v) => push_json_string(out, v),
        None => out.push_str("null"),
    }
}

/// The count fields whose following fields the range read nests, and the array each goes under.
const GROUPS: &[(&str, &str)] = &[
    ("lines_count", "lines"),
    ("hooks_count", "hooks"),
    ("children_count", "children"),
    ("attempts_count", "attempts"),
    ("billing_partitions_count", "billing_partitions"),
    ("billing_classes_count", "billing_classes"),
    ("labels_count", "labels"),
];

/// The array a count field opened, as the range read is filling it.
struct OpenGroup {
    /// The array's name: `lines` carries `lines[]` and `lines[].<member>`.
    group: &'static str,
    /// The field name every element starts with: the first one seen.
    first_member: Option<&'static str>,
    /// Whether an element object is open.
    in_object: bool,
    /// How many elements have been written.
    elements: usize,
}

/// Prints a record's digest fields as the range read's JSON object, nesting each group's fields.
struct JsonFields<'a> {
    out: &'a mut String,
    first: bool,
    open: Option<OpenGroup>,
}

impl JsonFields<'_> {
    /// Write one field value: every value goes out as a JSON string.
    fn value(&mut self, value: std::fmt::Arguments<'_>) {
        push_json_fmt(self.out, value);
    }

    /// Route one field: into the open group when it belongs there, else at the top level.
    fn field(&mut self, name: &'static str, value: std::fmt::Arguments<'_>) {
        if let Some(open) = &mut self.open {
            let member = name
                .strip_prefix(open.group)
                .and_then(|rest| rest.strip_prefix("[]"))
                .filter(|rest| rest.is_empty() || rest.starts_with('.'));
            let starts_element = open.first_member.is_none_or(|first| first == name);
            if let Some(rest) =
                member.filter(|rest| starts_element || (open.in_object && !rest.is_empty()))
            {
                if starts_element {
                    open.first_member = Some(name);
                    if open.in_object {
                        self.out.push('}');
                        open.in_object = false;
                    }
                    if open.elements > 0 {
                        self.out.push(',');
                    }
                    open.elements += 1;
                    if rest.is_empty() {
                        self.value(value);
                        return;
                    }
                    self.out.push('{');
                    open.in_object = true;
                } else {
                    self.out.push(',');
                }
                push_json_string(self.out, &rest[1..]);
                self.out.push(':');
                self.value(value);
                return;
            }
            self.close_group();
        }
        if !self.first {
            self.out.push(',');
        }
        self.first = false;
        push_json_string(self.out, name);
        self.out.push(':');
        self.value(value);
        if let Some((_, group)) = GROUPS.iter().find(|(count, _)| *count == name) {
            self.out.push(',');
            push_json_string(self.out, group);
            self.out.push_str(":[");
            self.open = Some(OpenGroup {
                group,
                first_member: None,
                in_object: false,
                elements: 0,
            });
        }
    }

    /// End the open group's array, and its last element object.
    fn close_group(&mut self) {
        if let Some(open) = self.open.take() {
            if open.in_object {
                self.out.push('}');
            }
            self.out.push(']');
        }
    }
}

impl FieldSink for JsonFields<'_> {
    fn text(&mut self, name: &'static str, value: &str) {
        self.field(name, format_args!("{value}"));
    }

    fn text_fmt(&mut self, name: &'static str, value: std::fmt::Arguments<'_>) {
        self.field(name, value);
    }

    fn num(&mut self, name: &'static str, value: u64) {
        self.field(name, format_args!("{value}"));
    }
}

/// One record as the range read prints it: the digest fields, grouped, then the seal.
fn push_record(out: &mut String, record: &AuditRecord) {
    out.push('{');
    let mut fields = JsonFields {
        out,
        first: true,
        open: None,
    };
    visit_fields(record, &mut fields);
    fields.close_group();
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
    member_str(&mut out, "recipe", DIGEST_RECIPE_V7);
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

/// THE RANGE READ: records by position, `from` through `to` inclusive. The envelope names the
/// recipe this build seals under; every record names its own.
#[must_use]
pub fn range_body(chain: &AuditChain, records: &[AuditRecord], from: u64, to: u64) -> String {
    if records
        .iter()
        .any(|r| r.seq >= from && r.seq <= to && !crate::record::billing::record_valid(r))
    {
        return "{\"error\":\"invalid audit billing representation\"}".into();
    }
    let mut out = String::new();
    out.push('{');
    member_str(&mut out, "recipe", DIGEST_RECIPE_V7);
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
    out.push(':');
    push_records(&mut out, records, from, to);
    out.push('}');
    out
}

/// The records of a bounded range, using the same lossless digest-field wire format.
#[must_use]
pub fn range_records_body(records: &[AuditRecord], from: u64, to: u64) -> String {
    if records
        .iter()
        .any(|r| r.seq >= from && r.seq <= to && !crate::record::billing::record_valid(r))
    {
        return "{\"error\":\"invalid audit billing representation\"}".into();
    }
    let mut out = String::new();
    push_records(&mut out, records, from, to);
    out
}

/// Write the records of a bounded range as a JSON array onto `out`.
fn push_records(out: &mut String, records: &[AuditRecord], from: u64, to: u64) {
    out.push('[');
    let mut first = true;
    for record in records.iter().filter(|r| r.seq >= from && r.seq <= to) {
        if !first {
            out.push(',');
        }
        first = false;
        push_record(out, record);
    }
    out.push(']');
}

/// THE KEY-SET READ: the public keys, so nothing is taken on trust out of band.
#[must_use]
pub fn keys_body(keys: &AuditKeySet) -> String {
    let mut out = String::new();
    out.push('{');
    member_str(&mut out, "recipe", DIGEST_RECIPE_V7);
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
