// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE THREE READS. What the node answers with; it never asks anyone anything.
//!
//! ## Pull, not push
//!
//! There is no client here, no outbound socket, no credential, no endpoint to configure. The node
//! ANSWERS. Whoever wants the chain — an auditor, a counter-signing service, an operator with
//! `curl` — comes and gets it. That is what makes this work behind a firewall and on an airgapped
//! box, and it is why anchoring lives outside: a node cannot anchor to itself, so the half that
//! publishes is somebody else's product and not this crate's business.
//!
//! ## Three reads, because a verifier needs three things
//!
//! * [`head_body`] — where the chain is NOW: position, digest, signature, key identifier, clock.
//!   The one fact an external party timestamps and counter-signs.
//! * [`range_body`] — the records themselves, by position, each carrying EVERY FIELD ITS DIGEST
//!   EATS plus the digest and the signature. So a puller recomputes the chain rather than believing
//!   our answer about it. A read that returned "verified: true" would be asking to be trusted,
//!   which is the thing an audit chain exists to stop being necessary.
//! * [`keys_body`] — the public keys. Published, so a verifier never has to ask us for the key out
//!   of band; a key obtained from the party being audited, over a channel nobody logged, is not
//!   evidence of anything.
//! * [`heads_body`] — the anchors, which outlive the records. See [`crate::heads`].
//!
//! ## The bodies are built here, not by whoever serves them
//!
//! Because the range body IS the published digest recipe rendered as data. A serving layer that
//! composed it from the record's public fields would be a second implementation of the recipe, and
//! the one thing this contract cannot survive is two spellings of itself.
//!
//! JSON is written out by hand rather than derived. The bodies must be byte-deterministic (a
//! counter-signer that hashes what it fetched needs the same bytes twice), the numeric fields that
//! are 128-bit go out as TEXT because a JSON number wide enough to hold them is not safely
//! readable by most parsers — and `i128` through an `f64` is exactly the loss #81 bans — and the
//! member order has to be the recipe's order rather than a serializer's.

use crate::heads::SignedHead;
use crate::recipe::{digest_fields, DigestField, DigestValue, DIGEST_RECIPE};
use crate::record::{AuditChain, AuditRecord};
use crate::sign::{AuditKeySet, SIGNATURE_ALGORITHM, SIGNATURE_DOMAIN};

/// Append one JSON string literal, escaped.
///
/// Hand-written because these fields hold arbitrary caller-named text and an escaper that missed a
/// control character would produce a body a strict parser refuses — from a node that is trying to
/// prove it is being honest. Escapes the two mandatory characters, the five short forms, and every
/// remaining control character as `\u00XX`.
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

/// `"name":<number>`.
fn member_num(out: &mut String, name: &str, value: u64) {
    push_json_string(out, name);
    out.push(':');
    out.push_str(&value.to_string());
}

/// `"name":"value"` or `"name":null` — the shape every optional member takes.
///
/// `null` and not an empty string: a record sealed with no signature and a record signed with the
/// empty string are different facts, and the read has to be able to tell them apart. (The DIGEST
/// spells an absent optional as the empty string, which is a separate ruling belonging to the
/// recipe; see [`crate::recipe`]. The two are not in conflict — the recipe's `destination` field is
/// what the digest ate, this member is what the record holds.)
fn member_opt(out: &mut String, name: &str, value: Option<&str>) {
    push_json_string(out, name);
    out.push(':');
    match value {
        Some(v) => push_json_string(out, v),
        None => out.push_str("null"),
    }
}

/// The repeated groups, as `(count field, group name)`.
///
/// Every group in the recipe is preceded by its own count, and the count is a digested field in its
/// own right — it is what stops two different groupings of the same values from digesting
/// identically. Naming the pairs here rather than inferring them from the `[]` in a field name is
/// what lets an EMPTY group still publish its (empty) array: a reader walking the published members
/// finds `"lines": []` rather than finding nothing and having to decide whether that meant zero
/// lines or a missing member.
const GROUPS: &[(&str, &str)] = &[
    ("lines_count", "lines"),
    ("hooks_count", "hooks"),
    ("children_count", "children"),
];

/// ONE RECORD, rendered as the fields its digest ate, plus the digest and the signature.
///
/// Member order is the recipe's order, and every value is already reduced to the exact text or
/// number that goes into the digest. A verifier walks the members in order, length-prefixes each
/// one, and has the preimage — without reimplementing a single one of this crate's tag functions.
/// A third party should not have to port `outcome_tag` to check a signature.
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
        // A count field is immediately followed by its group, which is published as an array under
        // the group's own name — empty or not.
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
    out.push('}');
}

/// One repeated group as a JSON array, from the flat recipe. Returns where the group ended.
///
/// A group's fields are named `group[]` when its elements are single values and `group[].member`
/// when they are several; the element boundary is the member name coming round again. Both shapes
/// are in the recipe today (`children[]` and `lines[].class`), so both are handled here rather than
/// at two call sites.
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

/// One recipe value, as JSON. Text is a string, a number is a number — the distinction the digest
/// makes, kept visible in the published body so a verifier does not have to infer it.
fn push_value(out: &mut String, value: &DigestValue) {
    match value {
        DigestValue::Text(s) => push_json_string(out, s),
        DigestValue::Num(n) => out.push_str(&n.to_string()),
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
///
/// Answers with the tip, the position the NEXT record will take, and the recipe and domain names a
/// verifier needs to know which rules to apply. A node that has sealed nothing answers with a null
/// head rather than an error: "this chain has no records" is a true answer and a legitimate state.
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
///
/// The caller hands in the records it holds; this selects the window and renders it. Selection is
/// here rather than at the caller so that "what the range verb means by from..to" has one
/// definition — inclusive at both ends, position order, and a window that runs off either end of
/// what is held is simply shorter rather than an error.
///
/// `anchor` is the head this node published at or before `to`, folded into the same body. A puller
/// reading a window it cannot trace to the genesis needs an independently published tip to tie it
/// to; making it a second round trip would let the two answers come from two different moments.
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
///
/// Public halves only. There is no path from this crate to the secret half of anything — see
/// [`crate::sign::AuditSigningKey`], which has no accessor for it.
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

/// THE ANCHOR READ: every head this node has published, which outlives the records.
///
/// Folded into the head read's body rather than given a verb of its own, because a puller asks
/// "where are you, and what have you been" in one breath, and two reads would let the answers come
/// from two different moments.
#[must_use]
pub fn heads_body(chain: &AuditChain) -> String {
    let mut out = String::new();
    out.push('{');
    member_str(&mut out, "recipe", DIGEST_RECIPE);
    out.push(',');
    member_num(&mut out, "sample_seconds", chain.heads().sample_seconds());
    out.push(',');
    push_json_string(&mut out, "anchors");
    out.push_str(":[");
    for (i, head) in chain.heads().anchors().iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        push_head(&mut out, head);
    }
    out.push_str("]}");
    out
}
