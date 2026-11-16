// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The patch writer (MIGRATE-ON-BOOT §A7 "Authored text"): config.yaml is rewritten by byte-range
//! edits of the operator's own text, never by re-serializing a tree, so comments, key order,
//! quoting, anchors and blank lines survive and only the changed spans differ. Every edit is
//! checked by its two proofs: re-parsing the written bytes gives the planned tree (one), and the
//! written bytes minus the changed spans equal the source bytes minus the same spans (two).
//!
//! [`rewrite`] reads the source twice through the facade: as the chain's tree, and as a span index
//! (a small [`Node`] read with serde-saphyr's `Spanned`, byte offsets from the string source; no
//! parser of our own). `diff(source tree, planned tree)` by path yields the edits, applied by byte
//! range:
//! - a changed scalar: its span, replaced by the facade emitter's scalar (which quotes a string
//!   that would re-read as another type);
//! - a removed entry or sequence item: from its line's start to the end of its last content line
//!   (comments after it stay);
//! - an added entry: emitted in block style at the siblings' indentation, after the entry the
//!   planned tree puts before it (so a top-level key a pass adds lands at the schema's position,
//!   [`schema_insert`]);
//! - an entry whose value changes kind: the entry re-emitted in place;
//! - any edit inside a flow collection: that collection re-emitted in flow style, every unchanged
//!   scalar and key copied from its source slice.
//!
//! Everything else is copied. An edit the writer cannot place refuses VERIFY naming the path.

use std::fmt;
use std::ops::Range;

use busbar_contract::yaml::{self, MappingExt, Pairs, Spanned, Value, ValueExt};
use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};

use crate::{Refusal, STAMP_KEY};

/// Insert `config_version: <format>` as the document's first key: after a leading block of blank
/// lines, comments, directives and the `---` marker, before the first key. Nothing else changes.
///
/// # Errors
/// CONFIG when the document's root is not a block mapping the line can open (proof one fails).
pub fn stamp(text: &str, format: u64) -> Result<String, Refusal> {
    let at = first_key_offset(text);
    let mut line = String::new();
    if at == text.len() && !text.is_empty() && !text.ends_with('\n') {
        line.push('\n');
    }
    line.push_str(STAMP_KEY);
    line.push_str(": ");
    line.push_str(&format.to_string());
    line.push('\n');
    let mut out = String::with_capacity(text.len() + line.len());
    out.push_str(&text[..at]);
    out.push_str(&line);
    out.push_str(&text[at..]);
    proof_one((at < text.len()).then_some(text), &out, format)?;
    debug_assert!(proof_two(text, &out, at, line.len()));
    Ok(out)
}

/// The byte offset of the first line that is not blank, a comment, a `%` directive or `---`.
fn first_key_offset(text: &str) -> usize {
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        let code = line.trim_start();
        let preamble = code.is_empty()
            || code.starts_with('#')
            || code.starts_with('%')
            || code.trim_end() == "---"
            || code.starts_with("--- #");
        if !preamble {
            break;
        }
        offset += line.len();
    }
    offset
}

/// Proof one: the written bytes parse to the stamp followed by exactly the source's tree (`None`:
/// the source holds no key).
fn proof_one(source: Option<&str>, written: &str, format: u64) -> Result<(), Refusal> {
    let refused = || {
        Refusal::Config(format!(
            "config.yaml's top level is not a block mapping that `{STAMP_KEY}: {format}` can \
             open; write its top-level keys one per line (`key: value`), then boot again"
        ))
    };
    let after: yaml::Value = yaml::from_str(written).map_err(|_| refused())?;
    let pairs = after.as_mapping().ok_or_else(refused)?;
    let (first, rest) = pairs.split_first().ok_or_else(refused)?;
    let stamped = first.0.as_str() == Some(STAMP_KEY) && first.1.as_u64() == Some(format);
    // A source with no key (blank, comments only) is the empty mapping.
    let original = match source {
        None => yaml::Value::Map(Vec::new()),
        Some(source) => yaml::from_str::<yaml::Value>(source).map_err(|_| refused())?,
    };
    if !original.is_mapping() {
        return Err(refused());
    }
    if stamped && yaml::same_tree(&yaml::Value::Map(rest.to_vec()), &original) {
        Ok(())
    } else {
        Err(refused())
    }
}

/// Proof two: the written bytes minus the inserted span equal the source.
fn proof_two(source: &str, written: &str, at: usize, inserted: usize) -> bool {
    written.len() == source.len() + inserted
        && written[..at] == source[..at]
        && written[at + inserted..] == source[at..]
}

/// Insert `key: value` into a top-level mapping at the position the 1.6.0 schema declares: after
/// the last key the schema orders before it (first when there is none). A key the schema does not
/// order goes last.
pub(crate) fn schema_insert(root: &mut Pairs, key: &str, value: Value) {
    let order = busbar_kernel::config::document_keys();
    let rank = |name: &str| order.iter().position(|known| *known == name);
    let at = match rank(key) {
        Some(want) => root
            .iter()
            .rposition(|(k, _)| k.as_str().and_then(rank).is_some_and(|r| r < want))
            .map_or(0, |i| i + 1),
        None => root.len(),
    };
    root.insert(at, (Value::from(key), value));
}

/// Rewrite `source` (whose tree is `before`) so that it reads as `after`, by byte-range edits of
/// the operator's text; `shown` names the file in a refusal. `after` is the chain's tree: the same
/// document with entries removed, added or changed.
///
/// # Errors
/// VERIFY naming the path whose authored text the writer cannot keep, or when proof one fails;
/// nothing is written.
pub fn rewrite(
    source: &str,
    before: &Value,
    after: &Value,
    shown: &str,
) -> Result<String, Refusal> {
    if yaml::same_tree(before, after) {
        return Ok(source.to_owned());
    }
    let writer = Writer {
        text: source,
        shown,
        edits: Vec::new(),
    };
    let out = writer.write(before, after)?;
    let reread: Value =
        yaml::from_str(&out).map_err(|_| writer_refusal(shown, "(the document)"))?;
    if yaml::same_tree(&reread, after) {
        Ok(out)
    } else {
        Err(proof_one_refusal(shown))
    }
}

/// Proof one failed: the written bytes parse, but not as the planned tree (§A7 "Authored text":
/// an anchor shared by aliases the chain changed differently fails here, CONFIG naming it).
fn proof_one_refusal(shown: &str) -> Refusal {
    Refusal::Config(format!(
        "the upgrade's rewrite of {shown} does not read back as planned (an anchor whose aliases \
         the upgrade would change differently, for example); nothing was written. Write that part \
         without the anchor, then boot again"
    ))
}

fn writer_refusal(shown: &str, at: &str) -> Refusal {
    Refusal::Authored(format!(
        "the upgrade could not keep {shown}'s authored text at `{at}`; nothing was written. Make \
         that part of the file plain block YAML (one `key: value` per line), then boot again"
    ))
}

/// One node of the span index: a mapping's entries and a sequence's items with their positions.
enum Node {
    Map(Vec<(Spanned<Node>, Spanned<Node>)>),
    Seq(Vec<Spanned<Node>>),
    Scalar,
}

impl<'de> Deserialize<'de> for Node {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(NodeVisitor)
    }
}

struct NodeVisitor;

impl<'de> Visitor<'de> for NodeVisitor {
    type Value = Node;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a YAML node")
    }

    fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Node, E> {
        Ok(Node::Scalar)
    }

    fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Node, E> {
        Ok(Node::Scalar)
    }

    fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<Node, E> {
        Ok(Node::Scalar)
    }

    fn visit_i128<E: serde::de::Error>(self, _: i128) -> Result<Node, E> {
        Ok(Node::Scalar)
    }

    fn visit_u128<E: serde::de::Error>(self, _: u128) -> Result<Node, E> {
        Ok(Node::Scalar)
    }

    fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Node, E> {
        Ok(Node::Scalar)
    }

    fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<Node, E> {
        Ok(Node::Scalar)
    }

    fn visit_bytes<E: serde::de::Error>(self, _: &[u8]) -> Result<Node, E> {
        Ok(Node::Scalar)
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Node, E> {
        Ok(Node::Scalar)
    }

    fn visit_none<E: serde::de::Error>(self) -> Result<Node, E> {
        Ok(Node::Scalar)
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Node, D::Error> {
        Node::deserialize(deserializer)
    }

    fn visit_newtype_struct<D: Deserializer<'de>>(self, deserializer: D) -> Result<Node, D::Error> {
        Node::deserialize(deserializer)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Node, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element::<Spanned<Node>>()? {
            items.push(item);
        }
        Ok(Node::Seq(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Node, A::Error> {
        let mut entries = Vec::new();
        while let Some(entry) = map.next_entry::<Spanned<Node>, Spanned<Node>>()? {
            entries.push(entry);
        }
        Ok(Node::Map(entries))
    }
}

/// The byte offset a node's text starts at.
fn offset(node: &Spanned<Node>) -> Option<usize> {
    node.referenced
        .span()
        .byte_offset()
        .and_then(|at| usize::try_from(at).ok())
}

/// The byte length of a scalar node's text.
fn length(node: &Spanned<Node>) -> Option<usize> {
    node.referenced
        .span()
        .byte_len()
        .and_then(|len| usize::try_from(len).ok())
}

fn is_scalar(value: &Value) -> bool {
    !matches!(value, Value::Map(_) | Value::Array(_))
}

/// Whether two values are the same kind of node (mapping, sequence or scalar), so `b` can be
/// written by editing `a`'s children. A collection emptied by the chain is not: a block mapping
/// or sequence with no entries left reads back as null, so its entry is re-emitted (`key: {}`).
fn same_kind(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Map(was), Value::Map(now)) => was.is_empty() || !now.is_empty(),
        (Value::Array(was), Value::Array(now)) => was.is_empty() || !now.is_empty(),
        _ => is_scalar(a) && is_scalar(b),
    }
}

/// One byte-range edit of the source.
struct Edit {
    at: Range<usize>,
    with: String,
}

struct Writer<'s> {
    text: &'s str,
    shown: &'s str,
    edits: Vec<Edit>,
}

impl Writer<'_> {
    fn write(mut self, before: &Value, after: &Value) -> Result<String, Refusal> {
        let (Value::Map(was), Value::Map(now)) = (before, after) else {
            // A document with no key (blank or comments only) gains its entries at the end.
            if before.is_null() {
                if let Value::Map(now) = after {
                    let mut out = self.text.to_owned();
                    if !out.is_empty() && !out.ends_with('\n') {
                        out.push('\n');
                    }
                    for (key, value) in now {
                        out.push_str(&self.block_entry(key, value, 0, "(the document)")?);
                    }
                    return Ok(out);
                }
            }
            return Err(writer_refusal(self.shown, "(the document)"));
        };
        let index: Spanned<Node> =
            yaml::from_str(self.text).map_err(|_| writer_refusal(self.shown, "(the document)"))?;
        let Node::Map(entries) = &index.value else {
            return Err(writer_refusal(self.shown, "(the document)"));
        };
        if self.is_flow(offset(&index).unwrap_or(0)) {
            return Err(writer_refusal(self.shown, "(the document)"));
        }
        let mut path = Vec::new();
        self.block_map(&mut path, entries, was, now, 0..self.text.len())?;
        self.apply()
    }

    fn fail(&self, path: &[String]) -> Refusal {
        let at = if path.is_empty() {
            "(the document)".to_owned()
        } else {
            path.join(".")
        };
        writer_refusal(self.shown, &at)
    }

    fn is_flow(&self, at: usize) -> bool {
        matches!(self.text.as_bytes().get(at), Some(b'{' | b'['))
    }

    /// The byte offset of the start of the line holding `at`.
    fn line_start(&self, at: usize) -> usize {
        self.text
            .get(..at)
            .and_then(|head| head.rfind('\n'))
            .map_or(0, |newline| newline + 1)
    }

    /// Whether only spaces precede `at` on its line.
    fn line_leading(&self, at: usize) -> bool {
        self.text
            .get(self.line_start(at)..at)
            .is_some_and(|lead| lead.bytes().all(|b| b == b' '))
    }

    /// Whether only spaces and one `- ` precede `at` on its line (a block sequence item).
    fn item_leading(&self, at: usize) -> bool {
        self.text
            .get(self.line_start(at)..at)
            .is_some_and(|lead| lead.trim() == "-")
    }

    /// The end of the last content line (not blank, not a comment) in `region`, after its newline.
    fn content_end(&self, region: &Range<usize>) -> usize {
        let Some(body) = self.text.get(region.clone()) else {
            return region.start;
        };
        let mut end = region.start;
        let mut at = region.start;
        for line in body.split_inclusive('\n') {
            at += line.len();
            let code = line.trim();
            if !code.is_empty() && !code.starts_with('#') {
                end = at;
            }
        }
        end
    }

    /// The source slice of a scalar node.
    fn slice(&self, node: &Spanned<Node>) -> Option<&str> {
        let start = offset(node)?;
        let end = start.checked_add(length(node)?)?;
        self.text.get(start..end)
    }

    /// The facade emitter's text for one scalar, on one line.
    fn scalar_text(&self, value: &Value, path: &[String]) -> Result<String, Refusal> {
        let text = yaml::to_string(value).map_err(|_| self.fail(path))?;
        let text = text.trim_end_matches('\n');
        if text.contains('\n') || text.is_empty() {
            return Err(self.fail(path));
        }
        Ok(text.to_owned())
    }

    /// `key: value` in block style at `indent` columns, ending in a newline.
    fn block_entry(
        &self,
        key: &Value,
        value: &Value,
        indent: usize,
        at: &str,
    ) -> Result<String, Refusal> {
        let emitted = yaml::to_string(&Value::Map(vec![(key.clone(), value.clone())]))
            .map_err(|_| writer_refusal(self.shown, at))?;
        let pad = " ".repeat(indent);
        let mut out = String::with_capacity(emitted.len() + 8 * pad.len());
        for line in emitted.split_inclusive('\n') {
            if !line.trim().is_empty() {
                out.push_str(&pad);
            }
            out.push_str(line);
        }
        if !out.ends_with('\n') {
            out.push('\n');
        }
        Ok(out)
    }

    fn push(&mut self, at: Range<usize>, with: String) {
        self.edits.push(Edit { at, with });
    }

    /// Insert `with` at `at`, after a newline if `at` is not at a line's start.
    fn insert(&mut self, at: usize, with: String) {
        let needs_newline = at > 0 && self.text.as_bytes().get(at - 1) != Some(&b'\n');
        let with = if needs_newline {
            format!("\n{with}")
        } else {
            with
        };
        self.push(at..at, with);
    }

    /// One node: `before` (whose text `node` indexes) becomes `after`. `region` bounds the node's
    /// block text (it ends where the next sibling's line starts).
    fn node(
        &mut self,
        path: &mut Vec<String>,
        before: &Value,
        after: &Value,
        node: &Spanned<Node>,
        region: Range<usize>,
    ) -> Result<(), Refusal> {
        if yaml::same_tree(before, after) {
            return Ok(());
        }
        // A block collection is placed by its children's keys and items; only a flow collection
        // and a scalar are edited at their own offset.
        let start = offset(node);
        if let Some(start) = start.filter(|at| !is_scalar(before) && self.is_flow(*at)) {
            let end = flow_end(self.text, start).ok_or_else(|| self.fail(path))?;
            let with = self.flow(path, after, Some((before, node)))?;
            self.push(start..end, with);
            return Ok(());
        }
        match (&node.value, before, after) {
            (Node::Map(entries), Value::Map(was), Value::Map(now)) => {
                self.block_map(path, entries, was, now, region)
            }
            (Node::Seq(items), Value::Array(was), Value::Array(now)) => {
                self.block_seq(path, items, was, now, region)
            }
            (Node::Scalar, was, now) if is_scalar(was) && is_scalar(now) => {
                let start = start.ok_or_else(|| self.fail(path))?;
                let len = length(node).ok_or_else(|| self.fail(path))?;
                let end = start.checked_add(len).ok_or_else(|| self.fail(path))?;
                let old = self.text.get(start..end).ok_or_else(|| self.fail(path))?;
                if old.contains('\n') {
                    return Err(self.fail(path));
                }
                let with = self.scalar_text(now, path)?;
                self.push(start..end, with);
                Ok(())
            }
            _ => Err(self.fail(path)),
        }
    }

    fn block_map(
        &mut self,
        path: &mut Vec<String>,
        entries: &[(Spanned<Node>, Spanned<Node>)],
        was: &Pairs,
        now: &Pairs,
        region: Range<usize>,
    ) -> Result<(), Refusal> {
        if entries.len() != was.len() || entries.is_empty() {
            return Err(self.fail(path));
        }
        let mut starts = Vec::with_capacity(entries.len());
        for (key, _) in entries {
            starts.push(offset(key).ok_or_else(|| self.fail(path))?);
        }
        let first = starts[0];
        let indent = first - self.line_start(first);
        let regions: Vec<Range<usize>> = (0..starts.len())
            .map(|i| {
                let end = starts
                    .get(i + 1)
                    .map_or(region.end, |next| self.line_start(*next));
                self.line_start(starts[i])..end
            })
            .collect();
        for (i, ((_, value_node), (key, value))) in entries.iter().zip(was).enumerate() {
            path.push(key.as_str().map_or_else(|| "?".to_owned(), str::to_owned));
            match now.get_key(key) {
                None => {
                    if !self.line_leading(starts[i]) {
                        return Err(self.fail(path));
                    }
                    let end = self.content_end(&regions[i]);
                    self.push(regions[i].start..end, String::new());
                }
                Some(kept) if yaml::same_tree(value, kept) => {}
                Some(kept) if same_kind(value, kept) && !value.is_null() => {
                    self.node(path, value, kept, value_node, regions[i].clone())?;
                }
                Some(kept) => {
                    // The value changes kind (a null `store:` becomes a mapping): the entry is
                    // re-emitted in place.
                    if !self.line_leading(starts[i]) {
                        return Err(self.fail(path));
                    }
                    let end = self.content_end(&regions[i]);
                    let with = self.block_entry(key, kept, indent, &path.join("."))?;
                    self.push(regions[i].start..end, with);
                }
            }
            path.pop();
        }
        for (j, (key, value)) in now.iter().enumerate() {
            if was.contains_key(key) {
                continue;
            }
            path.push(key.as_str().map_or_else(|| "?".to_owned(), str::to_owned));
            let anchor = now[..j]
                .iter()
                .rev()
                .find_map(|(k, _)| was.iter().position(|(w, _)| yaml::same_tree(w, k)));
            let at = match anchor {
                Some(i) => self.content_end(&regions[i]),
                None => regions[0].start,
            };
            let with = self.block_entry(key, value, indent, &path.join("."))?;
            self.insert(at, with);
            path.pop();
        }
        Ok(())
    }

    fn block_seq(
        &mut self,
        path: &mut Vec<String>,
        items: &[Spanned<Node>],
        was: &[Value],
        now: &[Value],
        region: Range<usize>,
    ) -> Result<(), Refusal> {
        if items.len() != was.len() {
            return Err(self.fail(path));
        }
        let mut starts = Vec::with_capacity(items.len());
        for item in items {
            starts.push(offset(item).ok_or_else(|| self.fail(path))?);
        }
        let regions: Vec<Range<usize>> = (0..starts.len())
            .map(|i| {
                let end = starts
                    .get(i + 1)
                    .map_or(region.end, |next| self.line_start(*next));
                self.line_start(starts[i])..end
            })
            .collect();
        if was.len() == now.len() {
            for (i, ((item, value), kept)) in items.iter().zip(was).zip(now).enumerate() {
                if yaml::same_tree(value, kept) {
                    continue;
                }
                path.push(i.to_string());
                if !(is_scalar(value) && is_scalar(kept)) {
                    return Err(self.fail(path));
                }
                self.node(path, value, kept, item, regions[i].clone())?;
                path.pop();
            }
            return Ok(());
        }
        // Items removed, the rest kept in order: each removed item's lines go.
        let mut kept = now.iter().peekable();
        let mut removed = Vec::new();
        for (i, value) in was.iter().enumerate() {
            match kept.peek() {
                Some(next) if yaml::same_tree(value, next) => {
                    kept.next();
                }
                _ => removed.push(i),
            }
        }
        if kept.next().is_some() {
            return Err(self.fail(path));
        }
        for i in removed {
            if !self.item_leading(starts[i]) {
                path.push(i.to_string());
                return Err(self.fail(path));
            }
            let end = self.content_end(&regions[i]);
            self.push(regions[i].start..end, String::new());
        }
        Ok(())
    }

    /// `after` in flow style. Where `source` (the node's old value and its index) holds the same
    /// key or an unchanged scalar, its source slice is copied.
    fn flow(
        &self,
        path: &mut Vec<String>,
        after: &Value,
        source: Option<(&Value, &Spanned<Node>)>,
    ) -> Result<String, Refusal> {
        match after {
            Value::Map(pairs) => {
                let old = match source {
                    Some((Value::Map(was), node)) => match &node.value {
                        Node::Map(entries) if entries.len() == was.len() => Some((was, entries)),
                        _ => None,
                    },
                    _ => None,
                };
                let mut parts = Vec::with_capacity(pairs.len());
                for (key, value) in pairs {
                    path.push(key.as_str().map_or_else(|| "?".to_owned(), str::to_owned));
                    let found = old.and_then(|(was, entries)| {
                        was.iter()
                            .position(|(w, _)| yaml::same_tree(w, key))
                            .and_then(|i| Some((&was.get(i)?.1, entries.get(i)?)))
                    });
                    let key_text = match found.and_then(|(_, (key_node, _))| self.slice(key_node)) {
                        Some(text) => text.to_owned(),
                        None => self.scalar_text(key, path)?,
                    };
                    let value_text = self.flow(
                        path,
                        value,
                        found.map(|(old_value, (_, value_node))| (old_value, value_node)),
                    )?;
                    parts.push(format!("{key_text}: {value_text}"));
                    path.pop();
                }
                Ok(format!("{{{}}}", parts.join(", ")))
            }
            Value::Array(items) => {
                let old = match source {
                    Some((Value::Array(was), node)) => match &node.value {
                        Node::Seq(nodes)
                            if nodes.len() == was.len() && was.len() == items.len() =>
                        {
                            Some((was, nodes))
                        }
                        _ => None,
                    },
                    _ => None,
                };
                let mut parts = Vec::with_capacity(items.len());
                for (i, value) in items.iter().enumerate() {
                    path.push(i.to_string());
                    let found = old.and_then(|(was, nodes)| Some((was.get(i)?, nodes.get(i)?)));
                    parts.push(self.flow(path, value, found)?);
                    path.pop();
                }
                Ok(format!("[{}]", parts.join(", ")))
            }
            scalar => {
                if let Some((old, node)) = source {
                    if yaml::same_tree(old, scalar) && matches!(node.value, Node::Scalar) {
                        if let Some(text) = self.slice(node) {
                            return Ok(text.to_owned());
                        }
                    }
                }
                self.scalar_text(scalar, path)
            }
        }
    }

    /// The edits applied in source order: the text between them copied, each replaced range
    /// written once. An insertion at a replaced range's start follows that replacement.
    fn apply(mut self) -> Result<String, Refusal> {
        self.edits.sort_by_key(|edit| edit.at.start);
        let mut out = String::with_capacity(self.text.len() + 256);
        let mut pos = 0;
        let mut last_start = 0;
        for edit in &self.edits {
            if edit.at.start < pos {
                let follows = edit.at.is_empty() && edit.at.start >= last_start;
                if !follows {
                    return Err(writer_refusal(self.shown, "(overlapping edits)"));
                }
            } else {
                out.push_str(
                    self.text
                        .get(pos..edit.at.start)
                        .ok_or_else(|| writer_refusal(self.shown, "(the document)"))?,
                );
                pos = edit.at.start;
            }
            out.push_str(&edit.with);
            pos = pos.max(edit.at.end);
            last_start = edit.at.start;
        }
        out.push_str(
            self.text
                .get(pos..)
                .ok_or_else(|| writer_refusal(self.shown, "(the document)"))?,
        );
        Ok(out)
    }
}

/// The byte offset just past the flow collection that opens at `start` (`{` or `[`), skipping
/// quoted scalars and comments; `None` when it does not close.
fn flow_end(text: &str, start: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    let mut i = start;
    while i < bytes.len() {
        let byte = bytes[i];
        let after_token = i == start
            || matches!(
                bytes[i - 1],
                b'{' | b'[' | b',' | b':' | b' ' | b'\t' | b'\n'
            );
        match byte {
            b'{' | b'[' => depth += 1,
            b'}' | b']' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            b'\'' if after_token => {
                i += 1;
                loop {
                    match bytes.get(i)? {
                        b'\'' if bytes.get(i + 1) == Some(&b'\'') => i += 2,
                        b'\'' => break,
                        _ => i += 1,
                    }
                }
            }
            b'"' if after_token => {
                i += 1;
                loop {
                    match bytes.get(i)? {
                        b'\\' => i += 2,
                        b'"' => break,
                        _ => i += 1,
                    }
                }
            }
            b'#' if i > start && matches!(bytes[i - 1], b' ' | b'\t') => {
                while bytes.get(i).is_some_and(|b| *b != b'\n') {
                    i += 1;
                }
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// The document's tree: a mapping (a blank or comments-only document is the empty mapping).
///
/// # Errors
/// CONFIG when the text is not YAML or its top level is not a mapping.
pub fn document(text: &str) -> Result<yaml::Value, Refusal> {
    if first_key_offset(text) == text.len() {
        return Ok(yaml::Value::Map(Vec::new()));
    }
    let value: yaml::Value = yaml::from_str(text)
        .map_err(|error| Refusal::Config(format!("config.yaml is not valid YAML: {error}")))?;
    match value {
        yaml::Value::Null => Ok(yaml::Value::Map(Vec::new())),
        value if value.is_mapping() => Ok(value),
        _ => Err(Refusal::Config(
            "config.yaml's top level is not a mapping; 1.5.5 did not boot it either".to_owned(),
        )),
    }
}

#[cfg(test)]
#[path = "tests/patch_tests.rs"]
mod tests;
