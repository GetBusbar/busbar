// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Shared guarded JSON engine for credential replies and settings. Neither hands `serde_json`
//! a material-bearing string byte: serde reads a view of the document whose string contents are
//! masked (`x`, same length, so every position is the document's), and each string the reader keeps
//! is decoded from the real bytes into a buffer wiped when it is released.
//!
//! A reply is walked, not built: only the selected path is kept, and every other value is
//! validated where it lies and dropped, so a reply under the 1 MiB cap cannot grow into a parsed
//! tree many times its size. A selected non-string value is written straight to the JSON text
//! `serde_json` prints for the parsed value (object keys sorted, the last of equal keys winning).
//!
//! Refusals report the guarded parser's current error and position without replaying the document.

use std::ops::Range;

use serde::de::{DeserializeSeed, Error, MapAccess, SeqAccess, Visitor};
use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

use super::{Held as Opaque, JsonReplyError};

/// What a parse filled a buffer with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Held {
    /// The document copy serde reads, before and after its strings are masked.
    View,
    /// A decoded object key.
    Key,
    /// A decoded string value, or a written value's JSON text.
    Value,
}

/// Where a parse reports each buffer it fills from the document, while that buffer is live. Tests
/// watch these to prove each one is wiped before it is freed; production passes [`Unwatched`].
pub(crate) trait Custody: Copy {
    /// `bytes`, the initialised start of a live buffer, hold document bytes of kind `what`.
    fn held(self, what: Held, bytes: &[u8]);
}

/// The production [`Custody`]: nothing is watched.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Unwatched;

impl Custody for Unwatched {
    fn held(self, what: Held, bytes: &[u8]) {
        #[cfg(any(test, feature = "test-seal"))]
        OBSERVER.with(|slot| {
            if let Some(observe) = slot.get() {
                observe(
                    match what {
                        Held::View => "parse view",
                        Held::Key => "parsed key",
                        Held::Value => "parsed value",
                    },
                    bytes,
                );
            }
        });
        let _ = (what, bytes);
    }
}

/// Structural outcome of selecting an object-field path. Indices refer only to the supplied
/// path: errors never disclose a response value or a sibling's name.
#[allow(missing_debug_implementations)]
pub enum SelectedJson {
    /// The object has no member at this path index.
    Missing { segment: usize },
    /// The value containing this path index is not an object.
    WrongContainer { segment: usize },
    /// The selected value is null.
    Null,
    /// Decoded string bytes, or canonical JSON for a non-string value.
    Value(Opaque<Vec<u8>>),
}

/// Consume a protected JSON body and select an object-field path (an empty path selects the
/// root). The entire document, including unselected siblings and trailing data, is validated.
/// Strings are decoded exactly; other values use serde_json rendering, sorted object keys and
/// last-duplicate-wins semantics. The input and intermediate strings wipe on every exit.
///
/// The caller bounds input bytes (the exchange API can do so). Serde's ordinary recursion limit
/// applies. Siblings are validated without a tree; selected objects use wiping rendering arenas,
/// with work O(depth * input + object members log members), bounded by input and nesting.
/// Official serde_json still owns numeric-token scratch; its wiping remains an upstream limit.
pub fn select_json(body: Opaque<Vec<u8>>, path: &[&str]) -> Result<SelectedJson, JsonReplyError> {
    select_with(body.wire(), path, Unwatched).map_err(JsonReplyError::from)
}

fn select_with<C: Custody>(
    body: &[u8],
    path: &[&str],
    custody: C,
) -> Result<SelectedJson, serde_json::Error> {
    let view = masked(body, custody);
    let doc = Doc {
        body,
        view: &view,
        custody,
    };
    let mut de = serde_json::Deserializer::from_slice(&view);
    Walk {
        doc,
        path,
        depth: 0,
    }
    .deserialize(&mut de)
    .and_then(|selected| de.end().map(|()| selected))
}

/// A copy of `body` with every byte inside a string (escapes included) replaced by `x`.
fn masked<C: Custody>(body: &[u8], custody: C) -> Zeroizing<Vec<u8>> {
    let mut view = Zeroizing::new(body.to_vec());
    custody.held(Held::View, &view);
    let mut inside = false;
    let mut escaped = false;
    for byte in view.iter_mut() {
        if !inside {
            inside = *byte == b'"';
        } else if !escaped && *byte == b'"' {
            inside = false;
        } else {
            let escape = !escaped && *byte == b'\\';
            *byte = b'x';
            escaped = escape;
        }
    }
    view
}

/// `serde_json`'s control-character refusal.
const CONTROL: &str = "control character (\\u0000-\\u001F) found while parsing a string";

/// The document a reader walks: its real bytes, the masked view serde reads, and the custody
/// every buffer filled from it is reported to.
#[derive(Clone, Copy)]
struct Doc<'a, C> {
    body: &'a [u8],
    view: &'a [u8],
    custody: C,
}

impl<'a, C: Custody> Doc<'a, C> {
    /// The real bytes of the string serde read as `masked` from the view.
    fn raw<E: Error>(self, masked: &str) -> Result<&'a [u8], E> {
        (masked.as_ptr() as usize)
            .checked_sub(self.view.as_ptr() as usize)
            .and_then(|start| self.body.get(start..start.checked_add(masked.len())?))
            .ok_or_else(|| E::custom("invalid JSON string span"))
    }

    /// The string serde read as `masked`, decoded from the real bytes into a guarded buffer.
    fn decoded<E: Error>(self, masked: &str, what: Held) -> Result<Zeroizing<String>, E> {
        let raw = self.raw::<E>(masked)?;
        let mut decoded = Zeroizing::new(String::with_capacity(raw.len()));
        let result = decode(raw, &mut *decoded);
        self.custody.held(what, decoded.as_bytes());
        result.map_err(E::custom)?;
        Ok(decoded)
    }

    /// Refuse the string serde read as `masked` unless it decodes, copying it nowhere.
    fn validated<E: Error>(self, masked: &str) -> Result<(), E> {
        let raw = self.raw::<E>(masked)?;
        decode(raw, &mut Discard).map_err(E::custom)
    }
}

/// A reply value walked toward `data.data.<field>`: the root at `depth` 0, `data` at 1 and
/// `data.data` at 2.
struct Walk<'a, C> {
    doc: Doc<'a, C>,
    path: &'a [&'a str],
    depth: usize,
}

impl<'de, C: Custody> DeserializeSeed<'de> for Walk<'_, C> {
    type Value = SelectedJson;

    fn deserialize<D: serde::Deserializer<'de>>(self, de: D) -> Result<SelectedJson, D::Error> {
        if self.depth == self.path.len() {
            Pick(self.doc).deserialize(de)
        } else {
            de.deserialize_any(self)
        }
    }
}

impl<'de, C: Custody> Visitor<'de> for Walk<'_, C> {
    type Value = SelectedJson;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_unit<E: Error>(self) -> Result<SelectedJson, E> {
        Ok(SelectedJson::WrongContainer {
            segment: self.depth,
        })
    }

    fn visit_bool<E: Error>(self, _: bool) -> Result<SelectedJson, E> {
        Ok(SelectedJson::WrongContainer {
            segment: self.depth,
        })
    }

    fn visit_i64<E: Error>(self, _: i64) -> Result<SelectedJson, E> {
        Ok(SelectedJson::WrongContainer {
            segment: self.depth,
        })
    }

    fn visit_u64<E: Error>(self, _: u64) -> Result<SelectedJson, E> {
        Ok(SelectedJson::WrongContainer {
            segment: self.depth,
        })
    }

    fn visit_f64<E: Error>(self, _: f64) -> Result<SelectedJson, E> {
        Ok(SelectedJson::WrongContainer {
            segment: self.depth,
        })
    }

    fn visit_borrowed_str<E: Error>(self, value: &'de str) -> Result<SelectedJson, E> {
        self.doc.validated::<E>(value)?;
        Ok(SelectedJson::WrongContainer {
            segment: self.depth,
        })
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<SelectedJson, A::Error> {
        while seq.next_element_seed(Skip(self.doc))?.is_some() {}
        Ok(SelectedJson::WrongContainer {
            segment: self.depth,
        })
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<SelectedJson, A::Error> {
        let wanted = self.path[self.depth];
        let mut found = SelectedJson::Missing {
            segment: self.depth,
        };
        while let Some(key) = map.next_key_seed(AnyKey(self.doc))? {
            let ObjectKey::Text(key) = key else {
                map.next_value_seed(NumberText)?;
                return Ok(SelectedJson::WrongContainer {
                    segment: self.depth,
                });
            };
            if key.as_str() != wanted {
                map.next_value_seed(Skip(self.doc))?;
            } else {
                found = map.next_value_seed(Walk {
                    doc: self.doc,
                    path: self.path,
                    depth: self.depth + 1,
                })?;
            }
        }
        Ok(found)
    }
}

/// The selected field's value.
struct Pick<'a, C>(Doc<'a, C>);

impl<C: Custody> Pick<'_, C> {
    /// `value` (a scalar) as its JSON text.
    fn written<T: serde::Serialize, E: Error>(self, value: &T) -> Result<SelectedJson, E> {
        let mut out = Guarded::empty(self.0.custody);
        out.json::<T, E>(value)?;
        Ok(SelectedJson::Value(Opaque::new(std::mem::take(
            &mut *out.exact(),
        ))))
    }
}

impl<'de, C: Custody> DeserializeSeed<'de> for Pick<'_, C> {
    type Value = SelectedJson;

    fn deserialize<D: serde::Deserializer<'de>>(self, de: D) -> Result<SelectedJson, D::Error> {
        de.deserialize_any(self)
    }
}

impl<'de, C: Custody> Visitor<'de> for Pick<'_, C> {
    type Value = SelectedJson;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_unit<E: Error>(self) -> Result<SelectedJson, E> {
        Ok(SelectedJson::Null)
    }

    fn visit_bool<E: Error>(self, value: bool) -> Result<SelectedJson, E> {
        self.written(&value)
    }

    fn visit_i64<E: Error>(self, value: i64) -> Result<SelectedJson, E> {
        self.written(&value)
    }

    fn visit_u64<E: Error>(self, value: u64) -> Result<SelectedJson, E> {
        self.written(&value)
    }

    fn visit_f64<E: Error>(self, value: f64) -> Result<SelectedJson, E> {
        self.written(&value)
    }

    fn visit_borrowed_str<E: Error>(self, value: &'de str) -> Result<SelectedJson, E> {
        let mut text = self.0.decoded::<E>(value, Held::Value)?;
        Ok(SelectedJson::Value(Opaque::new(
            std::mem::take(&mut *text).into_bytes(),
        )))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<SelectedJson, A::Error> {
        let mut out = Guarded::empty(self.0.custody);
        Render {
            doc: self.0,
            out: &mut out,
            lead: b"",
        }
        .visit_seq(seq)?;
        Ok(SelectedJson::Value(Opaque::new(std::mem::take(
            &mut *out.exact(),
        ))))
    }

    fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<SelectedJson, A::Error> {
        let mut out = Guarded::empty(self.0.custody);
        Render {
            doc: self.0,
            out: &mut out,
            lead: b"",
        }
        .visit_map(map)?;
        Ok(SelectedJson::Value(Opaque::new(std::mem::take(
            &mut *out.exact(),
        ))))
    }
}

/// One member of an object being written: its name's decoded bytes and its value's JSON text, as
/// ranges of the object's arena.
struct Member {
    name: Range<usize>,
    value: Range<usize>,
}

/// A value written as JSON text onto `out`, after `lead` (the separator from the value before it).
struct Render<'a, 'o, C: Custody> {
    doc: Doc<'a, C>,
    out: &'o mut Guarded<C>,
    lead: &'static [u8],
}

impl<C: Custody> Render<'_, '_, C> {
    /// Write scalar `value`.
    fn scalar<T: serde::Serialize + ?Sized, E: Error>(self, value: &T) -> Result<(), E> {
        let Self { out, .. } = self;
        out.json(value)
    }
}

impl<'de, C: Custody> DeserializeSeed<'de> for Render<'_, '_, C> {
    type Value = ();

    fn deserialize<D: serde::Deserializer<'de>>(self, de: D) -> Result<(), D::Error> {
        let Self { doc, out, lead } = self;
        out.push(lead);
        de.deserialize_any(Render {
            doc,
            out,
            lead: b"",
        })
    }
}

impl<'de, C: Custody> Visitor<'de> for Render<'_, '_, C> {
    type Value = ();

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_unit<E: Error>(self) -> Result<(), E> {
        self.scalar(&())
    }

    fn visit_bool<E: Error>(self, value: bool) -> Result<(), E> {
        self.scalar(&value)
    }

    fn visit_i64<E: Error>(self, value: i64) -> Result<(), E> {
        self.scalar(&value)
    }

    fn visit_u64<E: Error>(self, value: u64) -> Result<(), E> {
        self.scalar(&value)
    }

    fn visit_f64<E: Error>(self, value: f64) -> Result<(), E> {
        self.scalar(&value)
    }

    fn visit_borrowed_str<E: Error>(self, value: &'de str) -> Result<(), E> {
        let text = self.doc.decoded::<E>(value, Held::Value)?;
        self.scalar(text.as_str())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        let Self { doc, out, .. } = self;
        out.push(b"[");
        let mut lead: &'static [u8] = b"";
        while seq
            .next_element_seed(Render {
                doc,
                out: &mut *out,
                lead,
            })?
            .is_some()
        {
            lead = b",";
        }
        out.push(b"]");
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let Self { doc, out, .. } = self;
        let mut arena = Guarded::empty(doc.custody);
        let mut members = Vec::new();
        while let Some(key) = map.next_key_seed(AnyKey(doc))? {
            let ObjectKey::Text(key) = key else {
                let number = map.next_value_seed(NumberText)?;
                return out.json::<_, A::Error>(&number);
            };
            let start = arena.len();
            arena.push(key.as_bytes());
            let name = start..arena.len();
            map.next_value_seed(Render {
                doc,
                out: &mut arena,
                lead: b"",
            })?;
            members.push(Member {
                value: name.end..arena.len(),
                name,
            });
        }
        // The parsed value's map order (byte order of the keys), the last of equal keys winning:
        // the sort is stable, so the last of a run of equal names is the document's last.
        members.sort_by(|a, b| arena.get(&a.name).cmp(arena.get(&b.name)));
        out.push(b"{");
        let mut lead: &[u8] = b"";
        for (i, member) in members.iter().enumerate() {
            let name = arena.get(&member.name);
            if members
                .get(i + 1)
                .is_some_and(|next| arena.get(&next.name) == name)
            {
                continue;
            }
            out.push(lead);
            lead = b",";
            out.json::<str, A::Error>(std::str::from_utf8(name).map_err(A::Error::custom)?)?;
            out.push(b":");
            out.push(arena.get(&member.value));
        }
        out.push(b"}");
        Ok(())
    }
}

/// A buffer whose growth wipes the allocation it leaves, so no partial copy of what it holds is
/// freed unwiped; dropping it wipes it too.
struct Guarded<C: Custody>(Zeroizing<Vec<u8>>, C);

impl<C: Custody> Guarded<C> {
    fn empty(custody: C) -> Self {
        Self(Zeroizing::new(Vec::new()), custody)
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn get(&self, range: &Range<usize>) -> &[u8] {
        self.0.get(range.clone()).unwrap_or_default()
    }

    fn push(&mut self, bytes: &[u8]) {
        let needed = self.0.len().saturating_add(bytes.len());
        if needed > self.0.capacity() {
            let mut grown = Zeroizing::new(Vec::with_capacity(
                needed.max(self.0.capacity().saturating_mul(2)),
            ));
            grown.extend_from_slice(&self.0);
            self.1.held(Held::Value, &self.0);
            self.0 = grown;
        }
        self.0.extend_from_slice(bytes);
    }

    /// Write `value` as `serde_json` writes it.
    fn json<T: serde::Serialize + ?Sized, E: Error>(&mut self, value: &T) -> Result<(), E> {
        serde_json::to_writer(&mut *self, value).map_err(E::custom)
    }

    /// The text in a buffer of exactly its length; this one is reported to `custody`, then wiped.
    fn exact(self) -> Zeroizing<Vec<u8>> {
        let mut text = Vec::with_capacity(self.0.len());
        text.extend_from_slice(&self.0);
        self.1.held(Held::Value, &text);
        Zeroizing::new(text)
    }
}

impl<C: Custody> Drop for Guarded<C> {
    fn drop(&mut self) {
        self.1.held(Held::Value, &self.0);
    }
}

impl<C: Custody> std::io::Write for Guarded<C> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.push(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Any value, validated and dropped where it lies: nothing of it is copied.
struct Skip<'a, C>(Doc<'a, C>);

impl<'de, C: Custody> DeserializeSeed<'de> for Skip<'_, C> {
    type Value = ();

    fn deserialize<D: serde::Deserializer<'de>>(self, de: D) -> Result<(), D::Error> {
        de.deserialize_any(self)
    }
}

impl<'de, C: Custody> Visitor<'de> for Skip<'_, C> {
    type Value = ();

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_unit<E: Error>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_bool<E: Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }

    fn visit_i64<E: Error>(self, _: i64) -> Result<(), E> {
        Ok(())
    }

    fn visit_u64<E: Error>(self, _: u64) -> Result<(), E> {
        Ok(())
    }

    fn visit_f64<E: Error>(self, _: f64) -> Result<(), E> {
        Ok(())
    }

    fn visit_borrowed_str<E: Error>(self, value: &'de str) -> Result<(), E> {
        if self.0.raw::<E>(value).is_err() && value == "$serde_json::private::Number" {
            // A synthetic number key, not bytes from a JSON string in the document.
            Ok(())
        } else {
            self.0.validated(value)
        }
    }

    fn visit_str<E: Error>(self, _: &str) -> Result<(), E> {
        Err(E::custom("unexpected non-borrowed JSON string"))
    }

    fn visit_string<E: Error>(self, value: String) -> Result<(), E> {
        // Only serde_json's already-validated numeric token is owned; masked document
        // strings are borrowed and validated above, without decoding allocations.
        drop(Zeroizing::new(value));
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while seq.next_element_seed(Skip(self.0))?.is_some() {}
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while map.next_key_seed(Skip(self.0))?.is_some() {
            map.next_value_seed(Skip(self.0))?;
        }
        Ok(())
    }
}

/// An actual object key, or serde_json's synthetic arbitrary-precision number tag.
/// Actual keys always borrow from the masked view. Checking that provenance before the tag
/// prevents a document key with serde's private spelling from impersonating a number.
enum ObjectKey {
    Text(Zeroizing<String>),
    Number,
}

struct AnyKey<'a, C>(Doc<'a, C>);

impl<'de, C: Custody> DeserializeSeed<'de> for AnyKey<'_, C> {
    type Value = ObjectKey;

    fn deserialize<D: serde::Deserializer<'de>>(self, de: D) -> Result<ObjectKey, D::Error> {
        de.deserialize_str(self)
    }
}

impl<'de, C: Custody> Visitor<'de> for AnyKey<'_, C> {
    type Value = ObjectKey;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("an object key or a serde_json number tag")
    }

    fn visit_borrowed_str<E: Error>(self, value: &'de str) -> Result<ObjectKey, E> {
        if self.0.raw::<E>(value).is_ok() {
            self.0.decoded(value, Held::Key).map(ObjectKey::Text)
        } else if value == "$serde_json::private::Number" {
            Ok(ObjectKey::Number)
        } else {
            Err(E::custom("invalid JSON string span"))
        }
    }
}

/// Only the synthetic number map supplies an owned string. JSON strings still use the guarded
/// decoder above; this numeric token has already been validated by serde_json's lexer.
struct NumberText;

impl<'de> DeserializeSeed<'de> for NumberText {
    type Value = serde_json::Number;

    fn deserialize<D: serde::Deserializer<'de>>(self, de: D) -> Result<Self::Value, D::Error> {
        de.deserialize_string(self)
    }
}

impl<'de> Visitor<'de> for NumberText {
    type Value = serde_json::Number;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("serde_json's numeric token")
    }

    fn visit_str<E: Error>(self, value: &str) -> Result<Self::Value, E> {
        value.parse().map_err(E::custom)
    }

    fn visit_string<E: Error>(self, value: String) -> Result<Self::Value, E> {
        self.visit_str(&Zeroizing::new(value))
    }
}

/// Where [`decode`] writes a string's characters.
trait Sink {
    fn put(&mut self, text: &str);
}

impl Sink for String {
    fn put(&mut self, text: &str) {
        self.push_str(text);
    }
}

/// A [`Sink`] that keeps nothing: validation alone.
struct Discard;

impl Sink for Discard {
    fn put(&mut self, _: &str) {}
}

/// Decode the JSON string contents `raw` (between its quotes) into `out`, refusing what
/// `serde_json` refuses, in its words. `out` never needs more than `raw.len()` bytes.
fn decode(mut raw: &[u8], out: &mut impl Sink) -> Result<(), &'static str> {
    // serde validates UTF-8 only after the closing quote, after judging every escape.
    let mut invalid_unicode = false;
    while !raw.is_empty() {
        let end = raw
            .iter()
            .position(|byte| *byte == b'\\' || *byte < 0x20)
            .unwrap_or(raw.len());
        match std::str::from_utf8(&raw[..end]) {
            Ok(text) => out.put(text),
            Err(_) => invalid_unicode = true,
        }
        raw = &raw[end..];
        let Some((&first, tail)) = raw.split_first() else {
            break;
        };
        if first != b'\\' {
            return Err(CONTROL);
        }
        let Some((&escape, tail)) = tail.split_first() else {
            return Err("EOF while parsing a string");
        };
        raw = tail;
        let ch = match escape {
            b'"' => '"',
            b'\\' => '\\',
            b'/' => '/',
            b'b' => '\u{8}',
            b'f' => '\u{c}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => {
                let first = hex4(&mut raw)?;
                let code = if (0xD800..0xDC00).contains(&first) {
                    raw = raw
                        .strip_prefix(b"\\u")
                        .ok_or("unexpected end of hex escape")?;
                    let low = hex4(&mut raw)?;
                    if !(0xDC00..0xE000).contains(&low) {
                        return Err("lone leading surrogate in hex escape");
                    }
                    0x10000 + ((first - 0xD800) << 10) + (low - 0xDC00)
                } else {
                    first
                };
                char::from_u32(code).ok_or("lone leading surrogate in hex escape")?
            }
            _ => return Err("invalid escape"),
        };
        out.put(ch.encode_utf8(&mut [0; 4]));
    }
    if invalid_unicode {
        Err("invalid unicode code point")
    } else {
        Ok(())
    }
}

/// The four hex digits of a `\u` escape at the start of `raw`, consumed.
fn hex4(raw: &mut &[u8]) -> Result<u32, &'static str> {
    let digits = raw.get(..4).ok_or("EOF while parsing a string")?;
    let mut value = 0;
    for byte in digits {
        value = value * 16 + char::from(*byte).to_digit(16).ok_or("invalid escape")?;
    }
    *raw = &raw[4..];
    Ok(value)
}

/// A settings JSON value whose strings and object keys wipe on drop, including partially parsed
/// trees and replaced duplicate values. This is for readable configuration, not extracted secret
/// responses (those use [`SelectedJson`]). Numeric scratch in serde_json is not zeroized.
#[derive(Clone)]
pub struct SettingsValue(pub(crate) Value);

impl std::fmt::Debug for SettingsValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SettingsValue(<redacted>)")
    }
}

impl std::ops::Deref for SettingsValue {
    type Target = Value;
    fn deref(&self) -> &Value {
        &self.0
    }
}

impl From<Value> for SettingsValue {
    fn from(value: Value) -> Self {
        Self(value)
    }
}

impl SettingsValue {
    fn object() -> Self {
        Self(Value::Object(serde_json::Map::new()))
    }
    fn put(&mut self, key: &mut String, value: &mut Value) {
        if let Value::Object(items) = &mut self.0 {
            if let Some(previous) = items.get_mut(key.as_str()) {
                std::mem::swap(previous, value);
            } else {
                items.insert(std::mem::take(key), std::mem::take(value));
            }
        }
    }
    fn push(&mut self, value: &mut Value) {
        if let Value::Array(items) = &mut self.0 {
            items.push(std::mem::take(value));
        }
    }
    /// Move a configuration member out, leaving null under its wiping key.
    pub fn take(&mut self, key: &str) -> Option<Self> {
        self.0.get_mut(key).map(|value| Self(std::mem::take(value)))
    }
    /// Move a configuration string out. The caller owns its cleanup from here.
    pub fn into_string(mut self) -> Option<String> {
        match &mut self.0 {
            Value::String(s) => Some(std::mem::take(s)),
            _ => None,
        }
    }
}

impl Drop for SettingsValue {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

pub(crate) fn wipe(v: &mut Value) {
    match v {
        Value::String(s) => s.zeroize(),
        Value::Number(_) => *v = Value::from(0u64),
        Value::Bool(b) => *b = false,
        Value::Array(items) => items.iter_mut().for_each(wipe),
        Value::Object(map) => {
            for (mut key, mut value) in std::mem::take(map) {
                key.zeroize();
                wipe(&mut value);
            }
        }
        Value::Null => {}
    }
}

/// Read a configuration document with guarded strings, rejecting duplicate top-level members.
/// Schema and value policy belong to the caller. Nested objects retain last-duplicate-wins
/// semantics. Entire input validation and serde's ordinary nesting bound apply.
pub fn settings_document(body: &[u8]) -> Result<SettingsValue, JsonReplyError> {
    document(body, true).map_err(JsonReplyError::from)
}

pub(crate) fn document(body: &[u8], unique_root: bool) -> Result<SettingsValue, serde_json::Error> {
    let view = masked(body, Unwatched);
    let doc = Doc {
        body,
        view: &view,
        custody: Unwatched,
    };
    let mut de = serde_json::Deserializer::from_slice(&view);
    Tree(doc, unique_root)
        .deserialize(&mut de)
        .and_then(|value| de.end().map(|()| value))
}

/// Any value, kept whole (the token's reference).
struct Tree<'a, C>(Doc<'a, C>, bool);

impl<'de, C: Custody> DeserializeSeed<'de> for Tree<'_, C> {
    type Value = SettingsValue;

    fn deserialize<D: serde::Deserializer<'de>>(self, de: D) -> Result<SettingsValue, D::Error> {
        de.deserialize_any(self)
    }
}

impl<'de, C: Custody> Visitor<'de> for Tree<'_, C> {
    type Value = SettingsValue;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_unit<E: Error>(self) -> Result<SettingsValue, E> {
        Ok(SettingsValue(Value::Null))
    }

    fn visit_bool<E: Error>(self, value: bool) -> Result<SettingsValue, E> {
        Ok(SettingsValue(Value::Bool(value)))
    }

    fn visit_i64<E: Error>(self, value: i64) -> Result<SettingsValue, E> {
        Ok(SettingsValue(Value::from(value)))
    }

    fn visit_u64<E: Error>(self, value: u64) -> Result<SettingsValue, E> {
        Ok(SettingsValue(Value::from(value)))
    }

    fn visit_f64<E: Error>(self, value: f64) -> Result<SettingsValue, E> {
        Ok(SettingsValue(Value::from(value)))
    }

    fn visit_borrowed_str<E: Error>(self, value: &'de str) -> Result<SettingsValue, E> {
        let mut text = self.0.decoded::<E>(value, Held::Value)?;
        Ok(SettingsValue(Value::String(std::mem::take(&mut *text))))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<SettingsValue, A::Error> {
        let mut items = SettingsValue(Value::Array(Vec::new()));
        while let Some(mut item) = seq.next_element_seed(Tree(self.0, false))? {
            items.push(&mut item.0);
        }
        Ok(items)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<SettingsValue, A::Error> {
        let mut tree = SettingsValue::object();
        while let Some(key) = map.next_key_seed(AnyKey(self.0))? {
            let ObjectKey::Text(mut key) = key else {
                return Ok(SettingsValue(Value::Number(
                    map.next_value_seed(NumberText)?,
                )));
            };
            if self.1 && tree.0.get(key.as_str()).is_some() {
                return Err(A::Error::custom("duplicate configuration field"));
            }
            let mut value = map.next_value_seed(Tree(self.0, false))?;
            tree.put(&mut key, &mut value.0);
        }
        Ok(tree)
    }
}

#[cfg(any(test, feature = "test-seal"))]
type Observer = fn(&'static str, &[u8]);
#[cfg(any(test, feature = "test-seal"))]
thread_local! {
    static OBSERVER: std::cell::Cell<Option<Observer>> = const { std::cell::Cell::new(None) };
}
#[cfg(any(test, feature = "test-seal"))]
pub(crate) fn observing<T>(observe: Observer, action: impl FnOnce() -> T) -> T {
    struct Restore(Option<Observer>);
    impl Drop for Restore {
        fn drop(&mut self) {
            OBSERVER.with(|slot| slot.set(self.0));
        }
    }
    let _restore = Restore(OBSERVER.with(|slot| slot.replace(Some(observe))));
    action()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn selected(body: &str, path: &[&str]) -> Vec<u8> {
        match select_json(Opaque::new(body.as_bytes().to_vec()), path).unwrap() {
            SelectedJson::Value(value) => value.wire().clone(),
            _ => panic!("expected material"),
        }
    }

    #[test]
    fn protected_selection_preserves_strings_duplicates_numbers_and_rendering() {
        for body in [
            r#"{"data":{"data":{"k":"CANARY\u002d\n\uD834\uDD1E"}}}"#,
            r#"{"data":{"data":{"k":"first","\u006b":"last"}}}"#,
            r#"{"data":{"data":{"k":1}},"data":{"data":{"k":2}}}"#,
            r#"{"data":{"data":{"k":{"z":1,"a":[true,null,"x"],"z":2}}}}"#,
            r#"{"data":{"data":{"k":1.234567890123456789e+123}}}"#,
            r#"{"data":{"data":{"k":184467440737095516160000}}}"#,
            r#"{"data":{"data":{"k":false}}}"#,
            r#"{"data":{"data":{"k":[]}}}"#,
        ] {
            let tree: Value = serde_json::from_str(body).unwrap();
            let value = &tree["data"]["data"]["k"];
            let expected = value
                .as_str()
                .map_or_else(|| value.to_string(), str::to_owned);
            assert_eq!(selected(body, &["data", "data", "k"]), expected.as_bytes());
        }
        assert_eq!(selected(r#""root""#, &[]), b"root");
        assert_eq!(
            selected(r#"{"$serde_json::private::Number":"123"}"#, &[]),
            br#"{"$serde_json::private::Number":"123"}"#
        );
    }

    #[test]
    fn protected_selection_reports_only_path_positions() {
        let select = |body: &str| select_json(Opaque::new(body.as_bytes().to_vec()), &["a", "b"]);
        assert!(matches!(
            select("{}"),
            Ok(SelectedJson::Missing { segment: 0 })
        ));
        assert!(matches!(
            select(r#"{"a":{}}"#),
            Ok(SelectedJson::Missing { segment: 1 })
        ));
        assert!(matches!(
            select(r#"{"a":[]}"#),
            Ok(SelectedJson::WrongContainer { segment: 1 })
        ));
        assert!(matches!(
            select(r#"{"a":{"b":null}}"#),
            Ok(SelectedJson::Null)
        ));
        assert_eq!(selected(r#"{"a":""}"#, &["a"]), b"");
    }

    #[test]
    fn protected_selection_validates_siblings_trailing_input_and_depth_without_leaks() {
        for body in [
            r#"{"k":"ok","CANARY-SIBLING":"CANARY\q"}"#.to_owned(),
            r#"{"k":"ok","CANARY-SIBLING":[1,]}"#.to_owned(),
            r#"{"k":"CANARY\uD800"}"#.to_owned(),
            r#"{"k":"ok"} CANARY"#.to_owned(),
            format!(r#"{{"k":"ok","s":{}{}}}"#, "[".repeat(130), "]".repeat(130)),
        ] {
            let error = select_json(Opaque::new(body.into_bytes()), &["k"])
                .err()
                .unwrap();
            assert!(!format!("{error} {error:?}").contains("CANARY"));
        }
    }

    #[test]
    fn protected_settings_share_decoder_but_keep_distinct_duplicate_policy() {
        assert!(settings_document(br#"{"x":1,"x":2}"#).is_err());
        let config = settings_document(br#"{"x":{"k":"old","k":"\u006eew"}}"#).unwrap();
        assert_eq!(config["x"]["k"], "new");
        let config: std::collections::BTreeMap<String, super::super::Cred> =
            super::super::settings(br#"{"key":"old","key":"\u006eew"}"#).unwrap();
        assert_eq!(config["key"].wire(), b"new");
        assert!(settings_document(br#"{"x":"CANARY\q"}"#).is_err());
    }

    #[test]
    fn unrelated_subtrees_are_validated_without_decoding_allocations() {
        use std::cell::Cell;
        #[derive(Clone, Copy)]
        struct Count<'a>(&'a Cell<usize>);
        impl Custody for Count<'_> {
            fn held(self, what: Held, _: &[u8]) {
                if what != Held::View {
                    self.0.set(self.0.get() + 1);
                }
            }
        }
        let body = format!(
            r#"{{"ignored":[{}],"data":{{"data":{{"k":"secret"}}}}}}"#,
            vec![r#"{"":"unused"}"#; 10_000].join(",")
        );
        let count = Cell::new(0);
        let value = select_with(body.as_bytes(), &["data", "data", "k"], Count(&count)).unwrap();
        assert!(matches!(value, SelectedJson::Value(_)));
        assert_eq!(count.get(), 5);
        assert!(select_with(
            body.replace("unused", r"bad\q").as_bytes(),
            &["k"],
            Unwatched
        )
        .is_err());
    }
}
