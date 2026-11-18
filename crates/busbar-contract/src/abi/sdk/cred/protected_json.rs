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

use crate::abi::sdk::wipe::wipe_bytes;
use crate::secure::{SecureString, SecureVec};
use serde::de::{DeserializeSeed, Error, MapAccess, SeqAccess, Visitor};

use super::{Held as Opaque, JsonReplyError};
#[cfg(test)]
use crate::plugin_settings::guarded_reader::observing;
use crate::plugin_settings::guarded_reader::{
    masked, AnyKey, Custody, Doc, Held, NumberText, ObjectKey, Unwatched,
};

/// Structural outcome of selecting an object-field path. Indices refer only to the supplied
/// path: errors never disclose a response value or a sibling's name.
#[expect(
    missing_debug_implementations,
    reason = "holds secret bytes: no Debug, so none can print"
)]
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
    let selected = select_with(body.wire(), path, Unwatched);
    // The body is consumed: wiped as soon as its value is selected.
    drop(body);
    selected.map_err(JsonReplyError::from)
}

/// Read selected text members of a JSON object into wiping holders. Missing and null members
/// return `None`; other types and duplicate selected members are refused. Unselected members
/// are validated without retaining their values. Escaped names match their decoded spelling.
///
/// This recipe serves callers that must inspect token text (for example a JWT verifier). The
/// caller owns and must bound the input; it is not wiped by this borrowing function. Decoded
/// strings and temporary buffers wipe on every exit. Serde's numeric scratch remains an
/// upstream limitation, as with [`select_json`].
pub fn json_text_members<const N: usize>(
    body: &[u8],
    names: [&str; N],
) -> Result<[Option<SecureString>; N], JsonReplyError> {
    let view = masked(body, Unwatched);
    let doc = Doc {
        body,
        view: &view,
        custody: Unwatched,
    };
    let mut de = serde_json::Deserializer::from_slice(&view);
    serde::Deserializer::deserialize_map(&mut de, TextMembers { doc, names })
        .and_then(|members| de.end().map(|()| members))
        .map_err(JsonReplyError::from)
}

struct TextMembers<'a, C, const N: usize> {
    doc: Doc<'a, C>,
    names: [&'a str; N],
}

impl<'de, C: Custody, const N: usize> Visitor<'de> for TextMembers<'_, C, N> {
    type Value = [Option<SecureString>; N];

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a JSON object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut values = std::array::from_fn(|_| None);
        let mut seen = [false; N];
        while let Some(key) = map.next_key_seed(AnyKey(self.doc))? {
            let ObjectKey::Text(key) = key else {
                return Err(A::Error::custom("expected a JSON object"));
            };
            if let Some(index) = name_index(&self.names, key.as_str()) {
                if std::mem::replace(&mut seen[index], true) {
                    return Err(A::Error::custom("duplicate selected field"));
                }
                values[index] = map.next_value_seed(TextMember(self.doc))?;
            } else {
                map.next_value_seed(Skip(self.doc))?;
            }
        }
        Ok(values)
    }
}

struct TextMember<'a, C>(Doc<'a, C>);

impl<'de, C: Custody> DeserializeSeed<'de> for TextMember<'_, C> {
    type Value = Option<SecureString>;

    fn deserialize<D: serde::Deserializer<'de>>(self, de: D) -> Result<Self::Value, D::Error> {
        de.deserialize_any(self)
    }
}

impl<'de, C: Custody> Visitor<'de> for TextMember<'_, C> {
    type Value = Option<SecureString>;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a string or null")
    }

    fn visit_unit<E: Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_borrowed_str<E: Error>(self, value: &'de str) -> Result<Self::Value, E> {
        self.0.decoded(value, Held::Value).map(Some)
    }
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
        Ok(SelectedJson::Value(Opaque::new(out.exact().into_vec())))
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
        let text = self.0.decoded::<E>(value, Held::Value)?;
        Ok(SelectedJson::Value(Opaque::new(
            text.into_string().into_bytes(),
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
        Ok(SelectedJson::Value(Opaque::new(out.exact().into_vec())))
    }

    fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<SelectedJson, A::Error> {
        let mut out = Guarded::empty(self.0.custody);
        Render {
            doc: self.0,
            out: &mut out,
            lead: b"",
        }
        .visit_map(map)?;
        Ok(SelectedJson::Value(Opaque::new(out.exact().into_vec())))
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
            let value = name.end..arena.len();
            arena.member(Member { name, value });
        }
        out.push(b"{");
        let mut lead: &[u8] = b"";
        for member in &arena.2 {
            let name = arena.get(&member.name);
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
/// freed unwiped; dropping it wipes it too. An object's arena also keeps its members (ranges of
/// the buffer, no bytes) in the parsed value's map order.
struct Guarded<C: Custody>(Vec<u8>, C, Vec<Member>);

impl<C: Custody> Guarded<C> {
    fn empty(custody: C) -> Self {
        Self(Vec::new(), custody, Vec::new())
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn get(&self, range: &Range<usize>) -> &[u8] {
        self.0.get(range.clone()).unwrap_or_default()
    }

    /// Enter an object member whose name and value are already written here, in the parsed
    /// value's map order (byte order of the names): a later member of an equal name replaces the
    /// earlier, as the parsed value keeps the last.
    fn member(&mut self, member: Member) {
        let name = self.get(&member.name);
        match self.2.binary_search_by(|m| self.get(&m.name).cmp(name)) {
            Ok(i) => self.2[i] = member,
            Err(i) => self.2.insert(i, member),
        }
    }

    fn push(&mut self, bytes: &[u8]) {
        let needed = self.0.len().saturating_add(bytes.len());
        if needed > self.0.capacity() {
            // The block `append` is about to retire, recorded while it still holds the value.
            self.1.held(Held::Value, &self.0);
        }
        if needed > self.0.capacity() {
            let next = Vec::with_capacity(needed.max(self.0.capacity().saturating_mul(2)));
            let mut old = std::mem::replace(&mut self.0, next);
            self.0.extend_from_slice(&old);
            wipe_bytes(&mut old);
        }
        self.0.extend_from_slice(bytes);
    }

    /// Write `value` as `serde_json` writes it.
    fn json<T: serde::Serialize + ?Sized, E: Error>(&mut self, value: &T) -> Result<(), E> {
        serde_json::to_writer(&mut *self, value).map_err(E::custom)
    }

    /// The text in a buffer of exactly its length; this one is reported to `custody`, then wiped.
    fn exact(self) -> SecureVec {
        let text = SecureVec::from(self.0.as_slice());
        self.1.held(Held::Value, &text);
        text
    }
}

impl<C: Custody> Drop for Guarded<C> {
    fn drop(&mut self) {
        self.1.held(Held::Value, &self.0);
        wipe_bytes(&mut self.0);
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
        drop(SecureString::from(value));
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

/// The index of `key` among a reader's selected names (a handful, fixed by its caller).
fn name_index(names: &[&str], key: &str) -> Option<usize> {
    names.iter().position(|name| *name == key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::sdk::cred::settings_document;
    use serde_json::Value;

    #[test]
    fn text_members_decode_escapes_and_ignore_nested_or_unknown_values() {
        let body = br#"{"nested":{"token":"ignored"},"nested":null,"to\u006ben":"A\n\uD834\uDD1E","empty":"","nullable":null,"number":184467440737095516160000}"#;
        let [token, empty, nullable, absent] =
            json_text_members(body, ["token", "empty", "nullable", "absent"]).unwrap();
        let token = token.unwrap();
        assert_eq!(token.as_str(), "A\n\u{1D11E}");
        assert_eq!(token.capacity(), br"A\n\uD834\uDD1E".len());
        assert_eq!(empty.as_deref(), Some(""));
        assert!(nullable.is_none());
        assert!(absent.is_none());
    }

    #[test]
    fn text_members_reject_ambiguous_types_and_malformed_siblings_without_echo() {
        for body in [
            r#"{"token":"CANARY","to\u006ben":null}"#.to_owned(),
            r#"{"token":null,"token":"CANARY"}"#.to_owned(),
            r#"{"token":{"CANARY":1}}"#.to_owned(),
            r#"{"token":184467440737095516160000}"#.to_owned(),
            r#"{"token":true}"#.to_owned(),
            r#"{"token":["CANARY"]}"#.to_owned(),
            r#"{"token":"CANARY\uD800"}"#.to_owned(),
            r#"{"token":"CANARY","ignored":"bad\q"}"#.to_owned(),
            r#"{"token":"CANARY","bad\q":null}"#.to_owned(),
            r#"{"token":"CANARY"} trailing"#.to_owned(),
            r#"["CANARY"]"#.to_owned(),
            "184467440737095516160000".to_owned(),
            format!(
                r#"{{"token":"CANARY","ignored":{}{}}}"#,
                "[".repeat(130),
                "]".repeat(130)
            ),
        ] {
            let error = json_text_members(body.as_bytes(), ["token"]).unwrap_err();
            assert!(!format!("{error} {error:?}").contains("CANARY"));
        }
        assert!(json_text_members(b"{\"token\":\"\xff\"}", ["token"]).is_err());
    }

    #[test]
    fn text_members_wipe_allocations_on_success_and_partial_failure() {
        use crate::alloc_counter::{watch_initialized_payload, InitializedPayloadProbe};

        fn observe(_: &'static str, bytes: &[u8]) {
            // SAFETY: guarded parser buffers are exclusively owned on this thread, and the
            // observer receives their initialized allocation prefixes before they are freed.
            unsafe { watch_initialized_payload(bytes) };
        }
        for (body, valid) in [
            (
                r#"{"token":"CANARY\u002dtoken","unknown":{"key":"not decoded"}}"#,
                true,
            ),
            (r#"{"token":"CANARY\u002dtoken","unknown":[1,]}"#, false),
            (r#"{"token":"CANARY\u002dtoken"} trailing"#, false),
            (r#"{"token":"CANARY\uD800"}"#, false),
        ] {
            // SAFETY: every observed allocation remains initialized and exclusively owned
            // on this thread until its wiping holder drops within the observation scope.
            let probe = unsafe { InitializedPayloadProbe::start().unwrap() };
            observing(observe, || {
                let result = json_text_members(body.as_bytes(), ["token"]);
                assert_eq!(result.is_ok(), valid);
                drop(result);
            });
            let observed = probe.finish();
            assert!(!observed.reentered);
            assert!(observed.payloads.len() >= 3, "view, key and selected value");
            for payload in observed.payloads {
                assert!(payload.freed, "parser allocation survived: {payload:?}");
                assert!(!payload.reallocated, "decoded strings must not reallocate");
                #[cfg(target_os = "linux")]
                {
                    assert_eq!(payload.read_error, None);
                    assert!(payload.complete_read);
                    assert!(
                        payload.wiped,
                        "parser allocation freed unwiped: {payload:?}"
                    );
                }
                #[cfg(not(target_os = "linux"))]
                assert_eq!(payload.read_error, Some(std::io::ErrorKind::Unsupported));
            }
        }
    }

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
