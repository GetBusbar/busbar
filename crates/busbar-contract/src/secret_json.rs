// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SECRET-BEARING JSON IN CUSTODY (DES-SONIC-WIPE r3 §2-§4, #162).
//!
//! A JSON document that may carry a secret (an invocation's arguments, a source's extra values) is
//! never parsed into a tree: a tree's short strings and keys sit inline in its nodes and its parse
//! keeps a copy of the document, and neither can be wiped. It is held as one canonical text in a
//! wiping buffer, [`SecretJson`], and read on demand through the borrowed reader
//! (`json::from_slice_borrowed`) into a caller's wiping arena: a [`JsonView`] or a typed value
//! borrows every string, key and number lexeme from the text or the arena, and copies none of
//! them.
//!
//! Text moves in only from custody ([`SecretJson::from_secure`]) or from a public tree
//! ([`SecretJson::from_public`]), and out only into custody ([`SecretJson::into_secure`],
//! [`SecretJson::write_into`], [`SecretJson::take_str`]). There is no conversion from or to a
//! `String`, a `&str` or a `json::Value`. Non-secret JSON keeps the plain facade.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt;
use std::marker::PhantomData;

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::ser::{Serialize, SerializeStruct, Serializer};
use zeroize::Zeroize as _;

use crate::json;
use crate::secure::{SecureString, SecureVec};

/// One JSON document as canonical compact text in custody: object keys in byte order, the last of
/// duplicate keys kept, numbers verbatim, the JSON writer's escapes (the text `serde_json` wrote for
/// the same document, so screening, counting and egress see the bytes they saw before). Nested no
/// deeper than `json::MAX_JSON_DEPTH`. Wiped on drop; `Clone` copies into new custody of exact size;
/// equality is constant-time; `Debug` prints the length only.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretJson {
    text: SecureString,
    /// How deeply the document nests (a scalar is 0): it sizes the stack a read of it wipes.
    depth: usize,
}

/// Why a text was not taken into custody. Its text is fixed words and a position, never input.
#[derive(Debug, Clone, Copy)]
pub enum SecretJsonError {
    /// The text is not one JSON document (or not UTF-8).
    Json(json::BorrowedError),
    /// The text nests deeper than `json::MAX_JSON_DEPTH`.
    TooDeep,
    /// The canonical text's buffer could not be allocated.
    Overflow,
}

impl fmt::Display for SecretJsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(f, "secret JSON refused: {error}"),
            Self::TooDeep => write!(f, "secret JSON nesting exceeds {}", json::MAX_JSON_DEPTH),
            Self::Overflow => f.write_str("secret JSON buffer allocation failed"),
        }
    }
}

impl std::error::Error for SecretJsonError {}

impl SecretJson {
    /// Take `text` into custody as its canonical form. `text` and the decode arena are wiped on
    /// every path, the refusal included.
    ///
    /// # Errors
    /// [`SecretJsonError::TooDeep`] past `json::MAX_JSON_DEPTH`; [`SecretJsonError::Json`] when `text`
    /// is not exactly one JSON document in UTF-8; [`SecretJsonError::Overflow`] when the canonical
    /// buffer cannot be allocated.
    pub fn from_secure(text: SecureVec) -> Result<Self, SecretJsonError> {
        let taken = Self::canonical(text);
        // A refused text may have been read to any depth it holds (at most the maximum).
        wipe_stack(
            taken
                .as_ref()
                .map_or(json::MAX_JSON_DEPTH, |held| held.depth),
        );
        taken
    }

    /// [`Self::from_secure`] before its stack wipe.
    fn canonical(text: SecureVec) -> Result<Self, SecretJsonError> {
        if json::exceeds_max_depth(&text, json::MAX_JSON_DEPTH) {
            return Err(SecretJsonError::TooDeep);
        }
        let mut arena = SecureVec::zeroed(text.len());
        let view: JsonView<'_> =
            json::from_slice_borrowed(&text, &mut arena).map_err(SecretJsonError::Json)?;
        // Canonical text is never longer than its input: every escape the writer emits stood for
        // an escape at least as long, and whitespace and overridden members only go. So this is
        // room enough, allocated once.
        let mut out =
            SecureVec::with_capacity(text.len()).map_err(|_| SecretJsonError::Overflow)?;
        json::to_writer(&mut out, &view).map_err(|_| SecretJsonError::Overflow)?;
        debug_assert!(
            out.len() <= text.len(),
            "canonical JSON is never longer than its input"
        );
        Ok(Self::adopt(out, view.depth()))
    }

    /// The canonical text of a public tree: for fixtures, and for a plugin that builds its
    /// arguments from a plain tree of its own (plane-mcp until plane-mcp#25). Never for text that
    /// arrived in custody; that is [`Self::from_secure`].
    ///
    /// # Errors
    /// A tree the JSON writer refuses, or one nested deeper than `json::MAX_JSON_DEPTH`.
    pub fn from_public(tree: &json::Value) -> Result<Self, json::Error> {
        let mut text = SecureVec::new();
        json::to_writer(&mut text, tree)?;
        Self::from_secure(text).map_err(<json::Error as serde::ser::Error>::custom)
    }

    /// The writer's bytes, adopted: they are UTF-8 by construction (strings it was handed as `&str`
    /// and ASCII punctuation).
    fn adopt(out: SecureVec, depth: usize) -> Self {
        let text = String::from_utf8(out.into_vec()).expect("the JSON writer writes UTF-8");
        Self {
            text: SecureString::from(text),
            depth,
        }
    }

    /// The canonical text, borrowed. Copy it only into custody: a plain copy is a leak (R4).
    #[must_use]
    pub fn as_json(&self) -> &str {
        self.text.as_str()
    }

    /// The document as a borrowed [`JsonView`]: its strings borrow the text, or `arena` where an
    /// escape had to be decoded. `arena` is grown to the text's length when it is shorter; it is a
    /// wiping buffer, so the decoded bytes are wiped when it drops.
    ///
    /// # Errors
    /// None for a document in custody; the reader's refusal is passed through.
    pub fn view<'a>(
        &'a self,
        arena: &'a mut SecureVec,
    ) -> Result<JsonView<'a>, json::BorrowedError> {
        self.decode(arena)
    }

    /// The document read into `T`, borrowed as [`Self::view`] is. `T` keeps its text as `&'a str`,
    /// `json::BorrowedRaw<'a>` or [`JsonView<'a>`], or in custody (`SecureString`, `SecureVec`, or a
    /// struct of them that wipes on drop). A `T` that owns a `String`, `Vec<u8>`, `Box<str>`,
    /// `Cow::Owned` or `json::Value` would make a plain copy, and is not allowed here (busbar#464).
    ///
    /// # Errors
    /// A document `T` refuses, as fixed words and a position.
    pub fn decode<'a, T: Deserialize<'a>>(
        &'a self,
        arena: &'a mut SecureVec,
    ) -> Result<T, json::BorrowedError> {
        let len = self.text.len();
        if arena.len() < len {
            *arena = SecureVec::zeroed(len);
        }
        let read = json::from_slice_borrowed(self.text.as_bytes(), &mut arena[..]);
        wipe_stack(self.depth);
        read
    }

    /// The string at the JSON pointer `pointer`, copied once into custody; `None` when nothing is
    /// there or it is not a string.
    #[must_use]
    pub fn take_str(&self, pointer: &str) -> Option<SecureString> {
        let mut arena = SecureVec::new();
        let view = self.view(&mut arena).ok()?;
        match view.pointer(pointer)? {
            JsonView::Str(text) => Some(SecureString::from(*text)),
            _ => None,
        }
    }

    /// Append the canonical text to `out` (an egress body in custody).
    pub fn write_into(&self, out: &mut SecureVec) {
        out.extend_from_slice(self.text.as_bytes());
    }

    /// The canonical text's bytes, still in custody, without a copy.
    #[must_use]
    pub fn into_secure(self) -> SecureVec {
        self.text.into_bytes()
    }
}

/// The stack a read of secret text writes below its caller, as a base plus a step per level the
/// document nests, measured on engine-devbox-3 by painting the stack and reading back the lowest
/// byte written (from_secure, decode, digest_of; flat documents of 41 B and 1.2 KiB, nested 16,
/// 64 and 128 deep). Optimised: at most 2.1 KiB flat, 752 B per level, digest_of 0.9 KiB.
/// Unoptimised (this crate at opt-level 0, its dependencies at 3): about 3.1 KiB per level, and
/// the flat residue the wipe tests found lay within 36 KiB of the caller. Each bound is about
/// twice what was measured.
#[cfg(not(debug_assertions))]
const WIPE_BASE: usize = 4 * 1024;
#[cfg(not(debug_assertions))]
const WIPE_PER_LEVEL: usize = 1024;
#[cfg(debug_assertions)]
const WIPE_BASE: usize = 64 * 1024;
#[cfg(debug_assertions)]
const WIPE_PER_LEVEL: usize = 6 * 1024;
/// One frame of [`wipe_chunks`].
const WIPE_CHUNK: usize = 4 * 1024;

/// Overwrite the stack the read that just returned used, for a document nesting `depth` levels.
/// The SIMD JSON reader and writer, the UTF-8 check and the SHA-256 block function keep 16- to
/// 64-byte pieces of their input in registers that spill into their own frames, and nothing wipes
/// a frame when it returns: a short secret (one load holds all of it) survives there whole. Every
/// reader of secret text calls this on every exit, after the work and before its result goes back
/// to the caller, so the next frames to use that stack are these (zeroed) and the caller's own.
/// A plain zero fill, as every hot wipe here is (`secure` rule 5).
pub(crate) fn wipe_stack(depth: usize) {
    let bytes = WIPE_BASE + depth.min(json::MAX_JSON_DEPTH) * WIPE_PER_LEVEL;
    wipe_chunks(bytes.div_ceil(WIPE_CHUNK));
}

/// `left` frames of zeroed [`WIPE_CHUNK`] bytes, one below the other. The array is observed after
/// the inner call too, so each frame stays live (no tail call reuses it) and its zeros are stored.
#[inline(never)]
fn wipe_chunks(left: usize) {
    let area = [0_u8; WIPE_CHUNK];
    std::hint::black_box(&area);
    if left > 1 {
        wipe_chunks(left - 1);
    }
    std::hint::black_box(&area);
}

/// `null`, as an absent document reads (so `std::mem::take` leaves one behind).
impl Default for SecretJson {
    fn default() -> Self {
        Self {
            text: SecureString::from("null"),
            depth: 0,
        }
    }
}

impl fmt::Debug for SecretJson {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretJson")
            .field("len", &self.text.len())
            .finish()
    }
}

/// One JSON document read borrowed: pointers and lengths only, no byte of the document copied.
/// A number keeps its lexeme exactly as written.
pub enum JsonView<'a> {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// A number's lexeme.
    Number(&'a str),
    /// A string's decoded text.
    Str(&'a str),
    /// An array's items, in order.
    Array(Vec<JsonView<'a>>),
    /// An object's members by key (byte order); of duplicate keys the last is kept.
    Object(BTreeMap<&'a str, JsonView<'a>>),
}

impl<'a> JsonView<'a> {
    /// How deeply this value nests: a scalar is 0, an array or object one more than its deepest
    /// item.
    #[must_use]
    pub fn depth(&self) -> usize {
        match self {
            JsonView::Array(items) => 1 + items.iter().map(JsonView::depth).max().unwrap_or(0),
            JsonView::Object(members) => {
                1 + members.values().map(JsonView::depth).max().unwrap_or(0)
            }
            _ => 0,
        }
    }

    /// The value at the JSON pointer `pointer` (RFC 6901: `""` is this value; `/`-separated
    /// tokens, `~1` for `/` and `~0` for `~`; an array index is decimal without a leading zero).
    #[must_use]
    pub fn pointer(&self, pointer: &str) -> Option<&JsonView<'a>> {
        if pointer.is_empty() {
            return Some(self);
        }
        pointer
            .strip_prefix('/')?
            .split('/')
            .try_fold(self, |at, token| {
                let token: Cow<'_, str> = if token.contains('~') {
                    Cow::Owned(token.replace("~1", "/").replace("~0", "~"))
                } else {
                    Cow::Borrowed(token)
                };
                match at {
                    JsonView::Object(members) => members.get(token.as_ref()),
                    JsonView::Array(items) => {
                        let index = token.as_ref();
                        let decimal = !index.is_empty()
                            && index.bytes().all(|b| b.is_ascii_digit())
                            && (index == "0" || !index.starts_with('0'));
                        decimal
                            .then(|| index.parse::<usize>().ok())
                            .flatten()
                            .and_then(|at| items.get(at))
                    }
                    _ => None,
                }
            })
    }
}

/// The kind and size only: a view's text is secret.
impl fmt::Debug for JsonView<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JsonView::Null => f.write_str("Null"),
            JsonView::Bool(_) => f.write_str("Bool"),
            JsonView::Number(_) => f.write_str("Number"),
            JsonView::Str(text) => f.debug_struct("Str").field("len", &text.len()).finish(),
            JsonView::Array(items) => f.debug_struct("Array").field("len", &items.len()).finish(),
            JsonView::Object(members) => f
                .debug_struct("Object")
                .field("len", &members.len())
                .finish(),
        }
    }
}

/// The refusal of a string handed over as an owned copy: on a secret path every string is
/// borrowed from the text or the arena.
const OWNED_STRING: &str = "owned string on a secret path";

struct ViewVisitor<'a>(PhantomData<JsonView<'a>>);

impl<'de: 'a, 'a> Visitor<'de> for ViewVisitor<'a> {
    type Value = JsonView<'a>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value read borrowed")
    }

    fn visit_unit<E: de::Error>(self) -> Result<JsonView<'a>, E> {
        Ok(JsonView::Null)
    }

    fn visit_none<E: de::Error>(self) -> Result<JsonView<'a>, E> {
        Ok(JsonView::Null)
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<JsonView<'a>, E> {
        Ok(JsonView::Bool(value))
    }

    fn visit_borrowed_str<E: de::Error>(self, text: &'de str) -> Result<JsonView<'a>, E> {
        Ok(JsonView::Str(text))
    }

    fn visit_str<E: de::Error>(self, _text: &str) -> Result<JsonView<'a>, E> {
        Err(E::custom(OWNED_STRING))
    }

    fn visit_string<E: de::Error>(self, mut text: String) -> Result<JsonView<'a>, E> {
        text.zeroize();
        Err(E::custom(OWNED_STRING))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<JsonView<'a>, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element::<JsonView<'a>>()? {
            items.push(item);
        }
        Ok(JsonView::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<JsonView<'a>, A::Error> {
        let Some(first) = map.next_key::<&'a str>()? else {
            return Ok(JsonView::Object(BTreeMap::new()));
        };
        // The reader hands a number as a one-entry map keyed by the number token itself (by
        // address, so a document key spelled the same is an ordinary key).
        if json::is_number_token(first) {
            return Ok(JsonView::Number(map.next_value::<&'a str>()?));
        }
        let mut members = BTreeMap::new();
        members.insert(first, map.next_value::<JsonView<'a>>()?);
        while let Some((key, value)) = map.next_entry::<&'a str, JsonView<'a>>()? {
            members.insert(key, value);
        }
        Ok(JsonView::Object(members))
    }
}

/// Borrowed strings only: a string the reader would hand over as an owned copy is refused.
impl<'de: 'a, 'a> Deserialize<'de> for JsonView<'a> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(ViewVisitor(PhantomData))
    }
}

/// Compact JSON through the facade's writer: members in key order, a number's lexeme written
/// verbatim as the writer's raw-number token (no copy of it is made).
impl Serialize for JsonView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            JsonView::Null => serializer.serialize_unit(),
            JsonView::Bool(value) => serializer.serialize_bool(*value),
            JsonView::Number(lexeme) => {
                let mut number = serializer.serialize_struct(json::NUMBER_TOKEN, 1)?;
                number.serialize_field(json::NUMBER_TOKEN, lexeme)?;
                number.end()
            }
            JsonView::Str(text) => serializer.serialize_str(text),
            JsonView::Array(items) => serializer.collect_seq(items),
            JsonView::Object(members) => serializer.collect_map(members),
        }
    }
}
