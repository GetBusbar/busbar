// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! YAML for busbar: one parser and emitter, serde-saphyr (YAML 1.2, `forbid(unsafe_code)`), with
//! every option pinned to the meaning busbar 1.5.5 gave a configuration file, and one untyped tree,
//! ciborium's [`Value`], whose mappings keep their key order as a `Vec` of pairs.
//!
//! Every YAML read and write in core and in the plugins goes through this module. Nothing here is
//! a YAML parser, emitter or value type of our own: the parser and emitter are serde-saphyr's, the
//! tree is ciborium's, and the traits below only add serde_yaml-style lookups to that tree.
//!
//! What the pins keep from 1.5.5 (serde_yaml_ng 0.10 on libyaml), each with a test in
//! `tests/yaml_1_5_5_meaning.rs`:
//! - `yes`, `no`, `on`, `off`, `y`, `n` (any case) are strings, never booleans.
//! - Integers with redundant leading zeros (`0644`, `-007`, `+00`) are strings when read untyped.
//! - A quoted scalar (`'1024'`, `"true"`) is a string: an integer, float or boolean field
//!   refuses it.
//! - Numbers with underscores (`1_000`) are strings when read untyped.
//! - `1:30` (sexagesimal) is a string.
//! - `<<` is a literal key; merge keys are not expanded.
//! - A duplicate key means what it meant to the reader, as serde_yaml left it to the visitor: an
//!   untyped read ([`Value`], [`Mapping`]) refuses it (`duplicate entry with key "k"`, with the
//!   line and column of the repeat), a struct refuses it with serde's `duplicate field`, and a
//!   map (`HashMap`, `BTreeMap`, `IndexMap`) keeps the last value.
//! - `.inf`, `-.inf` and `.nan` are floats.
//! - Application tags (`!Tag value`) are accepted, as 1.5.5 accepted them, and an untyped read
//!   keeps them: a tagged node is a [`Value::Tag`] whose number names the tag through this
//!   module's registry ([`tag_id`], [`tag_name`]), as serde_yaml's `Value::Tagged` named it. Read
//!   on into an enum, `!Variant` selects the variant; written out, the tag is written back.
//! - A typed enum is written as serde_yaml wrote it: a unit variant as its plain name (`Variant`),
//!   a newtype, tuple or struct variant as `!Variant` over its payload (`!Size 127`, `!Rgb` over
//!   a sequence, `!Color` over a mapping), never serde-saphyr's `Variant: payload` mapping.
//! - A character outside YAML's printable set anywhere in the text (`\u{7}`, `\u{7f}`) refuses
//!   the document, as libyaml's reader refused it.
//! - A byte order mark after the first character is content, as libyaml read it, in an untyped
//!   read (`k: \u{feff}x` is the string `"\u{feff}x"`).
//! - Sequences and mappings nest 128 deep, as serde_yaml's recursion limit allowed.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::fmt;
use std::sync::{Mutex, OnceLock, PoisonError};

use serde::de::{DeserializeOwned, DeserializeSeed};
use serde::Serialize;

pub use ciborium::Value;
pub use serde_saphyr::{Deserializer, Location, Spanned};

/// The key/value pairs of a [`Value::Map`], in document order: the tree's own mapping payload.
pub type Pairs = Vec<(Value, Value)>;

/// A YAML mapping as serde_yaml's `Mapping` was: its pairs keep their insertion order for output,
/// and equality ignores that order (same keys, equal values; nested mappings likewise), as an
/// `IndexMap`'s did. It derefs to its [`Pairs`], so [`MappingExt`] and the `Vec` methods apply.
#[derive(Clone, Debug, Default)]
pub struct Mapping(Pairs);

impl Mapping {
    /// An empty mapping.
    #[must_use]
    pub fn new() -> Self {
        Self(Pairs::new())
    }

    /// An empty mapping with room for `capacity` pairs.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self(Pairs::with_capacity(capacity))
    }
}

impl std::ops::Deref for Mapping {
    type Target = Pairs;
    fn deref(&self) -> &Pairs {
        &self.0
    }
}

impl std::ops::DerefMut for Mapping {
    fn deref_mut(&mut self) -> &mut Pairs {
        &mut self.0
    }
}

impl From<Pairs> for Mapping {
    fn from(pairs: Pairs) -> Self {
        Self(pairs)
    }
}

impl From<Mapping> for Pairs {
    fn from(mapping: Mapping) -> Self {
        mapping.0
    }
}

impl From<Mapping> for Value {
    fn from(mapping: Mapping) -> Self {
        Value::Map(mapping.0)
    }
}

impl IntoIterator for Mapping {
    type Item = (Value, Value);
    type IntoIter = std::vec::IntoIter<(Value, Value)>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a Mapping {
    type Item = &'a (Value, Value);
    type IntoIter = std::slice::Iter<'a, (Value, Value)>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<'a> IntoIterator for &'a mut Mapping {
    type Item = &'a mut (Value, Value);
    type IntoIter = std::slice::IterMut<'a, (Value, Value)>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter_mut()
    }
}

impl FromIterator<(Value, Value)> for Mapping {
    fn from_iter<T: IntoIterator<Item = (Value, Value)>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl Extend<(Value, Value)> for Mapping {
    fn extend<T: IntoIterator<Item = (Value, Value)>>(&mut self, iter: T) {
        self.0.extend(iter);
    }
}

impl PartialEq for Mapping {
    /// serde_yaml's `Mapping` equality: the same keys with equal values, in any order.
    fn eq(&self, other: &Self) -> bool {
        same_pairs(&self.0, &other.0)
    }
}

impl Serialize for Mapping {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (key, value) in &self.0 {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

impl<'de> serde::Deserialize<'de> for Mapping {
    /// A YAML mapping, keeping its key order; null reads as an empty mapping, and a repeated key
    /// is refused (`duplicate entry with key "k"`), as serde_yaml's did.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match untag(untyped(deserializer)?) {
            Value::Map(pairs) => Ok(Self(pairs)),
            Value::Null => Ok(Self::new()),
            other => Err(serde::de::Error::invalid_type(
                unexpected(&other),
                &"a YAML mapping",
            )),
        }
    }
}

/// Whether two trees say the same thing, as serde_yaml (1.5.5) compared them: a mapping equals
/// another with the same keys and equal values in ANY order (serde_yaml's `Mapping` was an
/// `IndexMap`, whose equality ignores order), a sequence compares element by element, and NaN
/// equals NaN (YAML has one NaN). [`Value`]'s own `==` is order-sensitive over mappings.
#[must_use]
pub fn same_tree(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Map(a), Value::Map(b)) => same_pairs(a, b),
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(a, b)| same_tree(a, b))
        }
        (Value::Float(a), Value::Float(b)) => a == b || (a.is_nan() && b.is_nan()),
        (Value::Tag(at, a), Value::Tag(bt, b)) => at == bt && same_tree(a, b),
        (a, b) => a == b,
    }
}

/// [`same_tree`] over two mappings' pairs.
fn same_pairs(a: &[(Value, Value)], b: &[(Value, Value)]) -> bool {
    a.len() == b.len()
        && a.iter().all(|(key, value)| {
            b.iter()
                .find(|(other, _)| same_tree(key, other))
                .is_some_and(|(_, other)| same_tree(value, other))
        })
}

/// Everything a YAML call site needs in scope: the tree, the mapping, and their lookups.
pub mod prelude {
    pub use super::{Index, Mapping, MappingExt, Pairs, Value, ValueExt};
}

/// The parser options, pinned to 1.5.5's meaning. The one place they are set.
#[must_use]
pub fn options() -> serde_saphyr::Options {
    use serde_saphyr::{DuplicateKeyPolicy, MergeKeyPolicy, NonFiniteFloatPolicy};
    serde_saphyr::options! {
        null_scalars_as_text: true,
        // serde_yaml's rule: a quoted scalar is a string, never a number or a boolean.
        quoted_scalars_are_strings: true,
        // serde_yaml's rule: a unit struct reads only from null, never from `{}`.
        unit_structs_refuse_mappings: true,
        // serde_yaml's rule: `!!null` with non-null text (`!!null str`) is refused.
        null_tag_requires_null_text: true,
        // serde_yaml's placement: a missing field is reported at its mapping's start.
        missing_field_at_mapping_start: true,
        lowercase_radix_prefixes_only: true,
        bom_inside_document_as_content: true,
        // libyaml's rule: an auto-detected block scalar is indented at least one column.
        block_scalar_indent_at_least_one: true,
        // serde_yaml's rule: each repeated entry reaches the reader, which decides (a struct
        // refuses it, a map keeps the last value, an untyped read refuses it; see `untyped`).
        duplicate_keys: DuplicateKeyPolicy::PassThrough,
        merge_keys: MergeKeyPolicy::AsOrdinary,
        strict_booleans: true,
        legacy_octal_numbers: false,
        leading_zero_numbers_as_strings: true,
        underscored_numbers_as_strings: true,
        ignore_binary_tag_for_string: true,
        reject_unsupported_tags: false,
        non_finite_float_policy: NonFiniteFloatPolicy::PassThrough,
        with_snippet: false,
        // serde_yaml's recursion limit: 128 nested sequences or mappings read, the 129th
        // refused (serde-saphyr's default budget stops at 64).
        budget: serde_saphyr::budget! { max_depth: MAX_DEPTH },
    }
}

/// How deep sequences and mappings may nest, as serde_yaml's `remaining_depth` allowed.
const MAX_DEPTH: usize = 128;

/// Whether libyaml's reader accepted `c` in a YAML stream: YAML's printable set. Any other
/// character anywhere in the text (a scalar, a comment, a key) made 1.5.5 refuse the whole
/// document with `control characters are not allowed`; granit-parser lets some through (an
/// ASCII control inside a plain scalar), so the refusal is made here, before parsing.
fn libyaml_printable(c: char) -> bool {
    matches!(
        u32::from(c),
        0x09 | 0x0A
            | 0x0D
            | 0x20..=0x7E
            | 0x85
            | 0xA0..=0xD7FF
            | 0xE000..=0xFFFD
            | 0x1_0000..=0x10_FFFF
    )
}

/// 1.5.5's refusal of a document holding a character outside YAML's printable set, placed at the
/// first one (1-based line and column, in characters).
fn refuse_control_characters(text: &str) -> Result<(), Error> {
    let (mut line, mut column) = (1u64, 1u64);
    for c in text.chars() {
        if !libyaml_printable(c) {
            return Err(Error {
                message: "control characters are not allowed".to_owned(),
                path: None,
                location: located(line, column),
                placed_suffix: true,
            });
        }
        if c == '\n' {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }
    Ok(())
}

/// A [`Location`] at `line` and `column` (serde-saphyr builds them; its `Deserialize` is public).
fn located(line: u64, column: u64) -> Option<Location> {
    use serde::Deserialize;
    let fields = Value::Map(vec![
        (Value::from("line"), Value::from(line)),
        (Value::from("column"), Value::from(column)),
    ]);
    Location::deserialize(deserializer(fields)).ok()
}

/// A byte order mark after the first character, read as libyaml read it: an ordinary printable
/// character, content of the scalar it is in, or the first character of a plain scalar
/// (`k: \u{feff}[x]` is the string `"\u{feff}[x]"`). granit-parser refuses one that starts a token
/// (`BomInsideDocument`), so for an untyped read each is swapped for a private-use character the
/// text does not hold, which granit-parser reads as libyaml read the mark, and swapped back in the
/// tree ([`restore_byte_order_marks`]). The leading mark, which both skip, is kept as it is.
fn shield_inner_byte_order_marks(text: &str) -> (std::borrow::Cow<'_, str>, Option<char>) {
    use std::borrow::Cow;
    let body = text.strip_prefix('\u{feff}').unwrap_or(text);
    if !body.contains('\u{feff}') {
        return (Cow::Borrowed(text), None);
    }
    let Some(stand_in) = ('\u{F0000}'..='\u{FFFFD}').find(|c| !text.contains(*c)) else {
        return (Cow::Borrowed(text), None);
    };
    let lead = &text[..text.len() - body.len()];
    let shielded = format!(
        "{lead}{}",
        body.replace('\u{feff}', stand_in.encode_utf8(&mut [0; 4]))
    );
    (Cow::Owned(shielded), Some(stand_in))
}

/// Undo [`shield_inner_byte_order_marks`] in a tree: strings, keys and tag names.
fn restore_byte_order_marks(value: &mut Value, stand_in: char) {
    match value {
        Value::Text(s) if s.contains(stand_in) => *s = s.replace(stand_in, "\u{feff}"),
        Value::Array(items) => {
            for item in items {
                restore_byte_order_marks(item, stand_in);
            }
        }
        Value::Map(pairs) => {
            for (key, item) in pairs {
                restore_byte_order_marks(key, stand_in);
                restore_byte_order_marks(item, stand_in);
            }
        }
        Value::Tag(id, inner) => {
            if let Some(name) = tag_name(*id).filter(|name| name.contains(stand_in)) {
                *id = tag_id(&name.replace(stand_in, "\u{feff}"));
            }
            restore_byte_order_marks(inner, stand_in);
        }
        _ => {}
    }
}

/// A YAML read or write failure: the message, and where in the text it happened when known.
#[derive(Debug)]
pub struct Error {
    message: String,
    /// The document path to the failing node (`a.b[0].c`), as serde_yaml printed it; `None` at
    /// the root.
    path: Option<String>,
    location: Option<Location>,
    /// Whether `Display` appends the position (false when the message already carries one).
    placed_suffix: bool,
}

impl Error {
    /// Where in the YAML text the error happened (1-based line and column), when known.
    #[must_use]
    pub fn location(&self) -> Option<Location> {
        self.location
    }

    fn unplaced(message: impl fmt::Display) -> Self {
        Self {
            message: message.to_string(),
            path: None,
            location: None,
            placed_suffix: false,
        }
    }

    /// Undo [`shield_inner_byte_order_marks`] in the message and path (a key named in them).
    fn restore_byte_order_marks(mut self, stand_in: char) -> Self {
        self.message = self.message.replace(stand_in, "\u{feff}");
        self.path = self.path.map(|path| path.replace(stand_in, "\u{feff}"));
        self
    }
}

impl fmt::Display for Error {
    /// serde_yaml's shape: `path: ` when below the root, the message, then ` at line L column C`
    /// when the position is known.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(path) = &self.path {
            write!(f, "{path}: ")?;
        }
        f.write_str(&self.message)?;
        match self.location.filter(|_| self.placed_suffix) {
            Some(at) => write!(f, " at line {} column {}", at.line(), at.column()),
            None => Ok(()),
        }
    }
}

impl std::error::Error for Error {}

impl serde::de::Error for Error {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        Self::unplaced(msg)
    }
}

impl serde::ser::Error for Error {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        Self::unplaced(msg)
    }
}

impl From<serde_saphyr::Error> for Error {
    /// Keeps the bare message; [`Error`]'s `Display` adds the position as serde_yaml did
    /// (serde-saphyr writes ` at line L, column C`).
    fn from(error: serde_saphyr::Error) -> Self {
        let location = error.location().filter(|l| *l != Location::UNKNOWN);
        let mut message = error.to_string();
        let mut placed_suffix = false;
        if let Some(at) = location {
            let suffix = format!(" at line {}, column {}", at.line(), at.column());
            if let Some(bare) = message.strip_suffix(&suffix) {
                message = bare.to_owned();
                // serde_yaml placed a struct's missing field at its mapping's start and printed no
                // position when that start was the document's first character (line 1, column 1);
                // every other placed error kept its position.
                placed_suffix =
                    !(message.starts_with("missing field ") && at.line() == 1 && at.column() == 1);
            }
        }
        // serde-saphyr's own duplicate refusal names its options; `options()` passes duplicates
        // to the reader, so it should not arise, but if it does it reads as serde_yaml's.
        if let serde_saphyr::Error::DuplicateMappingKey { key, .. } = &error {
            message = match key {
                Some(key) => format!("{DUPLICATE_ENTRY}with key {key:?}"),
                None => format!("{DUPLICATE_ENTRY}in YAML map"),
            };
            placed_suffix = location.is_some();
        }
        Self {
            message,
            path: None,
            location,
            placed_suffix,
        }
    }
}

impl Error {
    /// Name the failing node's path, from serde_path_to_error's tracked `path` and the hops an
    /// untyped read mirrored below it (`hops`, see [`Hop`]): those hops replace the tail of the
    /// tracked path they match, so the tag read of every untyped node (serde-saphyr's `Tagged`
    /// protocol, a virtual sequence that the tracker counts as an index `[0]`) is left out, and a
    /// mapping key is named by its text.
    fn at_path(mut self, path: serde_path_to_error::Path, hops: Option<Vec<Hop>>) -> Self {
        use serde_path_to_error::Segment;
        let tracked: Vec<&Segment> = path.iter().collect();
        // (the segment's text, whether it is an index, whether it is a key being read)
        let mut segments: Vec<(String, bool, bool)> = tracked
            .iter()
            .map(|segment| {
                (
                    segment.to_string(),
                    matches!(segment, Segment::Seq { .. }),
                    matches!(segment, Segment::Unknown),
                )
            })
            .collect();
        // A failure before a hop's node was reached (the parser failing between items) is
        // tracked at the parent, so the last hop may be one the tracker never took.
        let matched = hops.as_deref().and_then(|hops| {
            [hops.len(), hops.len().saturating_sub(1)]
                .into_iter()
                .find_map(|taken| {
                    let start = tracked.len().checked_sub(taken)?;
                    hops_match(&hops[..taken], &tracked[start..]).then(|| (&hops[..taken], start))
                })
        });
        if let Some((hops, start)) = matched {
            segments.truncate(start);
            for (hop, segment) in hops.iter().zip(&tracked[start..]) {
                match hop {
                    Hop::Tag => {}
                    Hop::Key(Some(name)) => segments.push((name.clone(), false, false)),
                    Hop::KeyRead => segments.push((segment.to_string(), false, true)),
                    Hop::Seq(_) | Hop::Key(None) | Hop::Variant => segments.push((
                        segment.to_string(),
                        matches!(segment, Segment::Seq { .. }),
                        false,
                    )),
                }
            }
        }
        // A repeated key is refused while its key is read, so the tracked path ends in that
        // unnamed key; serde_yaml named the mapping holding it.
        if self.message.starts_with(DUPLICATE_ENTRY)
            && segments.last().is_some_and(|(_, _, key_read)| *key_read)
        {
            segments.pop();
        }
        if !segments.is_empty() {
            let mut text = String::new();
            for (at, (segment, index, _)) in segments.iter().enumerate() {
                if at > 0 && !index {
                    text.push('.');
                }
                text.push_str(segment);
            }
            self.path = Some(text);
        }
        self
    }
}

/// How serde_yaml began its refusal of a repeated key in an untyped mapping.
const DUPLICATE_ENTRY: &str = "duplicate entry ";

/// serde_yaml's refusal of a repeated mapping key, naming the key as it did.
fn duplicate_entry(key: &Value) -> String {
    match key {
        Value::Null => format!("{DUPLICATE_ENTRY}with null key"),
        Value::Bool(b) => format!("{DUPLICATE_ENTRY}with key `{b}`"),
        Value::Integer(i) => format!("{DUPLICATE_ENTRY}with key {}", i128::from(*i)),
        Value::Float(f) if f.is_nan() => format!("{DUPLICATE_ENTRY}with key .nan"),
        Value::Float(f) if f.is_infinite() => {
            let sign = if f.is_sign_negative() { "-" } else { "" };
            format!("{DUPLICATE_ENTRY}with key {sign}.inf")
        }
        Value::Float(f) => format!("{DUPLICATE_ENTRY}with key {f:?}"),
        Value::Text(s) => format!("{DUPLICATE_ENTRY}with key {s:?}"),
        _ => format!("{DUPLICATE_ENTRY}in YAML map"),
    }
}

impl From<serde_saphyr::SerializeError> for Error {
    fn from(error: serde_saphyr::SerializeError) -> Self {
        Self::unplaced(error)
    }
}

/// Read a YAML document into `T`.
///
/// An untyped read (`T` is [`Value`] or [`Mapping`]) means what serde_yaml's `Value` read meant:
/// a repeated mapping key is refused, and an application tag is kept as a [`Value::Tag`].
pub fn from_str<T: DeserializeOwned>(text: &str) -> Result<T, Error> {
    if untyped_target::<T>() {
        let (shielded, stand_in) = shield_inner_byte_order_marks(text);
        let mut tree =
            with_deserializer(&shielded, |d| Node.deserialize(d)).map_err(|e| match stand_in {
                Some(stand_in) => e.restore_byte_order_marks(stand_in),
                None => e,
            })?;
        if let Some(stand_in) = stand_in {
            restore_byte_order_marks(&mut tree, stand_in);
        }
        return from_value(tree);
    }
    with_deserializer(text, |d| T::deserialize(d))
}

/// Whether `T` (under any references) is the untyped tree or its mapping: those reads go through
/// this module's tag-aware, duplicate-refusing builder. Named by type so that `from_str` needs no
/// `'static` bound.
fn untyped_target<T: ?Sized>() -> bool {
    let name = std::any::type_name::<T>().trim_start_matches('&');
    name == std::any::type_name::<Value>() || name == std::any::type_name::<Mapping>()
}

/// Read one node as an untyped [`Value`] from any deserializer, as serde_yaml's `Value` read it:
/// a repeated mapping key is refused (`duplicate entry with key "k"`), and an application tag is
/// kept as a [`Value::Tag`]. For a `Value` field of a typed struct, which ciborium's own
/// `Deserialize` would read without either: `#[serde(deserialize_with = "yaml::untyped")]`.
pub fn untyped<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Value, D::Error> {
    Node.deserialize(deserializer)
}

/// A [`Value`] read through [`untyped`], for containers (`IndexMap<String, Untyped>`) whose
/// members serde would otherwise read with ciborium's own `Deserialize`.
#[derive(Debug, Clone)]
pub struct UntypedValue(pub Value);

impl<'de> serde::Deserialize<'de> for UntypedValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        untyped(deserializer).map(UntypedValue)
    }
}

// ---- Application tags ----

/// The first CBOR tag number the registry hands out: far above the IANA-registered ones, so an
/// application tag never reads as a CBOR meaning.
const APPLICATION_TAG_BASE: u64 = 0x7961_6d6c_0000_0000;

#[derive(Default)]
struct TagNames {
    ids: HashMap<String, u64>,
    names: Vec<String>,
}

fn tag_names() -> std::sync::MutexGuard<'static, TagNames> {
    static NAMES: OnceLock<Mutex<TagNames>> = OnceLock::new();
    NAMES
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

/// The [`Value::Tag`] number for the application tag `name` (`!Name`, as written), registered for
/// the life of the process on first use; the same name always gets the same number.
#[must_use]
pub fn tag_id(name: &str) -> u64 {
    let mut names = tag_names();
    if let Some(id) = names.ids.get(name) {
        return *id;
    }
    let id = APPLICATION_TAG_BASE + names.names.len() as u64;
    names.names.push(name.to_owned());
    names.ids.insert(name.to_owned(), id);
    id
}

/// The application tag a [`Value::Tag`] number stands for, when the registry handed it out.
#[must_use]
pub fn tag_name(id: u64) -> Option<String> {
    let at = usize::try_from(id.checked_sub(APPLICATION_TAG_BASE)?).ok()?;
    tag_names().names.get(at).cloned()
}

/// `value` under the application tag `name` (`!Name`), as an untyped read gives a tagged node.
#[must_use]
pub fn tagged(name: &str, value: Value) -> Value {
    Value::Tag(tag_id(name), Box::new(value))
}

/// The application tag on `value`, when it is a tagged node.
#[must_use]
pub fn tag_of(value: &Value) -> Option<String> {
    match value {
        Value::Tag(id, _) => tag_name(*id),
        _ => None,
    }
}

/// Builds one untyped node, asking serde-saphyr for the node's tag first (its `Tagged` protocol:
/// the node as the sequence `[value, tag?]`). Other deserializers answer with the node itself:
/// through `visit_newtype_struct`, or, for one that reads every request as `deserialize_any`
/// (serde's `MapAccessDeserializer`, `EnumAccessDeserializer`), as that node; a sequence such a
/// deserializer hands over cannot be told from the tag protocol, so read one with
/// [`untyped_seq`].
struct Node;

impl<'de> DeserializeSeed<'de> for Node {
    type Value = Value;
    fn deserialize<D: serde::Deserializer<'de>>(self, de: D) -> Result<Value, D::Error> {
        de.deserialize_newtype_struct(TAGGED, Node)
    }
}

/// [`Node`]'s answers for a deserializer that hands over the node itself rather than the tag
/// protocol: each is [`Untyped`]'s.
macro_rules! node_as_untyped {
    ($($visit:ident($ty:ty)),+ $(,)?) => {
        $(
            fn $visit<E: serde::de::Error>(self, v: $ty) -> Result<Value, E> {
                serde::de::Visitor::$visit(Untyped, v)
            }
        )+
    };
}

impl<'de> serde::de::Visitor<'de> for Node {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any YAML value")
    }
    fn visit_newtype_struct<D: serde::Deserializer<'de>>(self, de: D) -> Result<Value, D::Error> {
        de.deserialize_any(Untyped)
    }
    fn visit_seq<S: serde::de::SeqAccess<'de>>(self, mut seq: S) -> Result<Value, S::Error> {
        let value = hop(Hop::Tag, || seq.next_element_seed(UntypedSeed))?
            .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
        Ok(match hop(Hop::Tag, || seq.next_element::<String>())? {
            Some(tag) if !tag.starts_with("tag:yaml.org,2002:") => tagged(&tag, value),
            _ => value,
        })
    }
    node_as_untyped! {
        visit_bool(bool),
        visit_f32(f32),
        visit_f64(f64),
        visit_i8(i8),
        visit_i16(i16),
        visit_i32(i32),
        visit_i64(i64),
        visit_i128(i128),
        visit_u8(u8),
        visit_u16(u16),
        visit_u32(u32),
        visit_u64(u64),
        visit_u128(u128),
        visit_char(char),
        visit_str(&str),
        visit_string(String),
        visit_bytes(&[u8]),
        visit_byte_buf(Vec<u8>),
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_none<E: serde::de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_some<D: serde::Deserializer<'de>>(self, de: D) -> Result<Value, D::Error> {
        Node.deserialize(de)
    }
    fn visit_map<M: serde::de::MapAccess<'de>>(self, map: M) -> Result<Value, M::Error> {
        serde::de::Visitor::visit_map(Untyped, map)
    }
    fn visit_enum<A: serde::de::EnumAccess<'de>>(self, data: A) -> Result<Value, A::Error> {
        serde::de::Visitor::visit_enum(Untyped, data)
    }
}

/// Read the rest of a sequence as an untyped [`Value::Array`], each item as [`untyped`] reads a
/// node: for a visitor that was handed a sequence and wants it as the tree.
pub fn untyped_seq<'de, S: serde::de::SeqAccess<'de>>(seq: S) -> Result<Value, S::Error> {
    serde::de::Visitor::visit_seq(Untyped, seq)
}

/// Read the rest of a mapping as an untyped [`Value::Map`], as [`untyped`] reads one (a repeated
/// key refused): for a visitor that was handed a mapping and wants it as the tree.
pub fn untyped_map<'de, M: serde::de::MapAccess<'de>>(map: M) -> Result<Value, M::Error> {
    serde::de::Visitor::visit_map(Untyped, map)
}

struct UntypedSeed;

impl<'de> DeserializeSeed<'de> for UntypedSeed {
    type Value = Value;
    fn deserialize<D: serde::Deserializer<'de>>(self, de: D) -> Result<Value, D::Error> {
        de.deserialize_any(Untyped)
    }
}

/// A mapping key, refused when it repeats one of `0` (the pairs read so far). Refused while the
/// key is read, so serde-saphyr places the refusal at the repeat.
struct Key<'p>(&'p [(Value, Value)]);

impl<'de> DeserializeSeed<'de> for Key<'_> {
    type Value = Value;
    fn deserialize<D: serde::Deserializer<'de>>(self, de: D) -> Result<Value, D::Error> {
        let key = Node.deserialize(de)?;
        if self.0.iter().any(|(seen, _)| same_tree(seen, &key)) {
            return Err(serde::de::Error::custom(duplicate_entry(&key)));
        }
        Ok(key)
    }
}

/// The node itself, its tag already read: ciborium's `Value` visitor, with tagged children and
/// refused repeated keys.
struct Untyped;

macro_rules! visit_into_value {
    ($($visit:ident($ty:ty)),+ $(,)?) => {
        $(
            fn $visit<E: serde::de::Error>(self, v: $ty) -> Result<Value, E> {
                Ok(Value::from(v))
            }
        )+
    };
}

impl<'de> serde::de::Visitor<'de> for Untyped {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any YAML value")
    }
    visit_into_value! {
        visit_bool(bool),
        visit_f32(f32),
        visit_f64(f64),
        visit_i8(i8),
        visit_i16(i16),
        visit_i32(i32),
        visit_i64(i64),
        visit_i128(i128),
        visit_u8(u8),
        visit_u16(u16),
        visit_u32(u32),
        visit_u64(u64),
        visit_u128(u128),
        visit_char(char),
        visit_str(&str),
        visit_string(String),
        visit_bytes(&[u8]),
        visit_byte_buf(Vec<u8>),
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_none<E: serde::de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_some<D: serde::Deserializer<'de>>(self, de: D) -> Result<Value, D::Error> {
        Node.deserialize(de)
    }
    fn visit_newtype_struct<D: serde::Deserializer<'de>>(self, de: D) -> Result<Value, D::Error> {
        Node.deserialize(de)
    }
    fn visit_seq<S: serde::de::SeqAccess<'de>>(self, mut seq: S) -> Result<Value, S::Error> {
        let mut items = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(4096));
        while let Some(item) = hop(Hop::Seq(items.len()), || seq.next_element_seed(Node))? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }
    fn visit_map<M: serde::de::MapAccess<'de>>(self, mut map: M) -> Result<Value, M::Error> {
        let mut pairs = Pairs::with_capacity(map.size_hint().unwrap_or(0).min(4096));
        while let Some(key) = hop(Hop::KeyRead, || {
            unmirrored(|| map.next_key_seed(Key(&pairs)))
        })? {
            let name = key.as_text().map(str::to_owned);
            let value = hop(Hop::Key(name), || map.next_value_seed(Node))?;
            pairs.push((key, value));
        }
        Ok(Value::Map(pairs))
    }
    /// A tagged node handed over as an enum: ciborium's own tag protocol (a [`ValueDeserializer`]
    /// over a [`Value::Tag`]), or a serde_yaml-style variant, kept as the tag `!variant`.
    fn visit_enum<A: serde::de::EnumAccess<'de>>(self, data: A) -> Result<Value, A::Error> {
        use serde::de::VariantAccess;
        let (variant, content): (String, _) = data.variant()?;
        if variant == CBOR_TAGGED {
            content.tuple_variant(2, CborTagContent)
        } else {
            let value = hop(Hop::Variant, || content.newtype_variant_seed(Node))?;
            Ok(tagged(&format!("!{variant}"), value))
        }
    }
}

/// ciborium's variant name for a tagged item, in its `Value`'s serde form.
const CBOR_TAGGED: &str = "@@TAGGED@@";

/// The `(tag number, value)` content of ciborium's tagged-item variant.
struct CborTagContent;

impl<'de> serde::de::Visitor<'de> for CborTagContent {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a tag number and a value")
    }
    fn visit_seq<S: serde::de::SeqAccess<'de>>(self, mut seq: S) -> Result<Value, S::Error> {
        let id: u64 = seq
            .next_element()?
            .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
        let value = seq
            .next_element_seed(Node)?
            .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
        Ok(Value::Tag(id, Box::new(value)))
    }
}

/// Read a UTF-8 YAML document into `T`.
pub fn from_slice<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, Error> {
    let text = std::str::from_utf8(bytes).map_err(Error::unplaced)?;
    from_str(text)
}

/// Read a YAML document whose top level must be a mapping, keeping its key order.
pub fn mapping_from_str(text: &str) -> Result<Mapping, Error> {
    match from_str::<Value>(text)? {
        Value::Map(mapping) => Ok(Mapping(mapping)),
        _ => Err(Error::unplaced("invalid type: expected a mapping")),
    }
}

/// The deserializer [`with_deserializer`] hands its reader: serde-saphyr's, tracking the path to
/// the node being read so an error names it, as serde_yaml's did.
pub type Tracked<'t, 'de, 'e> = serde_path_to_error::Deserializer<'t, 't, Deserializer<'de, 'e>>;

/// Run `read` over a YAML deserializer for `text`: for generic `D: Deserializer` readers and
/// `DeserializeSeed`s, where serde_yaml offered `Deserializer::from_str`.
pub fn with_deserializer<'de, R, F>(text: &'de str, read: F) -> Result<R, Error>
where
    F: for<'t, 'e> FnOnce(Tracked<'t, 'de, 'e>) -> Result<R, serde_saphyr::Error>,
{
    refuse_control_characters(text)?;
    let mut track = serde_path_to_error::Track::new();
    let outer = HOPS.replace(Some(Hops::default()));
    let read = serde_saphyr::with_deserializer_from_str_with_options(text, options(), |de| {
        read(serde_path_to_error::Deserializer::new(de, &mut track))
    });
    let hops = HOPS.replace(outer).and_then(|hops| hops.failed);
    read.map_err(|e| Error::from(e).at_path(track.path(), hops))
}

// ---- The path below an untyped node ----

/// One step of the tracked path that an untyped read ([`Node`], [`Untyped`]) takes below the
/// node it starts at, mirrored so [`Error::at_path`] can tell them apart: serde_path_to_error
/// counts the tag read of each node (serde-saphyr's `Tagged` protocol, the virtual sequence
/// `[value, tag?]`) as an index, which serde_yaml's path never held.
#[derive(Clone, Debug)]
enum Hop {
    /// The tag read of one node: tracked as `[0]` (its value) or `[1]` (its tag).
    Tag,
    /// An item of a sequence.
    Seq(usize),
    /// The value of a mapping entry, named by its key's text when the key is a string.
    Key(Option<String>),
    /// A mapping key being read (the tracker names none).
    KeyRead,
    /// The content of a variant read as a tag (`!Variant content`).
    Variant,
}

/// Whether `hops` are the tracked `tail`, step for step.
fn hops_match(hops: &[Hop], tail: &[&serde_path_to_error::Segment]) -> bool {
    use serde_path_to_error::Segment;
    hops.iter()
        .zip(tail)
        .all(|(hop, segment)| match (hop, segment) {
            (Hop::Tag, Segment::Seq { index }) => *index <= 1,
            (Hop::Seq(at), Segment::Seq { index }) => at == index,
            (Hop::Key(_) | Hop::KeyRead, Segment::Map { .. } | Segment::Unknown) => true,
            (Hop::Variant, Segment::Enum { .. }) => true,
            _ => false,
        })
}

/// The hops of the untyped read in progress on this thread, inside one [`with_deserializer`].
#[derive(Default)]
struct Hops {
    stack: Vec<Hop>,
    /// While non-zero, nothing is mirrored: a mapping key is being read (the tracker follows no
    /// path inside a key), or an in-memory read ([`from_value`]) runs inside a tracked one.
    paused: usize,
    /// The hops to the first failure, kept as the tracker keeps its first path.
    failed: Option<Vec<Hop>>,
}

thread_local! {
    static HOPS: std::cell::RefCell<Option<Hops>> = const { std::cell::RefCell::new(None) };
}

/// Run `read` one hop below the current node: `hop` is mirrored while it runs and, if it fails,
/// the hops to it are kept for the error's path.
fn hop<T, E>(hop: Hop, read: impl FnOnce() -> Result<T, E>) -> Result<T, E> {
    let mirrored = HOPS.with_borrow_mut(|hops| match hops {
        Some(hops) if hops.paused == 0 => {
            hops.stack.push(hop);
            true
        }
        _ => false,
    });
    let result = read();
    if mirrored {
        HOPS.with_borrow_mut(|hops| {
            if let Some(hops) = hops {
                if result.is_err() && hops.failed.is_none() {
                    hops.failed = Some(hops.stack.clone());
                }
                hops.stack.pop();
            }
        });
    }
    result
}

/// Run `read` with nothing mirrored (see [`Hops::paused`]).
fn unmirrored<T>(read: impl FnOnce() -> T) -> T {
    let pause = |by: isize| {
        HOPS.with_borrow_mut(|hops| {
            if let Some(hops) = hops {
                hops.paused = hops.paused.saturating_add_signed(by);
            }
        });
    };
    pause(1);
    let result = read();
    pause(-1);
    result
}

/// The first application tag (`!Name`, or a non-core tag URI) anywhere in the document, keys
/// included; `None` when it has none. For a reader that must refuse tags before reading (a typed
/// read ignores a tag outside an enum).
pub fn first_application_tag(text: &str) -> Result<Option<String>, Error> {
    with_deserializer(text, |d| {
        serde::de::DeserializeSeed::deserialize(FindTag, d)
    })
}

/// serde-saphyr's newtype name for its public `serde_saphyr::Tagged<T>` wrapper: a deserializer
/// asked for it hands the visitor the node as the sequence `[value, tag?]`.
const TAGGED: &str = "__yaml_tagged";

struct FindTag;

impl<'de> serde::de::DeserializeSeed<'de> for FindTag {
    type Value = Option<String>;
    fn deserialize<D: serde::Deserializer<'de>>(self, de: D) -> Result<Self::Value, D::Error> {
        de.deserialize_newtype_struct(TAGGED, self)
    }
}

impl<'de> serde::de::Visitor<'de> for FindTag {
    type Value = Option<String>;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a YAML node")
    }
    fn visit_newtype_struct<D: serde::Deserializer<'de>>(
        self,
        de: D,
    ) -> Result<Self::Value, D::Error> {
        de.deserialize_any(FindTagInside)
    }
    fn visit_seq<S: serde::de::SeqAccess<'de>>(self, mut seq: S) -> Result<Self::Value, S::Error> {
        let inside = seq.next_element_seed(FindTagInsideSeed)?.flatten();
        let tag = seq
            .next_element::<String>()?
            .filter(|t| !t.starts_with("tag:yaml.org,2002:"));
        Ok(tag.or(inside))
    }
}

struct FindTagInsideSeed;

impl<'de> serde::de::DeserializeSeed<'de> for FindTagInsideSeed {
    type Value = Option<String>;
    fn deserialize<D: serde::Deserializer<'de>>(self, de: D) -> Result<Self::Value, D::Error> {
        de.deserialize_any(FindTagInside)
    }
}

/// The node itself (its own tag already read): scalars carry none further; collections are
/// searched through their keys and values.
struct FindTagInside;

impl<'de> serde::de::Visitor<'de> for FindTagInside {
    type Value = Option<String>;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a YAML node")
    }
    fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_i128<E: serde::de::Error>(self, _: i128) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_u128<E: serde::de::Error>(self, _: u128) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_bytes<E: serde::de::Error>(self, _: &[u8]) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_some<D: serde::Deserializer<'de>>(self, de: D) -> Result<Self::Value, D::Error> {
        de.deserialize_any(FindTagInside)
    }
    fn visit_seq<S: serde::de::SeqAccess<'de>>(self, mut seq: S) -> Result<Self::Value, S::Error> {
        let mut found = None;
        while let Some(tag) = seq.next_element_seed(FindTag)? {
            found = found.or(tag);
        }
        Ok(found)
    }
    fn visit_map<M: serde::de::MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
        let mut found = None;
        while let Some(tag) = map.next_key_seed(FindTag)? {
            found = found.or(tag);
            found = found.or(map.next_value_seed(FindTag)?);
        }
        Ok(found)
    }
}

/// Write `value` as a YAML document. Every tagged [`Value`] in it, at any depth (the whole value,
/// or one inside a struct field, an `Option`, a map or a sequence), writes its application tag
/// back (`!Name value`), as serde_yaml wrote a `Value::Tagged`; every enum variant with content
/// is written as serde_yaml wrote it, `!Variant` over the content (a unit variant: `Variant`).
pub fn to_string<T: Serialize + ?Sized>(value: &T) -> Result<String, Error> {
    Ok(serde_saphyr::to_string(&Tagging(value))?)
}

/// Write `value` as a YAML document to `writer`, as [`to_string`] writes it.
pub fn to_writer<W: std::io::Write, T: Serialize + ?Sized>(
    mut writer: W,
    value: &T,
) -> Result<(), Error> {
    Ok(serde_saphyr::to_io_writer(&mut writer, &Tagging(value))?)
}

/// The struct names a JSON library serializes a number or raw value under when it keeps the
/// lexeme (sonic-rs, serde_json `arbitrary_precision`). Written as YAML they would become a
/// marker map, so [`TagWriter`] refuses them; the spelling is the test because the name is a
/// `&'static str` from the library's code.
const JSON_TOKENS: [&str; 3] = [
    "$sonic_rs::private::JsonNumber",
    "$sonic_rs::LazyValue",
    "$serde_json::private::Number",
];

/// ciborium's enum name for a tagged item, in its `Value`'s serde form.
const CBOR_TAG: &str = "@@TAG@@";

/// `0` serialized through [`TagWriter`]: as it serializes itself, except that a [`Value::Tag`]
/// anywhere inside it is written as its application tag.
struct Tagging<'v, T: ?Sized>(&'v T);

impl<T: Serialize + ?Sized> Serialize for Tagging<'_, T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(TagWriter(serializer))
    }
}

/// A serializer (or one of its compound serializers) that passes every call through to `0`
/// unchanged, wrapping every nested element, field, key and value in [`Tagging`] so the rule
/// holds at any depth, except ciborium's tagged item (`@@TAG@@::@@TAGGED@@(id, value)`): a tag
/// the registry handed out is written through serde-saphyr's `Tagged` (`!Name value`), any other
/// (a genuine CBOR tag) as its value alone; and an enum's newtype, tuple or struct variant, written
/// through `Tagged` as `!Variant` over its content, which selects the variant (serde_yaml's form).
struct TagWriter<S>(S);

macro_rules! pass_through {
    ($($method:ident($ty:ty)),+ $(,)?) => {
        $(
            fn $method(self, v: $ty) -> Result<S::Ok, S::Error> {
                self.0.$method(v)
            }
        )+
    };
}

impl<S: serde::Serializer> serde::Serializer for TagWriter<S> {
    type Ok = S::Ok;
    type Error = S::Error;
    type SerializeSeq = TagWriter<S::SerializeSeq>;
    type SerializeTuple = TagWriter<S::SerializeTuple>;
    type SerializeTupleStruct = TagWriter<S::SerializeTupleStruct>;
    type SerializeTupleVariant = TagWriterVariant<S>;
    type SerializeMap = TagWriter<S::SerializeMap>;
    type SerializeStruct = TagWriter<S::SerializeStruct>;
    type SerializeStructVariant = TagWriterStructVariant<S>;

    pass_through! {
        serialize_bool(bool),
        serialize_i8(i8),
        serialize_i16(i16),
        serialize_i32(i32),
        serialize_i64(i64),
        serialize_i128(i128),
        serialize_u8(u8),
        serialize_u16(u16),
        serialize_u32(u32),
        serialize_u64(u64),
        serialize_u128(u128),
        serialize_f32(f32),
        serialize_f64(f64),
        serialize_char(char),
        serialize_str(&str),
        serialize_bytes(&[u8]),
        serialize_unit_struct(&'static str),
    }

    fn serialize_none(self) -> Result<S::Ok, S::Error> {
        self.0.serialize_none()
    }

    fn serialize_some<T: Serialize + ?Sized>(self, value: &T) -> Result<S::Ok, S::Error> {
        self.0.serialize_some(&Tagging(value))
    }

    fn serialize_unit(self) -> Result<S::Ok, S::Error> {
        self.0.serialize_unit()
    }

    fn serialize_unit_variant(
        self,
        name: &'static str,
        variant_index: u32,
        variant: &'static str,
    ) -> Result<S::Ok, S::Error> {
        self.0.serialize_unit_variant(name, variant_index, variant)
    }

    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        name: &'static str,
        value: &T,
    ) -> Result<S::Ok, S::Error> {
        self.0.serialize_newtype_struct(name, &Tagging(value))
    }

    /// serde_yaml's form: `!Variant payload`.
    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        name: &'static str,
        variant_index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<S::Ok, S::Error> {
        match variant_tag(variant) {
            Some(tag) => serde_saphyr::Tagged(
                NewtypeVariant {
                    name,
                    index: variant_index,
                    variant,
                    value,
                },
                Some(tag),
            )
            .serialize(self.0),
            None => self
                .0
                .serialize_newtype_variant(name, variant_index, variant, &Tagging(value)),
        }
    }

    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq, S::Error> {
        self.0.serialize_seq(len).map(TagWriter)
    }

    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple, S::Error> {
        self.0.serialize_tuple(len).map(TagWriter)
    }

    fn serialize_tuple_struct(
        self,
        name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct, S::Error> {
        self.0.serialize_tuple_struct(name, len).map(TagWriter)
    }

    fn serialize_tuple_variant(
        self,
        name: &'static str,
        variant_index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleVariant, S::Error> {
        if name == CBOR_TAG && variant == CBOR_TAGGED && len == 2 {
            return Ok(TagWriterVariant::Tag {
                serializer: Some(self.0),
                id: None,
                written: None,
            });
        }
        // serde_yaml's form: `!Variant` and the fields as a sequence.
        if let Some(tag) = variant_tag(variant) {
            return Ok(TagWriterVariant::Enum {
                serializer: self.0,
                tag,
                name,
                index: variant_index,
                variant,
                fields: Vec::with_capacity(len.min(4096)),
            });
        }
        self.0
            .serialize_tuple_variant(name, variant_index, variant, len)
            .map(TagWriterVariant::Through)
    }

    fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap, S::Error> {
        self.0.serialize_map(len).map(TagWriter)
    }

    fn serialize_struct(
        self,
        name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStruct, S::Error> {
        if JSON_TOKENS.contains(&name) {
            return Err(serde::ser::Error::custom(
                "a JSON number or raw value reached the YAML writer as its token struct; \
                 convert JSON numbers with json::to_yaml",
            ));
        }
        self.0.serialize_struct(name, len).map(TagWriter)
    }

    /// serde_yaml's form: `!Variant` and the fields as a mapping.
    fn serialize_struct_variant(
        self,
        name: &'static str,
        variant_index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStructVariant, S::Error> {
        if let Some(tag) = variant_tag(variant) {
            return Ok(TagWriterStructVariant::Enum {
                serializer: self.0,
                tag,
                name,
                index: variant_index,
                variant,
                len,
                fields: Vec::with_capacity(len.min(4096)),
            });
        }
        self.0
            .serialize_struct_variant(name, variant_index, variant, len)
            .map(|inner| TagWriterStructVariant::Through(TagWriter(inner)))
    }

    fn collect_str<T: fmt::Display + ?Sized>(self, value: &T) -> Result<S::Ok, S::Error> {
        self.0.collect_str(value)
    }

    fn is_human_readable(&self) -> bool {
        self.0.is_human_readable()
    }
}

impl<C: serde::ser::SerializeSeq> serde::ser::SerializeSeq for TagWriter<C> {
    type Ok = C::Ok;
    type Error = C::Error;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), C::Error> {
        self.0.serialize_element(&Tagging(value))
    }
    fn end(self) -> Result<C::Ok, C::Error> {
        self.0.end()
    }
}

impl<C: serde::ser::SerializeTuple> serde::ser::SerializeTuple for TagWriter<C> {
    type Ok = C::Ok;
    type Error = C::Error;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), C::Error> {
        self.0.serialize_element(&Tagging(value))
    }
    fn end(self) -> Result<C::Ok, C::Error> {
        self.0.end()
    }
}

impl<C: serde::ser::SerializeTupleStruct> serde::ser::SerializeTupleStruct for TagWriter<C> {
    type Ok = C::Ok;
    type Error = C::Error;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), C::Error> {
        self.0.serialize_field(&Tagging(value))
    }
    fn end(self) -> Result<C::Ok, C::Error> {
        self.0.end()
    }
}

impl<C: serde::ser::SerializeMap> serde::ser::SerializeMap for TagWriter<C> {
    type Ok = C::Ok;
    type Error = C::Error;
    fn serialize_key<T: Serialize + ?Sized>(&mut self, key: &T) -> Result<(), C::Error> {
        self.0.serialize_key(&Tagging(key))
    }
    fn serialize_value<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), C::Error> {
        self.0.serialize_value(&Tagging(value))
    }
    fn serialize_entry<K: Serialize + ?Sized, V: Serialize + ?Sized>(
        &mut self,
        key: &K,
        value: &V,
    ) -> Result<(), C::Error> {
        self.0.serialize_entry(&Tagging(key), &Tagging(value))
    }
    fn end(self) -> Result<C::Ok, C::Error> {
        self.0.end()
    }
}

impl<C: serde::ser::SerializeStruct> serde::ser::SerializeStruct for TagWriter<C> {
    type Ok = C::Ok;
    type Error = C::Error;
    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), C::Error> {
        self.0.serialize_field(key, &Tagging(value))
    }
    fn skip_field(&mut self, key: &'static str) -> Result<(), C::Error> {
        self.0.skip_field(key)
    }
    fn end(self) -> Result<C::Ok, C::Error> {
        self.0.end()
    }
}

impl<C: serde::ser::SerializeStructVariant> serde::ser::SerializeStructVariant for TagWriter<C> {
    type Ok = C::Ok;
    type Error = C::Error;
    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), C::Error> {
        self.0.serialize_field(key, &Tagging(value))
    }
    fn skip_field(&mut self, key: &'static str) -> Result<(), C::Error> {
        self.0.skip_field(key)
    }
    fn end(self) -> Result<C::Ok, C::Error> {
        self.0.end()
    }
}

/// [`TagWriter`]'s tuple variant: any other tuple variant passed through, ciborium's tagged
/// item (whose fields are the tag number and then the value), or an enum's tuple variant written
/// as serde_yaml wrote it, `!Variant` over the fields (gathered, then written in one go).
enum TagWriterVariant<S: serde::Serializer> {
    Through(S::SerializeTupleVariant),
    Tag {
        /// The serializer the tagged value is written to, until it is.
        serializer: Option<S>,
        /// The tag number, once field 0 is read.
        id: Option<u64>,
        /// The result of writing the value (field 1).
        written: Option<S::Ok>,
    },
    Enum {
        serializer: S,
        tag: String,
        name: &'static str,
        index: u32,
        variant: &'static str,
        fields: Vec<Content>,
    },
}

impl<S: serde::Serializer> serde::ser::SerializeTupleVariant for TagWriterVariant<S> {
    type Ok = S::Ok;
    type Error = S::Error;

    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), S::Error> {
        let (serializer, id, written) = match self {
            Self::Through(inner) => {
                return serde::ser::SerializeTupleVariant::serialize_field(inner, &Tagging(value))
            }
            Self::Enum { fields, .. } => {
                fields.push(capture::<S::Error, _>(value)?);
                return Ok(());
            }
            Self::Tag {
                serializer,
                id,
                written,
            } => (serializer, id, written),
        };
        let Some(number) = *id else {
            let number = Value::serialized(value)
                .map_err(<S::Error as serde::ser::Error>::custom)?
                .as_integer()
                .and_then(|i| u64::try_from(i).ok())
                .ok_or_else(|| {
                    <S::Error as serde::ser::Error>::custom("a CBOR tag number must be a u64")
                })?;
            *id = Some(number);
            return Ok(());
        };
        let serializer = serializer.take().ok_or_else(|| {
            <S::Error as serde::ser::Error>::custom("a tagged item has one value")
        })?;
        *written = Some(match tag_name(number) {
            Some(tag) => serde_saphyr::Tagged(Tagging(value), Some(tag)).serialize(serializer)?,
            None => Tagging(value).serialize(serializer)?,
        });
        Ok(())
    }

    fn end(self) -> Result<S::Ok, S::Error> {
        match self {
            Self::Through(inner) => serde::ser::SerializeTupleVariant::end(inner),
            Self::Tag { written, .. } => written.ok_or_else(|| {
                <S::Error as serde::ser::Error>::custom("a tagged item is missing its value")
            }),
            Self::Enum {
                serializer,
                tag,
                name,
                index,
                variant,
                fields,
            } => serde_saphyr::Tagged(
                TupleVariant {
                    name,
                    index,
                    variant,
                    fields: &fields,
                },
                Some(tag),
            )
            .serialize(serializer),
        }
    }
}

/// [`TagWriter`]'s struct variant: passed through when its name cannot be a tag, otherwise
/// written as serde_yaml wrote it, `!Variant` over the fields (gathered, then written in one go).
enum TagWriterStructVariant<S: serde::Serializer> {
    Through(TagWriter<S::SerializeStructVariant>),
    Enum {
        serializer: S,
        tag: String,
        name: &'static str,
        index: u32,
        variant: &'static str,
        len: usize,
        /// Each field in order; `None` for a skipped one.
        fields: Vec<(&'static str, Option<Content>)>,
    },
}

impl<S: serde::Serializer> serde::ser::SerializeStructVariant for TagWriterStructVariant<S> {
    type Ok = S::Ok;
    type Error = S::Error;

    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), S::Error> {
        match self {
            Self::Through(inner) => {
                serde::ser::SerializeStructVariant::serialize_field(inner, key, value)
            }
            Self::Enum { fields, .. } => {
                fields.push((key, Some(capture::<S::Error, _>(value)?)));
                Ok(())
            }
        }
    }

    fn skip_field(&mut self, key: &'static str) -> Result<(), S::Error> {
        match self {
            Self::Through(inner) => serde::ser::SerializeStructVariant::skip_field(inner, key),
            Self::Enum { fields, .. } => {
                fields.push((key, None));
                Ok(())
            }
        }
    }

    fn end(self) -> Result<S::Ok, S::Error> {
        match self {
            Self::Through(inner) => serde::ser::SerializeStructVariant::end(inner),
            Self::Enum {
                serializer,
                tag,
                name,
                index,
                variant,
                len,
                fields,
            } => serde_saphyr::Tagged(
                StructVariant {
                    name,
                    index,
                    variant,
                    len,
                    fields: &fields,
                },
                Some(tag),
            )
            .serialize(serializer),
        }
    }
}

/// The tag serde_yaml wrote for an enum variant with content, `!Variant`, when serde-saphyr can
/// write the variant under it: a variant whose name could not be a plain tag (empty, holding `:`
/// or `!`, or a YAML core type name such as `str`) is written in serde-saphyr's own form.
fn variant_tag(variant: &str) -> Option<String> {
    let plain = !variant.is_empty()
        && !variant.contains([':', '!'])
        && !matches!(
            variant,
            "null" | "bool" | "int" | "float" | "map" | "seq" | "str"
        );
    plain.then(|| format!("!{variant}"))
}

/// A newtype variant, written under its `!Variant` tag: serde-saphyr's tagged-variant form, the
/// tag selecting the variant and the payload written under it.
struct NewtypeVariant<'v, T: ?Sized> {
    name: &'static str,
    index: u32,
    variant: &'static str,
    value: &'v T,
}

impl<T: Serialize + ?Sized> Serialize for NewtypeVariant<'_, T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_newtype_variant(
            self.name,
            self.index,
            self.variant,
            &Tagging(self.value),
        )
    }
}

/// A tuple variant's gathered fields, written under its `!Variant` tag as a sequence.
struct TupleVariant<'f> {
    name: &'static str,
    index: u32,
    variant: &'static str,
    fields: &'f [Content],
}

impl Serialize for TupleVariant<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeTupleVariant;
        let mut tuple = serializer.serialize_tuple_variant(
            self.name,
            self.index,
            self.variant,
            self.fields.len(),
        )?;
        for field in self.fields {
            tuple.serialize_field(&Tagging(field))?;
        }
        tuple.end()
    }
}

/// A struct variant's gathered fields, written under its `!Variant` tag as a mapping.
struct StructVariant<'f> {
    name: &'static str,
    index: u32,
    variant: &'static str,
    len: usize,
    fields: &'f [(&'static str, Option<Content>)],
}

impl Serialize for StructVariant<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStructVariant;
        let mut fields =
            serializer.serialize_struct_variant(self.name, self.index, self.variant, self.len)?;
        for (key, value) in self.fields {
            match value {
                Some(value) => fields.serialize_field(key, &Tagging(value))?,
                None => fields.skip_field(key)?,
            }
        }
        fields.end()
    }
}

/// One serialized value, recorded call by call so it can be written later exactly as it would
/// have been written then (names, length hints and skipped fields included). A tuple or struct
/// variant's fields are gathered this way: serde hands them over one at a time, while
/// serde-saphyr writes a tagged node from one value.
enum Content {
    Bool(bool),
    I64(i64),
    I128(i128),
    U64(u64),
    U128(u128),
    F32(f32),
    F64(f64),
    Char(char),
    Str(String),
    Bytes(Vec<u8>),
    None,
    Some(Box<Content>),
    Unit,
    UnitStruct(&'static str),
    UnitVariant(&'static str, u32, &'static str),
    NewtypeStruct(&'static str, Box<Content>),
    NewtypeVariant(&'static str, u32, &'static str, Box<Content>),
    Seq(Option<usize>, Vec<Content>),
    Tuple(Vec<Content>),
    TupleStruct(&'static str, Vec<Content>),
    TupleVariant(&'static str, u32, &'static str, Vec<Content>),
    Map(Option<usize>, Vec<(Content, Content)>),
    Struct(&'static str, usize, Vec<(&'static str, Option<Content>)>),
    StructVariant(
        &'static str,
        u32,
        &'static str,
        usize,
        Vec<(&'static str, Option<Content>)>,
    ),
}

/// `value` recorded as [`Content`].
fn capture<E: serde::ser::Error, T: Serialize + ?Sized>(value: &T) -> Result<Content, E> {
    value.serialize(Capture(std::marker::PhantomData))
}

impl Serialize for Content {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::{
            SerializeMap, SerializeSeq, SerializeStruct, SerializeStructVariant, SerializeTuple,
            SerializeTupleStruct, SerializeTupleVariant,
        };
        match self {
            Self::Bool(v) => s.serialize_bool(*v),
            Self::I64(v) => s.serialize_i64(*v),
            Self::I128(v) => s.serialize_i128(*v),
            Self::U64(v) => s.serialize_u64(*v),
            Self::U128(v) => s.serialize_u128(*v),
            Self::F32(v) => s.serialize_f32(*v),
            Self::F64(v) => s.serialize_f64(*v),
            Self::Char(v) => s.serialize_char(*v),
            Self::Str(v) => s.serialize_str(v),
            Self::Bytes(v) => s.serialize_bytes(v),
            Self::None => s.serialize_none(),
            Self::Some(v) => s.serialize_some(&**v),
            Self::Unit => s.serialize_unit(),
            Self::UnitStruct(name) => s.serialize_unit_struct(name),
            Self::UnitVariant(name, index, variant) => {
                s.serialize_unit_variant(name, *index, variant)
            }
            Self::NewtypeStruct(name, v) => s.serialize_newtype_struct(name, &**v),
            Self::NewtypeVariant(name, index, variant, v) => {
                s.serialize_newtype_variant(name, *index, variant, &**v)
            }
            Self::Seq(len, items) => {
                let mut seq = s.serialize_seq(*len)?;
                for item in items {
                    seq.serialize_element(item)?;
                }
                seq.end()
            }
            Self::Tuple(items) => {
                let mut tuple = s.serialize_tuple(items.len())?;
                for item in items {
                    tuple.serialize_element(item)?;
                }
                tuple.end()
            }
            Self::TupleStruct(name, items) => {
                let mut tuple = s.serialize_tuple_struct(name, items.len())?;
                for item in items {
                    tuple.serialize_field(item)?;
                }
                tuple.end()
            }
            Self::TupleVariant(name, index, variant, items) => {
                let mut tuple = s.serialize_tuple_variant(name, *index, variant, items.len())?;
                for item in items {
                    tuple.serialize_field(item)?;
                }
                tuple.end()
            }
            Self::Map(len, entries) => {
                let mut map = s.serialize_map(*len)?;
                for (key, value) in entries {
                    map.serialize_entry(key, value)?;
                }
                map.end()
            }
            Self::Struct(name, len, fields) => {
                let mut record = s.serialize_struct(name, *len)?;
                for (key, value) in fields {
                    match value {
                        Some(value) => record.serialize_field(key, value)?,
                        None => record.skip_field(key)?,
                    }
                }
                record.end()
            }
            Self::StructVariant(name, index, variant, len, fields) => {
                let mut record = s.serialize_struct_variant(name, *index, variant, *len)?;
                for (key, value) in fields {
                    match value {
                        Some(value) => record.serialize_field(key, value)?,
                        None => record.skip_field(key)?,
                    }
                }
                record.end()
            }
        }
    }
}

/// The serializer that records a value as [`Content`], failing with the caller's error type.
struct Capture<E>(std::marker::PhantomData<fn() -> E>);

/// What a [`CaptureSeq`] makes.
enum SeqKind {
    Seq(Option<usize>),
    Tuple,
    TupleStruct(&'static str),
    TupleVariant(&'static str, u32, &'static str),
}

/// [`Capture`]'s sequence-like compounds: the items so far, and what they will make.
struct CaptureSeq<E> {
    kind: SeqKind,
    items: Vec<Content>,
    error: std::marker::PhantomData<fn() -> E>,
}

impl<E> CaptureSeq<E> {
    fn new(kind: SeqKind, len: usize) -> Self {
        Self {
            kind,
            items: Vec::with_capacity(len.min(4096)),
            error: std::marker::PhantomData,
        }
    }

    fn push<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), E>
    where
        E: serde::ser::Error,
    {
        self.items.push(capture::<E, _>(value)?);
        Ok(())
    }

    fn finish(self) -> Content {
        match self.kind {
            SeqKind::Seq(len) => Content::Seq(len, self.items),
            SeqKind::Tuple => Content::Tuple(self.items),
            SeqKind::TupleStruct(name) => Content::TupleStruct(name, self.items),
            SeqKind::TupleVariant(name, index, variant) => {
                Content::TupleVariant(name, index, variant, self.items)
            }
        }
    }
}

impl<E: serde::ser::Error> serde::ser::SerializeSeq for CaptureSeq<E> {
    type Ok = Content;
    type Error = E;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), E> {
        self.push(value)
    }
    fn end(self) -> Result<Content, E> {
        Ok(self.finish())
    }
}

impl<E: serde::ser::Error> serde::ser::SerializeTuple for CaptureSeq<E> {
    type Ok = Content;
    type Error = E;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), E> {
        self.push(value)
    }
    fn end(self) -> Result<Content, E> {
        Ok(self.finish())
    }
}

impl<E: serde::ser::Error> serde::ser::SerializeTupleStruct for CaptureSeq<E> {
    type Ok = Content;
    type Error = E;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), E> {
        self.push(value)
    }
    fn end(self) -> Result<Content, E> {
        Ok(self.finish())
    }
}

impl<E: serde::ser::Error> serde::ser::SerializeTupleVariant for CaptureSeq<E> {
    type Ok = Content;
    type Error = E;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), E> {
        self.push(value)
    }
    fn end(self) -> Result<Content, E> {
        Ok(self.finish())
    }
}

/// [`Capture`]'s map compound.
struct CaptureMap<E> {
    len: Option<usize>,
    entries: Vec<(Content, Content)>,
    key: Option<Content>,
    error: std::marker::PhantomData<fn() -> E>,
}

impl<E: serde::ser::Error> serde::ser::SerializeMap for CaptureMap<E> {
    type Ok = Content;
    type Error = E;
    fn serialize_key<T: Serialize + ?Sized>(&mut self, key: &T) -> Result<(), E> {
        self.key = Some(capture::<E, _>(key)?);
        Ok(())
    }
    fn serialize_value<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), E> {
        let key = self
            .key
            .take()
            .ok_or_else(|| E::custom("a map value was written before its key"))?;
        self.entries.push((key, capture::<E, _>(value)?));
        Ok(())
    }
    fn end(self) -> Result<Content, E> {
        Ok(Content::Map(self.len, self.entries))
    }
}

/// What a [`CaptureStruct`] makes.
enum StructKind {
    Struct(&'static str, usize),
    Variant(&'static str, u32, &'static str, usize),
}

/// [`Capture`]'s struct and struct-variant compounds.
struct CaptureStruct<E> {
    kind: StructKind,
    fields: Vec<(&'static str, Option<Content>)>,
    error: std::marker::PhantomData<fn() -> E>,
}

impl<E> CaptureStruct<E> {
    fn new(kind: StructKind, len: usize) -> Self {
        Self {
            kind,
            fields: Vec::with_capacity(len.min(4096)),
            error: std::marker::PhantomData,
        }
    }

    fn finish(self) -> Content {
        match self.kind {
            StructKind::Struct(name, len) => Content::Struct(name, len, self.fields),
            StructKind::Variant(name, index, variant, len) => {
                Content::StructVariant(name, index, variant, len, self.fields)
            }
        }
    }
}

impl<E: serde::ser::Error> serde::ser::SerializeStruct for CaptureStruct<E> {
    type Ok = Content;
    type Error = E;
    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), E> {
        self.fields.push((key, Some(capture::<E, _>(value)?)));
        Ok(())
    }
    fn skip_field(&mut self, key: &'static str) -> Result<(), E> {
        self.fields.push((key, None));
        Ok(())
    }
    fn end(self) -> Result<Content, E> {
        Ok(self.finish())
    }
}

impl<E: serde::ser::Error> serde::ser::SerializeStructVariant for CaptureStruct<E> {
    type Ok = Content;
    type Error = E;
    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), E> {
        self.fields.push((key, Some(capture::<E, _>(value)?)));
        Ok(())
    }
    fn skip_field(&mut self, key: &'static str) -> Result<(), E> {
        self.fields.push((key, None));
        Ok(())
    }
    fn end(self) -> Result<Content, E> {
        Ok(self.finish())
    }
}

macro_rules! capture_scalars {
    ($($method:ident($ty:ty) => $variant:ident),+ $(,)?) => {
        $(
            fn $method(self, v: $ty) -> Result<Content, E> {
                Ok(Content::$variant(v.into()))
            }
        )+
    };
}

impl<E: serde::ser::Error> serde::Serializer for Capture<E> {
    type Ok = Content;
    type Error = E;
    type SerializeSeq = CaptureSeq<E>;
    type SerializeTuple = CaptureSeq<E>;
    type SerializeTupleStruct = CaptureSeq<E>;
    type SerializeTupleVariant = CaptureSeq<E>;
    type SerializeMap = CaptureMap<E>;
    type SerializeStruct = CaptureStruct<E>;
    type SerializeStructVariant = CaptureStruct<E>;

    capture_scalars! {
        serialize_bool(bool) => Bool,
        serialize_i8(i8) => I64,
        serialize_i16(i16) => I64,
        serialize_i32(i32) => I64,
        serialize_i64(i64) => I64,
        serialize_i128(i128) => I128,
        serialize_u8(u8) => U64,
        serialize_u16(u16) => U64,
        serialize_u32(u32) => U64,
        serialize_u64(u64) => U64,
        serialize_u128(u128) => U128,
        serialize_f32(f32) => F32,
        serialize_f64(f64) => F64,
        serialize_char(char) => Char,
        serialize_str(&str) => Str,
        serialize_bytes(&[u8]) => Bytes,
    }

    fn serialize_none(self) -> Result<Content, E> {
        Ok(Content::None)
    }

    fn serialize_some<T: Serialize + ?Sized>(self, value: &T) -> Result<Content, E> {
        Ok(Content::Some(Box::new(capture::<E, _>(value)?)))
    }

    fn serialize_unit(self) -> Result<Content, E> {
        Ok(Content::Unit)
    }

    fn serialize_unit_struct(self, name: &'static str) -> Result<Content, E> {
        Ok(Content::UnitStruct(name))
    }

    fn serialize_unit_variant(
        self,
        name: &'static str,
        index: u32,
        variant: &'static str,
    ) -> Result<Content, E> {
        Ok(Content::UnitVariant(name, index, variant))
    }

    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        name: &'static str,
        value: &T,
    ) -> Result<Content, E> {
        Ok(Content::NewtypeStruct(
            name,
            Box::new(capture::<E, _>(value)?),
        ))
    }

    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        name: &'static str,
        index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<Content, E> {
        Ok(Content::NewtypeVariant(
            name,
            index,
            variant,
            Box::new(capture::<E, _>(value)?),
        ))
    }

    fn serialize_seq(self, len: Option<usize>) -> Result<CaptureSeq<E>, E> {
        Ok(CaptureSeq::new(SeqKind::Seq(len), len.unwrap_or(0)))
    }

    fn serialize_tuple(self, len: usize) -> Result<CaptureSeq<E>, E> {
        Ok(CaptureSeq::new(SeqKind::Tuple, len))
    }

    fn serialize_tuple_struct(self, name: &'static str, len: usize) -> Result<CaptureSeq<E>, E> {
        Ok(CaptureSeq::new(SeqKind::TupleStruct(name), len))
    }

    fn serialize_tuple_variant(
        self,
        name: &'static str,
        index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<CaptureSeq<E>, E> {
        Ok(CaptureSeq::new(
            SeqKind::TupleVariant(name, index, variant),
            len,
        ))
    }

    fn serialize_map(self, len: Option<usize>) -> Result<CaptureMap<E>, E> {
        Ok(CaptureMap {
            len,
            entries: Vec::with_capacity(len.unwrap_or(0).min(4096)),
            key: None,
            error: std::marker::PhantomData,
        })
    }

    fn serialize_struct(self, name: &'static str, len: usize) -> Result<CaptureStruct<E>, E> {
        Ok(CaptureStruct::new(StructKind::Struct(name, len), len))
    }

    fn serialize_struct_variant(
        self,
        name: &'static str,
        index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<CaptureStruct<E>, E> {
        Ok(CaptureStruct::new(
            StructKind::Variant(name, index, variant, len),
            len,
        ))
    }
}

/// Read a [`Value`] tree into `T`, in memory, as serde_yaml's `from_value` did: through
/// [`ValueDeserializer`], with its semantics and its error texts (which carry no position).
pub fn from_value<T: DeserializeOwned>(value: Value) -> Result<T, Error> {
    unmirrored(|| T::deserialize(deserializer(value)))
}

/// A [`Value`] tree as serde input, read in memory: what serde_yaml offered by making its `Value`
/// itself a `Deserializer`. Pass it wherever a generic `D: Deserializer` reader or a
/// `DeserializeSeed` wants the tree, instead of writing the tree out and parsing it again.
///
/// The rules are serde_yaml 0.9's `Value` deserializer's, rule by rule, on ciborium's variants:
/// - any: an integer is visited as `u64` when non-negative and `i64` otherwise (wider ones as
///   `u128`/`i128`), a float as `f64`, null as unit, a string, a bool, a sequence, a mapping
///   (keys read as values in turn), bytes as bytes;
/// - every number type takes any number, so an integer reads into an `f32`/`f64` field;
/// - null reads as `None`, as unit, as an empty sequence and as an empty mapping;
/// - an enum is a string (a unit variant), a single-key mapping (the variant and its content), or
///   a tagged node: `!Variant content` selects `Variant` (the tag without its `!`), as serde_yaml
///   0.9 read a `Value::Tagged`;
/// - any other read of a tagged node reads its value, except `any`, which hands the visitor the
///   tag in ciborium's own form (an enum, as serde_yaml handed its `Value::Tagged`), so a
///   [`Value`] read from this deserializer keeps it;
/// - human-readable, as YAML is; type errors are serde's `invalid type: ..., expected ...` texts.
#[derive(Debug, Clone)]
pub struct ValueDeserializer {
    value: Value,
}

/// A [`ValueDeserializer`] over `value`.
#[must_use]
pub fn deserializer(value: Value) -> ValueDeserializer {
    ValueDeserializer { value }
}

impl<'de> serde::de::IntoDeserializer<'de, Error> for ValueDeserializer {
    type Deserializer = Self;
    fn into_deserializer(self) -> Self {
        self
    }
}

impl<'de> serde::de::IntoDeserializer<'de, Error> for Value {
    type Deserializer = ValueDeserializer;
    fn into_deserializer(self) -> ValueDeserializer {
        deserializer(self)
    }
}

/// The value under any tags: ciborium's `Tag` wraps a value the reader sees through.
fn untag(mut value: Value) -> Value {
    loop {
        match value {
            Value::Tag(_, inner) => value = *inner,
            other => return other,
        }
    }
}

/// The value under any tags, by reference.
fn bare(value: &Value) -> &Value {
    match value {
        Value::Tag(_, inner) => bare(inner),
        other => other,
    }
}

/// The value under any tags, mutably.
fn bare_mut(value: &mut Value) -> &mut Value {
    match value {
        Value::Tag(_, inner) => bare_mut(inner),
        other => other,
    }
}

/// How serde names `value` in an `invalid type` error, as serde_yaml named its `Value`'s variants.
fn unexpected(value: &Value) -> serde::de::Unexpected<'_> {
    use serde::de::Unexpected;
    match value {
        Value::Null => Unexpected::Unit,
        Value::Bool(b) => Unexpected::Bool(*b),
        Value::Integer(i) => {
            let i = i128::from(*i);
            match (u64::try_from(i), i64::try_from(i)) {
                (Ok(u), _) => Unexpected::Unsigned(u),
                (_, Ok(s)) => Unexpected::Signed(s),
                _ => Unexpected::Other("integer"),
            }
        }
        Value::Float(f) => Unexpected::Float(*f),
        Value::Text(s) => Unexpected::Str(s),
        Value::Bytes(b) => Unexpected::Bytes(b),
        Value::Array(_) => Unexpected::Seq,
        Value::Map(_) => Unexpected::Map,
        Value::Tag(_, inner) => unexpected(inner),
        _ => Unexpected::Other("YAML value"),
    }
}

#[cold]
fn invalid_type(value: &Value, expected: &dyn serde::de::Expected) -> Error {
    serde::de::Error::invalid_type(unexpected(value), expected)
}

fn visit_integer<'de, V: serde::de::Visitor<'de>>(
    integer: ciborium::value::Integer,
    visitor: V,
) -> Result<V::Value, Error> {
    let i = i128::from(integer);
    if let Ok(u) = u64::try_from(i) {
        visitor.visit_u64(u)
    } else if let Ok(s) = i64::try_from(i) {
        visitor.visit_i64(s)
    } else if let Ok(u) = u128::try_from(i) {
        visitor.visit_u128(u)
    } else {
        visitor.visit_i128(i)
    }
}

fn visit_sequence<'de, V: serde::de::Visitor<'de>>(
    sequence: Vec<Value>,
    visitor: V,
) -> Result<V::Value, Error> {
    let len = sequence.len();
    let mut access = ValueSeq {
        iter: sequence.into_iter(),
    };
    let seq = visitor.visit_seq(&mut access)?;
    if access.iter.len() == 0 {
        Ok(seq)
    } else {
        Err(serde::de::Error::invalid_length(
            len,
            &"fewer elements in sequence",
        ))
    }
}

fn visit_mapping<'de, V: serde::de::Visitor<'de>>(
    mapping: Pairs,
    visitor: V,
) -> Result<V::Value, Error> {
    let len = mapping.len();
    let mut access = ValueMap {
        iter: mapping.into_iter(),
        value: None,
    };
    let map = visitor.visit_map(&mut access)?;
    if access.iter.len() == 0 {
        Ok(map)
    } else {
        Err(serde::de::Error::invalid_length(
            len,
            &"fewer elements in map",
        ))
    }
}

impl ValueDeserializer {
    fn deserialize_number<'de, V: serde::de::Visitor<'de>>(
        self,
        visitor: V,
    ) -> Result<V::Value, Error> {
        match untag(self.value) {
            Value::Integer(i) => visit_integer(i, visitor),
            Value::Float(f) => visitor.visit_f64(f),
            other => Err(invalid_type(&other, &visitor)),
        }
    }
}

impl<'de> serde::Deserializer<'de> for ValueDeserializer {
    type Error = Error;

    fn deserialize_any<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self.value {
            Value::Tag(id, value) => visitor.visit_enum(CborTag { id, value: *value }),
            Value::Null => visitor.visit_unit(),
            Value::Bool(b) => visitor.visit_bool(b),
            Value::Integer(i) => visit_integer(i, visitor),
            Value::Float(f) => visitor.visit_f64(f),
            Value::Text(s) => visitor.visit_string(s),
            Value::Bytes(b) => visitor.visit_byte_buf(b),
            Value::Array(s) => visit_sequence(s, visitor),
            Value::Map(m) => visit_mapping(m, visitor),
            other => Err(invalid_type(&other, &visitor)),
        }
    }

    fn deserialize_bool<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match untag(self.value) {
            Value::Bool(b) => visitor.visit_bool(b),
            other => Err(invalid_type(&other, &visitor)),
        }
    }

    fn deserialize_i8<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_number(visitor)
    }

    fn deserialize_i16<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_number(visitor)
    }

    fn deserialize_i32<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_number(visitor)
    }

    fn deserialize_i64<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_number(visitor)
    }

    fn deserialize_i128<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_number(visitor)
    }

    fn deserialize_u8<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_number(visitor)
    }

    fn deserialize_u16<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_number(visitor)
    }

    fn deserialize_u32<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_number(visitor)
    }

    fn deserialize_u64<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_number(visitor)
    }

    fn deserialize_u128<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_number(visitor)
    }

    fn deserialize_f32<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_number(visitor)
    }

    fn deserialize_f64<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_number(visitor)
    }

    fn deserialize_char<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_string(visitor)
    }

    fn deserialize_str<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_string(visitor)
    }

    fn deserialize_string<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match untag(self.value) {
            Value::Text(s) => visitor.visit_string(s),
            other => Err(invalid_type(&other, &visitor)),
        }
    }

    fn deserialize_bytes<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_byte_buf(visitor)
    }

    fn deserialize_byte_buf<V: serde::de::Visitor<'de>>(
        self,
        visitor: V,
    ) -> Result<V::Value, Error> {
        match untag(self.value) {
            Value::Text(s) => visitor.visit_string(s),
            Value::Bytes(b) => visitor.visit_byte_buf(b),
            Value::Array(s) => visit_sequence(s, visitor),
            other => Err(invalid_type(&other, &visitor)),
        }
    }

    /// Only a bare null is `None`; a tagged node is `Some`, its tag kept, as serde_yaml read it.
    fn deserialize_option<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self.value {
            Value::Null => visitor.visit_none(),
            other => visitor.visit_some(deserializer(other)),
        }
    }

    fn deserialize_unit<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match untag(self.value) {
            Value::Null => visitor.visit_unit(),
            other => Err(invalid_type(&other, &visitor)),
        }
    }

    fn deserialize_unit_struct<V: serde::de::Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.deserialize_unit(visitor)
    }

    fn deserialize_newtype_struct<V: serde::de::Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Error> {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_seq<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match untag(self.value) {
            Value::Array(s) => visit_sequence(s, visitor),
            Value::Null => visit_sequence(Vec::new(), visitor),
            other => Err(invalid_type(&other, &visitor)),
        }
    }

    fn deserialize_tuple<V: serde::de::Visitor<'de>>(
        self,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.deserialize_seq(visitor)
    }

    fn deserialize_tuple_struct<V: serde::de::Visitor<'de>>(
        self,
        _name: &'static str,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.deserialize_seq(visitor)
    }

    fn deserialize_map<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match untag(self.value) {
            Value::Map(m) => visit_mapping(m, visitor),
            Value::Null => visit_mapping(Pairs::new(), visitor),
            other => Err(invalid_type(&other, &visitor)),
        }
    }

    fn deserialize_struct<V: serde::de::Visitor<'de>>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.deserialize_map(visitor)
    }

    fn deserialize_enum<V: serde::de::Visitor<'de>>(
        self,
        name: &'static str,
        variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        let (variant, content) = match self.value {
            Value::Tag(id, content) => match tag_name(id) {
                Some(tag) => {
                    let variant = tag.strip_prefix('!').unwrap_or(&tag).to_owned();
                    (Value::Text(variant), Some(*content))
                }
                None => {
                    return serde::Deserializer::deserialize_enum(
                        deserializer(*content),
                        name,
                        variants,
                        visitor,
                    )
                }
            },
            variant @ Value::Text(_) => (variant, None),
            Value::Map(mut m) if m.len() == 1 => {
                let (variant, content) = m.swap_remove(0);
                (variant, Some(content))
            }
            other => return Err(invalid_type(&other, &"a Value::Tagged enum")),
        };
        visitor.visit_enum(ValueEnum { variant, content })
    }

    fn deserialize_identifier<V: serde::de::Visitor<'de>>(
        self,
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.deserialize_string(visitor)
    }

    fn deserialize_ignored_any<V: serde::de::Visitor<'de>>(
        self,
        visitor: V,
    ) -> Result<V::Value, Error> {
        visitor.visit_unit()
    }
}

/// A [`Value::Tag`] handed to a visitor in ciborium's form: the variant `@@TAGGED@@`, whose
/// tuple content is the tag number and the value.
struct CborTag {
    id: u64,
    value: Value,
}

impl<'de> serde::de::EnumAccess<'de> for CborTag {
    type Error = Error;
    type Variant = Self;

    fn variant_seed<V: serde::de::DeserializeSeed<'de>>(
        self,
        seed: V,
    ) -> Result<(V::Value, Self), Error> {
        let variant =
            seed.deserialize(serde::de::value::StrDeserializer::<Error>::new(CBOR_TAGGED))?;
        Ok((variant, self))
    }
}

impl<'de> serde::de::VariantAccess<'de> for CborTag {
    type Error = Error;

    fn unit_variant(self) -> Result<(), Error> {
        Err(invalid_type(&self.value, &"a tagged value"))
    }

    fn newtype_variant_seed<T: serde::de::DeserializeSeed<'de>>(
        self,
        seed: T,
    ) -> Result<T::Value, Error> {
        seed.deserialize(deserializer(self.value))
    }

    fn tuple_variant<V: serde::de::Visitor<'de>>(
        self,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value, Error> {
        visit_sequence(vec![Value::from(self.id), self.value], visitor)
    }

    fn struct_variant<V: serde::de::Visitor<'de>>(
        self,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        Err(invalid_type(&self.value, &visitor))
    }
}

/// A sequence's elements, each read as a [`ValueDeserializer`].
struct ValueSeq {
    iter: std::vec::IntoIter<Value>,
}

impl<'de> serde::de::SeqAccess<'de> for ValueSeq {
    type Error = Error;

    fn next_element_seed<T: serde::de::DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, Error> {
        match self.iter.next() {
            Some(value) => seed.deserialize(deserializer(value)).map(Some),
            None => Ok(None),
        }
    }

    fn size_hint(&self) -> Option<usize> {
        match self.iter.size_hint() {
            (lower, Some(upper)) if lower == upper => Some(upper),
            _ => None,
        }
    }
}

impl<'de> serde::Deserializer<'de> for ValueSeq {
    type Error = Error;

    /// serde_yaml's tuple-variant content: an empty sequence reads as unit.
    fn deserialize_any<V: serde::de::Visitor<'de>>(
        mut self,
        visitor: V,
    ) -> Result<V::Value, Error> {
        let len = self.iter.len();
        if len == 0 {
            return visitor.visit_unit();
        }
        let ret = visitor.visit_seq(&mut self)?;
        if self.iter.len() == 0 {
            Ok(ret)
        } else {
            Err(serde::de::Error::invalid_length(
                len,
                &"fewer elements in sequence",
            ))
        }
    }

    fn deserialize_ignored_any<V: serde::de::Visitor<'de>>(
        self,
        visitor: V,
    ) -> Result<V::Value, Error> {
        visitor.visit_unit()
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string bytes
        byte_buf option unit unit_struct newtype_struct seq tuple tuple_struct
        map struct enum identifier
    }
}

/// A mapping's pairs, keys and values each read as a [`ValueDeserializer`].
struct ValueMap {
    iter: std::vec::IntoIter<(Value, Value)>,
    value: Option<Value>,
}

impl<'de> serde::de::MapAccess<'de> for ValueMap {
    type Error = Error;

    fn next_key_seed<K: serde::de::DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, Error> {
        match self.iter.next() {
            Some((key, value)) => {
                self.value = Some(value);
                seed.deserialize(deserializer(key)).map(Some)
            }
            None => Ok(None),
        }
    }

    fn next_value_seed<T: serde::de::DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<T::Value, Error> {
        match self.value.take() {
            Some(value) => seed.deserialize(deserializer(value)),
            None => Err(serde::de::Error::custom("value is missing")),
        }
    }

    fn size_hint(&self) -> Option<usize> {
        match self.iter.size_hint() {
            (lower, Some(upper)) if lower == upper => Some(upper),
            _ => None,
        }
    }
}

impl<'de> serde::Deserializer<'de> for ValueMap {
    type Error = Error;

    /// serde_yaml's struct-variant content.
    fn deserialize_any<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        visitor.visit_map(self)
    }

    fn deserialize_ignored_any<V: serde::de::Visitor<'de>>(
        self,
        visitor: V,
    ) -> Result<V::Value, Error> {
        visitor.visit_unit()
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string bytes
        byte_buf option unit unit_struct newtype_struct seq tuple tuple_struct
        map struct enum identifier
    }
}

/// An enum read from a [`Value`]: the variant name, and its content when it has one.
struct ValueEnum {
    variant: Value,
    content: Option<Value>,
}

impl<'de> serde::de::EnumAccess<'de> for ValueEnum {
    type Error = Error;
    type Variant = ValueVariant;

    fn variant_seed<V: serde::de::DeserializeSeed<'de>>(
        self,
        seed: V,
    ) -> Result<(V::Value, ValueVariant), Error> {
        let variant = seed.deserialize(deserializer(self.variant))?;
        Ok((
            variant,
            ValueVariant {
                content: self.content,
            },
        ))
    }
}

/// An enum variant's content, read as serde_yaml read a `Value::Tagged`'s value.
struct ValueVariant {
    content: Option<Value>,
}

impl<'de> serde::de::VariantAccess<'de> for ValueVariant {
    type Error = Error;

    fn unit_variant(self) -> Result<(), Error> {
        match self.content {
            Some(content) => serde::Deserialize::deserialize(deserializer(content)),
            None => Ok(()),
        }
    }

    fn newtype_variant_seed<T: serde::de::DeserializeSeed<'de>>(
        self,
        seed: T,
    ) -> Result<T::Value, Error> {
        match self.content {
            Some(content) => seed.deserialize(deserializer(content)),
            None => Err(serde::de::Error::invalid_type(
                serde::de::Unexpected::UnitVariant,
                &"newtype variant",
            )),
        }
    }

    fn tuple_variant<V: serde::de::Visitor<'de>>(
        self,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value, Error> {
        match self.content.map(untag) {
            Some(Value::Array(s)) => serde::Deserializer::deserialize_any(
                ValueSeq {
                    iter: s.into_iter(),
                },
                visitor,
            ),
            Some(other) => Err(invalid_type(&other, &"tuple variant")),
            None => Err(serde::de::Error::invalid_type(
                serde::de::Unexpected::UnitVariant,
                &"tuple variant",
            )),
        }
    }

    fn struct_variant<V: serde::de::Visitor<'de>>(
        self,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        match self.content.map(untag) {
            Some(Value::Map(m)) => serde::Deserializer::deserialize_any(
                ValueMap {
                    iter: m.into_iter(),
                    value: None,
                },
                visitor,
            ),
            Some(other) => Err(invalid_type(&other, &"struct variant")),
            None => Err(serde::de::Error::invalid_type(
                serde::de::Unexpected::UnitVariant,
                &"struct variant",
            )),
        }
    }
}

/// Write `value` into a [`Value`] tree, as reading back its YAML text would give it.
/// Takes the value by value, as serde_yaml's `to_value` did (a reference serializes the same).
pub fn to_value<T: Serialize>(value: T) -> Result<Value, Error> {
    let text = to_string(&value)?;
    from_str(&text).map_err(|e| Error::unplaced(e.message))
}

/// A way to index into a [`Value`]: a string key, an integer key or sequence position, or a
/// [`Value`] key. The same set serde_yaml's `Index` accepted.
pub trait Index {
    /// The position of this key among `mapping`'s pairs.
    fn position(&self, mapping: &[(Value, Value)]) -> Option<usize>;
    /// The sequence element this index names, if it is a position.
    fn element<'v>(&self, _sequence: &'v [Value]) -> Option<&'v Value> {
        None
    }
    /// The sequence element this index names, mutably.
    fn element_mut<'v>(&self, _sequence: &'v mut [Value]) -> Option<&'v mut Value> {
        None
    }
    /// This index as a mapping key.
    fn key(&self) -> Value;
}

impl Index for str {
    fn position(&self, mapping: &[(Value, Value)]) -> Option<usize> {
        mapping
            .iter()
            .position(|(k, _)| matches!(k, Value::Text(t) if t == self))
    }
    fn key(&self) -> Value {
        Value::Text(self.to_owned())
    }
}

impl Index for String {
    fn position(&self, mapping: &[(Value, Value)]) -> Option<usize> {
        self.as_str().position(mapping)
    }
    fn key(&self) -> Value {
        Value::Text(self.clone())
    }
}

impl Index for usize {
    fn position(&self, mapping: &[(Value, Value)]) -> Option<usize> {
        let wanted = u64::try_from(*self).ok()?;
        mapping
            .iter()
            .position(|(k, _)| k.as_integer().and_then(|i| u64::try_from(i).ok()) == Some(wanted))
    }
    fn element<'v>(&self, sequence: &'v [Value]) -> Option<&'v Value> {
        sequence.get(*self)
    }
    fn element_mut<'v>(&self, sequence: &'v mut [Value]) -> Option<&'v mut Value> {
        sequence.get_mut(*self)
    }
    fn key(&self) -> Value {
        Value::from(*self as u64)
    }
}

impl Index for Value {
    fn position(&self, mapping: &[(Value, Value)]) -> Option<usize> {
        mapping.iter().position(|(k, _)| same_tree(k, self))
    }
    fn element<'v>(&self, sequence: &'v [Value]) -> Option<&'v Value> {
        let at = usize::try_from(self.as_integer()?).ok()?;
        sequence.get(at)
    }
    fn element_mut<'v>(&self, sequence: &'v mut [Value]) -> Option<&'v mut Value> {
        let at = usize::try_from(self.as_integer()?).ok()?;
        sequence.get_mut(at)
    }
    fn key(&self) -> Value {
        self.clone()
    }
}

impl<T: Index + ?Sized> Index for &T {
    fn position(&self, mapping: &[(Value, Value)]) -> Option<usize> {
        (**self).position(mapping)
    }
    fn element<'v>(&self, sequence: &'v [Value]) -> Option<&'v Value> {
        (**self).element(sequence)
    }
    fn element_mut<'v>(&self, sequence: &'v mut [Value]) -> Option<&'v mut Value> {
        (**self).element_mut(sequence)
    }
    fn key(&self) -> Value {
        (**self).key()
    }
}

static NULL: Value = Value::Null;

/// serde_yaml-style reads over a [`Value`].
pub trait ValueExt {
    /// The value at `index` in a mapping or sequence; `None` when absent or not a collection.
    fn get<I: Index>(&self, index: I) -> Option<&Value>;
    /// The value at `index`, mutably.
    fn get_mut<I: Index>(&mut self, index: I) -> Option<&mut Value>;
    /// `value[index]` as serde_yaml read it: the value at `index`, or `Null` when absent.
    fn at<I: Index>(&self, index: I) -> &Value;
    /// `value[index] = ..` as serde_yaml wrote it: a `Null` becomes an empty mapping, and a
    /// missing mapping key is inserted as `Null`.
    ///
    /// # Panics
    /// When the value is neither a mapping nor `Null`, or a sequence position is out of range, as
    /// serde_yaml's `IndexMut` did.
    fn at_mut<I: Index>(&mut self, index: I) -> &mut Value;
    /// The string, if this is a string.
    fn as_str(&self) -> Option<&str>;
    /// The mapping, if this is a mapping.
    fn as_mapping(&self) -> Option<&Pairs>;
    /// The mapping, mutably.
    fn as_mapping_mut(&mut self) -> Option<&mut Pairs>;
    /// The sequence, if this is a sequence.
    fn as_sequence(&self) -> Option<&Vec<Value>>;
    /// The sequence, mutably.
    fn as_sequence_mut(&mut self) -> Option<&mut Vec<Value>>;
    /// The integer as a `u64`, if it is one.
    fn as_u64(&self) -> Option<u64>;
    /// The integer as an `i64`, if it is one.
    fn as_i64(&self) -> Option<i64>;
    /// The number as an `f64` (integers included), if it is one.
    fn as_f64(&self) -> Option<f64>;
    /// Whether this is a mapping.
    fn is_mapping(&self) -> bool;
    /// Whether this is a sequence.
    fn is_sequence(&self) -> bool;
    /// Whether this is a string.
    fn is_string(&self) -> bool;
    /// Whether this is a number (integer or float).
    fn is_number(&self) -> bool;
    /// Whether this is an integer that fits a `u64`.
    fn is_u64(&self) -> bool;
    /// Whether this is an integer that fits an `i64`.
    fn is_i64(&self) -> bool;
    /// Whether this is a float.
    fn is_f64(&self) -> bool;
}

impl ValueExt for Value {
    // Every read looks through a tag to the tagged value, as serde_yaml's `Value` methods did.
    fn get<I: Index>(&self, index: I) -> Option<&Value> {
        match bare(self) {
            Value::Map(m) => index.position(m).map(|at| &m[at].1),
            Value::Array(s) => index.element(s),
            _ => None,
        }
    }

    fn get_mut<I: Index>(&mut self, index: I) -> Option<&mut Value> {
        match bare_mut(self) {
            Value::Map(m) => index.position(m).map(|at| &mut m[at].1),
            Value::Array(s) => index.element_mut(s),
            _ => None,
        }
    }

    fn at<I: Index>(&self, index: I) -> &Value {
        self.get(index).unwrap_or(&NULL)
    }

    fn at_mut<I: Index>(&mut self, index: I) -> &mut Value {
        let value = bare_mut(self);
        if value.is_null() {
            *value = Value::Map(Pairs::new());
        }
        match value {
            Value::Map(m) => {
                let at = match index.position(m) {
                    Some(at) => at,
                    None => {
                        m.push((index.key(), Value::Null));
                        m.len() - 1
                    }
                };
                &mut m[at].1
            }
            Value::Array(s) => index
                .element_mut(s)
                .expect("YAML sequence index out of range"),
            _ => panic!("cannot index into a YAML scalar"),
        }
    }

    fn as_str(&self) -> Option<&str> {
        bare(self).as_text()
    }

    fn as_mapping(&self) -> Option<&Pairs> {
        bare(self).as_map()
    }

    fn as_mapping_mut(&mut self) -> Option<&mut Pairs> {
        bare_mut(self).as_map_mut()
    }

    fn as_sequence(&self) -> Option<&Vec<Value>> {
        bare(self).as_array()
    }

    fn as_sequence_mut(&mut self) -> Option<&mut Vec<Value>> {
        bare_mut(self).as_array_mut()
    }

    fn as_u64(&self) -> Option<u64> {
        bare(self).as_integer().and_then(|i| u64::try_from(i).ok())
    }

    fn as_i64(&self) -> Option<i64> {
        bare(self).as_integer().and_then(|i| i64::try_from(i).ok())
    }

    #[allow(clippy::cast_precision_loss)]
    fn as_f64(&self) -> Option<f64> {
        match bare(self) {
            Value::Float(f) => Some(*f),
            Value::Integer(i) => Some(i128::from(*i) as f64),
            _ => None,
        }
    }

    fn is_mapping(&self) -> bool {
        bare(self).is_map()
    }

    fn is_sequence(&self) -> bool {
        bare(self).is_array()
    }

    fn is_string(&self) -> bool {
        bare(self).is_text()
    }

    fn is_number(&self) -> bool {
        let value = bare(self);
        value.is_integer() || value.is_float()
    }

    fn is_u64(&self) -> bool {
        self.as_u64().is_some()
    }

    fn is_i64(&self) -> bool {
        self.as_i64().is_some()
    }

    fn is_f64(&self) -> bool {
        bare(self).is_float()
    }
}

/// serde_yaml `Mapping`-style key operations over [`Pairs`] (and so over a [`Mapping`], by deref).
///
/// The names differ from serde_yaml's where `Vec` already has a method of that name
/// (`get`, `get_mut`, `insert`, `remove`, `retain`).
pub trait MappingExt {
    /// The value under `key`.
    fn get_key<I: Index>(&self, key: I) -> Option<&Value>;
    /// The value under `key`, mutably.
    fn get_key_mut<I: Index>(&mut self, key: I) -> Option<&mut Value>;
    /// Whether `key` is present.
    fn contains_key<I: Index>(&self, key: I) -> bool;
    /// Set `key` to `value`: replaced in place when present (keeping its position), appended
    /// otherwise. Returns the old value.
    fn insert_key(&mut self, key: impl Into<Value>, value: Value) -> Option<Value>;
    /// Remove `key`, as serde_yaml's `Mapping::remove` did: the last pair moves into its place
    /// (`swap_remove`), so migrated documents keep 1.5.5's key order. Returns its value.
    fn remove_key<I: Index>(&mut self, key: I) -> Option<Value>;
    /// Remove `key` and return the pair, as [`MappingExt::remove_key`] does.
    fn remove_entry_key<I: Index>(&mut self, key: I) -> Option<(Value, Value)>;
    /// The value under `key`, inserted from `make` first when absent.
    fn entry_or_insert_with<I: Index>(
        &mut self,
        key: I,
        make: impl FnOnce() -> Value,
    ) -> &mut Value;
    /// The keys, in order.
    fn keys(&self) -> impl Iterator<Item = &Value>;
    /// The values, in order.
    fn values(&self) -> impl Iterator<Item = &Value>;
    /// The values, in order, mutably.
    fn values_mut(&mut self) -> impl Iterator<Item = &mut Value>;
    /// Keep only the pairs `keep` accepts, in order.
    fn retain_pairs(&mut self, keep: impl FnMut(&Value, &mut Value) -> bool);
}

impl MappingExt for Pairs {
    fn get_key<I: Index>(&self, key: I) -> Option<&Value> {
        key.position(self).map(|at| &self[at].1)
    }

    fn get_key_mut<I: Index>(&mut self, key: I) -> Option<&mut Value> {
        key.position(self).map(|at| &mut self[at].1)
    }

    fn contains_key<I: Index>(&self, key: I) -> bool {
        key.position(self).is_some()
    }

    fn insert_key(&mut self, key: impl Into<Value>, value: Value) -> Option<Value> {
        let key = key.into();
        match key.position(self) {
            Some(at) => Some(std::mem::replace(&mut self[at].1, value)),
            None => {
                self.push((key, value));
                None
            }
        }
    }

    fn remove_key<I: Index>(&mut self, key: I) -> Option<Value> {
        self.remove_entry_key(key).map(|(_, v)| v)
    }

    fn remove_entry_key<I: Index>(&mut self, key: I) -> Option<(Value, Value)> {
        key.position(self).map(|at| self.swap_remove(at))
    }

    fn entry_or_insert_with<I: Index>(
        &mut self,
        key: I,
        make: impl FnOnce() -> Value,
    ) -> &mut Value {
        let at = match key.position(self) {
            Some(at) => at,
            None => {
                self.push((key.key(), make()));
                self.len() - 1
            }
        };
        &mut self[at].1
    }

    fn keys(&self) -> impl Iterator<Item = &Value> {
        self.iter().map(|(k, _)| k)
    }

    fn values(&self) -> impl Iterator<Item = &Value> {
        self.iter().map(|(_, v)| v)
    }

    fn values_mut(&mut self) -> impl Iterator<Item = &mut Value> {
        self.iter_mut().map(|(_, v)| v)
    }

    fn retain_pairs(&mut self, mut keep: impl FnMut(&Value, &mut Value) -> bool) {
        self.retain_mut(|(k, v)| keep(k, v));
    }
}

/// [`untyped`] for an optional field: `null` (or absent, with `#[serde(default)]`) is `None`.
pub fn untyped_option<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Value>, D::Error> {
    let value = untyped(deserializer)?;
    Ok((!value.is_null()).then_some(value))
}
