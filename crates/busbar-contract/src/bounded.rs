//! The bounded types every other module is built out of. Every ceiling below is pinned by the
//! crate-graph section of the design and enforced at the type, not by a runtime check buried in a
//! handler; the one resource a plugin is handed is the per-unit arena, and every byte a plugin
//! produces comes out of it. See `docs/design/contract-notes.md`.

use core::fmt;

/// The most keys any arena-backed fact map may carry.
///
/// The crate-graph section of the design pins this at thirty-two.
pub const MAX_KEYS: usize = 32;

/// The most steps one unit may record.
///
/// The loop has ten named steps; the ceiling leaves room for the amendment rows the audit section
/// appends without letting a unit's step list grow without bound.
pub const MAX_STEPS: usize = 16;

/// The most usage lines one unit may settle.
pub const MAX_USAGE_LINES: usize = 16;

/// The most bytes one fixed-size journal record may occupy.
pub const MAX_RECORD_BYTES: usize = 512;

/// The per-connection read cursor ceiling, in bytes, credential slab included.
///
/// The buffer grows lazily; resident memory counts the actual bytes, never the ceiling. A frame
/// prefix that would carry the cursor past this is the cursor-budget refusal of the arrival gate.
pub const MAX_CURSOR_BYTES: usize = 64 * 1024;

/// The most consecutive "need more" answers a session-transport handshake may take.
///
/// This bounds handshake framing only. Body-chunk spooling is charged to the node-global spill
/// budget instead, so a large request body is never refused by this number.
pub const MAX_NEEDMORE_FRAMES: usize = 256;

/// The most upstream connections one session may pair with itself.
pub const MAX_SESSION_UPSTREAMS: usize = 8;

/// The most legs one route plan may carry.
pub const MAX_LEGS: usize = 8;

/// The most leg replies one unit may collect.
pub const MAX_LEG_REPLIES: usize = 2;

/// The per-unit arena size in bytes.
///
/// The arena is reset per frame on the relay path of an open unit and at unit end otherwise.
/// Relay and egress bodies live in the connection slab, never here.
pub const ARENA_BYTES: usize = 4 * 1024;

/// A fixed-capacity list.
///
/// The capacity is part of the type, so a bound the design states in prose is a bound the compiler
/// carries. Pushing past the capacity returns the value back to the caller rather than growing,
/// panicking or silently dropping it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundedVec<T, const N: usize> {
    items: Vec<T>,
}

impl<T, const N: usize> Default for BoundedVec<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const N: usize> BoundedVec<T, N> {
    /// A new, empty list.
    #[must_use]
    pub fn new() -> Self {
        Self {
            items: Vec::with_capacity(0),
        }
    }

    /// The capacity this type was declared with.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        N
    }

    /// How many items the list holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether the list is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Whether the list is at its declared capacity.
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.items.len() >= N
    }

    /// Append an item. Errors with the item handed back unchanged when the list is already full.
    pub fn push(&mut self, item: T) -> Result<(), Overflow<T>> {
        if self.is_full() {
            return Err(Overflow { item, capacity: N });
        }
        self.items.push(item);
        Ok(())
    }

    /// The items, in insertion order.
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        &self.items
    }

    /// The items, in insertion order, mutably.
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        &mut self.items
    }
}

impl<T, const N: usize> IntoIterator for BoundedVec<T, N> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.items.into_iter()
    }
}

impl<'a, T, const N: usize> IntoIterator for &'a BoundedVec<T, N> {
    type Item = &'a T;
    type IntoIter = core::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.items.iter()
    }
}

/// What a full [`BoundedVec`] hands back instead of growing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Overflow<T> {
    /// The item that did not fit.
    pub item: T,
    /// The capacity that was reached.
    pub capacity: usize,
}

impl<T> fmt::Display for Overflow<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "bounded list is full at {} items", self.capacity)
    }
}

/// Bytes borrowed from the per-unit arena.
///
/// The crate-graph section of the design bans the `bytes` crate's reference-counted buffer from
/// the plugin surface: a plugin that could clone a buffer handle could hold bytes past the unit
/// that paid for them. Arena bytes borrow, so they cannot outlive the unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArenaBytes<'u> {
    bytes: &'u [u8],
}

impl<'u> ArenaBytes<'u> {
    /// Wrap a slice the arena handed out.
    #[must_use]
    pub const fn new(bytes: &'u [u8]) -> Self {
        Self { bytes }
    }

    /// The bytes.
    #[must_use]
    pub const fn as_slice(&self) -> &'u [u8] {
        self.bytes
    }

    /// How many bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether there are no bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// Bytes owned by a connection slab.
///
/// Frames arrive from a transport and outlive the arena reset that happens between relayed frames,
/// so they cannot borrow the arena. This is the one owning byte handle on the plugin surface, and
/// it is deliberately a plain shared slice rather than the banned reference-counted buffer type:
/// it can be cloned cheaply but it carries no writable view and no split-off cursor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlabBytes {
    buf: std::sync::Arc<[u8]>,
    start: usize,
    end: usize,
}

impl SlabBytes {
    /// Take a whole slab.
    #[must_use]
    pub fn new(buf: std::sync::Arc<[u8]>) -> Self {
        let end = buf.len();
        Self { buf, start: 0, end }
    }

    /// Take a window of a slab, clamped to the slab's own bounds.
    #[must_use]
    pub fn window(buf: std::sync::Arc<[u8]>, start: usize, end: usize) -> Self {
        let len = buf.len();
        let start = start.min(len);
        let end = end.clamp(start, len);
        Self { buf, start, end }
    }

    /// The bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[self.start..self.end]
    }

    /// How many bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.end - self.start
    }

    /// Whether there are no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.end == self.start
    }
}

/// The one resource handle a plugin is given.
///
/// The contract section of the design says the context carries exactly one resource — the per-unit
/// arena — and that everything else on the context is a borrowed read-only view. Allocation is
/// fallible because the arena is fixed size: exhaustion ends the unit at the step that asked, it
/// does not grow the arena.
///
/// # Errors
/// Both allocation methods return [`ArenaBudget`] when the request does not fit in what is left
/// of the arena.
pub trait Arena: Send + Sync {
    /// Copy bytes into the arena.
    fn alloc_bytes<'a>(&'a self, src: &[u8]) -> Result<ArenaBytes<'a>, ArenaBudget>;

    /// Copy a string into the arena.
    fn alloc_str<'a>(&'a self, src: &str) -> Result<&'a str, ArenaBudget>;

    /// How many bytes remain before the next allocation fails.
    fn remaining(&self) -> usize;
}

/// The arena said no.
///
/// The loop turns this into a failure at the step that asked for the bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArenaBudget {
    /// How many bytes were asked for.
    pub wanted: usize,
    /// How many bytes were left.
    pub remaining: usize,
}

impl fmt::Display for ArenaBudget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "arena exhausted: wanted {} bytes, {} remain",
            self.wanted, self.remaining
        )
    }
}

impl std::error::Error for ArenaBudget {}

/// One value in a fact map.
///
/// Facts are evidence, never amounts and never decisions. The value shapes are deliberately narrow:
/// a plane that wants to hand the kernel structure hands it several keys, not a nested document.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FactValue<'u> {
    /// A borrowed string.
    Str(&'u str),
    /// Borrowed bytes.
    Bytes(&'u [u8]),
    /// A whole number.
    Int(i64),
    /// A flag.
    Bool(bool),
}

/// An arena-backed bounded map from declared key to fact value.
///
/// Keys are declared by the plugin up front, the map is pre-sized from that declaration, and
/// writes are last-write-wins. The map never allocates: it is a fixed array of at most
/// [`MAX_KEYS`] entries whose strings and bytes borrow the arena.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Facts<'u> {
    entries: [Option<(&'u str, FactValue<'u>)>; MAX_KEYS],
    len: usize,
}

impl Default for Facts<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'u> Facts<'u> {
    /// An empty map.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: [None; MAX_KEYS],
            len: 0,
        }
    }

    /// How many keys are set.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether no key is set.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Set a key, replacing any earlier value for it. Errors with [`FactsExhausted`] when the map
    /// already holds [`MAX_KEYS`] distinct keys and the key is a new one (the loop's
    /// session-facts-exhausted failure).
    pub fn set(&mut self, key: &'u str, value: FactValue<'u>) -> Result<(), FactsExhausted> {
        for (k, v) in self.entries.iter_mut().take(self.len).flatten() {
            if *k == key {
                *v = value;
                return Ok(());
            }
        }
        if self.len == MAX_KEYS {
            return Err(FactsExhausted { capacity: MAX_KEYS });
        }
        self.entries[self.len] = Some((key, value));
        self.len += 1;
        Ok(())
    }

    /// Read a key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<FactValue<'u>> {
        self.entries
            .iter()
            .take(self.len)
            .flatten()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| *v)
    }

    /// Every key and value, in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (&'u str, FactValue<'u>)> + '_ {
        self.entries.iter().take(self.len).flatten().copied()
    }
}

/// The fact map is at its declared key ceiling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FactsExhausted {
    /// The ceiling that was reached.
    pub capacity: usize,
}

impl fmt::Display for FactsExhausted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "fact map is full at {} keys", self.capacity)
    }
}

impl std::error::Error for FactsExhausted {}

/// Metric labels for one unit.
///
/// A borrowed, bounded key/value view. Labels are cardinality-bounded on purpose: an unbounded
/// label set is an unbounded time series, and that is an operational outage, not a metric.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Labels<'u> {
    entries: Facts<'u>,
}

impl<'u> Labels<'u> {
    /// An empty label set.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Facts::new(),
        }
    }

    /// Set a label. Errors with [`FactsExhausted`] at the key ceiling.
    pub fn set(&mut self, key: &'u str, value: &'u str) -> Result<(), FactsExhausted> {
        self.entries.set(key, FactValue::Str(value))
    }

    /// Read a label.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&'u str> {
        match self.entries.get(key) {
            Some(FactValue::Str(s)) => Some(s),
            _ => None,
        }
    }

    /// Every label.
    pub fn iter(&self) -> impl Iterator<Item = (&'u str, FactValue<'u>)> + '_ {
        self.entries.iter()
    }
}

/// A half-open byte range inside a scanned prefix.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct Span {
    /// First byte of the range.
    pub start: usize,
    /// One past the last byte of the range.
    pub end: usize,
}

impl Span {
    /// How many bytes the span covers.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    /// Whether the span covers nothing.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.end <= self.start
    }
}

/// The kernel's view of a unit's body: the bytes plus the resolved pointer spans.
///
/// The claims section of the design makes one serialization — the object notation the span scanner
/// understands — the only structure the kernel reads, and it reads it as spans, never as a parsed
/// document. The intermediate representation borrows the frame buffer; it owns nothing and copies
/// nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ir<'u> {
    body: &'u [u8],
    spans: &'u [(&'u str, Span)],
}

impl<'u> Ir<'u> {
    /// Build a view over a body and the pointer spans the scanner resolved in it.
    #[must_use]
    pub const fn new(body: &'u [u8], spans: &'u [(&'u str, Span)]) -> Self {
        Self { body, spans }
    }

    /// The body bytes.
    #[must_use]
    pub const fn body(&self) -> &'u [u8] {
        self.body
    }

    /// The bytes at a declared pointer, if the scanner reached it.
    #[must_use]
    pub fn pointer(&self, ptr: &str) -> Option<&'u [u8]> {
        self.spans
            .iter()
            .find(|(p, _)| *p == ptr)
            .and_then(|(_, s)| self.body.get(s.start..s.end))
    }

    /// Every pointer the scanner resolved.
    pub fn pointers(&self) -> impl Iterator<Item = (&'u str, Span)> + '_ {
        self.spans.iter().copied()
    }
}

/// One replacement a gate hook asks the kernel to apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IrEdit<'u> {
    /// The pointer whose span is replaced.
    pub pointer: &'u str,
    /// The bytes that replace it.
    pub replacement: ArenaBytes<'u>,
}

/// A bounded set of edits a gate hook asks the kernel to apply to the spooled body.
///
/// The hook row of the plugin-kinds table is explicit that the kernel applies the patch, that it
/// applies it to the spooled body and never to bytes already on the wire, and that the price delta
/// it may cause is bounded by the hook's declaration.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IrPatch<'u> {
    /// The edits, in declaration order.
    pub edits: BoundedVec<IrEdit<'u>, MAX_KEYS>,
}
