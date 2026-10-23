//! Gemini citation offsets (UTF-8 bytes on the wire, characters in the IR) and the
//! `citationMetadata` / `groundingMetadata` read and write.
use super::{
    FIELD_CITATION_METADATA, FIELD_CITATION_SOURCES, FIELD_END_INDEX, FIELD_RETRIEVED_CONTEXT,
    FIELD_START_INDEX, FIELD_URI,
};
use crate::codec::keys;

/// Byte→character offset index for ONE response text, built in a single ordered pass over the
/// text's `char_indices()` and then answering each citation offset by binary search.
///
/// Gemini's `CitationSource`/`groundingSupports` offsets are documented in BYTES; the IR's
/// `IrCitation::start_index`/`end_index` contract is CHARACTERS. Converting a single offset means
/// counting the characters in a prefix, which is linear in the text — and a grounded answer converts
/// two offsets per source, so doing it per offset walked the whole response text once per number
/// (O(sources × text_len)) for what one walk answers. The index is built once per read and each
/// lookup is O(log n).
///
/// Results are IDENTICAL to converting each offset independently, including both degradations that
/// contract already promised: a negative or past-the-end offset clamps to `[0, text.len()]`, and an
/// offset landing MID-codepoint (a malformed or adversarial upstream value, which has no valid
/// character count at that exact point) resolves to the nearest EARLIER boundary rather than
/// panicking on a non-boundary slice.
pub(super) struct GeminiCharIndex<'a> {
    text: &'a str,
    /// The byte offset of character `k * CHAR_MARK_STRIDE`, for every such character the text
    /// holds, ascending. A lookup binary-searches the marks and walks at most one stride of
    /// characters, so the index holds one `usize` per stride rather than one per character.
    marks: std::borrow::Cow<'a, [usize]>,
}

/// Characters between two marks of a [`GeminiCharIndex`].
pub(super) const CHAR_MARK_STRIDE: usize = 64;

/// Characters an index walked (building or answering), for the work-bound tests. Per thread, so
/// parallel tests cannot see each other's walks.
#[cfg(test)]
thread_local! {
    pub(super) static CHARS_WALKED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[inline]
fn walked(n: usize) {
    #[cfg(test)]
    CHARS_WALKED.with(|w| w.set(w.get().saturating_add(n)));
    let _ = n;
}

/// Extend the marks of an APPEND-ONLY text by `appended`, the bytes that now follow the `base` bytes
/// already indexed (`chars` characters). The stream reader and writer call this as each text delta
/// lands, so their anchor text is indexed once in total rather than once per citation chunk.
pub(super) fn extend_char_marks(
    marks: &mut Vec<usize>,
    chars: &mut usize,
    base: usize,
    appended: &str,
) {
    for (b, _) in appended.char_indices() {
        if *chars % CHAR_MARK_STRIDE == 0 {
            marks.push(base + b);
        }
        *chars += 1;
    }
    walked(appended.len());
}

impl<'a> GeminiCharIndex<'a> {
    /// The single ordered pass. `char_indices()` yields character starts in ascending byte order, so
    /// the marks are sorted by construction.
    pub(super) fn build(text: &'a str) -> Self {
        let mut marks = Vec::new();
        let mut chars = 0;
        extend_char_marks(&mut marks, &mut chars, 0, text);
        Self {
            text,
            marks: std::borrow::Cow::Owned(marks),
        }
    }

    /// The index over a stream's anchor text whose marks were kept as it grew
    /// ([`extend_char_marks`]): no walk of the text at all.
    pub(super) fn from_marks(text: &'a str, marks: &'a [usize]) -> Self {
        Self {
            text,
            marks: std::borrow::Cow::Borrowed(marks),
        }
    }

    /// The character offset for a wire BYTE offset.
    pub(super) fn char_offset(&self, byte_idx: i64) -> i64 {
        let target = (byte_idx.max(0) as usize).min(self.text.len());
        // The last mark at or before `target` (the first is byte 0 for any non-empty text).
        let k = self.marks.partition_point(|&s| s <= target);
        if k == 0 {
            return 0;
        }
        let base = self.marks[k - 1];
        let mut before = (k - 1) * CHAR_MARK_STRIDE;
        let mut boundary = target == self.text.len();
        // Count the character starts strictly below `target`; a start equal to it proves `target`
        // is a boundary. When it is NOT, the character containing it was counted, so drop it to
        // land on the nearest earlier boundary.
        let mut steps = 0usize;
        for (b, _) in self.text[base..].char_indices() {
            steps += 1;
            let start = base + b;
            if start >= target {
                boundary = boundary || start == target;
                break;
            }
            before += 1;
        }
        walked(steps);
        if boundary {
            before as i64
        } else {
            before.saturating_sub(1) as i64
        }
    }

    /// The BYTE offset of a CHARACTER offset (the inverse; `gemini_char_offset_to_byte`'s answer):
    /// a negative offset clamps to 0, one at or past the character count to `text.len()`.
    pub(super) fn byte_offset(&self, char_idx: i64) -> i64 {
        let c = char_idx.max(0) as usize;
        let Some(&base) = self.marks.get(c / CHAR_MARK_STRIDE) else {
            return self.text.len() as i64;
        };
        let within = c % CHAR_MARK_STRIDE;
        walked(within + 1);
        match self.text[base..].char_indices().nth(within) {
            Some((b, _)) => (base + b) as i64,
            None => self.text.len() as i64,
        }
    }
}

/// Convert a Gemini `startIndex`/`endIndex` BYTE offset (Google's `CitationSource` is documented
/// measured in bytes) into a CHARACTER offset — the IR's `IrCitation::start_index`/`end_index`
/// contract (`ir/mod.rs`). `byte_idx` is clamped to `text.len()` so an
/// out-of-range upstream value degrades to "end of text" rather than panicking on a non-boundary
/// slice.
///
/// The straightforward per-offset conversion, kept as the REFERENCE the [`GeminiCharIndex`]
/// equivalence test measures against. Production reads go through the index, which answers the same
/// question for a whole candidate in one pass over the text.
#[cfg(test)]
pub(super) fn gemini_byte_offset_to_char(text: &str, byte_idx: i64) -> i64 {
    let clamped = byte_idx.max(0) as usize;
    let boundary = clamped.min(text.len());
    // A byte index that lands mid-codepoint (a malformed/adversarial upstream value) has no valid
    // char count at that exact point; fall back to the nearest earlier boundary rather than panic.
    let safe_boundary = (0..=boundary)
        .rev()
        .find(|&b| text.is_char_boundary(b))
        .unwrap_or(0);
    text[..safe_boundary].chars().count() as i64
}

/// The inverse of [`gemini_byte_offset_to_char`]: a CHARACTER offset (the IR contract) back to the
/// BYTE offset Gemini's wire format expects. `char_idx` is clamped to the text's char count.
///
/// Kept as the REFERENCE [`GeminiCharIndex::byte_offset`] is measured against; production writes go
/// through the index, so a text with many citations is not walked once per offset.
#[cfg(test)]
pub(super) fn gemini_char_offset_to_byte(text: &str, char_idx: i64) -> i64 {
    let clamped = char_idx.max(0) as usize;
    match text.char_indices().nth(clamped) {
        Some((byte_idx, _)) => byte_idx as i64,
        None => text.len() as i64,
    }
}

/// Map a Gemini candidate's `citationMetadata.citationSources[]` → neutral
/// [`crate::codec::ir::IrCitation`]s. A Gemini citation source is a grounding/web-search reference carrying
/// `startIndex`/`endIndex` — measured in BYTES per Google's `CitationSource` reference, converted to
/// CHARACTERS here since the IR's contract is characters — plus `uri`, `title`,
/// and `license`. We project it onto the neutral fields (uri→url, indices→start/end, title→title)
/// and stash the source object verbatim in `raw` so a same-protocol Gemini path can re-emit the
/// UNCONVERTED original (see `write_gemini_citation`'s raw short-circuit). The neutral `kind` is
/// `web_search_result_location` — a grounding source IS a URL reference, which is also the Anthropic
/// variant a cross-protocol Anthropic egress synthesizes for it. Returns empty when the candidate has
/// no citation metadata.
///
/// `anchor_text` is the response text these offsets index into (needed for the byte->char
/// conversion): the candidate's full text on the buffered path, the answer text streamed so far
/// (`StreamDecodeState::streamed_text`) on the stream (GEM-16). `None` leaves the wire bytes.
pub(super) fn read_gemini_citations(
    candidate: &serde_json::Value,
    anchor_text: Option<&str>,
) -> Vec<crate::codec::ir::IrCitation> {
    read_citations_at(candidate, &Anchor::text(anchor_text))
}

/// The stream's read: `text` is the answer streamed so far and `marks` the index the reader kept
/// as it grew ([`extend_char_marks`]), so a citation chunk converts without walking the answer.
pub(super) fn read_gemini_streamed_citations(
    candidate: &serde_json::Value,
    text: &str,
    marks: &[usize],
) -> Vec<crate::codec::ir::IrCitation> {
    read_citations_at(
        candidate,
        &Anchor {
            text: Some(text),
            index: std::cell::OnceCell::from(GeminiCharIndex::from_marks(text, marks)),
        },
    )
}

/// The text a candidate's citation offsets convert against, indexed on first use (once for both
/// citation slots), or already indexed by the stream that grew it. No text leaves the wire bytes.
struct Anchor<'a> {
    text: Option<&'a str>,
    index: std::cell::OnceCell<GeminiCharIndex<'a>>,
}

impl<'a> Anchor<'a> {
    fn text(text: Option<&'a str>) -> Self {
        Self {
            text,
            index: std::cell::OnceCell::new(),
        }
    }

    fn index(&self) -> Option<&GeminiCharIndex<'a>> {
        let text = self.text?;
        Some(self.index.get_or_init(|| GeminiCharIndex::build(text)))
    }
}

fn read_citations_at(
    candidate: &serde_json::Value,
    anchor: &Anchor<'_>,
) -> Vec<crate::codec::ir::IrCitation> {
    let sources = candidate
        .get(FIELD_CITATION_METADATA)
        .and_then(|m| m.get(FIELD_CITATION_SOURCES))
        .and_then(|s| s.as_array());
    let Some(sources) = sources else {
        // No `citationMetadata`, but a GROUNDED answer carries its sources in the OTHER slot. Fall
        // through to it rather than returning empty (which is what stripped every Google-Search
        // grounded answer's sources on the way to a foreign client).
        return grounding_citations_at(candidate, anchor);
    };
    // One pass over the anchor text for the WHOLE candidate, rather than one per offset converted.
    let char_index = anchor.index();
    let mut out: Vec<crate::codec::ir::IrCitation> = sources
        .iter()
        .map(|src| {
            let raw_start = src.get(FIELD_START_INDEX).and_then(|v| v.as_i64());
            let raw_end = src.get(FIELD_END_INDEX).and_then(|v| v.as_i64());
            let (start_index, end_index) = match char_index {
                Some(idx) => (
                    raw_start.map(|b| idx.char_offset(b)),
                    raw_end.map(|b| idx.char_offset(b)),
                ),
                // No anchor text to convert against: leave the raw wire value (bytes) rather
                // than silently mislabel it as characters.
                None => (raw_start, raw_end),
            };
            crate::codec::ir::IrCitation {
                domain: None,
                kind: Some(keys::WEB_SEARCH_RESULT_LOCATION.to_string()),
                cited_text: None,
                title: src
                    .get(keys::TITLE)
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
                url: src
                    .get(FIELD_URI)
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
                document_index: None,
                start_index,
                end_index,
                encrypted_index: None,
                raw: Some(src.clone()),
                ..Default::default()
            }
        })
        .collect();
    // A response can carry BOTH slots (a grounded answer that also cites its own attached corpus).
    // Append rather than choose, so neither set of sources is dropped for the other's presence.
    out.extend(grounding_citations_at(candidate, anchor));
    out
}

/// A candidate's grounding member, and its list of grounding chunks.
pub(super) const FIELD_GROUNDING_METADATA: &str = "groundingMetadata";
const FIELD_GROUNDING_CHUNKS: &str = "groundingChunks";

/// Most bytes of grounding chunks and cited text one candidate may clone into citations.
const MAX_GROUNDING_CLONE_BYTES: usize = 8 * 1024 * 1024;

/// An [`std::io::Write`] that only counts what it is handed.
struct ByteCount(usize);

impl std::io::Write for ByteCount {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.saturating_add(buf.len());
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Map a Gemini candidate's `groundingMetadata` → neutral [`crate::codec::ir::IrCitation`]s.
///
/// THE GAP THIS CLOSES: `groundingMetadata` is where a Google-Search-grounded Gemini answer puts its
/// SOURCES (`citationMetadata` is the older, corpus-citation slot and is absent on a grounded
/// answer). Nothing read it, so a grounded answer reached a foreign client as an unattributed
/// paragraph — the same class of loss as a Cohere RAG answer arriving with its citations stripped,
/// and the reason a customer could not tell a grounded reply from a hallucinated one after a hop.
///
/// This is NOT an untranslatable-vendor-concept: every protocol in the matrix models a citation, so
/// the sources have somewhere to go on all five foreign egresses.
///
/// Shape: `groundingChunks[]` are the sources (`{web: {uri, title}}`, or `{retrievedContext: {…}}`
/// for a Vertex datastore), and `groundingSupports[]` say WHICH SPAN of the answer each source
/// backs (`{segment: {startIndex, endIndex, text}, groundingChunkIndices: [i, …]}`). One citation is
/// emitted per (support, chunk) pair so the span survives; when there are no supports at all (Google
/// omits them on some grounded replies) one citation per chunk is emitted with no span, because a
/// source with no offsets is still the answer's provenance and dropping it would be the very loss
/// this function exists to stop.
///
/// `raw` is deliberately `None`: a grounding chunk is NOT a `citationSources[]` entry, and parking
/// one there would have `write_gemini_citation`'s raw short-circuit re-emit a grounding object in
/// the citation slot on a foreign→Gemini hop. Same-protocol Gemini traffic is a verbatim byte
/// passthrough that never reaches a writer, so nothing needs the escape hatch here.
///
/// Production reads reach this through [`read_gemini_citations`], which indexes the anchor text
/// once for both citation slots; this entry reads the grounding slot alone, for the tests.
#[cfg(test)]
pub(super) fn read_gemini_grounding_citations(
    candidate: &serde_json::Value,
    anchor_text: Option<&str>,
) -> Vec<crate::codec::ir::IrCitation> {
    grounding_citations_at(candidate, &Anchor::text(anchor_text))
}

fn grounding_citations_at(
    candidate: &serde_json::Value,
    anchor: &Anchor<'_>,
) -> Vec<crate::codec::ir::IrCitation> {
    let Some(gm) = candidate.get(FIELD_GROUNDING_METADATA) else {
        return Vec::new();
    };
    let chunks = gm
        .get(FIELD_GROUNDING_CHUNKS)
        .and_then(|c| c.as_array())
        .map(Vec::as_slice)
        .unwrap_or_default();
    if chunks.is_empty() {
        return Vec::new();
    }

    // Serialized size of a chunk, counted without building the string, per (support, chunk) pair
    // the budget below admits (so the measuring is itself bounded by the budget).
    let chunk_bytes = |chunk: &serde_json::Value| -> usize {
        let mut n = ByteCount(0);
        let _ = serde_json::to_writer(&mut n, chunk);
        n.0
    };

    // `{web: {uri, title}}` and `{retrievedContext: {uri, title}}` are the two documented chunk
    // members and carry the same two fields; read whichever is present rather than name only `web`.
    // A `web` chunk (Vertex, not `retrievedContext`) can ALSO carry `domain` — the bare hostname of
    // the source alongside its full `uri`/`title`. Undeclared by the pinned generativelanguage
    // discovery document (Vertex-only surface). It has no neutral IR field of its own (adding one to
    // `IrCitation` is a required field touching every dialect's own citation-construction/test
    // sites); instead the ORIGINAL chunk object is stashed in `raw` at each push site below and
    // `write_gemini_citation` re-derives `domain` from it — carried per OWNER RULING Q1,
    // docs/design/1.6.0-QUESTIONS.md Q36, rather than dropped.
    let chunk_source = |chunk: &serde_json::Value| -> (Option<String>, Option<String>) {
        let inner = chunk
            .get(keys::WEB)
            .or_else(|| chunk.get(FIELD_RETRIEVED_CONTEXT))
            .unwrap_or(chunk);
        (
            inner
                .get(FIELD_URI)
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(str::to_string),
            inner
                .get(keys::TITLE)
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(str::to_string),
        )
    };
    // `segment.startIndex`/`endIndex` are BYTE offsets into the candidate's full text, the same
    // convention `citationSources[]` uses — convert with the same helper, and with no anchor text
    // leave the wire value rather than mislabel bytes as characters.
    // One pass over the anchor text for the whole grounding block, not one per offset converted.
    let char_index = anchor.index();
    let convert = |b: Option<i64>| match char_index {
        Some(idx) => b.map(|b| idx.char_offset(b)),
        None => b,
    };

    let supports = gm
        .get("groundingSupports")
        .and_then(|s| s.as_array())
        .map(Vec::as_slice)
        .unwrap_or_default();

    let mut out = Vec::new();
    let mut cloned_bytes = 0usize;
    'supports: for support in supports {
        let segment = support.get("segment");
        let start = convert(
            segment
                .and_then(|s| s.get(FIELD_START_INDEX))
                .and_then(|v| v.as_i64()),
        );
        let end = convert(
            segment
                .and_then(|s| s.get(FIELD_END_INDEX))
                .and_then(|v| v.as_i64()),
        );
        let cited_text = segment
            .and_then(|s| s.get(keys::TEXT))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let mut seen: std::collections::HashSet<u64> = std::collections::HashSet::new();
        for idx in support
            .get("groundingChunkIndices")
            .and_then(|v| v.as_array())
            .map(Vec::as_slice)
            .unwrap_or_default()
        {
            let Some(chunk) = idx.as_u64().and_then(|i| chunks.get(i as usize)) else {
                continue;
            };
            // A chunk named twice by one support yields the identical citation; naming it N times
            // must not clone it N times.
            let i = idx.as_u64().unwrap_or_default();
            if !seen.insert(i) {
                continue;
            }
            // The clones (the chunk kept in `raw`, the cited text) are bounded per candidate, so a
            // support listing many large chunks cannot multiply the body into memory.
            cloned_bytes = cloned_bytes
                .saturating_add(chunk_bytes(chunk))
                .saturating_add(cited_text.as_ref().map_or(0, String::len));
            if cloned_bytes > MAX_GROUNDING_CLONE_BYTES {
                break 'supports;
            }
            let (url, title) = chunk_source(chunk);
            if url.is_none() && title.is_none() {
                continue;
            }
            out.push(crate::codec::ir::IrCitation {
                domain: None,
                kind: Some(keys::WEB_SEARCH_RESULT_LOCATION.to_string()),
                cited_text: cited_text.clone(),
                title,
                url,
                document_index: None,
                start_index: start,
                end_index: end,
                encrypted_index: None,
                // Stash the ORIGINAL chunk (not just its `web`/`retrievedContext` inner object) so
                // `write_gemini_citation` can re-derive `domain` from it — see `chunk_source`'s doc
                // comment above for why there is no dedicated `IrCitation` field for it. This does
                // NOT engage `write_gemini_citation`'s byte-exact short-circuit: that only fires on
                // a `raw` carrying `uri`/`startIndex`/`endIndex` at its OWN top level, which a
                // `{web: {...}}` / `{retrievedContext: {...}}` chunk never does.
                raw: Some(chunk.clone()),
                ..Default::default()
            });
        }
    }
    if out.is_empty() {
        // Sources with no support spans: still the answer's provenance (each chunk cloned once,
        // under the same budget).
        for chunk in chunks {
            cloned_bytes = cloned_bytes.saturating_add(chunk_bytes(chunk));
            if cloned_bytes > MAX_GROUNDING_CLONE_BYTES {
                break;
            }
            let (url, title) = chunk_source(chunk);
            if url.is_none() && title.is_none() {
                continue;
            }
            out.push(crate::codec::ir::IrCitation {
                domain: None,
                kind: Some(keys::WEB_SEARCH_RESULT_LOCATION.to_string()),
                cited_text: None,
                title,
                url,
                document_index: None,
                start_index: None,
                end_index: None,
                encrypted_index: None,
                raw: Some(chunk.clone()),
                ..Default::default()
            });
        }
    }
    out
}

/// Attach a Gemini candidate's `citationMetadata.citationSources[]` onto the RIGHT Text block(s) of
/// `content`, with indices re-expressed RELATIVE TO THAT BLOCK'S OWN TEXT — the non-stream (buffered)
/// response path only (the stream reader converts against its streamed text instead).
///
/// Google's `citationSources[].startIndex`/`endIndex` are byte offsets into the candidate's FULL
/// output text — the concatenation of every text part in order, NOT any single part. A candidate
/// commonly emits its answer as one `text` part, so anchoring against "the" text block used to be
/// harmless; but a candidate CAN split its output across multiple text parts (each of which becomes
/// its own `IrBlock::Text` — see the `content.push` loop above), and Gemini's offsets still address
/// the FULL concatenation, not the part they happen to land in.
///
/// The PRE-FIX code anchored the byte->char conversion against only the FIRST Text block's own text
/// and always attached every citation to that first block. Once a response had more than one text
/// part, any citation whose span fell in a LATER part got silently CLAMPED to the first part's
/// length (a garbage, off-by-however-much index) and was attached to the wrong block entirely — a
/// citation regression invisible on the single-part case this function's predecessor was written
/// against.
///
/// Fix: convert against the FULL concatenated candidate text (matching Google's actual offset
/// contract), then locate the Text block whose span (by cumulative char length) contains the
/// citation's start, and re-express `start_index`/`end_index` RELATIVE TO THAT BLOCK — matching the
/// per-block-relative contract Anthropic's own `char_location` variant already uses for
/// [`crate::codec::ir::IrCitation`] (see its doc comment: "char index (`char_location`)" is scoped to
/// whichever content block the citation is attached to, not the whole message). A citation whose
/// start lands past every block's end (an out-of-range upstream value) falls back to the LAST text
/// block, mirroring [`gemini_byte_offset_to_char`]'s own clamp-to-end fallback.
pub(super) fn attach_gemini_citations_to_text_blocks(
    candidate: &serde_json::Value,
    content: &mut [crate::codec::ir::IrBlock],
) {
    // Every Text block's content-array index + its own text, in candidate order.
    let text_positions: Vec<(usize, String)> = content
        .iter()
        .enumerate()
        .filter_map(|(i, b)| match b {
            crate::codec::ir::IrBlock::Text { text, .. } => Some((i, text.clone())),
            _ => None,
        })
        .collect();
    if text_positions.is_empty() {
        return; // No text block to anchor against (e.g. a tool-only turn) — nothing to attach.
    }

    // The candidate's FULL output text — the actual anchor Google's byte offsets are measured
    // against — is every text part concatenated IN ORDER, with no separator (Gemini streams answer
    // text as a single logical run split across parts; there is no implicit whitespace between them).
    let full_text: String = text_positions.iter().map(|(_, t)| t.as_str()).collect();

    let citations = read_gemini_citations(candidate, Some(&full_text));
    if citations.is_empty() {
        return;
    }

    // Cumulative CHAR start offset of each Text block within `full_text`, so a candidate-relative
    // citation index can be mapped to (owning block, block-relative index).
    let mut block_char_ranges: Vec<(usize, i64, i64)> = Vec::with_capacity(text_positions.len());
    let mut cursor: i64 = 0;
    for (content_idx, text) in &text_positions {
        let len = text.chars().count() as i64;
        block_char_ranges.push((*content_idx, cursor, cursor + len));
        cursor += len;
    }

    for citation in citations {
        let start = citation.start_index.unwrap_or(0);
        let owner = block_char_ranges
            .iter()
            .find(|&&(_, s, e)| start >= s && start < e)
            // An out-of-range start (upstream garbage, or a start exactly at the end of the last
            // block) falls back to the last text block rather than being silently dropped.
            .or_else(|| block_char_ranges.last());
        let Some(&(content_idx, block_start, _)) = owner else {
            continue; // Unreachable (text_positions non-empty guarantees at least one range).
        };
        let mut relative = citation;
        relative.start_index = relative.start_index.map(|s| s - block_start);
        relative.end_index = relative.end_index.map(|e| e - block_start);
        if let Some(crate::codec::ir::IrBlock::Text {
            citations: block_citations,
            ..
        }) = content.get_mut(content_idx)
        {
            block_citations.push(relative);
        }
    }
}

/// Map a neutral [`crate::codec::ir::IrCitation`] → a Gemini `citationSources[]` entry.
///
/// SAME-PROTOCOL FIDELITY: when `raw` is present AND it is a Gemini citation source (has a `uri` or
/// the Gemini index fields), re-emit it verbatim so a Gemini→IR→Gemini path is byte-exact — `raw`
/// already carries the ORIGINAL byte offsets, so no conversion runs on that path. A `raw` from a
/// FOREIGN protocol (e.g. an Anthropic citation object on an Anthropic→Gemini hop, or no `raw` at
/// all) would not be a valid Gemini source, so we ignore it and BUILD a Gemini source from the
/// neutral fields — which are CHARACTERS (the IR contract) and must be converted back to the BYTES
/// Gemini's wire format expects (the inverse of `gemini_byte_offset_to_char`),
/// against this block's own text (the same anchor the reader converted against).
///
/// `convert` maps a block-relative CHARACTER offset to Gemini's candidate-wide BYTE offset. The IR's
/// `start_index`/`end_index` on `c` are relative to THIS block's own text (the per-block-relative
/// contract `attach_gemini_citations_to_text_blocks` establishes on read), but Gemini's wire
/// `startIndex`/`endIndex` are candidate-relative byte offsets into the FULL concatenated text, so
/// the caller's converter adds the byte length of every text part before the block. `None` (no
/// anchor text: an empty block, or a stream block that has carried no text) passes the value
/// through UNCONVERTED: converting against an empty string would collapse every offset to 0.
pub(super) fn write_gemini_citation(
    c: &crate::codec::ir::IrCitation,
    convert: Option<&dyn Fn(i64) -> i64>,
) -> serde_json::Value {
    if let Some(raw) = &c.raw {
        if raw.get(FIELD_URI).is_some()
            || raw.get(FIELD_START_INDEX).is_some()
            || raw.get(FIELD_END_INDEX).is_some()
        {
            return raw.clone();
        }
    }
    let convert = |v: i64| convert.map_or(v, |f| f(v));
    let mut obj = serde_json::Map::new();
    if let Some(s) = c.start_index {
        obj.insert(FIELD_START_INDEX.to_string(), serde_json::json!(convert(s)));
    }
    if let Some(e) = c.end_index {
        obj.insert(FIELD_END_INDEX.to_string(), serde_json::json!(convert(e)));
    }
    if let Some(u) = &c.url {
        obj.insert(FIELD_URI.to_string(), serde_json::json!(u));
    }
    if let Some(t) = &c.title {
        obj.insert(keys::TITLE.to_string(), serde_json::json!(t));
    }
    // `domain` has no home in Gemini's `citationSources[]` shape (only a `groundingChunks[].web`
    // object carries one, and this writer always re-emits INTO `citationMetadata.citationSources`
    // regardless of which slot the source came from — see this function's caller), and `IrCitation`
    // has no dedicated field for it (see `chunk_source`'s doc comment in
    // `read_gemini_grounding_citations`) — a grounding-origin citation instead stashes the ORIGINAL
    // `{web: {...}}` / `{retrievedContext: {...}}` chunk in `raw` (this function's short-circuit
    // above does not fire on it: that chunk carries no top-level `uri`/`startIndex`/`endIndex`).
    // Re-derive `domain` from it here and re-emit as an additional sibling key, so a
    // grounding-sourced domain still SURVIVES the hop rather than being silently dropped (OWNER
    // RULING Q1, docs/design/1.6.0-QUESTIONS.md Q36); only present when the source carried one, so
    // an ordinary (non-grounding) citation stays byte-identical.
    if let Some(d) = c
        .raw
        .as_ref()
        .and_then(|r| r.get(keys::WEB).or_else(|| r.get(FIELD_RETRIEVED_CONTEXT)))
        .and_then(|w| w.get(keys::DOMAIN))
        .and_then(|d| d.as_str())
    {
        obj.insert(keys::DOMAIN.to_string(), serde_json::json!(d));
    }
    serde_json::Value::Object(obj)
}

/// A grounded candidate's `groundingMetadata.groundingChunks[].web` -> the IR's hosted web-search
/// record (DF-MAP item 2): each web chunk's `uri` and `title` as a result. `None` when the candidate
/// carries no web chunk (a Vertex `retrievedContext` datastore chunk is not a web search).
pub(super) fn read_grounding_record(
    candidate: &serde_json::Value,
) -> Option<crate::codec::ir::IrBlock> {
    let results: Vec<crate::codec::ir::IrSearchResult> = candidate
        .get(FIELD_GROUNDING_METADATA)?
        .get(FIELD_GROUNDING_CHUNKS)?
        .as_array()?
        .iter()
        .filter_map(|chunk| {
            let web = chunk.get(keys::WEB)?;
            Some(crate::codec::ir::IrSearchResult {
                url: web.get(FIELD_URI)?.as_str()?.to_string(),
                title: web
                    .get(keys::TITLE)
                    .and_then(|t| t.as_str())
                    .map(String::from),
                snippet: None,
            })
        })
        .collect();
    (!results.is_empty()).then_some(crate::codec::ir::IrBlock::HostedToolRecord {
        kind: crate::codec::ir::IrHostedToolKind::WebSearch,
        call_id: None,
        status: None,
        results,
    })
}

/// The hosted web-search records of an answer as Gemini's `groundingMetadata.groundingChunks`
/// (`None` when the answer carries none).
pub(super) fn write_grounding_chunks(
    content: &[crate::codec::ir::IrBlock],
) -> Option<serde_json::Value> {
    let chunks: Vec<serde_json::Value> = content
        .iter()
        .filter_map(|b| match b {
            crate::codec::ir::IrBlock::HostedToolRecord { results, .. } => Some(results),
            _ => None,
        })
        .flatten()
        .map(|r| {
            let mut web = serde_json::Map::new();
            web.insert(FIELD_URI.to_string(), serde_json::json!(r.url));
            if let Some(title) = &r.title {
                web.insert(keys::TITLE.to_string(), serde_json::json!(title));
            }
            serde_json::json!({ (keys::WEB): web })
        })
        .collect();
    (!chunks.is_empty()).then(|| serde_json::json!({ (FIELD_GROUNDING_CHUNKS): chunks }))
}
