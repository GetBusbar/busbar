//! Gemini citation offsets (UTF-8 bytes on the wire, characters in the IR) and the
//! `citationMetadata` / `groundingMetadata` read and write.

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
pub(super) struct GeminiCharIndex {
    /// Byte offset of every character START, ascending, with `text.len()` appended as the terminator
    /// so a clamp-to-end offset resolves without a special case.
    starts: Vec<usize>,
    len: usize,
}

impl GeminiCharIndex {
    /// The single ordered pass. `char_indices()` yields character starts in ascending byte order, so
    /// the vector is sorted by construction — no sort, and the binary searches below are valid.
    pub(super) fn build(text: &str) -> Self {
        let mut starts: Vec<usize> = text.char_indices().map(|(b, _)| b).collect();
        starts.push(text.len());
        Self {
            starts,
            len: text.len(),
        }
    }

    /// The character offset for a wire BYTE offset.
    pub(super) fn char_offset(&self, byte_idx: i64) -> i64 {
        let target = (byte_idx.max(0) as usize).min(self.len);
        // The count of character starts strictly BELOW `target`.
        let before = self.starts.partition_point(|&s| s < target);
        // `partition_point` returns the first index whose start is >= `target`, so an entry equal to
        // `target` there proves `target` is a character boundary (the appended `len` covers the
        // clamp-to-end case). When it is NOT a boundary, `before` has counted the character that
        // CONTAINS `target` — whose start is earlier — so drop it to land on the nearest earlier
        // boundary, which is what converting the offset on its own does.
        if self.starts.get(before) == Some(&target) {
            before as i64
        } else {
            before.saturating_sub(1) as i64
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
pub(super) fn gemini_char_offset_to_byte(text: &str, char_idx: i64) -> i64 {
    let clamped = char_idx.max(0) as usize;
    match text.char_indices().nth(clamped) {
        Some((byte_idx, _)) => byte_idx as i64,
        None => text.len() as i64,
    }
}

/// Map a Gemini candidate's `citationMetadata.citationSources[]` → neutral
/// [`crate::ir::IrCitation`]s. A Gemini citation source is a grounding/web-search reference carrying
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
) -> Vec<crate::ir::IrCitation> {
    let sources = candidate
        .get("citationMetadata")
        .and_then(|m| m.get("citationSources"))
        .and_then(|s| s.as_array());
    let Some(sources) = sources else {
        // No `citationMetadata`, but a GROUNDED answer carries its sources in the OTHER slot. Fall
        // through to it rather than returning empty (which is what stripped every Google-Search
        // grounded answer's sources on the way to a foreign client).
        return read_gemini_grounding_citations(candidate, anchor_text);
    };
    // One pass over the anchor text for the WHOLE candidate, rather than one per offset converted.
    let char_index = anchor_text.map(GeminiCharIndex::build);
    let mut out: Vec<crate::ir::IrCitation> = sources
        .iter()
        .map(|src| {
            let raw_start = src.get("startIndex").and_then(|v| v.as_i64());
            let raw_end = src.get("endIndex").and_then(|v| v.as_i64());
            let (start_index, end_index) = match char_index.as_ref() {
                Some(idx) => (
                    raw_start.map(|b| idx.char_offset(b)),
                    raw_end.map(|b| idx.char_offset(b)),
                ),
                // No anchor text to convert against: leave the raw wire value (bytes) rather
                // than silently mislabel it as characters.
                None => (raw_start, raw_end),
            };
            crate::ir::IrCitation {
                domain: None,
                kind: Some("web_search_result_location".to_string()),
                cited_text: None,
                title: src
                    .get("title")
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
                url: src.get("uri").and_then(|v| v.as_str()).map(str::to_string),
                document_index: None,
                start_index,
                end_index,
                encrypted_index: None,
                raw: Some(src.clone()),
            }
        })
        .collect();
    // A response can carry BOTH slots (a grounded answer that also cites its own attached corpus).
    // Append rather than choose, so neither set of sources is dropped for the other's presence.
    out.extend(read_gemini_grounding_citations(candidate, anchor_text));
    out
}

/// Map a Gemini candidate's `groundingMetadata` → neutral [`crate::ir::IrCitation`]s.
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
pub(super) fn read_gemini_grounding_citations(
    candidate: &serde_json::Value,
    anchor_text: Option<&str>,
) -> Vec<crate::ir::IrCitation> {
    let Some(gm) = candidate.get("groundingMetadata") else {
        return Vec::new();
    };
    let chunks = gm
        .get("groundingChunks")
        .and_then(|c| c.as_array())
        .map(Vec::as_slice)
        .unwrap_or_default();
    if chunks.is_empty() {
        return Vec::new();
    }

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
            .get("web")
            .or_else(|| chunk.get("retrievedContext"))
            .unwrap_or(chunk);
        (
            inner
                .get("uri")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(str::to_string),
            inner
                .get("title")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(str::to_string),
        )
    };
    // `segment.startIndex`/`endIndex` are BYTE offsets into the candidate's full text, the same
    // convention `citationSources[]` uses — convert with the same helper, and with no anchor text
    // leave the wire value rather than mislabel bytes as characters.
    // One pass over the anchor text for the whole grounding block, not one per offset converted.
    let char_index = anchor_text.map(GeminiCharIndex::build);
    let convert = |b: Option<i64>| match char_index.as_ref() {
        Some(idx) => b.map(|b| idx.char_offset(b)),
        None => b,
    };

    let supports = gm
        .get("groundingSupports")
        .and_then(|s| s.as_array())
        .map(Vec::as_slice)
        .unwrap_or_default();

    let mut out = Vec::new();
    for support in supports {
        let segment = support.get("segment");
        let start = convert(
            segment
                .and_then(|s| s.get("startIndex"))
                .and_then(|v| v.as_i64()),
        );
        let end = convert(
            segment
                .and_then(|s| s.get("endIndex"))
                .and_then(|v| v.as_i64()),
        );
        let cited_text = segment
            .and_then(|s| s.get("text"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        for idx in support
            .get("groundingChunkIndices")
            .and_then(|v| v.as_array())
            .map(Vec::as_slice)
            .unwrap_or_default()
        {
            let Some(chunk) = idx.as_u64().and_then(|i| chunks.get(i as usize)) else {
                continue;
            };
            let (url, title) = chunk_source(chunk);
            if url.is_none() && title.is_none() {
                continue;
            }
            out.push(crate::ir::IrCitation {
                domain: None,
                kind: Some("web_search_result_location".to_string()),
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
            });
        }
    }
    if out.is_empty() {
        // Sources with no support spans: still the answer's provenance.
        for chunk in chunks {
            let (url, title) = chunk_source(chunk);
            if url.is_none() && title.is_none() {
                continue;
            }
            out.push(crate::ir::IrCitation {
                domain: None,
                kind: Some("web_search_result_location".to_string()),
                cited_text: None,
                title,
                url,
                document_index: None,
                start_index: None,
                end_index: None,
                encrypted_index: None,
                raw: Some(chunk.clone()),
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
/// [`crate::ir::IrCitation`] (see its doc comment: "char index (`char_location`)" is scoped to
/// whichever content block the citation is attached to, not the whole message). A citation whose
/// start lands past every block's end (an out-of-range upstream value) falls back to the LAST text
/// block, mirroring [`gemini_byte_offset_to_char`]'s own clamp-to-end fallback.
pub(super) fn attach_gemini_citations_to_text_blocks(
    candidate: &serde_json::Value,
    content: &mut [crate::ir::IrBlock],
) {
    // Every Text block's content-array index + its own text, in candidate order.
    let text_positions: Vec<(usize, String)> = content
        .iter()
        .enumerate()
        .filter_map(|(i, b)| match b {
            crate::ir::IrBlock::Text { text, .. } => Some((i, text.clone())),
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
        if let Some(crate::ir::IrBlock::Text {
            citations: block_citations,
            ..
        }) = content.get_mut(content_idx)
        {
            block_citations.push(relative);
        }
    }
}

/// Map a neutral [`crate::ir::IrCitation`] → a Gemini `citationSources[]` entry.
///
/// SAME-PROTOCOL FIDELITY: when `raw` is present AND it is a Gemini citation source (has a `uri` or
/// the Gemini index fields), re-emit it verbatim so a Gemini→IR→Gemini path is byte-exact — `raw`
/// already carries the ORIGINAL byte offsets, so no conversion runs on that path. A `raw` from a
/// FOREIGN protocol (e.g. an Anthropic citation object on an Anthropic→Gemini hop, or no `raw` at
/// all) would not be a valid Gemini source, so we ignore it and BUILD a Gemini source from the
/// neutral fields — which are CHARACTERS (the IR contract) and must be converted back to the BYTES
/// Gemini's wire format expects (the inverse of `gemini_byte_offset_to_char`),
/// against `text` (this block's own text, the same anchor the reader converted against).
///
/// `byte_prefix` is the BYTE length of every text part that precedes this block's text in the
/// candidate's full output (0 for the first/only text block). The IR's `start_index`/`end_index` on
/// `c` are relative to THIS block's own text (the per-block-relative contract
/// `attach_gemini_citations_to_text_blocks` establishes on read), but Gemini's wire
/// `startIndex`/`endIndex` are candidate-relative byte offsets into the FULL concatenated text — so
/// the block-local converted byte offset must be shifted by `byte_prefix` to become candidate-wide
/// again. Callers with no multi-part accumulation (single text block, or the streaming call site
/// with no anchor at all) pass `0`.
pub(super) fn write_gemini_citation(
    c: &crate::ir::IrCitation,
    text: &str,
    byte_prefix: i64,
) -> serde_json::Value {
    if let Some(raw) = &c.raw {
        if raw.get("uri").is_some()
            || raw.get("startIndex").is_some()
            || raw.get("endIndex").is_some()
        {
            return raw.clone();
        }
    }
    // `text.is_empty()` marks "no anchor text available" (the streaming egress call site — see its
    // caller comment): converting against an empty string would collapse every offset to 0, which
    // is worse than the pre-fix behavior. Pass the value through UNCONVERTED there rather than
    // corrupt it; the non-stream call site always supplies the real anchor text.
    let convert = |v: i64| {
        if text.is_empty() {
            v
        } else {
            gemini_char_offset_to_byte(text, v) + byte_prefix
        }
    };
    let mut obj = serde_json::Map::new();
    if let Some(s) = c.start_index {
        obj.insert("startIndex".to_string(), serde_json::json!(convert(s)));
    }
    if let Some(e) = c.end_index {
        obj.insert("endIndex".to_string(), serde_json::json!(convert(e)));
    }
    if let Some(u) = &c.url {
        obj.insert("uri".to_string(), serde_json::json!(u));
    }
    if let Some(t) = &c.title {
        obj.insert("title".to_string(), serde_json::json!(t));
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
        .and_then(|r| r.get("web").or_else(|| r.get("retrievedContext")))
        .and_then(|w| w.get("domain"))
        .and_then(|d| d.as_str())
    {
        obj.insert("domain".to_string(), serde_json::json!(d));
    }
    serde_json::Value::Object(obj)
}
