// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! OpenAI-family citation `annotations` — the `url_citation` ↔ IR-citation mapping shared by the
//! Chat and Responses codecs. This is LLM-dialect codec logic; it lives beside the openai
//! readers/writers that use it, and the neutral router never names it.
//!
//! The two wires DIFFER in shape and each has its own builder here: Responses flattens the citation
//! onto the entry (`UrlCitationBody`), Chat nests it under a `url_citation` object
//! (`ChatCompletionResponseMessage.annotations`). The citation rules — which sources qualify, how a
//! span is resolved — are shared, so only the shape differs.

/// Build a RESPONSES `annotations` array from the IR citations that annotate a span of assistant
/// text — the flat `UrlCitationBody` shape. See [`chat_url_annotations`] for the Chat wire.
///
/// `text` is the ONE block the citations annotate, and `base` is where that block starts inside the
/// message's full content string — Chat joins every text block into one string, while Responses
/// keeps one part per block and so always passes `0`. Both the carried offsets and the ones
/// recovered from a quote are block-relative, so `base` applies uniformly to either.
///
/// The wire shape is `url_citation`, which requires `url`, `title`, `start_index` and `end_index`.
/// The IR's sources do not all carry those: an Anthropic `web_search_result_location` has a url and
/// a title but NO character offsets, and a Gemini `citationSources[]` entry has offsets but no
/// title. So a faithful mapping has to choose what to do about the gaps, and the choice here is
/// deliberate: **never invent a fact.**
///
/// - `url` is required outright. A citation without one is a document reference, which is a
///   different wire shape (`file_citation`) keyed by a `file_id` the IR does not carry — so it is
///   omitted rather than mis-shaped.
/// - Offsets are taken from the citation when present, and otherwise RECOVERED by locating the
///   quoted `cited_text` in the assembled text. A quote that does not appear, or appears more than
///   once, is ambiguous — omitted rather than guessed.
/// - `title` falls back to the url. That is the same datum re-presented, not a fabricated one, and
///   it is what a client renders anyway when a source has no title.
///
/// The alternative — emitting `start_index: 0, end_index: 0` or a placeholder title — trades a
/// silent drop for silent fabrication, which is worse for a translation layer whose claim is
/// fidelity. What is dropped here is dropped because the source genuinely lacks it.
pub fn url_annotations(
    text: &str,
    base: usize,
    citations: &[crate::ir::IrCitation],
) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    for c in citations {
        let Some(url) = c.url.as_deref().filter(|u| !u.is_empty()) else {
            continue;
        };
        let Some((start, end)) = citation_span(text, base, c) else {
            continue;
        };
        out.push(serde_json::json!({
            "type": "url_citation",
            "url": url,
            "title": citation_title(c, url),
            "start_index": start,
            "end_index": end,
        }));
    }
    out
}

/// Build a CHAT `annotations` array. Same citation rules as [`url_annotations`], different wire
/// shape: `ChatCompletionResponseMessage.annotations` items nest the citation under a
/// `url_citation` object rather than flattening its fields onto the entry. The flat form belongs to
/// the Responses API's `UrlCitationBody`, so the two must not be interchanged — and [`read_url_annotations`]
/// only recognizes the nested one, which is what makes a Chat write→read hop lossless.
///
/// Used by BOTH chat arms. The streaming arm has no assembled text to resolve a span against, so it
/// passes an empty `text` and a `base` of 0; a citation whose span cannot be resolved is emitted
/// WITHOUT one rather than with a fabricated one, since the span is the one part of the shape that
/// can be honestly omitted.
pub fn chat_url_annotations(
    text: &str,
    base: usize,
    citations: &[crate::ir::IrCitation],
) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    for c in citations {
        let Some(url) = c.url.as_deref().filter(|u| !u.is_empty()) else {
            continue;
        };
        let mut uc = serde_json::Map::new();
        uc.insert("url".to_string(), serde_json::json!(url));
        uc.insert(
            "title".to_string(),
            serde_json::json!(citation_title(c, url)),
        );
        if let Some((start, end)) = citation_span(text, base, c) {
            uc.insert("start_index".to_string(), serde_json::json!(start));
            uc.insert("end_index".to_string(), serde_json::json!(end));
        }
        out.push(serde_json::json!({
            "type": "url_citation",
            "url_citation": serde_json::Value::Object(uc),
        }));
    }
    out
}

/// `title` falls back to the url — the same datum re-presented, not a fabricated one, and what a
/// client renders anyway when a source has no title.
fn citation_title<'a>(c: &'a crate::ir::IrCitation, url: &'a str) -> &'a str {
    c.title.as_deref().filter(|t| !t.is_empty()).unwrap_or(url)
}

/// Resolve a citation's character span within `text`, shifted by `base`. Shared by both shapes so
/// the offset rules cannot drift apart between them. `None` when the source genuinely carries no
/// usable span; each caller decides what that means for its shape.
fn citation_span(text: &str, base: usize, c: &crate::ir::IrCitation) -> Option<(i64, i64)> {
    match (c.start_index, c.end_index) {
        // `saturating_add` (not `+`): `s`/`e` are upstream-controlled `i64` (only sign-checked
        // above), so `i64::MAX + base` would panic in debug / wrap in release — an
        // upstream-triggered crash on the response path. Same cure `billable_tokens` already
        // establishes for upstream-controlled counts (`ir/mod.rs`).
        (Some(s), Some(e)) if s >= 0 && e >= s => {
            Some((s.saturating_add(base as i64), e.saturating_add(base as i64)))
        }
        // Recover the span from the quote when the source carried no offsets, but only when it
        // occurs exactly once — two matches make the anchor ambiguous.
        _ => c
            .cited_text
            .as_deref()
            .filter(|q| !q.is_empty())
            .and_then(|q| {
                // `str::find` and `q.len()` are BYTE offsets/lengths; the IR contract is
                // CHARACTERS, not bytes (see `IrCitation::start_index`). `find` always returns
                // a char boundary, so the byte slice below stays valid — only the emitted span
                // needs converting.
                let first = text.find(q)?;
                if text[first + q.len()..].contains(q) {
                    return None;
                }
                let start_ch = text[..first].chars().count();
                let len_ch = q.chars().count();
                Some(((base + start_ch) as i64, (base + start_ch + len_ch) as i64))
            }),
    }
}

/// Read an OpenAI-family `annotations` array (`url_citation` entries) into IR citations. Shared by
/// the Chat and Responses readers, mirroring `url_annotations` above in the write direction.
///
/// BOTH published shapes are accepted, because the two dialects genuinely differ and this one
/// function reads for both: Chat nests the fields under a `url_citation` object, while the Responses
/// API's `UrlCitationBody` flattens `url`/`title`/`start_index`/`end_index` onto the entry itself.
/// Recognizing only the nested one silently dropped EVERY Responses citation — including on a
/// Responses→Responses hop, where this reader consumes the very bytes `url_annotations` had just
/// written in the flat shape the spec requires. The nested object wins when present, so a Chat entry
/// is never re-read as a flat one.
///
/// KNOWN LIMITATION — offsets are deliberately NOT carried. `IrCitation::start_index`/`end_index`
/// are CHARACTER offsets by contract (`ir/mod.rs`), and OpenAI does not document whether its
/// `start_index`/`end_index` count bytes or characters. Copying them across unconverted would
/// silently assert one of the two, and on non-ASCII text that is a wrong span — the same class of
/// defect the Gemini byte/char conversion (`gemini/mod.rs`) exists to prevent. Dropping an offset
/// we cannot interpret is a gap; asserting a unit we cannot verify is a lie. Until the unit is
/// established (one upstream response with a multi-byte character ahead of the cited span settles
/// it), the url and title — which need no unit — are preserved and the span is left `None`, which
/// every writer already treats as optional.
pub fn read_url_annotations(annotations: &serde_json::Value) -> Vec<crate::ir::IrCitation> {
    let mut out = Vec::new();
    let Some(arr) = annotations.as_array() else {
        return out;
    };
    for entry in arr {
        if entry.get("type").and_then(|t| t.as_str()) != Some("url_citation") {
            continue;
        }
        // Chat nests under `url_citation`; Responses (`UrlCitationBody`) flattens onto the entry.
        // Chat nests under `url_citation`; Responses (`UrlCitationBody`) flattens onto the entry.
        let citation = entry.get("url_citation").unwrap_or(entry);
        // Never invent a fact: an entry with no usable url is skipped, symmetric with
        // `url_annotations`' own rule in the write direction (a citation with no url is not
        // emitted there either).
        let Some(url) = citation
            .get("url")
            .and_then(|u| u.as_str())
            .filter(|u| !u.is_empty())
        else {
            continue;
        };
        let title = citation
            .get("title")
            .and_then(|t| t.as_str())
            .filter(|t| !t.is_empty())
            .map(String::from);
        out.push(crate::ir::IrCitation {
            kind: Some("web_search_result_location".to_string()),
            cited_text: None,
            title,
            url: Some(url.to_string()),
            document_index: None,
            start_index: None,
            end_index: None,
            encrypted_index: None,
            raw: None,
        });
    }
    out
}
