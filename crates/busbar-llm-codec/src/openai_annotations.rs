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
    // Carried offsets are a span of the RESPONSE TEXT only for a citation whose kind says so: a
    // url/web-search citation (OpenAI `url_citation`, Gemini `citationSources[]`, both read as
    // `web_search_result_location`) or an untyped one. Anthropic's document kinds carry offsets
    // too, but into the CITED DOCUMENT (`char_location` chars, `page_location` pages,
    // `content_block_location` / `search_result_location` block indices) — emitting those as a
    // span of the answer text would point at the wrong characters.
    let text_span_kind = matches!(c.kind.as_deref(), None | Some("web_search_result_location"));
    let carried = if text_span_kind {
        (c.start_index, c.end_index)
    } else {
        (None, None)
    };
    match carried {
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
/// OFFSETS ARE CARRIED (SHR-01, IR mapping Q57). `IrCitation::start_index`/`end_index` are
/// CHARACTER offsets into the response text by contract, and OpenAI documents its own the same
/// way: both the Chat `annotations[].url_citation` and the Responses `UrlCitationBody` define
/// `start_index` as "the index of the first character of the URL citation in the message" — a
/// character index, the IR's own unit — so both offsets copy across unconverted. Before this
/// they were dropped, and because the Responses writer requires a span, every citation an OpenAI
/// Chat backend returned vanished for a Responses client (and Responses -> Chat lost its offsets).
/// A negative or inverted pair is not a span and is left `None` rather than repaired.
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
        let (start_index, end_index) = match (
            citation.get("start_index").and_then(|v| v.as_i64()),
            citation.get("end_index").and_then(|v| v.as_i64()),
        ) {
            (Some(s), Some(e)) if s >= 0 && e >= s => (Some(s), Some(e)),
            _ => (None, None),
        };
        out.push(crate::ir::IrCitation {
            kind: Some("web_search_result_location".to_string()),
            cited_text: None,
            title,
            url: Some(url.to_string()),
            document_index: None,
            start_index,
            end_index,
            encrypted_index: None,
            raw: None,
        });
    }
    out
}

/// The OpenAI Files API id an IR attachment references, if it references one (SHR-03).
///
/// OpenAI Chat (`file.file_id`) and Responses (`input_file.file_id`, `input_image.file_id`) name
/// ONE namespace — the organisation's OpenAI Files uploads — but each reader tags the opaque
/// [`crate::ir::IrImageSource::Vendor`] reference with its own dialect name (`"openai"`,
/// `"responses"`), and each writer re-emitted only its own tag. So a Chat caller's uploaded PDF
/// never reached a Responses lane (and back), although the id is valid on both. Both readers store
/// the same `{"file_id": <id>}` value; this accepts either tag, so a writer calls this instead of
/// comparing against its own tag and the id crosses between the two OpenAI dialects. Any other
/// vendor (a Bedrock `s3Location`, an Anthropic Files id) is `None`: those namespaces do not
/// resolve at OpenAI.
pub fn openai_file_id(source: &crate::ir::IrImageSource) -> Option<&str> {
    match source {
        crate::ir::IrImageSource::Vendor { vendor, value }
            if OPENAI_FILES_VENDOR_TAGS.contains(vendor) =>
        {
            value
                .get("file_id")
                .and_then(|i| i.as_str())
                .filter(|id| !id.is_empty())
        }
        _ => None,
    }
}

/// The `Vendor` tags that name the OpenAI Files namespace: the Chat and the Responses readers'.
/// Kept in step with their `VENDOR_NAME` consts by `openai_file_vendor_tags_are_the_dialect_names`.
pub const OPENAI_FILES_VENDOR_TAGS: [&str; 2] = ["openai", "responses"];
