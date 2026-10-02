// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Anthropic citations: the location-type union read into and written from the neutral IrCitation.

use super::*;
use crate::codec::keys;

/// Map one RAW Anthropic citation object → neutral [`crate::codec::ir::IrCitation`]. Fills the neutral
/// fields it recognizes AND stashes the source object verbatim in `raw`, so the Anthropic writer can
/// re-emit it byte-exact (the no-regression guarantee) while a cross-protocol writer still has the
/// neutral coordinates. The Anthropic citation `type` union uses differently-named start/end fields
/// per variant (char/page/block index, or web-search `encrypted_index`); we read each into the shared
/// neutral `start_index`/`end_index`/`encrypted_index` slots, keyed off the `type` tag.
pub(super) fn read_citation(val: &serde_json::Value) -> crate::codec::ir::IrCitation {
    let kind = val
        .get(keys::TYPE)
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let cited_text = val
        .get(super::CITED_TEXT)
        .and_then(|v| v.as_str())
        .map(str::to_string);
    // `document_title` (document-location variants) OR `title` (web_search_result_location).
    let title = val
        .get(super::DOCUMENT_TITLE)
        .or_else(|| val.get(keys::TITLE))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    // `url` (web_search_result_location) OR `source` (search_result_location — the caller-supplied
    // `search_result.source` URI the passage came from). Reading only `url` lost the provenance of
    // every search-result citation on a foreign egress (ANT-18).
    let url = val
        .get(keys::URL)
        .or_else(|| val.get(keys::SOURCE))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    // `document_index` (document-location variants) OR `search_result_index`.
    let document_index = val
        .get(super::DOCUMENT_INDEX)
        .or_else(|| val.get(super::SEARCH_RESULT_INDEX))
        .and_then(|v| v.as_i64());
    // Per-variant start/end field names collapse into the shared neutral slots.
    let start_index = val
        .get(super::START_CHAR_INDEX)
        .or_else(|| val.get(super::START_PAGE_NUMBER))
        .or_else(|| val.get(super::START_BLOCK_INDEX))
        .and_then(|v| v.as_i64());
    let end_index = val
        .get(super::END_CHAR_INDEX)
        .or_else(|| val.get(super::END_PAGE_NUMBER))
        .or_else(|| val.get(super::END_BLOCK_INDEX))
        .and_then(|v| v.as_i64());
    let encrypted_index = val
        .get(super::ENCRYPTED_INDEX)
        .and_then(|v| v.as_str())
        .map(str::to_string);
    crate::codec::ir::IrCitation {
        domain: None,
        kind,
        cited_text,
        title,
        url,
        document_index,
        start_index,
        end_index,
        encrypted_index,
        // VERBATIM source object → byte-exact same-protocol re-emission.
        raw: Some(val.clone()),
    }..Default::default()
}

/// True when `raw` is an ANTHROPIC-shaped citation object — its `type` tag is one of the four
/// Anthropic citation variants. Gates the byte-exact `raw` passthrough so a foreign-protocol `raw`
/// (Gemini `citationSources[]`, which has no Anthropic `type`) is rebuilt from neutral fields rather
/// than emitted verbatim.
pub(super) fn is_anthropic_citation_shape(raw: &serde_json::Value) -> bool {
    matches!(
        raw.get(keys::TYPE).and_then(|v| v.as_str()),
        Some(
            CITATION_TYPE_CHAR
                | CITATION_TYPE_PAGE
                | CITATION_TYPE_CONTENT_BLOCK
                | CITATION_TYPE_WEB_SEARCH
                | CITATION_TYPE_SEARCH_RESULT
        )
    )
}

/// Map a neutral [`crate::codec::ir::IrCitation`] → an Anthropic citation object.
///
/// NO-REGRESSION GUARANTEE: when `raw` is present (an Anthropic-sourced citation, OR any source that
/// preserved its original object), it is emitted VERBATIM — so Anthropic→IR→Anthropic is byte-exact
/// regardless of how the neutral fields map. Only when `raw` is absent (a citation synthesized from
/// neutral fields on a cross-protocol hop, e.g. Gemini→Anthropic) do we BUILD an Anthropic object
/// from the neutral fields, keyed off `kind` to choose the variant + its field names.
pub(super) fn write_citation(c: &crate::codec::ir::IrCitation) -> serde_json::Value {
    // Re-emit `raw` VERBATIM only when it is an ANTHROPIC citation object (same-protocol path) — keyed
    // off an Anthropic `type` tag. A `raw` from a FOREIGN protocol (e.g. a Gemini `citationSources[]`
    // entry on a Gemini→Anthropic hop, which has `uri`/`startIndex` and no Anthropic `type`) must NOT
    // be emitted as-is; fall through to BUILD the Anthropic shape from the neutral fields instead.
    if let Some(raw) = &c.raw {
        if is_anthropic_citation_shape(raw) {
            return raw.clone();
        }
    }
    let mut obj = serde_json::Map::new();
    let kind = c.kind.as_deref().unwrap_or(CITATION_TYPE_WEB_SEARCH);
    obj.insert(keys::TYPE.to_string(), serde_json::json!(kind));
    if let Some(t) = &c.cited_text {
        obj.insert(super::CITED_TEXT.to_string(), serde_json::json!(t));
    }
    match kind {
        CITATION_TYPE_PAGE => {
            if let Some(di) = c.document_index {
                obj.insert(super::DOCUMENT_INDEX.to_string(), serde_json::json!(di));
            }
            if let Some(t) = &c.title {
                obj.insert(super::DOCUMENT_TITLE.to_string(), serde_json::json!(t));
            }
            if let Some(s) = c.start_index {
                obj.insert(super::START_PAGE_NUMBER.to_string(), serde_json::json!(s));
            }
            if let Some(e) = c.end_index {
                obj.insert(super::END_PAGE_NUMBER.to_string(), serde_json::json!(e));
            }
        }
        CITATION_TYPE_CONTENT_BLOCK => {
            if let Some(di) = c.document_index {
                obj.insert(super::DOCUMENT_INDEX.to_string(), serde_json::json!(di));
            }
            if let Some(t) = &c.title {
                obj.insert(super::DOCUMENT_TITLE.to_string(), serde_json::json!(t));
            }
            if let Some(s) = c.start_index {
                obj.insert(super::START_BLOCK_INDEX.to_string(), serde_json::json!(s));
            }
            if let Some(e) = c.end_index {
                obj.insert(super::END_BLOCK_INDEX.to_string(), serde_json::json!(e));
            }
        }
        // A search-result citation names its passage by `source` + `search_result_index` and its
        // span by content-BLOCK indices; building it with char-location names (the old fall-through)
        // produced an object no Anthropic SDK reads as a search-result citation (ANT-18).
        CITATION_TYPE_SEARCH_RESULT => {
            if let Some(u) = &c.url {
                obj.insert(keys::SOURCE.to_string(), serde_json::json!(u));
            }
            if let Some(t) = &c.title {
                obj.insert(keys::TITLE.to_string(), serde_json::json!(t));
            }
            if let Some(di) = c.document_index {
                obj.insert(
                    super::SEARCH_RESULT_INDEX.to_string(),
                    serde_json::json!(di),
                );
            }
            if let Some(s) = c.start_index {
                obj.insert(super::START_BLOCK_INDEX.to_string(), serde_json::json!(s));
            }
            if let Some(e) = c.end_index {
                obj.insert(super::END_BLOCK_INDEX.to_string(), serde_json::json!(e));
            }
        }
        CITATION_TYPE_WEB_SEARCH => {
            if let Some(u) = &c.url {
                obj.insert(keys::URL.to_string(), serde_json::json!(u));
            }
            if let Some(t) = &c.title {
                obj.insert(keys::TITLE.to_string(), serde_json::json!(t));
            }
            if let Some(ei) = &c.encrypted_index {
                obj.insert(super::ENCRYPTED_INDEX.to_string(), serde_json::json!(ei));
            }
        }
        // "char_location" and any unknown/None kind default to the char-location field names.
        _ => {
            if let Some(di) = c.document_index {
                obj.insert(super::DOCUMENT_INDEX.to_string(), serde_json::json!(di));
            }
            if let Some(t) = &c.title {
                obj.insert(super::DOCUMENT_TITLE.to_string(), serde_json::json!(t));
            }
            if let Some(s) = c.start_index {
                obj.insert(super::START_CHAR_INDEX.to_string(), serde_json::json!(s));
            }
            if let Some(e) = c.end_index {
                obj.insert(super::END_CHAR_INDEX.to_string(), serde_json::json!(e));
            }
        }
    }
    serde_json::Value::Object(obj)
}
