//! Converse `Citation` projection: the neutral [`crate::codec::ir::IrCitation`] to and from the Bedrock
//! `Citation` object and the buffered `citationsContent` block.

/// Project an [`crate::codec::ir::IrCitation`] into the Bedrock Converse `Citation` object — the SAME field
/// set the streaming `ContentBlockDelta`'s `citation` member (`CitationsDelta`) carries, which is why
/// one helper serves both paths.
///
/// The shape is `{ title, source, sourceContent: [{ text }], location }`, where `location` is a
/// UNION: `documentChar` / `documentPage` / `documentChunk` (`{ documentIndex, start, end }`),
/// `searchResultLocation` (`{ searchResultIndex, start, end }`) and `web` (`{ url, domain }`). A
/// neutral citation with character offsets takes `documentChar`; a search-result citation takes
/// `searchResultLocation`; a url-bearing citation with no other location takes `web` (BED-14).
///
/// Returns `None` when the citation projects to nothing at all (no title, no url, no quoted text, no
/// resolvable location) — emitting `{}` would put a member-less union on the wire that a Bedrock SDK
/// rejects, which is the one thing translation must never do. The caller warns on `None`.
use crate::codec::keys;
pub(super) fn write_bedrock_citation(
    c: &crate::codec::ir::IrCitation,
) -> Option<serde_json::Value> {
    let mut obj = serde_json::Map::new();

    let title = c.title.as_deref().filter(|s| !s.is_empty());
    let url = c.url.as_deref().filter(|s| !s.is_empty());
    if let Some(t) = title {
        obj.insert(keys::TITLE.to_string(), serde_json::json!(t));
    }

    if let Some(quoted) = c.cited_text.as_deref().filter(|s| !s.is_empty()) {
        obj.insert(
            super::SOURCE_CONTENT.to_string(),
            serde_json::json!([{ (keys::TEXT): quoted }]),
        );
    }

    // `documentChar` is filled from the neutral char offsets: `start_index` / `end_index` are
    // character offsets for every source that carries them EXCEPT an Anthropic `page_location` /
    // `content_block_location`, whose `kind` says so — those are page/block numbers and would be a
    // LIE inside `documentChar`, so they are left unlocated rather than mislabelled (the title and
    // quoted text still cross).
    let char_offsets = !matches!(
        c.kind.as_deref(),
        Some(keys::PAGE_LOCATION)
            | Some(keys::CONTENT_BLOCK_LOCATION)
            | Some(keys::SEARCH_RESULT_LOCATION)
    );
    let mut located = false;
    if char_offsets {
        if let (Some(start), Some(end)) = (c.start_index, c.end_index) {
            if start >= 0 && end >= start {
                obj.insert(
                    super::LOCATION.to_string(),
                    serde_json::json!({
                        (super::DOCUMENT_CHAR): {
                            (super::DOCUMENT_INDEX): c.document_index.unwrap_or(0).max(0),
                            (keys::START): start,
                            (keys::END): end,
                        }
                    }),
                );
                located = true;
            }
        }
    }

    // An Anthropic `search_result_location` names the same coordinates Converse's
    // `searchResultLocation` member carries (the search result's index and the block span in it).
    // Written only when the result index is actually known — defaulting it to 0 would point at the
    // wrong search result.
    if !located && c.kind.as_deref() == Some(keys::SEARCH_RESULT_LOCATION) {
        if let (Some(idx), Some(start), Some(end)) = (c.document_index, c.start_index, c.end_index)
        {
            if idx >= 0 && start >= 0 && end >= start {
                obj.insert(
                    super::LOCATION.to_string(),
                    serde_json::json!({
                        (super::SEARCH_RESULT_LOCATION_CAMEL): {
                            (super::SEARCH_RESULT_INDEX): idx,
                            (keys::START): start,
                            (keys::END): end,
                        }
                    }),
                );
                located = true;
            }
        }
    }

    // BED-14: a web citation's source url has a native slot — the `web` member of the
    // `CitationLocation` union (`{url, domain}`). `location` is a UNION (one member), so a citation
    // already located by character offsets keeps that member and its url cannot ride along; that
    // case alone drops the url, with a warn.
    if let Some(u) = url {
        if located {
            crate::codec::drops::writer_drop!(
                crate::codec::drops::TEXT,
                &crate::codec::diagnostics::IR_DROP_UNMODELED_KEYS,
                [url = %u, ],
                "dropping citation `url` on a bedrock egress: the Converse `CitationLocation` is a \
                 union and this citation's `documentChar` member already fills it");
        } else {
            // BED-14: `domain` beside the url when the IR carries it.
            let mut web = serde_json::Map::new();
            web.insert(keys::URL.to_string(), serde_json::json!(u));
            if let Some(d) = c.domain.as_deref().filter(|d| !d.is_empty()) {
                web.insert(keys::DOMAIN.to_string(), serde_json::json!(d));
            }
            obj.insert(
                super::LOCATION.to_string(),
                serde_json::json!({ (keys::WEB): serde_json::Value::Object(web) }),
            );
        }
    }

    (!obj.is_empty()).then_some(serde_json::Value::Object(obj))
}

/// Read one Converse `Citation` (the buffered `citationsContent.citations[]` entry, and the streamed
/// `contentBlockDelta.delta.citation` member — the same field set) into the neutral
/// [`crate::codec::ir::IrCitation`]: the inverse of [`write_bedrock_citation`] (BED-01).
///
/// `location` is a union: `documentChar` / `documentPage` / `documentChunk` carry
/// `{documentIndex, start, end}` and map onto the three Anthropic document-location kinds whose
/// offsets mean the same thing (char / page / block); `searchResultLocation` carries
/// `{searchResultIndex, start, end}` (block positions in a search result); `web` carries
/// `{url, domain}`. `sourceContent[].text` is the quoted source span. `raw` stays `None`: every
/// member Converse defines lands in a neutral field, and a Bedrock-shaped `raw` would only invite a
/// foreign writer's verbatim-passthrough check to misfire on it.
pub(super) fn read_bedrock_citation(c: &serde_json::Value) -> crate::codec::ir::IrCitation {
    let loc = c.get(super::LOCATION);
    let member = |k: &str| loc.and_then(|l| l.get(k)).filter(|v| v.is_object());
    let int =
        |v: Option<&serde_json::Value>, k: &str| v.and_then(|o| o.get(k)).and_then(|n| n.as_i64());
    // The offset locations, in precedence order: (wire member, IR kind, its index member), each
    // `{<index>, start, end}`.
    const OFFSET_LOCATIONS: [(&str, &str, &str); 4] = [
        (super::DOCUMENT_CHAR, "char_location", super::DOCUMENT_INDEX),
        ("documentPage", keys::PAGE_LOCATION, super::DOCUMENT_INDEX),
        (
            "documentChunk",
            keys::CONTENT_BLOCK_LOCATION,
            super::DOCUMENT_INDEX,
        ),
        (
            super::SEARCH_RESULT_LOCATION_CAMEL,
            keys::SEARCH_RESULT_LOCATION,
            super::SEARCH_RESULT_INDEX,
        ),
    ];
    let offsets = OFFSET_LOCATIONS.iter().find_map(|(wire, kind, index)| {
        member(wire).map(|m| {
            (
                Some(*kind),
                int(Some(m), index),
                int(Some(m), keys::START),
                int(Some(m), keys::END),
                None,
            )
        })
    });
    let (kind, document_index, start_index, end_index, url) =
        offsets.unwrap_or_else(|| match member(keys::WEB) {
            Some(m) => (
                Some("web_search_result_location"),
                None,
                None,
                None,
                m.get(keys::URL).and_then(|u| u.as_str()).map(String::from),
            ),
            None => (None, None, None, None, None),
        });
    let quoted: Vec<&str> = c
        .get(super::SOURCE_CONTENT)
        .and_then(|s| s.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|p| p.get(keys::TEXT).and_then(|t| t.as_str()))
                .collect()
        })
        .unwrap_or_default();
    // BED-14: the `web` location's `domain` member rides IrCitation.domain.
    let domain = member(keys::WEB)
        .and_then(|m| m.get(keys::DOMAIN))
        .and_then(|d| d.as_str())
        .map(String::from);
    crate::codec::ir::IrCitation {
        domain,
        kind: kind.map(String::from),
        cited_text: (!quoted.is_empty()).then(|| quoted.concat()),
        title: c
            .get(keys::TITLE)
            .and_then(|t| t.as_str())
            .map(String::from),
        url,
        document_index,
        start_index,
        end_index,
        encrypted_index: None,
        raw: None,
        ..Default::default()
    }
}

/// Read a Converse `citationsContent` block (`{content: [{text}], citations: [Citation]}`) into ONE
/// IR `Text` block carrying the cited answer text and its citations — the inverse of the buffered
/// writer's `citationsContent` projection (BED-01). The answer text lives INSIDE this block, so a
/// reader with no arm for it deleted the answer itself, not only its sources.
pub(super) fn read_bedrock_citations_content(v: &serde_json::Value) -> crate::codec::ir::IrBlock {
    let text: String = v
        .get(keys::CONTENT)
        .and_then(|c| c.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|p| p.get(keys::TEXT).and_then(|t| t.as_str()))
                .collect::<Vec<_>>()
                .concat()
        })
        .unwrap_or_default();
    let citations = v
        .get(keys::CITATIONS)
        .and_then(|c| c.as_array())
        .map(|a| a.iter().map(read_bedrock_citation).collect())
        .unwrap_or_default();
    crate::codec::ir::IrBlock::Text {
        text,
        cache_control: None,
        citations,
        refusal: false,
    }
}
