//! Converse `Citation` projection: the neutral [`crate::ir::IrCitation`] to and from the Bedrock
//! `Citation` object and the buffered `citationsContent` block.

/// Project an [`crate::ir::IrCitation`] into the Bedrock Converse `Citation` object — the SAME field
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
pub(super) fn write_bedrock_citation(c: &crate::ir::IrCitation) -> Option<serde_json::Value> {
    let mut obj = serde_json::Map::new();

    let title = c.title.as_deref().filter(|s| !s.is_empty());
    let url = c.url.as_deref().filter(|s| !s.is_empty());
    if let Some(t) = title {
        obj.insert("title".to_string(), serde_json::json!(t));
    }

    if let Some(quoted) = c.cited_text.as_deref().filter(|s| !s.is_empty()) {
        obj.insert(
            "sourceContent".to_string(),
            serde_json::json!([{ "text": quoted }]),
        );
    }

    // `documentChar` is filled from the neutral char offsets: `start_index` / `end_index` are
    // character offsets for every source that carries them EXCEPT an Anthropic `page_location` /
    // `content_block_location`, whose `kind` says so — those are page/block numbers and would be a
    // LIE inside `documentChar`, so they are left unlocated rather than mislabelled (the title and
    // quoted text still cross).
    let char_offsets = !matches!(
        c.kind.as_deref(),
        Some("page_location") | Some("content_block_location") | Some("search_result_location")
    );
    let mut located = false;
    if char_offsets {
        if let (Some(start), Some(end)) = (c.start_index, c.end_index) {
            if start >= 0 && end >= start {
                obj.insert(
                    "location".to_string(),
                    serde_json::json!({
                        "documentChar": {
                            "documentIndex": c.document_index.unwrap_or(0).max(0),
                            "start": start,
                            "end": end,
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
    if !located && c.kind.as_deref() == Some("search_result_location") {
        if let (Some(idx), Some(start), Some(end)) = (c.document_index, c.start_index, c.end_index)
        {
            if idx >= 0 && start >= 0 && end >= start {
                obj.insert(
                    "location".to_string(),
                    serde_json::json!({
                        "searchResultLocation": {
                            "searchResultIndex": idx,
                            "start": start,
                            "end": end,
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
            tracing::warn!(
                url = %u,
                "dropping citation `url` on a bedrock egress: the Converse `CitationLocation` is a \
                 union and this citation's `documentChar` member already fills it"
            );
        } else {
            // BED-14 (round 3 item 14): `domain` beside the url when the IR carries it.
            let mut web = serde_json::Map::new();
            web.insert("url".to_string(), serde_json::json!(u));
            if let Some(d) = c.domain.as_deref().filter(|d| !d.is_empty()) {
                web.insert("domain".to_string(), serde_json::json!(d));
            }
            obj.insert(
                "location".to_string(),
                serde_json::json!({ "web": serde_json::Value::Object(web) }),
            );
        }
    }

    (!obj.is_empty()).then_some(serde_json::Value::Object(obj))
}

/// Read one Converse `Citation` (the buffered `citationsContent.citations[]` entry, and the streamed
/// `contentBlockDelta.delta.citation` member — the same field set) into the neutral
/// [`crate::ir::IrCitation`]: the inverse of [`write_bedrock_citation`] (BED-01).
///
/// `location` is a union: `documentChar` / `documentPage` / `documentChunk` carry
/// `{documentIndex, start, end}` and map onto the three Anthropic document-location kinds whose
/// offsets mean the same thing (char / page / block); `searchResultLocation` carries
/// `{searchResultIndex, start, end}` (block positions in a search result); `web` carries
/// `{url, domain}`. `sourceContent[].text` is the quoted source span. `raw` stays `None`: every
/// member Converse defines lands in a neutral field, and a Bedrock-shaped `raw` would only invite a
/// foreign writer's verbatim-passthrough check to misfire on it.
pub(super) fn read_bedrock_citation(c: &serde_json::Value) -> crate::ir::IrCitation {
    let loc = c.get("location");
    let member = |k: &str| loc.and_then(|l| l.get(k)).filter(|v| v.is_object());
    let int =
        |v: Option<&serde_json::Value>, k: &str| v.and_then(|o| o.get(k)).and_then(|n| n.as_i64());
    let (kind, document_index, start_index, end_index, url) =
        if let Some(m) = member("documentChar") {
            (
                Some("char_location"),
                int(Some(m), "documentIndex"),
                int(Some(m), "start"),
                int(Some(m), "end"),
                None,
            )
        } else if let Some(m) = member("documentPage") {
            (
                Some("page_location"),
                int(Some(m), "documentIndex"),
                int(Some(m), "start"),
                int(Some(m), "end"),
                None,
            )
        } else if let Some(m) = member("documentChunk") {
            (
                Some("content_block_location"),
                int(Some(m), "documentIndex"),
                int(Some(m), "start"),
                int(Some(m), "end"),
                None,
            )
        } else if let Some(m) = member("searchResultLocation") {
            (
                Some("search_result_location"),
                int(Some(m), "searchResultIndex"),
                int(Some(m), "start"),
                int(Some(m), "end"),
                None,
            )
        } else if let Some(m) = member("web") {
            (
                Some("web_search_result_location"),
                None,
                None,
                None,
                m.get("url").and_then(|u| u.as_str()).map(String::from),
            )
        } else {
            (None, None, None, None, None)
        };
    let quoted: Vec<&str> = c
        .get("sourceContent")
        .and_then(|s| s.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|p| p.get("text").and_then(|t| t.as_str()))
                .collect()
        })
        .unwrap_or_default();
    // BED-14 (round 3 item 14): the `web` location's `domain` member rides IrCitation.domain.
    let domain = member("web")
        .and_then(|m| m.get("domain"))
        .and_then(|d| d.as_str())
        .map(String::from);
    crate::ir::IrCitation {
        domain,
        kind: kind.map(String::from),
        cited_text: (!quoted.is_empty()).then(|| quoted.concat()),
        title: c.get("title").and_then(|t| t.as_str()).map(String::from),
        url,
        document_index,
        start_index,
        end_index,
        encrypted_index: None,
        raw: None,
    }
}

/// Read a Converse `citationsContent` block (`{content: [{text}], citations: [Citation]}`) into ONE
/// IR `Text` block carrying the cited answer text and its citations — the inverse of the buffered
/// writer's `citationsContent` projection (BED-01). The answer text lives INSIDE this block, so a
/// reader with no arm for it deleted the answer itself, not only its sources.
pub(super) fn read_bedrock_citations_content(v: &serde_json::Value) -> crate::ir::IrBlock {
    let text: String = v
        .get("content")
        .and_then(|c| c.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|p| p.get("text").and_then(|t| t.as_str()))
                .collect::<Vec<_>>()
                .concat()
        })
        .unwrap_or_default();
    let citations = v
        .get("citations")
        .and_then(|c| c.as_array())
        .map(|a| a.iter().map(read_bedrock_citation).collect())
        .unwrap_or_default();
    crate::ir::IrBlock::Text {
        text,
        cache_control: None,
        citations,
        refusal: false,
    }
}
