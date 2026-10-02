// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Reading Anthropic content blocks, messages and tool definitions into the IR.

use super::*;
use crate::codec::dialect::ir_parse_error;
use crate::codec::keys;

// Helper functions for IR mapping (used by read_request/write_request)
pub(super) fn read_block(
    block_val: &serde_json::Value,
) -> Result<crate::codec::ir::IrBlock, IrError> {
    let obj = block_val.as_object().ok_or_else(ir_parse_error)?;

    let block_type = obj.get(keys::TYPE).and_then(|v| v.as_str()).unwrap_or("");

    match block_type {
        keys::TEXT => {
            let text = obj
                .get(keys::TEXT)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            // Parse cache_control - object form: {"type": "ephemeral"}
            let cache_control = read_cache_control(obj.get(super::CACHE_CONTROL))?;
            let citations = obj
                .get(keys::CITATIONS)
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().map(read_citation).collect())
                .unwrap_or_default();
            Ok(crate::codec::ir::IrBlock::Text {
                text,
                cache_control,
                citations,
                refusal: false,
            })
        }
        keys::THINKING => {
            let text = obj
                .get(keys::THINKING)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let signature = obj
                .get(keys::SIGNATURE)
                .and_then(|v| v.as_str().map(String::from));
            let cache_control = read_cache_control(obj.get(super::CACHE_CONTROL))?;
            // IR-18: a signature read off the Anthropic wire is Anthropic's, so a foreign writer
            // never sends it as its own reasoning blob — unless it is busbar's provenance envelope
            // (another family's signature handed to this client earlier), which restores the
            // original bytes and their origin.
            let (signature, signature_origin) = crate::codec::ir::sig_envelope::read_carried_opt(
                signature,
                Some(crate::codec::ir::IrSignatureOrigin::Anthropic),
            );
            Ok(crate::codec::ir::IrBlock::Thinking {
                text,
                signature,
                redacted: false,
                cache_control,
                kind: None,
                signature_origin,
            })
        }
        STOP_TOOL_USE => {
            // A present `tool_use` block MUST carry a non-empty string `id`: it is the correlation
            // key a later `tool_result` (and any egress dialect) pairs against. An absent/blank/
            // wrong-typed id yields an empty IR id that silently breaks that pairing — reject the
            // malformed block rather than inventing an id.
            let id = obj
                .get(keys::ID)
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .ok_or_else(ir_parse_error)?
                .to_string();
            let name = obj
                .get(keys::NAME)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let input = obj
                .get(keys::INPUT)
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let cache_control = read_cache_control(obj.get(super::CACHE_CONTROL))?;
            Ok(crate::codec::ir::IrBlock::ToolUse {
                id,
                name,
                input,
                cache_control,
                // Anthropic has no wire concept of a Gemini thoughtSignature.
                thought_signature: None,
            })
        }
        super::TOOL_RESULT => {
            let tool_use_id = obj
                .get(super::TOOL_USE_ID)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let content_val = obj.get(keys::CONTENT).unwrap_or(&serde_json::Value::Null);
            let content = if let Some(arr) = content_val.as_array() {
                read_blocks(arr)?
            } else {
                vec![crate::codec::ir::IrBlock::Text {
                    text: content_val.as_str().unwrap_or("").to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                    refusal: false,
                }]
            };
            let is_error = obj
                .get(super::IS_ERROR)
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let cache_control = read_cache_control(obj.get(super::CACHE_CONTROL))?;
            Ok(crate::codec::ir::IrBlock::ToolResult {
                tool_use_id,
                content,
                is_error,
                cache_control,
            })
        }
        keys::IMAGE => {
            let source = obj.get(keys::SOURCE).ok_or_else(ir_parse_error)?;
            // `cache_control` sits on the OUTER image block object (a sibling of `source`), not on
            // the source — read it once and attach to whichever source shape we produce.
            let cache_control = read_cache_control(obj.get(super::CACHE_CONTROL))?;
            if let Some(src_obj) = source.as_object() {
                // Anthropic's Messages API has TWO native image source shapes:
                //   - `{"type":"url","url":<url>}`           — a remote image reference
                //   - `{"type":"base64","media_type":...,"data":<b64>}` — inline bytes
                // The base64 path below extracts `media_type`/`data`, which are BOTH absent from a
                // url source — so a url image would otherwise flatten to empty base64 (cross-protocol
                // image data LOSS). Round-trip the url through the same `media_type:"image_url"`
                // sentinel the writer recognizes (see `write_block`'s Image arm): the raw url lives in
                // `data`, and `write_block` re-emits exactly `{"type":"url","url":<url>}` for it.
                // A Files-API `{"type":"file","file_id":…}` source (or any future source type that is
                // neither url nor base64) is an Anthropic-hosted handle with no neutral form. It used
                // to fall through to the base64 read below and become an EMPTY base64 image, which
                // foreign writers emitted as `data:;base64,` / an empty `inlineData` (ANT-03). Carry it
                // on the opaque `Vendor` escape instead: this protocol re-emits it verbatim, and every
                // other writer drops a foreign vendor handle with a warn.
                let src_type = src_obj.get(keys::TYPE).and_then(|v| v.as_str());
                if src_type.is_some_and(|t| t != keys::URL && t != keys::BASE64) {
                    return Ok(crate::codec::ir::IrBlock::Image {
                        source: crate::codec::ir::IrImageSource::Vendor {
                            vendor: VENDOR_NAME,
                            value: source.clone(),
                        },
                        cache_control,
                        detail: None,
                    });
                }
                if src_type == Some(keys::URL) {
                    let url = src_obj
                        .get(keys::URL)
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    return Ok(crate::codec::ir::IrBlock::Image {
                        source: crate::codec::ir::IrImageSource::Url(url),
                        cache_control,
                        detail: None,
                    });
                }
                let media_type = src_obj
                    .get(super::MEDIA_TYPE)
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let data = src_obj
                    .get(keys::DATA)
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                Ok(crate::codec::ir::IrBlock::Image {
                    source: crate::codec::ir::IrImageSource::Base64 { media_type, data },
                    cache_control,
                    detail: None,
                })
            } else {
                Err(ir_parse_error())
            }
        }
        // A native `document` block — the PDF/CSV/text attachment the model reads. Until
        // `IrBlock::Media` existed this fell into `read_block`'s degrade-to-empty-Text arm and the
        // ORIGINAL block was parked under `ANTHROPIC_UNMODELED_BLOCKS_SENTINEL` — which only ever
        // came back on an Anthropic→Anthropic hop, because the seam clears `extra`. So on all five
        // cross-protocol egresses the caller's document was destroyed and replaced with an empty text
        // block, even though Gemini and Bedrock both have a native slot for it. Now it is modelled,
        // which ALSO takes it out of the sentinel (see `is_modeled_anthropic_block_type`).
        //
        // Anthropic's `document.source` has four shapes; the two with a neutral form map onto the
        // neutral IR sources, and the two that are Anthropic-hosted/Anthropic-shaped
        // (`{"type":"file","file_id":…}`, `{"type":"content","content":[…]}`) ride the opaque
        // `Vendor` escape so this protocol re-emits them verbatim and no other protocol can emit a
        // handle its backend cannot resolve.
        BLOCK_TYPE_DOCUMENT => {
            // A `document` with NO `source` carries no payload at all. It must NOT be a 400: a
            // reader that hard-errors on a degenerate-but-parseable block turns forward-compatible
            // conversation history into a rejected request. Degrade to the empty-Text placeholder
            // (holding the block's POSITION in the turn) with a warn naming it, which is what every
            // other unmodeled Anthropic block does.
            // [`read_blocks`] never hands this arm a document with no `source` (it carries no
            // payload, so it is not read at all); a direct call with one is malformed.
            let Some(source) = obj.get(keys::SOURCE) else {
                return Err(ir_parse_error());
            };
            let cache_control = read_cache_control(obj.get(super::CACHE_CONTROL))?;
            // `document.context` (a free-text hint) and `document.citations` (an `{enabled}` toggle)
            // ride the IR-12 `Media.context` / `Media.citations` slots, so they cross to Bedrock
            // (the other dialect with the same two members). Same-protocol they are still kept
            // byte-exact: `stash_unmodeled_blocks` parks the raw document verbatim when either is
            // present, and `write_message` splices it back on an Anthropic→Anthropic hop.
            let doc_citations = obj
                .get(keys::CITATIONS)
                .and_then(|c| c.get(keys::ENABLED))
                .and_then(|v| v.as_bool());
            let doc_context = obj
                .get(keys::CONTEXT)
                .and_then(|v| v.as_str())
                .map(String::from);
            let name = obj
                .get(keys::TITLE)
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(String::from);
            let src_type = source
                .get(keys::TYPE)
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let ir_source = match src_type {
                keys::URL => crate::codec::ir::IrImageSource::Url(
                    source
                        .get(keys::URL)
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                ),
                // A `text` source carries the document as RAW text (`data` is the text itself, not
                // base64). The neutral `Base64` source is BASE64 by contract — every foreign writer
                // emits `data` as base64 (`data:text/plain;base64,…`, Bedrock `bytes`) — so storing
                // the raw text there corrupted the document on every cross-protocol hop (ANT-01).
                // Encode it on the way in; the Anthropic writer decodes it back into a `text` source.
                keys::TEXT => crate::codec::ir::IrImageSource::Base64 {
                    media_type: source
                        .get(super::MEDIA_TYPE)
                        .and_then(|v| v.as_str())
                        .unwrap_or(DOCUMENT_MIME_TEXT_PLAIN)
                        .to_string(),
                    data: busbar_contract::media::base64_encode(
                        source
                            .get(keys::DATA)
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .as_bytes(),
                    ),
                },
                // `base64` carries inline bytes (a PDF) plus a real mime type.
                keys::BASE64 => crate::codec::ir::IrImageSource::Base64 {
                    media_type: source
                        .get(super::MEDIA_TYPE)
                        .and_then(|v| v.as_str())
                        .unwrap_or(keys::APPLICATION_PDF)
                        .to_string(),
                    data: source
                        .get(keys::DATA)
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                },
                _ => crate::codec::ir::IrImageSource::Vendor {
                    vendor: VENDOR_NAME,
                    value: source.clone(),
                },
            };
            Ok(crate::codec::ir::IrBlock::Media {
                // A `document` is a document whatever its mime says — Anthropic has no audio/video
                // content block, so there is no other kind this can be.
                kind: crate::codec::ir::IrMediaKind::Document,
                source: ir_source,
                name,
                cache_control,
                citations: doc_citations,
                context: doc_context,
            })
        }
        // A native `search_result` block — the RAG grounding payload a caller supplies so the model
        // can answer from (and cite) retrieved documents. Shape:
        // `{"type":"search_result","source":"<uri>","title":"…","content":[{"type":"text","text":"…"}],
        //   "citations":{"enabled":true}}`.
        //
        // It used to fall into the `other =>` degrade-to-empty-Text arm below, so on every
        // cross-protocol egress the retrieved passages the caller paid to fetch were replaced with an
        // empty block and the model answered from its own memory instead — the classic "grounding
        // silently gone" failure, differing from a plain drop only in that the turn kept its slot.
        //
        // The payload is ENTIRELY TEXT (`content[]` is a text-block array by Anthropic's own schema),
        // so unlike a `document` there is no attachment to place: every protocol in the matrix can
        // express it as text. Project it that way, and carry the provenance as an `IrCitation` on the
        // block so a target that models citations (OpenAI annotations, Gemini `citationSources`,
        // Cohere `citations`) still shows the caller's source rather than an unattributed paragraph.
        //
        // Deliberately NOT added to `is_modeled_anthropic_block_type`: the raw block stays parked in
        // the unmodeled sentinel, so an Anthropic→Anthropic hop still splices the ORIGINAL bytes back
        // (`citations.enabled`, the block's `content[]` structure and any field Anthropic adds later
        // survive byte-exact). This arm is what the CROSS-protocol egresses read, which is the only
        // path where the sentinel is cleared.
        BLOCK_TYPE_SEARCH_RESULT => {
            let source = obj.get(keys::SOURCE).and_then(|v| v.as_str()).unwrap_or("");
            let title = obj.get(keys::TITLE).and_then(|v| v.as_str()).unwrap_or("");
            // Concatenate the text parts in wire order. A non-text part is not possible per the
            // documented schema; if one ever appears it contributes nothing rather than a sentinel.
            let body: String = obj
                .get(keys::CONTENT)
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter(|b| b.get(keys::TYPE).and_then(|t| t.as_str()) == Some(keys::TEXT))
                        .filter_map(|b| b.get(keys::TEXT).and_then(|t| t.as_str()))
                        .collect::<Vec<_>>()
                        .join("\n")
                })
                .unwrap_or_default();
            // A HEADER naming the result, so the model reading a foreign protocol's plain text can
            // still tell one retrieved passage from the next and attribute its answer. Built only
            // from the fields that are present — an empty header would prepend a bare newline.
            let mut header = String::new();
            if !title.is_empty() {
                header.push_str(title);
            }
            if !source.is_empty() {
                if !header.is_empty() {
                    header.push_str(" — ");
                }
                header.push_str(source);
            }
            let text = if header.is_empty() {
                body
            } else if body.is_empty() {
                header
            } else {
                format!("{header}\n{body}")
            };
            let citations = if source.is_empty() && title.is_empty() {
                Vec::new()
            } else {
                vec![crate::codec::ir::IrCitation {
                    domain: None,
                    kind: Some(keys::SEARCH_RESULT_LOCATION.to_string()),
                    cited_text: None,
                    title: (!title.is_empty()).then(|| title.to_string()),
                    url: (!source.is_empty()).then(|| source.to_string()),
                    document_index: None,
                    start_index: None,
                    end_index: None,
                    encrypted_index: None,
                    // No `raw`: the byte-exact same-protocol path is the sentinel splice above, not
                    // this citation, and parking an Anthropic SEARCH-RESULT object under a citation's
                    // `raw` would have the Anthropic writer re-emit it as a CITATION on a
                    // foreign→Anthropic hop — a different wire shape than the one it came from.
                    raw: None,
                    ..Default::default()
                }]
            };
            let cache_control = read_cache_control(obj.get(super::CACHE_CONTROL))?;
            Ok(crate::codec::ir::IrBlock::Text {
                text,
                cache_control,
                citations,
                refusal: false,
            })
        }
        // A native `redacted_thinking` block carries opaque `data` bytes (Anthropic's encrypted
        // reasoning). Map it onto the same typed IR carrier Bedrock's `redactedContent` uses: a
        // `Thinking { redacted: true }` with the opaque bytes in `text` and no signature. The
        // Anthropic WRITER matches `Thinking { redacted: true, .. }` and re-emits a native
        // `redacted_thinking` block, so a `read_response` -> `write_response` (Anthropic->Anthropic)
        // round-trip preserves the block. Forgery is structurally impossible: a client-supplied
        // `thinking` block on the REQUEST path can only set `text`/`signature` (it reads as
        // `redacted: false`), never the typed `redacted: true` flag — so no anti-forgery scrub is
        // needed (the old String-sentinel approach that required one is gone).
        BLOCK_TYPE_REDACTED_THINKING => {
            let data = block_val
                .get(keys::DATA)
                .and_then(|d| d.as_str())
                .unwrap_or("")
                .to_string();
            let cache_control = read_cache_control(block_val.get(super::CACHE_CONTROL))?;
            Ok(crate::codec::ir::IrBlock::Thinking {
                text: data,
                signature: None,
                redacted: true,
                cache_control,
                kind: None,
                signature_origin: None,
            })
        }
        // A provider-run web search's results (DF-MAP, ARCHITECT ruling 2026-10-02 item 2): the
        // IR's hosted-tool record. A `web_search_tool_result_error` content carries its error code
        // as the record's status and no results.
        WEB_SEARCH_TOOL_RESULT => Ok(read_web_search_tool_result(obj)),
        // A block kind the IR does not model never reaches here: [`read_blocks`] leaves it out of
        // the IR (nothing is put in its place, design F3 "Drops"). A direct call with one is
        // malformed.
        _ => Err(ir_parse_error()),
    }
}

/// Whether [`read_block`] reads `block_val` into the IR: a block of a kind the reader models
/// ([`BLOCK_KINDS`]) that carries a payload. A block of another kind (a type Anthropic added after
/// this build, a server-tool result) and a `document` with no `source` are not read: nothing
/// stands in for them in the IR. A same-dialect write splices the raw block back at its position
/// ([`ANTHROPIC_UNMODELED_BLOCKS_SENTINEL`]); a translate attempt drops it, named. A non-object is
/// read (and refused by [`read_block`] in the dialect's own error envelope).
pub(super) fn is_read_into_ir(block_val: &serde_json::Value) -> bool {
    let Some(obj) = block_val.as_object() else {
        return true;
    };
    let kind = obj.get(keys::TYPE).and_then(|v| v.as_str()).unwrap_or("");
    BLOCK_KINDS.contains(&kind) && !(kind == BLOCK_TYPE_DOCUMENT && obj.get(keys::SOURCE).is_none())
}

/// Read a content-block array into the IR: every block [`is_read_into_ir`] keeps, in order. A
/// `document` with no `source` is dropped through the one drop path (its kind is modelled, so the
/// block grammar does not name it); an unmodelled kind is named by the grammar walk at the seam.
pub(super) fn read_blocks(
    arr: &[serde_json::Value],
) -> Result<Vec<crate::codec::ir::IrBlock>, IrError> {
    let mut out = Vec::with_capacity(arr.len());
    for block_val in arr {
        if is_read_into_ir(block_val) {
            out.push(read_block(block_val)?);
        } else if block_val.get(keys::TYPE).and_then(|v| v.as_str()) == Some(BLOCK_TYPE_DOCUMENT) {
            crate::codec::drops::note(crate::codec::drops::Dropped::new(
                "messages[].content[].type=document",
                &crate::codec::diagnostics::IR_DROP_UNMODELED_KEYS,
                "dropping an Anthropic `document` block with no `source` on the cross-protocol \
                 seam: it carries no payload to translate (nothing is put in its place)",
            ));
        }
    }
    Ok(out)
}

pub(super) fn read_message(
    msg_val: &serde_json::Value,
) -> Result<crate::codec::ir::IrMessage, IrError> {
    let obj = msg_val.as_object().ok_or_else(ir_parse_error)?;

    let role_str = obj.get(keys::ROLE).and_then(|v| v.as_str()).unwrap_or("");
    let role = match role_str {
        keys::USER => crate::codec::ir::IrRole::User,
        keys::ASSISTANT => crate::codec::ir::IrRole::Assistant,
        keys::SYSTEM => crate::codec::ir::IrRole::System,
        _ => return Err(ir_parse_error()),
    };

    let content_val = obj.get(keys::CONTENT).unwrap_or(&serde_json::Value::Null);
    // EDGE-VALIDATE the per-message `content` TYPE. Anthropic `content` is legally a string or an
    // array of content blocks (absent/`null` is tolerated as an empty turn). A present number/bool/
    // object is a genuine TYPE violation the lenient `as_str().unwrap_or("")` fallback below would
    // silently swallow into an empty Text block — reject it with a 400 instead.
    if !content_val.is_null() && !content_val.is_string() && !content_val.is_array() {
        return Err(ir_parse_error());
    }
    let content = if let Some(arr) = content_val.as_array() {
        read_blocks(arr)?
    } else {
        vec![crate::codec::ir::IrBlock::Text {
            text: content_val.as_str().unwrap_or("").to_string(),
            cache_control: None,
            citations: Vec::new(),
            refusal: false,
        }]
    };

    Ok(crate::codec::ir::IrMessage { role, content })
}

pub(super) fn read_tool(tool_val: &serde_json::Value) -> Result<crate::codec::ir::IrTool, IrError> {
    let obj = tool_val.as_object().ok_or_else(ir_parse_error)?;

    let name = obj
        .get(keys::NAME)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let description = obj
        .get(keys::DESCRIPTION)
        .and_then(|v| v.as_str().map(String::from));
    let input_schema = obj
        .get(keys::INPUT_SCHEMA)
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let cache_control = read_cache_control(obj.get(super::CACHE_CONTROL))?;
    // Anthropic's GA per-tool `strict: true` (schema-guaranteed tool arguments) is the same contract
    // as OpenAI's `function.strict`; read it so it carries (ANT-04). A non-boolean is not a flag.
    let strict = obj.get(keys::STRICT).and_then(|v| v.as_bool());
    // An Anthropic-defined tool (`{"type":"web_search_20250305","name":"web_search",…}`, `bash_*`,
    // `text_editor_*`, `code_execution_*`, `mcp_toolset`, …) is NOT a function tool: it has no
    // caller schema, and reading it as one produced a function `web_search` with a null schema that
    // reached foreign backends (ANT-13). Mark it HOSTED with its raw definition — the cross-protocol
    // seam drops hosted tools, and this protocol's writer re-emits the raw definition verbatim.
    let hosted = obj
        .get(keys::TYPE)
        .and_then(|v| v.as_str())
        .filter(|t| *t != TOOL_TYPE_CUSTOM)
        .map(|_| tool_val.clone());

    Ok(crate::codec::ir::IrTool {
        name,
        description,
        input_schema,
        cache_control,
        hosted,
        strict,
    })
}

/// The block type of a provider-run web search's results.
pub(super) const WEB_SEARCH_TOOL_RESULT: &str = "web_search_tool_result";

/// Anthropic `web_search_tool_result` -> [`crate::codec::ir::IrBlock::HostedToolRecord`].
fn read_web_search_tool_result(
    obj: &serde_json::Map<String, serde_json::Value>,
) -> crate::codec::ir::IrBlock {
    let content = obj.get(keys::CONTENT);
    let results = content
        .and_then(|c| c.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|r| {
                    Some(crate::codec::ir::IrSearchResult {
                        url: r.get(keys::URL)?.as_str()?.to_string(),
                        title: r
                            .get(keys::TITLE)
                            .and_then(|t| t.as_str())
                            .map(String::from),
                        snippet: None,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let status = content
        .and_then(|c| c.get(ERROR_CODE))
        .and_then(|e| e.as_str())
        .map(String::from);
    crate::codec::ir::IrBlock::HostedToolRecord {
        kind: crate::codec::ir::IrHostedToolKind::WebSearch,
        call_id: obj
            .get(TOOL_USE_ID)
            .and_then(|v| v.as_str())
            .map(String::from),
        status,
        results,
    }
}

/// The error member of a `web_search_tool_result_error` content.
const ERROR_CODE: &str = "error_code";
