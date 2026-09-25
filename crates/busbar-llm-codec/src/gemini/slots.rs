//! The Gemini spelling of the Q57 typed IR request slots (ir-slots-landed.md): hosted tools
//! (IR-11), `labels` (IR-03), `allowedFunctionNames` (IR-10), `responseModalities` (IR-19), and the
//! slots Gemini has no form for (IR-04..07), which the writer drops with a warn and reports.

use crate::ir::{IrHostedTool, IrModality, IrRequest, IrTool, IrWebFetch, IrWebSearch};

/// Gemini's hosted-tool keys that have a neutral IR kind (IR-11).
const GEMINI_GOOGLE_SEARCH: &str = "googleSearch";
const GEMINI_CODE_EXECUTION: &str = "codeExecution";
const GEMINI_URL_CONTEXT: &str = "urlContext";

/// The tool entries Gemini carries beside `functionDeclarations` in one `tools[]` entry (GEM-10).
///
/// A kind with a neutral IR form (`googleSearch` → WebSearch, `codeExecution` → CodeExecution,
/// `urlContext` → WebFetch) goes into the typed hosted-tool slot, which crosses the seam (IR-11);
/// any sub-config it carries (e.g. `googleSearch.timeRangeFilter`) has no neutral member and is
/// dropped with a warn — the tool itself is kept. Any OTHER key (`googleSearchRetrieval`,
/// `fileSearch`, …) has no neutral kind and stays a raw hosted [`IrTool`], which the seam drops by
/// name on a cross-protocol hop.
pub(super) fn read_gemini_hosted_tools(
    tool_val: &serde_json::Value,
) -> (Vec<IrHostedTool>, Vec<IrTool>) {
    let mut typed = Vec::new();
    let mut raw_tools = Vec::new();
    let Some(obj) = tool_val.as_object() else {
        return (typed, raw_tools);
    };
    for (k, v) in obj {
        let kind = match k.as_str() {
            "functionDeclarations" => continue,
            GEMINI_GOOGLE_SEARCH => Some(IrHostedTool::WebSearch(IrWebSearch::default())),
            GEMINI_CODE_EXECUTION => Some(IrHostedTool::CodeExecution),
            GEMINI_URL_CONTEXT => Some(IrHostedTool::WebFetch(IrWebFetch::default())),
            _ => None,
        };
        match kind {
            Some(hosted) => {
                if v.as_object().is_some_and(|m| !m.is_empty()) {
                    tracing::warn!(
                        hosted_tool = %k,
                        "gemini hosted tool config has no neutral IR member; the tool crosses the \
                         seam without it"
                    );
                }
                typed.push(hosted);
            }
            None => {
                tracing::warn!(
                    hosted_tool = %k,
                    "gemini hosted tool read as a raw hosted IR tool: no neutral hosted-tool kind \
                     exists for it, so a cross-protocol hop drops it"
                );
                let mut raw = serde_json::Map::new();
                raw.insert(k.clone(), v.clone());
                raw_tools.push(IrTool {
                    name: String::new(),
                    description: None,
                    input_schema: serde_json::Value::Null,
                    cache_control: None,
                    hosted: Some(serde_json::Value::Object(raw)),
                    strict: None,
                });
            }
        }
    }
    (typed, raw_tools)
}

/// One Gemini `tools[]` entry per IR hosted tool (IR-11). Gemini's three hosted tools take no
/// neutral parameter, so a parameter the source set (Anthropic `max_uses`/`allowed_domains`/
/// `blocked_domains`/`user_location`, Responses `search_context_size`) is dropped with a warn and the
/// tool is kept.
pub(super) fn write_gemini_hosted_tools(hosted: &[IrHostedTool]) -> Vec<serde_json::Value> {
    hosted
        .iter()
        .map(|tool| {
            let (key, params_set) = match tool {
                IrHostedTool::WebSearch(ws) => (
                    GEMINI_GOOGLE_SEARCH,
                    ws.max_uses.is_some()
                        || !ws.allowed_domains.is_empty()
                        || !ws.blocked_domains.is_empty()
                        || ws.user_location.is_some()
                        || ws.search_context_size.is_some(),
                ),
                IrHostedTool::CodeExecution => (GEMINI_CODE_EXECUTION, false),
                IrHostedTool::WebFetch(wf) => (
                    GEMINI_URL_CONTEXT,
                    wf.max_uses.is_some()
                        || !wf.allowed_domains.is_empty()
                        || !wf.blocked_domains.is_empty(),
                ),
            };
            if params_set {
                tracing::warn!(
                    hosted_tool = tool.kind_str(),
                    "dropping hosted-tool parameters on Gemini egress: {key} takes none of them; \
                     the tool is kept"
                );
            }
            serde_json::json!({ key: {} })
        })
        .collect()
}

/// Gemini `labels` → the IR caller-metadata map (IR-03), in the caller's key order. Read only when
/// it is an object of string values (the only shape Gemini accepts); anything else stays raw in
/// `extra` and maps to nothing.
pub(super) fn read_gemini_labels(
    labels: Option<&serde_json::Value>,
) -> Option<Vec<(String, String)>> {
    let obj = labels?.as_object()?;
    obj.iter()
        .map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
        .collect()
}

/// Google Cloud label limits: at most 64 labels; a key is 1-63 characters, a value 0-63.
const GEMINI_MAX_LABELS: usize = 64;
const GEMINI_LABEL_MAX_CHARS: usize = 63;

/// A label key/value character: lowercase letter, digit, `_` or `-`; international characters are
/// allowed but never an upper-case letter.
fn gemini_label_char_ok(c: char) -> bool {
    c.is_ascii_lowercase()
        || c.is_ascii_digit()
        || c == '_'
        || c == '-'
        || (!c.is_ascii() && c.is_alphanumeric() && !c.is_uppercase())
}

/// Whether one metadata entry is a valid Gemini label: the key starts with a lowercase letter (or
/// an international one), both stay inside the character set and the 63-character limit.
fn gemini_label_ok(key: &str, value: &str) -> bool {
    let key_len = key.chars().count();
    let starts_ok = key.chars().next().is_some_and(|c| {
        c.is_ascii_lowercase() || (!c.is_ascii() && c.is_alphabetic() && !c.is_uppercase())
    });
    starts_ok
        && key_len <= GEMINI_LABEL_MAX_CHARS
        && key.chars().all(gemini_label_char_ok)
        && value.chars().count() <= GEMINI_LABEL_MAX_CHARS
        && value.chars().all(gemini_label_char_ok)
}

/// The IR caller-metadata map → Gemini `labels` (IR-03). An entry that breaks Gemini's label syntax
/// (e.g. an upper-case key, a space in a value) would 400 the whole request, so THAT entry is
/// dropped with a warn and the rest are kept, up to Gemini's cap of 64. An empty object when every
/// entry was dropped or the caller sent `{}`.
pub(super) fn write_gemini_labels(metadata: &[(String, String)]) -> serde_json::Value {
    let mut out = serde_json::Map::new();
    let mut dropped = 0usize;
    for (k, v) in metadata {
        if out.len() < GEMINI_MAX_LABELS && gemini_label_ok(k, v) && !out.contains_key(k) {
            out.insert(k.clone(), serde_json::Value::String(v.clone()));
        } else {
            dropped += 1;
        }
    }
    if dropped > 0 {
        tracing::warn!(
            dropped,
            "dropping metadata entries on Gemini egress: labels allow at most 64 entries of \
             lowercase letters, digits, '_' and '-' (a key starting with a letter), 63 characters each"
        );
    }
    serde_json::Value::Object(out)
}

/// `toolConfig.functionCallingConfig.allowedFunctionNames` → the IR tool subset (IR-10). Read when
/// the subset is a real restriction the single-tool `tool_choice` cannot say: mode `ANY` with more
/// than one name (`tool_choice` = Required), or mode `AUTO` with any names (`tool_choice` = Auto).
/// `ANY` with exactly one name is the targeted `Tool{name}` and carries no subset.
pub(super) fn read_gemini_allowed_tools(
    tool_config: Option<&serde_json::Value>,
) -> Option<Vec<String>> {
    let fcc = tool_config?.get("functionCallingConfig")?;
    let mode = fcc.get("mode").and_then(|m| m.as_str())?.to_uppercase();
    let names: Vec<String> = fcc
        .get("allowedFunctionNames")?
        .as_array()?
        .iter()
        .filter_map(|n| n.as_str().map(str::to_string))
        .collect();
    match mode.as_str() {
        "ANY" if names.len() > 1 => Some(names),
        "AUTO" if !names.is_empty() => Some(names),
        _ => None,
    }
}

/// `generationConfig.responseModalities` → the IR output modalities (IR-19). An unknown word is
/// dropped with a warn; `None` when the field is absent or nothing in it is known.
pub(super) fn read_gemini_response_modalities(
    gen_config: Option<&serde_json::Value>,
) -> Option<Vec<IrModality>> {
    let arr = gen_config?.get("responseModalities")?.as_array()?;
    let mut out = Vec::with_capacity(arr.len());
    for word in arr {
        match word.as_str().and_then(IrModality::parse) {
            Some(m) => out.push(m),
            None => tracing::warn!(
                modality = %word,
                "gemini responseModalities entry has no IR modality; not carried"
            ),
        }
    }
    (!out.is_empty()).then_some(out)
}

/// The IR output modalities in Gemini's upper-case spelling (IR-19).
pub(super) fn write_gemini_response_modalities(modalities: &[IrModality]) -> serde_json::Value {
    serde_json::Value::Array(
        modalities
            .iter()
            .map(|m| serde_json::Value::String(m.as_str().to_ascii_uppercase()))
            .collect(),
    )
}

/// The Q57 request slots Gemini has no form for (IR-04 `service_tier`, IR-05 `store`, IR-06
/// `safety_identifier`/`prompt_cache_key`, IR-07 `verbosity`): the writer drops each one a request
/// carries with a warn, and the seam audits the drop through `dropped_egress_controls`.
pub(super) fn gemini_unsupported_slots(req: &IrRequest) -> Vec<&'static str> {
    let mut dropped = Vec::new();
    if req.service_tier.is_some() {
        dropped.push("service_tier");
    }
    if req.store.is_some() {
        dropped.push("store");
    }
    if req.safety_identifier.is_some() {
        dropped.push("safety_identifier");
    }
    if req.prompt_cache_key.is_some() {
        dropped.push("prompt_cache_key");
    }
    if req.verbosity.is_some() {
        dropped.push("verbosity");
    }
    dropped
}

/// Whether a Gemini model accepts `thinkingBudget: 0` — reasoning switched off (IR-09). Only the
/// gemini-2.5-flash family (flash and flash-lite, any version or preview suffix) can stop thinking;
/// gemini-2.5-pro rejects a budget under 128, and the Gemini 3 models cannot switch thinking off. A
/// `models/` or publisher path prefix is ignored.
pub(super) fn gemini_model_accepts_thinking_off(model: &str) -> bool {
    let name = model.rsplit('/').next().unwrap_or(model);
    name.starts_with("gemini-2.5-flash")
}
