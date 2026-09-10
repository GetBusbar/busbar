// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WHAT A URL-MODEL DIALECT'S REQUEST LINE SAYS.
//!
//! Four of this plane's six dialects keep the model in the body. Two do not: Gemini names it in
//! `/{version}/models/{model}:{action}` and Bedrock in `/model/{model}/{verb}`, and in those two
//! dialects there is no `model` key for a body to carry. Reading it out is a statement about the
//! dialect's own URL space, which is the same kind of statement the ladder in [`crate::claims`]
//! makes about which dialect an address belongs to — so it is made here, once, and every driver of
//! those surfaces reads the same answer.
//!
//! ## Why it had to move
//!
//! This reading used to be spelled inside the engine's own arrival, bound to that path's host seam:
//! a caller that had no `ArrivalHost` — a MOUNTED leg, which holds an engine host and a contract
//! arrival and neither of the other two — could not reach it at all. So the mounted leg walked a
//! URL-model arrival as the body-model shape, the loop was handed a request with no model, and a
//! client got `Missing required parameter: 'model'` for a parameter its dialect has no place to
//! put. The reading is here now, it takes no host, it opens nothing and it answers with values.
//!
//! ## What is NOT here
//!
//! What is DONE about the answer. A URL this plane does not answer is a rejection to SHAPE and to
//! ACCOUNT, and both are the engine's: the native error envelope, the not-charged observability
//! finish, the epoch it is finished against. This module says what the URL says and stops. The
//! dialect's own not-found VOCABULARY is here, because the words are the dialect's; the decision to
//! use them is not.

/// WHAT A URL-MODEL DIALECT'S REQUEST LINE SAYS, once that dialect's own reading has read it.
///
/// Every field is a fact about the REQUEST rather than a decision about it: the model the URL named,
/// whether the URL asked for a stream, whether that stream is the JSON-array framing rather than the event framing, and the dialect's own model-miss copy where it has one. What is DONE with them is the
/// caller's, which is the whole point of the split.
///
/// WHICH OPERATION the endpoint resolves to is deliberately not here. That answer comes off the
/// protocol registry a pure kind may not name, every driver of these surfaces already holds it
/// before it asks this question, and a field this module could not fill would be a fact this module
/// was pretending to know.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UrlModel {
    /// The model the URL named.
    pub model: String,
    /// Whether the URL asked for a streamed answer.
    pub stream: bool,
    /// A request that asked to be streamed that is NOT `alt=sse` and must be framed as a JSON array.
    pub gemini_json_array: bool,
    /// This dialect's own model-not-found copy, versioned from the path the caller used, or `None`
    /// where the dialect uses the neutral sentence.
    pub model_not_found_message: Option<String>,
}

// ── GEMINI ────────────────────────────────────────────────────────────────────────────────────────

/// The action suffix that names a streamed answer on this dialect's model-scoped surface.
pub const GEMINI_STREAM_ACTION: &str = "streamGenerateContent";

/// The Gemini API version token to echo in the native error envelope, derived from the actual ingress
/// path the client used. busbar mounts the Gemini surface at both the stable `/v1/models/...` and the
/// `/v1beta/models/...` prefixes; the real Gemini API echoes whichever the caller sent. Matching the
/// prefix verbatim keeps the error indistinguishable from the native API. Unknown shapes fall back to
/// "v1beta" (the historical default and the documented full surface).
#[must_use]
pub fn gemini_api_version(path: &str) -> &'static str {
    if path.starts_with("/v1beta/") {
        "v1beta"
    } else if path.starts_with("/v1/") {
        "v1"
    } else {
        "v1beta"
    }
}

/// True when the raw query string carries an `alt=sse` pair (this dialect's event-framing selector). Scans
/// `&`-separated `key=value` pairs so it is not fooled by another param whose value contains the
/// substring `alt=sse`.
#[must_use]
pub fn query_has_alt_sse(query: &str) -> bool {
    query
        .split('&')
        .any(|pair| matches!(pair.split_once('='), Some(("alt", "sse"))))
}

/// The tail this dialect's model-scoped surface carries after `/models/`, still as the request line
/// spelled it.
///
/// Split out so every driver of this surface cuts the same segment rather than each spelling the
/// split. What a driver does about percent-encoding is its own: the driven path's arrival is handed a
/// tail an extractor already decoded once and decodes the wildcard remainder to match, and a mounted
/// arrival is handed the request line verbatim and decodes nothing that was never encoded twice.
#[must_use]
pub fn gemini_tail(path: &str) -> &str {
    path.split("/models/").nth(1).unwrap_or("")
}

/// WHAT A GEMINI MODEL-SCOPED URL NAMES.
///
/// Two answers and there is no third: the tail names a model AND an action, or it does not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GeminiUrl<'a> {
    /// The tail is `{model}:{action}`, both halves non-empty.
    Action {
        /// The model the URL named.
        model: &'a str,
        /// The action the URL named.
        action: &'a str,
    },
    /// No action suffix at all — which is NOT necessarily a malformed Gemini path: the stable
    /// `/v1/models/{id}` prefix is SHARED with the OpenAI SDK's `model.retrieve`, which carries no
    /// `:{action}`. Which envelope that gets is the caller's question, not this module's.
    NoAction,
}

/// READ A GEMINI MODEL-SCOPED TAIL. Split on the LAST colon into (model, action); an empty half on
/// either side is [`GeminiUrl::NoAction`], because a colon that names nothing named nothing.
#[must_use]
pub fn gemini_url(rest: &str) -> GeminiUrl<'_> {
    match rest.rsplit_once(':') {
        Some((model, action)) if !model.is_empty() && !action.is_empty() => {
            GeminiUrl::Action { model, action }
        }
        _ => GeminiUrl::NoAction,
    }
}

/// Whether a Gemini action asks for a streamed answer. Every other action this surface answers —
/// `generateContent`, `embedContent`, `predict` — is non-stream.
#[must_use]
pub fn gemini_is_stream(action: &str) -> bool {
    action == GEMINI_STREAM_ACTION
}

/// Whether a Gemini request must be framed as a JSON ARRAY rather than as SSE.
///
/// `?alt=sse` selects the event framing for a request that asked to be streamed; its ABSENCE means the native client
/// expects the JSON-array framing. Only a request that asked to be streamed without `alt=sse` engages it.
#[must_use]
pub fn gemini_json_array(stream: bool, query: Option<&str>) -> bool {
    stream && !query.map(query_has_alt_sse).unwrap_or(false)
}

/// This dialect's own copy for a tail that names no action, versioned with the path the caller used.
#[must_use]
pub fn gemini_invalid_path_message(rest: &str, api_version: &str) -> String {
    format!("Invalid resource path: models/{rest} is not found for API version {api_version}.")
}

/// This dialect's own copy for an action this surface does not proxy.
#[must_use]
pub fn gemini_unsupported_action_message(model: &str, api_version: &str, action: &str) -> String {
    format!(
        "models/{model} is not found for API version {api_version}, \
         or is not supported for {action}."
    )
}

/// This dialect's own model-not-found copy — versioned with the path-derived api_version, and with
/// no borrowed "does not exist" wording from another dialect. The engine renders it verbatim on a
/// model miss, so the shaping lives with the dialect and the engine names no dialect.
#[must_use]
pub fn gemini_model_not_found_message(model: &str, api_version: &str) -> String {
    format!(
        "models/{model} is not found for API version {api_version}, \
         or is not supported for the task you are trying to perform."
    )
}

// ── BEDROCK ─────────────────────────────────────────────────────────────────────────────────────

/// WHAT A BEDROCK MODEL-SCOPED URL NAMES — three shapes under one model path, and nothing else.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BedrockUrl {
    /// `POST /model/{model}/converse` — the model AND a non-streamed turn.
    Converse,
    /// `POST /model/{model}/converse-stream` — the model AND a streamed turn.
    ConverseStream,
    /// `POST /model/{model}/invoke` — the model only; the BODY names the operation.
    Invoke,
    /// Not an address this dialect answers.
    Unclaimed,
}

/// READ A BEDROCK MODEL-SCOPED PATH. The verb is the last segment and there are three of them.
#[must_use]
pub fn bedrock_url(path: &str) -> BedrockUrl {
    if path.ends_with("/converse") {
        BedrockUrl::Converse
    } else if path.ends_with("/converse-stream") {
        BedrockUrl::ConverseStream
    } else if path.ends_with("/invoke") {
        BedrockUrl::Invoke
    } else {
        BedrockUrl::Unclaimed
    }
}

/// THE MODEL BEDROCK'S REQUEST LINE NAMES — the middle segment of
/// `/model/{model}/{converse|converse-stream|invoke}`.
///
/// The codec crate's own `RequestHandler::path_model` cuts the same segment for the driven path,
/// which reaches it through the neutral protocol registry this crate does not name. The two are
/// asserted equal over a table of addresses by a cell in the one crate that can see both
/// (`busbar-llm`'s `arrival_tests`), so the cut cannot drift in one place only.
#[must_use]
pub fn bedrock_model(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("/model/")?;
    let (model, _verb) = rest.rsplit_once('/')?;
    (!model.is_empty()).then_some(model)
}

/// **WHAT THE REQUEST LINE SAYS, for the two dialects that keep the model there.**
///
/// The one entry point a driver with no host of its own needs: hand it the dialect the ladder named,
/// the request target without its query, and the query, and it answers with the facts or with
/// nothing.
///
/// `None` has exactly three meanings and they are all the same statement — *this request line names
/// no model*: the dialect keeps its model in the BODY (four of the six; the table in
/// [`crate::dialect`] is where that is declared, one `model_location` per row), or it is the one
/// URL-model address that leaves the operation to the body (`/model/{model}/invoke`, whose model is
/// a routing HINT rather than the arrival's own), or the address carries no model segment at all.
///
/// A rejection is not one of the answers. A URL this plane does not answer is a rejection to SHAPE
/// and to ACCOUNT, and both belong to the driver that has a host to account against.
#[must_use]
pub fn url_model(dialect: &str, path: &str, query: Option<&str>) -> Option<UrlModel> {
    match dialect {
        "gemini" => {
            let GeminiUrl::Action { model, action } = gemini_url(gemini_tail(path)) else {
                return None;
            };
            let stream = gemini_is_stream(action);
            Some(UrlModel {
                model: model.to_string(),
                stream,
                gemini_json_array: gemini_json_array(stream, query),
                model_not_found_message: Some(gemini_model_not_found_message(
                    model,
                    gemini_api_version(path),
                )),
            })
        }
        "bedrock" => {
            let stream = match bedrock_url(path) {
                BedrockUrl::Converse => false,
                BedrockUrl::ConverseStream => true,
                // `invoke` names the model and leaves the operation to the body: the body-model
                // shape with a routing hint, which is not a path-model arrival.
                BedrockUrl::Invoke | BedrockUrl::Unclaimed => return None,
            };
            Some(UrlModel {
                model: bedrock_model(path)?.to_string(),
                stream,
                // This dialect never uses the other one's JSON-array framing, and its model-miss
                // answer is the neutral sentence rather than a copy of its own.
                gemini_json_array: false,
                model_not_found_message: None,
            })
        }
        _ => None,
    }
}
