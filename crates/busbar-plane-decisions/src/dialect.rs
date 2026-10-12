//! THE PLANE'S DIALECTS, as data (`BUSBAR-1.6.0.md` section 2, the decisions bullet): `jev`, the
//! `/v1/systemone` spine its providers share, and `nanojev`, the one provider whose request spine
//! really differs (`POST /api/evaluate`). Everything that differs between them is a row here: the
//! claim, the operation, where the far end states its billing unit, and the shape of an error.
//! Bytes pass through in both: the plane reads its declared pointers and rewrites nothing else.
//!
//! NANOJEV, measured on its source (github.com/TianyuCodings/NanoJev at 76fdfc9,
//! `scripts/serve_decisions.py` and `scripts/predict_toy_decisions.py`): the request is exactly
//! `{"states": [{"id", "state", "questions"}]}` (its validator refuses any other top-level member,
//! so a request never names a model); the answer is `{..., "execution": {..., "states": <the number
//! of states evaluated>, ...}, "states": [{"id", "answers"}]}`; an error is `{"error": "<text>"}`
//! at 400, 404 or 500. Its billing unit is `execution.states`, counted from the answer already read.

use busbar_contract::ids::OpClassId;

use crate::codec::{self, PTR_USAGE_INPUT_TOKENS, PTR_USAGE_OUTPUT_TOKENS, PTR_USAGE_UNITS};
use crate::ops;

/// Index of `jev` in [`ROWS`] (and in the tail's dialects).
pub const JEV: u32 = 0;

/// Index of `nanojev` in [`ROWS`].
pub const NANOJEV: u32 = 1;

/// The pointer a NanoJev answer states its billing unit at: the number of states it evaluated.
pub const PTR_EXECUTION_STATES: &str = "/execution/states";

/// One dialect, as data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Row {
    /// Its name: a provider's `protocol`, or a model's override.
    pub name: &'static str,
    /// The one operation it serves.
    pub op: OpClassId,
    /// The exact path the operation is claimed and sent on.
    pub path: &'static str,
    /// Where a success states its billing unit (the `decision` count). Required.
    pub units: &'static str,
    /// Where a success states the input tokens it consumed; `None` = the dialect states none (0).
    pub input_tokens: Option<&'static str>,
    /// Where a success states the output tokens it produced; `None` = none (0).
    pub output_tokens: Option<&'static str>,
    /// Whether a request may name its model: a dialect whose request has no model member can
    /// never splice an `upstream_model`, so a model of it that sets one is refused at validate.
    pub names_model: bool,
    /// The dialect's error shape.
    pub refusal: Refusal,
}

/// How a dialect writes an error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// `{"error": {"code": <word>, "message": <text>}}`.
    CodeAndMessage,
    /// `{"error": <text>}`.
    Text,
}

/// The dialects, in tail order.
pub const ROWS: &[Row] = &[
    Row {
        name: crate::config::PROTOCOL,
        op: ops::OP_SYSTEMONE,
        path: ops::PATH_SYSTEMONE,
        units: PTR_USAGE_UNITS,
        input_tokens: Some(PTR_USAGE_INPUT_TOKENS),
        output_tokens: Some(PTR_USAGE_OUTPUT_TOKENS),
        names_model: true,
        refusal: Refusal::CodeAndMessage,
    },
    Row {
        name: "nanojev",
        op: ops::OP_EVALUATE,
        path: ops::PATH_EVALUATE,
        units: PTR_EXECUTION_STATES,
        input_tokens: None,
        output_tokens: None,
        names_model: false,
        refusal: Refusal::Text,
    },
];

/// The row at `index`; `jev`'s for an index past the table (never stated by this plane).
#[must_use]
pub fn row(index: u32) -> &'static Row {
    ROWS.get(index as usize).unwrap_or(&ROWS[0])
}

/// The index of the dialect named `name`.
#[must_use]
pub fn index_of(name: &str) -> Option<u32> {
    ROWS.iter()
        .position(|r| r.name == name)
        .and_then(|i| u32::try_from(i).ok())
}

/// The dialect a `(verb, path)` arrives on.
#[must_use]
pub fn of_path(path: &str) -> Option<u32> {
    ROWS.iter()
        .position(|r| r.path == path)
        .and_then(|i| u32::try_from(i).ok())
}

/// `text` in the dialect's error shape, `code` the word a code-and-message shape carries.
#[must_use]
pub fn error_body(index: u32, code: &str, text: &str) -> Vec<u8> {
    match row(index).refusal {
        Refusal::CodeAndMessage => codec::error_body(code, text),
        Refusal::Text => format!(
            "{{\"error\":{}}}",
            serde_json::to_string(text).unwrap_or_else(|_| "\"error\"".to_string())
        )
        .into_bytes(),
    }
}

#[cfg(test)]
#[path = "tests/dialect.rs"]
mod tests;
