//! The one-shot transcribe/TTS surface — a provisional wire shape, documented as such.
//!
//! `busbar-voice`'s own IR is duplex/session-only: per its crate-root documentation, Plane 4 is "the
//! duplex / live-voice plane," and nothing in `busbar_voice::ir` models a request with no session at
//! all. So there is no dedicated wire format anywhere in this crate's dependency closure to decode a
//! one-shot transcribe or text-to-speech request against — this is one of the places the task this
//! crate exists for names as a genuine gap rather than something to guess past silently.
//!
//! What this module does instead: it treats a one-shot request as [`busbar_contract::plane::Ingress::OneShot`]
//! — a single `IrClientEvent`/`IrServerEvent`-shaped exchange with no session state, in the same
//! event vocabulary the duplex dialects use, per this crate's documented plane-level decision. The
//! wire shape it decodes for the request body is the widely-used convention every OpenAI-Realtime-
//! adjacent provider's REST transcription/speech endpoints share (a JSON body carrying an `input`
//! or `model` field for TTS; an opaque audio body for transcription) — PROVISIONAL, stated as such:
//! it is not derived from any codec this crate depends on, and a future pass that finds a more
//! precise shape (e.g. multipart transcription uploads) should replace it without ceremony.

use serde_json::Value;

/// The text a one-shot text-to-speech request asks to be spoken, if the body is the provisional
/// JSON shape (`{"input": "...", ...}`) and the field is a string.
///
/// Used as this plane's estimate of the `text_tokens` class for a `tts` unit — there is no upstream
/// usage report to read the true count from before the audio comes back, so the input text length is
/// the honest, documented estimate rather than a fabricated number.
#[must_use]
pub fn tts_input_text(body: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(body).ok()?;
    value
        .get("input")
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// The voice a one-shot text-to-speech request asks for, if named in the provisional JSON shape.
#[must_use]
pub fn tts_voice(body: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(body).ok()?;
    value
        .get("voice")
        .and_then(Value::as_str)
        .map(str::to_string)
}
