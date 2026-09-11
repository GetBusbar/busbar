//! The `kind: hook` WIRE FACE — what a hook plugin implements, named by the one crate a plugin
//! manifest may name (`docs/design/1.6.0-one-face-per-kind.md` section 2). MOVED BY IDENTITY out of the
//! plugin tooling's SDK crate, where it lived beside the C glue rather than the contract: that
//! crate keeps the ABI version reader, the op-dispatch match and the boxed handle type (the C glue
//! and nothing else) and re-exports this trait at the path it has always published it under.
//!
//! `kinds::Hook` (this crate's `kinds` module) is the KIND FACE — what core, the root and the
//! units name. This is the WIRE FACE — what a plugin authors against. Exactly one loader-side
//! adapter (named in `docs/design/1.6.0-one-face-per-kind.md` section 1) will implement the kind face
//! over this wire face.

use crate::http_endpoint::{HttpEndpointRequest, HttpEndpointResponse, Route};

/// The sync contract a `kind: hook` plugin author implements. Each method receives the op's payload as
/// the opaque projection [`serde_json::Value`] the engine built (`hooks::wire::build`) and returns the
/// reply object the engine parses through its fail-closed normalizers. Every method has a DEFAULT so a
/// trivial hook (e.g. a gate that only ranks) implements just the ops it cares about; the rest degrade
/// to the safe "no opinion" / "unsupported" replies the engine already treats as fail-open.
///
/// A hook NEVER sees prompt/user content it was not granted: the engine only projects `prompt`/`user`
/// into `payload` when BOTH the operator grant and the signed-manifest intent allow it. The handler
/// just reads whatever keys are present.
pub trait HookHandler: Send + Sync {
    /// `decide` — rank candidates / return a verdict. Default: `{}` (abstain).
    ///
    /// Implement [`HookHandler::decide_result`] instead if your hook can FAIL as distinct from
    /// having no opinion. Returning `{}` from here says "no opinion", and the engine acts on that
    /// difference: an abstain lets the request proceed, a failure resolves the operator's
    /// `on_error` chain, whose terminal can be `reject`.
    fn decide(&self, _payload: &serde_json::Value) -> serde_json::Value {
        serde_json::json!({})
    }

    /// `decide`, with the ability to say the hook could not answer.
    ///
    /// ADDITIVE, and defaulted to the infallible [`HookHandler::decide`] so every existing
    /// implementation keeps compiling and behaving identically. Override this one when your hook
    /// depends on something that can be down: a remote scoring service, a database, a model.
    ///
    /// `Err(message)` reaches the engine as a failure and resolves the operator's configured
    /// `on_error` chain. `Ok(value)` is a successful reply, and `Ok(json!({}))` specifically means
    /// abstain. Before this existed there was no way to express the difference, so a gate whose
    /// dependency was down answered "no opinion" and an operator who had deliberately configured
    /// `on_error: reject` never got it.
    ///
    /// The message goes to the operator's log. Do not put request content in it.
    fn decide_result(&self, payload: &serde_json::Value) -> Result<serde_json::Value, String> {
        Ok(self.decide(payload))
    }
    /// `transform` — a `prompt: rw` gate's rewrite/reject pass. Default: `{}` (abstain, original body).
    ///
    /// Implement [`HookHandler::transform_result`] instead if your rewrite can FAIL as distinct from
    /// having nothing to change — the same difference `decide`/`decide_result` draw.
    fn transform(&self, _payload: &serde_json::Value) -> serde_json::Value {
        serde_json::json!({})
    }

    /// `transform`, with the ability to say the hook could not answer.
    ///
    /// ADDITIVE and defaulted to the infallible [`HookHandler::transform`], so every existing
    /// implementation keeps compiling and behaving identically. Override this one when the rewrite
    /// depends on something that can be down — a compressor's model endpoint, a PII screen's
    /// classifier.
    ///
    /// `Err(message)` reaches the engine as a rewrite-path FAILURE and resolves the operator's
    /// `on_error` chain. `Ok(json!({}))` remains a plain abstain: proceed with the original body.
    /// Before this existed the two were the same value, so a screening gate whose classifier was
    /// unreachable returned "no changes" and the request it was meant to stop went through with its
    /// body untouched.
    ///
    /// The message goes to the operator's log. Do not put request content in it.
    fn transform_result(&self, payload: &serde_json::Value) -> Result<serde_json::Value, String> {
        Ok(self.transform(payload))
    }
    /// `notify` — a tap observation (fire-and-forget). Default: no-op.
    fn notify(&self, _payload: &serde_json::Value) {}
    /// `configure` — accept a desired-state settings push. Return `true` to ACK the version (the engine
    /// requires the ack), `false`/anything-else to reject the push. Default: ACK (idempotent no-op).
    fn configure(
        &self,
        _settings: &serde_json::Map<String, serde_json::Value>,
        _settings_version: u64,
    ) -> bool {
        true
    }
    /// `describe` — the self-description envelope `{schema, dashboard?}`. Default: `{}` (none).
    fn describe(&self) -> serde_json::Value {
        serde_json::json!({})
    }
    /// `status` — observed settings + metrics (`{status: {...}}`). Default: `{}` (unsupported → the
    /// engine fails open).
    fn status(&self) -> serde_json::Value {
        serde_json::json!({})
    }
    /// The HTTP [`Route`]s this hook serves (a routing hook's inbound `/feedback`), collected once at
    /// load. Default: none. The engine confines a hook's routes to `/hooks/<name>/*`.
    fn routes(&self) -> Vec<Route> {
        Vec::new()
    }
    /// Serve one inbound HTTP request matched to a declared route. Default: `404`.
    fn handle_http(&self, _req: &HttpEndpointRequest) -> HttpEndpointResponse {
        HttpEndpointResponse {
            status: 404,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }
}
