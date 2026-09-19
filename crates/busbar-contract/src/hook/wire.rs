//! The cold `HookRequest`/`HookReply` envelope (`1.6.0-hook-plugin.md` Appendix A.6).
//!
//! One `busbar_call` per op: the variant IS the op-code, so the frozen six-symbol C ABI never grows.
//! Per-request ops carry `payload` = the host's `wire::build` projection (request + candidates +
//! context + any granted `argument`/`identity`) as opaque JSON. Replies are fail-closed normalized by
//! the HOST; a reply that does not deserialize is an `Err` at the host, routed through `on_error`,
//! never silently downgraded to abstain.

use serde::{Deserialize, Serialize};

/// The hook-plugin PAYLOAD schema version (the signed manifest's `abi_version` for `kind: hook`).
pub const HOOK_ABI_VERSION: u32 = 1;

/// A hook operation, serialized as the `busbar_call` request payload.
///
/// The variant IS the op-code, so the C symbol set stays at six. Per-request ops carry `payload` = the
/// host's `wire::build` projection as opaque JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum HookRequest {
    /// Rank candidates.
    Decide {
        /// The opaque JSON projection (request + candidates + context + any granted axes).
        payload: serde_json::Value,
    },
    /// Rewrite-phase.
    Transform {
        /// The opaque JSON projection.
        payload: serde_json::Value,
    },
    /// Fire-and-forget tap.
    Notify {
        /// The opaque JSON projection.
        payload: serde_json::Value,
    },
    /// Push a settings map.
    Configure {
        /// The settings map to apply.
        settings: serde_json::Map<String, serde_json::Value>,
        /// The settings version.
        settings_version: u64,
    },
    /// Describe the settings schema.
    Describe,
    /// Report observed settings + self-reported metrics.
    Status,
}

/// The hook reply, fail-closed normalized by the HOST (reject > restrict > abstain > order on
/// `decide`; reject > rewrite > abstain on `transform`).
///
/// A reply that does not deserialize is an `Err` at the host, routed through `on_error` — NEVER
/// silently downgraded to abstain.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookReply {
    /// A ranked order of candidate idxs.
    Order {
        /// The ranked candidate idxs, most-preferred first.
        order: Vec<usize>,
    },
    /// No opinion.
    Abstain,
    /// Reject the request.
    Reject {
        /// The refusal status.
        status: u16,
        /// The refusal message.
        message: String,
    },
    /// Keep only members carrying ANY of these tags.
    Restrict {
        /// The tags to keep.
        tags_any: Vec<String>,
    },
    /// Replace the body.
    Rewrite {
        /// The rewritten messages, as opaque per-plane JSON.
        messages: Vec<serde_json::Value>,
        /// The rewritten tools, as opaque per-plane JSON.
        tools: Vec<serde_json::Value>,
    },
    /// Could-not-answer.
    Failed {
        /// The could-not-answer detail.
        message: String,
    },
}
