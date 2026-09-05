// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The claim ladder: which dialect a caller is speaking, from the path and the headers alone.
//!
//! The authenticate step reads the CLAIM's scheme, and the claim is decided here. Fourteen rungs,
//! in one fixed order, reproduced exactly. The order is the whole content of the thing: a request
//! carrying both a signed authorization header and a chat-completions path is the first, not the
//! seventh, and moving any rung silently re-dialects live traffic.
//!
//! The rungs are DATA rather than a hand-written ladder of branches, and the two are the same
//! function: every rung a request matches is collected and the LOWEST-numbered one wins, which is
//! exactly what an early-returning ladder computes. Stating it as data is what lets a deployment
//! that ships no dialect at all simply claim nothing.

/// One rung: its position, the dialect it claims for, and the test it applies.
pub struct Rung {
    /// The rung's position. Lower binds tighter; ties cannot occur because the numbers are unique.
    pub strength: u16,
    /// The dialect this rung claims for.
    pub protocol: &'static str,
    /// The test, over the headers and the path.
    pub matches: fn(&dyn HeaderProbe, &str) -> bool,
}

/// The headers, as the ladder reads them: presence, and the value when a rung tests a prefix.
pub trait HeaderProbe {
    /// Whether a header is present at all.
    fn has(&self, name: &str) -> bool;
    /// A header's value, when it is present and is text.
    fn value(&self, name: &str) -> Option<&str>;
}

/// The dialect names the ladder claims for. Kept as constants so a rung and a test name the same
/// string.
pub mod protocol {
    /// The Bedrock dialect.
    pub const BEDROCK: &str = "bedrock";
    /// The Anthropic dialect.
    pub const ANTHROPIC: &str = "anthropic";
    /// The Gemini dialect.
    pub const GEMINI: &str = "gemini";
    /// The OpenAI chat-completions dialect.
    pub const OPENAI: &str = "openai";
    /// The Cohere dialect.
    pub const COHERE: &str = "cohere";
    /// The OpenAI responses dialect.
    pub const OPENAI_RESPONSES: &str = "openai-responses";
}

/// The fourteen rungs, in order.
///
/// Rungs 1 to 4 read headers, because a header a vendor SDK sets is the strongest statement of
/// intent a caller makes. Rungs 5 onward read the path, tightest shape first.
pub const LADDER: [Rung; 14] = [
    // 1 — a signed authorization header. The signature scheme names the dialect outright.
    Rung {
        strength: 1,
        protocol: protocol::BEDROCK,
        matches: |h, _| {
            h.value("authorization")
                .is_some_and(|a| a.starts_with("AWS4-HMAC-SHA256"))
        },
    },
    // 2 — either Anthropic version header.
    Rung {
        strength: 2,
        protocol: protocol::ANTHROPIC,
        matches: |h, _| h.has("anthropic-version") || h.has("anthropic-beta"),
    },
    // 3 — the Google key header.
    Rung {
        strength: 3,
        protocol: protocol::GEMINI,
        matches: |h, _| h.has("x-goog-api-key"),
    },
    // 4 — the Anthropic key header. Below the Google one because a caller sending both is far more
    // likely a Google SDK that also set a generic key header than the reverse.
    Rung {
        strength: 4,
        protocol: protocol::ANTHROPIC,
        matches: |h, _| h.has("x-api-key"),
    },
    // 5 — a Gemini action suffix on the path.
    Rung {
        strength: 5,
        protocol: protocol::GEMINI,
        matches: |_, p| {
            p.contains(":generateContent")
                || p.contains(":streamGenerateContent")
                || p.contains(":embedContent")
                || p.contains(":batchEmbedContents")
                || p.contains(":predict")
        },
    },
    // 6 — a Gemini models path.
    Rung {
        strength: 6,
        protocol: protocol::GEMINI,
        matches: |_, p| p.starts_with("/v1/models/") || p.starts_with("/v1beta/models/"),
    },
    // 7 — the OpenAI chat-completions path.
    Rung {
        strength: 7,
        protocol: protocol::OPENAI,
        matches: |_, p| p.ends_with("/v1/chat/completions"),
    },
    // 8 — a Cohere chat path, either version.
    Rung {
        strength: 8,
        protocol: protocol::COHERE,
        matches: |_, p| p.ends_with("/v2/chat") || p.ends_with("/v1/chat"),
    },
    // 9 — the other two Cohere paths.
    Rung {
        strength: 9,
        protocol: protocol::COHERE,
        matches: |_, p| p.ends_with("/v2/embed") || p.ends_with("/v2/rerank"),
    },
    // 10 — the OpenAI responses path.
    Rung {
        strength: 10,
        protocol: protocol::OPENAI_RESPONSES,
        matches: |_, p| p.ends_with("/v1/responses"),
    },
    // 11 — the Anthropic messages path.
    Rung {
        strength: 11,
        protocol: protocol::ANTHROPIC,
        matches: |_, p| p.contains("/v1/messages"),
    },
    // 12 — the Bedrock converse path.
    Rung {
        strength: 12,
        protocol: protocol::BEDROCK,
        matches: |_, p| p.contains("/converse"),
    },
    // 13 — the Bedrock invoke path.
    Rung {
        strength: 13,
        protocol: protocol::BEDROCK,
        matches: |_, p| p.starts_with("/model/") && p.ends_with("/invoke"),
    },
    // 14 — the remaining OpenAI paths. The catch-all rung, and last for that reason.
    Rung {
        strength: 14,
        protocol: protocol::OPENAI,
        matches: |_, p| {
            p.ends_with("/v1/embeddings")
                || p.ends_with("/v1/moderations")
                || p.contains("/v1/images/")
                || p.contains("/v1/audio/")
        },
    },
];

/// Which dialect a request claims, or `None` when no rung matches.
///
/// The lowest matching rung wins, which is the same answer an early-returning ladder gives.
pub fn protocol_id(path: &str, headers: &dyn HeaderProbe) -> Option<&'static str> {
    LADDER
        .iter()
        .filter(|r| (r.matches)(headers, path))
        .min_by_key(|r| r.strength)
        .map(|r| r.protocol)
}
