// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A DIALECT'S PROVIDER ADDRESS RULES — the names of the two dialects this plane speaks, the provider
//! endpoint each dials, and the scrub for the one dialect that carries its credential in that address.

/// THE DIALECT NAME this plane speaks first — OpenAI's bidirectional Realtime voice API. Named once
/// here; it is the dialect registry key and the FIRST of the plane's wire formats.
pub const OPENAI_REALTIME: &str = "openai_realtime";

/// THE SECOND DIALECT this plane speaks — Google's Gemini Live `BidiGenerateContent` API. Its codec is
/// `GeminiLiveCodec`; adding it to the wire formats is what EARNS the plane its superset IR
/// (a plane earns a superset at its SECOND wire format and not before).
pub const GEMINI_LIVE: &str = "gemini_live";

/// THE PROVIDER SIDE OF A DIAL — the origin, converted to its socket scheme, plus the fixed path the
/// dialect's realtime endpoint answers on. `api_key` rides in the URL for the ONE dialect whose native
/// scheme allows it (Gemini's documented `?key=` query form); OpenAI Realtime's native scheme is a
/// header (`Authorization: Bearer`) the kernel's neutral dialer (which has no custom-header hook)
/// cannot carry today — a known,
/// stated limit of the shared dialer, not something this plane's dial call papers over. A loopback test
/// provider (this plane's own conformance harness) does not check either scheme, so the wiring proves
/// out end to end even though a real OpenAI dial would still need the dialer's header hook to land.
pub fn provider_ws_url(base_url: &str, dialect: &str, api_key: &str) -> String {
    let ws = base_url
        .replacen("https://", "wss://", 1)
        .replacen("http://", "ws://", 1);
    let ws = ws.trim_end_matches('/');
    if dialect == GEMINI_LIVE {
        format!(
            "{ws}/ws/google.ai.generativelanguage.v1beta.GenerativeService.BidiGenerateContent?key={api_key}"
        )
    } else {
        format!("{ws}/v1/realtime")
    }
}

/// SCRUB a credential carried in a dial target's QUERY STRING out of a message before it is logged.
///
/// One dialect's native provider scheme puts the API key in the URL itself ([`provider_ws_url`]'s
/// `?key=` form), and the neutral dialer's URL-shaped refusals quote the target back verbatim — so a
/// `base_url` the dialer cannot use would otherwise write the deployment's resolved provider
/// credential into the process log at WARN, where it is exactly as readable as the config file it was
/// resolved from. The substrate's own hygiene covers URL userinfo and stops there; the query half is
/// this plane's to cover, because this plane is the one that puts a secret there.
///
/// Everything from `key=` to the next delimiter is replaced. Deliberately blunt: this runs only on an
/// error path about to be logged, and a message that over-redacts costs an operator nothing while one
/// that under-redacts costs them the credential.
pub fn redact_url_credentials(msg: &str) -> String {
    let mut out = String::with_capacity(msg.len());
    let mut rest = msg;
    while let Some(at) = rest.find("key=") {
        // Only a query/fragment parameter — `key=` inside an ordinary word is not a credential.
        let is_param = at == 0
            || matches!(
                rest.as_bytes()[at - 1],
                b'?' | b'&' | b';' | b'#' | b' ' | b'"'
            );
        let (head, tail) = rest.split_at(at + "key=".len());
        out.push_str(head);
        if is_param {
            let end = tail.find(['&', '#', '"', ' ', '\'']).unwrap_or(tail.len());
            if end > 0 {
                out.push_str("<redacted>");
            }
            rest = &tail[end..];
        } else {
            rest = tail;
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
#[path = "tests/provider_tests.rs"]
mod tests;
