// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Refusal mapping: the one place a refusal crosses kinds, generic codes and core's own text (IF §12.15).
//!
//! Every REFUSAL record a plane receives (render arg, P_ERROR, P_RV_FAILED) is built here. `code` is generic
//! (< 0x100) and `text` is core's own fixed text for it, which an operator may override per route
//! (`routes.<id>.refusals.<code>.text`). Plugin text never crosses: auth `Fail` text and kind codes, hook MESSAGE
//! (unless the operator exposes it), secret and store failures go to audit and logs only. No client refusal carries
//! a plugin code (`BUSBAR-<plugin>-NNNN`, IF §12.16 round 34).

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

use busbar_plugin_abi::fail::failed::{F_INTERNAL, F_TIMEOUT, F_UNAVAILABLE};
use busbar_plugin_abi::fail::refused::{
    R_AUTH_REQUIRED, R_BAD_CREDENTIAL, R_BUDGET, R_CONNECT_REQUIRED, R_EXPIRED, R_NOT_TRUSTED,
    R_NO_ROUTE, R_POLICY, R_RATE_LIMITED, R_REPLAYED,
};
use busbar_plugin_abi::fail::CallError;
use busbar_plugin_abi::kinds::auth::auth::{
    BAD_CREDENTIAL, EXPIRED, KEYS_STALE, NOT_MINE, SECURITY_CHECK,
};
use busbar_ports::PortError;

/// Encoded with `plane::encode_refusal` (§8.8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientRefusal {
    pub status: u16,
    pub code: u32,
    pub text: std::borrow::Cow<'static, str>,
}

/// The four sources of a client refusal (IF §12.15). The IF spells them `from_auth`, `from_hook`, `from_core` and
/// `from_port`; a `from_*` method taking `&self` is `clippy::wrong_self_convention` (denied, and no escape is
/// allowed), so they are `for_*` here with the IF's arguments and meaning unchanged.
pub trait RefusalMap: Send + Sync + 'static {
    /// An auth REFUSED: its kind code (NOT_MINE, BAD_CREDENTIAL, ...) or a generic code. The plugin's text never
    /// reaches this call.
    fn for_auth(&self, route: u32, kind_code: u32) -> ClientRefusal;
    /// A hook VERB_REJECT: R_POLICY at the hook's clamped `reject_status`. `message` is the hook's MESSAGE as its
    /// adapter scrubbed it (§12.16); it reaches the client only under `hooks.<name>.expose_message: true`.
    fn for_hook(
        &self,
        route: u32,
        hook: &str,
        reject_status: Option<u16>,
        message: Option<&str>,
    ) -> ClientRefusal;
    /// A refusal core itself decided (no credential, rate, budget, no route, replay, trust, connect).
    fn for_core(&self, route: u32, code: u32) -> ClientRefusal;
    /// Any port error of any kind: FAILED keeps its F_* code (F_INTERNAL when not generic), a CallError is
    /// F_TIMEOUT (deadline) or F_INTERNAL; a REFUSED keeps a core-vocabulary code and is F_INTERNAL otherwise.
    fn for_port(&self, route: u32, e: &PortError) -> ClientRefusal;
}

/// The most hook MESSAGE bytes core appends to its own text (IF §12.15).
pub(crate) const HOOK_MESSAGE_MAX: usize = 300;

/// The generic refusal codes a client may see, with their default status and core's fixed text.
fn refused_row(code: u32) -> Option<(u16, &'static str)> {
    Some(match code {
        R_AUTH_REQUIRED => (401, "authentication required"),
        R_BAD_CREDENTIAL => (401, "the credential was not accepted"),
        R_EXPIRED => (401, "the credential has expired"),
        R_RATE_LIMITED => (429, "rate limit exceeded"),
        R_BUDGET => (402, "budget exhausted"),
        R_NO_ROUTE => (503, "no upstream is available for this request"),
        R_POLICY => (403, "the request was refused by policy"),
        R_CONNECT_REQUIRED => (403, "a connection to the upstream is required"),
        R_REPLAYED => (409, "the request was already seen"),
        R_NOT_TRUSTED => (403, "the counterparty is not trusted"),
        _ => return None,
    })
}

/// A FAILED code as a client sees it: generic F_* kept (F_INTERNAL otherwise), 504 for a timeout, else 502.
fn failed_refusal(code: u32) -> ClientRefusal {
    let code = if (1..0x100).contains(&code) {
        code
    } else {
        F_INTERNAL
    };
    let (status, text) = match code {
        F_TIMEOUT => (504, "the upstream did not answer in time"),
        F_UNAVAILABLE => (502, "a backend is unavailable"),
        _ => (502, "the request failed"),
    };
    ClientRefusal {
        status,
        code,
        text: Cow::Borrowed(text),
    }
}

/// 400..=499 as the hook stated it, else 403 (today's hook rule).
fn clamp_reject_status(status: Option<u16>) -> u16 {
    status
        .filter(|status| (400..=499).contains(status))
        .unwrap_or(403)
}

/// True when `text` holds something shaped like a plugin code (`BUSBAR-` then a lowercase letter).
fn names_a_plugin_code(text: &str) -> bool {
    text.match_indices("BUSBAR-").any(|(at, m)| {
        text.as_bytes()
            .get(at + m.len())
            .is_some_and(u8::is_ascii_lowercase)
    })
}

/// The exposed part of a hook MESSAGE: control characters become spaces (one line), then the cut at a char
/// boundary. None when nothing printable is left, or when it would put a plugin code in front of a client.
fn exposed_message(message: &str) -> Option<String> {
    let mut out = String::with_capacity(message.len().min(HOOK_MESSAGE_MAX));
    for c in message.chars() {
        let c = if c.is_control() { ' ' } else { c };
        if out.len() + c.len_utf8() > HOOK_MESSAGE_MAX {
            break;
        }
        out.push(c);
    }
    let kept = out.trim();
    if kept.is_empty() || names_a_plugin_code(kept) {
        return None;
    }
    Some(String::from(kept))
}

/// Core's refusal map: the fixed table, the operator's per-route texts and the hooks whose MESSAGE is exposed.
#[derive(Clone, Debug, Default)]
pub struct CoreRefusals {
    /// `routes.<id>.refusals.<code>.text`, by (route, generic refusal code).
    texts: HashMap<(u32, u32), Box<str>>,
    /// `hooks.<name>.expose_message: true`.
    exposed: HashSet<Box<str>>,
}

impl CoreRefusals {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// `routes.<id>.refusals.<code>.text`. Only a generic refusal code a client can see takes a text; any other
    /// code is ignored (config load refuses it before this is reached).
    pub fn set_text(&mut self, route: u32, code: u32, text: impl Into<Box<str>>) {
        if refused_row(code).is_some() {
            self.texts.insert((route, code), text.into());
        }
    }

    /// `hooks.<name>.expose_message: true`.
    pub fn expose_hook_message(&mut self, hook: impl Into<Box<str>>) {
        self.exposed.insert(hook.into());
    }

    fn refused(&self, route: u32, code: u32) -> ClientRefusal {
        let Some((status, text)) = refused_row(code) else {
            return failed_refusal(F_INTERNAL);
        };
        let text = match self.texts.get(&(route, code)) {
            Some(own) => Cow::Owned(String::from(&**own)),
            None => Cow::Borrowed(text),
        };
        ClientRefusal { status, code, text }
    }
}

impl RefusalMap for CoreRefusals {
    fn for_auth(&self, route: u32, kind_code: u32) -> ClientRefusal {
        let code = match kind_code {
            NOT_MINE => R_AUTH_REQUIRED,
            BAD_CREDENTIAL | SECURITY_CHECK | KEYS_STALE => R_BAD_CREDENTIAL,
            EXPIRED => R_EXPIRED,
            c if refused_row(c).is_some() => c,
            _ => R_BAD_CREDENTIAL,
        };
        self.refused(route, code)
    }

    fn for_hook(
        &self,
        route: u32,
        hook: &str,
        reject_status: Option<u16>,
        message: Option<&str>,
    ) -> ClientRefusal {
        let mut refusal = self.refused(route, R_POLICY);
        refusal.status = clamp_reject_status(reject_status);
        if !self.exposed.contains(hook) {
            return refusal;
        }
        if let Some(shown) = message.and_then(exposed_message) {
            let mut text = refusal.text.into_owned();
            text.push_str(": ");
            text.push_str(&shown);
            refusal.text = Cow::Owned(text);
        }
        refusal
    }

    fn for_core(&self, route: u32, code: u32) -> ClientRefusal {
        self.refused(route, code)
    }

    fn for_port(&self, route: u32, e: &PortError) -> ClientRefusal {
        match e {
            PortError::Failed { code, .. } => failed_refusal(*code),
            PortError::Refused { code, .. } => self.refused(route, *code),
            PortError::Call(CallError::Deadline) => failed_refusal(F_TIMEOUT),
            PortError::Call(_) => failed_refusal(F_INTERNAL),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_ports::PluginCode;

    const PLUGIN_WORDS: &str = "secret-backend-said: token=abc BUSBAR-acme-auth-0042";

    fn acme() -> Option<PluginCode> {
        Some(PluginCode {
            plugin: "acme-auth",
            number: 42,
        })
    }

    fn clean(r: &ClientRefusal) {
        assert!(r.code < 0x100, "{r:?}");
        assert!(!names_a_plugin_code(&r.text), "{r:?}");
        assert!(!r.text.contains("secret-backend-said"), "{r:?}");
    }

    /// C-REFUSAL-MAP (kernel half): every kind code becomes a generic code with core's own text.
    #[test]
    fn auth_kind_codes_become_generic() {
        let map = CoreRefusals::new();
        let cases = [
            (NOT_MINE, R_AUTH_REQUIRED, 401),
            (BAD_CREDENTIAL, R_BAD_CREDENTIAL, 401),
            (SECURITY_CHECK, R_BAD_CREDENTIAL, 401),
            (KEYS_STALE, R_BAD_CREDENTIAL, 401),
            (EXPIRED, R_EXPIRED, 401),
            (0x1FF, R_BAD_CREDENTIAL, 401),
            (R_RATE_LIMITED, R_RATE_LIMITED, 429),
        ];
        for (kind, code, status) in cases {
            let r = map.for_auth(1, kind);
            assert_eq!((r.code, r.status), (code, status), "{kind:#x}");
            clean(&r);
        }
    }

    /// The core table's statuses (IF §12.15).
    #[test]
    fn core_codes_keep_their_status() {
        let map = CoreRefusals::new();
        for (code, status) in [
            (R_AUTH_REQUIRED, 401),
            (R_REPLAYED, 409),
            (R_POLICY, 403),
            (R_RATE_LIMITED, 429),
            (R_BUDGET, 402),
            (R_NO_ROUTE, 503),
            (R_CONNECT_REQUIRED, 403),
            (R_NOT_TRUSTED, 403),
        ] {
            let r = map.for_core(9, code);
            assert_eq!((r.code, r.status), (code, status));
        }
    }

    /// C-REFUSAL-MAP: no port error's text or plugin code reaches the client; FAILED keeps its F_* code.
    #[test]
    fn port_errors_carry_no_plugin_bytes() {
        let map = CoreRefusals::new();
        let failed = PortError::Failed {
            code: F_TIMEOUT,
            text: PLUGIN_WORDS.into(),
            retry_after_s: Some(3),
            backend_status: Some(503),
            error: acme(),
        };
        let r = map.for_port(1, &failed);
        assert_eq!((r.code, r.status), (F_TIMEOUT, 504));
        clean(&r);
        let kind_failed = PortError::Failed {
            code: 0x123,
            text: PLUGIN_WORDS.into(),
            retry_after_s: None,
            backend_status: None,
            error: acme(),
        };
        let r = map.for_port(1, &kind_failed);
        assert_eq!((r.code, r.status), (F_INTERNAL, 502));
        clean(&r);
        let refused = PortError::Refused {
            code: 0x104,
            text: PLUGIN_WORDS.into(),
            error: acme(),
        };
        let r = map.for_port(1, &refused);
        assert_eq!((r.code, r.status), (F_INTERNAL, 502));
        clean(&r);
        let r = map.for_port(1, &PortError::Call(CallError::Deadline));
        assert_eq!((r.code, r.status), (F_TIMEOUT, 504));
        let r = map.for_port(1, &PortError::Call(CallError::Quarantined));
        assert_eq!((r.code, r.status), (F_INTERNAL, 502));
    }

    /// C-CRYPTO-SELFTEST (e) / C-PANIC-HOST round 24 (kernel half): a crypto self-test failure or a panic inside a
    /// host crypto call reaches the port as FAILED F_UNAVAILABLE, and the client sees 502 F_UNAVAILABLE.
    #[test]
    fn unavailable_reaches_the_client_as_502() {
        let e = PortError::Failed {
            code: F_UNAVAILABLE,
            text: "crypto self-test failed".into(),
            retry_after_s: None,
            backend_status: None,
            error: None,
        };
        let r = CoreRefusals::new().for_port(3, &e);
        assert_eq!((r.code, r.status), (F_UNAVAILABLE, 502));
        assert!(!r.text.contains("self-test"));
    }

    /// The operator's per-route text replaces core's for that route and code only.
    #[test]
    fn route_text_overrides_core_text() {
        let mut map = CoreRefusals::new();
        map.set_text(7, R_RATE_LIMITED, "slow down");
        map.set_text(7, 0x101, "ignored: not a client code");
        assert_eq!(map.for_core(7, R_RATE_LIMITED).text, "slow down");
        assert_eq!(map.for_core(8, R_RATE_LIMITED).text, "rate limit exceeded");
        assert_eq!(
            map.for_auth(7, 0x101).text,
            "the credential was not accepted"
        );
    }

    /// Hook MESSAGE stays out by default; exposed, it is appended after core's text, one line, cut to 300 bytes,
    /// and dropped if it would show a plugin code (T9).
    #[test]
    fn hook_message_only_when_exposed() {
        let mut map = CoreRefusals::new();
        let hidden = map.for_hook(1, "gate", Some(451), Some("blocked: reason 7"));
        assert_eq!((hidden.status, hidden.code), (451, R_POLICY));
        assert!(!hidden.text.contains("reason 7"));
        assert_eq!(map.for_hook(1, "gate", Some(200), None).status, 403);
        map.expose_hook_message("gate");
        let shown = map.for_hook(1, "gate", None, Some("blocked:\nreason 7"));
        assert_eq!(
            shown.text,
            "the request was refused by policy: blocked: reason 7"
        );
        let long = "é".repeat(400);
        let cut = map.for_hook(1, "gate", None, Some(&long));
        let appended = cut.text.split_once(": ").expect("appended").1;
        assert!(appended.len() <= HOOK_MESSAGE_MAX);
        let coded = map.for_hook(1, "gate", None, Some("BUSBAR-acme-hook-0003: no"));
        assert_eq!(coded.text, "the request was refused by policy");
        clean(&coded);
    }
}
