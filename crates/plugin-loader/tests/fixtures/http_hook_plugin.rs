// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! AN HTTP-CALLING HOOK, built for core's own tests on the SDK hook door (owner ruling: "core knows
//! nothing about plugins, just kinds"). It is the hook kind's outbound shape and nothing more: each
//! `decide`, `transform` and `notify` POSTs the op's projection (the SDK's `write_projection`, with
//! its `op` key) to `settings.url` through its one declared need (outbound, loopback-allowed egress,
//! the host's `http` framer), and hands a 2xx JSON reply to the SDK's shared reply lowering. Any
//! other answer is the hook failing, so the host applies `on_error`.
//!
//! Settings: `url` (required, a non-blank `http://` or `https://` URL, reference-capable: the host
//! resolves a `{file:}`/`{env:}` reference at `url` in place) and `timeout_ms` (missing or null =
//! 5000; an unsigned integer clamped to `[1, 5000]`). Other keys are accepted and ignored.
//! `configure` merges the pushed keys over the live settings; a push older than the last one
//! applied is acknowledged and not applied. `status` reports the live settings as written (with the
//! url's host) and `describe` reports the settings schema; neither is forwarded.

use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::task::Poll;

use busbar_contract::abi::hook::{Tail, CLASS_GATE, PROMPT_RW, USER_RO};
use busbar_contract::abi::host::conn::connector::{
    Need, DIRECTION_OUTBOUND, EGRESS_LOOPBACK_ALLOWED, KEEP_NAMED,
};
use busbar_contract::abi::mechanism::call::Blob;
use busbar_contract::abi::mechanism::door::Statement;
use busbar_contract::abi::mechanism::extensions::EXT_REFERENCE_FIELDS;
use busbar_contract::abi::sdk::door::{abi_str, statement};
use busbar_contract::abi::sdk::exchange::{ExchangeResponse, Op, Request};
use busbar_contract::abi::sdk::hook::{
    lower_decide_reply, lower_transform_reply, statement_with_tail, tail, Decoded, DecodedTap,
    Hook, HookOpen, RewriteVerdict, Verdict,
};
use busbar_contract::abi::sdk::life::settings_value;
use busbar_contract::abi::sdk::settings::{AdminJson, SettingsMap};
use busbar_contract::hook_wire::{OP_DECIDE, OP_NOTIFY, OP_TRANSFORM};
use busbar_contract::plugin::markers::HookKind;

/// The module name an operator writes.
pub const NAME: &str = "http-hook";

/// The version its Statement states.
pub const VERSION: &str = "1.0.0";

/// How many ops one instance holds in flight; the host clamps.
pub const MAX_INFLIGHT: u32 = 64;

/// The timeout an open with no `timeout_ms` (or a null one) takes, and the most any may ask for.
pub const DEFAULT_TIMEOUT_MS: u64 = 5000;

/// The largest reply body read.
pub const MAX_REPLY_BYTES: usize = 64 * 1024;

/// The need index every op's exchange establishes on.
const NEED: u32 = 0;

/// THE ONE NEED: outbound over the host's `http` framer under the loopback-allowed egress class,
/// the target named per op (the configured url's origin).
const NEEDS: &[Need] = &[Need {
    direction: DIRECTION_OUTBOUND,
    egress_class: EGRESS_LOOPBACK_ALLOWED,
    transport: abi_str("http"),
    keep_mode: KEEP_NAMED,
    ..Need::EMPTY
}];

/// A gate that may see and rewrite the prompt and read the caller; the grant decides what it gets.
const TAIL: &Tail = &tail(CLASS_GATE, PROMPT_RW, USER_RO);

/// The settings schema, as `describe` reports it under `schema`.
const SCHEMA: &[u8] = br#"{"type":"object","required":["url"],"additionalProperties":true,"properties":{"url":{"type":"string","minLength":1,"pattern":"\\S"},"timeout_ms":{"type":["integer","null"],"minimum":0}}}"#;

busbar_contract::statement_extensions!(
    /// `url` is reference-capable and not a secret: the host resolves a reference there in place.
    pub EXTENSIONS: [(EXT_REFERENCE_FIELDS, br#"["url"]"#)]
);

/// THE STATEMENT: name, version, the gate tail, the one outbound need, the reference-capable `url`
/// and the settings schema.
pub const STATEMENT: Statement = Statement {
    settings_schema: Blob::json(SCHEMA),
    needs: NEEDS.as_ptr(),
    needs_len: NEEDS.len(),
    extensions: EXTENSIONS,
    ..statement_with_tail(statement(NAME, VERSION, MAX_INFLIGHT), TAIL)
};

/// The live target: the settings as the operator wrote them and what each exchange needs of them.
struct Live {
    url: String,
    timeout_written: AdminJson,
    timeout_ms: u64,
    origin: String,
    host: String,
    path: String,
}

impl Live {
    /// The target `url` and `timeout_ms` name, refused in this hook's words.
    fn new(url: &AdminJson, timeout: &AdminJson) -> Result<Self, String> {
        let Some(url) = url.as_str() else {
            return Err(format!("{NAME}: settings.url must be a string"));
        };
        if url.trim().is_empty() {
            return Err(format!("{NAME}: settings.url must not be empty"));
        }
        let Some(rest) = url
            .strip_prefix("http://")
            .or_else(|| url.strip_prefix("https://"))
        else {
            return Err(format!(
                "{NAME}: settings.url must be an http:// or https:// URL"
            ));
        };
        let (authority, path) = rest.find('/').map_or((rest, "/"), |at| rest.split_at(at));
        let host_port = authority.rsplit_once('@').map_or(authority, |(_, hp)| hp);
        let host = if let Some(bracketed) = host_port.strip_prefix('[') {
            bracketed.split_once(']').map_or(bracketed, |(h, _)| h)
        } else {
            host_port.split_once(':').map_or(host_port, |(h, _)| h)
        };
        if host.is_empty() {
            return Err(format!("{NAME}: settings.url names no host"));
        }
        let timeout_ms = if timeout.is_null() {
            DEFAULT_TIMEOUT_MS
        } else {
            timeout
                .as_u64()
                .ok_or_else(|| format!("{NAME}: settings.timeout_ms must be an unsigned integer"))?
                .clamp(1, DEFAULT_TIMEOUT_MS)
        };
        let scheme_len = url.len() - rest.len();
        Ok(Self {
            url: url.to_owned(),
            timeout_written: timeout.clone(),
            timeout_ms,
            origin: url[..scheme_len + authority.len()].to_owned(),
            host: host.to_owned(),
            path: path.to_owned(),
        })
    }

    /// The POST of one op's envelope.
    fn request(&self) -> Request {
        Request {
            method: b"POST".to_vec(),
            target: self.path.as_bytes().to_vec(),
            fields: vec![
                (b"content-type".to_vec(), b"application/json".to_vec()),
                (b"accept".to_vec(), b"*/*".to_vec()),
            ],
            body: Vec::new(),
            timeout_ms: self.timeout_ms,
        }
    }
}

/// The hook: the live target, swapped whole by `configure`, and the highest version applied.
pub struct HttpHook {
    live: RwLock<Arc<Live>>,
    applied: Mutex<u64>,
}

impl HttpHook {
    fn live(&self) -> Arc<Live> {
        Arc::clone(&self.live.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// POST the envelope `payload` writes to the target this op entered with: PENDING while the
    /// exchange pends; READY with the reply's JSON, or the failure text.
    fn post(
        &self,
        op: &Op<'_, HookKind>,
        payload: impl FnOnce(&mut Vec<u8>) -> Result<(), String>,
    ) -> Poll<Result<AdminJson, String>> {
        let live = match op.context(|| self.live()) {
            Ok(live) => live,
            Err(why) => return Poll::Ready(Err(why.to_owned())),
        };
        op.set_timeout_ms(live.timeout_ms);
        op.exchange_bounded(NEED, Some(&live.origin), MAX_REPLY_BYTES, || {
            let mut request = live.request();
            payload(&mut request.body)?;
            Ok(request)
        })
        .map(|answer| match answer {
            Ok(reply) => interpret(&reply),
            Err(failure) => Err(format!("{NAME}: request failed: {failure}")),
        })
    }
}

/// A 2xx reply with a JSON body is the hook's answer; every other reply is the hook failing.
fn interpret(reply: &ExchangeResponse) -> Result<AdminJson, String> {
    if !(200..300).contains(&reply.status) {
        return Err(format!("{NAME}: the target answered {}", reply.status));
    }
    if reply.body.is_empty() {
        return Err(format!(
            "{NAME}: the target answered {} with no body",
            reply.status
        ));
    }
    if reply.body.len() > MAX_REPLY_BYTES {
        return Err(format!("{NAME}: the reply is over {MAX_REPLY_BYTES} bytes"));
    }
    settings_value(&reply.body)
        .map_err(|_| format!("{NAME}: the reply ({} bytes) is not JSON", reply.body.len()))
}

impl Hook for HttpHook {
    fn decide(&self, view: &Decoded<'_>, op: &Op<'_, HookKind>) -> Poll<Verdict> {
        self.post(op, |body| {
            view.write_projection(OP_DECIDE, None, body)
                .map_err(|e| e.to_string())
        })
        .map(lower_decide_reply)
    }

    fn transform(&self, view: &Decoded<'_>, op: &Op<'_, HookKind>) -> Poll<RewriteVerdict> {
        self.post(op, |body| {
            view.write_projection(OP_TRANSFORM, None, body)
                .map_err(|e| e.to_string())
        })
        .map(lower_transform_reply)
    }

    fn notify(&self, tap: &DecodedTap<'_>, op: &Op<'_, HookKind>) -> Poll<()> {
        self.post(op, |body| {
            tap.write_projection(OP_NOTIFY, None, body)
                .map_err(|e| e.to_string())
        })
        .map(|_| ())
    }

    fn configure(&self, settings: &SettingsMap, version: u64) -> Result<(), String> {
        let mut applied = self.applied.lock().unwrap_or_else(PoisonError::into_inner);
        if version < *applied {
            return Ok(());
        }
        let current = self.live();
        let url = settings
            .get("url")
            .cloned()
            .unwrap_or_else(|| AdminJson::from(current.url.as_str()));
        let timeout = match settings.get("timeout_ms") {
            None | Some(AdminJson::Null) => current.timeout_written.clone(),
            Some(given) => given.clone(),
        };
        let next = Live::new(&url, &timeout)?;
        *self.live.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(next);
        *applied = version;
        Ok(())
    }

    fn status(&self) -> AdminJson {
        let live = self.live();
        let mut settings = SettingsMap::new();
        settings.insert("url".into(), AdminJson::from(live.url.as_str()));
        settings.insert("target_host".into(), AdminJson::from(live.host.as_str()));
        settings.insert("timeout_ms".into(), live.timeout_written.clone());
        let mut status = SettingsMap::new();
        status.insert("settings".into(), AdminJson::Object(settings));
        status.insert("metrics".into(), AdminJson::Array(Vec::new()));
        let mut envelope = SettingsMap::new();
        envelope.insert("status".into(), AdminJson::Object(status));
        AdminJson::Object(envelope)
    }

    fn describe(&self) -> AdminJson {
        let mut envelope = SettingsMap::new();
        if let Ok(schema) = settings_value(SCHEMA) {
            envelope.insert("schema".into(), schema);
        }
        AdminJson::Object(envelope)
    }
}

/// Opens the hook over its settings.
pub struct Open;

impl HookOpen for Open {
    fn open(settings: &str) -> Result<Box<dyn Hook>, String> {
        let value = settings_value(settings.as_bytes()).map_err(|e| format!("{NAME}: {e:?}"))?;
        let Some(map) = value.as_object() else {
            return Err(format!("{NAME}: settings must be an object"));
        };
        let url = map.get("url").cloned().unwrap_or(AdminJson::Null);
        let timeout = map.get("timeout_ms").cloned().unwrap_or(AdminJson::Null);
        Ok(Box::new(HttpHook {
            live: RwLock::new(Arc::new(Live::new(&url, &timeout)?)),
            applied: Mutex::new(0),
        }))
    }
}

busbar_contract::hook_door! {
    open: Open,
    statement: STATEMENT,
}
