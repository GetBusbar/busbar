// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! AUTH: the outbound `fields` call, once per upstream request, in both credential modes.
//!
//! The instance is opened as core opens an outbound auth plugin (`OutboundInstance::open_with`:
//! lifecycle `validate`, then `open`), and one style is bound with `open_outbound` (the operator's
//! credential and the provider's auth settings), as the kernel binds a provider at config time. All
//! bench threads share that one handle, as every request to the provider does.
//!
//! The measured op is what the plane driver's far end makes per attempt (`fields_now`): ONE inline
//! `fields` crossing at the head point, with the request facts of an OpenAI chat completion
//! (`POST api.openai.com /v1/chat/completions`), the host's sealed-fields capability extension,
//! and the host's lent field buffer (16 KiB) and span array (16), through the loader's `answer`,
//! which releases the answer's lease (if any) inside the crossing. Scenarios:
//!
//! - `own`: the operator's own credential (`authorization: Bearer <key>`), the common case.
//! - `passthrough`: the caller's verified credential, lent per request, presented by reference.
//! - `passthrough_invalid`: a caller credential no header value may carry (a trailing newline):
//!   nothing is presented and the plugin raises its diagnostic on the request, the miss path.
//!
//! Inbound identification is not measured: a kind whose tail declares no inbound capability (no
//! `verify` slot) is identified by the host's own default inbound style, without a crossing.
//!
//! Settings (`--settings`): `{"instance": {..}, "style": "bearer", "binding": {..}}`, the lifecycle
//! settings, the style bound and the binding's settings. The default binds `bearer` with
//! `{"protocol": "openai"}`.

use std::sync::Arc;

use busbar_contract::abi::auth::{
    slot, FieldSpan, FieldsIn, FieldsOut, OpenOutboundIn, OpenOutboundOut, RequestFacts,
    CAP_INBOUND, FIELDS_BUF_BYTES, FIELDS_MAX, FIELD_SENSITIVE, MODE_OWN, MODE_PASSTHROUGH,
    POINT_HEAD,
};
use busbar_contract::abi::mechanism::call::OutHead;
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Outcome, BLOB_OCTETS, BLOB_SECRET};
use busbar_contract::abi::mechanism::extensions;
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut, ValidateIn};
use busbar_contract::abi::sdk::auth_outbound::{EXT_SEALED_FIELDS, SEALED_FIELDS_V1};
use busbar_contract::json::{self, json, JsonValueTrait, Value};
use busbar_plugin_loader::dispatch::kinds::auth::{Auth, AuthFacts};
use busbar_plugin_loader::dispatch::{ConnTable, Dispatcher, Frame, Plugin};

use crate::frames::{abi, input, json as json_blob, output};
use crate::stats::Recorder;
use crate::{Config, Scenario, Spec, Target};

/// The operator's own key: a synthetic 56-byte token (an OpenAI project key's length).
const OWN_KEY: &[u8] = b"bench-operator-key-0000000000000000000000000000000000000";
/// A caller's key, verified by the host and lent per request (51 bytes).
const CALLER_KEY: &[u8] = b"bench-caller-key-0000000000000000000000000000000007";
/// A caller's key with a trailing newline: no header value may carry it.
const CALLER_BAD_KEY: &[u8] = b"bench-caller-key-0000000000000000000000000000000007\n";

const METHOD: &[u8] = b"POST";
const AUTHORITY: &[u8] = b"api.openai.com";
const PATH: &[u8] = b"/v1/chat/completions";
/// The fake clock's wall seconds (2023-11-14T22:13:20Z), the timestamp the host reads per call.
const TIMESTAMP: u64 = 1_700_000_000;

struct Opened {
    plugin: Plugin<Auth>,
    handle: u64,
    bearer: bool,
    _d: Arc<Dispatcher>,
}

// SAFETY: one opened auth instance is shared by the bench threads as core shares it between its
// request tasks; every measured op is a `Plugin::answer` on it.
unsafe impl Sync for Opened {}
unsafe impl Send for Opened {}

fn default_settings() -> Value {
    json!({
        "instance": {},
        "style": "bearer",
        "binding": {"protocol": "openai"}
    })
}

fn text(e: Option<Vec<u8>>) -> String {
    String::from_utf8_lossy(e.as_deref().unwrap_or_default()).into_owned()
}

fn secret(b: &[u8]) -> Blob {
    Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt: BLOB_OCTETS,
        flags: BLOB_SECRET,
    }
}

/// Open the instance (`validate`, `open`) and bind the style (`open_outbound`), as core does.
fn open(cfg: &Config, target: &Target) -> Result<Arc<Opened>, String> {
    let settings: Value = match &cfg.settings {
        Some(s) => json::parse_value(s).map_err(|e| format!("auth settings: {e}"))?,
        None => default_settings(),
    };
    let instance =
        json::to_vec(settings.get("instance").unwrap_or(&json!({}))).map_err(|e| e.to_string())?;
    let style = settings
        .get("style")
        .and_then(|v| v.as_str())
        .unwrap_or("bearer")
        .to_string();
    let binding =
        json::to_vec(settings.get("binding").unwrap_or(&json!({}))).map_err(|e| e.to_string())?;

    let d = crate::dispatcher();
    let plugin = crate::load::<Auth>(target, crate::bind(&d, "bench-auth", ConnTable::NoNeeds))?;
    let facts = plugin.context::<AuthFacts>().cloned().unwrap_or_default();
    if crate::report::verbose() {
        eprintln!(
            "[auth] caps={:#x} facts={:#x} styles={:?}",
            facts.caps,
            facts.facts,
            facts.styles.iter().map(|s| &s.name).collect::<Vec<_>>()
        );
    }
    if facts.caps & CAP_INBOUND != 0 {
        eprintln!("[auth] note: the plugin serves inbound `verify`; this workload measures outbound `fields` only");
    }

    let mut v: Frame<ValidateIn, OutHead> = Frame::new(input(), output());
    v.input.settings = json_blob(&instance);
    let called = plugin.answer(life::VALIDATE, &mut v);
    if called.outcome != Outcome::Ready {
        return Err(format!(
            "auth validate answered {:?}: {}",
            called.outcome,
            text(called.error)
        ));
    }
    let mut o: Frame<OpenIn, OpenOut> = Frame::new(input(), output());
    (o.input.generation, o.input.settings) = (1, json_blob(&instance));
    let called = plugin.answer(life::OPEN, &mut o);
    if called.outcome != Outcome::Ready {
        return Err(format!(
            "auth open answered {:?}: {}",
            called.outcome,
            text(called.error)
        ));
    }

    let mut b: Frame<OpenOutboundIn, OpenOutboundOut> = Frame::new(input(), output());
    b.input.style = abi(style.as_bytes());
    b.input.credential = secret(OWN_KEY);
    b.input.settings = json_blob(&binding);
    let called = plugin.answer(slot::OPEN_OUTBOUND, &mut b);
    let handle = b.out.handle;
    if called.outcome != Outcome::Ready {
        return Err(format!(
            "auth open_outbound({style}) answered {:?}: {}",
            called.outcome,
            text(called.error)
        ));
    }
    Ok(Arc::new(Opened {
        plugin,
        handle,
        bearer: style == "bearer",
        _d: d,
    }))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Case {
    Own,
    Passthrough,
    PassthroughInvalid,
}

impl Case {
    fn name(self) -> &'static str {
        match self {
            Case::Own => "own",
            Case::Passthrough => "passthrough",
            Case::PassthroughInvalid => "passthrough_invalid",
        }
    }
    /// The credential the answer presents, if it presents one.
    fn presented(self) -> Option<&'static [u8]> {
        match self {
            Case::Own => Some(OWN_KEY),
            Case::Passthrough => Some(CALLER_KEY),
            Case::PassthroughInvalid => None,
        }
    }
}

pub(crate) fn specs(cfg: &Config, target: &Target) -> Result<Vec<Spec>, String> {
    let opened = open(cfg, target)?;
    let mut specs = Vec::new();
    for case in [Case::Own, Case::Passthrough, Case::PassthroughInvalid] {
        let o = opened.clone();
        specs.push(Spec {
            name: format!("auth.fields {} (oai chat)", case.name()),
            ops: vec!["fields"],
            primary: 0,
            make: Box::new(move |_| {
                Ok(Box::new(Fields::new(o.clone(), case)?) as Box<dyn Scenario>)
            }),
        });
    }
    Ok(specs)
}

/// One thread's `fields` call: the host's lent buffers, allocated once and reused by every call.
struct Fields {
    opened: Arc<Opened>,
    case: Case,
    extensions: Box<[u8]>,
    field_buf: Box<[u8]>,
    spans: Box<[FieldSpan]>,
}

impl Fields {
    fn new(opened: Arc<Opened>, case: Case) -> Result<Self, String> {
        let mut x = Self {
            opened,
            case,
            extensions: extensions::encode(&[(EXT_SEALED_FIELDS, SEALED_FIELDS_V1)])
                .into_boxed_slice(),
            field_buf: vec![0; FIELDS_BUF_BYTES].into_boxed_slice(),
            spans: vec![FieldSpan::ZERO; FIELDS_MAX as usize].into_boxed_slice(),
        };
        // One unmeasured call proves the plugin answers this shape.
        let mut probe = Recorder::new(1, 0, u64::MAX, std::time::Instant::now(), 1, false);
        x.unit(&mut probe)
            .map_err(|e| format!("first fields call (unmeasured): {e}"))?;
        Ok(x)
    }

    fn frame(&mut self) -> Frame<FieldsIn, FieldsOut> {
        let mut i: FieldsIn = input();
        i.head.extensions = Blob {
            ptr: self.extensions.as_ptr(),
            len: self.extensions.len(),
            fmt: BLOB_OCTETS,
            flags: 0,
        };
        i.handle = self.opened.handle;
        i.point = POINT_HEAD;
        i.request = RequestFacts {
            method: abi(METHOD),
            authority: abi(AUTHORITY),
            canonical_path: abi(PATH),
            query: AbiStr {
                ptr: std::ptr::null(),
                len: 0,
            },
            timestamp: TIMESTAMP,
        };
        (i.mode, i.caller_credential) = match self.case {
            Case::Own => (MODE_OWN, Blob::ABSENT),
            Case::Passthrough => (MODE_PASSTHROUGH, secret(CALLER_KEY)),
            Case::PassthroughInvalid => (MODE_PASSTHROUGH, secret(CALLER_BAD_KEY)),
        };
        (i.field_buf, i.field_buf_cap) = (self.field_buf.as_mut_ptr(), self.field_buf.len());
        (i.fields, i.fields_cap) = (self.spans.as_mut_ptr(), self.spans.len() as u32);
        i.conn = 1;
        i.unit = 1;
        Frame::new(i, output())
    }

    /// The answer is the case's: one sensitive field carrying the credential, or none.
    fn check(&self, out: &FieldsOut) -> Result<(), String> {
        let at = |s: busbar_contract::abi::mechanism::call::Span| {
            let start = s.offset as usize;
            self.field_buf
                .get(start..start.saturating_add(s.len as usize))
                .unwrap_or_default()
        };
        match self.case.presented() {
            None if out.fields_len == 0 => Ok(()),
            None => Err(format!(
                "fields presented {} field(s) for an invalid credential",
                out.fields_len
            )),
            Some(key) => {
                if out.fields_len != 1 {
                    return Err(format!("fields answered {} fields, not 1", out.fields_len));
                }
                let span = self.spans[0];
                let (name, value) = (at(span.name), at(span.value));
                let good = span.flags & FIELD_SENSITIVE != 0
                    && if self.opened.bearer {
                        name == b"authorization"
                            && value.len() == 7 + key.len()
                            && value.starts_with(b"Bearer ")
                            && value.ends_with(key)
                    } else {
                        value.ends_with(key)
                    };
                if good {
                    Ok(())
                } else {
                    Err(format!(
                        "fields answered `{}: <{} bytes>` flags={:#x}, not the {} credential",
                        String::from_utf8_lossy(name),
                        value.len(),
                        span.flags,
                        self.case.name()
                    ))
                }
            }
        }
    }
}

impl Scenario for Fields {
    fn unit(&mut self, rec: &mut Recorder) -> Result<(), String> {
        let mut f = self.frame();
        let plugin = &self.opened.plugin;
        // The answer's lease (if any) is released inside the timed crossing (`answer`), so it is
        // part of the per-request crossing cost.
        let called = rec.time(0, || plugin.answer(slot::FIELDS, &mut f));
        if crate::report::verbose() {
            eprintln!(
                "[fields {}] outcome={:?} fields_len={} needed=({}, {}) ext_len={}",
                self.case.name(),
                called.outcome,
                f.out.fields_len,
                f.out.needed_fields,
                f.out.needed_bytes,
                f.out.head.extensions.len
            );
        }
        if called.outcome != Outcome::Ready {
            let why = text(called.error);
            return Err(format!(
                "fields ({}) answered {:?}: {why}",
                self.case.name(),
                called.outcome
            ));
        }
        // The fields are read after the release, as nothing the plugin answers here lives in its
        // own memory: the spans index the host's lent buffer.
        self.check(&f.out)
    }
}
