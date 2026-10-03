// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! # busbar-auth-header — the header-presentation auth styles, one auth-kind plugin
//!
//! BUSBAR-1.6.0.md THE DESIGN, §6 (OWNER-LOCKED 2026-09-27, split by mechanism per ARCHITECT ruling 2026-09-29):
//! *"bearer"*, *"api-key"* and *"x-goog-api-key"* are ONE mechanism — a credential presented
//! verbatim in an HTTP header, either the `authorization` bearer scheme or a raw custom header —
//! and live in one plugin, `busbar-auth-header`, loaded when some provider uses one of them. It
//! speaks the auth kind's memory ABI (`busbar_contract::abi::auth`, v3):
//!
//! * `open_outbound` binds one style to its credential and settings and answers a handle
//!   (generation data). It never touches the network.
//! * `fields` is the ONE per-request call the kernel makes (BUSBAR-1.6.0.md §6.4, §11.6): the auth fields for this
//!   attempt, written into the host's buffer, which join the head before the framer encodes it. It
//!   serves BOTH credential modes a style with [`busbar_contract::abi::auth::STYLE_CALLER_CREDENTIAL`]
//!   declares: the operator's own bound credential ([`busbar_contract::abi::auth::MODE_OWN`]), and the
//!   caller's verified credential passed per-request
//!   ([`busbar_contract::abi::auth::MODE_PASSTHROUGH`]) — ARCHITECT ruling 2026-09-29: a credential
//!   SOURCE is not a mechanism, so there is no separate `caller-credential` style; each mechanism
//!   plugin serves both modes of its own styles.
//! * `outbound_ready` is the handle's `ready` fact for the health prober: always ready — a header
//!   binding never mints.
//! * `tick` does nothing: nothing here refreshes ahead of a deadline.
//!
//! EACH BINDING BUILDS ITS HEADER ONCE, AT `open_outbound` (BUSBAR-1.6.0.md §6.5, [`style::Binding`]). The kernel
//! holds no auth cache and does no per-plugin branching.
//!
//! The style logic is `egress_auth/*` MOVED VERBATIM (KERNEL<>PLUGINS step 22), staged
//! `busbar-auth-outbound::{present,style}` (step 22), then split here by mechanism (AUTH-SPLIT):
//! each module names the file it came from. The inbound operations (`verify`, the login pair) are
//! not served and answer REFUSED (the tail declares only [`CAP_OUTBOUND`]).

#![deny(unsafe_code)]
#![deny(missing_docs)]

mod abi;
mod instance;
mod present;
mod style;

use std::ffi::c_void;
use std::mem::size_of;
use std::ptr;

use busbar_contract::abi::auth::{
    AuthTail, BeginLoginIn, BeginLoginOut, CompleteLoginIn, FieldsIn, FieldsOut, IdentifyOut,
    OpenOutboundIn, OpenOutboundOut, OutboundReadyIn, OutboundReadyOut, StyleDecl, VerifyIn,
    CANCEL_ABANDONED, CAP_OUTBOUND, FIELD_QUERY, LOGIN_KIND_NONE, MODE_OWN, MODE_PASSTHROUGH,
    POINT_HEAD, STYLE_CALLER_CREDENTIAL,
};
use busbar_contract::abi::mechanism::call::{AbiStr, Envelope, InHead, OutHead, Outcome};
use busbar_contract::abi::mechanism::door::{KindTailHead, Statement};
use busbar_contract::abi::mechanism::lifecycle::{
    CancelIn, CancelOut, DriveIn, GenIn, OpenIn, OpenOut, RefreshIn, ReleaseIn, TickIn, TickOut,
    ValidateIn,
};
use busbar_contract::abi::sdk::door::{abi_str, statement, Slot};

use crate::abi::{abi, blob, text};
use crate::instance::{EnvStore, Header};

/// The flags every field this plugin writes carries: NONE. 1.5.5 sent its credential headers
/// indexable, and an h2 encoder that honoured `FIELD_SENSITIVE` would send them never-indexed —
/// different bytes (ARCHITECT ruling 2026-09-28, Q4: the 1.5.5 bytes win; TODO item 583's
/// sensitive marking is a behaviour change not taken without the owner).
const FIELD_FLAGS: u32 = 0;

/// The styles, as the tail declares them: every one of them also serves the caller's verified
/// credential.
const STYLE_DECLS: [StyleDecl; 4] = [
    decl(style::BEARER),
    decl(style::API_KEY),
    decl(style::X_GOOG_API_KEY),
    decl(style::QUERY_KEY),
];

const fn decl(name: &'static str) -> StyleDecl {
    StyleDecl {
        name: abi_str(name),
        flags: STYLE_CALLER_CREDENTIAL,
        // A header style reads nothing past the head.
        points: POINT_HEAD,
    }
}

/// THE AUTH STATEMENT TAIL: outbound only, no login, no inbound carriers.
const TAIL: &AuthTail = &AuthTail {
    head: KindTailHead {
        size: size_of::<AuthTail>() as u32,
        _reserved: 0,
    },
    caps: CAP_OUTBOUND,
    facts: 0,
    login_kind: LOGIN_KIND_NONE,
    // Outbound only: `verify` is never called, so no inbound point.
    inbound_points: 0,
    styles: STYLE_DECLS.as_ptr(),
    styles_len: STYLE_DECLS.len(),
    operator_principal: abi_str(""),
    credential_kinds: std::ptr::null(),
    credential_kinds_len: 0,
};

/// The diagnostic ids, in [`instance::diag`] order: 1.5.5's catalog codes where the line had one.
const DIAG_IDS: [AbiStr; 3] = [
    abi_str("BUSBAR-4013"),
    abi_str("BUSBAR-7087"),
    abi_str("auth.credential-invalid-bytes"),
];

busbar_contract::plugin_door! {
    ops: busbar_contract::abi::auth::Ops,
    statement: Statement {
        kind_tail: ptr::from_ref(TAIL).cast::<KindTailHead>(),
        diag_ids: DIAG_IDS.as_ptr(),
        diag_ids_len: DIAG_IDS.len(),
        ..statement("busbar-auth-header", env!("CARGO_PKG_VERSION"), 1024)
    },
    lifecycle: {
        validate: Validate, open: Open, refresh: Refresh, retire: Retire, tick: Tick,
        drive: Drive, cancel: Cancel, release: Release, close: Close,
    },
    kind_ops: {
        verify: Verify, begin_login: BeginLogin, complete_login: CompleteLogin,
        open_outbound: OpenOutbound, outbound_ready: OutboundReady, fields: Fields,
    },
}

// The dropped door's one symbol, under `dropped-in` only: a build linking this crate beside other
// plugins must not carry a second `busbar_plugin_door`.
#[cfg(feature = "dropped-in")]
#[allow(unsafe_code)] // `export_door!` emits the one exported door symbol
mod dropped {
    busbar_contract::export_door!(crate::door);
}

fn inst<'a>(p: *mut c_void) -> Option<&'a Header> {
    abi::instance::<Header>(p)
}

/// Point `head` at `env`'s diagnostics and error text.
fn envelope(head: &mut OutHead, env: &EnvStore) {
    let d = env.diags();
    head.envelope = Envelope {
        metrics: ptr::null(),
        metrics_len: 0,
        diags: if d.is_empty() {
            ptr::null()
        } else {
            d.as_ptr()
        },
        diags_len: d.len(),
    };
    if !env.error.is_empty() {
        head.error = abi(&env.error);
    }
}

/// The plugin's own settings: none are read; present settings must be a JSON object.
fn settings_ok(b: Option<&[u8]>) -> bool {
    b.is_none_or(|b| {
        matches!(
            serde_json::from_slice::<serde_json::Value>(b),
            Ok(serde_json::Value::Object(_))
        )
    })
}

const SETTINGS_NOT_OBJECT: &str = "busbar-auth-header settings must be a JSON object";

/// `validate`.
pub struct Validate;
impl Slot for Validate {
    type In = ValidateIn;
    type Out = OutHead;
    fn call(_: *mut c_void, input: &ValidateIn, out: &mut OutHead) -> Outcome {
        if settings_ok(blob(&input.settings)) {
            Outcome::Ready
        } else {
            out.error = abi_str(SETTINGS_NOT_OBJECT);
            Outcome::Refused
        }
    }
}

/// `open`.
pub struct Open;
impl Slot for Open {
    type In = OpenIn;
    type Out = OpenOut;
    fn call(_: *mut c_void, input: &OpenIn, out: &mut OpenOut) -> Outcome {
        if !settings_ok(blob(&input.settings)) {
            out.head.error = abi_str(SETTINGS_NOT_OBJECT);
            return Outcome::Refused;
        }
        let h = Header::new(input.generation);
        out.instance = abi::into_instance(Box::new(h));
        Outcome::Ready
    }
}

/// `refresh`: the new generation.
pub struct Refresh;
impl Slot for Refresh {
    type In = RefreshIn;
    type Out = OutHead;
    fn call(instance: *mut c_void, input: &RefreshIn, out: &mut OutHead) -> Outcome {
        let Some(h) = inst(instance) else {
            return Outcome::Fault;
        };
        if !settings_ok(blob(&input.settings)) {
            out.error = abi_str(SETTINGS_NOT_OBJECT);
            return Outcome::Refused;
        }
        h.set_generation(input.generation);
        Outcome::Ready
    }
}

/// `retire`: the generation's handles go.
pub struct Retire;
impl Slot for Retire {
    type In = GenIn;
    type Out = OutHead;
    fn call(instance: *mut c_void, input: &GenIn, _: &mut OutHead) -> Outcome {
        let Some(h) = inst(instance) else {
            return Outcome::Fault;
        };
        h.retire(input.generation);
        Outcome::Ready
    }
}

/// `tick`: nothing refreshes ahead of a deadline here.
pub struct Tick;
impl Slot for Tick {
    type In = TickIn;
    type Out = TickOut;
    fn call(instance: *mut c_void, _: &TickIn, out: &mut TickOut) -> Outcome {
        if inst(instance).is_none() {
            return Outcome::Fault;
        }
        out.next_tick_ns = 0;
        Outcome::Ready
    }
}

/// `drive`: no driver ticket is held.
pub struct Drive;
impl Slot for Drive {
    type In = DriveIn;
    type Out = OutHead;
    fn call(_: *mut c_void, _: &DriveIn, _: &mut OutHead) -> Outcome {
        Outcome::Ready
    }
}

/// `cancel`: a header binding never pends, so nothing is ever waiting.
pub struct Cancel;
impl Slot for Cancel {
    type In = CancelIn;
    type Out = CancelOut;
    fn call(_: *mut c_void, _: &CancelIn, out: &mut CancelOut) -> Outcome {
        out.disposition = CANCEL_ABANDONED;
        Outcome::Ready
    }
}

/// `release`: no lease is handed out.
pub struct Release;
impl Slot for Release {
    type In = ReleaseIn;
    type Out = OutHead;
    fn call(_: *mut c_void, _: &ReleaseIn, _: &mut OutHead) -> Outcome {
        Outcome::Ready
    }
}

/// `close`.
pub struct Close;
impl Slot for Close {
    type In = InHead;
    type Out = OutHead;
    fn call(instance: *mut c_void, _: &InHead, _: &mut OutHead) -> Outcome {
        abi::drop_instance::<Header>(instance);
        Outcome::Ready
    }
}

/// `verify`: not served ([`CAP_OUTBOUND`] only).
pub struct Verify;
impl Slot for Verify {
    type In = VerifyIn;
    type Out = IdentifyOut;
    fn call(_: *mut c_void, _: &VerifyIn, _: &mut IdentifyOut) -> Outcome {
        Outcome::Refused
    }
}

/// `begin_login`: not served.
pub struct BeginLogin;
impl Slot for BeginLogin {
    type In = BeginLoginIn;
    type Out = BeginLoginOut;
    fn call(_: *mut c_void, _: &BeginLoginIn, _: &mut BeginLoginOut) -> Outcome {
        Outcome::Refused
    }
}

/// `complete_login`: not served.
pub struct CompleteLogin;
impl Slot for CompleteLogin {
    type In = CompleteLoginIn;
    type Out = IdentifyOut;
    fn call(_: *mut c_void, _: &CompleteLoginIn, _: &mut IdentifyOut) -> Outcome {
        Outcome::Refused
    }
}

/// `open_outbound`: bind a style; FAILED carries one `credential: …` / `settings: …` line per
/// finding (ARCHITECT ruling 2026-09-28).
pub struct OpenOutbound;
impl Slot for OpenOutbound {
    type In = OpenOutboundIn;
    type Out = OpenOutboundOut;
    fn call(instance: *mut c_void, input: &OpenOutboundIn, out: &mut OpenOutboundOut) -> Outcome {
        let Some(h) = inst(instance) else {
            return Outcome::Fault;
        };
        let mut env = h
            .open_env
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        env.clear();
        let Some(style) = text(&input.style) else {
            env.error = "settings: no outbound auth style was named".to_string();
            envelope(&mut out.head, &env);
            return Outcome::Refused;
        };
        let mut notes = Vec::new();
        let opened = style::open_binding(
            style,
            blob(&input.credential),
            blob(&input.settings),
            &mut notes,
        );
        Header::note_open(&mut env, &notes);
        let outcome = match opened {
            Ok(binding) => {
                out.handle = h.keep(binding);
                Outcome::Ready
            }
            Err(refusals) => {
                env.error = refusals
                    .iter()
                    .map(style::Refusal::line)
                    .collect::<Vec<_>>()
                    .join("\n");
                Outcome::Failed
            }
        };
        envelope(&mut out.head, &env);
        outcome
    }
}

/// `outbound_ready`: always ready — a header binding never mints.
pub struct OutboundReady;
impl Slot for OutboundReady {
    type In = OutboundReadyIn;
    type Out = OutboundReadyOut;
    fn call(instance: *mut c_void, input: &OutboundReadyIn, out: &mut OutboundReadyOut) -> Outcome {
        let Some(h) = inst(instance) else {
            return Outcome::Fault;
        };
        let Some(()) = h.with_binding(input.handle, |_| ()) else {
            return Outcome::Refused;
        };
        out.ready = 1;
        Outcome::Ready
    }
}

/// `fields`: THE ONE PER-REQUEST CALL, both credential modes.
pub struct Fields;
impl Slot for Fields {
    type In = FieldsIn;
    type Out = FieldsOut;
    fn call(instance: *mut c_void, input: &FieldsIn, out: &mut FieldsOut) -> Outcome {
        let Some(h) = inst(instance) else {
            return Outcome::Fault;
        };
        let write = |(fields, query): (Vec<(String, String)>, bool), out: &mut FieldsOut| {
            let f: Vec<(&str, &str)> = fields
                .iter()
                .map(|(n, v)| (n.as_str(), v.as_str()))
                .collect();
            let flags = if query { FIELD_QUERY } else { FIELD_FLAGS };
            abi::write_fields(input, out, &f, flags)
        };
        match input.mode {
            MODE_OWN => {
                let Some(fields) = h.with_binding(input.handle, |b| (b.own().to_vec(), b.query()))
                else {
                    return Outcome::Refused;
                };
                write(fields, out)
            }
            MODE_PASSTHROUGH => {
                let caller = blob(&input.caller_credential)
                    .and_then(|c| std::str::from_utf8(c).ok())
                    .unwrap_or("");
                let Some(fields) =
                    h.with_binding(input.handle, |b| (b.passthrough(caller), b.query()))
                else {
                    return Outcome::Refused;
                };
                write(fields, out)
            }
            _ => Outcome::Refused,
        }
    }
}
