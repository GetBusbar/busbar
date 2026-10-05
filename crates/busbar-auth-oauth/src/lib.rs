// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! # busbar-auth-oauth — the OAuth self-minting auth styles, one auth-kind plugin
//!
//! BUSBAR-1.6.0.md THE DESIGN, §6 (OWNER-LOCKED 2026-09-27, split by mechanism per ARCHITECT ruling 2026-09-29):
//! `jwt-bearer` (RFC 7523) and `oauth-client-credentials` (RFC 6749 §4.4) are ONE mechanism —
//! each obtains a short-lived bearer from a token endpoint and presents it as
//! `authorization: Bearer <token>`, differing only in the token request — and live in one plugin,
//! `busbar-auth-oauth`, loaded when some provider uses one of them. It speaks the auth kind's
//! memory ABI (`busbar_contract::abi::auth`, v3):
//!
//! * `open_outbound` binds one style to its credential and settings and answers a handle
//!   (generation data). It never touches the network.
//! * `fields` is the ONE per-request call the kernel makes (BUSBAR-1.6.0.md §6.4, §11.6): the auth fields for this
//!   attempt, written into the host's buffer, which join the head before the framer encodes it.
//!   Neither style serves the caller's credential — an OAuth token is always minted from the
//!   OPERATOR's own configured credential, never a per-request one — so neither style declares
//!   [`busbar_contract::abi::auth::STYLE_CALLER_CREDENTIAL`] (ARCHITECT ruling 2026-09-29).
//! * `outbound_ready` is the handle's `ready` fact for the health prober.
//! * `tick` refreshes minted tokens ahead of expiry.
//!
//! `oauth-token-exchange` (RFC 8693; ARCHITECT round 5 Q-L3B-EXCHANGE (B), BUSBAR-1.6.0.md B.3 item
//! 12) is the same mechanism minted ON DEMAND: its credential is busbar's own subject token, its
//! settings `{token_url, resource, subject_token_type?}`, and the scope each exchange asks for is
//! the per-call down-scope the request states in `fields`' extensions blob
//! (`busbar_contract::abi::auth::EXT_SCOPE`). Each scope is its own exchange and its own cached token;
//! a request that finds none usable waits (PENDING on its ticket) while the exchange runs on the
//! instance's driver ticket, and fails (FAILED) when the exchange does.
//!
//! EACH STYLE MINTS THROUGH THE PLUGIN'S OWN NEED and refreshes ahead of expiry on `tick`
//! ([`mint`]). The kernel holds no auth cache and does no per-plugin branching.
//!
//! The style logic is `egress_auth/*` MOVED VERBATIM (KERNEL<>PLUGINS step 22), staged
//! `busbar-auth-outbound::{mint,style,token_response}` (step 22), then split here by mechanism
//! (AUTH-SPLIT): each module names the file it came from. The inbound operations (`verify`, the
//! login pair) are not served and answer REFUSED (the tail declares only [`CAP_OUTBOUND`]).
//!
//! THE NEEDS ([`NEEDS`]; THE DESIGN §5 lists "auth mint endpoints (`token_url`, `token_uri`)" under
//! `open-web`; ARCHITECT ruling (SEAM-4f): a mint endpoint is https or LOOPBACK PLAINTEXT, exactly as
//! 1.5.5 validated it ("absolute https; loopback http allowed"), the destination guard still
//! applying — the `loopback-allowed` class's rule): one outbound need per token endpoint, over the http transport, its target the
//! binding's own setting (`target_from`), so the host declares it pinned to that endpoint when it
//! opens the instance with the binding's settings. The token exchange is ONE framed request and its
//! reply over that need, through the host's connector table (`mint::host_wire`), on the instance's
//! driver ticket: started on `tick`, or at once when a binding opens or a request waits on a token
//! nothing has minted yet (the driver ticket is woken and `drive` starts it), and carried on by the
//! `drive`s its pending reads wake.

#![deny(unsafe_code)]
#![deny(missing_docs)]

mod abi;
mod instance;
mod mint;
mod style;
mod token_response;

use std::ffi::c_void;
use std::mem::size_of;
use std::ptr;

use busbar_contract::abi::auth::{
    AuthTail, BeginLoginIn, BeginLoginOut, CompleteLoginIn, FieldsIn, FieldsOut, IdentifyOut,
    OpenOutboundIn, OpenOutboundOut, OutboundReadyIn, OutboundReadyOut, StyleDecl, VerifyIn,
    CANCEL_CONTINUES, CAP_OUTBOUND, EXT_SCOPE, LOGIN_KIND_NONE, MODE_OWN, POINT_HEAD,
};
use busbar_contract::abi::host::conn::connector::{
    Need, DIRECTION_OUTBOUND, EGRESS_LOOPBACK_ALLOWED, KEEP_NAMED,
};
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, Envelope, InHead, OutHead, Outcome, BLOB_ABSENT,
};
use busbar_contract::abi::mechanism::door::{KindTailHead, Statement};
use busbar_contract::abi::mechanism::lifecycle::{
    CancelIn, CancelOut, DriveIn, GenIn, OpenIn, OpenOut, RefreshIn, ReleaseIn, TickIn, TickOut,
    ValidateIn,
};
use busbar_contract::abi::sdk::door::{abi_str, statement, Slot};

use crate::abi::{abi, blob, text};
use crate::instance::{EnvStore, Oauth};
use crate::mint::Read;

/// The flags every field this plugin writes carries: NONE. 1.5.5 sent its credential headers
/// indexable, and an h2 encoder that honoured `FIELD_SENSITIVE` would send them never-indexed —
/// different bytes (ARCHITECT ruling 2026-09-28, Q4: the 1.5.5 bytes win; TODO item 583's
/// sensitive marking is a behaviour change not taken without the owner).
const FIELD_FLAGS: u32 = 0;

/// The styles this plugin serves. None carries [`busbar_contract::abi::auth::STYLE_CALLER_CREDENTIAL`]
/// (an OAuth token is always minted from the operator's own credential).
const STYLE_DECLS: [StyleDecl; 3] = [
    decl(style::JWT_BEARER),
    decl(style::OAUTH_CLIENT_CREDENTIALS),
    decl(style::OAUTH_TOKEN_EXCHANGE),
];

const fn decl(name: &'static str) -> StyleDecl {
    StyleDecl {
        name: abi_str(name),
        flags: 0,
        // A bearer token reads nothing past the head.
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

const NO_STR: AbiStr = AbiStr {
    ptr: ptr::null(),
    len: 0,
};

/// One token endpoint's need: outbound, `loopback-allowed` (https, or plaintext to loopback; the
/// destination guard judges the address as for every dial), over the http transport, its target
/// the binding's setting `target_from` names. It reads no response field beyond the reply's code.
const fn token_need(target_from: &'static str) -> Need {
    Need {
        direction: DIRECTION_OUTBOUND,
        egress_class: EGRESS_LOOPBACK_ALLOWED,
        transport: abi_str("http"),
        auth: NO_STR,
        target_from: abi_str(target_from),
        trust_from: NO_STR,
        details: Blob {
            ptr: ptr::null(),
            len: 0,
            fmt: BLOB_ABSENT,
            flags: 0,
        },
        keep_response_headers: ptr::null(),
        keep_response_headers_len: 0,
        timeout_ms: 0,
        keep_mode: KEEP_NAMED,
        _reserved: 0,
        deny_response_headers: ptr::null(),
        deny_response_headers_len: 0,
    }
}

/// THE PLUGIN'S OWN NEEDS, in [`mint::need`] order: `oauth-client-credentials` POSTs to the
/// binding's `token_url`, `jwt-bearer` to its `token_uri`.
pub const NEEDS: &[Need] = &[
    token_need("settings.token_url"),
    token_need("settings.token_uri"),
];

/// The diagnostic ids, in [`instance::diag`] order: 1.5.5's catalog codes where the line had one.
const DIAG_IDS: [AbiStr; 3] = [
    abi_str("BUSBAR-4014"),
    abi_str("BUSBAR-4015"),
    abi_str("BUSBAR-4016"),
];

busbar_contract::plugin_door! {
    ops: busbar_contract::abi::auth::Ops,
    statement: Statement {
        kind_tail: ptr::from_ref(TAIL).cast::<KindTailHead>(),
        diag_ids: DIAG_IDS.as_ptr(),
        diag_ids_len: DIAG_IDS.len(),
        needs: NEEDS.as_ptr(),
        needs_len: NEEDS.len(),
        ..statement("busbar-auth-oauth", env!("CARGO_PKG_VERSION"), 1024)
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

/// THE COMPILED-IN ENTRY a composition root's `auths` row names: the door at
/// `compiled_in::door::door`, the same [`door`] the dropped-in build exports (compiled-in =
/// dropped-in).
pub mod compiled_in {
    /// The door.
    pub mod door {
        pub use crate::door;
    }
}

// The dropped door's one symbol, under `dropped-in` only: a build linking this crate beside other
// plugins must not carry a second `busbar_plugin_door`.
#[cfg(feature = "dropped-in")]
#[allow(unsafe_code)] // `export_door!` emits the one exported door symbol
mod dropped {
    busbar_contract::export_door!(crate::door);
}

fn inst<'a>(p: *mut c_void) -> Option<&'a Oauth> {
    abi::instance::<Oauth>(p)
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

const SETTINGS_NOT_OBJECT: &str = "busbar-auth-oauth settings must be a JSON object";

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
        let o = Oauth::new(
            input.generation,
            abi::waker(input.host),
            abi::host(input.host),
        );
        out.instance = abi::into_instance(Box::new(o));
        Outcome::Ready
    }
}

/// `refresh`: the new generation. The token cache survives it (abi/auth: keyed by style,
/// credential and settings, never by handle).
pub struct Refresh;
impl Slot for Refresh {
    type In = RefreshIn;
    type Out = OutHead;
    fn call(instance: *mut c_void, input: &RefreshIn, out: &mut OutHead) -> Outcome {
        let Some(o) = inst(instance) else {
            return Outcome::Fault;
        };
        if !settings_ok(blob(&input.settings)) {
            out.error = abi_str(SETTINGS_NOT_OBJECT);
            return Outcome::Refused;
        }
        o.set_generation(input.generation);
        Outcome::Ready
    }
}

/// `retire`: the generation's handles go, and every token cell no live handle holds.
pub struct Retire;
impl Slot for Retire {
    type In = GenIn;
    type Out = OutHead;
    fn call(instance: *mut c_void, input: &GenIn, _: &mut OutHead) -> Outcome {
        let Some(o) = inst(instance) else {
            return Outcome::Fault;
        };
        o.retire(input.generation);
        Outcome::Ready
    }
}

/// `tick`: the refresh ahead of expiry, the wakes.
pub struct Tick;
impl Slot for Tick {
    type In = TickIn;
    type Out = TickOut;
    fn call(instance: *mut c_void, input: &TickIn, out: &mut TickOut) -> Outcome {
        let Some(o) = inst(instance) else {
            return Outcome::Fault;
        };
        let mut env = o
            .tick_env
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        env.clear();
        out.next_tick_ns = o.tick(input.now_ns, input.head.ticket, &mut env);
        envelope(&mut out.head, &env);
        Outcome::Ready
    }
}

/// `drive`: the driver ticket was woken (a read of the token exchange that pended, or a mint wanted
/// at once): the exchange goes on. It answers PENDING with `wake_at_ns` at the instant a cell is
/// next due, so a token minted between ticks is refreshed ahead of its expiry on the host's timer
/// (THE DESIGN §11: every call is Ready or Pending(wake); no plugin timer, no plugin thread).
pub struct Drive;
impl Slot for Drive {
    type In = DriveIn;
    type Out = OutHead;
    fn call(instance: *mut c_void, input: &DriveIn, out: &mut OutHead) -> Outcome {
        let Some(o) = inst(instance) else {
            return Outcome::Fault;
        };
        let mut env = o
            .drive_env
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        env.clear();
        let next = o.drive(input.head.ticket, &mut env);
        envelope(out, &env);
        match next {
            // A ticket-less PENDING is FAULT: only a drive on the driver ticket sets a timer.
            Some(at) if !input.head.ticket.is_none() => {
                out.wake_at_ns = at;
                Outcome::Pending
            }
            _ => Outcome::Ready,
        }
    }
}

/// `cancel`: a waiting `fields` is dropped; the mint it waited on completes in the background and
/// fills the cache.
pub struct Cancel;
impl Slot for Cancel {
    type In = CancelIn;
    type Out = CancelOut;
    fn call(instance: *mut c_void, input: &CancelIn, out: &mut CancelOut) -> Outcome {
        if let Some(o) = inst(instance) {
            o.unpark(input.ticket);
        }
        out.disposition = CANCEL_CONTINUES;
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
        abi::drop_instance::<Oauth>(instance);
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
        let Some(o) = inst(instance) else {
            return Outcome::Fault;
        };
        let mut env = o
            .open_env
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        env.clear();
        let Some(style) = text(&input.style) else {
            env.error = "settings: no outbound auth style was named".to_string();
            envelope(&mut out.head, &env);
            return Outcome::Refused;
        };
        let opened = style::open(style, blob(&input.credential), blob(&input.settings), o);
        let outcome = match opened {
            Ok(style::Binding::Minted(cell)) => {
                let fresh = !cell.is_ready();
                out.handle = o.keep(cell);
                if fresh {
                    o.mint_soon();
                }
                Outcome::Ready
            }
            // A token exchange mints nothing at open: each request's scope is its own exchange.
            Ok(binding) => {
                out.handle = o.keep_binding(binding);
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

/// `outbound_ready`.
pub struct OutboundReady;
impl Slot for OutboundReady {
    type In = OutboundReadyIn;
    type Out = OutboundReadyOut;
    fn call(instance: *mut c_void, input: &OutboundReadyIn, out: &mut OutboundReadyOut) -> Outcome {
        let Some(b) = inst(instance).and_then(|o| o.bound(input.handle)) else {
            return Outcome::Refused;
        };
        // A token exchange is ready whenever asked: each request's exchange is its own.
        out.ready = match b {
            style::Binding::Minted(cell) => u32::from(cell.is_ready()),
            style::Binding::Exchange(_) => 1,
        };
        Outcome::Ready
    }
}

/// `fields` for an `oauth-token-exchange` binding: the scope the call states
/// (`EXT_SCOPE` in its extensions blob; none = the empty scope) selects its cell. A usable token
/// answers READY in place; a ticket whose exchange failed answers FAILED (the attempt fails); with no
/// usable token the call is not ready: on a ticket it waits for the exchange it arms (PENDING,
/// bounded by its deadline, woken when the exchange lands or fails), ticket-less it answers REFUSED
/// (the host submits it again on a ticket).
fn exchange_fields(
    o: &Oauth,
    x: &style::ExchangeBinding,
    input: &FieldsIn,
    out: &mut FieldsOut,
    now: u64,
) -> Outcome {
    let ticket = input.head.ticket;
    if !ticket.is_none() && o.exchange_failed(ticket) {
        return Outcome::Failed;
    }
    let scope = blob(&input.head.extensions)
        .and_then(|b| busbar_contract::abi::mechanism::extensions::get(b, EXT_SCOPE))
        .map(String::from_utf8_lossy)
        .unwrap_or_default();
    let (key, cell) = x.cell(&scope, o);
    // Parked BEFORE the read arms the exchange: an exchange that lands at once still finds it.
    if !ticket.is_none() && !cell.usable(now) {
        o.park_exchange(key, ticket);
    }
    cell.read(now, |r| match r {
        Read::Header(h) => abi::write_fields(input, out, &[("authorization", h)], FIELD_FLAGS),
        Read::Nothing => abi::write_fields(input, out, &[], FIELD_FLAGS),
        Read::Wait if ticket.is_none() => {
            o.mint_soon();
            Outcome::Refused
        }
        Read::Wait => {
            o.mint_soon();
            out.head.wake_at_ns = input.head.deadline_ns;
            Outcome::Pending
        }
    })
}

/// `fields`: THE ONE PER-REQUEST CALL. Only [`MODE_OWN`]: neither style serves the caller's
/// credential (ARCHITECT ruling 2026-09-29). The cached bearer answers READY in place. With no token
/// to present (nothing minted yet, or expired with its refresh failed) the call is not ready: on a
/// ticket it answers PENDING and the ticket is woken when a mint lands; ticket-less it answers
/// REFUSED, never PENDING (abi/auth: the host submits the same call on a ticket).
pub struct Fields;
impl Slot for Fields {
    type In = FieldsIn;
    type Out = FieldsOut;
    fn call(instance: *mut c_void, input: &FieldsIn, out: &mut FieldsOut) -> Outcome {
        let Some(o) = inst(instance) else {
            return Outcome::Fault;
        };
        if input.mode != MODE_OWN {
            return Outcome::Refused;
        }
        let Some(bound) = o.bound(input.handle) else {
            return Outcome::Refused;
        };
        let now = if input.request.timestamp == 0 {
            mint::now_epoch()
        } else {
            input.request.timestamp
        };
        let m = match bound {
            style::Binding::Minted(m) => m,
            style::Binding::Exchange(x) => return exchange_fields(o, &x, input, out, now),
        };
        m.read(now, |r| match r {
            Read::Header(h) => abi::write_fields(input, out, &[("authorization", h)], FIELD_FLAGS),
            Read::Nothing => abi::write_fields(input, out, &[], FIELD_FLAGS),
            Read::Wait if input.head.ticket.is_none() => Outcome::Refused,
            Read::Wait => {
                o.park(input.head.ticket);
                o.mint_soon();
                out.head.wake_at_ns = input.head.deadline_ns;
                Outcome::Pending
            }
        })
    }
}
