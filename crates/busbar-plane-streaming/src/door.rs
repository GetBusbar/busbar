// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STREAMING PLANE'S DOOR: the one function a compiled-in row holds and a dropped-in image
//! exports (`examples/streaming_door.rs`), and everything it states and answers.
//!
//! The composition root links [`door`] on its `plane-door` axis under this fold's development-only
//! switch (`BUSBAR-1.6.0.md` Part 3, section 12, "The switch") and binds it through the loader's one
//! load beside the dropped-in plane doors. The default build links no door of this plane, and with
//! the switch on the legacy row still serves every route until the serve path hands this door the
//! arrivals it takes.
//!
//! ## What the plane states once
//!
//! The Statement tail ([`TAIL`]): the `streams:` section it declares (and the `providers:` section
//! a document must carry when the plane is linked), its dialects, the `session` grant kind, the six
//! billable classes a session counts in, the per-session fee, its connection needs per direction
//! and the config path its egress target is read from.
//!
//! ## What each generation publishes
//!
//! A snapshot per generation: the doors a session is opened through ([`ROUTES`]), and the audience
//! a caller's token must carry with the metadata URL a refused caller is pointed at, both one
//! reading of the deployment's public base URL. A deployment with no public URL fronts nothing: its
//! snapshot claims nothing and binds no audience.
//!
//! ## What the settings blob is
//!
//! The plane's own `streams:` section as JSON, the kernel's reserved keys already read and stripped.
//! [`read_settings`] judges it with the plane's grammar ([`crate::config::StreamsCfg`], unknown keys
//! refused); an empty blob is the default section.
//!
//! ## What each unit's pieces are answered
//!
//! A one-request door (the mint, the SDP offer, the metadata document) answers its pieces through
//! a [`RequestUnit`] the instance keeps by the kernel's unit key, built at the unit's first piece
//! over the newest live generation's session params and audience. Its answer's bytes are paid into
//! the reply buffer across `more = 1` re-calls ([`crate::piece`]).
//!
//! A piece that names a stream is a live session's, served by the door's [`Sessions`]
//! ([`crate::session_door`]): the driver's duplex vocabulary (K6), one frame per answer, the
//! session's unsolicited output named on the instance's driver ticket, and the session's cumulative
//! units on every answer. A request unit on a session door is refused.

use std::collections::BTreeMap;
use std::mem::size_of;
use std::ptr;
use std::sync::Mutex;

use crate::piece::{self, Owed};
use busbar_contract::abi::hook::REQUEST_STREAM;
use busbar_contract::abi::host::conn::connector::{
    Need, DIRECTION_INBOUND, DIRECTION_OUTBOUND, KEEP_NAMED,
};
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, InHead, OutHead, Outcome, Span, BLOB_ABSENT,
};
use busbar_contract::abi::mechanism::door::{
    KindTailHead, Section, Statement, SECTION_DECLARING, SECTION_REQUIRED,
};
use busbar_contract::abi::mechanism::lifecycle::{
    CancelIn, CancelOut, GenIn, RefreshIn, ReleaseIn, TickIn, TickOut, ValidateIn,
};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::plane::{
    ArriveIn, ArriveOut, BillableClass, DialectAuth, OnPieceIn, OnPieceOut, OpClass, OutField,
    PlaneDriveIn, PlaneDriveOut, PlaneOpenIn, PlaneOpenOut, PlaneRefreshOut, PlaneSnapshot,
    PlaneTail, ProjectIn, ProjectOut, RefusalIn, RefusalOut, ServeIn, ServeOut, UnitCount,
    CANCEL_FAILED, CLAIM_EXACT, CLAIM_OPEN, EMIT_DONE, EMIT_TO_FAR_END, FROM_CALLER, FROM_FAR_END,
    FROM_KERNEL, INGRESS_DUPLEX_SESSION, INGRESS_REQUEST_RESPONSE, PIECE_HAS_STATUS, PIECE_LAST,
    PIECE_OUT_TEXT, ROUTE_DIRECT, SHAPE_PIECEWISE, SPAN_ABSENT, UNITS_ESTIMATED, UNITS_REPORTED,
};
use busbar_contract::abi::sdk::door::{abi_str, statement};
use busbar_contract::abi::sdk::publish::{ClaimSpec, SnapshotSpec};
use busbar_contract::abi::sdk::{Generations, HostBuf, Instance, Lent, Out, Safe, SafeSlot, Wake};
use busbar_contract::plane::{PER_SESSION, TOKEN_FAMILY};

use crate::claims::{Dialect, HTTP_TRANSPORT, WS_TRANSPORT};
use crate::config::StreamsCfg;
use crate::driven::{Door, Steps};
use crate::meta;
use crate::provider::{GEMINI_LIVE, OPENAI_REALTIME};
use crate::request_unit::{self, Answer, Piece, RequestUnit};
use crate::session_door::{committed_session_config, Live, Sessions, Side, CEILING_TICK_NS};

/// The name the plane's Statement carries.
pub const NAME: &str = crate::codec::PLANE_KEY;
/// The plane's config section.
pub const SECTION: &str = "streams";
/// The grant kind that admits traffic on this plane: one live session.
pub const SCOPE: &str = "session";
/// The plane's human label.
pub const LABEL: &str = "Streaming";
/// What one live session on this plane is called.
pub const SUBJECT_NOUN: &str = "streaming session";
/// The singular noun for one session, in admin responses.
pub const ADMIN_NOUN: &str = "streaming-session";
/// The record resource kind a session is audited under.
pub const AUDIT_KIND: &str = "streaming_session";
/// The one value a key's `session` grant names to open a live session here: the pool every session
/// is served on.
pub const SESSION_POOL: &str = "streaming-server";
/// The section a document must carry when the plane is linked: the upstream destinations.
pub const PROVIDERS_SECTION: &str = "providers";
/// Where, inside `streams:`, the upstream a session dials is named.
pub const EGRESS_TARGET: &str = "session.model";
/// The inbound auth style of a keyed door.
pub const KEY_AUTH: &str = "bearer";
/// The inbound auth style of the telephony door: the carrier's signed request.
pub const SIGNATURE_AUTH: &str = "webhook-signature";

/// The mount every door of the plane sits under.
pub const MOUNT_PATH: &str = "/v1/realtime";
/// The metadata document a refused caller is pointed at.
pub const METADATA_PATH: &str = "/.well-known/oauth-protected-resource/v1/realtime";

/// An absent string.
const NONE: AbiStr = AbiStr {
    ptr: ptr::null(),
    len: 0,
};

const SECTIONS: &[Section] = &[
    Section {
        name: abi_str(SECTION),
        flags: SECTION_DECLARING,
        _reserved: 0,
    },
    Section {
        name: abi_str(PROVIDERS_SECTION),
        flags: SECTION_REQUIRED,
        _reserved: 0,
    },
];

/// The dialects, in the order the per-call `dialect` index names them; then the PROVIDER
/// protocols a member's provider states, as the far-end spellings of the two realtime dialects
/// (ARCHITECT Q-L5B-NEEDS: the provider protocol -> realtime dialect mapping is the plane's own):
/// `openai` is spoken as OpenAI Realtime, `gemini` as Gemini Live. No arrival names them.
pub const DIALECTS_BY_NAME: &[&str] = &[
    OPENAI_REALTIME,
    GEMINI_LIVE,
    Dialect::TwilioMediaStreams.name(),
    OPENAI_PROVIDER,
    GEMINI_PROVIDER,
];

/// The provider protocol whose realtime dialect is OpenAI Realtime.
pub const OPENAI_PROVIDER: &str = "openai";
/// The provider protocol whose realtime dialect is Gemini Live.
pub const GEMINI_PROVIDER: &str = "gemini";

const DIALECTS: &[AbiStr] = &[
    abi_str(DIALECTS_BY_NAME[0]),
    abi_str(DIALECTS_BY_NAME[1]),
    abi_str(DIALECTS_BY_NAME[2]),
    abi_str(DIALECTS_BY_NAME[3]),
    abi_str(DIALECTS_BY_NAME[4]),
];

/// The OpenAI Realtime far end's credential style (`Authorization: Bearer`).
pub const REALTIME_STYLE: &str = "bearer";
/// The Gemini Live far end's credential style (the `x-goog-api-key` header).
pub const LIVE_STYLE: &str = "x-goog-api-key";

const fn dialect_auth(dialect: u32, style: &'static str) -> DialectAuth {
    DialectAuth {
        dialect,
        _reserved: 0,
        style: abi_str(style),
        params: Blob::ABSENT,
    }
}

/// The upstream dialects' default auth styles: each realtime dialect's, and its provider
/// protocol's spelling's.
const DIALECT_AUTH: &[DialectAuth] = &[
    dialect_auth(0, REALTIME_STYLE),
    dialect_auth(1, LIVE_STYLE),
    dialect_auth(3, REALTIME_STYLE),
    dialect_auth(4, LIVE_STYLE),
];

const SCOPE_KINDS: &[AbiStr] = &[abi_str(SCOPE)];

/// The one operation every door serves: a session open (or the one request that brokers one).
const OP_CLASSES: &[OpClass] = &[OpClass {
    op: abi_str(meta::OP_SESSION_OPEN.as_str()),
    name: abi_str(LABEL),
}];

const fn class(class: &'static str, family: &'static str) -> BillableClass {
    BillableClass {
        class: abi_str(class),
        family: abi_str(family),
    }
}

/// The six classes a session counts in (`cached_tokens` is attribution only, never billed), then
/// the session's fee unit: `per_session`, reported `1` once the far end first answers the session
/// and never before, so a session whose open failed refunds its fee (ARCHITECT Q-L5-FEE (A), Q17-6;
/// the fee unit is a billable class reported as a count of 0 or 1 and never ledgered, Q17-5 (c)).
const BILLABLE_CLASSES: &[BillableClass] = &[
    class(meta::CLASS_AUDIO_TOKENS_IN.as_str(), TOKEN_FAMILY),
    class(meta::CLASS_AUDIO_TOKENS_OUT.as_str(), TOKEN_FAMILY),
    class(meta::CLASS_TEXT_TOKENS_IN.as_str(), TOKEN_FAMILY),
    class(meta::CLASS_TEXT_TOKENS_OUT.as_str(), TOKEN_FAMILY),
    class(meta::CLASS_AUDIO_SECONDS_IN.as_str(), "duration"),
    class(meta::CLASS_TOOL_CALLS.as_str(), "count"),
    class(PER_SESSION, "count"),
];

const FEE_UNITS: &[AbiStr] = &[abi_str(PER_SESSION)];

const EGRESS_TARGETS: &[AbiStr] = &[abi_str(EGRESS_TARGET)];

const fn need(direction: u32, transport: &'static str, auth: AbiStr, target: AbiStr) -> Need {
    Need {
        direction,
        egress_class: 0,
        transport: abi_str(transport),
        auth,
        target_from: target,
        trust_from: NONE,
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

/// The plane's connection needs: its keyed doors and its telephony door inbound; outbound, to the
/// upstream `streams.session.model` names, OpenAI Realtime's socket and its one-shot passes (the
/// mint, the SDP offer) under its bearer style, and Gemini Live's socket under its key header
/// (ARCHITECT Q-L5B-NEEDS: every outbound need declares its auth; the kernel binds each a member's
/// style names, one per (transport, auth), and a far request names the one it rides).
const NEEDS: &[Need] = &[
    need(DIRECTION_INBOUND, WS_TRANSPORT, abi_str(KEY_AUTH), NONE),
    need(DIRECTION_INBOUND, HTTP_TRANSPORT, abi_str(KEY_AUTH), NONE),
    need(
        DIRECTION_INBOUND,
        WS_TRANSPORT,
        abi_str(SIGNATURE_AUTH),
        NONE,
    ),
    need(
        DIRECTION_OUTBOUND,
        WS_TRANSPORT,
        abi_str(REALTIME_STYLE),
        abi_str(EGRESS_TARGET),
    ),
    need(
        DIRECTION_OUTBOUND,
        HTTP_TRANSPORT,
        abi_str(REALTIME_STYLE),
        abi_str(EGRESS_TARGET),
    ),
    need(
        DIRECTION_OUTBOUND,
        WS_TRANSPORT,
        abi_str(LIVE_STYLE),
        abi_str(EGRESS_TARGET),
    ),
];

/// The need a far request rides, as `OnPieceOut::need` names it (its index in [`NEEDS`] plus one):
/// OpenAI Realtime's socket.
pub const RIDES_REALTIME_SOCKET: u32 = 4;
/// OpenAI Realtime's one-shot passes (the mint, the SDP offer).
pub const RIDES_REALTIME_PASS: u32 = 5;
/// Gemini Live's socket.
pub const RIDES_LIVE_SOCKET: u32 = 6;

/// THE STATEMENT TAIL.
pub const TAIL: &PlaneTail = &PlaneTail {
    head: KindTailHead {
        size: size_of::<PlaneTail>() as u32,
        _reserved: 0,
    },
    flags: 0,
    ingress: INGRESS_REQUEST_RESPONSE | INGRESS_DUPLEX_SESSION,
    dispatch_shape: SHAPE_PIECEWISE,
    _reserved: 0,
    scope: abi_str(SCOPE),
    label: abi_str(LABEL),
    subject_noun: abi_str(SUBJECT_NOUN),
    admin_noun: abi_str(ADMIN_NOUN),
    audit_kind: abi_str(AUDIT_KIND),
    signing_domain: NONE,
    signing_kid_prefix: NONE,
    cli_help: NONE,
    dialects: DIALECTS.as_ptr(),
    dialects_len: DIALECTS.len(),
    dialect_auth: DIALECT_AUTH.as_ptr(),
    dialect_auth_len: DIALECT_AUTH.len(),
    scope_kinds: SCOPE_KINDS.as_ptr(),
    scope_kinds_len: SCOPE_KINDS.len(),
    op_classes: OP_CLASSES.as_ptr(),
    op_classes_len: OP_CLASSES.len(),
    billable_classes: BILLABLE_CLASSES.as_ptr(),
    billable_classes_len: BILLABLE_CLASSES.len(),
    route_cost: ptr::null(),
    route_cost_len: 0,
    fee_units: FEE_UNITS.as_ptr(),
    fee_units_len: FEE_UNITS.len(),
    record_kinds: ptr::null(),
    record_kinds_len: 0,
    egress_targets: EGRESS_TARGETS.as_ptr(),
    egress_targets_len: EGRESS_TARGETS.len(),
    record_chains: ptr::null(),
    record_chains_len: 0,
    trust_keys: ptr::null(),
    trust_keys_len: 0,
    refusal_statuses: ptr::null(),
    refusal_statuses_len: 0,
    caller_credential_refusal: NONE,
    admin_routes: ptr::null(),
    admin_routes_len: 0,
    admin_openapi: Blob::ABSENT,
};

/// The inbound auth style of the metadata door: none, it is read without a credential.
pub const NO_AUTH: &str = "none";

/// One door a live session is opened through: one line of this plane on a listener's guest list
/// (`BUSBAR-1.6.0.md` section 6, "Auth points and guest lists", step 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Route {
    /// The method set: every door takes one method.
    pub verb: &'static str,
    /// The path: exact, or a pattern where `{…}` is one path segment. No door is a prefix, and none
    /// carries a field-presence predicate: no two doors share a path.
    pub target: &'static str,
    /// The transport the line's bytes are read by.
    pub carrier: &'static str,
    /// `true` for an upgrade line: the listener's transport runs the line's auth at `Head` on the
    /// upgrade request, then the connection is handed to [`Route::carrier`].
    pub upgrade: bool,
    /// The default inbound auth style: applied only where the operator's config gives the line no
    /// auth.
    pub auth: &'static str,
    /// The dialect the line's units speak, by its index in the tail's dialects.
    pub dialect: u32,
    /// The dialect a refusal on this line is rendered in, by the same index.
    pub refusal_dialect: u32,
}

impl Route {
    /// Read without a credential.
    #[must_use]
    pub const fn open(&self) -> bool {
        let a = self.auth.as_bytes();
        let n = NO_AUTH.as_bytes();
        if a.len() != n.len() {
            return false;
        }
        let mut i = 0;
        while i < a.len() {
            if a[i] != n[i] {
                return false;
            }
            i += 1;
        }
        true
    }

    /// `true` for an exact path, `false` for a pattern.
    #[must_use]
    pub const fn exact(&self) -> bool {
        let b = self.target.as_bytes();
        let mut j = 0;
        while j < b.len() {
            if b[j] == b'{' {
                return false;
            }
            j += 1;
        }
        true
    }
}

/// The doors, in the order a snapshot claims them: the ephemeral-secret mint and the SDP offer (one
/// request each), the browser's sideband socket, the Gemini Live socket, the telephony socket, and
/// the protected-resource metadata document a refused caller is pointed at (read without a
/// credential). The three sockets are upgrade lines.
pub const ROUTES: &[Route] = &[
    Route {
        verb: "POST",
        target: "/v1/realtime/client_secrets",
        carrier: HTTP_TRANSPORT,
        upgrade: false,
        auth: KEY_AUTH,
        dialect: 0,
        refusal_dialect: 0,
    },
    Route {
        verb: "POST",
        target: "/v1/realtime/calls",
        carrier: HTTP_TRANSPORT,
        upgrade: false,
        auth: KEY_AUTH,
        dialect: 0,
        refusal_dialect: 0,
    },
    Route {
        verb: "GET",
        target: "/v1/realtime/sideband/{call_id}",
        carrier: WS_TRANSPORT,
        upgrade: true,
        auth: KEY_AUTH,
        dialect: 0,
        refusal_dialect: 0,
    },
    Route {
        verb: "GET",
        target: "/v1/realtime/gemini/{call_id}",
        carrier: WS_TRANSPORT,
        upgrade: true,
        auth: KEY_AUTH,
        dialect: 1,
        refusal_dialect: 1,
    },
    Route {
        verb: "GET",
        target: "/twilio/{call_id}",
        carrier: WS_TRANSPORT,
        upgrade: true,
        auth: SIGNATURE_AUTH,
        dialect: 2,
        refusal_dialect: 2,
    },
    Route {
        verb: "GET",
        target: METADATA_PATH,
        carrier: HTTP_TRANSPORT,
        upgrade: false,
        auth: NO_AUTH,
        dialect: 0,
        refusal_dialect: 0,
    },
];

impl Route {
    /// The door as a generation snapshot claims it.
    #[must_use]
    pub fn claim(&self) -> ClaimSpec {
        let flags =
            if self.exact() { CLAIM_EXACT } else { 0 } | if self.open() { CLAIM_OPEN } else { 0 };
        ClaimSpec {
            refusal_dialect: self.refusal_dialect as u16,
            ..ClaimSpec::new(self.verb, self.target, self.carrier, flags)
        }
    }
}

/// Judge a settings blob with the plane's grammar; an empty blob is the default section.
///
/// # Errors
/// The grammar's reason when the blob is not a `streams:` section.
pub fn read_settings(settings: &[u8]) -> Result<StreamsCfg, String> {
    if settings.is_empty() {
        return Ok(StreamsCfg::default());
    }
    serde_json::from_slice::<StreamsCfg>(settings).map_err(|e| e.to_string())
}

/// ONE READING of the public base URL: parse it and REPLACE the path wholesale, dropping query and
/// fragment, so a public URL with a path of its own cannot produce a second spelling.
#[must_use]
pub fn absolute(public_url: &str, path: &str) -> Option<String> {
    let mut u = url::Url::parse(public_url).ok()?;
    u.set_path(path);
    u.set_query(None);
    u.set_fragment(None);
    Some(u.to_string())
}

/// One generation's answer: the strings its snapshot names, read once from the public base URL.
pub struct Generation {
    generation: u64,
    audience: String,
    resource_metadata: String,
}

impl Generation {
    /// The generation `generation` of a plane whose deployment states `public_url`.
    #[must_use]
    pub fn build(generation: u64, public_url: Option<&str>) -> Self {
        let (audience, resource_metadata) = public_url
            .and_then(|p| Some((absolute(p, MOUNT_PATH)?, absolute(p, METADATA_PATH)?)))
            .unwrap_or_default();
        Generation {
            generation,
            audience,
            resource_metadata,
        }
    }

    /// Its generation.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// The audience a caller's token must carry; empty = no receiving side.
    #[must_use]
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// The metadata URL a refused caller is pointed at; empty = no receiving side.
    #[must_use]
    pub fn resource_metadata(&self) -> &str {
        &self.resource_metadata
    }

    /// Its snapshot as the plane publishes it: every door claimed and the audience and metadata
    /// URL bound, or, with no receiving side, nothing claimed.
    #[must_use]
    pub fn snapshot(&self) -> SnapshotSpec {
        if self.audience.is_empty() {
            return SnapshotSpec::default();
        }
        SnapshotSpec {
            claims: ROUTES.iter().map(Route::claim).collect(),
            audience: Some(self.audience.clone()),
            resource_metadata: Some(self.resource_metadata.clone()),
            ..SnapshotSpec::default()
        }
    }
}

/// The plane's refusal code for an arrival on a claim it does not publish: no door of the plane
/// serves it (a 404).
pub const REFUSAL_NO_DOOR: u32 = 1;

/// The most units an instance keeps state for at once; past it, the oldest is dropped first.
pub const MAX_UNITS: usize = 4096;

/// One unit on a one-request door, kept from its first piece to the caller's answer.
struct Held {
    /// The plane's answers to the unit's pieces.
    unit: RequestUnit,
    /// What the unit's answer still owes the reply buffer.
    owed: Owed,
    /// An answer that did not fit its field or arena buffer: the re-call carries the same piece,
    /// which is answered from here rather than read twice.
    short: Option<Answer>,
}

/// One open plane instance.
pub struct Plane {
    /// The deployment's public base URL, as `open` read it; a refresh keeps it.
    public_url: Option<String>,
    /// The live generations' settings and answers, oldest first (control lane only).
    generations: Mutex<Vec<(StreamsCfg, Generation)>>,
    /// The published snapshots, held by the SDK until their generation's `retire`.
    snapshots: Generations<PlaneSnapshot>,
    /// The request units in flight, by the kernel's unit key.
    units: Mutex<BTreeMap<u64, Held>>,
    /// The live sessions, by the kernel's stream.
    sessions: Mutex<Sessions>,
    /// The host's wake, as `open` handed it; `None` = no session output can be named.
    wake: Option<Wake>,
    /// The instance's driver ticket, as its last `tick` was handed it, and that tick's clock
    /// reading in milliseconds.
    driver: Mutex<(Ticket, u64)>,
}

impl Plane {
    /// A unit arriving on claim `claim`, under the newest live generation's session params and
    /// audience, naming its caller by `caller_ref`. `None` for a claim the plane never published,
    /// and for a door that opens a live session.
    fn held(&self, claim: u32, caller_ref: Option<String>) -> Option<Held> {
        let door = Door::of(claim)?;
        let generations = lock(&self.generations);
        let (cfg, g) = generations.last()?;
        let unit = RequestUnit::open(
            door,
            cfg.session.clone(),
            caller_ref,
            g.audience().to_string(),
        )?;
        Some(Held {
            unit,
            owed: Owed::default(),
            short: None,
        })
    }

    /// The newest live generation's section; `None` before the first publish.
    fn newest(&self) -> Option<StreamsCfg> {
        lock(&self.generations).last().map(|(cfg, _)| cfg.clone())
    }

    /// Whether any live generation configures a session wall-clock ceiling.
    fn any_ceiling(&self) -> bool {
        lock(&self.generations)
            .iter()
            .any(|(cfg, _)| cfg.session_max_secs.is_some())
    }

    /// Name the instance's driver ticket: a session owes output of its own.
    fn wake_driver(&self) {
        let (ticket, _) = *lock(&self.driver);
        if let (Some(wake), false) = (self.wake, ticket == Ticket::NONE) {
            wake.wake(ticket);
        }
    }

    /// Publish generation `generation` into the `out` field `pick` names.
    fn publish<T: busbar_contract::abi::sdk::door::AbiOut>(
        &self,
        out: &mut Out<'_, T>,
        pick: impl FnOnce(&T) -> &*const PlaneSnapshot,
        generation: u64,
        cfg: StreamsCfg,
    ) {
        let g = Generation::build(generation, self.public_url.as_deref());
        out.publish(pick, &self.snapshots, generation, &g.snapshot());
        lock(&self.generations).push((cfg, g));
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// One slot body on the SDK's safe surface over the instance's [`Plane`].
macro_rules! slot {
    ($name:ident, $in:ty, $out:ty, |$inst:pat_param, $input:pat_param, $o:ident| $body:block) => {
        struct $name;
        impl SafeSlot for $name {
            type In = $in;
            type Out = $out;
            type State = Plane;
            fn call(
                $inst: Instance<'_, Plane>,
                $input: Lent<'_, $in>,
                #[allow(unused_mut)] mut $o: Out<'_, $out>,
            ) -> Outcome {
                $body
            }
        }
    };
}

slot!(Validate, ValidateIn, OutHead, |_, input, _out| {
    match read_settings(input.field(|i| &i.settings).bytes()) {
        Ok(_) => Outcome::Ready,
        Err(_) => Outcome::Refused,
    }
});

slot!(Open, PlaneOpenIn, PlaneOpenOut, |instance, input, out| {
    let Ok(cfg) = read_settings(input.field(|i| &i.open.settings).bytes()) else {
        return Outcome::Refused;
    };
    let public_url = input
        .field(|i| &i.public_url)
        .as_str()
        .ok()
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    let wake = input.field(|i| &i.open).host().and_then(|h| Wake::of(&h));
    let p = Plane {
        public_url,
        generations: Mutex::new(Vec::new()),
        snapshots: Generations::new(),
        units: Mutex::new(BTreeMap::new()),
        sessions: Mutex::new(Sessions::default()),
        wake,
        driver: Mutex::new((Ticket::NONE, 0)),
    };
    p.publish(&mut out, |o| &o.snapshot, input.open.generation, cfg);
    instance.open(p);
    Outcome::Ready
});

slot!(
    Refresh,
    RefreshIn,
    PlaneRefreshOut,
    |instance, input, out| {
        let Some(p) = instance.get() else {
            return Outcome::Failed;
        };
        let Ok(cfg) = read_settings(input.field(|i| &i.settings).bytes()) else {
            return Outcome::Refused;
        };
        p.publish(&mut out, |o| &o.snapshot, input.generation, cfg);
        Outcome::Ready
    }
);

slot!(Retire, GenIn, OutHead, |instance, input, _out| {
    if let Some(p) = instance.get() {
        lock(&p.generations).retain(|(_, g)| g.generation() != input.generation);
        p.snapshots.retire(input.generation);
    }
    Outcome::Ready
});

// The tick: the instance's driver ticket is noted, every live session's clock and ceiling read on
// the tick clock, and a session that now owes its end names the driver ticket. While a live
// generation configures a ceiling the door asks to be ticked every `CEILING_TICK_NS`.
slot!(Tick, TickIn, TickOut, |instance, input, out| {
    let given = input.get();
    let next = match instance.get() {
        Some(p) => {
            *lock(&p.driver) = (given.head.ticket, given.now_ns / 1_000_000);
            if lock(&p.sessions).tick(given.now_ns) {
                p.wake_driver();
            }
            if p.any_ceiling() {
                given.now_ns.saturating_add(CEILING_TICK_NS)
            } else {
                0
            }
        }
        None => 0,
    };
    out.set(|o| &o.next_tick_ns, next);
    Outcome::Ready
});

// `drive`: the sessions with output of their own, by stream, as many as the host's buffer takes.
slot!(
    Drive,
    PlaneDriveIn,
    PlaneDriveOut,
    |instance, input, out| {
        let Some(p) = instance.get() else {
            return Outcome::Ready;
        };
        let sessions = lock(&p.sessions);
        let mut buf = input.sessions_buf();
        for stream in sessions.ready(usize::MAX) {
            buf.push(stream);
        }
        if !buf.fits() {
            out.set(|o| &o.sessions_needed, buf.needed() as u32);
            return Outcome::Failed;
        }
        out.set(|o| &o.sessions_written, buf.written() as u32);
        Outcome::Ready
    }
);

// `cancel`: an op on a session's ticket ends the session (each side tells the other); a request
// unit's cancel is declined.
slot!(Cancel, CancelIn, CancelOut, |instance, input, out| {
    if let Some(p) = instance.get() {
        lock(&p.sessions).cancel(input.get().ticket);
    }
    out.set(|o| &o.disposition, CANCEL_FAILED);
    Outcome::Ready
});

slot!(Release, ReleaseIn, OutHead, |_, _, _out| { Outcome::Ready });

slot!(Close, InHead, OutHead, |_, _, _out| { Outcome::Ready });

// A claimed arrival is classified: its door's dialect, the session open, a known principal. No
// admission estimate: a session's units are what the far end reports. A door that reaches the far end
// names its route: the DIRECT entry `streams.session.model` (ARCHITECT Q-L5B-ROUTE: the composition
// folds that top-level catalog model into the plane's route table, so the kernel's door steps resolve
// it as any section entry). The metadata door reaches none and names none.
slot!(Arrive, ArriveIn, ArriveOut, |instance, input, out| {
    let Some(a) = crate::driven::arrive(input.claim) else {
        out.set(|o| &o.refusal, REFUSAL_NO_DOOR);
        out.set(|o| &o.refusal_status, 404);
        return Outcome::Refused;
    };
    let mut units = input.units_buf();
    for (class, amount) in a.door.admit() {
        units.push(UnitCount {
            class,
            source: UNITS_ESTIMATED,
            amount,
        });
    }
    if !units.fits() {
        out.set(|o| &o.units_needed, units.needed() as u32);
        return Outcome::Failed;
    }
    out.set(|o| &o.units_written, units.written() as u32);
    out.set(|o| &o.op_class, a.op_class);
    out.set(|o| &o.dialect, a.dialect);
    out.set(|o| &o.principal_need, a.door.authenticate());
    let model = (!a.door.is_open())
        .then(|| instance.get().and_then(Plane::newest))
        .flatten()
        .and_then(|cfg| cfg.session.model);
    if let Some(model) = model {
        out.route(ROUTE_DIRECT, &model);
    }
    Outcome::Ready
});

/// The piece `input` carries, in the plane's own vocabulary; `None` for a source the kind does not
/// name. `head` holds the far end's kept response fields, read on its first piece.
fn piece_of<'h, 'a: 'h>(
    input: Lent<'a, OnPieceIn>,
    head: &'h mut Vec<(&'a [u8], &'a [u8])>,
) -> Option<Piece<'h>> {
    let given = input.get();
    let has_status = given.flags & PIECE_HAS_STATUS != 0;
    let from = match given.from {
        FROM_CALLER => request_unit::From::Caller,
        FROM_FAR_END => request_unit::From::FarEnd,
        FROM_KERNEL => request_unit::From::Kernel(given.attempt_no),
        _ => return None,
    };
    if has_status {
        head.extend(
            input
                .head_fields()
                .iter()
                .map(|f| (f.field(|f| &f.name).bytes(), f.field(|f| &f.value).bytes())),
        );
    }
    Some(Piece {
        from,
        bytes: input.field(|i| &i.bytes).bytes(),
        status: has_status.then(|| u16::try_from(given.status_code).unwrap_or(0)),
        last: given.flags & PIECE_LAST != 0,
        head: head.as_slice(),
    })
}

/// Write the head fields `pairs` (name, value) into the host's field buffer over its arena.
fn push_fields(
    fields: &mut HostBuf<'_, OutField>,
    arena: &mut HostBuf<'_, u8>,
    pairs: &[(&'static str, String)],
) {
    for (name, value) in pairs {
        fields.push(OutField {
            name: arena.span(name.as_bytes()),
            value: arena.span(value.as_bytes()),
        });
    }
}

/// Write the plane's `answer` for `held` into the host's buffers. Answers the outcome and whether
/// the unit is done.
fn answer_piece(
    held: &mut Held,
    answer: Answer,
    input: Lent<'_, OnPieceIn>,
    out: &mut Out<'_, OnPieceOut>,
) -> (Outcome, bool) {
    match answer {
        Answer::Nothing => (Outcome::Ready, false),
        Answer::Refused => (Outcome::Refused, true),
        Answer::ToFarEnd(bytes) => {
            held.owed.owe(&bytes, EMIT_TO_FAR_END, input, out);
            (Outcome::Ready, false)
        }
        Answer::Attempt(attempt) => {
            let (mut fields, units, mut arena) =
                (input.fields_buf(), input.units_buf(), input.arena_buf());
            let verb = arena.span(attempt.verb.as_bytes());
            let target = arena.span(attempt.target.as_bytes());
            push_fields(&mut fields, &mut arena, &attempt.fields);
            if piece::settle(out, &fields, &units, &arena) {
                held.short = Some(Answer::Attempt(attempt));
                return (Outcome::Failed, false);
            }
            out.set(|o| &o.verb, verb);
            out.set(|o| &o.target, target);
            out.set(|o| &o.need, RIDES_REALTIME_PASS);
            held.owed.owe(&attempt.body, EMIT_TO_FAR_END, input, out);
            (Outcome::Ready, false)
        }
        Answer::ToCaller(reply) => {
            let (mut fields, units, mut arena) =
                (input.fields_buf(), input.units_buf(), input.arena_buf());
            push_fields(&mut fields, &mut arena, &reply.fields);
            if piece::settle(out, &fields, &units, &arena) {
                held.short = Some(Answer::ToCaller(reply));
                return (Outcome::Failed, false);
            }
            out.set(|o| &o.reply_status, u32::from(reply.status));
            let done = held.owed.owe(&reply.body, EMIT_DONE, input, out);
            (Outcome::Ready, done)
        }
    }
}

/// A live session's piece (`stream != 0`), answered by its [`crate::session_door::Live`]: the
/// caller's and the far end's pieces go through the session, a collection (`FROM_KERNEL`, no
/// attempt) answers its next queued frame, and the turn's ATTEMPT carries nothing of its own (the
/// turn's request is the caller side's answer). Every answer reports the session's cumulative
/// units and writes at most one frame; a session still owing output names the driver ticket.
fn session_piece(p: &Plane, input: Lent<'_, OnPieceIn>, out: &mut Out<'_, OnPieceOut>) -> Outcome {
    let given = input.get();
    let Some(door) = Door::of(given.claim).filter(|d| d.is_session()) else {
        return Outcome::Refused;
    };
    let Some(cfg) = p.newest() else {
        return Outcome::Refused;
    };
    let now_ms = lock(&p.driver).1;
    let mut sessions = lock(&p.sessions);
    // Only the caller's piece opens a session: a far-end piece or a collection for a stream the
    // door holds nothing for (an ended or cancelled session) is refused, never a fresh session.
    let live = if given.from == FROM_CALLER {
        sessions.get_or_open(given.stream, door, &cfg)
    } else {
        sessions.get(given.stream)
    };
    if live.is_none() {
        return Outcome::Refused;
    }
    sessions.crossed(given.stream, given.head.ticket);
    let Some(live) = sessions.get(given.stream) else {
        return Outcome::Refused;
    };
    let near = given.from != FROM_FAR_END;
    // A re-call after a `more = 1` answer pays what that side's frame still owes.
    let owed = if near { &mut live.near } else { &mut live.far };
    if piece::is_recall(input) && owed.pending() {
        owed.pay(input, out);
        return Outcome::Ready;
    }
    let short = if near {
        live.short_near.take()
    } else {
        live.short_far.take()
    };
    let emit = match short {
        Some(emit) => emit,
        None => {
            let caller_last = given.from == FROM_CALLER && given.flags & PIECE_LAST != 0;
            let bytes = input.field(|i| &i.bytes).bytes();
            match given.from {
                FROM_CALLER => live.from_caller(bytes, caller_last),
                FROM_FAR_END => live.from_far_end(bytes, now_ms),
                FROM_KERNEL => {}
                _ => return Outcome::Refused,
            }
            // The caller's last piece ends the session: what it still owed either side has no
            // one to go to. A turn's ATTEMPT carries nothing of its own.
            if caller_last {
                crate::session_door::Emit {
                    frame: None,
                    done: true,
                }
            } else if given.from == FROM_KERNEL && given.attempt_no > 0 {
                crate::session_door::Emit::default()
            } else {
                live.next(near)
            }
        }
    };
    let (fields, mut units, mut arena) = (input.fields_buf(), input.units_buf(), input.arena_buf());
    for (class, amount) in live.units() {
        units.push(UnitCount {
            class,
            source: UNITS_REPORTED,
            amount,
        });
    }
    let target = match emit.frame {
        Some((Side::FarEnd, _)) => door.route(&cfg.session, None, &[]).ok().flatten(),
        _ => None,
    };
    let verb = target.as_ref().map(|a| arena.span(a.verb.as_bytes()));
    let path = target.as_ref().map(|a| arena.span(a.target.as_bytes()));
    if piece::settle(out, &fields, &units, &arena) {
        // Short as a whole: the re-call carries the same piece, answered from here.
        if near {
            live.short_near = Some(emit);
        } else {
            live.short_far = Some(emit);
        }
        return Outcome::Failed;
    }
    let done = match emit.frame {
        Some((Side::FarEnd, frame)) => {
            if let (Some(verb), Some(path)) = (verb, path) {
                out.set(|o| &o.verb, verb);
                out.set(|o| &o.target, path);
            }
            out.set(
                |o| &o.need,
                if door == Door::Gemini {
                    RIDES_LIVE_SOCKET
                } else {
                    RIDES_REALTIME_SOCKET
                },
            );
            // A realtime dialect's frame is a JSON text message on its socket.
            live.near
                .owe(&frame, EMIT_TO_FAR_END | PIECE_OUT_TEXT, input, out);
            false
        }
        Some((Side::Caller, frame)) => {
            let owed = if near { &mut live.near } else { &mut live.far };
            owed.owe(&frame, PIECE_OUT_TEXT, input, out);
            false
        }
        None if emit.done => {
            out.set(|o| &o.flags, EMIT_DONE);
            true
        }
        None => false,
    };
    let owes = live.ready();
    if done {
        sessions.close(given.stream);
    } else if owes {
        drop(sessions);
        p.wake_driver();
    }
    Outcome::Ready
}

// `on_piece`: a one-request door's pieces (the mint, the SDP offer, the metadata document), each
// answered by the unit's [`RequestUnit`]: the ATTEMPT's request with its body, the caller's body to
// the far end, and the caller's answer from the far end's. A finished or refused unit is forgotten.
// A piece that names a stream is a live session's ([`session_piece`]).
slot!(OnPiece, OnPieceIn, OnPieceOut, |instance, input, out| {
    let Some(p) = instance.get() else {
        return Outcome::Failed;
    };
    let given = input.get();
    if given.stream != 0 {
        return session_piece(p, input, &mut out);
    }
    let mut units = lock(&p.units);
    if piece::is_recall(input) {
        if let Some(held) = units.get_mut(&given.unit) {
            if held.owed.pending() {
                if held.owed.pay(input, &mut out) {
                    units.remove(&given.unit);
                }
                return Outcome::Ready;
            }
        }
    }
    if !units.contains_key(&given.unit) {
        let caller_ref = input
            .field(|i| &i.caller_ref)
            .as_str()
            .ok()
            .filter(|r| !r.is_empty())
            .map(str::to_owned);
        let Some(held) = p.held(given.claim, caller_ref) else {
            return Outcome::Refused;
        };
        while units.len() >= MAX_UNITS {
            if units.pop_first().is_none() {
                break;
            }
        }
        units.insert(given.unit, held);
    }
    let Some(held) = units.get_mut(&given.unit) else {
        return Outcome::Failed;
    };
    let answer = match held.short.take() {
        Some(answer) => answer,
        None => {
            let mut head = Vec::new();
            let Some(piece) = piece_of(input, &mut head) else {
                return Outcome::Refused;
            };
            held.unit.on_piece(piece)
        }
    };
    let (outcome, done) = answer_piece(held, answer, input, &mut out);
    if done {
        units.remove(&given.unit);
    }
    outcome
});

// The refusal render, the admin serve and the hook projection are declined: a declined unit is
// charged nothing.

/// A refusal in the realtime dialects' error shape (the OpenAI REST error envelope, which both
/// the session doors and the one-request doors answer a refused open in): the kernel's status read
/// as the error's type, its text as the message.
#[must_use]
pub fn refusal_body(status: u16, text: &str) -> Vec<u8> {
    let kind = match status {
        401 => "authentication_error",
        403 => "permission_error",
        404 => "not_found_error",
        429 => "rate_limit_error",
        400..=499 => "invalid_request_error",
        _ => "server_error",
    };
    serde_json::to_vec(&serde_json::json!({
        "error": {"message": text, "type": kind, "param": null, "code": null}
    }))
    .unwrap_or_default()
}

/// The response field naming a refusal body's document type.
const FIELD_CONTENT_TYPE: &str = "content-type";
/// A refusal body's document type.
const CONTENT_TYPE_JSON: &str = "application/json";

// `refusal`: the kernel's status and text (a hook's veto, an admission's refusal) in the dialects'
// error shape, as JSON, before any upgrade.
slot!(Refusal, RefusalIn, RefusalOut, |_, input, out| {
    let given = input.get();
    let status = u16::try_from(given.status).unwrap_or(0);
    let text = input.field(|i| &i.text).as_str().unwrap_or_default();
    let body = refusal_body(status, text);
    let (mut reply, mut fields, mut arena) =
        (input.reply_buf(), input.fields_buf(), input.arena_buf());
    reply.extend(&body);
    fields.push(OutField {
        name: arena.span(FIELD_CONTENT_TYPE.as_bytes()),
        value: arena.span(CONTENT_TYPE_JSON.as_bytes()),
    });
    let short = !(reply.fits() && fields.fits() && arena.fits());
    let (rw, rnd) = reply.settle(short);
    let (fw, fnd) = fields.settle(short);
    let (aw, and) = arena.settle(short);
    out.set(|o| &o.reply_written, rw as u64);
    out.set(|o| &o.reply_needed, rnd as u64);
    out.set(|o| &o.fields_written, fw as u32);
    out.set(|o| &o.fields_needed, fnd as u32);
    out.set(|o| &o.arena_written, aw as u64);
    out.set(|o| &o.arena_needed, and as u64);
    if short {
        Outcome::Failed
    } else {
        Outcome::Ready
    }
});

slot!(Serve, ServeIn, ServeOut, |_, _, _out| { Outcome::Refused });

slot!(Hydrate, GenIn, OutHead, |_, _, _out| { Outcome::Ready });

slot!(Start, GenIn, OutHead, |_, _, _out| { Outcome::Ready });

// `project` (ARCHITECT Q-L5B-PROJECT; K5): the hook view of a unit's open, once, when a hook is
// bound. A session door projects the session-open params it locks (the telephony door's µ-law, else
// the section's session) as the view's body, the session-open the hooks screen; a hook's rewrite is
// patched over them ([`committed_session_config`]), kept for the session the unit opens, and THAT is
// projected and answered. A rewrite that does not read back refuses the open. A one-request door
// projects its view with no body, and takes no rewrite.
slot!(Project, ProjectIn, ProjectOut, |instance, input, out| {
    let Some(p) = instance.get() else {
        return Outcome::Failed;
    };
    let given = input.get();
    let Some(door) = Door::of(given.claim) else {
        return Outcome::Refused;
    };
    let Some(cfg) = p.newest() else {
        return Outcome::Refused;
    };
    let rewrite = input.field(|i| &i.rewrite).bytes();
    let (body, rewritten) = if door.is_session() {
        let locked = Live::locked(door, &cfg);
        let params = if rewrite.is_empty() {
            locked
        } else {
            match committed_session_config(&locked, rewrite) {
                Ok(params) => {
                    lock(&p.sessions).rewrite(given.unit, params.clone());
                    params
                }
                Err(_) => return Outcome::Refused,
            }
        };
        let Ok(body) = serde_json::to_vec(&params) else {
            return Outcome::Refused;
        };
        (Some(body), !rewrite.is_empty())
    } else if rewrite.is_empty() {
        (None, false)
    } else {
        return Outcome::Refused;
    };
    let (signals, mut arena, turns) =
        (input.signals_buf(), input.arena_buf(), input.messages_buf());
    let dialect = DIALECTS_BY_NAME
        .get(door.dialect() as usize)
        .map(|d| arena.span(d.as_bytes()));
    let pool = cfg
        .session
        .model
        .as_deref()
        .map(|m| arena.span(m.as_bytes()));
    let body = body.as_deref().map(|b| arena.span(b));
    let short = !(signals.fits() && arena.fits() && turns.fits());
    let (sw, snd) = signals.settle(short);
    let (aw, and) = arena.settle(short);
    let (tw, tnd) = turns.settle(short);
    out.set(|o| &o.signals_needed, snd as u32);
    out.set(|o| &o.arena_written, aw as u64);
    out.set(|o| &o.arena_needed, and as u64);
    out.set(|o| &o.messages_needed, tnd as u32);
    let absent = Span {
        offset: SPAN_ABSENT,
        len: 0,
    };
    out.set(|o| &o.body, absent);
    out.set(|o| &o.rewritten, absent);
    if short {
        // The driver re-calls once with the buffers this named, the same rewrite with it: patching
        // it again over the locked params writes the same body.
        return Outcome::Failed;
    }
    if let Some(pool) = pool {
        out.host_str(|o| &o.view.pool, &arena, pool);
    }
    if let Some(dialect) = dialect {
        out.host_str(|o| &o.view.ingress_dialect, &arena, dialect);
    }
    out.set(
        |o| &o.view.flags,
        if door.is_session() { REQUEST_STREAM } else { 0 },
    );
    out.host_rows(|o| &o.view.signals, &signals);
    out.set(|o| &o.view.signals_len, sw);
    out.set(|o| &o.prompt.message_count, tw as u64);
    out.host_rows(|o| &o.prompt.messages, &turns);
    out.set(|o| &o.prompt.messages_len, tw);
    if let Some(body) = body {
        out.set(|o| &o.body, body);
        if rewritten {
            out.set(|o| &o.rewritten, body);
        }
    }
    Outcome::Ready
});

busbar_contract::plugin_door! {
    ops: busbar_contract::abi::plane::Ops,
    statement: Statement {
        kind_tail: ptr::from_ref(TAIL).cast::<KindTailHead>(),
        sections: SECTIONS.as_ptr(),
        sections_len: SECTIONS.len(),
        needs: NEEDS.as_ptr(),
        needs_len: NEEDS.len(),
        ..statement(NAME, env!("CARGO_PKG_VERSION"), 64)
    },
    lifecycle: {
        validate: Safe<Validate>, open: Safe<Open>, refresh: Safe<Refresh>, retire: Safe<Retire>,
        tick: Safe<Tick>, drive: Safe<Drive>, cancel: Safe<Cancel>, release: Safe<Release>,
        close: Safe<Close>,
    },
    kind_ops: {
        arrive: Safe<Arrive>, on_piece: Safe<OnPiece>, refusal: Safe<Refusal>, serve: Safe<Serve>,
        hydrate: Safe<Hydrate>, start: Safe<Start>, project: Safe<Project>,
    },
}

#[cfg(test)]
#[path = "tests/ladder_tests.rs"]
mod ladder_tests;

const _: () = {
    // The ride constants name the needs they say they name.
    assert!(NEEDS[RIDES_REALTIME_SOCKET as usize - 1].direction == DIRECTION_OUTBOUND);
    assert!(NEEDS[RIDES_REALTIME_PASS as usize - 1].direction == DIRECTION_OUTBOUND);
    assert!(NEEDS[RIDES_LIVE_SOCKET as usize - 1].direction == DIRECTION_OUTBOUND);
    assert!(DIALECTS.len() == DIALECTS_BY_NAME.len());
};
