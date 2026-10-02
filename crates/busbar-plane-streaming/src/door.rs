// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STREAMING PLANE'S DOOR: the one function a compiled-in row holds and a dropped-in image
//! exports (`examples/streaming_door.rs`), and everything it states and answers.
//!
//! The composition root links [`door`] on its `plane-door` axis under the streaming fold's
//! development-only switch `streaming-on-driver` (`BUSBAR-1.6.0.md` Part 3, section 12, "The
//! switch") and binds it through the loader's one load beside the dropped-in plane doors. The
//! default build links no streaming door, and with the switch on the `busbar-voice` row still serves
//! every streaming route until the serve path hands this door the arrivals it takes.
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

use std::mem::size_of;
use std::ptr;
use std::sync::Mutex;

use busbar_contract::abi::host::conn::connector::{Need, DIRECTION_INBOUND, DIRECTION_OUTBOUND};
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, InHead, OutHead, Outcome, BLOB_ABSENT};
use busbar_contract::abi::mechanism::door::{
    KindTailHead, Section, Statement, SECTION_DECLARING, SECTION_REQUIRED,
};
use busbar_contract::abi::mechanism::lifecycle::{
    CancelIn, CancelOut, GenIn, RefreshIn, ReleaseIn, TickIn, TickOut, ValidateIn,
};
use busbar_contract::abi::plane::{
    ArriveIn, ArriveOut, BillableClass, DialectAuth, OnPieceIn, OnPieceOut, OpClass, PlaneDriveIn,
    PlaneDriveOut, PlaneOpenIn, PlaneOpenOut, PlaneRefreshOut, PlaneSnapshot, PlaneTail, ProjectIn,
    ProjectOut, RefusalIn, RefusalOut, ServeIn, ServeOut, UnitCount, CANCEL_FAILED, CLAIM_EXACT,
    CLAIM_OPEN, INGRESS_DUPLEX_SESSION, INGRESS_REQUEST_RESPONSE, SHAPE_PIECEWISE, UNITS_ESTIMATED,
};
use busbar_contract::abi::sdk::door::{abi_str, statement};
use busbar_contract::abi::sdk::publish::{ClaimSpec, SnapshotSpec};
use busbar_contract::abi::sdk::{Generations, Instance, Lent, Out, Safe, SafeSlot};
use busbar_contract::plane::{PER_SESSION, TOKEN_FAMILY};

use crate::claims::{Dialect, HTTP_TRANSPORT, WS_TRANSPORT};
use crate::config::StreamsCfg;
use crate::driven::Steps;
use crate::meta;
use crate::provider::{GEMINI_LIVE, OPENAI_REALTIME};

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

/// The dialects, in the order the per-call `dialect` index names them.
pub const DIALECTS_BY_NAME: &[&str] = &[
    OPENAI_REALTIME,
    GEMINI_LIVE,
    Dialect::TwilioMediaStreams.name(),
];

const DIALECTS: &[AbiStr] = &[
    abi_str(DIALECTS_BY_NAME[0]),
    abi_str(DIALECTS_BY_NAME[1]),
    abi_str(DIALECTS_BY_NAME[2]),
];

/// The upstream dialects' default auth styles.
const DIALECT_AUTH: &[DialectAuth] = &[DialectAuth {
    dialect: 0,
    _reserved: 0,
    style: abi_str("bearer"),
}];

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

/// The six classes a session counts in; `cached_tokens` is attribution only, never billed.
const BILLABLE_CLASSES: &[BillableClass] = &[
    class(meta::CLASS_AUDIO_TOKENS_IN.as_str(), TOKEN_FAMILY),
    class(meta::CLASS_AUDIO_TOKENS_OUT.as_str(), TOKEN_FAMILY),
    class(meta::CLASS_TEXT_TOKENS_IN.as_str(), TOKEN_FAMILY),
    class(meta::CLASS_TEXT_TOKENS_OUT.as_str(), TOKEN_FAMILY),
    class(meta::CLASS_AUDIO_SECONDS_IN.as_str(), "duration"),
    class(meta::CLASS_TOOL_CALLS.as_str(), "count"),
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
    }
}

/// The plane's connection needs: its keyed doors and its telephony door inbound; the provider's
/// realtime socket and its one-shot passes outbound, to the upstream `streams.session.model` names.
/// The outbound credential is the kernel's, per the dialect's default style.
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
        NONE,
        abi_str(EGRESS_TARGET),
    ),
    need(
        DIRECTION_OUTBOUND,
        HTTP_TRANSPORT,
        NONE,
        abi_str(EGRESS_TARGET),
    ),
];

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

/// One open plane instance.
pub struct Plane {
    /// The deployment's public base URL, as `open` read it; a refresh keeps it.
    public_url: Option<String>,
    /// The live generations' settings and answers, oldest first (control lane only).
    generations: Mutex<Vec<(StreamsCfg, Generation)>>,
    /// The published snapshots, held by the SDK until their generation's `retire`.
    snapshots: Generations<PlaneSnapshot>,
}

impl Plane {
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
    let p = Plane {
        public_url,
        generations: Mutex::new(Vec::new()),
        snapshots: Generations::new(),
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

slot!(Tick, TickIn, TickOut, |_, _, out| {
    out.set(|o| &o.next_tick_ns, 0);
    Outcome::Ready
});

slot!(Drive, PlaneDriveIn, PlaneDriveOut, |_, _, _out| {
    Outcome::Ready
});

slot!(Cancel, CancelIn, CancelOut, |_, _, out| {
    out.set(|o| &o.disposition, CANCEL_FAILED);
    Outcome::Ready
});

slot!(Release, ReleaseIn, OutHead, |_, _, _out| { Outcome::Ready });

slot!(Close, InHead, OutHead, |_, _, _out| { Outcome::Ready });

// A claimed arrival is classified: its door's dialect, the session open, a known principal. No
// admission estimate: a session's units are what the far end reports.
slot!(Arrive, ArriveIn, ArriveOut, |_, input, out| {
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
    Outcome::Ready
});

// The door serves no unit's pieces yet: every piece, refusal render, admin serve and projection is
// declined, and a declined unit is charged nothing.

slot!(OnPiece, OnPieceIn, OnPieceOut, |_, _, _out| {
    Outcome::Refused
});

slot!(Refusal, RefusalIn, RefusalOut, |_, _, _out| {
    Outcome::Refused
});

slot!(Serve, ServeIn, ServeOut, |_, _, _out| { Outcome::Refused });

slot!(Hydrate, GenIn, OutHead, |_, _, _out| { Outcome::Ready });

slot!(Start, GenIn, OutHead, |_, _, _out| { Outcome::Ready });

slot!(Project, ProjectIn, ProjectOut, |_, _, _out| {
    Outcome::Refused
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
