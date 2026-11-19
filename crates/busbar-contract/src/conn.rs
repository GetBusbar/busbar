// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CONNECTION TABLE (the design's connections: "every plugin that needs an external connection

pub mod codes;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use crate::ids::StreamId;
use crate::rendering::ReadNeed;
use crate::secure::SecureString;
use crate::transport::wire::{WireFault, WireStatusClass};
use crate::transport::ConnFacts;

/// The frozen bytes an [`OpenDesc`] carries its body in.
pub use bytes::Bytes;

pub mod admissions;
/// Typed, declaration-directed inbound listener admission.
pub mod inbound;

/// A plugin instance, as the host numbers it. Never stated by a plugin: the host reads it off the
/// instance's own context.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct InstanceId(pub u64);

/// One need a plugin declared, by its position in the plugin's declared needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NeedId(pub u32);

/// An open connection. Its value carries a generation, so a closed id never names a later
/// connection that reused its slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnId(pub u64);

/// What opening a connection asks for: where, the head fields and body to open with (a framed
/// transport sends them as its first message; a raw byte stream takes none), and how long the open
/// may take.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct OpenDesc<'a> {
    /// The target, as the operator's settings spell it (the need's `target_from`).
    pub target: &'a str,
    /// Head fields, in order.
    pub fields: &'a [(&'a str, &'a [u8])],
    /// Host-completed protocol defaults; never accepted from a plugin ABI descriptor.
    pub completed_head: Option<&'a CompletedHead>,
    /// The body sent with the opening message: frozen once by the opener, so a connector that
    /// keeps it (and a retry that opens again) takes a reference, never a copy.
    pub body: Bytes,
    /// Milliseconds the open may take; `0` = the host's default.
    pub timeout_ms: u64,
    /// The opening message's method, a head word (`RequestPiece::method`); empty = none. A framer
    /// whose wire has head words takes it as the request's own, byte for byte; one without ignores
    /// it.
    pub method: &'a [u8],
    /// The opening message's target, a head word (`RequestPiece::target`: the path and query, or
    /// what the framer's protocol names a target); empty = none.
    pub head_target: &'a [u8],
    /// The addresses the dial must land on (`EstablishIn::within`): the address the judgement
    /// pins is held against them at the connect, before any byte is written, and one outside
    /// them refuses the open. Empty = no pin beyond the judgement's own.
    pub within: &'a [IpAddr],
    /// The REGISTRATION this open reaches, by its name in its plane's declaring section, where the
    /// opener names one (a member route's walk; a plane's own stream that names it,
    /// `EstablishIn::member`); empty = none. What the host sealed for that registration alone (its
    /// private reach, [`PollConns::seal_reach`]) applies to this open and to no other.
    pub member: &'a str,
    /// The UNIT this open serves, by its kernel-minted unit key, where the opener runs one (a
    /// unit's walk, `UnitRoute::unit`); `0` = none. What the host registered for that unit alone
    /// applies to this open and to no other; an open whose transport needs no such registration
    /// ignores it.
    pub unit: u64,
    /// HOST-ONLY, never accepted from a plugin ABI descriptor: the opener judged this open under its
    /// owner's core-held `insecure_transport.accept` (`transport_verdict`) and the acceptance
    /// admits PLAINTEXT to `target` (SEC-2, #297 model A). The connector admits a dial that is not
    /// secured from its first byte only so, or by an exact `advanced.tls.destinations` plaintext
    /// entry; no loopback address or name is exempt.
    pub plaintext_accepted: bool,
}

impl std::fmt::Debug for OpenDesc<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenDesc")
            .field("target", &self.target)
            .field("fields", &"<redacted>")
            .field("body", &"<redacted>")
            .field("timeout_ms", &self.timeout_ms)
            .field("method", &self.method)
            .field("head_target", &"<redacted>")
            .field("within", &self.within)
            .field("member", &self.member)
            .field("unit", &self.unit)
            .field("plaintext_accepted", &self.plaintext_accepted)
            .finish()
    }
}

/// What a piece a connection delivered carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PieceKind {
    /// Payload bytes.
    Body,
    /// A head: the far end's fields, as the field block
    /// ([`crate::transport::codes::fields`]) renders them, hop-by-hop fields dropped. The far end's
    /// HEAD is ONE fields frame, the answer's FIRST, carrying the status; it comes even when empty
    /// (a `len` of `0`), so it always precedes the first [`PieceKind::Body`]. A fields frame after
    /// the body is the far end's trailers.
    Fields,
    /// A hook's answer.
    HookReply,
    /// The exchange finished; no bytes.
    Completion,
}

/// One piece a connection delivered: what it is, the stream it came on, how many bytes of the
/// caller's buffer it filled, whether it ends its frame, and the status it reports where the wire
/// reports one — in the numbering `status_namespace` names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Piece {
    /// What the piece carries.
    pub kind: PieceKind,
    /// The stream it came on (`StreamId(0)` on a wire with one).
    pub stream: StreamId,
    /// How many bytes of the caller's buffer it filled.
    pub len: usize,
    /// This piece ends its frame.
    pub end: bool,
    /// The status class it reports.
    pub status: Option<WireStatusClass>,
    /// The exact status number it reports.
    pub status_code: Option<u32>,
    /// The numbering `status_code` is spelled in.
    pub status_namespace: Option<String>,
    /// How long the far side asked to be left alone, in seconds.
    pub retry_after_secs: Option<u64>,
    /// The transport's fault reading of the status, for the breaker (`None`: none stated, read as
    /// the caller's).
    pub fault: Option<WireFault>,
    /// On the far end's HEAD (a [`PieceKind::Fields`] that ends its frame): where in the caller's
    /// buffer its reason phrase is, exactly as sent, right after the field block's bytes. `None`
    /// where the wire has none (HTTP/2) or the caller's buffer could not also hold it.
    pub reason: Option<core::ops::Range<usize>>,
    /// On a head ([`PieceKind::Fields`]): the body length the message's head declared on the wire,
    /// as the framer stated it (`abi::transport::PIECE_HAS_DECLARED_LEN`); `None` where it stated
    /// none. The host hands it on as the framer stated it, never reading or checking it: a
    /// statement, not a count of the body pieces to come.
    pub declared_len: Option<u64>,
}

/// How much of a request to a far end the operating system accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Sent {
    /// Not one byte of it: the far end received nothing. Another attempt cannot cost twice.
    None,
    /// Some of it: the far end received an incomplete request.
    Part,
    /// All of it, through its end mark, flushed: the far end may have acted and may charge.
    Whole,
}

impl Sent {
    /// The word the record carries.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Part => "part",
            Self::Whole => "whole",
        }
    }
}

/// What the engine did about one attempt's end.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AttemptEnd {
    /// A kept connection turned out closed with nothing sent: the request was sent again on a fresh
    /// connection. The far end is not charged and the walk is not told.
    Redialled,
    /// The far end stated it did not act on the request: it was sent again once.
    RefusedUnprocessed,
    /// The operator's proxy failed: no far end was reached and none is charged.
    AtProxy,
    /// The attempt failed and was left to the walk.
    Failed,
    /// The engine's own fault: nobody is charged.
    Local,
}

/// The evidence of one attempt at a far end.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AttemptEvidence {
    /// What the operating system accepted of the request.
    pub sent: Sent,
    /// What the engine did about the attempt's end.
    pub end: AttemptEnd,
}

/// Why a connection operation did not answer with what was asked. The refusals carry the text an
/// operator reads.
///
/// Not exhaustive: a new cause is a new variant, and a plugin's match on it keeps a wildcard arm.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ConnError {
    /// Nothing is ready yet. Interest is registered for the caller's [`Ticket`]; the host wakes the
    /// ticket when something is, and the caller asks again then. Never a block.
    Pending,
    /// The operation's deadline CLASS passed, as the host enforces it.
    Timeout,
    /// The connection is closed, or was never opened.
    Closed,
    /// The connection belongs to another plugin instance.
    NotOwner,
    /// The caller never declared this need.
    UndeclaredNeed,
    /// The open was refused (the target, the egress rules, or the far end said no).
    Refused,
    /// The host failed the call.
    Fault,
    /// The plugin was handed no connection table: its host's open/refresh tables gave THIS instance
    /// none. Decided per instance, never per image.
    Unarmed,
    /// The credential the request is sent with, re-resolved for this request, is unavailable:
    /// nothing was presented and nothing was sent. A cause of its own so the plugin can tell a
    /// vanished secret from a refusal by the target, the egress rules or the far end.
    CredentialUnavailable,
    /// The request's auth REFUSED it: the bound auth answered stop, so nothing was sent. An auth
    /// outcome, never the destination failing: nothing is recorded against the destination, and
    /// the walk moves on as it does for an auth that answers nothing.
    AuthRefused,
    /// The request's auth FAILED: the auth call itself could not complete (the auth plugin
    /// faulted, refused the call or ran out of time), so nothing was sent. An auth outcome, never
    /// the destination failing, as [`ConnError::AuthRefused`].
    AuthFailed,
}

impl ConnError {
    /// The refusal's text, as an operator reads it.
    #[must_use]
    pub const fn text(self) -> &'static str {
        match self {
            Self::Pending => "nothing is ready on the connection yet",
            Self::Timeout => "the connection's deadline passed",
            Self::Closed => "the connection is closed",
            Self::NotOwner => "the connection belongs to another plugin instance",
            Self::UndeclaredNeed => "the plugin did not declare this need",
            Self::Refused => "the connection was refused",
            Self::Fault => "the host failed the connection call",
            Self::Unarmed => "this plugin was handed no connection table",
            Self::CredentialUnavailable => {
                "the request's credential is unavailable; nothing was sent"
            }
            Self::AuthRefused => "the request's auth refused it; nothing was sent",
            Self::AuthFailed => "the request's auth call failed; nothing was sent",
        }
    }

    /// Whether this is an AUTH outcome ([`ConnError::AuthRefused`], [`ConnError::AuthFailed`]):
    #[must_use]
    pub const fn is_auth(self) -> bool {
        matches!(self, Self::AuthRefused | Self::AuthFailed)
    }
}

impl std::fmt::Display for ConnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.text())
    }
}

impl std::error::Error for ConnError {}

/// THE CALLER'S WAKE TICKET: an opaque number the caller mints for the task waiting on a read or a
pub type Ticket = u64;

/// The ticket that names no waiting task: a call handed it registers no interest.
pub const NO_TICKET: Ticket = 0;

/// HOW A TABLE WAKES A CALLER'S TICKET: the caller the interest was registered for, and its ticket.
pub type ConnWake = std::sync::Arc<dyn Fn(InstanceId, Ticket) + Send + Sync>;

/// THE HOST'S CONNECTION TABLE, as the host implements it. Every method names the `caller`, which
pub trait Conns: Send + Sync {
    /// Open a connection for the caller's declared `need`.
    fn open(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
    ) -> Result<ConnId, ConnError>;

    /// Open while preserving the auth field batch's required connection security. A table that
    fn open_with_security(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
        require_secure: bool,
    ) -> Result<ConnId, ConnError> {
        if require_secure {
            return Err(ConnError::AuthRefused);
        }
        self.open(caller, need, desc)
    }

    /// [`Conns::open_with_security`], dialling the answer [`PollConns::locate_head`] already
    /// located for this open where the table carries one. A table that carries none (the default)
    /// ignores `located` and locates as it always does.
    fn open_located(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
        require_secure: bool,
        located: Option<&Arc<LocatedTarget>>,
    ) -> Result<ConnId, ConnError> {
        let _ = located;
        self.open_with_security(caller, need, desc, require_secure)
    }

    /// [`Conns::open_located`], opening with `head` as its fields in place of `desc.fields` (which
    /// a caller of this leaves empty): the table takes the head the opener built and keeps it for
    /// the dial without copying it again. A table that keeps none (the default) lends a view of
    /// `head` as `desc.fields` to [`Conns::open_located`], exactly as an opener lending it would,
    /// and the head's values are wiped when it drops.
    fn open_owned(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
        head: OwnedHead,
        require_secure: bool,
        located: Option<&Arc<LocatedTarget>>,
    ) -> Result<ConnId, ConnError> {
        let fields = head.view();
        self.open_located(
            caller,
            need,
            &OpenDesc {
                fields: &fields,
                ..desc.clone()
            },
            require_secure,
            located,
        )
    }

    /// Offer `bytes` to the connection (`end` = the caller's message is complete, `text` = it is a
    fn write(
        &self,
        caller: InstanceId,
        conn: ConnId,
        bytes: &[u8],
        end: bool,
        text: bool,
    ) -> Result<usize, ConnError>;

    /// The next piece, its bytes into `buf`; with nothing ready, [`ConnError::Pending`] and interest
    fn read(
        &self,
        caller: InstanceId,
        conn: ConnId,
        ticket: Ticket,
        buf: &mut [u8],
    ) -> Result<Piece, ConnError>;

    /// The position in `set` of a connection with a piece ready; with none ready,
    fn wait(&self, caller: InstanceId, set: &[ConnId], ticket: Ticket) -> Result<usize, ConnError>;

    /// What connection security established on the connection.
    fn facts(&self, caller: InstanceId, conn: ConnId) -> Result<ConnFacts, ConnError>;

    /// Close the connection.
    fn close(&self, caller: InstanceId, conn: ConnId) -> Result<(), ConnError>;
}

/// WHY A CONNECTION FAILED, as the host's table names it: the stage (`CAUSE_CONNECT`,
/// `CAUSE_SECURITY`, `CAUSE_EXCHANGE`, `CAUSE_DEADLINE`, `CAUSE_FRAMER`) and the underlying
/// error's own text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnCause {
    /// The `CAUSE_*` stage.
    pub stage: u64,
    /// The underlying error's own text (empty for a deadline).
    pub text: String,
    /// HOST-ONLY, never lowered to the ABI: raised only with `CAUSE_FRAMER`, and only when the
    /// framer crossing that failed was the host's OUTBOUND emit (an opening or a write it
    /// rendered for the far end), never an ingest of the far end's bytes, a resume or a socket
    /// read. Such a fault is the host's own: no member can cure it and none is to blame for it.
    pub outbound: bool,
}

/// WHY A NEED OR A CONNECTION FAILED BEFORE A LINE EXISTED, as the host's own table knows it
/// (host-only: never crosses the ABI; a plugin reads [`DeclaredConns::cause`] alone). It says who
/// failed: the host's own policy (nothing was dialled) or the path, and on the path which hop: the
/// target or the operator's egress proxy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NeedRefusal {
    /// The host's own policy refused the target. Nothing was dialled.
    Policy(&'static str),
    /// The path to the target failed before a line existed: a DNS outcome, or a dial failure's
    /// text (a far-end or unix-socket refusal alike, so it is never [`NeedRefusal::Policy`]).
    Unreached(String),
    /// The host's own policy refused the operator's egress proxy. Nothing was dialled.
    ProxyPolicy(&'static str),
    /// The hop to the operator's egress proxy failed: its DNS outcome, or its dial's text.
    ProxyUnreached(String),
}

impl NeedRefusal {
    /// THE ONE RENDERER: the reason in words naming who failed. `scrub` is applied to the dynamic
    /// (`*Unreached`) text only; every policy text is static.
    pub fn render(&self, scrub: impl Fn(&str) -> String) -> String {
        match self {
            Self::Policy(t) => format!("busbar refused it before connecting: {t}"),
            Self::Unreached(t) => format!("could not connect to the registry: {}", scrub(t)),
            Self::ProxyPolicy(t) => format!("busbar refused the egress proxy: {t}"),
            Self::ProxyUnreached(t) => {
                format!("could not connect to the egress proxy: {}", scrub(t))
            }
        }
    }
}

/// THE HOST'S CONNECTION TABLE, as the host declares an instance's needs on it (host-side: never
pub trait DeclaredConns: Conns {
    /// Record that `owner` declared `need` (its index in the instance's Statement), as the Statement
    fn declare(
        &self,
        owner: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        target: Option<&str>,
        trust: Option<&str>,
    ) -> Result<(), ConnError>;

    /// What [`DeclaredConns::declare`] answered for `owner`'s `need`; `None` = never declared.
    fn declared(&self, owner: InstanceId, need: NeedId) -> Option<Result<(), ConnError>>;

    /// Open with a dial bound separate from the whole request's [`OpenDesc::timeout_ms`].
    fn open_request(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
        require_secure: bool,
        dial_timeout_ms: u64,
    ) -> Result<ConnId, ConnError> {
        if dial_timeout_ms != 0 && dial_timeout_ms != desc.timeout_ms {
            return Err(ConnError::Refused);
        }
        self.open_with_security(caller, need, desc, require_secure)
    }

    /// Prepare a framed transport without sending an application request. The returned connection
    /// owns the original dial/deadline and exposes only actual established security through
    /// `landed`/`facts`. It is committed on that same connection by `commit_request` or closed.
    /// Tables without this capability refuse; opening a replacement request is not a fallback.
    fn prepare_request(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
        dial_timeout_ms: u64,
    ) -> Result<ConnId, ConnError> {
        let _ = (caller, need, desc, dial_timeout_ms);
        Err(ConnError::Refused)
    }

    /// Commit the framed request on its prepared connection, exactly once. Target/ownership,
    /// original deadlines and required actual connection security remain enforced by the host.
    /// Pending must leave the request uncommitted; retry must never duplicate its wire bytes.
    fn commit_request(
        &self,
        caller: InstanceId,
        conn: ConnId,
        desc: &OpenDesc<'_>,
        require_secure: bool,
    ) -> Result<(), ConnError> {
        let _ = (caller, conn, desc, require_secure);
        Err(ConnError::Refused)
    }

    /// UPGRADE `conn`, an open raw byte stream, to connection security from its next byte on
    fn upgrade_secure(
        &self,
        caller: InstanceId,
        conn: ConnId,
        name: Option<&str>,
        trust: Option<&str>,
        verify_off: bool,
        ticket: Ticket,
    ) -> Result<(), ConnError> {
        let _ = (caller, conn, name, trust, verify_off, ticket);
        Err(ConnError::Refused)
    }

    /// WHETHER `conn`'s DIAL HAS LANDED: the far end took the connect. An open answers with its
    fn landed(&self, caller: InstanceId, conn: ConnId, ticket: Ticket) -> Result<(), ConnError> {
        let _ = (caller, conn, ticket);
        Ok(())
    }

    /// Whether `owner`'s `need` is carried over a FRAMED transport (a framer composed over a
    fn framed(&self, owner: InstanceId, need: NeedId) -> bool {
        let _ = (owner, need);
        false
    }

    /// Whether a loaded transport serves `transport` (a need's scheme). THE BOOT'S SCHEME MATCH
    fn serves_scheme(&self, transport: &str) -> bool;

    /// Record that `owner` declared `need` (as [`DeclaredConns::declare`]), its target a PROGRAM
    fn declare_program(
        &self,
        owner: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        program: &Program,
    ) -> Result<(), ConnError> {
        let _ = (owner, need, spec, program);
        Err(ConnError::Refused)
    }

    /// Why `owner`'s connection `conn` failed, once it has: where (a `CAUSE_*` stage) and the
    fn cause(&self, owner: InstanceId, conn: ConnId) -> Option<ConnCause> {
        let _ = (owner, conn);
        None
    }

    /// Why `owner`'s `need` failed at `declare` or `open`, before any connection existed (the latest
    /// such failure; every `declare` overwrites it). `None` = none held, or this table keeps none.
    fn refusal(&self, owner: InstanceId, need: NeedId) -> Option<NeedRefusal> {
        let _ = (owner, need);
        None
    }

    /// Why `owner`'s `conn` failed while judging or dialling, before a line existed. `None` = none.
    fn conn_refusal(&self, owner: InstanceId, conn: ConnId) -> Option<NeedRefusal> {
        let _ = (owner, conn);
        None
    }

    /// THE HOST WRITES THE AUTHORITY of every connection `owner` opens: an open whose head
    fn hold_authority(&self, owner: InstanceId) {
        let _ = owner;
    }

    /// THE OWNER'S CORE-HELD `insecure_transport.accept` HOLDS `plaintext` (SEC-2, #297 model A):
    /// the host registers it when it binds `owner`, after the acceptance was logged and audited
    /// (BUSBAR-3162), and every open `owner` makes may then dial without TLS from the first byte.
    /// No other open is admitted plaintext but by its own [`OpenDesc::plaintext_accepted`] or an
    /// exact `advanced.tls.destinations` entry; no loopback address or name is exempt. The default
    /// registers nothing: plaintext stays refused. [`DeclaredConns::forget`] drops it.
    fn accept_plaintext(&self, owner: InstanceId) {
        let _ = owner;
    }

    /// The framer's complete defaults before auth signs the request. `timeout_ms` is the
    /// remaining attempt budget; zero means no deadline. Empty `target` uses the need's target.
    fn request_head(
        &self,
        owner: InstanceId,
        need: NeedId,
        target: &str,
        timeout_ms: u64,
    ) -> Result<HeadDefaults, ConnError> {
        let _ = (owner, need, target, timeout_ms);
        Ok(HeadDefaults::default())
    }

    /// Hold `binding` as the auth binding of `owner`'s requests on `need` that name the
    fn bind_auth(
        &self,
        owner: InstanceId,
        need: NeedId,
        member: &str,
        origin: &str,
        binding: ConnAuth,
    ) {
        let _ = (owner, need, member, origin, binding);
    }

    /// The binding [`DeclaredConns::bind_auth`] holds for `owner`'s requests on `need` that name
    fn auth_of(
        &self,
        owner: InstanceId,
        need: NeedId,
        member: &str,
        target: &str,
    ) -> Option<ConnAuth> {
        let _ = (owner, need, member, target);
        None
    }

    /// Record that `owner` declared `need` (as [`DeclaredConns::declare`]), its `target_from` the
    fn declare_member_programs(
        &self,
        owner: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        programs: &[(String, Program)],
    ) -> Result<(), ConnError> {
        let _ = (owner, need, spec, programs);
        Err(ConnError::Refused)
    }

    /// Declare member programs for a successor of the same loaded instance's CURRENT published
    fn declare_member_programs_from(
        &self,
        predecessor: InstanceId,
        owner: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        programs: &[(String, Program)],
    ) -> Result<(), ConnError> {
        let _ = predecessor;
        self.declare_member_programs(owner, need, spec, programs)
    }

    /// THE INSTANCE IS GONE (closed, replaced by a reload, or quarantined): it never crosses
    fn forget(&self, owner: InstanceId) {
        let _ = owner;
    }
}

/// THE ORIGIN of a URL, `scheme://authority`: what a member's route is sealed at and its binding
#[must_use]
pub fn origin_of(url: &str) -> &str {
    let before_query = url.find(['?', '#']).unwrap_or(url.len());
    let after = url[..before_query].find("://").map_or(0, |at| at + 3);
    let end = url[after..]
        .find(['/', '?', '#'])
        .unwrap_or(url.len() - after);
    &url[..after + end]
}

/// THE FRAMER'S OWN HEAD, located at a target ([`PollConns::head_defaults`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HeadDefaults {
    /// Its own head lines, `(name, value)`, in the framer's order.
    pub lines: Vec<(Vec<u8>, Vec<u8>)>,
    /// Whether its head states the body's length (`LocateOut::states_length`): the framer renders
    /// no length of its own, so the host states `content-length` for a non-empty body, last,
    /// before the auth signs the head ([`HeadDefaults::completing`]).
    pub states_length: bool,
}

/// Provenance for the exact protocol defaults the host appended before authentication.
/// This host-side Rust value has no plugin ABI representation or public fields.
#[derive(Clone, PartialEq, Eq)]
pub struct CompletedHead {
    caller: InstanceId,
    need: NeedId,
    target: String,
    body_len: usize,
    defaults: Vec<(Vec<u8>, Vec<u8>)>,
}

impl std::fmt::Debug for CompletedHead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompletedHead")
            .field("default_count", &self.defaults.len())
            .field("body_len", &self.body_len)
            .finish_non_exhaustive()
    }
}

impl CompletedHead {
    /// The exact suffix authentication must observe and submission must preserve.
    pub fn fields(&self) -> &[(Vec<u8>, Vec<u8>)] {
        &self.defaults
    }

    /// Validate custody and return the prefix still subject to caller-field restrictions.
    pub fn caller_field_count(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
    ) -> Option<usize> {
        if caller != self.caller
            || need != self.need
            || desc.target != self.target
            || desc.body.len() != self.body_len
        {
            return None;
        }
        let count = desc.fields.len().checked_sub(self.defaults.len())?;
        let (prefix, suffix) = desc.fields.split_at(count);
        if !suffix
            .iter()
            .zip(&self.defaults)
            .all(|((name, value), (n, v))| name.as_bytes() == n && *value == v.as_slice())
            || prefix.iter().any(|(name, _)| {
                self.defaults
                    .iter()
                    .any(|(n, _)| name.trim_ascii().as_bytes().eq_ignore_ascii_case(n))
            })
        {
            return None;
        }
        Some(count)
    }
}

/// ONE OUTBOUND HEAD, OWNED: the opening's fields, in order, built once by the opener and moved
/// into the open that sends them ([`Conns::open_owned`]), so a table keeps this very head for its
/// dial instead of copying a borrowed one. Every value is wiped when the head drops.
#[doc = "host-side; no ABI representation"]
#[derive(Default)]
pub struct OwnedHead(Vec<(String, Vec<u8>)>);

impl OwnedHead {
    /// An empty head with room for `capacity` fields.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self(Vec::with_capacity(capacity))
    }

    /// Append one field.
    pub fn push(&mut self, name: String, value: Vec<u8>) {
        self.0.push((name, value));
    }

    /// The head as the borrowed fields an [`OpenDesc`] lends, in order.
    #[must_use]
    pub fn view(&self) -> Vec<(&str, &[u8])> {
        self.0
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_slice()))
            .collect()
    }

    /// Wipe every field's value in place (dropping the head does this too).
    pub fn wipe(&mut self) {
        for (_, value) in &mut self.0 {
            zeroize::Zeroize::zeroize(value);
        }
    }

    /// The fields themselves, for a table that keeps them (and wipes their values when it lets
    /// them go).
    #[must_use]
    pub fn into_fields(mut self) -> Vec<(String, Vec<u8>)> {
        std::mem::take(&mut self.0)
    }
}

impl Extend<(String, Vec<u8>)> for OwnedHead {
    fn extend<I: IntoIterator<Item = (String, Vec<u8>)>>(&mut self, fields: I) {
        self.0.extend(fields);
    }
}

impl Drop for OwnedHead {
    fn drop(&mut self) {
        self.wipe();
    }
}

impl std::fmt::Debug for OwnedHead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnedHead")
            .field("fields", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// ONE LOCATE ANSWER, carried from the head's completion to the open that dials it
/// ([`PollConns::locate_head`], [`Conns::open_located`]): where the framer `need` rides said
/// `target` is. A table reads it only when the caller, need and target all equal the dial's own;
/// any other open locates afresh.
#[doc = "host-side; no ABI representation"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocatedTarget {
    caller: InstanceId,
    need: NeedId,
    target: String,
    authority: String,
    name: Option<String>,
    secure: bool,
    offer: Vec<Vec<u8>>,
    defaults: Vec<(Vec<u8>, Vec<u8>)>,
    states_length: bool,
}

impl LocatedTarget {
    /// The answer the framer gave for `caller`'s `need` at `target`.
    #[must_use]
    pub fn new(
        caller: InstanceId,
        need: NeedId,
        target: String,
        authority: String,
        name: Option<String>,
        secure: bool,
        offer: Vec<Vec<u8>>,
        defaults: Vec<(Vec<u8>, Vec<u8>)>,
        states_length: bool,
    ) -> Self {
        Self {
            caller,
            need,
            target,
            authority,
            name,
            secure,
            offer,
            defaults,
            states_length,
        }
    }

    /// Whether this answer was located for `caller`'s `need` at exactly `target`.
    #[must_use]
    pub fn answers(&self, caller: InstanceId, need: NeedId, target: &str) -> bool {
        self.caller == caller && self.need == need && self.target == target
    }

    /// The authority to dial (`host:port`).
    #[must_use]
    pub fn authority(&self) -> &str {
        &self.authority
    }

    /// The name to offer the far end, where one is.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Whether the target asks for connection security.
    #[must_use]
    pub fn secure(&self) -> bool {
        self.secure
    }

    /// The framer's protocol offer for the handshake, most preferred first.
    #[must_use]
    pub fn offer(&self) -> &[Vec<u8>] {
        &self.offer
    }

    /// The framer's own head lines, in its order.
    #[must_use]
    pub fn defaults(&self) -> &[(Vec<u8>, Vec<u8>)] {
        &self.defaults
    }

    /// Whether the framer's head states its body's length.
    #[must_use]
    pub fn states_length(&self) -> bool {
        self.states_length
    }
}

/// The one line the host states for a framer whose head states the body's length.
pub const CONTENT_LENGTH: &[u8] = b"content-length";

impl HeadDefaults {
    /// Complete a host-selected framer's head, binding its defaults to this request.
    /// Call only with the result of the connection table's `request_head`, before auth.
    pub fn completed_for(
        &self,
        caller: InstanceId,
        need: NeedId,
        target: &str,
        carried: impl Fn(&[u8]) -> bool,
        body_len: usize,
    ) -> Result<CompletedHead, ConnError> {
        let defaults = self.completing(carried, body_len);
        let legal_value = |bytes: &[u8]| {
            bytes
                .iter()
                .all(|&b| (b >= 0x20 && b != 0x7F) || b == b'\t')
        };
        for (index, (name, value)) in defaults.iter().enumerate() {
            if !crate::header::is_header_name_token(name)
                || !legal_value(value)
                || name.eq_ignore_ascii_case(b"transfer-encoding")
                || defaults[..index]
                    .iter()
                    .any(|(n, _)| n.eq_ignore_ascii_case(name))
                || name.eq_ignore_ascii_case(CONTENT_LENGTH)
                    && (!self.states_length || value != body_len.to_string().as_bytes())
            {
                return Err(ConnError::Refused);
            }
        }
        Ok(CompletedHead {
            caller,
            need,
            target: target.to_owned(),
            body_len,
            defaults,
        })
    }

    /// THE LINES THE HOST ADDS to a request head (THE DESIGN section 6, step 5: nothing is added
    #[must_use]
    pub fn completing(
        &self,
        carried: impl Fn(&[u8]) -> bool,
        body_len: usize,
    ) -> Vec<(Vec<u8>, Vec<u8>)> {
        Self::completing_lines(&self.lines, self.states_length, carried, body_len)
    }

    /// [`HeadDefaults::completing`] over lent `lines`: the same lines added, for a holder that
    /// shares its locate answer and so lends the framer's lines instead of handing them over.
    #[must_use]
    pub fn completing_lines(
        lines: &[(Vec<u8>, Vec<u8>)],
        states_length: bool,
        carried: impl Fn(&[u8]) -> bool,
        body_len: usize,
    ) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut added: Vec<(Vec<u8>, Vec<u8>)> = lines
            .iter()
            .filter(|(name, _)| !carried(name))
            .cloned()
            .collect();
        if states_length
            && body_len != 0
            && !carried(CONTENT_LENGTH)
            && !added
                .iter()
                .any(|(n, _)| n.eq_ignore_ascii_case(CONTENT_LENGTH))
        {
            added.push((CONTENT_LENGTH.to_vec(), body_len.to_string().into_bytes()));
        }
        added
    }
}

/// THE CREDENTIAL A UNIT LENDS its passthrough member (the kernel's caller-credential lending): the
pub trait LendCredential: Send + Sync {
    /// The credential `unit`'s caller presented, while the unit runs; `None` when it presented
    fn lent(&self, unit: u64) -> Option<crate::redacted::SharedSecret>;
}

/// ONE MEMBER'S AUTH BINDING, as the connector holds it for a plugin's own requests to that member
/// ([`DeclaredConns::bind_auth`]): the auth instance serving the member's style and the handle its
/// `open_outbound` answered, the style's flags and points, whether the member relays its caller's
/// credential (passthrough), and where that credential is lent from.
#[derive(Clone)]
pub struct ConnAuth {
    /// The auth instance serving the member's style.
    pub auth: Arc<dyn crate::auth_calls::OutboundAuth>,
    /// The handle `open_outbound` answered.
    pub handle: u64,
    /// `abi::auth::STYLE_NEEDS_HEADERS`.
    pub style_flags: u32,
    /// The style's `StyleDecl::points`.
    pub points: crate::route::AuthPoints,
    /// The member relays its caller's own verified credential: a request made inside a unit is
    /// lent that unit's ([`ConnAuth::lender`]); one made inside no unit has no caller, and opens
    /// nothing.
    pub passthrough: bool,
    /// Where a passthrough member's credential is lent from, by unit.
    pub lender: Option<Arc<dyn LendCredential>>,
    /// A binding refreshed off the request path ([`crate::auth_calls::PerRequestHandle`]): its
    /// current handle is asked for each request, in place of [`ConnAuth::handle`]. `None` = the
    /// handle stands for the generation.
    pub per_request: Option<Arc<dyn crate::auth_calls::PerRequestHandle>>,
}

impl std::fmt::Debug for ConnAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnAuth")
            .field("handle", &self.handle)
            .field("style_flags", &self.style_flags)
            .field("passthrough", &self.passthrough)
            .finish_non_exhaustive()
    }
}

/// THE OPENER'S SEALED FIELDS (TSEAL): a field of this name in an open's fields is the HOST'S,
pub const SEALED_FIELDS_FIELD: &str = "busbar-sealed-fields";

/// One host-owned auth query pair, percent-encoded as `name=value`. Repeated entries retain
pub const SEALED_QUERY_FIELD: &str = "busbar-sealed-query";

/// Whether a field carries the host's auth query metadata, never a wire header.
#[must_use]
pub fn is_sealed_query_field(name: &[u8]) -> bool {
    name.eq_ignore_ascii_case(SEALED_QUERY_FIELD.as_bytes())
}

/// Whether the field `name` is [`SEALED_FIELDS_FIELD`] (a field name compares case-insensitively).
#[must_use]
pub fn is_sealed_fields_field(name: &[u8]) -> bool {
    name.eq_ignore_ascii_case(SEALED_FIELDS_FIELD.as_bytes())
}

/// Host-only open constraint: the member incarnation previously observed in its first HEAD.
pub const PROGRAM_EXPECT_INSTANCE_FIELD: &str = "program-expect-instance";

/// Host-only generation constraint paired with [`PROGRAM_EXPECT_INSTANCE_FIELD`]. Both fields
pub const PROGRAM_EXPECT_GENERATION_FIELD: &str = "program-expect-generation";

/// The registration key a member's program environment is read from ([`Program::from_settings`]).
pub const PROGRAM_ENV_KEY: &str = "env";

/// The registration keys a member's program is read from ([`Program::of_member`]).
pub const PROGRAM_KEYS: [&str; 4] = ["command", "args", PROGRAM_ENV_KEY, "cwd"];

/// A PROGRAM a need dials (its `transport` a byte-stream framer the program's pipes carry): the
/// executable path, arguments, environment and optional working directory read from settings.
/// No shell; the child inherits no environment the settings did not write down. An environment
/// value may be secret, so it never prints ([`std::fmt::Debug`] shows names and byte counts).
#[derive(Clone, PartialEq, Eq)]
pub struct Program {
    /// The executable's absolute path.
    pub command: String,
    /// The child's absolute working directory, or the host's inherited directory when omitted.
    pub cwd: Option<String>,
    /// Its arguments, in order (not including the command).
    pub args: Vec<String>,
    /// Its environment entries written as values, name and value, in the settings' order.
    pub env: Vec<(String, String)>,
    /// Its environment entries written as declared source references or captured templates,
    /// name and reference, in the settings' order. The host resolves each at the SPAWN,
    /// never earlier: the reference is what a plane is handed and what the table holds, and the
    /// value exists only in the child's environment.
    pub env_refs: Vec<(String, crate::secret_ref::SecretRef)>,
}

impl std::fmt::Debug for Program {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let env: Vec<String> = self
            .env
            .iter()
            .map(|(name, value)| format!("{name} = <{} bytes>", value.len()))
            .collect();
        let env_refs: Vec<String> = self
            .env_refs
            .iter()
            .map(|(name, reference)| format!("{name} = {}", reference.describe()))
            .collect();
        f.debug_struct("Program")
            .field("command", &self.command)
            .field("cwd", &self.cwd)
            .field("args", &"<redacted>")
            .field("argument_count", &self.args.len())
            .field("env", &env)
            .field("env_refs", &env_refs)
            .finish()
    }
}

impl Drop for Program {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.command.zeroize();
        self.cwd.zeroize();
        self.args.zeroize();
        self.env.zeroize();
    }
}
impl zeroize::ZeroizeOnDrop for Program {}

/// Why a settings value is not a [`Program`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgramRefused {
    /// The value is not an object with a `command` string.
    NoCommand,
    /// The command is not an absolute path (no shell resolves a bare name).
    NotAbsolute,
    /// `args` is not a list of strings.
    Args,
    /// `cwd` is not an unpadded absolute directory path.
    Cwd,
    /// `env` is not a map of strings and secret references.
    Env,
    /// A key other than `command`, `args`, `env` and `cwd`.
    UnknownKey,
    /// A NUL byte in the command, an argument, or an environment name or value; or an environment
    /// name that is empty or holds `=`: none of them can be handed to a process.
    Nul,
}

impl Program {
    /// A REGISTRATION's program ([`crate::section::MEMBER_PROGRAM`]): its `command`, `args`, `cwd`
    pub fn of_member(
        registration: &serde_json::Value,
        sources: &crate::secret_ref::Sugars,
    ) -> Option<Result<Self, ProgramRefused>> {
        let map = registration.as_object()?;
        map.get("command")?;
        let picked = crate::plugin_settings::Tree(serde_json::Value::Object(
            map.iter()
                .filter(|(k, _)| PROGRAM_KEYS.contains(&k.as_str()))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        ));
        Some(Self::from_settings(&picked.0, sources))
    }

    /// The settings' spelling of a program: `{command, args?, env?, cwd?}` — paths are absolute,
    pub fn from_settings(
        value: &serde_json::Value,
        sources: &crate::secret_ref::Sugars,
    ) -> Result<Self, ProgramRefused> {
        let map = value.as_object().ok_or(ProgramRefused::NoCommand)?;
        if map.keys().any(|k| !PROGRAM_KEYS.contains(&k.as_str())) {
            return Err(ProgramRefused::UnknownKey);
        }
        let command = map
            .get("command")
            .and_then(serde_json::Value::as_str)
            .ok_or(ProgramRefused::NoCommand)?;
        if !std::path::Path::new(command).is_absolute() {
            return Err(ProgramRefused::NotAbsolute);
        }
        let cwd = match map.get("cwd") {
            None | Some(serde_json::Value::Null) => None,
            Some(value) => {
                let directory = value.as_str().ok_or(ProgramRefused::Cwd)?;
                if !std::path::Path::new(directory).is_absolute() || directory.trim() != directory {
                    return Err(ProgramRefused::Cwd);
                }
                Some(SecureString::from(directory))
            }
        };
        // Each element wipes itself; the vectors' own blocks hold only pointers and lengths.
        let mut args: Vec<SecureString> = Vec::new();
        if let Some(value) = map.get("args") {
            for argument in value.as_array().ok_or(ProgramRefused::Args)? {
                args.push(SecureString::from(
                    argument.as_str().ok_or(ProgramRefused::Args)?,
                ));
            }
        }

        let mut env: Vec<(SecureString, SecureString)> = Vec::new();
        let mut env_refs = Vec::new();
        if let Some(v) = map.get(PROGRAM_ENV_KEY) {
            for (k, v) in v.as_object().ok_or(ProgramRefused::Env)? {
                match v {
                    serde_json::Value::String(text) => env.push((
                        SecureString::from(k.as_str()),
                        SecureString::from(text.as_str()),
                    )),
                    serde_json::Value::Object(_) => env_refs.push((
                        k.clone(),
                        crate::secret_ref::context::deserialize(v.clone(), sources)
                            .map_err(|_| ProgramRefused::Env)?,
                    )),
                    _ => return Err(ProgramRefused::Env),
                }
            }
        }
        let nul = |s: &str| s.contains('\0');
        if nul(command)
            || cwd.as_deref().is_some_and(nul)
            || args.iter().any(|a| nul(a))
            || env
                .iter()
                .any(|(k, v)| nul(k) || nul(v) || k.is_empty() || k.contains('='))
            || env_refs
                .iter()
                .any(|(k, _)| nul(k) || k.is_empty() || k.contains('='))
        {
            return Err(ProgramRefused::Nul);
        }
        Ok(Self {
            command: command.to_owned(),
            // Into `Program`, which wipes every string it owns on drop.
            cwd: cwd.map(SecureString::into_string),
            args: args.into_iter().map(SecureString::into_string).collect(),
            env: env
                .into_iter()
                .map(|(k, v)| (k.into_string(), v.into_string()))
                .collect(),
            env_refs,
        })
    }
}

/// THE HOST-SIDE READER'S CONNECTION TABLE: [`Conns`] plus a read that wakes a [`Waker`] instead of
pub trait PollConns: Conns {
    /// [`Conns::read`], for a reader on the host's own side (the kernel's egress walk): with nothing
    fn poll_read(
        &self,
        caller: InstanceId,
        conn: ConnId,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<Piece, ConnError>>;

    /// Why `caller`'s connection `conn` failed, once it has ([`DeclaredConns::cause`]), for the
    /// host-side reader that must tell the host's own outbound framer fault
    /// ([`ConnCause::outbound`]) from a far end that failed.
    ///
    /// EVERY HOST TABLE AND EVERY FORWARDING WRAPPER (the root's `BoundConns`, the `Connector`)
    /// MUST implement it: a wrapper that forgot would read every fault as the far end's. It keeps
    /// a body only so the connection fakes plane crates carry in their root tests (built against
    /// this trait from their own pinned revisions) still compile; `None` reads as today's
    /// far-end failure (fail-over, breaker charge), never as a local refusal.
    fn failure_cause(&self, _caller: InstanceId, _conn: ConnId) -> Option<ConnCause> {
        None
    }

    /// On a connection whose wire carries messages (a WebSocket upstream after its 101): the kind of the
    /// message the body piece last read from `conn` belongs to: `Some(true)` text, `Some(false)` binary.
    /// `None` = the wire has no messages, or this table does not keep the kind: the reader then hands the
    /// piece on as bytes, never as text it did not see stated.
    ///
    /// A forwarding wrapper (the root's `BoundConns`) must forward it; the `Connector` answers from the
    /// exchange's own read state. The body is here for the tables that carry no message wire.
    fn message_text(&self, _caller: InstanceId, _conn: ConnId) -> Option<bool> {
        None
    }

    /// THE EVIDENCE OF EACH ATTEMPT `conn` made, in order, told to `each`: what the operating system
    /// accepted of the request the engine sent (`none` is proof the far end received nothing of it;
    /// `whole` means it may have acted and may charge), and what the engine did about the attempt's
    /// end. A request sent again after its first connection failed has two entries. The usage record
    /// carries them, so a request a provider may have worked on before a failover is visible.
    /// Default: none known.
    fn attempt_evidence(
        &self,
        _caller: InstanceId,
        _conn: ConnId,
        _each: &mut dyn FnMut(AttemptEvidence),
    ) {
    }

    /// SEAL THE TRUST ANCHORS of one destination `owner`'s declared `need` reaches at `target` (a
    fn anchor(
        &self,
        owner: InstanceId,
        need: NeedId,
        member: &str,
        target: &str,
        anchors: &crate::transport::trust::Anchors,
    ) -> Result<(), ConnError> {
        let _ = (owner, need, member, target);
        if anchors.is_empty() {
            Ok(())
        } else {
            Err(ConnError::Refused)
        }
    }

    /// The framer's complete defaults before auth signs the request. `timeout_ms` is the
    /// remaining attempt budget; zero means no deadline.
    fn head_defaults(
        &self,
        owner: InstanceId,
        need: NeedId,
        target: &str,
        timeout_ms: u64,
    ) -> Result<HeadDefaults, ConnError> {
        let _ = (owner, need, target, timeout_ms);
        Ok(HeadDefaults::default())
    }

    /// [`PollConns::head_defaults`], with the locate answer behind them where the table carries
    /// one, for [`Conns::open_located`] to dial instead of locating again. The default carries
    /// none.
    fn locate_head(
        &self,
        owner: InstanceId,
        need: NeedId,
        target: &str,
        timeout_ms: u64,
    ) -> Result<(HeadDefaults, Option<Arc<LocatedTarget>>), ConnError> {
        Ok((self.head_defaults(owner, need, target, timeout_ms)?, None))
    }

    /// SEAL ONE REGISTRATION'S PRIVATE REACH (`abi::plane::TRUST_PRIVATE_REACH`, SEAM-4k: keyed
    fn seal_reach(
        &self,
        owner: InstanceId,
        need: NeedId,
        member: &str,
        target: &str,
        reach: bool,
    ) -> Result<(), ConnError> {
        let _ = (owner, need, member, target);
        if reach {
            Err(ConnError::Refused)
        } else {
            Ok(())
        }
    }
}

/// One slab entry: free (with the generation the next occupant takes) or live.
enum Entry<T> {
    Free {
        generation: u32,
    },
    Live {
        generation: u32,
        owner: InstanceId,
        need: NeedId,
        state: Arc<T>,
    },
}

/// THE OWNERSHIP BOOK of a host's connections: which needs each instance declared, and which
pub struct ConnSlab<T> {
    entries: Mutex<Vec<Entry<T>>>,
    /// Indices of `Entry::Free` slots, so an insert reuses one without scanning. Locked only while
    /// `entries` is held.
    free: Mutex<Vec<usize>>,
    declared: Mutex<std::collections::BTreeSet<(InstanceId, NeedId)>>,
}

impl<T> Default for ConnSlab<T> {
    fn default() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            free: Mutex::new(Vec::new()),
            declared: Mutex::new(std::collections::BTreeSet::new()),
        }
    }
}

impl<T> std::fmt::Debug for ConnSlab<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnSlab").finish_non_exhaustive()
    }
}

impl<T> ConnSlab<T> {
    /// Record that `owner` declared `need`.
    pub fn declare(&self, owner: InstanceId, need: NeedId) {
        self.declared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert((owner, need));
    }

    /// Whether `caller` declared `need`.
    pub fn check_need(&self, caller: InstanceId, need: NeedId) -> Result<(), ConnError> {
        if self
            .declared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(&(caller, need))
        {
            Ok(())
        } else {
            Err(ConnError::UndeclaredNeed)
        }
    }

    /// Hold `state` as a connection `owner` opened for `need`, answering its id.
    pub fn insert(&self, owner: InstanceId, need: NeedId, state: T) -> Result<ConnId, ConnError> {
        let declared = self
            .declared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !declared.contains(&(owner, need)) {
            drop(declared);
            return Err(ConnError::UndeclaredNeed);
        }

        #[cfg(test)]
        tests::insert_admitted();
        let mut entries = self.lock();
        let state = Arc::new(state);
        let free = self
            .free
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pop();
        let (index, generation) = match free {
            Some(i) => {
                let Entry::Free { generation } = entries[i] else {
                    unreachable!("found free above")
                };
                entries[i] = Entry::Live {
                    generation,
                    owner,
                    need,
                    state,
                };
                (i, generation)
            }
            None => {
                entries.push(Entry::Live {
                    generation: 0,
                    owner,
                    need,
                    state,
                });
                (entries.len() - 1, 0)
            }
        };
        drop(entries);
        drop(declared);
        Ok(ConnId((u64::from(generation) << 32) | (index as u64 + 1)))
    }

    /// The live connection `conn`, when `caller` owns it: its need and state.
    pub fn get(&self, caller: InstanceId, conn: ConnId) -> Result<(NeedId, Arc<T>), ConnError> {
        let entries = self.lock();
        match Self::slot(&entries, conn)? {
            Entry::Live {
                owner, need, state, ..
            } if *owner == caller => Ok((*need, Arc::clone(state))),
            Entry::Live { .. } => Err(ConnError::NotOwner),
            Entry::Free { .. } => Err(ConnError::Closed),
        }
    }

    /// Release `conn`, when `caller` owns it, answering its state.
    pub fn remove(&self, caller: InstanceId, conn: ConnId) -> Result<Arc<T>, ConnError> {
        let mut entries = self.lock();
        let index = match Self::slot(&entries, conn)? {
            Entry::Live { owner, .. } if *owner == caller => Self::index(conn),
            Entry::Live { .. } => return Err(ConnError::NotOwner),
            Entry::Free { .. } => return Err(ConnError::Closed),
        };
        let generation = (conn.0 >> 32) as u32;
        match std::mem::replace(
            &mut entries[index],
            Entry::Free {
                generation: generation.wrapping_add(1),
            },
        ) {
            Entry::Live { state, .. } => {
                self.free
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(index);
                Ok(state)
            }
            Entry::Free { .. } => unreachable!("checked live above"),
        }
    }

    /// Forget `owner`: every need it declared is dropped (an insert or a need check for it is
    pub fn forget(&self, owner: InstanceId) -> Vec<ConnId> {
        self.declared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|(o, _)| *o != owner);
        self.lock()
            .iter()
            .enumerate()
            .filter_map(|(i, e)| match e {
                Entry::Live {
                    generation,
                    owner: o,
                    ..
                } if *o == owner => Some(ConnId((u64::from(*generation) << 32) | (i as u64 + 1))),
                _ => None,
            })
            .collect()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Entry<T>>> {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn index(conn: ConnId) -> usize {
        ((conn.0 & 0xffff_ffff) as usize).wrapping_sub(1)
    }

    /// The entry `conn` names at its generation; a stale generation reads as closed.
    fn slot(entries: &[Entry<T>], conn: ConnId) -> Result<&Entry<T>, ConnError> {
        let entry = entries.get(Self::index(conn)).ok_or(ConnError::Closed)?;
        let generation = (conn.0 >> 32) as u32;
        match entry {
            Entry::Live { generation: g, .. } if *g == generation => Ok(entry),
            _ => Err(ConnError::Closed),
        }
    }
}

#[cfg(test)]
#[path = "tests/conn_tests.rs"]
mod tests;
