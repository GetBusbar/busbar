// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CONNECTION TABLE (the design's connections: "every plugin that needs an external connection

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use crate::abi::mechanism::rendering::ReadNeed;
use crate::ids::StreamId;
use crate::transport::wire::{WireFault, WireStatusClass};
use crate::transport::ConnFacts;

/// The frozen bytes an [`OpenDesc`] carries its body in.
pub use bytes::Bytes;

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
            .finish()
    }
}

/// What a piece a connection delivered carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PieceKind {
    /// Payload bytes.
    Body,
    /// A head: the far end's fields, as the field block
    /// ([`crate::abi::transport::fields`]) renders them, hop-by-hop fields dropped. The far end's
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

    /// THE HOST WRITES THE AUTHORITY of every connection `owner` opens: an open whose head
    fn hold_authority(&self, owner: InstanceId) {
        let _ = owner;
    }

    /// THE FRAMER'S OWN HEAD on a request `owner`'s `need` opens to `target` (empty = the need's
    fn request_head(&self, owner: InstanceId, need: NeedId, target: &str) -> HeadDefaults {
        let _ = (owner, need, target);
        HeadDefaults::default()
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
    /// connection generation. Only host lifecycle composition supplies this provenance; it
    /// transfers no connection, authentication, reach or trust authority. Lifecycle composition
    /// serializes declarations of a freshly minted successor; this is not a concurrent reassignment
    /// API for an existing owner. Implementations that
    /// do not retain program declarations keep their ordinary declaration behavior.
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
    let after = url.find("://").map_or(0, |at| at + 3);
    url[after..].find('/').map_or(url, |at| &url[..after + at])
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

/// The one line the host states for a framer whose head states the body's length.
pub const CONTENT_LENGTH: &[u8] = b"content-length";

impl HeadDefaults {
    /// THE LINES THE HOST ADDS to a request head (THE DESIGN section 6, step 5: nothing is added
    #[must_use]
    pub fn completing(
        &self,
        carried: impl Fn(&[u8]) -> bool,
        body_len: usize,
    ) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut added: Vec<(Vec<u8>, Vec<u8>)> = self
            .lines
            .iter()
            .filter(|(name, _)| !carried(name))
            .cloned()
            .collect();
        if self.states_length
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
    fn lent(&self, unit: u64) -> Option<crate::redacted::Secret<Vec<u8>>>;
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
    pub points: crate::abi::auth::AuthPoints,
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

/// The field a member-program connection's HEAD carries (the first piece every open on it reads,
pub const PROGRAM_GENERATION_FIELD: &str = "generation";

/// The host member incarnation. A replacement launch configuration receives a distinct value,
pub const PROGRAM_INSTANCE_FIELD: &str = "program-instance";

/// Standard-base64 UTF-8 absolute command path from the host-admitted program. This identifies
pub const PROGRAM_IDENTITY_FIELD: &str = "program-identity";

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
    /// Its environment entries written as SECRET REFERENCES (`{ env: X }`, `{ file: P }`, a
    /// template), name and reference, in the settings' order. The host resolves each at the SPAWN,
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
            .field("args", &self.args)
            .field("env", &env)
            .field("env_refs", &env_refs)
            .finish()
    }
}

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
    pub fn of_member(registration: &serde_json::Value) -> Option<Result<Self, ProgramRefused>> {
        let map = registration.as_object()?;
        map.get("command")?;
        let picked: serde_json::Map<String, serde_json::Value> = map
            .iter()
            .filter(|(k, _)| PROGRAM_KEYS.contains(&k.as_str()))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        Some(Self::from_settings(&serde_json::Value::Object(picked)))
    }

    /// The settings' spelling of a program: `{command, args?, env?, cwd?}` — paths are absolute,
    pub fn from_settings(value: &serde_json::Value) -> Result<Self, ProgramRefused> {
        let map = value.as_object().ok_or(ProgramRefused::NoCommand)?;
        if map
            .keys()
            .any(|k| !matches!(k.as_str(), "command" | "args" | "env" | "cwd"))
        {
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
                Some(directory.to_owned())
            }
        };
        let args = match map.get("args") {
            None => Vec::new(),
            Some(v) => v
                .as_array()
                .ok_or(ProgramRefused::Args)?
                .iter()
                .map(|a| a.as_str().map(str::to_owned).ok_or(ProgramRefused::Args))
                .collect::<Result<Vec<_>, _>>()?,
        };

        let mut env = Vec::new();
        let mut env_refs = Vec::new();
        if let Some(v) = map.get(PROGRAM_ENV_KEY) {
            for (k, v) in v.as_object().ok_or(ProgramRefused::Env)? {
                match v {
                    serde_json::Value::String(text) => env.push((k.clone(), text.clone())),
                    serde_json::Value::Object(_) => env_refs.push((
                        k.clone(),
                        serde_json::from_value::<crate::secret_ref::SecretRef>(v.clone())
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
            cwd,
            args,
            env,
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

    /// THE FRAMER'S OWN HEAD on a request `owner`'s `need` opens to `target` (the transport ABI's
    fn head_defaults(&self, owner: InstanceId, need: NeedId, target: &str) -> HeadDefaults {
        let _ = (owner, need, target);
        HeadDefaults::default()
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
    declared: Mutex<std::collections::BTreeSet<(InstanceId, NeedId)>>,
}

impl<T> Default for ConnSlab<T> {
    fn default() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
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
        let free = entries.iter().position(|e| matches!(e, Entry::Free { .. }));
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
            Entry::Live { state, .. } => Ok(state),
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
