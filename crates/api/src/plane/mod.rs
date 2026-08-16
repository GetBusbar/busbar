// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The PLANE contract — a plane DECLARES, the core MOUNTS AND EXECUTES.
//!
//! A plane is the surface that SERVES a protocol: the config section whose existence turns it on,
//! the HTTP routes it answers, the scope/audit vocabulary its grants and records are filed under.
//! The shape this module copies is [`crate::LoginHop`]'s: *an HTTP hop the module DESCRIBES and the
//! CORE EXECUTES*. The plane never holds the router, never holds the app handle, never holds the
//! [`crate::Store`], and never opens a socket. It hands core DATA and core does the work.
//!
//! ## ABI v2 — what the first two migrations forced, and why each change is narrow
//!
//! v1 was designed against a reference plane and shipped with a working PoC. Two independent
//! migrations (MCP and A2A) then halted on it, in separate worktrees, with converging evidence.
//! Every v2 change below is one of those walls, and none of them is met by widening what a plane can
//! reach:
//!
//! 1. **[`PlaneHandler::serve`] is async.** Both planes do governed, pooled, SSRF-checked upstream
//!    round trips per request. A sync signature forces either a blocked executor or a
//!    `spawn_blocking` hop per request, and the hop was measured at +41.5 µs.
//! 2. **[`PlaneBody`] can stream.** Both planes stream (MCP `subscriptions/listen` and SSE; A2A
//!    REST, relay and gRPC). v1 filtered streaming routes out of the mount, so declaring `true`
//!    served nothing and declaring `false` buffered a long-lived subscription forever. Neither is
//!    shippable, and the honest resolution is that the ABI expresses streams — while streaming
//!    remains the property that makes a plane compiled-in-only (see [`PlaneDecl::requires_linking`]).
//! 3. **[`PlaneDecl::routes`] is a FUNCTION of config, not a static slice.** MCP's RFC 9728 metadata
//!    path is derived at boot from the operator's `canonical_uri`; core cannot statically ratify a
//!    path it does not know until it has read YAML.
//! 4. **[`PlaneAuth::PlaneVerified`] exists**, because A2A's push callback genuinely authenticates
//!    itself in-handler against a per-task HMAC capability core minted. It is ratified exactly as
//!    [`PlaneAuth::None`] is — see [`RatifiedRoute`] — so it is not a bar a plane can self-grant.
//! 5. **[`capability`] replaces the three-field context** with a reviewable set of narrow grants.
//!
//! ## What did NOT change, and must not
//!
//! **A plane may not lower its own admission bar.** Core's route ratchet caught v1's draft
//! declaring an unauthenticated route, and that property is preserved verbatim through the
//! ratification mechanism: a declared [`PlaneAuth::None`] or [`PlaneAuth::PlaneVerified`] that core
//! has not ratified is RAISED to [`PlaneAuth::Key`]. Given "downloaded and dropped in", this is the
//! single most important security property in the design.
//!
//! **No [`crate::Store`], no trust/governance/audit types.** See [`capability`]'s header for the
//! organising principle: the plane supplies the payload, the core supplies the linkage.

pub mod capability;
pub mod facts;

use std::pin::Pin;
use std::sync::Arc;

pub use capability::{
    ChainVerdict, PlaneApprovals, PlaneAsk, PlaneCallLog, PlaneCatalogue, PlaneClock, PlaneEgress,
    PlaneEgressRequest, PlaneEgressResponse, PlaneGovernance, PlaneGrant, PlaneJournal,
    PlaneMetering, PlaneMetrics, PlaneQuarantine, PlaneSecrets, PlaneTasks, PlaneVerdict,
};
pub use facts::{Magnitude, PlaneFacts, Screenable};

/// The HTTP method a plane route declares. Mirrors `busbar_plugin_abi::http_endpoint::RouteMethod`
/// token-for-token so a plane crate's declaration is portable between the linked and loaded forms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PlaneMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

impl PlaneMethod {
    /// The canonical uppercase HTTP method token — the same spelling that rides the plugin wire.
    pub fn as_str(&self) -> &'static str {
        match self {
            PlaneMethod::Get => "GET",
            PlaneMethod::Post => "POST",
            PlaneMethod::Put => "PUT",
            PlaneMethod::Patch => "PATCH",
            PlaneMethod::Delete => "DELETE",
        }
    }
}

/// The admission bar CORE enforces before a request reaches the plane. The plane DECLARES the bar
/// and never implements it — except for [`Self::PlaneVerified`], which is precisely a declaration
/// that the plane will, and which core therefore refuses to honour unless it has ratified it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PlaneAuth {
    /// Unauthenticated. Core bypasses the auth chain for this exact route. **Requires ratification**
    /// — the real case is RFC 9728 protected-resource metadata, which a caller must read before it
    /// holds any credential.
    None,
    /// A valid busbar client token — the data-plane bar.
    Key,
    /// The operator admin chain; the route is confined to the ADMIN listener.
    Admin,
    /// THE PLANE AUTHENTICATES THIS ROUTE ITSELF, against a capability CORE MINTED.
    ///
    /// Not a bypass and not a weaker `Key`: it is for a callback whose credential is not a busbar
    /// token at all. A2A's push callback is the case — busbar mints a per-task HMAC capability,
    /// hands it to the remote agent, and verifies it in constant time when the callback arrives. No
    /// chain in core can judge that credential because core did not issue it as an identity.
    ///
    /// **Requires ratification**, for the obvious reason: without that, any dropped-in crate could
    /// declare `PlaneVerified` and receive unauthenticated traffic while appearing to check it. The
    /// ratification entry is where a reviewer records that this plane's self-check was examined.
    PlaneVerified,
}

impl PlaneAuth {
    /// Whether core must have RATIFIED this bar for the route to be served as declared. The two
    /// variants that move admission away from core's own chain are exactly the two that need a
    /// reviewed entry; `Key` and `Admin` are core's own bars and need none.
    pub fn requires_ratification(&self) -> bool {
        matches!(self, PlaneAuth::None | PlaneAuth::PlaneVerified)
    }
}

/// One HTTP route a plane declares it will serve, resolved against the operator's config.
///
/// `path` is an owned `String` rather than `&'static str` because a plane's paths may be DERIVED
/// (MCP's metadata document sits under the operator's `canonical_uri`). That is also why
/// [`PlaneDecl::routes`] is a function: the route table cannot exist before the config is read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaneRoute {
    /// The absolute path this route claims (axum path syntax: `/example/{id}`).
    pub path: String,
    /// The method served. `{path, method}` is the collision key.
    pub method: PlaneMethod,
    /// The bar core enforces before dispatch.
    pub auth: PlaneAuth,
    /// STREAMING: `true` when this route's response is a stream (SSE, chunked, a long-lived
    /// session) rather than one buffered body.
    ///
    /// **This is the field that decides whether a plane can be dlopen'd.** A `false` route is unary
    /// and crosses the C ABI unchanged. A `true` route cannot: the loaded-plugin wire is one
    /// buffered request and one buffered response, and no ABI design turns that into a stream
    /// without inventing framing and backpressure over the boundary. Core serves streaming routes
    /// when the plane is LINKED, and refuses to load a dlopen'd plane that declares one — loudly and
    /// by name, rather than silently buffering it.
    pub streaming: bool,
}

/// One inbound request handed to a plane on a matched route, built by core AFTER the declared
/// [`PlaneAuth`] passed. `headers` is a bounded, pre-filtered projection — never the raw
/// `Authorization` header, because core already enforced the grant.
///
/// EXCEPTION, and it is deliberate: a [`PlaneAuth::PlaneVerified`] route DOES receive the credential
/// headers it declared in [`PlaneDecl::verified_headers`], because verifying them is the whole
/// reason that variant exists. The allowlist is per-plane, ratified, and cannot include
/// `Authorization`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaneRequest {
    pub method: String,
    pub path: String,
    /// The raw query string, no leading `?`. The plane parses its own params.
    pub query: String,
    pub headers: Vec<(String, String)>,
    /// The request body bytes, already subject to core's request-body cap.
    pub body: Vec<u8>,
}

/// A plane's response body: one buffered payload, or a stream of chunks.
///
/// The two arms are not interchangeable and the difference is load-bearing — [`Self::Stream`] is
/// what makes MCP's `subscriptions/listen` and A2A's relay expressible, and it is simultaneously
/// what confines those planes to the compiled-in form.
pub enum PlaneBody {
    /// One buffered payload. Crosses the C ABI unchanged.
    Unary(Vec<u8>),
    /// A stream of chunks, framed by the plane. Core relays them as they arrive and applies the
    /// same idle/total deadlines every other streamed response respects. LINKED PLANES ONLY.
    Stream(Pin<Box<dyn futures_core::Stream<Item = Result<Vec<u8>, PlaneError>> + Send>>),
}

impl PlaneBody {
    /// The buffered bytes, or `None` for a stream. The accessor exists because a PLANE tests its own
    /// unary responses and should not have to `match` a two-arm enum to do it; a stream deliberately
    /// has no equivalent, because consuming one to inspect it is not an inspection.
    pub fn as_unary(&self) -> Option<&[u8]> {
        match self {
            PlaneBody::Unary(b) => Some(b),
            PlaneBody::Stream(_) => None,
        }
    }
}

impl std::fmt::Debug for PlaneBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlaneBody::Unary(b) => f.debug_tuple("Unary").field(&b.len()).finish(),
            // Never renders the stream: polling it to describe it would consume it.
            PlaneBody::Stream(_) => f.write_str("Stream(..)"),
        }
    }
}

/// A plane's answer to a [`PlaneRequest`], relayed by core under the same response-body-size and
/// header-count caps every other proxied response respects.
#[derive(Debug)]
pub struct PlaneResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: PlaneBody,
}

impl PlaneResponse {
    /// A buffered JSON response — the common shape, so a plane does not restate the content-type
    /// header on every path.
    pub fn json(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            headers: vec![("content-type".to_string(), "application/json".to_string())],
            body: PlaneBody::Unary(body.into()),
        }
    }

    /// A server-sent-events response. Declaring the route `streaming: true` is what makes this
    /// servable; returning it from a route declared `false` is a plane bug core reports rather than
    /// silently buffers.
    pub fn sse(
        stream: Pin<Box<dyn futures_core::Stream<Item = Result<Vec<u8>, PlaneError>> + Send>>,
    ) -> Self {
        Self {
            status: 200,
            headers: vec![
                ("content-type".to_string(), "text/event-stream".to_string()),
                ("cache-control".to_string(), "no-cache".to_string()),
            ],
            body: PlaneBody::Stream(stream),
        }
    }
}

/// THE CAPABILITIES CORE GRANTS A PLANE — the narrow alternative to an app handle.
///
/// `AppHandle` can never live in `busbar-api`: core's app state holds plugin-typed fields, so a
/// plugin taking an `AppHandle` *from* this crate would require this crate to name the plugin's
/// types. The resolution is the one [`crate::AuthModule`] already uses — it takes `Option<&str>`,
/// never the app — generalised.
///
/// Every field is a capability core CHOSE to grant, and the field list is the audit: reading this
/// struct tells you exactly what a plane can reach. `#[non_exhaustive]` keeps granting additive;
/// [`Self::builder`] keeps a plane able to construct one for its own tests, which is a property
/// `auth-admin-tokens` has and no plugin should lose.
///
/// The optional capabilities are `Option` because **not every plane needs every power**, and a plane
/// that does not need one should not be handed it. Core grants only what a plane's declaration
/// justifies.
#[non_exhaustive]
pub struct PlaneCtx {
    /// The plane's own config section, as raw JSON, exactly as the operator wrote it. Core has
    /// established the section EXISTS and resolved its secret references; PARSING it into the
    /// plane's typed shape is the plane's business — which is how a plane gets a typed config
    /// section without core ever naming its type.
    pub config: Arc<str>,
    pub clock: Arc<dyn PlaneClock>,
    pub metrics: Arc<dyn PlaneMetrics>,
    pub journal: Option<Arc<dyn PlaneJournal>>,
    pub tasks: Option<Arc<dyn PlaneTasks>>,
    pub call_log: Option<Arc<dyn PlaneCallLog>>,
    pub quarantine: Option<Arc<dyn PlaneQuarantine>>,
    pub approvals: Option<Arc<dyn PlaneApprovals>>,
    pub governance: Option<Arc<dyn PlaneGovernance>>,
    pub egress: Option<Arc<dyn PlaneEgress>>,
    pub catalogue: Option<Arc<dyn PlaneCatalogue>>,
    pub secrets: Option<Arc<dyn PlaneSecrets>>,
}

impl PlaneCtx {
    /// Start building a context. Core calls this to grant capabilities; a PLANE calls it in its own
    /// tests, and that second caller is why it exists — `#[non_exhaustive]` alone would leave a
    /// plane unable to construct one, making every plane untestable without booting the engine.
    pub fn builder(
        config: Arc<str>,
        clock: Arc<dyn PlaneClock>,
        metrics: Arc<dyn PlaneMetrics>,
    ) -> PlaneCtxBuilder {
        PlaneCtxBuilder {
            ctx: PlaneCtx {
                config,
                clock,
                metrics,
                journal: None,
                tasks: None,
                call_log: None,
                quarantine: None,
                approvals: None,
                governance: None,
                egress: None,
                catalogue: None,
                secrets: None,
            },
        }
    }
}

/// Builder for [`PlaneCtx`]. Each `with_*` is one deliberate grant, so a context's construction site
/// reads as the list of powers that plane was given.
pub struct PlaneCtxBuilder {
    ctx: PlaneCtx,
}

macro_rules! grant {
    ($name:ident, $field:ident, $ty:ident) => {
        #[doc = concat!("Grant the `", stringify!($field), "` capability.")]
        pub fn $name(mut self, cap: Arc<dyn $ty>) -> Self {
            self.ctx.$field = Some(cap);
            self
        }
    };
}

impl PlaneCtxBuilder {
    grant!(with_journal, journal, PlaneJournal);
    grant!(with_tasks, tasks, PlaneTasks);
    grant!(with_call_log, call_log, PlaneCallLog);
    grant!(with_quarantine, quarantine, PlaneQuarantine);
    grant!(with_approvals, approvals, PlaneApprovals);
    grant!(with_governance, governance, PlaneGovernance);
    grant!(with_egress, egress, PlaneEgress);
    grant!(with_catalogue, catalogue, PlaneCatalogue);
    grant!(with_secrets, secrets, PlaneSecrets);

    pub fn build(self) -> PlaneCtx {
        self.ctx
    }
}

/// A plane's failure, in the vocabulary core can act on. Deliberately small: a plane CLASSIFIES,
/// core decides what a class MEANS for the breaker, the audit record and the operator's dashboard —
/// so a plane cannot opt itself out of a cross-cutting capability by inventing a fault shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaneError {
    /// The stable class token core routes on (`"refused"`, `"unavailable"`, `"invalid"`, …).
    pub class: &'static str,
    /// The operator-facing message. Never carries credential material.
    pub message: String,
}

impl PlaneError {
    pub fn new(class: &'static str, message: impl Into<String>) -> Self {
        Self {
            class,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for PlaneError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.class, self.message)
    }
}

impl std::error::Error for PlaneError {}

/// THE SERVING HALF — what a plane implements to answer the routes it declared.
///
/// ASYNC, because both real planes do governed, pooled, SSRF-checked upstream round trips on the
/// request path. A synchronous signature would force every such call through `spawn_blocking` (a
/// measured +41.5 µs per request) or block the executor outright.
#[async_trait::async_trait]
pub trait PlaneHandler: Send + Sync {
    /// Serve one matched request. Core has already enforced the route's declared [`PlaneAuth`],
    /// applied its body cap, and filtered the headers.
    async fn serve(&self, ctx: &PlaneCtx, req: &PlaneRequest) -> Result<PlaneResponse, PlaneError>;
}

/// EVERYTHING CORE KNOWS ABOUT A PLANE, declared once by the plane itself.
pub struct PlaneDecl {
    /// The registry key, the metrics label, the log label and the audit resource prefix.
    /// **OPERATOR-VISIBLE.**
    pub key: &'static str,

    /// The top-level config section whose mere EXISTENCE declares this plane on. Core reads the
    /// section as opaque JSON and hands it over in [`PlaneCtx::config`] — the TYPE stays in the
    /// plane, only the TEXT crosses.
    pub config_section: &'static str,

    /// The `ScopeRef` kinds that grant access ON this plane. Two planes sharing a scope kind is how
    /// one plane's grant admits another's traffic, so core refuses a colliding registration.
    pub scope_kinds: &'static [&'static str],

    /// What ONE registration on this plane is called, in the words an operator reads in a 404.
    pub subject_noun: &'static str,

    /// The audit RESOURCE KIND for this plane. Core stamps journal and call-log records with it, so
    /// a plane cannot file under another plane's kind.
    pub audit_kind: &'static str,

    /// The distinct WIRE FORMATS this plane translates between.
    pub wire_format_names: fn() -> &'static [&'static str],

    /// THE ROUTES this plane serves, AS A FUNCTION OF ITS CONFIG SECTION.
    ///
    /// A function rather than a slice because paths may be DERIVED: MCP's RFC 9728 metadata document
    /// sits under the operator's `canonical_uri`, so the route table does not exist until the config
    /// is read. Core calls this once at mount time with the same text it puts in
    /// [`PlaneCtx::config`], and mounts exactly what comes back.
    pub routes: fn(&str) -> Vec<PlaneRoute>,

    /// Request headers a [`PlaneAuth::PlaneVerified`] route receives so it can verify its own
    /// credential. A bounded allowlist, ratified with the route; `Authorization` may never appear.
    pub verified_headers: &'static [&'static str],

    /// The cell that serves this plane's declared routes. `None` is a plane that contributes
    /// vocabulary and serves nothing — a legitimate shape.
    pub handler: Option<&'static dyn PlaneHandler>,
}

impl PlaneDecl {
    /// True when this plane can only ever be COMPILED IN — i.e. core must refuse to dlopen it.
    ///
    /// Read at load and named in the refusal. Streaming is the disqualifier: the loaded-plugin wire
    /// is one buffered request and one buffered response.
    pub fn requires_linking(&self, config: &str) -> bool {
        (self.routes)(config).iter().any(|r| r.streaming)
    }
}

/// ONE RATIFIED ROUTE — core's record that a reviewer examined a plane's request to move admission
/// away from core's own auth chain.
///
/// A `&[&str]` of literal paths cannot express what the real planes need: MCP's metadata path is
/// derived from operator config, so core cannot know it statically. Ratification is therefore by
/// PATTERN, matched against the RESOLVED path at mount time — and the pattern, the plane and the
/// reason all live in CORE, where a plugin cannot add to them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RatifiedRoute {
    /// The plane whose route this ratifies. A pattern is scoped to one plane, so ratifying MCP's
    /// metadata document does not ratify anybody else's identically-shaped path.
    pub plane: &'static str,
    /// The path pattern. `*` matches one or more characters within a single segment; anything else
    /// matches literally. Deliberately weak — a ratification pattern should be boring to read.
    pub pattern: &'static str,
    /// The bar being ratified.
    pub auth: PlaneAuth,
    /// WHY, in the reviewer's words. Required, because the entry exists to be read by the next
    /// person deciding whether it still holds.
    pub reason: &'static str,
}

impl RatifiedRoute {
    /// Does this entry ratify `path` on `plane` at `auth`? All three must match: a pattern ratifies
    /// one plane's one path shape at one bar, never a class of them.
    pub fn ratifies(&self, plane: &str, path: &str, auth: PlaneAuth) -> bool {
        self.plane == plane && self.auth == auth && glob_segment_match(self.pattern, path)
    }
}

/// Match `pattern` against `path`, where `*` matches one or more characters not crossing a `/`.
///
/// Segment-bounded on purpose: a `*` that could span `/` would let a ratification for
/// `/mcp/*/metadata` also cover `/mcp/../../admin/metadata`, which is precisely the kind of quiet
/// over-grant this mechanism exists to prevent.
fn glob_segment_match(pattern: &str, path: &str) -> bool {
    let (mut p, mut s) = (pattern.split('/'), path.split('/'));
    loop {
        match (p.next(), s.next()) {
            (None, None) => return true,
            (Some(pp), Some(ss)) => {
                if !segment_match(pp, ss) {
                    return false;
                }
            }
            _ => return false,
        }
    }
}

fn segment_match(pat: &str, seg: &str) -> bool {
    match pat.find('*') {
        None => pat == seg,
        Some(i) => {
            let (pre, post) = (&pat[..i], &pat[i + 1..]);
            // `*` must consume at least one character, so an empty segment never matches a wildcard
            // — otherwise `/a/*/b` would ratify `/a//b`, a path that normalises differently
            // downstream.
            seg.len() > pre.len() + post.len()
                && seg.starts_with(pre)
                && seg.ends_with(post)
                && !seg[pre.len()..seg.len() - post.len()].contains('*')
        }
    }
}

#[cfg(test)]
#[path = "../tests/plane_tests.rs"]
mod tests;
