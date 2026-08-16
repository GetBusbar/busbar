// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The PLANE contract — a plane DECLARES, the core MOUNTS AND EXECUTES.
//!
//! A plane is the surface that SERVES a protocol: the config section whose existence turns it on,
//! the HTTP routes it answers, the scope/audit vocabulary its grants and records are filed under.
//! `busbar-api`'s existing kinds are the model — and the shape this module copies is
//! [`crate::LoginHop`]'s: *an HTTP hop the module DESCRIBES and the CORE EXECUTES*. The plane never
//! holds the router, never holds the app handle, never holds the [`crate::Store`] (which carries
//! the audit-chain methods), and never opens a socket. It hands core DATA and core does the work.
//!
//! ## Why that shape, and not "give the plane an `AppHandle`"
//!
//! `AppHandle` cannot live here: core's app state holds plugin-typed fields, so a plugin taking an
//! `AppHandle` *from* `busbar-api` would require `busbar-api` to name the plugin's own types. That
//! is circular. The resolution is the one [`crate::AuthModule`] already uses — it takes
//! `Option<&str>`, never the app — generalised: a plane receives a [`PlaneCtx`], a narrow bundle of
//! CAPABILITIES core grants it, and nothing else. Adding a capability is a deliberate, reviewable
//! act; handing over the app handle would grant every capability at once, forever.
//!
//! ## The ONE vocabulary, in-process and dlopen'd
//!
//! [`PlaneRoute`] / [`PlaneRequest`] / [`PlaneResponse`] are deliberately the same shape as
//! `busbar-plugin-abi`'s already-shipping `Route` / `HttpEndpointRequest` / `HttpEndpointResponse`
//! (which the built-in prometheus exporter serves `/metrics` through, over the C ABI, today). That
//! is not duplication for its own sake: it is what makes "sometimes in a plugins folder, sometimes
//! compiled in" true of the SAME crate. A plane written against this module is unary
//! bytes-in/bytes-out and can cross the C ABI unchanged. A plane that needs to STREAM declares
//! [`PlaneRoute::streaming`] and is compiled-in only — see this module's `STREAMING` note.

use std::sync::Arc;

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
/// and never implements it: the auth chain, the governance admission and the audit record stay
/// core's, which is what keeps "a protocol doesn't change breakers or failover or auditing" true by
/// construction rather than by every plane author's good behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PlaneAuth {
    /// Unauthenticated. Core bypasses the auth chain for this exact route. Declaring this is a
    /// security decision and the route table is where it is reviewable (RFC 9728 metadata routes
    /// are the real case).
    None,
    /// A valid busbar client token — the data-plane bar.
    Key,
    /// The operator admin chain; the route is confined to the ADMIN listener.
    Admin,
}

/// One HTTP route a plane DECLARES it will serve.
///
/// Core reserves it, collision-checks it against the real route table in a deterministic order, and
/// enforces [`Self::auth`] BEFORE dispatch. A plane's self-report never places a route outside the
/// namespace core confines it to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaneRoute {
    /// The absolute path this route claims (axum path syntax: `/example/{id}`).
    pub path: &'static str,
    /// The method served. `{path, method}` is the collision key.
    pub method: PlaneMethod,
    /// The bar core enforces before dispatch.
    pub auth: PlaneAuth,
    /// STREAMING: `true` when this route's response is a stream (SSE, chunked, a long-lived
    /// bidirectional session) rather than one buffered body.
    ///
    /// **This is the one field that decides whether a plane can be dlopen'd.** A `false` route is
    /// unary — [`PlaneRequest`] in, [`PlaneResponse`] out — and crosses the C ABI unchanged. A
    /// `true` route cannot: the loaded-plugin wire is one buffered request and one buffered
    /// response, and no amount of ABI design turns that into a stream without inventing a
    /// framing/backpressure protocol over the boundary. Core REFUSES to load a dlopen'd plane that
    /// declares a streaming route, loudly and by name, rather than silently buffering it.
    pub streaming: bool,
}

/// One inbound request handed to a plane on a matched route, built by core AFTER the declared
/// [`PlaneAuth`] passed. `headers` is a bounded, pre-filtered projection — never the raw
/// `Authorization` header, because core already enforced the grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaneRequest {
    /// The uppercase method token, validated against the DECLARED method before dispatch.
    pub method: String,
    /// The full matched path.
    pub path: String,
    /// The raw query string, no leading `?`. The plane parses its own params.
    pub query: String,
    /// Bounded, pre-filtered headers. Never the raw `Authorization` header.
    pub headers: Vec<(String, String)>,
    /// The request body bytes, already subject to core's request-body cap.
    pub body: Vec<u8>,
}

/// A plane's answer to a [`PlaneRequest`], relayed by core under the same response-body-size and
/// header-count caps every other proxied response respects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaneResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl PlaneResponse {
    /// A JSON response with the given status — the common shape, so a plane does not restate the
    /// content-type header on every path.
    pub fn json(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            headers: vec![("content-type".to_string(), "application/json".to_string())],
            body: body.into(),
        }
    }
}

/// THE CAPABILITIES CORE GRANTS A PLANE — the narrow alternative to an app handle.
///
/// Every field is a capability core chose to grant, not a door into core. The type is
/// `#[non_exhaustive]` so granting a new capability is additive, and each capability is its own
/// trait object so a plane's access can be audited by reading this struct's field list.
///
/// **What is deliberately ABSENT, and why.** There is no [`crate::Store`] here. `Store` is ONE
/// trait carrying the audit-chain append methods, so handing a plane a `Store` hands it the ability
/// to rewrite the append-only chain — the exact objection that stopped the earlier plane-seam
/// design, and it does not become safe just because the dependency arrow flipped. A plane that
/// needs durable state gets [`PlaneJournal`], which can append to ITS OWN records and nothing else.
#[non_exhaustive]
pub struct PlaneCtx {
    /// The plane's own config section, as raw JSON, exactly as the operator wrote it. Core has
    /// already established that the section EXISTS (that is what turns the plane on) and has done
    /// its own secret-reference resolution over it; parsing the section into the plane's typed
    /// shape is the plane's business, which is what keeps the typed config OUT of core.
    pub config: Arc<str>,
    /// The clock, as a capability rather than a module import. The extracted dialects reach for
    /// `busbar_core::store::now` by path today; that is precisely the shape a plugin ABI should
    /// forbid, because a module import is not grantable, not mockable and not auditable.
    pub clock: Arc<dyn PlaneClock>,
    /// Append-only, plane-scoped journal. See the type's doc for what it deliberately cannot do.
    pub journal: Arc<dyn PlaneJournal>,
}

impl PlaneCtx {
    /// Build a context. Core calls this to grant the capabilities; a PLANE calls it in its own
    /// tests, and that second caller is why the constructor exists at all.
    ///
    /// `#[non_exhaustive]` on the struct means a new capability can be granted without breaking
    /// every plane — but it also means nobody outside this crate can use a struct literal, which
    /// would have left a plane unable to test itself without booting the engine. `auth-admin-tokens`
    /// is testable standalone because it takes `Option<&str>`; a plane must keep that property, so
    /// the constructor is part of the contract rather than an accident of visibility. When a
    /// capability is added it gains a parameter here, and every plane's test setup gets one
    /// compiler error pointing at the exact line — which is the correct amount of friction for
    /// widening what a plugin can reach.
    pub fn new(
        config: Arc<str>,
        clock: Arc<dyn PlaneClock>,
        journal: Arc<dyn PlaneJournal>,
    ) -> Self {
        Self {
            config,
            clock,
            journal,
        }
    }
}

/// THE CLOCK, granted rather than imported.
pub trait PlaneClock: Send + Sync {
    /// Unix epoch seconds. `u64` to match core's own clock exactly: a narrowing conversion at this
    /// seam would put a panic (or a silent clamp) between core's time and the plane's, and a clamped
    /// `now` is how a durable ledger sweeps itself and then reports a replay as a first redemption.
    fn now_secs(&self) -> u64;
}

/// A PLANE-SCOPED, APPEND-ONLY JOURNAL — the narrow slice of durability a plane gets instead of
/// [`crate::Store`].
///
/// Core stamps every record with the plane's own [`PlaneDecl::audit_kind`], so a plane cannot write
/// under another plane's kind and cannot reach another plane's records. It is append-only by
/// signature: there is no update and no delete. The audit CHAIN itself — the hash linkage, the
/// verification, the seal — stays core's and is never reachable from here.
pub trait PlaneJournal: Send + Sync {
    /// Append one record. `payload` is the plane's own JSON. Core supplies the kind, the sequence
    /// and the chain linkage.
    fn append(&self, subject: &str, payload: &str) -> Result<(), PlaneError>;
    /// Read this plane's own records for one subject, oldest first, bounded by `limit`.
    fn read(&self, subject: &str, limit: usize) -> Result<Vec<String>, PlaneError>;
}

/// A plane's failure, in the vocabulary core can act on. Deliberately small: a plane classifies,
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

/// THE SERVING HALF — what a plane implements to answer the routes it declared.
///
/// Object-safe and unary on purpose: this is the exact signature that survives the C ABI, so the
/// same impl serves the linked and the loaded form.
pub trait PlaneHandler: Send + Sync {
    /// Serve one matched request. Core has already enforced the route's declared [`PlaneAuth`],
    /// applied its body cap, and filtered the headers.
    fn serve(&self, ctx: &PlaneCtx, req: &PlaneRequest) -> Result<PlaneResponse, PlaneError>;
}

/// EVERYTHING CORE KNOWS ABOUT A PLANE, declared once by the plane itself.
///
/// The direct analogue of `ProtocolDecl` on the plane axis, and the same contract: core routes,
/// mounts, sections, scopes and labels from this and from nothing else. A `&'static PlaneDecl` is
/// what a plane crate exports and what the composition root installs — the `auth-admin-tokens`
/// registration pattern, as DATA.
pub struct PlaneDecl {
    /// The registry key, the metrics label, the log label and the audit resource prefix.
    /// **OPERATOR-VISIBLE**: renaming one re-bases a metric series and invalidates config.
    pub key: &'static str,

    /// The top-level config section whose mere EXISTENCE declares this plane on. Core reads the
    /// section as opaque JSON and hands it to the plane in [`PlaneCtx::config`] — which is how a
    /// plane gets a TYPED config section without core ever naming its type. This is the answer to
    /// "typed config cannot cross the ABI": the TYPE stays in the plane, only the TEXT crosses.
    pub config_section: &'static str,

    /// The `ScopeRef` kinds that grant access ON this plane. Two planes sharing a scope kind is how
    /// one plane's grant admits another's traffic, so core refuses a registration that collides.
    pub scope_kinds: &'static [&'static str],

    /// What ONE registration on this plane is called, in the words an operator reads in a 404.
    pub subject_noun: &'static str,

    /// The audit RESOURCE KIND for this plane. Core stamps [`PlaneJournal`] records with it, so a
    /// plane cannot file under another plane's kind.
    pub audit_kind: &'static str,

    /// The distinct WIRE FORMATS this plane translates between. A function, not a slice, for one
    /// reason worth the indirection: the LLM plane's answer is read off the live protocol registry,
    /// so a seventh dialect does not depend on anyone remembering to bump a literal.
    pub wire_format_names: fn() -> &'static [&'static str],

    /// THE ROUTES this plane serves. Core mounts exactly these and nothing else — a plane cannot
    /// serve a path it did not declare, which is what makes the route table a reviewable artifact
    /// rather than a claim.
    pub routes: &'static [PlaneRoute],

    /// The cell that serves this plane's declared routes. `None` is a plane that contributes
    /// vocabulary (sections, scopes, audit kind) and serves nothing — a legitimate shape.
    pub handler: Option<&'static dyn PlaneHandler>,
}

impl PlaneDecl {
    /// True when any declared route streams — i.e. this plane is COMPILED-IN ONLY and core must
    /// refuse to dlopen it. Read at load, named in the refusal.
    pub fn requires_linking(&self) -> bool {
        self.routes.iter().any(|r| r.streaming)
    }
}

#[cfg(test)]
#[path = "tests/plane_tests.rs"]
mod tests;
