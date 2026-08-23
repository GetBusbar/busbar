// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE SPINE: which planes exist, what each one is called wherever it is named, and which
//! plane an inbound request belongs to.
//!
//! `plane-layering.md`, in code. The shape it describes is:
//!
//! ```text
//!     wire protocols
//!           |
//!        PLANE DISPATCH        <- decides which plane an inbound request belongs to
//!        /      |      \
//!      LLM     MCP     A2A     <- each plane owns ONE canonical type
//!       |
//!      IR                      <- only LLM has a superset IR, because only LLM needs one
//!       |
//!     wire protocols
//! ```
//!
//! ## Why this is one type and not three constants scattered per plane
//!
//! A plane is named in at least four places: its config section, its scope-grant kinds, its ingress
//! mount, and its audit resources. Those strings have to agree, and two of them agreeing by
//! coincidence is how one plane's grant ends up admitting another plane's traffic. So they are
//! stated once, per plane, and a test asserts they never collide across planes.
//!
//! ## The superset-IR rule is COMPUTED, not asserted
//!
//! An IR exists to solve N x M translation. Six protocols in and six out turns 30 conversions into
//! 12, and that is its entire justification. A plane with ONE wire format in and one out would have
//! an "IR" with exactly one protocol on each side, which is a data model wearing a costume, plus a
//! second thing to keep lossless and a second place for a translation bug in a product whose
//! headline claim is lossless translation.
//!
//! So [`Plane::has_superset_ir`] is derived from [`Plane::wire_formats`] rather than written as
//! `matches!(self, Plane::Llm)`. That makes it a RULE rather than a fact about today's planes: the
//! day a second dialect lands on some plane, that plane earns an IR and the test says so. And the
//! LLM count is read off the real protocol registry, so a seventh dialect does not depend on
//! anyone remembering to bump a literal here.
//!
//! A TRANSPORT IS NOT A WIRE FORMAT. MCP runs over stdio, streamable HTTP and SSE, and every one of
//! them carries the same JSON-RPC message shape. Counting transports would hand MCP an IR it has
//! not earned.
//!
//! ## Each plane still owns ONE canonical type
//!
//! Even without a superset, every plane has one canonical internal type, so the architecture reads
//! the same everywhere: protocol in, canonical type, protocol out. For a single-wire-format plane
//! that canonical type IS the protocol's own model, MIRRORED IN OUR STRUCTS rather than adopted
//! from a third party's generated ones. MCP is versioned and moving; if the internal representation
//! were somebody's generated types, a spec revision would ripple through the engine, the registry,
//! the catalogue cache and the audit records instead of staying contained to the reader and writer
//! at the edge.

// THE SPINE IS NOW LOAD-BEARING, which is what it was landed ahead of a caller for. FOUR
// production callers, none of them written per plane:
//
//   * [`observe`], the plane ingress boundary — asks `PlaneDispatch::mounted_plane_of` which plane
//     a request arrived on and labels that request's metrics with `Plane::key`. Before it, MCP and
//     A2A traffic appeared in no Prometheus series at all.
//   * verify-on-call (`crate::trust::verify`), which carries `Plane` as its diagnostic label.
//   * the admin trust verb surface (`crate::admin::planeverbs`), which reads `Plane::subject_noun`
//     for its one `404` and `Plane::audit_kind` for its audit action and resource.
//
// The last two REPLACED a pair of plane-local copies — a scheduler and an admin verb set written
// twice, discovered when ten branches merged and the structural lint saw both halves at once for
// the first time. That is precisely what landing the spine first was meant to prevent, and it is
// worth recording that the spine existing did not prevent it: two authors each wrote a plane-local
// copy without consulting it. The lint caught what the spine alone could not.
//
//   * the ERROR-SHAPING boundary, through [`PlaneDispatch::ingress_of`] — the one resolver that
//     answers "which plane, and in which wire dialect, is this path spoken". Every site that must
//     shape an answer from a path alone (the `413` reshape, the `404`/`405` fallbacks, the
//     auth-time `401`) reads it, so an oversized POST to a mounted plane is now refused in that
//     plane's own dialect instead of in a vendor envelope its client cannot decode.
//   * the CARD-PUBLISHING boundary, and the first caller to read the wire-format LIST rather than
//     its length: `a2a::serve::servable_bindings` decides which
//     `supportedInterfaces[].protocolBinding` busbar may publish on a card pointing at busbar's own
//     address. That was previously a literal in the rewrite, and it published a gRPC interface at an
//     address busbar does not serve gRPC on.
//
// STILL WITHOUT A PRODUCTION CALLER, and named rather than left to be discovered: `PlaneSections`
// and `has_superset_ir`. The candidate projection and the shared pools/tools/agents container are
// the dependants those are waiting on, so the attribute stays until they land.
//
// `wire_formats` is NOT in that list, and has two callers rather than one: `sole_wire_format` reads
// its length on the request path, and `servable_bindings` reads its contents to decide which
// bindings a served card may advertise. Both are named here because this header, not the call
// sites, is what states whether a member of this module is reachable.
#![cfg_attr(not(test), allow(dead_code))]

pub(crate) mod approvals;
pub(crate) mod auditlog;
pub(crate) mod calllog;
pub(crate) mod config;
pub mod cost;
pub mod host;
pub(crate) mod observe;
pub(crate) mod provenance;
pub(crate) mod quarantine;
pub mod registry;
pub(crate) mod store;
// `plane::taskstore` stores A2A task rows and depends on `crate::a2a::task`/`crate::a2a::pushnotify`
// types; every caller lives in `crate::a2a`. It is therefore an A2A-plane helper that happens to sit
// under `plane/`, and it is compiled out with the plane (`plane-a2a` off) alongside `src/a2a`.
#[cfg(feature = "plane-a2a")]
pub(crate) mod taskstore;

/// THE WIRE FORMAT both mounted planes speak: JSON-RPC 2.0. Named once, here, because it is read
/// twice as a [`Plane::wire_format_names`] entry and once more by the error-shaping boundary, which
/// decides that a refusal on a mounted plane is a JSON-RPC error object rather than a vendor
/// envelope. A literal spelled per site is how those two answers start to differ.
pub(crate) const WIRE_JSONRPC: &str = "jsonrpc";

/// THE SECOND WIRE FORMAT THE A2A PLANE SPEAKS: A2A's HTTP+JSON binding, where the REQUEST LINE
/// names the operation rather than a body member. Named once, here, because it is read three ways
/// and all three must agree — as a [`Plane::wire_format_names`] entry, as the
/// [`crate::transport::Transport::HttpJson`] label, and (upper-cased by
/// `a2a::serve::servable_bindings`) as the `protocolBinding` a served agent card advertises. The
/// card spelling is `HTTP+JSON`, so this is that string lower-cased and nothing else.
pub(crate) const WIRE_HTTP_JSON: &str = "http+json";

/// The A2A specification's gRPC binding, as a wire-format name. Lower-case here and upper-cased
/// once, by [`crate::a2a::serve::servable_bindings`], into the `GRPC` an agent card advertises — so
/// the card cannot claim a binding the plane does not list, which is the whole reason that function
/// reads this list rather than writing one of its own.
pub(crate) const WIRE_GRPC: &str = "grpc";

/// One governance plane. The variant set is the only thing a new plane adds here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Plane {
    /// Model traffic. The residual ingress, and the only plane with a superset IR.
    Llm,
    /// Tool traffic.
    Mcp,
    /// Agent traffic.
    A2a,
}

impl Plane {
    /// Every plane, in layering order. Iterated by dispatch, the config validator and the candidate
    /// projection, so a plane absent from here is a plane that silently does not exist.
    ///
    /// `Plane::Mcp` is present only when the MCP plane is compiled in (`plane-mcp`): with it off the
    /// plane has no built-in declaration, so it must not be iterated here — every `.decl()` on it
    /// would fault. The `Plane::Mcp` enum variant still exists (a `Copy` key some match arms name),
    /// but it is not a plane this build serves.
    ///
    /// `Plane::A2a` is present only when the A2A plane is compiled in (`plane-a2a`), for the same
    /// reason `Plane::Mcp` is gated: with it off the plane has no built-in declaration, so it must
    /// not be iterated here — every `.decl()` on it would fault. The `Plane::A2a` enum variant still
    /// exists (a `Copy` key some match arms name), but it is not a plane this build serves.
    pub(crate) const ALL: &'static [Plane] = &[
        Plane::Llm,
        #[cfg(feature = "plane-mcp")]
        Plane::Mcp,
        #[cfg(feature = "plane-a2a")]
        Plane::A2a,
    ];

    /// The plane's short stable name, for logs, metrics labels and audit resources.
    pub(crate) fn key(self) -> &'static str {
        self.decl().key
    }

    /// The top-level `config.yaml` section whose mere EXISTENCE declares this plane. The three are
    /// siblings of one shape, never cross-referencing sections.
    pub(crate) fn config_section(self) -> &'static str {
        self.decl().config_section
    }

    /// The `ScopeRef` kinds that grant access ON this plane, gated through `scope_allowed`.
    ///
    /// A slice rather than one string because a plane may grant at more than one granularity: MCP
    /// grants a whole server or a single tool. Cross-kind matching is fail-closed in the store, so
    /// these sets are what keep one plane's grant from admitting another plane's traffic.
    pub(crate) fn scope_kinds(self) -> &'static [&'static str] {
        self.decl().scope_kinds
    }

    /// WHAT ONE REGISTRATION ON THIS PLANE IS CALLED, in the words an operator reads back in a
    /// `404`. The vocabularies genuinely differ — a `tools:` entry is a server, an `agents:` entry
    /// is a fronted agent — and stating them here is what lets ONE not-found rule serve both admin
    /// surfaces instead of one hand-written refusal per plane that can drift apart in wording.
    ///
    /// The residual LLM plane has no registered upstream of its own; a pool is named by its own
    /// section and is not looked up through this rule.
    pub(crate) fn subject_noun(self) -> &'static str {
        self.decl().subject_noun
    }

    /// THE AUDIT RESOURCE KIND for a registration on this plane — the `kind` half of a
    /// `kind:name` audit resource, and the prefix of every audit ACTION word the plane's verbs
    /// record (`mcp_server.connect`, `a2a_agent.approve`).
    ///
    /// Named once, per plane, for the same reason the scope kinds are: these strings are read back
    /// by audit queries and compliance exports, and two of them agreeing by coincidence is how one
    /// plane's records start answering another plane's question.
    pub(crate) fn audit_kind(self) -> &'static str {
        self.decl().audit_kind
    }

    /// The distinct WIRE FORMATS this plane translates between, named. Not transports.
    ///
    /// These strings are the `ingress_protocol` metric-label vocabulary, which is why they are
    /// stated here beside [`Plane::key`] rather than per plane: a label that means "which dialect
    /// spoke to us" has to be spelled the same way on every plane or a dashboard cannot compare
    /// them, and two planes agreeing by coincidence is how the LLM plane's `openai` and some other
    /// plane's `openai` end up in one series meaning two things.
    pub(crate) fn wire_format_names(self) -> &'static [&'static str] {
        (self.decl().wire_format_names)()
    }

    /// How many distinct WIRE FORMATS this plane translates between. DERIVED from
    /// [`Plane::wire_format_names`] rather than written as a second literal, so a plane cannot gain
    /// a dialect in one place and keep its old count in the other — which would silently keep
    /// [`Plane::has_superset_ir`] answering the pre-change question.
    pub(crate) fn wire_formats(self) -> usize {
        self.wire_format_names().len()
    }

    /// The plane's ONE wire format, when it has exactly one — otherwise `None`.
    ///
    /// COMPUTED, like [`Plane::has_superset_ir`], and for the same reason. A plane with a single
    /// dialect can be labelled with it at the ingress BOUNDARY, before any handler has read a byte
    /// of the body, because there is nothing to decide. A plane with several cannot: which dialect
    /// spoke is a fact only its reader knows, so that plane labels its own requests from inside
    /// (the LLM plane does exactly this, in `ingress::finish_inner`). Writing this as
    /// `matches!(self, Plane::Mcp | Plane::A2a)` would make it a fact about today's planes; derived
    /// from the format list it is a RULE, and the day MCP speaks a second dialect the boundary
    /// stops labelling it and the rule says so rather than a stale literal quietly lying.
    pub(crate) fn sole_wire_format(self) -> Option<&'static str> {
        Self::sole_of(self.wire_format_names())
    }

    /// The `sole_wire_format` DERIVATION, split from the registry read so the ZERO-dialect case is
    /// a case a test can drive. The LLM plane's list is `known_protocols()`, and the core split
    /// (step 3.7) is what makes an EMPTY registry reachable — from step 4 a protocol is a
    /// dependency edge, and a build with every LLM edge removed is a legal build the deletion gate
    /// constructs on purpose. Before this arm existed, empty fell into the same `_ => None` as
    /// "several", so the plane silently stopped being labelled at the ingress boundary with no
    /// statement that anyone had decided that. The answer is STILL `None` — a plane with no
    /// dialect has nothing to label a request with — but it is now a signed decision with a test
    /// (`plane/tests/`), not a match arm's accident. Same for `has_superset_ir` below: zero wire
    /// formats have earned nothing, so `superset_of(0)` is `false` BY DECISION.
    pub(crate) fn sole_of(names: &'static [&'static str]) -> Option<&'static str> {
        match names {
            // ZERO dialects: nothing can be labelled, deliberately — see the doc comment.
            [] => None,
            [only] => Some(only),
            _ => None,
        }
    }

    /// Whether this plane has EARNED a superset intermediate representation. See the module header:
    /// the threshold is two wire formats, and nothing else.
    pub(crate) fn has_superset_ir(self) -> bool {
        Self::superset_of(self.wire_formats())
    }

    /// The `has_superset_ir` derivation, split out for the same zero-dialect reason as
    /// [`Plane::sole_of`].
    pub(crate) fn superset_of(wire_formats: usize) -> bool {
        wire_formats >= 2
    }
}

/// PLANE DISPATCH: which plane an inbound request belongs to.
///
/// The LLM plane is the RESIDUAL and is never mounted. That mirrors the router, where the protocol
/// catch-all claims every unclaimed path by construction, and it means there is exactly one door
/// per plane rather than a precedence question with no good answer.
///
/// A non-LLM plane claims a path only when the operator has MOUNTED it. A deployment that never
/// enabled MCP cannot have a request routed onto the MCP plane by URL shape alone: a plane exists
/// because it is configured, not because its name appears in a path.
///
/// ## WHY A PLANE MAY CLAIM MORE THAN ONE PATH
///
/// A plane's paths used to be one `Option<String>` each, which was right while every plane spoke one
/// binding over one channel. A2A's gRPC binding broke that, and not by preference: a gRPC client
/// derives the request path from the `.proto`'s package and service name and can be handed nothing
/// else — `grpc.insecure_channel` takes an AUTHORITY, never a path prefix — so busbar's gRPC A2A
/// binding is served at `/lf.a2a.v1.A2AService/*` and cannot be served under `/a2a`. (The HTTP+JSON
/// binding needed no second claim: its paths hang UNDER `/a2a`, which the first claim already
/// covers at a segment boundary.)
///
/// The alternative was to leave that path unclaimed, and it is worth naming what that would have
/// cost, because it is a security property rather than a tidiness one: [`Self::admission_for`]
/// resolves the RFC 8707 audience THROUGH this table, so an unclaimed path is a path where no
/// token's `aud` is checked. The gRPC binding would then have admitted a token minted for any other
/// resource — the exact confused-deputy hole the mount-side audience exists to close. A plane claims
/// every path it answers on, or its door is only as strong as its narrowest binding.
///
/// The FIRST claim is the plane's CANONICAL mount ([`Self::mount_of`]) — the one an audience is
/// derived from and the one a handler means when it asks for "its own path".
///
/// ## Why the table is keyed by plane KEY rather than by a typed field per plane
///
/// It used to be four fields — `mcp`, `a2a`, and an admission each — and that was the same closed
/// set the `Plane` enum is: a plane not named here could not be dispatched, no matter who linked
/// what. The claims and admission a plane contributes are now DATA, folded in from each plane's
/// [`registry::PlaneDecl`] against that plane's own runtime object, so a plane extracted to a crate
/// registers its door the same way it registers its vocabulary. The map is keyed by the plane's
/// [`Plane::key`] — the one stable string every other plane surface is already keyed by — so a
/// registered plane with no enum variant still has exactly one row here and exactly one audience.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PlaneDispatch {
    /// The paths each plane answers on, keyed by plane key, canonical claim first. A key is present
    /// only once the plane has MOUNTED at least one path; an absent key is an unmounted plane, which
    /// [`Self::claims_of`] reads as the empty slice.
    claims: std::collections::BTreeMap<&'static str, Vec<Claim>>,
    /// The admission facts each mounted plane bound, keyed by plane key. Resolved THROUGH
    /// [`Self::claims`] by [`Self::admission_for`], so an admission without a matching claim is inert
    /// — it never lends its audience to a path the plane does not answer on.
    admissions: std::collections::BTreeMap<&'static str, PlaneAdmission>,
}

/// ONE PATH A PLANE ANSWERS ON, and the WIRE FORMAT it is spoken in there.
///
/// The wire format is recorded WITH the path rather than derived from the plane, and that is what
/// keeps the ingress boundary able to label a plane that speaks more than one. [`Plane::wire_formats`]
/// answers "how many dialects does this plane translate between" — a fact about the plane, and the
/// threshold [`Plane::has_superset_ir`] reads. It cannot answer "which one is being spoken right
/// now", because that is a fact about the DOOR the request came through. A plane whose bindings each
/// have their own door can answer it at the door; one whose bindings share a door cannot, and says so
/// by declaring its CANONICAL format on that claim.
///
/// The A2A plane is both at once, which is why this is a per-claim fact and not a per-plane one:
/// `/a2a` answers JSON-RPC and HTTP+JSON, so its claim names `jsonrpc` (the canonical one, and the
/// one a door refusal's body is shaped in) and `a2a::receive::invoke` labels those requests itself
/// with the leg it actually read; `/lf.a2a.v1.A2AService` answers gRPC and nothing else, so its
/// claim names `grpc` and the boundary can label it before any handler runs.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Claim {
    /// The normalised mount path, matched at a segment boundary.
    path: String,
    /// The [`Plane::wire_format_names`] entry spoken here. Not a free string: a claim naming a
    /// format its plane does not list would put a label in the `ingress_protocol` series that no
    /// plane admits to speaking, which is exactly the kind of coincidence that vocabulary exists to
    /// prevent. `a_claim_only_names_a_wire_format_its_plane_speaks` holds it.
    wire: &'static str,
}

/// What a bearer token presented on a mounted plane must be BOUND to, and where a refused caller is
/// told to go and get one that is.
///
/// Both fields are RFC values, not busbar inventions, and neither names a plane — which is the
/// point. An audience-bound ingress is a general shape (OAuth 2.1 resource servers all have one);
/// MCP is merely the first plane to mount one, and A2A will mount a second with different strings
/// and no new code here.
///
/// ## Why the audience lives beside the mount rather than in the handler
///
/// The confused-deputy defence (RFC 8707) is "a token minted for someone else must not be spendable
/// here". If that check sat in a handler, a route added to this plane later would be admitted by the
/// middleware before anyone thought about it. Keeping it beside the MOUNT means the check is a
/// property of the door, so every path behind that door inherits it and a new handler cannot forget.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlaneAdmission {
    /// RFC 8707 resource indicator: the exact `aud` an admitted token must carry. Compared for
    /// EQUALITY, never prefix or suffix — a resource indicator is an opaque identifier, and treating
    /// it as a namespace is how `https://gw.example.com/mcp` starts admitting tokens minted for
    /// `https://gw.example.com/mcp-staging`.
    pub audience: String,
    /// The absolute URL of this resource's RFC 9728 protected-resource metadata document, quoted
    /// verbatim in the `resource_metadata` parameter of the `WWW-Authenticate` challenge. This is
    /// the whole of an MCP client's discovery story: it arrives with no credential, reads this URL
    /// out of the `401`, and follows it to the operator's authorization server.
    pub resource_metadata: String,
}

impl PlaneDispatch {
    /// Declare the admission facts for `plane`. Independent of [`Self::mount`] so the two can be set
    /// in either order, but WITHOUT a mount this is inert: [`Self::admission_for`] resolves a path
    /// through the mount first, so admission facts alone never claim a path.
    ///
    /// The residual LLM plane takes none. It is not an audience-bound resource: a plain data-plane
    /// busbar key carries no audience at all, and the verifier rejects any token that does
    /// (`governance::signing`, the 1.6.0 plane boundary). Handing the residual an audience here
    /// would quietly make every unclaimed path an OAuth resource server.
    pub(crate) fn admit(self, plane: Plane, admission: PlaneAdmission) -> Self {
        // The residual takes none — see the doc: an audience on an unmounted plane is inert, and one
        // on the LLM plane would quietly make every unclaimed path an OAuth resource server.
        if plane == Plane::Llm {
            return self;
        }
        self.admit_key(plane.key(), admission)
    }

    /// [`Self::admit`], keyed by plane key rather than by [`Plane`]. The seam the registry-driven
    /// [`registry::build_dispatch`] folds an admission in through, so a plane with no enum variant
    /// binds its audience the same way a built-in does. The residual guard lives on [`Self::admit`]:
    /// a decl that returns `None` for its admission simply never reaches here.
    pub(crate) fn admit_key(mut self, key: &'static str, admission: PlaneAdmission) -> Self {
        self.admissions.insert(key, admission);
        self
    }

    /// The admission facts governing `path`, or `None` when `path` is not under an audience-bound
    /// mount — which includes every path on the residual LLM plane.
    ///
    /// Resolved through [`Self::mounted_plane_of`], so it inherits the segment-boundary match:
    /// `/mcpx` is NOT under a `/mcp` mount and therefore is not audience-checked. That is
    /// deliberate in both directions — a sibling path must neither inherit the plane's grants nor
    /// its refusals.
    pub(crate) fn admission_for(&self, path: &str) -> Option<&PlaneAdmission> {
        // Resolve the plane by MOUNT first — the residual is never mounted, so it never claims a
        // path and never reaches the admission map — then read that plane's bound audience by key.
        self.admissions.get(self.mounted_plane_of(path)?.key())
    }
    /// Mount `plane` at `path`. Mounting [`Plane::Llm`] is a no-op: it is the residual.
    ///
    /// The path is NORMALISED to a leading slash with no trailing slash, so `/mcp`, `/mcp/`, `mcp`
    /// and `mcp/` all dispatch identically. The alternative is a deployment whose plane silently
    /// answers nothing because of a trailing slash.
    ///
    /// Called more than once for one plane, it ADDS a claim rather than replacing the previous one —
    /// see the type's note on why a plane may answer on several paths and why leaving one of them
    /// unclaimed would be an audience hole rather than an inconvenience. The FIRST claim stays
    /// canonical, so the order of these calls decides which path the plane calls its own. A repeated
    /// path is not claimed twice: mounting is idempotent, so a config apply that re-runs the same
    /// sequence cannot grow the table.
    pub(crate) fn mount(self, plane: Plane, path: &str, wire: &'static str) -> Self {
        // Mounting the residual is a no-op: it IS the catch-all, so a second door to it is a
        // precedence question with no good answer.
        if plane == Plane::Llm {
            return self;
        }
        self.mount_key(plane.key(), path, wire)
    }

    /// [`Self::mount`], keyed by plane key rather than by [`Plane`]. The seam
    /// [`registry::build_dispatch`] folds each plane's declared claims in through, so a registered
    /// plane claims a path the same way a built-in does. The residual guard lives on [`Self::mount`];
    /// a plane's decl claims no path for the residual, so it never reaches here for the LLM plane.
    pub(crate) fn mount_key(mut self, key: &'static str, path: &str, wire: &'static str) -> Self {
        let normalised = normalise_mount(path);
        if normalised.is_empty() {
            return self;
        }
        let claims = self.claims.entry(key).or_default();
        if !claims.iter().any(|c| c.path == normalised) {
            claims.push(Claim {
                path: normalised,
                wire,
            });
        }
        self
    }

    /// This plane's CANONICAL mount, or `None` when it is not mounted (always `None` for the
    /// residual LLM plane). Read by the router to mount the right handler, and by an inbound
    /// audience check that needs to know its own canonical path.
    ///
    /// The canonical mount is the FIRST claimed, never "the one that matched": a plane's identity —
    /// the audience a token must be minted for, the base its card publishes — is one string, and
    /// deriving it from whichever binding a request happened to arrive on would give one deployment
    /// two audiences and two published endpoints.
    pub(crate) fn mount_of(&self, plane: Plane) -> Option<&str> {
        self.claims_of(plane).first().map(|c| c.path.as_str())
    }

    /// THE WIRE FORMAT SPOKEN AT `path`, or `None` when no plane claims it.
    ///
    /// This is the `ingress_protocol` label for a request at a plane's door, and it is read off the
    /// CLAIM rather than off the plane so a plane with several bindings is still labellable. Before
    /// claims carried a format, the boundary asked the plane and got `None` the moment a second
    /// dialect landed — which would have silently stopped counting every A2A request on the day the
    /// gRPC binding armed, and a metric that stops is indistinguishable from traffic that stopped.
    pub(crate) fn wire_format_of(&self, path: &str) -> Option<&'static str> {
        Plane::ALL.iter().copied().find_map(|plane| {
            self.claims_of(plane)
                .iter()
                .find(|c| path_is_under(path, &c.path))
                .map(|c| c.wire)
        })
    }

    /// Every path `plane` claims, canonical first. Private: outside this type the distinction that
    /// matters is "which plane claims this path" ([`Self::mounted_plane_of`]) and "what is this
    /// plane's own path" ([`Self::mount_of`]), and handing out the list would invite a third reading.
    fn claims_of(&self, plane: Plane) -> &[Claim] {
        // The residual is never mounted, so its key is never present and this is the empty slice —
        // the same answer the old per-plane `Plane::Llm => &[]` arm gave, now by construction.
        self.claims.get(plane.key()).map_or(&[], Vec::as_slice)
    }

    /// Every plane key that has MOUNTED at least one path in this table, in key order. Read by the
    /// admission ratchets (`plane/tests`): R3 folds the collision check over the planes actually
    /// DISPATCHED here rather than over the declared list, because a scope- or audit-kind collision
    /// only admits another plane's traffic once both colliding planes have a door. Unlike
    /// [`Self::mounted_plane_of`] this names a plane by its KEY, so it reports a registered plane
    /// that has no [`Plane`] variant too.
    pub(crate) fn mounted_keys(&self) -> Vec<&'static str> {
        self.claims.keys().copied().collect()
    }

    /// THE RESOLVER: which plane `path` belongs to, and which WIRE DIALECT it is spoken in.
    ///
    /// ## Why this is one function and not two
    ///
    /// There were two: this table's `plane_of`, and `proto::proto_for_path`, a path-shape
    /// classifier that knew nothing of mounts and ended in `else { openai }`. Both answered "what
    /// is this path", and on a mounted plane they answered DIFFERENTLY: `/mcp` was the MCP plane to
    /// one and an OpenAI endpoint to the other. That is not a cosmetic disagreement — it shipped as
    /// a defect. An oversized POST to `/mcp` was refused with `{"error":{"type":
    /// "request_too_large"}}`, a vendor envelope no JSON-RPC client can decode, on a path the
    /// operator had explicitly mounted as something else. Two readers of one fact will eventually
    /// disagree, and the disagreement surfaces at the error path, where nobody is looking.
    ///
    /// So the order of resolution is now stated once, here, and it is the only order that respects
    /// what a mount MEANS: **the mount table first, the path shape only for what is left over.**
    ///
    /// ## Matching is on a SEGMENT BOUNDARY, never a bare prefix
    ///
    /// A mount at `/mcp` claims `/mcp` and `/mcp/...` and does not claim `/mcpx`. This is the same
    /// over-match the admin `/api` check guards, and getting it wrong here would hand a sibling
    /// path to a plane whose grants are meant to be inadmissible everywhere else — and, in the
    /// other direction, hand it that plane's REFUSALS, which is how a caller learns the shape of a
    /// door it was never at.
    ///
    /// ## A plane claims a path only when the operator MOUNTED it
    ///
    /// The residual is reached by falling THROUGH the mount table, never by naming it, so a
    /// deployment that never enabled MCP has no MCP plane and `/mcp` is an ordinary unclaimed path.
    /// Nothing here lets a plane claim a path by URL shape.
    pub(crate) fn ingress_of(&self, path: &str) -> Ingress {
        match self.mounted_plane_of(path) {
            Some(plane) => Ingress::Mounted(plane),
            // THE RESIDUAL ARM, and the only place a path SHAPE decides anything. It answers
            // `None` for a path that names no dialect — an honest answer the old classifier could
            // not give, because it spent that case on `openai`.
            None => Ingress::Residual(crate::proto::residual_dialect_for_path(path)),
        }
    }

    /// The plane that CLAIMS `path` BY MOUNT, or `None` when `path` falls through to the residual.
    ///
    /// The same walk [`Self::plane_of`] does — it is written once, here, and `plane_of` is merely
    /// the arm that names the residual — but it keeps the residual DISTINGUISHABLE, which
    /// `plane_of` deliberately does not. [`super::observe`] needs that distinction and does not
    /// want a plane comparison to get it: the plane ingress boundary emits a request's metrics only
    /// for a plane that has a DOOR of its own, because the residual labels its own requests from
    /// inside its handler, where the dialect it spoke is known. Written as `if plane == Plane::Llm`
    /// that would be a plane branch standing in for a property the mount table already knows — and
    /// it would be wrong the day a fourth plane is added as a residual sibling.
    ///
    /// The walk covers `Plane::ALL` rather than a hand-listed `[Mcp, A2a]`: the residual has no
    /// mount, so it is skipped by construction rather than by being left off a list a new plane
    /// would have to remember to join.
    pub(crate) fn mounted_plane_of(&self, path: &str) -> Option<Plane> {
        Plane::ALL.iter().copied().find(|plane| {
            self.claims_of(*plane)
                .iter()
                .any(|claim| path_is_under(path, &claim.path))
        })
    }
}

/// WHAT AN INBOUND PATH IS — the single answer [`PlaneDispatch::ingress_of`] gives, and the input
/// every site that must shape a reply from a path alone reads.
///
/// Two variants, and the split is the mount table's: a path is CLAIMED by a plane the operator
/// mounted, or it is not and belongs to the residual. There is deliberately no third variant for
/// "unknown": an unrecognised path is not a fourth kind of thing, it is a residual path whose
/// dialect is not legible, which is what `Residual(None)` says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Ingress {
    /// A path a plane CLAIMS BY MOUNT, at a segment boundary.
    Mounted(Plane),
    /// The residual LLM plane. `Some(dialect)` when the path shape names one of the registered LLM
    /// dialects; `None` when it names none — a bare `/`, a typo, a probe. `None` is a real answer
    /// and not a failure: what to SAY to a caller whose dialect is unknown is a decision for the
    /// site composing the reply, not for the resolver, which would otherwise have to invent a
    /// protocol identity for a path that carries none.
    Residual(Option<&'static str>),
}

impl Ingress {
    /// The WIRE FORMAT spoken on this path, or `None` when the path names none.
    ///
    /// This is the `ingress_protocol` metric-label vocabulary (see [`Plane::wire_format_names`]),
    /// so a mounted plane labels as its own dialect rather than as whichever LLM dialect its path
    /// happens to resemble.
    pub(crate) fn wire_format(self) -> Option<&'static str> {
        match self {
            // A plane with several dialects cannot be labelled from the boundary — which dialect
            // spoke is a fact only its reader knows. `sole_wire_format` is that rule, computed.
            Ingress::Mounted(plane) => plane.sole_wire_format(),
            Ingress::Residual(dialect) => dialect,
        }
    }

    /// THE DIALECT AN ANSWER IS SHAPED IN when the request itself could not say which — a `413` for
    /// a body nothing read, a `401` before any handler ran, a `404` for a path that matched nothing.
    ///
    /// ## Why this is a DIFFERENT question from [`Self::wire_format`], and why conflating them broke
    ///
    /// [`Self::wire_format`] answers "which dialect DID speak", and `None` is its honest answer for
    /// a plane with several: nobody at the door knows yet. That is exactly right for a metric label,
    /// where guessing invents a fact. It is exactly wrong for an ERROR BODY, where `None` is not an
    /// option — some bytes have to go back — and the caller of `envelope_dialect` had one fallback
    /// for both cases: OpenAI's envelope.
    ///
    /// That fallback was harmless while every mounted plane spoke one dialect. The moment the A2A
    /// plane spoke two, `wire_format()` started answering `None` for it and every door-level refusal
    /// on a MOUNTED, audience-bound plane would have been shaped, labelled and messaged as OPENAI —
    /// the precise defect the merged resolver was built to end, re-entering through the fallback
    /// rather than through a second classifier.
    ///
    /// So a mounted plane answers its FIRST wire format. Not an arbitrary pick: `supportedInterfaces`
    /// is an ORDERED list whose first entry is the preferred binding, busbar's own card publishes
    /// these in this order, and a refusal that cannot know which binding the caller intended is owed
    /// the one the card names first.
    pub(crate) fn shaping_wire_format(self) -> Option<&'static str> {
        match self {
            Ingress::Mounted(plane) => plane.wire_format_names().first().copied(),
            Ingress::Residual(dialect) => dialect,
        }
    }
}

/// `/mcp/` -> `/mcp`, `mcp` -> `/mcp`, `/` -> `` (which mounts nothing).
fn normalise_mount(path: &str) -> String {
    let trimmed = path.trim().trim_matches('/');
    if trimmed.is_empty() {
        return String::new();
    }
    format!("/{trimmed}")
}

/// `path` is `mount` exactly, or lies beneath it at a SEGMENT boundary.
fn path_is_under(path: &str, mount: &str) -> bool {
    match path.strip_prefix(mount) {
        Some("") => true,
        Some(rest) => rest.starts_with('/'),
        None => false,
    }
}

/// THE SHARED CONTAINER for the three sibling plane sections: `pools:`, `tools:` and `agents:` are
/// ONE code object with three namespaces, not three types that happen to look alike.
///
/// ## Siblings, and therefore no cross-references
///
/// The sections are INDEPENDENT namespaces. One name may exist in all three and each means a
/// different thing, so a name is not globally unique and must never be treated as if it were.
///
/// The rule that follows, and the reason this type exists rather than three maps: a name is
/// resolved ONLY within the plane doing the referencing. A `tools:` entry naming an agent is not a
/// clever shortcut, it is a plane boundary violation, and the resolver REFUSES it.
///
/// ## The refusal DIAGNOSES rather than merely denying
///
/// [`RefError::CrossPlane`] names the plane the entry actually lives on, so the operator reads
/// "that is an agent, referenced from a tools entry". A bare not-found would send someone hunting
/// for a typo that is not there, which is why an unknown name is a genuinely different error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PlaneSections<T> {
    llm: std::collections::BTreeMap<String, T>,
    mcp: std::collections::BTreeMap<String, T>,
    a2a: std::collections::BTreeMap<String, T>,
}

/// Why a name did not resolve. The two arms are kept distinct because only one of them is
/// actionable in the same way.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RefError {
    /// The name exists, but on ANOTHER plane. A plane boundary violation.
    CrossPlane {
        name: String,
        referenced_from: Plane,
        defined_in: Plane,
    },
    /// The name exists nowhere.
    Unknown { name: String, plane: Plane },
}

impl std::fmt::Display for RefError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RefError::CrossPlane {
                name,
                referenced_from,
                defined_in,
            } => write!(
                f,
                "`{}` references `{name}`, which is defined in `{}`. The plane sections are \
                 siblings and never reference each other: define `{name}` in `{}`, or move the \
                 reference.",
                referenced_from.config_section(),
                defined_in.config_section(),
                referenced_from.config_section()
            ),
            RefError::Unknown { name, plane } => write!(
                f,
                "`{}` references `{name}`, which is not defined.",
                plane.config_section()
            ),
        }
    }
}

// `Default` is hand-written, NOT derived. The derive would bound it on `T: Default`, which is
// wrong twice over: an EMPTY container needs nothing from `T`, and requiring it would force every
// entry type a plane ever holds to invent a meaningless empty value just to be storable here.
impl<T> Default for PlaneSections<T> {
    fn default() -> Self {
        Self {
            llm: std::collections::BTreeMap::new(),
            mcp: std::collections::BTreeMap::new(),
            a2a: std::collections::BTreeMap::new(),
        }
    }
}

impl<T> PlaneSections<T> {
    fn map(&self, plane: Plane) -> &std::collections::BTreeMap<String, T> {
        match plane {
            Plane::Llm => &self.llm,
            Plane::Mcp => &self.mcp,
            Plane::A2a => &self.a2a,
        }
    }

    fn map_mut(&mut self, plane: Plane) -> &mut std::collections::BTreeMap<String, T> {
        match plane {
            Plane::Llm => &mut self.llm,
            Plane::Mcp => &mut self.mcp,
            Plane::A2a => &mut self.a2a,
        }
    }

    /// Declare `name` on `plane`.
    pub(crate) fn insert(&mut self, plane: Plane, name: &str, entry: T) -> Option<T> {
        self.map_mut(plane).insert(name.to_string(), entry)
    }

    /// This plane's entry for `name`, or `None`. Scoped to the plane: it never reads a sibling
    /// section, so a caller cannot accidentally cross the boundary by using the cheap read.
    pub(crate) fn get(&self, plane: Plane, name: &str) -> Option<&T> {
        self.map(plane).get(name)
    }

    /// One plane's whole section.
    pub(crate) fn section(&self, plane: Plane) -> &std::collections::BTreeMap<String, T> {
        self.map(plane)
    }

    /// THE VALIDATOR ENTRY POINT: resolve `name` as referenced FROM `plane`, refusing a cross-plane
    /// reference with a diagnosis.
    ///
    /// The sibling scan runs in `Plane::ALL` order so a name defined on several other planes always
    /// diagnoses the same one. A nondeterministic diagnostic is worse than none: it makes a boot
    /// failure unreproducible.
    pub(crate) fn resolve(&self, plane: Plane, name: &str) -> Result<&T, RefError> {
        if let Some(entry) = self.map(plane).get(name) {
            return Ok(entry);
        }
        for other in Plane::ALL {
            if *other != plane && self.map(*other).contains_key(name) {
                return Err(RefError::CrossPlane {
                    name: name.to_string(),
                    referenced_from: plane,
                    defined_in: *other,
                });
            }
        }
        Err(RefError::Unknown {
            name: name.to_string(),
            plane,
        })
    }

    /// Every entry across every plane, attributed to the plane it belongs to. Walked by the config
    /// validator, so a plane absent here is a plane that is never validated.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (Plane, &str, &T)> {
        Plane::ALL.iter().flat_map(move |p| {
            self.map(*p)
                .iter()
                .map(move |(name, entry)| (*p, name.as_str(), entry))
        })
    }
}

#[cfg(test)]
#[path = "tests/plane_tests.rs"]
mod plane_tests;

#[cfg(test)]
#[path = "tests/sections_tests.rs"]
mod sections_tests;

#[cfg(test)]
#[path = "tests/metrics_tests.rs"]
mod metrics_tests;
