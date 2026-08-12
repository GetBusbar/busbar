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

// THE SPINE IS NOW LOAD-BEARING, which is what it was landed ahead of a caller for. THREE
// production callers, all arrived on the same day and none of them written per plane:
//
//   * [`observe`], the plane ingress boundary — asks `PlaneDispatch::mounted_plane_of` which plane
//     a request arrived on and labels that request's metrics with `Plane::key`. Before it, MCP and
//     A2A traffic appeared in no Prometheus series at all.
//   * the trust sweep job (`crate::trust::sweep`), which carries `Plane` as its log label.
//   * the admin trust verb surface (`crate::admin::planeverbs`), which reads `Plane::subject_noun`
//     for its one `404` and `Plane::audit_kind` for its audit action and resource.
//
// The last two REPLACED a pair of plane-local copies — a scheduler and an admin verb set written
// twice, discovered when ten branches merged and the structural lint saw both halves at once for
// the first time. That is precisely what landing the spine first was meant to prevent, and it is
// worth recording that the spine existing did not prevent it: two authors each wrote a plane-local
// copy without consulting it. The lint caught what the spine alone could not.
//
// STILL WITHOUT A PRODUCTION CALLER, and named rather than left to be discovered: `PlaneSections`,
// `has_superset_ir` and `wire_formats`. The candidate projection and the shared
// pools/tools/agents container are the dependants those are waiting on, so the attribute stays
// until they land.
#![cfg_attr(not(test), allow(dead_code))]

pub(crate) mod observe;

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
    pub(crate) const ALL: &'static [Plane] = &[Plane::Llm, Plane::Mcp, Plane::A2a];

    /// The plane's short stable name, for logs, metrics labels and audit resources.
    pub(crate) fn key(self) -> &'static str {
        match self {
            Plane::Llm => "llm",
            Plane::Mcp => "mcp",
            Plane::A2a => "a2a",
        }
    }

    /// The top-level `config.yaml` section whose mere EXISTENCE declares this plane. The three are
    /// siblings of one shape, never cross-referencing sections.
    pub(crate) fn config_section(self) -> &'static str {
        match self {
            Plane::Llm => "pools",
            Plane::Mcp => "tools",
            Plane::A2a => "agents",
        }
    }

    /// The `ScopeRef` kinds that grant access ON this plane, gated through `scope_allowed`.
    ///
    /// A slice rather than one string because a plane may grant at more than one granularity: MCP
    /// grants a whole server or a single tool. Cross-kind matching is fail-closed in the store, so
    /// these sets are what keep one plane's grant from admitting another plane's traffic.
    pub(crate) fn scope_kinds(self) -> &'static [&'static str] {
        match self {
            Plane::Llm => &["pool"],
            Plane::Mcp => &["mcp_server", "mcp_tool"],
            Plane::A2a => &["agent"],
        }
    }

    /// WHAT ONE REGISTRATION ON THIS PLANE IS CALLED, in the words an operator reads back in a
    /// `404`. The vocabularies genuinely differ — a `tools:` entry is a server, an `agents:` entry
    /// is a fronted agent — and stating them here is what lets ONE not-found rule serve both admin
    /// surfaces instead of one hand-written refusal per plane that can drift apart in wording.
    ///
    /// The residual LLM plane has no registered upstream of its own; a pool is named by its own
    /// section and is not looked up through this rule.
    pub(crate) fn subject_noun(self) -> &'static str {
        match self {
            Plane::Llm => "pool",
            Plane::Mcp => "MCP server",
            Plane::A2a => "fronted agent",
        }
    }

    /// THE AUDIT RESOURCE KIND for a registration on this plane — the `kind` half of a
    /// `kind:name` audit resource, and the prefix of every audit ACTION word the plane's verbs
    /// record (`mcp_server.connect`, `a2a_agent.approve`).
    ///
    /// Named once, per plane, for the same reason the scope kinds are: these strings are read back
    /// by audit queries and compliance exports, and two of them agreeing by coincidence is how one
    /// plane's records start answering another plane's question.
    pub(crate) fn audit_kind(self) -> &'static str {
        match self {
            Plane::Llm => "pool",
            Plane::Mcp => "mcp_server",
            Plane::A2a => "a2a_agent",
        }
    }

    /// The distinct WIRE FORMATS this plane translates between, named. Not transports.
    ///
    /// These strings are the `ingress_protocol` metric-label vocabulary, which is why they are
    /// stated here beside [`Plane::key`] rather than per plane: a label that means "which dialect
    /// spoke to us" has to be spelled the same way on every plane or a dashboard cannot compare
    /// them, and two planes agreeing by coincidence is how the LLM plane's `openai` and some other
    /// plane's `openai` end up in one series meaning two things.
    pub(crate) fn wire_format_names(self) -> &'static [&'static str] {
        match self {
            // Read off the real registry: the dialects busbar actually speaks are what earn this
            // plane its IR, so adding one cannot silently leave the rule behind.
            Plane::Llm => crate::proto::KNOWN_PROTOCOLS,
            // JSON-RPC 2.0, over any of three transports.
            Plane::Mcp => &["jsonrpc"],
            // JSON-RPC 2.0. One wire format today.
            Plane::A2a => &["jsonrpc"],
        }
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
        match self.wire_format_names() {
            [only] => Some(only),
            _ => None,
        }
    }

    /// Whether this plane has EARNED a superset intermediate representation. See the module header:
    /// the threshold is two wire formats, and nothing else.
    pub(crate) fn has_superset_ir(self) -> bool {
        self.wire_formats() >= 2
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
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct PlaneDispatch {
    mcp: Option<String>,
    a2a: Option<String>,
    mcp_admission: Option<PlaneAdmission>,
    a2a_admission: Option<PlaneAdmission>,
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
pub(crate) struct PlaneAdmission {
    /// RFC 8707 resource indicator: the exact `aud` an admitted token must carry. Compared for
    /// EQUALITY, never prefix or suffix — a resource indicator is an opaque identifier, and treating
    /// it as a namespace is how `https://gw.example.com/mcp` starts admitting tokens minted for
    /// `https://gw.example.com/mcp-staging`.
    pub(crate) audience: String,
    /// The absolute URL of this resource's RFC 9728 protected-resource metadata document, quoted
    /// verbatim in the `resource_metadata` parameter of the `WWW-Authenticate` challenge. This is
    /// the whole of an MCP client's discovery story: it arrives with no credential, reads this URL
    /// out of the `401`, and follows it to the operator's authorization server.
    pub(crate) resource_metadata: String,
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
    pub(crate) fn admit(mut self, plane: Plane, admission: PlaneAdmission) -> Self {
        match plane {
            Plane::Llm => {}
            Plane::Mcp => self.mcp_admission = Some(admission),
            Plane::A2a => self.a2a_admission = Some(admission),
        }
        self
    }

    /// The admission facts governing `path`, or `None` when `path` is not under an audience-bound
    /// mount — which includes every path on the residual LLM plane.
    ///
    /// Resolved through [`Self::plane_of`], so it inherits the segment-boundary match: `/mcpx` is
    /// NOT under a `/mcp` mount and therefore is not audience-checked. That is deliberate in both
    /// directions — a sibling path must neither inherit the plane's grants nor its refusals.
    pub(crate) fn admission_for(&self, path: &str) -> Option<&PlaneAdmission> {
        match self.plane_of(path) {
            Plane::Llm => None,
            Plane::Mcp => self.mcp_admission.as_ref(),
            Plane::A2a => self.a2a_admission.as_ref(),
        }
    }
    /// Mount `plane` at `path`. Mounting [`Plane::Llm`] is a no-op: it is the residual.
    ///
    /// The path is NORMALISED to a leading slash with no trailing slash, so `/mcp`, `/mcp/`, `mcp`
    /// and `mcp/` all dispatch identically. The alternative is a deployment whose plane silently
    /// answers nothing because of a trailing slash.
    pub(crate) fn mount(mut self, plane: Plane, path: &str) -> Self {
        let normalised = normalise_mount(path);
        if normalised.is_empty() {
            return self;
        }
        match plane {
            Plane::Llm => {}
            Plane::Mcp => self.mcp = Some(normalised),
            Plane::A2a => self.a2a = Some(normalised),
        }
        self
    }

    /// This plane's mount, or `None` when it is not mounted (always `None` for the residual LLM
    /// plane). Read by the router to mount the right handler, and by an inbound audience check that
    /// needs to know its own canonical path.
    pub(crate) fn mount_of(&self, plane: Plane) -> Option<&str> {
        match plane {
            Plane::Llm => None,
            Plane::Mcp => self.mcp.as_deref(),
            Plane::A2a => self.a2a.as_deref(),
        }
    }

    /// The plane `path` belongs to, falling back to the residual LLM plane.
    ///
    /// Matching is on a SEGMENT BOUNDARY, never a bare prefix: a mount at `/mcp` claims `/mcp` and
    /// `/mcp/...` but not `/mcpx`. This is the same over-match the admin `/api` check guards, and
    /// getting it wrong here would hand a sibling path to a plane whose grants are meant to be
    /// inadmissible everywhere else.
    pub(crate) fn plane_of(&self, path: &str) -> Plane {
        self.mounted_plane_of(path).unwrap_or(Plane::Llm)
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
            self.mount_of(*plane)
                .is_some_and(|mount| path_is_under(path, mount))
        })
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
