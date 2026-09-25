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
//!    plane   plane   plane    <- each plane owns ONE canonical type
//!       |
//!      IR                      <- only a plane with more than one wire format needs one
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
//! So [`has_superset_ir`] is derived from [`wire_formats`] rather than written as
//! `matches!(key, FALLBACK_KEY)`. That makes it a RULE rather than a fact about today's planes: the
//! day a second dialect lands on some plane, that plane earns an IR and the test says so. And the
//! fallback plane's dialect count is read off the real protocol registry, so a new dialect does not
//! depend on anyone remembering to bump a literal here.
//!
//! A TRANSPORT IS NOT A WIRE FORMAT. A plane can be reachable over several transports while every
//! one of them carries the same message shape. Counting transports would hand a single-dialect
//! plane an IR it has not earned.
//!
//! ## Each plane still owns ONE canonical type
//!
//! Even without a superset, every plane has one canonical internal type, so the architecture reads
//! the same everywhere: protocol in, canonical type, protocol out. For a single-wire-format plane
//! that canonical type IS the protocol's own model, MIRRORED IN OUR STRUCTS rather than adopted
//! from a third party's generated ones. A protocol that is versioned and moving must not let its
//! internal representation be somebody's generated types; if it were, a spec revision would ripple
//! through the engine, the registry, the catalogue cache and the audit records instead of staying
//! contained to the reader and writer at the edge.

// THE SPINE IS NOW LOAD-BEARING, which is what it was landed ahead of a caller for. FOUR
// production callers, none of them written per plane:
//
//   * [`observe`], the plane ingress boundary — asks `PlaneDispatch::mounted_plane_of` which plane
//     a request arrived on and labels that request's metrics with `Plane::key`. Before it, non-fallback
//     plane traffic appeared in no Prometheus series at all.
//   * verify-on-call (`crate::trust::verify`), which carries `Plane` as its diagnostic label.
//   * the admin trust verb surface (`crate::admin::planeverbs`), which reads `Plane::subject_noun`
//     for its one `404` and `Plane::audit_kind` for its audit action and resource.
//
// The last two REPLACED a pair of plane-local copies — a scheduler and a control-verb set written
// twice, discovered when ten branches merged and the structural lint saw both halves at once for
// the first time. That is precisely what landing the spine first was meant to prevent, and it is
// worth recording that the spine existing did not prevent it: two authors each wrote a plane-local
// copy without consulting it. The lint caught what the spine alone could not.
//
//   * the ERROR-SHAPING boundary, through [`PlaneDispatch::ingress_of`] — the one resolver that
//     answers "which plane, and in which wire dialect, is this path spoken". Every site that must
//     shape an answer from a path alone (the `413` reshape, the `404`/`405` fallbacks, the
//     auth-time `401`) reads it, so an oversized POST to a mounted plane is now refused in that
//     plane's own dialect instead of in another plane's envelope its client cannot decode.
//   * the CARD-PUBLISHING boundary, and the first caller to read the wire-format LIST rather than
//     its length: one plane's own serve-layer binding-advertiser decides which
//     `supportedInterfaces[].protocolBinding` busbar may publish on a card pointing at busbar's own
//     address. That was previously a literal in the rewrite, and it published a binding at an
//     address busbar does not serve it on.
//
// STILL WITHOUT A PRODUCTION CALLER, and named rather than left to be discovered: `PlaneSections`
// and `has_superset_ir`. The candidate projection and the shared sibling-section container are
// the dependants those are waiting on, so the attribute stays until they land.
//
// `wire_formats` is NOT in that list, and has two callers rather than one: `sole_wire_format` reads
// its length on the request path, and the card-publishing boundary reads its contents to decide which
// bindings a served card may advertise. Both are named here because this header, not the call
// sites, is what states whether a member of this module is reachable.
#![cfg_attr(not(test), allow(dead_code))]

pub mod approvals;
pub mod auditlog;
pub mod config;
pub mod cost;
pub mod observe;
pub(crate) mod quarantine;
pub mod registry;
// `store` is a core-internal plane primitive. Its module is widened to `pub` ONLY under the
// test-support surface so an extracted plane's own test binary can name the durable-body
// helpers it exercises (`StoreNamedTestExt`, `KIND_TASK_EVENT`, `task_event_row_from_body`); the
// tamper-critical `encode` stays `pub(crate)` regardless (see `store::encode`), so widening the
// module does NOT hand any out-of-crate caller the row-forging primitive.
// W4.b P2: widened to `pub` (planes absorbed substrate's neutral PlaneStore here); `encode` stays pub(crate).
pub mod store;
// A durable task set and its per-task provenance chain were RELOCATED wholesale to a plane crate
// in the 1.7.0 plane extraction: a task is a SINGLE-plane mechanism, so it lives on the plane that
// owns it, backed by the generic neutral `PlaneRecord` store. Core names none of it.

// THE WIRE FORMAT NAMES the mounted planes speak moved DOWN into the neutral `busbar-substrate`
// crate in Phase-B B0-b, so a plane crate can name them without reaching into core. They are the
// same three canonical spellings, re-exported here unchanged so every `crate::plane::WIRE_*` call
// site is untouched:
//
//   WIRE_JSONRPC   — the wire format multiple mounted planes may speak. Read twice as a
//                    `wire_format_names` entry and once by the error-shaping boundary, which decides
//                    a refusal on a mounted plane is shaped as this wire format's error object rather
//                    than another wire format's envelope. A literal spelled per site is how those two
//                    answers start to differ.
//   WIRE_HTTP_JSON — a request-line-addressed binding, where the REQUEST LINE names the operation
//                    rather than a body member. Read three ways that must agree: a `wire_format_names`
//                    entry, the `crate::transport::Transport::HttpJson` label, and (upper-cased by the
//                    owning plane's own serve-layer binding-advertiser) the `protocolBinding` a served
//                    card advertises. The card spelling is upper-cased; this is that lower-cased.
//   WIRE_GRPC      — a second binding a plane may declare as a wire-format name. Lower-case here and
//                    upper-cased once, by the owning plane's own serve-layer binding-advertiser, into
//                    the spelling a served card advertises — so the card cannot claim a binding the
//                    plane does not list.

/// The FALLBACK plane's registry key — DERIVED from the plane registry rather than a hard-coded
/// literal: the ONE built-in plane whose decl declares [`registry::PlaneDeclaration::fallback`]. Read by
/// the fallback guard (`PlaneDispatch::mount`/`admit` no-op) and the fallback-plane telemetry branch
/// so core names no dialect. The composition root (`register_planes`) installs the fallback plane
/// before any reader runs, and core's own test binary carries it in `registry::builtin_plane_decls`,
/// so exactly one fallback is always present. Core expresses "which plane handles unmatched routes"
/// by ASKING the declared fallback plane, never by hard-coding which plane that is.
pub fn fallback_key() -> &'static str {
    let decls = registry::plane_decls();
    // The fallback is FIRST-WINS: with two fallback decls the `find` below would silently pick one
    // and the other's paths would fall through nowhere. At most one plane may flag itself fallback.
    debug_assert!(
        decls.iter().filter(|d| d.fallback).count() <= 1,
        "more than one registered plane declares itself the fallback catch-all — it must be \
         unique or `fallback_key`/`is_fallback` first-win nondeterministically"
    );
    // Prefer the plane that DECLARES itself the fallback (always present in a production or
    // core-`cfg(test)` build). Fall back to the BASE (first-layered) registered plane for the one
    // build where no fallback is flagged: the `test-support`-only dependency-copy of core the plane
    // crates link, whose built-in plane rows are empty and which registers only the plane under
    // test — a TestApp built there has no fallback plane, so this key labels an empty telemetry
    // bank and is never emitted. Never a hard-coded literal, so core names no dialect.
    decls
        .iter()
        .find(|d| d.fallback)
        .or_else(|| decls.first())
        .map(|d| d.key)
        .unwrap_or("")
}

/// Whether `key` names THE FALLBACK plane — the non-panicking predicate the fallback GUARDS read
/// (`PlaneDispatch::mount`/`admit` no-op; the fallback-plane telemetry branch). Distinct from
/// [`fallback_key`]: it answers "is THIS key the fallback" WITHOUT requiring a fallback to be
/// registered, so it is safe in a build where the fallback plane's decl is absent — the
/// dependency-copy of core the plane crates link, whose built-in plane rows are empty and which only
/// ever asks this about a mounted plane's OWN key (never the fallback's key). `fallback_key`, by
/// contrast, is read only on paths (App build, request telemetry family) where the fallback is
/// always present.
pub(crate) fn is_fallback(key: &str) -> bool {
    registry::plane_decls()
        .iter()
        .any(|d| d.key == key && d.fallback)
}

/// Every built-in plane's registry key, in layering order. Iterated by dispatch, the config
/// validator and the candidate projection, so a plane absent from here is a plane that silently
/// does not exist.
///
/// Driven off [`registry::builtin_plane_decls`], which is itself cfg-gated: each non-fallback
/// plane's key is present only when that plane is compiled in, because with the plane off it has
/// no built-in declaration, so it must not be iterated here — every [`plane_decl`] on it would
/// fault. This is the successor to the old `Plane::ALL`, and the source of the LAYERING iteration
/// order every map walk must borrow rather than reinvent from a map's own key order.
pub fn plane_keys() -> impl Iterator<Item = &'static str> {
    registry::plane_decls().iter().map(|d| d.key)
}

/// The built-in plane declaration for `key`, or panic — the by-key indirection the former `Plane`
/// accessors now read through. Callers wanting a decl FIELD (`config_section`, `subject_noun`,
/// `audit_kind`, `scope_kinds`) read it straight off this; the free fns below are the accessors
/// that COMPUTED something rather than reading a field.
pub fn plane_decl(key: &str) -> &'static registry::PlaneDecl {
    registry::plane_decl_for(key)
        .unwrap_or_else(|| panic!("no built-in plane declared for key `{key}`"))
}

/// The distinct WIRE FORMATS this plane translates between, named. Not transports.
///
/// These strings are the `ingress_protocol` metric-label vocabulary: a label that means "which
/// dialect spoke to us" has to be spelled the same way on every plane or a dashboard cannot
/// compare them, and two planes agreeing by coincidence is how one plane's dialect spelling and
/// another plane's dialect spelling end up in one series meaning two things.
pub fn wire_format_names(key: &str) -> &'static [&'static str] {
    (plane_decl(key).wire_format_names)()
}

/// The plane's ONE wire format, when it has exactly one — otherwise `None`.
///
/// COMPUTED, like [`has_superset_ir`], and for the same reason. A plane with a single dialect can
/// be labelled with it at the ingress BOUNDARY, before any handler has read a byte of the body,
/// because there is nothing to decide. A plane with several cannot: which dialect spoke is a fact
/// only its reader knows, so that plane labels its own requests from inside (the fallback plane
/// does exactly this, in `ingress::finish_inner`). Derived from the format list it is a RULE, and
/// the day a plane speaks a second dialect the boundary stops labelling it and the rule says so
/// rather than a stale literal quietly lying.
pub fn sole_wire_format(key: &str) -> Option<&'static str> {
    sole_of(wire_format_names(key))
}

/// How many distinct WIRE FORMATS this plane translates between. DERIVED from
/// [`wire_format_names`] rather than written as a second literal, so a plane cannot gain a dialect
/// in one place and keep its old count in the other — which would silently keep [`has_superset_ir`]
/// answering the pre-change question.
pub fn wire_formats(key: &str) -> usize {
    wire_format_names(key).len()
}

/// Whether this plane has EARNED a superset intermediate representation. See the module header:
/// the threshold is two wire formats, and nothing else.
pub fn has_superset_ir(key: &str) -> bool {
    superset_of(wire_formats(key))
}

/// The `sole_wire_format` DERIVATION, split from the registry read so the ZERO-dialect case is
/// a case a test can drive. The fallback plane's list is its own registered dialect set, and the
/// core split (step 3.7) is what makes an EMPTY registry reachable — from step 4 a protocol is a
/// dependency edge, and a build with every fallback-plane edge removed is a legal build the
/// deletion gate constructs on purpose. Before this arm existed, empty fell into the same
/// `_ => None` as "several", so the plane silently stopped being labelled at the ingress boundary
/// with no statement that anyone had decided that. The answer is STILL `None` — a plane with no
/// dialect has nothing to label a request with — but it is now a signed decision with a test
/// (`plane/tests/`), not a match arm's accident. Same for `has_superset_ir` above: zero wire
/// formats have earned nothing, so `superset_of(0)` is `false` BY DECISION.
pub fn sole_of(names: &'static [&'static str]) -> Option<&'static str> {
    match names {
        // ZERO dialects: nothing can be labelled, deliberately — see the doc comment.
        [] => None,
        [only] => Some(only),
        _ => None,
    }
}

/// The `has_superset_ir` derivation, split out for the same zero-dialect reason as [`sole_of`].
pub fn superset_of(wire_formats: usize) -> bool {
    wire_formats >= 2
}

/// PLANE DISPATCH: which plane an inbound request belongs to.
///
/// The fallback plane is never mounted. That mirrors the router, where the protocol
/// catch-all claims every unclaimed path by construction, and it means there is exactly one door
/// per plane rather than a precedence question with no good answer.
///
/// A non-fallback plane claims a path only when the operator has MOUNTED it. A deployment that
/// never enabled that plane cannot have a request routed onto it by URL shape alone: a plane exists
/// because it is configured, not because its name appears in a path.
///
/// ## WHY A PLANE MAY CLAIM MORE THAN ONE PATH
///
/// A plane's paths used to be one `Option<String>` each, which was right while every plane spoke one
/// binding over one channel. A plane with a second binding broke that, and not by preference: a
/// client for that second binding derives the request path from its own service description and
/// can be handed nothing else — it takes an AUTHORITY, never a path prefix — so that binding is
/// served at its own dedicated path and cannot be served under the plane's primary mount. (The
/// primary binding needed no second claim: its paths hang under the plane's own mount, which the
/// first claim already covers at a segment boundary.)
///
/// The alternative was to leave that path unclaimed, and it is worth naming what that would have
/// cost, because it is a security property rather than a tidiness one: [`Self::admission_for`]
/// resolves the RFC 8707 audience THROUGH this table, so an unclaimed path is a path where no
/// token's `aud` is checked. A second binding left unclaimed would then admit a token minted for
/// any other resource — the exact confused-deputy hole the mount-side audience exists to close. A
/// plane claims every path it answers on, or its door is only as strong as its narrowest binding.
///
/// The FIRST claim is the plane's CANONICAL mount ([`Self::mount_of`]) — the one an audience is
/// derived from and the one a handler means when it asks for "its own path".
///
/// ## Why the table is keyed by plane KEY rather than by a typed field per plane
///
/// It used to be a fixed set of typed fields, one per plane plus an admission each, and that was
/// the same closed set the `Plane` enum is: a plane not named here could not be dispatched, no
/// matter who linked what. The claims and admission a plane contributes are now DATA, folded in
/// from each plane's [`registry::PlaneDecl`] against that plane's own runtime object, so a plane
/// extracted to a crate registers its door the same way it registers its vocabulary. The map is
/// keyed by the plane's own registry key — the one stable string every other plane surface is
/// already keyed by — so a registered plane with no enum variant still has exactly one row here
/// and exactly one audience.
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
/// keeps the ingress boundary able to label a plane that speaks more than one. [`wire_formats`]
/// answers "how many dialects does this plane translate between" — a fact about the plane, and the
/// threshold [`has_superset_ir`] reads. It cannot answer "which one is being spoken right
/// now", because that is a fact about the DOOR the request came through. A plane whose bindings each
/// have their own door can answer it at the door; one whose bindings share a door cannot, and says so
/// by declaring its CANONICAL format on that claim.
///
/// A plane with two bindings can be both at once, which is why this is a per-claim fact and not a
/// per-plane one: its primary mount can answer more than one dialect on a shared door, so its claim
/// names the canonical one (the one a door refusal's body is shaped in) and the plane's own receive
/// path labels those requests itself with the dialect it actually read; a secondary, dedicated mount
/// answers exactly one dialect and nothing else, so its claim names that dialect and the boundary
/// can label it before any handler runs.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Claim {
    /// The normalised mount path, matched at a segment boundary.
    path: String,
    /// The [`wire_format_names`] entry spoken here. Not a free string: a claim naming a
    /// format its plane does not list would put a label in the `ingress_protocol` series that no
    /// plane admits to speaking, which is exactly the kind of coincidence that vocabulary exists to
    /// prevent. `a_claim_only_names_a_wire_format_its_plane_speaks` holds it.
    wire: &'static str,
}

// What a bearer token presented on a mounted plane must be BOUND to, and where a refused caller is
// told to go and get one that is — [`PlaneAdmission`].
//
// Both fields are RFC values, not busbar inventions, and neither names a plane — which is the
// point. An audience-bound ingress is a general shape (OAuth 2.1 resource servers all have one);
// one plane is merely the first to mount one, and another plane will mount a second with different
// strings and no new code here. Phase-C config-seam relocated this POD to the neutral
// [`busbar_kernel::plane::PlaneAdmission`] so a plane crate contributes its admission across the
// mount seam without naming a core type; core re-exports it here so its own call sites are unchanged.

impl PlaneDispatch {
    /// Declare the admission facts for `plane`. Independent of [`Self::mount`] so the two can be set
    /// in either order, but WITHOUT a mount this is inert: [`Self::admission_for`] resolves a path
    /// through the mount first, so admission facts alone never claim a path.
    ///
    /// The fallback plane takes none. It is not an audience-bound resource: a plain data-plane
    /// busbar key carries no audience at all, and the verifier rejects any token that does
    /// (`governance::signing`, the 1.6.0 plane boundary). Handing the fallback an audience here
    /// would quietly make every unclaimed path an OAuth resource server.
    pub fn admit(self, key: &'static str, admission: PlaneAdmission) -> Self {
        // The fallback takes none — see the doc: an audience on an unmounted plane is inert, and one
        // on the fallback plane would quietly make every unclaimed path an OAuth resource server.
        if is_fallback(key) {
            return self;
        }
        self.admit_key(key, admission)
    }

    /// [`Self::admit`], keyed by plane key rather than by [`Plane`]. The seam the registry-driven
    /// [`registry::build_dispatch`] folds an admission in through, so a plane with no enum variant
    /// binds its audience the same way a built-in does. The fallback guard lives on [`Self::admit`]:
    /// a decl that returns `None` for its admission simply never reaches here.
    pub(crate) fn admit_key(mut self, key: &'static str, admission: PlaneAdmission) -> Self {
        self.admissions.insert(key, admission);
        self
    }

    /// The admission facts governing `path`, or `None` when `path` is not under an audience-bound
    /// mount — which includes every path on the fallback plane.
    ///
    /// Resolved through [`Self::mounted_plane_of`], so it inherits the segment-boundary match:
    /// a sibling path is NOT under a mount that only shares a name prefix, and therefore is not
    /// audience-checked. That is deliberate in both directions — a sibling path must neither
    /// inherit the plane's grants nor its refusals.
    pub fn admission_for(&self, path: &str) -> Option<&PlaneAdmission> {
        // Resolve the plane by MOUNT first — the fallback is never mounted, so it never claims a
        // path and never reaches the admission map — then read that plane's bound audience by key.
        self.admissions.get(self.mounted_plane_of(path)?)
    }
    /// Mount `plane` at `path`. Mounting the fallback plane ([`fallback_key`]) is a no-op.
    ///
    /// The path is NORMALISED to a leading slash with no trailing slash, so equivalent path
    /// spellings all dispatch identically. The alternative is a deployment whose plane silently
    /// answers nothing because of a trailing slash.
    ///
    /// Called more than once for one plane, it ADDS a claim rather than replacing the previous one —
    /// see the type's note on why a plane may answer on several paths and why leaving one of them
    /// unclaimed would be an audience hole rather than an inconvenience. The FIRST claim stays
    /// canonical, so the order of these calls decides which path the plane calls its own. A repeated
    /// path is not claimed twice: mounting is idempotent, so a config apply that re-runs the same
    /// sequence cannot grow the table.
    pub fn mount(self, key: &'static str, path: &str, wire: &'static str) -> Self {
        // Mounting the fallback is a no-op: it IS the catch-all, so a second door to it is a
        // precedence question with no good answer.
        if is_fallback(key) {
            return self;
        }
        self.mount_key(key, path, wire)
    }

    /// [`Self::mount`], keyed by plane key rather than by [`Plane`]. The seam
    /// [`registry::build_dispatch`] folds each plane's declared claims in through, so a registered
    /// plane claims a path the same way a built-in does. The fallback guard lives on [`Self::mount`];
    /// a plane's decl claims no path for the fallback, so it never reaches here for the fallback plane.
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
    /// fallback plane). Read by the router to mount the right handler, and by an inbound
    /// audience check that needs to know its own canonical path.
    ///
    /// The canonical mount is the FIRST claimed, never "the one that matched": a plane's identity —
    /// the audience a token must be minted for, the base its card publishes — is one string, and
    /// deriving it from whichever binding a request happened to arrive on would give one deployment
    /// two audiences and two published endpoints.
    pub fn mount_of(&self, key: &str) -> Option<&str> {
        self.claims_of(key).first().map(|c| c.path.as_str())
    }

    /// THE WIRE FORMAT SPOKEN AT `path`, or `None` when no plane claims it.
    ///
    /// This is the `ingress_protocol` label for a request at a plane's door, and it is read off the
    /// CLAIM rather than off the plane so a plane with several bindings is still labellable. Before
    /// claims carried a format, the boundary asked the plane and got `None` the moment a second
    /// dialect landed — which would have silently stopped counting every request on that plane the
    /// day a second binding armed, and a metric that stops is indistinguishable from traffic that
    /// stopped.
    pub fn wire_format_of(&self, path: &str) -> Option<&'static str> {
        self.claims.keys().copied().find_map(|key| {
            self.claims_of(key)
                .iter()
                .find(|c| path_is_under(path, &c.path))
                .map(|c| c.wire)
        })
    }

    /// Every path `plane` claims, canonical first. Private: outside this type the distinction that
    /// matters is "which plane claims this path" ([`Self::mounted_plane_of`]) and "what is this
    /// plane's own path" ([`Self::mount_of`]), and handing out the list would invite a third reading.
    fn claims_of(&self, key: &str) -> &[Claim] {
        // The fallback is never mounted, so its key is never present and this is the empty slice —
        // the same answer the old per-plane fallback-variant arm gave, now by construction.
        self.claims.get(key).map_or(&[], Vec::as_slice)
    }

    /// Every plane key that has MOUNTED at least one path in this table, in key order. Read by the
    /// admission ratchets (`plane/tests`): R3 folds the collision check over the planes actually
    /// DISPATCHED here rather than over the declared list, because a scope- or audit-kind collision
    /// only admits another plane's traffic once both colliding planes have a door. Unlike
    /// [`Self::mounted_plane_of`] this names a plane by its KEY, so it reports a registered plane
    /// that has no [`Plane`] variant too.
    pub fn mounted_keys(&self) -> Vec<&'static str> {
        self.claims.keys().copied().collect()
    }

    /// THE RESOLVER: which plane `path` belongs to, and which WIRE DIALECT it is spoken in.
    ///
    /// ## Why this is one function and not two
    ///
    /// There were two: this table's `plane_of`, and a separate path-shape classifier that knew
    /// nothing of mounts and fell back to one hard-coded dialect. Both answered "what is this
    /// path", and on a mounted plane they answered DIFFERENTLY: one path was a mounted plane to
    /// one and a fallback-dialect endpoint to the other. That is not a cosmetic disagreement — it
    /// shipped as a defect. An oversized POST to that path was refused in the fallback dialect's
    /// envelope, which the mounted plane's own client cannot decode, on a path the operator had
    /// explicitly mounted as something else. Two readers of one fact will eventually disagree, and
    /// the disagreement surfaces at the error path, where nobody is looking.
    ///
    /// So the order of resolution is now stated once, here, and it is the only order that respects
    /// what a mount MEANS: **the mount table first, the path shape only for what is left over.**
    ///
    /// ## Matching is on a SEGMENT BOUNDARY, never a bare prefix
    ///
    /// A mount claims its own path and everything beneath it, and does not claim a sibling path that
    /// merely shares a prefix. This is the same over-match the admin surface's own path check
    /// guards, and getting it wrong here would hand a sibling path to a plane whose grants are
    /// meant to be inadmissible everywhere else — and, in the other direction, hand it that plane's
    /// REFUSALS, which is how a caller learns the shape of a door it was never at.
    ///
    /// ## A plane claims a path only when the operator MOUNTED it
    ///
    /// The fallback is reached by falling THROUGH the mount table, never by naming it, so a
    /// deployment that never enabled a given plane has no door for it and that plane's usual path is
    /// an ordinary unclaimed path. Nothing here lets a plane claim a path by URL shape.
    pub fn ingress_of(&self, path: &str) -> Ingress {
        match self.mounted_plane_of(path) {
            Some(key) => Ingress::Mounted(key),
            // THE FALLBACK ARM, and the only place a path SHAPE decides anything. It answers
            // `None` for a path that names no dialect — an honest answer the old classifier could
            // not give, because it always spent that case on one hard-coded dialect.
            None => Ingress::Fallback(crate::proto::residual_dialect_for_path(path)),
        }
    }

    /// The plane that CLAIMS `path` BY MOUNT, or `None` when `path` falls through to the fallback.
    ///
    /// The same walk [`Self::plane_of`] does — it is written once, here, and `plane_of` is merely
    /// the arm that names the fallback — but it keeps the fallback DISTINGUISHABLE, which
    /// `plane_of` deliberately does not. [`super::observe`] needs that distinction and does not
    /// want a plane comparison to get it: the plane ingress boundary emits a request's metrics only
    /// for a plane that has a DOOR of its own, because the fallback labels its own requests from
    /// inside its handler, where the dialect it spoke is known. Written as a direct comparison
    /// against the fallback's variant that would be a plane branch standing in for a property the
    /// mount table already knows — and it would be wrong the day a further plane is added as a
    /// fallback sibling.
    ///
    /// The walk covers every claimed key rather than a hand-listed set of plane names: the fallback
    /// has no mount, so it is skipped by construction rather than by being left off a list a new
    /// plane would have to remember to join.
    pub fn mounted_plane_of(&self, path: &str) -> Option<&'static str> {
        self.claims.keys().copied().find(|key| {
            self.claims_of(key)
                .iter()
                .any(|claim| path_is_under(path, &claim.path))
        })
    }

    /// Whether ANY plane has mounted a path. A key is present in [`Self::claims`] only once its
    /// plane has mounted at least one path (see the field doc), so this is exactly "is there a
    /// plane [`observe`] could ever label". Planes register ONCE at boot
    /// ([`registry::install_planes`], before the first request) and the mount set is fixed for the
    /// process lifetime, so `false` here is `false` forever — which is what lets the router omit
    /// the plane-ingress layer STRUCTURALLY for a deployment with no mounted plane, rather than
    /// pay a per-request snapshot load and mount walk to pass every request straight through.
    /// NOT a statement about the current config snapshot's swappable fields: it is about which
    /// keys ever mounted, which does not swap.
    pub(crate) fn has_mounts(&self) -> bool {
        !self.claims.is_empty()
    }
}

/// WHAT AN INBOUND PATH IS — the single answer [`PlaneDispatch::ingress_of`] gives, and the input
/// every site that must shape a reply from a path alone reads.
///
/// Two variants, and the split is the mount table's: a path is CLAIMED by a plane the operator
/// mounted, or it is not and belongs to the fallback. There is deliberately no third variant for
/// "unknown": an unrecognised path is not a fourth kind of thing, it is a fallback path whose
/// dialect is not legible, which is what `Fallback(None)` says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ingress {
    /// A path a plane CLAIMS BY MOUNT, at a segment boundary, named by its registry key.
    Mounted(&'static str),
    /// The fallback plane. `Some(dialect)` when the path shape names one of the registered fallback
    /// dialects; `None` when it names none — a bare `/`, a typo, a probe. `None` is a real answer
    /// and not a failure: what to SAY to a caller whose dialect is unknown is a decision for the
    /// site composing the reply, not for the resolver, which would otherwise have to invent a
    /// protocol identity for a path that carries none.
    Fallback(Option<&'static str>),
}

impl Ingress {
    /// The WIRE FORMAT spoken on this path, or `None` when the path names none.
    ///
    /// This is the `ingress_protocol` metric-label vocabulary (see [`wire_format_names`]),
    /// so a mounted plane labels as its own dialect rather than as whichever fallback dialect its
    /// path happens to resemble.
    pub fn wire_format(self) -> Option<&'static str> {
        match self {
            // A plane with several dialects cannot be labelled from the boundary — which dialect
            // spoke is a fact only its reader knows. `sole_wire_format` is that rule, computed.
            Ingress::Mounted(key) => sole_wire_format(key),
            Ingress::Fallback(dialect) => dialect,
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
    /// for both cases: a single hard-coded dialect's envelope.
    ///
    /// That fallback was harmless while every mounted plane spoke one dialect. The moment a plane
    /// spoke two, `wire_format()` started answering `None` for it and every door-level refusal
    /// on a MOUNTED, audience-bound plane would have been shaped, labelled and messaged as that one
    /// hard-coded dialect — the precise defect the merged resolver was built to end, re-entering
    /// through the fallback rather than through a second classifier.
    ///
    /// So a mounted plane answers its FIRST wire format. Not an arbitrary pick: the card's advertised
    /// interface list is an ORDERED list whose first entry is the preferred binding, busbar's own
    /// card publishes these in this order, and a refusal that cannot know which binding the caller
    /// intended is owed the one the card names first.
    pub fn shaping_wire_format(self) -> Option<&'static str> {
        match self {
            Ingress::Mounted(key) => wire_format_names(key).first().copied(),
            Ingress::Fallback(dialect) => dialect,
        }
    }
}

/// A trailing-slash or bare-key path spelling normalises to a leading slash with no trailing slash;
/// an empty or root path normalises to the empty string (which mounts nothing).
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

/// THE SHARED CONTAINER for a plane's sibling config sections: several independent, per-plane
/// namespaces are ONE code object with N namespaces, not N types that happen to look alike.
///
/// ## Siblings, and therefore no cross-references
///
/// The sections are INDEPENDENT namespaces. One name may exist in all of them and each means a
/// different thing, so a name is not globally unique and must never be treated as if it were.
///
/// The rule that follows, and the reason this type exists rather than one map per section: a name
/// is resolved ONLY within the plane doing the referencing. An entry in one section naming an entry
/// in a sibling section is not a clever shortcut, it is a plane boundary violation, and the resolver
/// REFUSES it.
///
/// ## The refusal DIAGNOSES rather than merely denying
///
/// [`RefError::CrossPlane`] names the plane the entry actually lives on, so the operator reads
/// "that is defined on a different section of this plane". A bare not-found would send someone
/// hunting for a typo that is not there, which is why an unknown name is a genuinely different
/// error.
///
/// The TYPE (and [`RefError`], [`Self::insert`], [`Self::resolve`]) are `pub` rather than
/// `pub(crate)` so `tests/plane_config_cross_plane.rs::the_resolve_time_refusal_fires_on_a_bare_name_that_binds_across_the_boundary`
/// can drive the resolve-time refusal directly, over the REAL plane roster, exactly as the sibling
/// parse-time refusal in that file already does — the same "internal-only `busbar-kernel` crate
/// (`publish = false`) pays that cost" reasoning `registry_cross_plane.rs`'s header gives for its own
/// widened seams.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlaneSections<T> {
    /// One section per plane, keyed by plane registry key. An absent key is an EMPTY section, read
    /// as such by every accessor — the same answer the old three hard fields gave for a plane that
    /// happened to hold nothing. Iteration order is never taken from this map's own key order:
    /// every walk drives from [`plane_keys`] (LAYERING order) so the validator's diagnostics stay
    /// deterministic and in the order the module header describes.
    sections: std::collections::BTreeMap<&'static str, std::collections::BTreeMap<String, T>>,
}

/// Why a name did not resolve. The two arms are kept distinct because only one of them is
/// actionable in the same way.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RefError {
    /// The name exists, but on ANOTHER plane. A plane boundary violation.
    CrossPlane {
        name: String,
        referenced_from: &'static str,
        defined_in: &'static str,
    },
    /// The name exists nowhere.
    Unknown { name: String, plane: &'static str },
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
                plane_decl(referenced_from).config_section,
                plane_decl(defined_in).config_section,
                plane_decl(referenced_from).config_section
            ),
            RefError::Unknown { name, plane } => write!(
                f,
                "`{}` references `{name}`, which is not defined.",
                plane_decl(plane).config_section
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
            sections: std::collections::BTreeMap::new(),
        }
    }
}

impl<T> PlaneSections<T> {
    /// This plane's section, or `None` when the plane holds nothing — read as an EMPTY section.
    fn map(&self, plane: &str) -> Option<&std::collections::BTreeMap<String, T>> {
        self.sections.get(plane)
    }

    /// This plane's section, created empty on first write.
    fn map_mut(&mut self, plane: &'static str) -> &mut std::collections::BTreeMap<String, T> {
        self.sections.entry(plane).or_default()
    }

    /// Declare `name` on `plane`.
    pub fn insert(&mut self, plane: &'static str, name: &str, entry: T) -> Option<T> {
        self.map_mut(plane).insert(name.to_string(), entry)
    }

    /// This plane's entry for `name`, or `None`. Scoped to the plane: it never reads a sibling
    /// section, so a caller cannot accidentally cross the boundary by using the cheap read.
    pub(crate) fn get(&self, plane: &str, name: &str) -> Option<&T> {
        self.sections.get(plane).and_then(|m| m.get(name))
    }

    /// One plane's whole section, or `None` when the plane holds nothing.
    pub(crate) fn section(&self, plane: &str) -> Option<&std::collections::BTreeMap<String, T>> {
        self.map(plane)
    }

    /// THE VALIDATOR ENTRY POINT: resolve `name` as referenced FROM `plane`, refusing a cross-plane
    /// reference with a diagnosis.
    ///
    /// The sibling scan runs in [`plane_keys`] (LAYERING) order so a name defined on several other
    /// planes always diagnoses the same one. A nondeterministic diagnostic is worse than none: it
    /// makes a boot failure unreproducible.
    pub fn resolve(&self, plane: &'static str, name: &str) -> Result<&T, RefError> {
        if let Some(entry) = self.sections.get(plane).and_then(|m| m.get(name)) {
            return Ok(entry);
        }
        for other in plane_keys().filter(|k| *k != plane) {
            if self
                .sections
                .get(other)
                .is_some_and(|m| m.contains_key(name))
            {
                return Err(RefError::CrossPlane {
                    name: name.to_string(),
                    referenced_from: plane,
                    defined_in: other,
                });
            }
        }
        Err(RefError::Unknown {
            name: name.to_string(),
            plane,
        })
    }

    /// Every entry across every plane, attributed to the plane it belongs to. Walked by the config
    /// validator, so a plane absent here is a plane that is never validated. Driven from
    /// [`plane_keys`] so the walk is in LAYERING order regardless of the map's own key order.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&'static str, &str, &T)> {
        plane_keys().flat_map(move |k| {
            self.sections
                .get(k)
                .into_iter()
                .flatten()
                .map(move |(n, e)| (k, n.as_str(), e))
        })
    }
}

// `plane_tests` MOVED to `tests/plane_dispatch_cross_plane.rs` (the A6/HostCtx dev-dependency-cycle
// cleanup): it hard-codes the real `"llm"`/`"mcp"`/`"a2a"` keys and asserts against their REAL
// declared wire formats (the actual dialect/plane registries), which only type-checks/behaves
// correctly with ONE `busbar_kernel` in the graph and a real roster registered — an integration-test
// target, never this `#[cfg(test)]` unit module. See that file's header.

/// Build one ALL-STUB `PlaneDecl` for [`isolated_three_plane_test_registry`] — every hook is
/// `None`/no-op (no dialect, no wire format, no scope kind), like
/// [`crate::test_support::register_neutral_test_plane`]'s single fixture. `const fn` because it
/// backs `static` initializers: a function POINTER is a compile-time constant regardless of what
/// the function body does, so the closures below cost nothing to name here.
#[cfg(test)]
const fn neutral_sibling_decl(
    key: &'static str,
    config_section: &'static str,
    subject_noun: &'static str,
) -> registry::PlaneDecl {
    registry::PlaneDecl {
        declaration: registry::PlaneDeclaration {
            key,
            fallback: false,
            config_section,
            scope_kinds: &[],
            subject_noun,
            admin_noun: subject_noun,
            audit_kind: subject_noun,
            card_signing_domain: None,
            card_kid_prefix: None,
            owned_config_sections: &[],
            billable_classes: &[],
            fee_units: &[],
        },
        wire_format_names: || &[],
        claims: |_| Vec::new(),
        admission: |_| None,
        build: |_| None,
        routes: None,
        admin_routes: None,
        openapi: None,
        hydrate: None,
        start: None,
        config_validate: None,
        named_def_list: None,
        named_def_get: None,
        registry_contains: None,
        reresolve_gates: None,
        openapi_schemas: None,
        on_swap: None,
        parse_section: None,
        parse_endpoint: None,
        lower_endpoint: None,
        build_runtime: None,
        viewer: None,
        retain_verify_gates: None,
        default_section: None,
        resolve_provider: None,
    }
}

/// THE NEUTRAL THREE-PLANE TEST REGISTRY — for [`PlaneSections`]'s own unit tests (`sections_tests`).
/// Unlike [`crate::test_support::register_neutral_test_plane`] (ONE plane: "some plane exists so a
/// config section has an owner"), these are the CONTAINER's own tests: they exercise
/// [`PlaneSections::resolve`]'s sibling walk over THREE distinct registered keys, and one of them
/// (`sections_tests::iteration_covers_every_plane_and_attributes_each_entry`) counts [`plane_keys`]
/// against exactly the entries it inserted, so the registered set must be EXACTLY these three:
/// nothing a sibling test left registered, nothing more.
///
/// The three keys are DELIBERATELY not `"llm"`/`"mcp"`/`"a2a"`: this generic multi-tenant container
/// asserts nothing about what any real plane IS or DOES, and core naming those literals — even in a
/// `#[cfg(test)]`-only synthetic `PlaneDecl` — is exactly what the A6/HostCtx dev-dependency-cycle
/// cleanup deleted `TEST_BUILTIN_PLANE_DECLS` to stop (`cargo xtask gate construction`'s
/// `neutral-no-dialect` rule, ceiling 0, enforces this). `"alpha"`/`"beta"`/`"gamma"` are three
/// registry keys and nothing else. The one test in this file that DID need a real plane's own
/// section-name prose (`the_refusal_message_is_actionable`) moved to
/// `tests/plane_config_cross_plane.rs`, where naming the real planes is licensed.
///
/// Returns the [`registry::TestRegistryIsolation`] guard, which the caller holds for its test body's
/// lifetime: the registered set stays exactly these three regardless of what ran before it or runs
/// concurrently with it.
#[cfg(test)]
pub(crate) fn isolated_three_plane_test_registry() -> registry::TestRegistryIsolation {
    static ALPHA: registry::PlaneDecl =
        neutral_sibling_decl("alpha", "alpha-section", "alpha thing");
    static BETA: registry::PlaneDecl = neutral_sibling_decl("beta", "beta-section", "beta thing");
    static GAMMA: registry::PlaneDecl =
        neutral_sibling_decl("gamma", "gamma-section", "gamma thing");
    // `TestRegistryIsolation::seeded`, NOT `empty()` followed by `register_test_plane`: the guard
    // holds `TEST_REGISTRY_SERIAL` for its whole lifetime, and `register_test_plane` takes that same
    // (non-reentrant) lock — calling it after `empty()` on this thread would self-deadlock. `seeded`
    // installs the three decls atomically under the one lock acquisition instead.
    registry::TestRegistryIsolation::seeded(&[&ALPHA, &BETA, &GAMMA])
}

#[cfg(test)]
#[path = "tests/sections_tests.rs"]
mod sections_tests;

// ==== merged from busbar-substrate (W4.b P2 engine drain) ====
pub mod calllog;

// The NEUTRAL plane-observe response marker `Counted` — the one type a plane's handler and core's
// `plane::observe` boundary both name. It carries nothing and names no engine type, so it lives
// here; core re-exports it from `busbar_kernel::plane::observe` so its middleware reads the same type.

// The plane store seam's narrowing adapter: the `PlaneStore` trait a plane persists through and the
// `PlaneStoreView` that narrows a real `busbar_api::Store` to it. Both name only `busbar_api` leaf
// types, so they live here; core re-exports them from `busbar_kernel::plane::store`.

// Phase-C config-seam: the NEUTRAL config-seam CONTRACTS a plane's config section is read through
// (`PlaneCfg`/`PlaneEndpointCfg`/`ContainerGateInputs`) and the parse-time bare-hook-reference rule
// (`refuse_cross_plane_reference`). They name only `busbar_api::SecretRef` + `serde_json`/`std`, so
// they live here; core re-exports them. The registry-coupled READER half (`split_section`,
// `config_sections`, the reserved-key literal) stays core.

// S4b: the NEUTRAL PLANE-REGISTRY SURFACE — the plane VOCABULARY/SEAM declaration `PlaneDecl`, the
// `BuildCtx` its `build` reads, the neutral `PlaneBootCtx` boot-context trait + its `RestoredSummary`
// return, and the `BootHook` alias. Relocated here so an extracted plane crate constructs its own
// `PlaneDecl` and every seam type its fields name without a path back to core. Core re-exports each
// from `busbar_kernel::plane::registry`, and keeps the population glue + the concrete `BootCtx` (which
// borrows the core-live `App`) that implements `PlaneBootCtx`.

// SEAM-FIX #1 (axis-C): the NEUTRAL DURABLE-HANDLE ENGINE — the plane-agnostic async-handle /
// durable-session capability (registry of cross-request handles, durable write-through, retention
// sweep, boot rehydrate, inbound-push cursor, scoped anti-enumeration read). Lifted here out of the
// A2A plane's task store so every plane consumes ONE substrate-single-compiled engine rather than
// reaching into another plane. It names no plane noun: a plane's row is held opaquely behind
// `Arc<dyn Any>` beside a neutral `HandleMeta` projection, and the plane supplies its shape/statuses/
// vocab/digest through the entry-point callbacks.
pub mod handle_engine;

/// A PLANE'S OAUTH RESOURCE-SERVER ADMISSION FACTS — the audience a token must carry to be spent on
/// this plane's mount, and the RFC 9728 metadata URL a refused caller is pointed at. A neutral POD so
/// a plane crate contributes its admission across the mount seam without naming a core type; core
/// re-exports it, so `busbar_kernel::plane::PlaneAdmission` still resolves there.
///
/// The confused-deputy defence (RFC 8707) is "a token minted for someone else must not be spendable
/// here". Keeping the audience beside the MOUNT (not in a handler) means the check is a property of
/// the door, so every path behind that door inherits it and a new handler cannot forget.
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

/// THE THREE WIRE-FORMAT NAMES, re-exported at their historical path. They are read by
/// `Transport::name` as well as by the declarations here — one spelling for the metric label, the
/// plane's wire-format list and the served card's `protocolBinding`, which is the entire reason they
/// are constants — so they moved into the values crate with the transport axis. Nothing about them
/// changed: `busbar_kernel::plane::WIRE_JSONRPC` and its siblings still resolve to these strings.
pub use busbar_substrate_values::plane::{WIRE_GRPC, WIRE_HTTP_JSON, WIRE_JSONRPC};
