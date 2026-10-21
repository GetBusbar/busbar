// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR CLAIMS TABLE: which opened door an inbound path belongs to, by the claims each door
//! states (spec Part 3 section 12: the plane matches its own claimed routes; the kernel routes an
//! arrival to a door by the door's declared claims, never by a dialect name).
//!
//! [`PlaneDispatch`] is built once per generation from the installed door set
//! ([`crate::plane_driver::doors::build_dispatch`]); [`PlaneDispatch::ingress_of`] is the one
//! resolver every site that answers from a path alone reads ([`Ingress`]).

// Members some build surfaces read only from tests (the module this came from held the same
// posture, `plane/mod.rs`).
#![cfg_attr(not(test), allow(dead_code))]

use crate::plane_driver::doors::Doors;

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
/// from each plane's [`PlaneDecl`](crate::plane_driver::row::PlaneDecl) against that plane's own runtime object, so a plane
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
    /// The [`crate::plane_driver::doors::Doors::wire_format_names`] entry spoken here. Not a free string: a claim naming a
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
// [`crate::plane_driver::claims::PlaneAdmission`] so a plane crate contributes its admission across the
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
    pub fn admit(self, doors: Doors, key: &'static str, admission: PlaneAdmission) -> Self {
        // The fallback takes none — see the doc: an audience on an unmounted plane is inert, and one
        // on the fallback plane would quietly make every unclaimed path an OAuth resource server.
        if doors.is_fallback(key) {
            return self;
        }
        self.admit_key(key, admission)
    }

    /// [`Self::admit`], keyed by plane key rather than by [`Plane`]. The seam the registry-driven
    /// [`crate::plane_driver::doors::build_dispatch`] folds an admission in through, so a plane with no enum variant
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
    /// Mount `plane` at `path`. Mounting the fallback plane of `doors`
    /// ([`Doors::fallback_key`]) is a no-op.
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
    pub fn mount(self, doors: Doors, key: &'static str, path: &str, wire: &'static str) -> Self {
        // Mounting the fallback is a no-op: it IS the catch-all, so a second door to it is a
        // precedence question with no good answer.
        if doors.is_fallback(key) {
            return self;
        }
        self.mount_key(key, path, wire)
    }

    /// [`Self::mount`], keyed by plane key rather than by [`Plane`]. The seam
    /// [`crate::plane_driver::doors::build_dispatch`] folds each plane's declared claims in through, so a registered
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
    /// So the order of resolution is now stated once, here: **the mount table, and the fallback for
    /// what is left over.**
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
            // THE FALLBACK ARM. The kernel reads no dialect off a path shape: a plane matches its
            // own claimed routes and renders its own refusals through its door (spec Part 1,
            // Law 5; Part 3 section 12).
            None => Ingress::Fallback,
        }
    }

    /// The plane that CLAIMS `path` BY MOUNT, or `None` when `path` falls through to the fallback.
    ///
    /// The same walk [`Self::plane_of`] does — it is written once, here, and `plane_of` is merely
    /// the arm that names the fallback — but it keeps the fallback DISTINGUISHABLE, which
    /// `plane_of` deliberately does not. `ingress::observe` needs that distinction and does not
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
    /// (the door table the generation was lent, before the first request) and the mount set is fixed for the
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
/// "unknown": an unrecognised path is not a third kind of thing, it is a fallback path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ingress {
    /// A path a plane CLAIMS BY MOUNT, at a segment boundary, named by its registry key.
    Mounted(&'static str),
    /// A path no plane claims by mount. The kernel names no dialect for it: the plane whose door
    /// claims the path reads its own dialect off it, and the kernel's own answer is its neutral
    /// envelope.
    Fallback,
}

impl Ingress {
    /// The WIRE FORMAT spoken on this path, or `None` when the kernel cannot name one (a fallback
    /// path, or a mounted plane with several dialects).
    ///
    /// This is the `ingress_protocol` metric-label vocabulary (see [`crate::plane_driver::doors::Doors::wire_format_names`]),
    /// so a mounted plane labels as its own dialect.
    pub fn wire_format(self, doors: Doors) -> Option<&'static str> {
        match self {
            // A plane with several dialects cannot be labelled from the boundary — which dialect
            // spoke is a fact only its reader knows. `sole_wire_format` is that rule, computed.
            Ingress::Mounted(key) => doors.sole_wire_format(key),
            Ingress::Fallback => None,
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
    /// option — some bytes have to go back — and its caller once had one fallback for both cases:
    /// a single hard-coded dialect's envelope.
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
    pub fn shaping_wire_format(self, doors: Doors) -> Option<&'static str> {
        match self {
            Ingress::Mounted(key) => doors.wire_format_names(key).first().copied(),
            Ingress::Fallback => None,
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

/// A PLANE'S OAUTH RESOURCE-SERVER ADMISSION FACTS — the audience a token must carry to be spent on
/// this plane's mount, and the RFC 9728 metadata URL a refused caller is pointed at. A neutral POD so
/// a plane crate contributes its admission across the mount seam without naming a core type; core
/// re-exports it, so `crate::plane_driver::claims::PlaneAdmission` still resolves there.
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
/// changed: `crate::plane_driver::claims::WIRE_JSONRPC` and its siblings still resolve to these strings.
pub use busbar_contract::transport::transport::plane::{WIRE_GRPC, WIRE_HTTP_JSON, WIRE_JSONRPC};
