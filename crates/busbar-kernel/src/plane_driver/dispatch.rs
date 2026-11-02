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
//! So the superset rule is derived from [`wire_formats`] rather than written as
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

use super::registry;

pub fn fallback_key() -> &'static str {
    let decls = registry::plane_decls();

    debug_assert!(
        decls.iter().filter(|d| d.fallback).count() <= 1,
        "more than one registered plane declares itself the fallback catch-all — it must be \
         unique or `fallback_key`/`is_fallback` first-win nondeterministically"
    );

    decls
        .iter()
        .find(|d| d.fallback)
        .or_else(|| decls.first())
        .map(|d| d.key)
        .unwrap_or("")
}

pub(crate) fn is_fallback(key: &str) -> bool {
    registry::plane_decls()
        .iter()
        .any(|d| d.key == key && d.fallback)
}

pub(crate) fn fallback_decl() -> Option<&'static registry::PlaneDecl> {
    registry::plane_decls().iter().copied().find(|d| d.fallback)
}

pub fn plane_keys() -> impl Iterator<Item = &'static str> {
    registry::plane_decls().iter().map(|d| d.key)
}

pub fn plane_decl(key: &str) -> &'static registry::PlaneDecl {
    registry::plane_decl_for(key)
        .unwrap_or_else(|| panic!("no built-in plane declared for key `{key}`"))
}

pub fn wire_format_names(key: &str) -> &'static [&'static str] {
    let decl = plane_decl(key);
    (decl.wire_format_names)(decl)
}

pub fn provider_dialects() -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    for d in registry::plane_decls() {
        for name in (d.provider_dialects)(d) {
            if !out.contains(name) {
                out.push(name);
            }
        }
    }
    out
}

pub fn sole_wire_format(key: &str) -> Option<&'static str> {
    sole_of(wire_format_names(key))
}

pub fn wire_formats(key: &str) -> usize {
    wire_format_names(key).len()
}

pub fn sole_of(names: &'static [&'static str]) -> Option<&'static str> {
    match names {
        [] => None,
        [only] => Some(only),
        _ => None,
    }
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
/// A plane can serve multiple bindings at distinct paths. A client that derives a secondary binding's path from its service description takes an authority, not an arbitrary path prefix, so that binding requires its own dedicated path. The primary binding's paths remain under the plane's mount and are covered by its first segment-boundary claim.
///
///
///
///
///
///
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
/// Each plane contributes claims and admission data from its [`registry::PlaneDecl`], folded against that plane's runtime object. The map uses the plane's registry key, so every registered plane has one row and one audience without needing an enum variant or per-plane typed fields.
///
///
///
///
///
///
///
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
/// threshold the superset rule reads. It cannot answer "which one is being spoken right
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

impl PlaneDispatch {
    pub fn admission_of(&self, key: &str) -> Option<&PlaneAdmission> {
        self.admissions.get(key)
    }

    pub fn admit(self, key: &'static str, admission: PlaneAdmission) -> Self {
        if is_fallback(key) {
            return self;
        }
        self.admit_key(key, admission)
    }

    pub(crate) fn admit_key(mut self, key: &'static str, admission: PlaneAdmission) -> Self {
        self.admissions.insert(key, admission);
        self
    }

    pub fn admission_for(&self, path: &str) -> Option<&PlaneAdmission> {
        self.admissions.get(self.mounted_plane_of(path)?)
    }

    pub fn mount(self, key: &'static str, path: &str, wire: &'static str) -> Self {
        if is_fallback(key) {
            return self;
        }
        self.mount_key(key, path, wire)
    }

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

    pub fn mount_of(&self, key: &str) -> Option<&str> {
        self.claims_of(key).first().map(|c| c.path.as_str())
    }

    pub fn wire_format_of(&self, path: &str) -> Option<&'static str> {
        self.claims.keys().copied().find_map(|key| {
            self.claims_of(key)
                .iter()
                .find(|c| path_is_under(path, &c.path))
                .map(|c| c.wire)
        })
    }

    fn claims_of(&self, key: &str) -> &[Claim] {
        self.claims.get(key).map_or(&[], Vec::as_slice)
    }

    pub fn mounted_keys(&self) -> Vec<&'static str> {
        self.claims.keys().copied().collect()
    }

    pub fn ingress_of(&self, path: &str) -> Ingress {
        match self.mounted_plane_of(path) {
            Some(key) => Ingress::Mounted(key),

            None => Ingress::Fallback(crate::ingress::protocols::residual_dialect_for_path(path)),
        }
    }

    pub fn mounted_plane_of(&self, path: &str) -> Option<&'static str> {
        self.claims.keys().copied().find(|key| {
            self.claims_of(key)
                .iter()
                .any(|claim| path_is_under(path, &claim.path))
        })
    }

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
    pub fn wire_format(self) -> Option<&'static str> {
        match self {
            Ingress::Mounted(key) => sole_wire_format(key),
            Ingress::Fallback(dialect) => dialect,
        }
    }

    pub fn shaping_wire_format(self) -> Option<&'static str> {
        match self {
            Ingress::Mounted(key) => wire_format_names(key).first().copied(),
            Ingress::Fallback(dialect) => dialect,
        }
    }
}

fn normalise_mount(path: &str) -> String {
    let trimmed = path.trim().trim_matches('/');
    if trimmed.is_empty() {
        return String::new();
    }
    format!("/{trimmed}")
}

fn path_is_under(path: &str, mount: &str) -> bool {
    match path.strip_prefix(mount) {
        Some("") => true,
        Some(rest) => rest.starts_with('/'),
        None => false,
    }
}

#[cfg(test)]
pub(crate) const fn neutral_sibling_decl(
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
            metric_families: &[],
            record_kinds: &[],
            required_config_sections: &[],
            trust_keys: &[],
            served_op_classes: &[],
            caller_credential_refusal: None,
        },
        wire_format_names: |_| &[],
        provider_dialects: |_| &[],
        claims: |_| Vec::new(),
        admission: |_| None,
        build: |_, _| None,
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
        door: None,
    }
}

/// A PLANE'S OAUTH RESOURCE-SERVER ADMISSION FACTS — the audience a token must carry to be spent on
/// this plane's mount, and the RFC 9728 metadata URL a refused caller is pointed at. A neutral POD so
/// a plane crate contributes its admission across the mount seam without naming a core type; core
/// re-exports it, so `busbar_kernel::plane_driver::dispatch::PlaneAdmission` still resolves there.
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

pub use busbar_contract::transport::transport::plane::{WIRE_GRPC, WIRE_HTTP_JSON, WIRE_JSONRPC};
