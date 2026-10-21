// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OPENED DOOR TABLE, as the kernel is lent it (status row 82, D2; spec Part 2 #2: one loader,
//! one path for every plugin; Part 3 section 12: one driver).
//!
//! Plane registration is the loader's and the composition root's: the root binds every plane door,
//! linked or dropped in, folds each into the driver's row ([`crate::plane_driver::door::fold`]),
//! orders and checks the set ([`merged_boot_plane_decls`]) and OWNS the result. The kernel holds no
//! copy of it: the root lends the table by value ([`Doors`]) to what reads it — the config parse it
//! runs ([`crate::config::deploy_from_yaml_str`]) and the `App` each generation builds
//! ([`crate::state::App::doors`]) — as it hands its rules. Every reader is a method of the table it
//! was handed: which door owns a config section, which door is the fallback, which scope kinds the
//! doors state; the claims table is folded over it ([`build_dispatch`]). Two tables in one process
//! are two answers, each read only by what it was lent to.

// Members some build surfaces read only from tests (the module this came from held the same
// posture, `plane/mod.rs`).
#![cfg_attr(not(test), allow(dead_code))]

use crate::plane_driver::claims::PlaneDispatch;
use crate::plane_driver::row::{check_owned_config_claims, PlaneDecl, PlaneDeclaration};

/// THE OPENED DOOR TABLE, LENT (status row 82, D2): the rows the composition root folded, which the
/// root OWNS and hands, by value, to what reads them — the config parse it runs, the `App` each
/// generation builds ([`crate::state::App::doors`]) — exactly as it hands its rules
/// ([`crate::appbuild::RootRules`]). A `Copy` borrow of the root's table: the kernel keeps no copy of
/// its own, so two tables in one process are two answers, each read by what it was handed to.
///
/// Every reader the kernel had over the installed set is a method here, answering byte-for-byte what
/// the free function answered over the same rows.
#[derive(Clone, Copy, Default)]
pub struct Doors {
    rows: &'static [&'static PlaneDecl],
}

impl std::fmt::Debug for Doors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.rows.iter().map(|d| d.key))
            .finish()
    }
}

/// Two tables are equal when they lend the same rows (the same `&'static` decls) in the same order.
impl PartialEq for Doors {
    fn eq(&self, other: &Self) -> bool {
        self.rows.len() == other.rows.len()
            && (self.rows.iter().zip(other.rows)).all(|(a, b)| std::ptr::eq(*a, *b))
    }
}

impl Eq for Doors {}

impl Doors {
    /// No door: the table of a build that opened none.
    pub const NONE: Doors = Doors { rows: &[] };

    /// The table over `rows`, already folded ([`merged_boot_plane_decls`]) by the root that owns
    /// them.
    #[must_use]
    pub const fn lent(rows: &'static [&'static PlaneDecl]) -> Doors {
        Doors { rows }
    }

    /// Every opened door's row, in the root's fold order.
    #[must_use]
    pub fn decls(self) -> &'static [&'static PlaneDecl] {
        self.rows
    }

    /// THE SCOPE-KIND at ABI scope-kind index `idx`, DERIVED FROM REGISTRY DATA rather than a hard-coded
    /// table. Index `0` is core's neutral admission-pool topology (`"pool"`, the kind every deployment
    /// always has); indices `1..` are each installed plane's declared `PlaneDecl.scope_kinds` in
    /// registration order — the same order a plane encodes when it stamps a `TargetRef.scope_kind`. So a
    /// host entitlement slot resolves the opaque numeric kind to its string without core spelling any
    /// plane's kind token. `None` (fail-closed) for an index past the registered kinds.
    ///
    /// The index is a bijection over the DISTINCT kinds, base first: a plane that also declares the
    /// neutral base kind (one plane grants over `"pool"`, which `busbar_contract` already treats as the
    /// unconditional `BUILTIN_POOL_KIND`) must NOT re-count it. Without this dedup the base `"pool"` and
    /// that plane's own `"pool"` declaration would occupy indices 0 AND 1, shifting every later plane's
    /// kind up by one so a `pool` grant would wrongly resolve a different plane's scope kind (entitlement
    /// escalation). Folding a re-declared base onto its existing index 0 keeps each grant target mapped to
    /// the RIGHT plane's kind.
    #[must_use]
    pub fn scope_kind_at(self, idx: u32) -> Option<&'static str> {
        let mut seen: Vec<&'static str> = Vec::new();
        std::iter::once("pool")
            .chain(self.rows.iter().flat_map(|d| d.scope_kinds.iter().copied()))
            .filter(|k| {
                let fresh = !seen.contains(k);
                if fresh {
                    seen.push(k);
                }
                fresh
            })
            .nth(idx as usize)
    }

    /// THE ABI SCOPE-KIND INDEX for a kind string — the exact INVERSE of [`Self::scope_kind_at`], sharing its
    /// first-seen dedup so the two can never skew. Any encoder that must stamp a `TargetRef.scope_kind`
    /// routes through here rather than re-deriving the numbering, which is what keeps the base-kind
    /// entitlement escalation closed: if the encode side and the [`Self::scope_kind_at`] decode side computed
    /// the base-first dedup independently they could drift, and a `pool` grant could resolve a
    /// different plane's scope-kind target. Fail-closed (`None`) for a kind no registered plane declares.
    #[must_use]
    pub fn scope_kind_index(self, kind: &str) -> Option<u32> {
        let mut seen: Vec<&'static str> = Vec::new();
        std::iter::once("pool")
            .chain(self.rows.iter().flat_map(|d| d.scope_kinds.iter().copied()))
            .filter(|k| {
                let fresh = !seen.contains(k);
                if fresh {
                    seen.push(k);
                }
                fresh
            })
            .position(|k| k == kind)
            .map(|i| i as u32)
    }

    /// RESOLVE A PLANE DECLARATION BY KEY. Allocates nothing.
    ///
    /// NAMED FOR ITS AXIS, not `decl_for`: the kernel holds no by-name protocol resolution (the
    /// construction gate's `kernel-no-protocol-registry` refuses `fn decl_for` here), and plane
    /// resolution is a different axis that says so in its name.
    #[must_use]
    pub fn plane_decl_for(self, key: &str) -> Option<&'static PlaneDecl> {
        self.rows.iter().copied().find(|d| d.key == key)
    }

    /// RESOLVE A PLANE DECLARATION BY ITS CONFIG SECTION, against the PROCESS list — the neutral bridge
    /// the named-definition write path and the config parse/lower path cross to reach a plane's hooks
    /// without naming the plane. Resolves through this table (installed + built-ins, canonically
    /// ordered) rather than the built-ins alone, so an EXTRACTED plane the composition root installed
    /// is found on the same footing as a still-built-in one.
    #[must_use]
    pub fn plane_decl_for_config_section(self, section: &str) -> Option<&'static PlaneDecl> {
        self.rows
            .iter()
            .copied()
            .find(|d| d.config_section == section)
    }

    /// The FALLBACK plane's registry key — DERIVED from the plane registry rather than a hard-coded
    /// literal: the ONE built-in plane whose decl declares [`PlaneDeclaration::fallback`]. Read by
    /// the fallback guard (`PlaneDispatch::mount`/`admit` no-op) and the fallback-plane telemetry branch
    /// so core names no dialect. The composition root (`register_planes`) installs the fallback plane
    /// before any reader runs, and a test registers the fallback it needs, so exactly one fallback is
    /// present. Core expresses "which plane handles unmatched routes"
    /// by ASKING the declared fallback plane, never by hard-coding which plane that is.
    #[must_use]
    pub fn fallback_key(self) -> &'static str {
        debug_assert!(
            self.rows.iter().filter(|d| d.fallback).count() <= 1,
            "more than one registered plane declares itself the fallback catch-all — it must be \
             unique or `fallback_key`/`is_fallback` first-win nondeterministically"
        );
        self.rows
            .iter()
            .find(|d| d.fallback)
            .or_else(|| self.rows.first())
            .map(|d| d.key)
            .unwrap_or("")
    }

    /// Whether `key` names THE FALLBACK plane — the non-panicking predicate the fallback GUARDS read
    /// (`PlaneDispatch::mount`/`admit` no-op; the fallback-plane telemetry branch). Distinct from
    /// [`Self::fallback_key`]: it answers "is THIS key the fallback" WITHOUT requiring a fallback to be
    /// registered, so it is safe in a build where the fallback plane's decl is absent — the
    /// dependency-copy of core the plane crates link, whose built-in plane rows are empty and which only
    /// ever asks this about a mounted plane's OWN key (never the fallback's key). `fallback_key`, by
    /// contrast, is read only on paths (App build, request telemetry family) where the fallback is
    /// always present.
    #[must_use]
    pub fn is_fallback(self, key: &str) -> bool {
        self.rows.iter().any(|d| d.key == key && d.fallback)
    }

    /// The plane that DECLARES itself the fallback, resolved from ONE read of the plane list, or `None`
    /// when no registered plane flags itself fallback. Unlike [`Self::fallback_key`] it never degrades to a
    /// sibling's key, so App composition derives the fallback runtime's slot key AND the `build_runtime`
    /// that fills it from the same decl: the runtime under `runtime_slot_key(K)` is always plane `K`'s
    /// own state (BUSBAR-1.6.0.md §6). One table is one answer: the decl the slot key is read off is the
    /// decl whose `build_runtime` fills it.
    #[must_use]
    pub fn fallback_decl(self) -> Option<&'static PlaneDecl> {
        self.rows.iter().copied().find(|d| d.fallback)
    }

    /// Every built-in plane's registry key, in layering order. Iterated by dispatch, the config
    /// validator and the candidate projection, so a plane absent from here is a plane that silently
    /// does not exist.
    ///
    /// Driven off the installed set: a door the root did not bind has no row, so it is not iterated
    /// here — every [`Self::plane_decl`] on it would fault. This is the successor to the old `Plane::ALL`, and the source of the LAYERING iteration
    /// order every map walk must borrow rather than reinvent from a map's own key order.
    pub fn plane_keys(self) -> impl Iterator<Item = &'static str> {
        self.rows.iter().map(|d| d.key)
    }

    /// The built-in plane declaration for `key`, or panic — the by-key indirection the former `Plane`
    /// accessors now read through. Callers wanting a decl FIELD (`config_section`, `subject_noun`,
    /// `audit_kind`, `scope_kinds`) read it straight off this; the free fns below are the accessors
    /// that COMPUTED something rather than reading a field.
    #[must_use]
    pub fn plane_decl(self, key: &str) -> &'static PlaneDecl {
        self.plane_decl_for(key)
            .unwrap_or_else(|| panic!("no built-in plane declared for key `{key}`"))
    }

    /// The distinct WIRE FORMATS this plane translates between, named. Not transports.
    ///
    /// These strings are the `ingress_protocol` metric-label vocabulary: a label that means "which
    /// dialect spoke to us" has to be spelled the same way on every plane or a dashboard cannot
    /// compare them, and two planes agreeing by coincidence is how one plane's dialect spelling and
    /// another plane's dialect spelling end up in one series meaning two things.
    #[must_use]
    pub fn wire_format_names(self, key: &str) -> &'static [&'static str] {
        let decl = self.plane_decl(key);
        (decl.wire_format_names)(decl)
    }

    /// EVERY DIALECT A PROVIDER'S `protocol` MAY NAME: each registered plane's declared provider
    /// dialects ([`PlaneDecl::provider_dialects`]), in registration order and each plane's
    /// own order, each once (ARCHITECT ruling 2026-10-16, item 3; BUSBAR-1.6.0.md #49: the kernel
    /// reads declared data and names no dialect). A build that registers none accepts no provider.
    #[must_use]
    pub fn provider_dialects(self) -> Vec<&'static str> {
        let mut out: Vec<&'static str> = Vec::new();
        for d in self.rows {
            for name in (d.provider_dialects)(d) {
                if !out.contains(name) {
                    out.push(name);
                }
            }
        }
        out
    }

    /// The plane's ONE wire format, when it has exactly one — otherwise `None`.
    ///
    /// COMPUTED, like [`Self::has_superset_ir`], and for the same reason. A plane with a single dialect can
    /// be labelled with it at the ingress BOUNDARY, before any handler has read a byte of the body,
    /// because there is nothing to decide. A plane with several cannot: which dialect spoke is a fact
    /// only its reader knows, so that plane labels its own requests from inside (the fallback plane
    /// does exactly this, in `ingress::finish_inner`). Derived from the format list it is a RULE, and
    /// the day a plane speaks a second dialect the boundary stops labelling it and the rule says so
    /// rather than a stale literal quietly lying.
    #[must_use]
    pub fn sole_wire_format(self, key: &str) -> Option<&'static str> {
        sole_of(self.wire_format_names(key))
    }

    /// How many distinct WIRE FORMATS this plane translates between. DERIVED from
    /// [`Self::wire_format_names`] rather than written as a second literal, so a plane cannot gain a dialect
    /// in one place and keep its old count in the other — which would silently keep [`Self::has_superset_ir`]
    /// answering the pre-change question.
    #[must_use]
    pub fn wire_formats(self, key: &str) -> usize {
        self.wire_format_names(key).len()
    }

    /// Whether this plane has EARNED a superset intermediate representation. See the module header:
    /// the threshold is two wire formats, and nothing else.
    #[must_use]
    pub fn has_superset_ir(self, key: &str) -> bool {
        superset_of(self.wire_formats(key))
    }

    /// A TEST'S TABLE over `rows`, folded as the composition root folds its own
    /// ([`merged_boot_plane_decls`]: one row per key, in layering order, every owned-config claim
    /// checked) and leaked so it lives as long as the test binary: a test lends it to the `App` it
    /// builds ([`crate::test_support::TestApp::doors`]) and to every read it drives directly.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn for_test(rows: &[&'static PlaneDecl]) -> Doors {
        let folded = merged_boot_plane_decls(rows, &[]);
        Doors::lent(Box::leak(folded.into_boxed_slice()))
    }
}

/// ONE PLANE'S DEFAULT per-generation runtime, type-erased: the object `test_support::TestApp::build`
/// seeds under a `tools:`-owning plane's runtime slot when the table it was lent holds one. The
/// default test table holds none, so this is reached only by a test that lends one.
#[cfg(test)]
pub fn default_section_plane_test_runtime() -> std::sync::Arc<dyn std::any::Any + Send + Sync> {
    std::sync::Arc::new(())
}

/// THE BOOT FOLD the composition root runs over the rows it built, before it lends the table
/// ([`Doors::lent`]): installed rows ahead of `builtins` (none in production), one entry per KEY,
/// later same-key rows skipped audibly, ordered by the layering order the rows state, and refused
/// whole if two rows claim one config section or a row claims a section the kernel's config owns.
/// A pure function, so its order and skip semantics are drivable by a test.
pub fn merged_boot_plane_decls(
    installed: &[&'static PlaneDecl],
    builtins: &[&'static PlaneDecl],
) -> Vec<&'static PlaneDecl> {
    let mut decls: Vec<&'static PlaneDecl> = Vec::new();
    for d in installed.iter().chain(builtins) {
        if decls.iter().any(|p| p.key == d.key) {
            tracing::info!(
                plane = d.key,
                "skipping a later registration of an already-declared plane (composition-root copy \
                 and built-in copy of one plane)"
            );
            continue;
        }
        decls.push(d);
    }
    // NORMALISE TO CANONICAL LAYERING ORDER. The dedup above still runs installed-first, so the
    // composition-root copy still wins a same-key collision; this only reorders the SURVIVORS so an
    // extracted plane (installed) lands in the same slot its built-in copy held — a stable sort, so
    // any plane outside the canonical list keeps its relative fold position at the tail.
    //
    // The canonical order is DATA, not a hard-coded token list: it is the order each plane KEY first
    // appears across the built-in rows then the installed ones. In production the built-in rows
    // compile out and the composition root installs the planes in layering order, so that install
    // order IS the canonical order; under the test / test-support surface the built-in rows supply
    // it. Either way core names no plane token here — the order leaves with the decls.
    let canonical = canonical_key_order(installed, builtins);
    decls.sort_by_key(|d| {
        canonical
            .iter()
            .position(|k| *k == d.key)
            .unwrap_or(canonical.len())
    });
    // PLANE-OWNED-CONFIG DUP-CLAIM GUARD (1.6.0 config-seam, stage 1). Refuse the boot if two planes
    // claim the same top-level config section, or if a plane claims a section core STILL owns
    // concretely (`CORE_OWNED_CONCRETE_SECTIONS`) — the invariant that makes the later section moves
    // safe. In stage 1 every `owned_config_sections` is empty, so this is unconditionally `Ok(())` and
    // adds no behaviour; it exists so the FIRST move that mis-claims a section fails at boot, loudly,
    // rather than silently double-declaring the grammar. A panic (not a `Result`) because a mis-wired
    // composition root is a build bug, not an operator error to recover from.
    let declared: Vec<&PlaneDeclaration> = decls.iter().map(|d| &d.declaration).collect();
    if let Err(refusal) = check_owned_config_claims(&declared, CORE_OWNED_CONCRETE_SECTIONS) {
        panic!("plane-owned-config dup-claim guard: {refusal}");
    }
    decls
}

/// THE TOP-LEVEL CONFIG SECTIONS CORE STILL OWNS CONCRETELY as fields of
/// [`crate::config::DeployCfg`] — the reserved set the plane-owned-config dup-claim guard
/// ([`check_owned_config_claims`]) refuses a plane from claiming until the
/// section is actually evicted from core in the SAME change.
///
/// STAGE 1 lists all five: `providers`/`models`/`pools`/`rate_card`/`limits` are all concrete today.
/// As the LATER stages move a section into its owning plane crate, that stage DELETES the section's
/// key from this list in lockstep with adding it to the plane's `owned_config_sections` — the two
/// edits are one change, so at no instant is a section either owned by nobody or claimed by two. Per
/// the reconciled-audit scope, `pools` and `providers` stay neutral in core and are NEVER removed
/// here; only `rate_card`, `limits` and `models`-capabilities are evictable in later stages.
pub const CORE_OWNED_CONCRETE_SECTIONS: &[&str] =
    &["providers", "models", "pools", "rate_card", "limits"];

/// THE OPERATOR-VISIBLE LAYERING ORDER of the planes, by key — the order `config_sections` reports
/// and a cross-plane refusal names sections in — DERIVED FROM REGISTRATION DATA rather than a
/// hard-coded token list. It is the order each plane key FIRST APPEARS across the built-in rows then
/// the installed ones, deduped. The built-in rows (a plane's own registry row, `#[cfg(test)]`) fix
/// the canonical positions under the test/test-support surface; in production the built-ins compile
/// out and the composition root installs the planes in layering order, so the install order IS the
/// canonical order. Core spells no specific plane's key here — the order leaves with the decls.
///
/// `merged_boot_plane_decls` sorts its survivors by each key's index in this list (tail for a key not
/// present — an unknown/registered-later plane sorts stably after the canonical set rather than
/// jumping the queue), so the position is a property of the plane, not of whether it shipped as a
/// built-in or an installed crate.
fn canonical_key_order(
    installed: &[&'static PlaneDecl],
    builtins: &[&'static PlaneDecl],
) -> Vec<&'static str> {
    let mut order: Vec<&'static str> = Vec::new();
    for d in builtins.iter().chain(installed) {
        if !order.contains(&d.key) {
            order.push(d.key);
        }
    }
    order
}

/// FOLD THE DISPATCH TABLE from the registered plane declarations and the per-plane runtime objects
/// (`slots`, each type-erased as `&dyn Any` and keyed by plane key). For every decl with a slot this
/// reads the plane's declared claims and admission from its OWN object — the seam that lets a plane
/// crate contribute its door without core naming its type — mounts each claim, and binds the
/// admission.
///
/// Split from `appbuild` and taking its inputs by argument so the admission ratchets are drivable
/// without booting an `App`, over the rows of the table the build was lent ([`Doors::decls`]).
///
/// # The two security ratchets it enforces
/// - **R1 (every claimed path is audience-checked):** each `(path, wire)` a plane declares is
///   mounted, so [`PlaneDispatch::admission_for`] resolves an audience on it. A path a plane
///   answers on but omits here is unreachable through this table's audience check — which is why the
///   claim set, not the router, is the thing a test pins.
/// - **R2 (mounted ⇒ admitted, or boot refuses):** a plane that claims a path but has no admission
///   path would serve an unauthenticated resource. That is refused here with a named error rather
///   than mounted, so a future plane cannot lower its own bar to nothing by omitting an admission.
///   A claim is ADMITTED by an audience the plane binds, or — for a plane served through its door
///   ([`crate::plane_driver::door::is_door`]) — by the kernel's key-verify chain (`key_chain`: the data chain
///   verifies the busbar key), which admits a door claim exactly as it admits any data-plane path.
///   A door claim with neither is refused, as any plane's is.
pub fn build_dispatch(
    decls: &[&'static PlaneDecl],
    slots: &std::collections::BTreeMap<&'static str, &dyn std::any::Any>,
    key_chain: bool,
) -> Result<PlaneDispatch, String> {
    let mut dispatch = PlaneDispatch::default();
    for decl in decls {
        // A plane the operator did not configure has no runtime object, mounts nothing, and binds
        // no audience — skipped, exactly as the old `if let Some(..)` guards skipped it.
        let Some(slot) = slots.get(decl.key).copied() else {
            continue;
        };
        let claims = (decl.claims)(slot);
        let admission = (decl.admission)(slot);
        // R2: a claimed path with no admission path is a door with no lock. Refuse the boot.
        let key_admitted = key_chain && crate::plane_driver::door::is_door(decl);
        if !claims.is_empty() && admission.is_none() && !key_admitted {
            return Err(format!(
                "plane `{}` mounts {} path(s) but bound no admission; a mounted plane must bind an \
                 RFC 8707 audience (see PlaneDispatch::admission_for) or claim no path — serving a \
                 claimed path with no audience admits a token minted for any other resource",
                decl.key,
                claims.len()
            ));
        }
        for (path, wire) in claims {
            dispatch = dispatch.mount_key(decl.key, &path, wire);
        }
        if let Some(admission) = admission {
            dispatch = dispatch.admit_key(decl.key, admission);
        }
    }
    Ok(dispatch)
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

/// Build one ALL-STUB `PlaneDecl` for [`three_plane_test_doors`] — every hook is
/// `None`/no-op (no dialect, no wire format, no scope kind), like
/// [`crate::test_support::neutral_test_doors`]'s single fixture. `const fn` because it
/// backs `static` initializers: a function POINTER is a compile-time constant regardless of what
/// the function body does, so the closures below cost nothing to name here.
#[cfg(test)]
const fn neutral_sibling_decl(
    key: &'static str,
    config_section: &'static str,
    subject_noun: &'static str,
) -> PlaneDecl {
    PlaneDecl {
        declaration: PlaneDeclaration {
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

/// THE NEUTRAL THREE-PLANE TEST TABLE — for [`PlaneSections`]'s own unit tests (`sections_tests`):
/// the CONTAINER's own tests exercise [`PlaneSections::resolve`]'s sibling walk over THREE distinct
/// keys, and one of them counts [`Doors::plane_keys`] against exactly the entries it inserted, so
/// the table must be EXACTLY these three.
///
/// The three keys are DELIBERATELY not `"llm"`/`"mcp"`/`"a2a"`: this generic multi-tenant container
/// asserts nothing about what any real plane IS or DOES, and core naming those literals — even in a
/// `#[cfg(test)]`-only synthetic `PlaneDecl` — is what the construction gate's `neutral-no-dialect`
/// rule (ceiling 0) refuses. `"alpha"`/`"beta"`/`"gamma"` are three keys and nothing else. The test
/// that needs a real plane's own section-name prose lives in
/// `crates/busbar/tests/plane_config_cross_plane.rs`, where naming the real planes is licensed.
///
/// [`PlaneSections`]: crate::config::plane_refs::PlaneSections
/// [`PlaneSections::resolve`]: crate::config::plane_refs::PlaneSections::resolve
#[cfg(test)]
pub(crate) fn three_plane_test_doors() -> Doors {
    static ALPHA: PlaneDecl = neutral_sibling_decl("alpha", "alpha-section", "alpha thing");
    static BETA: PlaneDecl = neutral_sibling_decl("beta", "beta-section", "beta thing");
    static GAMMA: PlaneDecl = neutral_sibling_decl("gamma", "gamma-section", "gamma thing");
    static ROWS: [&PlaneDecl; 3] = [&ALPHA, &BETA, &GAMMA];
    Doors::lent(&ROWS)
}

#[cfg(test)]
#[path = "tests/doors_lent_tests.rs"]
mod doors_lent_tests;
