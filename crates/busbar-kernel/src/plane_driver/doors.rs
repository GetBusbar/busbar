// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OPENED DOOR SET, as the kernel holds it (status row 82, D2; spec Part 2 #2: one loader, one
//! path for every plugin; Part 3 section 12: one driver).
//!
//! Plane registration is the loader's and the composition root's: the root binds every plane door,
//! linked or dropped in, folds each into the driver's row ([`crate::plane_driver::door::fold`]),
//! orders and checks the set ([`merged_boot_plane_decls`]) and installs it ONCE through the
//! kernel-owned [`DoorSet`] seam ([`install_doors`]). The kernel builds no set and lists no door: it
//! reads the handle the root gave it ([`plane_decls`]) and every reader below is a read of that set
//! — which door owns a config section, which door is the fallback, which scope kinds the doors
//! state, and the claims table ([`build_dispatch`]).
//!
//! INSTALL BEFORE FIRST READ: a set installed after another layer resolved against the empty set
//! means two layers of one process disagree about which doors exist. Asserted.

// Members some build surfaces read only from tests (the module this came from held the same
// posture, `plane/mod.rs`).
#![cfg_attr(not(test), allow(dead_code))]

use crate::plane_driver::claims::PlaneDispatch;
use crate::plane_driver::row::{check_owned_config_claims, PlaneDecl, PlaneDeclaration};

/// THE KERNEL-OWNED HANDLE TO THE OPENED DOORS: what the composition root installs. The root owns
/// the set (it binds the doors, folds each, orders them and checks their claims); the kernel reads
/// its rows and nothing else.
pub trait DoorSet: Send + Sync {
    /// Every opened door's row, in the order the root folded them (the operator-visible layering
    /// order a cross-plane refusal names sections in).
    fn rows(&self) -> &[&'static PlaneDecl];
}

/// The rows of the set the composition root installed, read once at install: data, never a seam
/// another crate installs code into (door-only:static-seam).
static INSTALLED: std::sync::OnceLock<&'static [&'static PlaneDecl]> = std::sync::OnceLock::new();

/// The rows the composition root installed; empty before it installs.
fn installed() -> &'static [&'static PlaneDecl] {
    INSTALLED.get().copied().unwrap_or(&[])
}

/// INSTALL THE OPENED DOOR SET — the composition root's one write into the plane axis. `pub`: the
/// `busbar` binary crate is the composition root and calls this from `main` (`register_planes`),
/// before any config load or validation touches a plane.
///
/// # Panics
/// - if called twice: two composition roots is a wiring bug, not a merge to attempt.
/// - if called after [`plane_decls`] was first read: an early read already resolved against the
///   empty set, so installing now would leave two layers disagreeing about which doors exist.
pub fn install_doors(set: &'static dyn DoorSet) {
    assert!(
        INSTALLED.set(set.rows()).is_ok(),
        "install_doors called twice: there is one composition root, and it installs once"
    );
    #[cfg(not(any(test, feature = "test-support")))]
    assert!(
        !READ.load(std::sync::atomic::Ordering::Acquire),
        "install_doors called after the plane list was first read; install in main before any \
         config load or validation touches a plane"
    );
    #[cfg(any(test, feature = "test-support"))]
    assert!(
        TEST_MEMO.lock().unwrap().is_empty(),
        "install_doors called after the plane list was first read; install in main before any \
         config load or validation touches a plane"
    );
}

/// Whether the plane list was read (production): [`install_doors`] after a read is refused.
#[cfg(not(any(test, feature = "test-support")))]
static READ: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// ONE PLANE'S DEFAULT per-generation runtime, type-erased: the object `test_support::TestApp::build`
/// seeds under a `tools:`-owning plane's runtime slot when one is registered. No plane is registered
/// by default under `cfg(test)`, so this is reached only by a test that registers one.
#[cfg(test)]
pub fn default_section_plane_test_runtime() -> std::sync::Arc<dyn std::any::Any + Send + Sync> {
    std::sync::Arc::new(())
}

/// THE BOOT FOLD the composition root runs over the rows it built before it installs them
/// ([`install_doors`]): installed rows ahead of `builtins` (none in production), one entry per KEY,
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
    // composition root is a build bug, not an operator error to recover from — same disposition as the
    // `install_doors`-twice / read-before-install asserts above.
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

/// The opened door set the composition root installed, in its fold order: the rows every reader
/// below reads. Empty until the root installs. The first read marks the set read (the
/// install-before-first-read check); every later read is one acquire load and no store, so the
/// per-request readers (`is_fallback`) never write the shared flag's cache line.
#[cfg(not(any(test, feature = "test-support")))]
pub fn plane_decls() -> &'static [&'static PlaneDecl] {
    if !READ.load(std::sync::atomic::Ordering::Acquire) {
        READ.store(true, std::sync::atomic::Ordering::Release);
    }
    installed()
}

// ── TEST-SUPPORT DOOR SET ────────────────────────────────────────────────────────────────────────
// A test binary has no composition root installing once, so under the test-support surface a test
// REGISTERS the rows it needs ([`register_test_plane`]) and `plane_decls()` folds whatever the root
// installed (a root test) and the registered rows on every read, recomputing (and leaking once)
// only for a set it has not folded before — so a row registered by any test before it reads the
// list is visible regardless of test order, and the `&'static` contract holds.
// Keyed on the IDENTITY of the set — the address of every `&'static PlaneDecl` installed then
// registered, in fold order — never on its size. A size key aliases any two DISTINCT sets of equal
// length: a `TestRegistryIsolation::seeded(&[&A])` followed by a `seeded(&[&B])` (or an isolation's
// restore to a same-length snapshot) would hand back the fold of the OTHER set (item 117). Every
// folded set is kept, so a suite that alternates between isolations re-uses its fold instead of
// leaking again: at most one leak per distinct set the process ever folds.
/// The memo: every registration set folded so far (its decl addresses, in fold order) and the leaked
/// slice it produced.
#[cfg(any(test, feature = "test-support"))]
type TestMemoEntry = (Vec<usize>, &'static [&'static PlaneDecl]);
#[cfg(any(test, feature = "test-support"))]
static TEST_MEMO: std::sync::Mutex<Vec<TestMemoEntry>> = std::sync::Mutex::new(Vec::new());

#[cfg(any(test, feature = "test-support"))]
pub fn plane_decls() -> &'static [&'static PlaneDecl] {
    let reg = test_registered_planes();
    // The installed set (a root test that installs) ahead of the registered rows.
    let mut all: Vec<&'static PlaneDecl> = installed().to_vec();
    all.extend(reg.iter().copied());
    let want = test_memo_key(&all);
    let mut memo = TEST_MEMO.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((_, slice)) = memo.iter().find(|(k, _)| *k == want) {
        return slice;
    }
    // A set not folded before: fold it and leak ONCE for it.
    let merged = merged_boot_plane_decls(&all, &[]);
    let leaked: &'static [&'static PlaneDecl] = Box::leak(merged.into_boxed_slice());
    memo.push((want, leaked));
    leaked
}

/// The [`TEST_MEMO`] key for a registration set: each decl's ADDRESS, in fold order. Two sets share a
/// key only when they are the same `&'static` decls in the same order — which is exactly when they
/// fold to the same list — so no two distinct sets can alias, whatever their sizes.
#[cfg(any(test, feature = "test-support"))]
fn test_memo_key(set: &[&'static PlaneDecl]) -> Vec<usize> {
    set.iter()
        .map(|d| std::ptr::from_ref::<PlaneDecl>(*d) as usize)
        .collect()
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
pub fn scope_kind_at(idx: u32) -> Option<&'static str> {
    // `"pool"` is the neutral base kind (not a plane token); the plane kinds follow it as data,
    // de-duplicated in first-seen order so a re-declared base does not create a phantom index.
    let mut seen: Vec<&'static str> = Vec::new();
    std::iter::once("pool")
        .chain(
            plane_decls()
                .iter()
                .flat_map(|d| d.scope_kinds.iter().copied()),
        )
        .filter(|k| {
            let fresh = !seen.contains(k);
            if fresh {
                seen.push(k);
            }
            fresh
        })
        .nth(idx as usize)
}

/// THE ABI SCOPE-KIND INDEX for a kind string — the exact INVERSE of [`scope_kind_at`], sharing its
/// first-seen dedup so the two can never skew. Any encoder that must stamp a `TargetRef.scope_kind`
/// routes through here rather than re-deriving the numbering, which is what keeps the base-kind
/// entitlement escalation closed: if the encode side and the [`scope_kind_at`] decode side computed
/// the base-first dedup independently they could drift, and a `pool` grant could resolve a
/// different plane's scope-kind target. Fail-closed (`None`) for a kind no registered plane declares.
pub fn scope_kind_index(kind: &str) -> Option<u32> {
    // The identical sequence `scope_kind_at` indexes: the neutral base kind first, then each plane's
    // declared kinds, de-duplicated in first-seen order. `position` over it is the inverse of `nth`.
    let mut seen: Vec<&'static str> = Vec::new();
    std::iter::once("pool")
        .chain(
            plane_decls()
                .iter()
                .flat_map(|d| d.scope_kinds.iter().copied()),
        )
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
pub fn plane_decl_for(key: &str) -> Option<&'static PlaneDecl> {
    plane_decls().iter().copied().find(|d| d.key == key)
}

/// RESOLVE A PLANE DECLARATION BY ITS CONFIG SECTION, against the PROCESS list — the neutral bridge
/// the named-definition write path and the config parse/lower path cross to reach a plane's hooks
/// without naming the plane. Resolves through [`plane_decls`] (installed + built-ins, canonically
/// ordered) rather than the built-ins alone, so an EXTRACTED plane the composition root installed
/// is found on the same footing as a still-built-in one.
pub fn plane_decl_for_config_section(section: &str) -> Option<&'static PlaneDecl> {
    plane_decls()
        .iter()
        .copied()
        .find(|d| d.config_section == section)
}

/// FOLD THE DISPATCH TABLE from the registered plane declarations and the per-plane runtime objects
/// (`slots`, each type-erased as `&dyn Any` and keyed by plane key). For every decl with a slot this
/// reads the plane's declared claims and admission from its OWN object — the seam that lets a plane
/// crate contribute its door without core naming its type — mounts each claim, and binds the
/// admission.
///
/// Split from `appbuild` and taking its inputs by argument so the admission ratchets are drivable
/// without booting an `App`, exactly as [`merged_boot_plane_decls`] is split from [`plane_decls`].
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

// The registry's cross-plane tests live in `crates/busbar/tests/registry_cross_plane.rs`, where a
// real roster is linked; this neutral source names no plane.

/// The FALLBACK plane's registry key — DERIVED from the plane registry rather than a hard-coded
/// literal: the ONE built-in plane whose decl declares [`PlaneDeclaration::fallback`]. Read by
/// the fallback guard (`PlaneDispatch::mount`/`admit` no-op) and the fallback-plane telemetry branch
/// so core names no dialect. The composition root (`register_planes`) installs the fallback plane
/// before any reader runs, and a test registers the fallback it needs, so exactly one fallback is
/// present. Core expresses "which plane handles unmatched routes"
/// by ASKING the declared fallback plane, never by hard-coding which plane that is.
pub fn fallback_key() -> &'static str {
    let decls = plane_decls();
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
    plane_decls().iter().any(|d| d.key == key && d.fallback)
}

/// The plane that DECLARES itself the fallback, resolved from ONE read of the plane list, or `None`
/// when no registered plane flags itself fallback. Unlike [`fallback_key`] it never degrades to a
/// sibling's key, so App composition derives the fallback runtime's slot key AND the `build_runtime`
/// that fills it from the same decl: the runtime under `runtime_slot_key(K)` is always plane `K`'s
/// own state (BUSBAR-1.6.0.md §6). Reading the list once is what makes that hold where the list can
/// grow between reads (a test binary's `register_test_plane`); production's list is frozen at boot.
pub(crate) fn fallback_decl() -> Option<&'static PlaneDecl> {
    plane_decls().iter().copied().find(|d| d.fallback)
}

/// Every built-in plane's registry key, in layering order. Iterated by dispatch, the config
/// validator and the candidate projection, so a plane absent from here is a plane that silently
/// does not exist.
///
/// Driven off the installed set: a door the root did not bind has no row, so it is not iterated
/// here — every [`plane_decl`] on it would fault. This is the successor to the old `Plane::ALL`, and the source of the LAYERING iteration
/// order every map walk must borrow rather than reinvent from a map's own key order.
pub fn plane_keys() -> impl Iterator<Item = &'static str> {
    plane_decls().iter().map(|d| d.key)
}

/// The built-in plane declaration for `key`, or panic — the by-key indirection the former `Plane`
/// accessors now read through. Callers wanting a decl FIELD (`config_section`, `subject_noun`,
/// `audit_kind`, `scope_kinds`) read it straight off this; the free fns below are the accessors
/// that COMPUTED something rather than reading a field.
pub fn plane_decl(key: &str) -> &'static PlaneDecl {
    plane_decl_for(key).unwrap_or_else(|| panic!("no built-in plane declared for key `{key}`"))
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

/// EVERY DIALECT A PROVIDER'S `protocol` MAY NAME: each registered plane's declared provider
/// dialects ([`PlaneDecl::provider_dialects`]), in registration order and each plane's
/// own order, each once (ARCHITECT ruling 2026-10-16, item 3; BUSBAR-1.6.0.md #49: the kernel
/// reads declared data and names no dialect). A build that registers none accepts no provider.
pub fn provider_dialects() -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    for d in plane_decls() {
        for name in (d.provider_dialects)() {
            if !out.contains(name) {
                out.push(name);
            }
        }
    }
    out
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
        wire_format_names: || &[],
        provider_dialects: || &[],
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
/// `crates/busbar/tests/plane_config_cross_plane.rs`, where naming the real planes is licensed.
///
/// Returns the [`TestRegistryIsolation`] guard, which the caller holds for its test body's
/// lifetime: the registered set stays exactly these three regardless of what ran before it or runs
/// concurrently with it.
#[cfg(test)]
pub(crate) fn isolated_three_plane_test_registry() -> TestRegistryIsolation {
    static ALPHA: PlaneDecl = neutral_sibling_decl("alpha", "alpha-section", "alpha thing");
    static BETA: PlaneDecl = neutral_sibling_decl("beta", "beta-section", "beta thing");
    static GAMMA: PlaneDecl = neutral_sibling_decl("gamma", "gamma-section", "gamma thing");
    // `TestRegistryIsolation::seeded`, NOT `empty()` followed by `register_test_plane`: the guard
    // holds `TEST_REGISTRY_SERIAL` for its whole lifetime, and `register_test_plane` takes that same
    // (non-reentrant) lock — calling it after `empty()` on this thread would self-deadlock. `seeded`
    // installs the three decls atomically under the one lock acquisition instead.
    TestRegistryIsolation::seeded(&[&ALPHA, &BETA, &GAMMA])
}

// ── TEST-SUPPORT PLANE REGISTRATION (the neutral seam) ─────────────────────────────────────────────
// A plane's `testkit` registers its `&'static PlaneDecl` here — a SUBSTRATE type — exactly as
// production's composition root installs its set (`install_doors`). The test-support `plane_decls()`
// folds this list after the installed set on every read, so a plane registered by any test before
// it reads the list is visible regardless of test order.
#[cfg(any(test, feature = "test-support"))]
static TEST_REGISTERED: std::sync::Mutex<Vec<&'static PlaneDecl>> =
    std::sync::Mutex::new(Vec::new());

/// THE PROCESS-WIDE TEST-REGISTRY SERIAL LOCK. Held by [`TestRegistryIsolation`] for the whole body of
/// a test that asserts against the BUILT-IN plane set, and taken briefly by every [`register_test_plane`]
/// call, so a sibling test's registration (which the composition-root-shaped plane test-kits perform
/// whenever they build a plane) cannot race — or leak into — that assertion. A separate lock from
/// `TEST_REGISTERED`'s own so the guard can hold it across reads that themselves lock `TEST_REGISTERED`
/// without self-deadlocking; the lock ORDER is always serial-then-registered.
#[cfg(any(test, feature = "test-support"))]
static TEST_REGISTRY_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// THE THREAD THAT CURRENTLY HOLDS A [`TestRegistryIsolation`], if any. The isolating test reads the
/// process plane list (`plane_decl_for` → [`test_registered_planes`]) ON ITS OWN THREAD while holding
/// the guard, and `std`'s `Mutex` is not reentrant, so that thread MUST NOT re-take
/// [`TEST_REGISTRY_SERIAL`] on the read path or it would self-deadlock. Every OTHER thread's reader
/// takes the serial lock and so blocks for the guard's whole lifetime — the fix for the reader gap
/// where a concurrent reader could observe the emptied set. Recorded under its own tiny mutex,
/// consulted first on every read; `None` outside an isolation.
#[cfg(any(test, feature = "test-support"))]
static TEST_ISOLATION_OWNER: std::sync::Mutex<Option<std::thread::ThreadId>> =
    std::sync::Mutex::new(None);

/// TEST-SUPPORT SEAM — register an extracted plane's declaration into the process registry, the way
/// the composition root's `install_doors` does in production. Idempotent by plane key; a plane's
/// `testkit` calls it (from its build-time finalizer, and eagerly from config-surface tests) so the
/// fixture registry matches a shipped "busbar with this plane" binary. The storage lives HERE, on the
/// neutral substrate, so a plane crate names no `busbar_kernel::` implementation to register itself.
///
/// Takes the [`TEST_REGISTRY_SERIAL`] lock around the mutation so a concurrent [`TestRegistryIsolation`]
/// either observes this registration in full or excludes it for its whole lifetime — never a torn view.
#[cfg(any(test, feature = "test-support"))]
pub fn register_test_plane(decl: &'static PlaneDecl) {
    let _serial = TEST_REGISTRY_SERIAL
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let mut reg = TEST_REGISTERED.lock().unwrap_or_else(|e| e.into_inner());
    if !reg.iter().any(|d| d.key == decl.key) {
        reg.push(decl);
    }
}

/// TEST-SUPPORT SEAM — ISOLATE THE PROCESS PLANE REGISTRY for one test. RAII: construction takes the
/// process [`TEST_REGISTRY_SERIAL`] lock and snapshots-then-clears the registered planes, so a test that
/// asserts against the built-in plane set sees a registry with no sibling's [`register_test_plane`]
/// leaked into it. While the guard is alive that lock is held, so any parallel registration BLOCKS
/// rather than mutating the set mid-assertion. On drop it restores the snapshot and releases the lock —
/// so the isolation is scoped to exactly the test that asked for it and the suite stays order-independent.
///
/// `busbar-core`'s `plane_decls()` re-folds on every read and memoises by the registered set's IDENTITY
/// (its decl addresses, not its count), so clearing or seeding the set here makes that memo resolve
/// against exactly the set installed, with nothing else to do.
#[cfg(any(test, feature = "test-support"))]
#[must_use = "the registry stays isolated only while the guard is alive"]
pub struct TestRegistryIsolation {
    _serial: std::sync::MutexGuard<'static, ()>,
    saved: Vec<&'static PlaneDecl>,
}

#[cfg(any(test, feature = "test-support"))]
impl TestRegistryIsolation {
    /// Take the serial lock, snapshot the registered planes, and clear them for the guard's lifetime.
    pub fn empty() -> Self {
        Self::seeded(&[])
    }

    /// Take the serial lock, snapshot the registered planes, and install EXACTLY `decls` (first-wins
    /// dedup by key) for the guard's lifetime — the isolated-AND-seeded combination [`Self::empty`]
    /// alone cannot express: `std::sync::Mutex` is not reentrant, so a caller that took `empty()`'s
    /// guard and then called [`register_test_plane`] on the SAME thread would re-lock
    /// [`TEST_REGISTRY_SERIAL`] it already holds and self-deadlock. This seeds the set atomically,
    /// under the one lock acquisition, instead.
    pub fn seeded(decls: &[&'static PlaneDecl]) -> Self {
        let serial = TEST_REGISTRY_SERIAL
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Record this thread as the isolation owner BEFORE clearing, so this thread's own reads take
        // the reentrant fast path (no re-lock of the serial it now holds) while every other thread's
        // reader blocks on the serial for the guard's lifetime.
        *TEST_ISOLATION_OWNER
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(std::thread::current().id());
        let saved = {
            let mut reg = TEST_REGISTERED.lock().unwrap_or_else(|e| e.into_inner());
            let saved = std::mem::take(&mut *reg);
            for decl in decls {
                if !reg.iter().any(|d| d.key == decl.key) {
                    reg.push(decl);
                }
            }
            saved
        };
        Self {
            _serial: serial,
            saved,
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
impl Drop for TestRegistryIsolation {
    fn drop(&mut self) {
        {
            let mut reg = TEST_REGISTERED.lock().unwrap_or_else(|e| e.into_inner());
            *reg = std::mem::take(&mut self.saved);
        }
        // Clear the owner while the serial is still held (`_serial` drops after this body), so a
        // foreign reader unblocking on serial release always sees the restored set, never the owner.
        *TEST_ISOLATION_OWNER
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
    }
}

/// TEST-SUPPORT SEAM — the planes registered through [`register_test_plane`], snapshot in registration
/// order. `busbar-core`'s test-support `plane_decls()` reads this to fold the extracted planes into the
/// process registry.
#[cfg(any(test, feature = "test-support"))]
pub fn test_registered_planes() -> Vec<&'static PlaneDecl> {
    // If THIS thread owns the active isolation it already holds the serial lock exclusively and sees
    // the (emptied) set it installed — read straight through, since re-taking the non-reentrant serial
    // would self-deadlock. EVERY OTHER thread takes the serial lock, so a reader concurrent with an
    // isolation blocks for the guard's whole lifetime and never observes the emptied set (the reader
    // gap this closes) — releasing only after the guard restores the snapshot.
    let owned_by_us = *TEST_ISOLATION_OWNER
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        == Some(std::thread::current().id());
    let _serial = if owned_by_us {
        None
    } else {
        Some(
            TEST_REGISTRY_SERIAL
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
        )
    };
    TEST_REGISTERED
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

#[cfg(test)]
#[path = "tests/doors_memo_tests.rs"]
mod doors_memo_tests;
