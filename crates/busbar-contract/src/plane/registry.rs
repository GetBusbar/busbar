//! THE PLANE DECLARATION LIST — which planes exist in this process — kept as CONTRACT DATA.
//!
//! One process has one answer to "which planes are there", and every layer that reads it must read
//! the same one: the composition root that installs the planes, the config grammar that resolves a
//! section to its plane, the entitlement decoder that resolves an opaque scope-kind index. A list that
//! lived in one of those layers would make every other layer name it, and the config layer in
//! particular may name no plane and no layer that does. So the list lives here, below all of them, as
//! data: a plain declaration STRUCT ([`PlaneDeclaration`], the facts every plane states about itself),
//! pure functions over a given list (the boot fold, the section fold, the claim guard), and the
//! process SLOT with its by-key, by-section and by-index readers.
//!
//! Nothing here names a plane. The rows themselves are handed across as data by the crate that may
//! name the plane: the composition root through [`install`], a test binary's built-in rows through
//! [`install_builtins`], and a test-kit's late registrations through the source
//! [`install_late_registration_source`] binds. A plane's BEHAVIOUR — the hooks a layer runs for it —
//! is not a fact about which planes exist and is not here: the layer that runs those hooks keeps them
//! in its own table, keyed by the same [`PlaneDeclaration::key`].
//!
//! ## Invariants
//!
//! * **INSTALL BEFORE FIRST READ.** A declaration installed after another layer resolved against the
//!   smaller set means two layers of one process disagree about which planes exist. The installer
//!   checks [`first_read`] and refuses in its own words.
//! * **SAME KEY REGISTERED TWICE IS SKIPPED, AND REPORTED.** Under a test binary's feature unification
//!   a plane can arrive both as a built-in row and as the installed crate's own copy. The later copy is
//!   skipped and its key is returned in [`BootFold::skipped`], so the fact is checkable rather than
//!   only logged.
//! * **CANONICAL LAYERING ORDER, INSTALL-SOURCE-INDEPENDENT.** A plane keeps the position its key
//!   first appears in across the built-in rows then the installed ones, whether it arrived as a row
//!   or as a crate. See [`merged_boot_plane_decls`].
//! * **ONE FOLD PER SOURCE SET.** Without a late-registration source the list is folded once and
//!   frozen — one acquire-load per read thereafter. With one (a test surface, where planes register
//!   as their kits run) the list is re-folded exactly when a source grows or shrinks, memoised by the
//!   `(installed, late, built-in)` length tuple: a lone sum would alias "installed grew by one while
//!   late shrank by one" onto the previous fold and hand back a stale list.

use std::sync::{Mutex, OnceLock};

/// THE FACTS A PLANE STATES ABOUT ITSELF, as plain data. Every field is a constant of the plane, read
/// at registration; nothing here is a hook, a handle or a behaviour. Two planes sharing a scope kind
/// is how one plane's grant admits another plane's traffic, and two sharing an audit kind is how one
/// plane's records start answering another plane's question — so these are the strings that must
/// not agree by coincidence, and they are declared once, here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlaneDeclaration {
    /// The registry key: the label a plane is installed, resolved and indexed by. Also the metrics
    /// label, the log label and the audit resource prefix. Operator-visible.
    pub key: &'static str,
    /// TRUE for the one plane that declares itself the FALLBACK catch-all — the plane every unclaimed
    /// path falls through to. At most one plane in a list sets it.
    pub fallback: bool,
    /// The top-level config section whose mere existence declares this plane.
    pub config_section: &'static str,
    /// The scope kinds a grant on this plane is written over, in the plane's own declared order.
    pub scope_kinds: &'static [&'static str],
    /// What ONE registration on this plane is called, in the words an operator reads back.
    pub subject_noun: &'static str,
    /// The singular operator-surface noun for one registration in this plane's named-definition
    /// section — the hyphenated spelling an audit action, an audit resource and a validation subject
    /// are stamped with.
    pub admin_noun: &'static str,
    /// The audit resource kind for a registration on this plane, and the prefix of every audit
    /// action word the plane's verbs record.
    pub audit_kind: &'static str,
    /// The versioned domain this plane's card-signing subkey is derived under, or `None` for a plane
    /// that signs no cards. A constant, never a signer: the host derives and signs, the plane never
    /// holds material.
    pub card_signing_domain: Option<&'static str>,
    /// The `kid` prefix this plane stamps on its card signatures, or `None` for a plane that signs
    /// no cards.
    pub card_kid_prefix: Option<&'static str>,
    /// The top-level config sections this plane declares it owns the grammar of.
    pub owned_config_sections: &'static [&'static str],
}

/// THE TOP-LEVEL CONFIG SECTIONS THE LEGACY CONFIG GRAMMAR STILL DECLARES CONCRETELY — the reserved
/// set the claim guard ([`check_owned_config_claims`]) refuses a plane from claiming until the section
/// is evicted from that grammar in the SAME change. As a later stage moves a section into its owning
/// plane crate, that stage DELETES the key here in lockstep with adding it to the plane's
/// `owned_config_sections`, so at no instant is a section either owned by nobody or claimed by two.
pub const CORE_OWNED_CONCRETE_SECTIONS: &[&str] =
    &["providers", "models", "pools", "rate_card", "limits"];

/// THE CLAIM GUARD. Judges every declaration's `owned_config_sections` across the whole set against
/// the reserved set, returning `Ok(())` when every claim is disjoint and unique, or the FIRST refusal.
/// It is a hard error if two planes claim the same section (one plane's grammar would answer for
/// another's) or if a plane claims a reserved section (the grammar would be declared twice).
///
/// Pure: a declaration list and a reserved-key list in, a verdict out. The boot fold runs it over the
/// merged list; a test drives it directly.
pub fn check_owned_config_claims(
    decls: &[PlaneDeclaration],
    reserved: &[&'static str],
) -> Result<(), String> {
    // section key → the plane key that first claimed it, so a second claimant names its rival.
    let mut claimed: std::collections::BTreeMap<&'static str, &'static str> =
        std::collections::BTreeMap::new();
    for decl in decls {
        for &section in decl.owned_config_sections {
            if reserved.contains(&section) {
                return Err(format!(
                    "plane `{}` claims config section `{section}`, but core still owns it concretely: \
                     a section must be evicted from core's `DeployCfg` in the SAME change that a plane \
                     claims it, never before — else the grammar is declared twice and the config stops \
                     deserializing byte-identically",
                    decl.key
                ));
            }
            if let Some(other) = claimed.insert(section, decl.key) {
                return Err(format!(
                    "config section `{section}` is claimed by two planes (`{other}` and `{}`): a \
                     section is owned by exactly one plane, or one plane's grammar answers for \
                     another's",
                    decl.key
                ));
            }
        }
    }
    Ok(())
}

/// WHAT THE BOOT FOLD PRODUCED: the surviving declarations in canonical order, and the key of every
/// later same-key registration it skipped, in the order they were met.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootFold {
    /// One declaration per key, installed copy first, in canonical layering order.
    pub decls: Vec<PlaneDeclaration>,
    /// The keys whose later copy was skipped. Empty in a process with no duplicate rows.
    pub skipped: Vec<&'static str>,
}

/// THE BOOT FOLD: installed declarations ahead of built-ins, one entry per KEY, a later same-key
/// registration skipped and reported. The survivors are then put in CANONICAL LAYERING ORDER — the
/// order each key first appears across the built-in rows then the installed ones — so a plane that
/// arrived as a crate lands in the slot its built-in row held, and a key outside that order keeps its
/// relative position at the tail (a stable sort). Runs the claim guard over the survivors.
///
/// Pure over its inputs, so a test drives its order and skip rules directly rather than through the
/// process slot, which can be folded once per binary.
///
/// # Panics
/// If the claim guard refuses: a mis-wired composition root is a build bug, not an operator error.
pub fn merged_boot_plane_decls(
    installed: &[PlaneDeclaration],
    builtins: &[PlaneDeclaration],
) -> BootFold {
    let mut decls: Vec<PlaneDeclaration> = Vec::new();
    let mut skipped: Vec<&'static str> = Vec::new();
    for d in installed.iter().chain(builtins) {
        if decls.iter().any(|p| p.key == d.key) {
            skipped.push(d.key);
            continue;
        }
        decls.push(*d);
    }
    let canonical = canonical_key_order(installed, builtins);
    let rank = |key: &str| {
        canonical
            .iter()
            .position(|k| *k == key)
            .unwrap_or(canonical.len())
    };
    decls.sort_by_key(|d| rank(d.key));
    if let Err(refusal) = check_owned_config_claims(&decls, CORE_OWNED_CONCRETE_SECTIONS) {
        panic!("plane-owned-config dup-claim guard: {refusal}");
    }
    BootFold { decls, skipped }
}

/// THE OPERATOR-VISIBLE LAYERING ORDER, by key, derived from the registration data: the order each
/// key FIRST APPEARS across the built-in rows then the installed ones, deduped. In production the
/// built-in rows are empty and the composition root installs the planes in layering order, so the
/// install order IS the canonical order; under a test binary the built-in rows supply it.
fn canonical_key_order(
    installed: &[PlaneDeclaration],
    builtins: &[PlaneDeclaration],
) -> Vec<&'static str> {
    let mut order: Vec<&'static str> = Vec::new();
    for d in builtins.iter().chain(installed) {
        if !order.contains(&d.key) {
            order.push(d.key);
        }
    }
    order
}

/// THE SECTION FOLD: every top-level config section a bare reference could be reaching onto, DERIVED
/// from the declarations rather than written as a literal — each declaration's `config_section` in
/// list order, then the `trailing` sections the config grammar declares of its own (the
/// named-definition maps), deduped in that order so a section both halves name appears once, at its
/// first position. Deterministic, so a refusal naming a section names the same one on every run.
pub fn config_sections_from(
    decls: &[PlaneDeclaration],
    trailing: &[&'static str],
) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    for section in decls
        .iter()
        .map(|decl| decl.config_section)
        .chain(trailing.iter().copied())
    {
        if !out.contains(&section) {
            out.push(section);
        }
    }
    out
}

// ── THE PROCESS SLOT ──────────────────────────────────────────────────────────────────────────────

/// Declarations the composition root installed.
static INSTALLED: OnceLock<Vec<PlaneDeclaration>> = OnceLock::new();

/// The built-in rows a test binary installed. Empty in production, which carries none.
static BUILTINS: OnceLock<Vec<PlaneDeclaration>> = OnceLock::new();

/// The late-registration source, when a test surface bound one; absent in production.
static LATE: OnceLock<fn() -> Vec<PlaneDeclaration>> = OnceLock::new();

/// The frozen fold, taken on first read when no late source is bound.
static FROZEN: OnceLock<&'static [PlaneDeclaration]> = OnceLock::new();

/// One memo entry: the length tuple the fold was last computed for, and the leaked list it produced.
type Memo = ((usize, usize, usize), &'static [PlaneDeclaration]);

/// The re-foldable memo used once a late source is bound.
static MEMO: Mutex<Option<Memo>> = Mutex::new(None);

/// RECORD THE COMPOSITION ROOT'S INSTALLED DECLARATIONS. Returns `false` when a set is already
/// recorded, so the installer raises its own "one composition root, registers once" refusal.
pub fn install(decls: Vec<PlaneDeclaration>) -> bool {
    INSTALLED.set(decls).is_ok()
}

/// INSTALL A TEST BINARY'S BUILT-IN ROWS as data. Idempotent by first write: the rows are a
/// compile-time constant of the installing crate, so a repeat is the same list, not a second answer
/// to which planes exist.
pub fn install_builtins(decls: Vec<PlaneDeclaration>) {
    let _ = BUILTINS.set(decls);
}

/// BIND THE LATE-REGISTRATION SOURCE — the seam a test surface hands its growable registration set
/// through, so a plane a test-kit registers after the first read is visible to every later read. First
/// bind wins; a second is a no-op. Never bound in production, where the list freezes on first read.
pub fn install_late_registration_source(source: fn() -> Vec<PlaneDeclaration>) {
    let _ = LATE.set(source);
}

/// HAS THE LIST BEEN FOLDED YET? The witness behind INSTALL BEFORE FIRST READ: the frozen fold or
/// the re-foldable memo being populated.
pub fn first_read() -> bool {
    FROZEN.get().is_some() || MEMO.lock().unwrap_or_else(|e| e.into_inner()).is_some()
}

/// The process plane list, in canonical order. Frozen on first read unless a late source is bound,
/// in which case it is re-folded exactly when a source's length changes.
pub fn plane_decls() -> &'static [PlaneDeclaration] {
    let installed = INSTALLED.get().map(Vec::as_slice).unwrap_or(&[]);
    let builtins = BUILTINS.get().map(Vec::as_slice).unwrap_or(&[]);
    let Some(late) = LATE.get() else {
        return FROZEN.get_or_init(|| leak_fold(installed, &[], builtins));
    };
    let late = late();
    let want = (installed.len(), late.len(), builtins.len());
    let mut memo = MEMO.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((key, list)) = *memo {
        if key == want {
            return list;
        }
    }
    let list = leak_fold(installed, &late, builtins);
    *memo = Some((want, list));
    list
}

/// Fold and leak ONCE for this source set, so the `&'static` contract holds. Bounded: at most one
/// leak per distinct source set, which is one in production and at most one per registered plane
/// under a test surface.
fn leak_fold(
    installed: &[PlaneDeclaration],
    late: &[PlaneDeclaration],
    builtins: &[PlaneDeclaration],
) -> &'static [PlaneDeclaration] {
    let mut all: Vec<PlaneDeclaration> = installed.to_vec();
    all.extend_from_slice(late);
    Box::leak(
        merged_boot_plane_decls(&all, builtins)
            .decls
            .into_boxed_slice(),
    )
}

/// THE ABI PLANE-KEY (the registration INDEX) for a declaration key, or `u8::MAX` when no registered
/// plane owns it — the opaque numeric handle the ABI carries, resolved back by [`plane_key_at`]. The
/// number is only a position in the process list.
pub fn plane_key_index(key: &str) -> u8 {
    plane_decls()
        .iter()
        .position(|d| d.key == key)
        .map_or(u8::MAX, |i| i as u8)
}

/// The declaration key at ABI registration index `idx`, or `None` when out of range — the inverse of
/// [`plane_key_index`].
pub fn plane_key_at(idx: u8) -> Option<&'static str> {
    plane_decls().get(idx as usize).map(|d| d.key)
}

/// THE SCOPE KIND at ABI scope-kind index `idx`, derived from the list: index `0` is the neutral base
/// kind `"pool"` (the kind every deployment has); indices `1..` are each plane's declared scope kinds
/// in list order. `None` (fail-closed) past the registered kinds.
///
/// The index is a bijection over the DISTINCT kinds, base first: a plane that also declares the base
/// kind must NOT re-count it, or every later plane's kind shifts up by one and a grant over the base
/// kind resolves another plane's target. A re-declared base folds onto index 0.
pub fn scope_kind_at(idx: u32) -> Option<&'static str> {
    scope_kinds().nth(idx as usize)
}

/// THE ABI SCOPE-KIND INDEX for a kind — the exact inverse of [`scope_kind_at`], over the same
/// deduped sequence so the encode and decode sides cannot skew. `None` for a kind no registered plane
/// declares.
pub fn scope_kind_index(kind: &str) -> Option<u32> {
    scope_kinds().position(|k| k == kind).map(|i| i as u32)
}

/// The one sequence both scope-kind readers index: the base kind, then each plane's declared kinds,
/// deduplicated in first-seen order.
fn scope_kinds() -> impl Iterator<Item = &'static str> {
    let mut seen: Vec<&'static str> = Vec::new();
    std::iter::once("pool")
        .chain(
            plane_decls()
                .iter()
                .flat_map(|d| d.scope_kinds.iter().copied()),
        )
        .filter(move |k| {
            let fresh = !seen.contains(k);
            if fresh {
                seen.push(k);
            }
            fresh
        })
}

/// RESOLVE A DECLARATION BY KEY. Allocates nothing. Named for its axis: the protocol axis owns the one
/// `decl_for`, and a second by-name resolution under that name would be a second answer to which
/// protocols exist.
pub fn plane_decl_for(key: &str) -> Option<&'static PlaneDeclaration> {
    plane_decls().iter().find(|d| d.key == key)
}

/// RESOLVE A DECLARATION BY ITS CONFIG SECTION — the bridge a config path crosses to reach a plane
/// without naming it. Against the whole process list, so a plane installed as a crate is found on the
/// same footing as a built-in row.
pub fn plane_decl_for_config_section(section: &str) -> Option<&'static PlaneDeclaration> {
    plane_decls().iter().find(|d| d.config_section == section)
}

/// THE FALLBACK PLANE'S KEY over a GIVEN list — the one declaration that flags itself
/// [`PlaneDeclaration::fallback`], the plane every unclaimed path falls through to. A fact of the
/// list, so it is answered here beside the list rather than by whichever layer happens to read it:
/// the config grammar resolves the section the fallback plane owns through it, and the engine's
/// dispatch guards read the same answer. Neither may spell the key.
///
/// FIRST-WINS, and at most one: with two fallback declarations a `find` would silently pick one and
/// the other's paths would fall through nowhere, so a list carrying two is a programming error the
/// debug build reports. When NO declaration is flagged the BASE (first-layered) plane answers — the
/// one build where that happens is a test binary that registers only the plane under test, whose
/// key then labels an empty telemetry bank and is never emitted. An empty list answers `""`.
pub fn fallback_key_of(decls: &[PlaneDeclaration]) -> &'static str {
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

/// Whether `key` names THE FALLBACK plane in a GIVEN list — the non-panicking predicate a fallback
/// GUARD reads. Distinct from [`fallback_key_of`]: it answers "is THIS key the fallback" WITHOUT
/// requiring a fallback to be declared, so it is safe in a list where none is.
pub fn is_fallback_in(decls: &[PlaneDeclaration], key: &str) -> bool {
    decls.iter().any(|d| d.key == key && d.fallback)
}

/// [`fallback_key_of`] over the process list.
pub fn fallback_key() -> &'static str {
    fallback_key_of(plane_decls())
}

/// [`is_fallback_in`] over the process list.
pub fn is_fallback(key: &str) -> bool {
    is_fallback_in(plane_decls(), key)
}
