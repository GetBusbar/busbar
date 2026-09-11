// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE COMPOSITION ROOT'S ONE WRITE INTO THE PLANE AXIS.
//!
//! MOVED VERBATIM from the legacy core's `plane/registry.rs`, beside its protocol twin
//! (`proto_install`): the composition root owns the boot installers, and this one had exactly one
//! caller, `register_planes` in this crate's `main.rs`. It could not move while the plane LIST lived
//! in core — core's readers of that list cannot name a root module — and it can now that the list is
//! contract data (`busbar_contract::plane::registry`): the root writes the contract slot, core reads
//! it, and neither names the other.
//!
//! One installer, two tables, because a declaration is two things: the FACTS a plane states (its key,
//! section and scope kinds — the contract list every layer folds) and the BEHAVIOUR a layer runs for
//! it (the fn-pointer row the substrate's `PlaneDecl` keeps, keyed by the same key). Both refusal
//! sentences are the ones this function has always raised, byte-identical.
//!
//! IT TAKES THEM AS PAIRS, and that is the composition root doing its job rather than an argument
//! saved. A plane's FACTS live in its pure `busbar-plane-*` half (they name no host type) and its
//! BEHAVIOUR lives in its engine (it names nothing but); nobody but the root may name both crates,
//! so the root is the only place the two halves can be put beside each other, and a pair makes that
//! explicit instead of leaving two lists to stay in the same order by luck.

use busbar_contract::plane::PlaneDeclaration;
use busbar_core::plane::registry::install_plane_behaviours;

/// ONE PLANE, BOTH HALVES: the facts it states (its pure half's) and the behaviour a layer runs for
/// it (its engine's). Paired by the composition root, which is the only crate that may name both.
pub use busbar_core::plane::registry::PlaneRow;

/// JUDGE THE SET BEFORE ANY OF IT IS INSTALLED — pure over the rows, so a test drives it without
/// writing the process slot (which a binary can do once).
///
/// Two refusals, and each is a way a plane can fail to COMPOSE rather than fail to work:
///
/// * **A PAIR WHOSE HALVES DISAGREE ABOUT WHICH PLANE IT IS.** The facts table and the behaviour
///   table are joined BY KEY, so a mismatched pair does not fail loudly — it silently resolves one
///   plane's facts onto another plane's hooks, which is a plane serving under another plane's scope
///   kinds and stamping another plane's audit kind.
/// * **A DECLARATION MISSING A FACT.** Every string on a declaration is read by a kind-neutral layer
///   that has no other source for it: an empty `config_section` is a plane no config can declare and
///   no section can resolve to; an empty `audit_kind` stamps every record of this plane with the
///   empty resource kind; an empty `scope_kinds` is a plane no grant can be written over. None of
///   those fails at boot — they fail later, as a wrong answer, which is why they are refused HERE.
fn judge(rows: &[PlaneRow]) -> Result<(), String> {
    for (decl, row) in rows {
        judge_one(decl, row.key)?;
    }
    Ok(())
}

/// ONE ROW'S HALF OF [`judge`], taking the behaviour row's KEY rather than the row: the key is the
/// only field this rule reads off one, and taking it by value is what lets a test drive the rule
/// without hand-building a `PlaneDecl`'s twenty fn-pointer fields — which it could not do anyway,
/// since that type is the frozen substrate's and has no empty constructor to build from.
fn judge_one(decl: &PlaneDeclaration, row_key: &str) -> Result<(), String> {
    {
        {
            if decl.key != row_key {
                return Err(format!(
                "the row pairs the declaration of `{}` with the behaviour of `{}`: the two tables \
                 are joined by key, so a mismatched pair resolves one plane's facts onto another's \
                 hooks",
                decl.key, row_key
            ));
            }
            for (what, value) in [
                ("key", decl.key),
                ("config_section", decl.config_section),
                ("subject_noun", decl.subject_noun),
                ("admin_noun", decl.admin_noun),
                ("audit_kind", decl.audit_kind),
            ] {
                if value.is_empty() {
                    return Err(format!(
                    "plane `{}` declares an empty `{what}`: every fact on a declaration is read by \
                     a layer that has no other source for it, so a plane that does not state one \
                     does not compose",
                    decl.key
                ));
                }
            }
            if decl.scope_kinds.is_empty() {
                return Err(format!(
                "plane `{}` declares no scope kinds: a grant on this plane would be written over \
                 nothing, so no credential could ever be scoped to it",
                decl.key
            ));
            }
        }
    }
    Ok(())
}

/// INSTALL PLANE DECLARATIONS — the composition root's one write into the plane axis, called from
/// `main` (`register_planes`) before any config load or validation touches a plane.
///
/// Also registers each plane's scope kinds with the neutral scope-kind wire registry, so a
/// `VirtualKey` grant of a plane's kind serializes to its `allowed_{kind}s` wire field. The fold used
/// to do this on first read; the contract cannot name that registry, so the install site does it —
/// idempotent, the same set, earlier.
///
/// # Panics
/// - if called twice: two composition roots is a wiring bug, not a merge to attempt.
/// - if called after the plane list was first read: a declaration installed after another layer
///   resolved against the smaller set means two layers of one process disagree about which planes
///   exist.
pub fn install_planes(rows: &'static [PlaneRow]) {
    // EVERY REFUSAL BEFORE THE FIRST WRITE. The order used to be install-then-check, which is the
    // shape that made this function's own refusal test corrupt the binary it ran in: the refused
    // call had already written the process slot by the time it panicked, and every later test in the
    // same binary then resolved against the empty list it left behind. A function that refuses a
    // call should leave the process exactly as it found it, and the two checks below read state
    // rather than write it, so there is no reason for them to come second.
    assert!(
        !busbar_contract::plane::registry::first_read(),
        "install_planes called after the plane list was first read; register in main before any \
         config load or validation touches a plane"
    );
    if let Err(refusal) = judge(rows) {
        panic!("install_planes: {refusal}");
    }
    assert!(
        busbar_contract::plane::registry::install(rows.iter().map(|(d, _)| **d).collect()),
        "install_planes called twice: there is one composition root, and it registers once"
    );
    install_plane_behaviours(rows);
    for (decl, _) in rows {
        for kind in decl.scope_kinds {
            busbar_api::register_scope_kind(kind);
        }
    }
}

/// The installer's own proofs: the two composition refusals, the pair form, and the one write the
/// process slot allows. See `tests/plane_install.rs`.
#[cfg(test)]
#[path = "tests/plane_install.rs"]
mod tests;
