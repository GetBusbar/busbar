// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Voice plane diagnostics — the `VOICE_*` catalog entries this crate OWNS.
//!
//! The neutral `busbar_substrate::diagnostics` catalog names NO plane token (the plane-purity
//! discipline); each plane crate declares its own `Diagnostic` consts and hands them to the
//! composition root, exactly as `busbar-mcp` / `busbar-a2a` do. Each entry carries a stable
//! `BUSBAR-NNNN` number in the `Class::Plane` (7000) band and a kebab-case slug that names ONLY this
//! plane (`voice-…`) and no other plane or dialect noun.
//!
//! [`DIAGNOSTICS`] is the slice the composition root hands to
//! [`install_diagnostics`](busbar_substrate::diagnostics::install_diagnostics) so these codes join
//! the runtime catalog (`REGISTRY ∪ installed`) and resolve through `by_code`. The `busbar` binary
//! names one stable path: `busbar_voice::DIAGNOSTICS`. Voice is not yet booted by the binary
//! (`register_diagnostics` includes it at M5); the export exists now so M5 is a one-line addition.

use busbar_substrate::diagnostics::{Class, Diagnostic, Severity};

/// The D2 governance outcome: a live voice session was HARD-CLOSED when its metering lease reached
/// the real cap (settle-past-cap), rather than being allowed to run unmetered. This is the plane's
/// fail-closed spend ceiling doing its job on a long-lived session.
pub const VOICE_SESSION_LEASE_EXHAUSTED: Diagnostic = Diagnostic {
    code: 7050,
    class: Class::Plane,
    slug: "voice-session-lease-exhausted",
    title: "Voice session hard-closed on metering-lease exhaustion",
    severity: Severity::BenignRecurring,
    summary: "A live voice session reached its metering lease's real cap and was hard-closed rather \
              than allowed to keep spending. This is the plane's fail-closed ceiling on a long-lived \
              session doing its job — the carrier is torn down at the cap, not past it.",
    action: "None — self-heals. If a caller needs a larger envelope, raise its configured session \
             budget; the refusal reason is recorded in the session's audit trail.",
    since: "1.6.0",
    retired: false,
};

/// THE VOICE PLANE'S PLANE-CONTRIBUTED DIAGNOSTICS — the `&'static [&'static Diagnostic]` the
/// composition root installs via `install_diagnostics`. Ascending by code, mirroring the neutral
/// `REGISTRY` and the sibling plane catalogs.
pub static DIAGNOSTICS: &[&Diagnostic] = &[&VOICE_SESSION_LEASE_EXHAUSTED];

#[cfg(test)]
#[path = "tests/diagnostics_tests.rs"]
mod tests;
