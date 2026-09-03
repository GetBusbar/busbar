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
mod tests {
    use super::*;

    /// Codes are unique within this plane's catalog — a collision would make one un-resolvable.
    #[test]
    fn codes_are_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for d in DIAGNOSTICS {
            assert!(
                seen.insert(d.code),
                "duplicate code {} ({})",
                d.code,
                d.slug
            );
        }
    }

    /// The thousands digit of every code equals its class ordinal, and the x000 slot is reserved.
    #[test]
    fn code_thousands_digit_matches_class() {
        for d in DIAGNOSTICS {
            assert_eq!(
                d.code / 1000,
                d.class.ordinal(),
                "{} ({}) class/code mismatch",
                d.banner(),
                d.slug
            );
            assert!(
                d.code % 1000 != 0,
                "{} ({}) uses the reserved x000 slot",
                d.banner(),
                d.slug
            );
        }
    }

    /// Slugs are unique, non-empty, kebab-case — they are stable doc anchors and URL fragments.
    #[test]
    fn slugs_are_unique_and_kebab_case() {
        let mut seen = std::collections::BTreeSet::new();
        for d in DIAGNOSTICS {
            assert!(seen.insert(d.slug), "duplicate slug {:?}", d.slug);
            assert!(!d.slug.is_empty(), "{} has an empty slug", d.banner());
            assert!(
                d.slug
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
                "slug {:?} is not kebab-case",
                d.slug
            );
            assert!(
                !d.slug.starts_with('-') && !d.slug.ends_with('-') && !d.slug.contains("--"),
                "slug {:?} has a leading/trailing/double hyphen",
                d.slug
            );
        }
    }

    /// Every non-retired entry documents its meaning and an action.
    #[test]
    fn every_live_entry_documents_meaning_and_action() {
        for d in DIAGNOSTICS {
            if d.retired {
                continue;
            }
            assert!(d.summary.len() > 20, "{} has no real summary", d.banner());
            assert!(d.action.len() > 3, "{} has no action", d.banner());
        }
    }
}
