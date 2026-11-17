// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use serde::{Deserialize, Serialize};

/// One metric SERIES a plugin's signed manifest DECLARES it emits (`declares.metrics[]`) — the
/// FIRST-PARTY METRIC NAMESPACE (K9a S1).
///
/// A declaration is a claim the HOST grants or ignores; it never widens what an undeclared entry
/// may do. The host grants it only to a plugin admitted through the LINKED door or dropped in and
/// signed by the busbar release key: such a plugin may claim a reserved `busbar_*` name, and an
/// entry it reports under a granted name, of the declared `type`, renders exactly as declared —
/// the name as written and no `plugin=` provenance label. Every other plugin keeps the envelope's
/// rule (the reserved prefix refused, the `plugin=` label added) whatever it declares, and a claim
/// on a series the host itself emits is refused at open rather than merged into the host's.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SeriesDecl {
    /// The series name exactly as it renders (Prometheus charset).
    pub name: String,
    /// `counter` | `gauge` | `histogram` — the same tokens a `PluginMetric`'s `type` carries. An
    /// entry of another type under this name is not the declared series and is not granted.
    #[serde(rename = "type")]
    pub kind: String,
    /// THE SHED COUNTER (K9b, export ABI minor 7): a `counter` the HOST increments by one for every
    /// delivery it SHEDS for this sink at the sink's in-flight bound. A shed delivery never reaches
    /// the sink, so the sink cannot count it itself — the one fact of its own the host must report
    /// for it. Absent (`false`) on every declaration made before the flag existed, and skipped when
    /// false, so their canonical bytes — and signatures — are unchanged.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub shed: bool,
}

impl SeriesDecl {
    /// A declared series `name` of type `kind`.
    pub fn new(name: impl Into<String>, kind: impl Into<String>) -> SeriesDecl {
        SeriesDecl {
            name: name.into(),
            kind: kind.into(),
            shed: false,
        }
    }

    /// The same declaration, marked the sink's shed counter (see [`SeriesDecl::shed`]).
    #[must_use]
    pub fn shed(mut self) -> SeriesDecl {
        self.shed = true;
        self
    }
}

/// One `BUSBAR-NNNN` diagnostic a plugin's signed manifest DECLARES it raises
/// (`declares.diagnostics[]`) — PLUGIN DIAGNOSTICS (K9a S3).
///
/// The host registers a first-party plugin's declarations into its diagnostics catalogue through
/// the same seam a linked plane's owned codes take, before anything reads the catalogue, so a
/// `PluginDiagnostic` the plugin reports under the code resolves exactly as a built-in one does:
/// same code, same catalogue entry, same severity clamp. The fields are the catalogue entry's, one
/// for one; a declaration whose code is already in the catalogue, whose class (`code / 1000`) is not
/// one of the host's, or whose severity is not a severity token refuses the boot naming the plugin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticDecl {
    /// The numeric code (`1001` renders `BUSBAR-1001`); its thousands digit is its class.
    pub code: u16,
    /// Stable kebab-case anchor (the docs fragment).
    pub slug: String,
    /// Short human title.
    pub title: String,
    /// `benign_recurring` | `actionable` | `fatal` — the catalogue's severity tokens.
    pub severity: String,
    /// What the condition means.
    pub summary: String,
    /// What an operator should do.
    pub action: String,
    /// The version the code was introduced in.
    pub since: String,
}
