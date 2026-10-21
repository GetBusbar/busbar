// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE SECTIONS' NAMED ENTRIES, keyed by the door that owns each section, and the one rule a
//! reference between them follows: a section names only its own entries ([`PlaneSections::resolve`],
//! [`RefError`]). The owning doors and their sections are the lent door table's
//! ([`crate::plane_driver::doors::Doors`]).

// Members some build surfaces read only from tests (the module this came from held the same
// posture, `plane/mod.rs`).
#![cfg_attr(not(test), allow(dead_code))]

use crate::plane_driver::doors::Doors;

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
/// `pub(crate)` so `crates/busbar/tests/plane_config_cross_plane.rs::the_resolve_time_refusal_fires_on_a_bare_name_that_binds_across_the_boundary`
/// can drive the resolve-time refusal directly, over the REAL plane roster, exactly as the sibling
/// parse-time refusal in that file already does — the same "internal-only `busbar-kernel` crate
/// (`publish = false`) pays that cost" reasoning `crates/busbar/tests/registry_cross_plane.rs`'s header gives for its own
/// widened seams.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlaneSections<T> {
    /// One section per plane, keyed by plane registry key. An absent key is an EMPTY section, read
    /// as such by every accessor — the same answer the old three hard fields gave for a plane that
    /// happened to hold nothing. Iteration order is never taken from this map's own key order:
    /// every walk drives from the table's [`Doors::plane_keys`] (LAYERING order) so the
    /// validator's diagnostics stay deterministic and in the order the module header describes.
    sections: std::collections::BTreeMap<&'static str, std::collections::BTreeMap<String, T>>,
    /// The door table the sections belong to: its keys are the walk order.
    doors: Doors,
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

impl RefError {
    /// The operator's sentence for this refusal, naming each plane by the config section it owns in
    /// `doors`, the table the sections were resolved against.
    #[must_use]
    pub fn message(&self, doors: Doors) -> String {
        match self {
            RefError::CrossPlane {
                name,
                referenced_from,
                defined_in,
            } => format!(
                "`{}` references `{name}`, which is defined in `{}`. The plane sections are \
                 siblings and never reference each other: define `{name}` in `{}`, or move the \
                 reference.",
                doors.plane_decl(referenced_from).config_section,
                doors.plane_decl(defined_in).config_section,
                doors.plane_decl(referenced_from).config_section
            ),
            RefError::Unknown { name, plane } => format!(
                "`{}` references `{name}`, which is not defined.",
                doors.plane_decl(plane).config_section
            ),
        }
    }
}

// `Default` is hand-written, NOT derived. The derive would bound it on `T: Default`, which is
// wrong twice over: an EMPTY container needs nothing from `T`, and requiring it would force every
// entry type a plane ever holds to invent a meaningless empty value just to be storable here.
impl<T> Default for PlaneSections<T> {
    fn default() -> Self {
        Self::new(Doors::NONE)
    }
}

impl<T> PlaneSections<T> {
    /// An empty container over the sections of `doors`, the lent door table.
    #[must_use]
    pub fn new(doors: Doors) -> Self {
        Self {
            sections: std::collections::BTreeMap::new(),
            doors,
        }
    }

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
    /// The sibling scan runs in the table's [`Doors::plane_keys`] (LAYERING) order so a name defined on several other
    /// planes always diagnoses the same one. A nondeterministic diagnostic is worse than none: it
    /// makes a boot failure unreproducible.
    pub fn resolve(&self, plane: &'static str, name: &str) -> Result<&T, RefError> {
        if let Some(entry) = self.sections.get(plane).and_then(|m| m.get(name)) {
            return Ok(entry);
        }
        for other in self.doors.plane_keys().filter(|k| *k != plane) {
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
    /// the table's [`Doors::plane_keys`] so the walk is in LAYERING order regardless of the map's
    /// own key order.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&'static str, &str, &T)> {
        self.doors.plane_keys().flat_map(move |k| {
            self.sections
                .get(k)
                .into_iter()
                .flatten()
                .map(move |(n, e)| (k, n.as_str(), e))
        })
    }
}

#[cfg(test)]
#[path = "tests/plane_refs_tests.rs"]
mod plane_refs_tests;
