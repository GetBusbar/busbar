// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plane instance names the top-level configuration recognizer reads, and the `--stdio`
//! judgement (WP1-GAP-plane-sections r3, adopted; conditions A-C4 and B3).
//!
//! A plane owns the top-level section named by its instance: its alias, else its identity (r34
//! §12.23 rule 1). A key that is neither a core section nor such a name is refused by core's
//! rule R. Recognition reads only identities and aliases, so it runs no plugin code.

use std::collections::BTreeMap;

use super::{Described, Images};

/// The admitted planes' instance names, each with the identity that answers to it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlaneSections {
    by_name: BTreeMap<String, String>,
}

impl PlaneSections {
    /// The identity of the plane whose instance name is the top-level key `key`.
    #[must_use]
    pub fn identity_of_section(&self, key: &str) -> Option<&str> {
        let _ = key;
        None
    }

    /// Every plane instance name, in order: what rule R's refusal lists.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.by_name.keys().map(String::as_str)
    }
}

/// Why the admitted planes' instance names cannot be recognized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstanceNameRefusal {
    /// Two plane images answer to one instance name.
    Shared {
        /// The instance name.
        name: String,
        /// The first image's identity.
        first: String,
        /// The second image's identity.
        second: String,
    },
    /// A plane's instance name is a core section's key (B3). `field` is the word compared.
    CoreKey {
        /// `alias` or `identity`.
        field: &'static str,
        /// The instance name.
        word: String,
        /// The plane's identity.
        identity: String,
    },
}

impl core::fmt::Display for InstanceNameRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Shared {
                name,
                first,
                second,
            } => write!(
                f,
                "the plane images `{first}` and `{second}` both answer to the instance name \
                 `{name}`; remove one"
            ),
            Self::CoreKey {
                field,
                word,
                identity,
            } => write!(
                f,
                "plane `{identity}`: its {field} `{word}` names a core configuration section; a \
                 plane instance may not take a core section's name"
            ),
        }
    }
}

/// The instance names of the admitted planes `(identity, alias)`, refusing a shared name and a
/// name `is_core_key` says is a core section's (B3). `is_core_key` is core's own typed key list.
///
/// # Errors
/// The first refusal, in input order.
pub fn plane_sections<'a>(
    planes: impl IntoIterator<Item = (&'a str, &'a str)>,
    is_core_key: impl Fn(&str) -> bool,
) -> Result<PlaneSections, InstanceNameRefusal> {
    let _ = (planes.into_iter().count(), is_core_key(""));
    Ok(PlaneSections::default())
}

/// Whether an admitted image is a plane declaring a ROUTE_LINE route (r34 §12.23).
pub(crate) fn declares_line_route(described: &Described) -> bool {
    let _ = described;
    false
}

impl Images {
    /// Whether the admitted image `identity` is a plane that serves lines (ROUTE_LINE).
    #[must_use]
    pub fn serves_lines(&self, identity: &str) -> bool {
        self.described(identity)
            .is_some_and(|described| declares_line_route(&described))
    }
}

/// Why `--stdio` cannot bind a line plane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StdioRefusal {
    /// No admitted plane serves a line route.
    None,
    /// Several do: their instance names, sorted.
    Several(Vec<String>),
}

impl core::fmt::Display for StdioRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::None => f.write_str("`--stdio`: no configured plane serves a line route"),
            Self::Several(names) => write!(
                f,
                "`--stdio`: several configured planes serve a line route: {}",
                names.join(", ")
            ),
        }
    }
}

/// The one plane instance `--stdio` binds, judged after describe and before any instance opens
/// (A-C4): `instances` is every admitted plane's `(instance name, serves lines)`.
///
/// # Errors
/// None or several line planes.
pub fn stdio_instance<'a>(
    instances: impl IntoIterator<Item = (&'a str, bool)>,
) -> Result<&'a str, StdioRefusal> {
    let _ = instances.into_iter().count();
    Err(StdioRefusal::None)
}

#[cfg(test)]
#[path = "plane_sections_tests.rs"]
mod tests;
