// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plane instance names the top-level configuration recognizer reads, and the `--stdio`
//! judgement (WP1-GAP-plane-sections r3, adopted; conditions A-C4 and B3).
//!
//! A plane owns the top-level section named by its instance: its alias, else its identity (r34
//! §12.23 rule 1). A key that is neither a core section nor such a name is refused by core's
//! rule R. Recognition reads only identities and aliases, so it runs no plugin code.

use std::collections::BTreeMap;

use busbar_plugin_abi::plane::{tag as t, RouteRec, ROUTE_ADMIN, ROUTE_LINE, ROUTE_RECOVERY};
use busbar_plugin_abi::records::Rec;
use busbar_plugin_abi::types::KindCode;

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
        self.by_name.get(key).map(String::as_str)
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
    let mut by_name: BTreeMap<String, String> = BTreeMap::new();
    for (identity, alias) in planes {
        let (field, word) = if alias.is_empty() {
            ("identity", identity)
        } else {
            ("alias", alias)
        };
        if is_core_key(word) {
            return Err(InstanceNameRefusal::CoreKey {
                field,
                word: word.to_owned(),
                identity: identity.to_owned(),
            });
        }
        if let Some(first) = by_name.get(word) {
            return Err(InstanceNameRefusal::Shared {
                name: word.to_owned(),
                first: first.clone(),
                second: identity.to_owned(),
            });
        }
        by_name.insert(word.to_owned(), identity.to_owned());
    }
    Ok(PlaneSections { by_name })
}

/// Whether an admitted image is a plane declaring a ROUTE_LINE route (r34 §12.23).
pub(crate) fn declares_line_route(described: &Described) -> bool {
    route_flags(described).any(|flags| flags & ROUTE_LINE != 0)
}

/// Route flags that keep a route off the data listener. r34 has no HTTP route flag. Its plane
/// route-flag rules (r34 l.3968-3978) say ROUTE_LINE and ROUTE_RECOVERY routes are "never mounted on
/// a listener" and ROUTE_ADMIN routes mount on the admin router. Every other admitted route (plain,
/// ROUTE_CATALOG, and ROUTE_UPGRADE, whose upgrade starts as an HTTP GET head, §12.27) is served over
/// HTTP on the data listener.
const NOT_DATA_HTTP: u32 = ROUTE_LINE | ROUTE_RECOVERY | ROUTE_ADMIN;

/// Whether an admitted image is a plane declaring a route core serves over HTTP on the data listener.
pub(crate) fn declares_http_route(described: &Described) -> bool {
    route_flags(described).any(|flags| flags & NOT_DATA_HTTP == 0)
}

/// The flags of every D_ROUTE an admitted plane declared (none for another kind).
fn route_flags(described: &Described) -> impl Iterator<Item = u32> + '_ {
    let plane = described.kind == KindCode::Plane;
    described
        .items
        .iter()
        .filter(move |(tag, _)| plane && *tag == t::D_ROUTE)
        .filter_map(|(tag, body)| Rec { tag: *tag, body }.pod_tail::<RouteRec>().ok())
        .map(|(route, _)| route.flags)
}

impl Images {
    /// Whether the admitted image `identity` is a plane that serves lines (ROUTE_LINE).
    #[must_use]
    pub fn serves_lines(&self, identity: &str) -> bool {
        self.described(identity)
            .is_some_and(|described| declares_line_route(&described))
    }

    /// Whether the admitted image `identity` is a plane serving a route over HTTP on the data
    /// listener: any route that is not ROUTE_LINE, ROUTE_RECOVERY or ROUTE_ADMIN.
    #[must_use]
    pub fn serves_http(&self, identity: &str) -> bool {
        self.described(identity)
            .is_some_and(|described| declares_http_route(&described))
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
    let mut lines: Vec<&'a str> = instances
        .into_iter()
        .filter_map(|(name, serves)| serves.then_some(name))
        .collect();
    match lines.len() {
        0 => Err(StdioRefusal::None),
        1 => Ok(lines.remove(0)),
        _ => {
            lines.sort_unstable();
            Err(StdioRefusal::Several(
                lines.into_iter().map(str::to_owned).collect(),
            ))
        }
    }
}

#[cfg(test)]
#[path = "plane_sections_tests.rs"]
mod tests;
