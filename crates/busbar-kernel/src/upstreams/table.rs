// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The configured upstreams of one config load, read through [`Upstreams`] (IF §12.1).

use std::collections::BTreeMap;
use std::sync::Arc;

use busbar_contract::json::Map;

use super::{UpstreamDef, Upstreams};
use crate::config::min3::UpstreamCfg;
use crate::plugin_config::TrustAnchor;

/// Every `upstreams.<name>` of one config load, typed. Built once per load (a reload builds a new table); a lookup
/// is one ordered-map probe and an `Arc` clone.
#[derive(Default)]
pub struct ConfiguredUpstreams {
    by_name: BTreeMap<Box<str>, Arc<UpstreamDef>>,
}

impl ConfiguredUpstreams {
    /// A table of definitions already typed by the pure registration splitter.
    pub fn from_definitions(by_name: BTreeMap<Box<str>, Arc<UpstreamDef>>) -> Self {
        Self { by_name }
    }

    /// Types the `upstreams:` section `section` (upstream name → entry) over the `auth`/`upstream_credentials`
    /// keys the config grammar parsed (`parsed`, [`crate::config::min3::Min3Config::upstreams`]). A `parsed` name
    /// with no entry in `section` is refused: a binding needs an upstream to bind. Err = every refusal of every
    /// entry, in name order.
    pub fn from_config(
        section: &Map,
        parsed: &BTreeMap<Box<str>, UpstreamCfg>,
        anchor: &dyn Fn(&str) -> Result<Arc<TrustAnchor>, String>,
    ) -> Result<Self, Vec<String>> {
        let unbound = UpstreamCfg::default();
        let mut by_name = BTreeMap::new();
        let mut refused = Vec::new();
        for (name, entry) in section {
            let cfg = parsed.get(name).unwrap_or(&unbound);
            match UpstreamDef::from_config(name, entry, cfg, anchor) {
                Ok(def) => {
                    by_name.insert(Box::<str>::from(name), Arc::new(def));
                }
                Err(mut why) => refused.append(&mut why),
            }
        }
        for name in parsed.keys() {
            if !section.contains_key(&name.as_ref()) {
                refused.push(format!(
                    "`upstreams.{name}`: `auth` or `upstream_credentials` is set for an upstream with no `url:` \
                     or `command:`"
                ));
            }
        }
        if refused.is_empty() {
            Ok(Self { by_name })
        } else {
            Err(refused)
        }
    }

    /// The configured upstream names, in order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.by_name.keys().map(|name| &**name)
    }

    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }
}

impl Upstreams for ConfiguredUpstreams {
    fn get(&self, name: &str) -> Option<Arc<UpstreamDef>> {
        self.by_name.get(name).cloned()
    }
}

/// A shared table answers as the table: consumers hold `Arc<ConfiguredUpstreams>` (or `Arc<dyn Upstreams>`).
impl<U: Upstreams + ?Sized> Upstreams for Arc<U> {
    fn get(&self, name: &str) -> Option<Arc<UpstreamDef>> {
        (**self).get(name)
    }
}
