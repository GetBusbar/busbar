// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The configured upstreams of one config load, read through [`Upstreams`] (IF §12.1).

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::{Map, Value};

use super::{UpstreamDef, Upstreams};
use crate::config::min3::UpstreamCfg;
use crate::plugin_config::TrustAnchor;

/// Every `upstreams.<name>` of one config load, typed.
#[derive(Default)]
pub struct ConfiguredUpstreams {
    by_name: BTreeMap<Box<str>, Arc<UpstreamDef>>,
}

impl ConfiguredUpstreams {
    /// Types the `upstreams:` section over the keys the config grammar parsed.
    pub fn from_config(
        section: &Map<String, Value>,
        parsed: &BTreeMap<Box<str>, UpstreamCfg>,
        anchor: &dyn Fn(&str) -> Result<Arc<TrustAnchor>, String>,
    ) -> Result<Self, Vec<String>> {
        let _ = (section, parsed, anchor);
        todo!("W1-K1")
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
        let _ = name;
        todo!("W1-K1")
    }
}

impl<U: Upstreams + ?Sized> Upstreams for Arc<U> {
    fn get(&self, name: &str) -> Option<Arc<UpstreamDef>> {
        (**self).get(name)
    }
}
