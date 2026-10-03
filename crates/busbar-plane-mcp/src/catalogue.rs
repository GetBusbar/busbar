// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CATALOGUE THE DOOR ANSWERS FROM: every capability the operator's `tools:` section
//! registers, built once per generation from the section that generation's snapshot was published
//! over. An approval is a change to the section, so it is visible from the generation that carries
//! it and from no earlier one.
//!
//! Pure. What a caller may see is not judged in this module: each listing asks an `admit`
//! predicate, once per grant, with the two grants every capability needs (the server first, then
//! the capability's published name). The door binds the predicate to the kernel's entitlement
//! service; a test binds it to a table. The rendering is the served engine's, member for member,
//! and every cacheable result carries the same two caching hints.
//!
//! The catalogue LISTS what it will not dispatch: a tool with no approved hash is listed, so an
//! operator can see what is waiting. Only a tool whose live sighting is quarantined is hidden, and
//! that verdict is a second predicate, asked after the grants and never in place of them.

use std::collections::BTreeMap;

use serde_json::{json, Map, Value};

use crate::config::{namespaced, AskRoundCfg, PromptMessageCfg, ToolsCfg};
use crate::door::{SCOPE, SCOPE_TOOL};
use crate::jsonrpc::RESULT_TYPE_COMPLETE;
use crate::sanitize::normalise_opt;

/// The caching scope every cacheable result names: a result is scoped to its caller's grant.
pub const CACHE_SCOPE: &str = "private";

/// The caching lifetime every cacheable result names: none, as an approval can move at any time.
pub const CACHE_TTL_MS: i64 = 0;

/// One listed tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolEntry {
    /// The registered server id.
    pub server: String,
    /// The tool's name as the upstream spells it.
    pub tool: String,
    /// The published name: `publish_as`, else `{server}_{tool}`.
    pub namespaced: String,
    /// The approved schema hash; a blank one is none.
    pub schema_hash: Option<String>,
    description: Option<String>,
    input_schema: Option<Value>,
    output_schema: Option<Value>,
}

/// One listed prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromptEntry {
    /// The registered server id.
    pub server: String,
    /// The prompt's name as the operator wrote it.
    pub name: String,
    /// `{server}_{name}`.
    pub namespaced: String,
    pub(crate) description: Option<String>,
    pub(crate) template: Option<String>,
    pub(crate) messages: Vec<PromptMessageCfg>,
    /// The rounds of input asked of the caller before this prompt renders; empty = none.
    pub ask_caller: Vec<AskRoundCfg>,
}

/// One listed resource.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceEntry {
    /// The registered server id.
    pub server: String,
    /// The resource's own uri, which is what a caller reads it by.
    pub uri: String,
    /// `{server}_{uri}`: the grant value.
    pub namespaced: String,
    name: Option<String>,
    description: Option<String>,
    pub(crate) mime_type: Option<String>,
    pub(crate) text: Option<String>,
    pub(crate) blob: Option<String>,
}

/// One listed resource template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceTemplateEntry {
    /// The registered server id.
    pub server: String,
    /// The template as the operator wrote it.
    pub uri_template: String,
    /// `{server}_{uri_template}`: the grant value.
    pub namespaced: String,
    name: Option<String>,
    description: Option<String>,
    pub(crate) mime_type: Option<String>,
    pub(crate) text: Option<String>,
}

/// ONE GENERATION'S CATALOGUE. Built whole from one section and never changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Catalogue {
    generation: u64,
    servers: Vec<String>,
    tools: BTreeMap<String, ToolEntry>,
    prompts: BTreeMap<String, PromptEntry>,
    resources: BTreeMap<String, ResourceEntry>,
    resource_templates: BTreeMap<String, ResourceTemplateEntry>,
}

/// Which approval an address names, after the caller's grants narrowed the field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup<T> {
    /// Exactly one.
    One(T),
    /// None, or none the caller may see: one answer for both.
    NotFound,
    /// More than one the caller may see, named and sorted.
    Ambiguous(Vec<String>),
}

/// MATCH one level-1 uri template against a concrete uri. A binding is non-empty and holds no `/`,
/// so one template approves one shape and never a subtree.
#[must_use]
pub fn match_uri_template(template: &str, uri: &str) -> Option<BTreeMap<String, String>> {
    let mut bindings = BTreeMap::new();
    let mut t = template;
    let mut u = uri;
    loop {
        let Some(open) = t.find('{') else {
            return (t == u).then_some(bindings);
        };
        let literal = &t[..open];
        u = u.strip_prefix(literal)?;
        let after = &t[open + 1..];
        let close = after.find('}')?;
        let name = &after[..close];
        t = &after[close + 1..];
        let stop = &t[..t.find('{').unwrap_or(t.len())];
        let value = if stop.is_empty() {
            std::mem::take(&mut u)
        } else {
            let at = u.find(stop)?;
            let (v, rest) = u.split_at(at);
            u = rest;
            v
        };
        if value.is_empty() || value.contains('/') {
            return None;
        }
        bindings.insert(name.to_string(), value.to_string());
    }
}

/// A blank hash is no hash.
fn approved_hash(raw: Option<&str>) -> Option<String> {
    raw.map(str::trim)
        .filter(|h| !h.is_empty())
        .map(str::to_string)
}

/// Both grants a capability needs: the server first, then the capability.
fn granted(admit: &impl Fn(&str, &str) -> bool, server: &str, namespaced: &str) -> bool {
    admit(SCOPE, server) && admit(SCOPE_TOOL, namespaced)
}

/// A cacheable result with its two hints.
fn cache_hints(mut value: Value) -> Value {
    if let Some(obj) = value.as_object_mut() {
        obj.insert("cacheScope".into(), CACHE_SCOPE.into());
        obj.insert("ttlMs".into(), CACHE_TTL_MS.into());
    }
    value
}

/// A successful answer: the result stamped `complete`, the id echoed.
#[must_use]
pub fn complete(id: &Value, mut value: Value) -> Vec<u8> {
    if let Some(obj) = value.as_object_mut() {
        obj.insert("resultType".into(), RESULT_TYPE_COMPLETE.into());
    }
    let mut envelope = Map::new();
    envelope.insert("jsonrpc".into(), "2.0".into());
    envelope.insert("id".into(), id.clone());
    envelope.insert("result".into(), value);
    serde_json::to_vec(&Value::Object(envelope)).unwrap_or_default()
}

impl Catalogue {
    /// BUILD one generation's catalogue from the section it was published over.
    #[must_use]
    pub fn build(generation: u64, cfg: &ToolsCfg) -> Self {
        let mut catalogue = Catalogue {
            generation,
            servers: cfg.servers.keys().cloned().collect(),
            tools: BTreeMap::new(),
            prompts: BTreeMap::new(),
            resources: BTreeMap::new(),
            resource_templates: BTreeMap::new(),
        };
        for (id, def) in &cfg.servers {
            for (tool, allow) in &def.tools_allow {
                let published = allow
                    .publish_as
                    .clone()
                    .unwrap_or_else(|| namespaced(id, tool));
                catalogue.tools.insert(
                    published.clone(),
                    ToolEntry {
                        server: id.clone(),
                        tool: tool.clone(),
                        namespaced: published,
                        schema_hash: approved_hash(allow.schema_hash.as_deref()),
                        description: allow.description.clone(),
                        input_schema: allow.input_schema.clone(),
                        output_schema: allow.output_schema.clone(),
                    },
                );
            }
            for (name, allow) in &def.prompts_allow {
                let key = namespaced(id, name);
                catalogue.prompts.insert(
                    key.clone(),
                    PromptEntry {
                        server: id.clone(),
                        name: name.clone(),
                        namespaced: key,
                        description: allow.description.clone(),
                        template: allow.template.clone(),
                        messages: allow.messages.clone(),
                        ask_caller: allow.ask_caller.clone(),
                    },
                );
            }
            for (uri, allow) in &def.resources_allow {
                let key = namespaced(id, uri);
                catalogue.resources.insert(
                    key.clone(),
                    ResourceEntry {
                        server: id.clone(),
                        uri: uri.clone(),
                        namespaced: key,
                        name: allow.name.clone(),
                        description: allow.description.clone(),
                        mime_type: allow.mime_type.clone(),
                        text: allow.text.clone(),
                        blob: allow.blob.clone(),
                    },
                );
            }
            for (template, allow) in &def.resource_templates_allow {
                let key = namespaced(id, template);
                catalogue.resource_templates.insert(
                    key.clone(),
                    ResourceTemplateEntry {
                        server: id.clone(),
                        uri_template: template.clone(),
                        namespaced: key,
                        name: allow.name.clone(),
                        description: allow.description.clone(),
                        mime_type: allow.mime_type.clone(),
                        text: allow.text.clone(),
                    },
                );
            }
        }
        catalogue
    }

    /// The generation this catalogue was built for.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Whether the section registers no server at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.servers.is_empty()
    }

    /// The entry a published tool name names, whoever asks.
    #[must_use]
    pub fn tool(&self, published: &str) -> Option<&ToolEntry> {
        self.tools.get(published)
    }

    /// The tools this caller may see, in published-name order.
    pub fn tools_for(&self, admit: &impl Fn(&str, &str) -> bool) -> Vec<&ToolEntry> {
        self.tools
            .values()
            .filter(|t| granted(admit, &t.server, &t.namespaced))
            .collect()
    }

    /// The prompts this caller may see.
    pub fn prompts_for(&self, admit: &impl Fn(&str, &str) -> bool) -> Vec<&PromptEntry> {
        self.prompts
            .values()
            .filter(|p| granted(admit, &p.server, &p.namespaced))
            .collect()
    }

    /// The resources this caller may see.
    pub fn resources_for(&self, admit: &impl Fn(&str, &str) -> bool) -> Vec<&ResourceEntry> {
        self.resources
            .values()
            .filter(|r| granted(admit, &r.server, &r.namespaced))
            .collect()
    }

    /// The resource templates this caller may see.
    pub fn resource_templates_for(
        &self,
        admit: &impl Fn(&str, &str) -> bool,
    ) -> Vec<&ResourceTemplateEntry> {
        self.resource_templates
            .values()
            .filter(|t| granted(admit, &t.server, &t.namespaced))
            .collect()
    }

    /// The prompt a published name names, under the caller's grants. `None` covers no such prompt
    /// and not the caller's alike, so the answer leaks nothing about what the grant hides.
    pub fn prompt_for(
        &self,
        admit: &impl Fn(&str, &str) -> bool,
        published: &str,
    ) -> Option<&PromptEntry> {
        self.prompts
            .get(published)
            .filter(|p| granted(admit, &p.server, &p.namespaced))
    }

    /// The resource a caller's uri names, among those its grants reach. Two reachable approvals of
    /// one uri are named, sorted by server, never picked between.
    pub fn resource_by_uri(
        &self,
        admit: &impl Fn(&str, &str) -> bool,
        uri: &str,
    ) -> Lookup<&ResourceEntry> {
        let mut found: Vec<&ResourceEntry> = self
            .resources_for(admit)
            .into_iter()
            .filter(|r| r.uri == uri)
            .collect();
        match found.len() {
            0 => Lookup::NotFound,
            1 => Lookup::One(found.remove(0)),
            _ => {
                let mut servers: Vec<String> = found.iter().map(|r| r.server.clone()).collect();
                servers.sort();
                Lookup::Ambiguous(servers)
            }
        }
    }

    /// The template a caller's expanded uri matches, among those its grants reach, with its
    /// bindings. Two matches are named by their namespaced approvals, sorted, never picked between.
    pub fn resource_template_for(
        &self,
        admit: &impl Fn(&str, &str) -> bool,
        uri: &str,
    ) -> Lookup<(&ResourceTemplateEntry, BTreeMap<String, String>)> {
        let mut found: Vec<(&ResourceTemplateEntry, BTreeMap<String, String>)> = self
            .resource_templates_for(admit)
            .into_iter()
            .filter_map(|t| match_uri_template(&t.uri_template, uri).map(|b| (t, b)))
            .collect();
        match found.len() {
            0 => Lookup::NotFound,
            1 => Lookup::One(found.remove(0)),
            _ => {
                let mut names: Vec<String> =
                    found.iter().map(|(t, _)| t.namespaced.clone()).collect();
                names.sort();
                Lookup::Ambiguous(names)
            }
        }
    }

    /// `tools/list`: the caller's tools, minus any whose live sighting is quarantined.
    pub fn tools_list(
        &self,
        id: &Value,
        admit: &impl Fn(&str, &str) -> bool,
        quarantined: impl Fn(&ToolEntry) -> bool,
    ) -> Vec<u8> {
        let tools: Vec<Value> = self
            .tools_for(admit)
            .into_iter()
            .filter(|t| !quarantined(t))
            .map(ToolEntry::render)
            .collect();
        complete(id, cache_hints(json!({ "tools": tools })))
    }

    /// `prompts/list`.
    pub fn prompts_list(&self, id: &Value, admit: &impl Fn(&str, &str) -> bool) -> Vec<u8> {
        let prompts: Vec<Value> = self
            .prompts_for(admit)
            .into_iter()
            .map(PromptEntry::render)
            .collect();
        complete(id, cache_hints(json!({ "prompts": prompts })))
    }

    /// `resources/list`.
    pub fn resources_list(&self, id: &Value, admit: &impl Fn(&str, &str) -> bool) -> Vec<u8> {
        let resources: Vec<Value> = self
            .resources_for(admit)
            .into_iter()
            .map(ResourceEntry::render)
            .collect();
        complete(id, cache_hints(json!({ "resources": resources })))
    }

    /// `resources/templates/list`: the empty list for a caller who reaches none.
    pub fn resource_templates_list(
        &self,
        id: &Value,
        admit: &impl Fn(&str, &str) -> bool,
    ) -> Vec<u8> {
        let templates: Vec<Value> = self
            .resource_templates_for(admit)
            .into_iter()
            .map(ResourceTemplateEntry::render)
            .collect();
        complete(id, cache_hints(json!({ "resourceTemplates": templates })))
    }
}

impl ToolEntry {
    /// The entry as `tools/list` writes it.
    #[must_use]
    pub fn render(&self) -> Value {
        let mut obj = Map::new();
        obj.insert("name".into(), self.namespaced.clone().into());
        if let Some(d) = normalise_opt(self.description.as_deref()) {
            obj.insert("description".into(), d.into());
        }
        obj.insert(
            "inputSchema".into(),
            self.input_schema
                .clone()
                .unwrap_or_else(|| json!({ "type": "object" })),
        );
        if let Some(s) = &self.output_schema {
            obj.insert("outputSchema".into(), s.clone());
        }
        if let Some(h) = &self.schema_hash {
            obj.insert("_meta".into(), json!({ "io.busbar/schemaHash": h }));
        }
        Value::Object(obj)
    }
}

impl PromptEntry {
    /// The entry as `prompts/list` writes it.
    #[must_use]
    pub fn render(&self) -> Value {
        let mut obj = Map::new();
        obj.insert("name".into(), self.namespaced.clone().into());
        if let Some(d) = normalise_opt(self.description.as_deref()) {
            obj.insert("description".into(), d.into());
        }
        Value::Object(obj)
    }
}

impl ResourceEntry {
    /// The entry as `resources/list` writes it: the resource's own uri.
    #[must_use]
    pub fn render(&self) -> Value {
        let mut obj = Map::new();
        obj.insert("uri".into(), self.uri.clone().into());
        if let Some(n) = normalise_opt(self.name.as_deref()) {
            obj.insert("name".into(), n.into());
        }
        if let Some(d) = normalise_opt(self.description.as_deref()) {
            obj.insert("description".into(), d.into());
        }
        if let Some(m) = &self.mime_type {
            obj.insert("mimeType".into(), m.clone().into());
        }
        Value::Object(obj)
    }
}

impl ResourceTemplateEntry {
    /// The entry as `resources/templates/list` writes it: the operator's own template.
    #[must_use]
    pub fn render(&self) -> Value {
        let mut obj = Map::new();
        obj.insert("uriTemplate".into(), self.uri_template.clone().into());
        if let Some(n) = normalise_opt(self.name.as_deref()) {
            obj.insert("name".into(), n.into());
        }
        if let Some(d) = normalise_opt(self.description.as_deref()) {
            obj.insert("description".into(), d.into());
        }
        if let Some(m) = &self.mime_type {
            obj.insert("mimeType".into(), m.clone().into());
        }
        Value::Object(obj)
    }
}

#[cfg(test)]
#[path = "tests/catalogue.rs"]
mod tests;
