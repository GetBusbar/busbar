//! THE THREE SPEC ADAPTERS: OpenAPI 3.1 (openai, anthropic, cohere), Google Discovery (gemini) and
//! botocore (bedrock-runtime). Each one only translates its format's vocabulary into [`Norm`]; the
//! paths come from the one walker in `walk.rs`.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use super::walk::{Adapter, Handle, Norm};

/// The longest chain of `$ref` hops followed before a document is called malformed.
const MAX_HOPS: usize = 64;

fn json_text(v: &Value) -> String {
    serde_json::to_string(v).unwrap_or_default()
}

// ── OpenAPI 3.1 ──────────────────────────────────────────────────────────────────────────────────

pub(super) struct OpenApi<'d> {
    pub doc: &'d Value,
}

impl OpenApi<'_> {
    fn pointer(&self, r: &str) -> Result<&Value, String> {
        r.strip_prefix('#')
            .and_then(|p| self.doc.pointer(p))
            .ok_or_else(|| format!("unresolvable $ref `{r}`"))
    }

    /// Every property a node declares, through `allOf`; the node's own win over inherited ones.
    fn props_of<'a>(&'a self, h: &Handle<'a>, depth: usize) -> BTreeMap<String, &'a Value> {
        let mut out = BTreeMap::new();
        let Ok((_, v)) = self.deref(h) else {
            return out;
        };
        if depth > 16 {
            return out;
        }
        if let Some(all) = v.get("allOf").and_then(Value::as_array) {
            for m in all {
                out.extend(self.props_of(&Handle::Node(m), depth + 1));
            }
        }
        if let Some(p) = v.get("properties").and_then(Value::as_object) {
            for (k, s) in p {
                out.insert(k.clone(), s);
            }
        }
        out
    }

    /// The single constant a union arm holds in its tag member, if it holds one.
    fn tag_value(&self, h: &Handle<'_>, tagprop: &str) -> Option<String> {
        let props = self.props_of(h, 0);
        let p = *props.get(tagprop)?;
        let (_, p) = self.deref(&Handle::Node(p)).ok()?;
        if let Some(c) = p.get("const").and_then(Value::as_str) {
            return Some(c.to_string());
        }
        match p.get("enum").and_then(Value::as_array).map(Vec::as_slice) {
            Some([one]) => one.as_str().map(str::to_string),
            _ => None,
        }
    }
}

impl Adapter for OpenApi<'_> {
    fn deref<'a>(&'a self, h: &Handle<'a>) -> Result<(Vec<String>, &'a Value), String> {
        let mut names = Vec::new();
        let mut v = match h {
            Handle::Node(v) => *v,
            Handle::Ref(r) => {
                names.push(r.clone());
                self.pointer(r)?
            }
        };
        while let Some(r) = v.get("$ref").and_then(Value::as_str) {
            if names.len() > MAX_HOPS {
                return Err(format!("$ref chain longer than {MAX_HOPS} hops at `{r}`"));
            }
            names.push(r.to_string());
            v = self.pointer(r)?;
        }
        Ok((names, v))
    }

    fn norm<'a>(&'a self, v: &'a Value) -> Norm<'a> {
        let mut n = Norm::default();
        let Some(o) = v.as_object() else {
            return n;
        };
        match o.get("type") {
            Some(Value::String(t)) => {
                n.kinds.insert(t.clone());
            }
            Some(Value::Array(ts)) => {
                n.kinds
                    .extend(ts.iter().filter_map(Value::as_str).map(str::to_string));
            }
            _ => {}
        }
        if o.get("nullable") == Some(&Value::Bool(true)) {
            n.kinds.insert("null".to_string());
        }
        let consts = o.get("const").into_iter();
        for e in o
            .get("enum")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .chain(consts)
        {
            if e.is_null() {
                n.kinds.insert("null".to_string());
            } else {
                n.enums.insert(json_text(e));
            }
        }
        if let Some(p) = o.get("properties").and_then(Value::as_object) {
            if n.kinds.is_empty() {
                n.kinds.insert("object".to_string());
            }
            n.props = p.iter().map(|(k, s)| (k.clone(), Handle::Node(s))).collect();
        }
        if let Some(it) = o.get("items").filter(|i| i.is_object()) {
            if n.kinds.is_empty() {
                n.kinds.insert("array".to_string());
            }
            n.items = Some(Handle::Node(it));
        }
        if let Some(ap) = o
            .get("additionalProperties")
            .filter(|a| a.as_object().is_some_and(|m| !m.is_empty()))
        {
            n.values = Some(Handle::Node(ap));
        }
        n.alts = o
            .get("allOf")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(Handle::Node)
            .collect();

        let members: Vec<&Value> = ["oneOf", "anyOf"]
            .iter()
            .filter_map(|k| o.get(*k).and_then(Value::as_array))
            .flatten()
            .collect();
        let disc = o.get("discriminator").filter(|d| d.is_object());
        let tagprop = disc
            .and_then(|d| d.get("propertyName"))
            .and_then(Value::as_str)
            .unwrap_or("type")
            .to_string();
        // A discriminator mapping NAMES the arms, including ones the oneOf list omits (Cohere's
        // stream union maps citation-start/end to schemas outside its oneOf).
        let mapping: Vec<(String, String)> = disc
            .and_then(|d| d.get("mapping"))
            .and_then(Value::as_object)
            .map(|m| {
                m.iter()
                    .filter_map(|(k, t)| t.as_str().map(|t| (k.clone(), t.to_string())))
                    .collect()
            })
            .unwrap_or_default();
        let mapped: BTreeSet<&str> = mapping.iter().map(|(_, t)| t.as_str()).collect();
        let members: Vec<&Value> = members
            .into_iter()
            .filter(|m| {
                !m.get("$ref")
                    .and_then(Value::as_str)
                    .is_some_and(|r| mapped.contains(r))
            })
            .collect();
        let mut tagged: Vec<(String, Handle<'a>)> = mapping
            .iter()
            .map(|(k, t)| (k.clone(), Handle::Ref(t.clone())))
            .collect();
        let mut untagged: Vec<Handle<'a>> = Vec::new();
        for m in &members {
            match self.tag_value(&Handle::Node(*m), &tagprop) {
                Some(t) => tagged.push((t, Handle::Node(*m))),
                None => untagged.push(Handle::Node(*m)),
            }
        }
        if !tagged.is_empty() && (disc.is_some() || tagged.len() >= 2) {
            n.tagprop = Some(tagprop);
            n.arms = tagged;
            n.alts.extend(untagged);
        } else {
            n.alts.extend(members.into_iter().map(Handle::Node));
        }
        n
    }
}

// ── Google Discovery ─────────────────────────────────────────────────────────────────────────────

pub(super) struct Discovery<'d> {
    pub doc: &'d Value,
}

impl Discovery<'_> {
    fn schema(&self, name: &str) -> Result<&Value, String> {
        self.doc
            .get("schemas")
            .and_then(|s| s.get(name))
            .ok_or_else(|| format!("discovery document has no schema `{name}`"))
    }
}

impl Adapter for Discovery<'_> {
    fn deref<'a>(&'a self, h: &Handle<'a>) -> Result<(Vec<String>, &'a Value), String> {
        let mut names = Vec::new();
        let mut v = match h {
            Handle::Node(v) => *v,
            Handle::Ref(r) => {
                names.push(r.clone());
                self.schema(r)?
            }
        };
        while let Some(r) = v.get("$ref").and_then(Value::as_str) {
            if names.len() > MAX_HOPS {
                return Err(format!("$ref chain longer than {MAX_HOPS} hops at `{r}`"));
            }
            names.push(r.to_string());
            v = self.schema(r)?;
        }
        Ok((names, v))
    }

    fn norm<'a>(&'a self, v: &'a Value) -> Norm<'a> {
        let mut n = Norm::default();
        if let Some(t) = v.get("type").and_then(Value::as_str) {
            n.kinds.insert(t.to_string());
        }
        for e in v.get("enum").and_then(Value::as_array).into_iter().flatten() {
            n.enums.insert(json_text(e));
        }
        if let Some(p) = v.get("properties").and_then(Value::as_object) {
            if n.kinds.is_empty() {
                n.kinds.insert("object".to_string());
            }
            n.props = p.iter().map(|(k, s)| (k.clone(), Handle::Node(s))).collect();
        }
        if let Some(it) = v.get("items").filter(|i| i.is_object()) {
            n.items = Some(Handle::Node(it));
        }
        if let Some(ap) = v
            .get("additionalProperties")
            .filter(|a| a.as_object().is_some_and(|m| !m.is_empty()))
        {
            n.values = Some(Handle::Node(ap));
        }
        n
    }
}

// ── botocore ─────────────────────────────────────────────────────────────────────────────────────

pub(super) struct Botocore<'d> {
    pub doc: &'d Value,
}

/// botocore scalar shape types, in the walker's kind words. Shapes not listed keep their own name
/// (`string`, `boolean`, `blob`, `timestamp`, `document`).
const BOTO_KINDS: [(&str, &str); 4] = [
    ("integer", "integer"),
    ("long", "integer"),
    ("float", "number"),
    ("double", "number"),
];

impl Adapter for Botocore<'_> {
    fn deref<'a>(&'a self, h: &Handle<'a>) -> Result<(Vec<String>, &'a Value), String> {
        let name = match h {
            Handle::Ref(r) => r.clone(),
            Handle::Node(v) => v
                .get("shape")
                .and_then(Value::as_str)
                .ok_or_else(|| "botocore member names no shape".to_string())?
                .to_string(),
        };
        let v = self
            .doc
            .get("shapes")
            .and_then(|s| s.get(&name))
            .ok_or_else(|| format!("botocore model has no shape `{name}`"))?;
        Ok((vec![name], v))
    }

    fn norm<'a>(&'a self, v: &'a Value) -> Norm<'a> {
        let mut n = Norm::default();
        let t = v.get("type").and_then(Value::as_str).unwrap_or("any");
        match t {
            "structure" => {
                n.kinds.insert("object".to_string());
                // A member with a `location` (uri, header, querystring) is not in the JSON body.
                let members: Vec<(String, Handle<'a>)> = v
                    .get("members")
                    .and_then(Value::as_object)
                    .into_iter()
                    .flatten()
                    .filter(|(_, m)| m.get("location").is_none())
                    .map(|(k, m)| (k.clone(), Handle::Node(m)))
                    .collect();
                let union = v.get("union") == Some(&Value::Bool(true))
                    || v.get("eventstream") == Some(&Value::Bool(true));
                if union {
                    n.tagprop = Some(String::new());
                    n.arms = members;
                } else {
                    n.props = members;
                }
            }
            "list" => {
                n.kinds.insert("array".to_string());
                n.items = v.get("member").map(Handle::Node);
            }
            "map" => {
                n.kinds.insert("object".to_string());
                n.values = v.get("value").map(Handle::Node);
            }
            other => {
                let kind = BOTO_KINDS
                    .iter()
                    .find(|(b, _)| *b == other)
                    .map_or(other, |(_, k)| *k);
                n.kinds.insert(kind.to_string());
                for e in v.get("enum").and_then(Value::as_array).into_iter().flatten() {
                    n.enums.insert(json_text(e));
                }
            }
        }
        n
    }
}
