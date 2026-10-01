//! THE ONE WALKER. Each spec adapter answers two questions about a schema node, "what does this
//! reference resolve to" and "what does this node hold", in the neutral [`Norm`] shape. This file
//! turns that into wire paths, once, for all three spec formats.
//!
//! Path notation (ARCHITECT ruling, 2026-10-01, notation A):
//! * `a.b`: object member `b` of `a`; `a[]`: the items of array `a`; `a{}`: the values of map `a`.
//! * A tagged-union arm is its own segment, `<tagprop>=<tag>` (`messages[].content[].type=image`),
//!   and every arm is itself a path, so a new block type or stream event is a new path. The tag
//!   member is implied by the segment and is not repeated beneath it.
//! * A member-presence union (botocore) has the member name as a plain segment, marked `arm`.
//! * An untagged `anyOf`/`oneOf` (string | array) merges its alternatives in place.
//! * A named schema met again on its own path is cut there: the path gets kind `ref:<Name>`.
//! * `[]` and `{}` paths are folded into their parent's type (`array<object>`, `map<string>`), so
//!   every emitted path ends in a member or an arm.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

/// A schema node to walk: one borrowed from the document, or a reference by name/pointer that the
/// adapter resolves (a discriminator mapping target, a botocore shape, a root).
#[derive(Clone)]
pub(super) enum Handle<'a> {
    Node(&'a Value),
    Ref(String),
}

/// What one schema node holds, in format-neutral terms.
#[derive(Default)]
pub(super) struct Norm<'a> {
    pub kinds: BTreeSet<String>,
    /// Enum and const values, each as its compact JSON text (so they sort and compare as text).
    pub enums: BTreeSet<String>,
    pub props: Vec<(String, Handle<'a>)>,
    pub items: Option<Handle<'a>>,
    pub values: Option<Handle<'a>>,
    /// Walked at the SAME path: `allOf` members and the alternatives of an untagged union.
    pub alts: Vec<Handle<'a>>,
    /// `Some("type")` for an internally tagged union, `Some("")` for a member-presence union.
    pub tagprop: Option<String>,
    pub arms: Vec<(String, Handle<'a>)>,
}

pub(super) trait Adapter {
    /// Follow references to the node they name. Returns every name entered on the way (the
    /// recursion cut compares these) and the node.
    fn deref<'a>(&'a self, h: &Handle<'a>) -> Result<(Vec<String>, &'a Value), String>;
    fn norm<'a>(&'a self, v: &'a Value) -> Norm<'a>;
}

/// One emitted path.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Entry {
    pub ty: String,
    pub enums: Vec<Value>,
    pub tags: Vec<String>,
    pub tag: Option<String>,
    pub arm: bool,
}

#[derive(Default)]
struct Raw {
    kinds: BTreeSet<String>,
    enums: BTreeSet<String>,
    tags: BTreeSet<String>,
    tagprop: Option<String>,
    arm: bool,
}

fn join(path: &str, seg: &str) -> String {
    if path.is_empty() {
        seg.to_string()
    } else {
        format!("{path}.{seg}")
    }
}

fn short(name: &str) -> &str {
    name.rsplit('/').next().unwrap_or(name)
}

/// Every path under `root`. `seed` names schemas treated as already entered: the stream walk is
/// seeded with the response root, so an event that carries the whole response object (Responses'
/// `response.completed`, Anthropic's `message_start`) is cut at `ref:<Response>` rather than
/// repeating the response direction.
pub(super) fn generate(
    ad: &dyn Adapter,
    root: Handle<'_>,
    seed: &[String],
) -> Result<BTreeMap<String, Entry>, String> {
    let mut raw: BTreeMap<String, Raw> = BTreeMap::new();
    let mut stack: Vec<String> = seed.to_vec();
    walk(ad, &root, "", &mut stack, None, &mut raw)?;
    Ok(finalize(&raw))
}

fn walk<'a>(
    ad: &'a dyn Adapter,
    h: &Handle<'a>,
    path: &str,
    stack: &mut Vec<String>,
    skip: Option<&str>,
    raw: &mut BTreeMap<String, Raw>,
) -> Result<(), String> {
    let (names, v) = ad.deref(h)?;
    if let Some(n) = names.iter().find(|n| stack.contains(n)) {
        raw.entry(path.to_string())
            .or_default()
            .kinds
            .insert(format!("ref:{}", short(n)));
        return Ok(());
    }
    let depth = stack.len();
    stack.extend(names);
    let n = ad.norm(v);
    {
        let e = raw.entry(path.to_string()).or_default();
        e.kinds.extend(n.kinds.iter().cloned());
        e.enums.extend(n.enums.iter().cloned());
        if !n.arms.is_empty() {
            // Every arm of a union is an object; the site is one whatever the arms add beneath it.
            e.kinds.insert("object".to_string());
        }
    }
    for (k, c) in &n.props {
        if skip == Some(k.as_str()) {
            continue;
        }
        walk(ad, c, &join(path, k), stack, None, raw)?;
    }
    for a in &n.alts {
        walk(ad, a, path, stack, skip, raw)?;
    }
    if let Some(i) = &n.items {
        walk(ad, i, &format!("{path}[]"), stack, None, raw)?;
    }
    if let Some(m) = &n.values {
        walk(ad, m, &format!("{path}{{}}"), stack, None, raw)?;
    }
    let tagprop = n.tagprop.as_deref().filter(|t| !t.is_empty());
    for (tag, a) in &n.arms {
        {
            let e = raw.entry(path.to_string()).or_default();
            e.tags.insert(tag.clone());
            e.tagprop = n.tagprop.clone();
        }
        let ap = match tagprop {
            Some(tp) => join(path, &format!("{tp}={tag}")),
            None => join(path, tag),
        };
        raw.entry(ap.clone()).or_default().arm = true;
        walk(ad, a, &ap, stack, tagprop, raw)?;
    }
    stack.truncate(depth);
    Ok(())
}

fn render_kinds(raw: &BTreeMap<String, Raw>, p: &str) -> String {
    let Some(e) = raw.get(p) else {
        return "any".to_string();
    };
    let mut kinds = e.kinds.clone();
    let mut out: BTreeSet<String> = BTreeSet::new();
    let map = format!("{p}{{}}");
    if raw.contains_key(&map) {
        kinds.remove("object");
        out.insert(format!("map<{}>", render_kinds(raw, &map)));
    }
    let items = format!("{p}[]");
    for k in kinds {
        if k == "array" && raw.contains_key(&items) {
            out.insert(format!("array<{}>", render_kinds(raw, &items)));
        } else {
            out.insert(k);
        }
    }
    if out.is_empty() {
        "any".to_string()
    } else {
        out.into_iter().collect::<Vec<_>>().join("|")
    }
}

/// `[]`/`{}` paths fold into their parent; enums and union tags of array items surface on the
/// array (an `include` list of enum strings, a `content` list of tagged blocks).
fn finalize(raw: &BTreeMap<String, Raw>) -> BTreeMap<String, Entry> {
    let mut out = BTreeMap::new();
    for (p, e) in raw {
        if p.is_empty() || p.ends_with("[]") || p.ends_with("{}") {
            continue;
        }
        let mut enums: BTreeSet<String> = e.enums.clone();
        let mut tags: BTreeSet<String> = e.tags.clone();
        let mut tagprop = e.tagprop.clone();
        let mut q = p.clone();
        loop {
            q.push_str("[]");
            let Some(el) = raw.get(&q) else { break };
            enums.extend(el.enums.iter().cloned());
            tags.extend(el.tags.iter().cloned());
            if tagprop.is_none() {
                tagprop = el.tagprop.clone();
            }
        }
        let enums = enums
            .iter()
            .filter_map(|t| serde_json::from_str::<Value>(t).ok())
            .collect();
        out.insert(
            p.clone(),
            Entry {
                ty: render_kinds(raw, p),
                enums,
                tag: if tags.is_empty() {
                    None
                } else {
                    tagprop.filter(|t| !t.is_empty())
                },
                tags: tags.into_iter().collect(),
                arm: e.arm,
            },
        );
    }
    out
}
