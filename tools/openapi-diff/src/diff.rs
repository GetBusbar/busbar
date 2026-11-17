// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Every breaking change a head OpenAPI document makes to what a base document promised.
//!
//! Additive-only (ADMIN-API-1.6 r5 section 0.1): new paths, operations, statuses, optional request
//! fields, response fields and enum values are allowed. These fail: a removed path, operation,
//! `operationId`, response status, parameter or property; a request property or parameter made
//! required; a response property no longer guaranteed; an enum value removed; a type narrowed; a
//! raised `x-busbar-required-scope`. Schemas are compared through `$ref` (once per pair, so a
//! recursive schema terminates); `allOf`, `anyOf` and `oneOf` are compared branch by branch.

use std::collections::BTreeSet;

use busbar_contract::json::{self, JsonContainerTrait, JsonValueTrait};

const METHODS: [&str; 6] = ["get", "put", "post", "delete", "patch", "head"];
const SCHEMA_REF: &str = "#/components/schemas/";

/// Which way a schema is used: a request must still accept what it accepted, a response must still
/// promise what it promised.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Direction {
    Request,
    Response,
}

/// Every breaking change `head` makes to what `base` promised; empty when `head` is additive.
pub(crate) fn breaking_changes(base: &json::Value, head: &json::Value) -> Vec<String> {
    let mut walk = Walk {
        base,
        head,
        seen: BTreeSet::new(),
        out: Vec::new(),
    };
    walk.paths();
    walk.out.sort();
    walk.out.dedup();
    walk.out
}

struct Walk<'a> {
    base: &json::Value,
    head: &json::Value,
    seen: BTreeSet<(String, String, bool)>,
    out: Vec<String>,
}

fn scope_rank(scope: &str) -> u8 {
    match scope {
        "read-only" => 0,
        _ => 1,
    }
}

fn strings(value: &json::Value) -> BTreeSet<String> {
    match (value.as_str(), value.as_array()) {
        (Some(one), _) => BTreeSet::from([one.to_owned()]),
        (None, Some(items)) => items
            .into_iter()
            .filter_map(|item| item.as_str().map(str::to_owned))
            .collect(),
        _ => BTreeSet::new(),
    }
}

fn text(value: &json::Value) -> String {
    json::to_string_pretty(value).unwrap_or_default()
}

impl<'a> Walk<'a> {
    fn paths(&mut self) {
        let Some(paths) = self.base.get("paths").and_then(|paths| paths.as_object()) else {
            return;
        };
        for (path, item) in paths.iter() {
            let Some(new_item) = self.head.get("paths").and_then(|paths| paths.get(path)) else {
                self.out.push(format!("{path}: path removed"));
                continue;
            };
            for method in METHODS {
                let Some(old) = item.get(method) else {
                    continue;
                };
                let at = format!("{method} {path}");
                match new_item.get(method) {
                    Some(new) => self.operation(&at, old, new),
                    None => self.out.push(format!("{at}: operation removed")),
                }
            }
        }
    }

    fn operation(&mut self, at: &str, old: &json::Value, new: &json::Value) {
        if let (Some(was), Some(now)) = (
            old.get("operationId").and_then(|v| v.as_str()),
            new.get("operationId").and_then(|v| v.as_str()),
        ) {
            if was != now {
                self.out
                    .push(format!("{at}: operationId changed from {was} to {now}"));
            }
        }
        if let (Some(was), Some(now)) = (
            old.get("x-busbar-required-scope").and_then(|v| v.as_str()),
            new.get("x-busbar-required-scope").and_then(|v| v.as_str()),
        ) {
            if scope_rank(now) > scope_rank(was) {
                self.out
                    .push(format!("{at}: required scope raised from {was} to {now}"));
            }
        }
        self.parameters(at, old, new);
        self.request_body(at, old, new);
        self.responses(at, old, new);
    }

    fn parameters(&mut self, at: &str, old: &json::Value, new: &json::Value) {
        let key = |p: &json::Value| {
            (
                p.get("in")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned(),
                p.get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned(),
            )
        };
        let required = |p: &json::Value| p.get("required").and_then(|v| v.as_bool()) == Some(true);
        let news: Vec<&json::Value> = new
            .get("parameters")
            .and_then(|v| v.as_array())
            .map(|items| items.into_iter().collect())
            .unwrap_or_default();
        let olds: Vec<&json::Value> = old
            .get("parameters")
            .and_then(|v| v.as_array())
            .map(|items| items.into_iter().collect())
            .unwrap_or_default();
        for was in &olds {
            let (place, name) = key(was);
            match news
                .iter()
                .find(|now| key(now) == (place.clone(), name.clone()))
            {
                None => self
                    .out
                    .push(format!("{at}: parameter {name} ({place}) removed")),
                Some(now) => {
                    if required(now) && !required(was) {
                        self.out
                            .push(format!("{at}: parameter {name} became required"));
                    }
                    if let (Some(a), Some(b)) = (was.get("schema"), now.get("schema")) {
                        self.schema(&format!("{at}: parameter {name}"), a, b, Direction::Request);
                    }
                }
            }
        }
        for now in &news {
            let (place, name) = key(now);
            if required(now)
                && !olds
                    .iter()
                    .any(|was| key(was) == (place.clone(), name.clone()))
            {
                self.out
                    .push(format!("{at}: new parameter {name} is required"));
            }
        }
    }

    fn request_body(&mut self, at: &str, old: &json::Value, new: &json::Value) {
        let (Some(was), Some(now)) = (old.get("requestBody"), new.get("requestBody")) else {
            return;
        };
        let required = |b: &json::Value| b.get("required").and_then(|v| v.as_bool()) == Some(true);
        if required(now) && !required(was) {
            self.out.push(format!("{at}: request body became required"));
        }
        self.content(&format!("{at}: request body"), was, now, Direction::Request);
    }

    fn responses(&mut self, at: &str, old: &json::Value, new: &json::Value) {
        let Some(old) = old.get("responses").and_then(|v| v.as_object()) else {
            return;
        };
        for (status, was) in old.iter() {
            match new.get("responses").and_then(|r| r.get(status)) {
                None => self.out.push(format!("{at}: response {status} removed")),
                Some(now) => {
                    self.content(
                        &format!("{at}: response {status}"),
                        was,
                        now,
                        Direction::Response,
                    );
                }
            }
        }
    }

    fn content(&mut self, at: &str, old: &json::Value, new: &json::Value, dir: Direction) {
        let Some(media) = old.get("content").and_then(|v| v.as_object()) else {
            return;
        };
        for (kind, was) in media.iter() {
            match new.get("content").and_then(|c| c.get(kind)) {
                None => self.out.push(format!("{at}: media type {kind} removed")),
                Some(now) => {
                    if let (Some(a), Some(b)) = (was.get("schema"), now.get("schema")) {
                        self.schema(at, a, b, dir);
                    }
                }
            }
        }
    }

    /// The named schema a `$ref` points at, or the node itself.
    fn resolve<'v>(
        doc: &'v json::Value,
        node: &'v json::Value,
    ) -> (&'v json::Value, Option<String>) {
        match node.get("$ref").and_then(|v| v.as_str()) {
            Some(reference) => match reference.strip_prefix(SCHEMA_REF) {
                Some(name) => (
                    doc.get("components")
                        .and_then(|c| c.get("schemas"))
                        .and_then(|s| s.get(name))
                        .unwrap_or(node),
                    Some(name.to_owned()),
                ),
                None => (node, None),
            },
            None => (node, None),
        }
    }

    fn schema(&mut self, at: &str, old: &json::Value, new: &json::Value, dir: Direction) {
        let (base, head) = (self.base, self.head);
        let ((old, old_name), (new, new_name)) =
            (Self::resolve(base, old), Self::resolve(head, new));
        if let (Some(a), Some(b)) = (old_name, new_name) {
            if !self.seen.insert((a, b, dir == Direction::Request)) {
                return;
            }
        }
        let (was, now) = (strings(&old["type"]), strings(&new["type"]));
        if !was.is_empty() && !now.is_empty() && !was.is_subset(&now) {
            self.out.push(format!(
                "{at}: type changed from {} to {}",
                was.iter().cloned().collect::<Vec<_>>().join("|"),
                now.iter().cloned().collect::<Vec<_>>().join("|")
            ));
        }
        if let (Some(was), Some(now)) = (
            old.get("enum").and_then(|v| v.as_array()),
            new.get("enum").and_then(|v| v.as_array()),
        ) {
            for value in was {
                if !now.into_iter().any(|candidate| candidate == value) {
                    self.out
                        .push(format!("{at}: enum value {} removed", text(value).trim()));
                }
            }
        }
        if let Some(properties) = old.get("properties").and_then(|v| v.as_object()) {
            for (name, was) in properties.iter() {
                match new.get("properties").and_then(|p| p.get(name)) {
                    None => self.out.push(format!("{at}: property {name} removed")),
                    Some(now) => self.schema(&format!("{at}.{name}"), was, now, dir),
                }
            }
        }
        let required = |schema: &json::Value| strings(&schema["required"]);
        let (was, now) = (required(old), required(new));
        match dir {
            Direction::Request => {
                for name in now.difference(&was) {
                    self.out
                        .push(format!("{at}: property {name} became required"));
                }
            }
            Direction::Response => {
                for name in was.difference(&now) {
                    self.out
                        .push(format!("{at}: property {name} is no longer required"));
                }
            }
        }
        if let (Some(was), Some(now)) = (old.get("items"), new.get("items")) {
            self.schema(&format!("{at}[]"), was, now, dir);
        }
        for combinator in ["allOf", "anyOf", "oneOf"] {
            if let (Some(was), Some(now)) = (
                old.get(combinator).and_then(|v| v.as_array()),
                new.get(combinator).and_then(|v| v.as_array()),
            ) {
                for (index, (was, now)) in was.into_iter().zip(now.into_iter()).enumerate() {
                    self.schema(&format!("{at}.{combinator}[{index}]"), was, now, dir);
                }
            }
        }
    }
}
