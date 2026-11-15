// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ADMIN-API-1.6 section 17: engine events as rows of the one `/audit` feed. Each carries the
//! principal `node:<node_id>`, is sealed in the admin chain on the cold path, and is emitted on a
//! state transition only. Rows are coalesced per (action, instance) to at most one per second; the
//! folded ones are counted in `data.coalesced`.

use std::cell::Cell;
use std::collections::HashMap;
use std::sync::Mutex;

use super::auditlog::{emit_row_now, AuditRowInput};
use crate::audit_ring::AuditData;
use busbar_contract::vocab::OUTCOME_APPLIED;

/// Principal of every engine event on a node whose identity is not yet published.
const UNPUBLISHED_NODE: &str = "node:unpublished";

/// One engine event, before it is a row.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EngineEvent {
    pub action: &'static str,
    pub kind: Option<String>,
    pub instance: Option<String>,
    /// `info`, `warning` or `error`; empty is `info`.
    pub severity: &'static str,
    pub outcome: Option<&'static str>,
    pub message: String,
    /// A JSON object; empty means `{}`.
    pub data: String,
}

/// The principal of an engine event: `node:<node_id>`.
#[must_use]
pub fn node_principal(node_id: Option<&str>) -> String {
    match node_id {
        Some(id) => format!("node:{id}"),
        None => UNPUBLISHED_NODE.to_string(),
    }
}

/// `data` with `"coalesced": folded` added when `folded` is not zero.
#[must_use]
pub fn data_with_coalesced(data: &str, folded: u64) -> String {
    let data = if data.trim().is_empty() {
        "{}"
    } else {
        data.trim()
    };
    if folded == 0 {
        return data.to_string();
    }
    let body = data.strip_suffix('}').unwrap_or(data).trim_end();
    let sep = if body.ends_with('{') { "" } else { "," };
    format!("{body}{sep}\"coalesced\":{folded}}}")
}

/// The audit row of `event` as written by `node_id`, with `folded` earlier events coalesced into it.
#[must_use]
pub fn event_row(event: &EngineEvent, node_id: Option<&str>, folded: u64) -> AuditRowInput {
    let resource = match (&event.kind, &event.instance) {
        (Some(kind), Some(instance)) => format!("{kind}:{instance}"),
        (None, Some(instance)) => instance.clone(),
        _ => node_id.map_or_else(|| "node".to_string(), |id| format!("node:{id}")),
    };
    AuditRowInput {
        action: event.action.to_string(),
        resource,
        outcome: event.outcome.unwrap_or(OUTCOME_APPLIED).to_string(),
        principal: node_principal(node_id),
        kind: event.kind.clone(),
        instance: event.instance.clone(),
        severity: event.severity.to_string(),
        message: event.message.clone(),
        data: AuditData::from_json(&data_with_coalesced(&event.data, folded)).unwrap_or_default(),
        ..Default::default()
    }
}

/// Per (action, instance) state: the second of the last row and the events folded since.
#[derive(Debug, Default)]
pub struct Coalescer {
    seen: HashMap<(&'static str, String), (u64, u64)>,
}

impl Coalescer {
    /// `Some(folded)` when a row is due at second `now` (`folded` events were absorbed since the last
    /// row); `None` when this event folds into the row already written this second.
    pub fn admit(&mut self, action: &'static str, instance: &str, now: u64) -> Option<u64> {
        let key = (action, instance.to_string());
        match self.seen.get_mut(&key) {
            Some((last, folded)) if *last == now => {
                *folded += 1;
                None
            }
            Some((last, folded)) => {
                let due = *folded;
                *last = now;
                *folded = 0;
                Some(due)
            }
            None => {
                self.seen.insert(key, (now, 0));
                Some(0)
            }
        }
    }
}

static COALESCER: Mutex<Option<Coalescer>> = Mutex::new(None);

thread_local! {
    /// Writing a row may itself log a diagnostic; that diagnostic must not become another row.
    static EMITTING: Cell<bool> = const { Cell::new(false) };
}

/// Write `event` to the admin audit, coalesced. Cold path only: it takes a lock and seals a row.
pub fn engine_event(event: EngineEvent) {
    if EMITTING.with(Cell::get) {
        return;
    }
    let instance = event.instance.clone().unwrap_or_default();
    let due = COALESCER
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get_or_insert_with(Coalescer::default)
        .admit(event.action, &instance, busbar_kernel::store::now());
    let Some(folded) = due else { return };
    let node = crate::persistence::boot_identity::live().map(|live| live.node_id());
    EMITTING.with(|flag| flag.set(true));
    emit_row_now(event_row(&event, node.as_deref(), folded));
    EMITTING.with(|flag| flag.set(false));
}

fn json_str(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// `node.boot`: the node is up. `posture` names each unsafe posture it booted in (an open relay, an
/// ephemeral store, an overlay that was ignored).
#[must_use]
pub fn node_boot(posture: &[&str]) -> EngineEvent {
    let words: Vec<String> = posture.iter().map(|word| json_str(word)).collect();
    EngineEvent {
        action: "node.boot",
        severity: if posture.is_empty() {
            "info"
        } else {
            "warning"
        },
        message: "node booted".into(),
        data: format!("{{\"posture\":[{}]}}", words.join(",")),
        ..Default::default()
    }
}

/// `node.drain`: the node began its shutdown drain.
#[must_use]
pub fn node_drain() -> EngineEvent {
    EngineEvent {
        action: "node.drain",
        message: "node draining".into(),
        ..Default::default()
    }
}

/// `diagnostic.raised`: a diagnostic of severity `Actionable` fired (`count` is the times so far).
#[must_use]
pub fn diagnostic_raised(code: u16, name: &str, count: u64) -> EngineEvent {
    EngineEvent {
        action: "diagnostic.raised",
        instance: Some(code.to_string()),
        severity: "warning",
        message: name.to_string(),
        data: format!(
            "{{\"code\":{code},\"count\":{count},\"name\":{}}}",
            json_str(name)
        ),
        ..Default::default()
    }
}

static RAISED: Mutex<Option<HashMap<u16, u64>>> = Mutex::new(None);

/// Count one raising of diagnostic `code` and write its `diagnostic.raised` row (coalesced).
pub fn note_diagnostic(code: u16, name: &str) {
    let count = {
        let mut guard = RAISED.lock().unwrap_or_else(|p| p.into_inner());
        let n = guard
            .get_or_insert_with(HashMap::new)
            .entry(code)
            .or_insert(0);
        *n += 1;
        *n
    };
    engine_event(diagnostic_raised(code, name, count));
}

#[cfg(test)]
#[path = "tests/events_tests.rs"]
mod tests;
