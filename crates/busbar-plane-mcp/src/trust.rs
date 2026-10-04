// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TRUST SURFACE, PLANE SIDE: what a registered server was last seen to OFFER, judged against
//! what the operator APPROVED in the `tools:` section, and the three admin answers that render it
//! (`connect`, `changes`, `health`; ARCHITECT Q-L3B-VERBS). Pure: the section's registration and
//! the last sighting in, a state, a changes queue and the views out.
//!
//! * **The approval** is the registration as the operator wrote it: an authenticity root (a pin
//!   whose mechanism is a root and carries its key) and, per tool, the `sha256:` digest approved for
//!   it. A tool allowed with no digest is absent from the approval, which is `pending`; a
//!   registration with no root approves nothing.
//! * **The observation** is a live `tools/list`, each tool re-hashed here from the definition the
//!   upstream sent ([`tool_digest`]: name, description and input schema, length-framed, the schema in
//!   canonical JSON), never a digest the upstream supplied.
//! * **The state** is derived on every read, never stored: a failed contact is `error`; no root is
//!   `pending`; a sighting that disagrees with the approval is `quarantined`; anything else (no
//!   sighting yet, or one that agrees) is `approved`. Only `approved` serves.
//!
//! The kernel's trust book records each sighting's catalogue hash ([`catalogue_hash`],
//! `trust.sight`), which stamps the server's re-verification clock; the operator's view and the
//! dispatch gate read the comparison above, so both answer the one question the operator is looking
//! at. The identity axis (`pin_changed`) is reported `false`: an MCP hop through the host connector
//! presents no certificate key the plane could compare a `cert_spki`/`mtls` pin against.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::tools_config::McpServerDefCfg;

/// One tool's identity, as `sha256:<hex>` over its name, description and input schema: one digest,
/// because the operator's question is "is this the same tool I approved".
#[must_use]
pub fn tool_digest(name: &str, description: &str, input_schema: &Value) -> String {
    let mut framed = Vec::new();
    // Length-prefixed, so a description ending in what the next field starts with cannot forge the
    // same byte stream as a different split.
    for part in [name, description, &canonical_json(input_schema)] {
        framed.extend_from_slice(&(part.len() as u64).to_be_bytes());
        framed.extend_from_slice(part.as_bytes());
    }
    format!(
        "sha256:{}",
        hex(&busbar_contract::abi::sdk::digest::sha256(&framed))
    )
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// `value` with every object's keys sorted, recursively: key ORDER is not drift, any change of key,
/// value or shape is.
#[must_use]
pub fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Object(map) => {
            let sorted: BTreeMap<&String, &Value> = map.iter().collect();
            out.push('{');
            for (i, (k, v)) in sorted.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String((*k).clone()).to_string());
                out.push(':');
                write_canonical(v, out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, v) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(v, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

/// What an upstream was observed to offer: `tool -> digest`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Observation {
    /// The capability set.
    pub capabilities: BTreeMap<String, String>,
}

/// THE OBSERVATION a `tools/list` result carries, or why it is not one. Strict about the shape: a
/// missing `description` is the empty string and a missing `inputSchema` is `{}`, both hashed at
/// their defaulted value, so an upstream that later supplies one has drifted.
///
/// # Errors
///
/// The result carries no `tools` array, or an entry with no (or an empty) `name`.
pub fn observe(result: &Value) -> Result<Observation, String> {
    let Some(items) = result.get("tools").and_then(Value::as_array) else {
        return Err("the `tools/list` result carries no `tools` array".to_string());
    };
    let mut capabilities = BTreeMap::new();
    for item in items {
        let Some(name) = item.get("name").and_then(Value::as_str) else {
            return Err("a `tools/list` entry carries no `name`".to_string());
        };
        if name.trim().is_empty() {
            return Err("a `tools/list` entry carries an empty `name`".to_string());
        }
        let description = item
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let schema = item
            .get("inputSchema")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));
        capabilities.insert(name.to_string(), tool_digest(name, description, &schema));
    }
    Ok(Observation { capabilities })
}

/// The hash a sighting reports to the kernel's trust book (`trust.sight`): the observed capability
/// set, `name` and digest per line in name order.
#[must_use]
pub fn catalogue_hash(observation: &Observation) -> String {
    let mut bytes = Vec::new();
    for (name, digest) in &observation.capabilities {
        bytes.extend_from_slice(name.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(digest.as_bytes());
        bytes.push(b'\n');
    }
    format!(
        "sha256:{}",
        hex(&busbar_contract::abi::sdk::digest::sha256(&bytes))
    )
}

/// The last contact. `Never` is not a failure: a declaratively approved server has legitimately
/// never been reached.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Sighting {
    /// Never contacted.
    #[default]
    Never,
    /// The contact failed, with the operator-visible reason.
    Failed(String),
    /// Contacted, and this is what it offered.
    Seen(Observation),
}

/// The operator's standing decision about one registration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Approval {
    /// An authenticity root is declared (a root mechanism with its key).
    pub rooted: bool,
    /// `tool -> approved digest`; an allowed tool with no digest is absent (pending).
    pub capabilities: BTreeMap<String, String>,
}

impl Approval {
    /// The approval the registration `def` declares.
    #[must_use]
    pub fn of(def: &McpServerDefCfg) -> Self {
        let rooted = def.pin.mechanism.is_a_root()
            && def.pin.key.as_deref().is_some_and(|k| !k.trim().is_empty());
        if !rooted {
            return Self::default();
        }
        Self {
            rooted,
            capabilities: def
                .tools_allow
                .iter()
                .filter_map(|(tool, allow)| {
                    let hash = allow.schema_hash.as_deref().map(str::trim)?;
                    (!hash.is_empty()).then(|| (tool.clone(), hash.to_string()))
                })
                .collect(),
        }
    }
}

/// The derived trust state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// No authenticity root: nothing approved, nothing served.
    Pending,
    /// Rooted, and the last sighting (if any) agrees with the approval. Serves.
    Approved,
    /// Rooted, but the last sighting disagrees with the approval.
    Quarantined,
    /// The last contact failed.
    Error,
}

impl State {
    /// The wire word a UI branches on.
    #[must_use]
    pub fn word(self) -> &'static str {
        match self {
            State::Pending => "pending",
            State::Approved => "approved",
            State::Quarantined => "quarantined",
            State::Error => "error",
        }
    }
}

/// The changes queue: what the last sighting changed relative to the approval.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Drift {
    /// Offered now, never ruled on.
    pub added: Vec<String>,
    /// Approved, but offered at another digest: the rug-pull row.
    pub changed: Vec<String>,
    /// Approved, and no longer offered.
    pub removed: Vec<String>,
}

impl Drift {
    fn is_empty(&self) -> bool {
        self.added.is_empty() && self.changed.is_empty() && self.removed.is_empty()
    }
}

/// The changes queue of `sighting` against `approval`; empty with no successful sighting.
#[must_use]
pub fn drift(approval: &Approval, sighting: &Sighting) -> Drift {
    let Sighting::Seen(obs) = sighting else {
        return Drift::default();
    };
    let mut d = Drift::default();
    for (name, digest) in &obs.capabilities {
        match approval.capabilities.get(name) {
            Some(approved) if approved == digest => {}
            Some(_) => d.changed.push(name.clone()),
            None => d.added.push(name.clone()),
        }
    }
    for name in approval.capabilities.keys() {
        if !obs.capabilities.contains_key(name) {
            d.removed.push(name.clone());
        }
    }
    d
}

/// The derived state. Order is precedence: a failed contact is never reported as trust; an unrooted
/// registration is pending whatever else is true of it; quarantine is the presence of drift.
#[must_use]
pub fn state(approval: &Approval, sighting: &Sighting) -> State {
    if matches!(sighting, Sighting::Failed(_)) {
        return State::Error;
    }
    if !approval.rooted {
        return State::Pending;
    }
    if drift(approval, sighting).is_empty() {
        State::Approved
    } else {
        State::Quarantined
    }
}

/// How many tools the last successful sighting carried.
fn observed(sighting: &Sighting) -> usize {
    match sighting {
        Sighting::Seen(o) => o.capabilities.len(),
        _ => 0,
    }
}

/// Why the last contact failed, when it did.
fn failure(sighting: &Sighting) -> Option<&str> {
    match sighting {
        Sighting::Failed(reason) => Some(reason),
        _ => None,
    }
}

/// One capability's standing status, in the trust view.
#[derive(serde::Serialize)]
struct CapabilityView<'a> {
    tool: &'a str,
    status: &'static str,
    approved_digest: Option<&'a str>,
}

/// THE TRUST VIEW of one registration (`connect` and `changes` answer it), field for field the
/// served engine's: its name, the derived state, the pin mechanism, the identity axis, the changes
/// queue, the observation's size, the failure and every capability's standing status in name order.
#[derive(serde::Serialize)]
struct TrustView<'a> {
    name: &'a str,
    state: &'static str,
    pin_mechanism: &'static str,
    pin_changed: bool,
    added: Vec<String>,
    changed: Vec<String>,
    removed: Vec<String>,
    observed_tools: usize,
    failure: Option<&'a str>,
    capabilities: Vec<CapabilityView<'a>>,
}

/// THE HEALTH VIEW (`health` answers it): the one bit a caller polls for, and why.
#[derive(serde::Serialize)]
struct HealthView<'a> {
    name: &'a str,
    state: &'static str,
    serving: bool,
    contacted: bool,
    failure: Option<&'a str>,
    observed_tools: usize,
}

/// The trust view of registration `name` (`def`) under `sighting`, serialized in declaration order.
#[must_use]
pub fn trust_view(name: &str, def: &McpServerDefCfg, sighting: &Sighting) -> String {
    let approval = Approval::of(def);
    let d = drift(&approval, sighting);
    let mut capabilities: BTreeMap<&str, CapabilityView<'_>> = approval
        .capabilities
        .iter()
        .map(|(tool, digest)| {
            (
                tool.as_str(),
                CapabilityView {
                    tool,
                    status: "approved",
                    approved_digest: Some(digest),
                },
            )
        })
        .collect();
    for tool in def.tools_allow.keys() {
        capabilities.entry(tool).or_insert(CapabilityView {
            tool,
            status: "pending",
            approved_digest: None,
        });
    }
    let view = TrustView {
        name,
        state: state(&approval, sighting).word(),
        pin_mechanism: def.pin.mechanism.token(),
        pin_changed: false,
        added: d.added,
        changed: d.changed,
        removed: d.removed,
        observed_tools: observed(sighting),
        failure: failure(sighting),
        capabilities: capabilities.into_values().collect(),
    };
    serde_json::to_string(&view).unwrap_or_default()
}

/// The health view of registration `name` (`def`) under `sighting`, serialized in declaration order.
#[must_use]
pub fn health_view(name: &str, def: &McpServerDefCfg, sighting: &Sighting) -> String {
    let derived = state(&Approval::of(def), sighting);
    let view = HealthView {
        name,
        state: derived.word(),
        serving: derived == State::Approved,
        contacted: !matches!(sighting, Sighting::Never),
        failure: failure(sighting),
        observed_tools: observed(sighting),
    };
    serde_json::to_string(&view).unwrap_or_default()
}

/// THE DISPATCH GATE'S QUESTION about one tool of a registration under its last sighting: `None`
/// when it serves, else the state word it is refused as. A server that is not approved serves
/// nothing; an approved one serves a tool only at its approved digest (the live one when sighted).
#[must_use]
pub fn refused_as(def: &McpServerDefCfg, sighting: &Sighting, tool: &str) -> Option<&'static str> {
    let approval = Approval::of(def);
    let derived = state(&approval, sighting);
    if derived != State::Approved {
        return Some(derived.word());
    }
    match sighting {
        Sighting::Seen(obs) => {
            let approved = approval.capabilities.get(tool)?;
            (obs.capabilities.get(tool) != Some(approved)).then_some(State::Quarantined.word())
        }
        _ => None,
    }
}

#[cfg(test)]
#[path = "tests/trust_tests.rs"]
mod tests;
