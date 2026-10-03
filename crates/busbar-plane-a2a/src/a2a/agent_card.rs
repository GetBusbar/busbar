// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AGENT CARD, as the plane reads it: busbar's own structs, transcribed from the A2A
//! specification (moved from the served engine's `busbar-a2a` `card.rs`, which re-exports them).
//!
//! `#[serde(default)]` throughout, and unknown members are IGNORED rather than refused: an upstream
//! on a newer protocol revision must not become unreadable the moment it adds a member. These
//! structs are for READING a card; every hash is taken over the document as received.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The organization behind an agent. Operator-facing provenance, never an authenticity claim.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct AgentProvider {
    /// The organization's name.
    pub organization: String,
    /// The organization's URL.
    pub url: String,
}

/// One endpoint an agent can be reached on, and the wire format it speaks there.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct AgentInterface {
    /// The endpoint the card names (never dialled: the operator's `url:` says where).
    pub url: String,
    /// The binding's card word: `JSONRPC`, `HTTP+JSON` or `GRPC`.
    pub protocol_binding: String,
}

/// The optional protocol features an agent claims. Read by catalogue construction as STRUCTURAL
/// fitness (can this agent accept this shape of task at all), never as a quality signal.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct AgentCapabilities {
    /// The agent streams (`streaming`).
    #[serde(rename = "streaming")]
    pub is_stream: bool,
    /// The agent delivers push notifications.
    pub push_notifications: bool,
    /// The agent keeps its tasks' state history.
    pub state_transition_history: bool,
    /// The agent serves an authenticated extended card.
    pub extended_agent_card: bool,
}

/// One declared skill. THESE FIELDS ARE UPSTREAM-AUTHORED, and the trust model is built on knowing
/// that: an operator approving a card is vouching for what it claims, not verifying it. What the
/// digest of this structure buys is that the claim cannot CHANGE after the vouch without registering
/// as drift.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct AgentSkill {
    /// The skill's id: what an approval and a request name it by.
    pub id: String,
    /// Its name.
    pub name: String,
    /// Its description.
    pub description: String,
    /// Tags GROUP. They are never how one specific skill is named.
    pub tags: Vec<String>,
    /// The MIME modes it accepts; the card's defaults where empty.
    pub input_modes: Vec<String>,
    /// The MIME modes it produces; the card's defaults where empty.
    pub output_modes: Vec<String>,
    /// Example prompts.
    pub examples: Vec<String>,
}

/// A JWS signature over the card. Retained so an operator view can show WHICH key signed, and so a
/// card carrying several signatures is not silently reduced to its first.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct AgentCardSignature {
    /// The JWS protected header.
    pub protected: String,
    /// The JWS signature.
    pub signature: String,
    /// The JWS unprotected header.
    pub header: BTreeMap<String, Value>,
}

/// The Agent Card as busbar reads it.
///
/// `security_schemes` is carried as an open map rather than a mirrored union, and that is stated
/// rather than hidden: the schemes are an open, growing set, and half-mirroring a union produces a
/// struct that silently drops the arm it did not know about. busbar reads the scheme NAMES a caller
/// must satisfy; the scheme bodies travel verbatim and are hashed with the rest of the card.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct AgentCard {
    /// The A2A protocol version the card is written in.
    pub protocol_version: String,
    /// The agent's name.
    pub name: String,
    /// The agent's description.
    pub description: String,
    /// The agent's version.
    pub version: String,
    /// Who provides the agent.
    pub provider: AgentProvider,
    /// The bindings the agent is reachable on, preferred first.
    pub supported_interfaces: Vec<AgentInterface>,
    /// The MIME modes it accepts by default.
    pub default_input_modes: Vec<String>,
    /// The MIME modes it produces by default.
    pub default_output_modes: Vec<String>,
    /// The optional protocol features it claims.
    pub capabilities: AgentCapabilities,
    /// The skills it declares.
    pub skills: Vec<AgentSkill>,
    /// The security schemes, verbatim.
    pub security_schemes: BTreeMap<String, Value>,
    /// The scheme names a caller must satisfy.
    pub security: Vec<BTreeMap<String, Vec<String>>>,
    /// The JWS signatures over the card.
    pub signatures: Vec<AgentCardSignature>,
}

/// Read the members busbar acts on; `None` when the document is not a card (not an object, or a
/// member present with the wrong type). Unknown members are ignored.
#[must_use]
pub fn parse(card: &Value) -> Option<AgentCard> {
    if !card.is_object() {
        return None;
    }
    serde_json::from_value(card.clone()).ok()
}
