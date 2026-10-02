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
    pub organization: String,
    pub url: String,
}

/// One endpoint an agent can be reached on, and the wire format it speaks there.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct AgentInterface {
    pub url: String,
    /// `JSONRPC` today. `GRPC` is the revision that would earn this plane a superset intermediate
    /// representation, and it is out of scope until it exists.
    pub protocol_binding: String,
}

/// The optional protocol features an agent claims. Read by catalogue construction as STRUCTURAL
/// fitness (can this agent accept this shape of task at all), never as a quality signal.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct AgentCapabilities {
    #[serde(rename = "streaming")]
    pub is_stream: bool,
    pub push_notifications: bool,
    pub state_transition_history: bool,
    pub extended_agent_card: bool,
}

/// One declared skill. THESE FIELDS ARE UPSTREAM-AUTHORED, and the trust model is built on knowing
/// that: an operator approving a card is vouching for what it claims, not verifying it. What the
/// digest of this structure buys is that the claim cannot CHANGE after the vouch without registering
/// as drift.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct AgentSkill {
    pub id: String,
    pub name: String,
    pub description: String,
    /// Tags GROUP. They are never how one specific skill is named.
    pub tags: Vec<String>,
    pub input_modes: Vec<String>,
    pub output_modes: Vec<String>,
    pub examples: Vec<String>,
}

/// A JWS signature over the card. Retained so an operator view can show WHICH key signed, and so a
/// card carrying several signatures is not silently reduced to its first.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct AgentCardSignature {
    pub protected: String,
    pub signature: String,
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
    pub protocol_version: String,
    pub name: String,
    pub description: String,
    pub version: String,
    pub provider: AgentProvider,
    pub supported_interfaces: Vec<AgentInterface>,
    pub default_input_modes: Vec<String>,
    pub default_output_modes: Vec<String>,
    pub capabilities: AgentCapabilities,
    pub skills: Vec<AgentSkill>,
    pub security_schemes: BTreeMap<String, Value>,
    pub security: Vec<BTreeMap<String, Vec<String>>>,
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
