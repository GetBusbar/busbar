// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What this transport declares about itself.
//!
//! Everything here is an associated constant, because everything here is read once at registration
//! and sealed. Held as the kind's own `meta.rs` (`PLUGIN-TREE.md` §3) so two siblings of the
//! transport kind are indistinguishable in shape.

use busbar_contract::{Kind, Plugin, SelectorForm, TransportMeta};

use super::claims;
use super::SseTransport;

impl Plugin for SseTransport {
    fn key(&self) -> &'static str {
        Self::KEY
    }
    fn kind(&self) -> Kind {
        Kind::Transport
    }
    fn abi(&self) -> busbar_contract::transport::AbiVersion {
        busbar_contract::transport::registry::TRANSPORT_ABI
    }
}

impl TransportMeta for SseTransport {
    const KEY: &'static str = "sse";
    const SELECTOR_FORMS: &'static [SelectorForm] = claims::SELECTOR_FORMS;
    const EGRESS_SELECTOR_FORMS: &'static [SelectorForm] = claims::EGRESS_SELECTOR_FORMS;
    const COMPOSES_OVER: &'static [&'static str] = &["http"];
    const HANDOFF: Option<busbar_contract::transport::wire::Handoff> = None;
    const FRAMING: busbar_contract::transport::wire::Framing =
        busbar_contract::transport::wire::Framing::Stream;
    const SESSION: bool = false;
    const SESSION_BOUND: bool = false;
    const UNIT0_TRIGGER: Option<busbar_contract::transport::wire::Unit0Trigger> = None;
    const UPGRADES_TO: &'static [&'static str] = &[];
    const HANDSHAKE_TRIGGER: Option<busbar_contract::transport::wire::HandshakeTrigger> = None;
    const TRANSPORT_FACTS: &'static [&'static str] = &[];
    const DECODES_PAYLOAD: bool = false;
    const STATUS_CLASS: Option<busbar_contract::transport::wire::StatusAt> =
        Some(busbar_contract::transport::wire::StatusAt::FirstFrame);
    const STATUS_NAMESPACE: Option<&'static str> =
        Some(busbar_contract::transport::registry::status_ns::HTTP);
}
