// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What this transport declares about itself.
//!
//! Everything here is an associated constant, because everything here is read once at registration
//! and sealed. Held as the kind's own `meta.rs` (`PLUGIN-TREE.md` §3) so two siblings of the
//! transport kind are indistinguishable in shape.

use busbar_contract::grammar::SelectorForm;
use busbar_contract::transport::wire::Unit0Trigger;
use busbar_contract::transport::AbiVersion;
use busbar_contract::{Kind, Plugin, TransportMeta};

use crate::claims;
use crate::transport::StdioTransport;

impl Plugin for StdioTransport {
    fn key(&self) -> &'static str {
        <Self as TransportMeta>::KEY
    }
    fn kind(&self) -> Kind {
        Kind::Transport
    }
    fn abi(&self) -> AbiVersion {
        busbar_contract::transport::registry::TRANSPORT_ABI
    }
}

impl TransportMeta for StdioTransport {
    const KEY: &'static str = "stdio";
    const SELECTOR_FORMS: &'static [SelectorForm] = claims::SELECTOR_FORMS;
    const EGRESS_SELECTOR_FORMS: &'static [SelectorForm] = claims::EGRESS_SELECTOR_FORMS;
    const COMPOSES_OVER: &'static [&'static str] = &[];
    const HANDOFF: Option<busbar_contract::transport::wire::Handoff> = None;
    const FRAMING: busbar_contract::transport::wire::Framing =
        busbar_contract::transport::wire::Framing::Stream;
    const SESSION: bool = true;
    const SESSION_BOUND: bool = true;
    const UNIT0_TRIGGER: Option<Unit0Trigger> = Some(Unit0Trigger::FirstMessage);
    const UPGRADES_TO: &'static [&'static str] = &[];
    const HANDSHAKE_TRIGGER: Option<busbar_contract::transport::wire::HandshakeTrigger> = None;
    // No transport-level fact this carrier writes beyond the arrival record itself.
    const TRANSPORT_FACTS: &'static [&'static str] = &[];
    const DECODES_PAYLOAD: bool = false;
    // The transports table names no status leg for stdio; the plane's own `finish` class is the fee's sole
    // source here.
    const STATUS_CLASS: Option<busbar_contract::transport::wire::StatusAt> = None;
    const STATUS_NAMESPACE: Option<&'static str> = None;
}
