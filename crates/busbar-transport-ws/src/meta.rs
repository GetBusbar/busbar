// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What this transport declares about itself.
//!
//! Everything here is an associated constant, because everything here is read once at registration
//! and sealed. Held as the kind's own `meta.rs` (`BUSBAR-1.6.0.md` THE DESIGN, §2) so two siblings of the
//! transport kind are indistinguishable in shape, and so the declarations are readable without
//! reading the connection code they describe.

use busbar_contract::grammar::SelectorForm;
use busbar_contract::transport::registry::facts as tfacts;
use busbar_contract::transport::wire::Unit0Trigger;
use busbar_contract::transport::AbiVersion;
use busbar_contract::{Kind, Plugin, TransportMeta};

use crate::claims;
use crate::transport::WsTransport;

impl Plugin for WsTransport {
    fn key(&self) -> &'static str {
        <crate::WsFramer as TransportMeta>::KEY
    }
    fn kind(&self) -> Kind {
        Kind::Transport
    }
    fn abi(&self) -> AbiVersion {
        busbar_contract::transport::registry::TRANSPORT_ABI
    }
}

impl TransportMeta for crate::WsFramer {
    const KEY: &'static str = "ws";
    const SELECTOR_FORMS: &'static [SelectorForm] = claims::SELECTOR_FORMS;
    const EGRESS_SELECTOR_FORMS: &'static [SelectorForm] = claims::EGRESS_SELECTOR_FORMS;
    // The layers this one is actually built over: an inbound upgrade arrives on `http`, an
    // outbound one is dialled through `tcp` for a `ws://` target. No transport encrypts: TLS is
    // core's connection security, never a layer a transport composes over,
    // and this transport adds no encryption of its own, so `dial` refuses a `wss://` target rather
    // than put a cleartext upgrade on a wire the destination said was secure.
    const COMPOSES_OVER: &'static [&'static str] = &["http", "tcp"];
    const HANDOFF: Option<busbar_contract::transport::wire::Handoff> = None;
    const FRAMING: busbar_contract::transport::wire::Framing =
        busbar_contract::transport::wire::Framing::Stream;
    const SESSION: bool = true;
    const SESSION_BOUND: bool = true;
    const UNIT0_TRIGGER: Option<Unit0Trigger> = Some(Unit0Trigger::Upgrade);
    const UPGRADES_TO: &'static [&'static str] = &[];
    const HANDSHAKE_TRIGGER: Option<busbar_contract::transport::wire::HandshakeTrigger> = None;
    const TRANSPORT_FACTS: &'static [&'static str] = &[tfacts::PATH, tfacts::PEER];
    const DECODES_PAYLOAD: bool = false;
    // "frames after the upgrade carry no status leg" — the transports table's own words for this
    // row.
    const STATUS_CLASS: Option<busbar_contract::transport::wire::StatusAt> = None;
    const STATUS_NAMESPACE: Option<&'static str> = None;
}
