// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What this transport declares about itself — data only (`PLUGIN-TREE.md` §3).
//!
//! Every member here is an associated const read once at registration and sealed into policy. The
//! `COMPOSES_OVER` claim is not restated here: it is the registration claim, so it lives in
//! [`crate::claims`] and is referenced from the one place the boot reads it.

use busbar_contract::grammar::SelectorForm;
use busbar_contract::TransportMeta;
use busbar_contract_transport::wire::Unit0Trigger;

use crate::StdioTransport;

impl TransportMeta for StdioTransport {
    const KEY: &'static str = "stdio";
    // stdio carries no header, path or handshake surface to select on: a claim on this transport
    // can only ever be the whole channel. Empty rather than guessed — see the crate report.
    const SELECTOR_FORMS: &'static [SelectorForm] = &[];
    const EGRESS_SELECTOR_FORMS: &'static [SelectorForm] = &[];
    const COMPOSES_OVER: &'static [&'static str] = crate::claims::COMPOSES_OVER;
    const HANDOFF: Option<busbar_contract_transport::wire::Handoff> = None;
    const FRAMING: busbar_contract_transport::wire::Framing =
        busbar_contract_transport::wire::Framing::Stream;
    const SESSION: bool = true;
    const SESSION_BOUND: bool = true;
    const UNIT0_TRIGGER: Option<Unit0Trigger> = Some(Unit0Trigger::FirstMessage);
    const UPGRADES_TO: &'static [&'static str] = &[];
    const HANDSHAKE_TRIGGER: Option<busbar_contract_transport::wire::HandshakeTrigger> = None;
    // No transport-level fact this carrier writes beyond the arrival record itself.
    const TRANSPORT_FACTS: &'static [&'static str] = &[];
    const DECODES_PAYLOAD: bool = false;
    // The transports table names no status leg for stdio; the plane's own `finish` class is the fee's sole
    // source here.
    const STATUS_CLASS: Option<busbar_contract_transport::wire::StatusAt> = None;
    const STATUS_NAMESPACE: Option<&'static str> = None;
}
