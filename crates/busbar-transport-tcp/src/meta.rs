// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What this transport declares about itself — data only (`PLUGIN-TREE.md` §3).
//!
//! Every member here is an associated const read once at registration and sealed into policy. The
//! `COMPOSES_OVER` claim is not restated here: it is the registration claim, so it lives in
//! [`crate::claims`] and is referenced from the one place the boot reads it.

use busbar_contract::TransportMeta;
use busbar_contract_transport::registry::facts as tfacts;

use crate::TcpTransport;

impl TransportMeta for TcpTransport {
    const KEY: &'static str = "tcp";
    const SELECTOR_FORMS: &'static [busbar_contract::SelectorForm] =
        &[busbar_contract::SelectorForm::Port];
    const EGRESS_SELECTOR_FORMS: &'static [busbar_contract::SelectorForm] = &[];
    const COMPOSES_OVER: &'static [&'static str] = crate::claims::COMPOSES_OVER;
    const HANDOFF: Option<busbar_contract_transport::wire::Handoff> = None;
    const FRAMING: busbar_contract_transport::wire::Framing =
        busbar_contract_transport::wire::Framing::Stream;
    const SESSION: bool = true;
    const SESSION_BOUND: bool = false;
    const UNIT0_TRIGGER: Option<busbar_contract_transport::wire::Unit0Trigger> =
        Some(busbar_contract_transport::wire::Unit0Trigger::FirstBytes);
    const UPGRADES_TO: &'static [&'static str] = &["tls"];
    const HANDSHAKE_TRIGGER: Option<busbar_contract_transport::wire::HandshakeTrigger> = None;
    const TRANSPORT_FACTS: &'static [&'static str] = &[tfacts::PEER];
    const DECODES_PAYLOAD: bool = false;
    const STATUS_CLASS: Option<busbar_contract_transport::wire::StatusAt> = None;
    const STATUS_NAMESPACE: Option<&'static str> = None;
}
