// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What this transport declares about itself — data only (`PLUGIN-TREE.md` §3).
//!
//! Every member here is an associated const read once at registration and sealed into policy.
//! The `COMPOSES_OVER` claim is the registration claim, so it is kept in [`crate::claims`] and
//! referenced from the one place the boot reads it.

use busbar_contract::TransportMeta;
use busbar_contract_transport::registry::facts as tfacts;

use crate::HttpTransport;

impl TransportMeta for HttpTransport {
    const KEY: &'static str = "http";
    const SELECTOR_FORMS: &'static [busbar_contract::SelectorForm] = &[
        busbar_contract::SelectorForm::ExactPath,
        busbar_contract::SelectorForm::PrefixOneLevel,
        busbar_contract::SelectorForm::PathPattern,
        busbar_contract::SelectorForm::HeaderExact,
        busbar_contract::SelectorForm::HeaderPresent,
        busbar_contract::SelectorForm::HeaderPrefix,
        busbar_contract::SelectorForm::PathSuffix,
        busbar_contract::SelectorForm::PathContains,
    ];
    const EGRESS_SELECTOR_FORMS: &'static [busbar_contract::SelectorForm] = &[];
    const COMPOSES_OVER: &'static [&'static str] = crate::claims::COMPOSES_OVER;
    const HANDOFF: Option<busbar_contract_transport::wire::Handoff> = None;
    const FRAMING: busbar_contract_transport::wire::Framing =
        busbar_contract_transport::wire::Framing::Stream;
    const SESSION: bool = false;
    const SESSION_BOUND: bool = false;
    const UNIT0_TRIGGER: Option<busbar_contract_transport::wire::Unit0Trigger> = None;
    const UPGRADES_TO: &'static [&'static str] = &[];
    const HANDSHAKE_TRIGGER: Option<busbar_contract_transport::wire::HandshakeTrigger> = None;
    const TRANSPORT_FACTS: &'static [&'static str] = &[
        tfacts::PATH,
        tfacts::METHOD,
        tfacts::AUTHORITY,
        tfacts::PEER,
    ];
    const DECODES_PAYLOAD: bool = false;
    const STATUS_CLASS: Option<busbar_contract_transport::wire::StatusAt> =
        Some(busbar_contract_transport::wire::StatusAt::FirstFrame);
    const STATUS_NAMESPACE: Option<&'static str> =
        Some(busbar_contract_transport::registry::status_ns::HTTP);
}
