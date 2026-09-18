// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What this transport declares about itself — data only (`PLUGIN-TREE.md` §3).
//!
//! Every member here is an associated const read once at registration and sealed into policy. The
//! `COMPOSES_OVER` claim is not restated here: it is the registration claim, so it lives in
//! [`crate::claims`] and is referenced from the one place the boot reads it.

use busbar_contract::grammar::SelectorForm;
use busbar_contract::TransportMeta;
use busbar_contract_transport::registry::facts as tfacts;
use busbar_contract_transport::wire::Unit0Trigger;

use crate::GrpcTransport;

impl TransportMeta for GrpcTransport {
    const KEY: &'static str = "grpc";
    // See `busbar-transport-ws`'s identical note: grpc is the top transport of its stack and
    // therefore the one that owns claim selection over the request that opens each call, including
    // its `:path`.
    const SELECTOR_FORMS: &'static [SelectorForm] = &[
        SelectorForm::ExactPath,
        SelectorForm::PrefixOneLevel,
        SelectorForm::PathPattern,
        SelectorForm::HeaderExact,
        SelectorForm::HeaderPresent,
        SelectorForm::HeaderPrefix,
        SelectorForm::Sni,
        SelectorForm::Alpn,
        SelectorForm::Port,
    ];
    const EGRESS_SELECTOR_FORMS: &'static [SelectorForm] = &[];
    // The layers this one is actually built over, and the Cargo edges say the same: `http`
    // carries an inbound connection, `tcp` carries a dialled one.
    const COMPOSES_OVER: &'static [&'static str] = crate::claims::COMPOSES_OVER;
    const HANDOFF: Option<busbar_contract_transport::wire::Handoff> = None;
    const FRAMING: busbar_contract_transport::wire::Framing =
        busbar_contract_transport::wire::Framing::Stream;
    const SESSION: bool = true;
    const SESSION_BOUND: bool = true;
    const UNIT0_TRIGGER: Option<Unit0Trigger> = Some(Unit0Trigger::FirstMessage);
    const UPGRADES_TO: &'static [&'static str] = &[];
    const HANDSHAKE_TRIGGER: Option<busbar_contract_transport::wire::HandshakeTrigger> = None;
    const TRANSPORT_FACTS: &'static [&'static str] = &[tfacts::PATH, tfacts::PEER];
    const DECODES_PAYLOAD: bool = false;
    // "carries the per-frame StatusClass at Terminal (the grpc-status trailer)" — the transports
    // table's own words for this row.
    const STATUS_CLASS: Option<busbar_contract_transport::wire::StatusAt> =
        Some(busbar_contract_transport::wire::StatusAt::Terminal);
    const STATUS_NAMESPACE: Option<&'static str> =
        Some(busbar_contract_transport::registry::status_ns::GRPC);
}
