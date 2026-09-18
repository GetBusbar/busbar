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

use crate::WsTransport;

impl TransportMeta for WsTransport {
    const KEY: &'static str = "ws";
    // ws IS the top transport of its stack (composed over `http`), and the architecture states the
    // TOP transport owns claims — including the ones that, before the upgrade, are read off the
    // HTTP request carrying it. So this declares the request-shaped forms rather than none; a
    // genuine open question (flagged in the crate's report) is whether that reading is what the
    // design intends, since `http`'s own row would otherwise carry the identical set unused.
    const SELECTOR_FORMS: &'static [SelectorForm] = &[
        SelectorForm::ExactPath,
        SelectorForm::PrefixOneLevel,
        SelectorForm::PathPattern,
        SelectorForm::PathSuffix,
        SelectorForm::PathContains,
        SelectorForm::HeaderExact,
        SelectorForm::HeaderPresent,
        SelectorForm::HeaderPrefix,
        SelectorForm::Sni,
        SelectorForm::Alpn,
        SelectorForm::Port,
    ];
    const EGRESS_SELECTOR_FORMS: &'static [SelectorForm] = &[];
    // The layers this one is actually built over: an inbound upgrade arrives on `http`, an
    // outbound one is dialled through `tcp` for a `ws://` target and through `tls` for a `wss://`
    // one. `tls` is named because a secure target is dialled ON it directly — this transport adds
    // no encryption of its own, so that is the only composition under which `wss` is honest, and
    // `dial` refuses a secure target over any other lower layer.
    const COMPOSES_OVER: &'static [&'static str] = crate::claims::COMPOSES_OVER;
    const HANDOFF: Option<busbar_contract_transport::wire::Handoff> = None;
    const FRAMING: busbar_contract_transport::wire::Framing =
        busbar_contract_transport::wire::Framing::Stream;
    const SESSION: bool = true;
    const SESSION_BOUND: bool = true;
    const UNIT0_TRIGGER: Option<Unit0Trigger> = Some(Unit0Trigger::Upgrade);
    const UPGRADES_TO: &'static [&'static str] = &[];
    const HANDSHAKE_TRIGGER: Option<busbar_contract_transport::wire::HandshakeTrigger> = None;
    const TRANSPORT_FACTS: &'static [&'static str] = &[tfacts::PATH, tfacts::PEER];
    const DECODES_PAYLOAD: bool = false;
    // "frames after the upgrade carry no status leg" — the transports table's own words for this
    // row.
    const STATUS_CLASS: Option<busbar_contract_transport::wire::StatusAt> = None;
    const STATUS_NAMESPACE: Option<&'static str> = None;
}
