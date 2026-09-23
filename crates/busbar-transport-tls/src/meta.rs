// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What this transport declares about itself.
//!
//! Everything here is an associated constant, because everything here is read once at registration
//! and sealed. Held as the kind's own `meta.rs` (`PLUGIN-TREE.md` §3) so two siblings of the
//! transport kind are indistinguishable in shape.

use busbar_contract::transport::registry::facts as tfacts;
use busbar_contract::{Kind, Plugin, SelectorForm, TransportMeta};

use crate::claims;
use crate::TlsTransport;

impl Plugin for TlsTransport {
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

impl TransportMeta for TlsTransport {
    const KEY: &'static str = "tls";
    // `ClientCertSubject` is deliberately absent. The form reads a distinguished name off the
    // presented certificate, and this transport does not parse one: what it records is the
    // certificate's fingerprint, a real fact the handshake already established. Advertising the
    // form on a constant subject would mean every client certificate compares equal, so a
    // cert-subject distinction would collapse silently rather than fail — the form goes back on
    // this row the day the DN is parsed, and not before.
    const SELECTOR_FORMS: &'static [SelectorForm] = claims::SELECTOR_FORMS;
    const EGRESS_SELECTOR_FORMS: &'static [SelectorForm] = claims::EGRESS_SELECTOR_FORMS;
    const COMPOSES_OVER: &'static [&'static str] = &["tcp"];
    const HANDOFF: Option<busbar_contract::transport::wire::Handoff> = None;
    const FRAMING: busbar_contract::transport::wire::Framing =
        busbar_contract::transport::wire::Framing::Stream;
    const SESSION: bool = true;
    const SESSION_BOUND: bool = true;
    const UNIT0_TRIGGER: Option<busbar_contract::transport::wire::Unit0Trigger> =
        Some(busbar_contract::transport::wire::Unit0Trigger::FirstBytes);
    const UPGRADES_TO: &'static [&'static str] = &[];
    const HANDSHAKE_TRIGGER: Option<busbar_contract::transport::wire::HandshakeTrigger> = None;
    const TRANSPORT_FACTS: &'static [&'static str] = &[tfacts::SNI, tfacts::ALPN, tfacts::PEER];
    const DECODES_PAYLOAD: bool = false;
    const STATUS_CLASS: Option<busbar_contract::transport::wire::StatusAt> = None;
    const STATUS_NAMESPACE: Option<&'static str> = None;
}
