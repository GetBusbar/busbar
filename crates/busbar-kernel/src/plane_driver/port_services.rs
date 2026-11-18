// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The kernel services the core-resolved intents run on (IF §12.1, §12.11): what [`KernelIntents`] holds beside
//! its records, push queue and signals. A service not installed answers its fail-closed value (no grant, an
//! internal destination, a refused mint), never an unchecked yes.
//!
//! [`KernelIntents`]: super::port_intents::KernelIntents

use std::sync::Arc;

use busbar_plugin_abi::host_side::caller::{BoxFut, Caller};
use tokio::runtime::Handle;

use super::plane_judge::PlaneJudge;
use super::port_channels::Held;
use crate::channels::ChannelMsg;
use crate::media::{MediaBridge, MediaRendezvous};
use crate::plane_grants::{Entitlements, HostSigner, Tickets};
use crate::plugin_records::RecordsDenied;

/// The services behind the intents. `Default` installs none.
#[derive(Clone, Default)]
pub struct Services {
    /// ENTITLE (§12.11).
    pub entitlements: Option<Arc<dyn Entitlements>>,
    /// JUDGE (§12.1).
    pub judge: Option<PlaneJudge>,
    /// MINT (§12.11).
    pub tickets: Option<Arc<dyn Tickets>>,
    /// SIGN (§12.11).
    pub signer: Option<Arc<dyn HostSigner>>,
    /// CONNECT (§12.12).
    pub connections:
        Option<Arc<crate::connections::StoreConnections<crate::plugin_records::StoreRecords>>>,
    /// SIGHT and TRUST (§12.14).
    pub trust:
        Option<Arc<crate::trust::plane_book::CoreTrustBook<crate::plugin_records::StoreRecords>>>,
    /// RENDEZVOUS (§12.13).
    pub media: Option<Arc<dyn MediaRendezvous>>,
    /// OBS_SCOPE and OBSERVE (§12.4).
    pub observations: Option<Arc<dyn UsageObservations>>,
}

/// One item of a TRUST_STATE answer, owned (the book's sink borrows end with the call).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustItemOwned {
    pub name: String,
    /// DISTRUST_* for this item.
    pub verdict: u32,
    pub approved: Option<[u8; 32]>,
    pub sighted: Option<[u8; 32]>,
}

/// Decoded from one OBSERVE (counts are (class, amount, scale) of declared classes).
pub struct ObservationIn<'a> {
    pub scope: [u8; 32],
    pub event: &'a [u8],
    pub component: &'a [u8],
    pub revision: Option<(&'a [u8], u64)>,
    pub state: u32,
    pub counts: &'a [(&'a str, u64, u32)],
    pub rated_subject: u32,
    pub evidence: &'a [u8],
}

/// The kernel's observation custody behind one trait (IF §12.4; the adapter over `host_observations.rs` and
/// `plane_driver/money/observations.rs` is the K8 owner's). Every call is durable before it returns (CoreStore
/// commit). `principal` = the request's identity records (ID_*); ATTACH and CLOSE succeed only for the principal
/// and price binding that created the scope.
pub trait UsageObservations: Send + Sync + 'static {
    /// OBS_SCOPE. Returns (OBS_READY | OBS_CLOSED | OBS_PENDING | OBS_REFUSED, the scope id for READY/CLOSED).
    /// `require`: classes that must be priced in the (original) binding, else OBS_REFUSED.
    fn scope<'a>(
        &'a self,
        plane: &'a Caller<'_>,
        principal: &'a [u8],
        op: u32,
        scope: Option<[u8; 32]>,
        require: &'a [&'a str],
    ) -> BoxFut<'a, (u32, Option<[u8; 32]>)>;
    /// OBSERVE. Returns (OBS_ACCEPTED with the receipt bytes | OBS_PENDING | OBS_REFUSED). Provisional
    /// observations update evidence and never post; final ones settle the component, revisions ordered by
    /// `revision_order` under operator policy.
    fn observe<'a>(
        &'a self,
        plane: &'a Caller<'_>,
        principal: &'a [u8],
        o: &'a ObservationIn<'a>,
    ) -> BoxFut<'a, (u32, Box<[u8]>)>;
}

/// A media session's bridge, held by the plane session under its exchange: dropping it closes the media session.
/// The streams it carries to and from the plane (FROM_CLIENT pieces, EX_MSG back) are the media pump's, not this
/// holder's: a message sent through it is refused.
pub struct MediaHeld {
    bridge: MediaBridge,
    rt: Handle,
}

impl MediaHeld {
    #[must_use]
    pub fn new(bridge: MediaBridge, rt: Handle) -> Self {
        Self { bridge, rt }
    }
}

impl Held for MediaHeld {
    fn send(&mut self, _message: &[u8], _ask: bool) -> Result<(), RecordsDenied> {
        Err(RecordsDenied::Invalid)
    }

    fn ready(&mut self, _tail: &[u8]) {}

    fn remote(&mut self, description: &str) -> Result<(), RecordsDenied> {
        self.rt.block_on(self.bridge.remote(description))
    }

    fn refusal(&self) -> Option<String> {
        self.bridge.refusal().map(str::to_owned)
    }

    fn recv(&mut self) -> BoxFut<'_, Option<ChannelMsg>> {
        Box::pin(async move {
            self.bridge.closed().await;
            Some(ChannelMsg::Ended)
        })
    }
}
