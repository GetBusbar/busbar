// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! TOPOLOGY A — the BROWSER WebRTC SIDEBAND (design §5).
//!
//! busbar attaches to the session over a persistent WSS keyed by `call_id`, OWNING tools + instructions
//! (the locked [`SessionConfig`]). It mints the ephemeral client-secret the browser uses to establish
//! the media path DIRECTLY with the provider: media flows peer-to-peer, and only auth + the SDP
//! handshake + the sideband control transit busbar. busbar's role is MINT/GUARD + sideband control,
//! NOT a media relay — modelled here by a [`Carrier::sideband`] that relays no downlink audio.

use crate::ir::codec::{DuplexReader, DuplexWriter};
use crate::ir::config::SessionConfig;
use crate::runtime::carrier::Carrier;
use crate::runtime::scope::SessionHandle;
use crate::runtime::session::{SessionCore, VoiceSession};
use crate::runtime::VoiceRuntime;
use crate::topology::{begin_session, SessionBudget, StartError};
use async_trait::async_trait;
use std::sync::Arc;

/// AN EPHEMERAL CLIENT SECRET the browser presents to the provider to open its own media session — the
/// short-lived token busbar mints so the long-lived provider key never reaches the browser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EphemeralToken {
    /// The opaque secret value handed to the browser.
    pub value: String,
    /// Unix seconds after which the secret is rejected.
    pub expires_at_unix: u64,
}

/// Why minting an ephemeral client secret failed.
#[derive(Debug)]
pub enum MintError {
    /// The provider's client-secret endpoint refused or was unreachable.
    Provider(String),
}

impl std::fmt::Display for MintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MintError::Provider(m) => write!(f, "ephemeral token mint failed: {m}"),
        }
    }
}

impl std::error::Error for MintError {}

/// MINTS the ephemeral client secret via the provider's client-secret endpoint — dependency-inverted
/// so the composition root binds the real HTTPS call (no network dep leaks into the plane) while tests
/// bind a fake. The minted secret is scoped to the SAME locked config busbar governs.
#[async_trait]
pub trait TokenMinter: Send + Sync {
    /// Mint an ephemeral client secret for a browser session governed by `config`.
    async fn mint(&self, config: &SessionConfig) -> Result<EphemeralToken, MintError>;
}

/// Why attaching a sideband session failed.
#[derive(Debug)]
pub enum AttachError {
    /// The session could not begin (lease refused / durable open failed).
    Start(StartError),
    /// The ephemeral token could not be minted.
    Mint(MintError),
}

impl std::fmt::Display for AttachError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttachError::Start(e) => write!(f, "{e}"),
            AttachError::Mint(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for AttachError {}

/// AN ATTACHED SIDEBAND SESSION — everything busbar holds after the sideband is bound: the ephemeral
/// token to hand the browser, the [`VoiceSession`] plane to serve over the sideband WSS, its shared
/// [`SessionCore`], and the durable [`SessionHandle`] to close at teardown.
pub struct Attached<C> {
    /// The ephemeral client secret to return to the browser.
    pub token: EphemeralToken,
    /// The sideband control plane — serve it over the persistent WSS the plane opens THROUGH the neutral
    /// guarded WS transport ([`crate::topology::dial_provider`] → `serve_messages`); the plane holds no
    /// socket of its own.
    pub session: VoiceSession<C>,
    /// The shared session core (metering, tools, barge-in).
    pub core: Arc<SessionCore<C>>,
    /// The durable session binding to close at teardown.
    pub handle: SessionHandle,
}

/// ATTACH a browser WebRTC sideband session: lock the plane's `instructions` + `tools` into the
/// [`SessionConfig`], begin the governed session (lease + durable handle), and mint the ephemeral token
/// scoped to that locked config. The returned [`Attached::session`] is served over the persistent WSS;
/// media never transits busbar (the sideband carrier relays no audio).
#[allow(clippy::too_many_arguments)]
pub async fn attach<C, M>(
    rt: &VoiceRuntime,
    minter: &M,
    codec: C,
    owner: impl Into<String>,
    call_id: impl Into<String>,
    locked_config: SessionConfig,
    budget: SessionBudget,
    now: u64,
) -> Result<Attached<C>, AttachError>
where
    C: DuplexReader + DuplexWriter + Send + Sync + 'static,
    M: TokenMinter,
{
    // Mint the ephemeral secret scoped to the SAME config busbar will lock and re-apply.
    let token = minter
        .mint(&locked_config)
        .await
        .map_err(AttachError::Mint)?;

    // A sideband carrier: no downlink media relay — the browser's media path is peer-to-peer.
    let carrier = Carrier::sideband();
    let (core, handle) = begin_session(
        rt,
        codec,
        owner,
        call_id,
        Some(locked_config),
        carrier,
        budget,
        now,
    )
    .map_err(AttachError::Start)?;

    let session = VoiceSession::new(Arc::clone(&core));
    Ok(Attached {
        token,
        session,
        core,
        handle,
    })
}
