// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! TOPOLOGY B — the THIN TELEPHONY WS PROXY (design `plane4-duplex-session.md` §6).
//!
//! busbar sits between the telephony leg (the phone/carrier media stream) and the provider's Realtime
//! upstream, proxying frames both ways while metering, governing tools, and driving barge-in. It
//! chooses `g711_ulaw` END-TO-END so 8 kHz µ-law passes straight through with NO resample; the barge-in
//! truncate `audio_end_ms` is computed from the codec's playback marks (`DecodeState::flush_playback`)
//! and the queued outbound audio is flushed on `speech_started` — the truncate bookkeeping the codec
//! exposes, driven by [`crate::runtime::session::SessionCore`].
//!
//! WIRING. Two sockets, four directions. The provider socket's WRITE side is shared by two producers —
//! the downlink-facing [`VoiceSession`] (tool results / barge-in cancel) and the [`UplinkForwarder`]
//! (client audio → upstream) — so it is funnelled through one channel into a single writer. The client
//! socket's write side is the downlink, driven by the session [`Carrier`].

use crate::ir::codec::{DuplexReader, DuplexWriter};
use crate::ir::config::SessionConfig;
use crate::ir::media::AudioFormat;
use crate::runtime::carrier::Carrier;
use crate::runtime::scope::SessionHandle;
use crate::runtime::session::{SessionCore, UplinkForwarder, VoiceSession};
use crate::runtime::{LeaseCloseGuard, VoiceRuntime};
use crate::topology::{begin_session, SessionBudget, StartError};
use busbar_substrate::ingress::byte_duplex::serve_messages;
use futures::channel::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use futures::{Sink, Stream, StreamExt};
use std::sync::Arc;

/// THE LOCKED CONFIG for a telephony leg: `g711_ulaw` on BOTH the input and output audio formats so the
/// 8 kHz µ-law carrier passes straight through with no resample. Callers overlay their own
/// instructions/tools onto the returned config before locking it.
#[must_use]
pub fn g711_config() -> SessionConfig {
    SessionConfig {
        input_audio_format: Some(AudioFormat::G711Ulaw),
        output_audio_format: Some(AudioFormat::G711Ulaw),
        ..SessionConfig::default()
    }
}

/// A LIVE TELEPHONY PROXY — the two planes to serve (one per socket), the funnels between them, the
/// shared session core, and the durable handle. Build it with [`begin_telephony`]; drive it with
/// [`TelephonyProxy::run`].
pub struct TelephonyProxy<C> {
    /// The shared session core (metering, tools, barge-in).
    pub core: Arc<SessionCore<C>>,
    /// The durable session binding to close at teardown.
    pub handle: SessionHandle,
    /// The by-value D2 lease close guard — moved into [`TelephonyProxy::run`]'s frame so the reserve is
    /// closed deterministically on any exit, even when a parked handler pins `Arc<SessionCore>`.
    guard: LeaseCloseGuard,
    /// The downlink-facing plane — serve it over the PROVIDER socket.
    downlink_plane: Arc<VoiceSession<C>>,
    /// The uplink-facing plane — serve it over the CLIENT socket.
    uplink_plane: Arc<UplinkForwarder<C>>,
    /// The provider-write funnel receiver (both producers merge here).
    upstream_rx: UnboundedReceiver<Vec<u8>>,
    /// The provider-write funnel sender handed to the downlink plane's serve sink.
    upstream_tx: UnboundedSender<Vec<u8>>,
    /// The client-write (downlink) funnel receiver, fed by the session carrier.
    downlink_rx: UnboundedReceiver<Vec<u8>>,
}

/// BEGIN a telephony proxy: lock the `g711`-based config, open the governed session (lease + durable
/// handle), and build the two planes + the funnels between them. The provider/client sockets are bound
/// later by [`TelephonyProxy::run`].
#[allow(clippy::too_many_arguments)]
pub fn begin_telephony<C>(
    rt: &VoiceRuntime,
    codec: C,
    owner: impl Into<String>,
    call_id: impl Into<String>,
    locked_config: SessionConfig,
    budget: SessionBudget,
    meter: Option<crate::runtime::metering::TurnMeter>,
    now: u64,
) -> Result<TelephonyProxy<C>, StartError>
where
    C: DuplexReader + DuplexWriter + Send + Sync + 'static,
{
    // The client-write (downlink) funnel: the carrier relays server→client audio here.
    let (downlink_tx, downlink_rx) = unbounded::<Vec<u8>>();
    let carrier = Carrier::with_downlink(downlink_tx);

    let (core, handle, guard) = begin_session(
        rt,
        codec,
        owner,
        call_id,
        Some(locked_config),
        carrier,
        budget,
        meter,
        now,
    )?;

    // The provider-write funnel: both the downlink plane's `out` and the uplink forwarder merge here.
    let (upstream_tx, upstream_rx) = unbounded::<Vec<u8>>();
    let downlink_plane = Arc::new(VoiceSession::new(Arc::clone(&core)));
    let uplink_plane = Arc::new(UplinkForwarder::new(Arc::clone(&core), upstream_tx.clone()));

    Ok(TelephonyProxy {
        core,
        handle,
        guard,
        downlink_plane,
        uplink_plane,
        upstream_rx,
        upstream_tx,
        downlink_rx,
    })
}

impl<C> TelephonyProxy<C>
where
    C: DuplexReader + DuplexWriter + Send + Sync + 'static,
{
    /// The shared session core.
    #[must_use]
    pub fn core(&self) -> &Arc<SessionCore<C>> {
        &self.core
    }

    /// RUN the proxy until either socket ends OR the metering lease hard-closes the carrier. Binds the
    /// four socket halves — the PROVIDER pair is opened THROUGH the neutral guarded WS transport
    /// ([`crate::topology::dial_provider`], which resolves-then-pins-then-guards the upstream `wss://`),
    /// and the CLIENT pair is the telephony leg; the plane holds no socket plumbing, only these
    /// `Stream`/`Sink` halves:
    /// * `provider_in` / `provider_out` — the Realtime upstream (server→client in, client→server out).
    /// * `client_in` / `client_out` — the telephony leg (client audio in, downlink audio out).
    ///
    /// The provider-write funnel drains into `provider_out`; the downlink funnel drains into
    /// `client_out`. A hard close (budget dry) wins the `select!` and tears the session down.
    pub async fn run<PIn, POut, DIn, DOut>(
        self,
        provider_in: PIn,
        provider_out: POut,
        client_in: DIn,
        client_out: DOut,
    ) where
        PIn: Stream<Item = Vec<u8>> + Unpin,
        POut: Sink<Vec<u8>> + Unpin + Send + 'static,
        POut::Error: Send,
        DIn: Stream<Item = Vec<u8>> + Unpin,
        DOut: Sink<Vec<u8>> + Unpin + Send + 'static,
        DOut::Error: Send,
    {
        let TelephonyProxy {
            core,
            handle: _handle,
            guard,
            downlink_plane,
            uplink_plane,
            upstream_rx,
            upstream_tx,
            downlink_rx,
        } = self;

        // OWN the close guard in this frame: it drops when `run()` returns on ANY path — EOF, the
        // hard-close `select!` race below, or a panic unwinding through here — closing the D2 lease's
        // reserve deterministically, even if a parked-at-await handler still pins `Arc<SessionCore>`
        // (which would refcount-gate the settle handle's own `Drop` close and leak the reserve).
        let _lease_guard = guard;

        let carrier = core.carrier().clone();

        // The two writer drains run as detached tasks (their receivers/sinks are `Send + 'static`).
        // Each ends when ITS funnel's last sender drops — provider-write when both serve legs finish,
        // downlink when the session core (and its carrier) is dropped below.
        let up_drain = tokio::spawn(
            upstream_rx
                .map(Ok::<Vec<u8>, POut::Error>)
                .forward(provider_out),
        );
        let down_drain = tokio::spawn(
            downlink_rx
                .map(Ok::<Vec<u8>, DOut::Error>)
                .forward(client_out),
        );

        // Serve the provider socket: server→client events drive `on_server_frame`; `out` is the shared
        // provider-write funnel. Serve the client socket: client→server frames are forwarded to the
        // provider funnel; this socket's own write side is the downlink (driven by the carrier), so the
        // pump's sink discards — the uplink plane never writes through `out`.
        let up_serve = serve_messages(provider_in, upstream_tx, downlink_plane);
        let down_serve = serve_messages(client_in, futures::sink::drain(), uplink_plane);
        let serves = futures::future::join(up_serve, down_serve);

        // The marquee teardown: either both sockets reach EOF, or a hard close (budget dry) wins the
        // race and drops the serve futures (dropping the planes + the provider-write sender).
        tokio::select! {
            _ = serves => {}
            _ = carrier.closed() => {}
        }

        // Release the session so the downlink funnel's last sender (the carrier) drops and its drain
        // completes; then await both drains so queued frames are flushed to the sockets before return.
        drop(carrier);
        drop(core);
        let _ = up_drain.await;
        let _ = down_drain.await;
    }
}
