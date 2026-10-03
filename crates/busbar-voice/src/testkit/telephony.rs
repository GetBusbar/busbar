// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE PHONE CALL over a [`TelephonyProxy`], driven the way the carrier drives it: the caller speaks
//! Twilio Media Streams (`connected`, `start`, `media`, `stop`), the far end the realtime dialect.
//! Four in-memory channels stand in for the two sockets. Every wait is bounded, so a proxy that
//! never relays reads as an empty leg rather than a hung test, and both sockets are closed at the
//! end whatever happened.

use crate::ir::codec::{DuplexReader, DuplexWriter};
use crate::topology::telephony::TelephonyProxy;
use futures::channel::mpsc::{unbounded, UnboundedReceiver};
use futures::StreamExt;
use std::time::Duration;

/// The stream identifier the call's `start` names, and every `media` frame repeats.
pub const STREAM_SID: &str = "MZ-call";

/// The far end's reply: three bytes of µ-law, which base64 spells `////`.
pub const FAR_END_AUDIO: &[u8] = &[0xff; 3];
const FAR_END_DELTA: &str = "////";

/// How long the driver waits for one frame to cross before it gives up on it.
const WAIT: Duration = Duration::from_secs(2);

/// What crossed each socket during the call, as JSON, in order.
#[derive(Debug, Default)]
pub struct CallLegs {
    /// Every frame the far end received.
    pub to_far_end: Vec<serde_json::Value>,
    /// Every frame the caller received.
    pub to_caller: Vec<serde_json::Value>,
}

fn frame(v: &serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(v).expect("a JSON value serializes")
}

fn parsed(f: &[u8]) -> serde_json::Value {
    serde_json::from_slice(f).unwrap_or(serde_json::Value::Null)
}

/// Wait (bounded) for a frame on `rx` that `wanted` accepts, keeping every frame seen on `seen`.
async fn wait_for(
    rx: &mut UnboundedReceiver<Vec<u8>>,
    seen: &mut Vec<serde_json::Value>,
    wanted: impl Fn(&serde_json::Value) -> bool,
) {
    loop {
        match tokio::time::timeout(WAIT, rx.next()).await {
            Ok(Some(f)) => {
                let v = parsed(&f);
                let hit = wanted(&v);
                seen.push(v);
                if hit {
                    return;
                }
            }
            Ok(None) | Err(_) => return,
        }
    }
}

/// PLACE ONE CALL: the caller connects, starts the stream in `g711_ulaw`, and speaks `caller_audio`
/// (raw µ-law) as one `media` frame; once the far end has heard it, the far end answers with
/// [`FAR_END_AUDIO`] as one realtime audio delta; once the caller has received it, the caller hangs
/// up with `stop`. The far end's socket stays open throughout: the call ends on the caller's `stop`.
pub async fn place_call<C>(proxy: TelephonyProxy<C>, caller_audio: &[u8]) -> CallLegs
where
    C: DuplexReader + DuplexWriter + Send + Sync + 'static,
{
    let (prov_in_tx, prov_in_rx) = unbounded::<Vec<u8>>();
    let (prov_out_tx, mut prov_out_rx) = unbounded::<Vec<u8>>();
    let (cli_in_tx, cli_in_rx) = unbounded::<Vec<u8>>();
    let (cli_out_tx, mut cli_out_rx) = unbounded::<Vec<u8>>();
    let mut legs = CallLegs::default();

    let caller = {
        let legs = &mut legs;
        let (prov_out_rx, cli_out_rx) = (&mut prov_out_rx, &mut cli_out_rx);
        async move {
            for v in [
                serde_json::json!({"event": "connected", "protocol": "Call", "version": "1.0.0"}),
                serde_json::json!({"event": "start", "streamSid": STREAM_SID, "start": {
                    "streamSid": STREAM_SID, "callSid": "CA-call",
                    "mediaFormat": {"encoding": "audio/x-mulaw", "sampleRate": 8000, "channels": 1}
                }}),
            ] {
                let _ = cli_in_tx.unbounded_send(frame(&v));
            }
            let _ = cli_in_tx.unbounded_send(
                crate::topology::twilio::TwilioEnvelope::encode_media(STREAM_SID, caller_audio),
            );
            wait_for(prov_out_rx, &mut legs.to_far_end, |v| {
                v["type"] == "input_audio_buffer.append"
            })
            .await;
            let _ = prov_in_tx.unbounded_send(frame(&serde_json::json!({
                "type": "response.output_audio.delta",
                "delta": FAR_END_DELTA,
            })));
            wait_for(cli_out_rx, &mut legs.to_caller, |v| v["event"] == "media").await;
            let _ = cli_in_tx.unbounded_send(frame(&serde_json::json!({
                "event": "stop", "streamSid": STREAM_SID
            })));
            // A proxy that does not end the call on `stop` still ends when both sockets do.
            tokio::time::sleep(WAIT).await;
            drop(cli_in_tx);
            drop(prov_in_tx);
        }
    };
    let call = proxy.run(prov_in_rx, prov_out_tx, cli_in_rx, cli_out_tx);
    // The caller's script may still be sleeping when the call ends: the call is what the legs read.
    tokio::select! {
        () = call => {}
        () = async { caller.await; std::future::pending::<()>().await } => {}
    }

    prov_out_rx.close();
    while let Some(f) = prov_out_rx.next().await {
        legs.to_far_end.push(parsed(&f));
    }
    cli_out_rx.close();
    while let Some(f) = cli_out_rx.next().await {
        legs.to_caller.push(parsed(&f));
    }
    legs
}
