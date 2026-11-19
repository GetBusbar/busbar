// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::framed_stream::session::{Act, Actions, Flow, Slots, Task};
use busbar_contract::response_delivery::{CompletionRequirement, DeliveryTerminal, ResponseKey};
use busbar_kernel::limits::process_admission::{AdmissionClass, ProcessAdmission};
use std::collections::VecDeque;
use std::time::Duration;
use tokio::io::AsyncReadExt;

fn owner() -> (
    StorageSource,
    DeliveryLedger,
    crate::response_delivery::ResponseHandles,
) {
    let source = ProcessAdmission::new(1).connection_storage(AdmissionClass::Data);
    let mut ledger =
        DeliveryLedger::new(&source, 32.try_into().unwrap(), 4.try_into().unwrap()).unwrap();
    let key = ResponseKey {
        node: 1,
        incarnation: 1,
        unit: None,
        connection_generation: 1,
        stream: 1,
    };
    let handles = ledger.admit(key).unwrap();
    handles.release.freeze(key, 1).unwrap();
    handles.release.publish(key, 1).unwrap();
    assert!(matches!(
        ledger.next_control(),
        Some(DeliveryControl::Release { stream: 1 })
    ));
    handles.input.producer_ended();
    handles.input.reader_eof();
    assert!(ledger.next_control().is_none());
    (source, ledger, handles)
}

fn task() -> Task {
    Task {
        slots: Slots::default(),
        pending: VecDeque::new(),
        reading: true,
        wake_at: None,
    }
}

fn answer(source: &StorageSource, stream: u64) -> Actions {
    let mut acts = Actions::new(source).unwrap();
    acts.part(1, WireClass::Payload, b"body").unwrap();
    acts.push(Act::WireEnd {
        stream,
        requirement: CompletionRequirement::Flush,
    })
    .unwrap();
    acts.push(Act::Quiescent(1)).unwrap();
    acts
}

#[tokio::test]
async fn real_raw_prefix_and_flush_join_response_completion() {
    let (source, ledger, handles) = owner();
    let (stream, mut peer) = tokio::io::duplex(64);
    let raw = crate::raw_progress::test_carrier(stream);
    let progress = raw.progress();
    let mut io = DeliveryIo::new(raw, Delivery::new(ledger, progress), source.clone());
    assert!(matches!(
        task()
            .apply(
                &mut answer(&source, 1),
                &mut io,
                Duration::from_secs(1),
                &mut None
            )
            .await,
        Flow::Go
    ));
    let mut bytes = [0; 4];
    peer.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"body");
    assert!(handles.watch.snapshot().first_payload_written);
    assert_eq!(
        handles.watch.snapshot().terminal,
        Some(DeliveryTerminal::Complete)
    );
    drop(io);
    assert_eq!(
        handles.watch.snapshot().terminal,
        Some(DeliveryTerminal::Complete)
    );
}

#[tokio::test]
async fn malformed_late_fence_prevents_the_entire_answer_from_writing() {
    let (source, ledger, handles) = owner();
    let (stream, mut peer) = tokio::io::duplex(64);
    let raw = crate::raw_progress::test_carrier(stream);
    let progress = raw.progress();
    let mut io = DeliveryIo::new(raw, Delivery::new(ledger, progress.clone()), source.clone());
    assert!(matches!(
        task()
            .apply(
                &mut answer(&source, 99),
                &mut io,
                Duration::from_secs(1),
                &mut None
            )
            .await,
        Flow::Rejected(ResponseStop::Integrity)
    ));
    assert_eq!(progress.snapshot().written_plaintext, 0);
    drop(io);
    let mut byte = [0];
    assert_eq!(peer.read(&mut byte).await.unwrap(), 0);
    assert!(!handles.watch.snapshot().first_payload_written);
    assert!(matches!(
        handles.watch.snapshot().terminal,
        Some(DeliveryTerminal::Failed(_))
    ));
}

struct OuterError<S>(S);
impl<S: AsyncWrite + Unpin> AsyncWrite for OuterError<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.get_mut().0).poll_write(cx, &bytes[..1]) {
            Poll::Ready(Ok(_)) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            other => other,
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn outer_error_preserves_actual_prefix_before_writer_retirement() {
    let (source, ledger, handles) = owner();
    let (stream, mut peer) = tokio::io::duplex(64);
    let raw = crate::raw_progress::test_carrier(stream);
    let progress = raw.progress();
    let mut io = DeliveryIo::new(
        OuterError(raw),
        Delivery::new(ledger, progress),
        source.clone(),
    );
    assert!(matches!(
        task()
            .apply(
                &mut answer(&source, 1),
                &mut io,
                Duration::from_secs(1),
                &mut None
            )
            .await,
        Flow::Lost(_)
    ));
    assert!(handles.watch.snapshot().first_payload_written);
    assert_eq!(
        handles.watch.snapshot().terminal,
        None,
        "error alone has not retired the writer"
    );
    drop(io);
    let mut got = Vec::new();
    peer.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"b");
    assert!(matches!(
        handles.watch.snapshot().terminal,
        Some(DeliveryTerminal::Failed(_))
    ));
}
