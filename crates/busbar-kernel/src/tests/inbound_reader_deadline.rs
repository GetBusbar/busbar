// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

struct Reader {
    receive: Mutex<Option<futures::channel::oneshot::Receiver<()>>>,
    dropped: Arc<AtomicUsize>,
}

struct Waiting {
    receive: futures::channel::oneshot::Receiver<()>,
    dropped: Arc<AtomicUsize>,
}

impl Future for Waiting {
    type Output = VerifyAnswer;
    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        Pin::new(&mut self.receive)
            .poll(cx)
            .map(|_| VerifyAnswer::from(Verified::Reject))
    }
}
impl Verifying for Waiting {
    fn settled(&mut self) -> Option<VerifyAnswer> {
        None
    }
}
impl Drop for Waiting {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::SeqCst);
    }
}
impl AuthCalls for Reader {
    fn name(&self) -> &str {
        "parked-reader"
    }
    fn facts(&self) -> u32 {
        0
    }
    fn inbound_points(&self) -> AuthPoints {
        AuthPoints::HEAD_BODY
    }
    fn verify_now(&self, _: &VerifyRequest) -> Option<VerifyAnswer> {
        None
    }
    fn verify(&self, _: VerifyRequest) -> Box<dyn Verifying> {
        Box::new(Waiting {
            receive: self
                .receive
                .lock()
                .unwrap()
                .take()
                .expect("one signed verification"),
            dropped: Arc::clone(&self.dropped),
        })
    }
    fn refresh(&self) -> Result<u64, String> {
        Ok(0)
    }
}

#[tokio::test(start_paused = true)]
async fn a_pending_signed_reader_is_stopped_at_the_operations_deadline() {
    let (send, receive) = futures::channel::oneshot::channel();
    let dropped = Arc::new(AtomicUsize::new(0));
    let reader = Arc::new(Reader {
        receive: Mutex::new(Some(receive)),
        dropped: Arc::clone(&dropped),
    });
    let gov = signing_gov();
    let k = reader_kit(&gov, reader, true);
    let walk = k
        .inbound
        .prepare(Call {
            owner: OWNER,
            generation: GEN,
            auth: k.id(MESSAGES),
            unit: UnitRef::NONE,
            point: POINT_HEAD_BODY,
            conn: 1,
            stream: 1,
            framing: 1,
            head: signed_head(),
            body: Some(b"{}".to_vec()),
            deadline: Some(
                tokio::time::Instant::now().into_std() + std::time::Duration::from_secs(5),
            ),
        })
        .unwrap();
    tokio::pin!(walk);
    let initially_pending = matches!(futures::poll!(walk.as_mut()), std::task::Poll::Pending);
    tokio::time::advance(std::time::Duration::from_secs(5)).await;
    let at_deadline = match futures::poll!(walk.as_mut()) {
        std::task::Poll::Ready(answer) => Some(answer),
        std::task::Poll::Pending => None,
    };
    let expired = at_deadline.is_some();
    // Release before assertions, including on the unfixed implementation.
    let _ = send.send(());
    let answer = match at_deadline {
        Some(answer) => answer,
        None => walk.await,
    }
    .unwrap();
    k.inbound.exit(answer.unit.id);
    assert!(initially_pending);
    assert!(expired, "the signed reader ignored the operation deadline");
    assert_eq!(answer.flow, FLOW_STOP);
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
}
