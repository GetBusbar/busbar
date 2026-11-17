// SPDX-License-Identifier: Apache-2.0
//! Bounded serializer metadata and lifecycle; never carrier delivery receipts.
use super::*;
use crate::kinds::transport::transport::{
    COMPLETE_FLUSH, COMPLETE_SHUTDOWN, ResponseAbort, StreamFlow, WIRE_CONTROL, WIRE_PAYLOAD,
    WireEnd, WirePart,
};
use hyper::serialization::{CompletionRequirement, SerializedClass, SerializedEvent};

#[derive(Debug)]
pub(super) struct Response {
    id: u64,
    deadline: u64,
    finished: bool,
    barrier: bool,
    released: bool,
    aborted: bool,
    quiescent: bool,
    input_end: bool,
    settled: bool,
    abort_pending: bool,
    quiet_pending: bool,
    release_waker: Option<Waker>,
}

pub(super) struct Plan {
    pub(super) responses: Vec<Response>,
    response_limit: usize,
    last_identity: u64,
    pub(super) queue: VecDeque<SerializedEvent>,
    span_limit: usize,
    spans: usize,
    pub(super) byte_limit: usize,
    pub(super) serialized: u64,
    pub(super) accepted: u64,
    pub(super) emitted: u64,
    pub(super) fault: bool,
}
impl Plan {
    fn response(&self, id: u64) -> Option<&Response> {
        self.responses.iter().find(|r| r.id == id)
    }
    fn response_mut(&mut self, id: u64) -> io::Result<&mut Response> {
        self.responses
            .iter_mut()
            .find(|r| r.id == id)
            .ok_or_else(invalid)
    }
    fn eligible(&self) -> u64 {
        let mut bytes = 0u64;
        for event in &self.queue {
            match event {
                SerializedEvent::Span { len, .. } => bytes += len,
                SerializedEvent::ReleaseBarrier { stream } => {
                    if !self
                        .response(*stream)
                        .is_some_and(|r| r.released && !r.aborted)
                    {
                        break;
                    }
                }
                _ => {}
            }
        }
        bytes.min(self.accepted - self.emitted)
    }
    fn retire(&mut self) {
        self.responses.retain(|r| {
            !(r.quiescent
                && r.input_end
                && r.settled
                && !r.abort_pending
                && !r.quiet_pending
                && !self.queue.iter().any(|e| identity(e) == r.id))
        });
    }
    pub(super) fn drain(
        &mut self,
        bytes: &mut busbar_secure::SecureVec,
        out: &mut impl Writer,
    ) -> Result<(), Full> {
        if self.fault {
            return Err(Full);
        }
        for r in &mut self.responses {
            if r.abort_pending {
                out.put_pod(
                    tag::RESPONSE_ABORT,
                    &ResponseAbort {
                        stream: r.id,
                        code: 1,
                        _r: 0,
                    },
                )?;
                r.abort_pending = false;
            }
            if r.quiet_pending {
                out.put_pod(tag::RESPONSE_QUIESCENT, &StreamFlow { stream: r.id })?;
                r.quiet_pending = false;
            }
        }
        while let Some(event) = self.queue.front().copied() {
            match event {
                SerializedEvent::ReleaseBarrier { stream } => {
                    if !self
                        .response(stream)
                        .is_some_and(|r| r.released && !r.aborted)
                    {
                        break;
                    }
                    self.queue.pop_front();
                }
                SerializedEvent::Span { stream, class, len } => {
                    if bytes.is_empty() {
                        break;
                    }
                    let mut n = len.min(bytes.len() as u64).min(WRITE_CHUNK as u64) as usize;
                    loop {
                        let result = out.put_pod_tail(
                            tag::WIRE_PART,
                            &WirePart {
                                stream,
                                class: match class {
                                    SerializedClass::Control => WIRE_CONTROL,
                                    SerializedClass::Payload => WIRE_PAYLOAD,
                                },
                                _r: 0,
                            },
                            &bytes.as_slice()[..n],
                        );
                        match result {
                            Ok(()) => break,
                            Err(Full) if n > 1 => n /= 2,
                            Err(Full) => return Err(Full),
                        }
                    }
                    bytes.consume(n);
                    self.emitted += n as u64;
                    if n as u64 == len {
                        self.queue.pop_front();
                        self.spans -= 1;
                    } else if let Some(SerializedEvent::Span { len, .. }) = self.queue.front_mut() {
                        *len -= n as u64;
                    }
                }
                SerializedEvent::End {
                    stream,
                    requirement,
                } => {
                    out.put_pod(
                        tag::WIRE_END,
                        &WireEnd {
                            stream,
                            requirement: match requirement {
                                CompletionRequirement::Flush => COMPLETE_FLUSH,
                                CompletionRequirement::Shutdown => COMPLETE_SHUTDOWN,
                            },
                            _r: 0,
                        },
                    )?;
                    self.queue.pop_front();
                }
                _ => unreachable!("lifecycle facts use reserved slots"),
            }
        }
        self.retire();
        Ok(())
    }
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid serialization provenance",
    )
}
fn identity(event: &SerializedEvent) -> u64 {
    match event {
        SerializedEvent::Span { stream, .. }
        | SerializedEvent::ReleaseBarrier { stream }
        | SerializedEvent::End { stream, .. }
        | SerializedEvent::Abort { stream }
        | SerializedEvent::Quiescent { stream } => *stream,
    }
}

/// A connection's bounded serialization plan and reserved response lifecycles.
#[derive(Clone)]
pub struct Provenance {
    shared: Arc<Shared>,
}
impl std::fmt::Debug for Provenance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Provenance")
    }
}
impl Provenance {
    /// Current caller-supplied monotonic time, without consulting a local clock.
    pub fn now(&self) -> u64 {
        self.shared.now_ns.load(Ordering::Acquire)
    }

    fn with<T>(&self, f: impl FnOnce(&mut Plan) -> io::Result<T>) -> io::Result<T> {
        let mut pipes = lock(&self.shared.pipes);
        let plan = pipes.plan.as_mut().ok_or_else(invalid)?;
        if plan.fault {
            return Err(invalid());
        }
        let result = f(plan);
        if result.is_err() {
            plan.fault = true;
        }
        result
    }
    /// Reserve lifecycle credit before exposing a request to the host.
    pub fn admit(&self, id: u64, deadline: u64) -> io::Result<()> {
        self.with(|p| {
            if id <= p.last_identity
                || p.responses.len() == p.response_limit
                || p.response(id).is_some()
            {
                return Err(invalid());
            }
            p.last_identity = id;
            p.responses.push(Response {
                id,
                deadline,
                finished: false,
                barrier: false,
                released: false,
                aborted: false,
                quiescent: false,
                input_end: false,
                settled: false,
                abort_pending: false,
                quiet_pending: false,
                release_waker: None,
            });
            Ok(())
        })
    }
    /// Atomically reserve the whole metadata batch before bytes reach MemIo.
    pub fn record(&self, events: &[SerializedEvent]) -> io::Result<()> {
        self.with(|p| {
            let mut serialized = p.serialized;
            let mut spans = p.spans;
            let mut descriptors = p.queue.len();
            for (index, e) in events.iter().enumerate() {
                let id = identity(e);
                if id != 0 && p.response(id).is_none() {
                    return Err(invalid());
                }
                // Earlier entries in this same batch are provisional state.
                // Validate against them without committing a partial prefix.
                let prior_end = events[..index].iter().any(|e| {
                    matches!(e, SerializedEvent::End { stream, .. } if *stream == id)
                });
                let prior_abort = events[..index].iter().any(|e| {
                    matches!(e, SerializedEvent::Abort { stream } if *stream == id)
                });
                let prior_quiet = events[..index].iter().any(|e| {
                    matches!(e, SerializedEvent::Quiescent { stream } if *stream == id)
                });
                match e {
                    SerializedEvent::Span { stream, class, len } => {
                        if prior_end
                            || prior_quiet
                            || p.response(*stream).is_some_and(|r| r.finished || r.quiescent)
                            || *len == 0
                            || (*stream == 0 && *class == SerializedClass::Payload)
                        {
                            return Err(invalid());
                        }
                        serialized = serialized.checked_add(*len).ok_or_else(invalid)?;
                        spans = spans.checked_add(1).ok_or_else(invalid)?;
                        descriptors = descriptors.checked_add(1).ok_or_else(invalid)?;
                    }
                    SerializedEvent::End { stream, .. } => {
                        if prior_end
                            || prior_abort
                            || prior_quiet
                            || *stream == 0
                            || p.response(*stream)
                                .is_some_and(|r| r.finished || r.aborted || r.quiescent)
                        {
                            return Err(invalid());
                        }
                        descriptors = descriptors.checked_add(1).ok_or_else(invalid)?;
                    }
                    SerializedEvent::ReleaseBarrier { stream } => {
                        if prior_end
                            || prior_abort
                            || prior_quiet
                            || *stream == 0
                            || p.response(*stream).is_some_and(|r| {
                                r.barrier || r.finished || r.aborted || r.quiescent
                            })
                            || events[..index].iter().any(|e| {
                                matches!(e, SerializedEvent::ReleaseBarrier { stream: prior } if prior == stream)
                            })
                        {
                            return Err(invalid());
                        }
                        descriptors = descriptors.checked_add(1).ok_or_else(invalid)?;
                    }
                    _ if id == 0 => return Err(invalid()),
                    _ => {}
                }
            }
            if spans > p.span_limit
                || descriptors > p.span_limit + 2 * p.response_limit
                || serialized - p.emitted > p.byte_limit as u64
            {
                return Err(invalid());
            }
            p.serialized = serialized;
            p.spans = spans;
            for e in events {
                match *e {
                    SerializedEvent::Abort { stream } => {
                        let r = p.response_mut(stream)?;
                        if !r.aborted {
                            r.aborted = true;
                            r.abort_pending = true;
                        }
                    }
                    SerializedEvent::Quiescent { stream } => {
                        let r = p.response_mut(stream)?;
                        if !r.quiescent {
                            r.quiescent = true;
                            r.quiet_pending = true;
                        }
                    }
                    SerializedEvent::End { stream, .. } => {
                        p.response_mut(stream)?.finished = true;
                        p.queue.push_back(*e);
                    }
                    SerializedEvent::ReleaseBarrier { stream } => {
                        p.response_mut(stream)?.barrier = true;
                        p.queue.push_back(*e);
                    }
                    _ => p.queue.push_back(*e),

                }
            }
            Ok(())
        })
    }
    /// Consume an independently audited release control; this never creates End.
    pub fn release(&self, id: u64) -> io::Result<()> {
        let waker = self.with(|p| {
            let r = p.response_mut(id)?;
            if r.aborted {
                return Ok(None);
            }
            r.released = true;
            Ok(r.release_waker.take())
        })?;
        if let Some(waker) = waker {
            waker.wake();
        }
        if let Some(waker) = lock(&self.shared.pipes).writer.take() {
            waker.wake();
        }
        Ok(())
    }
    /// Record the real ordered input end independently of serializer completion.
    pub fn input_end(&self, id: u64) -> io::Result<()> {
        self.with(|p| {
            p.response_mut(id)?.input_end = true;
            p.retire();
            Ok(())
        })
    }
    /// Host acknowledgement of a frozen joined delivery terminal; no receipt is minted here.
    pub fn settled(&self, id: u64) -> io::Result<()> {
        self.with(|p| {
            p.response_mut(id)?.settled = true;
            p.retire();
            Ok(())
        })
    }
    /// Cancel input and prevent an unconsumed release from opening its gate.
    pub fn cancel(&self, id: u64) -> io::Result<()> {
        self.record(&[SerializedEvent::Abort { stream: id }])?;
        self.input_end(id)?;
        let wake = self.with(|p| Ok(p.response_mut(id)?.release_waker.take()))?;
        if let Some(wake) = wake {
            wake.wake();
        }
        Ok(())
    }
    /// Whether this response still owns its admitted lifecycle slot.
    pub fn is_live(&self, id: u64) -> bool {
        self.with(|p| Ok(p.response(id).is_some())).unwrap_or(false)
    }
    /// Whether the actual serializer has produced successful End.
    pub fn finished(&self, id: u64) -> bool {
        self.with(|p| Ok(p.response(id).is_some_and(|r| r.finished)))
            .unwrap_or(false)
    }
    /// Whether the bounded metadata plan has failed closed.
    pub fn faulted(&self) -> bool {
        lock(&self.shared.pipes)
            .plan
            .as_ref()
            .is_none_or(|p| p.fault)
    }
    /// Configured maximum simultaneous live response lifecycles.
    pub fn response_capacity(&self) -> usize {
        lock(&self.shared.pipes)
            .plan
            .as_ref()
            .map_or(0, |p| p.response_limit)
    }
    /// Accepted bytes before the first unopened terminal gate.
    pub fn eligible_bytes(&self) -> u64 {
        self.with(|p| Ok(p.eligible())).unwrap_or(0)
    }
    /// Earliest absolute deadline among live response lifecycles.
    pub fn deadline(&self) -> Option<u64> {
        self.with(|p| Ok(p.responses.iter().map(|r| r.deadline).min()))
            .ok()
            .flatten()
    }
    /// Poll authorization, storing one waker in the existing response slot.
    pub fn poll_release(&self, id: u64, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.with(|p| {
            let r = p.response_mut(id)?;
            if r.aborted {
                return Ok(None);
            }
            if r.released {
                return Ok(Some(true));
            }
            if r.release_waker
                .as_ref()
                .is_none_or(|w| !w.will_wake(cx.waker()))
            {
                r.release_waker = Some(cx.waker().clone());
            }
            Ok(Some(false))
        }) {
            Ok(Some(true)) => Poll::Ready(Ok(())),
            Ok(Some(false)) => Poll::Pending,
            Ok(None) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}
impl MemIo {
    /// Emit the ordered physical-close request only after the complete eligible
    /// byte/metadata prefix has left the plugin. Lifecycle slots remain callable.
    pub fn flush_attributed_close(&mut self, out: &mut impl Writer) -> Result<bool, Full> {
        let mut pipes = lock(&self.shared.pipes);
        let ready = pipes.shut
            && pipes.write.is_empty()
            && !pipes.close_reported
            && pipes
                .plan
                .as_ref()
                .is_some_and(|p| !p.fault && p.queue.is_empty());
        if ready {
            out.put_pod(
                tag::CLOSE,
                &crate::kinds::transport::transport::CloseRec {
                    how: crate::kinds::transport::transport::CLOSE_GRACEFUL,
                    _r: 0,
                },
            )?;
            pipes.close_reported = true;
        }
        Ok(ready)
    }

    /// Install attributed mode before the first protocol write. All allowances
    /// are reserved once; descriptor or byte exhaustion fails the connection.
    pub fn attributed_output(
        &mut self,
        responses: usize,
        spans: usize,
        bytes: usize,
    ) -> Provenance {
        let mut pipes = lock(&self.shared.pipes);
        assert!(pipes.write.is_empty() && pipes.plan.is_none());
        let descriptors = responses
            .checked_mul(2)
            .and_then(|n| n.checked_add(spans))
            .expect("metadata allowance overflow");
        pipes.plan = Some(Plan {
            responses: Vec::with_capacity(responses),
            response_limit: responses,
            last_identity: 0,
            queue: VecDeque::with_capacity(descriptors),
            span_limit: spans,
            spans: 0,
            byte_limit: bytes,
            serialized: 0,
            accepted: 0,
            emitted: 0,
            fault: false,
        });
        Provenance {
            shared: self.shared.clone(),
        }
    }
    /// Whether attributed output has failed closed.
    pub fn provenance_faulted(&self) -> bool {
        lock(&self.shared.pipes)
            .plan
            .as_ref()
            .is_some_and(|p| p.fault)
    }
}

impl Provenance {
    /// Whether an answer can emit a finite prefix now. A closed gate alone is
    /// not ready work and must never arm an immediate repeating timer.
    pub fn has_eligible_output(&self) -> bool {
        let pipes = lock(&self.shared.pipes);
        let Some(p) = &pipes.plan else {
            return false;
        };
        if p.responses
            .iter()
            .any(|r| r.abort_pending || r.quiet_pending)
        {
            return true;
        }
        for e in &p.queue {
            match e {
                SerializedEvent::ReleaseBarrier { stream } => {
                    if !p
                        .response(*stream)
                        .is_some_and(|r| r.released && !r.aborted)
                    {
                        return false;
                    }
                }
                SerializedEvent::Span { .. } => return p.accepted > p.emitted,
                SerializedEvent::End { .. } => return true,
                _ => {}
            }
        }
        pipes.shut && !pipes.close_reported && pipes.write.is_empty()
    }
}
impl MemIo {
    /// Drain only attributed output. `false` means answer capacity retained a
    /// suffix; already-written records remain a valid prefix of this answer.
    /// The caller reserves its useful continuation wake before draining.
    pub fn flush_attributed(&mut self, out: &mut impl Writer) -> io::Result<bool> {
        let mut pipes = lock(&self.shared.pipes);
        if pipes.plan.as_ref().is_none_or(|p| p.fault) {
            return Err(invalid());
        }
        let before = pipes.write.len();
        let Pipes { plan, write, .. } = &mut *pipes;
        let done = plan.as_mut().ok_or_else(invalid)?.drain(write, out).is_ok();
        if pipes.write.len() < before {
            if let Some(waker) = pipes.writer.take() {
                waker.wake();
            }
        }
        Ok(done)
    }
    /// Earliest executor continuation or real protocol timer, without emitting it.
    pub fn next_wake(&self) -> Option<u64> {
        if self.budget_out {
            Some(self.shared.now_ns.load(Ordering::Acquire))
        } else {
            self.earliest()
        }
    }
}
