use super::*;
use crate::diagnostics::{diag_error, diag_warn, METERING_FLUSH_PARTIAL_FAILURE};
use busbar_contract::abi::store::OpId;

/// One raw count operation. Its identity and body remain together until acknowledgement.
#[derive(Clone)]
pub(super) struct MeteringWrite {
    op: Option<OpId>,
    delta: MeteringDelta,
}

impl MeteringWrite {
    fn new((key, counts): (MeterKey, MeterCounts)) -> Option<Self> {
        if counts.is_zero() {
            return None;
        }
        let (key_id, bucket, model, provider, priced_from_ms, key_group_at_use, pricing_version) =
            key;
        Some(Self {
            op: None,
            delta: MeteringDelta {
                key_id,
                bucket,
                model,
                provider,
                tokens_input: counts.tokens_input,
                tokens_output: counts.tokens_output,
                tokens_cache_read: counts.tokens_cache_read,
                tokens_cache_write: counts.tokens_cache_write,
                requests: counts.requests,
                billable_requests: counts.requests,
                key_group_at_use,
                pricing_version,
                priced_from_ms,
                usage_units: counts.usage_units,
            },
        })
    }

    #[cfg(test)]
    pub(super) fn counts(&self) -> MeterCounts {
        MeterCounts {
            requests: self.delta.requests,
            tokens_input: self.delta.tokens_input,
            tokens_output: self.delta.tokens_output,
            tokens_cache_read: self.delta.tokens_cache_read,
            tokens_cache_write: self.delta.tokens_cache_write,
            usage_units: self.delta.usage_units.clone(),
        }
    }
}

struct FlushOwner<'a>(&'a PendingMetering);
impl Drop for FlushOwner<'_> {
    fn drop(&mut self) {
        *self.0.flushing.lock().unwrap_or_else(|p| p.into_inner()) = None;
        self.0.flush_finished.notify_all();
    }
}

impl GovState {
    /// Flush one retained snapshot through an explicitly supported supplied-id operation.
    /// Store calls run without accumulator or flight locks. A skipped concurrent caller cannot
    /// cancel the active owner, and unwinding releases the runner while keeping its operation.
    pub(super) fn flush_metering_deduped(&self, shutdown: bool) -> usize {
        let pending = &self.pending_metering;
        let current = std::thread::current().id();
        let mut runner = pending.flushing.lock().unwrap_or_else(|p| p.into_inner());
        while let Some(owner) = *runner {
            if !shutdown {
                return 0;
            }
            if owner == current {
                drop(runner);
                diag_error!(
                    METERING_FLUSH_PARTIAL_FAILURE,
                    "shutdown metering flush reentered its own active store call; \
                     the unacknowledged operation remains retained"
                );
                return 0;
            }
            // WriteBehind operations have no I/O deadline. A final caller waits actual completion,
            // then owns the retry itself; returning while another thread runs is not a final flush.
            runner = pending
                .flush_finished
                .wait(runner)
                .unwrap_or_else(|p| p.into_inner());
        }
        *runner = Some(current);
        drop(runner);
        let _owner = FlushOwner(pending);
        let mut captured = false;
        {
            let mut flight = pending.flight.lock().unwrap_or_else(|p| p.into_inner());
            if flight.is_empty() {
                // Capture once per invocation. An uncertain snapshot never absorbs newer arrivals,
                // so outage storage is bounded by one snapshot plus the bounded pending shards.
                flight.extend(pending.drain().into_iter().filter_map(MeteringWrite::new));
                captured = true;
            }
        }
        let mut flushed = 0;
        loop {
            let write = {
                pending
                    .flight
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .front()
                    .cloned()
            };
            let Some(write) = write else {
                if shutdown && !captured {
                    // Finish fresh arrivals after a retained retry. At most one new snapshot is
                    // captured per invocation, after the previous one is fully acknowledged.
                    let mut flight = pending.flight.lock().unwrap_or_else(|p| p.into_inner());
                    flight.extend(pending.drain().into_iter().filter_map(MeteringWrite::new));
                    captured = true;
                    continue;
                }
                return flushed;
            };
            let op = write.op.unwrap_or_else(|| {
                // Mint only after raw custody is installed. Even an allocator initialization
                // panic must leave the unsent counts available to a later caller.
                let op = crate::door::op_id();
                pending
                    .flight
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .front_mut()
                    .expect("runner owns the retained front")
                    .op = Some(op);
                op
            });
            match self
                .store
                .add_metering_batch_deduped(op, std::slice::from_ref(&write.delta))
            {
                Ok(()) => {
                    // Only this runner retires a front operation, only after its real acknowledgement.
                    let acknowledged = pending
                        .flight
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .pop_front();
                    drop(acknowledged);
                    flushed += 1;
                }
                Err(error) => {
                    let retained = pending
                        .flight
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .len();
                    if shutdown {
                        let fresh: usize = pending
                            .shards
                            .iter()
                            .map(|shard| shard.lock().unwrap_or_else(|p| p.into_inner()).len())
                            .sum();
                        diag_error!(
                            METERING_FLUSH_PARTIAL_FAILURE,
                            failed = retained + fresh,
                            fresh,
                            flushed,
                            key = %write.delta.key_id,
                            error = %error,
                            "shutdown metering flush: {retained} retained operation(s) remain \
                             unacknowledged and {fresh} fresh cell(s) remain pending at exit"
                        );
                    } else {
                        diag_warn!(
                            METERING_FLUSH_PARTIAL_FAILURE,
                            failed = retained,
                            flushed,
                            key = %write.delta.key_id,
                            error = %error,
                            "metering flush: {retained} cell(s) retained; retry will replay the \
                             same operation id and body"
                        );
                    }
                    return flushed;
                }
            }
        }
    }
}
