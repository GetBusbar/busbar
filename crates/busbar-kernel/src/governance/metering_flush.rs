use super::*;
use crate::diagnostics::{diag_error, diag_warn, METERING_FLUSH_PARTIAL_FAILURE};
use busbar_contract::abi::store::OpId;

/// One raw count operation. Its identity and body remain together until acknowledgement.
#[derive(Clone)]
pub(super) struct MeteringWrite {
    /// The receipt's retention starts at the first attempt, never at a later retry.
    op: Option<MeteringAttempt>,
    delta: MeteringDelta,
}

#[derive(Clone, Copy)]
struct MeteringAttempt {
    id: OpId,
    replay_before: std::time::Instant,
    first_sent_at_ms: u64,
}

impl MeteringWrite {
    #[cfg(test)]
    pub(super) fn expire_attempt(&mut self) {
        self.op
            .as_mut()
            .expect("the operation was attempted")
            .replay_before = std::time::Instant::now();
    }

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
                    let mut flight = pending.flight.lock().unwrap_or_else(|p| p.into_inner());
                    flight.extend(pending.drain().into_iter().filter_map(MeteringWrite::new));
                    captured = true;
                    continue;
                }
                return flushed;
            };
            let op = write.op.unwrap_or_else(|| {
                let replay_before = std::time::Instant::now()
                    + std::time::Duration::from_secs(
                        busbar_contract::abi::store::OP_ID_RETENTION_SECS,
                    );
                let op = MeteringAttempt {
                    id: crate::door::op_id(),
                    replay_before,
                    first_sent_at_ms: crate::store::now_ms(),
                };
                pending
                    .flight
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .front_mut()
                    .expect("runner owns the retained front")
                    .op = Some(op);
                op
            });

            if self.recovery_enabled() {
                let result = (|| {
                    self.confirm_pending_recovery(op.id.0)?;
                    if self.recovery_event(op.id.0).is_none() {
                        let event = self.metering_recovery_intent(
                            op.id.0,
                            op.first_sent_at_ms,
                            &write.delta,
                        )?;
                        self.keep_recovery_event(&event)?;
                    }
                    self.drive_raw_recovery(op.id.0)
                })();
                match result {
                    Ok(()) => {
                        let state = self
                            .recovery_event(op.id.0)
                            .expect("confirmed metering Intent")
                            .state;
                        if matches!(
                            state,
                            recovery::RecoveryState::Settled
                                | recovery::RecoveryState::LandedUnknown
                        ) {
                            pending
                                .flight
                                .lock()
                                .unwrap_or_else(|p| p.into_inner())
                                .pop_front();
                            flushed += usize::from(state == recovery::RecoveryState::Settled);
                            continue;
                        }
                    }
                    Err(error) => {
                        diag_warn!(METERING_FLUSH_PARTIAL_FAILURE, key = %write.delta.key_id,
                            error = %error, "metering operation remains in durable recovery custody");
                    }
                }
                return flushed;
            }

            let result = if std::time::Instant::now() >= op.replay_before {
                Err(RecordStoreError(
                    "metering receipt retention expired; exact operation and counts retained"
                        .into(),
                ))
            } else {
                self.store
                    .add_metering_batch_deduped(op.id, std::slice::from_ref(&write.delta))
            };
            match result {
                Ok(()) => {
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
                            "metering flush: {retained} cell(s) retained with their operation id \
                             and body; replay is allowed only within receipt retention"
                        );
                    }
                    return flushed;
                }
            }
        }
    }
}
