use super::*;
use crate::diagnostics::{diag_error, diag_warn, METERING_FLUSH_PARTIAL_FAILURE};
use busbar_contract::records::OpId;

/// One raw count operation. Its identity and body remain together until acknowledgement.
#[derive(Clone)]
pub(super) struct MeteringWrite {
    /// The receipt's retention starts at the first attempt, never at a later retry.
    op: Option<MeteringAttempt>,
    delta: MeteringDelta,
    remainder: MeterCounts,
    key: MeterKey,
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
        let (delta, remainder) = metering_chunk(&key, &counts);
        Some(Self {
            op: None,
            delta,
            remainder,
            key,
        })
    }

    #[cfg(test)]
    pub(super) fn counts(&self) -> MeterCounts {
        let mut counts = self.remainder.clone();
        counts.merge(MeterCounts {
            requests: self.delta.requests,
            tokens_input: Count::from_micros(self.delta.tokens_input),
            tokens_output: Count::from_micros(self.delta.tokens_output),
            tokens_cache_read: Count::from_micros(self.delta.tokens_cache_read),
            tokens_cache_write: Count::from_micros(self.delta.tokens_cache_write),
            usage_units: self
                .delta
                .usage_units
                .iter()
                .map(|(k, n)| (k.clone(), Count::from_micros(*n)))
                .collect(),
        });
        counts
    }
}

/// One representable store operation; the untouched remainder keeps its exact Count range.
pub(super) fn metering_chunk(key: &MeterKey, counts: &MeterCounts) -> (MeteringDelta, MeterCounts) {
    fn take(count: Count) -> (i128, Count) {
        assert!(!count.is_negative(), "negative metering count");
        (count.micros(), Count::ZERO)
    }
    let (input, input_left) = take(counts.tokens_input);
    let (output, output_left) = take(counts.tokens_output);
    let (read, read_left) = take(counts.tokens_cache_read);
    let (write, write_left) = take(counts.tokens_cache_write);
    let mut units = std::collections::BTreeMap::new();
    let mut units_left = std::collections::BTreeMap::new();
    for (name, n) in &counts.usage_units {
        let (raw, left) = take(*n);
        if raw != 0 {
            units.insert(name.clone(), raw);
        }
        if !left.is_zero() {
            units_left.insert(name.clone(), left);
        }
    }
    (
        MeteringDelta {
            key_id: key.0.clone(),
            bucket: key.1,
            model: key.2.clone(),
            provider: key.3.clone(),
            priced_from_ms: key.4,
            key_group_at_use: key.5.clone(),
            pricing_version: key.6.clone(),
            scale: COUNT_SCALE,
            requests: counts.requests,
            billable_requests: counts.requests,
            tokens_input: input,
            tokens_output: output,
            tokens_cache_read: read,
            tokens_cache_write: write,
            usage_units: units,
        },
        MeterCounts {
            requests: 0,
            tokens_input: input_left,
            tokens_output: output_left,
            tokens_cache_read: read_left,
            tokens_cache_write: write_left,
            usage_units: units_left,
        },
    )
}

fn finish_front(pending: &PendingMetering) {
    let mut flight = pending.flight.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(done) = flight.pop_front() {
        if let Some(next) = MeteringWrite::new((done.key, done.remainder)) {
            flight.push_front(next);
        }
    }
}

impl GovState {
    pub(super) async fn flush_metering_deduped(&self, shutdown: bool) -> usize {
        let core = match self.core_store() {
            Ok(core) => core,
            Err(error) => {
                diag_warn!(METERING_FLUSH_PARTIAL_FAILURE, error = %error,
                    "metering counts retained until async Store is attached");
                return 0;
            }
        };
        let pending = &self.pending_metering;
        let owner = match pending.flush_runner.enter(shutdown).await {
            Ok(owner) => owner,
            Err(_) => return 0,
        };
        owner.scope(async {
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
                if !captured {
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
                let result = async {
                    self.confirm_pending_recovery(op.id.0).await?;
                    if self.recovery_event(op.id.0).is_none() {
                        let event = self.metering_recovery_intent(
                            op.id.0,
                            op.first_sent_at_ms,
                            &write.delta,
                        )?;
                        self.keep_recovery_event(&event).await?;
                    }
                    self.drive_raw_recovery(op.id.0).await
                }
                .await;
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
                            finish_front(pending);
                            flushed += usize::from(state == recovery::RecoveryState::Settled);
                            self.forget_confirmed_recovery(op.id.0);
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
                core.ledger()
                    .add_metering_batch_deduped(op.id, std::slice::from_ref(&write.delta))
                    .await
            };
            match result {
                Ok(()) => {
                    finish_front(pending);
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
        }).await
    }
}
