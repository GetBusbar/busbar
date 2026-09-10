// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PER-CALL RECORD'S ONE CHOKEPOINT, and the durable path the composition root fills it with.
//!
//! Every terminal of an inbound `tools/call` and every terminal of the outbound client leg records
//! here, and nowhere else. What is HERE is the chokepoint and the slot; what is NOT here is a chain,
//! a digest, a sequence or a store — a plane performs no output, so the bytes this record frames to
//! and the store they land on belong to the composition root's kernel-held record leg.
//!
//! ## Why the slot, and why it is empty by default
//!
//! An empty slot is the documented `store: memory` deployment: the call still serves and nothing is
//! kept. That is a product contract rather than a degraded mode, so it is the DEFAULT state of this
//! module and not an error path — and it is why a write's return value is never read as evidence by
//! anything but the writer's own log line.
//!
//! ## The join key rides the LOG LINE, not the record
//!
//! `request_id` is a join key: it is legitimately empty on every path with no inbound request, and a
//! field that is sometimes absent must not be able to make an otherwise-intact chain unverifiable.
//! So it is emitted on the success line, at `debug!`, because a join key that appears in exactly one
//! place joins nothing.

use std::sync::{Arc, RwLock};

pub use busbar_substrate::plane::calllog::CallInput;

/// THE DURABLE PATH one per-call record is landed on, supplied by the composition root.
///
/// The plane declares its record; the root persists it. The method takes the record's own fields and
/// hands back the SEQUENCE the chain minted, because the sequence is the chain's authority and the
/// only part of the outcome this side has any business logging.
///
/// # Errors
///
/// The record could not be landed. The string is the root's own reason, carried verbatim into this
/// module's diagnostic — never interpreted here, because a plane that could read a store's refusal
/// would be a plane that knows what a store is.
pub trait CallRecordSink: Send + Sync {
    /// Land one record on `principal`'s chain and report the sequence it took.
    fn record(&self, principal: &str, input: &CallInput) -> Result<u64, String>;
}

/// The one slot. `RwLock` and not a `OnceLock`: a test attaches and DETACHES a durable path around
/// the read-back it is judging, and boot itself installs exactly once.
static SINK: RwLock<Option<Arc<dyn CallRecordSink>>> = RwLock::new(None);

/// INSTALL (or clear) the durable path. Called once at boot by the composition root, with `None`
/// meaning the documented ephemeral deployment.
pub fn install(sink: Option<Arc<dyn CallRecordSink>>) {
    *SINK.write().unwrap_or_else(|e| e.into_inner()) = sink;
}

/// RECORD one call.
///
/// The failure is swallowed at `error!` with the record's own identifying fields, never at `warn!`
/// and never silently: a deployment that is losing evidence has to be able to find out, and the ONE
/// thing that would make this defensible-looking and wrong is a failure nobody can see. A durable
/// write failure NEVER fails the call it records — a gateway whose data plane stops when its
/// evidence backend blinks has converted an observability dependency into an availability one.
///
/// The ERROR is surfaced only on the TRANSITION into the failing state and held at `debug!`
/// thereafter: a store outage recurs once per served call, and a line per call is how an operator
/// learns to stop reading the log. A success clears the latch so a later outage errors again.
pub(crate) fn record(principal: &str, input: &CallInput) {
    let Some(sink) = SINK
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .map(Arc::clone)
    else {
        return;
    };
    static WRITE_FAILED_LATCHED: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    match sink.record(principal, input) {
        Ok(seq) => {
            WRITE_FAILED_LATCHED.store(false, std::sync::atomic::Ordering::Relaxed);
            tracing::debug!(
                principal = %principal,
                request_id = %input.request_id,
                seq = seq,
                server = %input.server,
                tool = %input.tool,
                outcome = %input.outcome,
                "per-call record appended"
            );
        }
        Err(e) if !WRITE_FAILED_LATCHED.swap(true, std::sync::atomic::Ordering::Relaxed) => {
            busbar_substrate::diag_error!(
                busbar_substrate::diagnostics::PLANE_CALLLOG_WRITE_FAILED,
                principal = %principal,
                request_id = %input.request_id,
                server = %input.server,
                tool = %input.tool,
                outcome = %input.outcome,
                error = %e,
                "the durable per-call record could NOT be written: this call is being served and \
                 its evidence is being LOST. The chain position is unchanged, so the chain stays \
                 contiguous — what is missing is this record, not the ones after it."
            );
        }
        Err(e) => {
            busbar_substrate::diag_debug!(
                busbar_substrate::diagnostics::PLANE_CALLLOG_WRITE_FAILED,
                principal = %principal,
                request_id = %input.request_id,
                server = %input.server,
                tool = %input.tool,
                outcome = %input.outcome,
                error = %e,
                "the durable per-call record could NOT be written: this call is being served and \
                 its evidence is being LOST. The chain position is unchanged, so the chain stays \
                 contiguous — what is missing is this record, not the ones after it."
            );
        }
    }
}

/// WHAT A BOOT RESTORE OF THIS PLANE'S CHAINS FOUND, as the composition root read it back off the
/// store — every number reported rather than summed, because they mean different things to an
/// operator and a single number hides the one that is bad news.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RestoredCalls {
    /// The callers the store held a chain for.
    pub principals: usize,
    /// Records read back and seeded.
    pub records: usize,
    /// Chains the store enumerated but held no readable record for.
    pub empty_chains: usize,
    /// Rows the store returned that could NOT be decoded.
    pub unreadable: usize,
    /// Chains that FAILED to verify. TAMPER EVIDENCE.
    pub chain_breaks: Vec<String>,
}

/// NARRATE the boot restore of this plane's per-call chains.
///
/// The root reads the chains back — it owns the leg and the store — and the plane says what the
/// numbers MEAN, because the diagnostic codes an operator greps for are this plane's catalogue and
/// nothing else may spell them. A restore that found nothing says nothing: an empty store on a fresh
/// deployment is the ordinary case and a boot line for it is noise.
pub fn report_restore(outcome: Result<RestoredCalls, String>) {
    match outcome {
        Ok(r) if r == RestoredCalls::default() => {}
        Ok(r) => {
            tracing::info!(
                principals = r.principals,
                records = r.records,
                unreadable = r.unreadable,
                "MCP per-call log restored from the durable governance store"
            );
            // An UNDECODABLE row is an evidence record this build could not read back — counted and
            // SKIPPED per-record rather than aborting the restore, which would leave every chain
            // after it unseeded and fork it at sequence one. Fired whenever `unreadable > 0` even if
            // `records` is zero (a caller whose rows were ALL undecodable), so it is never invisible.
            if r.unreadable > 0 {
                busbar_substrate::diag_warn!(
                    busbar_substrate::diagnostics::PLANE_CALLLOG_ROW_UNREADABLE,
                    rows = r.unreadable,
                    "persisted MCP per-call records could not be decoded on restore and were SKIPPED; \
                     they were most likely written by a different engine version or the store is corrupt"
                );
            }
            // An ENUMERATED-BUT-EMPTY chain is the one shape the verifier cannot judge alone, and it
            // is what one caller's evidence being deleted wholesale looks like. Surfaced separately
            // rather than summed into `principals`.
            if r.empty_chains > 0 {
                busbar_substrate::diag_warn!(
                    crate::diagnostics::MCP_CALLLOG_EMPTY_CHAINS,
                    principals = r.empty_chains,
                    "the durable MCP call log enumerates these principals but holds NO records \
                     for them; their chains reopen at seq 1"
                );
            }
            for brk in &r.chain_breaks {
                busbar_substrate::diag_error!(
                    crate::diagnostics::MCP_CALLLOG_CHAIN_VERIFY_FAILED,
                    break_detail = %brk,
                    "MCP per-call CHAIN VERIFICATION FAILED on restore — TAMPER EVIDENCE"
                );
            }
        }
        Err(e) => busbar_substrate::diag_warn!(
            crate::diagnostics::MCP_CALLLOG_UNREAD,
            error = %e,
            "could not read the durable MCP per-call log; chains start at their persisted \
             tail being unknown, which means a principal with rows in the store may reopen at \
             seq 1 and collide"
        ),
    }
}
