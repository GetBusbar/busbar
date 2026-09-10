// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MCP PER-CALL RECORD, mounted on the kernel-held record leg.
//!
//! One hash-chained record per tool call, per authenticated caller — who called what, under which
//! approved digest, and whether it went out. The RECORD is the MCP plane's, the schema and the bytes
//! are the plane's declaration, the chain is the audit unit's, the leg is admitted by the kernel,
//! and the reach onto the published store protocol is here, because the composition root is the one
//! kind entitled to name a store, a unit and a plane in the same file.
//!
//! ## Why the mount is here and not in the plane
//!
//! The plane cannot build this. A plane performs no input and no output; what it keeps is the ONE
//! chokepoint every call is recorded through ([`busbar_mcp::mcp::callrecord`]) and a slot for the
//! durable path. That is the right split, because the chokepoint is a rule about the plane and the
//! durable path is a fact about the deployment.
//!
//! ## The chain scope is the PRINCIPAL, and the scope is in the digest
//!
//! Both are wire facts of the records already on disk rather than choices. The scope rides the
//! prelude here (unlike the operator-mutation log's, which does not), so a record sealed for one
//! caller cannot be replayed into another's chain — and moving either would make every
//! already-persisted call record report a digest mismatch at its next boot.
//!
//! ## Fire-and-forget, loudly
//!
//! A durable write failure NEVER fails the call it records. The failure is surfaced by the plane's
//! own chokepoint, which is where the call's identifying fields are; this file's job is to hand back
//! the reason it could not land the record, verbatim.

use std::sync::Arc;

use busbar_mcp::mcp::callrecord::{CallInput, CallRecordSink, RestoredCalls};
use busbar_plane_mcp::records as call_record;
use busbar_unit_audit::legacy::Framing;

use crate::root::records::{DeclaredSchemas, LegError, RecordLeg, Restored};

/// The MCP per-call record's durable path: one record leg, over the store the loader resolved.
///
/// It holds one chain position per principal and nothing else. The records live in the store, which
/// is the whole reason a durable log exists — holding every record of every caller in memory is the
/// thing this subsystem exists to avoid.
pub struct CallStream {
    leg: RecordLeg,
}

impl std::fmt::Debug for CallStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CallStream")
    }
}

impl CallStream {
    /// Bind the stream to a store.
    ///
    /// Length-prefixed, with the scope IN the digest: the two wire facts stated in the module
    /// header. There is no legacy decode — this stream has only ever been written in the neutral
    /// envelope, so the envelope is the only shape it ever sees.
    #[must_use]
    pub fn over(store: Arc<dyn busbar_api::Store>) -> Self {
        CallStream {
            leg: RecordLeg::new(
                store,
                Box::new(DeclaredSchemas::of(
                    call_record::RECORD_SCHEMAS,
                    call_record::operations_for,
                )),
                call_record::SCHEMA_CALL,
                Framing::LengthPrefixed,
                true,
                None,
            ),
        }
    }

    /// SEED every caller's chain from its persisted tail and report what was found.
    ///
    /// # Errors
    ///
    /// The store refused the enumeration or a read.
    pub fn restore(&self) -> Result<Restored, LegError> {
        self.leg.restore()
    }

    /// APPEND one record and report the sequence it took.
    ///
    /// # Errors
    ///
    /// The kernel refused the leg, the envelope could not be encoded, or the store refused.
    pub fn append(&self, principal: &str, input: &CallInput) -> Result<u64, LegError> {
        let suffix = call_record::call_suffix(
            input.ts,
            &input.server,
            &input.tool,
            input.outcome,
            &input.reason,
            &input.tool_digest,
            input.pin_generation,
        );
        self.leg
            .append(principal, call_record::OP_APPEND, input.ts, &suffix)
            .map(|appended| appended.seq)
    }
}

impl CallRecordSink for CallStream {
    fn record(&self, principal: &str, input: &CallInput) -> Result<u64, String> {
        self.append(principal, input).map_err(|e| e.to_string())
    }
}

/// BUILD the MCP per-call record's durable path: read every persisted chain back, verify it, seed
/// the leg's positions from the tails, and install the path the plane's chokepoint records through.
///
/// Called ONCE at boot, BEFORE a listener binds, so the first call of this process chains onto the
/// last call of the previous one rather than reopening a caller's chain at sequence one.
///
/// THE RESTORE IS NOT A FORMALITY. It is the only place in a running deployment where a persisted
/// call chain is recomputed, so it is also the only place a tamper is detected — every break it
/// finds is reported while the records stay restored, because refusing to restore a chain that does
/// not verify would let anyone able to write to the store DELETE a caller's history by corrupting
/// one byte.
///
/// A durable backend the deployment did not configure is not an error and not a warning: it is the
/// documented `store: memory` behaviour. The slot stays empty, the call still serves, and nothing is
/// kept.
pub fn mount(store: Option<Arc<dyn busbar_api::Store>>) {
    let Some(store) = store else {
        return;
    };
    let stream = CallStream::over(store);
    // The root READS the chains back — it owns the leg and the store — and the plane says what the
    // numbers mean, because the diagnostic codes an operator greps for are the plane's catalogue.
    busbar_mcp::mcp::callrecord::report_restore(
        stream
            .restore()
            .map(|r| RestoredCalls {
                principals: r.scopes,
                records: r.records,
                empty_chains: r.empty_chains,
                unreadable: r.unreadable,
                chain_breaks: r.chain_breaks.iter().map(ToString::to_string).collect(),
            })
            .map_err(|e| e.to_string()),
    );
    busbar_mcp::mcp::callrecord::install(Some(Arc::new(stream)));
}

// THE WRITER, PROVEN FROM THE OUTSIDE, across the real plugin C ABI. It lives with the leg because it
// has to name both halves — the plane's dispatcher and the root's persister — and this is the one
// kind entitled to.
#[cfg(test)]
#[path = "tests/call_record_dlopen.rs"]
mod call_record_dlopen;
