// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Host-side answers and the one METRIC decoder (IF §10.2, §12.17). W0-ABI stub: frozen signatures, `todo!()` bodies; W1-H1 fills it.

use core::marker::PhantomData;

use crate::host_side::pool::PooledOut;
use crate::records::Records;
use crate::types::Status;

pub struct Answer<'o> {
    pub status: Status,
    recs: Records<'o>,
}
impl<'o> Answer<'o> {
    /// OK: the answer records, excluding a leading TOKEN record. REFUSED/FAILED: empty (the answer is exactly
    /// one FAIL record, §6.4 step 2; round 21: on FAILED, followed by ≤ 2 FACT records with distinct keys in
    /// `FAIL_FACT_KEYS`, validated when the answer is built; any other record next to FAIL is FAULT BadRecords).
    /// Round 34: the validated tail is FAIL, at most one ERROR directly after it (REFUSED or FAILED), then the
    /// FAILED-only FACTs; a second ERROR or one after a FACT is FAULT BadRecords, and ERROR in an OK or NEED
    /// answer is FAULT UnknownTag (§3).
    pub fn records(&self) -> Records<'o> {
        let _ = &self.recs;
        todo!()
    }
    /// Round 21: a fact a FAILED answer carried after FAIL (`FACT_RETRY_AFTER_S`, `FACT_BACKEND_STATUS`); None
    /// for OK, REFUSED, or when absent. Read by the one `PortError::Failed` builder every adapter uses.
    pub fn fail_fact(&self, key: u32) -> Option<u64> {
        let _ = key;
        todo!()
    }
    /// Round 34: the ERROR number a REFUSED or FAILED answer carried after FAIL, as the raw `u32` it arrived as
    /// (0 = none, also for OK). Never narrowed here: the shared `PortError`/`OpenError` builder resolves it
    /// through the image's `ErrorBook` (§11.2), which treats anything above 9999 as not declared.
    pub fn fail_error(&self) -> u32 {
        todo!()
    }
    /// (code, text) for REFUSED or FAILED. The text is re-validated as UTF-8 and is **not cut** by the host
    /// (round 15: it is ≤ `FAIL_TEXT_WIRE_MAX`, the shim's wire bound). It is the plugin's raw text: adapters pass
    /// it through `scrub::fail_text` (§12.16: scrub, mask a trailing partial needle, then cut to 512) before it
    /// becomes a `PortError` text, a log line or an audit field; no core path cuts it before that call.
    pub fn fail(&self) -> Option<(u32, &'o str)> {
        todo!()
    }
    // W0-ABI: `pub(crate) fn session_token(&self) -> Option<Token>` (IF §10.2: the session token a session
    // opener answered with, bit 63 checked; read only by the §10.4 session-handle constructor) lands with
    // W1-H1 together with its caller (a crate-private fn with no caller would warn as dead code).
    pub fn is_ok(&self) -> bool {
        todo!()
    }
}

/// An async answer: owns its pooled buffer.
pub struct OwnedAnswer {
    status: Status,
    buf: PooledOut,
}
impl OwnedAnswer {
    pub fn answer(&self) -> Answer<'_> {
        let _ = (&self.status, &self.buf);
        todo!()
    }
}

// W0-ABI gap: the IF (§12.17, §8.8) names `abi::host::decode_metrics(answer, &mut impl FnMut(MetricObsIn<'_>))`
// but defines neither `MetricObsIn` nor the exact parameter/return types. `MetricObsIn` is an opaque stub here
// and `decode_metrics` takes `&Answer<'_>` and returns nothing; W1-H1 (with K8) freezes both.
// One decoded METRIC observation of an answer (§3 `MetricObs` plus its PAIR* label values).
pub struct MetricObsIn<'a> {
    _stub: PhantomData<&'a ()>,
}

// The one decoder of the generic METRIC records of every kind's answer, into core's recorder (§12.17, §8.8);
// no adapter decodes them itself.
pub fn decode_metrics(answer: &Answer<'_>, f: &mut impl FnMut(MetricObsIn<'_>)) {
    let _ = (answer, f);
    todo!()
}
