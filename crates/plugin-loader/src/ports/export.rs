// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The export port (IF §11.3, round 33 §49); `adapters::export::ExportAdapter` is its one implementation.

use busbar_plugin_abi::host_side::caller::BoxFut;

use crate::ports::{CallCx, PortError};

pub struct FamilyIn<'a> {
    pub kind: u32,
    pub name: &'a str,
    pub help: &'a str,
    pub samples: &'a [SampleIn<'a>],
}

pub struct SampleIn<'a> {
    pub value: f64,
    pub bound: f64,
    pub ts_ms: u64,
    pub role: u32,
    pub labels: &'a [(&'a str, &'a str)],
}

pub struct ScopeInfo {
    pub scope: u32,
    pub path: Box<str>,
}

pub struct RecorderNeeds {
    pub retention_s: u64,
    pub key_gauge_limit: u64,
}

/// Round 7. `Acked` = ACK only. `Append` = APPEND then ACK: `dest` is the instance-local handle (checked
/// against the instance's bindings by the adapter: out of range => FAULT BadRecords), `bytes` None = the batch.
/// Round 33: `Acked.custody` = the CUSTODY answered for the prefix (absent = ACCEPTED, `recheck_s` 0). `Append`
/// carries none: a file sink's custody is ACCEPTED, decided by core (§8.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Custody {
    pub level: u32,
    pub recheck_s: u32,
}

#[derive(Debug)]
pub enum Delivered {
    Acked {
        accepted: u64,
        custody: Custody,
    },
    Append {
        dest: u32,
        bytes: Option<Vec<u8>>,
        accepted: u64,
    },
}

pub trait ExportPort: Send + Sync + 'static {
    fn streams(&self) -> u32;
    /// D_SCOPE items: core mounts each path on its own listener and serves `render(scope)` there. Round 12: a
    /// path another instance already claims on the same listener refuses the config at load (§12.26).
    fn scopes(&self) -> &[ScopeInfo];
    /// D_RECORDER, clamped by core; the kernel's recorder keeps at least this for this instance.
    fn recorder(&self) -> Option<RecorderNeeds>;
    /// Round 29: the image declared FB_SPAN_RECORDS (§8.5). K8's traces pump adds the `span` member only for these.
    fn span_records(&self) -> bool;
    /// Round 7: returns what the plugin answered; for `Append` the kernel's export pump then calls
    /// `DiskSink::append` (§12.21) with the instance's bound destination and either `bytes` or, when None, the
    /// batch it delivered (no copy). Round 33: `delivery` and `attempt` are the pump's (minted and counted per
    /// §8.5), passed through unchanged.
    fn deliver<'a>(
        &'a self,
        cx: CallCx,
        stream: u32,
        delivery: u64,
        attempt: u32,
        lines: &'a [&'a [u8]],
    ) -> BoxFut<'a, Result<Delivered, PortError>>;
    /// Round 33: the custody ceiling the instance stated in its `open` answer (§8.5), None if it stated none.
    /// Read by K8C's admin instance view in 1.6.0 and by the 1.6.x config-load check.
    fn custody_ceiling(&self) -> Option<u32>;
    /// Writes CONTENT_TYPE and BODY through `sink` while the answer buffer is live (no copy into a Vec).
    fn render(
        &self,
        scope: u32,
        snapshot: &[FamilyIn<'_>],
        sink: &mut dyn FnMut(&str, &[u8]),
    ) -> Result<(), PortError>;
}
