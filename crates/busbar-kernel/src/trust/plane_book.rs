// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The trust book as the plane sees it: SIGHT, TRUST_SERVES, TRUST_STATE, TGT_SIGHT, TRUST_VERIFY and the operator's approve/revoke/release (IF §12.14). W0-ABI stub: frozen signatures, `todo!()` bodies; W1-K10 fills it.

// W0-ABI: IF §12.14 names this trait `TrustBook` in module `trust`; `trust/book.rs` already holds the kernel's
// concrete `TrustBook` struct, so the trait lives in this new file (`crate::trust::plane_book::TrustBook`).

use busbar_plugin_abi::host_side::caller::{BoxFut, Caller};
use busbar_plugin_loader::ports::plane::TrustItem;

use crate::plugin_records::RecordsDenied;

/// Keyed by (plane plugin, plane instance name, configured upstream name): durable, replica-shared.
pub trait TrustBook: Send + Sync + 'static {
    /// SIGHT: record the observation (catalogue hash stamps the re-verification clock; each item digest is
    /// compared with the approval; drift quarantines the counterparty and is audited `trust_drift`).
    fn sight<'a>(
        &'a self,
        plane: &'a Caller<'_>,
        party: &'a str,
        catalog: Option<[u8; 32]>,
        items: &'a [(&'a str, [u8; 32])],
    ) -> BoxFut<'a, Result<(), RecordsDenied>>;
    /// TRUST_SERVES: DISTRUST_NONE or the DISTRUST_* that refuses (digest None = the last sighting). Never pends.
    fn serves(
        &self,
        plane: &Caller<'_>,
        party: &str,
        item: Option<(&str, Option<[u8; 32]>)>,
    ) -> u32;
    /// TRUST_STATE: the counterparty verdict and per-item state, for the plane's admin views.
    fn state(&self, plane: &Caller<'_>, party: &str, sink: &mut dyn FnMut(TrustItem<'_>)) -> u32;
    /// Upstreams of this plane instance whose re-verification is due; K8 runs `probe(TGT_SIGHT)` for each
    /// (and on DX_RESIGHT), with RetrySite::PlaneProbe.
    fn due(&self, plane: &Caller<'_>, now_s: u64) -> Vec<Box<str>>;
    /// Round 7. TRUST_VERIFY: verify `signatures` (JSON array of `{protected, signature}`; empty = none) over
    /// `payload` with the authenticity root configured for (`plane.name`, `party`) in TRUST_APPROVAL. The root's
    /// key selects the algorithm (through `busbar-crypto`'s JWS verify, I12); a header naming another algorithm
    /// is SIGNED_ALGORITHM, an unknown `crit` member SIGNED_CRITICAL (both write the name into `named`, ≤ 128
    /// bytes). No root configured => SIGNED_MALFORMED_ROOT, audited `trust_root_missing`. Returns SIGNED_*
    /// (§8.6). Never pends, never allocates beyond `named`; audited `trust_verify` with the verdict. Today's
    /// kernel `trust.verify` body moves here unchanged.
    fn verify(
        &self,
        plane: &Caller<'_>,
        party: &str,
        payload: &[u8],
        signatures: &[u8],
        named: &mut String,
    ) -> u32;
    /// Operator actions (core admin API only, never ABI, never a plane verb; round 7): approve an item digest
    /// or the counterparty, revoke an approval, clear a quarantine.
    fn approve<'a>(
        &'a self,
        plane_name: &'a str,
        party: &'a str,
        item: &'a str,
        digest: [u8; 32],
    ) -> BoxFut<'a, Result<(), RecordsDenied>>;
    fn revoke<'a>(
        &'a self,
        plane_name: &'a str,
        party: &'a str,
        item: &'a str,
    ) -> BoxFut<'a, Result<(), RecordsDenied>>;
    fn release<'a>(
        &'a self,
        plane_name: &'a str,
        party: &'a str,
    ) -> BoxFut<'a, Result<(), RecordsDenied>>;
}
