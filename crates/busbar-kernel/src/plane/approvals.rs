// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST'S HALF OF A PLANE'S CALLER-FACING APPROVAL: the spent-approval ledger that makes an
//! approval single-use, the short replay window a sealed approval lives for, and the nonce a plane
//! seals into one.
//!
//! The seal itself — the sealed payload, its MAC domains, mint/open and the request match — is the
//! plane's own, in the plane's crate, sealed over the host's `sign` (ARCHITECT Q-L3B-ASK). Core
//! holds no plane-named seal domain and no copy of the payload (audit K2-H3).

/// THE SPENT-APPROVAL LEDGER — what makes an approval SINGLE-USE.
///
/// ## What the seal could not do on its own
///
/// Everything else about an approval is a statement the plane's seal itself can carry: who it was
/// minted for, what request, which round, until when. Single use is the one property that cannot
/// ride inside the blob, because a caller presenting the identical blob a second time presents an
/// identical, perfectly valid blob. The only thing that can tell the second presentation from the
/// first is a RECORD THAT THE FIRST HAPPENED — and until this existed there was none, so an operator
/// who gated a money-moving action behind a confirmation got confirm-once-execute-many.
///
/// ## Keyed on the nonce, and only the terminal redemption is recorded
///
/// The nonce already exists and is already unique per mint (`mrtr`'s multi-round scenario requires
/// it), so it is the natural handle and nothing new has to be sealed. What is recorded is the ONE
/// redemption that dispatches: an intermediate round's state is answered with a fresh ask and a
/// fresh state, so burning it would refuse the ordinary case of a client retrying a request whose
/// answer it never saw. The spend therefore happens exactly where the exchange COMPLETES.
///
/// ## TWO LEDGERS, and why one of them is not enough
///
/// The in-process map is the fast path and it is sufficient for exactly one shape of deployment: a
/// single node that never restarts. Neither half of that is a thing an operator has.
///
/// - **A RESTART** empties the map, and a state that has not lapsed is still openable, so the most a
///   restart used to restore was the unredeemed remainder of one [`DEFAULT_TTL_SECS`] window. Small,
///   bounded, self-closing — and on an action that moves money, one redemption is the whole defect.
/// - **A FLEET** never shared it. Two nodes of one deployment share `auth.signing_key`, because that
///   is what lets one logical exchange span requests that different nodes serve; sharing the key
///   means sharing the SEAL, so an approval minted on node A opens on node B. Sharing the seal
///   without sharing the ledger means one approval is redeemable once PER NODE, and the redemptions
///   need no timing skill at all — they are ordinary sequential requests to a load balancer.
///
/// So the record that the first redemption happened lives where both of those can see it: the
/// configured governance store, through [`busbar_contract::records::RecordStore::redeem_ask_state`]. The store's answer
/// is authoritative and the local map is consulted first purely to avoid a round trip on the
/// obvious replay.
///
/// The store method is a TEST-AND-SET rather than a read then a write, for the same reason the local
/// half is: two redemptions in flight at once is the attack, not the corner case.
///
/// ## A deployment with no durable store is exactly where it was
///
/// No sink — or a backend implementing none of it, which is the same thing from here — means the
/// store half is skipped and the in-process map is the whole gate: single-use per node, for the life
/// of the process. That is the pre-existing behaviour and the documented `store: memory` posture,
/// and it is asserted by a paired negative test rather than assumed.
///
/// ## The size of it
///
/// An entry lives at most as long as the state it records, and every call evicts what has lapsed, so
/// the table holds at most the approvals minted in one TTL window. The store is handed `now` on
/// every redemption so it can bound its own table the same way. Minting an approval costs the caller
/// a metered, budget-charged round, so the rate is bounded by governance rather than by this map.
#[derive(Default)]
pub struct SpentTokenLedger {
    /// nonce ⇒ the instant after which the entry is meaningless, because the state it records can
    /// no longer be opened anyway.
    seen: std::sync::Mutex<std::collections::HashMap<String, u64>>,
    /// The SHARED ledger: the configured governance store, attached once at boot. `None` is a
    /// deployment with no durable store, which is the process-local posture above.
    sink: std::sync::Mutex<Option<std::sync::Arc<dyn crate::plane::store::PlaneStore>>>,
}

/// Hand-written because `dyn Store` is not `Debug` — a backend must not be obliged to render itself,
/// and one that did would be a place a credential could surface in a log. The nonces are not printed
/// either: they identify live approvals.
impl std::fmt::Debug for SpentTokenLedger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpentTokenLedger")
            .field(
                "entries",
                &self.seen.lock().map(|s| s.len()).unwrap_or_default(),
            )
            .field("durable", &self.sink().is_some())
            .finish()
    }
}

impl SpentTokenLedger {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Attach the configured governance store as the SHARED ledger. Called once at boot, on the
    /// instance carried across every later config apply.
    pub fn set_sink(&self, store: std::sync::Arc<dyn crate::plane::store::PlaneStore>) {
        *self.sink.lock().unwrap_or_else(|e| e.into_inner()) = Some(store);
    }

    fn sink(&self) -> Option<std::sync::Arc<dyn crate::plane::store::PlaneStore>> {
        self.sink
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .cloned()
    }

    /// SPEND this approval. `true` if it had not been spent before; `false` if it had.
    ///
    /// Test-and-set on both halves, and that is not an optimisation: a caller that fires two
    /// redemptions of one approval concurrently is the obvious way to attack a check that reads and
    /// then writes, and it is the shape the whole gate exists to refuse.
    ///
    /// The LOCAL half runs first and, on a nonce it has already seen, answers `false` without a
    /// round trip. The DURABLE half is what a second node and a restarted process consult, and its
    /// `false` is final. Note the local map is written on the way past regardless of what the store
    /// then says — an approval this node has now attempted is one it need never ask about again.
    ///
    /// A STORE FAILURE REFUSES. This is the one place on this seam where a durable-write error is
    /// not swallowed, and the asymmetry is the point: the durable call log is EVIDENCE, so losing a
    /// row must not refuse a call, while this is ADMISSION, and a ledger that cannot answer "has
    /// this been redeemed" cannot be read as "no". Failing open here would mean a store outage
    /// silently restores confirm-once-execute-many across the fleet.
    pub(crate) fn spend(&self, nonce: &str, expires_at: u64, now: u64) -> bool {
        // Poison-recovering, like every other request-path lock in this process: the data behind it
        // is still valid after a panic, and cascading the poison would turn one stray panic into a
        // gate that refuses every confirmation for the life of the process.
        {
            let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
            seen.retain(|_, expiry| *expiry >= now);
            if seen.insert(nonce.to_string(), expires_at).is_some() {
                return false;
            }
        }
        let Some(store) = self.sink() else {
            return true;
        };
        match store.redeem_plane_token(crate::plane::store::KIND_ASK, nonce, expires_at, now) {
            Ok(fresh) => fresh,
            Err(e) => {
                crate::diagnostics::diag_error!(
                    crate::diagnostics::APPROVAL_LEDGER_UNREACHABLE_REFUSED,
                    error = %e,
                    "the shared spent-approval ledger could not be reached, so this redemption is \
                     REFUSED: a ledger that cannot say whether an approval was already spent must \
                     not be read as saying it was not"
                );
                false
            }
        }
    }
}

// ONE APPROVAL, REDEEMED ONCE — across a restart and across a fleet. Judged through the served
// door at the composition root (`crates/busbar/src/root/tests/door_steps.rs`, `spent_ledger`;
// ARCHITECT Q-L3B-ASK): the plane door mints and redeems the sealed state over the host's `sign`
// and spends it by the host's one-time `records.claim`, and only the root composes a door's
// served path (P3 DEL-MCP).

/// The DEFAULT life of a sealed state. Short, per `mrtr.mdx:236`: a caller answering an elicitation
/// is a human at a prompt, not a batch job, and every second of validity is a second of replay
/// window.
pub const DEFAULT_TTL_SECS: u64 = 300;

/// A fresh nonce. `getrandom` is the same fail-closed entropy source key secrets use; a failure is
/// not survivable here, because a predictable nonce is a `multi-round` scenario that passes by
/// accident and a replay window that is wider than it looks.
///
/// The draw itself is governance's one 128-bit hex draw (`governance::generate_binding_generation`);
/// it is named here beside the ledger so a plane mints a nonce through `plane::approvals::nonce`.
pub fn nonce() -> Result<String, getrandom::Error> {
    crate::governance::generate_binding_generation()
}

#[cfg(test)]
#[path = "tests/approvals_tests.rs"]
mod approvals_tests;
