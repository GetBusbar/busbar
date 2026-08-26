// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SEALED `requestState` — minted by busbar, verified by busbar, and bound to the caller.
//!
//! ## Why busbar MINTS state rather than relaying an upstream's
//!
//! `mrtr.mdx:232` makes it a `MUST` that a server reject `requestState` that fails verification, and
//! `mrtr.mdx:130` says the value is "meaningful only to the server" — a client "MUST NOT inspect,
//! parse, modify, or make any assumptions about its contents". Those two sentences together mean a
//! relayer cannot be conformant: an upstream's state is opaque to busbar by construction, so busbar
//! could only forward it blind, and the verification would then happen one hop away, at an upstream,
//! on behalf of a caller that upstream never authenticated.
//!
//! That is not merely inelegant. `mrtr.mdx:235` requires the state to bind **the authenticated
//! principal**, "rejecting state presented by a different principal" — and the only principal an
//! upstream can see is BUSBAR, identically for every one of busbar's callers. Relayed state
//! therefore binds to busbar rather than to the caller, so caller A's state is redeemable by caller
//! B and the upstream cannot tell the difference. Minting closes that by construction: the principal
//! in the sealed payload is the inbound key, so the cross-caller replay is a signature failure.
//!
//! ## What is sealed, and why each field is in there
//!
//! Every element `mrtr.mdx:234-237` lists as a `SHOULD`, plus two busbar can offer and the spec does
//! not ask for:
//!
//! | field | why |
//! |---|---|
//! | `principal` | `mrtr.mdx:235`. Caller A's state cannot be redeemed by caller B. |
//! | `method` + `capability` | `mrtr.mdx:237` — "an identifier for the originating request". State minted on `prompts/get` cannot be spent on `tools/call`, nor one tool's on another's. |
//! | `args_digest` | the rest of `mrtr.mdx:237` — "a digest of its salient parameters". |
//! | `issued_at` + `ttl` | `mrtr.mdx:236`, the short expiry. |
//! | `nonce` | two mints of an identical payload MUST differ, or the `multi-round` scenario's `r2.requestState !== r1.requestState` can never hold. A deterministic seal fails it. |
//! | `round` | THE LOOP BOUND. See below — this is the field without which the caller-facing loop has no cap at all. |
//! | `generation` | the catalogue generation the ask was minted under. State minted before an approval was revoked is refused after it — which the spec does not require and busbar can give for free, because dispatch already re-validates against a generation. |
//!
//! ## The round index is the bound, and it has to live IN the seal
//!
//! The upstream-facing loop ([`super::inputreq`]) is in-process, so its counter is a local variable
//! and the bound is per dispatch by construction. The caller-facing loop is not: it is spread across
//! INDEPENDENT HTTP requests, with no session, because this revision has none. A counter held in
//! memory between them would be a session by another name — the same objection
//! `client/jsonrpc.rs` already makes about `InputRequiredLoop`. So the count rides inside the
//! integrity-protected payload, where the caller can neither read it nor rewind it. Without that,
//! the cap is unenforceable: a caller replays round-1 state for ever and every replay is a fresh,
//! uncapped round.
//!
//! ## Integrity
//!
//! HMAC-SHA256 under a key DERIVED from `auth.signing_key` — the deployment's fleet-shared secret,
//! which is what lets one logical exchange span requests that different nodes may serve. Derived
//! rather than used raw, so this seal and the virtual-key token signer can never be confused for one
//! another even if one of them is later changed. Verification is `Mac::verify_slice`, which is
//! constant-time; the decode is strict base64url with no padding, because a decoder that tolerated
//! trailing bytes would accept the conformance suite's `+ "-TAMPERED"` mutation and the scenario
//! would go green while the property it names was absent.
//!
//! No signing key ⇒ no sealer ⇒ NO ASK. That is the fail-closed posture and it is deliberate: an ask
//! busbar cannot seal is an ask busbar cannot verify the answer to, and emitting one would be
//! inviting a retry it would have to trust.

use sha2::{Digest as _, Sha256};

// D3 Phase-C: the ask-state seal PODs + crypto (`AskState`, `Rejected`, `Sealer`, mint/open, and the
// `DERIVE_DOMAIN`/`MAC_DOMAIN`/`HmacSha256` they need) now live in the neutral substrate so a plane
// holds the seal without naming core. Re-exported here so every in-core call site (`ask_state_sealer`
// below, `crate::mcp::callerask`, the tests) is unchanged. The key DERIVATION stays core:
// `ask_state_sealer` reaches `GovState`'s crate-private signing seed and calls `Sealer::derive`.
pub use busbar_substrate::plane::approvals::{AskState, Rejected, Sealer};

/// The DEFAULT life of a sealed state. Short, per `mrtr.mdx:236`: a caller answering an elicitation
/// is a human at a prompt, not a batch job, and every second of validity is a second of replay
/// window.
pub const DEFAULT_TTL_SECS: u64 = 300;

/// SEAM: derive this deployment's ask-state [`Sealer`] from governance's fleet-shared signing
/// secret, WITHOUT the raw secret ever leaving core. The MCP plane holds no governance key material
/// — it asks core for a sealer, and core derives it here from the `pub(crate)` signing seed
/// ([`crate::governance::GovState::signing_secret`], which stays crate-private). `None` when
/// governance is disabled (no key), matching the pre-split behaviour where the plane derived the
/// sealer itself and refused rather than asking with unprotected state.
pub fn ask_state_sealer(gov: &crate::governance::GovState) -> Option<Sealer> {
    gov.signing_secret().map(|s| Sealer::derive(&s))
}

/// The digest of a request's salient parameters, per `mrtr.mdx:237`.
///
/// Over the SERIALISED value rather than a field walk: the point is that the retry asks for the same
/// thing the ask was issued about, and any field of `arguments` can change what is being asked for.
/// `serde_json::Value`'s object representation is a `BTreeMap`, so the serialisation is key-ordered
/// and two equal values digest equally regardless of the order the caller sent them in.
pub fn digest_arguments(arguments: &serde_json::Value) -> String {
    let mut h = Sha256::new();
    h.update(serde_json::to_vec(arguments).unwrap_or_default());
    hex::encode(h.finalize())
}

/// THE SPENT-APPROVAL LEDGER — what makes an approval SINGLE-USE.
///
/// ## What the seal could not do on its own
///
/// Everything else about this module is a statement the seal itself can carry: who it was minted
/// for, what request, which round, until when. Single use is the one property that cannot ride
/// inside the blob, because a caller presenting the identical blob a second time presents an
/// identical, perfectly valid blob. The only thing that can tell the second presentation from the
/// first is a RECORD THAT THE FIRST HAPPENED — and until this existed there was none, so an operator
/// who gated a money-moving tool behind a confirmation got confirm-once-execute-many.
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
///   bounded, self-closing — and on a tool that moves money, one redemption is the whole defect.
/// - **A FLEET** never shared it. Two nodes of one deployment share `auth.signing_key`, because that
///   is what lets one logical exchange span requests that different nodes serve; sharing the key
///   means sharing the SEAL, so an approval minted on node A opens on node B. Sharing the seal
///   without sharing the ledger means one approval is redeemable once PER NODE, and the redemptions
///   need no timing skill at all — they are ordinary sequential requests to a load balancer.
///
/// So the record that the first redemption happened lives where both of those can see it: the
/// configured governance store, through [`busbar_api::Store::redeem_ask_state`]. The store's answer
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

/// A fresh nonce. `getrandom` is the same fail-closed entropy source key secrets use; a failure is
/// not survivable here, because a predictable nonce is a `multi-round` scenario that passes by
/// accident and a replay window that is wider than it looks.
pub fn nonce() -> Result<String, getrandom::Error> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b)?;
    Ok(hex::encode(b))
}

#[cfg(test)]
#[path = "tests/askstate_tests.rs"]
mod askstate_tests;

// ONE APPROVAL, REDEEMED ONCE — across a restart and across a fleet. Kept in its own file rather
// than folded into the battery above because it is about a DIFFERENT seam: everything in
// `askstate_tests` is the seal, exercised in memory, and everything here crosses the real plugin ABI
// into a real durable store and is judged through `callerask::decide` rather than through `spend`.
#[cfg(test)]
#[path = "tests/spentledger_tests.rs"]
mod spentledger_tests;
