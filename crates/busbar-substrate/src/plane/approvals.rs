// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ASK-STATE SEAL — the `requestState` payload a plane mints, opens and matches, relocated to the
//! neutral substrate so a plane crate holds the seal without naming `busbar_core::plane::approvals`.
//!
//! [`Sealer::mint`] / [`Sealer::open`] are pure HMAC-SHA256 over a base64url payload and name no core
//! type; [`AskState`] and [`Rejected`] are pure PODs. The one thing that stays core is the key
//! DERIVATION from governance's signing secret — `busbar_core::plane::approvals::ask_state_sealer`
//! reaches `GovState` and calls [`Sealer::derive`], so no signing material crosses to the plane. Core
//! re-exports these, so `crate::plane::approvals::{AskState, Rejected, Sealer}` still resolves there.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hmac::digest::KeyInit as _;
use hmac::{Hmac, Mac as _};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Domain separation for the derived key. Changing this string invalidates every outstanding state,
/// which is the correct behaviour for a payload-format change.
const DERIVE_DOMAIN: &[u8] = b"busbar/mcp/askstate/derive/v1";

/// Domain separation for the MAC itself, prepended to the signed bytes. Belt and braces beside the
/// key derivation: even a deployment that somehow reused the raw key elsewhere cannot have one of
/// its blobs verify here.
const MAC_DOMAIN: &[u8] = b"busbar/mcp/askstate/v1\0";

/// The sealed payload. Field names are short because this rides in a JSON body on every retry, and
/// the wire form is an implementation detail no client may parse (`mrtr.mdx:130`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AskState {
    /// The AUTHENTICATED PRINCIPAL — the inbound key's stable id. `mrtr.mdx:235`.
    #[serde(rename = "p")]
    pub principal: String,
    /// The JSON-RPC method the ask was issued on: `tools/call` or `prompts/get`.
    #[serde(rename = "m")]
    pub method: String,
    /// The NAMESPACED capability — `{server}_{tool}`, or the namespaced prompt name.
    #[serde(rename = "c")]
    pub capability: String,
    /// A digest of the request's salient parameters. `mrtr.mdx:237`.
    #[serde(rename = "d")]
    pub args_digest: String,
    /// The catalogue generation the ask was minted under.
    #[serde(rename = "g")]
    pub generation: u64,
    /// Which round of the caller-facing loop this state ENDS. The retry that presents it is round
    /// `round + 1`, and that is what the per-server cap is compared against.
    #[serde(rename = "r")]
    pub round: u32,
    /// Fresh randomness, so two mints of an otherwise identical payload differ.
    #[serde(rename = "n")]
    pub nonce: String,
    /// Unix seconds at mint.
    #[serde(rename = "i")]
    pub issued_at: u64,
    /// Seconds of validity from `issued_at`.
    #[serde(rename = "t")]
    pub ttl_secs: u64,
    /// The principal's ROOTS EPOCH at mint — present exactly when the exchange this state
    /// continues includes a `roots/list` ask, absent otherwise so unrelated confirmations cannot
    /// be invalidated by a roots announcement. See `crate::mcp::roots` for the mechanism and
    /// [`Rejected::StaleRoots`] for the refusal a mismatch produces.
    #[serde(rename = "e", default, skip_serializing_if = "Option::is_none")]
    pub roots_epoch: Option<u64>,
}

/// Why a presented `requestState` was refused. Every arm is a REFUSAL — there is no arm that means
/// "accept anyway" and none that means "re-prompt". `mrtr.mdx:232` and the conformance suite's
/// `tampered-state` comment agree on that: a complete result OR a fresh ask in answer to tampered
/// state both mean the server did not reject it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rejected {
    /// Not two base64url segments, or the payload is not the JSON this module writes.
    Malformed,
    /// The MAC did not verify. THE TAMPER ARM.
    BadSignature,
    /// Past `issued_at + ttl_secs`.
    Expired,
    /// Sealed for a different authenticated principal. The cross-caller replay `mrtr.mdx:235` names.
    WrongPrincipal,
    /// Sealed for a different method, capability, or argument set.
    WrongRequest,
    /// Sealed under a catalogue generation that is no longer live — an approval moved underneath it.
    WrongGeneration,
    /// ALREADY REDEEMED. Perfectly valid, for this caller, for this request, inside its window — and
    /// already spent on the call it was minted to approve. See `SpentTokenLedger`.
    AlreadySpent,
    /// SEALED UNDER A ROOTS EPOCH THE CALLER ITSELF HAS SINCE MOVED. The state carried a roots
    /// answer, and the caller sent `notifications/roots/list_changed` after it was minted — so
    /// redeeming it would dispatch on roots the caller just disavowed. See `crate::mcp::roots`.
    StaleRoots,
}

impl Rejected {
    /// The stable audit reason word. Named here so a new arm cannot land without one.
    pub fn audit_reason(self) -> &'static str {
        match self {
            Rejected::Malformed => "state_malformed",
            Rejected::BadSignature => "state_bad_signature",
            Rejected::Expired => "state_expired",
            Rejected::WrongPrincipal => "state_wrong_principal",
            Rejected::WrongRequest => "state_wrong_request",
            Rejected::WrongGeneration => "state_wrong_generation",
            Rejected::AlreadySpent => "state_already_spent",
            Rejected::StaleRoots => "state_stale_roots",
        }
    }
}

impl std::fmt::Display for Rejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // ONE message for every arm that a FORGER can reach, deliberately. The distinctions above
        // exist for the audit row; telling a caller WHICH check its forged state failed is an
        // oracle for forging a better one, and `mrtr.mdx:269-272` names the caller as the attacker
        // for exactly this field.
        //
        // `StaleRoots` is the one deliberate exception, and the oracle argument is why it is safe:
        // the epoch is compared only AFTER the MAC verified, so the only party that can ever read
        // this message is the caller busbar genuinely minted the state for — and the trigger was
        // that caller's own `notifications/roots/list_changed`. It learns nothing it did not
        // announce itself, and it needs the distinct remedy: restart the exchange, answer with
        // current roots. The unified message's remedy (there is none) would be wrong.
        match self {
            Rejected::StaleRoots => f.write_str(
                "`requestState` was minted before you sent `notifications/roots/list_changed`, and \
                 the exchange it continues includes a `roots/list` answer — which your notification \
                 declared stale. Retry the request without `requestState` to restart the exchange \
                 and answer with your current roots.",
            ),
            _ => f.write_str(
                "`requestState` failed integrity verification and was refused. It is an opaque \
                 value minted by this server for one caller, one request and a short window; it \
                 cannot be modified, reused by another caller, replayed after it lapses, or \
                 presented on a different request.",
            ),
        }
    }
}

/// THE SEAL. Holds a key derived from the deployment's signing key; its `Debug` never prints it.
#[derive(Clone)]
pub struct Sealer {
    key: [u8; 32],
}

impl std::fmt::Debug for Sealer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sealer")
            .field("key", &"<redacted ask-state key>")
            .finish()
    }
}

impl Sealer {
    /// Derive the ask-state key from the deployment's `auth.signing_key` secret.
    ///
    /// A DERIVATION rather than the raw bytes: the same secret is the ed25519 virtual-key signer,
    /// and two unrelated uses of one secret should not be able to produce a blob the other accepts.
    ///
    /// `pub` (was `pub(crate)` in core) so `busbar_core::plane::approvals::ask_state_sealer` — the
    /// one seam that reaches `GovState` — can derive from the crate-private signing seed core-side.
    pub fn derive(signing_secret: &[u8; 32]) -> Self {
        let mut mac =
            HmacSha256::new_from_slice(signing_secret).expect("HMAC accepts a key of any length");
        mac.update(DERIVE_DOMAIN);
        let out = mac.finalize().into_bytes();
        let mut key = [0u8; 32];
        key.copy_from_slice(&out[..32]);
        Self { key }
    }

    /// MINT a sealed state for `state`. The returned string is what goes on the wire as
    /// `requestState`, and it is opaque to every party but this one.
    pub fn mint(&self, state: &AskState) -> String {
        let payload = serde_json::to_vec(state).expect("AskState serialises");
        let encoded = URL_SAFE_NO_PAD.encode(&payload);
        let tag = self.tag(encoded.as_bytes());
        format!("{encoded}.{}", URL_SAFE_NO_PAD.encode(tag))
    }

    /// OPEN a presented state: decode, verify the MAC, check the expiry. Nothing here consults the
    /// request — that is [`AskState::matches`], kept separate so the crypto has no way to be made
    /// context-dependent by a later edit.
    pub fn open(&self, blob: &str, now: u64) -> Result<AskState, Rejected> {
        let (encoded, sig) = blob.split_once('.').ok_or(Rejected::Malformed)?;
        // STRICT decode. `-` and `_` are base64url characters, so the conformance suite's
        // `+ "-TAMPERED"` decodes rather than erroring — and lands on a tag of the wrong length and
        // the wrong bytes, which is why the length check and the MAC check are both here and why
        // neither may be relaxed into "starts with".
        let tag = URL_SAFE_NO_PAD
            .decode(sig.as_bytes())
            .map_err(|_| Rejected::Malformed)?;
        let mut mac =
            HmacSha256::new_from_slice(&self.key).expect("HMAC accepts a key of any length");
        mac.update(MAC_DOMAIN);
        mac.update(encoded.as_bytes());
        // CONSTANT TIME, and it also rejects a tag of the wrong length rather than comparing a
        // prefix. A `==` on `Vec<u8>` would be neither.
        mac.verify_slice(&tag).map_err(|_| Rejected::BadSignature)?;

        let payload = URL_SAFE_NO_PAD
            .decode(encoded.as_bytes())
            .map_err(|_| Rejected::Malformed)?;
        let state: AskState = serde_json::from_slice(&payload).map_err(|_| Rejected::Malformed)?;
        // The expiry is checked here rather than in `matches` because it is a property of the state
        // alone, and because a state that has lapsed must be refused even by a caller that gets
        // every other field right.
        if now > state.issued_at.saturating_add(state.ttl_secs) {
            return Err(Rejected::Expired);
        }
        Ok(state)
    }

    /// The MAC over the domain tag and the encoded payload.
    fn tag(&self, encoded: &[u8]) -> [u8; 32] {
        let mut mac =
            HmacSha256::new_from_slice(&self.key).expect("HMAC accepts a key of any length");
        mac.update(MAC_DOMAIN);
        mac.update(encoded);
        let out = mac.finalize().into_bytes();
        let mut tag = [0u8; 32];
        tag.copy_from_slice(&out[..32]);
        tag
    }
}

impl AskState {
    /// Does this opened state belong to THE REQUEST NOW IN HAND?
    ///
    /// Separate from [`Sealer::open`] on purpose: `open` proves busbar minted the blob, and this
    /// proves busbar minted it FOR THIS. A seal that only proved the first would let any caller
    /// replay its own valid state onto a different tool, a different argument set, or a catalogue
    /// generation under which the approval has since been withdrawn.
    pub fn matches(
        &self,
        principal: &str,
        method: &str,
        capability: &str,
        args_digest: &str,
        generation: u64,
    ) -> Result<(), Rejected> {
        if self.principal != principal {
            return Err(Rejected::WrongPrincipal);
        }
        if self.method != method || self.capability != capability {
            return Err(Rejected::WrongRequest);
        }
        if self.args_digest != args_digest {
            return Err(Rejected::WrongRequest);
        }
        if self.generation != generation {
            return Err(Rejected::WrongGeneration);
        }
        Ok(())
    }
}
