// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DRIVER: the thing that actually looks.
//!
//! [`super::jws`], [`super::anomaly`] and [`super::reverify`] are decisions. Until this module
//! existed, nothing called them: the plane could say what a drifted card meant and had no way to
//! notice one. This is the loop that fetches, verifies against the operator's out-of-band key,
//! folds the answer into what is recorded, and applies the breaker.
//!
//! ## Verify FIRST, fingerprint only what passed
//!
//! A fingerprint taken before verification is a fingerprint of whatever arrived, and recording it
//! would put "this is what the agent offers" into the store about a document nobody authenticated.
//! [`super::pin::pin_a_signed_card`] enforces the ordering and this module never reaches around it.
//!
//! ## A failed verification is a FAILED CONTACT, not an absence of one
//!
//! The tempting shape is to skip recording when verification fails and leave the last good sighting
//! in place. That reads, from every operator-facing surface, as an agent that is still fine. So a
//! refusal is recorded as [`crate::trust::Sighting::Failed`] with the reason, which derives `Error`
//! and serves nothing — and, because `reverify::settle` deliberately does not clear the drift clock
//! on a failed contact, an upstream cannot age its own quarantine out by refusing connections.
//!
//! ## NO KNOB SLOWS DETECTION OR DELAYS DEMOTION
//!
//! The cadence has exactly one held direction and it is RECOVERY. There is no configuration in this
//! module, in [`super::reverify::Policy`] or in the `agents:` grammar that can make a drift be
//! noticed later or acted on later. That asymmetry is the point: a window an upstream can open for
//! itself by flapping is a window it will use, and choosing when to flap is entirely within its
//! gift. `tests/verify_tests.rs` enumerates the knobs and fails if one ever grows a direction.

use serde_json::Value;

use crate::trust::{Observation, Sighting};

use super::anomaly;
use super::card::{self, CardError};
use super::config::{AgentPinCfg, PinMechanism};
use super::fetch::{self, FetchPolicy, FetchRefusal, Resolver, Transport};
use super::jws::JwsError;
use super::pin::CardPin;
use super::registry::AgentRegistration;
use super::reverify::{self, Due, Settled};

/// Why a re-verification did not produce a usable observation. Every arm is a REFUSAL; there is no
/// arm meaning "could not check, carry on".
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum VerifyRefusal {
    /// The fetch itself was refused (SSRF guard, transport, status, shape).
    Fetch(FetchRefusal),
    /// The card is not signed by the operator's out-of-band issuer key. The look-alike case.
    Jws(JwsError),
    /// The card cannot be read or hashed.
    Card(CardError),
    /// `pin.mechanism: jws_issuer_key` with no key material. Refused rather than degraded: a
    /// registration that claims a signed root and has nothing to verify with has no root.
    NoIssuerKey,
    /// `pin.mechanism: unpinned` CARRYING key material. The config grammar already refuses this;
    /// it is refused HERE TOO, on the wire, because a config file is not the only way a
    /// registration reaches this code and key material that is never verified against reads to an
    /// operator as protection that does not exist.
    UnpinnedCarriesKey,
    /// A transport-layer mechanism (`cert_spki`, `mtls`) whose binding this build does not verify.
    ///
    /// REFUSED, NOT DEGRADED, and this is the honest arm of this module: the pin names the peer
    /// certificate's SPKI, and nothing in busbar's card fetch reads a peer certificate today.
    /// Treating the mechanism as satisfied because the fetch succeeded would be recording "pinned
    /// at the transport layer" about a connection nobody checked the transport of.
    TransportPinNotVerified(&'static str),
}

impl std::fmt::Display for VerifyRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyRefusal::Fetch(e) => write!(f, "{e}"),
            VerifyRefusal::Jws(e) => write!(f, "{e}"),
            VerifyRefusal::Card(e) => write!(f, "{e}"),
            VerifyRefusal::NoIssuerKey => write!(
                f,
                "`pin.mechanism: jws_issuer_key` carries no `pin.key:`; a registration that claims \
                 a signed root and has nothing to verify with has no root"
            ),
            VerifyRefusal::UnpinnedCarriesKey => write!(
                f,
                "`pin.mechanism: unpinned` carries `pin.key:`. `unpinned` means there is no \
                 authenticity root; key material that is never verified against reads to an \
                 operator as protection that does not exist"
            ),
            VerifyRefusal::TransportPinNotVerified(m) => write!(
                f,
                "`pin.mechanism: {m}` binds the CARD ENDPOINT's certificate, and this build does \
                 not read a peer certificate on the card fetch. Refused rather than recorded as \
                 satisfied: a fetch that succeeded is not a transport binding that was checked."
            ),
        }
    }
}

/// What a card VERIFIED as: the identity to compare against the locked pin, and what it offers.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct VerifiedCard {
    pub(crate) pin: CardPin,
    pub(crate) observation: Observation<CardPin>,
    /// The document AS RECEIVED, for the registration's cache.
    pub(crate) document: Value,
}

/// VERIFY ONE FETCHED DOCUMENT against the registration's declared mechanism.
///
/// This is where the out-of-band trust root stops being prose. The operator's key is the root; the
/// card's own claims about
/// who signed it are not consulted for anything except agreement.
pub(crate) fn verify_document(
    pin_cfg: &AgentPinCfg,
    document: &Value,
) -> Result<VerifiedCard, VerifyRefusal> {
    let key = pin_cfg
        .key
        .as_deref()
        .map(str::trim)
        .filter(|k| !k.is_empty());

    let pin = match pin_cfg.mechanism {
        PinMechanism::JwsIssuerKey => {
            let key = key.ok_or(VerifyRefusal::NoIssuerKey)?;
            // VERIFY FIRST, fingerprint only what passed. The ordering lives in `pin_a_signed_card`
            // and is not re-implemented here, because a second copy of it is a second chance to get
            // it the wrong way round.
            let (pin, _verified) =
                super::pin::pin_a_signed_card(document, key).map_err(VerifyRefusal::Jws)?;
            pin
        }
        PinMechanism::CertSpki => return Err(VerifyRefusal::TransportPinNotVerified("cert_spki")),
        PinMechanism::Mtls => return Err(VerifyRefusal::TransportPinNotVerified("mtls")),
        PinMechanism::Unpinned => {
            // ON THE WIRE, not only at parse. A registration does not have to have come from a
            // config file to reach here.
            if key.is_some() {
                return Err(VerifyRefusal::UnpinnedCarriesKey);
            }
            CardPin::Unpinned
        }
    };

    let observation =
        card::observation(document, Some(pin.clone())).map_err(VerifyRefusal::Card)?;
    Ok(VerifiedCard {
        pin,
        observation,
        document: document.clone(),
    })
}

/// What one pass of the re-verification job did, so a caller can audit it rather than infer it.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Pass {
    /// Why the registration was checked, or why it was not.
    pub(crate) due: Due,
    /// How the observation was folded in. `None` when nothing was checked.
    pub(crate) settled: Option<Settled<CardPin>>,
    /// The refusal, where the fetch or the verification failed. Recorded as a failed contact.
    pub(crate) refusal: Option<VerifyRefusal>,
    /// The anomaly trip that was applied on this pass, if any.
    pub(crate) trip: Option<anomaly::Trip>,
}

impl Pass {
    /// Nothing was checked, because nothing was due.
    fn skipped() -> Self {
        Self {
            due: Due::No,
            settled: None,
            refusal: None,
            trip: None,
        }
    }
}

/// ONE PASS OF THE RE-VERIFICATION JOB over one registration.
///
/// `operator_sync` is the explicit `POST …/sync` verb: it OUTRANKS the timer, because an operator
/// with out-of-band reason to suspect an agent, or one driving a scheduled vendor key rotation,
/// does not wait for it. It can only cause an EXTRA check; there is deliberately no argument, here
/// or anywhere, that can suppress one.
pub(crate) fn reverify_once(
    registration: &mut AgentRegistration,
    pin_cfg: &AgentPinCfg,
    resolver: &dyn Resolver,
    transport: &dyn Transport,
    fetch_policy: &FetchPolicy,
    now_ms: u64,
    operator_sync: bool,
) -> Pass {
    let due = reverify::due(
        &registration.ledger,
        &registration.reverify,
        now_ms,
        operator_sync,
    );
    if !due.should_check() {
        return Pass::skipped();
    }

    let observed = match fetch_and_verify(registration, pin_cfg, resolver, transport, fetch_policy)
    {
        Ok(verified) => {
            registration.cached_card = Some(verified.document);
            Ok(Sighting::Seen(verified.observation))
        }
        // A REFUSAL IS RECORDED, as a failed contact with its reason. Leaving the last good
        // sighting in place would present a card we could not authenticate as an agent that is
        // still fine.
        Err(refusal) => Err(refusal),
    };

    let (sighting, refusal) = match observed {
        Ok(s) => (s, None),
        Err(r) => (Sighting::Failed(r.to_string()), Some(r)),
    };

    let settled = reverify::settle(
        &registration.approval,
        &registration.sighting,
        sighting,
        &mut registration.ledger,
        &registration.reverify,
        now_ms,
    );
    registration.sighting = settled.sighting.clone();

    // The breaker is evaluated on the same pass, because a suspension that waits for the next
    // timer is a security control with a configurable delay on it.
    let trip = registration.apply_anomaly_breaker();

    Pass {
        due,
        settled: Some(settled),
        refusal,
        trip,
    }
}

/// Fetch the card at both well-known paths, canonical first, and verify what came back.
///
/// The legacy path is tried only when the canonical one produced NO DOCUMENT. A card that was
/// fetched and then FAILED VERIFICATION is not retried at the older path: retrying would let an
/// upstream serve a properly signed card at one path and a hostile one at the other, and have the
/// hostile one reached whenever the signed one is the first to be refused.
fn fetch_and_verify(
    registration: &AgentRegistration,
    pin_cfg: &AgentPinCfg,
    resolver: &dyn Resolver,
    transport: &dyn Transport,
    policy: &FetchPolicy,
) -> Result<VerifiedCard, VerifyRefusal> {
    let urls = fetch::discovery_urls(&registration.backend_url).map_err(VerifyRefusal::Fetch)?;
    let mut last: Option<FetchRefusal> = None;
    for url in &urls {
        match fetch::fetch_card(url, resolver, transport, policy) {
            Ok(fetched) => return verify_document(pin_cfg, &fetched.document),
            Err(e) => last = Some(e),
        }
    }
    Err(VerifyRefusal::Fetch(last.expect(
        "discovery_urls always yields at least the canonical path",
    )))
}

/// THE DELEGATING SIDE'S IMPLEMENTATION OF THE VERB LAYER'S TWO SEAMS.
///
/// [`super::verbs`] takes the card fetch and the card verification as traits so that every verb's
/// DECISION is testable against an answer a real network makes hard to produce on demand. This is
/// the production implementation of both, and it is one struct rather than two because the verbs
/// use them as a pair and a caller holding one without the other has half a probe.
///
/// The registration is borrowed rather than looked up: the backend URL is server-side only, and a
/// probe that resolved an `agent_id` to a URL itself would be a second place that decides where
/// busbar connects.
pub(crate) struct RegistrationProbe<'a> {
    pub(crate) registration: &'a AgentRegistration,
    pub(crate) pin_cfg: &'a AgentPinCfg,
    pub(crate) resolver: &'a dyn Resolver,
    pub(crate) transport: &'a dyn Transport,
    pub(crate) policy: &'a FetchPolicy,
}

impl super::verbs::CardSource for RegistrationProbe<'_> {
    /// Fetch at both well-known paths, canonical first, and hand back the document AS RECEIVED.
    ///
    /// `agent_id` is checked against the registration this probe was built for rather than used to
    /// look anything up. A probe answering about an agent it was not built for would be a
    /// cross-registration confusion in the one place where the answer becomes an approval.
    fn fetch_card(&self, agent_id: &str) -> Result<Value, String> {
        if agent_id != self.registration.agent_id {
            return Err(format!(
                "this probe was built for agent `{}` and was asked about `{agent_id}`",
                self.registration.agent_id
            ));
        }
        let urls =
            fetch::discovery_urls(&self.registration.backend_url).map_err(|e| e.to_string())?;
        let mut last = String::new();
        for url in &urls {
            match fetch::fetch_card(url, self.resolver, self.transport, self.policy) {
                Ok(fetched) => return Ok(fetched.document),
                Err(e) => last = e.to_string(),
            }
        }
        Err(last)
    }
}

impl super::verbs::CardObserver for RegistrationProbe<'_> {
    fn observe(&self, card: &Value) -> Result<Observation<CardPin>, String> {
        verify_document(self.pin_cfg, card)
            .map(|v| v.observation)
            .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
#[path = "tests/verify_tests.rs"]
mod verify_tests;
