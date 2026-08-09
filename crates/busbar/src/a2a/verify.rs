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
    /// A transport-pinned mechanism with no `pin.key:` SPKI to compare against. The sibling of
    /// [`VerifyRefusal::NoIssuerKey`], for the same reason: a registration that names a root and
    /// carries nothing to check it with has no root.
    NoTransportPin(&'static str),
    /// A transport-pinned mechanism whose fetch produced NO peer certificate — a plaintext hop, or
    /// a certificate the peer served that yielded no SubjectPublicKeyInfo.
    ///
    /// REFUSED, NOT DEGRADED. "We could not look" and "it matched" are the two answers a pin exists
    /// to keep apart, and a fetch that succeeded is not a transport binding that was checked.
    TransportPinNotObserved(&'static str),
    /// The peer certificate's SPKI is NOT the one the operator pinned. The transport-layer twin of
    /// [`JwsError::NoSignatureVerified`]: the endpoint answered, and it is not the endpoint the
    /// operator supplied a root for.
    TransportPinMismatch {
        mechanism: &'static str,
        expected: String,
        observed: String,
    },
    /// `pin.mechanism: mtls` — busbar has no client certificate to present, so the connection the
    /// card arrived over was authenticated in ONE direction.
    ///
    /// The peer half of an `mtls` pin is checked exactly as `cert_spki`'s is; what is missing is
    /// the MUTUAL half. Recording `mtls` as satisfied over a one-way handshake would put "busbar
    /// proved who it was to this endpoint" into the store about a connection where it did not, and
    /// an operator who chose `mtls` over `cert_spki` chose it for precisely that half. There is no
    /// grammar under `agents:` naming busbar's client certificate, so the refusal names the missing
    /// thing rather than the mechanism.
    MutualTlsNotPresented,
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
            VerifyRefusal::NoTransportPin(m) => write!(
                f,
                "`pin.mechanism: {m}` carries no `pin.key:`; it binds the card endpoint's \
                 certificate and there is no SubjectPublicKeyInfo hash to bind it to"
            ),
            VerifyRefusal::TransportPinNotObserved(m) => write!(
                f,
                "`pin.mechanism: {m}` binds the CARD ENDPOINT's certificate, and this fetch \
                 observed none — the hop was plaintext, or the peer's certificate yielded no \
                 subject-public-key-info. Refused rather than recorded as satisfied: a fetch that \
                 succeeded is not a transport binding that was checked."
            ),
            VerifyRefusal::TransportPinMismatch {
                mechanism,
                expected,
                observed,
            } => write!(
                f,
                "`pin.mechanism: {mechanism}`: the card endpoint served a certificate whose \
                 subject-public-key-info is `{observed}`, and the operator pinned `{expected}`. \
                 The endpoint answered and it is not the endpoint the operator supplied a root for."
            ),
            VerifyRefusal::MutualTlsNotPresented => write!(
                f,
                "`pin.mechanism: mtls` requires busbar to present a client certificate, and the \
                 `agents:` grammar names none, so the card arrived over a connection authenticated \
                 in one direction only. The peer half is checked exactly as `cert_spki`'s is; \
                 refused because an operator who chose `mtls` over `cert_spki` chose it for the \
                 mutual half. Use `cert_spki` for a one-way binding."
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
///
/// `observed_spki` is the transport-layer identity of the hop that SERVED this document — the
/// certificate the endpoint proved it held the key for, read off a handshake that had already
/// verified ([`super::transport`]). It is the root for the mechanisms whose root the network is,
/// and it is deliberately a separate argument rather than something read out of the document: a
/// card that named its own certificate would be naming its own trust root.
pub(crate) fn verify_document(
    pin_cfg: &AgentPinCfg,
    document: &Value,
    observed_spki: Option<&str>,
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
        // THE HONEST DEGRADE, implemented. An unsigned card has no JWS root; what it has is the
        // certificate its endpoint proved possession of, and that is a real network-layer root and
        // still not trust-on-first-use, because the operator supplied the SPKI out of band exactly
        // as they supply an issuer key.
        PinMechanism::CertSpki => {
            let expected = key.ok_or(VerifyRefusal::NoTransportPin("cert_spki"))?;
            let spki = transport_pin("cert_spki", expected, observed_spki)?;
            CardPin::CertSpki {
                spki,
                card_fingerprint: card::fingerprint(document).map_err(VerifyRefusal::Card)?,
            }
        }
        // The PEER half of `mtls` is the same check, and it is performed FIRST so that a mismatched
        // endpoint is reported as a mismatched endpoint rather than as busbar's missing client
        // certificate. Only once the peer is the pinned one does the missing mutual half become the
        // reason. Ordering the two the other way round would tell an operator staring at a
        // look-alike endpoint to go and configure a certificate.
        PinMechanism::Mtls => {
            let expected = key.ok_or(VerifyRefusal::NoTransportPin("mtls"))?;
            transport_pin("mtls", expected, observed_spki)?;
            return Err(VerifyRefusal::MutualTlsNotPresented);
        }
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

/// THE TRANSPORT-LAYER ROOT, checked. Returns the OBSERVED value, never the configured one.
///
/// Returning what was observed rather than echoing the operator's string is the point: the pin that
/// gets recorded is a fact about the connection, and a function that returned its own argument
/// would produce an identical-looking pin whether or not the comparison had happened at all.
///
/// The comparison is on the trimmed strings and is CASE-SENSITIVE. Base64 is case-significant, so a
/// case-insensitive compare would accept a value that is not the operator's key; and an operator who
/// has pasted a pin with the wrong case has pasted the wrong pin.
fn transport_pin(
    mechanism: &'static str,
    expected: &str,
    observed: Option<&str>,
) -> Result<String, VerifyRefusal> {
    let observed = observed
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or(VerifyRefusal::TransportPinNotObserved(mechanism))?;
    if observed != expected {
        return Err(VerifyRefusal::TransportPinMismatch {
            mechanism,
            expected: expected.to_string(),
            observed: observed.to_string(),
        });
    }
    Ok(observed.to_string())
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
            // The certificate of the hop that SERVED the card travels with the card. Re-fetching it
            // separately would ask the host a second question an attacker gets to answer
            // differently, which is the same hazard the single name resolution exists to remove.
            Ok(fetched) => {
                return verify_document(pin_cfg, &fetched.document, fetched.peer_spki.as_deref())
            }
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
    fn fetch_card(&self, agent_id: &str) -> Result<super::verbs::SightedCard, String> {
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
                Ok(fetched) => {
                    return Ok(super::verbs::SightedCard {
                        document: fetched.document,
                        peer_spki: fetched.peer_spki,
                    })
                }
                Err(e) => last = e.to_string(),
            }
        }
        Err(last)
    }
}

impl super::verbs::CardObserver for RegistrationProbe<'_> {
    fn observe(&self, card: &super::verbs::SightedCard) -> Result<Observation<CardPin>, String> {
        verify_document(self.pin_cfg, &card.document, card.peer_spki.as_deref())
            .map(|v| v.observation)
            .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
#[path = "tests/verify_tests.rs"]
mod verify_tests;
