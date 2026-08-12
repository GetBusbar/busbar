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
    /// `pin.mechanism: mtls` — the hop that carried this card presented NO client certificate of
    /// busbar's, so the connection was authenticated in ONE direction.
    ///
    /// The peer half of an `mtls` pin is checked exactly as `cert_spki`'s is; what is missing is
    /// the MUTUAL half. Recording `mtls` as satisfied over a one-way handshake would put "busbar
    /// proved who it was to this endpoint" into the store about a connection where it did not, and
    /// an operator who chose `mtls` over `cert_spki` chose it for precisely that half.
    ///
    /// The `agents:` grammar DOES name busbar's client certificate — `client_identity: {cert, key}`
    /// — so this is no longer a refusal for every `mtls` registration. It is a refusal for a
    /// registration whose card arrived over a hop that carried none, which the config grammar
    /// already refuses to write and which a registration reaching this code by another route can
    /// still be.
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
                "`pin.mechanism: mtls` requires busbar to present a client certificate, and the hop \
                 that served this card carried none, so it arrived over a connection authenticated \
                 in one direction only. The peer half is checked exactly as `cert_spki`'s is; \
                 refused because an operator who chose `mtls` over `cert_spki` chose it for the \
                 mutual half. Name the certificate with this registration's `client_identity.cert:` \
                 and `client_identity.key:`, or use `cert_spki` for a one-way binding."
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

/// WHAT THE CONNECTION THAT DELIVERED A CARD ESTABLISHED, in BOTH directions.
///
/// One struct rather than two arguments because the two facts are one connection's, and a caller
/// that could supply the peer's half while forgetting its own would silently ask for the one-way
/// answer. Every field is a fact about the hop that served the document — never something read out
/// of the document, because a card that named its own certificate would be naming its own trust
/// root.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Handshake<'a> {
    /// The transport-layer identity of the hop that SERVED this document — the certificate the
    /// endpoint proved it held the key for, read off a handshake that had already verified
    /// ([`super::transport`]). The root for the mechanisms whose root the network is.
    pub(crate) peer_spki: Option<&'a str>,
    /// THE OTHER DIRECTION: whether that hop carried busbar's client certificate for this
    /// registration ([`super::fetch::HttpResponse::client_identity_offered`]). The mutual half of
    /// `pin.mechanism: mtls`, and the reason it is a connection fact rather than a config read.
    pub(crate) client_identity_offered: bool,
}

/// VERIFY ONE FETCHED DOCUMENT against the registration's declared mechanism.
///
/// This is where the out-of-band trust root stops being prose. The operator's key is the root; the
/// card's own claims about
/// who signed it are not consulted for anything except agreement.
pub(crate) fn verify_document(
    pin_cfg: &AgentPinCfg,
    document: &Value,
    handshake: Handshake<'_>,
) -> Result<VerifiedCard, VerifyRefusal> {
    let observed_spki = handshake.peer_spki;
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
        // BOTH HALVES OF `mtls`, IN THIS ORDER. The PEER half is `cert_spki`'s check exactly, and it
        // is performed FIRST so that a mismatched endpoint is reported as a mismatched endpoint
        // rather than as busbar's missing client certificate. Only once the peer is the pinned one
        // does the mutual half become the reason. Ordering the two the other way round would tell an
        // operator staring at a look-alike endpoint to go and configure a certificate.
        //
        // The MUTUAL half is read off the hop that delivered this card, never off the registration's
        // config: `client_identity:` names what busbar WOULD present, and this asks what the
        // connection DID carry. A pass here is the same distinction the peer half draws — "we could
        // not look" and "it matched" are different answers — applied to busbar's own end.
        PinMechanism::Mtls => {
            let expected = key.ok_or(VerifyRefusal::NoTransportPin("mtls"))?;
            let spki = transport_pin("mtls", expected, observed_spki)?;
            if !handshake.client_identity_offered {
                return Err(VerifyRefusal::MutualTlsNotPresented);
            }
            CardPin::Mtls {
                spki,
                card_fingerprint: card::fingerprint(document).map_err(VerifyRefusal::Card)?,
            }
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
                return verify_document(
                    pin_cfg,
                    &fetched.document,
                    Handshake {
                        peer_spki: fetched.peer_spki.as_deref(),
                        client_identity_offered: fetched.client_identity_offered,
                    },
                )
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
                        client_identity_offered: fetched.client_identity_offered,
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
        verify_document(
            self.pin_cfg,
            &card.document,
            Handshake {
                peer_spki: card.peer_spki.as_deref(),
                client_identity_offered: card.client_identity_offered,
            },
        )
        .map(|v| v.observation)
        .map_err(|e| e.to_string())
    }
}

// ══ THE TIMER'S HALF: this plane's `Sweeper`, driven by the ONE job in `crate::trust::sweep` ═════
//
// [`reverify_once`] above is the pass; this is what puts it on a timer, which is the difference
// between a control that exists and a control that runs.
//
// THE ASYMMETRY SURVIVES BEING SCHEDULED, and that is why the knobs are somewhere else. A scheduler
// is made of exactly the settings that would lose it — a tick interval, a concurrency cap, a
// per-agent cooldown, a "skip if we checked recently" fast path — and every one of those slows
// DETECTION. So this plane supplies no scheduling policy at all: the tick, the clock, the shutdown
// and the panic containment are `crate::trust::sweep`, once, for every plane, and that module has
// no knob either. What is here is the only part that is genuinely this plane's: the fetch.
//
// ONE TRANSPORT PER REGISTRATION, and it is a correctness property rather than a refactor. This
// sweep used to build ONE transport and use it for every registration on the plane. That read as an
// efficiency, and it was a defect with a name: `pin.mechanism: mtls` could be written in config and
// could never work, because the client certificate busbar must present is per REGISTRATION — it is
// the certificate this operator agreed to present to THAT vendor — and a single plane-wide transport
// has exactly one place to put one. Anywhere it went, it went to everybody.

/// WHICH TRANSPORT ONE REGISTRATION IS RE-VERIFIED OVER.
///
/// THE SEAM THAT USED NOT TO EXIST, and its absence was the whole of the `mtls` defect. It is
/// deliberately not a factory returning an owned transport: the production implementation builds one
/// transport per agent ONCE per config generation, and a `-> Box<dyn Transport>` would have invited
/// a rebuild per agent per tick, which is a fresh TLS client every thirty seconds for every
/// registration.
pub(crate) trait CardTransports {
    /// The transport for `agent_id`. Total, because a sweep must never skip a registration: an
    /// agent with no client identity gets one that presents no certificate and is refused by an
    /// mTLS peer, which is an observation the ledger should record rather than a hole in the sweep.
    fn for_agent(&self, agent_id: &str) -> &dyn Transport;
}

/// ONE TRANSPORT FOR EVERY REGISTRATION — the shape this sweep used to have, kept as a NAMED adapter
/// so what it costs is legible at the call site.
///
/// It is `#[cfg(test)]`, so it is not merely unused in production — it is ABSENT from the release
/// binary. A future caller that wants one transport for the whole plane has to write the words "one
/// for all" and compile it in, which is the review conversation the old signature never prompted.
#[cfg(test)]
pub(crate) struct OneForAll<'a>(pub(crate) &'a dyn Transport);

#[cfg(test)]
impl CardTransports for OneForAll<'_> {
    fn for_agent(&self, _agent_id: &str) -> &dyn Transport {
        self.0
    }
}

/// WHAT ONE RE-VERIFICATION PASS FOUND, as the shared sweep job carries it.
///
/// The `pass` is [`reverify_once`]'s own answer, unflattened: the plane's tests assert against the
/// type their subject actually produces. `drift` is carried beside it so the operator's first notice
/// names the skills that moved rather than only the fact that something did — the shared renderer
/// itemises drift on every plane, and a plane that had nothing to itemise would be the odd one out.
#[derive(Debug)]
pub(crate) struct ReverifyDetail {
    pub(crate) pass: Pass,
    pub(crate) drift: crate::trust::Drift,
    /// The DERIVED trust state after the pass landed, in the word every plane renders. Read off the
    /// registration rather than inferred from `drift_observed`, because a suspension outranks a
    /// quarantine and a log line that reported the wrong one would send an operator to the wrong
    /// remedy.
    pub(crate) state: &'static str,
}

impl crate::trust::sweep::SweepDetail for ReverifyDetail {
    fn events(&self) -> Vec<crate::trust::sweep::SweepEvent> {
        use crate::trust::sweep::SweepEvent;
        let mut events = Vec::new();
        // The breaker is reported FIRST and independently of the observation: a suspension is a
        // statement about the pattern of contacts, not about this one.
        if let Some(trip) = &self.pass.trip {
            events.push(SweepEvent::Suspended {
                reason: trip.reason().to_string(),
            });
        }
        if let Some(refusal) = &self.pass.refusal {
            events.push(SweepEvent::ContactFailed {
                reason: refusal.to_string(),
            });
            return events;
        }
        let Some(settled) = &self.pass.settled else {
            return events;
        };
        if settled.drift_observed {
            events.push(SweepEvent::Drifted {
                state: self.state,
                drift: self.drift.clone(),
            });
        } else if settled.recovery_held {
            events.push(SweepEvent::RecoveryHeld);
        }
        events
    }
}

/// ONE SWEEP over every registration on the plane.
///
/// Takes the clock as an argument and holds no timer of its own, which is what makes the asymmetry
/// testable: a test drives the same function the job drives, at times it chooses, with no sleeping
/// and nothing for a scheduler to race.
///
/// The write lock is held for the whole sweep. That is deliberate on a registry whose size is the
/// operator's `agents:` count: a sweep that released the lock between registrations could interleave
/// with a config apply and leave half the registry re-verified against one generation's pins and
/// half against another's.
pub(crate) fn reverify_sweep(
    plane: &super::plane::A2aPlane,
    resolver: &dyn Resolver,
    transports: &dyn CardTransports,
    now_ms: u64,
) -> Vec<crate::trust::sweep::SweepOutcome<ReverifyDetail>> {
    let base: FetchPolicy = plane.fetch_policy().clone();
    plane.with_registrations_mut(|registrations| {
        let mut out = Vec::with_capacity(registrations.len());
        for reg in registrations.iter_mut() {
            // A registration whose pin is not in this generation's config is one the operator has
            // REMOVED. It is not re-verified against a remembered pin: verifying a card against a
            // trust root nobody currently declares would be busbar deciding the operator did not
            // mean it.
            let Some(pin_cfg) = plane.pin_for(&reg.agent_id).cloned() else {
                continue;
            };
            // THE POLICY IS PER REGISTRATION, because `allow_private:` is. Read off the record
            // rather than from `fetch_policy_for` — this closure already holds the registry's write
            // lock, and re-entering it to read one bool would deadlock. It is the same value: the
            // record is where `from_config` lowered the operator's line to.
            let policy = FetchPolicy {
                allow_private: reg.allow_private,
                ..base.clone()
            };
            // THE TRANSPORT THAT BELONGS TO THIS REGISTRATION, carrying this registration's client
            // certificate and no other's. Asked for INSIDE the loop, per agent, which is the entire
            // structural change: one transport per plane could only ever have presented one
            // identity.
            let transport = transports.for_agent(&reg.agent_id);
            let pass = reverify_once(
                reg, &pin_cfg, resolver, transport, &policy, now_ms,
                // THE TIMER IS NOT AN OPERATOR. `sync` outranks the timer; the timer never claims
                // to be a sync, and there is no argument here through which a check could be
                // suppressed.
                false,
            );
            // Read AFTER the pass, so it reflects what was just recorded rather than the previous
            // generation's changes queue.
            let drift = reg.changes();
            let state = reg.trust_state().word();
            out.push(crate::trust::sweep::SweepOutcome {
                subject: reg.agent_id.clone(),
                due: pass.due,
                detail: ReverifyDetail { pass, drift, state },
            });
        }
        out
    })
}

/// THIS PLANE'S `Sweeper`. Holds the plane this config generation built and the per-agent transports
/// built ONCE for the job's lifetime: the identities were resolved at boot, so rebuilding the bundle
/// every tick would re-derive a constant — and, now that a transport can carry a private key, would
/// do so with key material in hand every thirty seconds.
pub(crate) struct ReverifySweeper {
    pub(crate) plane: std::sync::Arc<super::plane::A2aPlane>,
    pub(crate) live: std::sync::Arc<super::transport::LiveCardFetch>,
}

impl crate::trust::sweep::Sweeper for ReverifySweeper {
    type Detail = ReverifyDetail;

    fn plane(&self) -> crate::plane::Plane {
        crate::plane::Plane::A2a
    }

    async fn sweep(&self, now_ms: u64) -> Vec<crate::trust::sweep::SweepOutcome<ReverifyDetail>> {
        let plane = std::sync::Arc::clone(&self.plane);
        let live = std::sync::Arc::clone(&self.live);
        // OFF THE REACTOR. A card fetch is a blocking socket read behind a guard that resolves,
        // pins and connects synchronously; running it on a worker thread would stall every request
        // sharing that thread for as long as an upstream chose to take.
        match tokio::task::spawn_blocking(move || {
            reverify_sweep(&plane, live.resolver(), live.as_ref(), now_ms)
        })
        .await
        {
            Ok(outcomes) => outcomes,
            // A PANIC IN THE BLOCKING SWEEP IS RE-RAISED so the ONE containment site in
            // `trust::sweep::spawn` sees it. Swallowing it here would give this plane its own
            // private panic handling, which is a second place for the "the job continues"
            // guarantee to be got wrong.
            Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
            Err(_) => Vec::new(),
        }
    }
}

#[cfg(test)]
#[path = "tests/verify_tests.rs"]
mod verify_tests;

// THE ASYMMETRY, DRIVEN THROUGH THE SWEEP the job actually calls rather than through the pure
// function underneath it.
#[cfg(test)]
#[path = "tests/scheduler_tests.rs"]
mod scheduler_tests;
