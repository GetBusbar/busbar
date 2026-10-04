// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TRUST SURFACE, PLANE SIDE: what a registered agent's card was last seen to BE, judged
//! against the identity the operator APPROVED, and the two admin answers that render it
//! (`connect`, `approve`; ARCHITECT Q-L3B-VERBS). Moved from the served engine (`busbar-a2a`
//! `verbs`, `pin`, `verify`, `fetch`), its words kept; pure: a fetched document, the kernel's
//! signature verdict, the standing approval and the last sighting in, a state, a drift and the
//! views out.
//!
//! * **The card** is fetched at the agent origin's two well-known paths, canonical first; the
//!   legacy path is tried only when the canonical one produced no document ([`read_card`]).
//! * **The verification** is the registration's declared mechanism ([`verify`]): a signed card is
//!   verified against the operator's out-of-band issuer key by the KERNEL (`trust.verify`, this
//!   plane only hands it the payload and the signatures and words the verdict, [`jws_refusal`]);
//!   a transport-pinned mechanism (`cert_spki`, `mtls`) is the key the hop that served the card
//!   presented, as the CONNECTOR observed it (Q-DEL-A2A-SPKI: the agent's pin is sealed into its
//!   member route and the connector enforces it on every connection, reporting what it saw,
//!   [`Handshake`]): a matching key is observed and approvable, none is refused as not observed,
//!   another as a mismatch, and `mtls` over a hop that presented no client identity of busbar's as
//!   one-way; `unpinned` has no root and no fingerprint.
//! * **The approval** is the identity a human locked against a fingerprint they saw: `connect`
//!   previews and never grants ([`preview_view`]), `approve` re-fetches, re-verifies, compares
//!   against what the operator names ([`agrees`]) and locks it ([`Approval::approve`]). An
//!   `unpinned` registration is capped: it can be captured and inspected, never approved.
//! * **The state** is derived on every read, never stored: a failed contact is `error`; nothing
//!   locked is `pending`; a sighting that differs from the lock is `quarantined`; otherwise
//!   `approved`.

use std::collections::BTreeMap;

use busbar_contract::abi::host::service as svc;
use serde_json::Value;

use crate::a2a::card::{self, CardError};
use crate::a2a::config::{AgentDefCfg, AgentPinCfg, PinMechanism};

/// The well-known card path an agent pinned to an older protocol revision still serves.
pub const WELL_KNOWN_CARD_PATH_LEGACY: &str = "/.well-known/agent.json";

/// The largest card body accepted: a card is a small JSON document, and an unbounded read is an
/// allocation the upstream chooses the size of.
pub const MAX_CARD_BYTES: usize = 512 * 1024;

/// How long one card fetch may take: ten seconds.
pub const CARD_FETCH_TIMEOUT_MS: u64 = 10 * 1_000;

/// The identity a card verified as. The mechanism is part of the value, so a registration cannot
/// claim one root while carrying another's material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CardPin {
    /// A root: the operator's out-of-band material, and the canonical fingerprint of the card it
    /// signed or served.
    Rooted {
        /// The mechanism.
        mechanism: PinMechanism,
        /// The operator's material, as written.
        key: String,
        /// The canonical card fingerprint.
        fingerprint: String,
    },
    /// No authenticity root: inspectable, never approvable.
    Unpinned,
}

impl CardPin {
    /// The canonical fingerprint this pin is bound to, where it has one.
    #[must_use]
    pub fn fingerprint(&self) -> Option<&str> {
        match self {
            CardPin::Rooted { fingerprint, .. } => Some(fingerprint),
            CardPin::Unpinned => None,
        }
    }

    /// The mechanism's config word.
    #[must_use]
    pub fn mechanism(&self) -> &'static str {
        match self {
            CardPin::Rooted { mechanism, .. } => mechanism.token(),
            CardPin::Unpinned => PinMechanism::Unpinned.token(),
        }
    }
}

/// What a verified card presented: its identity, and its skills by id, each at the digest of its
/// canonical form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    /// The identity.
    pub pin: CardPin,
    /// `skill id -> digest`.
    pub skills: BTreeMap<String, String>,
}

/// The last contact. `Never` is not a failure: an agent nobody looked at has not been contacted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Sighting {
    /// Never contacted.
    #[default]
    Never,
    /// The fetch or the verification failed, with the operator-visible reason.
    Failed(String),
    /// Contacted and verified, and this is what the card presented.
    Seen(Observation),
}

impl Sighting {
    fn seen(&self) -> Option<&Observation> {
        match self {
            Sighting::Seen(o) => Some(o),
            _ => None,
        }
    }

    fn failure(&self) -> Option<&str> {
        match self {
            Sighting::Failed(reason) => Some(reason),
            _ => None,
        }
    }

    /// The mechanism the OBSERVED identity names, or `unpinned` where nothing was observed: what
    /// the endpoint proved, never the operator's own input echoed back.
    fn mechanism(&self) -> &'static str {
        self.seen()
            .map_or(PinMechanism::Unpinned.token(), |o| o.pin.mechanism())
    }

    fn skill_count(&self) -> usize {
        self.seen().map_or(0, |o| o.skills.len())
    }
}

/// The derived trust state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Nothing locked: nothing served.
    Pending,
    /// The lock holds against the last sighting (or nothing was sighted since). Serves.
    Approved,
    /// The last sighting differs from the lock.
    Quarantined,
    /// Taken out of service whatever its card (the anomaly breaker).
    Suspended,
    /// The last contact failed.
    Error,
}

impl State {
    /// The wire word a UI branches on.
    #[must_use]
    pub fn word(self) -> &'static str {
        match self {
            State::Pending => "pending",
            State::Approved => "approved",
            State::Quarantined => "quarantined",
            State::Suspended => "suspended",
            State::Error => "error",
        }
    }
}

/// What a sighting changed relative to the lock.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Drift {
    /// The presented identity is not the locked one.
    pub pin_changed: bool,
    /// Offered now, never ruled on.
    pub added: Vec<String>,
    /// Approved, but offered at another digest: the rug-pull row.
    pub changed: Vec<String>,
    /// Approved, and no longer offered.
    pub removed: Vec<String>,
}

impl Drift {
    /// Nothing moved.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        !self.pin_changed
            && self.added.is_empty()
            && self.changed.is_empty()
            && self.removed.is_empty()
    }
}

/// The operator's standing decision about one registration: the locked identity and the skills
/// locked with it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Approval {
    pin: Option<CardPin>,
    skills: BTreeMap<String, String>,
    suspension: Option<String>,
}

impl Approval {
    /// The locked identity.
    #[must_use]
    pub fn pin(&self) -> Option<&CardPin> {
        self.pin.as_ref()
    }

    /// Why it is suspended, when it is.
    #[must_use]
    pub fn suspension(&self) -> Option<&str> {
        self.suspension.as_deref()
    }

    /// Take it out of service for `reason`, whatever its card.
    pub fn suspend(&mut self, reason: &str) {
        self.suspension = Some(reason.to_string());
    }

    /// The derived state of this lock under `sighting`. Order is precedence: a suspension is
    /// independent of the card; a failed contact is never reported as trust; nothing locked is
    /// pending whatever else is true.
    #[must_use]
    pub fn state(&self, sighting: &Sighting) -> State {
        if self.suspension.is_some() {
            return State::Suspended;
        }
        if sighting.failure().is_some() {
            return State::Error;
        }
        // This lock is the one owner of the answer (the plane's `Approval`, as the kernel's
        // `Approval::serves` was predev's): nothing locked is pending.
        match &self.pin {
            None => State::Pending,
            Some(_) if self.drift(sighting).is_empty() => State::Approved,
            Some(_) => State::Quarantined,
        }
    }

    /// What `sighting` changed relative to this lock; nothing for a sighting that saw nothing.
    #[must_use]
    pub fn drift(&self, sighting: &Sighting) -> Drift {
        let Some(seen) = sighting.seen() else {
            return Drift::default();
        };
        let mut drift = Drift {
            pin_changed: self.pin.as_ref().is_some_and(|p| *p != seen.pin),
            ..Drift::default()
        };
        for (id, digest) in &seen.skills {
            match self.skills.get(id) {
                None => drift.added.push(id.clone()),
                Some(locked) if locked != digest => drift.changed.push(id.clone()),
                Some(_) => {}
            }
        }
        drift.removed = self
            .skills
            .keys()
            .filter(|id| !seen.skills.contains_key(*id))
            .cloned()
            .collect();
        drift
    }

    /// LOCK what `sighting` presented: its identity and its skills. An `unpinned` identity is
    /// refused (the cap is this plane's ruling about what its artifact means), and so is a
    /// sighting that presented none.
    ///
    /// # Errors
    ///
    /// The refusal, in the served engine's words.
    pub fn approve(&mut self, sighting: &Sighting) -> Result<(), String> {
        let Some(seen) = sighting.seen() else {
            return Err(
                "cannot approve: no identity pin was supplied and none was observed".to_string(),
            );
        };
        if seen.pin == CardPin::Unpinned {
            return Err(
                "cannot approve: this registration has no authenticity root (unpinned). Supply an \
                 issuer key out of band, or pin the endpoint at the transport layer."
                    .to_string(),
            );
        }
        self.pin = Some(seen.pin.clone());
        self.skills.clone_from(&seen.skills);
        Ok(())
    }
}

/// ONE REGISTRATION'S TRUST, as the plane holds it in memory: the lock, the pin it was locked
/// under, the last sighting, and the re-verification ledger verify-on-call keeps.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Standing {
    /// The lock.
    pub approval: Approval,
    /// The registration's `pin:` when the lock was taken; a lock taken under another pin is not
    /// the operator's decision about this one.
    pub locked_under: Option<AgentPinCfg>,
    /// The last sighting.
    pub sighting: Sighting,
    /// When verify-on-call last looked, and when it last saw drift.
    pub ledger: Ledger,
    /// The anomaly breaker's observation window.
    pub window: crate::a2a::anomaly::Window,
    /// The anomaly breaker's trip points; none configured trips nothing.
    pub thresholds: crate::a2a::anomaly::Thresholds,
}

/// THE RE-VERIFICATION LEDGER of one registration (the served engine's `reverify::Ledger`): when
/// verify-on-call last looked, and when, and how often, it saw drift.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ledger {
    /// The last look, milliseconds on the host's wall clock; `None` = never.
    pub last_checked_ms: Option<u64>,
    /// The last look that saw drift.
    pub last_drift_ms: Option<u64>,
    /// How many looks saw drift.
    pub drift_observations: u64,
}

/// A registration's re-verification cadence (`reverify_ttl`, `recovery_backoff`), milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cadence {
    /// The longest a verification is reused before the card is re-fetched; `0` is strict-live.
    pub ttl_ms: u64,
    /// How long after a drift a clean answer is disbelieved.
    pub recovery_backoff_ms: u64,
}

impl Cadence {
    /// The cadence `def` spells, its absent keys at their declared defaults. The kernel judged
    /// both keys at parse, so a duration that does not read here reads as its default.
    #[must_use]
    pub fn of(def: &AgentDefCfg) -> Self {
        let ms = |given: Option<&str>, default: &str| {
            let secs = |text: &str| busbar_contract::duration::parse_duration_secs(text).ok();
            given
                .and_then(secs)
                .or_else(|| secs(default))
                .unwrap_or(0)
                .saturating_mul(1_000)
        };
        Self {
            ttl_ms: ms(
                def.reverify_ttl.as_deref(),
                crate::a2a::config::DEFAULT_REVERIFY_TTL,
            ),
            recovery_backoff_ms: ms(
                def.recovery_backoff.as_deref(),
                crate::door::DEFAULT_RECOVERY_BACKOFF,
            ),
        }
    }

    /// Is a look due at `now_ms` (the served engine's `reverify::due`)? Never looked, a clock that
    /// went backwards, and a lapsed `ttl_ms` are each due.
    #[must_use]
    pub fn due(&self, ledger: &Ledger, now_ms: u64) -> bool {
        ledger
            .last_checked_ms
            .is_none_or(|last| now_ms < last || now_ms - last >= self.ttl_ms)
    }

    /// FOLD what one look `observed` into what is recorded (the served engine's
    /// `reverify::settle`): a failed contact is recorded, never read as "unchanged"; drift is
    /// recorded at once and stamps the drift clock; a clean answer within `recovery_backoff_ms` of
    /// the last drift is disbelieved and the recorded sighting kept. Detection is never held.
    pub fn settle(
        &self,
        approval: &Approval,
        recorded: &Sighting,
        observed: Sighting,
        ledger: &mut Ledger,
        now_ms: u64,
    ) -> Sighting {
        ledger.last_checked_ms = Some(now_ms);
        match &observed {
            Sighting::Failed(_) => observed,
            Sighting::Never => recorded.clone(),
            Sighting::Seen(_) => {
                if !approval.drift(&observed).is_empty() {
                    ledger.drift_observations += 1;
                    ledger.last_drift_ms = Some(now_ms);
                    return observed;
                }
                let held = ledger.last_drift_ms.is_some_and(|drifted| {
                    now_ms < drifted || now_ms - drifted < self.recovery_backoff_ms
                });
                if held {
                    recorded.clone()
                } else {
                    observed
                }
            }
        }
    }
}

impl Standing {
    /// EVALUATE THE ANOMALY BREAKER AND ACT ON IT (the served engine's
    /// `AgentRegistration::apply_anomaly_breaker`, run after each re-verification): a trip suspends
    /// the registration with the trip's reason. It never lifts a suspension: resuming is an
    /// operator's act. The trip applied, if any.
    pub fn apply_anomaly_breaker(&mut self) -> Option<crate::a2a::anomaly::Trip> {
        if self.approval.suspension().is_some() {
            return None;
        }
        let trip = crate::a2a::anomaly::evaluate(&self.window, &self.thresholds)?;
        self.approval.suspend(&trip.reason());
        Some(trip)
    }

    /// The lock that holds under the registration's `pin` now: none when the pin moved since.
    #[must_use]
    pub fn approval_under(&self, pin: &AgentPinCfg) -> Approval {
        if self.locked_under.as_ref() == Some(pin) {
            self.approval.clone()
        } else {
            Approval::default()
        }
    }
}

/// THE ADMISSION GATE'S QUESTION about one registration (the served engine's ordered gate, its
/// artifact step): its derived state from what is recorded. Only `Approved` serves; a
/// registration nothing was ever locked for is `Pending`, an `unpinned` one among them, for it can
/// never be approved.
#[must_use]
pub fn state_of(standing: Option<&Standing>, def: &AgentDefCfg) -> State {
    standing.map_or(State::Pending, |s| {
        s.approval_under(&def.pin).state(&s.sighting)
    })
}

/// THE REFUSAL OF A UNIT WHOSE AGENT IS NOT SERVING, in the served engine's words: addressed to
/// the agent (`addressed`), its admission refusal (`503`, `-32004`, `fronted agent `<id>` is not
/// serving (<state>)[: <suspension>]`); routed by the caller's scope, the catalogue's (an agent that is not
/// serving is in no caller's catalogue, so none reaches: `400`, `-32004`).
#[must_use]
pub fn not_serving(
    addressed: Option<&str>,
    state: State,
    reason: Option<&str>,
) -> crate::arrival::Refusal {
    match (addressed, reason) {
        (Some(agent), Some(reason)) => crate::arrival::kernel_refusal(
            NOT_SERVING_STATUS,
            &format!("fronted agent `{agent}` is not serving ({state:?}): {reason}"),
        ),
        (Some(agent), None) => crate::arrival::kernel_refusal(
            NOT_SERVING_STATUS,
            &format!("fronted agent `{agent}` is not serving ({state:?})"),
        ),
        (None, _) => crate::arrival::scope_refusal(""),
    }
}

/// The status a unit addressed to an agent that is not serving is refused with.
pub const NOT_SERVING_STATUS: u32 = 503;

// ── THE FETCH ────────────────────────────────────────────────────────────────────────────────────

/// The two well-known discovery URLs of `endpoint`'s origin, canonical first.
///
/// # Errors
///
/// `endpoint` is not a URL.
pub fn discovery_urls(endpoint: &str) -> Result<[String; 2], String> {
    let base = url::Url::parse(endpoint)
        .map_err(|_| format!("agent card URL is not a URL: `{}`", endpoint.trim()))?;
    let at = |path: &str| {
        let mut u = base.clone();
        u.set_path(path);
        u.set_query(None);
        u.set_fragment(None);
        u.to_string()
    };
    Ok([
        at(crate::WELL_KNOWN_CARD_PATH),
        at(WELL_KNOWN_CARD_PATH_LEGACY),
    ])
}

/// The refusal of a card URL a registration may not be fetched at: a scheme other than `https`,
/// unless the registration's `allow_private` admits plaintext.
#[must_use]
pub fn scheme_refusal(url: &str, allow_private: bool) -> Option<String> {
    let scheme = url
        .split(':')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if scheme == "https" || (scheme == "http" && allow_private) {
        return None;
    }
    Some(format!(
        "agent card URL `{url}` uses scheme `{scheme}`; a card fetched over plaintext can be \
         rewritten in flight. Use https://, or set this registration's `allow_private: true` if \
         the endpoint is a loopback or private one you meant."
    ))
}

/// How many redirects one card fetch follows (the engine's `FetchPolicy::max_redirects`).
pub const MAX_REDIRECTS: u8 = 3;

/// THE NEXT HOP of a card fetch that answered `status` at `url` (the engine's `fetch_card`): `None`
/// when it is not a redirect; the URL its `location` names, resolved against `url`, when it is and
/// the chain has followed fewer than [`MAX_REDIRECTS`] (`redirects`).
///
/// # Errors
///
/// A redirect past the bound, or one with no usable `location`, in the engine's words.
pub fn next_hop(
    url: &str,
    status: u16,
    location: Option<&str>,
    redirects: u8,
) -> Result<Option<String>, String> {
    if !(300..400).contains(&status) {
        return Ok(None);
    }
    if MAX_REDIRECTS <= redirects {
        return Err(format!(
            "agent card fetch exceeded {MAX_REDIRECTS} redirect(s), still redirecting at `{url}`"
        ));
    }
    let without = || {
        format!("agent card fetch got HTTP {status} from `{url}` with no usable Location header")
    };
    let location = location
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .ok_or_else(without)?;
    let base = url::Url::parse(url).map_err(|_| without())?;
    base.join(location)
        .map(|next| Some(next.to_string()))
        .map_err(|_| without())
}

/// THE HOST a card URL names, as the engine's guard judged it: an IPv6 literal unbracketed and a
/// trailing root dot dropped; `None` for a URL with no host.
#[must_use]
pub fn host_of(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    let raw = parsed.host_str()?;
    let host = raw.strip_prefix('[').unwrap_or(raw);
    let host = host.strip_suffix(']').unwrap_or(host);
    Some(host.strip_suffix('.').unwrap_or(host).to_string())
}

/// THE GUARD'S REFUSAL OF A CARD HOST BY ITS NAME (the `DEST_*` verdict the destination judge gave
/// the name alone), in the engine's words; `None` for a verdict that admits it.
#[must_use]
pub fn refused_name(url: &str, verdict: u64) -> Option<String> {
    let host = host_of(url).unwrap_or_default();
    let why = match verdict {
        svc::DEST_ALLOWED => return None,
        svc::DEST_SCHEME | svc::DEST_PLAINTEXT => {
            return scheme_refusal(url, false)
                .or_else(|| Some(format!("agent card URL `{url}` has no host")))
        }
        svc::DEST_NO_HOST => return Some(format!("agent card URL `{url}` has no host")),
        svc::DEST_METADATA => "a cloud-metadata name",
        svc::DEST_INTERNAL => {
            "a loopback name; set this registration's `allow_private: true` if that is \
             deliberate"
        }
        svc::DEST_OBFUSCATED => {
            "an alternate IPv4 encoding a resolver still expands to an internal address"
        }
        svc::DEST_NO_ADDRESSES => return Some(no_addresses(&host)),
        svc::DEST_UNRESOLVABLE => return Some(unresolvable(&host, "")),
        _ => return Some(no_addresses(&host)),
    };
    Some(format!(
        "SSRF guard refused the agent card fetch: host `{host}` is {why}"
    ))
}

/// THE GUARD'S REFUSAL OF AN ADDRESS a card host resolved to, in the engine's words (a
/// cloud-metadata address and an internal one alike: the sentence says which the knob speaks for).
#[must_use]
pub fn refused_address(url: &str, addr: &str) -> String {
    let host = host_of(url).unwrap_or_default();
    format!(
        "SSRF guard refused the agent card fetch: host `{host}` resolved to the internal address \
         {addr}; set this registration's `allow_private: true` if reaching it is deliberate. A \
         cloud-metadata address is refused whatever that is set to."
    )
}

/// `host` as the URL a destination judge reads an address literal by; `None` when `host` is a
/// name, not an address.
#[must_use]
pub fn literal_url(host: &str) -> Option<String> {
    match url::Host::parse(host).or_else(|_| url::Host::parse(&format!("[{host}]"))) {
        Ok(url::Host::Ipv4(v4)) => Some(format!("https://{v4}/")),
        Ok(url::Host::Ipv6(v6)) => Some(format!("https://[{v6}]/")),
        _ => None,
    }
}

/// A card host that resolved to nothing, in the engine's words.
#[must_use]
pub fn no_addresses(host: &str) -> String {
    format!(
        "agent card host `{host}` resolved to no addresses at all; there is nothing to connect to \
         and nothing to have judged"
    )
}

/// A card host that did not resolve, in the engine's words, naming the resolver's `reason` (none
/// named when the judge gave none).
#[must_use]
pub fn unresolvable(host: &str, reason: &str) -> String {
    if reason.is_empty() {
        return format!("agent card host `{host}` did not resolve");
    }
    format!("agent card host `{host}` did not resolve: {reason}")
}

/// THE GUARD'S REFUSAL OF A CARD HOP, in the engine's words, from the destination judge's
/// `verdict` and what it named as deciding it (`detail`: the refused address, or the resolver's
/// reason): an address refusal — a literal host's, or one the name resolved to, cloud-metadata or
/// internal alike — names the address; a failed resolution names the resolver's reason; any other
/// refusal is the name's.
#[must_use]
pub fn refused_judgement(url: &str, verdict: u64, detail: Option<&str>) -> String {
    let host = host_of(url).unwrap_or_default();
    let address = match verdict {
        svc::DEST_INTERNAL | svc::DEST_METADATA => detail
            .map(str::to_string)
            .or_else(|| literal_url(&host).map(|_| host.clone())),
        svc::DEST_UNRESOLVABLE => return unresolvable(&host, detail.unwrap_or_default()),
        _ => None,
    };
    match address {
        Some(addr) => refused_address(url, &addr),
        None => refused_name(url, verdict).unwrap_or_else(|| no_addresses(&host)),
    }
}

/// The words the engine's HTTP client gave a hop whose deadline passed (predev
/// `egress::engine::HOP_DEADLINE_CAUSE`).
pub const HOP_DEADLINE_CAUSE: &str = "governed egress hop exceeded its deadline";

/// THE CONNECTION'S FAILURE IN THE ENGINE'S WORDS: what predev's card fetch printed after
/// "failed: " — its HTTP client's error with the cause chain flattened (`egress::with_cause` over
/// `EngineError`, `client error ({kind})`, then each cause): the socket's open failing as
/// `client error (Connect): tcp connect error: <the socket's error>`, connection security as
/// `client error (Connect): <its error>`, the open connection as
/// `client error (SendRequest): connection error: <the socket's error>`, the framer failing the
/// open connection as `client error (SendRequest): <its error>` (the far end closing before its
/// reply is whole: `connection closed before message completed`), and a deadline as the hop's own
/// words. `cause` is the `CAUSE_*` stage the connector named; with none named, the
/// connector's own text.
#[must_use]
pub fn transport_err(cause: u64, failure: &busbar_contract::abi::sdk::conn::ConnFailure) -> String {
    use busbar_contract::abi::host::conn::connector::{
        CAUSE_CONNECT, CAUSE_DEADLINE, CAUSE_EXCHANGE, CAUSE_FRAMER, CAUSE_SECURITY,
    };
    let text = failure.to_string();
    match cause {
        CAUSE_CONNECT => format!("client error (Connect): tcp connect error: {text}"),
        CAUSE_SECURITY => format!("client error (Connect): {text}"),
        CAUSE_EXCHANGE => format!("client error (SendRequest): connection error: {text}"),
        CAUSE_FRAMER => format!("client error (SendRequest): {text}"),
        CAUSE_DEADLINE => HOP_DEADLINE_CAUSE.to_string(),
        _ => text,
    }
}

/// THE CARD one fetch of `url` answered: `answer` is the far end's status and body, or why the
/// connection failed. A status outside 2xx, a body over [`MAX_CARD_BYTES`] and a body that is not
/// a JSON object are each refused in the served engine's words.
///
/// # Errors
///
/// The refusal.
pub fn read_card(url: &str, answer: Result<(u16, &[u8]), String>) -> Result<Value, String> {
    let (status, body) = answer.map_err(|e| format!("agent card fetch of `{url}` failed: {e}"))?;
    if !(200..300).contains(&status) {
        return Err(format!(
            "agent card fetch of `{url}` returned HTTP {status}"
        ));
    }
    if body.len() > MAX_CARD_BYTES {
        return Err(format!(
            "agent card at `{url}` is {} bytes, over the configured ceiling",
            body.len()
        ));
    }
    let not_a_card = |err: String| format!("the document at `{url}` is not an agent card: {err}");
    let document: Value = serde_json::from_slice(body).map_err(|e| not_a_card(e.to_string()))?;
    if !document.is_object() {
        return Err(not_a_card("the document is not a JSON object".to_string()));
    }
    Ok(document)
}

// ── THE VERIFICATION ─────────────────────────────────────────────────────────────────────────────

/// WHAT THE HOP THAT SERVED A CARD OBSERVED, as the connector's facts say (the served engine's
/// `Handshake`: `peer_key_pin` off the accepted handshake, `client_identity_offered`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Handshake {
    /// The far end's key pin; `None` = the hop carried no certificate.
    pub peer_key_pin: Option<String>,
    /// Whether busbar presented its client identity in that handshake.
    pub client_identity_offered: bool,
}

/// THE TRANSPORT-LAYER ROOT, checked (the served engine's `transport_pin`). Returns the OBSERVED
/// value, never the configured one: the pin recorded is a fact about the connection. The compare is
/// on the trimmed strings and CASE-SENSITIVE (base64 is case-significant).
fn transport_pin(
    mechanism: &str,
    expected: &str,
    observed: Option<&str>,
) -> Result<String, String> {
    let observed = observed
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| not_observed(mechanism))?;
    if observed != expected {
        return Err(format!(
            "`pin.mechanism: {mechanism}`: the card endpoint served a certificate whose \
             subject-public-key-info is `{observed}`, and the operator pinned `{expected}`. The \
             endpoint answered and it is not the endpoint the operator supplied a root for."
        ));
    }
    Ok(observed.to_string())
}

/// A transport-pinned fetch that observed no certificate, in the served engine's words.
fn not_observed(mechanism: &str) -> String {
    format!(
        "`pin.mechanism: {mechanism}` binds the CARD ENDPOINT's certificate, and this fetch \
         observed none — the hop was plaintext, or the peer's certificate yielded no \
         subject-public-key-info. Refused rather than recorded as satisfied: a fetch that \
         succeeded is not a transport binding that was checked."
    )
}

/// `mtls` over a hop that presented no client certificate of busbar's, in the served engine's
/// words.
const MUTUAL_TLS_NOT_PRESENTED: &str = "`pin.mechanism: mtls` requires busbar to present a client \
     certificate, and the hop that served this card carried none, so it arrived over a connection \
     authenticated in one direction only. The peer half is checked exactly as `cert_spki`'s is; \
     refused because an operator who chose `mtls` over `cert_spki` chose it for the mutual half. \
     Name the certificate with this registration's `client_identity.cert:` and \
     `client_identity.key:`, or use `cert_spki` for a one-way binding.";

/// THE REFUSAL A FAILED CARD FETCH OF A TRANSPORT-PINNED REGISTRATION READS AS, where the hop says
/// why: the connector refused a far end serving another key than the pinned one (`hop` names the
/// key it served: the served engine's mismatch), or refused a plaintext card URL (`url`), which
/// has no certificate to observe (its not-observed refusal). `None`: the fetch's own refusal
/// stands.
#[must_use]
pub fn hop_refusal(pin: &AgentPinCfg, hop: &Handshake, url: &str) -> Option<String> {
    if !matches!(
        pin.mechanism,
        PinMechanism::CertKeyPin | PinMechanism::MutualTls
    ) {
        return None;
    }
    let expected = pin
        .key
        .as_deref()
        .map(str::trim)
        .filter(|k| !k.is_empty())?;
    let mechanism = pin.mechanism.token();
    match hop.peer_key_pin.as_deref() {
        Some(observed) => transport_pin(mechanism, expected, Some(observed)).err(),
        None if url.trim_start().to_ascii_lowercase().starts_with("http:") => {
            Some(not_observed(mechanism))
        }
        None => None,
    }
}

/// What the kernel's `trust.verify` is handed for a signed card: the detached payload (the
/// canonical card minus its `signatures`) and the signatures as written (empty = none).
///
/// # Errors
///
/// The card cannot be canonicalized.
pub fn signed_parts(card: &Value) -> Result<(Vec<u8>, Vec<u8>), String> {
    let payload = card::signing_payload(card).map_err(|e| e.to_string())?;
    let signatures = card
        .get("signatures")
        .map(|s| serde_json::to_vec(s).unwrap_or_default())
        .unwrap_or_default();
    Ok((payload.into_bytes(), signatures))
}

/// The kernel's `SIGNED_*` verdict on `card`, in this plane's words: `None` when it verified;
/// `named` is the algorithm or critical member it refused.
#[must_use]
pub fn jws_refusal(verdict: u64, named: &str, card: &Value) -> Option<String> {
    Some(match verdict {
        svc::SIGNED_VERIFIED => return None,
        svc::SIGNED_MALFORMED_ROOT => {
            "the pinned issuer key is not an Ed25519 SubjectPublicKeyInfo".to_string()
        }
        svc::SIGNED_TOO_MANY => format!(
            "the agent card carries {} signatures, more than any legitimate card needs",
            card.get("signatures")
                .and_then(Value::as_array)
                .map_or(0, Vec::len)
        ),
        svc::SIGNED_MALFORMED_HEADER => {
            "a signature's protected header is not a base64url JSON object".to_string()
        }
        svc::SIGNED_ALGORITHM => format!(
            "signature algorithm `{named}` is refused: the pinned key selects the algorithm, and a \
             header that disagrees with it is not honored"
        ),
        svc::SIGNED_CRITICAL => {
            format!("a signature marks `{named}` critical and this verifier does not implement it")
        }
        svc::SIGNED_MALFORMED_SIGNATURE => "a signature is not 64 bytes of base64url".to_string(),
        svc::SIGNED_NOT_BY_ROOT => {
            "the agent card is signed, but not by the pinned issuer key".to_string()
        }
        _ => "the agent card carries no signature".to_string(),
    })
}

/// VERIFY one fetched card against the registration's declared pin. `signed` is the kernel's
/// verdict on the card's signatures (`trust.verify`), asked only for a signed root: `Ok` when they
/// verified, else the refusal in this plane's words. `hop` is what the connection that served the
/// card observed: a transport-pinned mechanism's root (the served engine's order: the peer half
/// first, then `mtls`'s mutual half).
///
/// # Errors
///
/// Why the card is not accepted as the registration's.
pub fn verify(
    pin: &AgentPinCfg,
    card: &Value,
    hop: &Handshake,
    signed: impl FnOnce() -> Result<(), String>,
) -> Result<Observation, String> {
    let key = pin.key.as_deref().map(str::trim).filter(|k| !k.is_empty());
    let mechanism = pin.mechanism;
    let fingerprint = |card: &Value| card::fingerprint(card).map_err(|e: CardError| e.to_string());
    let pin = match (mechanism, key) {
        (PinMechanism::JwsIssuerKey, None) => {
            return Err(
                "`pin.mechanism: jws_issuer_key` carries no `pin.key:`; a registration that \
                 claims a signed root and has nothing to verify with has no root"
                    .to_string(),
            )
        }
        (PinMechanism::JwsIssuerKey, Some(key)) => {
            signed()?;
            CardPin::Rooted {
                mechanism,
                key: key.to_string(),
                fingerprint: fingerprint(card)?,
            }
        }
        (PinMechanism::CertKeyPin | PinMechanism::MutualTls, None) => {
            return Err(format!(
                "`pin.mechanism: {}` carries no `pin.key:`; it binds the card endpoint's \
                 certificate and there is no SubjectPublicKeyInfo hash to bind it to",
                mechanism.token()
            ))
        }
        (PinMechanism::CertKeyPin | PinMechanism::MutualTls, Some(expected)) => {
            // THE PEER HALF FIRST: a mismatched endpoint is reported as one, never as busbar's
            // missing client certificate.
            let key = transport_pin(mechanism.token(), expected, hop.peer_key_pin.as_deref())?;
            if mechanism == PinMechanism::MutualTls && !hop.client_identity_offered {
                return Err(MUTUAL_TLS_NOT_PRESENTED.to_string());
            }
            CardPin::Rooted {
                mechanism,
                key,
                fingerprint: fingerprint(card)?,
            }
        }
        (PinMechanism::Unpinned, Some(_)) => {
            return Err(
                "`pin.mechanism: unpinned` carries `pin.key:`. `unpinned` means there is no \
                 authenticity root; key material that is never verified against reads to an \
                 operator as protection that does not exist"
                    .to_string(),
            )
        }
        (PinMechanism::Unpinned, None) => CardPin::Unpinned,
    };
    let skills = card::skill_digests(card).map_err(|e| e.to_string())?;
    Ok(Observation { pin, skills })
}

// ── THE VERBS' ANSWERS ───────────────────────────────────────────────────────────────────────────

/// THE TRUST VIEW of one registered agent, field for field the served engine's: what both verbs
/// answer with.
#[derive(serde::Serialize)]
struct TrustView<'a> {
    name: &'a str,
    state: &'static str,
    pin_mechanism: &'static str,
    fingerprint: Option<&'a str>,
    pin_changed: bool,
    added: Vec<String>,
    changed: Vec<String>,
    removed: Vec<String>,
    observed_skills: usize,
    failure: Option<&'a str>,
}

fn view(
    name: &str,
    state: State,
    fingerprint: Option<&str>,
    approval: &Approval,
    sighting: &Sighting,
) -> String {
    let d = approval.drift(sighting);
    serde_json::to_string(&TrustView {
        name,
        state: state.word(),
        pin_mechanism: sighting.mechanism(),
        fingerprint,
        pin_changed: d.pin_changed,
        added: d.added,
        changed: d.changed,
        removed: d.removed,
        observed_skills: sighting.skill_count(),
        failure: sighting.failure(),
    })
    .unwrap_or_default()
}

/// `connect`'s answer: a PREVIEW of `sighting` against `approval`. It never reports `approved` —
/// a match against an existing lock is reported `pending`, so the preview cannot be read as the
/// grant — and it surfaces the fingerprint the operator is being asked to approve.
#[must_use]
pub fn preview_view(name: &str, approval: &Approval, sighting: &Sighting) -> String {
    let state = match approval.state(sighting) {
        State::Approved => State::Pending,
        other => other,
    };
    let fingerprint = sighting.seen().and_then(|o| o.pin.fingerprint());
    view(name, state, fingerprint, approval, sighting)
}

/// `approve`'s answer: the registration as it now stands, its fingerprint the locked one.
#[must_use]
pub fn registration_view(name: &str, approval: &Approval, sighting: &Sighting) -> String {
    let fingerprint = approval.pin().and_then(CardPin::fingerprint);
    view(
        name,
        approval.state(sighting),
        fingerprint,
        approval,
        sighting,
    )
}

/// DOES WHAT THE ENDPOINT SERVES NOW AGREE WITH WHAT THE OPERATOR SAYS THEY APPROVED? Every arm
/// is a refusal but the one where the observed fingerprint is the one `claimed` names.
///
/// # Errors
///
/// The refusal, in the served engine's words.
pub fn agrees(sighting: &Sighting, claimed: &str) -> Result<(), String> {
    if claimed.is_empty() {
        return Err(
            "`fingerprint` must name the canonical card fingerprint `connect` reported. An \
             approval with nothing to compare is trust-on-first-use with a button on it."
                .to_string(),
        );
    }
    if let Some(reason) = sighting.failure() {
        return Err(format!(
            "the agent's card could not be authenticated, so there is nothing to approve: {reason}"
        ));
    }
    match sighting.seen().and_then(|o| o.pin.fingerprint()) {
        None => Err(
            "this registration has no authenticity root (`pin.mechanism: unpinned`), so the card \
             it serves has no fingerprint to approve. Supply an issuer key or a certificate SPKI \
             out of band and name it in `pin:`."
                .to_string(),
        ),
        Some(observed) if observed == claimed => Ok(()),
        Some(observed) => Err(format!(
            "the endpoint is serving fingerprint `{observed}` and the approval names `{claimed}`. \
             The card moved between the preview and the approval, or the approval is for a \
             different agent; re-run `connect` and read the new fingerprint before approving."
        )),
    }
}

/// THE `approve` BODY, `{"fingerprint": "…"}`, read as the served engine's JSON extractor read it:
/// a JSON media type first, then the one field and no other. The fingerprint, or the refusal.
///
/// # Errors
///
/// The refusal, naming what the body must be.
pub fn approve_body(content_type: Option<&str>, body: &[u8]) -> Result<String, String> {
    let refused = |e: String| {
        format!(
            "the approve body must be `{{\"fingerprint\": \"…\"}}` naming the fingerprint \
             `connect` reported: {e}"
        )
    };
    if !content_type.is_some_and(is_json_media_type) {
        return Err(refused(
            "Expected request with `Content-Type: application/json`".to_string(),
        ));
    }
    let mut inside = None;
    let mut reader = serde_json::Deserializer::from_slice(body);
    let fingerprint =
        serde::de::DeserializeSeed::deserialize(ApproveSeed(&mut inside), &mut reader)
            // Trailing bytes after the one document are a syntax refusal with no field to name.
            .and_then(|fp| reader.end().map(|()| fp));
    fingerprint.map_err(|e| {
        let at = inside.map(|seg| format!("{seg}: ")).unwrap_or_default();
        refused(match e.classify() {
            serde_json::error::Category::Data => {
                format!("Failed to deserialize the JSON body into the target type: {at}{e}")
            }
            _ => format!("Failed to parse the request body as JSON: {at}{e}"),
        })
    })
}

/// `application/json`, or any `application/*+json`, parameters aside.
fn is_json_media_type(value: &str) -> bool {
    let essence = value.split(';').next().unwrap_or_default().trim();
    let Some((kind, sub)) = essence.split_once('/') else {
        return false;
    };
    kind.eq_ignore_ascii_case("application")
        && (sub.eq_ignore_ascii_case("json") || sub.to_ascii_lowercase().ends_with("+json"))
}

/// The one field of the `approve` body, read with the path the reader was at when it failed
/// recorded in `.0` (the field's name, or `[0]` for the array spelling).
struct ApproveSeed<'a>(&'a mut Option<&'static str>);

impl<'de> serde::de::DeserializeSeed<'de> for ApproveSeed<'_> {
    type Value = String;

    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<String, D::Error> {
        d.deserialize_struct("ApproveReq", &["fingerprint"], self)
    }
}

impl<'de> serde::de::Visitor<'de> for ApproveSeed<'_> {
    type Value = String;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("struct ApproveReq")
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<String, A::Error> {
        *self.0 = Some("[0]");
        let fingerprint = seq.next_element::<String>()?;
        *self.0 = None;
        fingerprint
            .ok_or_else(|| serde::de::Error::invalid_length(0, &"struct ApproveReq with 1 element"))
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<String, A::Error> {
        let mut fingerprint = None;
        while let Some(key) = map.next_key::<String>()? {
            if key != "fingerprint" {
                return Err(serde::de::Error::unknown_field(&key, &["fingerprint"]));
            }
            if fingerprint.is_some() {
                return Err(serde::de::Error::duplicate_field("fingerprint"));
            }
            *self.0 = Some("fingerprint");
            fingerprint = Some(map.next_value::<String>()?);
            *self.0 = None;
        }
        fingerprint.ok_or_else(|| serde::de::Error::missing_field("fingerprint"))
    }
}

#[cfg(test)]
#[path = "tests/trust_tests.rs"]
mod tests;
