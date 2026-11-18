// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Versioned, owned usage observations. Ordinary `UnitCount` remains unchanged.
//! A scope is host-issued custody, never an upstream object identifier. These counts
//! must not also be emitted as ordinary billable counts for the same economic event.

use crate::{abi::mechanism::extensions, Count};
use std::collections::BTreeMap;

/// Host capability; advertised only after durable accounting admission is attached.
pub const CAPABILITY: &str = "busbar.plane.usage-observation/1";
/// Output extension carrying exactly one owned observation.
pub const INTENT: &str = "busbar.plane.usage-observation.intent/1";
/// Input extension carrying the host's durable acknowledgement.
pub const RESULT: &str = "busbar.plane.usage-observation.result/1";
/// Input extension carrying the invocation's authorized scope, never caller authority.
pub const SCOPE: &str = "busbar.plane.usage-observation.scope/1";
/// Output request to create or reattach host-authorized original accounting custody.
pub const SCOPE_INTENT: &str = "busbar.plane.usage-observation.scope-intent/1";

/// Request a host-issued scope before accepting a paid operation, or reattach it
/// under the host's authenticated principal and original upstream coordinates.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeRequest {
    /// None creates under operator policy; Some reattaches original custody.
    pub scope: Option<ScopeId>,
    /// Explicit declaration that every economic component is complete.
    #[serde(default)]
    pub close: bool,
    /// Declared usage classes that must be priced in the original host binding
    /// before paid work. Empty preserves existing lifecycle-only callers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_classes: Vec<u32>,
}
impl ScopeRequest {
    /// Request a newly reserved scope under host policy.
    pub fn create() -> Self {
        Self {
            scope: None,
            close: false,
            required_classes: Vec::new(),
        }
    }
    /// Reattach original authenticated accounting custody.
    pub fn attach(scope: ScopeId) -> Self {
        Self {
            scope: Some(scope),
            close: false,
            required_classes: Vec::new(),
        }
    }
    /// Declare complete lifecycle; host checks every known component is final.
    pub fn close(scope: ScopeId) -> Self {
        Self {
            scope: Some(scope),
            close: true,
            required_classes: Vec::new(),
        }
    }
    /// Reserve only when host policy prices every required declared usage class.
    pub fn create_requiring(classes: Vec<u32>) -> Self {
        Self {
            required_classes: classes,
            ..Self::create()
        }
    }
    /// Reattach only when original custody prices every required usage class.
    pub fn attach_requiring(scope: ScopeId, classes: Vec<u32>) -> Self {
        Self {
            required_classes: classes,
            ..Self::attach(scope)
        }
    }
    fn validate(&self) -> Result<(), InvalidObservation> {
        if self.scope == Some([0; 32])
            || (self.close && (self.scope.is_none() || !self.required_classes.is_empty()))
            || self.required_classes.len() > 64
            || has_duplicate(&self.required_classes)
        {
            return Err(InvalidObservation);
        }
        Ok(())
    }
    /// Bounded wire encoding, appended to `out` (the caller's buffer; left as it was on a refusal).
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), InvalidObservation> {
        self.validate()?;
        write_bounded(self, 1024, out)
    }
    /// Parse a bounded request, without inferring authorization from its bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, InvalidObservation> {
        if bytes.len() > 1024 {
            return Err(InvalidObservation);
        }
        let request: Self = serde_json::from_slice(bytes).map_err(|_| InvalidObservation)?;
        request.validate()?;
        Ok(request)
    }
    /// Encode the normal plane output extension, appended to `out` (the caller's buffer).
    pub fn extension(&self, out: &mut Vec<u8>) -> Result<(), InvalidObservation> {
        extensions::entry_into(out, SCOPE_INTENT, |value| self.encode(value))
    }
    /// Strictly parse one unique request from an extension blob.
    pub fn from_extensions(bytes: &[u8]) -> Result<Option<Self>, InvalidObservation> {
        extensions::unique(bytes, SCOPE_INTENT)
            .map_err(|_| InvalidObservation)?
            .map(Self::decode)
            .transpose()
    }
}
/// Host acknowledgement of durable accepted state, including idempotent no-ops.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    /// Host-generated unique durable transition identity.
    pub settlement_id: [u8; 16],
    /// These authoritative totals had already been accepted.
    pub duplicate: bool,
    /// Conflicting final evidence was retained without changing accepted totals.
    pub quarantined: bool,
}
impl Receipt {
    /// Read a bounded acknowledgement carried by the RESULT extension.
    pub fn decode(bytes: &[u8]) -> Result<Self, InvalidObservation> {
        if bytes.len() > 256 {
            return Err(InvalidObservation);
        }
        serde_json::from_slice(bytes).map_err(|_| InvalidObservation)
    }
}
/// Completed host exchange. Absence of RESULT means no completion is available yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObservationResult {
    /// A scope was durably created, reattached, or explicitly closed. The closed
    /// acknowledgement is distinct from the unchanged SCOPE input binding.
    ScopeReady { scope: ScopeId, closed: bool },
    /// Durable receipt, including quarantined evidence.
    Accepted(Receipt),
    /// Commit may have applied; retain the scope/intent for reconciliation and do
    /// not issue another paid create or substitute successful zero usage.
    PendingReconciliation,
    /// Definitive host refusal; never interpreted as successful zero usage.
    Refused,
}
/// Read the capability only from a strict complete host extension frame.
pub fn supported(bytes: &[u8]) -> Result<bool, InvalidObservation> {
    match extensions::unique(bytes, CAPABILITY).map_err(|_| InvalidObservation)? {
        None => Ok(false),
        Some(b"1") => Ok(true),
        Some(_) => Err(InvalidObservation),
    }
}
/// Read a host-issued scope without granting authority from possession alone.
pub fn scope(bytes: &[u8]) -> Result<Option<ScopeId>, InvalidObservation> {
    extensions::unique(bytes, SCOPE)
        .map_err(|_| InvalidObservation)?
        .map(|bytes| {
            let scope: ScopeId = bytes.try_into().map_err(|_| InvalidObservation)?;
            if scope == [0; 32] {
                return Err(InvalidObservation);
            }
            Ok(scope)
        })
        .transpose()
}
/// Distinguish pending (None), durable completion and definitive refusal.
pub fn result(bytes: &[u8]) -> Result<Option<ObservationResult>, InvalidObservation> {
    let Some(bytes) = extensions::unique(bytes, RESULT).map_err(|_| InvalidObservation)? else {
        return Ok(None);
    };
    if let Ok(receipt) = Receipt::decode(bytes) {
        return Ok(Some(ObservationResult::Accepted(receipt)));
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Failure {
        error: String,
    }
    if bytes.len() > 256 {
        return Err(InvalidObservation);
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ScopeReady {
        scope: ScopeId,
        closed: bool,
    }
    if let Ok(ready) = serde_json::from_slice::<ScopeReady>(bytes) {
        if ready.scope == [0; 32] {
            return Err(InvalidObservation);
        }
        return Ok(Some(ObservationResult::ScopeReady {
            scope: ready.scope,
            closed: ready.closed,
        }));
    }
    let failure: Failure = serde_json::from_slice(bytes).map_err(|_| InvalidObservation)?;
    match failure.error.as_str() {
        "refused" => Ok(Some(ObservationResult::Refused)),
        "pending" => Ok(Some(ObservationResult::PendingReconciliation)),
        _ => Err(InvalidObservation),
    }
}
/// Maximum serialized observation size before parsing or allocation.
pub const MAX_BYTES: usize = 16 * 1024;
/// Opaque host-generated scope identity; possession alone grants no authority.
pub type ScopeId = [u8; 32];

/// Whether counts describe a reservation snapshot or authoritative totals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    /// Update evidence without posting repeated charges or reducing the reservation.
    Provisional,
    /// Settle authoritative component totals, including billable failed/cancelled work.
    Final,
}

/// Adapter-authenticated ordering, used only under an operator-approved policy.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Revision {
    /// Opaque original revision evidence; never inferred from count magnitude.
    pub identity: Vec<u8>,
    /// Strictly increasing order authenticated by the authorized adapter.
    pub order: u64,
}

/// A bounded observation without prices, bucket IDs or dispatch authority.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    /// Wire version, independent of the plane ABI and `UnitCount` layout.
    pub version: u32,
    /// Original charging scope issued by the host.
    pub scope: ScopeId,
    /// Opaque economic event within the host-bound upstream account namespace.
    pub event_key: Vec<u8>,
    /// Independent economic component of the event.
    pub component_key: Vec<u8>,
    /// Authenticated revision identity/order, if the adapter supports corrections.
    pub revision: Option<Revision>,
    /// Provisional snapshots never become additive charges.
    pub state: State,
    /// Exact nonnegative quantities indexed by declared billable class.
    #[serde(deserialize_with = "unique_counts")]
    pub counts: BTreeMap<u32, Count>,
    /// Index into host-approved accounting subjects; zero is the serving subject.
    pub rated_subject: u32,
    /// Bounded protected evidence reference, not original response or credentials.
    pub evidence_ref: Vec<u8>,
}

fn unique_counts<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<u32, Count>, D::Error> {
    struct Counts;
    impl<'de> serde::de::Visitor<'de> for Counts {
        type Value = BTreeMap<u32, Count>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("at most 64 unique exact usage classes")
        }
        fn visit_map<M: serde::de::MapAccess<'de>>(
            self,
            mut map: M,
        ) -> Result<Self::Value, M::Error> {
            let mut counts = BTreeMap::new();
            while let Some((class, amount)) = map.next_entry::<u32, Count>()? {
                if counts.len() == 64 || counts.insert(class, amount).is_some() {
                    return Err(serde::de::Error::custom(
                        "duplicate or excessive usage class",
                    ));
                }
            }
            Ok(counts)
        }
    }
    deserializer.deserialize_map(Counts)
}

/// Content-free malformed/unbounded observation error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidObservation;
impl std::fmt::Display for InvalidObservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid usage observation")
    }
}
impl std::error::Error for InvalidObservation {}

impl Observation {
    /// Construct an owned observation; final validation happens at encode and host decode.
    pub fn new(scope: ScopeId, event_key: Vec<u8>, component_key: Vec<u8>) -> Self {
        Self {
            version: 1,
            scope,
            event_key,
            component_key,
            revision: None,
            state: State::Provisional,
            counts: BTreeMap::new(),
            rated_subject: 0,
            evidence_ref: Vec::new(),
        }
    }
    /// Add one exact class count; duplicate declarations are refused rather than overwritten.
    pub fn count(mut self, class: u32, amount: Count) -> Result<Self, InvalidObservation> {
        if amount < Count::ZERO || self.counts.insert(class, amount).is_some() {
            return Err(InvalidObservation);
        }
        Ok(self)
    }
    /// Mark authoritative totals, retaining all owned evidence.
    pub fn final_totals(mut self) -> Self {
        self.state = State::Final;
        self
    }
    /// Select a host-approved accounting subject; this does not dispatch a request.
    pub fn rated_to(mut self, subject: u32) -> Self {
        self.rated_subject = subject;
        self
    }
    /// Supply an authenticated correction identity and ordering.
    pub fn revision(mut self, identity: Vec<u8>, order: u64) -> Self {
        self.revision = Some(Revision { identity, order });
        self
    }
    /// Attach a protected reference to original usage evidence.
    pub fn evidence(mut self, reference: Vec<u8>) -> Self {
        self.evidence_ref = reference;
        self
    }
    /// Validate shape independently of host scope/class/subject authorization.
    pub fn validate(&self) -> Result<(), InvalidObservation> {
        let opaque = |b: &[u8]| !b.is_empty() && b.len() <= 256;
        if self.version != 1
            || self.scope == [0; 32]
            || !opaque(&self.event_key)
            || !opaque(&self.component_key)
            || (self.state == State::Final && self.counts.is_empty())
            || self.counts.len() > 64
            || self.evidence_ref.len() > 1024
            || any_negative(&self.counts)
            || self.revision.as_ref().is_some_and(|r| !opaque(&r.identity))
        {
            return Err(InvalidObservation);
        }
        Ok(())
    }
    /// Encode this intent as bounded bytes, appended to `out` (the caller's buffer; left as it was
    /// on a refusal).
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), InvalidObservation> {
        self.validate()?;
        write_bounded(self, MAX_BYTES, out)
    }
    /// Decode and validate bounded bytes; no host authorization is inferred.
    pub fn decode(bytes: &[u8]) -> Result<Self, InvalidObservation> {
        if bytes.len() > MAX_BYTES {
            return Err(InvalidObservation);
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| InvalidObservation)?;
        value.validate()?;
        Ok(value)
    }
    /// Encode the versioned extension for the normal SDK output publisher, appended to `out`.
    pub fn extension(&self, out: &mut Vec<u8>) -> Result<(), InvalidObservation> {
        extensions::entry_into(out, INTENT, |value| self.encode(value))
    }
    /// Strictly read a unique observation extension, including complete blob framing.
    pub fn from_extensions(bytes: &[u8]) -> Result<Option<Self>, InvalidObservation> {
        extensions::unique(bytes, INTENT)
            .map_err(|_| InvalidObservation)?
            .map(Self::decode)
            .transpose()
    }
}

/// `value` as JSON appended to `out`, refused (and `out` left as it was) past `max` bytes.
fn write_bounded(
    value: &impl serde::Serialize,
    max: usize,
    out: &mut Vec<u8>,
) -> Result<(), InvalidObservation> {
    let start = out.len();
    if serde_json::to_writer(&mut *out, value).is_err() || out.len() - start > max {
        out.truncate(start);
        return Err(InvalidObservation);
    }
    Ok(())
}

/// Whether an intent's own (at most 64) counts hold a negative one.
fn any_negative(counts: &BTreeMap<u32, Count>) -> bool {
    counts.values().any(|v| *v < Count::ZERO)
}

/// Whether a class is listed twice: at most 64, each compared with those before it, in place.
fn has_duplicate(classes: &[u32]) -> bool {
    (1..classes.len()).any(|i| classes[..i].contains(&classes[i]))
}

#[cfg(test)]
mod tests {
    use super::*;
    // The encoders append to the caller's buffer; the tests read them back owned.
    fn ext(
        f: impl FnOnce(&mut Vec<u8>) -> Result<(), InvalidObservation>,
    ) -> Result<Vec<u8>, InvalidObservation> {
        let mut out = Vec::new();
        f(&mut out).map(|()| out)
    }
    #[test]
    fn owned_observation_roundtrips_exact_counts_and_keeps_legacy_layout() {
        let value = Observation::new([1; 32], vec![2], vec![3])
            .count(4, Count::from_micros(i128::MAX))
            .unwrap()
            .final_totals();
        assert_eq!(
            Observation::from_extensions(&ext(|o| value.extension(o)).unwrap()).unwrap(),
            Some(value)
        );
        assert_eq!(std::mem::size_of::<crate::abi::plane::UnitCount>(), 16);
    }
    #[test]
    fn scope_lifecycle_and_unknown_outcomes_remain_distinct() {
        for request in [
            ScopeRequest::create(),
            ScopeRequest::attach([1; 32]),
            ScopeRequest::close([1; 32]),
            ScopeRequest::create_requiring(vec![0, 1, 2]),
            ScopeRequest::attach_requiring([1; 32], vec![0, 1, 2]),
        ] {
            assert_eq!(
                ScopeRequest::from_extensions(&ext(|o| request.extension(o)).unwrap()).unwrap(),
                Some(request)
            );
        }
        let refused = ScopeRequest {
            scope: None,
            close: true,
            required_classes: Vec::new(),
        };
        assert!(ext(|o| refused.encode(o)).is_err());
        assert!(ext(|o| ScopeRequest::create_requiring(vec![1, 1]).encode(o)).is_err());
        assert!(ext(|o| ScopeRequest::create_requiring((0..65).collect()).encode(o)).is_err());
        assert!(
            ScopeRequest::decode(br#"{"scope":null,"close":false,"required_classes":[1,1]}"#)
                .is_err()
        );
        assert_eq!(
            ScopeRequest::decode(br#"{"scope":null,"close":false}"#).unwrap(),
            ScopeRequest::create()
        );
        assert_eq!(result(&[]).unwrap(), None);
        assert_eq!(
            result(&extensions::encode(&[(RESULT, br#"{"error":"pending"}"#)])).unwrap(),
            Some(ObservationResult::PendingReconciliation)
        );
        assert_eq!(
            result(&extensions::encode(&[(RESULT, br#"{"error":"refused"}"#)])).unwrap(),
            Some(ObservationResult::Refused)
        );
        assert_eq!(
            scope(&extensions::encode(&[(SCOPE, &[1; 32])])).unwrap(),
            Some([1; 32])
        );
        assert!(scope(&extensions::encode(&[(SCOPE, &[1; 31])])).is_err());
    }
    #[test]
    fn malformed_and_duplicate_counts_are_refused() {
        let zero = Observation::new([0; 32], vec![1], vec![2]);
        assert!(ext(|o| zero.encode(o)).is_err());
        assert!(Observation::new([1; 32], vec![1], vec![2])
            .count(0, Count::ONE)
            .unwrap()
            .count(0, Count::ONE)
            .is_err());
        assert!(Observation::decode(&vec![b' '; MAX_BYTES + 1]).is_err());
        let one = Observation::new([1; 32], vec![1], vec![2])
            .count(0, Count::ONE)
            .unwrap()
            .final_totals();
        let encoded = ext(|o| one.encode(o)).unwrap();
        let duplicate = String::from_utf8(encoded)
            .unwrap()
            .replace("\"counts\":{\"0\":1}", "\"counts\":{\"0\":1,\"0\":2}");
        assert!(Observation::decode(duplicate.as_bytes()).is_err());
    }
}
