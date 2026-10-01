// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TWO HASHES TAKEN OVER AN AGENT CARD, and the per-skill digests (moved from `busbar-a2a`'s
//! card reader, ARCHITECT C2c S7 2026-10-01 move). The plane computes them and reports them to the
//! kernel's `trust.*`, which judges them (`BUSBAR-1.6.0.md` B.3.3).
//!
//! [`signing_payload`] is what a card's JWS signature covers: the canonical card with the
//! `signatures` member removed, because a signature cannot cover itself.
//!
//! [`fingerprint`] is what an operator APPROVES and what drift is measured against: the canonical
//! WHOLE card, signatures included, over the document AS RECEIVED, so a member busbar does not model
//! still registers as drift.

use std::collections::BTreeMap;

use busbar_contract::abi::sdk::digest::sha256_tagged;
use serde_json::Value;

use super::canonical::{canonicalize, CanonicalError};

/// What went wrong reading or hashing a card. Each arm is a case where continuing would produce an
/// approval an operator could not reason about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CardError {
    /// The document is not a JSON object, so it is not a card at all.
    NotAnObject,
    /// The document cannot be canonicalized, so no reproducible hash exists for it.
    Canonical(CanonicalError),
    /// A skill carries no `id`, so there is nothing for an operator to approve it BY. An index would
    /// be worse than an error: re-ordering the array would silently move every approval.
    SkillWithoutId,
    /// Two skills share one `id`. Whichever won would decide what "approved `plan` at this digest"
    /// meant, so the ambiguity is refused rather than resolved.
    DuplicateSkillId(String),
}

impl std::fmt::Display for CardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CardError::NotAnObject => write!(f, "agent card is not a JSON object"),
            CardError::Canonical(e) => write!(f, "agent card cannot be canonicalized: {e}"),
            CardError::SkillWithoutId => {
                write!(
                    f,
                    "agent card declares a skill with no `id` to approve it by"
                )
            }
            CardError::DuplicateSkillId(id) => write!(
                f,
                "agent card declares the skill id `{id}` twice; which one an approval refers to is \
                 ambiguous"
            ),
        }
    }
}

impl From<CanonicalError> for CardError {
    fn from(e: CanonicalError) -> Self {
        CardError::Canonical(e)
    }
}

/// THE PINNED FINGERPRINT: a hash of the canonical WHOLE card, signatures included.
///
/// Over the received document, never over a busbar-owned projection of it. A member busbar does not model is still a
/// member of the thing the operator approved, and a change to it is still a change.
pub fn fingerprint(card: &Value) -> Result<String, CardError> {
    if !card.is_object() {
        return Err(CardError::NotAnObject);
    }
    Ok(sha256_tagged(canonicalize(card)?.as_bytes()))
}

/// THE JWS PAYLOAD: the canonical card with `signatures` removed, because a signature cannot cover
/// itself. Removing the member is not the same as emptying it, and the distinction is load-bearing:
/// a signer that hashed `"signatures":[]` and a verifier that hashed an absent member would disagree
/// on every signed card in existence.
pub fn signing_payload(card: &Value) -> Result<String, CardError> {
    let mut stripped = card.clone();
    let obj = stripped.as_object_mut().ok_or(CardError::NotAnObject)?;
    obj.remove("signatures");
    Ok(canonicalize(&stripped)?)
}

/// The capability set the plane-neutral machine compares: skill id to a digest of that skill's
/// canonical form.
///
/// PER SKILL, not one hash for the whole set, because the changes queue an operator works is a row
/// at a time. A single set-wide hash would make one edited description look identical to a wholesale
/// replacement, and the only available response would be to re-approve everything.
pub fn skill_digests(card: &Value) -> Result<BTreeMap<String, String>, CardError> {
    let skills = card
        .as_object()
        .ok_or(CardError::NotAnObject)?
        .get("skills")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut out = BTreeMap::new();
    for skill in &skills {
        let id = skill
            .get("id")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or(CardError::SkillWithoutId)?;
        let digest = sha256_tagged(canonicalize(skill)?.as_bytes());
        if out.insert(id.to_string(), digest).is_some() {
            return Err(CardError::DuplicateSkillId(id.to_string()));
        }
    }
    Ok(out)
}

#[cfg(test)]
#[path = "tests/card_tests.rs"]
mod tests;
