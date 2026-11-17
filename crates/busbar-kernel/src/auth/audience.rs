// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use base64::Engine as _;

/// What could be established about a presented bearer's RFC 8707 audience binding — the outcome of
/// the audience pre-filter (`crate::auth::audience::inspect_bearer`), for credentials busbar did
/// not mint. The JUDGEMENT ([`inspect_bearer`]) stays here beside it, since it reaches core's
/// governance token prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Binding {
    /// A busbar-signed token. The real audience check happens in the verifier, which has the
    /// signature and the claims; the pre-filter must not pre-judge it.
    Deferred,
    /// A JWT whose `aud` includes the expected value. Not an admission — the chain still verifies it.
    Bound,
    /// A JWT whose `aud` does not include the expected value, or which carries no `aud` at all. Both
    /// are refused for the same reason: minted for someone else, or for nobody in particular.
    Mismatch,
    /// Not a JWT and not a busbar token: nothing to read. Refused.
    Opaque,
}

pub fn inspect_bearer(token: &str, expected_aud: &str) -> Binding {
    Bearer::read(token).binding(expected_aud)
}

/// What the kernel reads of a bearer, its JWT payload decoded ONCE per request: the audience
/// pre-filter ([`Bearer::binding`]) and the DPoP binding check (`auth::dpop`) both read it.
#[derive(Debug)]
pub enum Bearer {
    /// A busbar-signed token: never parsed here.
    Busbar,
    /// Not a three-segment JWS with a JSON payload: nothing to read.
    Opaque,
    /// A JWT's payload: checked once to be one JSON value, its claims read in place on demand.
    Jwt(JwtPayload),
}

/// A JWT payload known to be one well-formed JSON value. Only the claims the kernel judges are
/// read out of it, in place; no document is built.
#[derive(Debug)]
pub struct JwtPayload(Vec<u8>);

/// What a payload's `cnf.jkt` is: present (of any JSON type) or not.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Jkt {
    pub(crate) present: bool,
}

impl Bearer {
    #[must_use]
    pub fn read(token: &str) -> Bearer {
        if token.starts_with(crate::governance::signing::TOKEN_PREFIX) {
            return Bearer::Busbar;
        }

        let mut parts = token.split('.');
        let (Some(_header), Some(payload), Some(_sig), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Bearer::Opaque;
        };
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .ok()
            .filter(|bytes| busbar_contract::json::parse::<claims::Checked>(bytes).is_ok())
            .map_or(Bearer::Opaque, |bytes| Bearer::Jwt(JwtPayload(bytes)))
    }

    #[must_use]
    pub fn binding(&self, expected_aud: &str) -> Binding {
        match self {
            Bearer::Busbar => Binding::Deferred,
            Bearer::Opaque => Binding::Opaque,
            Bearer::Jwt(claims) => claims.binding(expected_aud),
        }
    }

    /// Whether the token is DPoP-bound: any `cnf.jkt`, whatever its type. A malformed jkt must not
    /// turn a sender-constrained credential into an ordinary bearer; it can only ever be refused,
    /// since proving it needs a string thumbprint.
    #[must_use]
    pub fn dpop_bound(&self) -> bool {
        matches!(self, Bearer::Jwt(claims) if claims.cnf_jkt().present)
    }
}

impl JwtPayload {
    /// `aud` names `expected_aud` (as a string, or a string in an array); anything else, or no
    /// `aud`, mismatches. A repeated member is judged by its last occurrence.
    fn binding(&self, expected_aud: &str) -> Binding {
        claims::member(&self.0, "aud", claims::Audience(expected_aud)).map_or(
            Binding::Mismatch,
            |bound| {
                if bound {
                    Binding::Bound
                } else {
                    Binding::Mismatch
                }
            },
        )
    }

    /// What `cnf.jkt` is, when `cnf` is an object; nothing otherwise.
    pub(crate) fn cnf_jkt(&self) -> Jkt {
        claims::member(&self.0, "cnf", claims::Cnf).unwrap_or_default()
    }
}

/// Visitors over a payload: one member judged in place, every other value skipped unread.
mod claims {
    use super::Jkt;
    use serde::de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
    use std::fmt;

    /// `seed`'s judgement of the last `name` member of the payload object; `None` when the
    /// payload is not an object or has no such member.
    pub(super) fn member<'de, S>(
        payload: &'de [u8],
        name: &'static str,
        seed: S,
    ) -> Option<S::Value>
    where
        S: DeserializeSeed<'de> + Copy,
    {
        let mut de = busbar_contract::json::Deserializer::from_slice(payload).use_rawnumber();
        de::Deserializer::deserialize_any(&mut de, Member { name, seed })
            .ok()
            .flatten()
    }

    /// Every value a judging visitor does not care about: scalars answer `$none`, containers are
    /// drained unread and answer `$none`.
    macro_rules! answer_others {
        ($none:expr) => {
            fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
                Ok($none)
            }
            fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
                Ok($none)
            }
            fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
                Ok($none)
            }
            fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
                Ok($none)
            }
            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok($none)
            }
        };
    }

    fn drain_seq<'de, A: SeqAccess<'de>>(mut seq: A) -> Result<(), A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(())
    }

    fn drain_map<'de, A: MapAccess<'de>>(mut map: A) -> Result<(), A::Error> {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(())
    }

    #[derive(Clone, Copy)]
    struct Member<S> {
        name: &'static str,
        seed: S,
    }

    impl<'de, S: DeserializeSeed<'de> + Copy> Visitor<'de> for Member<S> {
        type Value = Option<S::Value>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a JSON value")
        }
        answer_others!(None);
        fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<Self::Value, A::Error> {
            drain_seq(seq).map(|()| None)
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut judged = None;
            while let Some(named) = map.next_key_seed(KeyIs(self.name))? {
                if named {
                    judged = Some(map.next_value_seed(self.seed)?);
                } else {
                    map.next_value::<IgnoredAny>()?;
                }
            }
            Ok(judged)
        }
    }

    /// Whether a member name is `.0`, compared on the decoded name without keeping it.
    #[derive(Clone, Copy)]
    struct KeyIs(&'static str);

    impl<'de> DeserializeSeed<'de> for KeyIs {
        type Value = bool;
        fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<bool, D::Error> {
            d.deserialize_str(self)
        }
    }

    impl Visitor<'_> for KeyIs {
        type Value = bool;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a member name")
        }
        fn visit_str<E>(self, key: &str) -> Result<bool, E> {
            Ok(key == self.0)
        }
    }

    /// Whether a value is the string `.0`; any other value is skipped and is not.
    #[derive(Clone, Copy)]
    struct StrIs<'a>(&'a str);

    impl<'de> DeserializeSeed<'de> for StrIs<'_> {
        type Value = bool;
        fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<bool, D::Error> {
            d.deserialize_any(self)
        }
    }

    impl<'de> Visitor<'de> for StrIs<'_> {
        type Value = bool;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a JSON value")
        }
        answer_others!(false);
        fn visit_str<E>(self, s: &str) -> Result<bool, E> {
            Ok(self.0 == s)
        }
        fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<bool, A::Error> {
            drain_seq(seq).map(|()| false)
        }
        fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<bool, A::Error> {
            drain_map(map).map(|()| false)
        }
    }

    /// `aud` binds the expected audience: it is that string, or an array holding it.
    #[derive(Clone, Copy)]
    pub(super) struct Audience<'a>(pub(super) &'a str);

    impl<'de> DeserializeSeed<'de> for Audience<'_> {
        type Value = bool;
        fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<bool, D::Error> {
            d.deserialize_any(self)
        }
    }

    impl<'de> Visitor<'de> for Audience<'_> {
        type Value = bool;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a JSON value")
        }
        answer_others!(false);
        fn visit_str<E>(self, s: &str) -> Result<bool, E> {
            Ok(s == self.0)
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<bool, A::Error> {
            let mut bound = false;
            while let Some(element) = seq.next_element_seed(StrIs(self.0))? {
                bound |= element;
            }
            Ok(bound)
        }
        fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<bool, A::Error> {
            drain_map(map).map(|()| false)
        }
    }

    /// `cnf`: when an object, what its last `jkt` member is.
    #[derive(Clone, Copy)]
    pub(super) struct Cnf;

    impl<'de> DeserializeSeed<'de> for Cnf {
        type Value = Jkt;
        fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<Jkt, D::Error> {
            d.deserialize_any(self)
        }
    }

    impl<'de> Visitor<'de> for Cnf {
        type Value = Jkt;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a JSON value")
        }
        answer_others!(Jkt::default());
        fn visit_str<E>(self, _: &str) -> Result<Jkt, E> {
            Ok(Jkt::default())
        }
        fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<Jkt, A::Error> {
            drain_seq(seq).map(|()| Jkt::default())
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Jkt, A::Error> {
            let mut jkt = Jkt::default();
            while let Some(named) = map.next_key_seed(KeyIs("jkt"))? {
                if named {
                    map.next_value::<IgnoredAny>()?;
                    jkt = Jkt { present: true };
                } else {
                    map.next_value::<IgnoredAny>()?;
                }
            }
            Ok(jkt)
        }
    }

    /// One well-formed JSON value, walked so every string and member name is decoded (escapes and
    /// UTF-8 checked) as a parsed document would be, keeping nothing.
    pub(super) struct Checked;

    impl<'de> de::Deserialize<'de> for Checked {
        fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            d.deserialize_any(CheckedVisitor)
        }
    }

    struct CheckedVisitor;

    impl<'de> Visitor<'de> for CheckedVisitor {
        type Value = Checked;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a JSON value")
        }
        answer_others!(Checked);
        fn visit_str<E>(self, _: &str) -> Result<Checked, E> {
            Ok(Checked)
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Checked, A::Error> {
            while seq.next_element::<Checked>()?.is_some() {}
            Ok(Checked)
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Checked, A::Error> {
            while map.next_key::<Checked>()?.is_some() {
                map.next_value::<Checked>()?;
            }
            Ok(Checked)
        }
    }
}

pub(crate) const MISMATCH_DESCRIPTION: &str =
    "The access token's audience does not identify this resource. Request a token whose \
     `resource` (RFC 8707) is this server's canonical URI.";

pub(crate) const OPAQUE_DESCRIPTION: &str =
    "This credential carries no readable audience, so it cannot be shown to have been issued \
     for this resource. A JWT access token is required here.";

#[cfg(test)]
#[path = "tests/audience_tests.rs"]
mod audience_tests;
