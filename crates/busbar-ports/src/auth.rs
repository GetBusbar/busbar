// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The auth port (IF §11.3) and `IssuedShape` (IF §12.8: it lives in plugin-loader and the kernel re-exports
//! it). `Identity` keeps the verified answer as record bytes and reads them lazily.

use std::sync::Arc;

use busbar_contract::secure::SecureVec;
use busbar_plugin_abi::auth::{self as abi, tag as t};
use busbar_plugin_abi::host_side::caller::BoxFut;
use busbar_plugin_abi::records::{tag, FactRec, Full, Rec, RecErr, Records, Reply, U64Rec, Writer};
use busbar_plugin_abi::types::Pair;

use crate::{CallCx, PortError};

// W0-ABI: the IF types the secret bytes of `LoginAnswer` and `OutboundAnswer` as `zeroize::Zeroizing<Vec<u8>>`;
// the workspace bans `Zeroizing` crate-wide (clippy-crate-wide/clippy.toml, owner 2026-11-14), so the stub uses
// its named replacement `busbar_contract::secure::SecureVec`.

/// authority = h2/h3 `:authority`, else the h1 `Host` value (AuthReq.authority, Q_AUTHORITY); core fills it from
/// the request it parsed, once per request, alongside `headers`.
pub struct AuthIn<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub query: &'a str,
    pub authority: &'a str,
    pub headers: &'a [Pair<'a>],
    pub peer: &'a str,
    pub tls_peer_cert: &'a [u8],
    pub body: &'a [u8],
    pub now_s: u64,
}

/// The verified answer, kept as its record bytes: one allocation (the Arc) per uncached verify, none on a
/// verdict-cache hit (this is the cache value; round 23: the kernel `VerdictCache`, §12.28, rules 1-6). `identity_records()` is passed unchanged as
/// `PlaneIn::identity` and into hook views (generic ID_* tags, so no re-encode).
#[derive(Clone)]
pub struct Identity {
    recs: Arc<SecureVec>,
    id_len: u32,
    cache_s: Option<u32>,
    expires_at_s: Option<u64>,
    replay: Option<(Arc<SecureVec>, u64)>,
}

impl core::fmt::Debug for Identity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Identity")
            .field("identity_bytes", &self.id_len)
            .field("has_replay", &self.replay.is_some())
            .finish_non_exhaustive()
    }
}

impl Identity {
    /// The contiguous ID_SUBJECT, ID_GROUP*, ID_CLAIM* prefix (the adapter validates it is first and contiguous).
    pub fn identity_records(&self) -> &[u8] {
        // `id_len` is the length of the prefix the decoder wrote, so it is always inside `recs`.
        self.recs.get(..self.id_len as usize).unwrap_or_default()
    }

    /// Lazy typed accessors over the same bytes (policy, audit). No allocation.
    pub fn subject(&self) -> &str {
        self.prefix()
            .find(|r| r.tag == tag::ID_SUBJECT)
            .and_then(|r| r.text().ok())
            .unwrap_or_default()
    }

    pub fn groups(&self) -> impl Iterator<Item = &str> {
        self.prefix()
            .filter(|r| r.tag == tag::ID_GROUP)
            .filter_map(|r| r.text().ok())
    }

    pub fn claims(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.prefix()
            .filter(|r| r.tag == tag::ID_CLAIM)
            .filter_map(|r| r.pair().ok())
    }

    pub fn strip(&self) -> impl Iterator<Item = &str> {
        let tail = self.recs.get(self.id_len as usize..).unwrap_or_default();
        Records::new(tail)
            .map_while(Result::ok)
            .filter(|r| r.tag == t::STRIP)
            .filter_map(|r| r.text().ok())
    }

    /// None when the answer carried REPLAY (never verdict-cached), else F_CACHE_S.
    pub fn cache_s(&self) -> Option<u32> {
        if self.replay.is_some() {
            return None;
        }
        self.cache_s
    }

    pub fn expires_at_s(&self) -> Option<u64> {
        self.expires_at_s
    }

    /// The raw REPLAY claim (key, ttl_s); kernel policy runs before its atomic claim.
    pub fn replay(&self) -> Option<(&[u8], u64)> {
        self.replay.as_ref().map(|(key, ttl_s)| (&key[..], *ttl_s))
    }

    /// Built by core for a verified ticket (§12.11): ID_SUBJECT = the ticket subject, ID_CLAIM `scope`.
    pub fn from_ticket(subject: &str, scope: &str) -> Identity {
        let mut w = Reply::with_capacity(32 + subject.len() + scope.len());
        // A Reply refuses only past its 16 MiB cap; a ticket subject and scope are bounded far below it (§12.11).
        let written = w
            .put_text(tag::ID_SUBJECT, subject)
            .and_then(|()| w.put_pair(tag::ID_CLAIM, "scope", scope.as_bytes()));
        debug_assert!(written.is_ok(), "a ticket identity fits a Reply");
        let id_len = u32::try_from(w.len()).unwrap_or(0);
        Identity {
            recs: Arc::new(SecureVec::from(w.as_bytes())),
            id_len,
            cache_s: None,
            expires_at_s: None,
            replay: None,
        }
    }

    /// The identity prefix as records.
    fn prefix(&self) -> impl Iterator<Item = Rec<'_>> {
        Records::new(self.identity_records()).map_while(Result::ok)
    }
}

/// The longest REPLAY claim key (§8.3 ReplayRec) and the ttl clamp core applies to it.
const REPLAY_KEY_MAX: usize = 256;
pub const REPLAY_TTL_S: core::ops::RangeInclusive<u64> = 1..=86_400;

/// What one OK verify / verify_io answer said (§8.3): an identity (with or without a REPLAY claim the adapter
/// still has to win), or ISSUED_WANTED with the credential id core is asked to look up.
#[derive(Debug)]
pub enum VerifyOk {
    Identity(Identity),
    IssuedWanted(Box<str>),
}

/// Decodes an OK verify / verify_io answer (§8.3). Identity: ID_SUBJECT first and exactly once, then ID_GROUP*
/// and ID_CLAIM* (in any order between them, but contiguous: no ID_* after the first non-ID record), then STRIP*,
/// FACT(F_CACHE_S)?, FACT(F_EXPIRES_AT_S)?, REPLAY? in any order. ISSUED_WANTED stands alone. Generic METRIC
/// records are skipped (they are decoded once, by `decode_metrics`). Every other shape is RecErr, which the
/// adapter turns into a FAULT (BadRecords / UnknownTag).
pub fn decode_verify_ok(records: Records<'_>) -> Result<VerifyOk, RecErr> {
    let mut w = Reply::new();
    let mut id_len: Option<usize> = None;
    let mut subject = false;
    let mut wanted: Option<&str> = None;
    let mut cache_s: Option<u32> = None;
    let mut expires_at_s: Option<u64> = None;
    let mut replay: Option<(Arc<SecureVec>, u64)> = None;
    let mut any = false;
    let full = |_: Full| RecErr::Size;
    for rec in records {
        let rec = rec?;
        if rec.tag == tag::METRIC {
            continue;
        }
        if wanted.is_some() {
            return Err(RecErr::Unknown(rec.tag));
        }
        match rec.tag {
            tag::ID_SUBJECT if !any => {
                w.put_text(tag::ID_SUBJECT, rec.text()?).map_err(full)?;
                subject = true;
            }
            tag::ID_GROUP if subject && id_len.is_none() => {
                w.put_text(tag::ID_GROUP, rec.text()?).map_err(full)?;
            }
            tag::ID_CLAIM if subject && id_len.is_none() => {
                let (name, value) = rec.pair()?;
                w.put_pair(tag::ID_CLAIM, name, value).map_err(full)?;
            }
            t::ISSUED_WANTED if !any => wanted = Some(rec.text()?),
            other if !subject => return Err(RecErr::Unknown(other)),
            t::STRIP => {
                id_len.get_or_insert(w.len());
                w.put_text(t::STRIP, rec.text()?).map_err(full)?;
            }
            tag::FACT => {
                id_len.get_or_insert(w.len());
                let f = rec.pod::<FactRec>()?;
                if f._r != 0 {
                    return Err(RecErr::Reserved);
                }
                match f.key {
                    abi::F_CACHE_S if cache_s.is_none() => {
                        cache_s = Some(u32::try_from(f.value).unwrap_or(u32::MAX));
                    }
                    abi::F_EXPIRES_AT_S if expires_at_s.is_none() => expires_at_s = Some(f.value),
                    _ => return Err(RecErr::Size),
                }
            }
            t::REPLAY if replay.is_none() => {
                id_len.get_or_insert(w.len());
                let (head, key) = rec.pod_tail::<U64Rec>()?;
                if key.is_empty() || key.len() > REPLAY_KEY_MAX {
                    return Err(RecErr::Size);
                }
                let ttl_s = head.value.clamp(*REPLAY_TTL_S.start(), *REPLAY_TTL_S.end());
                replay = Some((Arc::new(SecureVec::from(key)), ttl_s));
            }
            other => return Err(RecErr::Unknown(other)),
        }
        any = true;
    }
    if let Some(id) = wanted {
        return Ok(VerifyOk::IssuedWanted(Box::from(id)));
    }
    if !subject {
        return Err(RecErr::Truncated);
    }
    let id_len = u32::try_from(id_len.unwrap_or(w.len())).map_err(|_| RecErr::Size)?;
    Ok(VerifyOk::Identity(Identity {
        recs: Arc::new(SecureVec::from(w.as_bytes())),
        id_len,
        cache_s,
        expires_at_s,
        replay,
    }))
}

/// Decodes the identity of an OK login answer (ID_* only; no STRIP, FACT or REPLAY belongs there, §8.3).
pub fn decode_login_identity(records: Records<'_>) -> Result<Identity, RecErr> {
    match decode_verify_ok(records)? {
        VerifyOk::Identity(id) if id.recs.len() == id.id_len as usize && id.replay.is_none() => {
            Ok(id)
        }
        VerifyOk::Identity(_) => Err(RecErr::Unknown(t::STRIP)),
        VerifyOk::IssuedWanted(_) => Err(RecErr::Unknown(t::ISSUED_WANTED)),
    }
}

/// The raw answer of exactly one plugin verify invocation. Host policy decides subsequent steps.
#[derive(Clone, Debug)]
pub enum VerifyAnswer {
    Identity(Identity),
    NotMine,
    Refused { code: u32, text: Box<str> },
    IssuedWanted(Box<str>),
    KeysStale,
}

/// Sync verification returns inline; verify_io drives exactly one plugin invocation.
pub enum Verify<'a> {
    Done(Result<VerifyAnswer, PortError>),
    Io(BoxFut<'a, Result<VerifyAnswer, PortError>>),
}

pub enum LoginIn<'a> {
    /// Round 22: code_challenge, nonce and code_verifier are core-minted (L_CODE_CHALLENGE, L_NONCE, L_CODE_VERIFIER).
    Begin {
        return_to: &'a str,
        redirect_uri: &'a str,
        state_key: &'a str,
        code_challenge: &'a str,
        nonce: &'a str,
        connect: Option<&'a str>,
        scope: Option<&'a str>,
    },
    Complete {
        callback_query: &'a str,
        state: &'a [u8],
        redirect_uri: &'a str,
        code_verifier: &'a str,
        nonce: &'a str,
        connect: Option<&'a str>,
    },
    Credential {
        username: &'a str,
        password: &'a [u8],
    },
}

pub enum LoginAnswer {
    Redirect {
        url: Box<str>,
        state: SecureVec,
    },
    Identity(Identity),
    /// COMPLETE of a caller connection (L_CONNECT): the grant blob core keeps (§12.12).
    Grant(SecureVec),
}

/// caller_cred = the inbound credential header(s) core verified for this request, set only when the route
/// enables passthrough and the outbound plugin declared FB_PASSTHROUGH (encoded as O_CALLER_CRED*).
/// scope = the plane's UP_SCOPE for this exchange (O_SCOPE), round 22: Some only for a STYLE_SCOPE binding.
/// caller_grant = the verified caller's stored grant for this upstream when the binding is caller-mode
/// (`UpstreamAuth.caller`, STYLE_CALLER) and core holds one (O_CALLER_GRANT).
pub struct UpstreamIn<'a> {
    pub method: &'a str,
    pub url: &'a str,
    pub headers: &'a [Pair<'a>],
    pub body_sha256: Option<[u8; 32]>,
    pub caller_cred: &'a [Pair<'a>],
    pub scope: Option<&'a str>,
    pub caller_grant: Option<&'a [u8]>,
    /// core's refresh-ahead margin in seconds (`CredPolicy.refresh_ahead_s`), written as FACT(F_MIN_VALID_S).
    pub min_valid_s: u32,
}

pub struct OutboundAnswer {
    pub headers: Vec<(Box<str>, SecureVec)>,
    pub query: Vec<(Box<str>, SecureVec)>,
    pub cache_s: u32,
    pub grant_update: Option<SecureVec>,
}

pub trait AuthPort: Send + Sync + 'static {
    fn facts(&self) -> u64;
    fn cred_headers(&self) -> &[Box<str>];
    /// D_ISSUED_KIND, if declared.
    fn issued_kind(&self) -> Option<&str>;
    fn verify<'a>(&'a self, cx: CallCx, req: &AuthIn<'_>, issued: Option<&[u8]>) -> Verify<'a>;
    fn login<'a>(
        &'a self,
        cx: CallCx,
        step: LoginIn<'a>,
    ) -> BoxFut<'a, Result<LoginAnswer, PortError>>;
    fn outbound<'a>(
        &'a self,
        cx: CallCx,
        req: &'a UpstreamIn<'a>,
    ) -> BoxFut<'a, Result<OutboundAnswer, PortError>>;
    fn refresh<'a>(&'a self, cx: CallCx) -> BoxFut<'a, Result<Option<u32>, PortError>>;
    /// Round 29 (FB_PROVISION only; otherwise `Err(Refused { code: R_UNSUPPORTED, .. })` without a call). `req` is the request
    /// K8 routed from `/provision/<instance>/*` after its own client check (§12.29); headers already stripped.
    fn serve<'a>(
        &'a self,
        cx: CallCx,
        req: &'a ServeIn<'a>,
    ) -> BoxFut<'a, Result<ServeOut, PortError>>;
}

/// Round 29. `path` = the path below the mount; `client` = the matched `provisioning.clients` name.
pub struct ServeIn<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub query: &'a str,
    pub headers: &'a [(&'a str, &'a [u8])],
    pub body: &'a [u8],
    pub client: &'a str,
}

pub struct ServeOut {
    pub status: u16,
    pub headers: Vec<(Box<str>, Vec<u8>)>,
    pub body: Vec<u8>,
}

/// Round 12: the shape core mints for one issued kind, from that kind's declaring auth plugin's D_ISSUED_SHAPE
/// (§8.3), via `Registry::issued_shapes` (§11.2). Field-for-field today's busbar-contract `IssuedShape`
/// (auth_calls.rs:285-306), which it replaces; it lives in plugin-loader and the kernel re-exports it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IssuedShape {
    pub id_prefix: Box<str>,
    pub id_len: usize,
    pub id_alphabet: Box<str>,
    pub secret_len: usize,
    pub secret_alphabet: Box<str>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn replay_identity() -> Identity {
        let mut reply = Reply::new();
        reply
            .put_text(tag::ID_SUBJECT, "identity-private-canary")
            .unwrap();
        reply
            .put_pair(tag::ID_CLAIM, "claim", b"claim-private-canary")
            .unwrap();
        reply
            .put_pod_tail(t::REPLAY, &U64Rec { value: 10 }, b"replay-private-canary")
            .unwrap();
        identity(&reply)
    }

    #[test]
    fn native_identity_nested_debug_redacts_records_and_replay() {
        let answer = VerifyOk::Identity(replay_identity());
        let debug = format!("{answer:?}");
        for canary in [
            "identity-private-canary",
            "claim-private-canary",
            "replay-private-canary",
        ] {
            assert!(!debug.contains(canary));
            let bytes = canary
                .bytes()
                .map(|byte| byte.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            assert!(
                !debug.contains(&bytes),
                "Debug exposed credential-bearing record bytes"
            );
        }
    }

    #[test]
    fn native_identity_shares_secure_backing_until_last_owner_drops() {
        let first = replay_identity();
        let follower = first.clone();
        assert!(Arc::ptr_eq(&first.recs, &follower.recs));
        assert_eq!(
            first.replay().unwrap().0.as_ptr(),
            follower.replay().unwrap().0.as_ptr()
        );
        let before = busbar_contract::secure::wipe_counts().1;
        drop(first);
        assert_eq!(busbar_contract::secure::wipe_counts().1, before);
        assert_eq!(follower.subject(), "identity-private-canary");
        assert_eq!(follower.replay().unwrap().0, b"replay-private-canary");
        drop(follower);
        assert_eq!(busbar_contract::secure::wipe_counts().1, before + 2);
    }

    #[test]
    fn native_identity_decode_failure_releases_replay_custody() {
        let mut reply = Reply::new();
        reply.put_text(tag::ID_SUBJECT, "subject").unwrap();
        reply
            .put_pod_tail(t::REPLAY, &U64Rec { value: 10 }, b"failed-replay-canary")
            .unwrap();
        reply
            .put_text(tag::ID_GROUP, "invalid-after-replay")
            .unwrap();
        let before = busbar_contract::secure::wipe_counts().1;
        assert!(decode_verify_ok(Records::new(reply.as_bytes())).is_err());
        assert_eq!(busbar_contract::secure::wipe_counts().1, before + 1);
    }

    #[test]
    fn native_ticket_identity_releases_secure_records() {
        let identity = Identity::from_ticket("private-ticket-subject", "scope");
        let before = busbar_contract::secure::wipe_counts().1;
        drop(identity);
        assert_eq!(busbar_contract::secure::wipe_counts().1, before + 1);
    }

    fn identity(w: &Reply) -> Identity {
        match decode_verify_ok(Records::new(w.as_bytes())).unwrap() {
            VerifyOk::Identity(id) => id,
            VerifyOk::IssuedWanted(id) => panic!("wanted {id}"),
        }
    }

    fn err(w: &Reply) -> RecErr {
        decode_verify_ok(Records::new(w.as_bytes())).unwrap_err()
    }

    #[test]
    fn an_identity_answer_reads_lazily_from_its_record_bytes() {
        let mut w = Reply::new();
        w.put_text(tag::ID_SUBJECT, "ada@example.com").unwrap();
        w.put_text(tag::ID_GROUP, "eng").unwrap();
        w.put_pair(tag::ID_CLAIM, "tenant", b"t1").unwrap();
        w.put_text(tag::ID_GROUP, "ops").unwrap();
        w.put_text(t::STRIP, "authorization").unwrap();
        w.put_fact(abi::F_CACHE_S, 120).unwrap();
        w.put_fact(abi::F_EXPIRES_AT_S, 1_700_000_600).unwrap();
        w.put_text(t::STRIP, "x-api-key").unwrap();
        w.put_metric(1, 1, 1.0, &[]).unwrap();
        let id = identity(&w);
        assert_eq!(id.subject(), "ada@example.com");
        assert_eq!(id.groups().collect::<Vec<_>>(), ["eng", "ops"]);
        assert_eq!(id.claims().collect::<Vec<_>>(), [("tenant", &b"t1"[..])]);
        assert_eq!(
            id.strip().collect::<Vec<_>>(),
            ["authorization", "x-api-key"]
        );
        assert_eq!(id.cache_s(), Some(120));
        assert_eq!(id.expires_at_s(), Some(1_700_000_600));
        assert_eq!(id.replay(), None);

        // identity_records() is exactly the ID_* prefix, passed unchanged to planes and hooks.
        let tags: Vec<u16> = Records::new(id.identity_records())
            .map(|r| r.unwrap().tag)
            .collect();
        assert_eq!(
            tags,
            [tag::ID_SUBJECT, tag::ID_GROUP, tag::ID_CLAIM, tag::ID_GROUP]
        );
    }

    #[test]
    fn the_identity_prefix_is_first_and_contiguous() {
        // ID_GROUP before ID_SUBJECT.
        let mut w = Reply::new();
        w.put_text(tag::ID_GROUP, "eng").unwrap();
        w.put_text(tag::ID_SUBJECT, "ada").unwrap();
        assert_eq!(err(&w), RecErr::Unknown(tag::ID_GROUP));
        // An ID_* record after STRIP.
        let mut w = Reply::new();
        w.put_text(tag::ID_SUBJECT, "ada").unwrap();
        w.put_text(t::STRIP, "authorization").unwrap();
        w.put_text(tag::ID_GROUP, "eng").unwrap();
        assert_eq!(err(&w), RecErr::Unknown(tag::ID_GROUP));
        // Two subjects.
        let mut w = Reply::new();
        w.put_text(tag::ID_SUBJECT, "ada").unwrap();
        w.put_text(tag::ID_SUBJECT, "eve").unwrap();
        assert_eq!(err(&w), RecErr::Unknown(tag::ID_SUBJECT));
        // No subject at all.
        assert_eq!(err(&Reply::new()), RecErr::Truncated);
        // A fact key the verify answer does not carry.
        let mut w = Reply::new();
        w.put_text(tag::ID_SUBJECT, "ada").unwrap();
        w.put_fact(abi::F_NEXT_REFRESH_S, 1).unwrap();
        assert_eq!(err(&w), RecErr::Size);
    }

    #[test]
    fn a_replay_answer_is_never_cached_and_its_claim_is_bounded() {
        let mut w = Reply::new();
        w.put_text(tag::ID_SUBJECT, "hook").unwrap();
        w.put_fact(abi::F_CACHE_S, 300).unwrap();
        w.put_pod_tail(t::REPLAY, &U64Rec { value: 0 }, b"standard-webhooks/1/abc")
            .unwrap();
        let id = identity(&w);
        assert_eq!(id.cache_s(), None);
        assert_eq!(id.replay(), Some((&b"standard-webhooks/1/abc"[..], 1)));

        let mut w = Reply::new();
        w.put_text(tag::ID_SUBJECT, "hook").unwrap();
        w.put_pod_tail(t::REPLAY, &U64Rec { value: u64::MAX }, b"k")
            .unwrap();
        assert_eq!(identity(&w).replay(), Some((&b"k"[..], 86_400)));

        let mut w = Reply::new();
        w.put_text(tag::ID_SUBJECT, "hook").unwrap();
        w.put_pod_tail(
            t::REPLAY,
            &U64Rec { value: 10 },
            &[b'k'; REPLAY_KEY_MAX + 1],
        )
        .unwrap();
        assert_eq!(err(&w), RecErr::Size);
        let mut w = Reply::new();
        w.put_text(tag::ID_SUBJECT, "hook").unwrap();
        w.put_pod_tail(t::REPLAY, &U64Rec { value: 10 }, b"")
            .unwrap();
        assert_eq!(err(&w), RecErr::Size);
    }

    #[test]
    fn issued_wanted_stands_alone() {
        let mut w = Reply::new();
        w.put_text(t::ISSUED_WANTED, "AKIAEXAMPLE").unwrap();
        match decode_verify_ok(Records::new(w.as_bytes())).unwrap() {
            VerifyOk::IssuedWanted(id) => assert_eq!(&*id, "AKIAEXAMPLE"),
            VerifyOk::Identity(_) => panic!("not ISSUED_WANTED"),
        }
        w.put_text(tag::ID_SUBJECT, "ada").unwrap();
        assert_eq!(err(&w), RecErr::Unknown(tag::ID_SUBJECT));
        let mut w = Reply::new();
        w.put_text(tag::ID_SUBJECT, "ada").unwrap();
        w.put_text(t::ISSUED_WANTED, "AKIAEXAMPLE").unwrap();
        assert_eq!(err(&w), RecErr::Unknown(t::ISSUED_WANTED));
    }

    #[test]
    fn a_ticket_identity_is_its_subject_and_scope() {
        let id = Identity::from_ticket("svc-browser", "realtime");
        assert_eq!(id.subject(), "svc-browser");
        assert_eq!(
            id.claims().collect::<Vec<_>>(),
            [("scope", &b"realtime"[..])]
        );
        assert_eq!(id.groups().count(), 0);
        assert_eq!(id.strip().count(), 0);
        assert_eq!(
            (id.cache_s(), id.expires_at_s(), id.replay()),
            (None, None, None)
        );
        assert_eq!(id.identity_records().len(), {
            let mut w = Reply::new();
            w.put_text(tag::ID_SUBJECT, "svc-browser").unwrap();
            w.put_pair(tag::ID_CLAIM, "scope", b"realtime").unwrap();
            w.len()
        });
    }

    #[test]
    fn a_login_identity_carries_no_strip_and_no_replay() {
        let mut w = Reply::new();
        w.put_text(tag::ID_SUBJECT, "ada").unwrap();
        assert_eq!(
            decode_login_identity(Records::new(w.as_bytes()))
                .unwrap()
                .subject(),
            "ada"
        );
        w.put_text(t::STRIP, "authorization").unwrap();
        assert!(decode_login_identity(Records::new(w.as_bytes())).is_err());
        let mut w = Reply::new();
        w.put_text(tag::ID_SUBJECT, "ada").unwrap();
        w.put_pod_tail(t::REPLAY, &U64Rec { value: 5 }, b"k")
            .unwrap();
        assert!(decode_login_identity(Records::new(w.as_bytes())).is_err());
        let mut w = Reply::new();
        w.put_text(t::ISSUED_WANTED, "id").unwrap();
        assert!(decode_login_identity(Records::new(w.as_bytes())).is_err());
    }
}
