// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The auth kind: the `Auth` trait and the `auth` module (IF §8.3, §10.4). W0-ABI stub: frozen signatures, `todo!()` bodies; W1-A7 fills it.

crate::kind::kind_stub! {
    /// An auth plugin checks credentials and produces credentials. It reports identities and facts.
    /// Core owns sessions, login state custody, verdict caching (§12.28), credential caching with its single-flight,
    /// refresh-ahead and failure window (§12.2), attribution and policy. Round 23: a plugin keeps no cache of
    /// verdicts or minted credentials, no mint scheduler and no backoff of its own.
    pub trait Auth: Send + Sync + 'static {
        /// Hot, pure compute: no Need, no allocation needed. Answer: ID_SUBJECT, ID_GROUP*, ID_CLAIM*, STRIP*,
        /// FACT(F_CACHE_S)?, FACT(F_EXPIRES_AT_S)?; or ISSUED_WANTED (sigv4-style key lookup; when the second
        /// call comes with `issued` empty, compute the same constant-time path against a dummy key and refuse
        /// BAD_CREDENTIAL). No credential this plugin recognises: REFUSED NOT_MINE. A signed request adds REPLAY.
        /// Keys it needs (JWKS, token hashes) were fetched in open or refresh; an unknown key id is REFUSED
        /// KEYS_STALE (core refreshes and asks again).
        fn verify(
            &self,
            h: &crate::host::Host,
            req: &auth::AuthReq<'_>,
            out: &mut crate::records::Out<'_>,
        ) -> Result<(), crate::fail::Fail> {
            let _ = (h, req, out);
            todo!()
        }
        /// The same verdict when checking needs I/O (LDAP bind, provider API). req = Q_* records. Declare
        /// exactly one of verify or verify_io.
        fn verify_io(
            &self,
            h: &'static crate::host::Host,
            req: crate::need::ChainBytes,
        ) -> impl core::future::Future<Output = Result<crate::records::Reply, crate::fail::Fail>> + Send {
            let _ = (h, req);
            async move { todo!() }
        }
        /// Interactive login. BEGIN(L_RETURN_TO, L_REDIRECT_URI, L_STATE_KEY, L_CODE_CHALLENGE, L_NONCE,
        /// L_CONNECT?, L_SCOPE?): REDIRECT + STATE. The plugin puts L_STATE_KEY in the URL's `state` parameter,
        /// L_CODE_CHALLENGE in `code_challenge` (method S256) and L_NONCE in `nonce` where its protocol has one.
        /// COMPLETE(L_CALLBACK_QUERY, L_STATE, L_REDIRECT_URI, L_CODE_VERIFIER, L_NONCE, L_CONNECT?): it sends
        /// L_CODE_VERIFIER as `code_verifier` and binds an id_token to L_NONCE; ID_*... for a user login, GRANT for
        /// a caller connection. Round 22: core mints the verifier, challenge, state and nonce (one copy, core's);
        /// STATE carries only what the plugin's protocol needs besides them (never a verifier or a nonce).
        /// CREDENTIAL(L_USERNAME, L_PASSWORD): ID_*.... Core stores STATE and finds it by state key.
        /// Round 21, outcomes other than an answer: the identity provider (or, for L_CONNECT, the upstream's
        /// authorization server) was not reached or answered an error = FAILED (F_UNAVAILABLE, F_TIMEOUT,
        /// F_BUSY or F_UPSTREAM) with the provider's Retry-After, if it sent one, as
        /// `with_fact(FACT_RETRY_AFTER_S, s)` (today's LOGIN_OUTAGE + `retry_after_extensions`); a state, nonce,
        /// PKCE or issuer check failed = REFUSED SECURITY_CHECK; the provider declined the user = any other
        /// REFUSED. The plugin never chooses the page, the status or the delay core shows (§8.3 login outcomes).
        fn login(
            &self,
            h: &'static crate::host::Host,
            step: u32,
            input: crate::need::ChainBytes,
        ) -> impl core::future::Future<Output = Result<crate::records::Reply, crate::fail::Fail>> + Send {
            let _ = (h, step, input);
            async move { todo!() }
        }
        /// Credentials for one upstream request (O_* records), for the one binding this instance was opened with
        /// (style, credential handle and settings are its config, §12.18). Answer: SET_HEADER*, SET_QUERY*, GRANT_UPDATE?,
        /// FACT(F_CACHE_S) (round 24: a style whose credential is per request declares STYLE_PER_REQUEST and core
        /// ignores F_CACHE_S for it; for any other style 0 = already expired, §12.2 rule 5). Core's credential cache keys on
        /// (auth instance, upstream, O_SCOPE hash only for a STYLE_SCOPE style, caller subject hash when
        /// O_CALLER_GRANT was sent). Round 23 (185): F_CACHE_S is a fact, never a margin: the credential's whole
        /// remaining validity as its issuer stated it (`expires_in`, or the held grant's expiry − F_NOW_S); core
        /// alone subtracts its refresh-ahead margin, single-flights the mint, rate-floors it and keeps the failure
        /// window (§12.2 `CredentialCache`). Every request carries FACT(F_MIN_VALID_S) = core's margin: a style
        /// that presents a credential it holds (a caller grant's access token) refreshes it when its remaining
        /// validity is below that, and otherwise presents it; a style that mints per call ignores it. One call =
        /// at most one mint: the plugin never retries, waits, caches, de-duplicates or schedules a mint.
        fn outbound(
            &self,
            h: &'static crate::host::Host,
            req: crate::need::ChainBytes,
        ) -> impl core::future::Future<Output = Result<crate::records::Reply, crate::fail::Fail>> + Send {
            let _ = (h, req);
            async move { todo!() }
        }
        /// Cold, scheduled by core (on F_NEXT_REFRESH_S, and once after a KEYS_STALE verify): re-fetch keys or
        /// metadata into instance state. Answer: FACT(F_NEXT_REFRESH_S)?. Round 29: an FB_PROVISION image may pull
        /// its upstream directory here with DIRECTORY Needs (`pull: true`).
        fn refresh(
            &self,
            h: &'static crate::host::Host,
        ) -> impl core::future::Future<Output = Result<crate::records::Reply, crate::fail::Fail>> + Send {
            let _ = h;
            async move { todo!() }
        }
        /// Round 29 (auth v4 provisioning; FB_PROVISION only). One HTTP request core routed to this instance's
        /// provisioning mount `/provision/<instance>/*`, from a client core already authenticated (§12.29). req =
        /// Q_METHOD, Q_PATH (the path below the mount), Q_QUERY, PAIR* headers (never `authorization`, a cookie or
        /// any header the instance reads credentials from), Q_BODY, Q_CLIENT. The plugin maps its protocol (SCIM)
        /// onto DIRECTORY Needs and answers SV_STATUS, SV_HEADER*, SV_BODY?; it never authenticates the client, never
        /// decides a deprovision limit and never touches a principal (core's, §12.29).
        fn serve(
            &self,
            h: &'static crate::host::Host,
            req: crate::need::ChainBytes,
        ) -> impl core::future::Future<Output = Result<crate::records::Reply, crate::fail::Fail>> + Send {
            let _ = (h, req);
            async move { todo!() }
        }
    }
}

pub mod auth {
    //! The auth kind's view, records, constants and method bits (IF §8.3), and its host-side `Proxy` (§10.4).

    /// One inbound request. Header names are lowercase. body is empty unless FB_NEEDS_BODY.
    /// issued = the core-issued credential core looked up after this plugin answered ISSUED_WANTED (empty
    /// on the first call, and empty when the id is unknown; flags has REQ_ISSUED_LOOKED_UP after a lookup).
    /// authority = the request's authority as the client sent it: the HTTP/2-3 `:authority`
    /// pseudo-header, else the HTTP/1.1 `Host` line (never in `headers` on h2, which carries no `host`);
    /// signing schemes that cover `host` (SigV4) sign this value.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct AuthReq<'a> {
        pub flags: u32,
        pub _r: u32,
        pub method: crate::types::Str<'a>,
        pub path: crate::types::Str<'a>,
        pub query: crate::types::Str<'a>,
        pub authority: crate::types::Str<'a>,
        pub headers: crate::types::Slice<'a, crate::types::Pair<'a>>,
        pub peer: crate::types::Str<'a>,
        pub tls_peer_cert: crate::types::Bytes<'a>,
        pub body: crate::types::Bytes<'a>,
        pub issued: crate::types::Bytes<'a>,
        pub now_s: u64,
    }
    // W0-ABI: `unsafe impl View for AuthReq<'_>` and its const size assert land with W1-A4 (`kind!`).

    /// A replay claim (verify / verify_io answer). Tail = the claim key (≤ 256 bytes, e.g.
    /// `standard-webhooks/<ts>/<id>`). ttl_s = how long a replay must be refused (clamped 1..=86_400).
    #[repr(C)]
    #[derive(
        Clone,
        Copy,
        zerocopy::FromBytes,
        zerocopy::IntoBytes,
        zerocopy::Immutable,
        zerocopy::KnownLayout,
    )]
    pub struct ReplayRec {
        pub ttl_s: u64,
    }
    /// Round 12, describe (D_ISSUED_SHAPE): the shape of the credential core mints for this plugin's
    /// D_ISSUED_KIND (today's MARK_WORD_ISSUED_* marks, busbar-contract auth_calls.rs `IssuedShape`).
    /// id_len = the public id's total length in characters, prefix included; secret_len = the secret's
    /// length. Tail = exactly three nested TEXT records, in order: id prefix (may be empty), id alphabet
    /// (the symbols after the prefix), secret alphabet. Core draws every symbol from `busbar_crypto`
    /// randomness with equal weight and names no format of its own.
    #[repr(C)]
    #[derive(
        Clone,
        Copy,
        zerocopy::FromBytes,
        zerocopy::IntoBytes,
        zerocopy::Immutable,
        zerocopy::KnownLayout,
    )]
    pub struct IssuedShapeRec {
        pub id_len: u32,
        pub secret_len: u32,
    }

    impl crate::records::Pod for IssuedShapeRec {}

    pub mod tag {
        /// answers: generic ID_SUBJECT, ID_GROUP*, ID_CLAIM* (records.rs; first and contiguous), then STRIP*
        /// (text header name) and FACT*. 0x0100..=0x0102 are retired (round 1's kind-local identity tags).
        pub const STRIP: u16 = 0x0103;
        /// login answers: REDIRECT (url text) + STATE (blob core stores), or ID_*...
        pub const REDIRECT: u16 = 0x0104;
        pub const STATE: u16 = 0x0105;
        /// outbound answers: SET_HEADER* / SET_QUERY* (pair shape), GRANT_UPDATE? (the refreshed caller grant
        /// blob; core stores it in place of the one it passed as O_CALLER_GRANT, §12.12).
        pub const SET_HEADER: u16 = 0x0106;
        pub const SET_QUERY: u16 = 0x0107;
        pub const GRANT_UPDATE: u16 = 0x0109;
        /// login COMPLETE answer for a caller connection (L_CONNECT set): GRANT (blob core keeps as that caller's
        /// grant for the upstream; e.g. access + refresh token). Never shown to any plane.
        pub const GRANT: u16 = 0x010A;
        /// verify / verify_io answer, with an identity: REPLAY (ReplayRec + key). Core claims the key once,
        /// atomically, in this instance's namespace before admitting the request; a lost claim refuses the
        /// request R_REPLAYED. An answer carrying REPLAY is never verdict-cached.
        pub const REPLAY: u16 = 0x010B;
        /// verify answer instead of a verdict: "look up the core-issued credential with this id" (text).
        /// Core looks it up under this plugin's D_ISSUED_KIND and calls the same method again with
        /// AuthReq.issued set (sync verify) or Q_ISSUED added (verify_io). At most once per request.
        pub const ISSUED_WANTED: u16 = 0x0108;
        /// verify_io request encoding of AuthReq (text/bytes, PAIR* for headers, FACT(F_NOW_S)).
        pub const Q_METHOD: u16 = 0x0110;
        pub const Q_PATH: u16 = 0x0111;
        pub const Q_QUERY: u16 = 0x0112;
        pub const Q_PEER: u16 = 0x0113;
        pub const Q_TLS_CERT: u16 = 0x0114;
        pub const Q_BODY: u16 = 0x0115;
        pub const Q_ISSUED: u16 = 0x0116;
        /// verify_io: AuthReq.authority (text).
        pub const Q_AUTHORITY: u16 = 0x0117;
        /// Round 29, `serve` request: the `provisioning.clients` entry name core matched the caller to (text).
        pub const Q_CLIENT: u16 = 0x0118;
        /// Round 29, `serve` answer: SV_STATUS (Pod U32Rec, 200..=599), SV_HEADER* (pair shape), SV_BODY? (bytes).
        pub const SV_STATUS: u16 = 0x0140;
        pub const SV_HEADER: u16 = 0x0141;
        pub const SV_BODY: u16 = 0x0142;
        /// login inputs.
        pub const L_RETURN_TO: u16 = 0x0120;
        pub const L_REDIRECT_URI: u16 = 0x0121;
        pub const L_STATE_KEY: u16 = 0x0122;
        pub const L_CALLBACK_QUERY: u16 = 0x0123;
        pub const L_STATE: u16 = 0x0124;
        pub const L_USERNAME: u16 = 0x0125;
        pub const L_PASSWORD: u16 = 0x0126;
        /// login input: L_CONNECT (text: the configured upstream name) marks a caller-connection login
        /// (consent for an upstream on behalf of the verified caller, §12.12); L_SCOPE (text) the scope wanted.
        pub const L_CONNECT: u16 = 0x0127;
        pub const L_SCOPE: u16 = 0x0128;
        /// Round 22, login inputs core mints (text; hosted_login.rs:97-100 for a user login, K10 for L_CONNECT):
        /// L_CODE_CHALLENGE (BEGIN: the S256 PKCE challenge, base64url), L_NONCE (BEGIN and COMPLETE: the OIDC
        /// nonce), L_CODE_VERIFIER (COMPLETE: the PKCE verifier). Every REDIRECT login gets all three; the
        /// plugin echoes them to the provider and never draws or keeps its own.
        pub const L_CODE_CHALLENGE: u16 = 0x0129;
        pub const L_NONCE: u16 = 0x012A;
        pub const L_CODE_VERIFIER: u16 = 0x012B;
        /// outbound inputs: O_METHOD, O_URL, PAIR* headers, O_BODY_SHA256 (32 bytes, if FB_NEEDS_BODY_HASH),
        /// O_CALLER_CRED* (pair shape: the inbound credential header name and raw value core verified for
        /// this request; present only if FB_PASSTHROUGH and the route enables passthrough), O_SCOPE (text,
        /// space-separated: the per-call down-scope the plane stated as UP_SCOPE; round 22: sent only to a
        /// binding whose style declared STYLE_SCOPE, e.g. RFC 8693 exchange), O_CALLER_GRANT (the stored
        /// grant blob of the verified caller for this upstream; round 22: only to a binding whose style
        /// declared STYLE_CALLER, and only when core holds one, §12.12).
        pub const O_METHOD: u16 = 0x0130;
        pub const O_URL: u16 = 0x0131;
        pub const O_BODY_SHA256: u16 = 0x0132;
        pub const O_CALLER_CRED: u16 = 0x0133;
        pub const O_SCOPE: u16 = 0x0134;
        pub const O_CALLER_GRANT: u16 = 0x0135;
        /// describe: a request header this plugin reads credentials from (core strips it upstream).
        pub const D_CRED_HEADER: u16 = 0x0180;
        /// describe: the core-issued credential kind this plugin may look up (text, e.g. "sigv4"). At most one.
        pub const D_ISSUED_KIND: u16 = 0x0181;
        /// Round 12, describe: IssuedShapeRec + 3 × TEXT. Exactly one when D_ISSUED_KIND is declared, none
        /// otherwise (DescribeInvalid).
        pub const D_ISSUED_SHAPE: u16 = 0x0183;
        /// describe: one outbound style this plugin implements (text; e.g. auth-header's "x-goog-api-key",
        /// auth-oauth's "oauth-token-exchange", auth-sigv4's "sigv4"). Core validates a binding's
        /// `style` against these at config load; one auth instance is one outbound binding (§12.18).
        pub const D_OUTBOUND_STYLE: u16 = 0x0182;
        /// Round 22, describe: what one declared style consumes (Pod MaskRec, mask = STYLE_*; tail = the style
        /// word, which must be one of this image's D_OUTBOUND_STYLE items; at most one per style; absent = 0;
        /// else DescribeInvalid). Core alone derives from it the upstream credential mode and O_SCOPE (§12.18).
        pub const D_STYLE_FLAGS: u16 = 0x0184;
    }

    pub const REQUIRED: u64 = 0;
    pub const LOGIN_BEGIN: u32 = 1;
    pub const LOGIN_COMPLETE: u32 = 2;
    pub const LOGIN_CREDENTIAL: u32 = 3;
    pub const REQ_ISSUED_LOOKED_UP: u32 = 1;
    /// refusal codes
    /// (these go to core only; core maps them to generic codes before anything is rendered, §12.15)
    pub const NOT_MINE: u32 = 0x100;
    pub const BAD_CREDENTIAL: u32 = 0x101;
    pub const EXPIRED: u32 = 0x102;
    pub const SECURITY_CHECK: u32 = 0x103;
    /// The credential names a key (e.g. a JWKS `kid`) not in the keys this instance fetched. Core runs
    /// `refresh` once, single-flight per instance and at most once per `auth.unknown_key_refresh_s`
    /// (default 30 s), then re-runs the same verify once; a second KEYS_STALE, or a refresh core declined
    /// by the rate limit, is treated as BAD_CREDENTIAL. The plugin never refetches on its own.
    pub const KEYS_STALE: u32 = 0x104;
    /// facts
    pub const F_CACHE_S: u32 = 0x100;
    pub const F_EXPIRES_AT_S: u32 = 0x101;
    pub const F_NEXT_REFRESH_S: u32 = 0x102;
    pub const F_NOW_S: u32 = 0x103;
    /// Round 23, outbound input (FACT, seconds): the least remaining validity core accepts for a held
    /// credential (its refresh-ahead margin, §12.2). A fact core states; the plugin compares, never chooses.
    pub const F_MIN_VALID_S: u32 = 0x104;
    /// describe fact bits
    pub const FB_NEEDS_BODY: u64 = 1;
    pub const FB_NEEDS_BODY_HASH: u64 = 2;
    pub const FB_OPERATOR: u64 = 4;
    pub const FB_PASSTHROUGH: u64 = 8;
    /// Round 22, D_STYLE_FLAGS: STYLE_SCOPE = the style reads O_SCOPE (core sends it and keys CredKey.scope);
    /// STYLE_CALLER = the style presents the verified caller's own grant (core resolves the mode to caller).
    pub const STYLE_SCOPE: u64 = 1;
    pub const STYLE_CALLER: u64 = 2;
    /// Round 24: STYLE_PER_REQUEST = the style's credential is bound to one request (sigv4, a header read
    /// per call); core never caches or shares it (§12.2 rule 5). Without it, F_CACHE_S 0 = already expired.
    pub const STYLE_PER_REQUEST: u64 = 4;
    /// Round 8, describe fact bits: which login this plugin offers (today's LOGIN_KIND_REDIRECT /
    /// LOGIN_KIND_CREDENTIAL). REDIRECT: `login` answers BEGIN/COMPLETE (browser redirect; oidc, github).
    /// CREDENTIAL: `login` answers CREDENTIAL (a username/password form; ldap). A plugin that declares
    /// `login` sets exactly one; a plugin without `login` sets neither (DescribeInvalid otherwise).
    pub const FB_LOGIN_REDIRECT: u64 = 16;
    pub const FB_LOGIN_CREDENTIAL: u64 = 32;
    /// Round 29 (auth v4, dev's CAP_PROVISION): the image serves `serve` under core's provisioning mount
    /// and may use the DIRECTORY Need (§6.1) from `serve` and `refresh`. Requires `serve` (DescribeInvalid
    /// otherwise, and `serve` without it).
    pub const FB_PROVISION: u64 = 64;

    pub const KIND: crate::types::KindCode = crate::types::KindCode::Auth;
    pub const ABI: u32 = 3;
    pub const FP: u64 = 0; // W0-ABI stub value; kind! computes it (W1-A4).

    pub const M_VERIFY: u64 = 1 << 0;
    pub const M_VERIFY_IO: u64 = 1 << 1;
    pub const M_LOGIN: u64 = 1 << 2;
    pub const M_OUTBOUND: u64 = 1 << 3;
    pub const M_REFRESH: u64 = 1 << 4;
    pub const M_SERVE: u64 = 1 << 5;
    pub const ALL: u64 = M_VERIFY | M_VERIFY_IO | M_LOGIN | M_OUTBOUND | M_REFRESH | M_SERVE;

    // W0-ABI: `Vt` (fields verify, verify_io, login, outbound, refresh, serve are unsafe extern "C" fn
    // pointers) and the `vt::<T>()` shims are unsafe; they land with W1-A4 (`kind!`) under an escapes.json
    // admission.

    /// `vt` points into the plugin image; it is valid because `inst` holds the image (I13), and it is never
    /// handed out with a lifetime longer than `&self`.
    #[cfg(feature = "host")]
    pub struct Proxy {
        // W0-ABI: fields `inst: Arc<Instance>` and `vt: NonNull<Vt>` land with W1-A4; `vt` needs the unsafe
        // `Vt`, and the `unsafe impl Send/Sync for Proxy` and `pub unsafe fn bind` land with it.
        _stub: core::marker::PhantomData<std::sync::Arc<crate::host_side::driver::Instance>>,
    }

    #[cfg(feature = "host")]
    impl Proxy {
        pub fn instance(&self) -> &std::sync::Arc<crate::host_side::driver::Instance> {
            let _ = &self._stub;
            todo!()
        }

        pub fn verify<'o>(
            &self,
            buf: &'o mut crate::host_side::pool::PooledOut,
            req: &AuthReq<'_>,
        ) -> Result<crate::host_side::answer::Answer<'o>, crate::fail::CallError> {
            let _ = (&self._stub, buf, req);
            todo!()
        }

        pub fn verify_io<'a, N: crate::host_side::needs::Needs>(
            &'a self,
            drv: &'a mut crate::host_side::driver::Driver<'a, N>,
            req: crate::host_side::pool::PooledOut,
        ) -> impl core::future::Future<
            Output = Result<crate::host_side::answer::OwnedAnswer, crate::fail::CallError>,
        > + Send
        + 'a {
            let _ = (&self._stub, drv, req);
            async move { todo!() }
        }

        pub fn login<'a, N: crate::host_side::needs::Needs>(
            &'a self,
            drv: &'a mut crate::host_side::driver::Driver<'a, N>,
            req: crate::host_side::pool::PooledOut,
            step: u32,
        ) -> impl core::future::Future<
            Output = Result<crate::host_side::answer::OwnedAnswer, crate::fail::CallError>,
        > + Send
        + 'a {
            let _ = (&self._stub, drv, req, step);
            async move { todo!() }
        }

        pub fn outbound<'a, N: crate::host_side::needs::Needs>(
            &'a self,
            drv: &'a mut crate::host_side::driver::Driver<'a, N>,
            req: crate::host_side::pool::PooledOut,
        ) -> impl core::future::Future<
            Output = Result<crate::host_side::answer::OwnedAnswer, crate::fail::CallError>,
        > + Send
        + 'a {
            let _ = (&self._stub, drv, req);
            async move { todo!() }
        }

        pub fn refresh<'a, N: crate::host_side::needs::Needs>(
            &'a self,
            drv: &'a mut crate::host_side::driver::Driver<'a, N>,
            req: crate::host_side::pool::PooledOut,
        ) -> impl core::future::Future<
            Output = Result<crate::host_side::answer::OwnedAnswer, crate::fail::CallError>,
        > + Send
        + 'a {
            let _ = (&self._stub, drv, req);
            async move { todo!() }
        }

        pub fn serve<'a, N: crate::host_side::needs::Needs>(
            &'a self,
            drv: &'a mut crate::host_side::driver::Driver<'a, N>,
            req: crate::host_side::pool::PooledOut,
        ) -> impl core::future::Future<
            Output = Result<crate::host_side::answer::OwnedAnswer, crate::fail::CallError>,
        > + Send
        + 'a {
            let _ = (&self._stub, drv, req);
            async move { todo!() }
        }
    }
}
