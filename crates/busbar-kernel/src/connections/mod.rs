// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Caller connections: per-caller outbound grants, BEGIN/STATUS/REVOKE and the caller-mode grant (IF §12.12). W0-ABI stub: frozen signatures, `todo!()` bodies; W1-K10 fills it.

use busbar_plugin_abi::host_side::caller::{BoxFut, Caller};

use crate::plugin_records::RecordsDenied;

/// Grants are custody: stored encrypted (core at-rest key), keyed by (plane plugin, plane instance **name**,
/// caller subject hash, configured upstream name), never by a runtime id, so they survive restart, reconfigure
/// and replicas. Never shown to any plane. Today's mcp door_connections / outbound_* services.
/// Round 21: "the upstream's configured auth instance" is `UpstreamDef.auth.instance` (§12.1); an upstream with
/// no `auth`, or whose instance did not declare FB_LOGIN_REDIRECT, answers BEGIN `Err(RecordsDenied::Invalid)` and STATUS
/// CONN_NONE. The implementing plugin is auth-oauth's `oauth-connection` style (§8.3 caller connections).
pub trait CallerConnections: Send + Sync + 'static {
    /// BEGIN: runs the upstream's configured auth instance `login(Begin{connect: Some(upstream), redirect_uri:
    /// <public_url + UpstreamAuth.connect_callback>, ..})` with a core state key; the callback lands on the
    /// route K10 mounts at `connect_callback` (round 21: so the operator's registered `redirect_uri` keeps
    /// working; a path another listener claim already holds refuses CONFIG under §12.26), which runs COMPLETE,
    /// stores the GRANT and redirects to `return_to`. Returns the URL for the plane to send the caller to.
    /// Round 22: K10 mints `code_verifier` (32 random bytes, base64url), its S256 `code_challenge`, the state key
    /// and the nonce with hosted_login's own two functions (`random_b64url`, `code_challenge_s256`, moved to one
    /// `busbar-core-oauth2::pkce` module both call, on `busbar_crypto::fill`/`digest`), passes L_CODE_CHALLENGE and
    /// L_NONCE on BEGIN, keeps the verifier and nonce in its own login state beside the plugin's STATE (core
    /// custody, encrypted, TTL as hosted_login's cookie), and passes L_CODE_VERIFIER and L_NONCE on COMPLETE.
    fn begin<'a>(
        &'a self,
        who: &'a Caller<'_>,
        subject: &'a str,
        upstream: &'a str,
        return_to: Option<&'a str>,
    ) -> BoxFut<'a, Result<Box<str>, RecordsDenied>>;
    fn status<'a>(
        &'a self,
        who: &'a Caller<'_>,
        subject: &'a str,
        upstream: &'a str,
    ) -> BoxFut<'a, u32 /* CONN_* */>;
    fn revoke<'a>(
        &'a self,
        who: &'a Caller<'_>,
        subject: &'a str,
        upstream: &'a str,
    ) -> BoxFut<'a, Result<(), RecordsDenied>>;
    /// A caller-mode binding (round 22: `UpstreamAuth.caller`, STYLE_CALLER): the stored grant, passed to auth `outbound` as O_CALLER_GRANT; a GRANT_UPDATE in the
    /// answer replaces it (refresh happens in the auth plugin, through FETCH). Round 21: an `outbound` REFUSED
    /// R_CONNECT_REQUIRED while a grant was passed deletes that grant (the server revoked it) before the exchange
    /// fails R_CONNECT_REQUIRED, so STATUS then answers CONN_NONE, as today after a failed refresh.
    // W0-ABI: the IF's value type is `zeroize::Zeroizing<Vec<u8>>`, which core bans (LR-094); the stub uses its
    // replacement `busbar_contract::secure::SecureVec`.
    fn grant<'a>(
        &'a self,
        plane: &'a Caller<'_>,
        subject: &'a str,
        upstream: &'a str,
    ) -> BoxFut<'a, Option<busbar_contract::secure::SecureVec>>;
    fn update<'a>(
        &'a self,
        plane: &'a Caller<'_>,
        subject: &'a str,
        upstream: &'a str,
        grant: &'a [u8],
    ) -> BoxFut<'a, Result<(), RecordsDenied>>;
}
