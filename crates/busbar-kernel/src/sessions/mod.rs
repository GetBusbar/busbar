// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Login state custody for auth BEGIN/COMPLETE (IF §12.6). W0-ABI stub: frozen signatures, `todo!()` bodies; W1-K5 fills it.

use busbar_plugin_abi::host_side::caller::{BoxFut, Caller};

use crate::plugin_records::RecordsDenied;

/// Auth login STATE custody. Core generates state_key (32 random bytes, base64url) per BEGIN, stores the STATE
/// blob durably (CoreStore, so the callback may land on another replica) under (auth plugin, auth instance
/// **name**, state_key) for ≤ 600 s, and takes it exactly once on the callback's `state` param.
pub trait LoginStates: Send + Sync + 'static {
    fn new_key(&self) -> Box<str>;
    fn put<'a>(
        &'a self,
        auth: &'a Caller<'_>,
        key: &'a str,
        state: &'a [u8],
    ) -> BoxFut<'a, Result<(), RecordsDenied>>;
    // W0-ABI: the IF's value type is `zeroize::Zeroizing<Vec<u8>>`, which core bans (LR-094); the stub uses its
    // replacement `busbar_contract::secure::SecureVec`.
    fn take<'a>(
        &'a self,
        auth: &'a Caller<'_>,
        key: &'a str,
    ) -> BoxFut<'a, Option<busbar_contract::secure::SecureVec>>;
}
