// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Caller connections: per-caller outbound grants, BEGIN/STATUS/REVOKE and the caller-mode grant (IF §12.12). The
//! frozen contract is the public methods of [`StoreConnections`] (store.rs), W1-K10's implementation, its browser callback
//! [`StoreConnections::callback`] with the route claims in callback.rs, the grant deletion on R_CONNECT_REQUIRED
//! [`settle_outbound`], and core's one PKCE/state/nonce minting module [`pkce`].

mod callback;
pub mod pkce;
mod store;

pub use callback::CallbackAnswer;
pub use store::{settle_outbound, ConnectLogins, StoreConnections, LOGIN_TTL_S};

pub mod grant;
#[cfg(test)]
#[path = "tests.rs"]
mod tests;

#[cfg(test)]
#[path = "grant/owner_tests.rs"]
mod grant_owner_tests;
