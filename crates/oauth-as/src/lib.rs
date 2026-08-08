// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! An embeddable OAuth 2.1 Authorization Server library.
//!
//! This crate is the AUTHORIZATION SERVER half of OAuth: it registers clients, runs grant state
//! machines, issues and introspects tokens, and produces exactly the wire shapes the RFCs define.
//! It is a LIBRARY, not a server binary: the host owns the HTTP listener, the routes, TLS, rate
//! limiting, and persistence. The host hands request parameters to [`server::AuthorizationServer`]
//! and serializes the returned response/error types (they carry their own `serde` shapes and HTTP
//! status codes).
//!
//! What is implemented in this pass:
//!
//! - Core protocol types mirroring the specs in OUR OWN structs (a deliberate project rule; no
//!   third party's generated types): [`client::Client`], [`grant::GrantType`],
//!   [`token::TokenResponse`], [`scope::ScopeSet`], [`authorization::AuthorizationRequest`], and
//!   the RFC 6749 section 5.2 / RFC 8628 section 3.5 error object ([`error::ErrorResponse`]).
//! - The RFC 8628 device authorization grant, as a full state machine: `authorization_pending`,
//!   `slow_down` (with the mandated 5 second interval increase), `expired_token`, `access_denied`,
//!   single-use redemption, and user-code normalization per RFC 8628 section 6.1.
//! - Refresh-token rotation (single use, absolute lifetime), the OAuth 2.1 stance.
//! - PKCE S256 primitives ([`pkce`]), verified against the RFC 7636 appendix B vector.
//! - A storage seam ([`store::Storage`]) the HOST implements, plus [`store::MemoryStorage`] for
//!   tests and single-process embedding. This crate never assumes what the host's store looks like.
//!
//! The interactive authorization-code endpoint machine (login page, redirects) is a later pass;
//! its request/response types are already pinned in [`authorization`] so the wire shape cannot
//! drift when it lands.
//!
//! # Zero cost until enabled
//!
//! A host that compiles this crate in but never turns it on must pay nothing at runtime. The crate
//! keeps that promise structurally: there are NO global statics, NO lazy singletons, NO background
//! tasks, and no allocation at load time. The only allocation entry point is
//! [`server::AuthorizationServer::new`] (plus whatever `Storage` the host constructs to pass in),
//! so "enabled by config" for a host means exactly "construct the value when config says so".
//!
//! # Concurrency contract
//!
//! Single-use artifacts (device codes at redemption, rotating refresh tokens) are consumed through
//! the storage trait's atomic `take_*` operations. [`store::MemoryStorage`] satisfies the contract
//! with a mutex; a multi-node host must back `take_*` with a genuinely atomic remove-and-return
//! (compare-and-set, `DELETE ... RETURNING`, or equivalent) or single-use guarantees become
//! per-node only.

pub mod authorization;
pub mod client;
pub mod device;
pub mod error;
pub mod grant;
pub mod pkce;
pub mod scope;
pub mod server;
pub mod store;
pub mod token;

pub use authorization::{
    AuthorizationRequest, AuthorizationResponse, CodeChallengeMethod, ResponseType,
};
pub use client::{Client, ClientAuth, ClientId};
pub use device::{DeviceAuthorizationResponse, DeviceGrant, DeviceGrantState};
pub use error::{ErrorCode, ErrorResponse};
pub use grant::GrantType;
pub use scope::{Scope, ScopeSet};
pub use server::{AuthorizationServer, Clock, ServerConfig, SystemClock, TokenRequest};
pub use store::{MemoryStorage, Storage, StorageError};
pub use token::{IssuedToken, RefreshTokenRecord, TokenResponse, TokenType};
