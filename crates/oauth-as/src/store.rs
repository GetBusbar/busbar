// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The storage seam. This crate never assumes what the host's persistence looks like: the host
//! implements [`Storage`], and the server only ever talks through it. [`MemoryStorage`] is the
//! reference implementation, used by this crate's tests and suitable for single-process embedding.
//!
//! CONTRACT NOTES the server relies on:
//!
//! - `take_*` operations are ATOMIC remove-and-return. They are how single-use artifacts (device
//!   codes at redemption, rotating refresh tokens) stay single use under concurrency. A shared
//!   multi-node store must implement them with a genuinely atomic primitive (compare-and-set,
//!   `DELETE ... RETURNING`, or equivalent); a plain read-then-delete reintroduces the double-spend.
//! - `put_device_grant` upserts by `device_code` and must keep any user-code index consistent.
//! - User-code lookups are by NORMALIZED code (see [`crate::device::normalize_user_code`]); the
//!   store indexes what it is given and does not normalize.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::sync::Mutex;

use crate::authorization::AuthorizationCodeRecord;
use crate::client::{Client, ClientId};
use crate::device::DeviceGrant;
use crate::token::{IssuedToken, RefreshTokenRecord};

/// An opaque host-side storage failure. The server maps these to `server_error` on wire paths;
/// the text is for the host's logs, never for the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageError(pub String);

impl StorageError {
    /// Wrap a failure description.
    pub fn new(msg: impl Into<String>) -> Self {
        StorageError(msg.into())
    }
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "storage error: {}", self.0)
    }
}

impl std::error::Error for StorageError {}

/// What the authorization server needs from the host's persistence. All futures are `Send` so the
/// server can be driven from any multi-threaded async runtime.
pub trait Storage: Send + Sync {
    /// Look up a registered client.
    fn get_client(
        &self,
        client_id: &ClientId,
    ) -> impl Future<Output = Result<Option<Client>, StorageError>> + Send;

    /// Insert or replace a client registration.
    fn put_client(&self, client: Client) -> impl Future<Output = Result<(), StorageError>> + Send;

    /// Insert or replace a device grant, keyed by `device_code` (also maintaining the user-code
    /// index).
    fn put_device_grant(
        &self,
        grant: DeviceGrant,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;

    /// Look up a device grant by device code.
    fn get_device_grant(
        &self,
        device_code: &str,
    ) -> impl Future<Output = Result<Option<DeviceGrant>, StorageError>> + Send;

    /// Look up a device grant by NORMALIZED user code.
    fn find_device_grant_by_user_code(
        &self,
        normalized_user_code: &str,
    ) -> impl Future<Output = Result<Option<DeviceGrant>, StorageError>> + Send;

    /// Atomically remove and return a device grant. This is the single-use redemption primitive:
    /// under concurrent redemption exactly one caller receives the grant.
    fn take_device_grant(
        &self,
        device_code: &str,
    ) -> impl Future<Output = Result<Option<DeviceGrant>, StorageError>> + Send;

    /// Persist a pending authorization code, keyed by `code`.
    fn put_authorization_code(
        &self,
        record: AuthorizationCodeRecord,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;

    /// Atomically remove and return an authorization code record. Single-use redemption, same
    /// contract as [`Storage::take_device_grant`]: under concurrent redemption exactly one
    /// caller receives the record (RFC 6749 section 4.1.2 makes codes single use).
    fn take_authorization_code(
        &self,
        code: &str,
    ) -> impl Future<Output = Result<Option<AuthorizationCodeRecord>, StorageError>> + Send;

    /// Persist an issued access token.
    fn put_token(
        &self,
        token: IssuedToken,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;

    /// Look up an access token (introspection).
    fn get_token(
        &self,
        access_token: &str,
    ) -> impl Future<Output = Result<Option<IssuedToken>, StorageError>> + Send;

    /// Persist a refresh token record.
    fn put_refresh_token(
        &self,
        record: RefreshTokenRecord,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;

    /// Atomically remove and return a refresh token record. This is what makes rotation single
    /// use: under concurrent refresh exactly one caller wins and every other presentation of the
    /// same token is `invalid_grant`.
    fn take_refresh_token(
        &self,
        refresh_token: &str,
    ) -> impl Future<Output = Result<Option<RefreshTokenRecord>, StorageError>> + Send;
}

#[derive(Default)]
struct MemoryInner {
    clients: HashMap<String, Client>,
    device_by_code: HashMap<String, DeviceGrant>,
    /// normalized user code -> device_code
    user_code_index: HashMap<String, String>,
    auth_codes: HashMap<String, AuthorizationCodeRecord>,
    tokens: HashMap<String, IssuedToken>,
    refresh: HashMap<String, RefreshTokenRecord>,
}

/// The in-memory [`Storage`]: a mutexed set of maps. Reference implementation for the trait's
/// contract (its `take_*` are atomic by construction) and the store this crate's own tests run on.
/// Allocates nothing beyond its empty maps until used.
#[derive(Default)]
pub struct MemoryStorage {
    inner: Mutex<MemoryInner>,
}

impl MemoryStorage {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, MemoryInner> {
        // A poisoned mutex means a panic mid-update; the maps hold owned values that are written
        // whole, so continuing with the recovered guard is sound.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Storage for MemoryStorage {
    async fn get_client(&self, client_id: &ClientId) -> Result<Option<Client>, StorageError> {
        Ok(self.lock().clients.get(client_id.as_str()).cloned())
    }

    async fn put_client(&self, client: Client) -> Result<(), StorageError> {
        self.lock()
            .clients
            .insert(client.client_id.as_str().to_string(), client);
        Ok(())
    }

    async fn put_device_grant(&self, grant: DeviceGrant) -> Result<(), StorageError> {
        let mut g = self.lock();
        let normalized = crate::device::normalize_user_code(&grant.user_code);
        g.user_code_index
            .insert(normalized, grant.device_code.clone());
        g.device_by_code.insert(grant.device_code.clone(), grant);
        Ok(())
    }

    async fn get_device_grant(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceGrant>, StorageError> {
        Ok(self.lock().device_by_code.get(device_code).cloned())
    }

    async fn find_device_grant_by_user_code(
        &self,
        normalized_user_code: &str,
    ) -> Result<Option<DeviceGrant>, StorageError> {
        let g = self.lock();
        Ok(g.user_code_index
            .get(normalized_user_code)
            .and_then(|dc| g.device_by_code.get(dc))
            .cloned())
    }

    async fn take_device_grant(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceGrant>, StorageError> {
        let mut g = self.lock();
        let grant = g.device_by_code.remove(device_code);
        if let Some(grant) = &grant {
            let normalized = crate::device::normalize_user_code(&grant.user_code);
            g.user_code_index.remove(&normalized);
        }
        Ok(grant)
    }

    async fn put_authorization_code(
        &self,
        record: AuthorizationCodeRecord,
    ) -> Result<(), StorageError> {
        self.lock().auth_codes.insert(record.code.clone(), record);
        Ok(())
    }

    async fn take_authorization_code(
        &self,
        code: &str,
    ) -> Result<Option<AuthorizationCodeRecord>, StorageError> {
        Ok(self.lock().auth_codes.remove(code))
    }

    async fn put_token(&self, token: IssuedToken) -> Result<(), StorageError> {
        self.lock().tokens.insert(token.access_token.clone(), token);
        Ok(())
    }

    async fn get_token(&self, access_token: &str) -> Result<Option<IssuedToken>, StorageError> {
        Ok(self.lock().tokens.get(access_token).cloned())
    }

    async fn put_refresh_token(&self, record: RefreshTokenRecord) -> Result<(), StorageError> {
        self.lock()
            .refresh
            .insert(record.refresh_token.clone(), record);
        Ok(())
    }

    async fn take_refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<Option<RefreshTokenRecord>, StorageError> {
        Ok(self.lock().refresh.remove(refresh_token))
    }
}
