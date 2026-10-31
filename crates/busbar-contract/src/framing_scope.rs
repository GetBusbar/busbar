// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Host-only connection ownership shared by the connector and loader. This is Rust metadata;
//! it is never lent to a plugin or included in a C ABI frame.

/// One host-owned framing leg, independent of the tickets its operations use.
pub trait FramingScope: std::fmt::Debug + Send + Sync {
    /// The actual loaded plugin owner.
    fn owner(&self) -> u64;
    /// The accepting listener registration, or zero for an outbound connection.
    fn listener(&self) -> u64;
    /// The physical connection incarnation, retained across authorized adoption.
    fn connection(&self) -> u64;
    /// The framing leg incarnation.
    fn leg(&self) -> u64;
    /// Validate a service's caller and plugin-local connection token.
    ///
    /// # Errors
    /// The caller/token differs, or the leg no longer permits the service.
    fn check(&self, owner: u64, conn: u64, teardown: bool) -> Result<(), &'static str>;
    /// Confirm the token returned by a READY opening, including prior provisional claims.
    ///
    /// # Errors
    /// A mismatching token or a leg no longer opening.
    fn confirm(&self, conn: u64) -> Result<(), &'static str>;
    /// Stop ordinary admission before teardown.
    fn closing(&self);
    /// End authority once, even if asynchronous operations still retain this object.
    fn end(&self);
}
