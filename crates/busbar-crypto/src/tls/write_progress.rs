// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Provider-owned TLS output provenance, without an async runtime dependency.

pub use rustls::{OutputStorageError, OutputStorageLimits, OutputStoragePlan};
pub use rustls::{WriteProgress, WriteTrackingError, WriteTrackingFault, WriteTrackingLimits};

/// The explicitly adopted server and dialer output shape, charged before TLS construction.
/// These are all-wire record and requested-backing limits, not response/request counts.
pub fn output_plan() -> Result<OutputStoragePlan, OutputStorageError> {
    use std::num::NonZeroUsize;
    OutputStoragePlan::new(OutputStorageLimits {
        pending_records: NonZeroUsize::new(64).ok_or(OutputStorageError::Limit)?,
        ciphertext_bytes: NonZeroUsize::new(64 * 1024).ok_or(OutputStorageError::Limit)?,
        serialization_bytes: NonZeroUsize::new(256 * 1024).ok_or(OutputStorageError::Limit)?,
    })
}

/// Validate an already selected client profile and install its immutable allocation plan.
pub fn configure_client(
    config: &mut rustls::ClientConfig,
    plan: OutputStoragePlan,
) -> Result<(), OutputStorageError> {
    config.output_storage = Some(plan);
    config.validate_output_storage()
}

/// Validate an already selected server profile and install its immutable allocation plan.
pub fn configure_server(
    config: &mut rustls::ServerConfig,
    plan: OutputStoragePlan,
) -> Result<(), OutputStorageError> {
    config.output_storage = Some(plan);
    config.validate_output_storage()
}

/// Refuse an unfunded or incompatible client configuration before handshake construction.
pub fn client_plan(config: &rustls::ClientConfig) -> Result<OutputStoragePlan, OutputStorageError> {
    config.validate_output_storage()?;
    config
        .output_storage
        .ok_or(OutputStorageError::UnsupportedProvider)
}

/// Refuse an unfunded or incompatible server configuration before handshake construction.
pub fn server_plan(config: &rustls::ServerConfig) -> Result<OutputStoragePlan, OutputStorageError> {
    config.validate_output_storage()?;
    config
        .output_storage
        .ok_or(OutputStorageError::UnsupportedProvider)
}

/// Enable finite output tracking after a handshake and before application output.
///
/// This records successful output to rustls's supplied writer. The transport owner must
/// bind that writer to a proven unbuffered carrier before treating it as socket evidence.
pub fn enable<Data>(
    connection: &mut rustls::ConnectionCommon<Data>,
    limits: WriteTrackingLimits,
) -> Result<(), WriteTrackingError> {
    connection.enable_write_tracking(limits)
}

/// Read the crypto-owned monotone output frontiers without granting mutation authority.
#[must_use]
pub fn snapshot(connection: &rustls::CommonState) -> Option<WriteProgress> {
    connection.write_progress()
}
