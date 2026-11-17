// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Preserve operational failure classes across the predecessor boundary.

use crate::persistence::{facade::AccessError, host_records, journal};
use busbar_contract::persistence::Failure;

/// A predecessor step's failure (SEALING-FIX §3.6.2). Transient failures never become
/// permanent merely because a backend remained unavailable for a long time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetireError {
    /// Retry this step with capped backoff while the process is running.
    Transient(String),
    /// Invalid identity, malformed data, or a rejected predicate: skip this predecessor.
    Permanent(String),
}

impl std::fmt::Display for RetireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transient(cause) | Self::Permanent(cause) => f.write_str(cause),
        }
    }
}
impl std::error::Error for RetireError {}

impl From<String> for RetireError {
    fn from(cause: String) -> Self {
        Self::Permanent(cause)
    }
}
impl From<&str> for RetireError {
    fn from(cause: &str) -> Self {
        Self::Permanent(cause.to_owned())
    }
}
impl From<Failure> for RetireError {
    fn from(cause: Failure) -> Self {
        match cause {
            Failure::Unavailable | Failure::Overloaded | Failure::Unknown | Failure::StaleScan => {
                Self::Transient(format!("{cause:?}"))
            }
            Failure::Refused | Failure::Corrupt => Self::Permanent(format!("{cause:?}")),
        }
    }
}
impl From<AccessError> for RetireError {
    fn from(cause: AccessError) -> Self {
        match cause {
            AccessError::Backend(cause) => cause.into(),
            AccessError::Overloaded | AccessError::UnknownOperation => {
                Self::Transient(format!("{cause:?}"))
            }
            _ => Self::Permanent(format!("{cause:?}")),
        }
    }
}
impl From<host_records::Error> for RetireError {
    fn from(cause: host_records::Error) -> Self {
        match cause {
            host_records::Error::Backend(cause) => cause.into(),
            host_records::Error::Access(cause) => cause.into(),
            _ => Self::Permanent(format!("{cause:?}")),
        }
    }
}
impl From<journal::Error> for RetireError {
    fn from(cause: journal::Error) -> Self {
        match cause {
            journal::Error::Backend(cause) => cause.into(),
            journal::Error::Access(cause) => cause.into(),
            _ => Self::Permanent(format!("{cause:?}")),
        }
    }
}
