// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Boot-captured deregistration allowance; the engine drain budget remains fixed.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::time::Duration;

/// The top-level `shutdown:` section (1.6 development builds read it as `advanced.shutdown`; an
/// old configuration's block is carried here when the document is read). Changes require a
/// restart.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ShutdownCfg {
    /// Readiness-to-drain interval for operator shutdown, from zero through 300 seconds. Safety
    /// shutdown and force bypass this interval. Absent: no interval ([`ShutdownCfg::delay`] is
    /// zero), as v1.5.5 had none; the operator states their load balancer's probe period times its
    /// failure threshold.
    #[serde(
        default,
        deserialize_with = "read_delay",
        serialize_with = "write_delay",
        skip_serializing_if = "Option::is_none"
    )]
    pub deregister_delay: Option<Duration>,
}

impl ShutdownCfg {
    /// The deregistration allowance in force: the stated one, else none.
    #[must_use]
    pub fn delay(&self) -> Duration {
        self.deregister_delay.unwrap_or(Duration::ZERO)
    }
}

fn read_delay<'de, D: Deserializer<'de>>(input: D) -> Result<Option<Duration>, D::Error> {
    use serde::de::Error as _;
    let written = String::deserialize(input).map_err(|error| {
        D::Error::custom(format!(
            "shutdown.deregister_delay requires a duration string: {error}"
        ))
    })?;
    let seconds = super::parse::parse_duration_secs(&written).map_err(|error| {
        D::Error::custom(format!("shutdown.deregister_delay {written:?}: {error}"))
    })?;
    if seconds > 300 {
        return Err(D::Error::custom(format!(
            "shutdown.deregister_delay {written:?} is outside 0s..300s"
        )));
    }
    Ok(Some(Duration::from_secs(seconds)))
}

fn write_delay<S: Serializer>(delay: &Option<Duration>, output: S) -> Result<S::Ok, S::Error> {
    match delay {
        Some(delay) => output.serialize_str(&format!("{}s", delay.as_secs())),
        None => output.serialize_none(),
    }
}
