// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Boot-captured deregistration allowance; the engine drain budget remains fixed.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::time::Duration;

/// The document-only `advanced.shutdown` section. Changes require a restart.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdvancedShutdownCfg {
    /// Readiness-to-drain interval for operator shutdown, from zero through 300 seconds.
    /// Safety shutdown and force bypass this interval. Defaults to five seconds.
    #[serde(
        default = "default_delay",
        deserialize_with = "read_delay",
        serialize_with = "write_delay"
    )]
    pub deregister_delay: Duration,
}

fn default_delay() -> Duration {
    Duration::from_secs(5)
}

impl Default for AdvancedShutdownCfg {
    fn default() -> Self {
        Self {
            deregister_delay: default_delay(),
        }
    }
}

fn read_delay<'de, D: Deserializer<'de>>(input: D) -> Result<Duration, D::Error> {
    use serde::de::Error as _;
    let written = String::deserialize(input).map_err(|error| {
        D::Error::custom(format!(
            "advanced.shutdown.deregister_delay requires a duration string: {error}"
        ))
    })?;
    let seconds = super::parse::parse_duration_secs(&written).map_err(|error| {
        D::Error::custom(format!(
            "advanced.shutdown.deregister_delay {written:?}: {error}"
        ))
    })?;
    if seconds > 300 {
        return Err(D::Error::custom(format!(
            "advanced.shutdown.deregister_delay {written:?} is outside 0s..300s"
        )));
    }
    Ok(Duration::from_secs(seconds))
}

fn write_delay<S: Serializer>(delay: &Duration, output: S) -> Result<S::Ok, S::Error> {
    output.serialize_str(&format!("{}s", delay.as_secs()))
}
