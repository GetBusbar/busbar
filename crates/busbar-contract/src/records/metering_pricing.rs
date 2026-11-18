// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::count::CountError;
use serde::{Deserialize, Serialize};

/// The selected row identity. Outcome counters are deliberately absent from the key.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MeteringRole {
    Usage,
    Request,
    Fee { lane: Option<String> },
}

/// Core-owned selected metering evidence, never a second budget fee operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Wire", into = "Wire")]
pub enum MeteringPricingV1 {
    SelectedUsage,
    SelectedRequest,
    SelectedFee {
        lane: Option<String>,
        charged: u64,
        refunded: u64,
        unknown: u64,
    },
}

/// The wire form: `{"version":1,"role":"usage"|"request"}` or
/// `{"version":1,"role":"fee","lane":<text|null>,"charged":n,"refunded":n,"unknown":n}`.
///
/// Written as an internally tagged enum, but decoded through [`FlatWire`]: serde decodes an internally
/// tagged enum by buffering the object, and a buffered number under the workspace's sonic-rs
/// `arbitrary_precision` is its exact-number map, never a `u8`/`u64` ("invalid type: map, expected
/// u8"). The flat form reads every number directly and keeps the tagged form's refusals: an unknown
/// role or field, a usage/request row carrying fee fields, a fee row missing any of them.
#[derive(Serialize)]
#[serde(tag = "role", rename_all = "snake_case")]
enum Wire {
    Usage {
        version: u8,
    },
    Request {
        version: u8,
    },
    Fee {
        version: u8,
        lane: Option<String>,
        charged: u64,
        refunded: u64,
        unknown: u64,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FlatWire {
    role: FlatRole,
    version: u8,
    /// `Some(lane)` when the key is present (its value may be null), `None` when absent.
    #[serde(default, deserialize_with = "present")]
    lane: Option<Option<String>>,
    charged: Option<u64>,
    refunded: Option<u64>,
    unknown: Option<u64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum FlatRole {
    Usage,
    Request,
    Fee,
}

fn present<'de, D: serde::Deserializer<'de>>(
    decoder: D,
) -> Result<Option<Option<String>>, D::Error> {
    Option::<String>::deserialize(decoder).map(Some)
}

impl<'de> Deserialize<'de> for Wire {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        let flat = FlatWire::deserialize(decoder)?;
        let fee_fields = flat.lane.is_some()
            || flat.charged.is_some()
            || flat.refunded.is_some()
            || flat.unknown.is_some();
        match flat.role {
            FlatRole::Usage if !fee_fields => Ok(Self::Usage {
                version: flat.version,
            }),
            FlatRole::Request if !fee_fields => Ok(Self::Request {
                version: flat.version,
            }),
            FlatRole::Usage | FlatRole::Request => Err(D::Error::custom(
                "a usage or request pricing carries no fee fields",
            )),
            FlatRole::Fee => match (flat.lane, flat.charged, flat.refunded, flat.unknown) {
                (Some(lane), Some(charged), Some(refunded), Some(unknown)) => Ok(Self::Fee {
                    version: flat.version,
                    lane,
                    charged,
                    refunded,
                    unknown,
                }),
                _ => Err(D::Error::custom(
                    "a fee pricing names lane, charged, refunded and unknown",
                )),
            },
        }
    }
}

impl TryFrom<Wire> for MeteringPricingV1 {
    type Error = &'static str;
    fn try_from(wire: Wire) -> Result<Self, Self::Error> {
        match wire {
            Wire::Usage { version: 1 } => Ok(Self::SelectedUsage),
            Wire::Request { version: 1 } => Ok(Self::SelectedRequest),
            Wire::Fee {
                version: 1,
                lane,
                charged,
                refunded,
                unknown,
            } if lane.as_ref().is_none_or(|lane| {
                !lane.is_empty() && lane.len() <= 4096 && !lane.contains('\0')
            }) =>
            {
                Ok(Self::SelectedFee {
                    lane,
                    charged,
                    refunded,
                    unknown,
                })
            }
            _ => Err("unsupported or invalid selected metering pricing"),
        }
    }
}

impl From<MeteringPricingV1> for Wire {
    fn from(pricing: MeteringPricingV1) -> Self {
        match pricing {
            MeteringPricingV1::SelectedUsage => Self::Usage { version: 1 },
            MeteringPricingV1::SelectedRequest => Self::Request { version: 1 },
            MeteringPricingV1::SelectedFee {
                lane,
                charged,
                refunded,
                unknown,
            } => Self::Fee {
                version: 1,
                lane,
                charged,
                refunded,
                unknown,
            },
        }
    }
}

impl MeteringRole {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Usage => "usage",
            Self::Request => "request",
            Self::Fee { .. } => "fee",
        }
    }
    pub fn lane(&self) -> Option<&str> {
        match self {
            Self::Fee { lane } => lane.as_deref(),
            _ => None,
        }
    }
}

impl MeteringPricingV1 {
    pub fn identity(&self) -> MeteringRole {
        match self {
            Self::SelectedUsage => MeteringRole::Usage,
            Self::SelectedRequest => MeteringRole::Request,
            Self::SelectedFee { lane, .. } => MeteringRole::Fee { lane: lane.clone() },
        }
    }

    pub fn zeroed(&self) -> Self {
        match self {
            Self::SelectedFee { lane, .. } => Self::SelectedFee {
                lane: lane.clone(),
                charged: 0,
                refunded: 0,
                unknown: 0,
            },
            other => other.clone(),
        }
    }

    pub fn has_fee_evidence(&self) -> bool {
        matches!(self, Self::SelectedFee { charged, refunded, unknown, .. } if *charged != 0 || *refunded != 0 || *unknown != 0)
    }

    /// Zero fee evidence is allowed only while assembling an empty destination before addition.
    pub fn validate_counts(
        &self,
        requests: u64,
        billable: u64,
        has_units: bool,
    ) -> Result<(), CountError> {
        let valid = match self {
            Self::SelectedUsage => requests == 0 && billable == 0,
            Self::SelectedRequest => !has_units,
            Self::SelectedFee { lane, .. } => {
                requests == 0
                    && billable == 0
                    && !has_units
                    && lane.as_ref().is_none_or(|lane| {
                        !lane.is_empty() && lane.len() <= 4096 && !lane.contains('\0')
                    })
            }
        };
        if valid {
            Ok(())
        } else {
            Err(CountError::Malformed)
        }
    }

    pub fn checked_add(&self, other: &Self) -> Result<Self, CountError> {
        if self.identity() != other.identity() {
            return Err(CountError::Malformed);
        }
        match (self, other) {
            (
                Self::SelectedFee {
                    lane,
                    charged: a,
                    refunded: b,
                    unknown: c,
                },
                Self::SelectedFee {
                    charged: x,
                    refunded: y,
                    unknown: z,
                    ..
                },
            ) => Ok(Self::SelectedFee {
                lane: lane.clone(),
                charged: a.checked_add(*x).ok_or(CountError::Overflow)?,
                refunded: b.checked_add(*y).ok_or(CountError::Overflow)?,
                unknown: c.checked_add(*z).ok_or(CountError::Overflow)?,
            }),
            _ => Ok(self.clone()),
        }
    }
}
