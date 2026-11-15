// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `plane_driver::dispatch`'s off-path code: a door's lane qualifier, made once per configuration;
//! the provider dialect list, read when a configuration is built or validated; and the plane
//! dispatch table's mounts, built once per generation. A request resolves through the built table.

use crate::plane_driver::dispatch::{is_fallback, InvalidLaneQualifier};
use crate::plane_driver::dispatch::{Claim, LaneQualifier, Mount, PlaneDispatch};
use crate::plane_driver::registry;

impl LaneQualifier {
    /// The one way to make a qualifier: `""` (the models plane) or plain text with no control
    /// character (the plane/lane separator `U+001F` is one, so a qualifier can never split a lane
    /// name) and no surrounding whitespace.
    pub fn parse(qualifier: &str) -> Result<Self, InvalidLaneQualifier> {
        if qualifier.chars().any(char::is_control) || qualifier.trim() != qualifier {
            return Err(InvalidLaneQualifier);
        }
        Ok(Self(qualifier.to_string()))
    }
}

pub fn provider_dialects() -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    for d in registry::plane_decls() {
        for name in (d.provider_dialects)(d) {
            if !out.contains(name) {
                out.push(name);
            }
        }
    }
    out
}

impl PlaneDispatch {
    pub fn mount(self, key: &'static str, path: &str, wire: &'static str) -> Self {
        if is_fallback(key) {
            return self;
        }
        self.mount_key(key, path, wire)
    }

    pub(crate) fn mount_key(mut self, key: &'static str, path: &str, wire: &'static str) -> Self {
        let normalised = normalise_mount(path);
        if normalised.is_empty() {
            return self;
        }
        let claims = self.claims.entry(key).or_default();
        if !claims.iter().any(|c| c.path == normalised) {
            // Indexed by the mount's first segment, each bucket in plane-key order and, within a
            // plane, in claim order: the order a resolution walks the claims in.
            let segment = normalised[1..].split('/').next().unwrap_or_default();
            let bucket = self.mounts.entry(segment.to_owned()).or_default();
            let at = bucket.partition_point(|m| m.key <= key);
            bucket.insert(
                at,
                Mount {
                    key,
                    path: normalised.clone(),
                    wire,
                },
            );
            claims.push(Claim {
                path: normalised,
                wire,
            });
        }
        self
    }
}

pub(crate) fn normalise_mount(path: &str) -> String {
    let trimmed = path.trim().trim_matches('/');
    if trimmed.is_empty() {
        return String::new();
    }
    format!("/{trimmed}")
}
