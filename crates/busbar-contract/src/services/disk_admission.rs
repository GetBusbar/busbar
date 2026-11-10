// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Host admission of the common declared disk destination grammar.

use std::collections::BTreeMap;

use super::{DiskDest, DiskRotate, DISK_KEEP_KEY, DISK_ROTATE_KEY};
use crate::{caps::KernelSeal, plugin_settings::Settings};

/// Root-issued authority for interpreting declared filesystem destinations.
/// Privileged issuance remains subject to the host source-direction boundary.
/// A plugin's generic grant cannot issue this authority.
///
/// ```compile_fail,E0308
/// use busbar_contract::{services::disk_admission::DiskAuthority, plugin::KernelSeal};
/// fn forge(grant: &dyn KernelSeal) { let _ = DiskAuthority::issue(grant); }
/// ```
#[derive(Clone, Debug)]
pub struct DiskAuthority {
    _private: (),
}

impl DiskAuthority {
    /// Issue at kernel composition using the concrete root minter.
    pub fn issue(_: &KernelSeal) -> Self {
        Self { _private: () }
    }

    /// Bind the admitted declaration once, before opening the instance.
    pub fn bind(&self, keys: &[String], keep: &BTreeMap<String, u32>) -> DiskAdmission {
        DiskAdmission {
            keys: keys.to_vec(),
            keep: keep.clone(),
        }
    }
}

/// One instance's fixed declared destinations and default retention policy.
/// Admission accepts no caller-selected settings path and no readable callback.
#[derive(Clone, Debug)]
pub struct DiskAdmission {
    keys: Vec<String>,
    keep: BTreeMap<String, u32>,
}

impl DiskAdmission {
    /// Resolve each generation's operator settings into host filesystem actuator inputs.
    /// Invalid or absent destinations remain unbound, preserving refusal by `disk.append`.
    pub fn admit(&self, settings: &Settings) -> Vec<DiskDest> {
        let doc = &settings.0 .0;
        let rotate_at = doc
            .get(DISK_ROTATE_KEY)
            .and_then(serde_json::Value::as_u64)
            .map(|mb| mb.saturating_mul(1024 * 1024));
        let operator_keep = doc
            .get(DISK_KEEP_KEY)
            .and_then(serde_json::Value::as_u64)
            .map(|n| u32::try_from(n).unwrap_or(u32::MAX));
        self.keys
            .iter()
            .filter_map(|key| {
                let path = doc.get(key)?.as_str()?;
                (!path.is_empty() && !path.contains('\0')).then(|| DiskDest {
                    key: key.clone(),
                    path: path.to_owned(),
                    rotate_at,
                    rotate: DiskRotate::declared(
                        operator_keep.or_else(|| self.keep.get(key).copied()),
                    ),
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn settings(value: serde_json::Value) -> Settings {
        serde_json::from_value(value).unwrap()
    }
    fn admission() -> DiskAdmission {
        DiskAdmission {
            keys: vec!["output".into()],
            keep: BTreeMap::from([("output".into(), 3)]),
        }
    }
    #[test]
    fn only_fixed_declared_destinations_are_admitted_each_generation() {
        let grant = admission();
        let first = grant.admit(&settings(
            serde_json::json!({"output":"/first", "other":"/unadmitted"}),
        ));
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].path, "/first");
        assert_eq!(first[0].rotate, DiskRotate::Rename { keep: 3 });
        let next = grant.admit(&settings(serde_json::json!({"output":"/next"})));
        assert_eq!(next[0].path, "/next");
        assert_eq!(first[0].path, "/first");
        for invalid in [
            serde_json::Value::Null,
            serde_json::json!(7),
            serde_json::json!(""),
            serde_json::json!("bad\0path"),
        ] {
            assert!(grant
                .admit(&settings(serde_json::json!({"output":invalid})))
                .is_empty());
        }
    }
    #[test]
    fn common_rotation_preserves_default_zero_saturation_and_malformed_semantics() {
        for (keep, expected) in [
            (serde_json::json!(0), DiskRotate::Truncate),
            (
                serde_json::json!(u64::MAX),
                DiskRotate::Rename { keep: u32::MAX },
            ),
            (serde_json::json!("bad"), DiskRotate::Rename { keep: 3 }),
        ] {
            let got = admission().admit(&settings(
                serde_json::json!({"output":"/file", "keep":keep, "rotate_mb":u64::MAX}),
            ));
            assert_eq!(got[0].rotate, expected);
            assert_eq!(got[0].rotate_at, Some(u64::MAX));
        }
        let got = admission().admit(&settings(
            serde_json::json!({"output":"/file", "rotate_mb":"bad"}),
        ));
        assert_eq!(got[0].rotate_at, None);
    }
}
