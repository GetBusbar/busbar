// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Root-owned export adapters over opened MIN3 ports and their exact instance bindings.

use busbar_contract::services::{DiskDest, DiskReport, DiskRotate};
use busbar_kernel::host_disk::DiskLane;
use busbar_plugin_loader::export_door::port::{AppendBytes, AppendDenied, DestAppend};
use busbar_ports::binder::ConfigBinder;

/// The exact prepared export pumps. Routing borrows their ExportCalls handles; shutdown
/// retains these concrete owners to observe worker quiescence before Store retirement.
pub(crate) struct Exports {
    doors:
        std::collections::BTreeMap<String, Arc<busbar_plugin_loader::export_door::port::PortDoor>>,
}

impl Exports {
    pub(crate) fn new(
        doors: Vec<(
            String,
            Arc<busbar_plugin_loader::export_door::port::PortDoor>,
        )>,
    ) -> Result<Self, String> {
        let mut owned = std::collections::BTreeMap::new();
        for (name, door) in doors {
            if owned.insert(name.clone(), door).is_some() {
                return Err(format!("duplicate opened export instance `{name}`"));
            }
        }
        Ok(Self { doors: owned })
    }

    pub(crate) fn calls(
        &self,
    ) -> std::collections::BTreeMap<String, Arc<dyn busbar_contract::export_calls::ExportCalls>>
    {
        self.doors
            .iter()
            .map(|(name, door)| {
                (
                    name.clone(),
                    Arc::clone(door) as Arc<dyn busbar_contract::export_calls::ExportCalls>,
                )
            })
            .collect()
    }

    pub(crate) fn start(&self) -> Result<(), String> {
        for door in self.doors.values() {
            door.start()?;
        }
        Ok(())
    }

    pub(crate) fn stop_until(
        self,
        deadline: std::time::Instant,
    ) -> Vec<(String, busbar_plugin_loader::export_door::port::StopReport)> {
        for door in self.doors.values() {
            door.begin_drain(deadline);
        }
        self.doors
            .into_iter()
            .map(|(name, door)| (name, door.stop_until(deadline)))
            .collect()
    }
}
use std::sync::Arc;

pub(crate) struct BoundDisk {
    instance: u64,
    binder: Arc<dyn ConfigBinder>,
    lane: Arc<DiskLane>,
}

impl BoundDisk {
    pub(crate) fn new(instance: u64, binder: Arc<dyn ConfigBinder>, lane: Arc<DiskLane>) -> Self {
        Self {
            instance,
            binder,
            lane,
        }
    }
}

impl DestAppend for BoundDisk {
    fn append(&self, handle: u32, bytes: AppendBytes<'_>) -> Result<(), AppendDenied> {
        let bound = self
            .binder
            .dest(self.instance, handle)
            .ok_or(AppendDenied::Foreign)?;
        let dest = DiskDest {
            key: handle.to_string(),
            path: bound.path.to_string(),
            rotate_at: Some(bound.rotate_mb.saturating_mul(1024 * 1024)),
            rotate: DiskRotate::declared(Some(bound.keep)),
        };
        let bytes = match bytes {
            AppendBytes::Owned(bytes) => bytes,
            AppendBytes::Batch(lines) => {
                let mut bytes = busbar_contract::secure::SecureVec::new();
                for line in lines {
                    bytes
                        .extend(line)
                        .and_then(|()| bytes.push(b'\n'))
                        .map_err(|_| {
                            AppendDenied::Failed(busbar_plugin_abi::fail::failed::F_LIMIT)
                        })?;
                }
                bytes.into_vec()
            }
        };
        let (send, received) = std::sync::mpsc::sync_channel(1);
        self.lane
            .submit(
                dest,
                bytes,
                Box::new(move |stored| {
                    let _ = send.send(DiskReport::of(&stored));
                }),
            )
            .map_err(|report| {
                if report.error == busbar_kernel::host_disk::LANE_FULL {
                    AppendDenied::LaneFull
                } else {
                    AppendDenied::LaneGone
                }
            })?;
        // The export pump is a blocking worker. An accepted append must get its real receipt;
        // abandoning it and retrying could duplicate a write still owned by the disk lane.
        // PortDoor's bounded stop reports a nonquiescent worker without closing its owners.
        let report = received.recv().map_err(|_| AppendDenied::LaneGone)?;
        if report.step == 0 {
            Ok(())
        } else {
            Err(AppendDenied::Failed(
                u32::try_from(report.step)
                    .unwrap_or(busbar_plugin_abi::fail::failed::F_UNAVAILABLE),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use busbar_plugin_loader::export_door::port::{AppendBytes, AppendDenied, DestAppend};
    use busbar_ports::binder::ConfigBinder;
    use std::sync::Arc;

    #[test]
    fn append_uses_only_its_reserved_instances_bound_destination() {
        let path = std::env::temp_dir().join(format!(
            "busbar-min3-export-bound-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let config = busbar_contract::json::to_vec(
            &busbar_contract::json::json!({"path": path.to_str().unwrap(), "keep": 0}),
        )
        .unwrap();
        let binder: Arc<dyn ConfigBinder> = Arc::new(busbar_kernel::plugin_config::Binder::new(
            Arc::default(),
            Vec::new(),
        ));
        binder.bind(41, &config, &[], &[], &[""], &[]).unwrap();
        let lane = Arc::new(busbar_kernel::host_disk::DiskLane::default());
        let own = super::BoundDisk::new(41, binder.clone(), lane.clone());
        let other = super::BoundDisk::new(42, binder.clone(), lane);
        assert_eq!(
            other.append(1, AppendBytes::Owned(b"foreign".to_vec())),
            Err(AppendDenied::Foreign)
        );
        assert_eq!(
            own.append(0, AppendBytes::Owned(b"zero".to_vec())),
            Err(AppendDenied::Foreign)
        );
        assert!(!path.exists());
        own.append(1, AppendBytes::Batch(&[b"first", b"second"]))
            .unwrap();
        own.append(1, AppendBytes::Owned(b"encoded".to_vec()))
            .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"first\nsecond\nencoded");
        binder.unbind(41);
        assert_eq!(
            own.append(1, AppendBytes::Owned(b"retired".to_vec())),
            Err(AppendDenied::Foreign)
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"first\nsecond\nencoded");
        std::fs::remove_file(path).unwrap();
    }
}
