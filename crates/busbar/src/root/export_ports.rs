// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Root-owned export adapters over opened MIN3 ports and their exact instance bindings.

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
