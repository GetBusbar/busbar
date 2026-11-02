// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![cfg(unix)]
#![cfg(linked_section_pools)]

mod common;

use common::plugins;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const PUBLISHED_1_5_5: &[(&str, u32)] = &[
    ("store", 2),
    ("auth", 2),
    ("hook", 1),
    ("export", 2),
    ("secret", 1),
];

const DEADLINE: Duration = Duration::from_secs(60);

fn fixture_dir(kind: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-1-5-5-refused-{kind}-{}-{}",
        std::process::id(),
        {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            format!(
                "{}-{}-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos()),
                line!(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            )
        }
    ));
    std::fs::create_dir_all(d.join("plugins")).unwrap();
    d
}

fn write_configs(dir: &Path, data_port: u16, admin_port: u16) {
    std::fs::write(
        dir.join("providers.yaml"),
        "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            "listen: \"127.0.0.1:{data_port}\"\nadmin_listen: \"127.0.0.1:{admin_port}\"\n\
             admin_require_mtls: false\nstore: {{module: memory}}\nplugins:\n  enabled: true\n  dir: '{}'\n  trust:\n    \
             allow_unsigned: true\nproviders:\n  mock:\n    api_key: {{ env: MOCK_KEY }}\n\
             models:\n  test-model:\n    provider: mock\n",
            dir.join("plugins").display()
        ),
    )
    .unwrap();
}

fn boot(dir: &Path) -> Option<(i32, String)> {
    let mut child = Command::new(common::boot::exe())
        .env("MOCK_KEY", "test-key-value")
        .env(
            "BUSBAR_SIGNING_KEY",
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn busbar");
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll busbar") {
            break Some(status);
        }
        if start.elapsed() > DEADLINE {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let mut stderr = String::new();
    if let Some(mut e) = child.stderr.take() {
        let _ = e.read_to_string(&mut stderr);
    }
    status.map(|s| (s.code().unwrap_or(-1), stderr))
}

#[test]
fn a_1_5_5_json_contract_plugin_is_refused_at_boot_naming_the_rebuild() {
    for &(kind, v155) in PUBLISHED_1_5_5 {
        let dir = fixture_dir(kind);
        let mut m = plugins::manifest(kind, &format!("busbar-{kind}-published"), "acme");
        m.abi_version = v155;
        std::fs::write(
            dir.join("plugins").join("published.tar.gz"),
            plugins::seal(m, b"published lib"),
        )
        .unwrap();
        write_configs(&dir, common::boot::free_port(), common::boot::free_port());

        let Some((code, stderr)) = boot(&dir) else {
            panic!(
                "{kind}: a 1.5.5 plugin (abi_version {v155}) booted and served for {DEADLINE:?}"
            );
        };
        assert_ne!(code, 0, "{kind}: the boot must refuse: {stderr}");
        for want in [
            "published.tar.gz".to_string(),
            format!("'{kind}'"),
            format!("abi_version {v155} is not supported"),
            "rebuild the plugin against the 1.6.0 SDK".to_string(),
        ] {
            assert!(
                stderr.contains(&want),
                "{kind}: the refusal names `{want}`: {stderr}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
