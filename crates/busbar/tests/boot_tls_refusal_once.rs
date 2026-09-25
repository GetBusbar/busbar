// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A listener whose `tls:` material does not parse refuses boot with ONE line naming it, exactly as
//! the published 1.5.5 binary does (oracle cell `boot.refusal|BOOT-181|boot`):
//!
//! `[error] TLS configuration error for '<addr>': TLS cert (env:…) contains no certificates …`
//!
//! `busbar_core_connsec::FailClosed` already renders that prefix; the composition root wrapped it in
//! the same prefix a second time (since 029230dd7), so the line read `TLS configuration error for
//! '<addr>': TLS configuration error for '<addr>': …`. This boots the real binary on the oracle's own
//! mutation (non-PEM bytes resolved from the environment) and counts the prefix.
//!
//! The fixture is an LLM config (`providers:`/`models:`/`pools:`), so it needs the LLM plane in the
//! build: without `proto-llm` no plane owns those sections and boot refuses them before the listener
//! is ever reached — the same gate every LLM-config boot test in `cli_validate.rs` carries.
#![cfg(all(unix, linked_axis_body_ingress))]

use std::path::PathBuf;
use std::process::Command;

fn fixture_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-boot-tls-once-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn a_tls_material_refusal_names_the_listener_once() {
    let dir = fixture_dir();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    std::fs::write(
        dir.join("providers.yaml"),
        "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n  api_key_env: MOCK_KEY\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            r#"listen: "127.0.0.1:{port}"
admin_listen: "127.0.0.1:0"
tls:
  cert: {{ env: BOOT_TLS_ONCE_CERT }}
  key: {{ env: BOOT_TLS_ONCE_KEY }}
providers:
  mock:
    api_key: {{ env: MOCK_KEY }}
models:
  test-model:
    provider: mock
pools:
  op:
    members:
      - model: test-model
"#
        ),
    )
    .unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_busbar"))
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
        .env("MOCK_KEY", "x")
        .env("BOOT_TLS_ONCE_CERT", "not-a-pem-certificate")
        .env("BOOT_TLS_ONCE_KEY", "not-a-pem-key")
        .output()
        .expect("run busbar");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(1),
        "boot must refuse; stderr:\n{stderr}"
    );
    let line = stderr
        .lines()
        .find(|l| l.contains("TLS configuration error for '"))
        .unwrap_or_else(|| panic!("no TLS refusal line; stderr:\n{stderr}"));
    assert_eq!(
        line.matches("TLS configuration error for '").count(),
        1,
        "the refusal names the listener once, as 1.5.5 does: {line}"
    );
    assert!(
        line.contains(&format!(
            "TLS configuration error for '127.0.0.1:{port}': TLS cert"
        )),
        "the reason follows the listener directly: {line}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
