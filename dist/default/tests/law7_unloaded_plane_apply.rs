// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![cfg(unix)]
#![cfg(linked_every_plane_door)]

mod common;

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

const ADMIN_TOKEN: &str = "law7-unloaded-plane-admin";

const MOCK_PROVIDER: &str = include_str!("fixtures/mock_provider.yaml");

const PLANE_SECTIONS: [&str; 2] = [
    include_str!("fixtures/tool_plane_section.yaml"),
    include_str!("fixtures/unloaded_plane_sections.yaml"),
];

const PLANE_PREFIX: &str = "busbar-plane-";

struct Plane {
    name: String,

    section: &'static str,

    admin: &'static str,

    door: &'static str,
}

fn plane() -> Plane {
    let rows: Vec<(&'static str, &'static str)> = include_str!("fixtures/unloaded_plane.txt")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let (fact, value) = l.split_once(' ').expect("`<fact> <value>`");
            (fact, value.trim())
        })
        .collect();
    let fact = |name: &str| {
        let found: Vec<&'static str> = rows
            .iter()
            .filter(|(f, _)| *f == name)
            .map(|(_, v)| *v)
            .collect();
        assert_eq!(
            found.len(),
            1,
            "unloaded_plane.txt: exactly one `{name}` row"
        );
        found[0]
    };
    assert_eq!(rows.len(), 2, "unloaded_plane.txt lost or gained a row");
    let section = fact("section");

    let rows: Vec<String> = common::manifest_table("package.metadata.busbar.linked-section")
        .into_iter()
        .filter(|(_, s)| s == section)
        .map(|(row, _)| row)
        .collect();
    assert_eq!(
        rows.len(),
        1,
        "exactly one linked door row declares `{section}`: {rows:?}"
    );
    let package = common::manifest_table("package.metadata.busbar.linked")
        .into_iter()
        .find(|(row, _)| *row == rows[0])
        .map(|(_, package)| package)
        .unwrap_or_else(|| panic!("the door row `{}` links a package", rows[0]));
    let name = package
        .strip_prefix(PLANE_PREFIX)
        .unwrap_or_else(|| panic!("`{package}` is a plane package"))
        .to_string();
    Plane {
        name,
        section,
        admin: fact("admin"),
        door: tool_plane_wire("door_path"),
    }
}

fn tool_plane_wire(key: &str) -> &'static str {
    include_str!("fixtures/tool_plane_wire.txt")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .find_map(|l| {
            let (k, v) = l.split_once('=')?;
            (k.trim() == key).then(|| v.trim())
        })
        .unwrap_or_else(|| panic!("tests/fixtures/tool_plane_wire.txt has no `{key}` row"))
}

fn refusal(plane: &Plane) -> String {
    format!(
        "`{section}:` is the section of the `{name}` plane, which this process did not load \
         because its configuration did not use it at start; a first `{section}:` cannot take \
         effect on a running process, so the change was refused and nothing was changed: write \
         it in the config file and restart.",
        section = plane.section,
        name = plane.name,
    )
}

struct Booted {
    child: Child,
    data: String,
    admin: String,
    log: PathBuf,
}

impl Drop for Booted {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn read_to_string(path: &Path) -> String {
    let mut s = String::new();
    if let Ok(mut f) = std::fs::File::open(path) {
        let _ = f.read_to_string(&mut s);
    }
    s
}

fn base_config(dir: &Path, data: u16, admin: u16) -> String {
    format!(
        r#"listen: "127.0.0.1:{data}"
admin_listen: "127.0.0.1:{admin}"
advanced:
  allow_destinations: ["127.0.0.1"]
store: {{module: memory}}
public_url: "http://127.0.0.1:{data}"
identity-providers:
  admin-tokens:
    module: admin-tokens
    token: {{ env: BUSBAR_ADMIN_TOKEN }}
auth:
  chain: [keys]
  signing_key: {{ file: "{signing}" }}
  admin_auth:
    - admin-tokens
providers:
  mock:
    api_key: {{ env: MOCK_KEY }}
models:
  test-model:
    provider: mock
"#,
        signing = dir.join("signing.key").display()
    )
}

fn plane_sections(data: u16, admin: u16) -> String {
    PLANE_SECTIONS
        .concat()
        .replace("{data_port}", &data.to_string())
        .replace("{admin_port}", &admin.to_string())
}

fn boot(dir: &Path, data: u16, admin: u16, run: &str) -> Booted {
    let log = dir.join(format!("out-{run}.log"));
    let out = std::fs::File::create(&log).unwrap();
    let child = Command::new(common::boot::exe())
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
        .env("MOCK_KEY", "x")
        .env("BUSBAR_ADMIN_TOKEN", ADMIN_TOKEN)
        .stdout(out.try_clone().unwrap())
        .stderr(out)
        .spawn()
        .expect("spawn busbar");
    let mut booted = Booted {
        child,
        data: format!("127.0.0.1:{data}"),
        admin: format!("127.0.0.1:{admin}"),
        log,
    };
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if common::boot::healthz_answers(data) {
            break;
        }
        let text = read_to_string(&booted.log);
        if let Some(status) = booted.child.try_wait().expect("try_wait") {
            panic!("busbar exited before listening ({status:?}):\n{text}");
        }
        assert!(Instant::now() < deadline, "busbar did not listen:\n{text}");
        std::thread::sleep(Duration::from_millis(50));
    }
    booted
}

fn request(
    addr: &str,
    method: &str,
    path: &str,
    body: Option<&str>,
    token: Option<&str>,
) -> (u16, String) {
    let (status, body, _) = request_with_challenge(addr, method, path, body, token);
    (status, body)
}

fn request_with_challenge(
    addr: &str,
    method: &str,
    path: &str,
    body: Option<&str>,
    token: Option<&str>,
) -> (u16, String, Option<String>) {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("client");
        let method = reqwest::Method::from_bytes(method.as_bytes()).expect("method");
        let mut req = client.request(method, format!("http://{addr}{path}"));
        if let Some(t) = token {
            req = req.header(reqwest::header::AUTHORIZATION, format!("Bearer {t}"));
        }
        if let Some(b) = body {
            req = req
                .header("content-type", "application/json")
                .body(b.to_string());
        }
        let resp = req.send().await.expect("request");
        let challenge = resp
            .headers()
            .get(reqwest::header::WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        (
            resp.status().as_u16(),
            resp.text().await.unwrap_or_default(),
            challenge,
        )
    })
}

fn admin(b: &Booted, method: &str, path: &str, body: Option<&str>) -> (u16, String) {
    request(
        &b.admin,
        method,
        &format!("/api/v1/admin{path}"),
        body,
        Some(ADMIN_TOKEN),
    )
}

fn kept_files(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out: Vec<(String, Vec<u8>)> = std::fs::read_dir(dir)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.path().is_file())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n != "config.yaml" && n != "providers.yaml" && !n.starts_with("out-"))
        .map(|n| {
            let bytes = std::fs::read(dir.join(&n)).unwrap();
            (n, bytes)
        })
        .collect();
    out.sort();
    out
}

fn plane_challenge(b: &Booted, plane: &Plane) -> String {
    format!(
        "Bearer resource_metadata=\"http://{}/.well-known/oauth-protected-resource{}\"",
        b.data, plane.door
    )
}

fn is_plane_door(b: &Booted, plane: &Plane, response: &(u16, String, Option<String>)) -> bool {
    let expected = plane_challenge(b, plane);
    response.0 == 401
        && response.2.as_deref() == Some(expected.as_str())
        && serde_json::from_str::<serde_json::Value>(&response.1)
            .is_ok_and(|body| body == serde_json::json!({"error": "unauthorized"}))
}

#[test]
fn a_first_section_of_an_unloaded_plane_is_refused_whole_and_served_after_a_restart() {
    let dir = std::env::temp_dir().join(format!(
        "busbar-law7-unloaded-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos()),
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let plane = plane();
    let refusal = refusal(&plane);
    let (data, admin_port) = (common::boot::free_port(), common::boot::free_port());
    std::fs::write(dir.join("providers.yaml"), MOCK_PROVIDER).unwrap();
    let key = Command::new(common::boot::exe())
        .arg("--generate-signing-key")
        .output()
        .expect("generate a signing key");
    assert!(key.status.success(), "--generate-signing-key");
    std::fs::write(dir.join("signing.key"), &key.stdout).unwrap();
    let base = base_config(&dir, data, admin_port);
    std::fs::write(dir.join("config.yaml"), &base).unwrap();

    let b = boot(&dir, data, admin_port, "first");
    let unmounted = admin(&b, "GET", "/no-such-path", None);
    assert_eq!(
        unmounted.0, 404,
        "the unmounted-path control: {unmounted:?}"
    );
    assert_eq!(admin(&b, "GET", plane.admin, None), unmounted);
    let before = admin(&b, "GET", "/config", None);
    assert_eq!(before.0, 200, "{before:?}");
    let kept_before = kept_files(&dir);

    let with_plane = format!("{base}{}", plane_sections(data, admin_port));
    std::fs::write(dir.join("config.yaml"), &with_plane).unwrap();
    let (status, body) = admin(&b, "POST", "/config/reload", None);
    assert_eq!(status, 400, "the reload is refused: {body}");
    assert!(
        body.contains(&format!("config.yaml: {refusal}")),
        "the reload names the section and the plane in the pinned sentence: {body}"
    );

    let doc: serde_yaml::Value = serde_yaml::from_str(&with_plane).unwrap();
    let providers: serde_yaml::Value = serde_yaml::from_str(MOCK_PROVIDER).unwrap();
    let apply = serde_json::json!({
        "config": serde_json::to_value(&doc).unwrap(),
        "providers": serde_json::to_value(&providers).unwrap(),
    });
    let (status, body) = admin(&b, "POST", "/config/apply", Some(&apply.to_string()));
    assert_eq!(status, 400, "the apply is refused: {body}");
    assert!(
        body.contains(&refusal) && !body.contains("config.yaml: "),
        "the apply names the section and the plane in the pinned sentence: {body}"
    );

    assert_eq!(
        admin(&b, "GET", "/config", None),
        before,
        "the running generation's effective config and version are unchanged"
    );
    assert_eq!(
        admin(&b, "GET", plane.admin, None),
        unmounted,
        "the plane serves nothing after a refused change"
    );
    let door = request_with_challenge(&b.data, "POST", plane.door, None, None);
    assert!(
        !is_plane_door(&b, &plane, &door)
            && door.2.as_deref() != Some(plane_challenge(&b, &plane).as_str()),
        "the plane's door is not mounted after a refused change: {door:?}"
    );
    assert_eq!(
        kept_files(&dir),
        kept_before,
        "a refused change writes nothing busbar keeps"
    );
    drop(b);

    let b = boot(&dir, data, admin_port, "restart");
    assert_eq!(
        admin(&b, "GET", plane.admin, None).0,
        200,
        "after a restart the plane serves its section"
    );
    let door = request_with_challenge(&b.data, "POST", plane.door, None, None);
    assert!(
        is_plane_door(&b, &plane, &door),
        "after a restart the plane's door answers as that plane's door: {door:?}"
    );
    drop(b);
    let _ = std::fs::remove_dir_all(&dir);
}
