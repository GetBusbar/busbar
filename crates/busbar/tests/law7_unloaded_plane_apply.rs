// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A FIRST SECTION OF AN UNLOADED PLANE, END TO END (u67 BLOCK 2 item 2, ruled (iv)).
//! BUSBAR-1.6.0.md Law 7 (l.547): "A plane loads iff its verb is present", read at start; §6
//! item 8 (l.980-982): a reload that fails a check "is refused, leaving the running generation
//! serving".
//!
//! The shipped binary boots on a 1.5.5-shaped config, so a linked plane that config does not use is
//! discovered and not loaded. The operator then writes that plane's sections into the config file
//! and reloads, and posts the same document to `config/apply`: both are refused whole with one
//! pinned sentence naming the section and the plane, and nothing changes. The live generation's
//! effective config and version are the same, the plane serves nothing, and no file busbar keeps is
//! written. The restart that follows loads the plane, and its section is served.
//!
//! Every word about the plane (its name, its sections, its admin path and its door) is DATA, and
//! each is read where the tree already states it rather than spelled again: the declaring section
//! and the admin path are `tests/fixtures/unloaded_plane.txt`; the plane is the linked door row
//! whose declaring section that is (the manifest's `linked-section` and `linked` rows), named by its
//! package; its own section and its door path are the tool plane's fixtures
//! (`tool_plane_section.yaml`, `tool_plane_wire.txt`), and the declaring section's body is
//! `unloaded_plane_sections.yaml`. This source names no plane, and no fixture repeats a plane word
//! another already holds.
//!
//! RED before the fix: no rule judged the document, so the parse refused the section as an unknown
//! field, without saying the plane was not loaded or that a restart takes it.
#![cfg(unix)]
#![cfg(linked_every_plane)]

mod common;

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

const ADMIN_TOKEN: &str = "law7-unloaded-plane-admin";

/// The provider catalog row is test data (`fixtures/mock_provider.yaml`), not a literal here.
const MOCK_PROVIDER: &str = include_str!("fixtures/mock_provider.yaml");

/// The unloaded plane's own section (the tool plane's, as its integrity suite configures it) and
/// its declaring section's body, as DATA, with `{data_port}` and `{admin_port}` to fill.
const PLANE_SECTIONS: [&str; 2] = [
    include_str!("fixtures/tool_plane_section.yaml"),
    include_str!("fixtures/unloaded_plane_sections.yaml"),
];

/// The kind prefix every plane package carries; the rest of the package name is the plane's name.
const PLANE_PREFIX: &str = "busbar-plane-";

/// The unloaded plane, as DATA (`tests/fixtures/unloaded_plane.txt` and the manifest).
struct Plane {
    /// The plane's name, as the refusal names it.
    name: String,
    /// The section of it the refusal names.
    section: &'static str,
    /// An admin path the plane serves once loaded.
    admin: &'static str,
    /// The data-listener path of the plane's door.
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
    // THE PLANE IS THE LINKED DOOR ROW THAT DECLARES THIS SECTION, named by its package.
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

/// The tool plane's wire, as DATA (`tests/fixtures/tool_plane_wire.txt`): one `key = value` per
/// line.
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

/// The pinned refusal, as the running process answers a document that first writes the plane's
/// section.
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

/// The 1.5.5 shape: one provider, one model, keys on the data plane, an admin token.
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

/// The unloaded plane's sections, filled with this run's ports.
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
        let text = read_to_string(&booted.log);
        if common::boot::log_shows_data_and_admin_listening(&text) {
            break;
        }
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
        (
            resp.status().as_u16(),
            resp.text().await.unwrap_or_default(),
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

/// Every file in `dir` busbar may keep (the config and providers files the operator owns and the
/// logs excluded), with its bytes: what a refused change must leave as it was.
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

/// The shape a mounted plane door answers an unauthenticated caller with (RFC 6750), as opposed to
/// the catch-all plane's protocol-native envelope.
fn is_plane_door(body: &str) -> bool {
    body.contains("error_description")
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

    // ── BOOT on the 1.5.5 shape: the plane is discovered, not loaded, and serves nothing.
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

    // ── RELOAD a config file that first writes the plane's sections: refused whole, pinned.
    let with_plane = format!("{base}{}", plane_sections(data, admin_port));
    std::fs::write(dir.join("config.yaml"), &with_plane).unwrap();
    let (status, body) = admin(&b, "POST", "/config/reload", None);
    assert_eq!(status, 400, "the reload is refused: {body}");
    assert!(
        body.contains(&format!("config.yaml: {refusal}")),
        "the reload names the section and the plane in the pinned sentence: {body}"
    );

    // ── APPLY the same document: refused whole with the same sentence.
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

    // ── NOTHING CHANGED: the live generation, the plane's surface and every file busbar keeps.
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
    let (_, door) = request(&b.data, "POST", plane.door, None, None);
    assert!(
        !is_plane_door(&door),
        "the plane's door is not mounted after a refused change: {door}"
    );
    assert_eq!(
        kept_files(&dir),
        kept_before,
        "a refused change writes nothing busbar keeps"
    );
    drop(b);

    // ── RESTART on the config file: the plane is loaded and its section is served.
    let b = boot(&dir, data, admin_port, "restart");
    assert_eq!(
        admin(&b, "GET", plane.admin, None).0,
        200,
        "after a restart the plane serves its section"
    );
    let (status, door) = request(&b.data, "POST", plane.door, None, None);
    assert!(
        status == 401 && is_plane_door(&door),
        "after a restart the plane's door answers as that plane's door: {status} {door}"
    );
    drop(b);
    let _ = std::fs::remove_dir_all(&dir);
}
