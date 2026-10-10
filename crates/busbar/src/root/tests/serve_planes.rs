// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR PLANES' COMPOSITION (TODO U6-U7, ARCHITECT Q-SW4 2026-10-02), over the test plane
//! dropped in (its `plane_driver_test_plane` example `cdylib`, admitted against the Statement its
//! own library states; the binary forbids unsafe code, so the fixture's source is never compiled
//! into it): a bound plane whose section the deployment writes is opened, driven and its admin
//! routes published; one whose section is absent stays unopened (LAW 7).

use std::collections::BTreeMap;
use std::sync::Arc;

use busbar_kernel::governance::{GovState, MemoryStore};
use busbar_kernel::host_services::KernelServices;
use busbar_kernel::plane_driver::{EndPost, PlaneMoney};

use crate::root::plane_node::NodeEndPost;

use super::{compose_planes, LateServices};
use crate::root::loader::dispatch::{
    load_dropped, rendering_of_library, Bind, DispatchConfig, Dispatcher, NoSink,
};

/// The money steps of a composition: an ungoverned book (a unit that runs here admits nothing that
/// bills), posting abandoned ends onto the process's one node.
pub(crate) fn money() -> Arc<PlaneMoney> {
    let gov = Arc::new(GovState::new(Arc::new(MemoryStore::new()), None).expect("governance"));
    Arc::new(PlaneMoney::new(gov, post() as Arc<dyn EndPost>))
}

/// The process's one posting site, over its one node.
pub(super) fn post() -> Arc<NodeEndPost> {
    Arc::new(NodeEndPost::new(crate::root::plane_node::node()))
}

/// THE ADMIN TABLE IS THE PROCESS'S ONE: every test that publishes a plane's admin routes holds
/// this while its plane is published, and withdraws it ([`Published`]) before letting go.
pub(crate) static PUBLISHING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A published instance, withdrawn from the admin table when the test lets go of it.
pub(crate) struct Published(pub(crate) &'static str);

impl Drop for Published {
    fn drop(&mut self) {
        busbar_kernel::plane_driver::serve::withdraw(self.0);
    }
}

/// The test plane's example `cdylib` beside this test binary; `None` where a scoped run did not
/// build it. Under CI a missing artifact is a failure.
fn dropped_path() -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let path = exe.parent()?.parent()?.join("examples").join(format!(
        "{}plane_driver_test_plane{}",
        std::env::consts::DLL_PREFIX,
        std::env::consts::DLL_SUFFIX
    ));
    let found = path.exists().then_some(path);
    assert!(
        found.is_some() || std::env::var_os("CI").is_none(),
        "the plane_driver_test_plane example cdylib is not built under CI"
    );
    found
}

/// The test plane, dropped in and bound on `dispatcher` as `instance`; `None` where its `cdylib`
/// is not built.
pub(super) fn bound(
    instance: &str,
    dispatcher: &Arc<Dispatcher>,
) -> Option<crate::root::boot::DoorPlane> {
    let path = dropped_path()?;
    let stated = rendering_of_library(&path)
        .expect("the test plane's library reads")
        .expect("the test plane states its Statement");
    let plane = load_dropped(
        &path,
        &stated,
        Bind {
            instance: Arc::from(instance),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            // These rows never dial (the plane's far end is not reached): its need is not
            // declared, bound as a probe.
            conns: crate::root::loader::dispatch::ConnTable::Probe,
        },
    )
    .expect("the dropped-in door binds");
    Some(plane)
}

pub(crate) fn composed_services() -> Arc<LateServices> {
    let late = LateServices::new();
    let kernel = Arc::new(KernelServices::new());
    late.install_kernel(Arc::clone(&kernel), kernel)
        .expect("installed once");
    late
}

/// An admin request on the admin router's plane table: its status, or `None` (the router's 404).
fn admin(path: &str) -> Option<u16> {
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("{}{path}", busbar_kernel::api::ADMIN_PREFIX))
        .body(axum::body::Body::from("go"))
        .expect("a request");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    rt.block_on(async {
        busbar_kernel::plane_driver::serve::answer(req)
            .await
            .map(|r| r.status().as_u16())
    })
}

#[test]
fn a_configured_door_plane_is_opened_driven_and_its_admin_routes_published() {
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let instance = "serve-compose-configured";
    let _one = PUBLISHING.blocking_lock();
    let _published = Published(instance);
    let Some(plane) = bound(instance, &dispatcher) else {
        eprintln!("skip: the test plane's cdylib is not built in this scoped run");
        return;
    };
    let doors = vec![(instance.to_string(), plane)];
    let mut sections = BTreeMap::new();
    sections.insert("test_plane", serde_yaml::Value::Mapping(Default::default()));
    let late = composed_services();
    let served = compose_planes(
        &doors,
        &dispatcher,
        &late,
        &sections,
        None,
        &money,
        None,
        None,
    )
    .expect("the door plane composes");
    assert_eq!(served.planes.len(), 1, "one plane composed");
    let p = &served.planes[0];
    assert_eq!(p.instance, instance);
    let claims: Vec<(&str, &str)> = p
        .snapshot
        .claims
        .iter()
        .map(|c| (c.verb.as_str(), c.target.as_str()))
        .collect();
    assert_eq!(
        claims,
        [("POST", "/call"), ("POST", "/open"), ("POST", "/framed")],
        "its open published its claims"
    );
    assert_eq!(
        admin("/items/composed/act"),
        Some(200),
        "its audited admin route is served by its `serve` op"
    );
    assert_eq!(
        admin("/items/composed/hook"),
        None,
        "a public route is never on the admin table"
    );
}

#[test]
fn a_door_plane_whose_section_is_absent_stays_unopened() {
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let instance = "serve-compose-unconfigured";
    let Some(plane) = bound(instance, &dispatcher) else {
        eprintln!("skip: the test plane's cdylib is not built in this scoped run");
        return;
    };
    let doors = vec![(instance.to_string(), plane)];
    let late = composed_services();
    let served = compose_planes(
        &doors,
        &dispatcher,
        &late,
        &BTreeMap::new(),
        None,
        &money,
        None,
        None,
    )
    .expect("nothing to compose is not a refusal");
    assert!(served.planes.is_empty(), "LAW 7: no section, no plane");
}

#[test]
fn no_door_plane_composes_nothing_and_needs_no_services() {
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let served = compose_planes(
        &[],
        &dispatcher,
        &LateServices::new(),
        &BTreeMap::new(),
        None,
        &money,
        None,
        None,
    )
    .expect("an empty composition");
    assert!(served.planes.is_empty());
}

/// A PLANE NEVER RECEIVES SECRET BYTES (THE DESIGN §6; SECURITY ruling 2026-10-07). `${VAR}` is
/// spliced into the config text before it is parsed, so its plaintext used to reach a door plane's
/// `open` settings, its owned sections and its `refresh` settings. The test plane records the bytes
/// it is handed at the ABI. At every CREDENTIAL position (`token`, `api_key`, a program's `env`) the
/// blobs carry the reference: `{ env: VAR }` for a whole value, a template reference for a part.
/// An operator-written reference crosses as written, unresolved. Every other position (`url`,
/// `args`, `command`) keeps the load-time interpolation, as 1.5.5 handed it on.
#[test]
fn an_interpolated_credential_reaches_a_door_plane_as_its_reference_never_its_bytes() {
    const PLAIN: &str = "sk-plane-bound-PLAINTEXT-0001";
    const RESOLVED: &str = "sk-plane-bound-RESOLVED-0002";
    let pid = std::process::id();
    let plain_var = format!("BUSBAR_PLANE_BOUND_SECRET_{pid}");
    let ref_var = format!("BUSBAR_PLANE_BOUND_REF_{pid}");
    let host_var = format!("BUSBAR_PLANE_BOUND_HOST_{pid}");
    std::env::set_var(&plain_var, PLAIN);
    std::env::set_var(&ref_var, RESOLVED);
    std::env::set_var(&host_var, "upstream.invalid");
    let dir = std::env::temp_dir().join(format!("busbar-plane-bound-{pid}"));
    let template = format!(
        r#"
test_plane:
  capture_to: "{dir}"
  reg1:
    url: "http://${{{host_var}}}/v1"
    api_key: {{env: {ref_var}}}
    token: "${{{plain_var}}}"
    args: ["--flag", "${{{host_var}}}"]
    env:
      WHOLE: "${{{plain_var}}}"
      PART: "Bearer ${{{plain_var}}}"
test_plane_owned:
  reg: {{api_key: "${{{plain_var}}}", ref: {{env: {ref_var}}}, url: "http://${{{host_var}}}/o"}}
"#,
        dir = dir.display()
    );
    let text = busbar_kernel::config::interpolate_env_with(
        &template,
        busbar_kernel::config::EnvSubst::Strict,
        &mut Vec::new(),
    )
    .expect("interpolates");
    let doc: serde_yaml::Mapping = serde_yaml::from_str(&text).expect("parses");
    let mut sections = BTreeMap::new();
    for key in ["test_plane", "test_plane_owned"] {
        sections.insert(key, doc.get(key).cloned().expect("written"));
    }
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let instance = "serve-compose-plane-bound";
    let _one = PUBLISHING.blocking_lock();
    let _published = Published(instance);
    let Some(plane) = bound(instance, &dispatcher) else {
        eprintln!("skip: the test plane's cdylib is not built in this scoped run");
        return;
    };
    let doors = vec![(instance.to_string(), plane)];
    let late = composed_services();
    let served = compose_planes(
        &doors,
        &dispatcher,
        &late,
        &sections,
        None,
        &money,
        None,
        None,
    )
    .expect("the door plane composes");
    let secrets = busbar_kernel::config::secret::SecretResolver::builtins_only();
    served.planes[0]
        .live
        .refreshed(&sections["test_plane"], 2, &secrets)
        .expect("the plane refreshes");

    let read = |name: &str| {
        String::from_utf8_lossy(&std::fs::read(dir.join(name)).unwrap_or_default()).into_owned()
    };
    let whole = serde_json::json!({ "env": plain_var });
    let part = serde_json::to_value(busbar_contract::secret_ref::SecretRef::template(format!(
        "Bearer ${{{plain_var}}}"
    )))
    .expect("a reference");
    let written_reference = serde_json::json!({ "env": ref_var });
    for name in ["open.settings", "open.owned", "refresh.settings"] {
        let text = read(name);
        assert!(!text.is_empty(), "the plane recorded its {name}");
        assert!(
            !text.contains(PLAIN),
            "{name} carries the secret's bytes: {text}"
        );
        assert!(
            !text.contains(RESOLVED),
            "{name} carries a resolved reference: {text}"
        );
    }
    for name in ["open.settings", "refresh.settings"] {
        let text = read(name);
        let settings: serde_json::Value = serde_json::from_str(&text).expect("JSON");
        assert_eq!(settings["reg1"]["token"], whole, "{name}: {text}");
        assert_eq!(settings["reg1"]["env"]["WHOLE"], whole, "{name}: {text}");
        assert_eq!(settings["reg1"]["env"]["PART"], part, "{name}: {text}");
        assert_eq!(
            settings["reg1"]["api_key"], written_reference,
            "{name}: {text}"
        );
        // Not a credential field: the load-time interpolation, as 1.5.5 handed it on.
        assert_eq!(
            settings["reg1"]["url"], "http://upstream.invalid/v1",
            "{name}: {text}"
        );
        assert_eq!(
            settings["reg1"]["args"],
            serde_json::json!(["--flag", "upstream.invalid"]),
            "{name}: {text}"
        );
    }
    let text = read("open.owned");
    let owned: serde_json::Value = serde_json::from_str(&text).expect("JSON");
    assert_eq!(owned["test_plane_owned"]["reg"]["api_key"], whole, "{text}");
    assert_eq!(
        owned["test_plane_owned"]["reg"]["ref"], written_reference,
        "{text}"
    );
    assert_eq!(
        owned["test_plane_owned"]["reg"]["url"], "http://upstream.invalid/o",
        "{text}"
    );
}
