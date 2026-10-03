// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DATA ROUTE (SERVE-WIRE P2, TODO U6-U7): a request a composed door plane claims reaches that
//! plane's driver through the kernel's data door (the one the data router's fallback asks first),
//! and the plane answers it through the driver. The plane is the jev plane's own door, linked and
//! bound through the loader's one load, as its door row binds it.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::body::Bytes;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use busbar_contract::caps::ReasonCode;
use busbar_contract::records::PlaneRequestCtx;
use busbar_kernel::plane_driver::refusal_status;
use busbar_kernel::plane_driver::serve::{claimed, DataRequest};
use busbar_plane_decisions::plane_door::door as jev_door;

use super::planes_tests::{composed_services, money};
use super::{compose_planes, mount};
use crate::root::loader::dispatch::kinds::plane::Plane;
use crate::root::loader::dispatch::{
    load_linked, Bind, DispatchConfig, Dispatcher, LinkedRow, NoSink,
};

/// The jev plane's one claim, with one model configured.
const CLAIMED: &str = "/v1/systemone";

fn request(path: &str) -> DataRequest {
    DataRequest {
        method: Method::POST,
        uri: path.parse::<Uri>().expect("a target"),
        headers: HeaderMap::new(),
        body: Bytes::from_static(b"{}"),
        gov: PlaneRequestCtx { key: None },
        consumed: None,
        app: busbar_kernel::test_support::TestApp::new().build(),
    }
}

#[tokio::test]
async fn a_claimed_request_is_answered_by_the_plane_door_through_its_driver() {
    // RED ARM, before the mount: the kernel's data door claims nothing.
    let back = claimed(request(CLAIMED))
        .err()
        .expect("no data door is mounted yet");
    assert_eq!(back.uri.path(), CLAIMED);

    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let instance = "serve-door-jev";
    let row = LinkedRow::of(jev_door).expect("the door states its Statement");
    let plane = load_linked::<Plane>(
        &row,
        Bind {
            instance: Arc::from(instance),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: None,
        },
    )
    .expect("the linked door binds");
    let section = plane.served().section;
    let doors = vec![(instance.to_string(), plane)];
    let mut sections = BTreeMap::new();
    sections.insert(
        section,
        serde_yaml::from_str("models: {jev: {provider: typesafe}}").expect("a section"),
    );
    let late = composed_services();
    let served = compose_planes(&doors, &dispatcher, &late, &sections, &money)
        .expect("the door plane composes");
    mount(served).expect("the data routes mount");

    // A path no plane claims comes back whole, for the fallback's own dispatch.
    let back = claimed(request("/v1/unclaimed")).err().expect("unclaimed");
    assert_eq!(back.uri.path(), "/v1/unclaimed");
    assert_eq!(&back.body[..], b"{}");

    // The claimed request is the plane's unit: `arrive` decodes it, the kernel's steps refuse it
    // (no destination is sealed for it yet), and the plane renders the refusal in its own shape.
    let answer = claimed(request(CLAIMED)).ok().expect("the plane claims it");
    let response = answer.await;
    assert_eq!(
        u32::from(response.status().as_u16()),
        refusal_status(ReasonCode::NoDestination)
    );
    assert_ne!(response.status(), StatusCode::NOT_FOUND);
    let kind = response.headers()["content-type"].to_str().expect("a type");
    assert!(kind.starts_with("application/json"), "{kind}");
    let body = axum::body::to_bytes(response.into_body(), 1 << 16)
        .await
        .expect("the body");
    let body: serde_json::Value = serde_json::from_slice(&body).expect("the plane's JSON");
    assert_eq!(
        body["error"]["code"], "unsupported_operation",
        "the plane chose the code word for the status: {body}"
    );
    assert_eq!(
        body["error"]["message"],
        ReasonCode::NoDestination.as_str(),
        "the kernel wrote the text: {body}"
    );
    assert!(
        mount(super::Served::default()).is_ok(),
        "a composition that claims nothing mounts nothing"
    );
}
