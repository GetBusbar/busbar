// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::{Arc, Mutex};

use busbar_contract::secure::SecureVec;
use busbar_plugin_abi::host_side::caller::{BoxFut, Caller};
use busbar_plugin_abi::need::egress;
use busbar_plugin_abi::plane::tag as plane;
use busbar_plugin_abi::records::{tag, Reply, Writer};

use crate::plane_driver::port_fetch::{PlaneFetch, PlaneFetchReply, PlaneFetchRequest};
use crate::retry::PortError;

use super::ConnectorPushSink;

struct Fetch {
    status: u16,
    calls: Mutex<Vec<(u64, String, String, u32, Vec<u8>)>>,
}
impl PlaneFetch for Fetch {
    fn fetch<'a>(
        &'a self,
        who: &'a Caller<'_>,
        request: PlaneFetchRequest<'a>,
    ) -> BoxFut<'a, Result<PlaneFetchReply, PortError>> {
        Box::pin(async move {
            self.calls.lock().unwrap().push((
                who.instance,
                request.method.into(),
                request.url.into(),
                request.egress,
                request.body.to_vec(),
            ));
            assert_eq!(request.headers.into_iter().count(), 1);
            Ok(PlaneFetchReply {
                status: self.status,
                headers: Vec::new(),
                body: SecureVec::zeroed(0),
            })
        })
    }
}
fn request() -> Reply {
    let mut recs = Reply::new();
    recs.put_text(tag::H_METHOD, "POST").unwrap();
    recs.put_text(plane::PUSH_URL, "https://callback.example/event")
        .unwrap();
    recs.put_pair(tag::PAIR, "content-type", b"application/json")
        .unwrap();
    recs.put(plane::BODY, b"event").unwrap();
    recs
}

#[tokio::test]
async fn delivery_fetch_uses_live_caller_and_open_web() {
    let fetch = Arc::new(Fetch {
        status: 204,
        calls: Mutex::default(),
    });
    let sink = ConnectorPushSink::new(fetch.clone());
    let who = super::tests::caller("p", "configured", 77);
    sink.deliver(&who, request().as_bytes()).await.unwrap();
    assert_eq!(
        *fetch.calls.lock().unwrap(),
        vec![(
            77,
            "POST".into(),
            "https://callback.example/event".into(),
            egress::OPEN_WEB,
            b"event".to_vec()
        )]
    );
}

#[tokio::test]
async fn redirect_is_a_failed_delivery_and_is_not_followed() {
    let fetch = Arc::new(Fetch {
        status: 302,
        calls: Mutex::default(),
    });
    let sink = ConnectorPushSink::new(fetch.clone());
    let who = super::tests::caller("p", "configured", 77);
    assert!(sink.deliver(&who, request().as_bytes()).await.is_err());
    assert_eq!(fetch.calls.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn malformed_queue_records_never_reach_the_connector() {
    let fetch = Arc::new(Fetch {
        status: 204,
        calls: Mutex::default(),
    });
    let sink = ConnectorPushSink::new(fetch.clone());
    let who = super::tests::caller("p", "configured", 77);
    for bytes in [Vec::new(), b"broken".to_vec()] {
        assert!(sink.deliver(&who, &bytes).await.is_err());
    }
    let mut duplicate = request();
    duplicate
        .put_text(plane::PUSH_URL, "https://other.example/")
        .unwrap();
    assert!(sink.deliver(&who, duplicate.as_bytes()).await.is_err());
    assert!(fetch.calls.lock().unwrap().is_empty());
}
