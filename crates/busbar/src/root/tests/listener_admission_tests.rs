use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::http::{Request, StatusCode, Version};
use busbar_contract::abi::mechanism::endpoint::{EndpointRequest, EndpointResponse};
use busbar_contract::abi::mechanism::route::{Route, RouteAuth, RouteMethod};
use busbar_kernel::plugin_routes::{build_route_table, PluginHttpDispatch, RouteDecl, RouteKind};
use bytes::Bytes;

const PATH: &str = "/exports/admission-probe/read";
const BOUND: Duration = Duration::from_secs(3);

struct Counter(Arc<AtomicUsize>);

impl PluginHttpDispatch for Counter {
    fn handle_http(&self, _: &EndpointRequest) -> EndpointResponse {
        self.0.fetch_add(1, Ordering::SeqCst);
        EndpointResponse {
            status: 200,
            headers: Vec::new(),
            body: b"done".to_vec(),
        }
    }
}

fn app(auth: RouteAuth, calls: &Arc<AtomicUsize>) -> Arc<busbar_kernel::state::App> {
    let mut app = busbar_kernel_testkit::test_support::TestApp::new().build();
    Arc::get_mut(&mut app).unwrap().plugin_routes = Arc::new(
        build_route_table(vec![RouteDecl {
            owner: "admission-probe".into(),
            source_instance: "admission-probe".into(),
            dispatch_available: true,
            kind: RouteKind::Export,
            route: Route {
                path: PATH.into(),
                method: RouteMethod::Get,
                auth,
            },
            scrape: false,
            persistent: false,
            dispatch: Arc::new(Counter(calls.clone())),
        }])
        .unwrap(),
    );
    app
}

fn data_router(calls: &Arc<AtomicUsize>) -> axum::Router {
    let app = app(RouteAuth::None, calls);
    let prepared = Arc::new(
        busbar_kernel::router::PreparedListener::new(
            &app,
            &app.plugin_routes,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            None,
            true,
        )
        .unwrap()
        .with_dispatch_layer(super::deferred_dispatch_layer),
    );
    busbar_kernel::router::serve_listener_generations(
        Arc::new(busbar_kernel::state::AppHandle::new(app)),
        move |_| Some(prepared.clone()),
        32 * 1024 * 1024,
        1,
        false,
    )
}

async fn client(
    router: axum::Router,
) -> (
    h2::client::SendRequest<Bytes>,
    tokio::task::JoinHandle<()>,
    tokio::task::JoinHandle<()>,
) {
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let server = tokio::spawn(async move {
        super::serve_plain(socket, router, std::future::pending(), None)
            .await
            .unwrap();
    });
    let io = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (sender, connection) = h2::client::handshake(io).await.unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    (sender, server, driver)
}

fn get() -> Request<()> {
    Request::builder()
        .uri(format!("http://localhost{PATH}"))
        .version(Version::HTTP_2)
        .body(())
        .unwrap()
}

async fn send_past_one_receive_window(body: &mut h2::SendStream<Bytes>) {
    // One additional byte needs receive credit from the server polling the first body's data.
    let mut bytes = Bytes::from(vec![b'x'; 1024 * 1024 + 1]);
    while !bytes.is_empty() {
        body.reserve_capacity(bytes.len());
        let available =
            tokio::time::timeout(BOUND, std::future::poll_fn(|cx| body.poll_capacity(cx)))
                .await
                .expect("the first body is being consumed")
                .expect("the stream remains open")
                .unwrap();
        let n = available.min(bytes.len());
        body.send_data(bytes.split_to(n), false).unwrap();
    }
}

#[tokio::test]
async fn an_unauthorized_admin_h2_get_is_refused_without_reading_its_open_body() {
    let calls = Arc::new(AtomicUsize::new(0));
    let handle = Arc::new(busbar_kernel::state::AppHandle::new(app(
        RouteAuth::Admin,
        &calls,
    )));
    let router = busbar_kernel::router::build_admin_router_on_with_dispatch_layer(
        &handle,
        32 * 1024 * 1024,
        false,
        super::deferred_dispatch_layer,
    );
    let (mut client, server, driver) = client(router).await;
    client = client.ready().await.unwrap();
    let (response, _open_body) = client.send_request(get(), false).unwrap();
    let response = tokio::time::timeout(BOUND, response)
        .await
        .expect("admin auth answers before an unauthenticated body ends")
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    driver.abort();
    server.abort();
}

#[tokio::test]
async fn a_deferred_h2_get_holds_the_existing_data_permit_until_its_body_finishes() {
    let calls = Arc::new(AtomicUsize::new(0));
    let (mut client, server, driver) = client(data_router(&calls)).await;
    client = client.ready().await.unwrap();
    let (first_response, mut first_body) = client.send_request(get(), false).unwrap();
    send_past_one_receive_window(&mut first_body).await;
    assert_eq!(calls.load(Ordering::SeqCst), 0, "no early handler dispatch");
    client = client.ready().await.unwrap();
    let (second_response, _second_open_body) = client.send_request(get(), false).unwrap();
    let second = tokio::time::timeout(BOUND, second_response)
        .await
        .expect("the over-cap request is shed before buffering its body")
        .unwrap();
    assert_eq!(second.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(second.headers()[axum::http::header::RETRY_AFTER], "1");
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    first_body.send_data(Bytes::new(), true).unwrap();
    assert_eq!(
        tokio::time::timeout(BOUND, first_response)
            .await
            .unwrap()
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    client = client.ready().await.unwrap();
    let (next_response, _) = client.send_request(get(), true).unwrap();
    assert_eq!(
        tokio::time::timeout(BOUND, next_response)
            .await
            .unwrap()
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "the completed body released its permit"
    );
    driver.abort();
    server.abort();
}

#[tokio::test]
async fn cancelling_a_deferred_h2_body_releases_the_data_permit_without_dispatch() {
    let calls = Arc::new(AtomicUsize::new(0));
    let (mut client, server, driver) = client(data_router(&calls)).await;
    client = client.ready().await.unwrap();
    let (_first_response, mut first_body) = client.send_request(get(), false).unwrap();
    send_past_one_receive_window(&mut first_body).await;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    first_body.send_reset(h2::Reason::CANCEL);
    let response = tokio::time::timeout(BOUND, async {
        loop {
            client = client.ready().await.unwrap();
            let (response, _) = client.send_request(get(), true).unwrap();
            let response = response.await.unwrap();
            if response.status() != StatusCode::SERVICE_UNAVAILABLE {
                break response;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("cancelled body releases the permit");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "only the replacement request dispatched"
    );
    driver.abort();
    server.abort();
}
