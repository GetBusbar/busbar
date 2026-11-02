use http_body::{Body, Frame};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
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

struct OpenBody {
    pieces: tokio::sync::mpsc::UnboundedReceiver<Bytes>,
    polled: Arc<AtomicUsize>,
    moved: Arc<tokio::sync::Notify>,
    ended: bool,
}

impl Body for OpenBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        match self.pieces.poll_recv(cx) {
            Poll::Ready(Some(bytes)) => {
                self.polled.fetch_add(bytes.len(), Ordering::SeqCst);
                self.moved.notify_one();
                Poll::Ready(Some(Ok(Frame::data(bytes))))
            }
            Poll::Ready(None) => {
                self.ended = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.ended
    }
}

fn open_body() -> (OpenBody, tokio::sync::mpsc::UnboundedSender<Bytes>) {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    (
        OpenBody {
            pieces: rx,
            polled: Arc::default(),
            moved: Arc::default(),
            ended: false,
        },
        tx,
    )
}

type Client = hyper::client::conn::http2::SendRequest<OpenBody>;

async fn client(
    router: axum::Router,
) -> (
    Client,
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
    let (sender, connection) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        hyper_util::rt::TokioIo::new(io),
    )
    .await
    .unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    (sender, server, driver)
}

fn get(body: OpenBody) -> Request<OpenBody> {
    Request::builder()
        .uri(format!("http://localhost{PATH}"))
        .version(Version::HTTP_2)
        .body(body)
        .unwrap()
}

fn send(
    mut client: Client,
    body: OpenBody,
) -> tokio::task::JoinHandle<Result<hyper::Response<hyper::body::Incoming>, hyper::Error>> {
    tokio::spawn(async move { client.send_request(get(body)).await })
}

async fn send_past_one_receive_window(
    tx: &tokio::sync::mpsc::UnboundedSender<Bytes>,
    polled: &AtomicUsize,
    moved: &tokio::sync::Notify,
) {
    // This exceeds the locked server's 1 MiB window and the client's 1 MiB send buffer.
    // Polling every frame therefore requires server receive credit, not just a queued request.
    const TOTAL: usize = 2 * 1024 * 1024 + 1;
    let mut remaining = TOTAL;
    while remaining != 0 {
        let n = remaining.min(16 * 1024);
        tx.send(Bytes::from(vec![b'x'; n])).unwrap();
        remaining -= n;
    }
    tokio::time::timeout(BOUND, async {
        while polled.load(Ordering::SeqCst) < TOTAL {
            moved.notified().await;
        }
    })
    .await
    .expect("the server is consuming the first open body");
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
    let (client, server, driver) = client(router).await;
    let (body, _open_body) = open_body();
    let response = send(client, body);
    let response = tokio::time::timeout(BOUND, response)
        .await
        .expect("admin auth answers before an unauthenticated body ends")
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    driver.abort();
    server.abort();
}

#[tokio::test]
async fn a_deferred_h2_get_holds_the_existing_data_permit_until_its_body_finishes() {
    let calls = Arc::new(AtomicUsize::new(0));
    let (client, server, driver) = client(data_router(&calls)).await;
    let (body, first_body) = open_body();
    let (polled, moved) = (body.polled.clone(), body.moved.clone());
    let first_response = send(client.clone(), body);
    send_past_one_receive_window(&first_body, &polled, &moved).await;
    assert_eq!(calls.load(Ordering::SeqCst), 0, "no early handler dispatch");
    let (body, _second_open_body) = open_body();
    let second_response = send(client.clone(), body);
    let second = tokio::time::timeout(BOUND, second_response)
        .await
        .expect("the over-cap request is shed before buffering its body")
        .unwrap()
        .unwrap();
    assert_eq!(second.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(second.headers()[axum::http::header::RETRY_AFTER], "1");
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    drop(first_body);
    assert_eq!(
        tokio::time::timeout(BOUND, first_response)
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let (body, end) = open_body();
    drop(end);
    let next_response = send(client.clone(), body);
    assert_eq!(
        tokio::time::timeout(BOUND, next_response)
            .await
            .unwrap()
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
    let (client, server, driver) = client(data_router(&calls)).await;
    let (body, _first_body) = open_body();
    let (polled, moved) = (body.polled.clone(), body.moved.clone());
    let first_response = send(client.clone(), body);
    send_past_one_receive_window(&_first_body, &polled, &moved).await;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    first_response.abort();
    let response = tokio::time::timeout(BOUND, async {
        loop {
            let (body, end) = open_body();
            drop(end);
            let response = send(client.clone(), body).await.unwrap().unwrap();
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
