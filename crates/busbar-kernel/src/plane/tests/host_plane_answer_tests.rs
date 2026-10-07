use super::PlaneAnswer;

#[tokio::test]
async fn unary_materialises_status_headers_and_body_byte_for_byte() {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("content-type", "application/json".parse().unwrap());
    headers.insert("x-busbar-plane", "neutral".parse().unwrap());
    let body = axum::body::Bytes::from_static(b"{\"ok\":true}");
    let answer = PlaneAnswer::Unary(
        axum::http::StatusCode::ACCEPTED,
        headers.clone(),
        body.clone(),
    );

    let resp = answer.into_response();
    assert_eq!(resp.status(), axum::http::StatusCode::ACCEPTED);
    assert_eq!(resp.headers(), &headers);
    let got = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body drains");
    assert_eq!(got, body);
}

#[tokio::test]
async fn live_is_handed_through_untouched() {
    let mut live = axum::response::Response::new(axum::body::Body::from("stream"));
    *live.status_mut() = axum::http::StatusCode::CREATED;
    let resp = PlaneAnswer::Live(live).into_response();
    assert_eq!(resp.status(), axum::http::StatusCode::CREATED);
}

#[test]
fn plane_in_flight_stores_and_takes_by_key() {
    use super::PlaneInFlight;
    let table = PlaneInFlight::new();
    table.open(7);
    // Before a store, the slot yields nothing.
    assert!(table.take(9).is_none());
    table.store(
        7,
        PlaneAnswer::Unary(
            axum::http::StatusCode::OK,
            axum::http::HeaderMap::new(),
            axum::body::Bytes::from_static(b"x"),
        ),
    );
    let taken = table.take(7);
    assert!(matches!(taken, Some(PlaneAnswer::Unary(..))));
    // Taken once, gone after.
    assert!(table.take(7).is_none());
}
