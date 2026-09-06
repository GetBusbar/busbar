
#[cfg(all(test, feature = "root-admin"))]
mod scratch_probe {
    use super::*;
    #[tokio::test]
    async fn probe() {
        use tower::ServiceExt;
        let inner = axum::Router::new().fallback(axum::routing::any(|| async {
            (
                axum::http::StatusCode::NOT_FOUND,
                "{\"error\":\"not_found\"}",
            )
        }));
        let wrapped = mount(
            inner,
            busbar_kernel::teller::Kernel::new(),
            1024,
            crate::root::kernel::ProductionUnits::admin_only,
        );
        for (m, p) in [
            ("POST", "/api/v1/admin/chain-break"),
            ("POST", "/api/v1/admin/store-restore"),
            ("POST", "/api/v1/admin/reseal-epoch-floor"),
        ] {
            let r = wrapped
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .method(m)
                        .uri(p)
                        .header("authorization", "Bearer x")
                        .body(axum::body::Body::from("{}"))
                        .unwrap(),
                )
                .await
                .unwrap();
            let st = r.status();
            let b = axum::body::to_bytes(r.into_body(), usize::MAX)
                .await
                .unwrap();
            println!("PROBE {m} {p} -> {st} {}", String::from_utf8_lossy(&b));
        }
        panic!("scratch");
    }
}
