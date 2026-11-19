// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The auth middleware hands the next layer one holder of the caller's credential:
//! `ConsumedCredentials.caller`, the one wiping buffer passthrough lends upstream. Whatever else it
//! adds to the request is the principal and its governance context, neither of which carries the
//! credential. Measured against a route the middleware lets through untouched (`RouteAuth::None`),
//! so the extensions axum and the outer layers add cancel out.

use super::*;
use busbar_contract::route::{RouteAuth, RouteMethod};
use std::sync::{Arc, Mutex};
use tower::ServiceExt as _;

const TOKEN: &str = "sk-caller-custody-0001";
const OPEN: &str = "/caller-custody/open";
const KEYED: &str = "/caller-custody/keyed";

/// What the next layer saw: the consumed credentials (removed), and how many extensions were
/// left once the principal and its governance context were removed too.
type Seen = Arc<Mutex<Vec<(String, Option<ConsumedCredentials>, usize)>>>;

fn app() -> Arc<crate::state::App> {
    let mut app = crate::inbound::native::tests::app();
    Arc::get_mut(&mut app).expect("a fresh app").auth = Arc::new(AuthMiddleware {
        keys_in_chain: false,
        chain: Vec::new(),
        readers: Vec::new(),
        reader_by_carrier: Default::default(),
        carriers: vec![AUTHORIZATION],
        issued: None,
    });
    app
}

async fn handed_on(seen: Seen, mut req: Request<Body>) -> StatusCode {
    let consumed = req.extensions_mut().remove::<ConsumedCredentials>();
    req.extensions_mut().remove::<AuthPrincipal>();
    req.extensions_mut().remove::<crate::governance::GovCtx>();
    seen.lock().unwrap().push((
        req.uri().path().to_owned(),
        consumed,
        req.extensions().len(),
    ));
    StatusCode::NO_CONTENT
}

#[tokio::test]
async fn the_request_handed_on_holds_the_caller_credential_only_in_consumed_credentials() {
    let handle = Arc::new(crate::state::AppHandle::new(app()));
    let seen: Seen = Arc::default();
    let (open, keyed) = (Arc::clone(&seen), Arc::clone(&seen));
    let (router, routes) = crate::core_routes::CoreRouter::new()
        .route(
            OPEN,
            RouteMethod::Post,
            RouteAuth::None,
            move |req: Request<Body>| handed_on(Arc::clone(&open), req),
        )
        .route(
            KEYED,
            RouteMethod::Post,
            RouteAuth::Key,
            move |req: Request<Body>| handed_on(Arc::clone(&keyed), req),
        )
        .into_parts();
    let router = crate::router::apply_common_layers(router, routes, &handle, 1024, false);
    for path in [OPEN, KEYED] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT, "{path} reached");
    }

    let seen = std::mem::take(&mut *seen.lock().unwrap());
    let [(open_path, open_consumed, untouched), (keyed_path, keyed_consumed, left)] =
        <[_; 2]>::try_from(seen).expect("both requests reached the next layer");
    assert_eq!((open_path.as_str(), keyed_path.as_str()), (OPEN, KEYED));
    assert!(
        open_consumed.is_none(),
        "a RouteAuth::None route is not judged"
    );
    let caller = keyed_consumed
        .and_then(|consumed| consumed.caller)
        .expect("the judged request carries the caller credential on");
    assert_eq!(
        caller.lend().expose(&crate::seal::lend()).as_slice(),
        TOKEN.as_bytes(),
        "ConsumedCredentials.caller holds the presented credential (passthrough's source)"
    );
    assert_eq!(
        left, untouched,
        "the middleware added an extension besides ConsumedCredentials, AuthPrincipal and \
         GovCtx: a second holder of the caller's credential"
    );
}

/// A line session's credential (read from its environment variable) is moved into the admission
/// in a holder that wipes on drop: the admission task is its last holder.
#[test]
fn a_line_sessions_credential_enters_admission_in_a_wiping_holder() {
    fn wipes<T: zeroize::ZeroizeOnDrop, F>(_: fn(Arc<crate::state::App>, Option<T>, String) -> F) {}
    wipes(crate::auth::admit::admit_session);
}
