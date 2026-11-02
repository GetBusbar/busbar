use super::{connect_reply, AdminReply, AdminReqCtx, PlaneTrust, PlaneVerbError};
use crate::plane_driver::EngineHost;
use crate::test_support::TestApp;
use std::collections::BTreeMap;
use std::sync::Arc;

/// A view `serde_json` cannot render: JSON object keys are strings, so a map keyed by a pair is
/// a serialization error rather than a type error -- exactly the shape of mistake a plane's own
/// view struct can acquire without the compiler saying a word.
#[derive(serde::Serialize)]
struct UnrenderableView {
    per_endpoint: BTreeMap<(String, String), u64>,
}

struct NanPlane;

impl PlaneTrust for NanPlane {
    const PLANE: &'static str = "fixture";
    type Subject = ();
    type View = UnrenderableView;

    fn resolve(_host: &Arc<dyn EngineHost>, _name: &str) -> Result<(), PlaneVerbError> {
        Ok(())
    }

    async fn look(
        _subject: (),
        _host: Arc<dyn EngineHost>,
        _name: String,
    ) -> Result<UnrenderableView, PlaneVerbError> {
        Ok(UnrenderableView {
            per_endpoint: BTreeMap::from([(("a".to_string(), "b".to_string()), 1)]),
        })
    }
}

#[tokio::test]
async fn a_view_that_will_not_serialize_is_not_answered_as_applied() {
    let app = TestApp::new().build();
    let host: Arc<dyn EngineHost> = crate::plane_driver::engine_host(&app);
    let ctx = AdminReqCtx {
        host,
        name: "anything".to_string(),
        body: axum::body::Bytes::new(),
        headers: axum::http::HeaderMap::new(),
        principal: None,
        consumed: None,
        query: None,
        serve: crate::plane_driver::serve::ServeTables::default(),
    };
    let reply = connect_reply::<NanPlane>(ctx).await;
    assert!(
        matches!(reply, AdminReply::Rejected(PlaneVerbError::Internal(_))),
        "a view that will not serialize is an internal rejection, never an empty success"
    );
}
