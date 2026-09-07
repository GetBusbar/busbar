//! Tests for `admin_verbs.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::{connect_reply, AdminReply, AdminReqCtx, PlaneTrust, PlaneVerbError};
use crate::plane_host::EngineHost;
use crate::testkit::fixture_host::FixtureHost;
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

/// A view that will not serialize must not be answered as a success. Falling back to an empty
/// object hands the caller a `200` with nothing in it AND writes `applied` to the audit -- a
/// record of a look that succeeded whose answer nobody ever saw.
#[tokio::test]
async fn a_view_that_will_not_serialize_is_not_answered_as_applied() {
    let host: Arc<dyn EngineHost> = Arc::new(FixtureHost::new());
    let ctx = AdminReqCtx {
        host,
        name: "anything".to_string(),
        body: axum::body::Bytes::new(),
        headers: axum::http::HeaderMap::new(),
        principal: None,
    };
    let reply = connect_reply::<NanPlane>(ctx).await;
    assert!(
        matches!(reply, AdminReply::Rejected(PlaneVerbError::Internal(_))),
        "a view that will not serialize is an internal rejection, never an empty success"
    );
}
