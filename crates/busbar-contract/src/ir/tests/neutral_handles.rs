//! Tests for `neutral_handles.rs`. Lifted out of the implementation file so its line count

use super::*;
use crate::ir::subscribe::SubscribeIntent;

/// `facts()` shares the request's allocation instead of cloning the arguments `Value`. The refcount rises while the handle continues to point to the same arguments.

#[test]
fn invoke_facts_share_the_request_rather_than_cloning_it() {
    let req = Arc::new(InvokeReq {
        tool: "search".to_string(),
        arguments: serde_json::json!({"q": "hello"}),
        extra: Default::default(),
    });
    let arguments_ptr = std::ptr::addr_of!(req.arguments);
    let handle = InvokeReqHandle(Arc::clone(&req));
    let before = Arc::strong_count(&req);

    let facts = handle.facts();
    assert_eq!(
        Arc::strong_count(&req),
        before + 1,
        "facts() must SHARE the request (one refcount bump), not clone it"
    );
    assert_eq!(
        std::ptr::addr_of!(handle.0.arguments),
        arguments_ptr,
        "the arguments Value must not have been cloned"
    );
    assert_eq!(facts.verb(), OpVerb::INVOKE);
    drop(facts);
    assert_eq!(Arc::strong_count(&req), before, "the share is released");
}

/// The same for `Subscribe`.
#[test]
fn subscribe_facts_share_the_request_rather_than_cloning_it() {
    let req = Arc::new(SubscribeReq {
        intent: SubscribeIntent::Register,
        target: "file:///doc".to_string(),
        extra: Default::default(),
    });
    let target_ptr = std::ptr::addr_of!(req.target);
    let handle = SubscribeReqHandle(Arc::clone(&req));
    let before = Arc::strong_count(&req);
    let facts = handle.facts();
    assert_eq!(Arc::strong_count(&req), before + 1);
    assert_eq!(std::ptr::addr_of!(handle.0.target), target_ptr);
    drop(facts);
    assert_eq!(Arc::strong_count(&req), before);
}
