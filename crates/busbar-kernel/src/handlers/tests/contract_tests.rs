use super::*;
use busbar_substrate_values::handlers::{
    CodecError, IngressReject, OperationHandler, RequestHandler,
};
use busbar_substrate_values::wire::EgressCtx;

// A trivial OperationHandler + RequestHandler prove the trait objects are object-safe and the no-OperationHandler lookup works.
struct NoopModeration;
impl OperationHandler for NoopModeration {
    fn read_request(
        &self,
        _body: &[u8],
        _content_type: &str,
    ) -> Result<Box<dyn crate::ir::handle::IrHandle>, IngressReject> {
        Err(IngressReject::BadRequest("noop".into()))
    }
    fn read_response(&self, _w: &[u8]) -> Result<Box<dyn crate::ir::handle::IrHandle>, CodecError> {
        Err(CodecError::Malformed("noop".into()))
    }
}

struct WidgetLike;
impl RequestHandler for WidgetLike {
    fn protocol_name(&self) -> &'static str {
        "widget"
    }
    fn operation_handler(&self, op: OpVerb) -> Option<&dyn OperationHandler> {
        // widget serves moderation; not, say, chat-on-a-moderation-only stub → None = no-handler 404.
        match op {
            OpVerb::MODERATION => Some(&NoopModeration),
            _ => None,
        }
    }
    fn upstream_path(&self, ctx: &EgressCtx) -> String {
        match ctx.operation {
            OpVerb::MODERATION => "/v1/moderations".into(),
            _ => String::new(),
        }
    }
    fn resolve_operation(&self, path: &str, _body: &[u8]) -> Option<OpVerb> {
        path.ends_with("/v1/moderations")
            .then_some(OpVerb::MODERATION)
    }
}

#[test]
fn no_handler_lookup_returns_none_for_unsupported_op() {
    let h = WidgetLike;
    assert!(h.operation_handler(OpVerb::MODERATION).is_some());
    assert!(
        h.operation_handler(OpVerb::CHAT).is_none(),
        "an absent OperationHandler IS the no-handler 404"
    );
    assert_eq!(h.protocol_name(), "widget");
}

#[test]
fn sub_op_reject_carries_op_and_model() {
    let r = IngressReject::UnsupportedSubOp {
        op: OpVerb::IMAGE,
        model: "gpt-image-1".into(),
    };
    assert!(matches!(
        r,
        IngressReject::UnsupportedSubOp {
            op: OpVerb::IMAGE,
            ..
        }
    ));
}
