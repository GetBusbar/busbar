use crate::operation::OpVerb;
use busbar_contract::codec::{
    CodecError, EgressCtx, IngressReject, OperationHandler, RequestHandler,
};

struct NoopModeration;
impl OperationHandler for NoopModeration {
    fn read_request(
        &self,
        _body: &[u8],
        _content_type: &str,
    ) -> Result<Box<dyn busbar_contract::ir::handle::IrHandle>, IngressReject> {
        Err(IngressReject::BadRequest("noop".into()))
    }
    fn read_response(
        &self,
        _host: &dyn busbar_contract::codec::CodecHost,
        _w: &[u8],
    ) -> Result<Box<dyn busbar_contract::ir::handle::IrHandle>, CodecError> {
        Err(CodecError::Malformed("noop".into()))
    }
}

struct WidgetLike;
impl RequestHandler for WidgetLike {
    fn protocol_name(&self) -> &'static str {
        "widget"
    }
    fn operation_handler(&self, op: OpVerb) -> Option<&dyn OperationHandler> {
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
fn request_and_operation_handlers_are_callable_through_trait_objects() {
    let h: &dyn RequestHandler = &WidgetLike;
    let operation: &dyn OperationHandler = h
        .operation_handler(OpVerb::MODERATION)
        .expect("the fixture serves moderation");
    assert!(matches!(
        operation.read_request(b"{}", "application/json"),
        Err(IngressReject::BadRequest(message)) if message == "noop"
    ));
    assert!(h.operation_handler(OpVerb::CHAT).is_none());
    assert_eq!(h.protocol_name(), "widget");
}
