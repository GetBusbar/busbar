use super::*;
use crate::operation::Operation;
use crate::proto::{
    PROTO_ANTHROPIC, PROTO_BEDROCK, PROTO_COHERE, PROTO_GEMINI, PROTO_OPENAI, PROTO_RESPONSES,
};

#[test]
fn registry_resolves_openai_and_its_moderation_handler() {
    let h = request_handler(PROTO_OPENAI).expect("the shipped protocol's handler is registered");
    assert_eq!(h.protocol_name(), PROTO_OPENAI);
    assert!(h.operation_handler(Operation::MODERATION).is_some());
    assert!(
        request_handler("zzz-unknown").is_none(),
        "unknown protocol → None"
    );
}

#[test]
fn every_protocol_serves_chat_via_its_request_handler() {
    // Chat is operation #1, reached through the SAME registry as every other op. All six
    // protocols resolve a handler and a chat OperationHandler — the unified dispatch, no special path.
    for proto in [
        PROTO_OPENAI,
        PROTO_ANTHROPIC,
        PROTO_GEMINI,
        PROTO_BEDROCK,
        PROTO_COHERE,
        PROTO_RESPONSES,
    ] {
        let h = request_handler(proto).expect("protocol registered");
        assert!(
            h.operation_handler(Operation::CHAT).is_some(),
            "{proto} must serve chat via operation_handler(Chat)"
        );
    }
}
