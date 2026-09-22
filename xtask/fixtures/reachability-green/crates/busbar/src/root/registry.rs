use busbar_plane_a2a::A2aPlane;
use busbar_plane_decision::DecisionPlane;
use busbar_plane_llm::LlmPlane;
use busbar_plane_mcp::McpPlane;
use busbar_plane_streaming::StreamingPlane;

pub fn plane_claims() -> Vec<&'static str> {
    let mut claims: Vec<&'static str> = Vec::new();
    claims.push(LlmPlane::KEY);
    claims.push(McpPlane::KEY);
    claims.push(A2aPlane::KEY);
    claims.push(StreamingPlane::KEY);
    claims.push(DecisionPlane::KEY);
    claims
}
