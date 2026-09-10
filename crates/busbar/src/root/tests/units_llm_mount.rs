//! Tests for `units_llm_mount.rs`. Lifted out of the implementation file so its line count measures
//! implementation and nothing else; still a direct child module, so `use super::*` reaches what it
//! always did.
//!
//! What is here is the PLANE-SIDE half of the claim walk: the generic cells beside `plane_mount`
//! prove the grammar's shapes are read, and these prove that this plane's own declared surface — the
//! fourteen-rung ladder, not a list restated in a test — is claimed by the mount that would serve it.

use super::*;

/// **The plane's own declared surface is claimed by the generic walk.**
///
/// Not a path list: every address below is one this plane's ladder declares, and the assertion is
/// that the mount's walk over `claims::CLAIMS` reaches them. Before the seam commit beside this one,
/// every one of these was false — the walk read `ExactPath` and `PathPattern` and this plane
/// declares neither for these rungs — which is the same sentence as "this plane could be mounted and
/// never reached".
#[test]
fn the_ladders_own_addresses_are_claimed_by_the_mounts_walk() {
    // Rung 7, the widely-copied chat surface, declared as a suffix.
    assert!(claims_the_path("/v1/chat/completions"));
    // The same surface behind a deployment prefix, which is exactly why the rung is a suffix and
    // not an address.
    assert!(claims_the_path("/openai/v1/chat/completions"));
    // Rung 11, declared as a contained literal.
    assert!(claims_the_path("/v1/messages"));
    // Rung 10, and rung 14's two non-chat surfaces.
    assert!(claims_the_path("/v1/responses"));
    assert!(claims_the_path("/v1/embeddings"));
    assert!(claims_the_path("/v1/moderations"));
    // Rung 6, declared as a segment pattern — the shape the walk always read.
    assert!(claims_the_path("/v1/models/gemini-2.0-flash"));
}

/// **A trailing slash is the same address here too**, by the mount's one normalisation and not by
/// anything this file does.
#[test]
fn a_trailing_slash_is_the_same_address_on_this_planes_surface() {
    assert!(claims_the_path("/v1/embeddings"));
    assert!(claims_the_path("/v1/embeddings/"));
}

/// **A path no rung of the ladder names is not this plane's**, which is what keeps a mounted
/// listener's other routes answering as they always did.
#[test]
fn a_path_the_ladder_does_not_name_is_left_to_the_surface_underneath() {
    assert!(!claims_the_path("/healthz"));
    assert!(!claims_the_path("/mcp"));
    assert!(!claims_the_path("/a2a/agents/one"));
    assert!(!claims_the_path("/"));
    // The voice plane's two one-shot audio operations, which this plane's rung 14 deliberately does
    // NOT claim — the rung names the audio paths one at a time for exactly this reason.
    assert!(!claims_the_path("/v1/audio/transcriptions"));
    assert!(!claims_the_path("/v1/audio/speech"));
}

/// **The media type is the plane's, and it is the one its dialects answer with.**
#[test]
fn the_document_answers_carry_this_planes_own_media_type() {
    assert_eq!(media_type(), "application/json");
}
