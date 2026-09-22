//! Tests for `proto.rs`. Lifted out of the implementation file so its line count measures
//! implementation and nothing else; still a direct child module, so `use super::*` reaches what it
//! always did.
//!
//! ONE assertion, and it is the whole reason the fold exists: a declaration whose model is in the URL
//! path must arrive with an arrival. The success path is NOT tested here — both installs behind it are
//! set-once per process and this crate's test binary is shared — and it does not need to be: the two
//! installs are the leaf's and this crate's own, each already covered where it is defined. What is only
//! true HERE is that the parity is checked BEFORE either of them, so the refusal leaves both seams
//! unwritten rather than one of the two.

use super::*;

/// The one field this fold reads that is not the neutral zero. Everything else comes from the
/// leaf's own name-only row ([`ProtocolDecl::named`]), so a field added to the declaration is added
/// in one place and this fixture does not have to be found and edited to stay compiling.
static URL_MODEL_WITHOUT_ARRIVAL: ProtocolDecl = ProtocolDecl {
    has_model_in_url: true,
    ..ProtocolDecl::named("telex")
};

/// A path-model declaration installed with NO arrival would resolve no arrival and fall through to the
/// body-model branch — a silent, 404-shaped wrong answer on a protocol the operator did install. The
/// fold refuses the boot instead, and refuses it BEFORE either seam is written: this test's process
/// never reaches `install_protocols`, so a panic here is the guard and not an install.
#[test]
#[should_panic(expected = "registered no path_ingress arrival")]
fn a_url_model_declaration_without_its_arrival_refuses_the_boot() {
    install_protocols_with_path_ingress(vec![&URL_MODEL_WITHOUT_ARRIVAL], Vec::new());
}
