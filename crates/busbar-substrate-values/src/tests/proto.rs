//! Tests for `proto.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;

static ROOTED: ProtocolDecl = ProtocolDecl::named("rooted");
static TEST_ONLY: ProtocolDecl = ProtocolDecl::named("test-only");

/// The one test in this binary that installs a root: `install_protocols` is once per process.
/// A test-built binary with a real composition root must fold to the same declaration list
/// as the shipped one, with no re-declaration for the boot fold to skip audibly.
#[test]
fn the_test_seam_does_not_redeclare_what_the_root_installed() {
    install_protocols(vec![&ROOTED]);
    register_test_protocol(&ROOTED);
    register_test_protocol(&TEST_ONLY);
    let names: Vec<&str> = test_registered_protocols().iter().map(|d| d.name).collect();
    assert_eq!(
        names,
        ["test-only"],
        "a root-installed name must not enter the test set"
    );
    let folded: Vec<&str> = registry().decls().iter().map(|d| d.name).collect();
    assert_eq!(
        folded,
        ["rooted", "test-only"],
        "installed first, each name once"
    );
}
