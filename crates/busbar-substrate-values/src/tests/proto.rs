//! Tests for `proto.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;

static ROOTED: ProtocolDecl = ProtocolDecl::named("rooted");
static TEST_ONLY: ProtocolDecl = ProtocolDecl::named("test-only");

/// D02: `Registry::decl` interned-name fast path must compare the slice LENGTH as well as the start
/// pointer. `"root"` carved from the interned `"rooted"` shares its start pointer but denotes a
/// different, shorter name; a pointer-only test would settle it onto the wrong (longer) decl —
/// a caller asking for `"root"` (or any prefix of a codec/auth/verbs protocol name) would be handed
/// the protocol it merely prefixes. This is a self-contained `Registry` (no process-singleton root),
/// so it can run beside the install test.
#[test]
fn decl_prefix_subslice_does_not_pointer_match_a_longer_interned_name() {
    let reg = Registry::new(vec![&ROOTED]);
    let prefix = &ROOTED.name[..4];
    assert_eq!(prefix, "root");
    assert_eq!(
        prefix.as_ptr(),
        ROOTED.name.as_ptr(),
        "test premise: the prefix subslice shares the interned name's start pointer"
    );
    assert!(
        reg.decl(prefix).is_none(),
        "a prefix subslice must not pointer-match the longer interned decl"
    );
    assert_eq!(
        reg.decl("rooted").map(|d| d.name),
        Some("rooted"),
        "the exact interned name still resolves"
    );
}

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
