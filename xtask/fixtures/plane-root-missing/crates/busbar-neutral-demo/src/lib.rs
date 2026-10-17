//! FIXTURE: a tree whose `crates/` directory is populated and readable, and in which NO plane
//! declares its grammar — the shape a plane that split away into its own repository leaves behind.
//!
//! The three scanners that share the plane resolver (`response-header`, `settings-leak`,
//! `blocking-ffi`) each own a `plane-roots` row whose whole job is to refuse this tree. Every other
//! row they own is cleared by what is LEFT: the fixed roots still resolve, they still hold files,
//! and the scan floor is still met, so a lost plane reads to all of them as a quieter tree.
//!
//! There is no `pub const PLANE_DECL` anywhere below this directory, and that is the point. A file
//! is present so the failure being proven is "the plane is not here", never "the walk found
//! nothing at all".

/// A neutral declaration, deliberately naming nothing a plane rule bans.
pub const NEUTRAL_DEMO: &str = "neutral";
