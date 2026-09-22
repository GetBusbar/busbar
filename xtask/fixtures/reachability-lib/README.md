THE SCOPE-CLAIM FIXTURE: the same crate, with a `[lib]` target added.

Every answer this gate gives is scoped to `crates/busbar/src/**` on the ground that a binary-only
crate can have no construction site outside itself. A library target makes that false — another
crate could link `busbar::root::…` and build a unit there. The gate must REFUSE such a tree rather
than answer it from the old scope, and this fixture is what proves it does.
