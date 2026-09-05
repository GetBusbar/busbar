# busbar-contract / busbar-caps — module notes

`ARCHITECTURE.md` pins `busbar-caps` + `busbar-contract` at <= 3k raw lines together. The
module-level essays that used to live as `//!` doc comments in each source file are collected
here instead, one section per module, so the source keeps a one-sentence summary and a pointer
to this file rather than the full "why" narrative. Nothing here is a substitute for the code —
every honesty table (KernelSeal, grammar overlaps, SlabBytes, what Rust actually enforces) stays
in the source itself; only the surrounding prose moved.

## busbar-contract

### `lib.rs` — the plugin-visible contract

busbar is a byte-governance router. Bytes come in over a transport; a plane says what they mean;
the kernel runs the same seven steps on every unit of work — authenticate, verify, approve,
admit, route, meter, audit — and bytes go out. The kernel does not know what any protocol is.

This crate is the seam that makes that true. It carries the traits a plugin implements, the
closed grammars a plugin declares against, and the bounded types a plugin is handed. It does not
carry the kernel, the capability types, any unit, any plane or any transport, and it never will:
a plugin's manifest may name this crate, and naming anything else in the workspace is a failure
in the gate. That direction is the whole architecture — core calls plugin, never the reverse.

**What is deliberately not here.** The capability types — the per-step decision, the hold, the
accrual, the posted settlement, the durability loss marker, and the tokens that build them — live
in the capability crate, which the kernel and the units name and a plugin cannot. They are absent
here on purpose: a plugin that could name a hold could hold one, and a plugin that could build a
decision would not need the loop's permission for anything. Where this crate needs to describe a
kernel-built value a plugin merely reads, it uses the seal marker in the plugin module and says so
at the point of use.

**The three properties this crate is meant to have.** No default bodies — the honesty table of
the design requires that every method of every kind trait be implemented by the plugin; a default
body is a plugin quietly declining to answer, and the loop cannot tell that apart from an answer.
Feature-invariant — this crate declares no cargo features, so the surface a plugin compiles
against is the same surface everywhere. Bounded — every collection on this surface has a ceiling
that is part of its type, with the two exceptions the design itself names: the candidate set and
the permutation over it, which are unbounded because configured pools are unbounded and bounding
them would refuse a configuration the previous release accepted.

### `plane.rs` — the plane trait family

(see source header for the one-sentence summary; the fuller rationale for why a plane session is
split the way it is, and why progress is reported rather than pushed, lived here before the trim
and is reconstructable from the design doc's plane-session section.)

### `kinds.rs` — the other plugin kinds

The plugin-kinds table of the design gives each kind a closed shape the kernel calls and an open
vocabulary the plugin declares. Two kinds are pure — a hook and an egress-auth scheme perform no
input or output and are held to the source denylist. Four own their input and output by
definition: a store, a secret plugin, an export sink and a network-backed auth scheme all reach
outside the process. Those four are not trusted more for it; they are bounded instead by the
signature, by a load entry, by a kernel-enforced per-call deadline, by an access entry per
external call, and by review. Every one of their calls runs on a bounded blocking pool, which is
why they are written as ordinary blocking methods rather than as futures.

**Fallibility convention (was repeated per method as `# Errors`):** every fallible method on
`Store`, `Secret`, `Signer` and `Anchor` returns the kind's own error enum on failure; the
per-method doc used to restate "returns an error when the call fails" almost verbatim on every
method. That sentence now lives once on the trait, and a method's doc only adds words when its
failure mode is distinctive (e.g. a fencing race, a stale epoch).

### `ids.rs` — the open vocabulary

The open-vocabulary section of the design draws the line these types sit on: the kernel has no
closed list a plugin could need to extend, so each identifier is a name, not a variant, and the
kernel never compares one against a literal of its own. Every identifier is a borrowed static
string because the declarations that carry them are associated constants on the meta traits, and
a constant cannot own a heap allocation; a dynamically loaded plugin's keys come in through its
adapter, which leaks the strings once at load and hands over static names.

### `bounded.rs` — the bounded collection family

The bounded types are the design's answer to "what stops an attacker-sized input from becoming an
attacker-sized allocation": every collection surfaced to a plugin carries its ceiling in its own
type rather than in a runtime check a caller could skip. The `# Errors` sections on the
constructors collapse to the same rule as `kinds.rs`: a bounded constructor returns the rejected
value or its length back when the ceiling is exceeded, and only says more when the ceiling itself
needs explaining.

## busbar-caps

### `lib.rs` — capability crate overview

A capability type is not sealed by visibility, it is sealed by a token: the only way to build one
is to already hold the proof that you are the unit entitled to build it. That trick only works if
the constructors and the tokens live in one crate that nothing below the kernel depends on. No
dependencies is a property, not a convenience: this crate's trusted computing base is `std` and
nothing more.

### `hold.rs` — the hold, its cell, the accrual and the posting

A hold is the accounting side of admission: the door decides, and the hold is the reservation
that decision sized. It comes into being at the door and is taken out of its cell exactly once, on
the one exit path. It has no `Drop` of its own on purpose — there is no such thing as "the hold
cleaned itself up"; a hold that goes away without a posting is a bug the canary must see, not a
thing a destructor should paper over.

The doctest fixtures in the source show, in order: opening a hold needs the admission unit's own
token; with the token the same call is ordinary; a hold cannot be carried into `catch_unwind`
because it is deliberately not unwind-safe; it cannot be let fall out of scope under
`#[deny(unused_must_use)]`; it cannot be taken out of its cell without an exit token; and it
cannot be duplicated because it is neither `Clone` nor `Copy`.

**What the compiler cannot refuse, stated plainly.** `drop(hold)`, `std::mem::forget(hold)`,
`ManuallyDrop::new(hold)` and `Box::leak` all compile, and no amount of type design changes that:
Rust has no linear types, so "this value must be consumed by exactly this function" is not
expressible. Four partial mechanisms cover it instead: `#[must_use]` catches the accident above,
the cell catches the double take, the canary catches the omission after the fact in arithmetic,
and the deliberate escape is caught by a source scan whose symbols are in
[`crate::lint::HOLD_ESCAPES`].

### `token.rs` — the tokens that seal every constructor

A token is proof, not a permission bit: the only way to hold one is to already be the crate the
design names for that step, and the doctest fixtures below exist to make the alternative visible
rather than assumed. Each fixture shows one way of getting a token wrong (naming a private
constructor, minting a kernel-only token from a unit, calling a kind-mismatched constructor) and
then the corrected, kernel-only call.

### `decision.rs` — the per-step decision

Every step in the loop answers with the same shape: proceed, or refuse with a reason from that
step's own closed list. The doctest fixtures show a decision cannot be built without the step's
own token, and that a reason from one step's list cannot be used to refuse a different step — the
type parameter on `Decision<S>` is what a reviewer would otherwise have to check by hand.

### `unit_end.rs` — the one exit path

There is exactly one way out of a unit — `UnitEnd` — and it is minted only by the exit token so
that every unit, success or failure, is forced through the same posting-and-cleanup path. The
doctest fixtures show that end cannot be constructed without the token and that it cannot be
constructed twice for the same unit.

### `tests.rs` — shared test fixtures

Helper builders in this file exist to keep each test focused on the one behaviour it is checking
rather than re-deriving a valid `Hold`/`Decision`/token chain inline. They are not part of the
crate's public surface (the file is `#[cfg(test)]`-only) and carry no invariant of their own
beyond "build a minimal valid value of this shape."
