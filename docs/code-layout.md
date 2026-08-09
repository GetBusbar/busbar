# Code layout conventions

The point of these rules is **predictable location**: given a concept, there is exactly one place
it can live, derivable from its name and role. "I'm looking for X, and I know where it is" should be
true by construction. Size reduction is a side effect of getting that right, not the goal.

Four invariants, all mechanically enforced by `scripts/structure-lint.sh` (run in CI). If they hold,
the tree cannot drift back into giant, inconsistent files.

The same script enforces one further invariant that is about *behavior* rather than layout — the
**choke-point registry** (every hazard class has one owner, and no file hand-rolls a bypass). It
belongs to the remediation contract; it is documented in
[testing.md](testing.md#the-remediation-contract), and § "Running the lint" below covers all four.

## 0. Workspace layout: all Rust lives under `crates/`

The repo is a Cargo workspace. Every crate lives under `crates/`, and nothing else at the root is
Rust, so "code vs not-code" is obvious at a glance:

```
crates/
  busbar/            the engine + binary (src/main.rs, the request path, admin plane, protocols)
  api/               the plugin CONTRACT crate — traits/types both the engine and every plugin build against
  auth-admin-tokens/ built-in `admin-tokens` admin plugin (default-on, removable feature)
  hooks-ranking/     built-in cheapest/fastest/… policies (default-on, removable feature)
```

Dependency direction is one-way: `busbar` → `api` ← plugins. A plugin depends only on `api`, never on
the engine, so a built-in is structured exactly like a third-party plugin would be (no privileged
access). Each plugin is an `optional` dependency gated by a feature, so `--no-default-features` compiles
it out entirely. Non-Rust lives at the root: `examples/`, `scripts/`, `docs/`, `config.yaml`,
`providers.yaml`, `Dockerfile`. The `[profile.release]` and `[workspace]` table are in the root
`Cargo.toml`; each crate's `[package]` is in its own `crates/<name>/Cargo.toml`.

The invariants below govern module layout *within* each crate's `src/`.

## 1. A module is a file *or* a folder, never both

`foo.rs` and `foo/` must not coexist. The moment a module needs a second file, the parent `foo.rs`
becomes `foo/mod.rs` and everything moves under `foo/`. (The old `admin.rs` + `admin/` hybrid is the
anti-pattern this kills: the key handlers now live at `admin/keys.rs`, not stranded in a parent
`admin.rs`.)

## 2. Tests live in one predictable place, mirroring the impl

Impl at `foo/X.rs` → its tests at `foo/tests/X_tests.rs`. **Always.** No implementation file carries
an inline test body: not a hub (`mod.rs`), not a leaf, not a small one. What the impl file keeps is
the one-line `#[path]` **declaration**, which leaves the test module a direct child so `use super::*`
still reaches private items:

```rust
// at the bottom of foo/X.rs (or foo/mod.rs)
#[cfg(test)]
#[path = "tests/x_behaviour.rs"]
mod x_behaviour;   // file lives in foo/tests/, still a direct child → super::* unchanged
```

**Why there is no "small leaf file" exception any more.** The rule earns its keep by making a file's
length mean one thing. `config/overlay.rs` used to read as 2,111 lines; a reviewer compared it with
`config/migrate.rs` at 2,379 and drew a conclusion about the pair. The real implementation figure was
607 lines, and nothing in either file said so. Two sizes that measure different things cannot be
compared, and the reader has no way to tell which is which. So: the declaration stays, the body
moves.

Because the declaration keeps the module a direct child, **moving a test never costs it private
access** — `use super::*` behaves identically before and after. That is why the tree has no test
that "has to" stay inline.

Two shapes are deliberately *not* violations, because neither is a test:

- the `#[path]` declaration above (it is brace-less, and gates only its own line);
- a `#[cfg(test)]` **support** item that declares no test — a log tap, a serialising mutex, a probe
  method on a production type. Those are production-side hooks with no own-file to move to.

If a test genuinely cannot move, the marker that permits it must **name its reason**:

```rust
// structure-lint: allow inline-test: <why this body cannot move>
```

A bare `// structure-lint: allow inline-test` is its own lint failure (`ALLOW-WITHOUT-REASON`). An
allow with no reason is the permission-to-ignore mechanism this project banned outright, and it may
not be a quieter pass than the thing it suppresses. There are currently **zero** such markers in the
tree.

## 3. Objective size trigger, not vibes

A file crosses to a folder-module when it exceeds **~1,500 impl lines** or carries **more than one**
named test module. The lint's hard ceiling on **impl** files is **2,500 lines**: it exists to forbid
genuine monster files (the thing that makes a codebase unnavigable), not to micromanage a cohesive
unit at 1,600. **Test files are exempt** from the size cap: they are located by name
(`foo/tests/<what>.rs`), not read top-to-bottom, so the navigability the cap protects is already
served by the tests/ folder convention and one-module-per-file.

## 4. Files are role-named: the name predicts the content

The filename is a total function of the code's role, so you never hunt:

- `proxy/signing.rs` - request signing / auth headers
- `proxy/select.rs` - lane selection + failover walk
- `proto/gemini/writer.rs` - the Gemini response writer
- `admin/rate.rs` - admin-plane rate limiting

Every protocol dialect has the identical shape (`proto/<name>/{mod,reader,writer}.rs` +
`proto/<name>/tests/`) so learning one lets you find anything in any of the six.

## Naming vocabulary

Module names use the product/API vocabulary (ingress, egress, pool, lane, hook, operation):

| Module | Role |
|---|---|
| `ingress/` | ingress entry handlers (the request comes in here) |
| `proxy/` | proxies the request to the provider: select lane, translate, call, fail over, stream back |
| `hooks/` | the hook system: pool routing resolution + hook transports (socket/webhook/dlopen/wire) |
| `proto/` | wire dialects; `proto::detect` sniffs which dialect a request speaks |

## Running the lint

```
scripts/structure-lint.sh
```

Non-zero exit on any violation, with the offending path and the fix. It runs in CI (the `check` job),
so a PR that reintroduces a giant file or a hybrid module fails before merge — and likewise a PR that
leaves a test body inline (`INLINE-TEST`), silences one without saying why (`ALLOW-WITHOUT-REASON`),
hand-rolls a durable write, a plugin export, or a config swap outside its choke point
(`DURABLE-BYPASS` / `EXPORT-BYPASS` / `MUTATION-BYPASS`), or deletes a choke point's class-level
test (`MISSING-CLASS-TEST`). See [testing.md](testing.md#the-remediation-contract).

The scanner that decides "is this line test code?" is itself guarded:

```
scripts/structure-lint.sh --selftest
```

It runs the real scanners over a fixture corpus whose every shape is a known way to lie about being
test code, with each fixture declaring the verdict it must get — including fixtures that must **miss**
(a legitimately test-only file, the correct `#[path]` shape, a support module with no tests). It
fails if zero cases execute and it fails if a fixture does not reach disk, because a self-test that
skipped to green would report exactly what a passing one reports.
