# De-skeleton plan — busbar-voice stale deferral markers

Read-only survey. No code touched. Scope: every SKELETON / "dev-only until DoD" / STUB / PENDING
marker on the voice path, file:line, exact current text, corrected text, and whether the marker is
**stale-reword** (code behind it is done; only prose is wrong) or **real-gap-must-implement** (there
is still something to build, and rewording it would be laundering a live deferral).

Finding up front: I found **zero** `todo!()`/`unimplemented!()` in any function body under
`crates/busbar-voice/src/`. The only two `todo!()` occurrences in the whole tree are inside comments
that describe themselves ("the skeleton ... left `todo!()`") — i.e. they are stale-reword too, not
live deferrals. `IrDuplexUsage` is consumed end-to-end (`metering::Pricing::price`, `HostMeteringPort`
→ `cost_settle`), both codecs (`OpenAiRealtimeCodec`, `GeminiLiveCodec`) have real bodies, and
`testing/voice-conformance/legs/*.sh` are **all four `LEG_STATUS=ready`** (not `pending`), confirming
the user's premise that the scaffold has been filled in since these headers were written.

The one genuine (non-doc) gap is **not** a `todo!()` — it's `crates/busbar-voice/src/lib.rs`'s
`PLANE_DECL`: `claims`, `admission`, `build`, `routes`, `handler`, `verbs`, `parse_section`,
`default_section` are still `|_| None` / `Vec::new()` / `&[]`. That's real, but it's explicitly scoped
as later work (P2 config-grammar / M5 boot-wiring) elsewhere in the same file — it should stay
described as deferred, just not conflated with the T2 runtime/codec/IR work that IS done.

---

## Sequencing warning (read first)

`crates/busbar-voice/src/lib.rs` is the **convergence file** — Stage A, M5, and gemini-flip all have
pending edits to it. This de-skeleton pass touches only doc-comments/strings (zero behavior change),
but every hunk in lib.rs is a merge-conflict surface. **Do this pass LAST**, after Stage A / M5 /
gemini-flip land, as a single small "correct stale markers" commit that touches only comments — never
interleave it with any of those three, and rebase-not-merge if it lands first by accident.

---

## crates/busbar-voice/src/lib.rs (convergence file — sequence LAST)

| Line(s) | Current text | Category | Corrected text |
|---|---|---|---|
| 4 | `//! busbar-voice — the DUPLEX / LIVE-VOICE plane (Plane 4), as ONE plugin crate. SKELETON.` | stale-reword | Drop trailing `SKELETON.` — e.g. `//! busbar-voice — the DUPLEX / LIVE-VOICE plane (Plane 4), as ONE plugin crate.` |
| 9–11 | `the plane's OWN four-layer duplex/session IR as TYPE STUBS ([`ir`]). There is no pump, no reader/writer body, no session store yet: this is the skeleton the P2 build (see plane4-duplex-session.md §8) fills in.` | stale-reword | `the plane's OWN four-layer duplex/session IR ([`ir`]), with a working pump, reader/writer bodies, and session store (`crate::runtime`, behind the `runtime` feature — see §8). Boot-wiring into the composition root (config-section grammar, route/admission mounting) is separate, tracked work — see [`PLANE_DECL`].` |
| 37 | `// HARD RULE 4). The default / prod build compiles the skeleton IR + declarations only; turning the` | stale-reword | `// HARD RULE 4). The default / prod build compiles the IR + declarations only (no async runtime pulled in); turning the` |
| 39 | `// binding, and the browser-sideband / telephony topologies. Voice stays dev-only until DoD.` | stale-reword | `// binding, and the browser-sideband / telephony topologies — all feature-gated OFF by default (HARD RULE 4), not because the code is incomplete.` |
| 46–47 | `/// ([`runtime::build_runtime`]) behind the `runtime` feature, `None` in the default skeleton build so the prod `PLANE_DECL` is byte-unchanged (voice stays dev-only until DoD). Split by `cfg` because the` | stale-reword | `/// ([`runtime::build_runtime`]) behind the `runtime` feature, `None` when the feature is off so the default `PLANE_DECL` is byte-unchanged. Split by `cfg` because the` |
| 80–81 | `/// `busbar` binary names one stable path (`busbar_voice::PLANE_DECL`). SKELETON: it declares the plane's identity (key, config section, audit kind, wire format) and returns EMPTY/`None` from every runtime hook —` | **real-gap** (the None hooks are true) | `/// `busbar` binary names one stable path (`busbar_voice::PLANE_DECL`). It declares the plane's identity (key, config section, audit kind, wire format); the runtime engine itself is implemented behind the `runtime` feature (see [`runtime`]), but this decl still returns `None`/empty from the boot-mounting hooks —` |
| 104 | `// SKELETON: the plane mounts nothing, admits no one, and builds no runtime object yet — the` | **real-gap** — keep as deferral, just retarget the noun | `// NOT YET MOUNTED: the runtime engine exists (crate::runtime, behind "runtime"), but this decl still mounts nothing and admits no one at boot — the` |
| 128–129 | `// feature (see [`VOICE_BUILD_RUNTIME`]); `None` in the default skeleton build so the prod build is byte-unchanged. The remaining runtime hooks (`build` / `hydrate` / `start` /` | stale-reword (the "skeleton build" phrase) + **real-gap** (hooks genuinely None) | `// feature (see [`VOICE_BUILD_RUNTIME`]); `None` when the feature is off so the default build is byte-unchanged. The remaining boot-mounting hooks (`build` / `hydrate` / `start` /` |
| 145 | `/// SKELETON: `handler: None` and `verbs: &[]` — the duplex handler / gauntlet-session entry is the P2` | **real-gap** — true today | `/// NOT YET MOUNTED: `handler: None` and `verbs: &[]` — the duplex handler / gauntlet-session entry is the P2` |
| 152 | `// SKELETON: no request handler yet — the duplex pump / session entry is P2.` | **real-gap** — true today | `// NOT YET MOUNTED: no request handler wired here yet — the duplex pump exists in crate::runtime; the entry point is P2.` |
| 154 | `// SKELETON: no verbs declared yet (the long-lived Subscribe/Control shapes arrive with the pump).` | **real-gap** — true today | `// NOT YET MOUNTED: no verbs declared yet (the long-lived Subscribe/Control shapes arrive with the boot-mounting pass).` |

## crates/busbar-voice/Cargo.toml

| Line(s) | Current text | Category | Corrected text |
|---|---|---|---|
| 1 | `# busbar-voice — THE DUPLEX / LIVE-VOICE PLANE CRATE (Plane 4). SKELETON.` | stale-reword | Drop `SKELETON.` suffix. |
| 9–10 | `# STATUS: SKELETON ONLY. The four-layer duplex/session IR (plane4-duplex-session.md §2) is present as TYPE STUBS with no pump, no reader/writer bodies, no session store. It compiles, registers, and is strong-form deletable.` | stale-reword | `# STATUS: the four-layer duplex/session IR (plane4-duplex-session.md §2), both dialect codecs, the T2 session pump, and both topologies are implemented behind the "runtime" feature (68/68 tests green). Boot-mounting into the composition root (PLANE_DECL's build/admission/routes hooks) is separate, tracked work. It compiles, registers, and is strong-form deletable.` |
| 22 | `description = "... as one removable plugin. Skeleton — no audio/pump logic yet."` | stale-reword | `description = "... as one removable plugin."` (drop the trailing clause) |
| 33–34 | `# session engine + tokio); the default / prod build never compiles it, so voice stays dev-only until DoD exactly as the rest of the crate does.` | stale-reword | `# session engine + tokio); the default / prod build never compiles it — it's gated behind the "runtime" feature like the rest of the async surface.` |
| 70 | `# skeleton IR + declarations need no async runtime.` | stale-reword | `# IR + declarations need no async runtime.` |
| 73 | `# OPTIONAL dep the `runtime` feature turns on, keeping voice dev-only until DoD (HARD RULE 4).` | stale-reword | `# OPTIONAL dep the `runtime` feature turns on (HARD RULE 4: async surface stays feature-gated, not compiled into the default build).` |
| 80–81 | `# lease + both topologies). OFF by default: voice is dev-only until DoD, so the default workspace build is UNAFFECTED and the crate still compiles with the flag off (the skeleton).` | stale-reword | `# lease + both topologies). OFF by default (HARD RULE 4): the default workspace build is UNAFFECTED and the crate still compiles with the flag off (IR + declarations only, no async runtime pulled in).` |
| 90 | `# `#[cfg(feature = "openapi-schema")]` field site and the struct definition in lock-step. The skeleton` | stale-reword | `# `#[cfg(feature = "openapi-schema")]` field site and the struct definition in lock-step. The plane` |

## crates/busbar-voice/src/runtime/mod.rs

| Line(s) | Current text | Category | Corrected text |
|---|---|---|---|
| 5–6 | `` `runtime` cargo feature (OFF by default): the default / prod build compiles the skeleton IR + declarations only, so the workspace is unaffected and voice stays dev-only until DoD. `` | stale-reword | `` `runtime` cargo feature (OFF by default, HARD RULE 4): the default / prod build compiles the IR + declarations only, so the workspace is unaffected regardless of this module's state. `` |
| 85 | `` skeleton build leaves the hook `None`. `` | stale-reword | `` default (feature-off) build leaves the hook `None`. `` |
| 93 | `change. Voice is dev-only until DoD, so a dev-default runtime object is the honest interim.` | **real-gap, keep truthful — do not delete the fact, just drop the crate-wide framing** | `change. The config-derived dependencies (engine/tools/pricing from the plane's own config section) are a separate, tracked slice — see the SEQUENCING note above — so a dev-default runtime object is the honest interim for `build_runtime` specifically (not a statement about the crate as a whole).` |

Note on 93: the underlying fact — `build_runtime` binds `LocalMeteringPort` / `EchoToolExecutor` /
zero-priced `Pricing` rather than config-derived production dependencies — is **true today** and is a
**real-gap**, not stale. Only the generic "voice is dev-only until DoD" framing (implying the whole
crate is provisional) is stale; the specific claim about `build_runtime`'s dev defaults must survive
the reword unchanged in substance.

## crates/busbar-voice/src/ir/mod.rs

| Line(s) | Current text | Category | Corrected text |
|---|---|---|---|
| 4 | `//! THE PLANE-4 DUPLEX / SESSION IR — the plane's OWN vocabulary (skeleton).` | stale-reword | `//! THE PLANE-4 DUPLEX / SESSION IR — the plane's OWN vocabulary.` |
| 24–25 | `//! SKELETON: every type below is a STUB. No reader/writer body, no pump, no session store — bodies are `todo!()` or minimal. The shapes mirror plane4-duplex-session.md §2.2–2.6.` | stale-reword | `//! Both dialect codecs (OpenAI Realtime, Gemini Live) implement the reader/writer pair; the T2 session pump and session store live in `crate::runtime` behind the `runtime` feature. The shapes mirror plane4-duplex-session.md §2.2–2.6.` |

## crates/busbar-voice/src/ir/usage.rs

| Line | Current text | Category | Corrected text |
|---|---|---|---|
| 15 | `/// SKELETON: a plain token-class tally; the `CostBreakdown` fold is future work.` | stale-reword (verify before landing — see caveat) | `/// A plain token-class tally, priced via `runtime::metering::Pricing::price` and settled through the D2 `cost_settle` leg (`runtime::metering::HostMeteringPort`).` |

Caveat: `Pricing::price(&IrDuplexUsage)` (crates/busbar-voice/src/runtime/metering.rs:102) and the
`cost_settle` call (metering.rs:234) are real and exercised by `runtime/tests.rs`. I did not chase
whether the *specific* `busbar_core::CostBreakdown` type (with its labeled top-level components) is
constructed at the `journal_append_scoped` call site, or whether pricing currently flows as a single
scalar. Whoever does the final pass should grep for `CostBreakdown` at the call site before committing
this line's reword — if the labeled-component fold genuinely isn't wired, keep this one as
**real-gap** and word it as an accurate TODO, not a completion claim.

## crates/busbar-voice/src/runtime/session.rs

| Line | Current text | Category | Corrected text |
|---|---|---|---|
| 4 | `` //! THE LIVE DUPLEX SESSION RUNTIME — the pump body the skeleton in `lib.rs` left `todo!()`. `` | stale-reword | `//! THE LIVE DUPLEX SESSION RUNTIME — the pump body behind the `runtime` feature.` |

## crates/busbar-voice/src/bin/voice-conform.rs

No stale markers found. Line 15 ("documented sub-item gaps that must stay HONESTLY PENDING rather
than be dressed as a green") and the per-concept `SUBITEM ... PENDING` prints (e.g. line 616) are
**not** deferral markers on the crate/plane as a whole — they're the harness's own accurate,
still-true design principle for individually-absent cross-dialect concepts. Leave unchanged.

## testing/voice-conformance/voice-conformance.sh

| Line(s) | Current text | Category | Corrected text |
|---|---|---|---|
| 5–8 | `... but in an HONEST SCAFFOLD state: the voice runtime does not exist yet, so no leg can assert real conformance. This file exists so that the SHAPE lands green and stays enforced, and so that filling a leg later is a drop-in rather than a rebuild.` | stale-reword | `... The voice runtime now exists and all four legs are LEG_STATUS=ready. This file (and its PENDING/ready machinery below) stays in place so a future leg or slice can still land as a drop-in, exercised by --selftest.` |
| 17–19 | `Here the runtime does NOT exist yet. A voice leg cannot be "armed and vacuous", because there is nothing to arm it against. So the honest report is PENDING — stated loudly, per leg, and never dressed up as a conformance pass. The scaffold's job is to make the transition from PENDING to a` | stale-reword | `The runtime now exists and every shipped leg is armed (LEG_STATUS=ready): "armed and vacuous" is exactly the failure mode the ready-leg anti-vacuity check below guards against. The PENDING path stays live for any future leg/slice that isn't armed yet — stated loudly, per leg, never dressed up as a conformance pass. The self-test's job is to keep the transition from PENDING to a` |
| 29 | `# trusted to judge busbar. (Scaffolded: the control side of each leg is PENDING today.)` | stale-reword | `# trusted to judge busbar.` (drop the parenthetical — control sides are exercised by the ready legs today) |
| 337 | `# And finally: the REAL legs on disk must load and account cleanly, all-pending, right now.` | stale-reword | `# And finally: the REAL legs on disk must load and account cleanly, right now (whatever mix of ready/pending they currently declare).` |

Lines 53–54, 117, 130–133, 170, 173, 183, 204, 217, 220, 233–234, 257–332 (the `--selftest` fixture
machinery and generic mode descriptions) are **not stale** — they describe the still-live
pending/ready mechanism the self-test exercises in a scratch tmpdir, independent of what the shipped
legs currently declare. Leave unchanged.

---

## Count

- **stale-reword** (correct the words, zero behavior change): lib.rs ×5 (lines 4, 9–11, 37, 39,
  46–47), Cargo.toml ×8, runtime/mod.rs ×2, ir/mod.rs ×2, runtime/session.rs ×1,
  voice-conformance.sh ×4 = **22 sites**
- **real-gap-must-implement / must-stay-a-deferral** (reword the framing only, keep the underlying
  gap truthfully stated — do not launder): lib.rs PLANE_DECL hooks ×5 (lines 80–81, 104, 128–129, 145,
  152, 154 — counted as one connected gap, the "not yet mounted at boot" cluster), runtime/mod.rs L93
  (dev-default `build_runtime` dependencies) = **2 sites** (one multi-line cluster + one single line)
- **needs verification before deciding** (ir/usage.rs L15, `CostBreakdown` fold — may be stale or may
  be real, didn't chase the call site) = **1 site**

File: `/Users/matthew/Developer/GetBusbar/busbar/.claude/worktrees/config-seam-work/docs/design/playbook/de-skeleton-plan.md`
