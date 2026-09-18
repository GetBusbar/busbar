# Parity divergence packets — busbar 1.6.0 Parity STOP (owner adjudication aid)

> **What this is.** An adjudication aid for the owner's one-at-a-time sign-off on the
> unsigned money-path / parity divergences at the 1.6.0 Parity STOP. It references the
> shadow oracle (`testing/shadow-oracle/`) and the published 1.5.5 golden; it is **NOT a
> spec** and it accepts nothing. A divergence is only accepted when it lands in
> `testing/shadow-oracle/accepted-differences.json` with an owner byline (and, where the
> class demands, a `CHANGELOG.md` line). The ship gate is unchanged: **zero UNACCEPTED
> divergences.**
>
> **Provenance / limits.** The 1.5.5 columns below are read verbatim from the recorded
> golden cells under `testing/shadow-oracle/golden/1.5.5/cells/`. The 1.6.0 columns are
> **derived from the current source on `busbar-1.6.0-config-neutral-half-parse-byte-safe`**
> (files and line numbers cited per packet), because the record/replay oracle is
> CI/linux-only and was **not run** to produce this aid (per the STOP's read-only rule).
> Each "current output" is therefore a source-grounded prediction the owner should have
> CI/linux confirm on record before an `accepted-differences.json` entry is finalised.
>
> **Protocol applied** (per DECISIONS #10 deny-and-fix, #15 no-defer, and the owner's
> divergence protocol): each divergence is judged individually; root cause first; **agent
> laziness / drift is fixed at root and NOT brought for sign-off**; only a genuine need is
> a sign-off candidate. Classification: **MINOR = additive** (a new field / list member /
> endpoint; a 1.5.5 client keeps working unchanged) · **MAJOR = modifies an existing
> field / value / wire shape** (a 1.5.5 client can observe the change).

## Summary

| # | cell(s) | class | root cause | recommendation |
|---|---|---|---|---|
| 1 | `admin.ops\|PutConfigSettings\|ok` | **MAJOR** | drift: `reload_to_apply` gained `skip_serializing_if=Vec::is_empty` in the 1.6.0 rewrite → the restart-defer field 1.5.5 always emitted is now omitted when empty | **fix-at-root** (laziness/drift — not a sign-off candidate) |
| 2 | `admin.ops\|PutConfigSettings\|if-match-stale` | **MAJOR** | same root cause as #1 (same handler, same applying view) | **fix-at-root** (laziness/drift — not a sign-off candidate) |
| 3 | `neutrality\|NEUT-U-auth\|validate` | **MINOR** (additive) | genuine: D38 operator-sealing added `auth.operator_pub` to the frozen `AuthCfg`, so it appears in the `expected one of` list | **owner-sign-off-with-rationale** (or fix-at-root for byte-identity via prepass lift) |
| 4 | `boot.refusal\|BOOT-135\|boot` | **MINOR** (wording, same exit/code) | genuine: dependency-driven change of the interpolated `{e}` archive-read error text; busbar's own format string is unchanged | **owner-sign-off-with-rationale** (twin of the accepted BOOT-141 wording) |
| 5 | `neutrality\|boot-lines` | n/a (harness) | not a busbar divergence: the two `busbar listening` lines / `<PORT>` normalization are order-nondeterministic | **flake-stabilize** (harness fix — not a sign-off candidate) |

**Laziness / harness — NOT sign-off candidates (flagged):** packets **#1 and #2**
(`PutConfigSettings` restart-defer field omission) are drift introduced by the 1.6.0
`reload_to_apply_fields` rewrite and must be **fixed at root**, not signed off. Packet
**#5** (`boot-lines` port flake) is a **harness normalization gap**, not a product
divergence, and must be **stabilized**, not signed off. Only **#3** (`NEUT-U-auth`) and
**#4** (`BOOT-135`) are genuine sign-off candidates.

---

## Packet 1 & 2 — `PutConfigSettings` restart-defer field dropped when empty (2 cells)

**Cells / ids.**
`admin.ops|PutConfigSettings|ok` and `admin.ops|PutConfigSettings|if-match-stale`
(`testing/shadow-oracle/cells.json:9603` and `:9581`; golden at
`testing/shadow-oracle/golden/1.5.5/cells/admin.ops__PutConfigSettings__ok.json` and
`…__if-match-stale.json`; owed at `testing/shadow-oracle/owed-baseline.txt:215,214`). Both
cells PUT the same body (`{"limits":{"request_body_max_bytes":33554432}}`,
`testing/shadow-oracle/fixtures/admin-bodies.json:1976`) and return `200` with a
`ConfigSettingsView`. These are the only two `PutConfigSettings` cells that emit the view
body; `bad-body` (400), `if-match-malformed` (400) and `unauth` (401) do not, which is why
the STOP counts exactly **2×**.

**Exact diff (1.5.5 golden vs derived 1.6.0).** In the `body.json` object:

```
 {
   "applied": true,
   "config_version": 1,
   "note": "applied live",
-  "reload_to_apply": [],            <-- 1.5.5 emits the restart-defer field even when empty
   "settings": { "limits": { "request_body_max_bytes": 33554432 } }
 }
```

- **1.5.5 golden** (`admin.ops__PutConfigSettings__ok.json`): body carries
  `"reload_to_apply": []` and `"note": "applied live"`.
- **1.6.0 (derived)**: `ConfigSettingsView.reload_to_apply` is
  `#[serde(default, skip_serializing_if = "Vec::is_empty")]`
  (`crates/busbar-core/src/admin/v1/contract/schema.rs:264-266`), so for a PUT that touches
  only live-swappable fields (empty `reload_to_apply`) the **key is omitted entirely** from
  the response body. `note` is `skip_serializing_if = "Option::is_none"` and is `Some("applied
  live")` on a PUT, so it still serializes and does not diverge. Net observable delta: the
  `reload_to_apply` member disappears from both cells' bodies.

**Root-cause analysis.** The 1.6.0 rewrite of the restart-defer machinery
(`reload_to_apply_fields`, `crates/busbar-admin/src/v1/json/handlers.rs:2644`, and the
`ConfigSettingsView` schema) is a legitimate drift-guard (an exhaustive `RootSettings`
destructure that forces every new field to be classified boot-frozen vs live). But it
**also carried a wire-contract change as a side effect**: adding
`skip_serializing_if = "Vec::is_empty"` to a field the published 1.5.5 always emitted. The
field's own doc calls it "frozen wire" (`schema.rs:212-215, 259-263`: *"The field NAME is
frozen wire; only this description changed"*) — yet the presence semantics changed. A 1.5.5
client that reads `body.reload_to_apply` (e.g. `.length` / iterates it) now gets an absent
key instead of `[]`. This is **agent drift, not a genuine need**: nothing in 1.6.0 required
dropping the field, and the "frozen wire" contract was asserted while being broken.

**Classification.** **MAJOR** — it modifies an existing response wire shape (a member the
1.5.5 client always received becomes conditionally absent). Not additive.

**Recommendation.** **Fix-at-root** (deny-and-fix, DECISIONS #10). Remove
`skip_serializing_if = "Vec::is_empty"` from `ConfigSettingsView.reload_to_apply` so the
field always serializes on a PUT (restoring the 1.5.5 `[]`), and re-record — the two cells
return byte-identical, no `accepted-differences.json` entry owed. **Do NOT bring for
sign-off.** (If the owner instead *wants* omit-when-empty as a deliberate 1.6.0 wire change,
it would be a `breaking` entry naming a `CHANGELOG.md` line — but the default is to restore
byte-identity.)

> **Note on the "restart-defer" name / oracle confirmation.** `reload_to_apply` *is* the
> restart-defer signal (it names the fields stored-but-not-live-until-restart;
> `schema.rs:259`). The recorded fixture touches `request_body_max_bytes`, which is
> genuinely live on both binaries (it is **not** one of the four boot-frozen `limits.*`
> fields — `upstream_request_timeout_secs`, `pool_max_idle_per_host`,
> `pool_idle_timeout_secs`, `max_inbound_concurrent`; `handlers.rs:2644-2700`), so the
> non-empty "applied live except …" note path (`handlers.rs:3085-3094`) is not exercised
> here and does not diverge. The divergence is confined to the empty-vec serialization
> above. CI/linux record should confirm this is the sole delta on these two cells before an
> entry (or the fix) is finalised.

---

## Packet 3 — `NEUT-U-auth` gains `operator_pub` in the `auth:` unknown-key list

**Cell / id.** `neutrality|NEUT-U-auth|validate`
(`testing/shadow-oracle/cells.json:30597`; mutation `NEUT-U-auth` at
`testing/shadow-oracle/fixtures/boot-mutations.json:5072`; golden at
`testing/shadow-oracle/golden/1.5.5/cells/neutrality__NEUT-U-auth__validate.json`; owed at
`testing/shadow-oracle/owed-baseline.txt:848`). The mutation sets `auth.bogus_key: true`
and expects `exit 1` with `unknown field \`bogus_key\``; the cell captures the full
`serde` `expected one of` list on `--validate`.

**Exact diff (1.5.5 golden vs derived 1.6.0).** The stderr `[error]` line:

```
-[error] config.yaml: invalid YAML: auth: unknown field `bogus_key`, expected one of `signing_key`, `chain`, `admin_auth`, `role_bindings`, `key_ttl` at line 15 column 3
+[error] config.yaml: invalid YAML: auth: unknown field `bogus_key`, expected one of `signing_key`, `operator_pub`, `chain`, `admin_auth`, `role_bindings`, `key_ttl` at line 15 column 3
```

- **1.5.5 golden**: `expected one of` `signing_key`, `chain`, `admin_auth`,
  `role_bindings`, `key_ttl` (5 members).
- **1.6.0 (derived)**: `operator_pub` is inserted at position 2. `serde`'s
  `deny_unknown_fields` list follows struct field declaration order, and the frozen parse
  struct `AuthCfg` now declares `signing_key` (`crates/busbar-substrate/src/config/auth.rs:357`),
  then `operator_pub` (`:367`), then `chain` (`:370`), `admin_auth` (`:373`),
  `role_bindings` (`:375`), `key_ttl` (`:382`). Exit code (1) and the leading `unknown field
  \`bogus_key\`` are unchanged.

**Root-cause analysis.** **Genuine need, not laziness.** `auth.operator_pub` is the D38
production operator-sealing key (the reference to the pre-provisioned ed25519 operator
public key used to verify signed money-governance actions such as `amend_rate_history`;
`crates/busbar-core/src/preflight.rs:582-630`, `config_validate/secret_refs.rs:267-283`,
schema snapshot `config/config-schema.snapshot.json:168`). It is a real, deliberate 1.6.0
feature. The divergence is a *consequence* of adding a legitimate optional field to the
config grammar.

Notably, this cell was previously part of the accepted `F-013` register and was **dropped**
on 2026-09-05 by the plane-key-lift fix: the 1.6.0-additive keys (the plane sections and
`auth.policy`) are lifted off the document by `config::prepass` **before** the frozen
1.5.5-shaped parse, restoring the `auth:` list to byte-identity (see
`testing/shadow-oracle/findings-2026-09-04.md`, F-013 "NARROWED 2026-09-05", and
`docs/design/1.6.0-TRACKER.md:157`). `operator_pub`, however, was added directly to the
frozen `AuthCfg` struct rather than being lifted in the prepass, so it re-opens NEUT-U-auth.

**Classification.** **MINOR** (additive) — a new optional field appended to the schema; the
five 1.5.5 members are unchanged and a 1.5.5 config keeps validating. (The observable byte
is a mid-list insert into an existing error line, but the change to the schema itself is
purely additive.)

**Recommendation.** **Owner-sign-off-with-rationale**, OR fix-at-root for byte-identity —
the owner picks the neutrality posture:
- **(a) Sign off as `improvement`** — accept the additive `operator_pub` in the `auth:`
  list; add an `accepted-differences.json` entry (re-widening the F-013 cell regex to
  re-cover `NEUT-U-auth`) with a `CHANGELOG.md` line (e.g. *"`auth.operator_pub`: reference
  to the operator ceremony public key (D38 production sealing)."*). Honest "we added a real
  field" path.
- **(b) Fix-at-root for byte-identity** — lift `operator_pub` in `config::prepass` the same
  way `auth.policy` is lifted, keeping the `auth:` `expected one of` list byte-identical to
  1.5.5. This is the more consistent choice given the deliberate 09-05 plane-key-lift
  neutrality decision, and needs no register entry.

Either is defensible; this is a genuine owner call, **not** laziness to fix silently.

---

## Packet 4 — `BOOT-135` truncated-tarball error wording

**Cell / id.** `boot.refusal|BOOT-135|boot`
(`testing/shadow-oracle/cells.json:12958`, `config: mutation:BOOT-135`; mutation at
`testing/shadow-oracle/fixtures/boot-mutations.json:3667`; golden at
`testing/shadow-oracle/golden/1.5.5/cells/boot.refusal__BOOT-135__boot.json`; owed at
`testing/shadow-oracle/owed-baseline.txt:386`). The mutation enables plugins and truncates
the published `busbar-webrequest-1.0.6` tarball to 200 bytes in `plugins.dir`; the boot
must refuse (`exit 1`) because `scan_and_validate` cannot read the tarball's manifest
member.

**Exact diff (1.5.5 golden vs derived 1.6.0).** The stderr second `[error]` line's trailing
error text:

```
 [error] plugin validation failed:
-  - invalid plugin '<WORK>/plugins/busbar-webrequest-1.0.6-<TRIPLE>.tar.gz': cannot read manifest member: unexpected end of file
+  - invalid plugin '<WORK>/plugins/busbar-webrequest-1.0.6-<TRIPLE>.tar.gz': cannot read manifest member: <new archive-lib EOF message>
```

- **1.5.5 golden**: `… cannot read manifest member: unexpected end of file`.
- **1.6.0 (derived)**: busbar's own wrapping is **unchanged** — the outer
  `plugin validation failed:\n  - {joined}` (`crates/busbar-core/src/preflight.rs:215`), the
  per-plugin `invalid plugin '{}': {reason}` (`crates/plugin-loader/src/registry.rs:659`),
  and the read wrapper `cannot read {what} member: {e}` (`crates/plugin-loader/src/tarball.rs:114`)
  are all byte-stable. The divergence is confined to the interpolated `{e}` — the underlying
  archive/decompress read error whose text is produced by the (upgraded) `tar`/decompression
  dependency, not by busbar. Exit code (1), the `BOOT-135` diagnostic, the outer wording, and
  the tarball path are all unchanged.

**Root-cause analysis.** **Genuine, not laziness.** busbar's error-construction bytes are
identical to 1.5.5; only the third-party error string interpolated at `tarball.rs:114`
moved with a dependency version. This is the same class as the already-accepted **BOOT-141**
("download error text is reqwest's new wording") folded into `F-013`
(`testing/shadow-oracle/findings-2026-09-04.md`). Same refusal, same exit, same diagnostic
code — a wording-only delta on a dependency-owned substring.

**Classification.** **MINOR** — wording-only; it modifies an existing error line's trailing
substring but changes no field, value, status, or exit code, and a 1.5.5 operator sees the
same refusal at the same gate.

**Recommendation.** **Owner-sign-off-with-rationale** — accept as the twin of BOOT-141: add
an `accepted-differences.json` entry for `boot.refusal|BOOT-135|boot`, ideally with a
line-precise `transform.candidate` regex that rewrites the dependency's EOF phrase back to
`unexpected end of file` before the diff (so the cell reports **ACCEPTED**, and any *other*
future change to that line still shows as RED), plus the register's required `changelog`
line (or an explicit `changelog: null` + `changelog_reason` for a pure dependency-text
delta). Alternatively, if the owner wants strict byte-identity, normalize/pin the archive
EOF message at the read site. Confirm the exact 1.6.0 `{e}` text on a CI/linux record before
writing the transform regex.

---

## Packet 5 — `neutrality|boot-lines` `<PORT>` / listening-line flake (harness, not a divergence)

**Cell / id.** `neutrality|boot-lines`
(`testing/shadow-oracle/cells.json:30716`; defined in
`testing/shadow-oracle/cells/__init__.py:1468` — `mode="boot"`, `config="baseline"`,
`env RUST_LOG=info`; golden at
`testing/shadow-oracle/golden/1.5.5/cells/neutrality__boot-lines.json`; owed at
`testing/shadow-oracle/owed-baseline.txt:845`). The cell captures the full INFO boot banner
on a 1.5.5 config and pins the neutral INFO set.

**Exact diff (nature of the flake).** The golden `body.text` contains **two identical
adjacent lines** after `<PORT>` normalization:

```
<TS>  INFO busbar listening listen=127.0.0.1:<PORT>
<TS>  INFO busbar listening listen=127.0.0.1:<PORT>
```

(the data listener and the admin listener). The cell's `applied` normalizers are
`["body.keep-lines","boot.exhaustion-order","boot.pool-order","text.port"]`. There is a
`boot.pool-order` / `boot.exhaustion-order` sort for the pool lines and a `text.port`
substitution for `<PORT>`, but **no order-normalizer for the two `busbar listening`
lines**. When the two listeners bind/log in a run-to-run nondeterministic order (or the
per-listener port assignment races), the recorded pair can swap or a raw port can slip the
`<PORT>` mask, producing a spurious byte diff on re-record — a **flake**, not a change in
busbar behaviour.

This is distinct from the already-fixed B14 regression (a voice line, a thread-per-core
line, 18 listening lines and three dropped pool-exhaustion lines on a 1.5.5 config; fixed
`d82ace56`, pinned by `crates/busbar/tests/boot_lines_neutrality.rs`,
`docs/design/1.6.0-TRACKER.md:190`). B14 was a genuine neutrality regression and is closed;
this remaining item is purely the port/listen-line recording nondeterminism.

**Root-cause analysis.** **Harness, not busbar.** The finders' own harness notes already
document that the 1.5.5 binary emits banner lines in map order and that `normalize.py`
sorts pool/error/key listings in place so "every rule fires on both sides"
(`testing/shadow-oracle/findings-2026-09-04.md`, "Harness facts"). The two `busbar
listening` lines are the one banner group that lacks such a sort rule. This is an oracle
stabilization gap — the "no retry may hide a red" flake policy
(`docs/design/store-qa-cycle.md:633-652`) says such nondeterminism is handled *by
construction* (a normalizer), not by tolerance.

**Classification.** **n/a** — this is not a product divergence (no MINOR/MAJOR applies); it
is a harness normalization defect.

**Recommendation.** **Flake-stabilize** — add a deterministic normalizer for the listening
lines (e.g. a `boot.listen-order` sort of the adjacent `busbar listening listen=…` lines,
mirroring `boot.pool-order`) and ensure `text.port` masks every `127.0.0.1:<port>` on those
lines, then re-record. **Do NOT bring for owner sign-off** — signing a harness flake would
launder a construction gap into an accepted product difference. This is a
harness-laziness-to-fix.

---

## Disposition roll-up

- **Fix-at-root (do not sign off):** #1, #2 (`PutConfigSettings` `reload_to_apply`
  omit-when-empty drift — MAJOR wire regression).
- **Flake-stabilize (do not sign off):** #5 (`boot-lines` listen/port normalization gap —
  harness).
- **Genuine sign-off candidates (owner call, one at a time):** #3 (`NEUT-U-auth`
  `operator_pub`, MINOR/additive — accept as `improvement` **or** prepass-lift for
  byte-identity) and #4 (`BOOT-135` dependency wording, MINOR — accept as the BOOT-141 twin
  with a `transform` regex, **or** pin the message).

Nothing here may report as a silent PASS. Every accept must land in
`testing/shadow-oracle/accepted-differences.json` with an owner byline (and a `CHANGELOG.md`
line where the class requires one); every fix must re-record byte-identical; the ship gate
stays **zero UNACCEPTED divergences**.
