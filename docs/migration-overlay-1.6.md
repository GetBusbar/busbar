# Upgrading a released 1.5.5 deployment that used a configuration overlay

1.6.0 has no `--migrate-config` and no `--migrate-overlay`. The first boot of a 1.5.5
`config.yaml` migrates it in place. Follow the stop, backup and artifact prerequisites in the
[upgrade guide](migration-1.6.md#upgrade), including the additional full-stop requirements for
[shared core record-format changes](migration-1.6.md#shared-datasets-with-a-changing-core-record-format).
The development upgrade procedure still requires release-candidate qualification. The
[source notes](migration-1.6.md#source-notes) pin the migration implementation inspected here;
they do not qualify a Store backend or a release artifact.

```sh
busbar --config /deployment/config.yaml
```

Keep the old secret sources and working directory available. Mount the configuration directory
writable for migration's file replacements and sibling backups; a single-file mount does not
support those replacements. Keep `BUSBAR_PROVIDERS`, if used by 1.5.5, through this first boot
so migration captures the same catalog; do not pass `--providers` on an unstamped boot.
`--validate` does not perform this conversion. A later startup refusal can follow Store changes
or created secret/catalog files, so it does not prove that returning to 1.5.5 is safe.

## Selection and folding

The upgrader selects `config.overlay.file`, otherwise a nonempty `BUSBAR_CONFIG_OVERLAY` when
the selector is absent or null, otherwise `busbar-overlay.json` beside the config. Relative
`config.overlay.file` paths resolve beside the config; an environment-selected relative path uses the working
directory. A locked configuration has no overlay. A file 1.5.5 could not write was not read
by that version and is not folded. Review the report naming the selected absolute path and
whether it was folded, absent or not writable; investigate an unexpected absence.

For a mutable config, `config.overlay: false`, `true` or `{file: null}` refuses with guidance
rather than selecting the default file; 1.5.5 refused those forms too. A locked config skips
overlay selection. Values containing a literal `${` refuse folding because moving them into
interpolated YAML would change their meaning; preserve the original and resolve the named value
deliberately. Migration does not guess a replacement value.

Recognized settings, definitions and removals are folded with their old semantics. Conflicting
definitions, invalid recognized shapes and unsupported default-hook ordering refuse instead
of guessing. Unknown top-level keys in an otherwise valid overlay are dropped and reported
by name, as 1.5.5 ignored them. This rule does not permit unknown current configuration or
plugin settings. Old plugin rollback pins are also dropped and reported: their 1.5.x artifacts
cannot load on the new ABI.

Invalid JSON, duplicate JSON keys, unsupported versions, an oversized file (over 64 MiB) or
an unreadable selected file refuses migration. Resolve the refusal or deliberately preserve
and move aside the unwanted file before retrying. Do not use `--ignore-overlay` to bypass
settings that still need folding; it refuses an upgrade with such an overlay.

## Handoff and recovery

The plan checks existing config and overlay backup conflicts before opening instances. The
final write checks them again under its directory lock, so a new conflict or a later failure
can still happen after Store conversion. Preserve the Store snapshot and every recovery file;
an unchanged `config.yaml` is not evidence that no other write occurred.

After instance conversion, core-record processing and successful write-back, the accepted
configuration carries `config_version: 1` and the process re-executes onto it. The original
configuration remains at `<config>.1.5.5`. A matching stamp skips the one-shot file migration;
a newer unsupported stamp refuses startup. Do not add a stamp to bypass conversion: it does
not establish that the Store has the current format.

The original overlay bytes remain at `<overlay>.1.5.5`; its old path is guarded by a directory
containing `busbar-1.6-folded`. Keep that guard while an old executable could still launch.
An interrupted fold can leave `<overlay>.busbar-folding`. If both an ordinary overlay file and
a folding copy exist, stop all writers and reconcile the snapshots; do not delete one to
force progress. Preserve recovery files until the deployment and any rollback are verified.

A stamped boot reads current YAML and the Store overlay, never the old file or its selector.
`--safe-mode` is removed. After migration, `--ignore-overlay` reads the base configuration
alone and leaves the Store overlay intact; omit it to apply the stored configuration again.

Preserve the existing signing-key reference and material, revocations, expiry, limits and
accounting in the original Store. Released 1.5.5 had one effective rate card rather than dated
card history; retain that card, including its overlay values, as the opening current card.
Identity transitions needing trusted historical IDs remain explicit cold maintenance; a
mutable username cannot establish a stable numeric identity.

Verify `GET /readyz`, administrative access, supported traffic and Store recovery before
accepting the upgrade. For rollback, stop the new cohort and restore the complete Store and
configuration snapshot together, including the old overlay path. Restoring only the YAML
backup does not undo Store changes. See [rolling back](migration-1.6.md#rolling-back).
