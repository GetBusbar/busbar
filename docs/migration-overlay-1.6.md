# Importing a released 1.5.5 configuration overlay

Stop the old deployment and retain its configuration, providers catalog, overlay and database backup. Run the new binary with the old launch environment available to the one-time migration commands. Use a distinct output file and keep it private:

```sh
umask 077
busbar --migrate-config /deployment/config.yaml > /deployment/config-1.6.yaml
busbar --config /deployment/config-1.6.yaml --migrate-overlay /deployment/config.yaml
busbar --config /deployment/config-1.6.yaml
```

The configuration command captures the effective historical Store selection from `overlay.root.store` into the new base YAML. This is necessary because 1.6 opens that Store to recover its overlay. It also captures supported retired environment values and performs plugin-owned settings migrations. It preserves the original files. Review any reported operator decisions before starting the new deployment; do not redirect output over the source file.

The overlay command selects the file using the actual 1.5.5 precedence: explicit `config.overlay.file` relative to the old configuration directory, otherwise `BUSBAR_CONFIG_OVERLAY` relative to the old process working directory, otherwise `busbar-overlay.json` beside the old configuration. Keep the same working directory when the old deployment used relative paths. An old locked deployment or missing overlay requires no import and returns `not_required`.

The importer retains hooks, global wiring, groups, tombstones, root controls, named definitions and explicit plugin floors. It normalizes old hook keys only in this command and invokes the current plugins' migration and pure settings-validation operations. An unknown, ambiguous or invalid source is refused rather than partially imported. A real overlay requires a Store instance that confirms durable persistence and supports atomic conditional records. The effective configuration is resolved and validated before publication.

The overlay and its source/conversion digest receipt commit in one Store transaction. The old files remain untouched. An interrupted import can be retried with the same source and converted settings. A successful retry reports `already_applied`; it does not replay the old overlay over later administrative changes. An unrelated existing destination or different source/conversion is refused. The command exits before opening listeners. Receipts and normal output contain hashes and status, never historical secret literals.

Literal secrets requested by a plugin's migration are externalized using the protected, retry-safe files described in [migration-secret-files.md](migration-secret-files.md). Empty or trailing-CR/LF literals require explicit operator handling because the current text resolver cannot preserve those values exactly. File preparation can precede a later validation failure; the original configuration remains unchanged, and a retry reuses only identical private artifacts. Do not remove the resulting files while migrated configuration refers to them.

Normal 1.6 startup reads the configured Store and current YAML only. It does not consult an old overlay file or retired environment selectors. Bootstrap opens the base Store before resolving overlay-owned definitions; the complete recovered configuration must pass normal validation before any listener opens. Preserve the existing signing-key SecretRef to continue accepting valid existing signed keys. Revocations, expiry, limits and accounting remain in the original Store; the overlay command does not recreate or reset them.

Released 1.5.5 had Store-backed audit/usage data and one effective rate card, not dated historical rate cards or a deployment keyset file. Keep that effective card, including its overlay values, as the opening current card. Identity transitions that require trusted historical IDs remain explicit cold maintenance; a mutable username is not sufficient evidence to invent a stable numeric identity.
