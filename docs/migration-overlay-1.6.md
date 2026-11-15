# Upgrading a released 1.5.5 deployment that used a configuration overlay

1.6.0 has no `--migrate-config` and no `--migrate-overlay`. The first boot of a 1.5.5 `config.yaml` migrates it in place; nothing else is run. Stop the old deployment, keep a backup of its configuration, providers catalog, overlay and database, and start the 1.6.0 binary on the same files with the same launch environment.

```sh
busbar --config /deployment/config.yaml
```

The boot reads `config.yaml`. A config that carries no `config_version` is a 1.5.5 config: the boot writes the migrated file once, in place, with `config_version: 1`, keeps the original beside it as `config.yaml.1.5.5`, and then serves. A config that already carries `config_version` is read as written. The 1.5.5 overlay, when the deployment used one, is folded into `config.yaml` on this one upgrade boot and the file it came from is kept beside the original as `<overlay>.1.5.5`.

Run the first boot from the directory the old deployment was launched from when it used relative paths, so the overlay and providers files resolve as they did. The deployment's directory must be writable for the first boot; a read-only one is refused with the reason, before anything is written.

Review what the boot reported: every change, the decisions it could not make for you, and the overlay file it folded. Do not delete `config.yaml.1.5.5` until the new deployment has served.

Normal 1.6 startup reads the configured Store and current YAML only. It never applies an old overlay file or a retired environment selector. Preserve the existing signing-key SecretRef to continue accepting valid existing signed keys. Revocations, expiry, limits and accounting remain in the original Store.

Released 1.5.5 had Store-backed audit/usage data and one effective rate card, not dated historical rate cards or a deployment keyset file. Keep that effective card, including its overlay values, as the opening current card. Identity transitions that require trusted historical IDs remain explicit cold maintenance; a mutable username is not sufficient evidence to invent a stable numeric identity.

## Serving checks for an overlay file that was not folded

Serving still answers for the overlay file 1.5.5 would have read, chosen by the 1.5.5 precedence from the deployment being served (relative to its directory). Messages name the file and how it was selected, never its settings.

- The file holds settings and this Store has no import receipt: serving refuses to start with BUSBAR-3027. The upgrade boot folds a 1.5.5 overlay into `config.yaml`; a `config.yaml` that is already migrated no longer reads it. Re-apply the settings you still want through the admin API (on a durable Store), keeping a copy of the file first, or move the file away to abandon the settings deliberately.
- The file exists but cannot be read (not a regular file, over 64 MiB, not valid JSON, duplicate keys) or this Store's import state cannot be read: serving refuses, because it cannot prove that nothing would be lost.
- The file was folded or imported earlier (a receipt exists), holds no settings, or a `config.overlay` selector or `BUSBAR_CONFIG_OVERLAY` names a file that does not exist, or the configuration is locked (1.5.5 ignored the file too): serving starts with a BUSBAR-3028 warning. Remove the leftover file and the variable from the launcher.
- `--safe-mode` never refuses; it prints the same message as a warning.
