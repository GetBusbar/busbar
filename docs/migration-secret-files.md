# Credential files created during config migration

The migration host can replace a plugin's old literal credential setting with an explicit file
SecretRef when that plugin requests it. This happens only during migration. Serving does not create
credential files or reinterpret literal values as paths.

On Unix, generated files live in `.busbar-migrated-secrets` beside the input configuration. The
directory must be owned by the current user with mode `0700`; credential files must be regular,
current-user-owned files with mode `0600`. File names identify the public configuration site and
setting path, using a digest that does not contain or depend on credential bytes. The returned file
reference is absolute. Existing source configuration is left unchanged.

Credential bytes are copied exactly, including literal `${...}`, newlines and trailing bytes.
No environment interpolation occurs in this operation. A repeat migration reuses an existing file
only when its bytes and permissions match. A different credential at the same site is refused;
the writer never overwrites an existing artifact. An interrupted publication may leave a private
`.pending-*` entry; retry can reuse the matching published credential. Preserve generated files as
part of the deployment's private credentials when moving or backing up the migrated config.

Symlink components, symlink artifacts and insecure existing artifact permissions are refused.
Use the real, symlink-free absolute path to the old configuration when migrating. On filesystems
that cannot provide atomic hard-link publication and directory synchronization, automatic conversion
fails instead of publishing an unverified file.

Automatic file creation is refused on Windows because this helper cannot establish and verify a
private Windows ACL. For Windows, or after a refusal that requires operator action, provision a
credential file with the platform's private access controls, copy the exact original credential bytes
without shell or environment expansion, and set the plugin's credential setting to an explicit file
SecretRef such as `{file: 'C:\private\service-credential'}`. On Unix the corresponding manual file
must be owned by the deployment user with mode `0600` in a private directory. Validate the resulting
configuration before deploying it. Migration errors and reports do not include the credential bytes.
