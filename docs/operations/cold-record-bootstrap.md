# Cold record bootstrap

A plugin rebuilding durable aggregate metadata may ask the existing service
`Services.entitled(handle, "record-quota-bootstrap:")`. This is a host capability,
reserved before ordinary principal scopes. It is false unless the process operator
has supplied a valid cold-bootstrap receipt for that instance. No plugin ABI changes
or protocol-specific record interpretation are involved.

The supported migration procedure requires a maintenance boundary. Stop **every** old
writer to the selected record namespace, including other nodes, and settle or abort
all of their outstanding backend transactions. Fence those producers for the entire
bootstrap. An unloaded plugin, cancelled request, expired lease, stopped process, or
empty local write queue does **not** prove the remote database has stopped its commands.
The operator explicitly attests both sender and backend quiescence; the host cannot
independently verify those external facts. This is the same trust boundary as operator
recovery attestations. Do not issue a receipt while either fact is unknown.

While that boundary holds:

1. Identify the effective store configuration and the instance label. Capture a stable,
   public identity row from the actual backing database/namespace using its operator
   tooling. Its schema, raw key, and raw value form the store witness. If the fresh
   store has no identity row, provision a random identity row with trusted store tooling
   during maintenance. The witness must be present and unique to that store, not an
   absent row or a shared constant. Never use a credential as the witness.
2. Create a private, operator-controlled JSON receipt. The format is below. Use a fresh
   random 16-byte epoch for every attempted cold boot. The namespace is the hex of
   `u16_be(instance_utf8_length) || instance_utf8`. The store fingerprint is SHA-256 of
   the compact JSON serialization of the final effective `store` object (module and
   settings, after configuration resolution), computed by
   `busbar_kernel::host_record_bootstrap::store_fingerprint`.
3. Launch the new process with `BUSBAR_RECORD_BOOTSTRAP_RECEIPT=/absolute/receipt.json`.
   This input is read only during cold startup, after attaching the selected store and
   before admitting planes. Keep the old senders fenced. The host atomically compares
   the exact witness and consumes the epoch in `busbar.record-bootstrap.v1`; unknown,
   refused, replayed, and wrong-store results fail startup without a grant.
4. The intended plugin's normal startup/request path may now initialize its metadata.
   The host binds the grant to its exact loader caller and first admission. Repeated
   callbacks in this generation keep the grant. A hot re-admission or different caller
   identity is refused; this includes otherwise identical instance/plugin names.
5. After the plugin publishes its durable ready metadata, stop this migration process
   normally and remove the receipt environment setting for the next ordinary boot.
   Ready metadata uses the plugin's ordinary durable conditional-write path and needs
   no bootstrap grant. A failed/interrupted bootstrap requires renewed quiescence and
   a **new** receipt epoch on the next cold boot. Never delete/reset quota metadata to
   bypass this procedure.

Example shape (replace every placeholder with measured values):

```json
{
  "version": 1,
  "epoch": "32-lowercase-hex-digits-from-16-random-bytes",
  "instance": "configured-instance-label",
  "namespace_hex": "hex-of-length-prefixed-instance-label",
  "store_config_sha256": "sha256-of-effective-store-json",
  "store_witness": {
    "schema": "operator-chosen-public-identity-schema",
    "key_hex": "hex-of-existing-identity-key",
    "value_hex": "hex-of-existing-nonempty-identity-value"
  },
  "sender_quiesced": true,
  "backend_quiesced": true,
  "actor": "maintenance-operator",
  "reason": "maintenance reference and evidence of sender/backend settlement"
}
```

The receipt is capped at 16 KiB and rejects unknown JSON fields. Retain the private
receipt and startup log for the maintenance audit. Consumed epochs persist globally
within the selected store, including after crashes, and cannot be reused under another
instance. Plugins cannot declare the receipt schema, and host record purging refuses
it. Restoring a database backup also restores its consumed-receipt history: treat that
as another maintenance operation and issue fresh epochs; never replay old receipt files.

This capability proves authorization for the supported cold procedure. The plugin still
owns the durable initializing gate, exact counter/task predicates, bounded complete
listing, replay handling, and transition to ready. It does not permit an online rebuild
beside old prepared writes, and it does not grant unrelated instances any authority.
