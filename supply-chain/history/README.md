# Historical cargo-vet attestations

These files preserve the local review evidence removed from active trust for
[core #390](https://github.com/GetBusbar/busbar/-/issues/390). They are inert
text snapshots, **not cargo-vet imports, audits, exemptions, or certification**.
Do not import them into either store.

The baseline is core commit `dde67baae1`. DEP-5 permits imported audit sets and
trusted publishers, with only the existing `aws-lc-rs` and `fastrand` local records
grandfathered. The root store contained 29 records; the default integration store
contained 20. The root retains `aws-lc-rs 1.19.0` and `fastrand 2.5.0`; default
retains its existing `aws-lc-rs 1.19.0`. All 46 other records are historical only.
No replacement exemption or dependency version/source change accompanies this
reconciliation. Existing imports, exemptions, and `audit-as-crates-io` policies
are preserved; an uncovered Git revision must not become implicitly first-party.

The repository's `busbar-ci-checks` tests compare each entire active audit file
with the exact grandfathered records from these snapshots. Additional full,
delta, wildcard, or differently spelled TOML records cannot pass that comparison.
The tests preserve record identity and content, not just an allowed package name.
New trusted-publisher configuration requires a deliberate corresponding policy
test change; this reconciliation adds none.

## Evidence identity

| Snapshot | SHA-256 of complete file |
| --- | --- |
| `core-audits-before-dep5-390.txt` | `27a44cb7a67008f23e8db4330f1f9aec8b18f069ebe447b8db18f7bbad97cebc` |
| `default-audits-before-dep5-390.txt` | `6c999d7c170ad3b6b5a06cc1fd4652e9bfddcc4b5891f9d481650a8d0b0fb2f7` |

`local-records.tsv` inventories every historical record and its disposition.
Its record digest covers the literal `[[audits.NAME]]` record through its last
non-whitespace byte, followed by one newline. The retained record digests are:

| Record | SHA-256 |
| --- | --- |
| `aws-lc-rs 1.19.0`, both stores | `08ce7fd17dc0f0066837f61a7b29f2d69c20d8cc9b3bd846a99c24948ebd2010` |
| `fastrand 2.5.0`, root only | `58645f9ee3adf9cdd7fdf8ca9f9e1f72ea6163e831a8262722af6744fc292a8d` |

## Coverage remains outstanding

`coverage-gaps.tsv` identifies the 13 root and 14 default locked dependency
identities affected by the removed records that have neither an exact existing
exemption nor a grandfathered record. The committed import stores contain no
audit or trusted-publisher records for these package names. This is a static
inventory at the baseline commit, not a cargo-vet execution result or a complete
inventory of unrelated coverage gaps. Future lock/import changes require fresh
resolution in CI.

The [2026-11-17 imported-coverage follow-up](imported-coverage-follow-up.md)
records the exact upstream chain subsequently restored for pkg-config 0.3.34 in
both stores, immutable source identities, and the remaining 12 root/13 default
gaps. The baseline TSV remains historical; the follow-up is not a green vet result.

Some removed records were already disconnected from the actual graphs:
`constant_time_eq` is absent from both locks; `fancy-regex` remains at exempted
`0.19.0`; `oauth-as` is exempted at `1.1.0`; root `olpc-cjson` has an existing exact
Git exemption. Root no longer locks `stringprep` or `unicode-properties`. Default
locks a newer `stringprep` Git revision than its local attestation, and its local
YAML attestations stop before the locked `granit-parser`/`serde-saphyr` revisions.
Those historical records must not be described as current coverage.

Policy restoration is not a green vet result. #390 remains open until approved
imported/trusted-publisher coverage or individually justified dispositions exist
for the remaining identities and both exact stores are qualified in GitLab CI.
The coordinator owns CI execution; no local build, test, or cargo-vet run is part
of this reconciliation.
