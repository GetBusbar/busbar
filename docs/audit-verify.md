# Verify an audit range offline

`busbar-audit-verify` verifies captured audit API responses without starting the busbar server,
loading plugins, contacting a node, or reading any signing secret. It uses the published
[v2](audit-chain-digest-v2.md) and [v4](audit-chain-digest-v4.md) digest contracts, SHA-256 and strict
Ed25519 verification. The recipe pages are embedded in the executable.

```sh
busbar-audit-verify --keys trusted-keys.json --range range.json
busbar-audit-verify --keys trusted-keys.json --range range.json --trusted-head retained-head.json
```

Inputs are ordinary JSON files containing the unmodified bodies from these reads:

| Option | Body | Trust requirement |
| --- | --- | --- |
| `--keys` | `/api/v1/admin/audit/keys` | Authenticate these public keys independently, using your deployment's established trusted channel or previously recorded keys. |
| `--range` | `/api/v1/admin/audit/range?from=START&to=END` | Untrusted evidence to verify. Request the exact inclusive window you intend to check. |
| `--trusted-head` | `/api/v1/admin/audit/head` | An independently retained terminal head whose origin and custody you trust. Its sequence must equal `END`. |

The tool cannot establish the provenance of a file you mark trusted. Downloading keys and a head
alongside a range from an untrusted party supplies no independent trust. The range's own `anchor`
is never treated as an external anchor. If its record is included, all five head fields are checked
against that record. For a source anchor before the window, only its digest signature can be
checked: its sequence and clock are not independently authenticated by that signature.

Exit status **0** means verification succeeded. Standard output is one JSON object containing the
inclusive `from` and `to`, record count, `starts_at_genesis`, and one of these results:

- `signed-consistent-window`: every requested record has a valid signature under the supplied
  trusted keys, its published digest fields match its hash, and positions and links are consecutive.
  This says nothing about omitted records outside the window. Rewriting the unsigned range bounds
  can disguise a truncated chain as a shorter window.
- `complete-through-trusted-head`: the same checks, plus the final record matches the independently
  retained terminal head, including its position, hash, signature, key identifier and wall clock.
  Completeness applies **only from the reported start through that head**. A window starting after
  genesis proves nothing about earlier retained records; the first predecessor is taken as given.

Both results set `freshness_verified` and `source_anchor_is_external_trust` to false. An old trusted
head proves an old prefix, not that it is the current tip. A signature proves possession of the
signing key, not an honest clock or absence of events that were never recorded. A key holder can
rewrite and re-sign a chain; an independently preserved head detects rewrites affecting its prefix.

Exit status **1** means an input or verification failed; the reason is written to standard error.
A short API response is reported as an incomplete requested fetch, not automatically as tampering.
The API allows short responses, but this tool requires the exact requested window. It refuses an
empty requested window because there is no signed record to verify. Fetch the retained window up
to the independently recorded head before using completeness mode.

Unknown recipe versions, signature domains and algorithms are refused. V2 records may inherit
their recipe from a v2 envelope, as in the original published API. V4 and mixed windows require
each record's recipe. Recipe numbers must be canonical decimal strings, preserving full u64
precision; group counts must match array lengths. Unsigned records cannot pass signed verification.
Only the fields defined by the published recipe are digested; unrelated JSON additions are not
authenticated by an audit signature.

For source distributions, build the independent tool with
`cargo build --locked --release -p busbar-kernel-audit --bin busbar-audit-verify`.
No busbar server configuration or running deployment is needed to use the resulting executable.
