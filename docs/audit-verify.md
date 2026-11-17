# Verify an audit range offline

`busbar-audit-verify` verifies captured audit API responses without starting the busbar server,
loading plugins, contacting a node, or reading any signing secret. It uses the published
[v2](audit-chain-digest-v2.md), [v4](audit-chain-digest-v4.md), [v5](audit-chain-digest-v5.md),
[v6](audit-chain-digest-v6.md), [v7](audit-chain-digest-v7.md), and
[link-v1](audit-link-v1.md) digest contracts, SHA-256 and strict Ed25519 verification.
The recipe pages are embedded in the executable. Linked windows support direct
Bootstrap-signed page stamps and break notices. Delegated certificate/authority proofs
are not supported; this is not the complete SF4 verification protocol.

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

For a linked window, `--keys` must contain exactly one key that you have independently
established is the **deployment Bootstrap key authorized for the node being checked**.
Authenticating a public key alone does not establish that role. An authentic delegated key,
an arbitrary one-row `/keys` response, or a stamp declaring `key_cert:0` is insufficient.
This key-to-deployment/node authorization is your trust premise; the tool cannot derive it
from the untrusted range. Legacy individually signed windows continue to accept multiple
independently trusted keys.

The tool cannot establish the provenance of a file you mark trusted. Downloading keys and a head
alongside a range from an untrusted party supplies no independent trust. The range's own `anchor`
is never treated as an external anchor. For legacy windows, if its record is included, all five head fields are checked
against that record. For a source anchor before the window, only its digest signature can be
checked: its sequence and clock are not independently authenticated by that signature.
For linked windows, a non-null anchor must exactly equal one supplied page stamp. A stamp's
optional `seq`, `hash`, and `wall` aliases must agree with its signed `to`, `fingerprint`,
and `stamped_ms / 1000` fields. The same check applies to a separately trusted stamp head.

Exit status **0** means the checks completed without invalid evidence. A linked window can still
be partially or wholly unauthenticated: inspect the result and coverage fields. Standard output
is one JSON object containing the inclusive `from` and `to`, record count, `starts_at_genesis`,
and one of these results:

- `signed-consistent-window`: for legacy windows, every requested record has a valid signature
  under the supplied trusted keys. For linked windows, at least one requested record is
  authenticated, either by its legacy signature or by a checked Bootstrap page and the digest/link
  walk through that page's endpoint. Check `all_requested_records_authenticated`,
  `authenticated_records`, `breaks`, `unauthenticated_tail`, and `unchecked_stamps` before treating
  a linked window as fully authenticated. All returned and covering records must match their
  digests and have consecutive positions and links.
  This says nothing about omitted records outside the window. Rewriting the unsigned range bounds
  can disguise a truncated chain as a shorter window.
- `complete-through-trusted-head`: every requested record is authenticated and the independently
  retained terminal head matches. Legacy heads match position, hash, signature, key identifier and
  wall clock. Linked heads match every signed page field and each supplied alias; no requested
  position may be in a break, and no stamp may remain endpoint-unchecked.
  Completeness applies **only from the reported start through that head**. A window starting after
  genesis proves nothing about earlier retained records; the first predecessor is taken as given.
- `null`: the linked digest/link walk is consistent but no requested record is authenticated.
  A valid break signature does not authenticate any record. An endpoint outside the downloaded
  records and cover is counted in `unchecked_stamps` and grants no coverage.

Linked reports set `authority_mode` to `caller-trusted-deployment-bootstrap-for-node` and
`delegated_authority_supported` to false. A page authenticates only the suffix actually walked
through its endpoint, never an unwalked prefix. `pages`, `final_pages`, and `restart_sealed` count
checked pages intersecting the requested window. A signed break explains an unsealed interval;
it does not repair missing authentication. Empty signed break intervals report an observation
without assigning any line. Overlapping pages, page/break overlap, and gaps between pages without
signed break evidence are refused. Supplying `--trusted-head` with incomplete evidence fails.

Every report sets `freshness_verified` and `source_anchor_is_external_trust` to false. An old trusted
head proves an old prefix, not that it is the current tip. A signature proves possession of the
signing key, not an honest clock or absence of events that were never recorded. A key holder can
rewrite and re-sign a chain; an independently preserved head detects rewrites affecting its prefix.

Exit status **1** means an input or verification failed; the reason is written to standard error.
A short API response is reported as an incomplete requested fetch, not automatically as tampering.
The API allows short responses, but this tool requires the exact requested window. It refuses an
empty requested window because there is no signed record to verify. Fetch the retained window up
to the independently recorded head before using completeness mode.

Unknown recipe versions, signature domains and algorithms are refused. A linked envelope uses
`recipe:"busbar.audit.link.v1"`, `signature_domain:"busbar.audit.stamp.v1"`, and the established
signature algorithm. Its `records` contain the exact requested window; `cover` contains a
consecutive authentication suffix immediately afterward; `stamps` contains complete signed pages
and break notices (`kind:"break"`). Page and break integers are JSON integers; record integers
remain canonical decimal strings. Missing or rewritten signed fields fail verification.
Certificate chain records and stamps with nonzero `key_cert` are refused. Sparse `certs`, supplied
WAL positions, or a claimed `authority_complete` flag never establish delegated authority.
V2 records may inherit
their recipe from a v2 envelope, as in the original published API. V4 to V7 and mixed windows require
each record's recipe. Recipe numbers must be canonical decimal strings, preserving full u64
precision; group counts must match array lengths. A linked fingerprint includes the optional v7
records tail when present. Unsigned linked records cannot pass authentication without a checked page.
Only the fields defined by the published recipe are digested; unrelated JSON additions are not
authenticated by an audit signature.

For source distributions, build the independent tool with
`cargo build --locked --release -p busbar-kernel-audit --bin busbar-audit-verify`.
No busbar server configuration or running deployment is needed to use the resulting executable.
