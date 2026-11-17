# Complete selected-attempt audit links

`busbar.audit.link.v2` is `Recipe::V9`, persisted as `audit.v9`. One line retains
one logical unit's complete ordered session/preparation history. The four diagnostic
attempt slots remain separate. V9 carries no per-line signature: authenticated page
coverage must bind its exact canonical fingerprint and original journal identity.
The presence of a line or an unverified stamp is not proof of coverage.

## Canonical hash

Use SHA-256. Frame every field as its byte length (u64 big endian) followed by
its bytes. Text is UTF-8; numeric field bytes are u64 big endian; the predecessor
is 32 raw bytes, with zero bytes at genesis. Do not insert an intermediate content
digest. The exact sequence is:

1. `link_recipe` text, literal `busbar.audit.link.v2`.
2. Existing V8 content from `subject_tag` through `attempts_total`, in
   `recipe::visit_content` order. `lines_count` must be zero.
3. Mandatory `user_present` number, `user` text, `labels_count` number, then
   ordered `labels[].name` and `labels[].value` texts. Absent user is `0,""`;
   empty labels still carry their zero count.
4. The billing fields below, as emitted by `PartitionedBillingV1::visit`.
5. Existing trailer: `linked_ms`, `seq`, raw `prev_hash`.

Billing common fields, in order (N numeric, T text):

```
billing_version N (=1)
billing_revision N
billing_request_pool T
billing_routing_generation N
billing_era_at N
billing_era_entry_present N
billing_era_entry T
billing_session_instance T
billing_session_lane T
billing_session_provider_present N
billing_session_provider T
billing_metered N
billing_logical_request T
billing_logical_preparation N
billing_fee_state T
billing_fee_lane_present N
billing_fee_lane T
billing_fee_era_at N
billing_fee_era_entry_present N
billing_fee_era_entry T
billing_disposition T
billing_reason T
billing_far_end_answered N
billing_caller_bytes_committed N
billing_final_target_present N
billing_final_target N
billing_partitions_count N
```

Each ordered `billing_partitions[]` row has:

```
scope T, preparation N, dispatch_present N, dispatch N,
kind T, instance T, lane T,
provider_present N, provider T,
selected_pool_present N, selected_pool T,
resource_present N, resource T,
transport T, finality T, classes_count N
```

Then `billing_classes_count N`, followed by each partition's classes in ascending
class-name order. Each `billing_classes[]` row has:

```
partition N, class T,
reported_present N, reported_count T,
floor_present N, floor_count T,
estimated_present N, estimated_count T,
selected_present N, selected_count T, selected_source T,
billed_present N, billed_count T, billed_source T,
rate_high_water T
```

`partition` is the zero-based partition index. All presence/boolean fields are
exactly 0 or 1. An absent text/count has an explicit empty text; an absent selected
or billed quantity also has empty source text. Counts are canonical nonnegative
exact decimals, including known zero. Sources are `reported`, `floor`, `estimated`;
an estimate can be selected but cannot be billed. Era identities are 24 lowercase
hex characters, or explicitly absent. Usage and fee eras are independent.

Scope is `session` or `attempt`; session ordinals are zero/absent. Preparation
ordinals are strictly increasing; committed dispatch ordinals are consecutive.
Target kinds are `session`, `model`, `registration`. Transport is absent for a
session, otherwise `prepared`, `committed`, `no_send`. Finality is `complete`,
`partial`, `unknown`. Logical request is `none`, `host_origin`, or
`delivered_preparation`; only the last has a nonzero logical preparation ordinal.
Fee state is `not_owner`, `charged`, `refunded`, `unknown`. Disposition is `end`,
`failed`, `cancel`, `recovered_running`; only cancel carries a nonempty reason.
Recovered unresolved fees remain unknown without rewriting the terminal disposition.

## Journal and read contract

Journal fields use existing u32 big-endian byte lengths, and u64 big-endian
numbers. Header: text `audit.v9`, text `busbar.audit.link.v2`, seq, raw prev32,
raw hash32, linked_ms. Then existing V8 journal content through attempts_total,
mandatory records block, billing tables, EOF. The recipe domain is supplied by
the header, not duplicated in the journal content. Wrong recipe/tag pairing,
extra bytes, noncanonical options or invalid bounds refuse the entire record.

Bounds: 256 attempts plus one session; 64 classes per partition and in their
distinct union; 4096 bytes per identity; 64 bytes per class using `[a-z0-9_.:]`;
4 MiB canonical billing extension; 16 MiB complete V9 journal body. Collections
and strings are bounded before allocation. There is no truncation or aggregate
pricing fallback. Full body writing is bounded before extending its buffer.

The audit export includes both full arrays and the mandatory records fields.
Admin `/records` emits `busbar.unit_record.v2` with structured `billing` evidence
only for V9. Each partition is priced with its captured lane and exact usage era;
the fee uses its original lane/base and exact fee era. Missing original entry
identity, conflicting effective date, unpriced class, arithmetic overflow, or
unknown fee withholds the total. Exact component amounts are summed before one
nano-unit projection. Component `priced_by` identities remain separate; the
legacy scalar is set only when every priced term uses the same entry.

V2/V4/V5/V6/V7/V8 framing and journal bytes remain unchanged. Their optional
records tail remains optional. Old item JSON omits `billing` entirely.

Selected activation also requires the explicit backend v2 registration,
standalone verifier grammar, complete immutable producer mapping, durable fee
completion, and shared authenticated coverage producer. These are integration
dependencies; this schema does not grant checkpoint-retirement authority.
