// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

// Oracle transfer ledger: the former one-case test constructed an application
// with invented HookAxis/HookCalls, Export dispatch and a toggled RootRules.
// Its product obligations now run in the ordinary distribution composition:
// busbar/src/tests/admin_application/admin_hook_timeout.rs,
// timeout_only_admin_put_refreshes_the_actual_policy_atomically.
//
// - A timeout-only admin PUT changes 11ms to 29ms, atomically publishes the
//   real signed Webrequest policy, and leaves retained readers on the old App,
//   original policy Arc and original timeout.
// - A real invalid-URL Webrequest open refusal never publishes its candidate;
//   the live App Arc, definition and policy timeout remain unchanged.
// - An actual Prometheus ExportInstance keeps serving /metrics on the SAME
//   data listener after the hook update. Its descriptor retains Export kind,
//   source_instance sink-instance and the persistent scrape grant.
// - Zero and explicit default resolve the SAME actual cached policy Arc and
//   effective timeout. Private production-used hooks::same_call_inputs tests
//   additionally cover timeout/module/settings mismatches in the route, open
//   and gate reuse paths without constructing a fake axis.
//
// The old /hooks/receiver/{feedback,admin} bodies echoed fixture-assigned ids,
// open budgets and caller budgets; the exact open-counter values, literal
// retained-export response, and arbitrary RootRules refusal switch were
// fixture-only observations and are retired with explicit controller approval.
// The successful real reload follows build_with_hook -> rebuild_hook_derived ->
// RootRules::check_built (core-admin/src/v1/service.rs). This maps the former
// injected completed-count assertion to its actual production call path.
// The malformed-URL rollback proves no-publish behavior, NOT completed
// ListenerPlan refusal: physical-listener validation remains owned by the
// ordinary root listener tests. No claim of that separate runtime path is made.
