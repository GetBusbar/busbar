// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

// The ordinary data contracts are mounted beside keys.rs in admin_pure_contracts.rs.
// Actual application behavior now lives in busbar/src/tests/admin_application:
// - admin_hook_settings_ack: configure acknowledgment, committed names, schema shape.
// - admin_credential_cache: real OIDC cache flush, scope, selection, malformed input.
// - admin_openapi_route_parity: both directions of served route/document parity.
// - admin_stuck_key_sentinel: old in-flight mint/rotate refusal and unchanged Store.
// The nested configuration cases retain their original test names in:
// - config_store_overlay (all five original overlay custody cases),
// - config_price_activation (all five original price publication cases),
// - config_at_rest_recovery (unchanged reload maintenance),
// - config_boundaries (oversized hook timeout and environment policy refusal).
// Their old fixture modules remain on disk while native qualification is pending;
// they are no longer mounted into a rootless kernel test binary.
