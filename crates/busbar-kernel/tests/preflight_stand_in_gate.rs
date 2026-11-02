// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

// The actual OIDC plugin-disabled refusal oracle lives in the distribution's
// kernel_application/external_preflight.rs, where the real composition root exists.
// The old test-only auth-module self-registration assertion was fixture scaffolding:
// those modules do not exist in the product and are intentionally not registered.
