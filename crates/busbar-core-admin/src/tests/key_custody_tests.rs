// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

// The nine custody tests are ordinary actual-root tests in
// busbar/src/tests/admin_application/admin_custody_outcomes.rs. Their blocking
// and failure controls decorate the configured signed Store; requests traverse
// the actual admin router with genuine OIDC identities. The three typed durable
// receipt assertions still call the production durable::claim API, using the
// exact original create-key framing and the OIDC-qualified original subject.
