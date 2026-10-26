#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# subject-config.sh <dir> <port>: the subject busbar's config.yaml and providers.yaml. The smallest
# config that serves: a `tls:` listener on the run-time self-signed cert (<dir>/cert.pem, key.pem),
# a closed auth chain, no providers.
set -euo pipefail
d="$1"; port="$2"
cat >"$d/config.yaml" <<YAML
listen: "127.0.0.1:$port"
store: { module: memory }
tls:
  cert: { file: "$d/cert.pem" }
  key: { file: "$d/key.pem" }
providers: {}
models: {}
pools: {}
identity-providers:
  admin-tokens: { module: admin-tokens, token: { env: BUSBAR_ADMIN_TOKEN } }
auth:
  chain: [keys]
  admin_auth: [admin-tokens]
  signing_key: { file: "$d/signing.key" }
YAML
