#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# sign-kms.sh <signed-bytes-file> <sig-out>
#
# Sign a keys document with the non-exportable Cloud KMS HSM P-256 root. gcloud hashes the input
# with SHA-256, checks request/response integrity, and writes the binary ASN.1 DER signature that
# release_trust::wire reads. This command neither creates keys nor exports private material.
#
# BUSBAR_KMS_PROJECT and BUSBAR_KMS_LOCATION are required; no project/location is inferred.
# BUSBAR_KMS_KEYRING defaults to busbar-plugin-signing, BUSBAR_KMS_KEY to busbar-plugins-root,
# and BUSBAR_KMS_VERSION to 1. The configured key version must use ec-sign-p256-sha256.
set +x
set -euo pipefail
umask 077
[ "$#" -eq 2 ] || { echo "usage: $0 <signed-bytes-file> <sig-out>" >&2; exit 2; }
[ -f "$1" ] && [ -r "$1" ] || { echo "sign-kms.sh: input must be a readable file" >&2; exit 2; }
[[ ! "$1" -ef "$2" ]] || { echo "sign-kms.sh: signature output must differ from input" >&2; exit 2; }
: "${BUSBAR_KMS_PROJECT:?set BUSBAR_KMS_PROJECT}" "${BUSBAR_KMS_LOCATION:?set BUSBAR_KMS_LOCATION}"
exec gcloud kms asymmetric-sign \
  --project="${BUSBAR_KMS_PROJECT}" \
  --location="${BUSBAR_KMS_LOCATION}" \
  --keyring="${BUSBAR_KMS_KEYRING:-busbar-plugin-signing}" \
  --key="${BUSBAR_KMS_KEY:-busbar-plugins-root}" \
  --version="${BUSBAR_KMS_VERSION:-1}" \
  --digest-algorithm=sha256 \
  --input-file="$1" \
  --signature-file="$2"
