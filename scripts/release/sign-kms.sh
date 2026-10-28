#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# sign-kms.sh <signed-bytes-file> <sig-out>
#
# Signs with a Cloud KMS HSM ECDSA P-256 key (ec-sign-p256-sha256): gcloud hashes the file with
# SHA-256 locally and KMS signs the digest; the signature written is ASN.1 DER, the encoding
# release_trust::wire reads for P-256 (docs/design/release-trust.md). The private key never leaves
# the HSM. Used by the ROOT (`busbar-plugins-root`) to sign a keys document; any signer key in KMS
# works the same way.
#
#   BUSBAR_KMS_PROJECT   the GCP project holding the key ring      (required)
#   BUSBAR_KMS_LOCATION  the key ring's location                   (required)
#   BUSBAR_KMS_KEYRING   default busbar-plugin-signing
#   BUSBAR_KMS_KEY       default busbar-plugins-root
#   BUSBAR_KMS_VERSION   default 1
set -euo pipefail
[ "$#" -eq 2 ] || { echo "usage: $0 <signed-bytes-file> <sig-out>" >&2; exit 2; }
: "${BUSBAR_KMS_PROJECT:?set BUSBAR_KMS_PROJECT}" "${BUSBAR_KMS_LOCATION:?set BUSBAR_KMS_LOCATION}"
exec gcloud kms asymmetric-sign \
  --project "${BUSBAR_KMS_PROJECT}" \
  --location "${BUSBAR_KMS_LOCATION}" \
  --keyring "${BUSBAR_KMS_KEYRING:-busbar-plugin-signing}" \
  --key "${BUSBAR_KMS_KEY:-busbar-plugins-root}" \
  --version "${BUSBAR_KMS_VERSION:-1}" \
  --digest-algorithm sha256 \
  --input-file "$1" \
  --signature-file "$2"
