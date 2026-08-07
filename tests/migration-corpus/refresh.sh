#!/usr/bin/env bash
# Regenerate the migration corpus from git tags.
#
# The corpus is every `config*.yaml` and its companion `providers*.yaml` from every non-rc tag: the
# documents actually shipped to users, not hand-written fixtures. Hand-written fixtures only ever
# contain the shapes somebody thought of, which is precisely the set that does not catch a shape
# that quietly aged out.
#
# Run after cutting a release so the new version joins the corpus. Idempotent, and safe to re-run:
# it rewrites the directories from scratch, so a file removed upstream disappears here too.
set -euo pipefail
cd "$(dirname "$0")/../.."

out_cfg="tests/migration-corpus/from-tags"
out_prov="tests/migration-corpus/providers"
rm -rf "$out_cfg" "$out_prov"
mkdir -p "$out_cfg" "$out_prov"

n_cfg=0; n_prov=0
for tag in $(git tag --sort=v:refname | grep -vE 'rc'); do
  # `.github/ISSUE_TEMPLATE/config.yml` is GitHub's, not ours.
  for f in $(git ls-tree -r --name-only "$tag" | grep -E '(^|/)config[^/]*\.ya?ml$' | grep -v '^\.github/'); do
    git show "$tag:$f" > "$out_cfg/$(echo "$tag/$f" | tr '/' '_')" && n_cfg=$((n_cfg+1))
  done
  for f in $(git ls-tree -r --name-only "$tag" | grep -E 'providers[^/]*\.ya?ml$'); do
    git show "$tag:$f" > "$out_prov/$(echo "$tag/$f" | tr '/' '_')" && n_prov=$((n_prov+1))
  done
done
echo "corpus: $n_cfg config(s), $n_prov providers file(s) across $(git tag | grep -vcE 'rc') tags"
echo "verify with: cargo test -p busbar --test migration_corpus"
