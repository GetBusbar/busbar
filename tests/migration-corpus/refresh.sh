#!/usr/bin/env bash
# Regenerate the migration corpus from git tags — or, with --check, prove it is whole.
#
# The corpus is every `config*.yaml` and its companion `providers*.yaml` from every release tag: the
# documents actually shipped to users, not hand-written fixtures. Hand-written fixtures only ever
# contain the shapes somebody thought of, which is precisely the set that does not catch a shape
# that quietly aged out.
#
# Run after cutting a release so the new version joins the corpus. Idempotent, and safe to re-run:
# it rewrites `from-tags/` from scratch, so a config removed upstream disappears here too.
#
# `providers/` is NOT wiped: besides the tag-derived catalogs it holds hand-added COMPANION catalogs
# (27a377525: the docker and claude-code-bedrock example configs shipped with no providers.yaml of
# their own, so each got a minimal catalog naming its one provider). Wiping the directory deleted
# them on every refresh. Tag-derived catalogs are (re)written; companions are left alone.
#
# THE CORPUS IS EXCLUDED FROM ITS OWN SOURCE. From v1.5.3 on, every tag CONTAINS this corpus, and the
# unanchored `providers*.yaml` pattern then matched `tests/migration-corpus/providers/*.yaml` inside
# the tag — each refresh would have copied the previous corpus into itself as
# `v1.5.3_tests_migration-corpus_providers_v0.10.0_providers.yaml` and so on. Nothing under
# tests/migration-corpus/ shipped as a user's config.
#
#   --check [--corpus-dir DIR]   exit 1 unless every file the tags shipped is present in DIR
#                                (default: this directory) byte-identical, and from-tags/ holds
#                                nothing the tags did not ship. A release whose configs never joined
#                                the corpus (v1.5.3/1.5.4/1.5.5 did not — TODO item 48) is named.
#                                Refuses — never passes — on a clone with no release tags.
set -euo pipefail
cd "$(dirname "$0")/../.."

mode=write
corpus="tests/migration-corpus"
while [ $# -gt 0 ]; do
  case "$1" in
    --check) mode=check; shift ;;
    --corpus-dir) corpus="${2:?--corpus-dir needs a directory}"; shift 2 ;;
    *) echo "usage: $0 [--check [--corpus-dir DIR]]" >&2; exit 2 ;;
  esac
done

# RELEASE tags only (`vX.Y.Z`): a clone also carries archive/, backup/ and working tags that no user
# was ever handed, and a bare `grep -v rc` let every one of them in as "shipped".
tags="$(git tag --sort=v:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' || true)"
if [ -z "$tags" ]; then
  echo "no release (vX.Y.Z) git tags in this clone (shallow or --no-tags checkout?) — the shipped set cannot be" >&2
  echo "derived, so the corpus cannot be checked against it; refusing rather than passing" >&2
  exit 1
fi

# Every (tag, path, corpus-dir, corpus-name) the tags shipped, one per line, tab-separated.
shipped() {
  local tag f
  for tag in $tags; do
    # `.github/ISSUE_TEMPLATE/config.yml` is GitHub's, not ours.
    for f in $(git ls-tree -r --name-only "$tag" | grep -E '(^|/)config[^/]*\.ya?ml$' | grep -vE '^(\.github|tests/migration-corpus)/'); do
      printf '%s\t%s\tfrom-tags\t%s\n' "$tag" "$f" "$(echo "$tag/$f" | tr '/' '_')"
    done
    for f in $(git ls-tree -r --name-only "$tag" | grep -E 'providers[^/]*\.ya?ml$' | grep -vE '^tests/migration-corpus/'); do
      printf '%s\t%s\tproviders\t%s\n' "$tag" "$f" "$(echo "$tag/$f" | tr '/' '_')"
    done
  done
}

if [ "$mode" = write ]; then
  rm -rf "$corpus/from-tags"
  mkdir -p "$corpus/from-tags" "$corpus/providers"
  n_cfg=0; n_prov=0
  while IFS=$'\t' read -r tag f dir name; do
    git show "$tag:$f" > "$corpus/$dir/$name"
    if [ "$dir" = from-tags ]; then n_cfg=$((n_cfg+1)); else n_prov=$((n_prov+1)); fi
  done < <(shipped)
  echo "corpus: $n_cfg config(s), $n_prov providers file(s) across $(printf '%s\n' $tags | wc -l | tr -d ' ') tags"
  echo "verify with: cargo test -p busbar --test migration_corpus && $0 --check"
  exit 0
fi

# --check
bad=0; want_cfg=""; seen_tags=""
tmp="$(mktemp "${TMPDIR:-/tmp}/migration-corpus-check.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
while IFS=$'\t' read -r tag f dir name; do
  [ "$dir" = from-tags ] && want_cfg="$want_cfg $name"
  git show "$tag:$f" > "$tmp"
  if [ ! -f "$corpus/$dir/$name" ]; then
    echo "MISSING  $dir/$name — $tag shipped $f and the corpus has never seen it"; bad=1
  elif ! cmp -s "$tmp" "$corpus/$dir/$name"; then
    echo "CHANGED  $dir/$name differs from what $tag shipped as $f — the corpus is evidence; fix the migrator, not the corpus"; bad=1
  fi
  case " $seen_tags " in *" $tag "*) ;; *) seen_tags="$seen_tags $tag" ;; esac
done < <(shipped)
for p in "$corpus"/from-tags/*; do
  [ -e "$p" ] || continue
  case " $want_cfg " in *" $(basename "$p") "*) ;; *) echo "EXTRA    from-tags/$(basename "$p") — no tag shipped it"; bad=1 ;; esac
done
n="$(printf '%s\n' $want_cfg | grep -c . || true)"
if [ "$bad" -ne 0 ]; then
  echo "migration corpus: NOT WHOLE against the shipped tags (run tests/migration-corpus/refresh.sh)"
  exit 1
fi
echo "migration corpus: whole — $n shipped config(s) from$(printf ' %s' $seen_tags | tr ' ' '\n' | grep -c . | sed 's/^/ /') tag(s), newest$(printf '%s\n' $tags | tail -1 | sed 's/^/ /')"
