#!/usr/bin/env bash
# Create or verify the run-stable release produced by this repository's CI.
set -euo pipefail
if [[ $# -ne 2 ]]; then echo 'usage: publish-release.sh vMAJOR.MINOR.PATCH ASSET_DIR' >&2; exit 2; fi
tag="$1"
assets=$(cd "$2" && pwd)
product=${GITHUB_REPOSITORY##*/}
source_sha=$GITHUB_SHA
[[ "$GITHUB_REPOSITORY" == lmctl-ai/* ]] || { echo 'unexpected release repository' >&2; exit 2; }
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'invalid release tag' >&2; exit 2; }
[[ "$source_sha" =~ ^[0-9a-f]{40}$ ]] || { echo 'source commit SHA is required' >&2; exit 2; }
version=${tag#v}
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT

verify_assets() {
  python3 - "$1" <<'PY'
from pathlib import Path
import hashlib, re, sys
root = Path(sys.argv[1])
files = list(root.iterdir())
assert files and all(p.is_file() and not p.is_symlink() for p in files), 'release assets must be regular files'
assert 'SHA256SUMS' in {p.name for p in files}, 'missing SHA256SUMS'
listed = {}
for line in (root/'SHA256SUMS').read_text(encoding='utf-8').splitlines():
    match = re.fullmatch(r'([0-9a-f]{64})  ([^/]+)', line)
    assert match and match[2] != 'SHA256SUMS' and match[2] not in listed, 'invalid checksum manifest'
    listed[match[2]] = match[1]
assert set(listed) == {p.name for p in files if p.name != 'SHA256SUMS'}, 'checksum manifest/asset set differs'
for name, digest in listed.items():
    assert hashlib.sha256((root/name).read_bytes()).hexdigest() == digest, f'checksum mismatch: {name}'
PY
  local binary="$1/$product-linux-x64"
  chmod +x "$binary"
  local actual
  actual=$("$binary" --version)
  [[ "$actual" == "$product $version"* ]] || { echo "tag $tag does not match $actual" >&2; return 1; }
}

verify_release_identity() {
  RELEASE_JSON="$1" EXPECTED_TAG="$tag" EXPECTED_SHA="$source_sha" python3 - <<'PY'
import json, os
release = json.loads(os.environ['RELEASE_JSON'])
assert release['tagName'] == os.environ['EXPECTED_TAG'], 'release tag mismatch'
assert not release['isDraft'] and not release['isPrerelease'], 'expected a published stable release'
assert f"source-commit: {os.environ['EXPECTED_SHA']}" in release.get('body',''), 'release source commit mismatch'
PY
}

notes="$temporary/release-notes.md"
printf 'source-commit: %s\nworkflow-run: %s\n\n' "$source_sha" "${GITHUB_RUN_ID:-unknown}" > "$notes"
if existing=$(gh release view "$tag" --repo "$GITHUB_REPOSITORY" --json tagName,isDraft,isPrerelease,body 2>/dev/null); then
  verify_release_identity "$existing"
  if gh release download "$tag" --repo "$GITHUB_REPOSITORY" --dir "$temporary/existing" >/dev/null 2>&1 && verify_assets "$temporary/existing" >/dev/null 2>&1; then
    echo "Verified existing run-stable release $tag."
    exit 0
  fi
  echo "Repairing incomplete assets for the same-source release $tag."
  gh release upload "$tag" --repo "$GITHUB_REPOSITORY" --clobber "$assets"/*
else
  gh release create "$tag" "$assets"/* --repo "$GITHUB_REPOSITORY" --target "$source_sha" --latest \
    --title "$product $tag" --notes-file "$notes"
fi
gh release download "$tag" --repo "$GITHUB_REPOSITORY" --dir "$temporary/verify"
verify_release_identity "$(gh release view "$tag" --repo "$GITHUB_REPOSITORY" --json tagName,isDraft,isPrerelease,body)"
verify_assets "$temporary/verify"
echo "Verified stable run-derived release $tag."
