#!/usr/bin/env bash
# Use the committed version floor plus the stable Actions run number for each release.
set -euo pipefail
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
current=$(head -n1 "$ROOT/VERSION" | tr -d '[:space:]')
if [[ ! "$current" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
  echo "VERSION must contain MAJOR.MINOR.PATCH, got '$current'" >&2
  exit 2
fi
major=${BASH_REMATCH[1]}
minor=${BASH_REMATCH[2]}
floor_patch=${BASH_REMATCH[3]}
if [[ "${1:-}" == "--diagnostic" ]]; then echo "$current"; exit 0; fi
run_number=${1:-}
if [[ ! "$run_number" =~ ^[0-9]+$ ]] || (( 10#$run_number < 1 )); then
  echo "workflow run number must be a positive integer" >&2
  exit 2
fi
echo "$major.$minor.$((10#$floor_patch + 10#$run_number))"
