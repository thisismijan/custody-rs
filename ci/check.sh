#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: ci/check.sh <workspace-dir>" >&2
  exit 2
fi

if [ "${CI:-}" = "true" ] && [ -n "${CI_CHECK_ADVISORY_DB+set}" ]; then
  echo "CI_CHECK_ADVISORY_DB is not allowed in CI"
  exit 1
fi

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
workspace=$(cd "$1" && pwd)
cd "$workspace"

deny_config=""
trap 'rm -f "$deny_config"' EXIT

step() {
  local name=$1
  shift
  echo "check: $name"
  if ! "$@"; then
    echo "FAILED: $name"
    exit 1
  fi
}

policy() {
  if [ ! -f "$workspace/Cargo.lock" ]; then
    echo "Cargo.lock is missing"
    return 1
  fi
  python3 -I "$repo_root/ci/policy.py" "$workspace" "$repo_root/deny.toml"
}

check_path_dependencies() {
  cargo metadata --locked --all-features --format-version 1 | python3 -I -c '
import json, sys
meta = json.load(sys.stdin)
members = set(meta["workspace_members"])
outside = [p for p in meta["packages"] if p["source"] is None and p["id"] not in members]
for p in outside:
    print("path dependency outside the workspace: " + p["name"] + " at " + p["manifest_path"])
sys.exit(1 if outside else 0)
'
}

deny() {
  local status=0
  if [ -n "${CI_CHECK_ADVISORY_DB:-}" ]; then
    deny_config=$(mktemp)
    CI_CHECK_ADVISORY_DB_TOML=$CI_CHECK_ADVISORY_DB awk '
      { print }
      /^\[advisories\]$/ {
        print "db-path = \"" ENVIRON["CI_CHECK_ADVISORY_DB_TOML"] "\""
        print "db-urls = [\"https://example.invalid/advisory-db\"]"
      }
    ' "$repo_root/deny.toml" >"$deny_config"
    cargo deny --offline --locked --config "$deny_config" check advisories licenses sources || status=1
  else
    cargo deny --locked --config "$repo_root/deny.toml" check advisories licenses sources || status=1
  fi
  check_path_dependencies || status=1
  return "$status"
}

step policy policy
step deny deny
step build cargo build --locked --workspace --all-targets --all-features
step fmt cargo fmt --all -- --check
step clippy cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
step test cargo test --locked --workspace --all-targets --all-features

echo "all checks passed: policy deny build fmt clippy test"
