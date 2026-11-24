#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "toolchain-channel: $1" >&2
  exit 1
}

file=${1:-}
[ -f "$file" ] || fail "no such file: $file"

table=""
count=0
value=""
value_table=""
while IFS= read -r line || [ -n "$line" ]; do
  if [[ $line =~ ^\[.*\]$ ]]; then
    table=$line
  elif [[ $line =~ ^channel\ =\ \"(.*)\"$ ]]; then
    count=$((count + 1))
    value=${BASH_REMATCH[1]}
    value_table=$table
  fi
done < "$file"

[ "$count" -eq 1 ] || fail "expected exactly one channel line in $file, found $count"
[ "$value_table" = "[toolchain]" ] || fail "the channel line is not inside the [toolchain] table"
[[ $value =~ ^[0-9A-Za-z._-]+$ ]] || fail "the channel value contains disallowed characters"

printf '%s\n' "$value"
