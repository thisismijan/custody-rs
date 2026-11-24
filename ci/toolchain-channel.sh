#!/usr/bin/env bash
set -euo pipefail

exec python3 -I - "${1:-}" <<'PY'
import re
import sys

if sys.version_info < (3, 11):
    print("toolchain-channel: python 3.11 or later is required", file=sys.stderr)
    sys.exit(1)

import tomllib


def fail(message):
    print(f"toolchain-channel: {message}", file=sys.stderr)
    sys.exit(1)


path = sys.argv[1]
try:
    with open(path, "rb") as handle:
        data = tomllib.load(handle)
except FileNotFoundError:
    fail(f"no such file: {path}")
except (ValueError, OSError) as error:
    fail(f"{path} cannot be read as TOML: {error}")

extra = sorted(set(data) - {"toolchain"})
if extra:
    fail(f"{path} may contain only the [toolchain] table, found: {', '.join(extra)}")

table = data.get("toolchain")
if not isinstance(table, dict):
    fail(f"{path} has no [toolchain] table")
channel = table.get("channel")
if not isinstance(channel, str):
    fail("toolchain.channel is missing or is not a string")
if not re.fullmatch(r"[0-9A-Za-z._-]+", channel):
    fail("the channel value contains disallowed characters")

print(channel)
PY
