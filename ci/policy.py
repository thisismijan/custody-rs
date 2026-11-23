import os
import re
import sys

if sys.version_info < (3, 11):
    print("python 3.11 or later is required")
    sys.exit(1)

import tomllib

# deny.toml must equal this exactly, apart from advisories.ignore.
DENY_POLICY = {
    "graph": {"all-features": True},
    "advisories": {
        "yanked": "deny",
        "unmaintained": "all",
        "unsound": "all",
    },
    "licenses": {
        "allow": [
            "MIT",
            "Apache-2.0",
            "Apache-2.0 WITH LLVM-exception",
            "BSD-2-Clause",
            "BSD-3-Clause",
            "ISC",
            "Unicode-3.0",
            "Zlib",
        ],
        "private": {"ignore": True},
    },
    "sources": {
        "unknown-registry": "deny",
        "unknown-git": "deny",
    },
}

CONFIG_KEY_ALLOWLIST = frozenset()
MANIFEST_FORBIDDEN_KEYS = ("source", "patch", "replace")
ADVISORY_ID = re.compile(r"RUSTSEC-\d{4}-\d{4}")
FIXTURES = ("crates", "ci-checks", "tests", "fixtures")

failures = []


def fail(message):
    failures.append(message)


def load(path, shown):
    try:
        with open(path, "rb") as handle:
            return tomllib.load(handle)
    except (ValueError, OSError) as error:
        fail(f"{shown}: cannot be read as TOML: {error}")
        return None


def diff(expected, actual, prefix=""):
    for key in expected.keys() | actual.keys():
        path = f"{prefix}{key}"
        if key not in actual:
            fail(f"deny.toml: {path} removed")
        elif key not in expected:
            fail(f"deny.toml: {path} added")
        elif isinstance(expected[key], dict) and isinstance(actual[key], dict):
            diff(expected[key], actual[key], f"{path}.")
        elif expected[key] != actual[key] or type(expected[key]) is not type(actual[key]):
            fail(f"deny.toml: {path} changed")


def check_ignore(entries):
    if not isinstance(entries, list):
        fail("deny.toml: advisories.ignore must be a list")
        return
    for entry in entries:
        valid = (
            isinstance(entry, dict)
            and set(entry) == {"id", "reason"}
            and isinstance(entry["id"], str)
            and ADVISORY_ID.fullmatch(entry["id"])
            and isinstance(entry["reason"], str)
            and entry["reason"].strip()
        )
        if not valid:
            fail(f"deny.toml: invalid advisories.ignore entry: {entry!r}")


def check_deny(path):
    policy = load(path, "deny.toml")
    if policy is None:
        return
    advisories = policy.get("advisories")
    if isinstance(advisories, dict) and "ignore" in advisories:
        advisories = dict(advisories)
        check_ignore(advisories.pop("ignore"))
        policy = {**policy, "advisories": advisories}
    diff(DENY_POLICY, policy)


def check_config(path, shown):
    config = load(path, shown)
    for key in sorted(config or {}):
        if key not in CONFIG_KEY_ALLOWLIST:
            fail(f"{shown}: key {key!r} is not allowed in a cargo config file")


def check_manifest(path, shown):
    manifest = load(path, shown)
    for key in MANIFEST_FORBIDDEN_KEYS:
        if manifest and key in manifest:
            fail(f"{shown}: top-level key {key!r} is not allowed in a manifest")


def is_fixture_dir(relative_parts):
    return len(relative_parts) == len(FIXTURES) + 1 and relative_parts[:-1] == FIXTURES


def scan(root):
    for directory, subdirs, files in os.walk(root):
        relative = os.path.relpath(directory, root)
        parts = () if relative == "." else tuple(relative.split(os.sep))
        subdirs[:] = [
            name
            for name in subdirs
            if name not in ("target", ".git") and not is_fixture_dir(parts + (name,))
        ]
        for name in subdirs:
            path = os.path.join(directory, name)
            if os.path.islink(path):
                fail(f"{os.path.relpath(path, root)}: symbolic links are not allowed")
        for name in files:
            path = os.path.join(directory, name)
            shown = os.path.relpath(path, root)
            if os.path.islink(path):
                fail(f"{shown}: symbolic links are not allowed")
                continue
            if name == "Cargo.toml":
                check_manifest(path, shown)
            elif name in ("config", "config.toml") and os.path.basename(directory) == ".cargo":
                check_config(path, shown)


def main():
    workspace, deny_path = sys.argv[1:3]
    check_deny(deny_path)
    scan(workspace)
    for message in failures:
        print(message)
    return 1 if failures else 0


sys.exit(main())
