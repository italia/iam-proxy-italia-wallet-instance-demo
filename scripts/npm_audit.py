#!/usr/bin/env python3
"""Run npm audit and ignore advisories that have no patched release."""

import json
import subprocess
import sys

# picomatch <=4.0.7 has no patched release (GHSA-fc5q-39xc-vjpf).
# Stylelint is a devDependency and matches CSS paths from this repository.
IGNORED_ADVISORIES = frozenset({"GHSA-fc5q-39xc-vjpf"})


def main() -> None:
    completed = subprocess.run(
        ["npm", "audit", "--package-lock-only", "--json"],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode not in (0, 1):
        sys.stderr.write(completed.stderr)
        sys.stdout.write(completed.stdout)
        sys.exit(completed.returncode or 1)

    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError:
        sys.stdout.write(completed.stdout)
        sys.stderr.write(completed.stderr)
        sys.exit(1)

    vulnerabilities = report.get("vulnerabilities") or {}
    blocked = blocked_packages(vulnerabilities)
    if blocked:
        print("Vulnerabilities found:")
        for name in sorted(blocked):
            info = vulnerabilities[name]
            detail = vulnerability_detail(info)
            print(f"  {name} ({info.get('severity', 'unknown')}) via {detail}")
        sys.exit(1)

    ignored = sorted(name for name, info in vulnerabilities.items() if ignored_advisory(info))
    if not ignored:
        print("found 0 vulnerabilities")
        return

    print(f"No known vulnerabilities found, {len(ignored)} ignored")
    print(f"{'Name':<12} Advisory")
    print(f"{'-' * 12} {'-' * 22}")
    for name in ignored:
        print(f"{name:<12} {', '.join(advisory_ids(vulnerabilities[name]))}")


def advisory_ids(info: dict) -> list[str]:
    ids = []
    for item in info.get("via") or []:
        if not isinstance(item, dict):
            continue
        url = item.get("url") or ""
        advisory = url.rstrip("/").rsplit("/", 1)[-1]
        if advisory:
            ids.append(advisory)
    return ids


def ignored_advisory(info: dict) -> bool:
    advisories = advisory_ids(info)
    return bool(advisories) and set(advisories) <= IGNORED_ADVISORIES


def vulnerability_detail(info: dict) -> str:
    advisories = [advisory for advisory in advisory_ids(info) if advisory not in IGNORED_ADVISORIES]
    if advisories:
        return ", ".join(advisories)
    via_names = [item for item in info.get("via") or [] if isinstance(item, str)]
    return ", ".join(via_names)


def blocked_packages(vulnerabilities: dict) -> set[str]:
    blocked: set[str] = set()
    changed = True
    while changed:
        changed = absorb_blocked(vulnerabilities, blocked)
    return blocked


def absorb_blocked(vulnerabilities: dict, blocked: set[str]) -> bool:
    changed = False
    for name, info in vulnerabilities.items():
        if name in blocked or not package_blocked(info, blocked):
            continue
        blocked.add(name)
        changed = True
    return changed


def package_blocked(info: dict, blocked: set[str]) -> bool:
    if any(advisory not in IGNORED_ADVISORIES for advisory in advisory_ids(info)):
        return True
    via_names = [item for item in info.get("via") or [] if isinstance(item, str)]
    return any(name in blocked for name in via_names)


if __name__ == "__main__":
    main()
