#!/usr/bin/env python3
"""Print name==version pins for every package in poetry.lock."""

import sys
from pathlib import Path

import tomllib


def main() -> None:
    lock_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("poetry.lock")
    with lock_path.open("rb") as lock_file:
        lock = tomllib.load(lock_file)
    packages = lock.get("package", [])
    if not packages:
        print(f"No packages found in {lock_path}", file=sys.stderr)
        sys.exit(1)
    for package in packages:
        name = package.get("name")
        version = package.get("version")
        if not name or not version:
            print(f"Package entry missing name or version in {lock_path}", file=sys.stderr)
            sys.exit(1)
        print(f"{name}=={version}")


if __name__ == "__main__":
    main()
