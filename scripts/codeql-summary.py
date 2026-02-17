#!/usr/bin/env python3
"""Print CodeQL SARIF results and exit 1 if any security issues are reported."""
import json
import sys

def main():
    if len(sys.argv) < 2:
        print("Usage: codeql-summary.py <sarif-file>", file=sys.stderr)
        sys.exit(2)
    with open(sys.argv[1]) as f:
        data = json.load(f)
    results = []
    for run in data.get("runs", []):
        for r in run.get("results", []):
            rule = r.get("ruleId", "?")
            loc = r.get("locations", [{}])[0].get("physicalLocation", {})
            path = loc.get("artifactLocation", {}).get("uri", "")
            line = loc.get("region", {}).get("startLine")
            msg = (r.get("message", {}).get("text", "") or "")[:70]
            results.append((rule, path, line, msg))
    print("CodeQL findings:", len(results))
    for rule, path, line, msg in results:
        loc_str = f"{path}:L{line}" if line else path
        print(f"  - {rule} {loc_str} | {msg}")
    sys.exit(1 if results else 0)


if __name__ == "__main__":
    main()
